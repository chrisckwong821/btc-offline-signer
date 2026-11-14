//! A human-readable summary of what a transaction does, for the user to read
//! before broadcasting.
//!
//! The tool can prove an address is well-formed, but only a person can tell
//! whether it is the *intended* one. Showing every destination and amount is
//! the last line of defence against paying the wrong address.

use std::fmt;

use bitcoin::{Address, Amount, Network, TxOut};

use crate::builder::UnsignedTx;

/// Where the money in a transaction comes from and goes to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Review {
    /// How many coins are being spent, and their combined value.
    input_count: usize,
    input_total: Amount,
    /// One entry per recipient, in the order requested.
    payments: Vec<Destination>,
    /// `None` when the leftover was too small to be worth an output.
    change: Option<Destination>,
    fee: Amount,
}

/// One line of the review: an amount and where it goes.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Destination {
    amount: Amount,
    /// The address, or the raw script when it has no address form.
    to: String,
}

impl Review {
    /// Describes `unsigned`, writing addresses in the format of `network`.
    ///
    /// It reads the transaction that is about to be signed, not the params
    /// file, so what the user reviews is exactly what gets signed.
    pub fn new(unsigned: &UnsignedTx, network: Network) -> Self {
        // Turns an output's lock script back into the address a person
        // would recognise.
        let destination = |output: &TxOut| Destination {
            amount: output.value,
            to: match Address::from_script(&output.script_pubkey, network) {
                Ok(address) => address.to_string(),
                Err(_) => format!("script {}", output.script_pubkey.to_hex_string()),
            },
        };

        Self {
            input_count: unsigned.prevouts().len(),
            input_total: unsigned
                .prevouts()
                .iter()
                .map(|prevout| prevout.value)
                .sum(),
            payments: unsigned.payments().iter().map(destination).collect(),
            change: unsigned.change().map(destination),
            fee: unsigned.fee(),
        }
    }
}

/// One line per movement of money, with the amounts in a right-aligned column.
impl fmt::Display for Review {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Writes "label:   <amount> sat<rest>". `{label:<10}` pads the label
        // to 10 characters; `{:>10}` right-aligns the number in 10.
        let line = |f: &mut fmt::Formatter<'_>, label: &str, amount: Amount, rest: &str| {
            writeln!(f, "{label:<10}{:>10} sat{rest}", amount.to_sat())
        };

        let plural = if self.input_count == 1 { "" } else { "s" };
        let source = format!(" from {} input{plural}", self.input_count);
        line(f, "spending:", self.input_total, &source)?;

        for payment in &self.payments {
            line(f, "pay:", payment.amount, &format!(" to {}", payment.to))?;
        }

        match &self.change {
            Some(change) => line(f, "change:", change.amount, &format!(" to {}", change.to))?,
            None => writeln!(
                f,
                "{:<10}none (leftover is below the dust limit and goes to the fee)",
                "change:"
            )?,
        }

        line(f, "fee:", self.fee, "")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builder::build_unsigned;
    use crate::key::SigningKey;
    use crate::params::SpendRequest;
    use serde_json::{json, Value};

    // Secret key 1 on testnet with its P2WPKH address, and the BIP173 example P2WSH address.
    const OWNER_WIF: &str = "cMahea7zqjxrtgAbB7LSGbcQUr1uX1ojuat9jZodMN87JcbXMTcA";
    const OWNER: &str = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx";
    const RECIPIENT: &str = "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7";
    const OTHER: &str = "tb1pmfr3p9j00pfxjh0zmgp99y8zftmd3s5pmedqhyptwy6lm87hf5ssk79hv2";

    fn review(params: Value) -> String {
        let request = SpendRequest::from_json(&params.to_string()).unwrap();
        let key = SigningKey::from_wif(OWNER_WIF, request.network).unwrap();
        let unsigned = build_unsigned(&request, key.owner()).unwrap();
        Review::new(&unsigned, request.network).to_string()
    }

    fn params(recipient_sats: u64) -> Value {
        json!({
            "network": "testnet4",
            "utxos": [{ "txid": "aa".repeat(32), "vout": 0, "amount_sat": 100_000 }],
            "recipients": [{ "address": RECIPIENT, "amount_sat": recipient_sats }],
            "fee_rate_sat_per_vb": 2
        })
    }

    #[test]
    fn lists_inputs_payment_change_and_fee() {
        let expected = format!(
            "spending:     100000 sat from 1 input\n\
             pay:           30000 sat to {RECIPIENT}\n\
             change:        69694 sat to {OWNER}\n\
             fee:             306 sat\n"
        );

        assert_eq!(review(params(30_000)), expected);
    }

    #[test]
    fn lists_every_recipient_in_order() {
        let mut params = params(30_000);
        params["recipients"]
            .as_array_mut()
            .unwrap()
            .push(json!({ "address": OTHER, "amount_sat": 20_000 }));

        let text = review(params);
        let lines: Vec<&str> = text.lines().collect();

        assert_eq!(lines[1], format!("pay:           30000 sat to {RECIPIENT}"));
        assert_eq!(lines[2], format!("pay:           20000 sat to {OTHER}"));
        assert!(lines[3].starts_with("change:"));
    }

    #[test]
    fn shows_an_explicit_change_address() {
        let mut params = params(30_000);
        params["change_address"] = json!(OTHER);

        let text = review(params);

        assert!(text
            .lines()
            .any(|line| line.starts_with("change:") && line.ends_with(OTHER)));
        assert!(!text.contains(OWNER));
    }

    #[test]
    fn counts_and_totals_multiple_inputs() {
        let mut params = params(30_000);
        params["utxos"]
            .as_array_mut()
            .unwrap()
            .push(json!({ "txid": "bb".repeat(32), "vout": 1, "amount_sat": 50_000 }));

        let text = review(params);

        assert_eq!(
            text.lines().next().unwrap(),
            "spending:     150000 sat from 2 inputs"
        );
    }

    #[test]
    fn says_so_when_there_is_no_change_output() {
        // Leaves 500 sat: enough for the fee, too little for a change output.
        let text = review(params(99_500));

        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(
            lines[2],
            "change:   none (leftover is below the dust limit and goes to the fee)"
        );
        assert_eq!(lines[3], "fee:             500 sat");
    }

    #[test]
    fn amounts_always_add_up() {
        // spending = pay + change + fee, read back from the printed text.
        let text = review(params(30_000));
        let sats = |label: &str| -> u64 {
            text.lines()
                .filter(|line| line.starts_with(label))
                .map(|line| {
                    line.split_whitespace()
                        .nth(1)
                        .unwrap()
                        .parse::<u64>()
                        .unwrap()
                })
                .sum()
        };

        assert_eq!(
            sats("spending:"),
            sats("pay:") + sats("change:") + sats("fee:")
        );
    }
}
