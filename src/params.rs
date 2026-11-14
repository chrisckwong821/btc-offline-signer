//! Turns the user's JSON params file into a validated [`SpendRequest`].
//!
//! Parsing happens in stages so that the rest of the crate never sees
//! unvalidated input:
//!
//! 1. `serde` maps the JSON onto `RawParams`, which holds plain strings and
//!    numbers exactly as the user wrote them.
//! 2. [`SpendRequest::try_from`] converts those into `bitcoin` types
//!    (`Address`, `Amount`, `OutPoint`, ...), rejecting anything malformed.
//! 3. [`SpendRequest::new`] checks the rules that involve more than one
//!    field. It is the only way to create a `SpendRequest`, whether the values
//!    came from JSON or from other code.

use std::collections::HashSet;

use bitcoin::address::NetworkUnchecked;
use bitcoin::{Address, Amount, FeeRate, Network, OutPoint, Txid};
use serde::Deserialize;

use crate::{Error, InputKind};

/// A fully validated description of what the user wants to do.
///
/// Fields cannot be set from outside this crate, so every `SpendRequest` has
/// passed the checks in [`SpendRequest::new`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpendRequest {
    pub(crate) network: Network,
    /// Coins to spend. All of them are used as inputs.
    pub(crate) utxos: Vec<Utxo>,
    pub(crate) recipients: Vec<Recipient>,
    /// Where leftover funds go. `None` means "back to the signer's address".
    pub(crate) change_address: Option<Address>,
    pub(crate) fee_rate: FeeRate,
}

/// An unspent output owned by the signing key: a "coin" to spend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Utxo {
    /// Which coin: the transaction that created it plus the output's index.
    pub outpoint: OutPoint,
    /// How much it is worth. Must be exact, because it gets signed.
    pub amount: Amount,
    /// How the output is locked, and therefore how it must be signed.
    pub kind: InputKind,
}

/// Someone to pay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Recipient {
    /// Well-formed by construction; [`SpendRequest::new`] checks that it is
    /// on the request's network.
    pub address: Address,
    pub amount: Amount,
}

impl SpendRequest {
    /// Creates a request from already-typed values, checking the rules that
    /// make them a sensible payment:
    ///
    /// - there is at least one coin to spend and one recipient,
    /// - no coin is listed twice (spending it twice in one transaction is
    ///   invalid),
    /// - every address belongs to `network`,
    /// - the fee rate is not zero (nodes do not relay free transactions).
    pub fn new(
        network: Network,
        utxos: Vec<Utxo>,
        recipients: Vec<Recipient>,
        change_address: Option<Address>,
        fee_rate: FeeRate,
    ) -> Result<Self, Error> {
        if utxos.is_empty() {
            return Err(Error::NoUtxos);
        }
        if recipients.is_empty() {
            return Err(Error::NoRecipients);
        }

        // `insert` returns false when the set already holds the value.
        let mut seen = HashSet::new();
        if let Some(repeat) = utxos.iter().find(|utxo| !seen.insert(utxo.outpoint)) {
            return Err(Error::DuplicateUtxo(repeat.outpoint));
        }

        let recipient_addresses = recipients.iter().map(|recipient| &recipient.address);
        for address in recipient_addresses.chain(&change_address) {
            if !address.as_unchecked().is_valid_for_network(network) {
                return Err(Error::InvalidAddress {
                    address: address.to_string(),
                    reason: format!("not an address on {network}"),
                });
            }
        }

        if fee_rate == FeeRate::ZERO {
            return Err(Error::InvalidFeeRate(0));
        }

        Ok(Self {
            network,
            utxos,
            recipients,
            change_address,
            fee_rate,
        })
    }

    /// Reads a params file's text. Either every field is valid and a
    /// `SpendRequest` comes back, or the first problem found is returned.
    pub fn from_json(json: &str) -> Result<Self, Error> {
        let raw: RawParams = serde_json::from_str(json)?;
        Self::try_from(raw)
    }

    pub fn network(&self) -> Network {
        self.network
    }

    /// The coins to spend, in the order they become inputs.
    pub fn utxos(&self) -> &[Utxo] {
        &self.utxos
    }

    /// Who is paid, in the order they become outputs.
    pub fn recipients(&self) -> &[Recipient] {
        &self.recipients
    }

    /// Where change goes, or `None` for "back to the signer".
    pub fn change_address(&self) -> Option<&Address> {
        self.change_address.as_ref()
    }

    pub fn fee_rate(&self) -> FeeRate {
        self.fee_rate
    }
}

/// Maps a user-facing network name to a [`Network`].
pub fn parse_network(name: &str) -> Result<Network, Error> {
    match name {
        "mainnet" => Ok(Network::Bitcoin),
        "testnet" => Ok(Network::Testnet),
        "testnet4" => Ok(Network::Testnet4),
        "signet" => Ok(Network::Signet),
        "regtest" => Ok(Network::Regtest),
        other => Err(Error::UnknownNetwork(other.to_string())),
    }
}

/// The conversion step: plain text and numbers in, typed values out, which
/// are then handed to [`SpendRequest::new`] for the final checks.
impl TryFrom<RawParams> for SpendRequest {
    type Error = Error;

    fn try_from(raw: RawParams) -> Result<Self, Error> {
        // The network comes first: addresses are checked against it below.
        let network = parse_network(&raw.network)?;

        let utxos = parse_utxos(&raw.utxos)?;

        // `collect` into a `Result` stops at the first recipient that fails.
        let recipients = raw
            .recipients
            .iter()
            .map(|r| {
                Ok(Recipient {
                    address: parse_address(&r.address, network)?,
                    amount: Amount::from_sat(r.amount_sat),
                })
            })
            .collect::<Result<Vec<_>, Error>>()?;

        // Optional field: parse it only if present. `transpose` turns
        // "maybe a parse result" into "a result holding maybe an address",
        // so `?` can report a bad address.
        let change_address = raw
            .change_address
            .as_deref()
            .map(|address| parse_address(address, network))
            .transpose()?;

        // `None` here means the number is too large to be a fee rate.
        let fee_rate = FeeRate::from_sat_per_vb(raw.fee_rate_sat_per_vb)
            .ok_or(Error::InvalidFeeRate(raw.fee_rate_sat_per_vb))?;

        Self::new(network, utxos, recipients, change_address, fee_rate)
    }
}

/// Converts each UTXO entry, rejecting a malformed txid or an unknown `type`.
fn parse_utxos(raw: &[RawUtxo]) -> Result<Vec<Utxo>, Error> {
    raw.iter()
        .map(|utxo| {
            let txid: Txid = utxo
                .txid
                .parse()
                .map_err(|e: bitcoin::hex::HexToArrayError| Error::InvalidTxid {
                    txid: utxo.txid.clone(),
                    reason: e.to_string(),
                })?;
            let outpoint = OutPoint::new(txid, utxo.vout);
            let kind = match &utxo.kind {
                Some(name) => name.parse()?,
                None => InputKind::default(),
            };
            Ok(Utxo {
                outpoint,
                amount: Amount::from_sat(utxo.amount_sat),
                kind,
            })
        })
        .collect()
}

/// Parses an address and proves it belongs to `network`.
///
/// Parsing checks the address's built-in checksum, which catches typos.
/// `require_network` then stops, say, a mainnet address in a testnet payment,
/// and gives the unchecked address the type the rest of the code can use.
fn parse_address(text: &str, network: Network) -> Result<Address, Error> {
    let invalid = |reason: String| Error::InvalidAddress {
        address: text.to_string(),
        reason,
    };

    text.parse::<Address<NetworkUnchecked>>()
        .map_err(|e| invalid(e.to_string()))?
        .require_network(network)
        .map_err(|e| invalid(e.to_string()))
}

/// The params file exactly as written by the user.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)] // a misspelled field is an error, not silently ignored
struct RawParams {
    network: String,
    utxos: Vec<RawUtxo>,
    recipients: Vec<RawRecipient>,
    change_address: Option<String>,
    fee_rate_sat_per_vb: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawUtxo {
    txid: String,
    vout: u32,
    amount_sat: u64,
    /// One of the [`InputKind`] names. Omitted means native SegWit.
    #[serde(rename = "type")]
    kind: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRecipient {
    address: String,
    amount_sat: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    const TXID_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const TESTNET_ADDR: &str = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx";
    const MAINNET_ADDR: &str = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";

    fn valid() -> Value {
        json!({
            "network": "testnet4",
            "utxos": [{ "txid": TXID_A, "vout": 1, "amount_sat": 100_000 }],
            "recipients": [{ "address": TESTNET_ADDR, "amount_sat": 30_000 }],
            "change_address": TESTNET_ADDR,
            "fee_rate_sat_per_vb": 2
        })
    }

    fn parse(value: Value) -> Result<SpendRequest, Error> {
        SpendRequest::from_json(&value.to_string())
    }

    #[test]
    fn parses_a_valid_file_into_typed_values() {
        let request = parse(valid()).unwrap();

        assert_eq!(request.network, Network::Testnet4);
        assert_eq!(request.utxos.len(), 1);
        assert_eq!(request.utxos[0].outpoint.txid.to_string(), TXID_A);
        assert_eq!(request.utxos[0].outpoint.vout, 1);
        assert_eq!(request.utxos[0].amount, Amount::from_sat(100_000));
        assert_eq!(request.recipients[0].address.to_string(), TESTNET_ADDR);
        assert_eq!(request.recipients[0].amount, Amount::from_sat(30_000));
        assert_eq!(request.change_address.unwrap().to_string(), TESTNET_ADDR);
        assert_eq!(request.fee_rate, FeeRate::from_sat_per_vb(2).unwrap());
    }

    #[test]
    fn change_address_is_optional() {
        let mut params = valid();
        params.as_object_mut().unwrap().remove("change_address");
        assert_eq!(parse(params).unwrap().change_address, None);
    }

    #[test]
    fn utxo_type_defaults_to_native_segwit() {
        assert_eq!(parse(valid()).unwrap().utxos[0].kind, InputKind::P2wpkh);
    }

    #[test]
    fn utxo_type_can_be_any_supported_kind() {
        for kind in InputKind::ALL {
            let mut params = valid();
            params["utxos"][0]["type"] = json!(kind.name());
            assert_eq!(parse(params).unwrap().utxos[0].kind, kind);
        }
    }

    #[test]
    fn rejects_unknown_utxo_type() {
        let mut params = valid();
        params["utxos"][0]["type"] = json!("p2wsh");
        assert!(matches!(parse(params), Err(Error::UnknownInputType(_))));
    }

    #[test]
    fn network_names() {
        assert_eq!(parse_network("mainnet").unwrap(), Network::Bitcoin);
        assert_eq!(parse_network("testnet").unwrap(), Network::Testnet);
        assert_eq!(parse_network("testnet4").unwrap(), Network::Testnet4);
        assert_eq!(parse_network("signet").unwrap(), Network::Signet);
        assert_eq!(parse_network("regtest").unwrap(), Network::Regtest);
        assert!(matches!(
            parse_network("dogecoin"),
            Err(Error::UnknownNetwork(_))
        ));
    }

    #[test]
    fn rejects_malformed_json() {
        let err = SpendRequest::from_json("{ not json").unwrap_err();
        assert!(matches!(err, Error::InvalidJson(_)));
    }

    #[test]
    fn rejects_unknown_fields() {
        let mut params = valid();
        params["fee_rate"] = json!(5); // typo for fee_rate_sat_per_vb
        assert!(matches!(parse(params), Err(Error::InvalidJson(_))));
    }

    #[test]
    fn rejects_negative_amounts() {
        let mut params = valid();
        params["recipients"][0]["amount_sat"] = json!(-1);
        assert!(matches!(parse(params), Err(Error::InvalidJson(_))));
    }

    #[test]
    fn rejects_unknown_network() {
        let mut params = valid();
        params["network"] = json!("dogecoin");
        assert!(matches!(parse(params), Err(Error::UnknownNetwork(_))));
    }

    #[test]
    fn rejects_bad_txid() {
        let mut params = valid();
        params["utxos"][0]["txid"] = json!("abc123");
        assert!(matches!(parse(params), Err(Error::InvalidTxid { .. })));
    }

    #[test]
    fn rejects_recipient_on_another_network() {
        let mut params = valid();
        params["recipients"][0]["address"] = json!(MAINNET_ADDR);
        assert!(matches!(parse(params), Err(Error::InvalidAddress { .. })));
    }

    #[test]
    fn rejects_change_address_on_another_network() {
        let mut params = valid();
        params["change_address"] = json!(MAINNET_ADDR);
        assert!(matches!(parse(params), Err(Error::InvalidAddress { .. })));
    }

    #[test]
    fn rejects_unparseable_address() {
        let mut params = valid();
        params["recipients"][0]["address"] = json!("hello");
        assert!(matches!(parse(params), Err(Error::InvalidAddress { .. })));
    }

    #[test]
    fn rejects_empty_utxos() {
        let mut params = valid();
        params["utxos"] = json!([]);
        assert!(matches!(parse(params), Err(Error::NoUtxos)));
    }

    #[test]
    fn rejects_empty_recipients() {
        let mut params = valid();
        params["recipients"] = json!([]);
        assert!(matches!(parse(params), Err(Error::NoRecipients)));
    }

    #[test]
    fn rejects_duplicate_utxo() {
        let mut params = valid();
        let utxo = params["utxos"][0].clone();
        params["utxos"].as_array_mut().unwrap().push(utxo);
        assert!(matches!(parse(params), Err(Error::DuplicateUtxo(_))));
    }

    /// Typed values for the same payment as `valid()`.
    fn typed() -> (Network, Vec<Utxo>, Vec<Recipient>, FeeRate) {
        let request = parse(valid()).unwrap();
        (
            request.network,
            request.utxos,
            request.recipients,
            request.fee_rate,
        )
    }

    fn mainnet_address() -> Address {
        MAINNET_ADDR.parse::<Address<_>>().unwrap().assume_checked()
    }

    #[test]
    fn new_accepts_valid_typed_values() {
        let (network, utxos, recipients, fee_rate) = typed();

        let request = SpendRequest::new(network, utxos, recipients, None, fee_rate).unwrap();

        assert_eq!(request.network(), Network::Testnet4);
        assert_eq!(request.utxos().len(), 1);
        assert_eq!(request.recipients().len(), 1);
        assert_eq!(request.change_address(), None);
        assert_eq!(request.fee_rate(), fee_rate);
    }

    #[test]
    fn new_rejects_empty_lists() {
        let (network, utxos, recipients, fee_rate) = typed();

        let no_utxos = SpendRequest::new(network, vec![], recipients.clone(), None, fee_rate);
        let no_recipients = SpendRequest::new(network, utxos, vec![], None, fee_rate);

        assert!(matches!(no_utxos, Err(Error::NoUtxos)));
        assert!(matches!(no_recipients, Err(Error::NoRecipients)));
    }

    #[test]
    fn new_rejects_a_coin_listed_twice() {
        let (network, mut utxos, recipients, fee_rate) = typed();
        utxos.push(utxos[0].clone());

        let result = SpendRequest::new(network, utxos, recipients, None, fee_rate);

        assert!(matches!(result, Err(Error::DuplicateUtxo(_))));
    }

    #[test]
    fn new_rejects_addresses_from_another_network() {
        let (network, utxos, mut recipients, fee_rate) = typed();

        let bad_change = SpendRequest::new(
            network,
            utxos.clone(),
            recipients.clone(),
            Some(mainnet_address()),
            fee_rate,
        );
        recipients[0].address = mainnet_address();
        let bad_recipient = SpendRequest::new(network, utxos, recipients, None, fee_rate);

        assert!(matches!(bad_change, Err(Error::InvalidAddress { .. })));
        assert!(matches!(bad_recipient, Err(Error::InvalidAddress { .. })));
    }

    #[test]
    fn new_rejects_zero_fee_rate() {
        let (network, utxos, recipients, _) = typed();

        let result = SpendRequest::new(network, utxos, recipients, None, FeeRate::ZERO);

        assert!(matches!(result, Err(Error::InvalidFeeRate(0))));
    }

    #[test]
    fn rejects_zero_fee_rate() {
        let mut params = valid();
        params["fee_rate_sat_per_vb"] = json!(0);
        assert!(matches!(parse(params), Err(Error::InvalidFeeRate(0))));
    }
}
