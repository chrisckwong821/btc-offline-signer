//! Turns a [`SpendRequest`] into an unsigned transaction.
//!
//! This module is pure arithmetic and policy: it decides the outputs, the fee
//! and the change. It never touches a private key.
//!
//! The one rule everything here follows:
//!
//! ```text
//! money in (the UTXOs) = payments + change + fee
//! ```
//!
//! The payments are given, the fee is worked out from the transaction's size,
//! and the change is whatever is left.

use bitcoin::absolute::LockTime;
use bitcoin::transaction::{predict_weight, InputWeightPrediction, Version};
use bitcoin::{Amount, FeeRate, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};

use crate::key::Owner;
use crate::params::SpendRequest;
use crate::{Error, InputKind};

/// A transaction that is complete except for its signatures.
///
/// Fields are only writable inside this crate, so an `UnsignedTx` obtained
/// from [`build_unsigned`] always has exactly one prevout and one kind per
/// input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsignedTx {
    /// The transaction itself, with empty scriptSigs and witnesses.
    pub(crate) tx: Transaction,
    /// The output each input spends ("previous output"), in input order.
    pub(crate) prevouts: Vec<TxOut>,
    /// How each of those outputs is locked, in input order.
    pub(crate) input_kinds: Vec<InputKind>,
    /// Whose coins these are. Only this owner's key can sign the transaction.
    pub(crate) owner: Owner,
    /// What the miner receives: money in minus money out.
    pub(crate) fee: Amount,
    /// Whether the last output is change rather than a payment.
    pub(crate) has_change: bool,
}

/// Read-only views. Nothing outside this crate can change an `UnsignedTx`.
impl UnsignedTx {
    /// The transaction, still without signatures.
    pub fn tx(&self) -> &Transaction {
        &self.tx
    }

    /// The outputs being spent, in the same order as the transaction's inputs.
    /// Signing needs their scripts and amounts.
    pub fn prevouts(&self) -> &[TxOut] {
        &self.prevouts
    }

    /// How each input's prevout is locked, in the same order as the inputs.
    pub fn input_kinds(&self) -> &[InputKind] {
        &self.input_kinds
    }

    /// The key holder whose coins the transaction spends.
    pub fn owner(&self) -> &Owner {
        &self.owner
    }

    /// The outputs that pay recipients, in the order they were requested.
    pub fn payments(&self) -> &[TxOut] {
        // Change, when present, is always the last output, so the payments
        // are everything before it. `usize::from(true)` is 1, `false` is 0.
        let payment_count = self.tx.output.len() - usize::from(self.has_change);
        &self.tx.output[..payment_count]
    }

    /// The output returning leftover funds, if there is one.
    pub fn change(&self) -> Option<&TxOut> {
        // "The last output, but only if that output is change."
        self.tx.output.last().filter(|_| self.has_change)
    }

    /// The miner's fee: `sum(prevouts) - sum(outputs)`. A transaction never
    /// states its fee; it is simply the money that no output claims.
    pub fn fee(&self) -> Amount {
        self.fee
    }
}

/// Builds the unsigned transaction for `request`.
///
/// `owner` is the key that holds every UTXO in the request. When the request
/// names no change address, change goes back to the owner, at the same kind of
/// address as the first UTXO came from.
///
/// Fails if a payment is too small to relay (dust) or if the UTXOs cannot
/// cover the payments plus the fee.
pub fn build_unsigned(request: &SpendRequest, owner: &Owner) -> Result<UnsignedTx, Error> {
    let first_utxo = request.utxos.first().ok_or(Error::NoUtxos)?;
    let input_kinds: Vec<InputKind> = request.utxos.iter().map(|utxo| utxo.kind).collect();

    // Step 1: one output per recipient, and decide where change would go.
    let mut outputs = recipient_outputs(request)?;
    let change_script = match &request.change_address {
        Some(address) => address.script_pubkey(),
        None => owner.script_pubkey(first_utxo.kind),
    };

    // Step 2: add up the money coming in and the money being paid out.
    let available = sum(request.utxos.iter().map(|utxo| utxo.amount))?;
    let spent = sum(outputs.iter().map(|output| output.value))?;

    // Step 3: check the UTXOs can afford it. Without a change output this is
    // the least the transaction can cost.
    let recipient_scripts = || outputs.iter().map(|output| &output.script_pubkey);
    let fee_without_change = fee_for(request.fee_rate, &input_kinds, recipient_scripts())?;
    let required = spent
        .checked_add(fee_without_change)
        .ok_or(Error::AmountOverflow)?;
    if available < required {
        return Err(Error::InsufficientFunds {
            available,
            required,
        });
    }

    // Step 4: work out the change. A change output makes the transaction
    // bigger, so the fee is recalculated with it included. Change is only
    // created if what is left after that larger fee is not dust; `change` is
    // `None` when the leftover is too small (or would be negative).
    let fee_with_change = fee_for(
        request.fee_rate,
        &input_kinds,
        recipient_scripts().chain([&change_script]),
    )?;
    let leftover = available.checked_sub(spent).ok_or(Error::AmountOverflow)?;
    let change = leftover
        .checked_sub(fee_with_change)
        .filter(|change| *change >= change_script.minimal_non_dust());

    // Step 5: settle the final fee, adding the change output if there is one.
    let fee = match change {
        Some(value) => {
            outputs.push(TxOut {
                value,
                script_pubkey: change_script,
            });
            fee_with_change
        }
        // Too small to be worth an output: the whole leftover goes to the miner.
        None => leftover,
    };

    // Step 6: describe the outputs being spent. The signer needs each one's
    // lock script and amount, and they are not part of the transaction itself.
    let prevouts = request
        .utxos
        .iter()
        .map(|utxo| TxOut {
            value: utxo.amount,
            script_pubkey: owner.script_pubkey(utxo.kind),
        })
        .collect();

    // Step 7: assemble the transaction, with every input still unsigned.
    let tx = Transaction {
        // Version 2 is the current standard.
        version: Version::TWO,
        // No lock time: the transaction may be mined straight away.
        lock_time: LockTime::ZERO,
        input: request
            .utxos
            .iter()
            .map(|utxo| unsigned_input(utxo.outpoint))
            .collect(),
        output: outputs,
    };

    Ok(UnsignedTx {
        tx,
        prevouts,
        input_kinds,
        owner: owner.clone(),
        fee,
        has_change: change.is_some(),
    })
}

/// One output per recipient, in the order given. Rejects dust amounts, which
/// nodes would refuse to relay.
///
/// "Dust" is an output worth less than it would cost in fees to spend later.
/// The limit depends on the kind of address, so the library is asked for it.
fn recipient_outputs(request: &SpendRequest) -> Result<Vec<TxOut>, Error> {
    request
        .recipients
        .iter()
        .map(|recipient| {
            let script_pubkey = recipient.address.script_pubkey();
            let minimum = script_pubkey.minimal_non_dust();
            if recipient.amount < minimum {
                return Err(Error::DustOutput {
                    address: recipient.address.to_string(),
                    amount: recipient.amount,
                    minimum,
                });
            }
            Ok(TxOut {
                value: recipient.amount,
                script_pubkey,
            })
        })
        .collect()
}

/// An input that points at the coin to spend (`previous_output`) but carries
/// no proof of ownership yet.
fn unsigned_input(previous_output: OutPoint) -> TxIn {
    TxIn {
        previous_output,
        // The signer fills in the scriptSig and witness.
        script_sig: ScriptBuf::new(),
        // Opt in to Replace-By-Fee so a stuck transaction can be fee-bumped.
        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
        witness: Witness::new(),
    }
}

/// The most room an input of each kind can take up once signed: the size of
/// its scriptSig and of each item in its witness.
fn signed_input_size(kind: InputKind) -> InputWeightPrediction {
    /// A scriptSig that pushes the 22-byte P2WPKH script the P2SH hash commits to.
    const NESTED_SCRIPT_SIG_LEN: usize = 23;
    /// An ECDSA signature (at most 72 bytes) and a compressed public key.
    const SIGNATURE_AND_KEY: &[usize] = &[72, 33];

    match kind {
        InputKind::P2pkh => InputWeightPrediction::P2PKH_COMPRESSED_MAX,
        InputKind::P2shP2wpkh => {
            InputWeightPrediction::from_slice(NESTED_SCRIPT_SIG_LEN, SIGNATURE_AND_KEY)
        }
        InputKind::P2wpkh => InputWeightPrediction::P2WPKH_MAX,
        InputKind::P2tr => InputWeightPrediction::P2TR_KEY_DEFAULT_SIGHASH,
    }
}

/// The fee for a transaction with one input per kind and one output per
/// script, based on the size it will have once signed.
///
/// `fee = fee rate (sat per virtual byte) x size (virtual bytes)`. The size
/// has to be predicted because the signatures do not exist yet, and adding
/// them later cannot change the fee: the fee is fixed by the output amounts,
/// which the signatures cover.
fn fee_for<'a>(
    fee_rate: FeeRate,
    input_kinds: &[InputKind],
    output_scripts: impl Iterator<Item = &'a ScriptBuf>,
) -> Result<Amount, Error> {
    let inputs = input_kinds.iter().copied().map(signed_input_size);
    let weight = predict_weight(inputs, output_scripts.map(|script| script.len()));

    // Nodes measure size in whole virtual bytes, rounding up, so the fee must
    // too; otherwise the rate actually paid could fall just short of the one
    // requested.
    fee_rate
        .fee_vb(weight.to_vbytes_ceil())
        .ok_or(Error::AmountOverflow)
}

/// Adds up amounts, returning an error instead of wrapping around if the
/// total is too large for a 64-bit number.
fn sum(mut amounts: impl Iterator<Item = Amount>) -> Result<Amount, Error> {
    amounts
        .try_fold(Amount::ZERO, |total, amount| total.checked_add(amount))
        .ok_or(Error::AmountOverflow)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::{Recipient, Utxo};
    use bitcoin::secp256k1::Secp256k1;
    use bitcoin::{Address, CompressedPublicKey, Network, PrivateKey, Txid};

    const NETWORK: Network = Network::Testnet4;

    // Predicted sizes for P2WPKH-only transactions.
    // Nodes round the size up to whole virtual bytes, and so does the fee.
    //   1 input, 1 output  -> 438 WU = 109.5 vB -> 110 vB
    //   1 input, 2 outputs -> 562 WU = 140.5 vB -> 141 vB
    const FEE_1_IN_1_OUT_AT_2: u64 = 220;
    const FEE_1_IN_2_OUT_AT_2: u64 = 282;
    const P2WPKH_DUST: u64 = 294;

    /// A deterministic key holder; different `seed`s give different keys.
    fn holder(seed: u8) -> Owner {
        let key = PrivateKey::from_slice(&[seed; 32], NETWORK).unwrap();
        let public = CompressedPublicKey::from_private_key(&Secp256k1::new(), &key).unwrap();
        Owner::new(public, NETWORK)
    }

    /// A deterministic P2WPKH address.
    fn address(seed: u8) -> Address {
        holder(seed).address(InputKind::P2wpkh)
    }

    fn owner() -> Owner {
        holder(1)
    }

    fn utxo(seed: u8, sats: u64) -> Utxo {
        utxo_of(InputKind::P2wpkh, seed, sats)
    }

    fn utxo_of(kind: InputKind, seed: u8, sats: u64) -> Utxo {
        let txid: Txid = format!("{seed:02x}").repeat(32).parse().unwrap();
        Utxo {
            outpoint: OutPoint::new(txid, 0),
            amount: Amount::from_sat(sats),
            kind,
        }
    }

    fn recipient(seed: u8, sats: u64) -> Recipient {
        Recipient {
            address: address(seed),
            amount: Amount::from_sat(sats),
        }
    }

    fn request(utxos: Vec<Utxo>, recipients: Vec<Recipient>) -> SpendRequest {
        SpendRequest {
            network: NETWORK,
            utxos,
            recipients,
            change_address: None,
            fee_rate: FeeRate::from_sat_per_vb(2).unwrap(),
        }
    }

    fn total_out(unsigned: &UnsignedTx) -> u64 {
        unsigned.tx.output.iter().map(|o| o.value.to_sat()).sum()
    }

    #[test]
    fn pays_recipient_then_returns_change_to_owner() {
        let req = request(vec![utxo(0xaa, 100_000)], vec![recipient(2, 30_000)]);

        let unsigned = build_unsigned(&req, &owner()).unwrap();
        let outputs = &unsigned.tx.output;

        assert_eq!(outputs.len(), 2);
        assert_eq!(outputs[0].value, Amount::from_sat(30_000));
        assert_eq!(outputs[0].script_pubkey, address(2).script_pubkey());
        assert_eq!(
            outputs[1].value,
            Amount::from_sat(100_000 - 30_000 - FEE_1_IN_2_OUT_AT_2)
        );
        assert_eq!(
            outputs[1].script_pubkey,
            owner().script_pubkey(InputKind::P2wpkh)
        );
    }

    #[test]
    fn inputs_equal_outputs_plus_fee() {
        let req = request(vec![utxo(0xaa, 100_000)], vec![recipient(2, 30_000)]);

        let unsigned = build_unsigned(&req, &owner()).unwrap();

        assert_eq!(unsigned.fee, Amount::from_sat(FEE_1_IN_2_OUT_AT_2));
        assert_eq!(total_out(&unsigned) + unsigned.fee.to_sat(), 100_000);
    }

    #[test]
    fn fee_scales_with_fee_rate() {
        let mut req = request(vec![utxo(0xaa, 100_000)], vec![recipient(2, 30_000)]);
        req.fee_rate = FeeRate::from_sat_per_vb(10).unwrap();

        let unsigned = build_unsigned(&req, &owner()).unwrap();

        assert_eq!(unsigned.fee, Amount::from_sat(1410)); // 141 vB * 10
    }

    #[test]
    fn fee_is_based_on_size_rounded_up_to_whole_virtual_bytes() {
        // Nodes measure 562 WU as 141 vB, so at 1 sat/vB they expect 141 sat.
        let mut req = request(vec![utxo(0xaa, 100_000)], vec![recipient(2, 30_000)]);
        req.fee_rate = FeeRate::from_sat_per_vb(1).unwrap();

        let unsigned = build_unsigned(&req, &owner()).unwrap();

        assert_eq!(unsigned.fee, Amount::from_sat(141));
    }

    #[test]
    fn uses_explicit_change_address_when_given() {
        let mut req = request(vec![utxo(0xaa, 100_000)], vec![recipient(2, 30_000)]);
        req.change_address = Some(address(3));

        let unsigned = build_unsigned(&req, &owner()).unwrap();

        assert_eq!(
            unsigned.tx.output[1].script_pubkey,
            address(3).script_pubkey()
        );
    }

    #[test]
    fn inputs_are_unsigned_replaceable_and_match_the_utxos() {
        let utxos = vec![utxo(0xaa, 60_000), utxo(0xbb, 40_000)];
        let req = request(utxos.clone(), vec![recipient(2, 30_000)]);

        let unsigned = build_unsigned(&req, &owner()).unwrap();

        assert_eq!(unsigned.tx.input.len(), 2);
        for (input, utxo) in unsigned.tx.input.iter().zip(&utxos) {
            assert_eq!(input.previous_output, utxo.outpoint);
            assert!(input.script_sig.is_empty());
            assert!(input.witness.is_empty());
            assert!(input.sequence.is_rbf());
        }
    }

    #[test]
    fn prevouts_describe_the_coins_being_spent() {
        let req = request(
            vec![utxo(0xaa, 60_000), utxo(0xbb, 40_000)],
            vec![recipient(2, 30_000)],
        );

        let unsigned = build_unsigned(&req, &owner()).unwrap();

        let expected: Vec<TxOut> = [60_000, 40_000]
            .map(|sats| TxOut {
                value: Amount::from_sat(sats),
                script_pubkey: owner().script_pubkey(InputKind::P2wpkh),
            })
            .to_vec();
        assert_eq!(unsigned.prevouts, expected);
    }

    #[test]
    fn fee_depends_on_the_kind_of_input_being_spent() {
        // One input, a P2WPKH payment, and change back to the input's own kind
        // of address. Sizes in virtual bytes, worked out by hand:
        //   p2pkh        223    (no witness discount at all)
        //   p2sh  164.5 -> 165
        //   p2wpkh       140.5 -> 141
        //   p2tr         142    (smaller signature, larger change output)
        let expected_vsize = [
            (InputKind::P2pkh, 223),
            (InputKind::P2shP2wpkh, 165),
            (InputKind::P2wpkh, 141),
            (InputKind::P2tr, 142),
        ];
        for (kind, vsize) in expected_vsize {
            let req = request(
                vec![utxo_of(kind, 0xaa, 100_000)],
                vec![recipient(2, 30_000)],
            );

            let unsigned = build_unsigned(&req, &owner()).unwrap();

            assert_eq!(unsigned.fee, Amount::from_sat(2 * vsize), "{kind}");
        }
    }

    #[test]
    fn prevouts_and_default_change_use_the_address_of_the_input_kind() {
        for kind in InputKind::ALL {
            let req = request(
                vec![utxo_of(kind, 0xaa, 100_000)],
                vec![recipient(2, 30_000)],
            );

            let unsigned = build_unsigned(&req, &owner()).unwrap();

            let script = owner().script_pubkey(kind);
            assert_eq!(unsigned.prevouts[0].script_pubkey, script);
            assert_eq!(unsigned.change().unwrap().script_pubkey, script);
            assert_eq!(unsigned.input_kinds(), [kind]);
        }
    }

    #[test]
    fn records_the_owner_the_transaction_was_built_for() {
        let req = request(vec![utxo(0xaa, 100_000)], vec![recipient(2, 30_000)]);

        let unsigned = build_unsigned(&req, &owner()).unwrap();

        assert_eq!(unsigned.owner(), &owner());
    }

    #[test]
    fn mixed_inputs_keep_their_own_kind_and_change_follows_the_first() {
        let req = request(
            vec![
                utxo_of(InputKind::P2tr, 0xaa, 60_000),
                utxo_of(InputKind::P2pkh, 0xbb, 40_000),
            ],
            vec![recipient(2, 30_000)],
        );

        let unsigned = build_unsigned(&req, &owner()).unwrap();

        assert_eq!(unsigned.input_kinds(), [InputKind::P2tr, InputKind::P2pkh]);
        assert_eq!(
            unsigned.prevouts[1].script_pubkey,
            owner().script_pubkey(InputKind::P2pkh)
        );
        assert_eq!(
            unsigned.change().unwrap().script_pubkey,
            owner().script_pubkey(InputKind::P2tr)
        );
    }

    #[test]
    fn multiple_inputs_and_recipients_add_up() {
        let req = request(
            vec![utxo(0xaa, 60_000), utxo(0xbb, 40_000)],
            vec![recipient(2, 30_000), recipient(3, 20_000)],
        );

        let unsigned = build_unsigned(&req, &owner()).unwrap();

        // 2 inputs, 3 outputs: 562 + 272 (extra input) + 124 (extra output) WU
        // = 958 WU = 239.5 vB -> 240 vB.
        assert_eq!(unsigned.fee, Amount::from_sat(480));
        assert_eq!(unsigned.tx.output.len(), 3);
        assert_eq!(total_out(&unsigned) + 480, 100_000);
    }

    #[test]
    fn transaction_uses_version_2_and_no_locktime() {
        let req = request(vec![utxo(0xaa, 100_000)], vec![recipient(2, 30_000)]);

        let unsigned = build_unsigned(&req, &owner()).unwrap();

        assert_eq!(unsigned.tx.version, Version::TWO);
        assert_eq!(unsigned.tx.lock_time, LockTime::ZERO);
    }

    #[test]
    fn dust_change_is_dropped_and_becomes_fee() {
        // Change would be 281 + 293 - 281 = 293 sats: one below the dust limit.
        let amount = 100_000 - FEE_1_IN_2_OUT_AT_2 - (P2WPKH_DUST - 1);
        let req = request(vec![utxo(0xaa, 100_000)], vec![recipient(2, amount)]);

        let unsigned = build_unsigned(&req, &owner()).unwrap();

        assert_eq!(unsigned.tx.output.len(), 1);
        assert_eq!(unsigned.fee, Amount::from_sat(100_000 - amount));
    }

    #[test]
    fn change_exactly_at_dust_limit_is_kept() {
        let amount = 100_000 - FEE_1_IN_2_OUT_AT_2 - P2WPKH_DUST;
        let req = request(vec![utxo(0xaa, 100_000)], vec![recipient(2, amount)]);

        let unsigned = build_unsigned(&req, &owner()).unwrap();

        assert_eq!(unsigned.tx.output.len(), 2);
        assert_eq!(unsigned.tx.output[1].value, Amount::from_sat(P2WPKH_DUST));
    }

    #[test]
    fn can_spend_everything_when_inputs_exactly_cover_amount_and_fee() {
        let amount = 100_000 - FEE_1_IN_1_OUT_AT_2;
        let req = request(vec![utxo(0xaa, 100_000)], vec![recipient(2, amount)]);

        let unsigned = build_unsigned(&req, &owner()).unwrap();

        assert_eq!(unsigned.tx.output.len(), 1);
        assert_eq!(unsigned.fee, Amount::from_sat(FEE_1_IN_1_OUT_AT_2));
    }

    #[test]
    fn rejects_when_one_sat_short_of_the_fee() {
        let amount = 100_000 - FEE_1_IN_1_OUT_AT_2 + 1;
        let req = request(vec![utxo(0xaa, 100_000)], vec![recipient(2, amount)]);

        let err = build_unsigned(&req, &owner()).unwrap_err();

        match err {
            Error::InsufficientFunds {
                available,
                required,
            } => {
                assert_eq!(available, Amount::from_sat(100_000));
                assert_eq!(required, Amount::from_sat(100_001));
            }
            other => panic!("expected InsufficientFunds, got {other:?}"),
        }
    }

    #[test]
    fn rejects_dust_recipient_output() {
        let req = request(
            vec![utxo(0xaa, 100_000)],
            vec![recipient(2, P2WPKH_DUST - 1)],
        );

        let err = build_unsigned(&req, &owner()).unwrap_err();

        assert!(matches!(err, Error::DustOutput { .. }));
    }

    #[test]
    fn rejects_amounts_that_overflow() {
        let req = request(
            vec![utxo(0xaa, u64::MAX), utxo(0xbb, 1)],
            vec![recipient(2, 30_000)],
        );

        let err = build_unsigned(&req, &owner()).unwrap_err();

        assert!(matches!(err, Error::AmountOverflow));
    }
}
