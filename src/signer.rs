//! Signs an [`UnsignedTx`] with a [`SigningKey`].
//!
//! This module is pure cryptography: it changes nothing about the transaction
//! except filling in each input's unlocking data (scriptSig and witness).
//!
//! | Kind          | What is hashed  | Signature | Where it goes                  |
//! |---------------|-----------------|-----------|--------------------------------|
//! | `p2pkh`       | legacy digest   | ECDSA     | scriptSig                      |
//! | `p2sh` | BIP143 digest   | ECDSA     | witness, plus a small scriptSig |
//! | `p2wpkh`      | BIP143 digest   | ECDSA     | witness                        |
//! | `p2tr`        | BIP341 digest   | Schnorr   | witness                        |

use bitcoin::script::PushBytesBuf;
use bitcoin::secp256k1::{All, Keypair, Message, Secp256k1};
use bitcoin::sighash::{EcdsaSighashType, Prevouts, SighashCache, TapSighashType};
use bitcoin::taproot;
use bitcoin::{ecdsa, key::TapTweak, ScriptBuf, Transaction, TxOut, Witness};

use crate::builder::UnsignedTx;
use crate::key::SigningKey;
use crate::{Error, InputKind};

/// Every ECDSA signature commits to all inputs and all outputs.
const ECDSA_SIGHASH: EcdsaSighashType = EcdsaSighashType::All;

/// Signs every input and returns the transaction ready for broadcast.
///
/// Takes `unsigned` by value: once signed, the unsigned form has no further use.
///
/// For each input this does the same three things: compute a digest (a
/// 32-byte fingerprint of the transaction), sign the digest with the key, and
/// put the signature where that kind of input expects it.
pub fn sign(unsigned: UnsignedTx, key: &SigningKey) -> Result<Transaction, Error> {
    // Take the pieces out of `unsigned`; `..` ignores the ones not needed.
    let UnsignedTx {
        mut tx,
        prevouts,
        input_kinds,
        owner,
        ..
    } = unsigned;

    // Safety check: `key` must be the key this transaction was built for.
    // Any other key's signatures would not open the coins being spent.
    if owner.public_key() != key.owner().public_key() {
        return Err(Error::KeyMismatch);
    }

    // Every signature is made over the same unsigned transaction, so all of
    // them are computed first and only then written into it.
    let mut signer = InputSigner {
        // The elliptic-curve engine that does the signing maths.
        secp: Secp256k1::new(),
        key,
        cache: SighashCache::new(&tx),
        prevouts: &prevouts,
    };
    let unlocks = input_kinds
        .iter()
        .enumerate()
        .map(|(index, kind)| signer.unlock(index, *kind))
        .collect::<Result<Vec<_>, Error>>()?;

    // `zip` pairs each input with the unlocking data computed for it.
    for (input, unlock) in tx.input.iter_mut().zip(unlocks) {
        input.script_sig = unlock.script_sig;
        input.witness = unlock.witness;
    }
    Ok(tx)
}

/// The data that proves an input may be spent. Depending on the kind of
/// input, the proof goes in one field, the other, or both.
struct Unlock {
    /// The original place for signatures, inside the input itself.
    script_sig: ScriptBuf,
    /// The SegWit place for signatures, stored apart from the input.
    witness: Witness,
}

/// What signing one input needs, bundled so each kind gets a short function.
struct InputSigner<'a> {
    secp: Secp256k1<All>,
    key: &'a SigningKey,
    /// Reuses the parts of the digests that are the same for every input.
    cache: SighashCache<&'a Transaction>,
    /// The outputs being spent, in input order.
    prevouts: &'a [TxOut],
}

impl InputSigner<'_> {
    /// Produces the proof for input number `index`, choosing the method that
    /// matches how its coin is locked.
    fn unlock(&mut self, index: usize, kind: InputKind) -> Result<Unlock, Error> {
        match kind {
            InputKind::P2pkh => self.p2pkh(index),
            InputKind::P2shP2wpkh => self.p2sh_p2wpkh(index),
            InputKind::P2wpkh => self.p2wpkh(index),
            InputKind::P2tr => self.p2tr(index),
        }
    }

    /// Legacy: `<signature> <public key>` in the scriptSig, no witness.
    fn p2pkh(&mut self, index: usize) -> Result<Unlock, Error> {
        let sighash = self
            .cache
            .legacy_signature_hash(
                index,
                &self.prevouts[index].script_pubkey,
                ECDSA_SIGHASH.to_u32(),
            )
            .map_err(|e| sighash_error(index, e))?;
        let signature = self.ecdsa(sighash.into());

        let mut script_sig = ScriptBuf::new();
        script_sig.push_slice(signature.serialize());
        script_sig.push_slice(self.key.owner().public_key().to_bytes());
        Ok(Unlock {
            script_sig,
            witness: Witness::new(),
        })
    }

    /// Native SegWit: `[signature, public key]` in the witness, empty scriptSig.
    fn p2wpkh(&mut self, index: usize) -> Result<Unlock, Error> {
        Ok(Unlock {
            script_sig: ScriptBuf::new(),
            witness: self.p2wpkh_witness(index)?,
        })
    }

    /// Nested SegWit: the same witness as P2WPKH, plus a scriptSig revealing
    /// the P2WPKH script whose hash the P2SH output commits to.
    fn p2sh_p2wpkh(&mut self, index: usize) -> Result<Unlock, Error> {
        let redeem_script = self.key.owner().script_pubkey(InputKind::P2wpkh);
        let push = PushBytesBuf::try_from(redeem_script.into_bytes())
            .expect("a 22-byte script is small enough to push");

        let mut script_sig = ScriptBuf::new();
        script_sig.push_slice(push);
        Ok(Unlock {
            script_sig,
            witness: self.p2wpkh_witness(index)?,
        })
    }

    /// Taproot key path: one Schnorr signature in the witness.
    fn p2tr(&mut self, index: usize) -> Result<Unlock, Error> {
        // Unlike the older digests, this one covers the script and amount of
        // every input, not just the one being signed.
        let sighash_type = TapSighashType::Default;
        let sighash = self
            .cache
            .taproot_key_spend_signature_hash(index, &Prevouts::All(self.prevouts), sighash_type)
            .map_err(|e| sighash_error(index, e))?;

        // The output is locked to the tweaked key, so that is what must sign.
        let keypair = Keypair::from_secret_key(&self.secp, self.key.secret_key())
            .tap_tweak(&self.secp, None)
            .to_keypair();
        // No extra randomness: the same input always gives the same signature,
        // which keeps the output reproducible and testable.
        let signature = self
            .secp
            .sign_schnorr_no_aux_rand(&Message::from(sighash), &keypair);

        Ok(Unlock {
            script_sig: ScriptBuf::new(),
            witness: Witness::p2tr_key_spend(&taproot::Signature {
                signature,
                sighash_type,
            }),
        })
    }

    /// The BIP143 signature and public key shared by both P2WPKH forms.
    fn p2wpkh_witness(&mut self, index: usize) -> Result<Witness, Error> {
        // The digest is always over the key's P2WPKH script, even when that
        // script is hidden behind a P2SH hash.
        let script = self.key.owner().script_pubkey(InputKind::P2wpkh);
        let sighash = self
            .cache
            .p2wpkh_signature_hash(index, &script, self.prevouts[index].value, ECDSA_SIGHASH)
            .map_err(|e| sighash_error(index, e))?;

        let signature = self.ecdsa(sighash.into());
        Ok(Witness::p2wpkh(
            &signature,
            &self.key.owner().public_key().0,
        ))
    }

    /// Deterministic (RFC 6979) ECDSA signature over `digest`.
    fn ecdsa(&self, digest: Message) -> ecdsa::Signature {
        ecdsa::Signature {
            signature: self.secp.sign_ecdsa(&digest, self.key.secret_key()),
            sighash_type: ECDSA_SIGHASH,
        }
    }
}

/// Wraps any of the library's digest errors in our own error type, keeping
/// the number of the input that failed.
fn sighash_error(index: usize, error: impl std::fmt::Display) -> Error {
    Error::Sighash {
        index,
        reason: error.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builder::build_unsigned;
    use crate::params::SpendRequest;
    use crate::test_support::consensus_verify;
    use bitcoin::consensus::encode::serialize_hex;
    use bitcoin::{Amount, Network, PrivateKey};
    use serde_json::json;

    const NETWORK: Network = Network::Testnet4;

    fn key(seed: u8) -> SigningKey {
        let wif = PrivateKey::from_slice(&[seed; 32], NETWORK)
            .unwrap()
            .to_wif();
        SigningKey::from_wif(&wif, NETWORK).unwrap()
    }

    /// Two inputs owned by `key(1)`, one payment to `key(2)`, change to `key(1)`.
    fn unsigned() -> UnsignedTx {
        let request = SpendRequest::from_json(
            &json!({
                "network": "testnet4",
                "utxos": [
                    { "txid": "aa".repeat(32), "vout": 0, "amount_sat": 60_000 },
                    { "txid": "bb".repeat(32), "vout": 3, "amount_sat": 40_000 }
                ],
                "recipients": [
                    { "address": key(2).owner().address(InputKind::P2wpkh).to_string(), "amount_sat": 30_000 }
                ],
                "fee_rate_sat_per_vb": 2
            })
            .to_string(),
        )
        .unwrap();
        build_unsigned(&request, key(1).owner()).unwrap()
    }

    /// One 50,000-sat input of each given kind owned by `key(1)`, and one
    /// payment to `key(2)`.
    fn unsigned_spending(kinds: &[InputKind]) -> UnsignedTx {
        let utxos: Vec<_> = kinds
            .iter()
            .enumerate()
            .map(|(i, kind)| {
                json!({
                    "txid": format!("{:02x}", 0xa0 + i).repeat(32),
                    "vout": i,
                    "amount_sat": 50_000,
                    "type": kind.name()
                })
            })
            .collect();
        let request = SpendRequest::from_json(
            &json!({
                "network": "testnet4",
                "utxos": utxos,
                "recipients": [{
                    "address": key(2).owner().address(InputKind::P2wpkh).to_string(),
                    "amount_sat": 30_000
                }],
                "fee_rate_sat_per_vb": 2
            })
            .to_string(),
        )
        .unwrap();
        build_unsigned(&request, key(1).owner()).unwrap()
    }

    /// Splits a script made only of data pushes into the pushed items.
    fn pushes(script: &ScriptBuf) -> Vec<Vec<u8>> {
        script
            .instructions()
            .map(|instruction| {
                instruction
                    .unwrap()
                    .push_bytes()
                    .unwrap()
                    .as_bytes()
                    .to_vec()
            })
            .collect()
    }

    #[test]
    fn p2wpkh_input_is_unlocked_by_a_signature_and_public_key_witness() {
        let signer = key(1);

        let tx = sign(unsigned(), &signer).unwrap();

        assert_eq!(tx.input.len(), 2);
        for input in &tx.input {
            let witness: Vec<&[u8]> = input.witness.iter().collect();
            assert_eq!(witness.len(), 2);
            let (signature, public_key) = (witness[0], witness[1]);
            assert_eq!(signature.last(), Some(&(EcdsaSighashType::All as u8)));
            assert_eq!(public_key, signer.owner().public_key().to_bytes());
            assert!(input.script_sig.is_empty());
        }
    }

    #[test]
    fn p2pkh_input_is_unlocked_by_its_script_sig() {
        let signer = key(1);

        let tx = sign(unsigned_spending(&[InputKind::P2pkh]), &signer).unwrap();

        let items = pushes(&tx.input[0].script_sig);
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].last(), Some(&(EcdsaSighashType::All as u8)));
        assert_eq!(items[1], signer.owner().public_key().to_bytes());
        assert!(tx.input[0].witness.is_empty());
    }

    #[test]
    fn transaction_with_only_legacy_inputs_has_no_witness_section() {
        let tx = sign(unsigned_spending(&[InputKind::P2pkh]), &key(1)).unwrap();

        // Version, then the input count straight away: no SegWit marker and flag.
        assert!(serialize_hex(&tx).starts_with("0200000001"));
        assert_eq!(tx.weight().to_wu(), 4 * tx.total_size() as u64);
    }

    #[test]
    fn nested_segwit_input_reveals_its_p2wpkh_script_and_signs_in_the_witness() {
        let signer = key(1);

        let tx = sign(unsigned_spending(&[InputKind::P2shP2wpkh]), &signer).unwrap();

        let p2wpkh_script = signer.owner().script_pubkey(InputKind::P2wpkh);
        assert_eq!(
            pushes(&tx.input[0].script_sig),
            [p2wpkh_script.into_bytes()]
        );
        let witness: Vec<&[u8]> = tx.input[0].witness.iter().collect();
        assert_eq!(witness.len(), 2);
        assert_eq!(witness[0].last(), Some(&(EcdsaSighashType::All as u8)));
        assert_eq!(witness[1], signer.owner().public_key().to_bytes());
    }

    #[test]
    fn taproot_input_is_unlocked_by_a_single_schnorr_signature() {
        let tx = sign(unsigned_spending(&[InputKind::P2tr]), &key(1)).unwrap();

        let witness: Vec<&[u8]> = tx.input[0].witness.iter().collect();
        assert_eq!(witness.len(), 1);
        assert_eq!(witness[0].len(), 64); // no sighash byte: the default type
        assert!(tx.input[0].script_sig.is_empty());
    }

    #[test]
    fn every_kind_of_input_passes_bitcoin_core_script_verification() {
        for kind in InputKind::ALL {
            let unsigned = unsigned_spending(&[kind]);
            let prevouts = unsigned.prevouts().to_vec();

            let tx = sign(unsigned, &key(1)).unwrap();

            consensus_verify(&tx, &prevouts).unwrap_or_else(|e| panic!("{kind}: {e}"));
        }
    }

    #[test]
    fn inputs_of_different_kinds_can_be_spent_together() {
        let unsigned = unsigned_spending(&InputKind::ALL);
        let prevouts = unsigned.prevouts().to_vec();

        let tx = sign(unsigned, &key(1)).unwrap();

        assert_eq!(tx.input.len(), 4);
        consensus_verify(&tx, &prevouts).unwrap();
    }

    #[test]
    fn changing_an_output_invalidates_every_kind_of_signature() {
        for kind in InputKind::ALL {
            let unsigned = unsigned_spending(&[kind]);
            let prevouts = unsigned.prevouts().to_vec();
            let mut tx = sign(unsigned, &key(1)).unwrap();

            tx.output[0].value += Amount::from_sat(1);

            assert!(consensus_verify(&tx, &prevouts).is_err(), "{kind}");
        }
    }

    #[test]
    fn segwit_and_taproot_signatures_commit_to_the_input_amount() {
        for kind in [InputKind::P2shP2wpkh, InputKind::P2wpkh, InputKind::P2tr] {
            let mut unsigned = unsigned_spending(&[kind]);
            let real_prevouts = unsigned.prevouts().to_vec();
            unsigned.prevouts[0].value -= Amount::from_sat(1);

            let tx = sign(unsigned, &key(1)).unwrap();

            assert!(consensus_verify(&tx, &real_prevouts).is_err(), "{kind}");
        }
    }

    #[test]
    fn legacy_signature_does_not_commit_to_the_input_amount() {
        // The weakness BIP143 fixed: a legacy signature stays valid whatever
        // the signer was told the input is worth.
        let mut unsigned = unsigned_spending(&[InputKind::P2pkh]);
        let real_prevouts = unsigned.prevouts().to_vec();
        unsigned.prevouts[0].value -= Amount::from_sat(1);

        let tx = sign(unsigned, &key(1)).unwrap();

        consensus_verify(&tx, &real_prevouts).unwrap();
    }

    #[test]
    fn taproot_signature_commits_to_the_amounts_of_the_other_inputs_too() {
        let mut unsigned = unsigned_spending(&[InputKind::P2tr, InputKind::P2pkh]);
        let real_prevouts = unsigned.prevouts().to_vec();
        unsigned.prevouts[1].value -= Amount::from_sat(1);

        let tx = sign(unsigned, &key(1)).unwrap();

        let error = consensus_verify(&tx, &real_prevouts).unwrap_err();
        assert!(error.starts_with("input 0 "), "{error}");
    }

    #[test]
    fn signing_changes_nothing_but_the_unlocking_data_for_every_kind() {
        let unsigned = unsigned_spending(&InputKind::ALL);
        let before = unsigned.tx().clone();

        let mut tx = sign(unsigned, &key(1)).unwrap();

        for input in &mut tx.input {
            input.script_sig = ScriptBuf::new();
            input.witness.clear();
        }
        assert_eq!(tx, before);
    }

    #[test]
    fn accepts_the_same_key_loaded_for_another_test_network() {
        // Testnet and testnet4 share key and address formats, and a lock
        // script carries no network, so this is the same key and must sign.
        let unsigned = unsigned_spending(&InputKind::ALL);
        let prevouts = unsigned.prevouts().to_vec();
        let same_key = SigningKey::from_wif(&key(1).to_wif(), Network::Testnet).unwrap();

        let tx = sign(unsigned, &same_key).unwrap();

        consensus_verify(&tx, &prevouts).unwrap();
    }

    #[test]
    fn rejects_a_key_other_than_the_one_the_transaction_was_built_for() {
        let err = sign(unsigned_spending(&InputKind::ALL), &key(9)).unwrap_err();

        assert!(matches!(err, Error::KeyMismatch));
    }

    #[test]
    fn signed_size_never_exceeds_the_predicted_size_for_any_kind() {
        let all = InputKind::ALL;
        for kinds in [&all[0..1], &all[1..2], &all[2..3], &all[3..4], &all[..]] {
            let unsigned = unsigned_spending(kinds);
            let fee = unsigned.fee();

            let tx = sign(unsigned, &key(1)).unwrap();

            assert!(fee.to_sat() >= 2 * tx.vsize() as u64, "{kinds:?}");
        }
    }

    #[test]
    fn signing_is_deterministic_for_every_kind() {
        let first = sign(unsigned_spending(&InputKind::ALL), &key(1)).unwrap();
        let second = sign(unsigned_spending(&InputKind::ALL), &key(1)).unwrap();

        assert_eq!(serialize_hex(&first), serialize_hex(&second));
    }

    #[test]
    fn matches_known_transaction() {
        // Snapshot of the fixture signed by this implementation, accepted by
        // libbitcoinconsensus above. Fails if serialization, sighash or
        // fee/change behaviour changes unintentionally.
        let tx = sign(unsigned(), &key(1)).unwrap();

        let expected = concat!(
            "02000000000102aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa00",
            "00000000fdffffffbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "0300000000fdffffff023075000000000000160014ebc0ee0b2ab9e8277a600c251475e22a3241a1",
            "c1ce0f01000000000016001479b000887626b294a914501a4cd226b58b2359830247304402201b2c",
            "9c40b6ba6f66e9263ff399a1a0d9bce38dd9b6d3d2cdc35a2eb4b1e9ecfd022023e3c143a6304345",
            "1d312651a350cf95b6911cc17f2b604b91d235dd130de8280121031b84c5567b126440995d3ed5aa",
            "ba0565d71e1834604819ff9c17f5e9d5dd078f0247304402204c25252ae0e9464b1612f3b35ddd31",
            "935d64cf03db700625682ae096723feec702201b002296255486887209c1cfc77ee29c844e5d0035",
            "281a81ac79153b11b893e40121031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17",
            "f5e9d5dd078f00000000",
        );
        assert_eq!(serialize_hex(&tx), expected);
    }

    #[test]
    fn matches_known_transaction_with_every_kind_of_input() {
        // Snapshot of a legacy, a nested SegWit, a native SegWit and a Taproot
        // input signed together, accepted by libbitcoinconsensus above.
        let tx = sign(unsigned_spending(&InputKind::ALL), &key(1)).unwrap();

        let expected = concat!(
            "02000000000104a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a000",
            "0000006b483045022100a3429e575cd8cb22f4d35928edebdbbb18557d47e1d2fe31f01faabc3b6b",
            "fb09022004c184b032f66938986f80ffb428788a07685ba33d5516b3a5e31fcf798c3dc60121031b",
            "84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078ffdffffffa1a1a1a1a1",
            "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1010000001716001479b0008876",
            "26b294a914501a4cd226b58b235983fdffffffa2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2",
            "a2a2a2a2a2a2a2a2a2a2a20200000000fdffffffa3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3",
            "a3a3a3a3a3a3a3a3a3a3a3a30300000000fdffffff023075000000000000160014ebc0ee0b2ab9e8",
            "277a600c251475e22a3241a1c19e940200000000001976a91479b000887626b294a914501a4cd226",
            "b58b23598388ac0002483045022100b419940d0de6eeb611453477070ab9d85af3f5ef2851e81486",
            "2e637cc3c0991402203c97a29e28aa10334bd75191ad13e206cd16c7743c6f53b6f9da9c69646e4d",
            "110121031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f02473044",
            "022003e844a32b453b24372f77906ca0743a9c9d8aaad48b084dff6bbba4b308236c02207dd925f3",
            "993d9488b9db15961fae41bbf69e3578fab94190f514f3ddc517ab5d0121031b84c5567b12644099",
            "5d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f01403f74fc39eb3a892b8b39ac2b9f95ad",
            "446d70af67fb2bf9073e49cfc75ee4b205b510675268dbd106ad4a8ecf6c2449e843ae7b1e7c9ae7",
            "116a444d423feaa00100000000",
        );
        assert_eq!(serialize_hex(&tx), expected);
    }
}
