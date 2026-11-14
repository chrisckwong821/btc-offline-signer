//! One test per address type: paying each kind of address must produce
//! exactly the lock script that type defines, in a consensus-valid transaction.
//!
//! Every address below belongs to the secret key with value 1 (see
//! docs/address-derivation.md, where each is derived step by step), so the
//! expected scripts are known independently of this code. Mainnet formats are
//! used because that is how the specifications publish their examples;
//! nothing here is ever broadcast.

use bitcoin::address::AddressType;
use bitcoin::{Address, Amount, Network, Transaction, TxOut};
use serde_json::json;

use btc_offline_signer::builder::build_unsigned;
use btc_offline_signer::key::SigningKey;
use btc_offline_signer::params::SpendRequest;
use btc_offline_signer::signer::sign;

mod common;

const WIF: &str = "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn";
const INPUT_SATS: u64 = 100_000;
const PAYMENT_SATS: u64 = 30_000;
const FEE_RATE: u64 = 2;

/// Signs a payment to `address` and returns the transaction together with the
/// output it spends.
fn pay(address: &str) -> (Transaction, TxOut) {
    let key = SigningKey::from_wif(WIF, Network::Bitcoin).unwrap();
    let params = json!({
        "network": "mainnet",
        "utxos": [{ "txid": "aa".repeat(32), "vout": 0, "amount_sat": INPUT_SATS }],
        "recipients": [{ "address": address, "amount_sat": PAYMENT_SATS }],
        "fee_rate_sat_per_vb": FEE_RATE
    });
    let request = SpendRequest::from_json(&params.to_string()).unwrap();

    let unsigned = build_unsigned(&request, key.owner()).unwrap();
    let spent = unsigned.prevouts()[0].clone();
    (sign(unsigned, &key).unwrap(), spent)
}

/// Checks everything that should hold whichever address type is paid.
fn assert_pays(address: &str, expected_type: AddressType, expected_script_hex: &str) {
    let parsed = address.parse::<Address<_>>().unwrap().assume_checked();
    assert_eq!(parsed.address_type(), Some(expected_type));

    let (tx, spent) = pay(address);
    let payment = &tx.output[0];

    // The recipient gets the exact amount, locked by the script their address encodes.
    assert_eq!(payment.value, Amount::from_sat(PAYMENT_SATS));
    assert_eq!(payment.script_pubkey.to_hex_string(), expected_script_hex);

    // The fee accounts for this output type's size: the rate asked for is met.
    let paid_out: Amount = tx.output.iter().map(|output| output.value).sum();
    let fee = Amount::from_sat(INPUT_SATS) - paid_out;
    assert!(fee.to_sat() >= FEE_RATE * tx.vsize() as u64);

    // Bitcoin Core's script interpreter accepts the transaction.
    common::consensus_verify(&tx, &[spent]).expect("transaction should be consensus-valid");
}

#[test]
fn pays_p2pkh_legacy_address() {
    assert_pays(
        "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH",
        AddressType::P2pkh,
        "76a914751e76e8199196d454941c45d1b3a323f1433bd688ac",
    );
}

#[test]
fn pays_p2sh_script_hash_address() {
    assert_pays(
        "3JvL6Ymt8MVWiCNHC7oWU6nLeHNJKLZGLN",
        AddressType::P2sh,
        "a914bcfeb728b584253d5f3f70bcb780e9ef218a68f487",
    );
}

#[test]
fn pays_p2wpkh_native_segwit_address() {
    assert_pays(
        "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
        AddressType::P2wpkh,
        "0014751e76e8199196d454941c45d1b3a323f1433bd6",
    );
}

#[test]
fn pays_p2wsh_witness_script_hash_address() {
    assert_pays(
        "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3",
        AddressType::P2wsh,
        "00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262",
    );
}

#[test]
fn pays_p2tr_taproot_address() {
    assert_pays(
        "bc1pmfr3p9j00pfxjh0zmgp99y8zftmd3s5pmedqhyptwy6lm87hf5sspknck9",
        AddressType::P2tr,
        "5120da4710964f7852695de2da025290e24af6d8c281de5a0b902b7135fd9fd74d21",
    );
}
