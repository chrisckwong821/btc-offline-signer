//! End-to-end tests that run the compiled binary the way a user would.

use std::fs;
use std::path::PathBuf;

use assert_cmd::Command;
use bitcoin::consensus::encode::deserialize_hex;
use bitcoin::{Amount, Transaction, TxOut};
use predicates::prelude::*;
use serde_json::json;
use tempfile::TempDir;

// Secret key 1 on testnet and its P2WPKH address (the BIP173 example address).
const WIF: &str = "cMahea7zqjxrtgAbB7LSGbcQUr1uX1ojuat9jZodMN87JcbXMTcA";
const OWNER_ADDRESS: &str = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx";
// Every address secret key 1 controls on testnet, by the name of its type.
const OWNER_ADDRESSES: [(&str, &str); 4] = [
    ("p2pkh", "mrCDrCybB6J1vRfbwM5hemdJz73FwDBC8r"),
    ("p2sh", "2NAUYAHhujozruyzpsFRP63mbrdaU5wnEpN"),
    ("p2wpkh", OWNER_ADDRESS),
    (
        "p2tr",
        "tb1pmfr3p9j00pfxjh0zmgp99y8zftmd3s5pmedqhyptwy6lm87hf5ssk79hv2",
    ),
];
const RECIPIENT_ADDRESS: &str = "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7";
const KEY_ENV: &str = "BTC_SIGNER_WIF";

mod common;

/// A temp directory holding a params file and a key file.
struct Fixture {
    dir: TempDir,
}

impl Fixture {
    fn new() -> Self {
        let fixture = Self {
            dir: TempDir::new().unwrap(),
        };
        let params = json!({
            "network": "testnet4",
            "utxos": [{ "txid": "aa".repeat(32), "vout": 0, "amount_sat": 100_000 }],
            "recipients": [{ "address": RECIPIENT_ADDRESS, "amount_sat": 30_000 }],
            "fee_rate_sat_per_vb": 2
        });
        fs::write(fixture.params(), params.to_string()).unwrap();
        fs::write(fixture.key(), format!("{WIF}\n")).unwrap();
        fixture
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn params(&self) -> PathBuf {
        self.path("params.json")
    }

    fn key(&self) -> PathBuf {
        self.path("key.wif")
    }
}

/// The binary, with the key variable cleared so the developer's own
/// environment cannot influence a test.
fn signer() -> Command {
    let mut command = Command::cargo_bin("btc-offline-signer").unwrap();
    command.env_remove(KEY_ENV);
    command
}

fn script_of(address: &str) -> bitcoin::ScriptBuf {
    address
        .parse::<bitcoin::Address<_>>()
        .unwrap()
        .assume_checked()
        .script_pubkey()
}

/// Checks that `hex` is the fixture's transaction and that Bitcoin Core's
/// script interpreter accepts it.
fn assert_valid_fixture_transaction(hex: &str) {
    let tx: Transaction = deserialize_hex(hex.trim()).expect("stdout should be a transaction");
    let owner_script = OWNER_ADDRESS
        .parse::<bitcoin::Address<_>>()
        .unwrap()
        .assume_checked()
        .script_pubkey();
    let spent = TxOut {
        value: Amount::from_sat(100_000),
        script_pubkey: owner_script.clone(),
    };

    assert_eq!(tx.output.len(), 2);
    assert_eq!(tx.output[0].value, Amount::from_sat(30_000));
    assert_eq!(tx.output[1].script_pubkey, owner_script);
    common::consensus_verify(&tx, &[spent]).expect("transaction should be consensus-valid");
}

#[test]
fn sign_prints_only_the_transaction_hex_on_stdout() {
    let fixture = Fixture::new();

    let output = signer()
        .arg("sign")
        .arg(fixture.params())
        .arg("--key-file")
        .arg(fixture.key())
        .assert()
        .success()
        .stderr(predicate::str::contains("txid"))
        .get_output()
        .clone();

    let stdout = String::from_utf8(output.stdout).unwrap();
    assert_eq!(stdout.lines().count(), 1);
    assert!(stdout.trim().chars().all(|c| c.is_ascii_hexdigit()));
    assert_valid_fixture_transaction(&stdout);
}

#[test]
fn sign_reads_the_key_from_the_environment() {
    let fixture = Fixture::new();

    let output = signer()
        .arg("sign")
        .arg(fixture.params())
        .env(KEY_ENV, WIF)
        .assert()
        .success()
        .get_output()
        .clone();

    assert_valid_fixture_transaction(&String::from_utf8(output.stdout).unwrap());
}

#[test]
fn sign_can_write_the_transaction_to_a_file() {
    let fixture = Fixture::new();
    let out = fixture.path("signed.hex");

    signer()
        .arg("sign")
        .arg(fixture.params())
        .arg("--key-file")
        .arg(fixture.key())
        .arg("--output")
        .arg(&out)
        .assert()
        .success()
        .stdout(predicate::str::is_empty());

    assert_valid_fixture_transaction(&fs::read_to_string(out).unwrap());
}

#[test]
fn sign_without_a_key_explains_how_to_provide_one() {
    let fixture = Fixture::new();

    signer()
        .arg("sign")
        .arg(fixture.params())
        .assert()
        .failure()
        .stdout(predicate::str::is_empty())
        .stderr(predicate::str::contains("--key-file").and(predicate::str::contains(KEY_ENV)));
}

#[test]
fn sign_reports_a_missing_params_file() {
    let fixture = Fixture::new();

    signer()
        .arg("sign")
        .arg(fixture.path("does-not-exist.json"))
        .arg("--key-file")
        .arg(fixture.key())
        .assert()
        .failure()
        .stdout(predicate::str::is_empty())
        .stderr(predicate::str::contains("does-not-exist.json"));
}

#[test]
fn sign_reports_validation_errors_without_printing_a_transaction() {
    let fixture = Fixture::new();
    let params = json!({
        "network": "testnet4",
        "utxos": [{ "txid": "aa".repeat(32), "vout": 0, "amount_sat": 1_000 }],
        "recipients": [{ "address": RECIPIENT_ADDRESS, "amount_sat": 30_000 }],
        "fee_rate_sat_per_vb": 2
    });
    fs::write(fixture.params(), params.to_string()).unwrap();

    signer()
        .arg("sign")
        .arg(fixture.params())
        .arg("--key-file")
        .arg(fixture.key())
        .assert()
        .failure()
        .stdout(predicate::str::is_empty())
        .stderr(predicate::str::contains("insufficient funds"));
}

#[test]
fn error_messages_never_contain_the_private_key() {
    let fixture = Fixture::new();
    let params = fs::read_to_string(fixture.params())
        .unwrap()
        .replace("testnet4", "mainnet");
    fs::write(fixture.params(), params).unwrap();

    signer()
        .arg("sign")
        .arg(fixture.params())
        .arg("--key-file")
        .arg(fixture.key())
        .assert()
        .failure()
        .stderr(predicate::str::contains(WIF).not());
}

#[test]
fn address_prints_the_address_for_a_key() {
    let fixture = Fixture::new();

    signer()
        .args(["address", "--network", "testnet4", "--key-file"])
        .arg(fixture.key())
        .assert()
        .success()
        .stdout(format!("{OWNER_ADDRESS}\n"));
}

#[test]
fn address_prints_each_type_of_address_for_a_key() {
    let fixture = Fixture::new();

    for (kind, address) in OWNER_ADDRESSES {
        signer()
            .args(["address", "--network", "testnet4", "--type", kind])
            .arg("--key-file")
            .arg(fixture.key())
            .assert()
            .success()
            .stdout(format!("{address}\n"));
    }
}

#[test]
fn address_rejects_an_unknown_type() {
    let fixture = Fixture::new();

    signer()
        .args(["address", "--network", "testnet4", "-t", "p2wsh"])
        .arg("--key-file")
        .arg(fixture.key())
        .assert()
        .failure()
        .stderr(predicate::str::contains("unknown input type"));
}

#[test]
fn sign_spends_inputs_of_every_type_in_one_transaction() {
    let fixture = Fixture::new();
    let utxos: Vec<_> = OWNER_ADDRESSES
        .iter()
        .enumerate()
        .map(|(vout, (kind, _))| {
            json!({ "txid": "aa".repeat(32), "vout": vout, "amount_sat": 50_000, "type": kind })
        })
        .collect();
    let params = json!({
        "network": "testnet4",
        "utxos": utxos,
        "recipients": [{ "address": RECIPIENT_ADDRESS, "amount_sat": 30_000 }],
        "fee_rate_sat_per_vb": 2
    });
    fs::write(fixture.params(), params.to_string()).unwrap();

    let output = signer()
        .arg("sign")
        .arg(fixture.params())
        .arg("--key-file")
        .arg(fixture.key())
        .assert()
        .success()
        .stderr(predicate::str::contains(
            "spending:     200000 sat from 4 inputs",
        ))
        .get_output()
        .clone();

    let hex = String::from_utf8(output.stdout).unwrap();
    let tx: Transaction = deserialize_hex(hex.trim()).unwrap();
    let spent: Vec<TxOut> = OWNER_ADDRESSES
        .iter()
        .map(|(_, address)| TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: script_of(address),
        })
        .collect();
    common::consensus_verify(&tx, &spent).expect("transaction should be consensus-valid");
    // Change goes back to the kind of address the first input came from.
    assert_eq!(tx.output[1].script_pubkey, script_of(OWNER_ADDRESSES[0].1));
}

#[test]
fn sign_rejects_a_utxo_whose_stated_type_is_unknown() {
    let fixture = Fixture::new();
    let params = json!({
        "network": "testnet4",
        "utxos": [{ "txid": "aa".repeat(32), "vout": 0, "amount_sat": 100_000, "type": "p2wsh" }],
        "recipients": [{ "address": RECIPIENT_ADDRESS, "amount_sat": 30_000 }],
        "fee_rate_sat_per_vb": 2
    });
    fs::write(fixture.params(), params.to_string()).unwrap();

    signer()
        .arg("sign")
        .arg(fixture.params())
        .arg("--key-file")
        .arg(fixture.key())
        .assert()
        .failure()
        .stdout("")
        .stderr(predicate::str::contains("unknown input type \"p2wsh\""));
}

#[test]
fn keygen_writes_a_key_file_and_prints_its_address() {
    let fixture = Fixture::new();
    let new_key = fixture.path("new.wif");

    let output = signer()
        .args(["keygen", "--network", "testnet4", "--key-file"])
        .arg(&new_key)
        .assert()
        .success()
        .get_output()
        .clone();
    let printed_address = String::from_utf8(output.stdout).unwrap();
    assert!(printed_address.starts_with("tb1q"));

    // The address command must agree with what keygen printed.
    signer()
        .args(["address", "--network", "testnet4", "--key-file"])
        .arg(&new_key)
        .assert()
        .success()
        .stdout(printed_address);
}

#[test]
fn keygen_refuses_to_overwrite_an_existing_key() {
    let fixture = Fixture::new();

    signer()
        .args(["keygen", "--network", "testnet4", "--key-file"])
        .arg(fixture.key())
        .assert()
        .failure();

    assert_eq!(fs::read_to_string(fixture.key()).unwrap().trim(), WIF);
}

#[cfg(unix)]
#[test]
fn keygen_makes_the_key_file_private() {
    use std::os::unix::fs::PermissionsExt;
    let fixture = Fixture::new();
    let new_key = fixture.path("new.wif");

    signer()
        .args(["keygen", "--network", "testnet4", "--key-file"])
        .arg(&new_key)
        .assert()
        .success();

    let mode = fs::metadata(new_key).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600);
}

#[test]
fn sign_shows_where_the_money_goes_for_review() {
    let fixture = Fixture::new();

    signer()
        .arg("sign")
        .arg(fixture.params())
        .arg("--key-file")
        .arg(fixture.key())
        .assert()
        .success()
        .stderr(
            predicate::str::contains("spending:     100000 sat from 1 input")
                .and(predicate::str::contains(format!(
                    "pay:           30000 sat to {RECIPIENT_ADDRESS}"
                )))
                .and(predicate::str::contains(format!(
                    "change:        69694 sat to {OWNER_ADDRESS}"
                )))
                .and(predicate::str::contains("fee:             306 sat")),
        );
}

/// The params file shipped as an example must keep working, and must keep
/// producing the output the README shows for it.
#[test]
fn shipped_example_params_sign_to_the_output_shown_in_the_readme() {
    let example = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("params.example.json");
    let review = "\
spending:     100000 sat from 1 input
pay:           30000 sat to tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7
change:        69694 sat to tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx
fee:             306 sat
size:            153 vB
txid:     6279873ad4796f2324f9920a7c7a4104126644846ad872994c6ebe6f0cd96600
";

    let output = signer()
        .arg("sign")
        .arg(example)
        .env(KEY_ENV, WIF)
        .assert()
        .success()
        .stderr(review)
        .get_output()
        .clone();

    assert_valid_fixture_transaction(&String::from_utf8(output.stdout).unwrap());
}
