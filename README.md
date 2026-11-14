# btc-offline-signer

A small Rust CLI that builds and signs a Bitcoin transfer transaction **without any network access**, and prints it as hex ready to broadcast.

```
$ btc-offline-signer sign params.example.json --key-file key.wif
spending:     100000 sat from 1 input
pay:           30000 sat to tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7
change:        69694 sat to tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx
fee:             306 sat
size:            153 vB
txid:     6279873ad4796f2324f9920a7c7a4104126644846ad872994c6ebe6f0cd96600
02000000000101aaaa…00000000
```

The hex is the only thing written to stdout. The review above it goes to stderr: **read it before broadcasting**. The tool rejects malformed and wrong-network addresses, but only you can tell whether an address is the one you meant to pay.

## What it does

- Spends UTXOs owned by one private key, at any of the four kinds of address that key controls:

  | `type` | Kind | Address looks like |
  |--------|------|--------------------|
  | `p2pkh` | Legacy | `1…` / `m…`, `n…` |
  | `p2sh` | Nested SegWit | `3…` / `2…` |
  | `p2wpkh` (default) | Native SegWit | `bc1q…` / `tb1q…` |
  | `p2tr` | Taproot, key path | `bc1p…` / `tb1p…` |

  Kinds can be mixed in one transaction.
- Pays one or more recipients at any standard address type.
- Calculates the fee from a fee rate (sat/vB) and the predicted signed size.
- Returns change to the sender (or a given change address); drops it if it would be dust. By default it goes to the same kind of address as the first UTXO.
- Works on `mainnet`, `testnet`, `testnet4`, `signet` and `regtest`. It refuses a mainnet address or key on a test network and the reverse. The test networks share their key format and most address formats, so they cannot always be told apart from each other.

## Quick start

Needs a stable Rust toolchain ([rustup](https://rustup.rs)). All commands run from the repository root.

**1. Build.** This is the only step that needs the internet, to download dependencies.

```bash
cargo build --release
```

**2. Create a key.** Prints your address and writes the private key to `key.wif`.

```bash
./target/release/btc-offline-signer keygen --network testnet4 --key-file key.wif
```

**3. Get test coins.** Send some to the printed address from a faucet such as <https://mempool.space/testnet4/faucet>. Then look the address up on <https://mempool.space/testnet4> and note the funding transaction's txid, the index of the output that pays you (`vout`), and its amount in sats.

**4. Describe the payment.** Copy the example and replace the placeholder `txid`, `vout`, `amount_sat` and recipient with your own.

```bash
cp params.example.json params.json
```

```json
{
  "network": "testnet4",
  "utxos": [
    { "txid": "<funding txid>", "vout": 0, "amount_sat": 100000 }
  ],
  "recipients": [
    { "address": "<where to send>", "amount_sat": 30000 }
  ],
  "fee_rate_sat_per_vb": 2
}
```

If the coin was sent to one of the key's other addresses rather than the one `keygen` printed, also give its `"type"`: see [Params file](#params-file).

**5. Sign.** Disconnect from the network first if you want to see that it works offline. Read the review it prints, then take the hex.

```bash
./target/release/btc-offline-signer sign params.json --key-file key.wif
```

**6. Broadcast.** Reconnect and paste the hex into <https://mempool.space/testnet4/tx/push>.

`*.wif` files and `params*.json` (except the example) are git-ignored so they can't be committed by accident.

## Broadcast proof

Two transactions built and signed by this tool, both confirmed on testnet4:

| Spends | Signature | Transaction |
|--------|-----------|-------------|
| Native SegWit (`p2wpkh`) input | ECDSA in the witness | [2a9eb172…083a1903](https://mempool.space/testnet4/tx/2a9eb1723df752daadf7fa520781b2dc01a37854cf01ba2134145168083a1903) |
| Legacy (`p2pkh`) input | ECDSA in the scriptSig | [f212b5cf…d5714e8d](https://mempool.space/testnet4/tx/f212b5cfb5ea94f67862b073dde0128914e9365a570c06789ca18030d5714e8d) |

The first pays 1000 sat to the key's own legacy address, with change, at 2 sat/vB. The second spends that legacy output.

## Code layout

```
params.json ─▶ SpendRequest ─▶ UnsignedTx ─▶ Transaction ─▶ hex
              (params.rs)      (builder.rs)   (signer.rs)
```

| File | Responsibility |
|------|----------------|
| [src/params.rs](src/params.rs) | Parse and validate the params file into typed values |
| [src/input_kind.rs](src/input_kind.rs) | The four kinds of output one key can unlock |
| [src/key.rs](src/key.rs) | Load/generate the private key, derive its addresses |
| [src/builder.rs](src/builder.rs) | Build the unsigned transaction: outputs, fee, change, dust rules |
| [src/signer.rs](src/signer.rs) | Sighash and signature for each input: ECDSA for legacy and SegWit, Schnorr for Taproot |
| [src/review.rs](src/review.rs) | The summary of inputs, payments, change and fee shown before the hex |
| [src/error.rs](src/error.rs) | The library's error type |
| [src/main.rs](src/main.rs) | CLI: arguments, file I/O, exit codes |

How each of the four address types is computed from a public key, with worked examples, is in [docs/address-derivation.md](docs/address-derivation.md).

## Reference

The binary is `target/release/btc-offline-signer` after `cargo build --release`.

### Commands

**`keygen --network <net> --key-file <path>`** creates a new key and prints its native SegWit address. The file is created with `0600` permissions, and an existing file is never overwritten.

**`address --network <net> [--type <type>] [--key-file <path>]`** prints one of a key's addresses. `--type` (or `-t`) is `p2pkh`, `p2sh`, `p2wpkh` (the default) or `p2tr`. Any WIF key file works, so a key exported from another wallet can be used as is.

**`sign <params.json> [--key-file <path>] [--output <path>]`** builds and signs the transaction. `--output` (or `-o`) writes the hex to a file instead of stdout.

For `address` and `sign`, the key is read from `--key-file`, or from the `BTC_SIGNER_WIF` environment variable if that is omitted. It is deliberately not accepted as a command-line argument or in the params file.

### Params file

[params.example.json](params.example.json) is a minimal file that signs as it stands, which is how the output at the top of this page was made (with the well-known test key whose secret is the number 1). Its txid is a placeholder, so the result cannot be broadcast.

With every optional field shown:

```json
{
  "network": "testnet4",
  "utxos": [
    { "txid": "<txid of the transaction that paid you>", "vout": 0, "amount_sat": 100000, "type": "p2wpkh" }
  ],
  "recipients": [
    { "address": "tb1q...", "amount_sat": 30000 }
  ],
  "change_address": "tb1q...",
  "fee_rate_sat_per_vb": 2
}
```

| Field | Meaning |
|-------|---------|
| `network` | `mainnet`, `testnet`, `testnet4`, `signet` or `regtest` |
| `utxos` | Coins to spend. **All** listed UTXOs are used, and each must belong to the signing key. `amount_sat` must be exact: it is part of what gets signed |
| `utxos[].type` | Optional. Which kind of address the coin was sent to: `p2pkh`, `p2sh`, `p2wpkh` (default) or `p2tr`. The tool is offline and cannot look this up |
| `recipients` | Who to pay and how much, in satoshis |
| `change_address` | Optional. Defaults to the signing key's own address, of the same kind as the first UTXO |
| `fee_rate_sat_per_vb` | Fee rate in satoshis per virtual byte (whole number ≥ 1) |

Unknown fields are rejected, so a typo cannot be silently ignored.

## Security properties

### Offline by construction

The binary contains no networking code and depends on no networking crate, so signing cannot reach the internet even by accident. You can check:

```bash
cargo tree -e normal
```

Everything the transaction needs (which coins to spend and how much each is worth) is supplied in the params file.

### Signature nonces

Every signature uses a secret one-time number called a **nonce**. The rule that matters: **a nonce must never be used to sign two different transactions.** If it is, anyone who sees both signatures can calculate the private key and take every coin it controls. This has drained real wallets.

You do not choose or manage nonces with this tool. It derives each one from the private key and the exact data being signed, so there is nothing to get wrong:

| Input type | Signature | Nonce derived by |
|------------|-----------|------------------|
| `p2pkh`, `p2sh`, `p2wpkh` | ECDSA | RFC 6979: HMAC-SHA256 of the private key and the transaction digest |
| `p2tr` | Schnorr | BIP340: SHA-256 of the private key, the public key and the transaction digest |

What this means in practice:

- **Different transactions get different nonces.** Any change to a transaction changes its digest, and so the nonce. Two inputs of the same transaction also get different nonces, because each input's digest includes its position.
- **Signing is reproducible.** The same key and params always produce the same hex. Signing the same transaction twice repeats the same signature, which reveals nothing new.
- **No random number generator is used when signing**, so a weak or broken one cannot leak the key. Randomness is only used by `keygen`.

BIP340 lets a signer also mix fresh random bytes into the Taproot nonce, as protection against physical attacks on the signing device (power analysis, fault injection). This tool leaves that out to keep output reproducible; it is designed to run on a computer you control, not on hardware an attacker can probe.

## Limitations

- Inputs must be single-key outputs of one private key. No multisig, P2WSH, Taproot script path, seed phrases or extended keys.
- A legacy (`p2pkh`) signature does not cover the input's amount. If `amount_sat` is wrong for such an input, the transaction is still valid and the real fee differs from the one shown.
- No coin selection: you choose the UTXOs.
- The tool cannot check that the UTXOs exist or are unspent; a wrong txid, index or amount produces a transaction the network will reject.
- The tool cannot check a UTXO's `type` either: offline, it has no way to see how the coin is really locked, so it trusts the params file. A wrong or missing `type` still signs and prints a normal-looking review, but the broadcast fails (for example with `bad-witness-nonstandard`). No money can be lost this way. If that happens, look the coin up on a block explorer and set `type` to match its address.
- The key file is stored unencrypted. Use test networks, or protect the file appropriately.

## Tests

```bash
cargo test
```

- **Unit tests** in each module cover key handling, params validation, fee/change/dust arithmetic and signing.
- Signed transactions are checked with **Bitcoin Core's own script interpreter** (`libbitcoinconsensus`), so "valid" means what a real node means by it. This is done for every kind of input, alone and mixed in one transaction.
- **Integration tests** in [tests/cli.rs](tests/cli.rs) run the compiled binary. One of them signs [params.example.json](params.example.json) and compares the result with the output shown at the top of this page, so the example cannot go stale.
- [tests/address_types.rs](tests/address_types.rs) has one test per recipient address type (P2PKH, P2SH, P2WPKH, P2WSH, P2TR), checking the exact lock script produced when paying each.

Running the tests needs a C++ compiler (on macOS, the Xcode command-line tools), because the interpreter is C++ and is compiled on the first run. Building and running the tool itself does not.

## Dependencies

In the tool itself:

| Crate | Used for |
|-------|----------|
| [`bitcoin`](https://crates.io/crates/bitcoin) 0.32 | Transaction and address types, sighash calculation, and (through its bundled `secp256k1`) ECDSA and Schnorr signing |
| [`clap`](https://crates.io/crates/clap) 4 | Command-line arguments |
| [`serde`](https://crates.io/crates/serde), [`serde_json`](https://crates.io/crates/serde_json) 1 | Reading the params file |
| [`thiserror`](https://crates.io/crates/thiserror) 2 | The error type's messages |

No cryptography is implemented in this repository; it all comes from `bitcoin` and `secp256k1`.

In tests only (never part of the built tool):

| Crate | Used for |
|-------|----------|
| [`bitcoinconsensus`](https://crates.io/crates/bitcoinconsensus) 0.106 | Bitcoin Core's script interpreter, as an independent judge of every signed transaction |
| [`assert_cmd`](https://crates.io/crates/assert_cmd) 2, [`predicates`](https://crates.io/crates/predicates) 3 | Running the compiled binary and checking what it prints |
| [`tempfile`](https://crates.io/crates/tempfile) 3 | Throwaway directories for key and params files |

## License

[MIT](LICENSE)
