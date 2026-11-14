# How each Bitcoin address type is computed

Every example below starts from the **same private key** so you can see how one key leads to five different addresses. All values were computed with the `bitcoin` crate (v0.32), not written from memory.

## The one idea behind all of them

An address is not stored on the blockchain. What is stored in a transaction output is a **lock script** (`script_pubkey`): a few bytes saying what must be shown to spend the coins. An address is just that script written in a form humans can copy safely:

```
address  =  network marker  +  the important bytes of the lock script  +  checksum
```

So every address type answers three questions:

1. **What bytes go in?** A hash of a public key, a hash of a script, or a public key itself.
2. **What lock script do they produce?**
3. **How is the text encoded?** Base58Check (old) or Bech32/Bech32m (new).

| Type | Introduced | Payload | Encoding | Mainnet starts with | Testnet starts with |
|------|-----------|---------|----------|---------------------|---------------------|
| P2PKH | 2009 | HASH160 of public key (20 bytes) | Base58Check | `1` | `m` or `n` |
| P2SH | 2012 (BIP16) | HASH160 of a script (20 bytes) | Base58Check | `3` | `2` |
| P2WPKH | 2017 (BIP141) | HASH160 of public key (20 bytes) | Bech32 | `bc1q` | `tb1q` |
| P2WSH | 2017 (BIP141) | SHA256 of a script (32 bytes) | Bech32 | `bc1q` | `tb1q` |
| P2TR | 2021 (BIP341) | A tweaked public key (32 bytes) | Bech32m | `bc1p` | `tb1p` |

## Building blocks

### Hash functions

| Name | Definition | Output |
|------|------------|--------|
| SHA256 | Standard SHA-256 | 32 bytes |
| RIPEMD160 | Standard RIPEMD-160 | 20 bytes |
| **HASH160** | `RIPEMD160(SHA256(x))` | 20 bytes |
| **HASH256** | `SHA256(SHA256(x))` | 32 bytes |

### Base58Check (used by `1…` and `3…` addresses)

1. Take `version byte + payload`.
2. Checksum = first 4 bytes of `HASH256(version + payload)`.
3. Treat `version + payload + checksum` as one big number and write it in base 58.

The 58-character alphabet is `123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz`. It leaves out `0`, `O`, `I` and `l` because they look alike. The version byte decides the first character of the result.

### Bech32 and Bech32m (used by `bc1…` addresses)

A Bech32 address has four parts:

```
bc   1   q   w508d6qejxtdg4y5r3zarvary0c5xw7k   v8f3t4
│    │   │   │                                  └ checksum (6 characters)
│    │   │   └ the payload ("witness program"), regrouped from 8-bit bytes into 5-bit groups
│    │   └ witness version: q = 0, p = 1
│    └ separator, always "1"
└ human-readable part: bc = mainnet, tb = testnet/signet, bcrt = regtest
```

- The alphabet has 32 characters (`qpzry9x8gf2tvdw0s3jn54khce6mua7l`), so each character carries exactly 5 bits. It is all lowercase and avoids `1`, `b`, `i`, `o`.
- The checksum is a BCH error-detecting code computed over the human-readable part and the data. It is guaranteed to catch up to 4 mistyped characters.
- **Bech32** (BIP173) is used for witness version 0. **Bech32m** (BIP350) is used for version 1 and above. They differ only in one constant used in the checksum; Bech32m fixed a weakness where adding or removing certain characters went undetected.

## Starting point: the key

```
private key (32 bytes):
  0000000000000000000000000000000000000000000000000000000000000001

private key in WIF:
  mainnet  KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn
  testnet  cMahea7zqjxrtgAbB7LSGbcQUr1uX1ojuat9jZodMN87JcbXMTcA
```

**Never use this key for real money.** The number 1 is the most famous private key there is; anything sent to it is taken within seconds.

The public key is a point `(x, y)` on the secp256k1 curve, obtained by multiplying the curve's fixed starting point `G` by the private key.

```
uncompressed (65 bytes) = 04 + x + y
  04 79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
     483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8

compressed (33 bytes) = 02 if y is even, 03 if y is odd, then x
  02 79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
```

`y` can be recalculated from `x` and its even/odd flag, so the compressed form loses nothing. Everything modern uses compressed keys, and SegWit requires them.

---

## 1. P2PKH — Pay to Public Key Hash (`1…`)

The original address type. The lock says: "show a public key that hashes to this value, and a signature made with it".

**Steps**

```
1. public key (compressed)
     0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798

2. SHA256 of it
     0f715baf5d4c2ed329785cef29e562f73488c8a2bb9dbc5700b361d54b9b0554

3. RIPEMD160 of that  →  the "public key hash" (20 bytes)
     751e76e8199196d454941c45d1b3a323f1433bd6

4. put the version byte in front (00 = mainnet)
     00 751e76e8199196d454941c45d1b3a323f1433bd6

5. checksum = first 4 bytes of HASH256 of step 4
     510d1634

6. Base58 of (step 4 + step 5)
     1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH
```

**Testnet** uses version byte `6f` instead of `00`: checksum `55c484e3`, address `mrCDrCybB6J1vRfbwM5hemdJz73FwDBC8r`.

**Lock script** (25 bytes)

```
76 a9 14 751e76e8199196d454941c45d1b3a323f1433bd6 88 ac

OP_DUP  OP_HASH160  <20-byte hash>  OP_EQUALVERIFY  OP_CHECKSIG
```

Why hash the key instead of using it directly? Shorter addresses, and the public key stays hidden until the coins are spent.

---

## 2. P2SH — Pay to Script Hash (`3…`)

Instead of the hash of a key, the address holds the hash of a **script** (called the redeem script). The sender doesn't need to know what the script is; the spender reveals it later and satisfies it. This is how multisig and other conditions became practical.

The example wraps a P2WPKH script inside P2SH ("nested SegWit"), which was the common way to get SegWit benefits while old wallets could still pay you.

**Steps**

```
1. redeem script = the P2WPKH lock script for our key (see section 3)
     0014751e76e8199196d454941c45d1b3a323f1433bd6

2. HASH160 of the redeem script  →  the "script hash" (20 bytes)
     SHA256:     8838f796bf4970b148779c05b74b8c49515b322d04035f7faa5d9b2375df2396
     RIPEMD160:  bcfeb728b584253d5f3f70bcb780e9ef218a68f4

3. put the version byte in front (05 = mainnet)
     05 bcfeb728b584253d5f3f70bcb780e9ef218a68f4

4. checksum = first 4 bytes of HASH256 of step 3
     923b88af

5. Base58 of (step 3 + step 4)
     3JvL6Ymt8MVWiCNHC7oWU6nLeHNJKLZGLN
```

**Testnet** uses version byte `c4`: checksum `66426fb7`, address `2NAUYAHhujozruyzpsFRP63mbrdaU5wnEpN`.

**Lock script** (23 bytes)

```
a9 14 bcfeb728b584253d5f3f70bcb780e9ef218a68f4 87

OP_HASH160  <20-byte hash>  OP_EQUAL
```

A `3…` address tells you nothing about what is inside: it could be a 2-of-3 multisig, a nested SegWit key, or anything else. Only the hash is visible until it is spent.

---

## 3. P2WPKH — Pay to Witness Public Key Hash (`bc1q…`, 42 characters)

The SegWit version of P2PKH, and **the type this project signs for**. It uses the same 20-byte public key hash, but the lock script is shorter and the address is Bech32.

**Steps**

```
1. public key hash = HASH160(compressed public key)   (same as P2PKH step 3)
     751e76e8199196d454941c45d1b3a323f1433bd6

2. this is the "witness program". Witness version is 0.

3. Bech32-encode:
     human-readable part  bc
     separator            1
     version 0            q
     program, as 5-bit groups (20 bytes = 160 bits = 32 characters)
                          w508d6qejxtdg4y5r3zarvary0c5xw7k
     checksum             v8f3t4

     bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4
```

**Testnet:** the human-readable part becomes `tb`, which also changes the checksum: `tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx`. The middle part is identical because the key hash is the same.

**Lock script** (22 bytes)

```
00 14 751e76e8199196d454941c45d1b3a323f1433bd6

OP_0  <20-byte hash>
```

Compare with P2PKH: same hash, but the script is just "version, then program". The rules for spending it are not written in the script; nodes know that "version 0 with a 20-byte program" means "check a signature against this key hash".

---

## 4. P2WSH — Pay to Witness Script Hash (`bc1q…`, 62 characters)

The SegWit version of P2SH. It uses a plain SHA256 (32 bytes) rather than HASH160 (20 bytes), because 20 bytes is too weak against collision attacks when several parties build a script together.

The example script is the simplest possible one: "this public key must sign".

**Steps**

```
1. witness script
     21 0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798 ac

     <push 33 bytes: public key>  OP_CHECKSIG

2. SHA256 of the witness script  →  witness program (32 bytes)
     1863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262

3. Bech32-encode with version 0
     bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3
```

**Testnet:** `tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7`

**Lock script** (34 bytes)

```
00 20 1863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262

OP_0  <32-byte hash>
```

How to tell P2WPKH and P2WSH apart: both start with `bc1q` (version 0). Nodes look at the program length — 20 bytes means key hash, 32 bytes means script hash. In address form that is 42 versus 62 characters.

---

## 5. P2TR — Pay to Taproot (`bc1p…`, 62 characters)

Taproot does something different: the address contains **a public key itself**, not a hash. That key is a "tweaked" version of your key, and the tweak can secretly commit to a set of alternative spending scripts. Spending with just the key looks identical whether or not any scripts exist, which is good for privacy.

Taproot uses **x-only** public keys: only the 32-byte `x` coordinate, with `y` assumed even.

The example is the simplest case: one key, no scripts.

**Steps**

```
1. internal key P = x coordinate of our public key (32 bytes)
     79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798

2. tweak t = tagged hash "TapTweak" of P
     tag  = SHA256("TapTweak")
          = e80fe1639c9ca050e3af1b39c143c63e429cbceb15d940fbb5c5a1f4af57c5e9
     t    = SHA256(tag + tag + P)
          = 3cf5216d476a5e637bf0da674e50ddf55c403270dd36494dfcca438132fa30e7

   (with scripts, the root hash of the script tree is appended after P)

3. output key Q = P + t·G        (elliptic-curve point addition; keep only x)
     da4710964f7852695de2da025290e24af6d8c281de5a0b902b7135fd9fd74d21

4. Bech32m-encode with version 1 (the character "p")
     bc1pmfr3p9j00pfxjh0zmgp99y8zftmd3s5pmedqhyptwy6lm87hf5sspknck9
```

**Testnet:** `tb1pmfr3p9j00pfxjh0zmgp99y8zftmd3s5pmedqhyptwy6lm87hf5ssk79hv2`

**Lock script** (34 bytes)

```
51 20 da4710964f7852695de2da025290e24af6d8c281de5a0b902b7135fd9fd74d21

OP_1  <32-byte output key>
```

Notes:

- A **tagged hash** is `SHA256(SHA256(tag) + SHA256(tag) + data)`. Prefixing with a tag makes sure a hash computed for one purpose can never be confused with a hash for another.
- The tweak is applied even when there are no scripts. This proves the key has no hidden script path.
- To spend, the owner signs with the private key adjusted by the same tweak (`d + t`), using **Schnorr** signatures (BIP340) instead of ECDSA.

---

## All five side by side

Same private key, mainnet:

| Type | Address | Lock script |
|------|---------|-------------|
| P2PKH | `1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH` | `76a914751e…3bd688ac` |
| P2SH (wrapping P2WPKH) | `3JvL6Ymt8MVWiCNHC7oWU6nLeHNJKLZGLN` | `a914bcfe…68f487` |
| P2WPKH | `bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4` | `0014751e…3bd6` |
| P2WSH (key + CHECKSIG) | `bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3` | `00201863…3262` |
| P2TR (key only) | `bc1pmfr3p9j00pfxjh0zmgp99y8zftmd3s5pmedqhyptwy6lm87hf5sspknck9` | `5120da47…4d21` |

Things worth noticing:

- P2PKH and P2WPKH contain the **same 20-byte hash** (`751e…3bd6`). Only the script wrapper and the text encoding differ.
- Coins sent to one of these addresses cannot be spent as if they were at another. Each is a different lock, even though one key opens all of them.
- An address does not reveal the public key (except Taproot, which reveals a tweaked one) and never reveals the private key.

## The same thing in Rust

Each address type is one call in the `bitcoin` crate:

```rust
use bitcoin::{Address, CompressedPublicKey, Network, PublicKey, ScriptBuf};
use bitcoin::secp256k1::Secp256k1;

let secp = Secp256k1::new();
let public = CompressedPublicKey::from_private_key(&secp, &private_key)?;
let network = Network::Bitcoin;

let p2pkh  = Address::p2pkh(PublicKey::from(public), network);
let p2wpkh = Address::p2wpkh(&public, network);

let redeem_script = ScriptBuf::new_p2wpkh(&public.wpubkey_hash());
let p2sh   = Address::p2sh(&redeem_script, network)?;

let p2wsh  = Address::p2wsh(&witness_script, network);

let (internal_key, _parity) = public.0.x_only_public_key();
let p2tr   = Address::p2tr(&secp, internal_key, None, network);
```

In this project, [src/key.rs](../src/key.rs) uses `Address::p2wpkh` to derive the signer's address.

## Specifications

- **BIP13 / BIP16** — P2SH addresses and rules
- **BIP141** — SegWit, witness programs
- **BIP173** — Bech32
- **BIP350** — Bech32m
- **BIP340 / BIP341** — Schnorr signatures and Taproot
