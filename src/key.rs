//! The private key used for signing and everything derived from it.
//!
//! ```text
//! private key (secret) --> public key --> addresses (one per InputKind)
//! ```
//!
//! Each arrow only works in that direction. [`SigningKey`] holds the secret;
//! [`Owner`] holds just the public key, for code that must not be able to sign.

use std::fmt;

use bitcoin::secp256k1::{Secp256k1, SecretKey};
use bitcoin::{Address, CompressedPublicKey, Network, NetworkKind, PrivateKey, ScriptBuf};

use crate::{Error, InputKind};

/// The public half of a key: enough to work out its addresses, never to sign.
///
/// The transaction builder takes this rather than a [`SigningKey`], so it has
/// no access to the secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Owner {
    /// The 33-byte ("compressed") form of the public key.
    public: CompressedPublicKey,
    /// Decides how addresses are written, e.g. `bc1…` versus `tb1…`.
    network: Network,
}

impl Owner {
    /// Wraps a public key. No secret is involved, so this cannot fail.
    pub fn new(public: CompressedPublicKey, network: Network) -> Self {
        Self { public, network }
    }

    /// The address of the given kind controlled by this key.
    ///
    /// The same key gives four different addresses, because each kind wraps
    /// the public key in a different lock script.
    pub fn address(&self, kind: InputKind) -> Address {
        match kind {
            InputKind::P2pkh => Address::p2pkh(self.public, self.network),
            InputKind::P2shP2wpkh => Address::p2shwpkh(&self.public, self.network),
            InputKind::P2wpkh => Address::p2wpkh(&self.public, self.network),
            // Key-only Taproot (BIP86): the output key is this key tweaked by
            // a hash of itself, committing to "there is no script path".
            InputKind::P2tr => Address::p2tr(
                &Secp256k1::verification_only(),
                self.public.0.into(),
                None,
                self.network,
            ),
        }
    }

    /// The lock script of [`Self::address`]: the bytes that actually appear in
    /// a transaction output. An address is only a readable way to write it.
    pub fn script_pubkey(&self, kind: InputKind) -> ScriptBuf {
        self.address(kind).script_pubkey()
    }

    /// The public key itself, which the signer has to reveal when spending.
    pub(crate) fn public_key(&self) -> &CompressedPublicKey {
        &self.public
    }
}

/// A private key bound to a network, with its public half.
///
/// Only compressed keys are accepted: SegWit forbids uncompressed ones, and
/// no current wallet creates them.
pub struct SigningKey {
    /// The secret. Never printed, logged or returned outside this crate
    /// except through [`Self::to_wif`].
    private: PrivateKey,
    /// The public half derived from it.
    owner: Owner,
}

impl SigningKey {
    /// Decodes a WIF string and checks that it belongs to `network`.
    ///
    /// WIF ("Wallet Import Format") is the usual way to write a private key
    /// as text. Whitespace around it is ignored, so a key file ending in a
    /// newline works.
    pub fn from_wif(wif: &str, network: Network) -> Result<Self, Error> {
        let private = PrivateKey::from_wif(wif.trim())
            .map_err(|e| Error::InvalidPrivateKey(e.to_string()))?;

        // A WIF only distinguishes "mainnet" from "any test network".
        if private.network != NetworkKind::from(network) {
            return Err(Error::KeyNetworkMismatch { expected: network });
        }
        Self::from_private_key(private, network)
    }

    /// Creates a new random key using the operating system's randomness.
    pub fn generate(network: Network) -> Self {
        Self::from_private_key(PrivateKey::generate(network), network)
            .expect("generated keys are always compressed")
    }

    /// Derives the public key and pairs it with the secret. Shared by
    /// [`Self::from_wif`] and [`Self::generate`].
    fn from_private_key(private: PrivateKey, network: Network) -> Result<Self, Error> {
        let public = CompressedPublicKey::from_private_key(&Secp256k1::new(), &private)
            .map_err(|_| Error::InvalidPrivateKey("uncompressed keys are not supported".into()))?;
        Ok(Self {
            private,
            owner: Owner::new(public, network),
        })
    }

    /// The public half, from which this key's addresses are derived.
    pub fn owner(&self) -> &Owner {
        &self.owner
    }

    /// The key in Wallet Import Format. This is the secret: handle with care.
    pub fn to_wif(&self) -> String {
        self.private.to_wif()
    }

    /// The raw secret, for the signer only (`pub(crate)` keeps it inside
    /// this library).
    pub(crate) fn secret_key(&self) -> &SecretKey {
        &self.private.inner
    }
}

/// Hand-written so that the secret can never end up in logs or panic messages.
impl fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SigningKey")
            .field("owner", &self.owner)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The secret key with value 1. Its public key hash is the one used in the
    // BIP173 example addresses, which gives us independent expected values.
    const TESTNET_WIF: &str = "cMahea7zqjxrtgAbB7LSGbcQUr1uX1ojuat9jZodMN87JcbXMTcA";
    const MAINNET_WIF: &str = "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn";
    const UNCOMPRESSED_MAINNET_WIF: &str = "5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAnchuDf";

    #[test]
    fn testnet_wif_gives_bip173_testnet_address() {
        let key = SigningKey::from_wif(TESTNET_WIF, Network::Testnet).unwrap();
        assert_eq!(
            key.owner().address(InputKind::P2wpkh).to_string(),
            "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx"
        );
    }

    #[test]
    fn mainnet_wif_gives_bip173_mainnet_address() {
        let key = SigningKey::from_wif(MAINNET_WIF, Network::Bitcoin).unwrap();
        assert_eq!(
            key.owner().address(InputKind::P2wpkh).to_string(),
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
        );
    }

    #[test]
    fn one_key_controls_an_address_of_every_kind() {
        // Expected values are derived step by step in docs/address-derivation.md.
        let owner = SigningKey::from_wif(MAINNET_WIF, Network::Bitcoin).unwrap();
        let address = |kind| owner.owner().address(kind).to_string();

        assert_eq!(
            address(InputKind::P2pkh),
            "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"
        );
        assert_eq!(
            address(InputKind::P2shP2wpkh),
            "3JvL6Ymt8MVWiCNHC7oWU6nLeHNJKLZGLN"
        );
        assert_eq!(
            address(InputKind::P2wpkh),
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
        );
        assert_eq!(
            address(InputKind::P2tr),
            "bc1pmfr3p9j00pfxjh0zmgp99y8zftmd3s5pmedqhyptwy6lm87hf5sspknck9"
        );
    }

    #[test]
    fn script_pubkey_is_the_lock_script_of_the_address() {
        let key = SigningKey::from_wif(MAINNET_WIF, Network::Bitcoin).unwrap();
        let script = |kind| key.owner().script_pubkey(kind).to_hex_string();

        assert_eq!(
            script(InputKind::P2pkh),
            "76a914751e76e8199196d454941c45d1b3a323f1433bd688ac"
        );
        assert_eq!(
            script(InputKind::P2shP2wpkh),
            "a914bcfeb728b584253d5f3f70bcb780e9ef218a68f487"
        );
        assert_eq!(
            script(InputKind::P2wpkh),
            "0014751e76e8199196d454941c45d1b3a323f1433bd6"
        );
        assert_eq!(
            script(InputKind::P2tr),
            "5120da4710964f7852695de2da025290e24af6d8c281de5a0b902b7135fd9fd74d21"
        );
    }

    #[test]
    fn test_wif_is_valid_on_every_test_network() {
        for network in [Network::Testnet, Network::Testnet4, Network::Signet] {
            assert!(SigningKey::from_wif(TESTNET_WIF, network).is_ok());
        }
    }

    #[test]
    fn surrounding_whitespace_is_ignored() {
        let padded = format!("  {TESTNET_WIF}\n");
        assert!(SigningKey::from_wif(&padded, Network::Testnet).is_ok());
    }

    #[test]
    fn rejects_key_for_another_network() {
        let err = SigningKey::from_wif(TESTNET_WIF, Network::Bitcoin).unwrap_err();
        assert!(matches!(
            err,
            Error::KeyNetworkMismatch {
                expected: Network::Bitcoin
            }
        ));
    }

    #[test]
    fn rejects_garbage() {
        let err = SigningKey::from_wif("not-a-key", Network::Testnet).unwrap_err();
        assert!(matches!(err, Error::InvalidPrivateKey(_)));
    }

    #[test]
    fn rejects_uncompressed_key() {
        let err = SigningKey::from_wif(UNCOMPRESSED_MAINNET_WIF, Network::Bitcoin).unwrap_err();
        assert!(matches!(err, Error::InvalidPrivateKey(_)));
    }

    #[test]
    fn generated_key_round_trips_through_wif() {
        let key = SigningKey::generate(Network::Testnet4);
        let reloaded = SigningKey::from_wif(&key.to_wif(), Network::Testnet4).unwrap();
        assert_eq!(
            key.owner().address(InputKind::P2wpkh),
            reloaded.owner().address(InputKind::P2wpkh)
        );
        assert!(key
            .owner()
            .address(InputKind::P2wpkh)
            .to_string()
            .starts_with("tb1q"));
    }

    #[test]
    fn debug_output_does_not_contain_the_secret() {
        let key = SigningKey::from_wif(TESTNET_WIF, Network::Testnet).unwrap();
        assert!(!format!("{key:?}").contains(TESTNET_WIF));
    }
}
