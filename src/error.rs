//! The single error type returned by every fallible function in this crate.
//!
//! Each variant is one thing that can go wrong. The text in `#[error("…")]`
//! is the message the user sees after `error:` on the command line, so it is
//! written for them, not for a programmer.

use bitcoin::{Amount, Network, OutPoint};
use thiserror::Error;

/// Variants are listed in the order the problems can arise: loading the key,
/// reading the params file, building the transaction, then signing it.
#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid private key: {0}")]
    InvalidPrivateKey(String),

    #[error("private key is for a different network than {expected}")]
    KeyNetworkMismatch { expected: Network },

    #[error("params file is not valid: {0}")]
    InvalidJson(#[from] serde_json::Error),

    #[error("unknown network \"{0}\" (expected mainnet, testnet, testnet4, signet or regtest)")]
    UnknownNetwork(String),

    #[error("unknown input type \"{0}\" (expected p2pkh, p2sh, p2wpkh or p2tr)")]
    UnknownInputType(String),

    #[error("invalid txid \"{txid}\": {reason}")]
    InvalidTxid { txid: String, reason: String },

    #[error("invalid address \"{address}\": {reason}")]
    InvalidAddress { address: String, reason: String },

    #[error("at least one UTXO is required")]
    NoUtxos,

    #[error("at least one recipient is required")]
    NoRecipients,

    #[error("UTXO {0} is listed more than once")]
    DuplicateUtxo(OutPoint),

    #[error("fee rate of {0} sat/vB is not usable (must be at least 1)")]
    InvalidFeeRate(u64),

    #[error("output of {amount} to {address} is below the dust limit of {minimum}")]
    DustOutput {
        address: String,
        amount: Amount,
        minimum: Amount,
    },

    #[error("insufficient funds: inputs total {available} but outputs plus fee need {required}")]
    InsufficientFunds { available: Amount, required: Amount },

    #[error("amounts are too large to add up")]
    AmountOverflow,

    #[error("the transaction was built for a different key than the one given to sign it")]
    KeyMismatch,

    #[error("could not compute the signature hash for input {index}: {reason}")]
    Sighash { index: usize, reason: String },
}
