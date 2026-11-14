//! Build and sign Bitcoin transactions without any network access.
//!
//! The data flows one way, each stage producing a stricter type:
//! `params` (JSON -> `SpendRequest`) -> `builder` (-> `UnsignedTx`) ->
//! `signer` (-> signed `Transaction`).

pub mod builder;
pub mod error;
pub mod input_kind;
pub mod key;
pub mod params;
pub mod review;
pub mod signer;

pub use error::Error;
pub use input_kind::InputKind;

/// The consensus-verification helper, shared with the integration tests.
#[cfg(test)]
#[path = "../tests/common/mod.rs"]
mod test_support;
