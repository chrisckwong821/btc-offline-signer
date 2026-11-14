//! The kinds of output a single private key can unlock.

use std::fmt;
use std::str::FromStr;

use crate::Error;

/// How a UTXO is locked. This decides which address it was paid to, how big
/// the input spending it will be, and how it has to be signed.
///
/// The tool works offline and cannot look this up, so the params file states
/// it for each UTXO.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum InputKind {
    /// Legacy (`1…` / `m…`, `n…`): ECDSA signature in the scriptSig.
    P2pkh,
    /// Nested SegWit (`3…` / `2…`): a P2WPKH wrapped in P2SH so that old
    /// wallets can pay it. Named just `p2sh` for the user, as it is the only
    /// kind of P2SH output a single key controls here.
    P2shP2wpkh,
    /// Native SegWit (`bc1q…` / `tb1q…`): ECDSA signature in the witness.
    #[default]
    P2wpkh,
    /// Taproot key path (`bc1p…` / `tb1p…`): Schnorr signature in the witness.
    P2tr,
}

impl InputKind {
    /// Every kind, for code and tests that need to go through all of them.
    pub const ALL: [Self; 4] = [Self::P2pkh, Self::P2shP2wpkh, Self::P2wpkh, Self::P2tr];

    /// The name used in the params file and on the command line.
    pub fn name(self) -> &'static str {
        match self {
            Self::P2pkh => "p2pkh",
            Self::P2shP2wpkh => "p2sh",
            Self::P2wpkh => "p2wpkh",
            Self::P2tr => "p2tr",
        }
    }
}

/// Lets `"p2tr".parse::<InputKind>()` work. The command-line parser uses
/// this for `--type`, and the params file for each UTXO's `type`.
impl FromStr for InputKind {
    type Err = Error;

    /// Finds the kind whose name is exactly `name`. Names are case-sensitive.
    fn from_str(name: &str) -> Result<Self, Error> {
        Self::ALL
            .into_iter()
            .find(|kind| kind.name() == name)
            .ok_or_else(|| Error::UnknownInputType(name.to_string()))
    }
}

/// Printing a kind gives the same name that parses back to it.
impl fmt::Display for InputKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_kind_round_trips_through_its_name() {
        for kind in InputKind::ALL {
            assert_eq!(kind.to_string().parse::<InputKind>().unwrap(), kind);
        }
    }

    #[test]
    fn names_are_the_ones_documented_for_the_params_file() {
        let names = InputKind::ALL.map(InputKind::name);
        assert_eq!(names, ["p2pkh", "p2sh", "p2wpkh", "p2tr"]);
    }

    #[test]
    fn default_is_native_segwit() {
        assert_eq!(InputKind::default(), InputKind::P2wpkh);
    }

    #[test]
    fn rejects_unknown_and_differently_cased_names() {
        for name in ["p2wsh", "P2TR", "taproot", ""] {
            let err = name.parse::<InputKind>().unwrap_err();
            assert!(matches!(err, Error::UnknownInputType(n) if n == name));
        }
    }
}
