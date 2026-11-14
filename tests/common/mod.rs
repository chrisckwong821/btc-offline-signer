//! Test helper shared by the unit tests and the integration tests: asks
//! Bitcoin Core's own script interpreter (libbitcoinconsensus) whether a
//! transaction's inputs validly spend the outputs they claim to.

use bitcoin::consensus::encode::serialize;
use bitcoin::{Transaction, TxOut};

/// Checks every input of `tx` against the matching entry of `prevouts`.
///
/// On failure, says which input the interpreter rejected.
pub fn consensus_verify(tx: &Transaction, prevouts: &[TxOut]) -> Result<(), String> {
    assert_eq!(tx.input.len(), prevouts.len(), "one prevout per input");
    let tx_bytes = serialize(tx);

    // A Taproot signature covers every output the transaction spends, so the
    // interpreter is given all of them, not just the one being checked.
    let spent_outputs: Vec<bitcoinconsensus::Utxo> = prevouts
        .iter()
        .map(|prevout| bitcoinconsensus::Utxo {
            script_pubkey: prevout.script_pubkey.as_bytes().as_ptr(),
            script_pubkey_len: prevout.script_pubkey.len() as u32,
            value: prevout.value.to_sat() as i64,
        })
        .collect();

    for (index, prevout) in prevouts.iter().enumerate() {
        bitcoinconsensus::verify(
            prevout.script_pubkey.as_bytes(),
            prevout.value.to_sat(),
            &tx_bytes,
            Some(&spent_outputs),
            index,
        )
        .map_err(|error| format!("input {index} rejected: {error:?}"))?;
    }
    Ok(())
}
