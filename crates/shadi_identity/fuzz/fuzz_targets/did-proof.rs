#![no_main]

use libfuzzer_sys::fuzz_target;
use shadi_identity::{
    looks_like_did_proof, unwrap_signed_message, DID_PROOF_HEADER_MAX_BYTES,
    DID_PROOF_PAYLOAD_MAX_BYTES,
};

// A2A / SLIM peers can send arbitrary bytes. unwrap_signed_message must
// reject malformed envelopes without panicking, and must refuse payloads
// or headers above the documented caps.
fuzz_target!(|data: &[u8]| {
    let looks = looks_like_did_proof(data);
    match unwrap_signed_message(data) {
        Ok(verified) => {
            assert!(looks, "verified envelope must start with DID-proof magic");
            assert!(
                verified.did.starts_with("did:key:"),
                "verified DID leaked a non-did:key claim: {}",
                verified.did
            );
            assert!(
                verified.did.len() <= DID_PROOF_HEADER_MAX_BYTES,
                "verified DID exceeded header cap"
            );
            assert!(
                verified.payload.len() <= DID_PROOF_PAYLOAD_MAX_BYTES,
                "verified payload exceeded cap: {}",
                verified.payload.len()
            );
        }
        Err(_) => {
            let header_budget = 17 + 1 + DID_PROOF_HEADER_MAX_BYTES + 1 + DID_PROOF_HEADER_MAX_BYTES + 1;
            if data.len() > header_budget + DID_PROOF_PAYLOAD_MAX_BYTES {
                // Oversize input must not verify.
            }
        }
    }
});
