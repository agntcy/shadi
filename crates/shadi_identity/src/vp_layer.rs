// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! `SHADI-VP/1`: framing for a verifiable presentation carried inside an
//! agent's DID-proof payload.
//!
//! Pure framing, exactly like [`crate::binding`] — no crypto here, and the
//! presentation itself is opaque bytes. Layer order inside a DID-proof
//! payload is binding (optional), then VP (optional), then the payload.

use crate::IdentityError;

const MAGIC: &[u8] = b"SHADI-VP/1";

/// Maximum size of the whole VP layer.
pub const VP_MAX_BYTES: usize = 8192;

const FIELD: &[u8] = b"vp_token: ";

fn err(msg: &str) -> IdentityError {
    IdentityError::Proof(msg.to_string())
}

/// True when `bytes` start with the VP layer header.
pub fn looks_like_vp(bytes: &[u8]) -> bool {
    bytes.starts_with(MAGIC) && bytes.get(MAGIC.len()) == Some(&b'\n')
}

/// Frame `vp_token` as a header on `payload`.
pub fn wrap_vp(vp_token: &str, payload: &[u8]) -> Result<Vec<u8>, IdentityError> {
    if vp_token.is_empty() {
        return Err(err("vp_token cannot be empty"));
    }
    // A newline would let the caller forge extra layer lines.
    if vp_token.contains('\n') {
        return Err(err("vp_token cannot contain a newline"));
    }
    let layer_len = MAGIC.len() + 1 + FIELD.len() + vp_token.len() + 2;
    if layer_len > VP_MAX_BYTES {
        return Err(IdentityError::Proof(format!(
            "VP layer exceeds {VP_MAX_BYTES} bytes"
        )));
    }

    let mut out = Vec::with_capacity(layer_len + payload.len());
    out.extend_from_slice(MAGIC);
    out.push(b'\n');
    out.extend_from_slice(FIELD);
    out.extend_from_slice(vp_token.as_bytes());
    out.extend_from_slice(b"\n\n");
    out.extend_from_slice(payload);
    Ok(out)
}

/// Split the VP layer off, if there is one. An absent layer is not an error.
pub fn split_vp(bytes: &[u8]) -> Result<(Option<&str>, &[u8]), IdentityError> {
    if !looks_like_vp(bytes) {
        return Ok((None, bytes));
    }
    let start = MAGIC.len() + 1;
    // Never look past the cap, so a flood without a terminator is cheap.
    let window = &bytes[start..bytes.len().min(VP_MAX_BYTES + 1)];
    let line = window
        .strip_prefix(FIELD)
        .ok_or_else(|| err("VP layer is missing its vp_token"))?;
    let Some(len) = line.iter().position(|b| *b == b'\n') else {
        return Err(if bytes.len() > VP_MAX_BYTES {
            IdentityError::Proof(format!("VP layer exceeds {VP_MAX_BYTES} bytes"))
        } else {
            err("VP layer is truncated")
        });
    };
    let end = start + FIELD.len() + len + 2;
    if end > VP_MAX_BYTES {
        return Err(IdentityError::Proof(format!(
            "VP layer exceeds {VP_MAX_BYTES} bytes"
        )));
    }
    match bytes.get(end - 1) {
        Some(b'\n') => {}
        Some(_) => return Err(err("VP layer is missing its blank line")),
        None => return Err(err("VP layer is truncated")),
    }
    let token = std::str::from_utf8(&line[..len]).map_err(|_| err("vp_token is not UTF-8"))?;
    if token.is_empty() {
        return Err(err("vp_token cannot be empty"));
    }
    Ok((Some(token), &bytes[end..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_wrapped_presentation_splits_back_out() {
        let framed = wrap_vp("eyJhbGc.eyJpc3M.c2ln~ZGlzYw~", b"prompt\n\nwith blanks").unwrap();
        assert!(looks_like_vp(&framed));
        let (token, rest) = split_vp(&framed).unwrap();
        assert_eq!(token, Some("eyJhbGc.eyJpc3M.c2ln~ZGlzYw~"));
        assert_eq!(rest, b"prompt\n\nwith blanks");
    }

    #[test]
    fn an_empty_payload_round_trips() {
        let framed = wrap_vp("tok", b"").unwrap();
        assert_eq!(split_vp(&framed).unwrap(), (Some("tok"), &b""[..]));
    }

    #[test]
    fn an_absent_layer_is_not_an_error() {
        for payload in [&b""[..], b"plain prompt", b"\xff\xfe\x00", b"SHADI-VP/1"] {
            assert_eq!(split_vp(payload).unwrap(), (None, payload));
        }
    }

    #[test]
    fn a_payload_that_merely_contains_the_magic_is_not_split() {
        for payload in [
            &b"say SHADI-VP/1\nvp_token: x\n\nhi"[..],
            b" SHADI-VP/1\nvp_token: x\n\nhi",
            b"SHADI-VP/10\nvp_token: x\n\nhi",
        ] {
            assert!(!looks_like_vp(payload));
            assert_eq!(split_vp(payload).unwrap(), (None, payload));
        }
        // Wrapped, the inner lookalike stays payload.
        let inner = b"SHADI-VP/1\nvp_token: forged\n\nx";
        let framed = wrap_vp("real", inner).unwrap();
        assert_eq!(split_vp(&framed).unwrap(), (Some("real"), &inner[..]));
    }

    #[test]
    fn splitting_a_truncated_layer_fails() {
        let framed = wrap_vp("tok", b"").unwrap();
        // Every strict prefix that still has the header is a cut layer.
        for cut in (MAGIC.len() + 1)..framed.len() {
            assert!(
                split_vp(&framed[..cut]).is_err(),
                "cut {cut} accepted a truncated layer"
            );
        }
    }

    #[test]
    fn a_wrong_field_or_missing_blank_line_fails() {
        assert!(split_vp(b"SHADI-VP/1\nother: x\n\npayload").is_err());
        assert!(split_vp(b"SHADI-VP/1\nvp_token: x\npayload").is_err());
        assert!(split_vp(b"SHADI-VP/1\nvp_token: \n\npayload").is_err());
        assert!(split_vp(b"SHADI-VP/1\nvp_token: \xff\n\npayload").is_err());
    }

    #[test]
    fn wrapping_rejects_an_oversized_token() {
        let err = wrap_vp(&"a".repeat(VP_MAX_BYTES), b"").unwrap_err();
        assert!(err.to_string().contains("exceeds"), "should report the cap");
    }

    #[test]
    fn wrapping_rejects_a_newline_or_empty_token() {
        let err = wrap_vp("a\n\nforged", b"").unwrap_err();
        assert!(err.to_string().contains("newline"), "should report newline");
        assert!(wrap_vp("", b"").is_err());
    }

    #[test]
    fn splitting_stops_at_the_size_cap() {
        let mut flood = Vec::from(MAGIC);
        flood.push(b'\n');
        flood.extend_from_slice(FIELD);
        flood.extend(std::iter::repeat_n(b'a', VP_MAX_BYTES * 2));
        flood.extend_from_slice(b"\n\n");
        let err = split_vp(&flood).unwrap_err();
        assert!(err.to_string().contains("exceeds"), "should report the cap");

        // Terminated, but the layer itself runs past the cap.
        let mut long = Vec::from(&b"SHADI-VP/1\nvp_token: "[..]);
        long.extend(std::iter::repeat_n(b'a', VP_MAX_BYTES));
        long.extend_from_slice(b"\n\npayload");
        assert!(split_vp(&long).is_err());
    }

    #[test]
    fn the_largest_token_that_fits_round_trips() {
        let max = VP_MAX_BYTES - (MAGIC.len() + 1 + FIELD.len() + 2);
        let token = "a".repeat(max);
        let framed = wrap_vp(&token, b"p").unwrap();
        assert_eq!(
            split_vp(&framed).unwrap(),
            (Some(token.as_str()), &b"p"[..])
        );
        assert!(wrap_vp(&"a".repeat(max + 1), b"p").is_err());
    }
}
