//! `NAME=VALUE` mapping parsing shared by the CLI flags that name secrets.

use std::collections::HashMap;

/// Split one `KEY=NAME` argument, rejecting a missing `=` and an empty half.
///
/// `error` is the caller's flag-specific message, so `--trusted-secret` and
/// `--trusted-secret-fd-env` each report their own expected format.
pub fn parse_key_name<'a>(value: &'a str, error: &str) -> Result<(&'a str, &'a str), String> {
    let mut parts = value.splitn(2, '=');
    let key = parts.next().unwrap_or("");
    let name = parts.next().unwrap_or("");
    if key.is_empty() || name.is_empty() {
        return Err(error.to_string());
    }
    Ok((key, name))
}

/// Parse repeated `NAME=VALUE` arguments into a map, rejecting a duplicate
/// name rather than letting the last one win.
pub fn parse_name_mappings(
    values: &[String],
    error: &str,
) -> Result<HashMap<String, String>, String> {
    let mut mappings = HashMap::new();
    for value in values {
        let (name, mapped) = parse_key_name(value, error)?;
        if mappings
            .insert(name.to_string(), mapped.to_string())
            .is_some()
        {
            return Err(format!("{}: duplicate mapping for '{}'", error, name));
        }
    }
    Ok(mappings)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_name_mappings_requires_name_and_value() {
        let err = parse_name_mappings(&["broken".to_string()], "bad mapping").unwrap_err();
        assert!(err.contains("bad mapping"));
    }

    #[test]
    fn parse_name_mappings_rejects_duplicates() {
        let err = parse_name_mappings(
            &["token=TOKEN_FD".to_string(), "token=OTHER_FD".to_string()],
            "bad mapping",
        )
        .unwrap_err();
        assert!(err.contains("duplicate mapping"));
        assert!(err.contains("token"));
    }

    #[test]
    fn parse_key_name_splits_on_the_first_equals_only() {
        let (key, name) = parse_key_name("token=A=B", "bad").unwrap();
        assert_eq!(key, "token");
        assert_eq!(name, "A=B");
    }

    #[test]
    fn parse_key_name_rejects_an_empty_half() {
        assert!(parse_key_name("=NAME", "bad").is_err());
        assert!(parse_key_name("KEY=", "bad").is_err());
        assert!(parse_key_name("KEY", "bad").is_err());
        assert!(parse_key_name("", "bad").is_err());
    }
}
