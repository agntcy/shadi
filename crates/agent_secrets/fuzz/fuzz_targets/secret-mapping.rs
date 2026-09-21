#![no_main]

use libfuzzer_sys::fuzz_target;

use agent_secrets::parse_name_mappings;

const ERROR: &str = "trusted-secret must be in KEY=NAME format";

// These strings arrive as repeated `--trusted-secret` / `--trusted-secret-fd-env`
// flags, and each accepted pair names a secret that shadictl will hand to a
// sandboxed child. A duplicate that silently resolves to the last value would
// let a second flag redirect a name the operator already bound, so a map that
// comes back must account for every argument exactly once.
fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };

    let values: Vec<String> = text.split('\n').map(str::to_string).collect();
    let Ok(mappings) = parse_name_mappings(&values, ERROR) else {
        return;
    };

    assert_eq!(
        mappings.len(),
        values.len(),
        "parse_name_mappings collapsed {} arguments into {} entries: {values:?}",
        values.len(),
        mappings.len()
    );

    for value in &values {
        let (name, mapped) = value
            .split_once('=')
            .expect("an accepted argument contains a separator");
        assert!(
            !name.is_empty() && !mapped.is_empty(),
            "accepted argument {value:?} has an empty half"
        );
        assert_eq!(
            mappings.get(name).map(String::as_str),
            Some(mapped),
            "argument {value:?} did not land in the map under its own name"
        );
    }
});
