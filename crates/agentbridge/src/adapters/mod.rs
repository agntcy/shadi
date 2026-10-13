pub mod generic_stdio;
pub mod profile;
mod workdir;

use std::process::Command;

/// Keep the credential vault's database key out of an adapter subprocess.
///
/// Adapters inherit the parent's whole environment, and off macOS the secret
/// store is a no-op, so an environment variable is the only working carrier of
/// this key. A model subprocess that inherits it and can read the database file
/// has the credentials.
pub(crate) fn scrub_vault_env(command: &mut Command) {
    command.env_remove("SHADI_CREDENTIAL_KEY");
    command.env_remove("SHADI_MEMORY_KEY");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scrub_marks_the_vault_keys_for_removal() {
        let mut command = Command::new("true");
        command.env("SHADI_CREDENTIAL_KEY", "secret");
        command.env("SHADI_MEMORY_KEY", "secret");
        scrub_vault_env(&mut command);

        for name in ["SHADI_CREDENTIAL_KEY", "SHADI_MEMORY_KEY"] {
            let removed = command
                .get_envs()
                .any(|(key, value)| key == name && value.is_none());
            assert!(removed, "{name} is still passed to the child");
        }
    }
}
