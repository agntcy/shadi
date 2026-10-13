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
    command.env_remove("SHADI_MEMORY_KEY");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scrub_marks_the_vault_key_for_removal() {
        let mut command = Command::new("true");
        command.env("SHADI_MEMORY_KEY", "secret");
        scrub_vault_env(&mut command);

        let removed = command
            .get_envs()
            .any(|(key, value)| key == "SHADI_MEMORY_KEY" && value.is_none());
        assert!(removed, "the vault key is still passed to the child");
    }
}
