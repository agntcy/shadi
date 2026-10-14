pub mod generic_stdio;
pub mod profile;
mod workdir;

use std::process::Command;

/// Keep the vault database keys out of an adapter subprocess.
///
/// A child inherits the whole environment, and a child holding a key and able
/// to read the database file holds its contents.
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
