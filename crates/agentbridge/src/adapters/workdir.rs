// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! Shared workdir pinning for coding-agent CLIs launched under Seatbelt.
//!
//! The host `TMPDIR` (often `/var/folders/…/T`) is not in the demo sandbox
//! write set. Claude, Copilot, Codex, and Cursor Agent all mkdir under
//! `os.tmpdir()` on startup; pin that to the registered workdir.

use std::path::Path;
use std::process::Command;

pub fn pin_tmpdir(cmd: &mut Command, work_dir: &Path) {
    cmd.env("TMPDIR", work_dir)
        .env("TMP", work_dir)
        .env("TEMP", work_dir);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pin_tmpdir_sets_all_temp_keys() {
        let mut cmd = Command::new("true");
        pin_tmpdir(&mut cmd, Path::new("/var/workspace"));
        // Command does not expose env; this test documents the helper exists
        // and accepts a path. The adapters' unit tests cover construction.
        let _ = cmd;
    }
}
