// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! The embedded terminal (agntcy/shadi#122): `shadictl shell`, or another
//! `shadictl` invocation such as `-- <command>`, in a real PTY so the shell's
//! line editing, history and completion work. This is the one place the
//! Desktop runs the CLI instead of linking a crate, and it only ever runs
//! `shadictl`.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Mutex;

use portable_pty::{native_pty_system, ChildKiller, CommandBuilder, MasterPty, PtySize};
use serde::Serialize;
use tauri::ipc::Channel;

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TerminalEvent {
    Output { data: String },
    Exit { code: Option<u32> },
}

struct Terminal {
    master: Box<dyn MasterPty + Send>,
    writer: Box<dyn Write + Send>,
    killer: Box<dyn ChildKiller + Send + Sync>,
}

/// Registered with `.manage(...)`.
#[derive(Default)]
pub struct TerminalState {
    terminals: Mutex<HashMap<u32, Terminal>>,
    next: AtomicU32,
}

/// `SHADI_SHADICTL`, else `shadictl` on `PATH`, else where installers put it.
/// A GUI app's `PATH` often lacks the latter.
fn shadictl() -> PathBuf {
    if let Some(path) = std::env::var_os("SHADI_SHADICTL") {
        return PathBuf::from(path);
    }
    let exe = if cfg!(windows) {
        "shadictl.exe"
    } else {
        "shadictl"
    };
    let mut dirs: Vec<PathBuf> = std::env::var_os("PATH")
        .map(|path| std::env::split_paths(&path).collect())
        .unwrap_or_default();
    if let Some(home) = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")) {
        dirs.push(PathBuf::from(home).join(".cargo").join("bin"));
    }
    dirs.extend(["/opt/homebrew/bin", "/usr/local/bin"].map(PathBuf::from));
    dirs.into_iter()
        .map(|dir| dir.join(exe))
        .find(|path| path.is_file())
        .unwrap_or_else(|| PathBuf::from(exe))
}

/// Decode what `carry` and `chunk` hold, keeping an incomplete trailing
/// UTF-8 sequence for the next chunk.
fn decode(carry: &mut Vec<u8>, chunk: &[u8]) -> String {
    carry.extend_from_slice(chunk);
    let valid = match std::str::from_utf8(carry) {
        Ok(_) => carry.len(),
        Err(err) if err.error_len().is_none() => err.valid_up_to(),
        Err(_) => carry.len(),
    };
    let text = String::from_utf8_lossy(&carry[..valid]).into_owned();
    carry.drain(..valid);
    text
}

fn size(cols: u16, rows: u16) -> PtySize {
    PtySize {
        rows: rows.max(1),
        cols: cols.max(1),
        pixel_width: 0,
        pixel_height: 0,
    }
}

/// Run `program args` in a new pty, sending what it writes to `send` until it
/// exits or `send` returns false.
fn start(
    program: PathBuf,
    args: &[String],
    cols: u16,
    rows: u16,
    send: impl Fn(TerminalEvent) -> bool + Send + 'static,
) -> Result<Terminal, String> {
    let pair = native_pty_system()
        .openpty(size(cols, rows))
        .map_err(|e| format!("no pty: {e}"))?;
    let mut command = CommandBuilder::new(&program);
    command.args(args);
    command.env("TERM", "xterm-256color");
    if let Some(home) = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")) {
        command.cwd(home);
    }
    let mut child = pair
        .slave
        .spawn_command(command)
        .map_err(|e| format!("could not start {}: {e}", program.display()))?;
    // The child holds its own end; ours would keep the pty open after it exits.
    drop(pair.slave);

    let mut reader = pair.master.try_clone_reader().map_err(|e| e.to_string())?;
    let writer = pair.master.take_writer().map_err(|e| e.to_string())?;
    let killer = child.clone_killer();
    std::thread::Builder::new()
        .name("shadi-terminal".into())
        .spawn(move || {
            let mut carry = Vec::new();
            let mut buf = [0u8; 8192];
            while let Ok(n) = reader.read(&mut buf) {
                if n == 0 {
                    break;
                }
                let data = decode(&mut carry, &buf[..n]);
                if !data.is_empty() && !send(TerminalEvent::Output { data }) {
                    break;
                }
            }
            let code = child.wait().ok().map(|status| status.exit_code());
            send(TerminalEvent::Exit { code });
        })
        .map_err(|e| e.to_string())?;
    Ok(Terminal {
        master: pair.master,
        writer,
        killer,
    })
}

/// Start `shadictl <args>` (`shadictl shell` when `args` is empty) and stream
/// its output to `on_event`. Returns the terminal's id.
#[tauri::command]
pub async fn terminal_open(
    state: tauri::State<'_, TerminalState>,
    args: Vec<String>,
    cols: u16,
    rows: u16,
    on_event: Channel<TerminalEvent>,
) -> Result<u32, String> {
    let args = if args.is_empty() {
        vec!["shell".to_string()]
    } else {
        args
    };
    let terminal = start(shadictl(), &args, cols, rows, move |event| {
        on_event.send(event).is_ok()
    })?;
    let id = state.next.fetch_add(1, Ordering::SeqCst);
    state
        .terminals
        .lock()
        .map_err(|_| "terminal state poisoned")?
        .insert(id, terminal);
    Ok(id)
}

/// Send keystrokes to a terminal.
#[tauri::command]
pub async fn terminal_write(
    state: tauri::State<'_, TerminalState>,
    id: u32,
    data: String,
) -> Result<(), String> {
    let mut terminals = state
        .terminals
        .lock()
        .map_err(|_| "terminal state poisoned")?;
    let terminal = terminals
        .get_mut(&id)
        .ok_or_else(|| format!("no terminal {id}"))?;
    terminal
        .writer
        .write_all(data.as_bytes())
        .and_then(|()| terminal.writer.flush())
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn terminal_resize(
    state: tauri::State<'_, TerminalState>,
    id: u32,
    cols: u16,
    rows: u16,
) -> Result<(), String> {
    let terminals = state
        .terminals
        .lock()
        .map_err(|_| "terminal state poisoned")?;
    terminals
        .get(&id)
        .ok_or_else(|| format!("no terminal {id}"))?
        .master
        .resize(size(cols, rows))
        .map_err(|e| e.to_string())
}

/// Stop a terminal's process and forget it.
#[tauri::command]
pub async fn terminal_close(state: tauri::State<'_, TerminalState>, id: u32) -> Result<(), String> {
    let terminal = state
        .terminals
        .lock()
        .map_err(|_| "terminal state poisoned")?
        .remove(&id);
    if let Some(mut terminal) = terminal {
        let _ = terminal.killer.kill();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_character_split_across_chunks_is_kept_whole() {
        let bytes = "héllo ✓".as_bytes();
        let split = bytes.len() - 2;
        let mut carry = Vec::new();
        let first = decode(&mut carry, &bytes[..split]);
        let second = decode(&mut carry, &bytes[split..]);
        assert_eq!(format!("{first}{second}"), "héllo ✓");
        assert!(carry.is_empty());

        assert_eq!(decode(&mut carry, b"a\xffb"), "a\u{fffd}b");
    }

    #[cfg(unix)]
    #[test]
    fn a_program_in_the_pty_streams_its_output_and_exit() {
        let (tx, rx) = std::sync::mpsc::channel();
        let terminal = start(
            PathBuf::from("/bin/echo"),
            &["hello from the pty".to_string()],
            80,
            24,
            move |event| tx.send(event).is_ok(),
        )
        .unwrap();
        let mut output = String::new();
        loop {
            match rx.recv_timeout(std::time::Duration::from_secs(10)).unwrap() {
                TerminalEvent::Output { data } => output.push_str(&data),
                TerminalEvent::Exit { code } => {
                    assert_eq!(code, Some(0));
                    break;
                }
            }
        }
        assert!(output.contains("hello from the pty"), "{output:?}");
        drop(terminal);
    }

    #[test]
    fn the_terminal_runs_shadictl_from_an_override() {
        let dir = tempfile::tempdir().unwrap();
        let fake = dir.path().join("shadictl");
        std::env::set_var("SHADI_SHADICTL", &fake);
        assert_eq!(shadictl(), fake);
        std::env::remove_var("SHADI_SHADICTL");
    }
}
