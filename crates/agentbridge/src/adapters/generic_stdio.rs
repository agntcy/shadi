use serde::{Deserialize, Serialize};
use shadi_mas::AgentId;
use std::{
    io::{BufRead, BufReader, Read, Write},
    process::{Child, Command, Stdio},
    sync::Mutex,
};

use crate::{
    adapter::{CliAdapter, CliAdapterError},
    context::ContextPacket,
};

// --- Wire protocol ----------------------------------------------------------
//
// Newline-delimited JSON on stdin/stdout.
//
// Requests (agentbridge → subprocess stdin):
//   {"cmd":"snapshot"}
//   {"cmd":"inject","context":{...}}
//   {"cmd":"execute","prompt":"..."}
//
// Responses (subprocess stdout → agentbridge):
//   {"ok":true,"data":<value>}
//   {"ok":false,"error":"<message>"}

#[derive(Serialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
enum Request<'a> {
    Snapshot,
    Inject { context: &'a ContextPacket },
    Execute { prompt: &'a str },
}

/// Maximum bytes accepted for one response line, including the newline.
/// Mirrors `shadi_sandbox::control::CONTROL_LINE_MAX_BYTES`: a subprocess
/// that never emits a newline must not be able to grow this buffer without
/// bound.
pub const STDIO_LINE_MAX_BYTES: usize = 64 * 1024;

#[derive(Debug, Deserialize)]
pub struct Response {
    pub ok: bool,
    #[serde(default)]
    pub data: serde_json::Value,
    #[serde(default)]
    pub error: Option<String>,
}

/// Read one newline-terminated response from `reader` and decode it.
///
/// Rejects a line longer than [`STDIO_LINE_MAX_BYTES`] instead of buffering
/// whatever the subprocess sends.
pub fn read_response<R: BufRead>(reader: &mut R) -> Result<Response, CliAdapterError> {
    let mut buf = String::new();
    let read = Read::take(&mut *reader, STDIO_LINE_MAX_BYTES as u64 + 1).read_line(&mut buf)?;
    if read == 0 {
        return Err(CliAdapterError::Protocol(
            "subprocess closed stdout before answering".to_string(),
        ));
    }
    if read > STDIO_LINE_MAX_BYTES {
        return Err(CliAdapterError::Protocol(format!(
            "response line exceeds {STDIO_LINE_MAX_BYTES} bytes"
        )));
    }
    Ok(serde_json::from_str(buf.trim())?)
}

// --- I/O abstraction --------------------------------------------------------

struct Io {
    writer: Box<dyn Write + Send>,
    reader: BufReader<Box<dyn Read + Send>>,
}

impl Io {
    fn from_process(child: &mut Child) -> Result<Self, CliAdapterError> {
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| CliAdapterError::Subprocess("no stdin on child process".to_string()))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| CliAdapterError::Subprocess("no stdout on child process".to_string()))?;
        Ok(Self {
            writer: Box::new(stdin),
            reader: BufReader::new(Box::new(stdout)),
        })
    }

    #[cfg(test)]
    fn from_buffers(
        writer: impl Write + Send + 'static,
        reader: impl Read + Send + 'static,
    ) -> Self {
        Self {
            writer: Box::new(writer),
            reader: BufReader::new(Box::new(reader)),
        }
    }
}

// --- Adapter ----------------------------------------------------------------

/// Generic CLI adapter that communicates with a subprocess via the
/// newline-delimited JSON protocol defined in this module.
///
/// Any tool that implements the three-command protocol can be driven by this
/// adapter. Argv-driven coding CLIs use `ProfileAdapter` and a JSON profile.
pub struct GenericStdioAdapter {
    id: AgentId,
    /// Held to keep the subprocess alive; not accessed after spawning.
    _child: Option<Mutex<Child>>,
    io: Mutex<Io>,
}

impl GenericStdioAdapter {
    /// Spawn `command` (with optional `args`) and return an adapter bound to
    /// that subprocess.
    pub fn spawn(
        id: impl Into<String>,
        command: &str,
        args: &[&str],
    ) -> Result<Self, CliAdapterError> {
        let mut child = Command::new(command)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()?;

        let io = Io::from_process(&mut child)?;

        Ok(Self {
            id: AgentId(id.into()),
            _child: Some(Mutex::new(child)),
            io: Mutex::new(io),
        })
    }

    fn send_request(&self, req: &Request<'_>) -> Result<Response, CliAdapterError> {
        let mut io = self
            .io
            .lock()
            .map_err(|_| CliAdapterError::Subprocess("io lock poisoned".to_string()))?;

        let line = serde_json::to_string(req)?;
        writeln!(io.writer, "{line}").map_err(|e| CliAdapterError::Subprocess(e.to_string()))?;
        io.writer
            .flush()
            .map_err(|e| CliAdapterError::Subprocess(e.to_string()))?;

        read_response(&mut io.reader)
    }
}

impl CliAdapter for GenericStdioAdapter {
    fn agent_id(&self) -> &AgentId {
        &self.id
    }

    fn snapshot_context(&self) -> Result<ContextPacket, CliAdapterError> {
        let resp = self.send_request(&Request::Snapshot)?;
        if !resp.ok {
            return Err(CliAdapterError::Protocol(
                resp.error.unwrap_or_else(|| "snapshot failed".to_string()),
            ));
        }
        Ok(serde_json::from_value(resp.data)?)
    }

    fn inject_context(&self, ctx: &ContextPacket) -> Result<(), CliAdapterError> {
        let resp = self.send_request(&Request::Inject { context: ctx })?;
        if !resp.ok {
            return Err(CliAdapterError::Protocol(
                resp.error.unwrap_or_else(|| "inject failed".to_string()),
            ));
        }
        Ok(())
    }

    fn execute_prompt(&self, prompt: &str) -> Result<String, CliAdapterError> {
        let resp = self.send_request(&Request::Execute { prompt })?;
        if !resp.ok {
            return Err(CliAdapterError::Protocol(
                resp.error.unwrap_or_else(|| "execute failed".to_string()),
            ));
        }
        Ok(match resp.data {
            serde_json::Value::String(s) => s,
            other => other.to_string(),
        })
    }
}

// --- Tests ------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn make_adapter(response_json: &str) -> GenericStdioAdapter {
        // Pre-load a Cursor with the server's canned response.
        let reader = Cursor::new(format!("{response_json}\n").into_bytes());
        // Writer goes to a Vec we don't inspect (request serialization is
        // tested separately via the Request serde).
        let writer = Vec::<u8>::new();

        GenericStdioAdapter {
            id: AgentId("test".to_string()),
            _child: None,
            io: Mutex::new(Io::from_buffers(writer, reader)),
        }
    }

    #[test]
    fn read_response_rejects_a_line_over_the_cap() {
        let mut line = vec![b'a'; STDIO_LINE_MAX_BYTES + 1];
        line.push(b'\n');
        let err = read_response(&mut line.as_slice()).unwrap_err();
        assert!(
            err.to_string().contains("exceeds"),
            "oversize line should be rejected by the cap, got: {err}"
        );
    }

    /// Serves `a` forever and trips if asked for more than `limit` bytes, so a
    /// reader that buffers without bound fails the test instead of hanging.
    struct EndlessReader {
        served: usize,
        limit: usize,
    }

    impl Read for EndlessReader {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.served += buf.len();
            assert!(
                self.served <= self.limit,
                "read_response pulled {} bytes from a subprocess that never sent a newline",
                self.served
            );
            buf.fill(b'a');
            Ok(buf.len())
        }
    }

    #[test]
    fn read_response_stops_pulling_from_a_subprocess_that_never_sends_a_newline() {
        let mut reader = BufReader::new(EndlessReader {
            served: 0,
            limit: 1024 * 1024,
        });
        let err = read_response(&mut reader).unwrap_err();
        assert!(
            err.to_string().contains("exceeds"),
            "an endless line must be rejected by the cap, got: {err}"
        );
    }

    #[test]
    fn read_response_reports_eof_rather_than_a_parse_error() {
        let err = read_response(&mut b"".as_slice()).unwrap_err();
        assert!(
            err.to_string().contains("closed stdout"),
            "EOF should name the closed subprocess, got: {err}"
        );
    }

    #[test]
    fn execute_prompt_parses_ok_string_response() {
        let pkt = ContextPacket::new("test");
        let data = serde_json::to_string(&pkt).unwrap();
        let resp = format!(r#"{{"ok":true,"data":{data}}}"#);
        let adapter = make_adapter(&resp);
        // snapshot_context should parse the pre-loaded ContextPacket.
        let result = adapter.snapshot_context();
        assert!(result.is_ok(), "{result:?}");
        assert_eq!(result.unwrap().source_agent, "test");
    }

    #[test]
    fn execute_prompt_returns_error_on_not_ok() {
        let adapter = make_adapter(r#"{"ok":false,"error":"boom"}"#);
        let result = adapter.execute_prompt("hello");
        assert!(matches!(result, Err(CliAdapterError::Protocol(msg)) if msg == "boom"));
    }

    #[test]
    fn request_snapshot_serializes_correctly() {
        let json = serde_json::to_string(&Request::Snapshot).unwrap();
        assert_eq!(json, r#"{"cmd":"snapshot"}"#);
    }

    #[test]
    fn request_execute_serializes_correctly() {
        let json = serde_json::to_string(&Request::Execute { prompt: "hello" }).unwrap();
        assert_eq!(json, r#"{"cmd":"execute","prompt":"hello"}"#);
    }

    #[test]
    fn request_inject_serializes_correctly() {
        let pkt = ContextPacket::new("src");
        let json = serde_json::to_string(&Request::Inject { context: &pkt }).unwrap();
        assert!(json.contains(r#""cmd":"inject""#));
        assert!(json.contains("src"));
    }

    #[test]
    fn snapshot_context_returns_error_on_not_ok() {
        let adapter = make_adapter(r#"{"ok":false,"error":"snap-fail"}"#);
        let result = adapter.snapshot_context();
        assert!(matches!(result, Err(CliAdapterError::Protocol(msg)) if msg == "snap-fail"));
    }

    #[test]
    fn snapshot_context_uses_default_error_when_no_error_field() {
        let adapter = make_adapter(r#"{"ok":false}"#);
        let result = adapter.snapshot_context();
        assert!(matches!(result, Err(CliAdapterError::Protocol(msg)) if msg == "snapshot failed"));
    }

    #[test]
    fn inject_context_ok_returns_unit() {
        let adapter = make_adapter(r#"{"ok":true}"#);
        let pkt = ContextPacket::new("src");
        assert!(adapter.inject_context(&pkt).is_ok());
    }

    #[test]
    fn inject_context_returns_error_on_not_ok() {
        let adapter = make_adapter(r#"{"ok":false,"error":"inject-fail"}"#);
        let pkt = ContextPacket::new("src");
        let result = adapter.inject_context(&pkt);
        assert!(matches!(result, Err(CliAdapterError::Protocol(msg)) if msg == "inject-fail"));
    }

    #[test]
    fn inject_context_uses_default_error_when_no_error_field() {
        let adapter = make_adapter(r#"{"ok":false}"#);
        let pkt = ContextPacket::new("src");
        let result = adapter.inject_context(&pkt);
        assert!(matches!(result, Err(CliAdapterError::Protocol(msg)) if msg == "inject failed"));
    }

    #[test]
    fn execute_prompt_returns_string_response() {
        let adapter = make_adapter(r#"{"ok":true,"data":"fn answer() {}"}"#);
        let result = adapter.execute_prompt("write a function");
        assert_eq!(result.unwrap(), "fn answer() {}");
    }

    #[test]
    fn execute_prompt_stringifies_non_string_json_data() {
        // When data is a JSON object (not a plain string), it is serialized to string.
        let adapter = make_adapter(r#"{"ok":true,"data":{"key":"value"}}"#);
        let result = adapter.execute_prompt("any");
        let text = result.unwrap();
        assert!(text.contains("key"));
        assert!(text.contains("value"));
    }

    #[test]
    fn execute_prompt_uses_default_error_when_no_error_field() {
        let adapter = make_adapter(r#"{"ok":false}"#);
        let result = adapter.execute_prompt("prompt");
        assert!(matches!(result, Err(CliAdapterError::Protocol(msg)) if msg == "execute failed"));
    }

    #[test]
    fn agent_id_returns_configured_id() {
        let adapter = make_adapter(r#"{"ok":true}"#);
        assert_eq!(adapter.agent_id().0, "test");
    }

    #[test]
    fn spawn_with_real_process_succeeds() {
        // Spawn a real subprocess (cat) to exercise the production spawn path.
        // We don't send any commands — just verify the adapter was constructed.
        let result = GenericStdioAdapter::spawn("cat-adapter", "cat", &[]);
        assert!(result.is_ok(), "spawn failed");
        // Drop the adapter to close stdin and let cat exit.
    }
}
