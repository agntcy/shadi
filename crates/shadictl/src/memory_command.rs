use super::*;

pub(crate) fn run_memory_command(cli: MemoryCli) -> ExitCode {
    let key = match resolve_memory_key(&cli) {
        Ok(key) => key,
        Err(err) => {
            eprintln!("{}", err);
            return ExitCode::from(1);
        }
    };

    let store = match SqlCipherStore::open(&cli.db, &key) {
        Ok(store) => store,
        Err(err) => {
            eprintln!("{}", err);
            return ExitCode::from(1);
        }
    };

    match handle_memory_command(&cli, &store) {
        Ok(output) => {
            println!("{}", output);
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("{}", err);
            ExitCode::from(1)
        }
    }
}

pub(crate) fn handle_memory_command(cli: &MemoryCli, store: &SqlCipherStore) -> Result<String, String> {
    let span = info_span!(
        "shadi.memory.command",
        memory.command = field::Empty,
        memory.scope = field::Empty,
        memory.entry_key = field::Empty,
        memory.limit = field::Empty,
        memory.query = field::Empty,
    );
    let _guard = span.enter();

    match &cli.command {
        MemoryCommand::Init => {
            span.record("memory.command", &"init");
            Ok("ok".to_string())
        }
        MemoryCommand::Put {
            scope,
            entry_key,
            payload,
            payload_file,
        } => {
            span.record("memory.command", &"put");
            span.record("memory.scope", &field::display(scope));
            span.record("memory.entry_key", &field::display(entry_key));
            let payload = read_memory_payload(payload.clone(), payload_file.clone())?;
            let id = store
                .put(scope, entry_key, &payload)
                .map_err(|err| err.to_string())?;
            Ok(serde_json::json!({"status": "saved", "id": id}).to_string())
        }
        MemoryCommand::Get { scope, entry_key } => {
            span.record("memory.command", &"get");
            span.record("memory.scope", &field::display(scope));
            span.record("memory.entry_key", &field::display(entry_key));
            let entry = store
                .get_latest(scope, entry_key)
                .map_err(|err| err.to_string())?;
            match entry {
                Some(entry) => serde_json::to_string_pretty(&entry).map_err(|err| err.to_string()),
                None => Ok(serde_json::json!({"found": false}).to_string()),
            }
        }
        MemoryCommand::Search {
            scope,
            query,
            limit,
        } => {
            span.record("memory.command", &"search");
            if let Some(scope) = scope.as_ref() {
                span.record("memory.scope", &field::display(scope));
            }
            span.record("memory.query", &field::display(query));
            span.record("memory.limit", &(*limit as i64));
            let entries = store
                .search(scope.as_deref(), query, *limit)
                .map_err(|err| err.to_string())?;
            format_memory_entries(entries)
        }
        MemoryCommand::List { scope, limit } => {
            span.record("memory.command", &"list");
            if let Some(scope) = scope.as_ref() {
                span.record("memory.scope", &field::display(scope));
            }
            span.record("memory.limit", &(*limit as i64));
            let entries = store
                .list(scope.as_deref(), *limit)
                .map_err(|err| err.to_string())?;
            format_memory_entries(entries)
        }
        MemoryCommand::Delete { scope, entry_key } => {
            span.record("memory.command", &"delete");
            span.record("memory.scope", &field::display(scope));
            span.record("memory.entry_key", &field::display(entry_key));
            let affected = store
                .delete(scope, entry_key)
                .map_err(|err| err.to_string())?;
            Ok(serde_json::json!({"deleted": affected}).to_string())
        }
    }
}

pub(crate) fn resolve_memory_key(cli: &MemoryCli) -> Result<String, String> {
    if let Some(key) = cli.key.as_ref() {
        if key.is_empty() {
            return Err("SHADI_MEMORY_KEY is empty".to_string());
        }
        return Ok(key.to_string());
    }

    let store = default_secret_store();
    let secret = store
        .get(&cli.key_name)
        .map_err(|_| format!("missing SHADI key: {}", cli.key_name))?;
    let raw = secret.expose(|bytes| bytes.to_vec());
    String::from_utf8(raw).map_err(|_| "SHADI memory key is not utf-8".to_string())
}

pub(crate) fn read_memory_payload(
    payload: Option<String>,
    payload_file: Option<PathBuf>,
) -> Result<String, String> {
    match (payload, payload_file) {
        (Some(text), None) => Ok(text),
        (None, Some(path)) => std::fs::read_to_string(&path)
            .map_err(|err| format!("failed to read payload file: {}", err)),
        (None, None) => Err("payload or payload-file must be provided".to_string()),
        (Some(_), Some(_)) => Err("use either payload or payload-file".to_string()),
    }
}

pub(crate) fn format_memory_entries(entries: Vec<MemoryEntry>) -> Result<String, String> {
    serde_json::to_string_pretty(&entries).map_err(|err| err.to_string())
}
