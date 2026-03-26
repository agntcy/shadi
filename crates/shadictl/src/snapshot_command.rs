// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! Shell commands for browsing git snapshot artifacts.

use std::path::PathBuf;

use serde_json::Value;

fn default_snapshot_dir() -> PathBuf {
    std::env::var_os("SHADI_TMP_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("./.tmp"))
        .join("git-snapshots")
}

pub(crate) fn snapshot_list(dir_override: Option<&str>) {
    let dir = dir_override
        .map(PathBuf::from)
        .unwrap_or_else(default_snapshot_dir);
    let runs_dir = dir.join("runs");

    if !runs_dir.exists() {
        eprintln!("no snapshots found ({})", runs_dir.display());
        return;
    }

    let mut entries = Vec::new();
    if let Ok(read_dir) = std::fs::read_dir(&runs_dir) {
        for entry in read_dir.flatten() {
            let snapshot_file = entry.path().join("snapshot.json");
            if let Ok(data) = std::fs::read_to_string(&snapshot_file) {
                if let Ok(value) = serde_json::from_str::<Value>(&data) {
                    entries.push(value);
                }
            }
        }
    }

    entries.sort_by(|a, b| {
        let a_ts = a
            .pointer("/timestamps/started_at_ms")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let b_ts = b
            .pointer("/timestamps/started_at_ms")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        b_ts.cmp(&a_ts)
    });

    if entries.is_empty() {
        println!("no snapshots found");
        return;
    }

    println!(
        "{:<50} {:<9} {:<6} {}",
        "ARTIFACT ID", "CHANGED", "EXIT", "COMMAND"
    );
    for entry in &entries {
        let id = entry["artifact_id"].as_str().unwrap_or("?");
        let changed = entry
            .pointer("/git/any_repo_changed")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let exit_code = entry
            .pointer("/outcome/exit_code")
            .and_then(|v| v.as_i64());
        let cmd = entry["command"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str())
                    .collect::<Vec<_>>()
                    .join(" ")
            })
            .unwrap_or_default();

        println!(
            "{:<50} {:<9} {:<6} {}",
            id,
            if changed { "yes" } else { "no" },
            exit_code
                .map(|c| c.to_string())
                .unwrap_or_else(|| "-".to_string()),
            cmd,
        );
    }
    println!("\n{} snapshot(s)", entries.len());
}

pub(crate) fn snapshot_show(id: &str, dir_override: Option<&str>) {
    let dir = dir_override
        .map(PathBuf::from)
        .unwrap_or_else(default_snapshot_dir);

    let path = if id == "latest" {
        dir.join("latest.json")
    } else {
        dir.join("runs").join(id).join("snapshot.json")
    };

    if !path.exists() {
        eprintln!("snapshot not found: {}", path.display());
        return;
    }

    match std::fs::read_to_string(&path) {
        Ok(data) => match serde_json::from_str::<Value>(&data) {
            Ok(value) => print_snapshot_summary(&value),
            Err(err) => eprintln!("invalid snapshot data: {}", err),
        },
        Err(err) => eprintln!("failed to read snapshot: {}", err),
    }
}

fn print_snapshot_summary(snapshot: &Value) {
    let id = snapshot["artifact_id"].as_str().unwrap_or("?");
    let cmd = snapshot["command"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str())
                .collect::<Vec<_>>()
                .join(" ")
        })
        .unwrap_or_else(|| "?".to_string());
    let exit_code = snapshot
        .pointer("/outcome/exit_code")
        .and_then(|v| v.as_i64());
    let error = snapshot
        .pointer("/outcome/error")
        .and_then(|v| v.as_str());
    let duration_ms = snapshot
        .pointer("/timestamps/duration_ms")
        .and_then(|v| v.as_u64());
    let changed = snapshot
        .pointer("/git/any_repo_changed")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let repos_changed = snapshot
        .pointer("/git/changed_repositories")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    println!("Snapshot: {}", id);
    println!("Command:  {}", cmd);
    if let Some(code) = exit_code {
        println!("Exit:     {}", code);
    }
    if let Some(err) = error {
        println!("Error:    {}", err);
    }
    if let Some(ms) = duration_ms {
        println!("Duration: {} ms", format_duration(ms));
    }
    println!();

    if changed {
        println!("Git changes detected ({} repository/ies changed):", repos_changed);
        print_repositories(snapshot);
    } else {
        println!("No git changes detected");
    }

    // Show snapshot file location.
    if let Some(file) = snapshot.pointer("/layout/snapshot_file").and_then(|v| v.as_str()) {
        println!("\nArtifact: {}", file);
    }
}

fn print_repositories(snapshot: &Value) {
    let repos = match snapshot.pointer("/git/repositories").and_then(|v| v.as_array()) {
        Some(repos) => repos,
        None => {
            // Fall back to top-level diff_summary.
            if let Some(diff) = snapshot.pointer("/git/diff_summary") {
                print_diff_summary(diff, "  ");
            }
            return;
        }
    };

    for repo in repos {
        let root = repo["relative_path"].as_str().unwrap_or(".");
        let repo_changed = repo
            .pointer("/comparison/overall_changed")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        println!("  {} {}", root, if repo_changed { "(changed)" } else { "(unchanged)" });

        if let Some(comp) = repo.get("comparison") {
            if comp["head_changed"].as_bool().unwrap_or(false) {
                let before = repo
                    .pointer("/before/head")
                    .and_then(|v| v.as_str())
                    .unwrap_or("?");
                let after = repo
                    .pointer("/after/head")
                    .and_then(|v| v.as_str())
                    .unwrap_or("?");
                println!("    HEAD: {} → {}", &before[..7.min(before.len())], &after[..7.min(after.len())]);
            }
        }

        if let Some(diff) = repo.get("diff_summary") {
            print_diff_summary(diff, "    ");
        }
    }
}

fn print_diff_summary(diff: &Value, indent: &str) {
    let fields = [
        ("added", "Added"),
        ("modified", "Modified"),
        ("deleted", "Deleted"),
        ("renamed", "Renamed"),
        ("untracked", "Untracked"),
    ];
    for (key, label) in fields {
        let count = diff[key].as_u64().unwrap_or(0);
        if count > 0 {
            println!("{}{:<12} {}", indent, label, count);
        }
    }
}

fn format_duration(ms: u64) -> String {
    if ms < 1000 {
        format!("{}", ms)
    } else if ms < 60_000 {
        format!("{:.1}s", ms as f64 / 1000.0)
    } else {
        let mins = ms / 60_000;
        let secs = (ms % 60_000) / 1000;
        format!("{}m {:02}s", mins, secs)
    }
}

pub(crate) fn format_bytes(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{} B", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.2} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn format_bytes_formats_human_readable() {
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(2048), "2.0 KB");
        assert_eq!(format_bytes(5 * 1024 * 1024), "5.0 MB");
        assert_eq!(format_bytes(2 * 1024 * 1024 * 1024), "2.00 GB");
    }

    #[test]
    fn format_duration_formats_human_readable() {
        assert_eq!(format_duration(500), "500");
        assert_eq!(format_duration(1500), "1.5s");
        assert_eq!(format_duration(90_000), "1m 30s");
    }

    #[test]
    fn snapshot_list_handles_missing_directory() {
        // Should not panic, just print a message.
        snapshot_list(Some("/tmp/shadi-nonexistent-snapshot-dir-test"));
    }

    #[test]
    fn snapshot_show_handles_missing_file() {
        snapshot_show("nonexistent-id", Some("/tmp/shadi-nonexistent-snapshot-dir-test"));
    }

    #[test]
    fn snapshot_show_handles_latest_alias() {
        snapshot_show("latest", Some("/tmp/shadi-nonexistent-snapshot-dir-test"));
    }

    #[test]
    fn print_snapshot_summary_formats_output() {
        let snapshot = json!({
            "artifact_id": "1234567890-42-bash",
            "command": ["bash", "demo.sh"],
            "timestamps": {
                "started_at_ms": 1234567890000u64,
                "duration_ms": 5234u64,
            },
            "outcome": {
                "exit_code": 0,
            },
            "git": {
                "any_repo_changed": true,
                "changed_repositories": 1,
                "diff_summary": {
                    "added": 2,
                    "modified": 3,
                    "deleted": 0,
                    "renamed": 0,
                    "untracked": 1,
                    "changed": true,
                },
            },
            "layout": {
                "snapshot_file": "/tmp/snapshot.json",
            },
        });
        // Should not panic.
        print_snapshot_summary(&snapshot);
    }

    #[test]
    fn print_snapshot_summary_with_repositories() {
        let snapshot = json!({
            "artifact_id": "test-id",
            "command": ["python3", "agent.py"],
            "timestamps": { "started_at_ms": 100u64, "duration_ms": 200u64 },
            "outcome": { "exit_code": 1, "error": "crash" },
            "git": {
                "any_repo_changed": true,
                "changed_repositories": 1,
                "repositories": [{
                    "repo_root": "/work",
                    "relative_path": ".",
                    "comparison": {
                        "overall_changed": true,
                        "head_changed": true,
                    },
                    "before": { "head": "abc1234def" },
                    "after": { "head": "bcd2345efg" },
                    "diff_summary": {
                        "added": 1,
                        "modified": 0,
                        "deleted": 0,
                        "renamed": 0,
                        "untracked": 0,
                        "changed": true,
                    },
                }],
            },
        });
        print_snapshot_summary(&snapshot);
    }

    #[test]
    fn print_snapshot_summary_no_changes() {
        let snapshot = json!({
            "artifact_id": "no-change",
            "command": ["echo", "hi"],
            "timestamps": { "started_at_ms": 100u64 },
            "outcome": {},
            "git": { "any_repo_changed": false, "changed_repositories": 0 },
        });
        print_snapshot_summary(&snapshot);
    }

    #[test]
    fn default_snapshot_dir_returns_path() {
        let dir = default_snapshot_dir();
        assert!(dir.to_string_lossy().contains("git-snapshots"));
    }
}
