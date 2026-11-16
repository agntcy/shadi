//! Turning a record, skill or agent name into a token a narrower namespace can
//! hold. The namespaces differ on purpose, so each caller passes its own set:
//!
//! - an agent id ([`slim_char`]) becomes a SLIM name component, a lease file
//!   name and a workload id, so it holds only ASCII letters, digits, `-`, `_`;
//! - a skill directory ([`file_char`]) also keeps `.`, as in `org.agntcy`,
//!   which a directory name can hold and SLIM can't.
//!
//! So `agntcy/k8s.troubleshoot` is the agent `agntcy-k8s-troubleshoot` and the
//! skill directory `agntcy-k8s.troubleshoot`.

/// A character a SLIM name component can hold.
pub(crate) fn slim_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '-' || c == '_'
}

/// A character a skill directory name keeps.
pub(crate) fn file_char(c: char) -> bool {
    slim_char(c) || c == '.'
}

/// `name` with each run of characters `keep` rejects replaced by one `-`.
/// The characters it keeps stay as they are, so names that differ only in
/// kept characters stay distinct.
pub(crate) fn replace_runs(name: &str, keep: impl Fn(char) -> bool) -> String {
    let mut out = String::with_capacity(name.len());
    let mut replacing = false;
    for c in name.chars() {
        if keep(c) {
            out.push(c);
            replacing = false;
        } else if !replacing {
            out.push('-');
            replacing = true;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_record_name_becomes_an_agent_id_and_a_skill_directory() {
        let name = "agntcy/k8s.troubleshoot";
        assert_eq!(replace_runs(name, slim_char), "agntcy-k8s-troubleshoot");
        assert_eq!(replace_runs(name, file_char), "agntcy-k8s.troubleshoot");
    }

    #[test]
    fn a_run_of_rejected_characters_becomes_one_dash() {
        assert_eq!(replace_runs("team :: reviewer", slim_char), "team-reviewer");
        assert_eq!(
            replace_runs("code--review_v2", slim_char),
            "code--review_v2"
        );
    }
}
