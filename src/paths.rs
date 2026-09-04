//! Where E-OS Guard keeps its baseline database. A product decision, kept OUT of the
//! shared engine crate on purpose (`crates/eos-fsintegrity/src/lib.rs`): the path is the
//! only place where "one engine" could quietly become "one file for every product".
//!
//! The value is byte-for-byte what `db::default_path()` returned before `PR-004`; whether
//! Guard and Control should keep sharing this file is an open owner decision, and this
//! module changes nothing about it.

use std::path::{Path, PathBuf};

/// `$HOME/.local/share/eos-guard/baseline.db`, or `/tmp/eos-guard.db` without a `HOME`.
pub fn baseline_db() -> PathBuf {
    match std::env::var_os("HOME") {
        Some(home) => Path::new(&home)
            .join(".local")
            .join("share")
            .join("eos-guard")
            .join("baseline.db"),
        None => PathBuf::from("/tmp/eos-guard.db"),
    }
}

#[cfg(test)]
mod tests {
    use super::baseline_db;

    /// The path this product opens is the one its README documents, and the one it opened
    /// before the engine moved out. This is what pins "same file as before" (no HOME
    /// juggling: the test process has one, and the suffix is what matters).
    #[test]
    fn the_baseline_lives_where_it_always_did() {
        let p = baseline_db();
        let s = p.to_string_lossy();
        assert!(
            s.ends_with("/.local/share/eos-guard/baseline.db") || s == "/tmp/eos-guard.db",
            "{s}"
        );
    }
}
