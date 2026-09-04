//! E-OS file-integrity engine — the code that was `src/{scan,db}.rs` in both
//! `eos-guard` and `eos-control` (ROADMAP `PR-004`: one engine, not two copies).
//!
//! [`scan`] walks a set of directories and blake3-hashes every regular file, flagging
//! setuid/setgid/world-writable ones on the way. [`db`] keeps the result as a
//! tamper-evident SQLite (WAL) baseline and diffs a later scan against it.
//!
//! Deliberately NOT here: where the baseline database lives on disk. That is a
//! product decision (each product keeps its own `paths.rs`), and it must stay outside
//! this crate so that sharing the engine does not silently become sharing the file.

pub mod db;
pub mod scan;

/// Cap on the number of files a single GUI scan hashes, so pointing a product at a huge
/// tree cannot wedge its single-threaded event loop. Both products used this value.
pub const DEFAULT_SCAN_BUDGET: usize = 20_000;

/// The roots field of both products is comma-separated free text. Split it, trim each
/// piece, drop the empties; order and duplicates are left to [`db::canonical_roots`].
pub fn parse_roots(s: &str) -> Vec<String> {
    s.split(',')
        .map(|r| r.trim())
        .filter(|r| !r.is_empty())
        .map(str::to_string)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::parse_roots;

    #[test]
    fn roots_are_split_on_commas_and_trimmed() {
        assert_eq!(parse_roots(" /usr/bin , /etc"), vec!["/usr/bin", "/etc"]);
    }

    #[test]
    fn empty_pieces_are_dropped_not_kept_as_empty_roots() {
        assert_eq!(parse_roots(",, /etc ,"), vec!["/etc"]);
        assert!(parse_roots("").is_empty());
        assert!(parse_roots(" , ").is_empty());
    }
}
