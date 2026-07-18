//! Headless proof of the scan + baseline + diff pipeline, run by
//! `eos-guard --selftest`. Prints `GUARD-SELFTEST-OK` on success (asserted
//! from the boot serial / CI).

use crate::db::{Db, Status};
use crate::scan;
use std::fs;
use std::path::Path;

pub fn run(db_path: &Path) -> Result<(), String> {
    let _ = fs::remove_file(db_path);

    // A throwaway tree to scan.
    let root = std::env::temp_dir().join("eos-guard-selftest");
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(root.join("sub")).map_err(|e| format!("mkdir: {e}"))?;
    fs::write(root.join("a.txt"), b"alpha").map_err(|e| format!("write a: {e}"))?;
    fs::write(root.join("sub/b.txt"), b"beta").map_err(|e| format!("write b: {e}"))?;

    let roots = vec![root.to_string_lossy().into_owned()];

    let mut db = Db::open(db_path).map_err(|e| format!("open: {e}"))?;
    let mode = db
        .journal_mode()
        .map_err(|e| format!("journal_mode: {e}"))?;
    if mode.to_lowercase() != "wal" {
        return Err(format!("journal_mode is '{mode}', expected 'wal'"));
    }

    // Baseline the tree.
    let (entries, _) = scan::scan_roots(&roots, 10_000);
    if entries.len() != 2 {
        return Err(format!("expected 2 files, scanned {}", entries.len()));
    }
    db.set_baseline(&entries)
        .map_err(|e| format!("set_baseline: {e}"))?;
    if db.baseline_count().map_err(|e| format!("count: {e}"))? != 2 {
        return Err("baseline count != 2".into());
    }

    // A clean re-scan must be all-OK.
    let (again, _) = scan::scan_roots(&roots, 10_000);
    let (findings, sum) = db.diff(&again).map_err(|e| format!("diff clean: {e}"))?;
    if sum.ok != 2 || !findings.is_empty() {
        return Err(format!("clean re-scan not all-OK: {sum:?}"));
    }

    // Mutate one file, add one, remove one → MODIFIED + NEW + REMOVED.
    fs::write(root.join("a.txt"), b"ALPHA-changed").map_err(|e| format!("rewrite a: {e}"))?;
    fs::write(root.join("c.txt"), b"gamma").map_err(|e| format!("write c: {e}"))?;
    fs::remove_file(root.join("sub/b.txt")).map_err(|e| format!("rm b: {e}"))?;

    let (mutated, _) = scan::scan_roots(&roots, 10_000);
    let (findings, sum) = db
        .diff(&mutated)
        .map_err(|e| format!("diff mutated: {e}"))?;
    if sum.modified != 1 {
        return Err(format!("expected 1 modified, got {}", sum.modified));
    }
    if sum.new != 1 {
        return Err(format!("expected 1 new, got {}", sum.new));
    }
    if sum.removed != 1 {
        return Err(format!("expected 1 removed, got {}", sum.removed));
    }
    let modified = findings
        .iter()
        .find(|f| f.status == Status::Modified)
        .ok_or("no MODIFIED finding")?;
    if !modified.path.ends_with("a.txt") {
        return Err(format!("wrong modified path: {}", modified.path));
    }

    let _ = fs::remove_dir_all(&root);
    Ok(())
}
