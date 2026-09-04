//! Headless proof of the scan + baseline + diff pipeline (incl. the U-090
//! permission audit and baseline-integrity digest), run by
//! `eos-guard --selftest`. Prints `GUARD-SELFTEST-OK` on success (asserted
//! from the boot serial / CI).

use crate::db::{BaselineState, Db, Status};
use crate::scan;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

pub fn run(db_path: &Path) -> Result<(), String> {
    let _ = fs::remove_file(db_path);

    // A throwaway tree: two ordinary files plus one setuid binary for the audit.
    let root = std::env::temp_dir().join("eos-guard-selftest");
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(root.join("sub")).map_err(|e| format!("mkdir: {e}"))?;
    fs::write(root.join("a.txt"), b"alpha").map_err(|e| format!("write a: {e}"))?;
    fs::write(root.join("sub/b.txt"), b"beta").map_err(|e| format!("write b: {e}"))?;
    let suid = root.join("suid.bin");
    fs::write(&suid, b"root-power").map_err(|e| format!("write suid: {e}"))?;
    fs::set_permissions(&suid, fs::Permissions::from_mode(0o4755))
        .map_err(|e| format!("chmod suid: {e}"))?;

    let roots = vec![root.to_string_lossy().into_owned()];

    let mut db = Db::open(db_path).map_err(|e| format!("open: {e}"))?;
    let mode = db
        .journal_mode()
        .map_err(|e| format!("journal_mode: {e}"))?;
    if mode.to_lowercase() != "wal" {
        return Err(format!("journal_mode is '{mode}', expected 'wal'"));
    }

    // Baseline the tree (3 files).
    let (entries, _) = scan::scan_roots(&roots, 10_000);
    if entries.len() != 3 {
        return Err(format!("expected 3 files, scanned {}", entries.len()));
    }
    db.set_baseline(&entries)
        .map_err(|e| format!("set_baseline: {e}"))?;
    if db.baseline_count().map_err(|e| format!("count: {e}"))? != 3 {
        return Err("baseline count != 3".into());
    }
    if !db.verify_baseline().is_intact() {
        return Err(format!(
            "fresh baseline is not intact: {:?}",
            db.verify_baseline()
        ));
    }

    // A clean re-scan: no changes, but the audit must flag the setuid file.
    let (again, _) = scan::scan_roots(&roots, 10_000);
    let (findings, sum) = db.diff(&again).map_err(|e| format!("diff clean: {e}"))?;
    if sum.modified != 0 || sum.new != 0 || sum.removed != 0 {
        return Err(format!("clean re-scan shows changes: {sum:?}"));
    }
    if sum.ok != 2 {
        return Err(format!("expected 2 OK on clean re-scan, got {}", sum.ok));
    }
    if sum.warn != 1 {
        return Err(format!("expected 1 audit warning, got {}", sum.warn));
    }
    let warn = findings
        .iter()
        .find(|f| f.status == Status::Warn)
        .ok_or("no WARN finding for the setuid file")?;
    if !warn.path.ends_with("suid.bin") || !warn.detail.contains("setuid") {
        return Err(format!("wrong audit finding: {warn:?}"));
    }

    // Mutate one file, add one, remove one → MODIFIED + NEW + REMOVED
    // (the setuid file is unchanged, so it stays a WARN).
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

    // Tamper with the baseline out of band (as an attacker hiding a change would)
    // and confirm the digest catches it.
    {
        let conn = rusqlite::Connection::open(db_path).map_err(|e| format!("reopen raw: {e}"))?;
        conn.execute(
            "UPDATE baseline SET hash = 'deadbeef' WHERE path LIKE '%a.txt'",
            [],
        )
        .map_err(|e| format!("tamper: {e}"))?;
    }
    let db = Db::open(db_path).map_err(|e| format!("reopen: {e}"))?;
    if db.verify_baseline().is_intact() {
        return Err("tampered baseline still passes its digest".into());
    }
    // THE ARM THIS SELFTEST NEVER HAD, and the one the defect lived in. The cheapest attack on a
    // digest kept beside its data is to delete the digest -- ONE ROW -- and before this change that
    // worked perfectly: `verify_baseline` answered `Ok(true)` and the window said the baseline was
    // fine, permanently. Done with raw SQL rather than a helper on `Db`, because a shipped method
    // that erases the integrity digest is a door, not a test fixture.
    {
        let conn =
            rusqlite::Connection::open(db_path).map_err(|e| format!("reopen for digest: {e}"))?;
        let n = conn
            .execute("DELETE FROM meta WHERE k = 'baseline_digest'", [])
            .map_err(|e| format!("delete digest: {e}"))?;
        if n != 1 {
            return Err(format!("expected to delete 1 digest row, deleted {n}"));
        }
    }
    let db = Db::open(db_path).map_err(|e| format!("reopen after digest delete: {e}"))?;
    match db.verify_baseline() {
        BaselineState::NoDigest => {}
        other => {
            return Err(format!(
                "a baseline whose digest row was deleted reported {other:?}, not NoDigest"
            ))
        }
    }

    let _ = fs::remove_dir_all(&root);
    Ok(())
}
