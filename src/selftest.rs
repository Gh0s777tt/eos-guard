//! Headless proof of the scan + baseline + diff pipeline (incl. the U-090
//! permission audit and baseline-integrity digest), run by
//! `eos-guard --selftest`. Prints `GUARD-SELFTEST-OK` on success (asserted
//! from the boot serial / CI).

use crate::db::{self, BaselineState, Db, ScopeState, Status};
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
    db.set_baseline(&entries, &roots)
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
    let (findings, sum) = db
        .diff(&again, &roots)
        .map_err(|e| format!("diff clean: {e}"))?;
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
    if sum.out_of_scope != 0 {
        return Err(format!(
            "a scan over the baseline's own roots skipped {} files",
            sum.out_of_scope
        ));
    }

    // ── Scan scope ──────────────────────────────────────────────────────────────────────────
    // Narrow the roots to the subdirectory, exactly as editing the field in the window does, and
    // re-diff the UNTOUCHED tree. Before this change the two files above `sub/` came back
    // USUNIĘTY -- "brak na dysku" -- for a tree the scan never opened; with real roots that is
    // thousands of rows, and an integrity monitor nobody reads protects nobody.
    let narrowed = vec![root.join("sub").to_string_lossy().into_owned()];
    let (inner, _) = scan::scan_roots(&narrowed, 10_000);
    if inner.len() != 1 {
        return Err(format!(
            "expected 1 file under sub/, scanned {}",
            inner.len()
        ));
    }
    let (findings, sum) = db
        .diff(&inner, &narrowed)
        .map_err(|e| format!("diff narrowed: {e}"))?;
    if sum.removed != 0 {
        return Err(format!(
            "a narrowed scan reported {} removals it never looked for",
            sum.removed
        ));
    }
    if sum.out_of_scope != 2 {
        return Err(format!(
            "expected 2 baseline files out of scope, got {}",
            sum.out_of_scope
        ));
    }
    if let Some(f) = findings.iter().find(|f| f.status == Status::Removed) {
        return Err(format!("a narrowed scan still listed a removal: {f:?}"));
    }
    // The scope has to be NAMED, not merely counted: the window must be able to say which root
    // went missing, and it must say something at all.
    match db.scope(&narrowed) {
        ScopeState::Changed { ref dropped, .. } if dropped.len() == 1 && dropped[0] == roots[0] => {
        }
        other => return Err(format!("narrowed scan reported scope {other:?}")),
    }
    let note = db::scope_note(&db.scope(&narrowed), sum.out_of_scope)
        .ok_or("a narrowed scan that skipped 2 files printed no scope note")?;
    if !note.contains("NIE SPRAWDZONO") || !note.contains('2') {
        return Err(format!("scope note says too little: {note}"));
    }
    // ...and the same scan over the baseline's own roots must say NOTHING. A warning on every
    // scan is a warning nobody reads (CLAUDE.md §5.4: show when the check refuses AND when it
    // does not).
    if let Some(quiet) = db::scope_note(&db.scope(&roots), 0) {
        return Err(format!("an unchanged scope still printed: {quiet}"));
    }

    // Mutate one file, add one, remove one → MODIFIED + NEW + REMOVED
    // (the setuid file is unchanged, so it stays a WARN).
    fs::write(root.join("a.txt"), b"ALPHA-changed").map_err(|e| format!("rewrite a: {e}"))?;
    fs::write(root.join("c.txt"), b"gamma").map_err(|e| format!("write c: {e}"))?;
    fs::remove_file(root.join("sub/b.txt")).map_err(|e| format!("rm b: {e}"))?;

    let (mutated, _) = scan::scan_roots(&roots, 10_000);
    let (findings, sum) = db
        .diff(&mutated, &roots)
        .map_err(|e| format!("diff mutated: {e}"))?;
    if sum.modified != 1 {
        return Err(format!("expected 1 modified, got {}", sum.modified));
    }
    if sum.new != 1 {
        return Err(format!("expected 1 new, got {}", sum.new));
    }
    // THE OTHER DIRECTION, and the reason the suppression above is not a blanket. Same roots as
    // the baseline, one file genuinely deleted: it must still be reported.
    if sum.removed != 1 {
        return Err(format!("expected 1 removed, got {}", sum.removed));
    }
    if sum.out_of_scope != 0 {
        return Err(format!(
            "an unchanged root set put {} files out of scope",
            sum.out_of_scope
        ));
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
