//! SQLite (WAL) baseline store for E-OS Guard.
//!
//! A "baseline" is the blake3 hash + metadata of every scanned file. A later
//! scan is diffed against it to surface NEW / MODIFIED / REMOVED files.

use crate::scan::Entry;
use rusqlite::{params, Connection};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// What the baseline's own digest says about the baseline.
///
/// THIS IS AN ENUM BECAUSE A BOOL COULD NOT TELL THE TRUTH HERE. `verify_baseline` used to return
/// `rusqlite::Result<bool>`, and there are two distinct ways the answer is neither yes nor no --
/// no digest was ever recorded, and the database could not be read. Both were being spelled
/// `true`, which is the spelling that means "safe":
///
///   * the function itself returned `Ok(true)` when `meta.baseline_digest` was absent, so deleting
///     ONE ROW turned tamper detection off permanently and the window said "intact";
///   * every caller wrote `.unwrap_or(true)`, so a database error said "intact" too.
///
/// Four call sites across two products chose the open default in a program whose only job is to
/// notice that something changed. CLAUDE.md section 5.5 asks for fail-closed with an explicit
/// exception; this was fail-open with none. The type now refuses to carry that answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BaselineState {
    /// The digest recomputed from the stored rows matches the recorded one.
    Intact,
    /// It does not: the rows were edited out of band, or the store is corrupt.
    Tampered,
    /// No digest is recorded. Either the baseline predates digest support, or somebody removed the
    /// row. THE TWO ARE INDISTINGUISHABLE FROM HERE, which is exactly why this may not be reported
    /// as intact -- the cheapest attack on a digest kept beside its data is to delete the digest.
    NoDigest,
    /// The store could not be read. Carries the error so the window can say what happened rather
    /// than fall back to a reassuring default.
    Unreadable(String),
}

impl BaselineState {
    /// True for `Intact` and nothing else. Every other state is a thing to tell the person about.
    pub fn is_intact(&self) -> bool {
        matches!(self, Self::Intact)
    }

    /// A phrase for the status line, in the language the rest of this window speaks.
    pub fn describe(&self) -> String {
        match self {
            Self::Intact => "nienaruszony".to_string(),
            Self::Tampered => "NARUSZONY".to_string(),
            Self::NoDigest => {
                "BEZ ODCISKU — nie da się stwierdzić, czy jest nienaruszony".to_string()
            }
            Self::Unreadable(e) => format!("NIE DA SIĘ SPRAWDZIĆ ({e})"),
        }
    }
}

pub struct Db {
    conn: Connection,
}

/// How a scanned file compares to the baseline.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    /// Never constructed as a FINDING, and that is the design rather than an oversight:
    /// a file that is present, unchanged and unflagged is COUNTED (`Summary::ok`,
    /// incremented at line ~222, shown by the GUI as `n_ok`, and asserted by
    /// `--selftest` as "expected 2 OK on clean re-scan"), not listed. The variant is the
    /// label for that count -- `label()` and `kind_of()` both handle it -- so removing it
    /// would delete a real state from the model, not dead weight. What would make it
    /// constructed is a verbose mode that lists clean files too; until then, this.
    #[allow(dead_code)]
    Ok,
    New,
    Modified,
    Removed,
    /// Present + unchanged, but the security lint flagged it (world-writable).
    Warn,
}

impl Status {
    pub fn label(self) -> &'static str {
        match self {
            Status::Ok => "OK",
            Status::New => "NOWY",
            Status::Modified => "ZMIENIONY",
            Status::Removed => "USUNIĘTY",
            Status::Warn => "OSTRZEŻENIE",
        }
    }
}

#[derive(Clone, Debug)]
pub struct Finding {
    pub path: String,
    pub status: Status,
    pub detail: String,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Summary {
    pub ok: u32,
    pub new: u32,
    pub modified: u32,
    pub removed: u32,
    pub warn: u32,
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

pub fn default_path() -> PathBuf {
    match std::env::var_os("HOME") {
        Some(home) => Path::new(&home)
            .join(".local")
            .join("share")
            .join("eos-guard")
            .join("baseline.db"),
        None => PathBuf::from("/tmp/eos-guard.db"),
    }
}

impl Db {
    pub fn open(path: &Path) -> rusqlite::Result<Self> {
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let conn = Connection::open(path)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.execute(
            "CREATE TABLE IF NOT EXISTS baseline (
                path   TEXT PRIMARY KEY,
                hash   TEXT NOT NULL,
                size   INTEGER NOT NULL,
                mode   INTEGER NOT NULL,
                mtime  INTEGER NOT NULL,
                seen_at INTEGER NOT NULL
            )",
            [],
        )?;
        conn.execute(
            "CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT NOT NULL)",
            [],
        )?;
        Ok(Db { conn })
    }

    pub fn journal_mode(&self) -> rusqlite::Result<String> {
        self.conn.query_row("PRAGMA journal_mode", [], |r| r.get(0))
    }

    pub fn baseline_count(&self) -> rusqlite::Result<i64> {
        self.conn
            .query_row("SELECT COUNT(*) FROM baseline", [], |r| r.get(0))
    }

    /// Replace the whole baseline with a fresh scan, recording a blake3 digest
    /// over its canonical (path-sorted) contents so later scans can detect an
    /// out-of-band edit or corruption of the baseline itself.
    pub fn set_baseline(&mut self, entries: &[Entry]) -> rusqlite::Result<()> {
        let t = now();
        let tx = self.conn.transaction()?;
        tx.execute("DELETE FROM baseline", [])?;
        {
            let mut stmt = tx.prepare(
                "INSERT INTO baseline (path, hash, size, mode, mtime, seen_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            )?;
            for e in entries {
                stmt.execute(params![e.path, e.hash, e.size, e.mode, e.mtime, t])?;
            }
        }
        let digest = Self::digest_rows(entries.iter().map(|e| (&e.path, &e.hash, e.size, e.mode)));
        for (k, v) in [("baseline_at", t.to_string()), ("baseline_digest", digest)] {
            tx.execute(
                "INSERT INTO meta (k, v) VALUES (?1, ?2)
                 ON CONFLICT(k) DO UPDATE SET v = excluded.v",
                params![k, v],
            )?;
        }
        tx.commit()
    }

    /// Canonical blake3 digest over baseline rows (path-sorted), covering the
    /// path, content hash, size and mode of every entry.
    fn digest_rows<'a>(rows: impl Iterator<Item = (&'a String, &'a String, i64, u32)>) -> String {
        let mut lines: Vec<String> = rows
            .map(|(path, hash, size, mode)| format!("{path}\0{hash}\0{size}\0{mode}"))
            .collect();
        lines.sort();
        let mut hasher = blake3::Hasher::new();
        for line in &lines {
            hasher.update(line.as_bytes());
            hasher.update(b"\n");
        }
        hasher.finalize().to_hex().to_string()
    }

    /// Recompute the baseline digest from the stored rows and compare it to the recorded one.
    ///
    /// RETURNS A STATE, NOT A BOOL, AND NOT A `Result` -- deliberately. A `Result<bool>` gave a
    /// caller two ways to spell "safe" for a question that had not been answered, and both were
    /// taken: `Ok(true)` on a missing digest here, `.unwrap_or(true)` on a database error there.
    /// With `BaselineState` there is no `true` to fall back to, so a caller that ignores the
    /// difference does not compile into something reassuring -- it does not compile.
    ///
    /// The doc comment this replaces also contradicted its own code: it claimed `Ok(false)` covered
    /// a baseline that "predates digest support", while the body returned `Ok(true)` for exactly
    /// that case. Whoever read the comment and trusted it was reading a promise the function did
    /// not keep.
    ///
    /// NOTE, unchanged and still true: the digest lives in the same database, so this catches
    /// corruption and naive tampering — not an attacker who also recomputes it. A key-signed
    /// baseline (the `R-711` class) is future work, and `NoDigest` is a hint of why it matters.
    pub fn verify_baseline(&self) -> BaselineState {
        let stored: Option<String> = self
            .conn
            .query_row("SELECT v FROM meta WHERE k = 'baseline_digest'", [], |r| {
                r.get(0)
            })
            .ok();
        let Some(stored) = stored else {
            return BaselineState::NoDigest;
        };
        let mut stmt = match self
            .conn
            .prepare("SELECT path, hash, size, mode FROM baseline")
        {
            Ok(s) => s,
            Err(e) => return BaselineState::Unreadable(e.to_string()),
        };
        let rows: rusqlite::Result<Vec<(String, String, i64, u32)>> = stmt
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
            .and_then(|m| m.collect());
        let rows = match rows {
            Ok(r) => r,
            Err(e) => return BaselineState::Unreadable(e.to_string()),
        };
        let actual = Self::digest_rows(rows.iter().map(|(p, h, s, m)| (p, h, *s, *m)));
        if actual == stored {
            BaselineState::Intact
        } else {
            BaselineState::Tampered
        }
    }

    fn load_baseline(&self) -> rusqlite::Result<HashMap<String, String>> {
        let mut stmt = self.conn.prepare("SELECT path, hash FROM baseline")?;
        let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?;
        rows.collect()
    }

    /// Diff a fresh scan against the stored baseline.
    pub fn diff(&self, entries: &[Entry]) -> rusqlite::Result<(Vec<Finding>, Summary)> {
        let mut base = self.load_baseline()?;
        let mut findings = Vec::new();
        let mut sum = Summary::default();

        for e in entries {
            // The permission audit runs on every file, regardless of whether it
            // changed: a setuid/setgid/world-writable binary is a security fact
            // worth surfacing even if it's been there all along.
            let flags = e.security_flags();
            let flag_note = if flags.is_empty() {
                String::new()
            } else {
                format!(" — {} (mode {:o})", flags.join(", "), e.mode & 0o7777)
            };
            if !flags.is_empty() {
                sum.warn += 1;
            }

            match base.remove(&e.path) {
                None => {
                    sum.new += 1;
                    findings.push(Finding {
                        path: e.path.clone(),
                        status: Status::New,
                        detail: format!("{} B{}", e.size, flag_note),
                    });
                }
                Some(old_hash) if old_hash != e.hash => {
                    sum.modified += 1;
                    findings.push(Finding {
                        path: e.path.clone(),
                        status: Status::Modified,
                        detail: format!("hash zmieniony{flag_note}"),
                    });
                }
                Some(_) => {
                    if flags.is_empty() {
                        sum.ok += 1;
                    } else {
                        findings.push(Finding {
                            path: e.path.clone(),
                            status: Status::Warn,
                            detail: flags.join(", ") + &format!(" (mode {:o})", e.mode & 0o7777),
                        });
                    }
                }
            }
        }
        // Whatever is left in `base` was in the baseline but not seen now.
        let mut removed: Vec<String> = base.into_keys().collect();
        removed.sort();
        for path in removed {
            sum.removed += 1;
            findings.push(Finding {
                path,
                status: Status::Removed,
                detail: "brak na dysku".into(),
            });
        }

        // Most interesting first: modified, removed, new, warn.
        findings.sort_by_key(|f| match f.status {
            Status::Modified => 0,
            Status::Removed => 1,
            Status::New => 2,
            Status::Warn => 3,
            Status::Ok => 4,
        });
        Ok((findings, sum))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// These are the first unit tests in this repository. Until now every check on this engine went
    /// through the `--selftest` binary path, which can only run as a whole program and so could not
    /// reach a single function -- and the defect these tests exist for lived in a single function.
    fn entry(path: &str, hash: &str) -> Entry {
        Entry {
            path: path.to_string(),
            hash: hash.to_string(),
            size: 10,
            mode: 0o644,
            mtime: 1,
        }
    }

    fn db_with_baseline(dir: &std::path::Path) -> Db {
        let mut db = Db::open(&dir.join("t.db")).expect("open");
        db.set_baseline(&[entry("/a", "aa"), entry("/b", "bb")])
            .expect("set_baseline");
        db
    }

    fn tmpdir(name: &str) -> std::path::PathBuf {
        // Not `mktemp`: CLAUDE.md P-16 -- on macOS `mktemp -d` ignores TMPDIR unless given a
        // template, and this only needs a unique directory, not a secure one.
        let d = std::env::temp_dir().join(format!("eos-db-test-{name}"));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).expect("mkdir");
        d
    }

    #[test]
    fn fresh_baseline_is_intact() {
        let d = tmpdir("fresh");
        let db = db_with_baseline(&d);
        assert_eq!(db.verify_baseline(), BaselineState::Intact);
    }

    #[test]
    fn edited_rows_are_tampered() {
        let d = tmpdir("tampered");
        let db = db_with_baseline(&d);
        db.conn
            .execute("UPDATE baseline SET hash = 'zz' WHERE path = '/a'", [])
            .expect("tamper");
        assert_eq!(db.verify_baseline(), BaselineState::Tampered);
    }

    /// THE REGRESSION TEST FOR THE DEFECT. Deleting one row -- the digest -- used to turn tamper
    /// detection off permanently: `verify_baseline` returned `Ok(true)` and the window said the
    /// baseline was intact. The cheapest attack on a digest stored beside its data is to remove the
    /// digest, so "no digest" may not be spelled the same way as "verified intact".
    #[test]
    fn a_deleted_digest_is_not_intact() {
        let d = tmpdir("nodigest");
        let db = db_with_baseline(&d);
        let n = db
            .conn
            .execute("DELETE FROM meta WHERE k = 'baseline_digest'", [])
            .expect("delete digest");
        assert_eq!(
            n, 1,
            "the digest row was not there to delete -- test is vacuous"
        );
        assert_eq!(db.verify_baseline(), BaselineState::NoDigest);
        assert!(!db.verify_baseline().is_intact());
    }

    /// Without this, the test above would pass just as well if `verify_baseline` returned
    /// `NoDigest` for EVERYTHING -- which would be a different, quieter defect.
    #[test]
    fn no_digest_is_not_the_answer_to_everything() {
        let d = tmpdir("notalways");
        let db = db_with_baseline(&d);
        assert_ne!(db.verify_baseline(), BaselineState::NoDigest);
    }

    /// `digest_rows` sorts before hashing, so the same set in a different order is the same
    /// baseline. If it stopped sorting, `verify_baseline` would report tampering on an untouched
    /// store every time SQLite returned rows in another order.
    #[test]
    fn the_digest_does_not_depend_on_row_order() {
        let a = ("/a".to_string(), "aa".to_string(), 1i64, 0o644u32);
        let b = ("/b".to_string(), "bb".to_string(), 2i64, 0o600u32);
        let one = Db::digest_rows([&a, &b].into_iter().map(|(p, h, s, m)| (p, h, *s, *m)));
        let two = Db::digest_rows([&b, &a].into_iter().map(|(p, h, s, m)| (p, h, *s, *m)));
        assert_eq!(one, two);
    }

    /// And it must still depend on the things it claims to cover. A digest that ignored `mode`
    /// would let a file become setuid without the baseline noticing.
    #[test]
    fn the_digest_covers_mode_and_size() {
        let base = ("/a".to_string(), "aa".to_string(), 1i64, 0o644u32);
        let mode = ("/a".to_string(), "aa".to_string(), 1i64, 0o4755u32);
        let size = ("/a".to_string(), "aa".to_string(), 999i64, 0o644u32);
        let d = |t: &(String, String, i64, u32)| {
            Db::digest_rows([t].into_iter().map(|(p, h, s, m)| (p, h, *s, *m)))
        };
        assert_ne!(d(&base), d(&mode), "digest ignores mode");
        assert_ne!(d(&base), d(&size), "digest ignores size");
    }
}
