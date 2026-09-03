//! SQLite (WAL) baseline store for E-OS Guard.
//!
//! A "baseline" is the blake3 hash + metadata of every scanned file. A later
//! scan is diffed against it to surface NEW / MODIFIED / REMOVED files.

use crate::scan::Entry;
use rusqlite::{params, Connection};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

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

    /// Recompute the baseline digest from the stored rows and compare it to the
    /// recorded one. `Ok(true)` means intact; `Ok(false)` means the baseline was
    /// edited/corrupted out of band (or predates digest support).
    ///
    /// NOTE: the digest lives in the same database, so this catches corruption
    /// and naive tampering — not an attacker who also recomputes it. A
    /// key-signed baseline (the `R-711` class) is future work.
    pub fn verify_baseline(&self) -> rusqlite::Result<bool> {
        let stored: Option<String> = self
            .conn
            .query_row("SELECT v FROM meta WHERE k = 'baseline_digest'", [], |r| {
                r.get(0)
            })
            .ok();
        let Some(stored) = stored else {
            return Ok(true); // no digest recorded (legacy baseline) — don't cry wolf
        };
        let mut stmt = self
            .conn
            .prepare("SELECT path, hash, size, mode FROM baseline")?;
        let rows: Vec<(String, String, i64, u32)> = stmt
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?
            .collect::<rusqlite::Result<_>>()?;
        let actual = Self::digest_rows(rows.iter().map(|(p, h, s, m)| (p, h, *s, *m)));
        Ok(actual == stored)
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
