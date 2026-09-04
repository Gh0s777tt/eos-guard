//! SQLite (WAL) baseline store for E-OS Guard.
//!
//! A "baseline" is the blake3 hash + metadata of every scanned file, plus the set
//! of directories it was taken over. A later scan is diffed against it to surface
//! NEW / MODIFIED / REMOVED files -- and, when that scan walked different ground
//! than the baseline covers, to say so instead of calling the difference removal.

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

/// What the baseline was taken over, next to what the scan being diffed against it actually walked.
///
/// SEPARATE FROM `BaselineState`, AND WEAKER THAN IT, ON PURPOSE. `BaselineState` answers a
/// security question -- were the stored rows edited out of band -- so it refuses to collapse its
/// unknowns into the reassuring answer. This type answers an EXPLANATORY one: why does this scan
/// cover less (or more) ground than the baseline? Nothing that protects the person rides on the
/// answer. `Summary::out_of_scope` does that job, and `Db::diff` computes it from the roots the
/// scan actually walked -- never from the value recorded here.
///
/// That split is what makes the recorded value affordable. `meta.roots` is deliberately NOT an
/// input to the baseline digest (see `set_baseline`), so anyone who can write the database can
/// write it. Because the suppression decision ignores it, forging it cannot hide a removal: at
/// worst the window's *explanation* of a scope change is wrong, while the count of files this scan
/// never checked stays right.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ScopeState {
    /// The baseline recorded its roots and this scan covered the same ground.
    Same,
    /// It recorded them and the ground moved. Never constructed with both lists empty -- `scope`
    /// returns `Same` for that, because two root sets that cover each other are the same scope
    /// even when the strings differ ("/usr" after "/usr/bin, /usr/lib" drops nothing).
    Changed {
        /// Baseline roots no current root covers.
        dropped: Vec<String>,
        /// Roots this scan walked that no baseline root covered.
        added: Vec<String>,
    },
    /// The baseline records no roots: it predates the field, or the row was removed.
    ///
    /// ONE ARM FOR BOTH SPELLINGS OF "CANNOT SAY", which is the opposite of what `BaselineState`
    /// does -- and the difference is earned, not sloppy. There, `NoDigest` and `Unreadable` lead
    /// to different actions and one of them may not be reported as safe. Here neither leads
    /// anywhere: either way the window cannot name what the baseline covered, and either way
    /// `Summary::out_of_scope` still says how much of it went unchecked. A distinction that
    /// changes no decision is a distinction worth not inventing.
    Unknown,
}

// DELIBERATELY NO `is_same()` HERE, though `BaselineState::is_intact()` sits a few lines above and
// the symmetry is tempting. That predicate works because "is this worth telling the person" depends
// on the state alone. Here it does not: it depends on the state AND on how many baseline files went
// unchecked, and the two disagree in both directions -- `Unknown` with nothing skipped is not worth
// a line, while `Unknown` with seven skipped files is. A bool on this type would answer the wrong
// question convincingly, so the decision lives in `scope_note`, which sees both halves and is
// tested on both.

/// `meta.roots` joins the canonical roots with a newline, not with the comma the UI field uses,
/// because a path may legitimately contain a comma. It cannot contain a newline in any root this
/// product can express: the field it is typed into is single-line, comma-separated text.
const ROOTS_SEP: char = '\n';

/// Canonical form of a root set: trimmed, empties dropped, de-duplicated, sorted.
///
/// Canonical rather than literal because these arrive from a free-text field. "/usr/bin, /etc" and
/// " /etc ,/usr/bin,/etc " name the same ground, and a scope check that called those two different
/// would warn on every scan -- the same "cry wolf until nobody looks" failure this change exists to
/// remove, pointed the other way.
pub fn canonical_roots(roots: &[String]) -> Vec<String> {
    let mut v: Vec<String> = roots
        .iter()
        .map(|r| r.trim().to_string())
        .filter(|r| !r.is_empty())
        .collect();
    v.sort();
    v.dedup();
    v
}

/// Is `path` inside one of `roots`?
///
/// COMPONENT-WISE, via `Path::starts_with`, and not a string prefix. `"/usr/binary"` is not inside
/// `"/usr/bin"`, while `"/etc/"` and `"/etc"` are one root. A `str::starts_with` here would mark a
/// whole sibling tree as covered when nothing walked it -- which is precisely the false
/// reassurance this function exists to prevent, so it is worth the `Path` allocation.
fn covered_by(path: &str, roots: &[String]) -> bool {
    let p = Path::new(path);
    roots.iter().any(|r| p.starts_with(Path::new(r)))
}

/// The status line's sentence about scan scope, or `None` when there is genuinely nothing to say.
///
/// RETURNING `None` IS A REAL ANSWER AND IT HAS ITS OWN TEST. A warning printed on every scan is a
/// warning nobody reads, and training the person to ignore the window is the failure this whole
/// change is about; so silence must stay reachable, and something must keep proving it is
/// (`scope_note_stays_quiet_when_the_scan_covers_the_baseline`).
///
/// The rule in one line: speak up when this scan left part of the baseline unchecked, or when the
/// roots moved. An `Unknown` scope ON ITS OWN is not worth a line -- if `out_of_scope` is zero then
/// every baseline path lay inside a root this scan walked, so the scan was complete with respect to
/// the baseline, and it changes nothing that the baseline forgot to write down which roots made it.
pub fn scope_note(scope: &ScopeState, out_of_scope: u32) -> Option<String> {
    let mut parts: Vec<String> = Vec::new();
    match scope {
        ScopeState::Changed { dropped, added } => {
            if !dropped.is_empty() {
                parts.push(format!("wzorzec obejmuje też {}", dropped.join(", ")));
            }
            if !added.is_empty() {
                parts.push(format!("ten skan objął dodatkowo {}", added.join(", ")));
            }
        }
        ScopeState::Unknown if out_of_scope > 0 => {
            parts.push("wzorzec nie zapisał swoich katalogów".to_string());
        }
        ScopeState::Same | ScopeState::Unknown => {}
    }
    if out_of_scope > 0 {
        parts.push(format!(
            "{out_of_scope} plików wzorca NIE SPRAWDZONO — leżą poza katalogami tego skanu, \
             więc nie są zgłaszane jako usunięte"
        ));
    }
    if parts.is_empty() {
        None
    } else {
        Some(format!("  ⚠ ZAKRES: {}.", parts.join("; ")))
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
    /// incremented in `diff`, shown by the GUI as `n_ok`, and asserted by
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
    /// Baseline files that lay outside every root this scan walked, so nothing looked for them.
    ///
    /// NOT A CHANGE, AND NOT A FINDING -- a third thing, which is why it gets its own counter
    /// rather than folding into `removed`. These files were not observed at all, and the window
    /// may not claim an observation it never made. `Db::diff` counts them here instead of
    /// listing them, and `scope_note` puts the count in the status line on every scan where it is
    /// non-zero, so a narrowed scan is visible as a number rather than as an absence.
    pub out_of_scope: u32,
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
    ///
    /// `roots` -- the directories the scan walked -- is recorded in `meta.roots`, and is
    /// DELIBERATELY NOT AN INPUT TO THE DIGEST. `digest_rows` defines what "this baseline is
    /// intact" means, so widening it would recompute every digest already written: every store in
    /// the field would report NARUSZONY on its next scan, for a change that touched not one file
    /// hash. A tamper alarm that fires on an upgrade is a tamper alarm people learn to dismiss.
    ///
    /// The cost is real and stated rather than hidden: `meta.roots` is unprotected. It is
    /// affordable only because no safety decision reads it -- `diff` decides what was checked from
    /// the roots the scan walked, and `ScopeState` spells out the rest.
    pub fn set_baseline(&mut self, entries: &[Entry], roots: &[String]) -> rusqlite::Result<()> {
        let t = now();
        let roots = canonical_roots(roots).join(&ROOTS_SEP.to_string());
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
        // UNCHANGED INPUT, ON PURPOSE: path, hash, size, mode. Not the roots -- see the note above.
        let digest = Self::digest_rows(entries.iter().map(|e| (&e.path, &e.hash, e.size, e.mode)));
        for (k, v) in [
            ("baseline_at", t.to_string()),
            ("baseline_digest", digest),
            ("roots", roots),
        ] {
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

    /// The roots the baseline was taken over, as recorded by `set_baseline`.
    ///
    /// `None` for a baseline written before the field existed, for one whose row was removed, and
    /// for a store that cannot be read -- all three are advisory in the same way, and `ScopeState`
    /// says why one arm is enough for them.
    pub fn baseline_roots(&self) -> Option<Vec<String>> {
        let raw: String = self
            .conn
            .query_row("SELECT v FROM meta WHERE k = 'roots'", [], |r| r.get(0))
            .ok()?;
        let roots = canonical_roots(&raw.split(ROOTS_SEP).map(str::to_string).collect::<Vec<_>>());
        (!roots.is_empty()).then_some(roots)
    }

    /// Compare the ground this scan walked with the ground the baseline was taken over.
    ///
    /// Compared BY COVERAGE, not by string equality: a root the current set already contains the
    /// whole of is not "dropped". Baselining "/usr/bin, /usr/lib" and later scanning "/usr" moves
    /// no ground, and reporting it as a scope change would be a false alarm on a strictly wider
    /// scan. When neither list ends up with anything in it, the answer is `Same` -- which is why
    /// `Changed` can never carry two empty lists.
    ///
    /// Advisory only. Read it to EXPLAIN a scope difference, never to decide whether a missing
    /// file counts as removed; `diff` owns that and does not consult this.
    pub fn scope(&self, scan_roots: &[String]) -> ScopeState {
        let Some(base) = self.baseline_roots() else {
            return ScopeState::Unknown;
        };
        let now = canonical_roots(scan_roots);
        let dropped: Vec<String> = base
            .iter()
            .filter(|r| !covered_by(r, &now))
            .cloned()
            .collect();
        let added: Vec<String> = now
            .iter()
            .filter(|r| !covered_by(r, &base))
            .cloned()
            .collect();
        if dropped.is_empty() && added.is_empty() {
            ScopeState::Same
        } else {
            ScopeState::Changed { dropped, added }
        }
    }

    fn load_baseline(&self) -> rusqlite::Result<HashMap<String, String>> {
        let mut stmt = self.conn.prepare("SELECT path, hash FROM baseline")?;
        let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?;
        rows.collect()
    }

    /// Diff a fresh scan against the stored baseline.
    ///
    /// `scan_roots` is the ground this scan actually walked, and it settles the one question this
    /// function used to answer wrongly: when a baseline path does not turn up, was it removed, or
    /// was it never looked for?
    pub fn diff(
        &self,
        entries: &[Entry],
        scan_roots: &[String],
    ) -> rusqlite::Result<(Vec<Finding>, Summary)> {
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
        // Whatever is left in `base` was in the baseline and did not turn up now. THERE ARE TWO
        // REASONS FOR THAT AND THEY ARE NOT THE SAME FACT.
        //
        // The file lay inside a root this scan walked and is gone -> REMOVED, exactly as before.
        //
        // The file lay outside every root this scan walked -> nothing looked for it, so nothing
        // may be said about it. `Status::Removed` carries the detail "brak na dysku" -- missing
        // from disk -- and asserting that about a tree nobody opened is not noise, it is a false
        // statement, and it was two clicks away: baseline "/usr/bin, /etc", edit the field down to
        // "/etc", press Skanuj, and every file under /usr/bin came back USUNIĘTY. Clearing the
        // field entirely condemned the whole baseline, because `on_scan` never required a root.
        // An integrity monitor that reports thousands of removals that did not happen teaches the
        // person to stop reading it, and after that it protects nobody.
        //
        // COUNTED, NOT LISTED, and never dropped in silence. Listing them would rebuild the same
        // wall of rows under a politer label; discarding them without a count would be fail-open,
        // the exact shape of the `Ok(true)` defect this module has just finished removing. So the
        // number goes to `Summary::out_of_scope`, and `scope_note` puts it in the status line
        // every time it is not zero.
        //
        // NOTE WHAT THE TEST READS: `scan_roots`, never `meta.roots`. A baseline written before
        // that row existed is still diffed correctly, and someone who rewrites the undigested
        // `meta.roots` cannot use it to make a genuine removal disappear.
        let roots = canonical_roots(scan_roots);
        let mut missing: Vec<String> = base.into_keys().collect();
        missing.sort();
        for path in missing {
            if covered_by(&path, &roots) {
                sum.removed += 1;
                findings.push(Finding {
                    path,
                    status: Status::Removed,
                    detail: "brak na dysku".into(),
                });
            } else {
                sum.out_of_scope += 1;
            }
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

    fn roots(rs: &[&str]) -> Vec<String> {
        rs.iter().map(|r| r.to_string()).collect()
    }

    fn db_with_baseline(dir: &std::path::Path) -> Db {
        let mut db = Db::open(&dir.join("t.db")).expect("open");
        db.set_baseline(&[entry("/a", "aa"), entry("/b", "bb")], &roots(&["/"]))
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

    // ── Scan scope ───────────────────────────────────────────────────────────────────────────
    //
    // The defect these cover, measured on this file before the change: a baseline taken over
    // "/usr/bin, /etc, /opt/eos" and then diffed against a scan of "/usr/bin, /etc" reported
    //
    //     PROBE state=Intact
    //     PROBE removed=2 new=0 modified=0
    //     PROBE finding /opt/eos/x USUNIĘTY brak na dysku
    //     PROBE finding /opt/eos/y USUNIĘTY brak na dysku
    //
    // -- two removals that did not happen, from a directory the scan never opened, over a
    // baseline the digest called intact. With real roots that is thousands of rows.

    /// A store baselined over three roots, rescanned over two of them.
    fn db_over_three_roots(name: &str) -> (std::path::PathBuf, Db) {
        let d = tmpdir(name);
        let mut db = Db::open(&d.join("s.db")).expect("open");
        db.set_baseline(
            &[
                entry("/usr/bin/ls", "aa"),
                entry("/etc/passwd", "bb"),
                entry("/opt/eos/x", "cc"),
                entry("/opt/eos/y", "dd"),
            ],
            &roots(&["/usr/bin", "/etc", "/opt/eos"]),
        )
        .expect("set_baseline");
        (d, db)
    }

    /// THE REGRESSION TEST. Narrowing the roots field must not manufacture removals.
    #[test]
    fn a_narrower_scan_does_not_call_unscanned_files_removed() {
        let (_d, db) = db_over_three_roots("narrower");
        let (findings, sum) = db
            .diff(
                &[entry("/usr/bin/ls", "aa"), entry("/etc/passwd", "bb")],
                &roots(&["/usr/bin", "/etc"]),
            )
            .expect("diff");
        assert_eq!(sum.removed, 0, "reported a removal it never looked for");
        assert_eq!(
            sum.out_of_scope, 2,
            "the two unchecked files were not counted"
        );
        assert!(
            !findings.iter().any(|f| f.status == Status::Removed),
            "a REMOVED finding survived: {findings:?}"
        );
    }

    /// THE NEGATIVE TEST (CLAUDE.md §5.4): the check above has to be able to REFUSE to suppress.
    /// Without this, `covered_by` returning `false` unconditionally -- an integrity monitor that
    /// can no longer report a deletion at all -- would pass the whole scope suite.
    #[test]
    fn a_removal_inside_the_scanned_roots_is_still_reported() {
        let (_d, db) = db_over_three_roots("realremoval");
        let (findings, sum) = db
            .diff(
                // /etc/passwd is gone, and /etc IS being scanned this time.
                &[
                    entry("/usr/bin/ls", "aa"),
                    entry("/opt/eos/x", "cc"),
                    entry("/opt/eos/y", "dd"),
                ],
                &roots(&["/usr/bin", "/etc", "/opt/eos"]),
            )
            .expect("diff");
        assert_eq!(sum.removed, 1, "a real removal was suppressed");
        assert_eq!(sum.out_of_scope, 0, "nothing was outside these roots");
        let r = findings
            .iter()
            .find(|f| f.status == Status::Removed)
            .expect("no REMOVED finding for a file that really went missing");
        assert_eq!(r.path, "/etc/passwd");
    }

    /// The two-click case in its purest form: clear the roots field and press Skanuj. `on_scan`
    /// never required a root, so this used to condemn the entire baseline as USUNIĘTY.
    #[test]
    fn an_empty_root_set_checks_nothing_and_so_removes_nothing() {
        let (_d, db) = db_over_three_roots("noroots");
        let (findings, sum) = db.diff(&[], &[]).expect("diff");
        assert_eq!(sum.removed, 0);
        assert_eq!(
            sum.out_of_scope, 4,
            "all four baseline files went unchecked"
        );
        assert!(
            findings.is_empty(),
            "findings from a scan that walked nothing: {findings:?}"
        );
    }

    /// `covered_by` compares path COMPONENTS. As a string, "/usr/binary" starts with "/usr/bin";
    /// as a path it is a different tree, and calling it covered would silently mark a sibling
    /// tree as checked. This is the test that dies if the `Path` comparison becomes a `str` one.
    #[test]
    fn coverage_is_measured_in_path_components_not_characters() {
        assert!(covered_by("/usr/bin/ls", &roots(&["/usr/bin"])));
        assert!(
            covered_by("/etc/passwd", &roots(&["/etc/"])),
            "trailing slash"
        );
        assert!(!covered_by("/usr/binary/ls", &roots(&["/usr/bin"])));
        assert!(!covered_by("/etcetera/x", &roots(&["/etc"])));
    }

    /// THE SECURITY PROPERTY. `meta.roots` is outside the digest, so anyone who can write the
    /// database can write it. Suppression must therefore not consult it: forging the row may
    /// spoil the window's explanation, but it may not hide a deletion.
    #[test]
    fn suppression_ignores_the_recorded_roots() {
        let (_d, db) = db_over_three_roots("forged");
        // An attacker narrows the record to hide that /opt/eos was ever covered.
        db.conn
            .execute("UPDATE meta SET v = '/etc' WHERE k = 'roots'", [])
            .expect("forge roots");
        let (_, sum) = db
            .diff(
                &[entry("/etc/passwd", "bb")],
                &roots(&["/usr/bin", "/etc", "/opt/eos"]),
            )
            .expect("diff");
        // The scan really walked /usr/bin and /opt/eos, so those three files really are gone.
        assert_eq!(
            sum.removed, 3,
            "a forged meta.roots suppressed real removals"
        );
        assert_eq!(sum.out_of_scope, 0);
    }

    #[test]
    fn the_baseline_records_the_roots_it_was_taken_over() {
        let (_d, db) = db_over_three_roots("recorded");
        assert_eq!(
            db.baseline_roots(),
            Some(roots(&["/etc", "/opt/eos", "/usr/bin"])),
            "canonical order is sorted"
        );
    }

    #[test]
    fn the_same_ground_in_another_order_is_the_same_scope() {
        let (_d, db) = db_over_three_roots("sameorder");
        assert_eq!(
            db.scope(&roots(&["/opt/eos", " /etc ", "/usr/bin", "/etc", ""])),
            ScopeState::Same
        );
    }

    #[test]
    fn a_narrowed_scan_names_the_root_it_dropped() {
        let (_d, db) = db_over_three_roots("dropped");
        assert_eq!(
            db.scope(&roots(&["/usr/bin", "/etc"])),
            ScopeState::Changed {
                dropped: roots(&["/opt/eos"]),
                added: vec![]
            }
        );
    }

    #[test]
    fn a_widened_scan_names_the_root_it_added() {
        let (_d, db) = db_over_three_roots("added");
        assert_eq!(
            db.scope(&roots(&["/usr/bin", "/etc", "/opt/eos", "/var/log"])),
            ScopeState::Changed {
                dropped: vec![],
                added: roots(&["/var/log"])
            }
        );
    }

    /// Scope is coverage, not string equality: scanning "/usr" after baselining "/usr/bin" walks
    /// strictly more ground, and calling that a dropped root would be a false alarm.
    #[test]
    fn a_root_swallowed_by_its_parent_was_not_dropped() {
        let d = tmpdir("parent");
        let mut db = Db::open(&d.join("p.db")).expect("open");
        db.set_baseline(
            &[entry("/usr/bin/ls", "aa")],
            &roots(&["/usr/bin", "/usr/lib"]),
        )
        .expect("set_baseline");
        assert_eq!(
            db.scope(&roots(&["/usr"])),
            ScopeState::Changed {
                dropped: vec![],
                added: roots(&["/usr"]),
            }
        );
    }

    /// A baseline written before `meta.roots` existed. It must still diff, still verify, and be
    /// honest that it cannot say what it covered.
    #[test]
    fn a_baseline_without_recorded_roots_is_unknown_not_same() {
        let (_d, db) = db_over_three_roots("legacy");
        let n = db
            .conn
            .execute("DELETE FROM meta WHERE k = 'roots'", [])
            .expect("delete roots");
        assert_eq!(
            n, 1,
            "the roots row was not there to delete -- test is vacuous"
        );
        assert_eq!(db.scope(&roots(&["/usr/bin"])), ScopeState::Unknown);
        // ...and suppression still works, because it never needed the row.
        let (_, sum) = db
            .diff(&[entry("/usr/bin/ls", "aa")], &roots(&["/usr/bin"]))
            .expect("diff");
        assert_eq!(sum.removed, 0);
        assert_eq!(sum.out_of_scope, 3);
    }

    /// THE CONSTRAINT, WRITTEN DOWN AS A TEST. Recording the roots must not reach `digest_rows`:
    /// if it ever did, every baseline already in the field would read NARUSZONY after an upgrade
    /// that changed no file. This goes red the moment somebody adds roots to the digest input.
    #[test]
    fn recording_the_roots_does_not_change_the_baseline_digest() {
        let d = tmpdir("digestinput");
        let mut db = Db::open(&d.join("d.db")).expect("open");
        let files = [entry("/a", "aa"), entry("/b", "bb")];
        let digest_of = |db: &Db| -> String {
            db.conn
                .query_row("SELECT v FROM meta WHERE k = 'baseline_digest'", [], |r| {
                    r.get(0)
                })
                .expect("digest")
        };
        db.set_baseline(&files, &roots(&["/one"])).expect("set 1");
        let first = digest_of(&db);
        db.set_baseline(&files, &roots(&["/completely", "/different"]))
            .expect("set 2");
        assert_eq!(
            first,
            digest_of(&db),
            "the roots leaked into the digest input"
        );
        assert_eq!(db.verify_baseline(), BaselineState::Intact);
    }

    /// And the store stays verifiable with the row absent entirely -- the shape every baseline
    /// written before this change has on disk.
    #[test]
    fn a_baseline_predating_the_roots_row_still_verifies_intact() {
        let (_d, db) = db_over_three_roots("legacydigest");
        db.conn
            .execute("DELETE FROM meta WHERE k = 'roots'", [])
            .expect("delete roots");
        assert_eq!(db.verify_baseline(), BaselineState::Intact);
    }

    // ── The status line ──────────────────────────────────────────────────────────────────────

    /// SILENCE IS A RESULT AND IT IS TESTED. A note on every scan is a note nobody reads.
    #[test]
    fn scope_note_stays_quiet_when_the_scan_covers_the_baseline() {
        assert_eq!(scope_note(&ScopeState::Same, 0), None);
    }

    /// An unrecorded scope, on its own, changes nothing the person can act on: every baseline
    /// path was inside a walked root, so the scan was complete. It earns a line only once
    /// something actually went unchecked.
    #[test]
    fn an_unknown_scope_alone_is_not_worth_a_line() {
        assert_eq!(scope_note(&ScopeState::Unknown, 0), None);
        let spoken = scope_note(&ScopeState::Unknown, 7).expect("7 unchecked files said nothing");
        assert!(spoken.contains('7'), "{spoken}");
        assert!(spoken.contains("nie zapisał"), "{spoken}");
    }

    #[test]
    fn scope_note_names_the_dropped_root_and_counts_what_went_unchecked() {
        let note = scope_note(
            &ScopeState::Changed {
                dropped: roots(&["/opt/eos"]),
                added: vec![],
            },
            1234,
        )
        .expect("a dropped root and 1234 unchecked files said nothing");
        assert!(note.contains("/opt/eos"), "{note}");
        assert!(note.contains("1234"), "{note}");
        assert!(note.contains("NIE SPRAWDZONO"), "{note}");
    }

    /// A widened scan is warned about, not suppressed: every NOWY it produces is a TRUE statement
    /// ("this file is not in the baseline"), merely an uninformative one. That is the opposite of
    /// a false USUNIĘTY, and it earns the opposite treatment.
    #[test]
    fn a_widened_scan_is_explained_even_though_nothing_went_unchecked() {
        let note = scope_note(
            &ScopeState::Changed {
                dropped: vec![],
                added: roots(&["/var/log"]),
            },
            0,
        )
        .expect("an added root said nothing");
        assert!(note.contains("/var/log"), "{note}");
        assert!(
            !note.contains("NIE SPRAWDZONO"),
            "nothing went unchecked: {note}"
        );
    }
}
