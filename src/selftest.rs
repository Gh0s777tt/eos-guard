//! Headless proof of the scan + baseline + diff pipeline (incl. the U-090
//! permission audit and baseline-integrity digest), run by
//! `eos-guard --selftest`. Prints `GUARD-SELFTEST-OK` on success (asserted
//! from the boot serial / CI).

use eos_fsintegrity::db::{self, BaselineState, Db, ScopeState, Status};
use eos_fsintegrity::scan;
use std::fs;
use std::io;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

use crate::sysstatus;

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

    // ── Trust-status lines (PR-004: FDE / RAID-1 / repository) ────────────────────────────
    // Each line is proven in BOTH directions (CLAUDE.md §5.4): that it can say the definite thing,
    // and that it refuses to without the token that justifies it. The fixtures are the producers'
    // own formats -- the bootloader env block, raid1d's state file, pkg-lib's three files -- and
    // the two real-path cases are guarded, so the same binary is a boot probe on the image and a
    // host check here without either reading as the other.
    selftest_fde()?;
    selftest_raid()?;
    selftest_repo()?;
    selftest_trust_lines()?;

    let _ = fs::remove_dir_all(&root);
    Ok(())
}

fn selftest_fde() -> Result<(), String> {
    use sysstatus::FdeState;
    const ACTIVE: &str = "REDOXFS_BLOCK=0000000000001000\nREDOXFS_UUID=0123-4567-89ab\n\
                          REDOXFS_PASSWORD_ADDR=00000000000ff000\nREDOXFS_PASSWORD_SIZE=0000000000000007\n";
    const INACTIVE: &str = "REDOXFS_BLOCK=0000000000001000\nREDOXFS_UUID=0123-4567-89ab\n";
    const LIVE: &str = "DISK_LIVE_ADDR=0000000080000000\nDISK_LIVE_SIZE=0000000010000000\n";

    // (1) The password key is there -> active, and no "live" anywhere in the sentence.
    let s = sysstatus::parse_fde(ACTIVE);
    if s != (FdeState::Active { live: false }) {
        return Err(format!(
            "FDE (1): an env with REDOXFS_PASSWORD_ADDR parsed as {s:?}"
        ));
    }
    let text = s.describe();
    if !text.contains("aktywne") || text.contains("NIEAKTYWNE") || text.contains("live") {
        return Err(format!("FDE (1): wrong sentence: {text}"));
    }
    // (1b) Both keys: an encrypted disk booted live is still active, with the suffix.
    let s = sysstatus::parse_fde(&format!("{LIVE}{ACTIVE}"));
    if s != (FdeState::Active { live: true }) {
        return Err(format!("FDE (1b): an encrypted live boot parsed as {s:?}"));
    }
    let text = s.describe();
    if !text.contains("aktywne") || !text.contains("live") {
        return Err(format!("FDE (1b): wrong sentence: {text}"));
    }
    // (2) UUID and no password key -> inactive, with the glyph, without "live".
    let s = sysstatus::parse_fde(INACTIVE);
    if s != (FdeState::Inactive { live: false }) {
        return Err(format!(
            "FDE (2): an env without the password key parsed as {s:?}"
        ));
    }
    let text = s.describe();
    if !text.starts_with('⚠') || !text.contains("NIEAKTYWNE") || text.contains("live") {
        return Err(format!("FDE (2): wrong sentence: {text}"));
    }
    // (3) The shipped live image: live is a SUFFIX, so the warning stays.
    let s = sysstatus::parse_fde(&format!(
        "{LIVE}REDOXFS_BLOCK=0000000000000000\nREDOXFS_UUID=0123-4567-89ab\n"
    ));
    if s != (FdeState::Inactive { live: true }) {
        return Err(format!("FDE (3): an unencrypted live boot parsed as {s:?}"));
    }
    let text = s.describe();
    if !text.starts_with('⚠') || !text.contains("NIEAKTYWNE") || !text.contains("live") {
        return Err(format!("FDE (3): a live boot lost its warning: {text}"));
    }
    // (4) The real path. On a host it does not exist and the line MUST say "nieznane". On the
    // image it does, and the answer MUST be definite -- active or inactive, never "nieznane":
    // sys:env has no uid gate and the bootloader always writes REDOXFS_UUID, so an unknown there
    // is a regression in this reader, not a legitimate reading. (RAID (4) is looser on purpose:
    // a restricted namespace can hide /scheme entries; nothing hides the kernel env.) Printed,
    // so a boot log carries the measurement.
    let env = Path::new(sysstatus::FDE_ENV_PATH);
    let s = sysstatus::read_fde(env);
    let text = s.describe();
    if !env.exists() {
        if !matches!(s, FdeState::Unknown(_)) || !text.contains("nieznane") {
            return Err(format!(
                "FDE (4): {} does not exist here, yet read_fde said: {text}",
                sysstatus::FDE_ENV_PATH
            ));
        }
    } else {
        if !matches!(s, FdeState::Active { .. } | FdeState::Inactive { .. }) {
            return Err(format!(
                "FDE (4): {} exists, yet the line is not definite: {text}",
                sysstatus::FDE_ENV_PATH
            ));
        }
        eprintln!("eos-guard selftest: {text}");
    }
    // (5) NEGATIVE: the token inside a value, or as a prefix of a longer key, is not the key.
    let s = sysstatus::parse_fde(
        "REDOXFS_UUID=0123-4567-89ab\nBOOT_NOTE=REDOXFS_PASSWORD_ADDR=1\nREDOXFS_PASSWORD_ADDR2=00ff\n",
    );
    if s != (FdeState::Inactive { live: false }) {
        return Err(format!(
            "an env whose VALUE mentions REDOXFS_PASSWORD_ADDR was read as FDE active ({s:?})"
        ));
    }
    // (6) NEGATIVE: no REDOXFS_UUID is no evidence either way.
    for env in ["", "FOO=bar\n"] {
        let s = sysstatus::parse_fde(env);
        if !matches!(s, FdeState::Unknown(_)) {
            return Err(format!(
                "FDE (6): an env without REDOXFS_UUID ({env:?}) was read as {s:?}, not Unknown"
            ));
        }
    }
    Ok(())
}

fn selftest_raid() -> Result<(), String> {
    use sysstatus::{RaidState, RaidStateFile, RAID_STATE_READ_LIMIT};
    const OPTIMAL: &str = "array = ab12\nusable_mib = 1024\nblock_size = 4096\nstatus = optimal\n\
                           members = 2/2\nmember 0 = active (generation 5, /scheme/disk.nvme/0)\n\
                           member 1 = active (generation 5, /scheme/disk.nvme/1)\n";
    const DEGRADED: &str =
        "array = ab12\nusable_mib = 1024\nblock_size = 4096\nstatus = degraded\n\
                            members = 1/2\nmember 0 = active (generation 5, /scheme/disk.nvme/0)\n\
                            member 1 = excluded (generation 3, /scheme/disk.nvme/1)\n";
    fn names(list: &[&str]) -> io::Result<Vec<String>> {
        Ok(list.iter().map(|s| s.to_string()).collect())
    }
    fn absent() -> io::Result<RaidStateFile> {
        Err(io::Error::from(io::ErrorKind::NotFound))
    }
    /// A state file only root could have written -- raid1d's own.
    fn by_root(text: &str) -> io::Result<RaidStateFile> {
        Ok(RaidStateFile {
            text: text.into(),
            distrust: None,
        })
    }

    // (1) Scheme registered (the trailing newline getdents may add, on purpose) + a consistent
    // optimal file -> healthy.
    let s = sysstatus::raid_state(names(&["disk.nvme", "disk.raid1\n"]), by_root(OPTIMAL));
    if s != (RaidState::Healthy {
        active: 2,
        total: 2,
    }) {
        return Err(format!(
            "RAID (1): a registered optimal array parsed as {s:?}"
        ));
    }
    let text = s.describe();
    if !text.contains("sprawna") || !text.contains("2 z 2") {
        return Err(format!("RAID (1): wrong sentence: {text}"));
    }
    // (2) Degraded, one member excluded.
    let s = sysstatus::raid_state(names(&["disk.raid1"]), by_root(DEGRADED));
    if s != (RaidState::Degraded {
        active: 1,
        total: 2,
    }) {
        return Err(format!("RAID (2): a degraded array parsed as {s:?}"));
    }
    let text = s.describe();
    if !text.starts_with('⚠') || !text.contains("ZDEGRADOWANA") || !text.contains("1 z 2") {
        return Err(format!("RAID (2): wrong sentence: {text}"));
    }
    // (3) Neither signal -> not detected, said as the absence it is.
    let s = sysstatus::raid_state(names(&["disk.nvme", "ip"]), absent());
    if s != RaidState::NotDetected {
        return Err(format!("RAID (3): no scheme and no file parsed as {s:?}"));
    }
    let text = s.describe();
    if !text.contains("nie wykryto") || text.contains("sprawna") {
        return Err(format!("RAID (3): wrong sentence: {text}"));
    }
    // (4) The real paths, guarded exactly like FDE (4): a host without /scheme must read
    // "nieznane"; on the image any of the four labels is a legitimate answer (a restricted
    // namespace yields Unknown), so only the label set is asserted, and the line is printed.
    let s = sysstatus::read_raid();
    let text = s.describe();
    if !Path::new(sysstatus::SCHEME_DIR).exists() {
        if !matches!(s, RaidState::Unknown(_)) || !text.contains("nieznane") {
            return Err(format!(
                "RAID (4): {} does not exist here, yet read_raid said: {text}",
                sysstatus::SCHEME_DIR
            ));
        }
    } else {
        if !(text.contains("sprawna")
            || text.contains("ZDEGRADOWANA")
            || text.contains("nie wykryto")
            || text.contains("nieznane"))
        {
            return Err(format!(
                "RAID (4): unrecognised sentence for the real array: {text}"
            ));
        }
        eprintln!("eos-guard selftest: {text}");
    }
    // (5) NEGATIVE: a status token raid1d never writes.
    let s = sysstatus::raid_state(
        names(&["disk.raid1"]),
        by_root("status = healthy\nmembers = 2/2\n"),
    );
    if matches!(s, RaidState::Healthy { .. }) {
        return Err("a state file saying status = healthy was reported as an optimal array".into());
    }
    if !matches!(s, RaidState::Unknown(_)) {
        return Err(format!("RAID (5): an unknown status token parsed as {s:?}"));
    }
    // (6) NEGATIVE: self-contradictory file.
    let s = sysstatus::raid_state(
        names(&["disk.raid1"]),
        by_root("status = optimal\nmembers = 1/2\n"),
    );
    if !matches!(s, RaidState::Unknown(_)) {
        return Err(format!(
            "RAID (6): optimal with 1/2 members parsed as {s:?}"
        ));
    }
    // (7) NEGATIVE: a file without the daemon -- what a planted file in sticky /tmp looks like.
    let s = sysstatus::raid_state(names(&["disk.nvme"]), by_root(OPTIMAL));
    if !matches!(s, RaidState::Unknown(_)) || !s.describe().contains("bez działającego demona") {
        return Err(format!(
            "RAID (7): a state file with no disk.raid1 scheme parsed as {s:?}"
        ));
    }
    // (8) NEGATIVE: the daemon without its file is not "not detected".
    let s = sysstatus::raid_state(names(&["disk.raid1"]), absent());
    if !matches!(s, RaidState::Unknown(_)) {
        return Err(format!(
            "RAID (8): disk.raid1 registered with no state file parsed as {s:?}"
        ));
    }
    // (9) NEGATIVE: the daemon is up and the file says optimal, but the file is one anyone could
    // have written (not root's, or writable by others). /tmp is world-writable: if raid1d's own
    // file could be replaced, its content proves nothing and the line must not say "sprawna".
    let s = sysstatus::raid_state(
        names(&["disk.raid1"]),
        Ok(RaidStateFile {
            text: OPTIMAL.into(),
            distrust: Some("nie należy do roota"),
        }),
    );
    let text = s.describe();
    if !matches!(s, RaidState::Unknown(_))
        || !text.contains("nie należy do roota")
        || text.contains("sprawna")
    {
        return Err(format!(
            "RAID (9): an optimal file that is not root's was reported as: {text}"
        ));
    }
    // (10) The reader behind (9), on a fixture: the facts have to come from the filesystem.
    let dir = std::env::temp_dir().join("eos-guard-selftest-raid");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).map_err(|e| format!("mkdir raid fixture: {e}"))?;
    let state = dir.join("raid1d.state");
    // (10a) 0644 is trusted iff root's. The file's uid is whoever runs this -- root on the image,
    // a user on a host -- so the file's own uid picks the arm; both arms are real assertions.
    fs::write(&state, OPTIMAL).map_err(|e| format!("write raid1d.state: {e}"))?;
    fs::set_permissions(&state, fs::Permissions::from_mode(0o644))
        .map_err(|e| format!("chmod 644: {e}"))?;
    let owner = fs::metadata(&state)
        .map_err(|e| format!("stat raid1d.state: {e}"))?
        .uid();
    let f = sysstatus::read_raid_state_file(&state).map_err(|e| format!("RAID (10a): {e}"))?;
    if f.text != OPTIMAL {
        return Err(format!(
            "RAID (10a): the text read back differs: {:?}",
            f.text
        ));
    }
    match (owner, f.distrust) {
        (0, None) => {}
        (0, Some(why)) => {
            return Err(format!(
                "RAID (10a): root's 0644 state file was distrusted: {why}"
            ))
        }
        (_, Some(why)) if why.contains("roota") => {}
        (uid, other) => {
            return Err(format!(
                "RAID (10a): a 0644 state file owned by uid {uid} came back as {other:?}"
            ))
        }
    }
    // (10b) Writable by others: distrusted whoever owns it.
    fs::set_permissions(&state, fs::Permissions::from_mode(0o666))
        .map_err(|e| format!("chmod 666: {e}"))?;
    let f = sysstatus::read_raid_state_file(&state).map_err(|e| format!("RAID (10b): {e}"))?;
    if !f.distrust.is_some_and(|why| why.contains("zapisywalny")) {
        return Err(format!(
            "RAID (10b): a 0666 state file came back as {:?}",
            f.distrust
        ));
    }
    // (10c) A symlink, even to that file, is not the regular file raid1d writes.
    let link = dir.join("raid1d.link");
    std::os::unix::fs::symlink(&state, &link).map_err(|e| format!("symlink: {e}"))?;
    let f = sysstatus::read_raid_state_file(&link).map_err(|e| format!("RAID (10c): {e}"))?;
    if !f
        .distrust
        .is_some_and(|why| why.contains("zwykłym plikiem"))
    {
        return Err(format!(
            "RAID (10c): a symlink to the state file came back as {:?}",
            f.distrust
        ));
    }
    // (10d) Bounded: a file past the limit is read up to it and no further, and distrusted.
    let big = dir.join("raid1d.big");
    fs::write(&big, vec![b'x'; RAID_STATE_READ_LIMIT as usize + 1])
        .map_err(|e| format!("write big: {e}"))?;
    let f = sysstatus::read_raid_state_file(&big).map_err(|e| format!("RAID (10d): {e}"))?;
    if f.text.len() as u64 != RAID_STATE_READ_LIMIT {
        return Err(format!(
            "RAID (10d): the read was not bounded: {} bytes came back",
            f.text.len()
        ));
    }
    if !f.distrust.is_some_and(|why| why.contains("większy")) {
        return Err(format!(
            "RAID (10d): an oversized state file came back as {:?}",
            f.distrust
        ));
    }
    // (10e) Absent: NotFound passed through -- the one error raid_state may read as "not detected".
    match sysstatus::read_raid_state_file(&dir.join("absent")) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        other => {
            return Err(format!(
                "RAID (10e): a missing state file came back as {other:?}"
            ))
        }
    }
    let _ = fs::remove_dir_all(&dir);
    Ok(())
}

/// One fixture sysroot in pkg-lib's layout. Rebuilt from scratch per case so nothing leaks between
/// them; `key`/`state` `None` means the file is absent.
fn repo_fixture(
    root: &Path,
    key: Option<&str>,
    source: &str,
    state: Option<&str>,
) -> Result<(), String> {
    let _ = fs::remove_dir_all(root);
    fs::create_dir_all(root.join("etc/pkg.d")).map_err(|e| format!("mkdir pkg.d: {e}"))?;
    fs::create_dir_all(root.join("etc/pkg")).map_err(|e| format!("mkdir pkg: {e}"))?;
    if let Some(key) = key {
        fs::write(root.join("etc/pkg/eos-repo-sign.pub.toml"), key)
            .map_err(|e| format!("write key: {e}"))?;
    }
    fs::write(root.join("etc/pkg.d/50_eos"), source).map_err(|e| format!("write 50_eos: {e}"))?;
    if let Some(state) = state {
        fs::write(root.join("etc/pkg/repo-state.toml"), state)
            .map_err(|e| format!("write repo-state: {e}"))?;
    }
    Ok(())
}

fn selftest_repo() -> Result<(), String> {
    use sysstatus::RepoState;
    const HEX32: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let key_with_ml_dsa = format!(
        "# E-OS repo signing PUBLIC keys — ship with the repo/verifier.\n[public_keys]\n\
         ed25519 = \"{HEX32}\"\nml_dsa_65 = \"deadbeef\"\n"
    );
    let key_ed25519_only = format!("[public_keys]\ned25519 = \"{HEX32}\"\n");
    const SOURCE: &str = "https://example.invalid/pkg\n";
    const SOURCE_X86_64: &str =
        "# E-OS package source (R-701)\n#https://gh0s777tt.github.io/eos-pkg-x86_64/pkg\n";
    let root = std::env::temp_dir().join("eos-guard-selftest-root");

    // (1) Key, source, watermark -> the accepted-index sentence, which names the facts and never
    // says "podpisane": the file it reads is written without a key and is root-writable.
    repo_fixture(
        &root,
        Some(&key_with_ml_dsa),
        SOURCE,
        Some("serial = 10480\n"),
    )?;
    let s = sysstatus::read_repo(&root);
    match &s {
        RepoState::Accepted {
            serial: 10480,
            key,
            sources,
        } if key.ml_dsa_65 && sources.len() == 1 => {}
        other => return Err(format!("repo (1): a full tree parsed as {other:?}")),
    }
    let text = s.describe();
    if !text.contains("ostatni przyjęty indeks") || !text.contains("10480") {
        return Err(format!("repo (1): wrong sentence: {text}"));
    }
    if !text.contains("NIE sprawdzane") || text.contains("podpisane") {
        return Err(format!("repo (1): the sentence claims too much: {text}"));
    }
    // (1t) The twin without ml_dsa_65: the presence flag must flip the wording.
    repo_fixture(
        &root,
        Some(&key_ed25519_only),
        SOURCE,
        Some("serial = 10480\n"),
    )?;
    let text = sysstatus::read_repo(&root).describe();
    if !text.contains("brak w kluczu") || text.contains("NIE sprawdzane") {
        return Err(format!(
            "repo (1t): a key without ml_dsa_65 described as: {text}"
        ));
    }
    // (2) No watermark: says so, and hints at S-11 rather than at a command that cannot help.
    repo_fixture(&root, Some(&key_with_ml_dsa), SOURCE, None)?;
    let s = sysstatus::read_repo(&root);
    if !matches!(s, RepoState::NoWatermark { .. }) {
        return Err(format!(
            "repo (2): a tree without repo-state.toml parsed as {s:?}"
        ));
    }
    let text = s.describe();
    if !text.contains("brak znaku wodnego") || text.contains("podpisane") {
        return Err(format!("repo (2): wrong sentence: {text}"));
    }
    // (3) The x86_64 file: a commented URL is not a source.
    repo_fixture(&root, Some(&key_with_ml_dsa), SOURCE_X86_64, None)?;
    let s = sysstatus::read_repo(&root);
    if !matches!(s, RepoState::NoSource { .. }) {
        return Err(format!(
            "repo (3): a comment-only pkg.d file parsed as {s:?}"
        ));
    }
    if !s.describe().contains("brak skonfigurowanego źródła") {
        return Err(format!("repo (3): wrong sentence: {}", s.describe()));
    }
    // (4) No /etc/pkg.d at all -> unknown, not "NIEPODPISANE": the host case.
    let s = sysstatus::read_repo(Path::new("/nonexistent-eos-guard"));
    if !matches!(s, RepoState::Unknown(_)) || !s.describe().contains("nieznane") {
        return Err(format!("repo (4): a missing sysroot parsed as {s:?}"));
    }
    // (5) NEGATIVE: a 2-byte ed25519 field is not a key.
    repo_fixture(
        &root,
        Some("[public_keys]\ned25519 = \"abcd\"\n"),
        SOURCE,
        Some("serial = 10480\n"),
    )?;
    let s = sysstatus::read_repo(&root);
    if matches!(s, RepoState::Accepted { .. }) {
        return Err("a 2-byte ed25519 field was accepted as a pinned key".into());
    }
    if s != RepoState::KeyInvalid || !s.describe().contains("NIEPOPRAWNY") {
        return Err(format!("repo (5): a malformed key parsed as {s:?}"));
    }
    // (6) NEGATIVE: source and watermark but no key -> NIEPODPISANE; the watermark buys nothing.
    repo_fixture(&root, None, SOURCE, Some("serial = 10480\n"))?;
    let s = sysstatus::read_repo(&root);
    if s != RepoState::Unsigned || !s.describe().contains("NIEPODPISANE") {
        return Err(format!("repo (6): a tree without a key parsed as {s:?}"));
    }
    // (7) NEGATIVE: an unparsable serial is no watermark ...
    repo_fixture(
        &root,
        Some(&key_with_ml_dsa),
        SOURCE,
        Some("serial = abc\n"),
    )?;
    let s = sysstatus::read_repo(&root);
    if !matches!(s, RepoState::NoWatermark { .. }) {
        return Err(format!("repo (7): `serial = abc` parsed as {s:?}"));
    }
    // (7b) ... and neither is 0, which pkg-lib never writes.
    repo_fixture(&root, Some(&key_with_ml_dsa), SOURCE, Some("serial = 0\n"))?;
    let s = sysstatus::read_repo(&root);
    if matches!(s, RepoState::Accepted { .. }) {
        return Err(
            "a watermark of serial 0 -- one pkg-lib never writes -- bought the accepted-index sentence"
                .into(),
        );
    }
    if !matches!(s, RepoState::NoWatermark { .. }) {
        return Err(format!("repo (7b): `serial = 0` parsed as {s:?}"));
    }
    // (8) Blank lines are skipped: exactly one source, not three.
    repo_fixture(
        &root,
        Some(&key_with_ml_dsa),
        "\n\nhttps://example.invalid/pkg\n",
        Some("serial = 10480\n"),
    )?;
    match sysstatus::read_repo(&root) {
        RepoState::Accepted { sources, .. } if sources.len() == 1 => {}
        other => {
            return Err(format!(
                "repo (8): blank lines in pkg.d parsed as {other:?}"
            ))
        }
    }
    // (9) NEGATIVE: a line pkg itself refuses is neither a source nor "no source".
    repo_fixture(
        &root,
        Some(&key_with_ml_dsa),
        "not-a-url\n",
        Some("serial = 10480\n"),
    )?;
    let s = sysstatus::read_repo(&root);
    if !matches!(s, RepoState::Unknown(_)) {
        return Err(format!("repo (9): `not-a-url` in pkg.d parsed as {s:?}"));
    }
    // (10) NEGATIVE: an UNREADABLE key is not a MISSING key. Skipped where the file stays readable
    // after chmod 000 (root), because then nothing was made unreadable.
    repo_fixture(
        &root,
        Some(&key_with_ml_dsa),
        SOURCE,
        Some("serial = 10480\n"),
    )?;
    let key_path = root.join("etc/pkg/eos-repo-sign.pub.toml");
    fs::set_permissions(&key_path, fs::Permissions::from_mode(0o000))
        .map_err(|e| format!("chmod key: {e}"))?;
    let unreadable = fs::read(&key_path).is_err();
    let s = sysstatus::read_repo(&root);
    let _ = fs::set_permissions(&key_path, fs::Permissions::from_mode(0o644));
    if unreadable && !matches!(s, RepoState::Unknown(_)) {
        return Err(format!(
            "repo (10): an unreadable key file parsed as {s:?}, not Unknown"
        ));
    }
    // (10b) NEGATIVE: an UNREADABLE watermark is not a MISSING watermark. A directory in place of
    // the file fails `read_to_string` with EISDIR on Linux and macOS whoever runs it, so unlike
    // (10) this control holds as root. It is guarded only for a platform whose read of a
    // directory succeeds (Redox may hand back the listing), and says so when it skips.
    repo_fixture(&root, Some(&key_with_ml_dsa), SOURCE, None)?;
    let state_path = root.join("etc/pkg/repo-state.toml");
    fs::create_dir(&state_path).map_err(|e| format!("mkdir repo-state.toml: {e}"))?;
    if fs::read_to_string(&state_path).is_err() {
        let s = sysstatus::read_repo(&root);
        let text = s.describe();
        if !matches!(s, RepoState::Unknown(_))
            || !text.contains("nieznane")
            || !text.contains("repo-state.toml")
            || text.contains("brak znaku wodnego")
        {
            return Err(format!(
                "repo (10b): an unreadable repo-state.toml was reported as: {text}"
            ));
        }
    } else {
        eprintln!(
            "eos-guard selftest: repo (10b) skipped -- this platform reads a directory as a file"
        );
    }
    // (10c) NEGATIVE: an UNREADABLE key is not a MISSING key -- the root-proof twin of (10), same
    // directory shape and the same guard.
    repo_fixture(&root, None, SOURCE, Some("serial = 10480\n"))?;
    let key_dir = root.join("etc/pkg/eos-repo-sign.pub.toml");
    fs::create_dir(&key_dir).map_err(|e| format!("mkdir key dir: {e}"))?;
    if fs::read_to_string(&key_dir).is_err() {
        let s = sysstatus::read_repo(&root);
        let text = s.describe();
        if !matches!(s, RepoState::Unknown(_))
            || !text.contains("nieznane")
            || !text.contains("eos-repo-sign.pub.toml")
            || text.contains("NIEPODPISANE")
        {
            return Err(format!(
                "repo (10c): an unreadable key file was reported as: {text}"
            ));
        }
    } else {
        eprintln!(
            "eos-guard selftest: repo (10c) skipped -- this platform reads a directory as a file"
        );
    }
    // (10d) NEGATIVE: an UNREADABLE pkg.d file is not "no source". Only chmod 000 fits here (a
    // directory is skipped, as pkg-lib skips it), so like (10) this is skipped as root.
    repo_fixture(
        &root,
        Some(&key_with_ml_dsa),
        SOURCE,
        Some("serial = 10480\n"),
    )?;
    let source_path = root.join("etc/pkg.d/50_eos");
    fs::set_permissions(&source_path, fs::Permissions::from_mode(0o000))
        .map_err(|e| format!("chmod 50_eos: {e}"))?;
    let unreadable = fs::read(&source_path).is_err();
    let s = sysstatus::read_repo(&root);
    let _ = fs::set_permissions(&source_path, fs::Permissions::from_mode(0o644));
    if unreadable {
        let text = s.describe();
        if !matches!(s, RepoState::Unknown(_))
            || !text.contains("50_eos")
            || text.contains("brak skonfigurowanego źródła")
        {
            return Err(format!(
                "repo (10d): an unreadable pkg.d file was reported as: {text}"
            ));
        }
    }
    // (10e) NEGATIVE: a pkg.d entry that cannot be stat'ed is not "no source" either. A dangling
    // symlink is listed but fails the stat whoever runs this; `is_file()` would have swallowed
    // that error and skipped the entry.
    repo_fixture(
        &root,
        Some(&key_with_ml_dsa),
        SOURCE,
        Some("serial = 10480\n"),
    )?;
    std::os::unix::fs::symlink(
        "nonexistent-eos-guard-target",
        root.join("etc/pkg.d/60_link"),
    )
    .map_err(|e| format!("symlink 60_link: {e}"))?;
    let s = sysstatus::read_repo(&root);
    let text = s.describe();
    if !matches!(s, RepoState::Unknown(_))
        || !text.contains("60_link")
        || text.contains("brak skonfigurowanego źródła")
    {
        return Err(format!(
            "repo (10e): a dangling symlink in pkg.d was reported as: {text}"
        ));
    }
    // (10f) The same through a pkg.d without its search bit: listable, entries not stat-able.
    // Skipped as root, which stats through it.
    repo_fixture(
        &root,
        Some(&key_with_ml_dsa),
        SOURCE,
        Some("serial = 10480\n"),
    )?;
    let pkg_d = root.join("etc/pkg.d");
    fs::set_permissions(&pkg_d, fs::Permissions::from_mode(0o444))
        .map_err(|e| format!("chmod pkg.d: {e}"))?;
    let unstatable = fs::metadata(pkg_d.join("50_eos")).is_err();
    let s = sysstatus::read_repo(&root);
    let _ = fs::set_permissions(&pkg_d, fs::Permissions::from_mode(0o755));
    if unstatable {
        let text = s.describe();
        if !matches!(s, RepoState::Unknown(_)) || text.contains("brak skonfigurowanego źródła") {
            return Err(format!(
                "repo (10f): a pkg.d whose entries cannot be stat'ed was reported as: {text}"
            ));
        }
    }

    let _ = fs::remove_dir_all(&root);
    Ok(())
}

/// The string `gui.rs` hands to `set_trust_status`, proven here rather than only typed there:
/// three newline-separated non-empty lines, labelled FDE / RAID-1 / repository in that order --
/// the same labels the artefact check greps for in the built binary.
fn selftest_trust_lines() -> Result<(), String> {
    let joined = sysstatus::trust_lines();
    let lines: Vec<&str> = joined.split('\n').collect();
    if lines.len() != 3 {
        return Err(format!(
            "trust_lines() returned {} lines, expected 3:\n{joined}",
            lines.len()
        ));
    }
    for (line, label) in lines
        .iter()
        .zip(["Szyfrowanie dysku (FDE)", "RAID-1", "Repozytorium"])
    {
        if line.trim().is_empty() || !line.contains(label) {
            return Err(format!(
                "trust line for {label:?} is missing or empty: {line:?}"
            ));
        }
    }
    Ok(())
}
