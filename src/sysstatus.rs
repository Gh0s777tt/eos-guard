//! The three trust-status lines under the scan status: full-disk encryption, the RAID-1
//! array, and the package repository's pinned-key state (ROADMAP `PR-004`, the lines the
//! engine split left open). Product code, like `paths.rs`: every reader here is bound to
//! a Redox path constant, which is exactly what the engine crate promises not to know
//! about (`crates/eos-fsintegrity/src/lib.rs`).
//!
//! THE SHAPE IS BORROWED FROM `db::BaselineState`: one enum per line, `describe()` in the
//! language the window speaks, and `Unknown` as a first-class answer that carries its
//! reason. None of the three questions has a safe default, so nothing here returns a
//! bool and no `Unknown` is ever rendered as a definite state (CLAUDE.md §5.4; the
//! `.unwrap_or(true)` that once stood in eos-control's gui.rs:427 is the precedent for
//! why). Every parser is pure and takes its text as an argument, so the selftest and the
//! contract tests can prove both directions -- that a line CAN say "aktywne" / "sprawna",
//! and that it refuses to without the token that justifies it.
//!
//! What these lines do NOT measure (stated again in the README): the FDE line reads the
//! bootloader's environment, not the disk -- a password key present means the bootloader
//! unlocked the root with a password; no TPM, no Secure Boot. The RAID line is raid1d's
//! assembly-time snapshot, so a member dropping out mid-run is invisible until the next
//! boot. The repository line reads three files and never a live verification: ML-DSA-65
//! is not checked on the device, and no published index carries `expires`.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// The kernel's copy of the bootloader environment: one `KEY=VALUE` per line, readable
/// without root (the `sys` scheme gates only its writable entries).
pub const FDE_ENV_PATH: &str = "/scheme/sys/env";
/// Every registered scheme appears here by name; `disk.raid1` only while raid1d serves an array.
pub const SCHEME_DIR: &str = "/scheme";
/// raid1d's assembly-time snapshot (`status = optimal|degraded`, `members = A/M`). `/tmp` is
/// wiped on every boot, so the file can never be a previous boot's.
pub const RAID_STATE_PATH: &str = "/tmp/raid1d.state";
/// The scheme name raid1d registers once an array is assembled -- and never otherwise.
const RAID_SCHEME: &str = "disk.raid1";

// pkg-lib's three private path constants, relative to the install root (`/` on a running
// system). Not `pub` there, so they are repeated here under a `root: &Path` parameter.
const PKG_SOURCES_DIR: &str = "etc/pkg.d";
const PKG_PUBKEY_PATH: &str = "etc/pkg/eos-repo-sign.pub.toml";
const PKG_STATE_PATH: &str = "etc/pkg/repo-state.toml";

// ── FDE ──────────────────────────────────────────────────────────────────────────────────

/// Whether the root RedoxFS was unlocked with a password at boot.
///
/// Read from the env KEYS only, never the values: they are physical addresses of the
/// password page, reachable through `memory:physical`, which is root-only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FdeState {
    /// The env carries a `REDOXFS_PASSWORD_ADDR` key: the bootloader unlocked an encrypted
    /// root. `live` (a `DISK_LIVE_ADDR` key) is an annotation and never changes the state.
    Active {
        /// The root is a RAM copy of the disk image (the boot menu's live mode).
        live: bool,
    },
    /// `REDOXFS_UUID` is there and the password key is not: the root was opened without one.
    Inactive {
        /// Same annotation as on `Active`; the `⚠` stays regardless.
        live: bool,
    },
    /// The env could not be read, or it is not a bootloader env at all (no `REDOXFS_UUID`).
    /// An env without the UUID is not evidence of an unencrypted disk.
    Unknown(String),
}

impl FdeState {
    /// A sentence for the trust line. The `⚠` glyph stays on every inactive variant; the live
    /// annotation is a suffix and nothing more.
    pub fn describe(&self) -> String {
        let live_suffix = |live: bool| {
            if live {
                " (obraz live, root w RAM)"
            } else {
                ""
            }
        };
        match self {
            Self::Active { live } => format!(
                "Szyfrowanie dysku (FDE): aktywne — root odblokowany hasłem przy rozruchu \
                 (RedoxFS AES-XTS-128; bez TPM/Secure Boot){}.",
                live_suffix(*live)
            ),
            Self::Inactive { live } => format!(
                "⚠ Szyfrowanie dysku (FDE): NIEAKTYWNE — system plików root nie jest szyfrowany{}.",
                live_suffix(*live)
            ),
            Self::Unknown(reason) => format!("Szyfrowanie dysku (FDE): nieznane — {reason}."),
        }
    }
}

/// Parse the bootloader environment text. Each line is split on its FIRST `=` and only the
/// KEY is compared, exactly (the `lived` driver's rule): the token inside a value, or as a
/// prefix of a longer key, does not count.
pub fn parse_fde(env: &str) -> FdeState {
    let mut uuid = false;
    let mut password = false;
    let mut live = false;
    for line in env.lines() {
        let Some((key, _value)) = line.split_once('=') else {
            continue;
        };
        match key {
            "REDOXFS_UUID" => uuid = true,
            "REDOXFS_PASSWORD_ADDR" => password = true,
            "DISK_LIVE_ADDR" => live = true,
            _ => {}
        }
    }
    if !uuid {
        return FdeState::Unknown("środowisko rozruchu bez REDOXFS_UUID".to_string());
    }
    if password {
        FdeState::Active { live }
    } else {
        FdeState::Inactive { live }
    }
}

/// Read and parse `path` (`FDE_ENV_PATH` in production). EVERY read error is `Unknown`, absence
/// included: a missing env says nothing about the disk.
pub fn read_fde(path: &Path) -> FdeState {
    match fs::read_to_string(path) {
        Ok(text) => parse_fde(&text),
        Err(e) => FdeState::Unknown(format!("nie odczytano {} ({e})", path.display())),
    }
}

// ── RAID-1 ───────────────────────────────────────────────────────────────────────────────

/// One parsed `/tmp/raid1d.state`, in raid1d's own terms.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RaidArray {
    /// `status = optimal` (every member active, at least two of them) rather than `degraded`.
    pub optimal: bool,
    /// Active members -- the `A` of `members = A/M`.
    pub active: u32,
    /// Members the array was assembled from -- the `M`.
    pub total: u32,
}

/// What the machine says about its RAID-1 array. TWO SIGNALS, BOTH REQUIRED for any definite
/// state: the `disk.raid1` scheme name (raid1d registers it only after assembly) and the
/// state file (written at assembly, before registration). `/tmp` is sticky-world-writable,
/// so any local user can plant the file when it is absent -- which is why the file alone
/// renders `Unknown`, never `Healthy`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RaidState {
    /// `disk.raid1` is registered and the state file says `optimal`, consistently.
    Healthy {
        /// Active members.
        active: u32,
        /// Members assembled.
        total: u32,
    },
    /// `disk.raid1` is registered and the state file says `degraded`.
    Degraded {
        /// Active members.
        active: u32,
        /// Members assembled.
        total: u32,
    },
    /// `/scheme` lists no `disk.raid1` and there is no state file. What the absence of both
    /// signals proves, and nothing more: no array was ASSEMBLED this boot. Not "none
    /// configured" -- a daemon that never started, or died on a hostile superblock before
    /// `write_state`, leaves the same nothing.
    NotDetected,
    /// One signal without the other, an inconsistent file, or a directory that could not be
    /// listed. Carries the reason.
    Unknown(String),
}

impl RaidState {
    /// A sentence for the trust line. Both definite states say "stan z chwili rozruchu": the
    /// daemon enters a null namespace after startup and cannot update the file.
    pub fn describe(&self) -> String {
        match self {
            Self::Healthy { active, total } => {
                format!("RAID-1: sprawna — {active} z {total} członków (stan z chwili rozruchu).")
            }
            Self::Degraded { active, total } => format!(
                "⚠ RAID-1: ZDEGRADOWANA — aktywnych {active} z {total} członków (stan z chwili \
                 rozruchu; sprawdź `raid1d status`)."
            ),
            Self::NotDetected => format!(
                "RAID-1: nie wykryto macierzy ({RAID_SCHEME} niezarejestrowany, brak {RAID_STATE_PATH})."
            ),
            Self::Unknown(reason) => format!("RAID-1: nieznane — {reason}."),
        }
    }
}

/// Parse raid1d's state file. `None` is a real answer: no `status =` line, a status token raid1d
/// never writes, no `members = A/M`, `A > M`, or `optimal` with fewer than all (or fewer than
/// two) members active -- raid1d writes `optimal` iff `active == member_count && active >= 2`,
/// so a file saying otherwise was not written by raid1d and proves nothing.
pub fn parse_raid_state(text: &str) -> Option<RaidArray> {
    let mut status: Option<&str> = None;
    let mut members: Option<(u32, u32)> = None;
    for line in text.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        match key.trim() {
            "status" => status = Some(value.trim()),
            "members" => {
                let (a, m) = value.trim().split_once('/')?;
                members = Some((a.trim().parse().ok()?, m.trim().parse().ok()?));
            }
            _ => {}
        }
    }
    let optimal = match status? {
        "optimal" => true,
        "degraded" => false,
        _ => return None,
    };
    let (active, total) = members?;
    if active > total {
        return None;
    }
    if optimal && (active != total || active < 2) {
        return None;
    }
    Some(RaidArray {
        optimal,
        active,
        total,
    })
}

/// How much of the state file is read: raid1d writes a header and one line per member, a few
/// hundred bytes. `/tmp` is world-writable, so without a bound a planted multi-gigabyte file
/// would have the window allocate it at startup; with it the cost is 64 KiB, and a file that
/// long is refused as not raid1d's.
pub const RAID_STATE_READ_LIMIT: u64 = 64 * 1024;

/// raid1d's state file as read, together with the one question its content cannot answer
/// about itself: could anyone but root have written it?
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RaidStateFile {
    /// The text, at most `RAID_STATE_READ_LIMIT` bytes of it.
    pub text: String,
    /// Why the file could be anyone's, when it could -- a predicate completing "plik stanu
    /// /tmp/raid1d.state ...": not a regular file, longer than raid1d ever writes, writable by
    /// group or others, or not owned by uid 0. `None` means only root could have produced it,
    /// which is what makes the content worth parsing at all.
    pub distrust: Option<&'static str>,
}

/// Open `path` (`RAID_STATE_PATH` in production) and read it with the facts `RaidStateFile`
/// carries. Anything but a regular file is refused BEFORE the open (a symlink could point at
/// any root-owned file; a FIFO would block the window on open); the owner and mode come from
/// `fstat` on the handle the text is read from, so they describe the same inode as the text.
/// Read errors, absence included, come back as they are: `raid_state` decides what they mean.
pub fn read_raid_state_file(path: &Path) -> io::Result<RaidStateFile> {
    use std::io::Read;
    use std::os::unix::fs::MetadataExt;
    if !fs::symlink_metadata(path)?.file_type().is_file() {
        return Ok(RaidStateFile {
            text: String::new(),
            distrust: Some("nie jest zwykłym plikiem"),
        });
    }
    let file = fs::File::open(path)?;
    let meta = file.metadata()?;
    let mut text = String::new();
    file.take(RAID_STATE_READ_LIMIT).read_to_string(&mut text)?;
    let distrust = if !meta.is_file() {
        Some("nie jest zwykłym plikiem")
    } else if text.len() as u64 >= RAID_STATE_READ_LIMIT {
        Some("jest większy niż jakikolwiek zapis raid1d")
    } else if meta.mode() & 0o022 != 0 {
        Some("jest zapisywalny dla grupy lub innych")
    } else if meta.uid() != 0 {
        Some("nie należy do roota")
    } else {
        None
    };
    Ok(RaidStateFile { text, distrust })
}

/// Combine the two signals. `listing` is the names under `/scheme`, `state` the state file as
/// `read_raid_state_file` returns it, so the selftest can hand in fixtures. Only "listable, no
/// `disk.raid1`, file NOT FOUND" is `NotDetected`; any other read error stays `Unknown`, and so
/// does a file anyone could have written, whatever it says.
pub fn raid_state(listing: io::Result<Vec<String>>, state: io::Result<RaidStateFile>) -> RaidState {
    let names = match listing {
        Ok(names) => names,
        Err(e) => return RaidState::Unknown(format!("nie odczytano {SCHEME_DIR} ({e})")),
    };
    // getdents may hand a name back with a trailing newline (raid1d warns about it), hence trim.
    let registered = names.iter().any(|n| n.trim() == RAID_SCHEME);
    match (registered, state) {
        (
            true,
            Ok(RaidStateFile {
                distrust: Some(why),
                ..
            }),
        ) => RaidState::Unknown(format!(
            "macierz zgłoszona ({RAID_SCHEME}), ale plik stanu {RAID_STATE_PATH} {why}"
        )),
        (true, Ok(RaidStateFile { text, .. })) => match parse_raid_state(&text) {
            Some(RaidArray {
                optimal: true,
                active,
                total,
            }) => RaidState::Healthy { active, total },
            Some(RaidArray {
                optimal: false,
                active,
                total,
            }) => RaidState::Degraded { active, total },
            None => RaidState::Unknown(format!(
                "macierz zgłoszona ({RAID_SCHEME}), ale niespójny {RAID_STATE_PATH}"
            )),
        },
        (true, Err(e)) => RaidState::Unknown(format!(
            "macierz zgłoszona ({RAID_SCHEME}), ale brak lub nieczytelny {RAID_STATE_PATH} ({e})"
        )),
        (false, Ok(_)) => RaidState::Unknown(format!(
            "plik stanu {RAID_STATE_PATH} bez działającego demona ({RAID_SCHEME} nie jest \
             zarejestrowany)"
        )),
        (false, Err(e)) if e.kind() == io::ErrorKind::NotFound => RaidState::NotDetected,
        (false, Err(e)) => RaidState::Unknown(format!("nie odczytano {RAID_STATE_PATH} ({e})")),
    }
}

/// `raid_state` over the two real paths.
pub fn read_raid() -> RaidState {
    let listing = fs::read_dir(SCHEME_DIR).and_then(|rd| {
        rd.map(|entry| entry.map(|e| e.file_name().to_string_lossy().into_owned()))
            .collect::<io::Result<Vec<String>>>()
    });
    raid_state(listing, read_raid_state_file(Path::new(RAID_STATE_PATH)))
}

// ── Package repository ───────────────────────────────────────────────────────────────────

/// What the pinned repository key file holds, as far as this line reads it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PinnedKey {
    /// An `ml_dsa_65` field with a non-empty hex value is present. PRESENCE ONLY: the device
    /// verifies the ed25519 half alone (pkg-lib checks nothing else), and the sentence says so.
    pub ml_dsa_65: bool,
}

/// What the machine's own files say about its package repository. Facts, in the order they
/// are established: is `/etc/pkg.d` there at all, is a key pinned, is a source named, did
/// pkg-lib ever advance its serial watermark here. NEVER "signed": the watermark file is
/// written even when no key is pinned, and root can rewrite it, so that word waits for a
/// live verification this line does not perform.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RepoState {
    /// Key pinned, at least one source, and `repo-state.toml` carries a serial > 0: pkg-lib once
    /// accepted an index with that serial on this machine.
    Accepted {
        /// The source URLs, in `/etc/pkg.d` file order.
        sources: Vec<String>,
        /// The watermark, as written.
        serial: u64,
        /// What the key file holds.
        key: PinnedKey,
    },
    /// Key pinned and a source configured, but no watermark: the index was never fetched here,
    /// or it carries no serial (the live aarch64 index predates V2-MS15 -- `S-11`), which
    /// leaves no file behind either.
    NoWatermark {
        /// The source URLs.
        sources: Vec<String>,
        /// What the key file holds.
        key: PinnedKey,
    },
    /// Key pinned, but no file under `/etc/pkg.d` names a source (x86_64 ships a commented URL).
    NoSource {
        /// What the key file holds.
        key: PinnedKey,
    },
    /// No key file at all. pkg-lib then prints a warning and accepts an unsigned index.
    Unsigned,
    /// A key file whose `ed25519` field is missing or not 32 bytes; pkg-lib treats it as no key.
    KeyInvalid,
    /// A read failed for a reason other than absence, or a source line pkg itself would reject.
    Unknown(String),
}

fn ml_dsa_note(key: &PinnedKey) -> &'static str {
    if key.ml_dsa_65 {
        "ML-DSA-65: w kluczu, NIE sprawdzane na urządzeniu"
    } else {
        "ML-DSA-65: brak w kluczu"
    }
}

fn sources_phrase(sources: &[String]) -> String {
    let noun = if sources.len() == 1 {
        "źródło"
    } else {
        "źródła"
    };
    format!("{noun} {}", sources.join(", "))
}

impl RepoState {
    /// A sentence for the trust line, leading with the facts measured.
    pub fn describe(&self) -> String {
        match self {
            Self::Accepted {
                sources,
                serial,
                key,
            } => format!(
                "Repozytorium: klucz ed25519 przypięty; {}; ostatni przyjęty indeks serial {serial} \
                 (zapis pkg-lib w /{PKG_STATE_PATH}, plik zapisywalny przez roota); {}.",
                sources_phrase(sources),
                ml_dsa_note(key)
            ),
            Self::NoWatermark { sources, key } => format!(
                "Repozytorium: klucz ed25519 przypięty; {}; brak znaku wodnego serial w \
                 /{PKG_STATE_PATH} (indeks bez numeru seryjnego — S-11 — lub nigdy nie pobrany); {}.",
                sources_phrase(sources),
                ml_dsa_note(key)
            ),
            Self::NoSource { key } => format!(
                "Repozytorium: brak skonfigurowanego źródła w /{PKG_SOURCES_DIR} (klucz ed25519 \
                 przypięty; {}).",
                ml_dsa_note(key)
            ),
            Self::Unsigned => format!(
                "⚠ Repozytorium: NIEPODPISANE — brak przypiętego klucza /{PKG_PUBKEY_PATH}; pkg \
                 zaakceptuje niepodpisany indeks."
            ),
            Self::KeyInvalid => format!(
                "⚠ Repozytorium: klucz w /{PKG_PUBKEY_PATH} NIEPOPRAWNY (ed25519 nie ma 32 B) — \
                 traktowany jak brak klucza."
            ),
            Self::Unknown(reason) => format!("Repozytorium: nieznane — {reason}."),
        }
    }
}

/// Strict hex: even length, ASCII hex digits only. `u8::from_str_radix` alone would accept a
/// leading `+`, which is not a byte anyone signed with.
fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

/// pkg-lib's `field_hex`, re-stated: line-wise `key = "<hex>"`, skipping blank, `#` and `[` lines.
fn field_hex(text: &str, key: &str) -> Option<Vec<u8>> {
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with('[') {
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        if k.trim() != key {
            continue;
        }
        return decode_hex(v.trim().trim_matches('"'));
    }
    None
}

/// Parse the pinned key file. `None` when the `ed25519` field is absent or does not decode to
/// exactly 32 bytes -- the same two ways pkg-lib's `load_pinned_ed25519` returns `None`.
pub fn parse_pubkey(text: &str) -> Option<PinnedKey> {
    let ed25519 = field_hex(text, "ed25519")?;
    if ed25519.len() != 32 {
        return None;
    }
    let ml_dsa_65 = field_hex(text, "ml_dsa_65").is_some_and(|v| !v.is_empty());
    Some(PinnedKey { ml_dsa_65 })
}

/// `scheme://host/...` -> `host`, or `None` when there is no scheme or no host: the shape pkg's
/// `extract_host` refuses with `RepoPathInvalid`, which makes pkg unusable rather than sourced.
fn source_host(url: &str) -> Option<&str> {
    let rest = url.split_once("://")?.1;
    let host = rest.split('/').next()?;
    if host.is_empty() {
        None
    } else {
        Some(host)
    }
}

/// Source URLs from one `/etc/pkg.d` file, pkg-lib's way: every line not starting with `#`,
/// trimmed. Whitespace-only lines are skipped -- they are not sources. A non-comment line
/// without `scheme://host` comes back as `Err(line)`: pkg itself refuses it, so this line may
/// count it neither as a source nor as "no source".
pub fn parse_sources(text: &str) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    for line in text.lines() {
        if line.starts_with('#') {
            continue;
        }
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        match source_host(line) {
            Some(_) => out.push(line.to_string()),
            None => return Err(line.to_string()),
        }
    }
    Ok(out)
}

/// The freshness watermark, read exactly as pkg-lib reads it back (`serial = N`, first line that
/// parses). `0` is NO watermark: pkg-lib advances the mark only for `serial > mark` and the
/// mark starts at 0, so it never writes 0 -- a file that says so was not written by pkg-lib.
pub fn parse_watermark(text: &str) -> Option<u64> {
    text.lines()
        .find_map(|l| l.strip_prefix("serial = ")?.trim().parse::<u64>().ok())
        .filter(|&serial| serial > 0)
}

fn unreadable(path: &Path, e: &io::Error) -> RepoState {
    RepoState::Unknown(format!("nie odczytano {} ({e})", path.display()))
}

/// Read the three files under `root` (`/` in production; a fixture tree in the selftest).
/// `NotFound` is the only error that yields a definite state, and only for the key file
/// (`Unsigned`) and the watermark (`NoWatermark`); every other error is `Unknown` with the
/// path and the errno -- including an entry under `/etc/pkg.d` that cannot be stat'ed (a
/// dangling symlink, a directory without its search bit), which is not evidence of "no
/// source". An unlistable `/etc/pkg.d` is `Unknown` too -- that is the host case, and a dev
/// build must say "nieznane" rather than "NIEPODPISANE".
pub fn read_repo(root: &Path) -> RepoState {
    let sources_dir = root.join(PKG_SOURCES_DIR);
    let entries = match fs::read_dir(&sources_dir) {
        Ok(rd) => rd,
        Err(e) => return unreadable(&sources_dir, &e),
    };
    // The key first: without it nothing else earns a sentence, and the fail-closed wording wins.
    let key_path = root.join(PKG_PUBKEY_PATH);
    let key = match fs::read_to_string(&key_path) {
        Ok(text) => match parse_pubkey(&text) {
            Some(key) => key,
            None => return RepoState::KeyInvalid,
        },
        Err(e) if e.kind() == io::ErrorKind::NotFound => return RepoState::Unsigned,
        Err(e) => return unreadable(&key_path, &e),
    };
    // Sources: regular files only, sorted by name, the order pkg-lib walks them in.
    let mut files: Vec<PathBuf> = Vec::new();
    for entry in entries {
        let path = match entry {
            Ok(entry) => entry.path(),
            Err(e) => return unreadable(&sources_dir, &e),
        };
        // An explicit stat rather than `is_file()`, which swallows its error. Directories and
        // the like are skipped, as pkg-lib skips them; a failed stat is a read error like any other.
        match fs::metadata(&path) {
            Ok(meta) if meta.is_file() => files.push(path),
            Ok(_) => {}
            Err(e) => return unreadable(&path, &e),
        }
    }
    files.sort();
    let mut sources: Vec<String> = Vec::new();
    for path in files {
        let text = match fs::read_to_string(&path) {
            Ok(text) => text,
            Err(e) => return unreadable(&path, &e),
        };
        match parse_sources(&text) {
            Ok(list) => sources.extend(list),
            Err(line) => {
                return RepoState::Unknown(format!(
                    "niepoprawny wpis w {} („{line}”)",
                    path.display()
                ))
            }
        }
    }
    if sources.is_empty() {
        return RepoState::NoSource { key };
    }
    let state_path = root.join(PKG_STATE_PATH);
    match fs::read_to_string(&state_path) {
        Ok(text) => match parse_watermark(&text) {
            Some(serial) => RepoState::Accepted {
                sources,
                serial,
                key,
            },
            None => RepoState::NoWatermark { sources, key },
        },
        Err(e) if e.kind() == io::ErrorKind::NotFound => RepoState::NoWatermark { sources, key },
        Err(e) => unreadable(&state_path, &e),
    }
}

// ── The window's text ────────────────────────────────────────────────────────────────────

/// The three sentences the window shows, newline-joined, always in the order FDE / RAID-1 /
/// repository. The selftest asserts that shape, so the string `set_trust_status` receives is
/// proven and not merely typed.
pub fn trust_lines() -> String {
    [
        read_fde(Path::new(FDE_ENV_PATH)).describe(),
        read_raid().describe(),
        read_repo(Path::new("/")).describe(),
    ]
    .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    // ── FDE ──

    const ENV_ACTIVE: &str = "REDOXFS_BLOCK=0000000000001000\nREDOXFS_UUID=0123-4567\n\
                              REDOXFS_PASSWORD_ADDR=00000000000ff000\nREDOXFS_PASSWORD_SIZE=0000000000000007\n";
    const ENV_INACTIVE: &str = "REDOXFS_BLOCK=0000000000001000\nREDOXFS_UUID=0123-4567\n";

    #[test]
    fn fde_password_key_means_active_and_no_live_suffix() {
        let s = parse_fde(ENV_ACTIVE);
        assert_eq!(s, FdeState::Active { live: false });
        let text = s.describe();
        assert!(
            text.contains("aktywne") && !text.contains("NIEAKTYWNE"),
            "{text}"
        );
        assert!(!text.contains("live"), "{text}");
    }

    #[test]
    fn fde_uuid_without_password_key_means_inactive_with_the_glyph() {
        let s = parse_fde(ENV_INACTIVE);
        assert_eq!(s, FdeState::Inactive { live: false });
        let text = s.describe();
        assert!(
            text.starts_with('⚠') && text.contains("NIEAKTYWNE"),
            "{text}"
        );
        assert!(!text.contains("live"), "{text}");
    }

    #[test]
    fn fde_live_is_a_suffix_on_both_states_and_keeps_the_glyph() {
        let active = parse_fde(&format!("DISK_LIVE_ADDR=1\nDISK_LIVE_SIZE=2\n{ENV_ACTIVE}"));
        assert_eq!(active, FdeState::Active { live: true });
        let text = active.describe();
        assert!(text.contains("aktywne") && text.contains("live"), "{text}");

        let inactive = parse_fde(&format!(
            "DISK_LIVE_ADDR=1\nDISK_LIVE_SIZE=2\n{ENV_INACTIVE}"
        ));
        assert_eq!(inactive, FdeState::Inactive { live: true });
        let text = inactive.describe();
        assert!(
            text.starts_with('⚠') && text.contains("NIEAKTYWNE"),
            "{text}"
        );
        assert!(text.contains("live"), "{text}");
    }

    #[test]
    fn fde_token_in_a_value_or_as_a_key_prefix_does_not_count() {
        let env =
            "REDOXFS_UUID=0123\nBOOT_NOTE=REDOXFS_PASSWORD_ADDR=1\nREDOXFS_PASSWORD_ADDR2=ff\n";
        assert_eq!(parse_fde(env), FdeState::Inactive { live: false });
    }

    #[test]
    fn fde_without_a_uuid_is_unknown_not_inactive() {
        assert!(matches!(parse_fde(""), FdeState::Unknown(_)));
        assert!(matches!(parse_fde("FOO=bar\n"), FdeState::Unknown(_)));
        // A password key with no UUID is not a bootloader env either.
        assert!(matches!(
            parse_fde("REDOXFS_PASSWORD_ADDR=1\n"),
            FdeState::Unknown(_)
        ));
        let text = parse_fde("FOO=bar\n").describe();
        assert!(
            text.contains("nieznane") && text.contains("REDOXFS_UUID"),
            "{text}"
        );
    }

    #[test]
    fn fde_read_error_is_unknown_with_the_path() {
        let s = read_fde(Path::new("/nonexistent-eos-guard/env"));
        let text = s.describe();
        assert!(matches!(s, FdeState::Unknown(_)), "{text}");
        assert!(
            text.contains("nieznane") && text.contains("/nonexistent-eos-guard/env"),
            "{text}"
        );
    }

    // ── RAID ──

    const RAID_OPTIMAL: &str = "array = ab12\nusable_mib = 1024\nblock_size = 4096\nstatus = optimal\n\
                                members = 2/2\nmember 0 = active (generation 5, /scheme/disk.nvme/0)\n\
                                member 1 = active (generation 5, /scheme/disk.nvme/1)\n";
    const RAID_DEGRADED: &str = "array = ab12\nusable_mib = 1024\nblock_size = 4096\nstatus = degraded\n\
                                 members = 1/2\nmember 0 = active (generation 5, /scheme/disk.nvme/0)\n\
                                 member 1 = excluded (generation 3, /scheme/disk.nvme/1)\n";

    fn listing(names: &[&str]) -> io::Result<Vec<String>> {
        Ok(names.iter().map(|n| n.to_string()).collect())
    }

    fn not_found() -> io::Result<RaidStateFile> {
        Err(io::Error::from(io::ErrorKind::NotFound))
    }

    /// A state file only root could have written -- what raid1d's own looks like.
    fn root_file(text: &str) -> io::Result<RaidStateFile> {
        Ok(RaidStateFile {
            text: text.into(),
            distrust: None,
        })
    }

    #[test]
    fn raid_parser_reads_raid1d_format_both_ways() {
        assert_eq!(
            parse_raid_state(RAID_OPTIMAL),
            Some(RaidArray {
                optimal: true,
                active: 2,
                total: 2
            })
        );
        assert_eq!(
            parse_raid_state(RAID_DEGRADED),
            Some(RaidArray {
                optimal: false,
                active: 1,
                total: 2
            })
        );
    }

    #[test]
    fn raid_parser_refuses_what_raid1d_never_writes() {
        assert_eq!(parse_raid_state("status = healthy\nmembers = 2/2\n"), None);
        assert_eq!(parse_raid_state("status = optimal\nmembers = 1/2\n"), None);
        assert_eq!(parse_raid_state("status = optimal\nmembers = 1/1\n"), None);
        assert_eq!(parse_raid_state("status = degraded\nmembers = 3/2\n"), None);
        assert_eq!(parse_raid_state("status = optimal\n"), None);
        assert_eq!(parse_raid_state("members = 2/2\n"), None);
        assert_eq!(parse_raid_state(""), None);
    }

    #[test]
    fn raid_healthy_needs_the_scheme_and_a_consistent_file() {
        let s = raid_state(
            listing(&["disk.nvme", "disk.raid1\n"]),
            root_file(RAID_OPTIMAL),
        );
        assert_eq!(
            s,
            RaidState::Healthy {
                active: 2,
                total: 2
            }
        );
        let text = s.describe();
        assert!(text.contains("sprawna") && text.contains("2 z 2"), "{text}");

        let s = raid_state(listing(&["disk.raid1"]), root_file(RAID_DEGRADED));
        assert_eq!(
            s,
            RaidState::Degraded {
                active: 1,
                total: 2
            }
        );
        let text = s.describe();
        assert!(text.starts_with('⚠') && text.contains("ZDEGRADOWANA") && text.contains("1 z 2"));
    }

    #[test]
    fn raid_absence_of_both_signals_is_not_detected() {
        let s = raid_state(listing(&["disk.nvme", "ip"]), not_found());
        assert_eq!(s, RaidState::NotDetected);
        let text = s.describe();
        assert!(text.contains("nie wykryto"), "{text}");
        assert!(!text.contains("sprawna"), "{text}");
    }

    #[test]
    fn raid_one_signal_without_the_other_is_unknown() {
        // A planted file in sticky /tmp, no daemon.
        let s = raid_state(listing(&["disk.nvme"]), root_file(RAID_OPTIMAL));
        assert!(matches!(s, RaidState::Unknown(_)), "{s:?}");
        assert!(
            s.describe().contains("bez działającego demona"),
            "{}",
            s.describe()
        );
        // The daemon is up but its file is gone.
        let s = raid_state(listing(&["disk.raid1"]), not_found());
        assert!(matches!(s, RaidState::Unknown(_)), "{s:?}");
        // The daemon is up but the file is nonsense.
        let s = raid_state(
            listing(&["disk.raid1"]),
            root_file("status = healthy\nmembers = 2/2\n"),
        );
        assert!(matches!(s, RaidState::Unknown(_)), "{s:?}");
        assert!(s.describe().contains("nieznane"), "{}", s.describe());
    }

    #[test]
    fn raid_file_anyone_could_have_written_is_unknown_even_when_optimal() {
        // The daemon is up and the file says optimal -- but the file is not root's. In a
        // world-writable /tmp that is a file anyone could have put there, whatever it says.
        let s = raid_state(
            listing(&["disk.raid1"]),
            Ok(RaidStateFile {
                text: RAID_OPTIMAL.into(),
                distrust: Some("nie należy do roota"),
            }),
        );
        let text = s.describe();
        assert!(matches!(s, RaidState::Unknown(_)), "{text}");
        assert!(
            text.contains("nieznane") && text.contains("nie należy do roota"),
            "{text}"
        );
        assert!(!text.contains("sprawna"), "{text}");
    }

    #[test]
    fn raid_state_file_reader_reports_who_could_have_written_it() {
        use std::os::unix::fs::MetadataExt;
        let dir = std::env::temp_dir().join("eos-guard-sysstatus-raid-file");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let state = dir.join("raid1d.state");
        fs::write(&state, RAID_OPTIMAL).unwrap();
        fs::set_permissions(&state, fs::Permissions::from_mode(0o644)).unwrap();
        let f = read_raid_state_file(&state).unwrap();
        assert_eq!(f.text, RAID_OPTIMAL);
        // 0644 is trusted iff root's, and the file's uid is whoever runs the test.
        if fs::metadata(&state).unwrap().uid() == 0 {
            assert_eq!(f.distrust, None);
        } else {
            assert!(
                f.distrust.is_some_and(|why| why.contains("roota")),
                "{:?}",
                f.distrust
            );
        }
        // Writable by others: distrusted whoever owns it.
        fs::set_permissions(&state, fs::Permissions::from_mode(0o666)).unwrap();
        let f = read_raid_state_file(&state).unwrap();
        assert!(
            f.distrust.is_some_and(|why| why.contains("zapisywalny")),
            "{:?}",
            f.distrust
        );
        // A symlink, even to that file, is not raid1d's regular file.
        let link = dir.join("raid1d.link");
        std::os::unix::fs::symlink(&state, &link).unwrap();
        let f = read_raid_state_file(&link).unwrap();
        assert!(
            f.distrust
                .is_some_and(|why| why.contains("zwykłym plikiem")),
            "{:?}",
            f.distrust
        );
        // Bounded: read up to the limit and no further, and distrusted for its size.
        let big = dir.join("raid1d.big");
        fs::write(&big, vec![b'x'; RAID_STATE_READ_LIMIT as usize + 1]).unwrap();
        let f = read_raid_state_file(&big).unwrap();
        assert_eq!(f.text.len() as u64, RAID_STATE_READ_LIMIT);
        assert!(
            f.distrust.is_some_and(|why| why.contains("większy")),
            "{:?}",
            f.distrust
        );
        // Absent: the one error that may mean "not detected", passed through as such.
        let e = read_raid_state_file(&dir.join("absent")).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::NotFound);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn raid_read_errors_other_than_absence_stay_unknown() {
        let s = raid_state(
            Err(io::Error::from(io::ErrorKind::PermissionDenied)),
            not_found(),
        );
        assert!(matches!(s, RaidState::Unknown(_)), "{s:?}");
        let s = raid_state(
            listing(&["disk.nvme"]),
            Err(io::Error::from(io::ErrorKind::PermissionDenied)),
        );
        assert!(matches!(s, RaidState::Unknown(_)), "{s:?}");
    }

    // ── Repository ──

    const HEX32: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn key_toml(ml_dsa: bool) -> String {
        let mut s = format!(
            "# E-OS repo signing PUBLIC keys — ship with the repo/verifier.\n[public_keys]\ned25519 = \"{HEX32}\"\n"
        );
        if ml_dsa {
            s.push_str("ml_dsa_65 = \"deadbeef\"\n");
        }
        s
    }

    #[test]
    fn pubkey_needs_32_bytes_of_ed25519_and_reports_ml_dsa_presence() {
        assert_eq!(
            parse_pubkey(&key_toml(true)),
            Some(PinnedKey { ml_dsa_65: true })
        );
        assert_eq!(
            parse_pubkey(&key_toml(false)),
            Some(PinnedKey { ml_dsa_65: false })
        );
        assert_eq!(parse_pubkey("[public_keys]\ned25519 = \"abcd\"\n"), None);
        assert_eq!(
            parse_pubkey("[public_keys]\nml_dsa_65 = \"deadbeef\"\n"),
            None
        );
        assert_eq!(
            parse_pubkey(&key_toml(true).replace(HEX32, &HEX32[1..])),
            None
        );
        // A `+` is not a hex digit, whatever `from_str_radix` thinks.
        assert_eq!(parse_pubkey(&key_toml(true).replace("01", "+1")), None);
        // An empty ml_dsa_65 value is not a key.
        assert_eq!(
            parse_pubkey(&key_toml(false).replace("\n", "\nml_dsa_65 = \"\"\n")),
            Some(PinnedKey { ml_dsa_65: false })
        );
    }

    #[test]
    fn sources_skip_comments_and_blank_lines_and_refuse_what_pkg_refuses() {
        assert_eq!(
            parse_sources(
                "# E-OS package source (R-701)\n#https://gh0s777tt.github.io/eos-pkg-x86_64/pkg\n"
            ),
            Ok(vec![])
        );
        assert_eq!(
            parse_sources("\n\nhttps://example.invalid/pkg\n"),
            Ok(vec!["https://example.invalid/pkg".to_string()])
        );
        assert_eq!(parse_sources("not-a-url\n"), Err("not-a-url".to_string()));
        assert_eq!(
            parse_sources("https:///pkg\n"),
            Err("https:///pkg".to_string())
        );
    }

    #[test]
    fn watermark_is_read_like_pkg_lib_and_zero_is_no_watermark() {
        assert_eq!(parse_watermark("serial = 10480\n"), Some(10480));
        assert_eq!(parse_watermark("serial = abc\n"), None);
        assert_eq!(parse_watermark("serial = 0\n"), None);
        assert_eq!(parse_watermark(""), None);
        assert_eq!(parse_watermark("serial=5\n"), None);
    }

    fn fixture(name: &str, key: Option<&str>, source: &str, state: Option<&str>) -> PathBuf {
        let root = std::env::temp_dir().join(format!("eos-guard-sysstatus-{name}"));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join(PKG_SOURCES_DIR)).unwrap();
        fs::create_dir_all(root.join("etc/pkg")).unwrap();
        if let Some(key) = key {
            fs::write(root.join(PKG_PUBKEY_PATH), key).unwrap();
        }
        fs::write(root.join(PKG_SOURCES_DIR).join("50_eos"), source).unwrap();
        if let Some(state) = state {
            fs::write(root.join(PKG_STATE_PATH), state).unwrap();
        }
        root
    }

    #[test]
    fn repo_reads_the_tree_and_never_says_podpisane() {
        let root = fixture(
            "accepted",
            Some(&key_toml(true)),
            "https://example.invalid/pkg\n",
            Some("serial = 10480\n"),
        );
        let s = read_repo(&root);
        assert_eq!(
            s,
            RepoState::Accepted {
                sources: vec!["https://example.invalid/pkg".to_string()],
                serial: 10480,
                key: PinnedKey { ml_dsa_65: true }
            }
        );
        let text = s.describe();
        assert!(
            text.contains("ostatni przyjęty indeks") && text.contains("10480"),
            "{text}"
        );
        assert!(
            text.contains("NIE sprawdzane") && !text.contains("podpisane"),
            "{text}"
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn repo_without_a_key_is_unsigned_even_with_a_watermark() {
        let root = fixture(
            "unsigned",
            None,
            "https://example.invalid/pkg\n",
            Some("serial = 10480\n"),
        );
        let s = read_repo(&root);
        assert_eq!(s, RepoState::Unsigned);
        assert!(s.describe().contains("NIEPODPISANE"));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn repo_unlistable_pkg_d_is_unknown() {
        let s = read_repo(Path::new("/nonexistent-eos-guard"));
        assert!(matches!(s, RepoState::Unknown(_)), "{s:?}");
        assert!(s.describe().contains("nieznane"));
    }

    // A directory where a file should be: `read_to_string` fails with EISDIR on Linux and macOS,
    // as root too -- the one "not found"-free read error root cannot read through, which is what
    // makes the next two tests hold on a root CI runner where chmod 000 proves nothing.

    #[test]
    fn repo_unreadable_watermark_is_unknown_not_no_watermark() {
        let root = fixture(
            "watermark-dir",
            Some(&key_toml(true)),
            "https://example.invalid/pkg\n",
            None,
        );
        fs::create_dir(root.join(PKG_STATE_PATH)).unwrap();
        let s = read_repo(&root);
        let text = s.describe();
        assert!(matches!(s, RepoState::Unknown(_)), "{text}");
        assert!(
            text.contains("nieznane") && text.contains("repo-state.toml"),
            "{text}"
        );
        assert!(!text.contains("brak znaku wodnego"), "{text}");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn repo_unreadable_key_is_unknown_not_unsigned() {
        let root = fixture(
            "key-dir",
            None,
            "https://example.invalid/pkg\n",
            Some("serial = 10480\n"),
        );
        fs::create_dir(root.join(PKG_PUBKEY_PATH)).unwrap();
        let s = read_repo(&root);
        let text = s.describe();
        assert!(matches!(s, RepoState::Unknown(_)), "{text}");
        assert!(
            text.contains("nieznane") && text.contains("eos-repo-sign.pub.toml"),
            "{text}"
        );
        assert!(!text.contains("NIEPODPISANE"), "{text}");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn repo_unreadable_pkg_d_file_is_unknown_not_no_source() {
        // chmod 000 is the only shape here (a directory is skipped as pkg-lib skips it), and root
        // reads through it, so the assertion is guarded by the read actually failing.
        let root = fixture(
            "source-000",
            Some(&key_toml(true)),
            "https://example.invalid/pkg\n",
            Some("serial = 10480\n"),
        );
        let source = root.join(PKG_SOURCES_DIR).join("50_eos");
        fs::set_permissions(&source, fs::Permissions::from_mode(0o000)).unwrap();
        let unreadable = fs::read(&source).is_err();
        let s = read_repo(&root);
        let _ = fs::set_permissions(&source, fs::Permissions::from_mode(0o644));
        if unreadable {
            let text = s.describe();
            assert!(matches!(s, RepoState::Unknown(_)), "{text}");
            assert!(
                text.contains("50_eos") && !text.contains("brak skonfigurowanego źródła"),
                "{text}"
            );
        }
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn repo_entry_that_cannot_be_stated_is_unknown_not_no_source() {
        // A dangling symlink: listed, not stat-able, whoever runs this.
        let root = fixture(
            "dangling",
            Some(&key_toml(true)),
            "https://example.invalid/pkg\n",
            Some("serial = 10480\n"),
        );
        std::os::unix::fs::symlink(
            "nonexistent-eos-guard-target",
            root.join(PKG_SOURCES_DIR).join("60_link"),
        )
        .unwrap();
        let s = read_repo(&root);
        let text = s.describe();
        assert!(matches!(s, RepoState::Unknown(_)), "{text}");
        assert!(
            text.contains("60_link") && !text.contains("brak skonfigurowanego źródła"),
            "{text}"
        );
        let _ = fs::remove_dir_all(&root);
        // pkg.d without its search bit: listable, its entries not stat-able -- unless root.
        let root = fixture(
            "pkgd-444",
            Some(&key_toml(true)),
            "https://example.invalid/pkg\n",
            Some("serial = 10480\n"),
        );
        let dir = root.join(PKG_SOURCES_DIR);
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o444)).unwrap();
        let unstatable = fs::metadata(dir.join("50_eos")).is_err();
        let s = read_repo(&root);
        let _ = fs::set_permissions(&dir, fs::Permissions::from_mode(0o755));
        if unstatable {
            let text = s.describe();
            assert!(matches!(s, RepoState::Unknown(_)), "{text}");
            assert!(!text.contains("brak skonfigurowanego źródła"), "{text}");
        }
        let _ = fs::remove_dir_all(&root);
    }
}
