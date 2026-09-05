# E-OS Guard

Crimson-themed **filesystem integrity monitor** for
[E-OS](https://gitlab.com/e-os/e-os) — the second E-OS original application.

Guard baselines a set of directories (the blake3 hash + size/mode/mtime of every
regular file, plus the directories themselves, stored in SQLite/WAL) and diffs a
later scan against that baseline, surfacing:

- **ZMIENIONY** — the file's blake3 hash changed;
- **NOWY** — a file that wasn't in the baseline;
- **USUNIĘTY** — a baseline file that's gone **from a directory this scan walked**;
- **OSTRZEŻENIE** — the permission audit: a setuid, setgid or world-writable file
  (surfaced on every scan, regardless of whether the file changed);
- **Poza zakresem** — a *count*, not a list: baseline files lying outside every
  directory this scan walked. See below.

## Scan scope

The directories are a free-text field, editable between one scan and the next, and
the baseline now records the set it was taken over (`meta.roots`).

**A file the scan never looked for is not a file that was removed.** Baseline
`/usr/bin, /etc`, narrow the field to `/etc`, press Skanuj, and every file under
`/usr/bin` used to come back **USUNIĘTY — brak na dysku**, about a tree nothing had
opened. Clearing the field entirely condemned the whole baseline the same way. With
real roots that is thousands of rows, and an integrity monitor that reports thousands
of removals that did not happen is one people learn to close.

Those files are now **counted, not listed** — the `Poza zakresem` chip and a
`⚠ ZAKRES:` line in the status bar, which also names which root was dropped or added.
Counting rather than listing is the point: a thousand rows saying *not checked* is the
same wall of noise under a politer label, and dropping them silently would be
fail-open. The number is never hidden.

Two things this deliberately does **not** do:

- **It does not suppress a widened scan.** Baseline `/etc`, then scan `/etc, /usr/bin`,
  and every file under `/usr/bin` is reported **NOWY**. Each of those findings is a
  *true* statement — the file really is absent from the baseline — merely an
  uninformative one, which is the opposite of a false USUNIĘTY and earns the opposite
  treatment: the `⚠ ZAKRES:` line names the added root, and nothing is filtered.
- **It does not trust `meta.roots` for the decision.** What counts as unchecked is
  computed from the roots *this scan actually walked*, never from the recorded ones.
  So a baseline written before this field existed still diffs correctly, and rewriting
  `meta.roots` — which is not covered by the integrity digest, see below — cannot make
  a real removal disappear. It can only make the *explanation* wrong.

`meta.roots` is **not** an input to the baseline digest, on purpose: widening the digest
input would recompute every digest already on disk, so every existing baseline would
report **⚠ WZORZEC NARUSZONY** after an upgrade that changed no file. A tamper alarm that
fires on an upgrade is one people learn to dismiss.

The baseline itself is protected by a blake3 **integrity digest** (`U-090`): a
scan recomputes it and flags **⚠ WZORZEC NARUSZONY** if the baseline was edited
out of band or corrupted. (The digest lives in the same DB, so it catches
corruption and naive tampering — a key-signed baseline is future work.)

- **UI:** Slint over the shared [`eos-ui`](https://gitlab.com/e-os/eos-ui)
  Orbital backend (software renderer, no GPU).
- **Hash:** `blake3` (portable Rust) — the same hash `pkgar` and the SBOM use.
- **Storage:** SQLite/WAL at `$HOME/.local/share/eos-guard/baseline.db`.

## Crate layout — one engine, two products (`PR-004`)

The walk, the hashing and the baseline store live in the workspace member
[`crates/eos-fsintegrity`](crates/eos-fsintegrity) (`eos_fsintegrity::{scan, db}`,
plus `parse_roots` and `DEFAULT_SCAN_BUDGET`); this repository's root package is the
Guard binary, which depends on it by path. `eos-control`'s Security tab depends on the
same crate by git revision, so the engine exists once instead of as two copies that
have to be patched twice. A workspace **member** rather than a separate repository, on
the `eos-credpolicy` precedent: a git dependency finds a package by name among a
repository's workspace members, and a member needs no third mirror and no third pin.

What is deliberately **not** in the crate: where the database lives. `src/paths.rs`
keeps the path above, unchanged; whether Guard and Control should go on sharing one
file is an open owner decision, and moving the engine did not pre-empt it.

The engine's unit tests run only with `cargo test --workspace` — at a workspace root
plain `cargo test` runs the root package alone (measured: 1 test instead of 26), which
is why CI says `--workspace` on every test and coverage line.

## Linie stanu zaufania

Under the scan status the window shows three lines, one per sentence, read once at start
by `src/sysstatus.rs` (product code, beside `paths.rs` — the engine crate stays ignorant
of Redox paths). Each line reports **what one world-readable source says**, and nothing
it does not:

- **Szyfrowanie dysku (FDE)** reads `/scheme/sys/env`, the kernel's copy of the
  bootloader environment. A `REDOXFS_PASSWORD_ADDR` *key* (never the value — it is a
  physical address) means the bootloader unlocked the root with a password →
  *aktywne*; `REDOXFS_UUID` without it → *⚠ NIEAKTYWNE*. `DISK_LIVE_ADDR` only appends
  *(obraz live, root w RAM)*; it never changes the state or removes the warning.
- **RAID-1** needs *two* signals: the `disk.raid1` scheme name under `/scheme` (raid1d
  registers it only after assembling an array) **and** raid1d's own `/tmp/raid1d.state`
  (`status = optimal|degraded`, `members = A/M`). Both present and consistent →
  *sprawna* or *⚠ ZDEGRADOWANA*; both absent → *nie wykryto macierzy*. One without the
  other is *nieznane*: `/tmp` is sticky-world-writable, so a planted state file with no
  daemon behind it must not buy *sprawna*. The file must also be one only root could have
  written — a regular file (no symlink), owned by uid 0, not writable by group or others,
  no longer than raid1d writes (the read stops at 64 KiB) — else *nieznane* with the
  reason: a file anyone could have replaced proves nothing, whatever it says.
- **Repozytorium** reads pkg-lib's three files: the pinned key
  `/etc/pkg/eos-repo-sign.pub.toml` (the `ed25519` field must decode to 32 bytes, else
  *⚠ NIEPOPRAWNY*; missing → *⚠ NIEPODPISANE*, because pkg then accepts an unsigned
  index), the sources under `/etc/pkg.d` (non-`#` lines; x86_64 ships a commented URL
  only → *brak skonfigurowanego źródła*), and the serial watermark
  `/etc/pkg/repo-state.toml` → *ostatni przyjęty indeks serial N*, or *brak znaku
  wodnego serial* when absent, unparsable or `0` (pkg-lib never writes 0).

**`nieznane` means exactly that.** A read error other than "file not found", a `pkg.d`
entry that cannot be stat'ed (a dangling symlink, a directory without its search bit), a
bootloader env without `REDOXFS_UUID`, a state file raid1d could not have written, a
`pkg.d` line pkg itself refuses — each renders *nieznane* with its reason, never a
definite state in either direction. On a development host all three lines read
*nieznane*, which is the honest answer for a machine that is not E-OS.

**What is NOT verified on the device, and the lines say so:**

- **ML-DSA-65.** The key file carries a hybrid ed25519 + ML-DSA-65 public key, but pkg-lib
  checks the ed25519 half only. The line reports whether the field is *present* (*w
  kluczu, NIE sprawdzane na urządzeniu* / *brak w kluczu*), nothing more.
- **`expires`.** No on-disk file carries it and no published index has it (`S-11`), so
  the line does not mention it rather than print a caveat on every render.
- **Live RAID state.** raid1d writes its file at assembly time and then enters a null
  namespace, so a member dropping out mid-run is invisible until the next boot — hence
  *stan z chwili rozruchu* on both definite variants.
- **A live signature check.** The watermark is written by pkg-lib even without a pinned
  key and is root-writable, so the repository line says *ostatni przyjęty indeks* and
  never *podpisane*; that word waits for a verification the line does not perform.

## Headless self-test

`eos-guard --selftest` proves the pipeline without a display: it builds a
throwaway tree, baselines it, verifies a clean re-scan is all-OK, then mutates /
adds / removes files and asserts the diff reports exactly one MODIFIED, one NEW
and one REMOVED (and that WAL is active), printing `GUARD-SELFTEST-OK`. Used by
CI and boot probes.

It also asserts both directions of the scope rule, because a check that can only pass
is not a check: re-scanning the *untouched* tree with the roots narrowed to a
subdirectory must report **zero** removals and two files out of scope and must print a
`⚠ ZAKRES:` line naming the dropped root — while a scan over the baseline's own roots
must report the genuine deletion and print **nothing** about scope. Breaking the
coverage test either way turns the selftest red with the reason:

```text
GUARD-SELFTEST-FAIL: a narrowed scan reported 2 removals it never looked for
```

The three trust lines are proven the same way, from the producers' own formats (a
bootloader env block, raid1d's state file, a pkg-lib sysroot built under `$TMPDIR`):
every definite sentence has a fixture that earns it and a negative fixture that must not —
the token inside a value, `status = healthy`, a 2-byte `ed25519`, `serial = 0`, a state
file with no daemon behind it, a state file that is not root's or is writable by others, a
directory in place of the key or the watermark file (a read error root cannot read
through, so the control holds on a root CI runner too). The two real-path cases are
guarded, so the same binary is a boot probe on the image (it prints the lines it read; the
FDE line must be definite there, the RAID line may read *nieznane* in a restricted
namespace) and a host check elsewhere (where both must read *nieznane*). It also calls `trust_lines()` itself and asserts three
labelled lines in order, so the string the window sets is tested and not merely typed.

## Download

PR-008: Guard should be obtainable on its own, not only as an E-OS recipe.
`packaging/release.sh <target-triple> [outdir]` builds one target, **looks at the file it
produced** — `file -b` against a per-target rule, plus a 1 MiB floor — packages it, and
writes a `.sha256` beside it. A green `cargo build` is not evidence, so the script does
not accept one.

**Neither download is publishable yet.** What follows is what was actually measured on the
reference host (Apple Silicon macOS, zig 0.16.0 + cargo-zigbuild 0.23.4), 2026-09-03:

| Target | Binary builds? | `file -b` | Bytes | Archive |
|---|---|---|---|---|
| `x86_64-unknown-linux-gnu` | **yes**, 15m 27s | `ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.0.0, stripped` | 21 699 848 | not produced here — see below |
| `x86_64-pc-windows-gnu` | **no** | — | — | — |

The binaries will be **unsigned** when they do ship: no Authenticode certificate, no
notarisation, so Windows SmartScreen and macOS Gatekeeper will object. Verify the
`.sha256` beside the archive instead. Signing needs a key, and generating one is a human
action, never an automated one.

### Linux: the binary is fine, the packager's Linux path is not

`release.sh` uses `cargo zigbuild` only for `*windows-gnu`; every other target falls to
plain `cargo build --target`, which is why the script's own header says to run it *inside
a Linux container* for this triple. On macOS that arm dies after 21m 25s at the first C
dependency, with no cross compiler to give cc-rs:

```
Compiling libsqlite3-sys v0.28.0
CC_x86_64-unknown-linux-gnu = None ... CC = None ... CROSS_COMPILE = None
error occurred in cc-rs: failed to find tool "x86_64-linux-gnu-gcc": No such file or directory (os error 2)
```

The same tree with the same flags, built through zigbuild, finishes cleanly and clears
both of the packager's checks — so the `fontconfig-dlopen` stanza in `Cargo.toml` does its
job, and zig cross-compiles the bundled SQLite C without complaint:

```
$ cargo zigbuild --locked --release --features host-backend --target x86_64-unknown-linux-gnu
    Finished `release` profile [optimized] target(s) in 15m 27s
$ file -b target/x86_64-unknown-linux-gnu/release/eos-guard
ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.0.0, stripped
$ wc -c < target/x86_64-unknown-linux-gnu/release/eos-guard
21699848
```

Making the archive needs either an x86_64 Linux runner (where the script works as its
header intends) or a `cargo zigbuild` arm for `*linux-gnu`. Editing the packager was out
of scope for the change that added it.

### Windows does not build, and the reason is Guard

The cross-toolchain is not the problem: the whole Slint/winit/muda graph compiled, and so
did the bundled SQLite C. After 18m 14s the build died in Guard's own source:

```
error[E0433]: cannot find `unix` in `os`   --> src/scan.rs:4:14
error[E0433]: cannot find `unix` in `os`   --> src/selftest.rs:9:14
error[E0599]: no method named `mode` found for struct `Permissions`
                                           --> src/scan.rs:81:39
error[E0599]: no associated function or constant named `from_mode` found for struct
              `Permissions`                --> src/selftest.rs:23:49
```

That is the permission audit. `setuid`, `setgid` and world-writable are POSIX mode bits;
Windows has none of them, so `OSTRZEŻENIE` — one of Guard's four finding kinds — has
nothing to stand on, and `--selftest` (which chmods a file `0o4755` and asserts exactly
one warning comes back) has nothing to prove.

This is left unfixed on purpose. Compiling the audit away behind `#[cfg(unix)]` would
produce something that looks exactly like Guard, carries its name, and can never raise a
permission finding — a check that can only pass, shipped as a security product. What
Guard *means* on Windows is a product decision, not a packaging one.

## Building

Built as an E-OS recipe (`recipes/gui/eos-guard`) for
`aarch64-unknown-redox` / `x86_64-unknown-redox`. Host build of the CLI half:
`cargo build --no-default-features`.

## Hosting

Dev + CI on GitLab (`gitlab.com/e-os/eos-guard`); `github.com/Gh0s777tt/eos-guard`
is a read-only mirror the build recipes fetch from. License: AGPL-3.0-or-later.
