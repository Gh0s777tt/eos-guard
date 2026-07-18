# E-OS Guard

Crimson-themed **filesystem integrity monitor** for
[E-OS](https://gitlab.com/e-os/e-os) — the second E-OS original application.

Guard baselines a set of directories (the blake3 hash + size/mode/mtime of every
regular file, stored in SQLite/WAL) and diffs a later scan against that baseline,
surfacing:

- **ZMIENIONY** — the file's blake3 hash changed;
- **NOWY** — a file that wasn't in the baseline;
- **USUNIĘTY** — a baseline file that's gone;
- **OSTRZEŻENIE** — a world-writable file (the security lint).

- **UI:** Slint over the shared [`eos-ui`](https://gitlab.com/e-os/eos-ui)
  Orbital backend (software renderer, no GPU).
- **Hash:** `blake3` (portable Rust) — the same hash `pkgar` and the SBOM use.
- **Storage:** SQLite/WAL at `$HOME/.local/share/eos-guard/baseline.db`.

## Headless self-test

`eos-guard --selftest` proves the pipeline without a display: it builds a
throwaway tree, baselines it, verifies a clean re-scan is all-OK, then mutates /
adds / removes files and asserts the diff reports exactly one MODIFIED, one NEW
and one REMOVED (and that WAL is active), printing `GUARD-SELFTEST-OK`. Used by
CI and boot probes.

## Building

Built as an E-OS recipe (`recipes/gui/eos-guard`) for
`aarch64-unknown-redox` / `x86_64-unknown-redox`. Host build of the CLI half:
`cargo build --no-default-features`.

## Hosting

Dev + CI on GitLab (`gitlab.com/e-os/eos-guard`); `github.com/Gh0s777tt/eos-guard`
is a read-only mirror the build recipes fetch from. License: AGPL-3.0-or-later.
