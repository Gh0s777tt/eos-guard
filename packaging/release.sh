#!/usr/bin/env bash
# Package this product for one target, and refuse to call a build a package until the FILE has
# been looked at.
#
#   packaging/release.sh <target-triple> [<output-dir>]
#   packaging/release.sh --selftest
#   packaging/release.sh --help
#
# Targets measured on the eos-heavy runner (macOS, Apple Silicon), 2026-09-03:
#
#   aarch64-apple-darwin     native `cargo build`                           ~4 min
#   x86_64-pc-windows-gnu    `cargo zigbuild`, needs zig + cargo-zigbuild   ~1.5 min
#   x86_64-unknown-linux-gnu `cargo zigbuild` as well                       ~3 min
#
# THE LINUX ARM IS A CORRECTION, and the wrong version of it cost four agents about an hour of
# successful compilation each. The first draft of this script sent ONLY `*windows-gnu` through
# cargo zigbuild and let every other triple fall through to plain `cargo build --target`. On macOS
# that hands GNU linker flags to Apple's ld:
#
#   ld: unknown options: --as-needed -Bstatic -Bdynamic --eh-frame-hdr -z --gc-sections
#   error: could not compile ... (bin "...") due to 1 previous error
#
# The header above it was wrong in the same way: it said a zig cross to Linux "fails in
# yeslogic-fontconfig-sys' build.rs". That WAS true, and stopped being true the moment
# `i-slint-common/fontconfig-dlopen` moved fontconfig from link time to runtime -- the comment
# outlived the measurement it described. Any GNU or musl Linux triple goes through zigbuild now.
#
# WHY THE CHECKS ARE FUNCTIONS AND WHY --selftest EXISTS.  The first version of this script checked
# the built binary inline, and its negative test was "corrupt the .exe and re-run". That test
# PASSED GREEN twice: cargo noticed the output had changed and relinked it, so the assertion ran
# against a freshly correct binary both times. A mutation the build repairs is not a mutation --
# it looks exactly like a gate that works (CLAUDE.md §5.9, level 2). The checks now live in
# functions that --selftest feeds fabricated files, where nothing can quietly repair them.
#
# Exit codes follow the E-OS convention: 1 = the package is wrong, 2 = the packager could not run.
set -euo pipefail

die()    { printf 'release: %s\n' "$*" >&2; return 1; }
cannot() { printf 'release: cannot run -- %s\n' "$*" >&2; exit 2; }

# --- the two checks, callable in isolation ----------------------------------------------------

# check_format <file> <target>: does `file` say this is the binary format that target implies?
check_format() {
  local f="$1" target="$2" kind
  [ -f "$f" ] || { die "the build reported success and produced no $f"; return 1; }
  kind="$(file -b "$f")"
  case "$target" in
    *windows*) case "$kind" in *"PE32+"*x86-64*) return 0 ;; esac ;;
    *linux*)   case "$kind" in *ELF*x86-64*|*ELF*aarch64*) return 0 ;; esac ;;
    *darwin*)  case "$kind" in *Mach-O*) return 0 ;; esac ;;
    *)         die "no format rule for target $target"; return 1 ;;
  esac
  die "$f is not what $target implies -- file says: $kind"
  return 1
}

needs_zig() {
  case "$1" in
    *windows-gnu|*linux-gnu|*linux-gnueabi*|*linux-musl*) return 0 ;;
    *) return 1 ;;
  esac
}

# check_size <file>: a Slint binary with the software renderer and an embedded font is tens of
# megabytes. Anything under a megabyte is a stub, a wrapper, or a stripped-to-nothing accident --
# and shipping one would look exactly like shipping the real thing.
check_size() {
  local f="$1" bytes
  bytes="$(wc -c < "$f" | tr -d ' ')"
  case "$bytes" in ''|*[!0-9]*) die "cannot size $f"; return 1 ;; esac
  [ "$bytes" -ge 1048576 ] && return 0
  die "$f is only $bytes bytes -- that is not this application"
  return 1
}

selftest() {
  local tmp rc fails=0
  tmp="$(mktemp -d "${TMPDIR:-/tmp}/eos-release-selftest.XXXXXX")"
  trap 'rm -rf "$tmp"' RETURN

  printf 'this is not a program\n' > "$tmp/text"
  head -c 2097152 /dev/zero > "$tmp/big"          # 2 MiB, wrong format on purpose
  head -c 512000  /dev/zero > "$tmp/small"

  run() { # <expected-rc> <label> <command...>
    local want="$1" label="$2"; shift 2
    set +e; "$@" >/dev/null 2>&1; rc=$?; set -e
    if [ "$rc" -eq "$want" ]; then printf '  selftest %-38s ok (exit %s)\n' "$label" "$rc"
    else printf '  selftest %-38s FAIL (exit %s, wanted %s)\n' "$label" "$rc" "$want"; fails=$((fails+1)); fi
  }

  run 1 "a text file is not a Windows binary" check_format "$tmp/text" x86_64-pc-windows-gnu
  run 1 "a text file is not a Linux binary"   check_format "$tmp/text" x86_64-unknown-linux-gnu
  run 1 "zeroes are not a Mach-O binary"      check_format "$tmp/big"  aarch64-apple-darwin
  run 1 "a missing file is not a binary"      check_format "$tmp/absent" x86_64-pc-windows-gnu
  run 1 "an unknown target has no rule"       check_format "$tmp/big"  s390x-ibm-zos
  run 1 "a 512 KB file is a stub"             check_size   "$tmp/small"
  run 0 "a 2 MiB file passes the size floor"  check_size   "$tmp/big"

  # The routing decision gets its own cases, because getting it wrong is exactly what happened:
  # only Windows went through zig, so Linux quietly used the host linker and died after twenty
  # minutes of successful compilation. A rule this cheap to check should never be checked by
  # waiting for a build.
  run 0 "windows-gnu needs zig"               needs_zig x86_64-pc-windows-gnu
  run 0 "linux-gnu needs zig"                 needs_zig x86_64-unknown-linux-gnu
  run 0 "aarch64 linux-gnu needs zig"         needs_zig aarch64-unknown-linux-gnu
  run 0 "linux-musl needs zig"                needs_zig x86_64-unknown-linux-musl
  run 1 "apple-darwin does not need zig"      needs_zig aarch64-apple-darwin
  run 1 "redox does not need zig"             needs_zig x86_64-unknown-redox

  if [ "$fails" -gt 0 ]; then
    printf 'release: selftest FAILED -- %d check(s) did not behave\n' "$fails"; return 1
  fi
  printf 'release: selftest ok -- every check refuses what it is meant to refuse\n'
}

case "${1:-}" in
  --selftest) selftest; exit $? ;;
  ""|-h|--help)
    sed -n '2,26p' "$0" | sed 's/^# \{0,1\}//'
    [ -z "${1:-}" ] && exit 2 || exit 0 ;;
esac

TARGET="$1"
OUTDIR="${2:-dist}"

command -v cargo >/dev/null 2>&1 || cannot "cargo is not on PATH"
[ -f Cargo.toml ] || cannot "run me from the repository root (no Cargo.toml here)"
command -v python3 >/dev/null 2>&1 || cannot "python3 is needed to read cargo metadata"

meta() { cargo metadata --no-deps --format-version 1 | python3 -c "import sys,json; print(json.load(sys.stdin)['packages'][0]['$1'])"; }
NAME="$(meta name)"
VERSION="$(meta version)"
HOST="$(rustc -vV | awk '/^host:/{print $2}')"

# A target that is not this host and is not Apple needs a cross linker, and zig IS that linker.
# Deciding by triple rather than by "is it Windows" is the whole fix: the previous shape asked the
# wrong question and answered it correctly. (needs_zig is defined with the other checks above, so
# --selftest can exercise it without running a build.)
if [ "$TARGET" = "$HOST" ]; then
  cargo build --locked --release --features host-backend
  BIN="target/release/$NAME"
elif needs_zig "$TARGET"; then
  command -v cargo-zigbuild >/dev/null 2>&1 || cannot "cargo-zigbuild is missing (cargo install cargo-zigbuild)"
  command -v zig >/dev/null 2>&1 || cannot "zig is missing (brew install zig)"
  cargo zigbuild --locked --release --features host-backend --target "$TARGET"
  case "$TARGET" in
    *windows*) BIN="target/$TARGET/release/$NAME.exe" ;;
    *)         BIN="target/$TARGET/release/$NAME" ;;
  esac
else
  cargo build --locked --release --features host-backend --target "$TARGET"
  BIN="target/$TARGET/release/$NAME"
fi

check_format "$BIN" "$TARGET" || exit 1
check_size   "$BIN"           || exit 1
KIND="$(file -b "$BIN")"

mkdir -p "$OUTDIR"
STAGE="$(mktemp -d "${TMPDIR:-/tmp}/eos-release.XXXXXX")"   # explicit template: CLAUDE.md P-16
trap 'rm -rf "$STAGE"' EXIT
PKGDIR="$STAGE/$NAME-$VERSION-$TARGET"
mkdir -p "$PKGDIR"
cp "$BIN" "$PKGDIR/"
for extra in LICENSE README.md; do [ -f "$extra" ] && cp "$extra" "$PKGDIR/"; done
[ -d assets ] && cp -R assets "$PKGDIR/assets"

case "$TARGET" in
  *windows*)
    command -v zip >/dev/null 2>&1 || cannot "zip is missing"
    ( cd "$STAGE" && zip -qr "$(basename "$PKGDIR").zip" "$(basename "$PKGDIR")" )
    ART="$OUTDIR/$(basename "$PKGDIR").zip"
    mv "$STAGE/$(basename "$PKGDIR").zip" "$ART" ;;
  *)
    ART="$OUTDIR/$(basename "$PKGDIR").tar.gz"
    tar -czf "$ART" -C "$STAGE" "$(basename "$PKGDIR")" ;;
esac

if command -v sha256sum >/dev/null 2>&1; then SUM=sha256sum; else SUM="shasum -a 256"; fi
( cd "$OUTDIR" && $SUM "$(basename "$ART")" > "$(basename "$ART").sha256" )

printf 'release: %s  %s bytes  (%s)\n' "$ART" "$(wc -c < "$ART" | tr -d ' ')" "$KIND"
cat "$ART.sha256"
