#!/usr/bin/env bash
#
# Builds the client and the server with cargo in release mode, and wraps the binaries into binary
# RPMs, without a source tarball or an SRPM. Every argument is passed on to `cargo build`, for
# example:
#
#   rpm/assemble.sh --offline
#
# Usage: rpm/assemble.sh [CARGO_BUILD_ARGS...]
#
# The binaries are found wherever cargo builds them, so --target and --target-dir work. The RPMs
# land in target/rpm/RPMS/<arch>/, where <arch> is the first component of the target triple: that of
# --target or CARGO_BUILD_TARGET, or else the host triple that rustc reports. Without a target,
# or with --target naming the host, cargo reuses the build of `cargo build --release` in
# target/release.
#
# CARGO_SUBCOMMAND replaces `build`, so a cross build may go through cargo-zigbuild, which also
# accepts a glibc version after the triple. Amazon Linux 2023 on Graviton, for example:
#
#   CARGO_SUBCOMMAND=zigbuild rpm/assemble.sh --target aarch64-unknown-linux-gnu.2.34

set -euo pipefail

host="$(rustc -vV | sed -n 's/^host: //p')"
triple=""
args=()
while (($#)); do
  case "$1" in
    --target) triple="$2" && args+=("$1" "$2") && shift ;;
    --target=*) triple="${1#--target=}" && args+=("$1") ;;
    *) args+=("$1") ;;
  esac
  shift
done
# cargo builds for an explicit --target into a directory of its own, apart from target/release, even
# when the target is the host. The binaries of plain cargo build match, so the host's triple is
# dropped to reuse them; not for cargo-zigbuild, whose linker differs.
if [[ "$triple" == "$host" && -z "${CARGO_SUBCOMMAND:-}" ]]; then
  for i in "${!args[@]}"; do
    case "${args[i]-}" in
      --target) unset 'args[i]' 'args[i+1]' ;;
      --target=*) unset 'args[i]' ;;
    esac
  done
fi
# Without --target, cargo builds for build.target of its configuration or CARGO_BUILD_TARGET, and
# without either for the host.
[[ -n "$triple" ]] ||
  triple="$(cargo -Zunstable-options config get --format json-value build.target 2>/dev/null |
    tr -d '"')" || true
triple="${triple:-$host}"
arch="${triple%%-*}"

REPO="$(cd "$(dirname "$0")/.." && pwd)"
TOPDIR="$REPO/target/rpm"
mkdir -p "$TOPDIR/tmp"
# openSUSE's brp-99-pesign hashes kernel modules for signing into the default %_topdir, outside
# TOPDIR; an empty list of files to sign skips it.
export BRP_PESIGN_FILES=

# cargo reports each executable that it builds; the diagnostics go to stderr as usual.
artifacts="$TOPDIR/tmp/artifacts.json"
cargo "${CARGO_SUBCOMMAND:-build}" --manifest-path "$REPO/Cargo.toml" --release -p innernet -p innernet-server \
  --message-format=json-render-diagnostics ${args[@]+"${args[@]}"} >"$artifacts"
mapfile -t executables < <(
  python3 -I -c '
import json, sys
for line in sys.stdin:
    message = json.loads(line)
    if message.get("reason") == "compiler-artifact" and message.get("executable"):
        print(message["executable"])
' <"$artifacts"
)

for package in innernet innernet-server; do
  binary=""
  for executable in "${executables[@]}"; do
    [[ "$(basename "$executable")" == "$package" ]] && binary="$executable"
  done
  if [[ -z "$binary" ]]; then
    echo "cargo built no $package binary." >&2
    exit 1
  fi

  version="$(cargo pkgid --offline --manifest-path "$REPO/Cargo.toml" -p "$package" | cut -d '@' -f 2)"

  rpmbuild -bb "$REPO/rpm/$package.spec" --target "$arch" \
    --define "_topdir $TOPDIR" \
    --define "_tmppath $TOPDIR/tmp" \
    --define "repo $REPO" \
    --define "bin_dir $(dirname "$binary")" \
    --define "pkg_version $version"
done

ls "$TOPDIR"/RPMS/*/
