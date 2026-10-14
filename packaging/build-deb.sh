#!/usr/bin/env bash
# Build lustless_0.1.9_amd64.deb.
#
#   packaging/build-deb.sh               full build: compile the Cargo
#                                        workspace against the glibc 2.35
#                                        baseline (packaging/build-binaries.sh
#                                        → ubuntu:22.04 container, CONTRACTS
#                                        §2), assemble the shared payload
#                                        tree (packaging/stage.sh), then
#                                        dpkg-deb
#   packaging/build-deb.sh --skip-build  reuse binaries already in
#                                        target/release/ (must be glibc
#                                        2.35-compatible; repackage only)
#
# Runnable from anywhere; paths resolve relative to the repo root. Output:
#   ./lustless_0.1.9_amd64.deb
#
# Model bundle: staged automatically by packaging/stage.sh (see that script).
# Without it the package still builds — screen accountability needs the
# bundle at runtime (see packaging/README.md). No placeholder artifacts.
set -euo pipefail

VERSION="0.1.9"
ARCH="amd64"

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
stage="$repo_root/target/pkg-root"
out="$repo_root/lustless_${VERSION}_${ARCH}.deb"

usage() {
    sed -n '2,20p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

skip_build=0
for arg in "$@"; do
    case "$arg" in
        --skip-build) skip_build=1 ;;
        -h|--help)    usage; exit 0 ;;
        *) echo "build-deb.sh: unknown argument: $arg" >&2; exit 2 ;;
    esac
done

if [ "$skip_build" -eq 0 ]; then
    "$repo_root/packaging/build-binaries.sh" glibc
fi

# --- Shared payload tree (single source for all four formats) --------------
"$repo_root/packaging/stage.sh" "$stage" glibc

# --- DEBIAN/ control area ---------------------------------------------------
mkdir -p "$stage/DEBIAN"
install -m 0644 "$repo_root/packaging/debian/control"   "$stage/DEBIAN/control"
install -m 0644 "$repo_root/packaging/debian/conffiles" "$stage/DEBIAN/conffiles"
install -m 0755 "$repo_root/packaging/debian/postinst"  "$stage/DEBIAN/postinst"
install -m 0755 "$repo_root/packaging/debian/prerm"     "$stage/DEBIAN/prerm"
install -m 0755 "$repo_root/packaging/debian/postrm"    "$stage/DEBIAN/postrm"

installed_size="$(du -sk "$stage" | cut -f1)"
sed -i "/^Description:/i Installed-Size: $installed_size" "$stage/DEBIAN/control"
# The version lives in this script's $VERSION, never duplicated in the
# checked-in control file (a stale copy there once shipped 0.1.2 binaries as
# a 0.1.0 package).
sed -i "s/^Version: .*/Version: $VERSION/" "$stage/DEBIAN/control"

# --- Build ------------------------------------------------------------------
dpkg-deb --build --root-owner-group "$stage" "$out"
echo "build-deb.sh: built $out"
