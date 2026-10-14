#!/usr/bin/env bash
# Build lustless-0.1.6-1.x86_64.rpm (Fedora Workstation, Bazzite rpm-ostree;
# PACKAGING-MATRIX §2).
#
#   packaging/build-rpm.sh               full build: compile against the glibc
#                                        2.35 baseline (build-binaries.sh),
#                                        assemble the shared payload tree
#                                        (stage.sh), then rpmbuild in a fedora
#                                        container
#   packaging/build-rpm.sh --skip-build  reuse binaries already in
#                                        target/release/ (must be glibc
#                                        2.35-compatible; repackage only)
#
# Output: ./lustless-0.1.6-1.x86_64.rpm
set -euo pipefail

VERSION="0.1.6"
RELEASE="1"

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
stage="$repo_root/target/pkg-root"
topdir="$repo_root/target/rpmbuild"
out="$repo_root/lustless-${VERSION}-${RELEASE}.x86_64.rpm"

skip_build=0
for arg in "$@"; do
    case "$arg" in
        --skip-build) skip_build=1 ;;
        -h|--help)    sed -n '2,14p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "build-rpm.sh: unknown argument: $arg" >&2; exit 2 ;;
    esac
done

if [ "$skip_build" -eq 0 ]; then
    "$repo_root/packaging/build-binaries.sh" glibc
fi

"$repo_root/packaging/stage.sh" "$stage" glibc

rm -rf "$topdir"
mkdir -p "$topdir"/{SPECS,RPMS,BUILD,BUILDROOT,SOURCES,SRPMS}
cp "$repo_root/packaging/rpm/lustless.spec" "$topdir/SPECS/lustless.spec"

docker run --rm -i \
    -v "$repo_root:/src" \
    -w /src \
    fedora:latest bash -s <<'DOCKER_EOF'
set -euo pipefail
dnf -y install rpm-build >/dev/null
rpmbuild -bb --define "_topdir /src/target/rpmbuild" \
    /src/target/rpmbuild/SPECS/lustless.spec
DOCKER_EOF

built="$(find "$topdir/RPMS" -name 'lustless-*.rpm' | head -1)"
if [ -z "$built" ]; then
    echo "build-rpm.sh: rpmbuild produced no rpm" >&2
    exit 1
fi
cp "$built" "$out"
rpm -qp --requires "$out" 2>/dev/null || true
echo "build-rpm.sh: built $out"
