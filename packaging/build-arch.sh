#!/usr/bin/env bash
# Build lustless-0.1.0-1-x86_64.pkg.tar.zst (Arch Linux, SteamOS base;
# PACKAGING-MATRIX §2/§9).
#
#   packaging/build-arch.sh               full build: compile against the
#                                        glibc 2.35 baseline, assemble the
#                                        shared payload tree, then makepkg in
#                                        an archlinux container
#   packaging/build-arch.sh --skip-build  reuse binaries already in
#                                        target/release/
#
# Output: ./lustless-0.1.0-1-x86_64.pkg.tar.zst
set -euo pipefail

VERSION="0.1.0"
PKGREL="1"

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
stage="$repo_root/target/pkg-root"
work="$repo_root/target/arch-pkg"
out="$repo_root/lustless-${VERSION}-${PKGREL}-x86_64.pkg.tar.zst"

skip_build=0
for arg in "$@"; do
    case "$arg" in
        --skip-build) skip_build=1 ;;
        -h|--help)    sed -n '2,14p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "build-arch.sh: unknown argument: $arg" >&2; exit 2 ;;
    esac
done

if [ "$skip_build" -eq 0 ]; then
    "$repo_root/packaging/build-binaries.sh" glibc
fi

"$repo_root/packaging/stage.sh" "$stage" glibc

rm -rf "$work"
mkdir -p "$work"
cp "$repo_root/packaging/arch/PKGBUILD" "$work/PKGBUILD"
cp "$repo_root/packaging/arch/lustless.install" "$work/lustless.install"

docker run --rm -i \
    -v "$repo_root:/src" \
    -w /src/target/arch-pkg \
    archlinux:latest bash -s <<'DOCKER_EOF'
set -euo pipefail
pacman -Sy --noconfirm --needed base-devel >/dev/null
useradd -m builder
# makepkg refuses root; give the builder read access to the stage tree and
# write access to the build dir.
cp -a /src/target/pkg-root /src/target/arch-pkg/srcdir_stage_tmp
mkdir -p /src/target/arch-pkg/src
mv /src/target/arch-pkg/srcdir_stage_tmp /src/target/arch-pkg/src/stage
chown -R builder:builder /src/target/arch-pkg
sudo -u builder makepkg -f --nodeps
DOCKER_EOF

built="$(find "$work" -maxdepth 1 -name "lustless-${VERSION}-${PKGREL}-*.pkg.tar.zst" | head -1)"
if [ -z "$built" ]; then
    echo "build-arch.sh: makepkg produced no package" >&2
    exit 1
fi
cp "$built" "$out"
echo "build-arch.sh: built $out"
