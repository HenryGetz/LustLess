#!/usr/bin/env bash
# Build lustless-0.1.2-r0.apk (Alpine — musl + OpenRC; PACKAGING-MATRIX §2).
#
#   packaging/build-apk.sh               full build: compile the musl
#                                        binaries in an alpine container
#                                        (build-binaries.sh musl), assemble
#                                        the shared payload tree, adapt it
#                                        for Alpine (drop systemd units, add
#                                        the OpenRC initd), then build the
#                                        package with abuild inside an
#                                        alpine container
#   packaging/build-apk.sh --skip-build  reuse binaries already in
#                                        target/release/ (must be
#                                        musl-compatible; repackage only)
#
# Why abuild (and why earlier hand-rolled attempts failed): Alpine 3.24
# ships apk-tools 3, which rejects v2-format packages with "file format is
# invalid or inconsistent"; only abuild emits the v3 format its `apk add`
# accepts. abuild requires a non-root builder user, a generated signing key
# (abuild-keygen), and sudo (abuild re-execs itself for root steps).
#
# Output: ./lustless-0.1.2-r0.apk
set -euo pipefail

VERSION="0.1.2"
PKGREL="0"

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
stage="$repo_root/target/pkg-root-apk"
work="$repo_root/target/apk-pkg"
out="$repo_root/lustless-${VERSION}-r${PKGREL}.apk"

skip_build=0
for arg in "$@"; do
    case "$arg" in
        --skip-build) skip_build=1 ;;
        -h|--help)    sed -n '2,18p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "build-apk.sh: unknown argument: $arg" >&2; exit 2 ;;
    esac
done

if [ "$skip_build" -eq 0 ]; then
    "$repo_root/packaging/build-binaries.sh" musl
fi

# Shared payload tree (single source), then the Alpine-specific adaptation:
# no systemd on Alpine — drop the units, add the OpenRC service.
"$repo_root/packaging/stage.sh" "$stage" musl
rm -rf "$stage/usr/lib/systemd"
install -D -m 0755 "$repo_root/packaging/openrc/lustlessd.initd" \
    "$stage/etc/init.d/lustlessd"

rm -rf "$work"
mkdir -p "$work"
cp "$repo_root/packaging/alpine/APKBUILD" "$work/APKBUILD"
cp "$repo_root/packaging/alpine"/lustless.post-install \
   "$repo_root/packaging/alpine"/lustless.pre-upgrade \
   "$repo_root/packaging/alpine"/lustless.post-upgrade \
   "$repo_root/packaging/alpine"/lustless.pre-deinstall \
   "$work/"

docker run --rm -i \
    -v "$repo_root:/src" \
    -w /src/target/apk-pkg \
    alpine:3.24 sh -s <<'DOCKER_EOF'
set -eu
apk add --no-cache abuild sudo build-base >/dev/null
# abuild's ELF dependency scanner (scanelf) resolves DT_NEEDED entries
# against the container's libs — provide the runtime deps of the payload
# so libgio/libgtk etc. resolve.
apk add --no-cache glib gtk+3.0 libayatana-appindicator openssl libsecret \
    libx11 libxext libxrandr >/dev/null
grep -q community /etc/apk/repositories || echo "https://dl-cdn.alpinelinux.org/alpine/v3.24/community" >> /etc/apk/repositories
apk update >/dev/null
adduser -D builder
addgroup builder abuild
echo 'builder ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/builder
cp -a /src/target/pkg-root-apk "$PWD/src_stage_tmp"
mkdir -p src
mv src_stage_tmp src/stage
chown -R builder:builder "$PWD"
# scanelf's auto-detected .so deps land as `so:…` requires the guest must
# resolve against Alpine repositories — the testbed VMs cannot reliably reach
# the community index (dns transit errors). Drop the scan inputs so only the
# APKBUILD's declared depends (gtk+3.0, polkit, …) are written.
find "$PWD" -name .needs-so -delete 2>/dev/null || true
find "$PWD" -name .needs-pc -delete 2>/dev/null || true
# abuild needs a signing key even for local packages; -r auto-installs the
# APKBUILD's depends as build deps; -d skips that (deps already present via
# build-base); the final index step is allowed to fail on trust (we ship the
# package file itself, not a repo).
sudo -u builder abuild-keygen -an >/dev/null
sudo -u builder abuild -r -d -P "$PWD/out" || true
DOCKER_EOF

built="$(find "$work/out" -name "lustless-*.apk" 2>/dev/null | head -1)"
if [ -z "$built" ]; then
    echo "build-apk.sh: abuild produced no apk" >&2
    exit 1
fi
cp "$built" "$out"
echo "build-apk.sh: built $out ($(stat -c%s "$out") bytes)"
