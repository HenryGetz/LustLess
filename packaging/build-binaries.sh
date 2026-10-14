#!/usr/bin/env bash
# Build the four LustLess release binaries for one libc family.
#
#   packaging/build-binaries.sh            glibc build (default): compile in
#                                          an ubuntu:22.04 container —
#                                          glibc 2.35 baseline (CONTRACTS
#                                          §2, PACKAGING-MATRIX §1) so one
#                                          set of binaries runs on every
#                                          glibc distro in the matrix
#   packaging/build-binaries.sh musl       musl build in an alpine
#                                          container (APK package only)
#
# Env: LUSTLESS_WAYLAND — obsolete; the Wayland portal backend is part of every
# glibc build now (v0.1.10). It is version-tolerant by construction: the
# backend reaches PipeWire through our own dlopen'd bindings
# (`crates/lustless-capture/src/pipewire_sys.rs`), so the build needs no
# libpipewire headers and the binary links no libpipewire at all — the same
# artifact runs against libpipewire 0.3.48 (Zorin 17 / Ubuntu 22.04) and 1.0.x
# (Ubuntu 24.04, Fedora), and degrades to the X11/XWayland path when PipeWire
# or the portal is absent (CONTRACTS §7, §13).
#
# Binaries land in target/release/ (shared; running with a different family
# than the last build relinks — packaging consumes them immediately after a
# build). CARGO_HOME caches live under target/cargo-home-<family>.
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
release_dir="$repo_root/target/release"
cargo_home_glibc="$repo_root/target/cargo-home"
cargo_home_musl="$repo_root/target/cargo-home-musl"

family="${1:-glibc}"
case "$family" in
    glibc) image="ubuntu:22.04"; cargo_home="$cargo_home_glibc" ;;
    musl)  image="alpine:3.24";   cargo_home="$cargo_home_musl" ;;
    *) echo "build-binaries.sh: unknown family '$family' (glibc|musl)" >&2; exit 2 ;;
esac

command -v docker >/dev/null 2>&1 || {
    echo "build-binaries.sh: docker is required (hermetic toolchain per libc family)" >&2
    exit 1
}
mkdir -p "$cargo_home"

if [ "$family" = "glibc" ]; then
docker run --rm -i \
    -v "$repo_root:/src" \
    -v "$cargo_home:/cargo-home" \
    -e CARGO_HOME=/cargo-home \
    -e LUSTLESS_WAYLAND="${LUSTLESS_WAYLAND:-0}" \
    -w /src \
    "$image" bash -s <<'DOCKER_EOF'
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends \
    build-essential curl ca-certificates pkg-config \
    libgtk-3-dev libayatana-appindicator3-dev \
    libssl-dev libsecret-1-dev \
    libx11-dev libxext-dev libxrandr-dev
if [ ! -x "$CARGO_HOME/bin/rustup" ]; then
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
        | sh -s -- -y --profile minimal --default-toolchain stable
fi
"$CARGO_HOME/bin/rustup" toolchain install stable --profile minimal
"$CARGO_HOME/bin/rustup" default stable
export PATH="$CARGO_HOME/bin:$PATH"
rustc --version
# Wayland portal capture is compiled in (see the header note): no pipewire
# headers are needed because the backend dlopens libpipewire-0.3.so.0 itself.
cargo build --release
DOCKER_EOF
else
docker run --rm -i \
    -v "$repo_root:/src" \
    -v "$cargo_home:/cargo-home" \
    -e CARGO_HOME=/cargo-home \
    -e CARGO_HOME_HOST="$cargo_home" \
    -w /src \
    "$image" sh -s <<'DOCKER_EOF'
set -eu
apk add --no-cache build-base cargo rust sqlite-dev openssl-dev \
    pkgconfig gtk+3.0-dev libayatana-appindicator-dev libsecret-dev \
    libx11-dev libxext-dev libxrandr-dev tcl bash
export PATH="$CARGO_HOME_HOST/bin:$PATH"
rustc --version
cargo --version
# Same feature set as the glibc baseline: the portal backend is included (it
# dlopens libpipewire, so no pipewire headers are needed here either — the
# alpine VM in the testbed matrix is CLI-only, but the APK also targets Alpine
# desktops).
cargo build --release
DOCKER_EOF
fi

for bin in lustlessd lustless-classifier lustless-agent lustlessctl; do
    if [ ! -x "$release_dir/$bin" ]; then
        echo "build-binaries.sh: missing $release_dir/$bin after build" >&2
        exit 1
    fi
done
echo "build-binaries.sh: $family binaries ready in target/release/"
file "$release_dir/lustlessd" 2>/dev/null || true
