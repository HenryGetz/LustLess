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
# Env: LUSTLESS_WAYLAND=1 — glibc only; include the Wayland portal backend
# (needs pipewire 1.x headers; the 22.04 base carries 0.3.x so the default
# glibc build ships --no-default-features and Wayland falls back to
# XWayland/X11 root capture — CONTRACTS §2 and build-deb.sh history).
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
    libx11-dev libxext-dev libxrandr-dev \
    libpipewire-0.3-dev libclang-dev
if [ ! -x "$CARGO_HOME/bin/rustup" ]; then
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
        | sh -s -- -y --profile minimal --default-toolchain stable
fi
"$CARGO_HOME/bin/rustup" toolchain install stable --profile minimal
"$CARGO_HOME/bin/rustup" default stable
export PATH="$CARGO_HOME/bin:$PATH"
rustc --version
# Wayland portal capture stays OUT of the shipped binaries: the `pipewire`
# crate's spa_sys bindings need a libspa newer than the Ubuntu 22.04 / Zorin 17
# baseline provides (0.3.48) — it fails to build here, and a binary linked
# against a newer libspa would not load on the target at all. The backend is
# implemented (`crates/lustless-capture/src/wayland.rs`, `wayland-portal`
# feature, builds with `LUSTLESS_WAYLAND=1` on a newer toolchain) and the
# capture dispatcher logs the X11/XWayland fallback on Wayland sessions.
# Closing this is a real work item (dlopen-style version-tolerant PipeWire
# bindings, or a crate pin that matches 0.3.48) — see docs/impl/PARITY.md.
if [ "${LUSTLESS_WAYLAND:-0}" = "1" ]; then
    cargo build --release
else
    cargo build --release --no-default-features
fi
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
    libx11-dev libxext-dev libxrandr-dev clang-dev tcl bash
export PATH="$CARGO_HOME_HOST/bin:$PATH"
rustc --version
cargo --version
# Same feature set as the glibc baseline (see the note above): no portal.
cargo build --release --no-default-features
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
