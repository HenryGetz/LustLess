#!/usr/bin/env bash
# Build lustless_0.1.0_amd64.deb.
#
#   packaging/build-deb.sh               full build: compile the Cargo
#                                        workspace inside an ubuntu:22.04
#                                        container (glibc 2.35 target —
#                                        CONTRACTS §2), then assemble the
#                                        package with dpkg-deb
#   packaging/build-deb.sh --skip-build  reuse binaries already in
#                                        target/release/ (must be glibc
#                                        2.35-compatible; repackage only)
#
# Runnable from anywhere; paths resolve relative to the repo root. Output:
#   ./lustless_0.1.0_amd64.deb
#
# Model bundle: staged automatically from crates/lustless-classifier/models
# (populated by fetch-model.sh from the CE bundle artifacts, AUTHORIZATION.md);
# it is packaged as /usr/share/lustless/models/. Without
# it the package still builds — screen accountability needs the bundle at
# runtime (see packaging/README.md). No placeholder artifacts are shipped.
set -euo pipefail

VERSION="0.1.0"
ARCH="amd64"
IMAGE="ubuntu:22.04"

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
release_dir="$repo_root/target/release"
stage="$repo_root/target/deb-root"
cargo_home="$repo_root/target/cargo-home"
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
    command -v docker >/dev/null 2>&1 || {
        echo "build-deb.sh: docker is required to build against glibc 2.35 (CONTRACTS §2)" >&2
        exit 1
    }
    mkdir -p "$cargo_home"
    docker run --rm -i \
        -v "$repo_root:/src" \
        -v "$cargo_home:/cargo-home" \
        -e CARGO_HOME=/cargo-home \
        -w /src \
        "$IMAGE" bash -s <<'DOCKER_EOF'
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
# The release build ships WITHOUT the Wayland portal backend by default (the
# glibc-2.35 base carries pipewire 0.3.x headers, which pipewire-rs 0.10 cannot
# bind); X11 capture is complete everywhere and Wayland sessions fall back to
# X11/XWayland root capture with a journal warning. Set LUSTLESS_WAYLAND=1 on a
# pipewire-1.x build host to include the portal backend.
if [ "${LUSTLESS_WAYLAND:-0}" = "1" ]; then
    cargo build --release
else
    cargo build --release --no-default-features
fi
DOCKER_EOF
fi

# --- Stage the package tree -------------------------------------------------
for bin in lustlessd lustless-classifier lustless-agent lustlessctl; do
    if [ ! -x "$release_dir/$bin" ]; then
        echo "build-deb.sh: missing $release_dir/$bin — run without --skip-build" >&2
        exit 1
    fi
done

rm -rf "$stage"
mkdir -p "$stage/DEBIAN"

# Binaries (§4)
install -D -m 0755 "$release_dir/lustlessd"          "$stage/usr/bin/lustlessd"
install -D -m 0755 "$release_dir/lustless-classifier" "$stage/usr/bin/lustless-classifier"
install -D -m 0755 "$release_dir/lustless-agent"     "$stage/usr/bin/lustless-agent"
install -D -m 0755 "$release_dir/lustlessctl"        "$stage/usr/bin/lustlessctl"

# Model bundle (§4/§7) — auto-staged from the classifier crate's fetch script.
install -d -m 0755 "$stage/usr/share/lustless/models"
model_src="$repo_root/crates/lustless-classifier/models"
if [ ! -f "$model_src/manifest.json" ] && [ -x "$repo_root/crates/lustless-classifier/fetch-model.sh" ]; then
    echo "build-deb.sh: staging model bundle via fetch-model.sh"
    "$repo_root/crates/lustless-classifier/fetch-model.sh"
fi
if [ -f "$model_src/manifest.json" ]; then
    cp -a "$model_src/." "$stage/usr/share/lustless/models/"
    rm -f "$stage/usr/share/lustless/models/.gitignore"
    find "$stage/usr/share/lustless/models" -type d -exec chmod 0755 {} +
    find "$stage/usr/share/lustless/models" -type f -exec chmod 0644 {} +
else
    echo "build-deb.sh: note: no models/ directory — model bundle not packaged (see packaging/README.md)"
fi

# Dashboard extras dir (§4, MAY hold extras)
install -d -m 0755 "$stage/usr/share/lustless/dashboard"

# systemd units (§4/§11)
install -D -m 0644 "$repo_root/packaging/systemd/lustlessd.service" \
    "$stage/usr/lib/systemd/system/lustlessd.service"
install -D -m 0644 "$repo_root/packaging/systemd/lustless-agent.service" \
    "$stage/usr/lib/systemd/user/lustless-agent.service"

# Polkit action — staged as a source copy; postinst installs it to
# /usr/share/polkit-1/actions/ so postrm purge can remove/restore it.
install -D -m 0644 "$repo_root/packaging/polkit/org.lustless.policy" \
    "$stage/usr/share/lustless/polkit/org.lustless.policy"

# Browser DoH-lockdown policies — staged as source copies; postinst installs
# them merge-safely (see packaging/README.md).
for p in chrome chromium brave edge firefox; do
    install -D -m 0644 "$repo_root/packaging/browser-policies/$p.json" \
        "$stage/usr/share/lustless/browser-policies/$p.json"
done

# Sample system config (conffile)
install -D -m 0644 "$repo_root/packaging/etc/lustless.toml" \
    "$stage/etc/lustless/lustless.toml"

# Pixmap (Icon: field in DEBIAN/control; CE logo, see packaging/assets/README.md)
install -D -m 0644 "$repo_root/packaging/assets/lustless-256.png" \
    "$stage/usr/share/pixmaps/lustless.png"

# --- DEBIAN/ control area ---------------------------------------------------
install -m 0644 "$repo_root/packaging/debian/control"   "$stage/DEBIAN/control"
install -m 0644 "$repo_root/packaging/debian/conffiles" "$stage/DEBIAN/conffiles"
install -m 0755 "$repo_root/packaging/debian/postinst"  "$stage/DEBIAN/postinst"
install -m 0755 "$repo_root/packaging/debian/prerm"     "$stage/DEBIAN/prerm"
install -m 0755 "$repo_root/packaging/debian/postrm"    "$stage/DEBIAN/postrm"

installed_size="$(du -sk "$stage" | cut -f1)"
sed -i "/^Description:/i Installed-Size: $installed_size" "$stage/DEBIAN/control"

# --- Build ------------------------------------------------------------------
dpkg-deb --build --root-owner-group "$stage" "$out"
echo "build-deb.sh: built $out"
