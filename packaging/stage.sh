#!/usr/bin/env bash
# Build the shared payload tree consumed by every package format.
#
#   packaging/stage.sh [dest]     assemble the CONTRACTS §4 filesystem
#                                 layout at [dest] (default:
#                                 target/pkg-root)
#
# Requires the four release binaries in target/release/ (run
# packaging/build-binaries.sh first, or build-deb.sh's --skip-build
# equivalent for the other formats). All four packages MUST be assembled
# from this one tree (PACKAGING-MATRIX §2) — format builders add only
# metadata, scriptlets and format-specific extras (OpenRC initd, XDG
# autostart) on top.
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
release_dir="$repo_root/target/release"
dest="${1:-$repo_root/target/pkg-root}"
want_libc="${2:-}"

for bin in lustlessd lustless-classifier lustless-agent lustlessctl; do
    if [ ! -x "$release_dir/$bin" ]; then
        echo "stage.sh: missing $release_dir/$bin — run packaging/build-binaries.sh" >&2
        exit 1
    fi
done

# Guard against mixing libc families: target/release is shared between the
# glibc and musl builds, and --skip-build repackages whatever is there.
if [ -n "$want_libc" ]; then
    interp="$(readelf -l "$release_dir/lustlessd" 2>/dev/null \
        | grep -oE 'ld-(musl|linux)[^ ]*' | head -1 || true)"
    case "$want_libc" in
        glibc) case "$interp" in ld-linux*) : ;; *)
            echo "stage.sh: target/release holds a $interp binary — expected glibc; rerun without --skip-build" >&2; exit 1 ;;
        esac ;;
        musl) case "$interp" in ld-musl*) : ;; *)
            echo "stage.sh: target/release holds a ${interp:-unknown} binary — expected musl; rerun without --skip-build" >&2; exit 1 ;;
        esac ;;
    esac
fi

rm -rf "$dest"
mkdir -p "$dest"

# Binaries (§4)
install -D -m 0755 "$release_dir/lustlessd"           "$dest/usr/bin/lustlessd"
install -D -m 0755 "$release_dir/lustless-classifier" "$dest/usr/bin/lustless-classifier"
install -D -m 0755 "$release_dir/lustless-agent"      "$dest/usr/bin/lustless-agent"
install -D -m 0755 "$release_dir/lustlessctl"         "$dest/usr/bin/lustlessctl"

# Maintainer helper (PACKAGING-MATRIX §3) — one source for every scriptlet.
install -D -m 0755 "$repo_root/packaging/maintainer/lustless-maintainer" \
    "$dest/usr/lib/lustless/lustless-maintainer"

# Model bundle (§4/§7) — auto-staged from the classifier crate's fetch script.
install -d -m 0755 "$dest/usr/share/lustless/models"
model_src="$repo_root/crates/lustless-classifier/models"
if [ ! -f "$model_src/manifest.json" ] && [ -x "$repo_root/crates/lustless-classifier/fetch-model.sh" ]; then
    echo "stage.sh: staging model bundle via fetch-model.sh"
    "$repo_root/crates/lustless-classifier/fetch-model.sh"
fi
if [ -f "$model_src/manifest.json" ]; then
    cp -a "$model_src/." "$dest/usr/share/lustless/models/"
    rm -f "$dest/usr/share/lustless/models/.gitignore"
    find "$dest/usr/share/lustless/models" -type d -exec chmod 0755 {} +
    find "$dest/usr/share/lustless/models" -type f -exec chmod 0644 {} +
else
    echo "stage.sh: note: no models/ directory — model bundle not packaged (see packaging/README.md)" >&2
fi

# Dashboard extras dir (§4, MAY hold extras)
install -d -m 0755 "$dest/usr/share/lustless/dashboard"

# XDG autostart fallback for the tray agent — single-instance via
# GApplication id (crates/lustless-agent/src/main.rs), so coexistence with
# the systemd user unit is safe; it is the ONLY path on Alpine (no systemd
# user sessions) and covers LXQt autostart as well. NoDisplay: autostart
# only, the visible entry is the application-menu launcher below.
install -D -m 0644 "$repo_root/packaging/xdg/lustless-agent.desktop" \
    "$dest/etc/xdg/autostart/lustless-agent.desktop"

# Application-menu launcher: `lustless-agent --show` presents the sign-in
# dialog (or the dashboard when signed in). This is the sign-in surface on
# desktops with no StatusNotifier host, where the tray menu is unavailable.
install -D -m 0644 "$repo_root/packaging/xdg/lustless-app.desktop" \
    "$dest/usr/share/applications/lustless-agent.desktop"

# systemd units (§4/§11) — used by every glibc distro in the matrix; the
# Alpine package drops these and installs packaging/openrc/lustlessd.initd.
install -D -m 0644 "$repo_root/packaging/systemd/lustlessd.service" \
    "$dest/usr/lib/systemd/system/lustlessd.service"
install -D -m 0644 "$repo_root/packaging/systemd/lustless-agent.service" \
    "$dest/usr/lib/systemd/user/lustless-agent.service"

# Polkit action — staged as a source copy; the maintainer helper installs it
# to /usr/share/polkit-1/actions/ so purge can remove/restore it.
install -D -m 0644 "$repo_root/packaging/polkit/org.lustless.policy" \
    "$dest/usr/share/lustless/polkit/org.lustless.policy"

# Browser DoH-lockdown policies — staged as source copies; the maintainer
# helper installs them merge-safely (see packaging/README.md).
for p in chrome chromium brave edge firefox; do
    install -D -m 0644 "$repo_root/packaging/browser-policies/$p.json" \
        "$dest/usr/share/lustless/browser-policies/$p.json"
done

# Sample system config (conffile semantics per format)
install -D -m 0644 "$repo_root/packaging/etc/lustless.toml" \
    "$dest/etc/lustless/lustless.toml"

# Pixmap (Icon: field of package metadata; CE logo, packaging/assets/README.md)
install -D -m 0644 "$repo_root/packaging/assets/lustless-256.png" \
    "$dest/usr/share/pixmaps/lustless.png"

# The CE shield at every size the desktop asks for (menus 16/24, panels and
# window decorations 32/48, launchers and About dialogs 256) so the icon in
# the application menu, the taskbar and the sign-in window is the same mark
# the original Windows client ships — not a scaled-up 256 or a generic
# fallback. `Icon=lustless` in the .desktop files resolves here first.
for size in 16 24 32 48 256; do
    install -D -m 0644 "$repo_root/packaging/assets/lustless-$size.png" \
        "$dest/usr/share/icons/hicolor/${size}x${size}/apps/lustless.png"
done

echo "stage.sh: staged payload at $dest"
