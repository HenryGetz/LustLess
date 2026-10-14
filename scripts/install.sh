#!/bin/sh
# LustLess universal installer — detects the distro family and installs the
# matching package (PACKAGING-MATRIX §2). POSIX sh, pipe-safe:
#
#   curl -fsSL <raw-url>/scripts/install.sh | sudo bash      # download + install
#   sh install.sh ./lustless_0.1.8_amd64.deb                 # install a local file
#
# Env:
#   LUSTLESS_RELEASE_URL   base URL of the release assets
#                          (default: the project's GitHub v0.1.8 release)
#
# Families: apk (Alpine), pacman (Arch/SteamOS), rpm-ostree (Bazzite — a
# reboot is required after layering), dnf/rpm (Fedora), apt (Debian/Ubuntu/
# Mint/Zorin). Removal afterwards uses the native tool of the same family
# (see packaging/README.md for the exact commands and what uninstall
# restores).
set -eu
set -o pipefail 2>/dev/null || true

VERSION="0.1.8"
DEFAULT_BASE="https://github.com/HenryGetz/LustLess/releases/download/v0.1.8"
BASE="${LUSTLESS_RELEASE_URL:-$DEFAULT_BASE}"

die() { echo "install.sh: $*" >&2; exit 1; }

detect_family() {
    if [ -f /etc/alpine-release ]; then echo apk; return; fi
    if command -v rpm-ostree >/dev/null 2>&1; then echo rpm-ostree; return; fi
    if command -v pacman >/dev/null 2>&1; then echo pacman; return; fi
    if command -v dnf >/dev/null 2>&1 || command -v rpm >/dev/null 2>&1; then echo dnf; return; fi
    if command -v apt-get >/dev/null 2>&1; then echo apt; return; fi
    die "no supported package manager found (need apk/pacman/rpm-ostree/dnf/apt)"
}

asset_for() {
    case "$1" in
        apt)         echo "lustless_${VERSION}_amd64.deb" ;;
        dnf)         echo "lustless-${VERSION}-1.x86_64.rpm" ;;
        rpm-ostree)  echo "lustless-${VERSION}-1.x86_64.rpm" ;;
        pacman)      echo "lustless-${VERSION}-1-x86_64.pkg.tar.zst" ;;
        apk)         echo "lustless-${VERSION}-r0.apk" ;;
    esac
}

as_root() {
    if [ "$(id -u)" -eq 0 ]; then "$@"; else sudo "$@"; fi
}

family="$(detect_family)"
asset="$(asset_for "$family")"

pkg="${1:-}"
work="$(mktemp -d)"
# 0755 so apt's _apt sandbox user can read the deb (0700 makes apt warn
# "Download is performed unsandboxed as root").
chmod 0755 "$work"
trap 'rm -rf "$work"' EXIT
if [ -n "$pkg" ]; then
    [ -f "$pkg" ] || die "local package not found: $pkg"
else
    pkg="$work/$asset"
    echo "install.sh: downloading $asset from $BASE"
    if command -v curl >/dev/null 2>&1; then
        curl -fL --retry 5 -o "$pkg" "$BASE/$asset" \
            || die "download failed — fetch the asset manually and rerun with the local file path"
    else
        wget -O "$pkg" "$BASE/$asset" \
            || die "download failed — fetch the asset manually and rerun with the local file path"
    fi
fi

echo "install.sh: installing $pkg via $family"
case "$family" in
    apt)
        as_root apt-get update -qq || true
        # Recommends matter here: the tray needs a StatusNotifier host
        # (xfce4-indicator-plugin on Xfce — Zorin/Xubuntu).
        as_root env DEBIAN_FRONTEND=noninteractive apt-get install -y "$pkg" ;;
    dnf)
        as_root dnf install -y "$pkg" ;;
    rpm-ostree)
        as_root rpm-ostree install "$pkg" \
            && echo "install.sh: layered — reboot to activate (systemd unit starts on first boot)" ;;
    pacman)
        # SteamOS (and other immutable Arch images) mount / read-only: the
        # vendor tool has to open it before pacman can write, and it is put
        # back afterwards either way (also on failure, via `die`).
        if command -v steamos-readonly >/dev/null 2>&1; then
            as_root steamos-readonly disable
            if ! as_root pacman -U --noconfirm "$pkg"; then
                as_root steamos-readonly enable || true
                die "pacman -U failed on the read-only filesystem"
            fi
            as_root steamos-readonly enable
        else
            as_root pacman -U --noconfirm "$pkg"
        fi ;;
    apk)
        as_root apk add --allow-untrusted "$pkg" ;;
esac

# Bring up the per-user agent for the invoking user right now instead of
# waiting for their next login: the XDG autostart entry only runs at session
# start, so without this the agent looks "not installed" until a re-login.
# Starting the agent is also what opens the sign-in window — a signed-out
# agent presents it two seconds after startup, so a fresh machine goes
# install → window → sign in with no tray or menu hunting.
start_user_agent() {
    [ "$(id -u)" -eq 0 ] || return 0
    [ -n "${SUDO_USER:-}" ] || return 0
    user="$SUDO_USER"
    [ "$user" = "root" ] && return 0
    uid="$(id -u "$user" 2>/dev/null)" || return 0
    runtime="${XDG_RUNTIME_DIR:-/run/user/$uid}"
    [ -d "$runtime" ] || return 0
    command -v systemctl >/dev/null 2>&1 || return 0

    user_systemctl() {
        sudo -H -u "$user" env XDG_RUNTIME_DIR="$runtime" \
            DBUS_SESSION_BUS_ADDRESS="unix:path=$runtime/bus" \
            systemctl --user "$@"
    }

    echo "install.sh: starting the LustLess agent for $user"
    user_systemctl daemon-reload >/dev/null 2>&1 || true
    if user_systemctl enable --now lustless-agent.service >/dev/null 2>&1; then
        echo "install.sh: the sign-in window is opening in your session"
    else
        # No usable user manager (unusual): fall back to launching the window
        # directly when this shell still knows the display (sudo keeps
        # DISPLAY/WAYLAND_DISPLAY on most desktops).
        if [ -n "${DISPLAY:-}${WAYLAND_DISPLAY:-}" ]; then
            sudo -H -u "$user" env XDG_RUNTIME_DIR="$runtime" \
                DISPLAY="${DISPLAY:-}" WAYLAND_DISPLAY="${WAYLAND_DISPLAY:-}" \
                XAUTHORITY="${XAUTHORITY:-}" HOME="${HOME:-}" \
                setsid --fork /usr/bin/lustless-agent --show >/dev/null 2>&1 &
        fi
        echo "install.sh: sign in from the application menu entry \"LustLess\", or run:"
        echo "            lustless-agent --show"
    fi
}
start_user_agent

echo
echo "install.sh: done. Check with:  lustlessctl status"
echo "install.sh: sign in in the LustLess window (application menu entry"
echo "            \"LustLess\" opens it again), or headless with:"
echo "            lustlessctl signin <username>"
echo "install.sh: DNS filtering is active system-wide after install; the tray"
echo "            agent runs in your session (application menu / tray icon)."
echo "            See /etc/lustless/lustless.toml for configuration."
