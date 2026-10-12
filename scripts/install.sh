#!/bin/sh
# LustLess universal installer — detects the distro family and installs the
# matching package (PACKAGING-MATRIX §2). POSIX sh, pipe-safe:
#
#   curl -fsSL <raw-url>/scripts/install.sh | sudo bash      # download + install
#   sh install.sh ./lustless_0.1.0_amd64.deb                 # install a local file
#
# Env:
#   LUSTLESS_RELEASE_URL   base URL of the release assets
#                          (default: the project's GitHub v0.1.1 release)
#
# Families: apk (Alpine), pacman (Arch/SteamOS), rpm-ostree (Bazzite — a
# reboot is required after layering), dnf/rpm (Fedora), apt (Debian/Ubuntu/
# Mint/Zorin). Removal afterwards uses the native tool of the same family
# (see packaging/README.md for the exact commands and what uninstall
# restores).
set -eu
set -o pipefail 2>/dev/null || true

VERSION="0.1.0"
DEFAULT_BASE="https://github.com/HenryGetz/LustLess/releases/download/v0.1.1"
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
        as_root pacman -U --noconfirm "$pkg" ;;
    apk)
        as_root apk add --allow-untrusted "$pkg" ;;
esac

# Bring up the per-user tray agent for the invoking user right now instead of
# waiting for their next login: the XDG autostart entry only runs at session
# start, so without this the agent looks "not installed" until a re-login.
start_user_agent() {
    [ "$(id -u)" -eq 0 ] || return 0
    [ -n "${SUDO_USER:-}" ] || return 0
    user="$SUDO_USER"
    [ "$user" = "root" ] && return 0
    uid="$(id -u "$user" 2>/dev/null)" || return 0
    runtime="${XDG_RUNTIME_DIR:-/run/user/$uid}"
    [ -d "$runtime" ] || return 0
    command -v systemctl >/dev/null 2>&1 || return 0
    echo "install.sh: starting the LustLess tray agent for $user"
    sudo -u "$user" env XDG_RUNTIME_DIR="$runtime" DBUS_SESSION_BUS_ADDRESS="unix:path=$runtime/bus" \
        systemctl --user daemon-reload >/dev/null 2>&1 || true
    sudo -u "$user" env XDG_RUNTIME_DIR="$runtime" DBUS_SESSION_BUS_ADDRESS="unix:path=$runtime/bus" \
        systemctl --user enable --now lustless-agent.service >/dev/null 2>&1 \
        || echo "install.sh: enable lustless-agent.service for $user after login (systemctl --user enable --now lustless-agent.service)"
}
start_user_agent

echo
echo "install.sh: done. Check with:  lustlessctl status"
echo "install.sh: sign in from the application menu entry \"LustLess\", or"
echo "            headless with:  lustlessctl signin <username>"
echo "install.sh: DNS filtering is active system-wide after install; the tray"
echo "            agent runs in your session (application menu / tray icon)."
echo "            See /etc/lustless/lustless.toml for configuration."
