#!/usr/bin/env bash
# LustLess universal installer — detects the distro family and installs the
# matching package (PACKAGING-MATRIX §2). Works from a downloaded release
# asset or a local package file:
#
#   scripts/install.sh                                  download + install
#   scripts/install.sh ./lustless_0.1.0_amd64.deb       install a local file
#
# Env:
#   LUSTLESS_RELEASE_URL   base URL of the release assets
#                          (default: the project's GitHub latest release)
#
# Families: apk (Alpine), pacman (Arch/SteamOS), rpm-ostree (Bazzite — a
# reboot is required after layering), dnf/rpm (Fedora), apt (Debian/Ubuntu/
# Mint/Zorin). Removal afterwards uses the native tool of the same family
# (see packaging/README.md for the exact commands and what uninstall
# restores).
set -euo pipefail

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
if [ -n "$pkg" ]; then
    [ -f "$pkg" ] || die "local package not found: $pkg"
else
    pkg="$asset"
    echo "install.sh: downloading $asset from $BASE"
    curl -fL --retry 5 -o "$pkg.tmp" "$BASE/$asset" \
        || die "download failed — fetch the asset manually and rerun with the local file path"
    mv "$pkg.tmp" "$pkg"
fi

echo "install.sh: installing $pkg via $family"
case "$family" in
    apt)
        as_root env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "./$pkg" ;;
    dnf)
        as_root dnf install -y "./$pkg" ;;
    rpm-ostree)
        as_root rpm-ostree install "./$pkg" \
            && echo "install.sh: layered — reboot to activate (systemd unit starts on first boot)" ;;
    pacman)
        as_root pacman -U --noconfirm "./$pkg" ;;
    apk)
        as_root apk add --allow-untrusted "./$pkg" ;;
esac

echo
echo "install.sh: done. Check with:  lustlessctl status"
echo "install.sh: DNS filtering is active system-wide after install; the tray"
echo "            agent starts on graphical login (XDG autostart / systemd user"
echo "            unit). See /etc/lustless/lustless.toml for configuration."
