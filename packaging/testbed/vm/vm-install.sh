#!/bin/sh
# VM-side package installer (PACKAGING-MATRIX §6 step 1). Runs INSIDE a test
# VM; fetches the right package for the detected family from the host server
# and installs it with the native tool. Root or passwordless sudo both work.
#
#   wget -O vm-install.sh http://172.30.16.1:9996/vm-install.sh && sh vm-install.sh
set -u
HOST="http://$(ip route 2>/dev/null | awk "/default/ {print \$3; exit}"):9996"

as_root() { if [ "$(id -u)" -eq 0 ]; then "$@"; else sudo "$@"; fi; }

detect() {
    if [ -f /etc/alpine-release ]; then echo apk; return; fi
    if command -v rpm-ostree >/dev/null 2>&1; then echo rpm-ostree; return; fi
    if command -v pacman >/dev/null 2>&1; then echo pacman; return; fi
    if command -v dnf >/dev/null 2>&1 || command -v rpm >/dev/null 2>&1; then echo dnf; return; fi
    if command -v apt-get >/dev/null 2>&1; then echo apt; return; fi
    echo unknown
}

family="$(detect)"
echo "== family: $family"
case "$family" in
    apt)        pkg="lustless_0.1.2_amd64.deb" ;;
    dnf)        pkg="lustless-0.1.2-1.x86_64.rpm" ;;
    rpm-ostree) pkg="lustless-0.1.2-1.x86_64.rpm" ;;
    pacman)     pkg="lustless-0.1.2-1-x86_64.pkg.tar.zst" ;;
    apk)        pkg="lustless-0.1.2-r0.apk" ;;
    *) echo "vm-install: unsupported family"; exit 1 ;;
esac

echo "== resolver state before install =="
ls -la /etc/resolv.conf; head -3 /etc/resolv.conf 2>/dev/null

wget -O "/tmp/$pkg" "$HOST/$pkg" || { echo "vm-install: download failed"; exit 1; }
echo "== installing $pkg =="
case "$family" in
    apt)        as_root env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "/tmp/$pkg" ;;
    dnf)        as_root dnf install -y "/tmp/$pkg" ;;
    rpm-ostree) as_root rpm-ostree install -y "/tmp/$pkg" ;;
    pacman)     as_root pacman -U --noconfirm "/tmp/$pkg" ;;
    apk)        as_root apk add --allow-untrusted "/tmp/$pkg" ;;
esac
rc=$?
echo "vm-install: exit=$rc"
if [ "$family" = "rpm-ostree" ]; then
    echo "vm-install: rpm-ostree layered — REBOOT before verifying services"
fi
exit $rc
