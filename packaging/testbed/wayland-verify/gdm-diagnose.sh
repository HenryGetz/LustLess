#!/bin/bash
# Wave-5 step 1a: find out why GDM is not offering/starting the Wayland
# session, and fix the two places that decide it:
#   * /etc/gdm3/custom.conf  — WaylandEnable=false disables Wayland entirely
#     (Zorin ships X11-first, which is why the login screen showed no session
#     chooser at all)
#   * AccountsService XSession/Session — which session GDM starts for the user
PASS="${PASS:-lustless123}"
R=/tmp/w2-report.txt
SUDO() { printf '%s\n' "$PASS" | sudo -S -p '' "$@"; }

{
  echo "===== gdm config ====="
  SUDO cat /etc/gdm3/custom.conf 2>&1
  echo "===== WaylandEnable lines ====="
  SUDO grep -rn "WaylandEnable" /etc/gdm3/ 2>&1
  echo "===== gdm version ====="
  dpkg -l gdm3 2>/dev/null | tail -1
  echo "===== udev/qemu vga ====="
  lspci 2>/dev/null | grep -iE "vga|display" || echo "(no lspci)"
  echo "===== kernel cmdline / modules ====="
  cat /proc/cmdline
  echo "===== gnome-shell wayland support ====="
  ls -l /usr/bin/gnome-shell
  echo "===== accounts service keys ====="
  SUDO cat /var/lib/AccountsService/users/tester
  echo "===== writing both session keys ====="
  SUDO tee /tmp/aset.py >/dev/null <<'PY'
import configparser
import sys

path = "/var/lib/AccountsService/users/tester"
cfg = configparser.ConfigParser()
cfg.optionxform = str
cfg.read(path)
if not cfg.has_section("User"):
    cfg.add_section("User")
cfg.set("User", "Session", "zorin-wayland")
cfg.set("User", "XSession", "zorin-wayland")
with open(path, "w") as fh:
    cfg.write(fh)
print("wrote", path)
PY
  SUDO python3 /tmp/aset.py 2>&1
  SUDO cat /var/lib/AccountsService/users/tester
  echo "===== enabling wayland in gdm ====="
  if SUDO grep -qE "^WaylandEnable=false" /etc/gdm3/custom.conf; then
    SUDO sed -i 's/^WaylandEnable=false/#WaylandEnable=false  # re-enabled for the LustLess Wayland capture test/' /etc/gdm3/custom.conf
    echo "commented out WaylandEnable=false"
  else
    echo "WaylandEnable=false not present"
  fi
  SUDO grep -n "WaylandEnable" /etc/gdm3/custom.conf || echo "(no WaylandEnable line now)"
  echo "===== done ====="
} > "$R" 2>&1

cat "$R"
curl -s -X POST --data-binary @"$R" "http://172.30.16.1/report-w2.txt" >/dev/null 2>&1
