#!/bin/bash
# Make a testbed VM able to run a Wayland session, and select it.
#
# Two independent gates had to be cleared (both were closed on these images):
#   * /etc/gdm3/custom.conf  — `WaylandEnable=false` uncommented: GDM then never
#     offers or starts a Wayland session at all (which is why the login screen
#     showed no session chooser and why XSession=...-wayland was ignored).
#   * AccountsService — the per-user session choice; GNOME 42+ reads `Session`,
#     older GDM reads `XSession`, so both are written.
#
# Usage: wy.sh <wayland-session-name>   (e.g. ubuntu-wayland | zorin-wayland)
PASS="${PASS:-lustless123}"
SESSION="${1:-ubuntu-wayland}"
USERNAME="$(id -un)"
R=/tmp/wy.txt
SUDO() { printf '%s\n' "$PASS" | sudo -S -p '' "$@"; }

{
  echo "===== $USERNAME -> $SESSION ====="
  echo "----- available sessions -----"
  ls /usr/share/wayland-sessions/ /usr/share/xsessions/ 2>&1
  echo "----- gdm before -----"
  SUDO cat /etc/gdm3/custom.conf 2>&1
  if SUDO grep -qE "^[[:space:]]*WaylandEnable[[:space:]]*=[[:space:]]*false" /etc/gdm3/custom.conf; then
    SUDO sed -i -E 's|^[[:space:]]*WaylandEnable[[:space:]]*=[[:space:]]*false.*|#WaylandEnable=false   # re-enabled for the LustLess Wayland capture verification|' /etc/gdm3/custom.conf
    echo ">>> commented out WaylandEnable=false"
  else
    echo ">>> no active WaylandEnable=false"
  fi
  echo "----- gdm after -----"
  SUDO grep -n "WaylandEnable" /etc/gdm3/custom.conf 2>&1 || echo "(none)"

  # The helper is written as the unprivileged user (so the sudo password can be
  # piped on stdin) and then executed with sudo.
  cat > /tmp/set_session.py <<'PY'
import configparser
import sys

user, session = sys.argv[1], sys.argv[2]
path = "/var/lib/AccountsService/users/" + user
cfg = configparser.ConfigParser()
cfg.optionxform = str
cfg.read(path)
if not cfg.has_section("User"):
    cfg.add_section("User")
cfg.set("User", "Session", session)
cfg.set("User", "XSession", session)
with open(path, "w") as fh:
    cfg.write(fh)
print("wrote", path)
PY
  SUDO python3 /tmp/set_session.py "$USERNAME" "$SESSION" 2>&1
  echo "----- accounts service after -----"
  SUDO cat "/var/lib/AccountsService/users/$USERNAME" 2>&1
  echo "===== logging out ====="
} > "$R" 2>&1

wget -q -O /dev/null --post-file="$R" http://172.30.16.1/report-wy.txt
cat "$R"
gnome-session-quit --logout --no-prompt
