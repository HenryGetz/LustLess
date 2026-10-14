#!/bin/bash
# Wave-5 step 2 (runs inside a Wayland session): install the package, sign in,
# let a capture tick happen, and ship the evidence back to the harness.
#
# Fetched with a single unshifted command in the VM:
#   curl 172.30.16.1/go.sh -o /tmp/go.sh; sh /tmp/go.sh
PASS="${PASS:-lustless123}"
HOST=172.30.16.1
R=/tmp/wave5-report.txt

# Non-interactive sudo: a freshly logged-in session has no sudo timestamp, and
# the console used to drive this VM cannot reliably type shifted characters, so
# the password goes in over stdin where it cannot be mistyped.
SUDO() { printf '%s\n' "$PASS" | sudo -S -p '' "$@"; }

{
  echo "==================== SESSION ===================="
  echo "XDG_SESSION_TYPE=$XDG_SESSION_TYPE"
  echo "DISPLAY=$DISPLAY XDG_RUNTIME_DIR=$XDG_RUNTIME_DIR"
  echo "WAYLAND_DISPLAY=$WAYLAND_DISPLAY DBUS_SESSION_BUS_ADDRESS=$DBUS_SESSION_BUS_ADDRESS"
  for s in $(loginctl list-sessions --no-legend | awk '{print $1}'); do
    echo "--- session $s ---"
    loginctl show-session "$s" -p Id -p Type -p Display -p Active -p Remote -p Class -p State 2>&1
  done
  echo "==================== PIPEWIRE / PORTAL ===================="
  dpkg -l 2>/dev/null | grep -E "libpipewire-0.3-0|xdg-desktop-portal" | awk '{print $2, $3}'
  echo "libpipewire soname: $(ls /usr/lib/x86_64-linux-gnu/libpipewire-0.3.so.0 2>/dev/null || echo NO)"
  echo "portal on the session bus: $(busctl --user list 2>/dev/null | grep -c org.freedesktop.portal.Desktop)"
  echo "==================== INSTALL ===================="
  SUDO apt-get install -y /tmp/lustless.deb 2>&1 | tail -8
  echo "==================== SIGN IN (offline account) ===================="
  printf '%s\n' "$PASS" | SUDO lustlessctl signin testuser 2>&1 | head -3
  SUDO lustlessctl status 2>&1 | head -14
  echo "==================== WAITING FOR A CAPTURE TICK ===================="
  echo "(accept the ScreenCast dialog in the desktop session)"
  sleep 100
  echo "==================== SPOOL ===================="
  SUDO find /var/lib/lustless/spool -maxdepth 5 2>/dev/null | head -30
  echo "--- images written ---"
  SUDO find /var/lib/lustless/spool -name '*.png' 2>/dev/null | head -6
  echo "--- manifest (first 1200 bytes) ---"
  SUDO find /var/lib/lustless/spool -name 'manifest.json' 2>/dev/null | head -1 | xargs -r SUDO head -c 1200
  echo
  echo "--- portal restore token ---"
  SUDO ls -l /var/lib/lustless/*/portal-restore-token 2>/dev/null || echo "(none yet)"
  echo "==================== CLASSIFIER ===================="
  SUDO journalctl -u lustless-classifier -n 20 --no-pager 2>&1 | tail -20
  echo "==================== DAEMON (capture lines) ===================="
  SUDO journalctl -u lustlessd -n 400 --no-pager 2>&1 \
    | grep -iE "capture|portal|pipewire|wayland|screenstate|spool|classifier|backend" | tail -40
  echo "==================== DONE ===================="
} > "$R" 2>&1

echo "report written to $R"
wget -q -O /dev/null --post-file="$R" "http://$HOST/report-$(hostname).txt" && echo " report uploaded" || echo " report upload failed"
tail -25 "$R"
