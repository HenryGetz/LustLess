#!/bin/bash
# Wave-5 capture proof, run inside a Wayland session: give the daemon time to
# take a screenstate, then ship the evidence back.
#
# The single interactive step is the compositor's ScreenCast dialog, which the
# harness accepts over VNC while this script sleeps.
PASS="${PASS:-lustless123}"
R=/tmp/cap.txt
SUDO() { printf '%s\n' "$PASS" | sudo -S -p '' "$@"; }

{
  echo "===== session ====="
  echo "XDG_SESSION_TYPE=$XDG_SESSION_TYPE WAYLAND_DISPLAY=$WAYLAND_DISPLAY"
  for s in $(loginctl list-sessions --no-legend | awk '{print $1}'); do
    echo "--- $s ---"; loginctl show-session "$s" -p Type -p Active -p Display -p Remote
  done
  echo "===== status before ====="
  SUDO lustlessctl status 2>&1 | head -12
  echo "===== daemon capture log (last 10 min) ====="
  SUDO journalctl -u lustlessd --since "-10 min" --no-pager 2>&1 \
    | grep -iE "capture|wayland|portal|pipewire|backend|stream|screenstate|spool" | tail -40
  echo "===== waiting 70s for a capture tick ====="
  sleep 70
  echo "===== spool ====="
  SUDO find /var/lib/lustless/spool -maxdepth 5 2>/dev/null | head -30
  echo "--- images written ---"
  SUDO find /var/lib/lustless/spool -name '*.png' 2>/dev/null | head -6
  echo "--- manifest (first 1500 bytes) ---"
  SUDO find /var/lib/lustless/spool -name 'manifest.json' 2>/dev/null | head -1 | xargs -r SUDO head -c 1500
  echo
  echo "--- portal restore token ---"
  SUDO ls -l /var/lib/lustless/1000/portal-restore-token 2>/dev/null || echo "(none)"
  echo "===== daemon capture log (after) ====="
  SUDO journalctl -u lustlessd --since "-5 min" --no-pager 2>&1 \
    | grep -iE "capture|wayland|portal|pipewire|backend|stream|screenstate" | tail -30
  echo "===== classifier activity ====="
  SUDO journalctl -u lustlessd --since "-5 min" --no-pager 2>&1 \
    | grep -iE "score|flag|analyze|consum|batch|window" | tail -20
  echo "===== status after ====="
  SUDO lustlessctl status 2>&1 | head -12
  echo "===== done ====="
} > "$R" 2>&1

wget -q -O /dev/null --post-file="$R" http://172.30.16.1/report-cap.txt && echo uploaded || echo "upload failed"
tail -45 "$R"
