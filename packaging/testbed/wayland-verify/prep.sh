#!/bin/bash
# Wave-5 prep on a testbed VM: install the freshly built 0.1.10 package, put the
# daemon in its documented offline mode (empty upload.base_url — these VMs have
# no reachable API), restart it, and sign in so the capture gate opens.
PASS="${PASS:-lustless123}"
R=/tmp/prep.txt
SUDO() { printf '%s\n' "$PASS" | sudo -S -p '' "$@"; }

{
  echo "===== fetching the package ====="
  wget -q 172.30.16.1/lustless.deb -O /tmp/lustless.deb && ls -la /tmp/lustless.deb
  echo "===== installing ====="
  SUDO apt-get install -y /tmp/lustless.deb 2>&1 | tail -6
  dpkg -l lustless 2>/dev/null | tail -1
  echo "===== offline mode (documented: upload.base_url empty) ====="
  SUDO cp -n /etc/lustless/lustless.toml /etc/lustless/lustless.toml.orig
  SUDO sed -i 's|^base_url = .*|base_url = ""|' /etc/lustless/lustless.toml
  grep -nE "^base_url|^\[upload\]" /etc/lustless/lustless.toml
  echo "===== restarting the daemon ====="
  SUDO systemctl restart lustlessd
  sleep 3
  SUDO systemctl is-active lustlessd
  echo "===== sign in (offline) ====="
  printf '%s\n' "$PASS" | SUDO lustlessctl signin testuser 2>&1 | head -3
  sleep 4
  SUDO lustlessctl status 2>&1 | head -20
  echo "===== policy ====="
  SUDO lustlessctl policy 2>&1 | head -20
  echo "===== session ====="
  loginctl list-sessions --no-legend
  for s in $(loginctl list-sessions --no-legend | awk '{print $1}'); do
    loginctl show-session "$s" -p Type -p Active -p Display
  done
  echo "XDG_SESSION_TYPE=$XDG_SESSION_TYPE WAYLAND_DISPLAY=$WAYLAND_DISPLAY"
  echo "===== daemon log ====="
  SUDO journalctl -u lustlessd --since "-3 min" --no-pager 2>&1 | tail -25
  echo "===== done ====="
} > "$R" 2>&1

wget -q -O /dev/null --post-file="$R" http://172.30.16.1/report-prep.txt && echo uploaded || echo "upload failed"
head -70 "$R"
