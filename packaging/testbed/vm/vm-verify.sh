#!/bin/sh
# VM-side acceptance verification (PACKAGING-MATRIX §6). Runs INSIDE a test
# VM after vm-install.sh; collects every §6 check into a plain-text report
# and POSTs it to the host server. Exit code reflects PASS/FAIL overall but
# the report always contains every section.
#
#   wget -O vm-verify.sh http://172.30.16.1:9996/vm-verify.sh && sh vm-verify.sh <distro-label>
LABEL="${1:-unknown}"
HOST="http://$(ip route 2>/dev/null | awk "/default/ {print \$3; exit}"):9996"
R=/tmp/lustless-verify.txt
FAIL=0

as_root() { if [ "$(id -u)" -eq 0 ]; then "$@"; else sudo "$@"; fi; }
sec() { printf '\n== %s ==\n' "$1"; }
flag() { # <ok|FAIL> <text>
    [ "$1" = ok ] || FAIL=1
    printf '%s: %s\n' "$1" "$2"
}

{
printf 'lustless verify report — distro: %s\n' "$LABEL"
printf 'date: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
printf 'kernel: %s\n' "$(uname -sr)"
if [ -r /etc/os-release ]; then . /etc/os-release; printf 'os: %s\n' "${PRETTY_NAME:-?}"; fi

sec "0 init system"
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    echo "systemd: yes"
else
    echo "systemd: no"
fi
command -v rc-service >/dev/null 2>&1 && echo "openrc: yes"

sec "1 package installed"
if command -v dpkg >/dev/null 2>&1; then dpkg -l lustless 2>&1 | tail -2
elif command -v rpm >/dev/null 2>&1; then rpm -q lustless 2>&1
elif command -v pacman >/dev/null 2>&1; then pacman -Qi lustless 2>&1 | grep -E 'Name|Version'
elif command -v apk >/dev/null 2>&1; then apk info -e lustless 2>&1
fi
if command -v dpkg >/dev/null 2>&1 && dpkg -l lustless 2>/dev/null | grep -q '^ii'; then flag ok "package installed (deb)"
elif command -v rpm >/dev/null 2>&1 && rpm -q lustless >/dev/null 2>&1; then flag ok "package installed (rpm)"
elif command -v pacman >/dev/null 2>&1 && pacman -Qi lustless >/dev/null 2>&1; then flag ok "package installed (pacman)"
elif command -v apk >/dev/null 2>&1 && apk info -e lustless >/dev/null 2>&1; then flag ok "package installed (apk)"
else flag FAIL "package NOT installed"; fi

sec "2 files (CONTRACTS §4)"
for f in /usr/bin/lustlessd /usr/bin/lustless-classifier /usr/bin/lustless-agent /usr/bin/lustlessctl \
         /usr/lib/lustless/lustless-maintainer /etc/lustless/lustless.toml \
         /usr/lib/systemd/system/lustlessd.service /etc/init.d/lustlessd \
         /etc/xdg/autostart/lustless-agent.desktop; do
    [ -e "$f" ] && echo "present: $f" || echo "absent:  $f"
done

sec "3 service"
if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
    systemctl is-active lustlessd && flag ok "lustlessd active (systemd)" || flag FAIL "lustlessd not active (systemd)"
    systemctl is-enabled lustlessd 2>&1
    systemctl --user is-active lustless-agent.service 2>&1 | head -1
elif command -v rc-service >/dev/null 2>&1; then
    rc-service lustlessd status && flag ok "lustlessd started (OpenRC)" || flag FAIL "lustlessd not started (OpenRC)"
    rc-update show default 2>&1 | grep lustlessd || flag FAIL "lustlessd not in default runlevel"
else
    flag FAIL "no service manager detected"
fi

sec "4 lustlessctl status"
if as_root /usr/bin/lustlessctl status 2>&1 | head -20; then flag ok "lustlessctl status ran"; else flag FAIL "lustlessctl status failed"; fi

sec "5 dns: blocked query via 127.0.0.2"
if command -v dig >/dev/null 2>&1; then
    blocked=$(dig @127.0.0.2 blocked.example.test A +short +time=3 +tries=1 2>&1)
else
    # Alpine/busybox: nslookup queries the given server directly.
    blocked=$(nslookup blocked.example.test 127.0.0.2 2>&1 | grep -A2 -i answer | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -1)
fi
echo "answer: ${blocked:-<empty>}"
# Blocked verdict synthesizes A 127.0.0.2 (block.rs BLOCK_ANSWER_IPV4).
if printf '%s' "$blocked" | grep -q '^127\.0\.0\.2$'; then
    flag ok "blocked name answered with block verdict 127.0.0.2"
else
    flag FAIL "blocked name NOT answered with the block verdict"
fi

sec "6 dns: allowed query via 127.0.0.2"
if command -v dig >/dev/null 2>&1; then
    allowed=$(dig @127.0.0.2 example.com A +short +time=3 +tries=1 2>&1 | head -2)
else
    allowed=$(nslookup example.com 127.0.0.2 2>&1 | grep -A2 -i answer | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -1)
fi
echo "answer: ${allowed:-<empty>}"
# A blocked verdict (127.0.0.2 per block.rs) means the "allowed" name was
# NOT allowed through — the default filter policy blocks far more than adult
# test names, so an empty/blocked answer is a FAIL, never a pass.
if [ -z "${allowed:-}" ]; then
    flag FAIL "allowed name did NOT resolve"
elif printf '%s' "$allowed" | grep -q '^127\.0\.0\.2$'; then
    flag FAIL "allowed name was blocked (policy may be broader than expected)"
else
    flag ok "allowed name resolves ($allowed)"
fi

sec "7 resolver state"
ls -la /etc/resolv.conf; cat /etc/resolv.conf 2>/dev/null | head -5
grep resolvers /etc/lustless/lustless.toml 2>/dev/null

sec "8 dashboard"
code=$(curl -s -m 3 -o /dev/null -w '%{http_code}' http://127.0.0.1:8760/ 2>&1)
echo "http: ${code:-none}"
if [ "${code:-0}" = "200" ] || [ "${code:-0}" = "401" ] || [ "${code:-0}" = "302" ]; then
    flag ok "dashboard reachable ($code)"
else
    flag FAIL "dashboard unreachable ($code)"
fi

sec "9 journal / log"
if command -v journalctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    journalctl -u lustlessd -n 8 --no-pager 2>&1
elif [ -f /var/log/lustless/lustlessd.log ]; then
    tail -8 /var/log/lustless/lustlessd.log
else
    echo "(no journal/log found)"
fi

sec "10 result"
if [ "$FAIL" -eq 0 ]; then echo "OVERALL: PASS"; else echo "OVERALL: FAIL"; fi
} > "$R" 2>&1

cat "$R"
wget -q -O /dev/null --post-file="$R" "$HOST/?name=verify-$LABEL" \
    && echo "REPORT-SENT" || echo "REPORT-SEND-FAILED (report at $R)"
exit $FAIL
