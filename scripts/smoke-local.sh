#!/bin/bash
# D2 local smoke (CONTRACTS §16): exercise daemon + DNS + classifier + CLI on a
# dev host WITHOUT touching the system resolver. Root not required except for
# the DNS bind (falls back to a high port when unprivileged).
set -u
cd "$(dirname "$0")/.."
PORT="${LUSTLESS_SMOKE_DNS_PORT:-53535}"
STATE="$(mktemp -d)"
trap 'rm -rf "$STATE"; pkill -P $$ 2>/dev/null' EXIT
fail=0
note() { echo "smoke: $*"; }
check() { if [ "$1" = "0" ]; then note "PASS $2"; else note "FAIL $2"; fail=1; fi }

# 1. workspace artifacts exist
for bin in target/debug/lustlessd target/debug/lustlessctl target/debug/lustless-classifier; do
  [ -x "$bin" ]; check $? "binary $bin exists"
done

# 2. config for a hermetic run: high DNS port, no upload, no update, tiny capture cadence
cat > "$STATE/lustless.toml" <<EOF
[daemon]
socket_path = "$STATE/lustlessd.sock"
dashboard_enabled = true
dashboard_port = 18760
state_dir = "$STATE"

[dns]
enabled = true
listen = "127.0.0.1:$PORT"
doh_url = ""
user_resolvers = []
block_page = false
fail_closed_when_signed_out = true

[capture]
enabled = false
spool_dir = "$STATE/spool"

[classifier]
enabled = false
bin = "target/debug/lustless-classifier"
model_dir = "crates/lustless-classifier/models"

[upload]
base_url = ""

[update]
feed_url = ""
EOF

# 3. daemon up
target/debug/lustlessd --config "$STATE/lustless.toml" >"$STATE/daemon.log" 2>&1 &
DAEMON=$!
for _ in $(seq 1 50); do [ -S "$STATE/lustlessd.sock" ] && break; sleep 0.2; done
[ -S "$STATE/lustlessd.sock" ]; check $? "daemon created the IPC socket"

# 4. CLI status/policy round-trips over the socket
target/debug/lustlessctl --config "$STATE/lustless.toml" status >/dev/null 2>&1
check $? "lustlessctl status"
target/debug/lustlessctl --config "$STATE/lustless.toml" policy >/dev/null 2>&1
check $? "lustlessctl policy"
target/debug/lustlessctl --config "$STATE/lustless.toml" flush --deadline 5 >/dev/null 2>&1
check $? "lustlessctl flush (0x69 partial-ok contract)"

# 5. DNS verdicts on the smoke port (no upstreams configured => fail-closed blocks)
ANS=$(dig @127.0.0.1 -p "$PORT" blocked.example.test A +short +time=2 +tries=1 2>/dev/null)
echo "$ANS" | grep -q '127.0.0.2'; check $? "blocked query synthesizes 127.0.0.2 (got: $ANS)"

# 6. outbox picked the query up as a queued dns_activity row
sleep 1
ROW=$(sqlite3 "$STATE/outbox.db" "SELECT domain||'|'||status FROM dns_activity ORDER BY id DESC LIMIT 1" 2>/dev/null)
echo "$ROW" | grep -q 'blocked.example.test|queued'; check $? "dns_activity row lands 'queued' (got: $ROW)"

# 7. dashboard requires a token (401 anonymous)
CODE=$(curl -s -o /dev/null -w '%{http_code}' -m 3 "http://127.0.0.1:18760/status" 2>/dev/null)
[ "$CODE" = "401" ]; check $? "dashboard rejects anonymous (got: $CODE)"

# 8. classifier protocol: hello/result/bye over a synthetic spool transaction
if [ -x target/debug/lustless-classifier ] && [ -f crates/lustless-classifier/models/manifest.json ]; then
  target/debug/lustless-classifier --model crates/lustless-classifier/models \
    --data "$STATE/cl-data" --cache "$STATE/cl-cache" --version smoke --verbose \
    < /dev/null > "$STATE/cl.out" 2>&1
  head -1 "$STATE/cl.out" | grep -q '"type":"hello"'
  check $? "classifier emits hello"
else
  note "SKIP classifier protocol (model bundle not fetched)"
fi

kill $DAEMON 2>/dev/null; wait $DAEMON 2>/dev/null
note "daemon log tail:"; tail -5 "$STATE/daemon.log"
if [ "$fail" = "0" ]; then note "SMOKE-OK"; else note "SMOKE-FAILED"; exit 1; fi
