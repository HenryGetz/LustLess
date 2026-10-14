# LustLess implementation contracts

Normative build contract for the LustLess Linux client (clean-room reimplementation of the
Covenant Eyes "Victory Shield" 10.1.44 **behavior surface**, not its code). Every decision
here maps to `re/findings/91-linux-mapping.md` (design decisions) and the subsystem findings
it cites (evidence). Where this document and a findings doc disagree, the findings doc wins
for *CE facts* and this document wins for *LustLess choices*.

Status vocabulary: **MUST/SHOULD/MAY** per RFC 2119.

---

## 1. Product shape

| item | value |
|---|---|
| product / package | `lustless` |
| version | `0.1.6` (semver; `.deb` version = same) |
| components | `lustlessd` (system daemon), `lustless-classifier` (scoring process, daemon-spawned), `lustless-agent` (per-session tray + dashboard helper), `lustlessctl` (admin/diagnostics CLI) |
| kernel components | none (CE's observable surface is pure user mode — `re/findings/01-dynamic-recon/live-surface.md` §a–§f) |
| target OS | **Zorin OS 17 (Lite and Core), Ubuntu 24.04, Xubuntu 24.04, Lubuntu 24.04** and generic systemd Linux desktops. Built against glibc 2.35 (ubuntu:22.04 build container) so one `.deb` runs on both 22.04-base (Zorin 17) and 24.04-base systems. Desktop-shell reality to respect: GNOME (Ubuntu/Zorin Core — SNI via AppIndicator extension, on by default in Ubuntu), Xfce (Xubuntu/Zorin Lite — SNI via `xfce4-indicator-plugin`), LXQt (Lubuntu — no SNI host; agent MUST degrade gracefully, §13) |

## 2. Toolchain and build

- **Language: Rust** (edition 2021), single Cargo workspace at repo root.
- **Binaries MUST build against glibc 2.35**: all build/packaging runs inside an
  `ubuntu:22.04` container (`packaging/build-deb.sh`), never against the host glibc.
  The host (Ubuntu 24.04, rustc 1.95) is used for fast edit/test loops only.
- Crates SHOULD prefer these dependency families (pin exact versions in `Cargo.toml`):
  `serde`/`serde_json`/`toml`, `rusqlite` (bundled SQLite) for the outbox,
  `rusqlite` + `libsqlcipher-dev` for the settings DB, `tokio`, `axum` (dashboard),
  `reqwest`+`rustls` (DoH + REST), `hickory-proto` (DNS wire codec), `nix`/`zbus`
  (logind, D-Bus), `gtk` 0.18 + `libappindicator`/`ayatana` (tray), `ort` (ONNX scoring),
  `sha2`, `rand`, `ed25519-dalek` (update signatures), `tracing` + `tracing-journald`.
- Formatting/gates run **once per phase** by the orchestrator across the union of changed
  files (`cargo fmt`, `cargo clippy -- -D warnings`, `cargo test`); component tasks edit
  only.

## 3. Crate graph and ownership

```
lustless-core      (lib)  config, wire codec, records/envelope, outbox DB, settings DB,
                          metrics, clock anchor, policy snapshot, ids
lustless-dns       (lib)  DNS forwarder engine: dual DoH resolution, verdicts, block
                          synthesis, per-process attribution, health machine
lustless-capture   (lib)  capture backends (X11 XShm / Wayland portal), screenstate spool
                          writer, manifest (schema 3.0.0) types, jittered scheduler
lustless-net       (lib)  network services: REST uploader (outbox state machine), updater
                          (feed + ed25519 verify), dashboard (axum) — driven by the daemon
                          through `PolicyProvider`/`Notifier` traits
lustlessd          (bin)  IPC server, session/policy state machine, capture loop +
                          classifier supervision, DNS lifecycle, drives lustless-net
                          (uses core + dns + capture + net)
lustless-classifier(bin)  spool consumer, clean-room scoring engine, bundle manager
                          (uses core + capture for manifest/spool types)
lustless-agent     (bin)  GTK tray only: status icon + menu, opens the daemon-hosted
                          dashboard via `xdg-open` (uses core)
lustlessctl        (bin)  CLI (uses core)
```

`lustless-core` is the shared contract surface; its public API (types and function
signatures) is fixed by §5–§9 below and MUST NOT drift without updating this file.

## 4. Filesystem and process layout

| path | owner | mode | content |
|---|---|---|---|
| `/usr/bin/lustless{d,-classifier,-agent,ctl}` | root | 0755 | binaries |
| `/usr/share/lustless/models/` | root | 0755 | model bundle: `manifest.json` + content-addressed artifacts |
| `/usr/share/lustless/dashboard/` | root | 0755 | embedded-static fallback assets (dashboard is embedded; dir MAY hold extras) |
| `/etc/lustless/lustless.toml` | root | 0644 | system config (§10) |
| `/var/lib/lustless/` | root | 0700 | daemon state root |
| `/var/lib/lustless/outbox.db` | root | 0600 | plain SQLite outbox (§6) |
| `/var/lib/lustless/<uid>/settings.db` | root | 0700 | SQLCipher per-user settings (§6) |
| `/var/lib/lustless/<uid>/settings.key` | root | 0600 | per-install settings-DB key (generated on first use) |
| `/var/lib/lustless/previous-config/` | root | 0700 | uninstall/upgrade backup of state |
| `/var/lib/lustless/spool/<uid>/pdl/<ts>/` | root | 0700 | screenstate transactions (§7) |
| `/var/log/lustless/classifier/<pid>.log` | root | 0600 | classifier logs (CE `<PID>.log` shape) |
| `/run/lustless/lustlessd.sock` | root | 0666 | IPC UDS (auth = `SO_PEERCRED`, §5) |
| `/usr/lib/systemd/system/lustlessd.service` | root | 0644 | system unit |
| `/usr/lib/systemd/user/lustless-agent.service` | root | 0644 | user unit |
| `/usr/share/polkit-1/actions/org.lustless.policy` | root | 0644 | polkit actions (§11) |

Processes: `lustlessd` (root, `lustlessd.service`), `lustless-classifier` (root child of
`lustlessd`, one per filtering/screen-accountability user session),
`lustless-agent` (user session, `lustless-agent.service`), plus on-demand `lustlessctl`.

## 5. IPC contract (agent/CLI ↔ daemon)

- Transport: one Unix stream socket `/run/lustless/lustlessd.sock`, mode 0666.
  **Every** accepted connection MUST `SO_PEERCRED` the peer (uid/pid/gid) and derive an
  authorization scope before serving any frame. This replaces CE's unauthenticated
  `127.0.0.1:48867` (`re/findings/13-service-ipc/service-ipc.md` §1) — no credential is
  ever served to an unauthenticated peer.
- Framing: `u8 code | u32 LE length | payload` where payload is UTF-8 JSON
  (`serde_json::Value`). Max frame 64 KiB. Unknown codes: log-and-ignore (CE behavior,
  `service-ipc.md` §2).
- Wire vocabulary — CE codes kept verbatim (`re/findings/91-linux-mapping.md` §4;
  `service-ipc.md` §2), LustLess extensions in the `0x60+` block:

| code | name | dir | payload | auth scope |
|---|---|---|---|---|
| 0x02 | `NOTIFICATION` | d→c | `{"level","message","progress"?,…}` | connection |
| 0x43 | `COLLECT_DEBUG_LOGS` | c→d | `{}` | root or self |
| 0x4c | `USER_LOGOUT` | c→d | `{}` | self |
| 0x4d | `SEND_METRICS` | c→d | `{}` | root or self |
| 0x51 | `QUIT` | c→d | `{}` | **root only** |
| 0x52 | `SET_CLIENT_CONFIG` | c→d | `{"key","value"}` | **root only** (was `SET_WINDOWS_REGISTRY`; same code, registry semantics die with Windows) |
| 0x53 | `USER_SETTINGS_CHANGE` | c→d | `{fields}` | self |
| 0x54 | `SEND_TELEMETRY` | c→d | `{}` | root or self |
| 0x55 | `POLL` | c→d | empty | connection |
| 0x60 | `POLICY_GET` | c→d | `{}` → `PolicySnapshot` (§9) | self |
| 0x61 | `STATUS_GET` | c→d | `{}` → daemon status | self |
| 0x62 | `DNS_ACTIVITY_QUERY` | c→d | `{"limit","before"?}` → rows | self (own rows) / root (all) |
| 0x63 | `FILTER_SET_LEVEL` | c→d | `{"level"}` | self |
| 0x64 | `FILTER_SET_OVERRIDES` | c→d | `{"domain","verdict":"allow"\|"block"\|"na"}` | self |
| 0x65 | `SIGN_IN` | c→d | `{"username","password"}` → `{"token",…}` | connection (password never stored) |
| 0x66 | `SIGN_OUT` | c→d | `{}` | self |
| 0x67 | `UPDATE_CHECK` | c→d | `{}` → recommendation | self |
| 0x68 | `BREAK_GLASS` | c→d | `{"reason"}` | **root only**; MUST be preceded by polkit auth `org.lustless.break-glass` and journald audit line |
| 0x69 | `FLUSH_OUTBOX` | c→d | `{"deadline_sec"?}` → `{"flushed":N}` | **root only** (used by `lustlessctl flush` in `prerm` §11: drains activity+metrics+telemetry outbox within the deadline, partial flush still returns ok) |

- Replies reuse the request code with `{"ok":true,…}` or `{"ok":false,"error":{…}}`.
  `NOTIFICATION` carries async progress ("Diagnostics are being collected…",
  "We've finished collecting diagnostics" — CE vocabulary,
  `service-ipc.md` §2) with bounded retries (2×6×100 ms).
- `POLL` (0x55) is the empty-poll sentinel; it drains queued notifications or returns an
  empty 0x55 frame.
- Policy: user-scope connections see only their own uid's state; mutations to system config
  require root. Stale-peer reset is handled by connection lifecycle (CE's `QUIT`/`IgnoreMe`
  queue-priming trick is unnecessary with per-connection sockets).

## 6. State stores

### 6.1 Outbox DB — `ce-file` schema kept verbatim

Normative SQL: `re/findings/02-artifacts/local-db.md` §Evidence ("Full schema (verbatim)").
Tables: `install_metadata`, `logins`, `metrics`, `circumventions`, `switch_users`,
`dns_activity`, plus indexes `circumventions_matching (username, status, interruption_type)`
and `dns_activity_matching (username, status, process_name, datetime_created)`. WAL mode,
0600, daemon-owned. Timestamps: ISO-8601 UTC (`…Z`) + separate `timezone_offset` string.

- Row lifecycle (evidence: `filter-enforcement.md` §3 INSERT literal — rows are born
  `status='queued'` with `status_changed_at/created_at = DATETIME('now')`):
  `insert(queued) → claim(sending) → ack(sent)`; stale-`sending` rows (claim older than
  5 min) are reaped back to `queued`. A min-age gate (30 s) prevents claiming rows newer
  than one upload cycle. Invalid records are dropped, never failing a batch
  (`upload-protocol.md` §4).
- `metrics` lifecycle: born `collecting`, `bucket_size=3600`, `bucket_current` counts
  seconds accumulated in the open bucket (3600 = complete); rolls to `queued` when the
  bucket ages out. `bucket_id`/`tags`/`fields` are JSON with
  `INDEXED/CARDINAL/INCIDENTAL` aggregation annotations (shape verbatim from
  `local-db.md` sample rows).
- LustLess addition: table `telemetry (id, client_type, device_name, name, value,
  utc_timestamp, status, status_changed_at, created_at)` — CE's `telemetry` table columns
  are unrecovered; this is the LustLess shape (documented deviation).

### 6.2 Settings DB — SQLCipher per user

Table set kept from `ce-user-file` (`91-linux-mapping.md` §5; tables from
`filter-enforcement.md` verdict c): `user_info`, `user_dns_filter`
(`over_https_url`, `level`, `ipv4_primary/secondary`, `ipv6_primary/secondary`),
`global_domain_overrides`, `custom_domain_overrides` (tri-state allow/block/na),
`api_credentials`. **Deviation (documented):** the plaintext `password` column is NOT
reproduced; `api_credentials` stores `device_token`/`refresh_token` only.

Crypto: SQLCipher 4 (per-page AES + HMAC, PBKDF2-HMAC-SHA512) is preserved in *shape*;
key management is replaced. Key chain: per-install keyfile `settings.key` (0600, generated
by the daemon on first use) is the shipping default — an honest improvement over CE's
hardcoded XOR-obfuscated passphrase (`service-ipc.md` §5) — with optional libsecret/TPM
sealing left as a documented extension point. Lazy `ALTER TABLE` migrations like CE
(`filter-enforcement.md` §4).

### 6.3 Screenstate spool — file transaction verbatim

Producer (daemon capture loop) writes `/var/lib/lustless/spool/<uid>/pdl/<ts>/` containing
`im<N>.png` per monitor, `manifest.json`, and an atomic `ready` marker
(write-temp-then-rename); consumer (classifier) `inotify`-wakes on the marker, consumes,
writes its result, and the startup folder cleanup removes orphaned transactions
(`capture-pipeline.md` §2; `91-linux-mapping.md` §1). Tamper signal: removal/rename of a
transaction folder logs `Circumvention: PDL transaction file removed|renamed` and records
a `circumventions` row (CE behavior, `capture-pipeline.md` §2/§3).

Manifest keys **verbatim** (screenstate schema 3.0.0, `capture-pipeline.md` §2):
`schemaVersion`, `urlSafeUsername`, `datetime_created`, `local_utc_offset`,
`images[{filename, screenRect}]`, `monitors`,
`apps[{name, window_title, appRect, doNotScore}]`, `clientPayload.device`.

## 7. Capture + classifier contract

- CLI contract (`classifier-data.md` "Launch contract"): `lustless-classifier
  --model=<dir> --data=<uid-state-dir> --cache=<uid-cache-dir> --version=<ver> [--verbose]`.
  Daemon spawns + supervises with CE's 5 s relaunch poll
  (`capture-pipeline.md` §4 `LaunchAndMonitorScreenMonitoring`).
- Cadence: `sleep ~ U[(1−v)·I, (1+v)·I]` from `capture.interval_sec` / `variance_pct`;
  fixed short retries (5 s while classifier is down, 40 s default, 60 s worst case).
  Gate on logind `LockedHint`/`Active`, screensaver state, classifier alive; **skip**
  capture entirely while locked/screensaver-active (improvement on CE's
  `saver_while_capture` telemetry, `91-linux-mapping.md` §1).
- Backends: `auto` = X11 (`XShmGetImage` per RandR output) when `XDG_SESSION_TYPE=x11`,
  Wayland portal ScreenCast (PipeWire) otherwise. Restricted/protected windows are
  captured and flagged (`doNotScore: true` + `circumventions` row), never aborted
  (`capture-pipeline.md` §3).
- Classifier → daemon channel: JSON Lines on the child's stdout pipe; every message
  `{"type":…, "ts":…, …}`. Message types: `hello {version, model_ids}`, `result
  {batch_ts, windows[{app, title, rect, score, flagged}], summary{flagged, top_score,
  scored_windows}, analyzed_count}`, `log {level, message}`, `bye {reason}`. (CE's
  `cs/ht/pp/dd/re4*` vocabulary is documented in
  `re/findings/10-classifier/classifier-internals-classifier.md`; LustLess keeps the
  *semantics* — result + control messages — over a debuggable channel.)
- Scoring model: **Covenant Eyes' production classifier** (upstream authorization —
  clean-room requirement waived by CE). The
  `b1`/`b2`/`b3` shards are the `ensem_3cls-6.1.2` scoring ensemble
  (`bundle-formats.md` §2), `sw` = Snowball NLP word/feature data for title scoring,
  `mn` = bundle manifest. Ship the original `.dat.enc` artifacts byte-identical and
  decrypt at load time with the documented scheme (`bundle-formats.md` §1: AES-CBC +
  PKCS#7, no IV prefix/MAC; context-0 key derivation + fixed IV are recovered and
  verified against every sample). Bundle layout stays CONTRACTS `manifest.json` +
  content-addressed `<sha256>-<role>.<ext>` — roles `{scorer, labels, calibration}`
  map to the CE shards via the manifest; startup logs the loaded artifact ids.
  CE's exact scoring semantics (per-window crops, `doNotScore` handling,
  scoreImage/scoreWindowTitle flow) are implemented natively in Rust, derived from
  the recovered bundle data and the classifier-internals findings.
- Screen-derived data NEVER leaves the device (ratified invariant). Note the evidence
  nuance found by the classifier-internals passes (`re/findings/10-classifier/
  classifier-internals-{classifier,client}.md`): CE's comm-service outbox is records-only
  (`upload-protocol.md` §6 stands, scoped to that uploader), but CE's classifier authors
  HTTP requests as `ht.dat` that `VictoryShield.exe`'s libcurl executes — its score
  batches DO reach `api.cvnt.net` over that request-proxy channel. LustLess is therefore
  **deliberately stricter than CE**: no images, no scores, no crops on ANY channel. The
  only screen-adjacent uploaded evidence is CE's existing `circumventionRecord` (app +
  window title of flagged/restricted windows), and it is a first-class record type with an
  admin toggle `upload.circumvention_records` (default **true**, matching CE).
- UI counter semantics: CE's "N screenshots analyzed in the last 60 minutes" tray label
  counts *captures* (`screenshot_telemetry` rows), not analyses. LustLess reports real
  analysis counts from `result` messages (`analyzed_count`) — documented improvement.

## 8. DNS engine contract (`lustless-dns`)

- Listener `udp/tcp 127.0.0.2:53` (config `dns.listen`); `postinst` redirects system DNS
  to it (systemd-resolved/NetworkManager drop-in). Config names MUST match their effect
  (fix CE's inverted `DnsProxyDisable`, `filter-enforcement.md` §5).
- Dual resolution per query (CE's engine, `filter-enforcement.md` "What it does"): DoH
  RFC 8484 GET `?dns=<b64url-wire>` to `dns.doh_url` (filter path) **and** the user's
  resolvers (user path); per-query verdict picks the response endpoint. Connection pool ≤5
  per endpoint, least-loaded dispatch. `X-CB-Location`-style response-header tag recorded
  into `resolution_datacenter`.
- Verdict vocabulary — CE's 15 `resolution_type` codes kept verbatim as the
  `dns_activity.resolution_type` schema (`filter-enforcement.md` verdict b):

| code | value | trigger |
|---|---|---|
| 0xb | `BlockedCustom` | custom-override block |
| 10 | `BlockedGlobal` | global-override block |
| 9 | `BlockedFilter` | upstream filter block (RPZ marker e.g. `cleanbrowsing.rpz.noc.org`) |
| 5 / 4 | `UnrestrictedAllowCustom` / `UnrestrictedAllowGlobal` | explicit allow override |
| 1 / 6 | `UnrestrictedFiltered` / `UnrestrictedUnknown` | clean filter answer / flag path |
| 8 | `SafeSearchEnforced` | safe-search domain-list hit |
| 2 / 3 | `UnrestrictedUnFiltered` / `UnrestrictedAlwaysAllowable` | no filter path / always-allow predicate |
| 7 | `UnrestrictedOutage` | filter-path outage state |
| 12–15 | `TimedOut` / `TimedOutFilter` / `TimedOutSystem` / `Failed` | upstream failure paths |

- Block answers (CE `overrideForBlocking` mechanics,
  `filter-enforcement.md` verdict b): zero the answer/authority/additional sections of the
  upstream reply, append synthesized A/AAAA (`127.0.0.2` / `::1`) + CNAME
  `blocked.lustless.local`, so the daemon's loopback HTTP block page is reachable. The
  `blocked.lustless.local` vhost serves a static block page over `127.0.0.2:80`.
- Attribution: `dns_activity.process_id/process_name` resolved per query from the UDP
  socket owner (`SOCK_DIAG`/`inet_diag` netlink + `/proc/*/fd`); `unknown` is the
  tolerated default (CE's racy UDP-table lookup is the precedent,
  `filter-enforcement.md` verdict a).
- Row write: INSERT with `status='queued'` (shape verbatim §6.1); dashboard read-back is
  the `ViewDnsActivityHandler` query (LIMIT 500 DESC).
- Health machine (CE's, `filter-enforcement.md` §7): per-lookup counters
  (`client_cleanbrowsing_success`/`client_cleanbrowsing_problem` metrics), outage state →
  periodic `error-recovery` test packets → recovery timer. Failure feeds the local
  health state and the polkit break-glass path (§5, 0x68) — a **working** escape, unlike
  CE's dead "Filter guardian" dialog (`filter-surface.md` §6).
- Lifecycle: forwarder active while ≥1 signed-in user needs filtering (ref-count, CE's
  `checkForProxySwitch`, `filter-enforcement.md` §5); `signed out ⇒ web blocked` is one
  fail-closed policy flag owned by the forwarder.

## 9. Policy snapshot

Read-only struct served over IPC (0x60) and to the dashboard — replaces CE's
`CE_SPYMapObj` shared-memory block (`ui-architecture.md` §4b):

```
PolicySnapshot { username, signed_in, state: LOGGED_OUT|LOGGING_IN|LOGGED_IN|SWITCHING_USER,
  has_accountability, has_filtering, has_screen_accountability, has_url_accountability,
  has_dns_filtering, has_url_filtering, can_override, is_panicked,
  filter: { level, fail_closed, health }, capture: { active, backend, last_screenstate_at } }
```

## 9.1 System configuration — `/etc/lustless/lustless.toml`

TOML, 0644 root-owned. Every key is documented in the shipped sample config; names MUST
match their effect (no inverted flags — CE's `DnsProxyDisable` lesson,
`filter-enforcement.md` §5). Unknown keys are ignored with a warning; parse failures fall
back to these defaults and log `config parse failed: <err>`.

```toml
[daemon]
socket_path = "/run/lustless/lustlessd.sock"
dashboard_enabled = true
dashboard_port = 8760
state_dir = "/var/lib/lustless"

[dns]
enabled = true
listen = "127.0.0.2:53"
doh_url = "https://dns.cleanbrowsing.org/doh/adult-filter"   # filter path (RFC 8484)
user_resolvers = ["system"]        # "system" = read current upstream resolvers
block_page = true
block_page_host = "blocked.lustless.local"
fail_closed_when_signed_out = true # "signed out ⇒ web blocked" product semantic
pool_size = 5                      # DoH connections per endpoint

[capture]
enabled = true
backend = "auto"                   # auto | x11 | wayland
interval_sec = 30
variance_pct = 20                  # jitter ±%
spool_dir = "/var/lib/lustless/spool"

[classifier]
enabled = true
bin = "/usr/bin/lustless-classifier"
model_dir = "/usr/share/lustless/models"

[upload]
base_url = "https://api.lustless.invalid"   # deployment-specific
batch_size = 100
heartbeat_sec = 600                # local bookkeeping tick (CE 600 s)
retry_sec = 60
circumvention_records = true       # upload CE's circumventionRecord vocabulary
logs_store = false                 # support event log behind debug toggle

[update]
feed_url = ""                      # empty = updater disabled
pubkey = ""                        # ed25519 (base64) — REQUIRED when feed_url set
check_sec = 86400
disable_silent_upgrade = false
host_allowlist = ["packages.lustless.invalid"]
```

## 10. Uploader contract

Topology verbatim from CE (`upload-protocol.md` §3–§5; `91-linux-mapping.md` §6): one
uploader in `lustlessd`, one outbox, batch **100** rows/request, per-user batching for the
activity log, claim/reaper state machine (§6.1), server-requested throttling persisted as
`upload.resume_not_before`, a purely local bookkeeping heartbeat tick (600 s steady / 60 s
retry — distinct from upload stamps), and a `(server_time, local_ticks)` clock anchor
refreshed hourly from `status/time` (system-time fallback). Fresh TCP connect per exchange
(CE rotates ~301 s), self-metrics `client_api_success`/`client_api_problem` with
host/route/status tags around every HTTP call.

Routes (path shapes kept):

| route | method | body |
|---|---|---|
| `/v2/user/{username}/report/activity_log.json` | POST | `{"records":[…]}` typed activity records |
| `/v1/metrics` | POST | JSON array of metric records |
| `/v1/logs/store` | POST | support event log records (debug toggle) |
| `/v1/telemetry/store` | POST | telemetry records |
| `/v1/status/time` | GET | clock anchor |
| `/v1/status/ping` | GET | liveness pre-flight |
| `/v1/desktop_client_update` | POST | update check (§12) |

Activity record vocabulary (five keys, exhaustive in CE —
`upload-protocol.md` §5): `webActivityRecord` (from `dns_activity`),
`loginActivityRecord` (from `logins`), `circumventionRecord` (from `circumventions`),
`switchUserActivityRecord` (from `switch_users`), `installActivityRecord` (install
report). Envelope per record:
`{"<recordType>": {"client": {"architecture","platform":"Linux","platformVersion","version"},
"timestamp": …}}` with shared key `utc_datetime_created`.

Auth: per-device credentials as revocable Bearer tokens (`device_token` in `api_credentials`);
no account password is ever stored (`91-linux-mapping.md` §6). TLS with normal CA
validation.

## 11. Watchdog, tamper, uninstall

- `lustlessd.service`: `Restart=always`, `RestartSec=1`,
  `StartLimitIntervalSec=0` (never give up), `After=network-online.target`,
  `WantedBy=multi-user.target`, and
  `ExecStartPost=lustless-maintainer dns-redirect`.
  `lustless-agent.service` (user): `WantedBy=graphical-session.target`.
  The daemon is the machine's resolver — system DNS points at 127.0.0.2 — so a
  daemon left dead is a machine with no name resolution at all. It is therefore
  restarted without limit; the *filtering* is what fails closed (a signed-out
  or degraded filter answers "blocked"), never the resolver.
  Alpine/OpenRC: `supervise-daemon` with `respawn_delay=1`, `respawn_max=0`
  (unlimited).
- DNS redirect discipline (`lustless-maintainer`): the redirect is applied
  only after the forwarder *answers* on 127.0.0.2:53 (probed with
  `dig`/`nslookup`, else a listening-socket check). If it does not answer, the
  installer leaves system DNS untouched and says so; the unit's
  `ExecStartPost` re-applies the redirect on every daemon start, so a machine
  installed while the filter was broken cannot stay unfiltered once it runs.
  `remove`/`purge` restore the original resolver.
- Classifier crash budget (CE verbatim, `watchdog.md` §5/§7;
  `crash-reporting.md` §5): per-uid `last_crash_at` + 10-minute no-relaunch
  suppress window + total counter; >3 restarts ⇒ stop auto-restarting *the
  classifier*, escalate to a human-visible notification. This is separate from
  the daemon's own restart policy above.
- Tamper protection = package ownership + ONE documented, polkit-gated, audited action
  `org.lustless.disable-protection` (also used by uninstall). No hidden disarm exports, no
  process-level anti-kill (`91-linux-mapping.md` §7).
- Uninstall order (CE's, `updater.md` §6): flush pending uploads (bounded) → stop units →
  reverse config (DNS redirect, browser policies, polkit) → move state to
  `PreviousConfiguration` backup → remove units. Uninstall MUST leave the system's DNS
  configuration exactly as found.

## 12. Updater

Feed JSON (decision shape from CE's `getClientUpdate`, `updater.md` §2):
`{"recommendation":"now"|"later"|"none","critical":bool,"version","url","sig"}`; the
recommendation is the whole policy — no client-side version comparison. Packages are
`.deb`s from our signed apt repo; `lustlessd` **MUST verify an ed25519 signature** (pubkey
pinned in `/etc/lustless/lustless.toml`) over the payload before invoking any package
tooling (CE ships DSA support but never configures a key — `updater.md` §5 — that lesson
is the requirement). Download-URL host allowlist as a second layer. Check cadence 86 400 s;
unattended apply is `critical`-only behind `update.disable_silent_upgrade` (24 h grace).
Upgrade transaction order = §11 uninstall order, ending in a version-encoded state dir
(`…-v001.000.001`-style) for rollback. No forced reboots.

## 13. Dashboard + agent

- Dashboard: embedded `axum` HTTP server on `127.0.0.1:8760` (config
  `daemon.dashboard_port`), **token-authenticated** (bearer token issued over IPC 0x65 /
  appended by the agent when opening the browser). Pages: status, sign-in/out, settings
  (filter level, overrides, toggles), DNS-activity log (the CE `ViewDnsActivityHandler`
  query), diagnostics. There is NO keys route (CE's
  `/local/user/:u:/keys.:d:` exposure is the anti-pattern — `service-ipc.md` §1).
- `lustless-agent`: GTK3 + libayatana-appindicator tray — status icon color, menu
  (Sign in/out, Switch user, Open dashboard, View activity, Refresh settings, Collect
  diagnostics, Check for updates — CE's menu vocabulary, `ui-architecture.md` §1);
  single-instance via `GApplication`; opens URLs with `xdg-open` (CE embeds no browser
  either, `ui-architecture.md` §3); stores its session token in the user keyring via
  libsecret when available. UI never holds long-lived secrets; `lustlessd` holds the
  session.
- Session gating: logind D-Bus `Lock`/`Unlock`/`SessionNew`/`SessionRemoved` drives
  capture policy (WTS equivalent, `signin-and-settings.md` §4).

## 14. Logging and metrics

- journald via `tracing-journald`; structured fields carry CE's tag taxonomy
  (`Classifier`, `pdl-edi`, `bundleManager` → our `classifier`, `capture`, `bundles`).
  Classifier keeps `<pid>.log` files for support bundles.
- Metric names kept from CE's taxonomy (`local-db.md` sample rows): `client_startup`,
  `client_api_success`, `client_api_problem`, `client_network`, `client_screenshot`,
  `client_cleanbrowsing_success`, `client_cleanbrowsing_problem`, `client_crash`,
  `collect_diagnostics_in_progress`.

## 15. Packaging (`packaging/`)

- `packaging/debian/` → single binary package `lustless`, architecture `amd64`, Depends:
  `libssl3, libgtk-3-0, libayatana-appindicator3-1, systemd, policykit-1, dbus,
  ca-certificates` (verified against the shipped binaries' `ldd` output — SQLCipher is
  compiled in via rusqlite `bundled-sqlcipher`, so no system SQLCipher; `libsecret` and
  `sqlite3` are Suggests, not links).
- `postinst`: create `lustless` state dir + `lustless` system user NOT needed (daemon runs
  root) → instead: `adduser`-free; enable+start `lustlessd.service`; install DNS redirect
  drop-in (resolved/NetworkManager) pointing system DNS at `127.0.0.2`; install browser
  DoH-lockdown managed policies — Chrome/Edge/Brave `DnsOverHttpsMode=off`
  (+ `BuiltInDnsClientEnabled=0`), Firefox `policies.json`
  `DNSOverHTTPS{Enabled:false,Locked:true}` (`browser-integration.md` §2 Linux notes);
  install polkit action; log `installActivityRecord`.
- `prerm`: bounded flush → stop units → reverse DNS redirect + browser policies.
  `postrm purge`: move `/var/lib/lustless` to `PreviousConfiguration` backup semantics and
  remove; verify DNS config restored.
- Browser policy paths (Linux): `/etc/opt/chrome/policies/managed/lustless.json`,
  `/etc/chromium/policies/managed/lustless.json`,
  `/etc/microsoft-edge/policies/managed/lustless.json` (Edge may be absent — file is
  inert), `/usr/lib/firefox/policies.json` (merge-safe if file exists — do not clobber an
  admin's file; document).

## 16. Testing contract

- Each crate: unit tests for its contract surface (wire codec round-trips, outbox state
  machine incl. claim/reaper edge cases, verdict mapping table, manifest schema
  round-trip, config parsing). Deterministic, isolated, no network (DoH/uploader tests use
  local mock servers on 127.0.0.1).
- Integration smoke (`scripts/smoke-local.sh`, phase D): run daemon + DNS forwarder on a
  non-privileged port + classifier against a synthetic spool; assert: query verdicts,
  `dns_activity` rows land `queued`, result messages parse, policy snapshot sane.
- Zorin testbed (phase E): install `.deb` on the live Zorin VM, verify units, a real
  blocked/allowed DNS query, dashboard reachability, tray presence, and full uninstall
  reversibility.
