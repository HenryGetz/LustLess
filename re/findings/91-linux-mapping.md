# 91-linux-mapping — LustLess Linux reimplementation decisions (Zorin OS / generic Linux desktop)

This document records **decisions only**: for every Victory Shield v10.1.44 subsystem, what
LustLess builds, adapts, or skips, on which Linux mechanism, and which observed CE behavior
that decision maps from. The system description of the CE client is in
`re/findings/90-architecture.md`; mechanism detail lives in the subsystem findings docs cited
per row (`findings/…` below = `re/findings/…`). Nothing here re-proves a mechanism — it maps
one to a Linux equivalent.

Decision vocabulary:

- **Build** — no portable counterpart exists (Windows-only mechanism); implement fresh on Linux.
- **Adapt** — keep CE's design/shape, swap the platform mechanism.
- **Skip** — CE behavior deliberately not reproduced (rationale in the notes).

Synthesis-level claims that no single findings doc states carried inference tags; each now carries
its verdict inline (`[VERIFIED: <cite>]`, `[INFERENCE — unresolved: <what is missing>]`,
`⚠ evidence correction`) — full log in `## Inference audit log` at the end.

## Decision summary

| # | Subsystem | Decision | Linux mechanism | CE evidence (findings cite) |
|---|---|---|---|---|
| 1 | Screen capture + screenstate pipeline | **Build** backend, **Adapt** pipeline shape | X11: `XShmGetImage` per RandR output; Wayland: `xdg-desktop-portal` ScreenCast → PipeWire stream. File-transaction handoff kept verbatim: per-capture spool dir + `imN.png` + manifest + atomic ready marker, consumer woken via inotify | `findings/10-classifier/capture-pipeline.md` §1–§3 (scheduler, file-transaction verdict, restrictions); `findings/02-artifacts/classifier-data.md` (per-SID `data/pdl/` tree) |
| 2 | Classifier (on-device ML) | **Build** engine, **Adapt** bundle/manifest mechanics | On-device scoring (never service-side). Separate supervised classifier process with CE's CLI contract (`--model/--data/--cache/--version`); models as content-addressed `<id>-<role>` artifacts; screenstate manifest schema 3.0.0 reused verbatim | `findings/10-classifier/capture-pipeline.md` §2/§4 (handoff + model-data negative); `findings/02-artifacts/enc-data.md` (role taxonomy, content-id prefixes); `findings/02-artifacts/classifier-data.md` (launch contract); `findings/16-updater/upload-protocol.md` §6 (no scores/images ever uploaded) |
| 3 | DNS/URL filtering | **Build** forwarder, **Adapt** policies + lifecycle | Small DNS forwarder on `127.0.0.2:53` (systemd-resolved/NetworkManager redirect system DNS to it); dual resolution — DoH (RFC 8484) to a per-user CleanBrowsing-family endpoint + user's own resolvers; per-query verdict; RPZ-style synthetic block answers (`blocked.<domain>` CNAME); browser DoH-lockdown policies via managed policy files; ref-count activation per signed-in filtering user | `findings/12-network/filter-enforcement.md` (verdicts a–c, §1–§2, §5, §7); `findings/12-network/filter-surface.md` §1/§3/§6/§7; `findings/12-network/browser-integration.md` §2 + Linux notes |
| 4 | Local IPC + dashboard | **Adapt** | One Unix domain socket per user session with `SO_PEERCRED` peer auth (replaces unauthenticated TCP `127.0.0.1:48867`); keep the 1-byte-code + payload wire format and the full code vocabulary; local web dashboard optional and, if shipped, authenticated | `findings/13-service-ipc/service-ipc.md` §1 (10 routes, **no auth**, key-exposure route), §2 (queue codes, back-channel); `findings/02-artifacts/event-queue.md` (queue geometry); `findings/15-ui/ui-architecture.md` §4 |
| 5 | State stores | **Adapt** | `ce-file` outbox pattern kept verbatim (schema shape + `queued→sending→sent` state machine) in a plain SQLite DB; `ce-user-file` → SQLCipher-encrypted per-user settings DB whose key is held by the OS (Secret Service/kernel keyring or TPM-sealed per-install key), never a hardcoded passphrase | `findings/02-artifacts/local-db.md` (schema, outbox triple, indexes, metric buckets); `findings/13-service-ipc/service-ipc.md` §4–§5 (writers, SQLCipher verdict + hardcoded key); `findings/02-artifacts/user-file.md` (container shape) |
| 6 | Upload protocol | **Adapt** | One daemon, one outbox, 7-route-equivalent REST (activity log, metrics, logs, telemetry, status/time, status/ping, client update); **activity-records-only privacy model kept** (no image bytes ever); auth = per-device key/secret presented as revocable Bearer tokens — no account password stored | `findings/16-updater/upload-protocol.md` §2–§6 (auth, route catalog, outbox lifecycle, record types, no-images verdict) |
| 7 | Watchdog / persistence / anti-tamper | **Adapt** | systemd system unit (`Restart=`, `StartLimit*`, `After=`) + per-session user services (logind event-driven); crash back-off and restart budget kept; tamper-protection = package-manager ownership + a **documented, audited polkit toggle** — not hidden `disable*Protection` exports | `findings/14-watchdog/watchdog.md` §2–§5/§7–§8/§10/§12; `findings/14-watchdog/protectors.md` (protect/repair machinery + exports); `findings/01-dynamic-recon/live-surface.md` §a–§d |
| 8 | UI | **Build** shell, **Adapt** flows | Thin GTK/libayatana tray app (status, menu, notifications) + browser-opened local dashboard carrying sign-in/settings/activity; daemon holds the session (UI never holds long-lived secrets); logind D-Bus signals gate capture; XAML/WinRT not ported | `findings/15-ui/ui-architecture.md` §1–§4 (tray, XAML island, no embedded browser, IPC); `findings/15-ui/signin-and-settings.md` §3–§5 (credential path, WTS gating, logout semantics) |
| 9 | Updater | **Adapt** channel, **Build** signing | Own JSON feed returning `recommendation: now\|later\|none` + `critical` + download URL; packages delivered via a signed apt repository; client **verifies an ed25519/minisign signature** on every update payload; 24 h check cadence; short disable-silent-upgrade grace flag | `findings/16-updater/updater.md` §2 (`getClientUpdate`), §4 (silent-upgrade gating), §5 (DSA machinery shipped but never enabled) |
| 10 | Crash reporting + diagnostics | **Adapt** | coredump/`coredumpctl` or Crashpad-style minidump + zipped logs + **sanitized** state summary (never the activity DBs); restart helper with crash counters and ≤3-restart escalation; `lustlessctl collect-debug` equivalent spawned by the daemon over IPC with progress notifications | `findings/16-updater/crash-reporting.md` §3–§5 (attachments incl. the DB-upload problem, counters, test hooks); `findings/13-service-ipc/service-ipc.md` §2 (`0x43 COLLECT_DEBUG_LOGS` handler); `findings/14-watchdog/watchdog.md` §5/§7 |
| 11 | Packaging (Zorin OS) | **Build** | `.deb` + systemd system/user units + `postinst`/`prerm` (enable units, DNS redirect config, browser policy files, polkit rule); **no kernel modules** — CE's observable surface is pure user mode | `findings/01-dynamic-recon/live-surface.md` §a–§c verdicts + §d (persistence shape); `re/INVENTORY.md` §3 |

Decisions deferred to pending evidence are listed in `## Open items` at the end.

Component names used below: `lustlessd` (system daemon — comm-service + enforcement
equivalent), `lustless-agent` (per-session tray/UI helper), `lustless-classifier` (scoring
process), `lustlessctl` (admin/diagnostics CLI).

---

## Rationale notes

### 1. Screen capture + screenstate pipeline

**Decision: Build the capture backend; Adapt CE's pipeline shape.**

- **Backends.** DXGI Desktop Duplication is Windows-only
  (`findings/15-ui/ui-architecture.md` §5 — the entire D3D footprint of `VictoryShield.exe` is
  `ScreenCaptureLibrary` capture, not rendering). On X11, capture each RandR output with
  `XShmGetImage` (the portable equivalent of CE's per-monitor loop with `im0.dat`, `im1.dat`, …
  per output — `findings/10-classifier/capture-pipeline.md` §1/§2). On Wayland, consume an
  `xdg-desktop-portal` ScreenCast session as a PipeWire stream; the portal also supplies the
  compositor's notion of protected/restricted surfaces, which replaces the Windows display-
  affinity probe (§3). Where the compositor normalizes to SDR, drop CE's HDR tone-map step
  (`Win32DxgiCapture::toneMap`, §1) and keep it only if HDR sources are observed in practice.
- **Handoff — Adapt verbatim.** The file-transaction protocol ports cleanly
  (`findings/10-classifier/capture-pipeline.md` §2 and its Linux notes): producer writes
  `spool/<user>/pdl/<timestamp>/{imN.png, manifest.json, ready}` with an atomic ready marker
  (write-temp-then-rename), consumer `inotify`-wakes on it. The named-event wakeup
  (`PdlNotifyARE`) is only an optimization; the marker alone is a complete protocol. Keep the
  per-message-type file vocabulary, the startup folder cleanup, and the tamper watch — CE logs
  `Circumvention: PDL transaction file removed|renamed` on transaction-folder meddling
  (§2), an integrity signal worth its few lines of code.
- **Manifest — Adapt.** Reuse CE's screenstate schema 3.0.0 key set verbatim for
  classifier-side tooling compatibility: `schemaVersion`, `urlSafeUsername`,
  `datetime_created`, `local_utc_offset`, `images[{filename, screenRect}]`, `monitors`,
  `apps[{name, window_title, appRect, doNotScore}]`, `clientPayload.device`
  (`findings/10-classifier/capture-pipeline.md` §2 step 3).
- **Cadence — Adapt.** Backend-configured interval with jitter: sleep uniformly in
  `[(1−v)·I, (1+v)·I]` from `imageScreenshotInterval_sec`/`_Variance_pct`
  (`findings/10-classifier/capture-pipeline.md` §1); fixed short retries (5 s while the
  classifier is down, 40 s default without config, 60 s worst-case fallback). Gate on logind
  `LockedHint`/`Active` (replaces WTS lock/logoff gating, `findings/15-ui/signin-and-settings.md`
  §4), screensaver inactive, and classifier alive — the gate pattern is live-validated on CE's
  side: a full 57.6-min WTS-locked capture produced zero transaction folders and only a silent
  5.06 s retry (`findings/03-runtime/api-trace.md` §d). Unlike CE — which captures and then records
  `saver_while_capture` telemetry — skip capture entirely while locked or screensaver-active.
- **Restricted windows — Adapt.** CE never skips or blacks restricted windows: it captures
  them, logs `Possible circumvention: …`, records a `circumventions` row
  (`windows-screen-recording-not-allowed` + app + window title), and marks the app entry
  `doNotScore: true` (`findings/10-classifier/capture-pipeline.md` §3;
  `findings/12-network/filter-surface.md` §7). Keep the "flag, don't abort" behavior; on
  Wayland treat portal refusals/black surfaces as the trigger, on X11 the equivalent of
  `_NET_WM_WINDOW_TYPE`/screensaver surfaces. The `circumventions` table is part of the upload
  record set (§6), so this is the one place capture policy becomes reportable evidence.

### 2. Classifier

**Decision: Build an on-device classifier; Adapt CE's bundle/manifest/launch mechanics.
On-device, not service-side.**

- **On-device scoring is the only design consistent with the privacy model.** CE captures
  screenstates, scores them locally, and its **comm-service uploader** carries **no images and no
  scores — ever** (`findings/16-updater/upload-protocol.md` §6: exhaustive record-key scan finds
  only the five activity record types; no encoder, no multipart builder — that verdict stands for
  this uploader). ⚠ evidence correction (scope): score batches **do** leave the machine via the
  classifier's file-mediated HTTP reverse channel — the classifier (which imports no socket/HTTP
  API at all) authors `ht.dat` request templates that the client executes with its own libcurl;
  the captured score-batch descriptor is a POST to `https://eyesonapi.cvnt.net/images` with
  `CE_BASIC` auth, its `images[]` entries carrying `evaluationData`/`splicedResult`/`label`/
  `image_sha1_hash`/`pHashImageHash`/`baseBlurredImage`
  (`findings/10-classifier/classifier-internals-client.md` §2/§4;
  `findings/10-classifier/bundle-formats.md` §3). The screenstate records (`ss.dat`) themselves
  stay on-box. A service-side classifier would require shipping pixels off-device and would break
  the activity-records-only model adopted in §6 — so LustLess classifies locally (decision
  unchanged). CE's backend-visible "screen accountability" signal arrives via that channel
  [VERIFIED: `findings/10-classifier/classifier-internals-client.md` TL;DR 1 + §4 — the "templated
  HTTP reverse channel" is confirmed and refined: a file-mediated request proxy, classifier→
  client→backend, entirely outside the comm service].
- **Process shape — Adapt.** Keep a separate `lustless-classifier` supervised by the daemon,
  launched with CE's CLI contract `--model=<dir> --data=<per-user dir> --cache=<per-user dir>
  --version=… [--verbose]` (`findings/02-artifacts/classifier-data.md` "Launch contract";
  `findings/10-classifier/capture-pipeline.md` §4 `LaunchAndMonitorScreenMonitoring` with its
  5 s relaunch poll). Crash isolation for a large ML runtime is worth the second process; the
  daemon owns capture and monitoring.
- **Model bundles — Adapt to content-addressed artifacts.** CE ships six encrypted blobs named
  `<20-hex-id>-<role>.dat.enc` with a closed role set `{b1,b2,b3,j1,mn,sw}`; the id survives
  across releases when the payload does not change (`findings/02-artifacts/enc-data.md` naming
  table), and the installer deletes exactly the obsolete set on upgrade (`RemoveClassifierModelData`,
  same doc). LustLess: `<sha256>-<role>.enc` (id = hash of the plaintext), a small **plaintext**
  manifest (roles, versions, hashes — CE's `mn`-shaped artifact), installed read-only outside
  per-user state. Encrypt at rest only if the threat model needs it; if so use an AEAD with a
  per-file nonce — CE's three `bN` shards leak a byte-identical 9,584-byte prefix because of
  deterministic encryption (`findings/02-artifacts/enc-data.md` header analysis; the scheme is
  recovered and empirically verified as AES-CBC with hardcoded IVs,
  `findings/10-classifier/bundle-formats.md` §1). Log the loaded file ids at startup — CE never
  does, and the id→file mapping that was left as inference there is now recovered: the 20-hex id is the
  first 80 bits of the SHA-512 of the shipped `.dat.enc` file, and every role is proven
  (`b1/b2/b3` = the scoring-model shards, `sw` = Snowball NLP word data, `j1` = the JS bundle,
  `mn` = the manifest)
  [VERIFIED: `findings/10-classifier/bundle-formats.md` §2.1–§2.2 — ⚠ evidence correction: the
  "mapping unrecovered" premise is superseded].
- **Per-user state — Adapt.** Mirror CE's per-user tree
  (`findings/02-artifacts/classifier-data.md`): `cache/` for small control files (e.g. the
  `nxu.dat`-style update-schedule marker), `data/<epoch-ms>/` for fetched batches, `data/<ts>/`
  for work batches; one `<PID>.log` per process in the `time SEV tag: message` format. Treat
  "user DB unavailable" as a warning and keep classifying offline (CE does — SQLite error 26 is
  non-fatal in every logged run).
- **Schema — Adapt.** Screenstate schema 3.0.0 is portable and stays as-is (§1). If A/B
  experiments are ever used, persist the assignment per user and log the roll once (CE's
  `ONE-TIME NOTE: Experimental chance set to 0` — `findings/02-artifacts/classifier-data.md`),
  so support logs explain behavior.
- **What is NOT decided here:** LustLess's own scoring model and its plaintext artifact format,
  and whether to copy CE's hot-updatable JS-bundle layer (discovered by the classifier-internals
  pass — see Open items 1). The classifier→client message semantics that were pending are now
  answered (`findings/10-classifier/classifier-internals-client.md` §2 /
  `findings/10-classifier/classifier-internals-classifier.md` §C-2: inbound `{ss,su,pc,hr}.dat`,
  outbound `{cs,ht}.dat`, `rr/pp/dd` state markers), and the model-blob plaintext formats and
  roles are recovered (`findings/10-classifier/bundle-formats.md` §2). Two negatives are already
  firm and shape the design: the capture client holds **no** model data (string-complete negative in
  `findings/10-classifier/capture-pipeline.md` §4), and the network uploader holds **no**
  classifier outputs (`findings/16-updater/upload-protocol.md` §6) — model handling stays
  exclusively inside the classifier process.

### 3. DNS/URL filtering

**Decision: Build a small forwarder; Adapt the policy model, browser lockdown, and lifecycle.**

- **Forwarder — Build.** CE's actual 10.1.44 enforcement engine is a user-mode per-adapter DNS
  proxy on `127.0.0.2` that resolves every query twice (filter path + user path) and answers by
  a per-query verdict (`findings/12-network/filter-enforcement.md` "What it does" + §1). LustLess:
  one small forwarder listening on `127.0.0.2:53`, with systemd-resolved/NetworkManager
  configured (by `postinst`, §11) to point system DNS at it. A bare systemd-resolved stub cannot
  express per-user policy and synthesized answers, so the verdict engine is ours; resolved only
  does redirection. **Do not** port CE's 10.1.1 per-adapter "Removing DNS servers" enforcement
  loops or the `fec0:0:0:ffff::` residue (`findings/12-network/filter-enforcement.md` §6 —
  dead 10.1.1 leftover).
- **Resolution — Adapt.** Dual path exactly like CE: DoH (RFC 8484 GET `?dns=`) to the per-user
  filter endpoint (default a CleanBrowsing-family resolver such as
  `https://dns.cleanbrowsing.org/doh/adult-filter`), plus the user's own resolvers as the second
  path; record the winner in the verdict
  (`findings/12-network/filter-enforcement.md` §1–§2). A small pooled HTTPS client (CE: ≤5
  connections per endpoint, least-loaded dispatch) suffices; keep the response-header tag
  (CE's `X-CB-Location` → `resolution_datacenter`) — it made fleet debugging possible (§2).
- **Block answers — Adapt.** For override/filter blocks, synthesize NOERROR answers locally
  (CE zeroes the answer section, appends synthesized A/AAAA from the matched override plus a
  CNAME to `blocked.cvnt.net`, `findings/12-network/filter-enforcement.md` verdict b /
  `overrideForBlocking`) so a block page can be served at `blocked.<our-domain>`. Detect
  upstream filter blocks via the RPZ marker (`cleanbrowsing.rpz.noc.org`, code 9
  `BlockedFilter`). Keep CE's 15-code `resolution_type` vocabulary
  (`BlockedCustom/BlockedGlobal/BlockedFilter/UnrestrictedAllow*/SafeSearchEnforced/
  UnrestrictedOutage/TimedOut*/…`, verdict b table) as the `dns_activity` schema — it is a
  complete, battle-tested decision taxonomy. NXDOMAIN-only answers are the fallback if no block
  page ships; synthetic + CNAME is the default because it is what CE's block-page flow expects.
- **URL filtering = DNS-level only — Skip URL inspection.** CE proves `has_url_filtering` has
  no URL/HTTP enforcement consumer; "URL filtering" is domain overrides plus category filtering
  (`findings/12-network/filter-enforcement.md` verdict b). No TLS interception exists in CE
  (zero CE certificates — `findings/01-dynamic-recon/live-surface.md` §f) and LustLess ships
  none either. Domain-override lists (`global`/`custom`, tri-state allow/block/n-a verdicts at
  request time, `findings/12-network/filter-enforcement.md` §4) are the whole URL-filtering
  surface.
- **Browser DoH lockdown — Adapt, directly portable.** If enforcement is DNS-based, browsers
  must not re-route DNS: managed policy files per browser — Chrome/Edge/Brave
  `DnsOverHttpsMode=off` (+ Edge `BuiltInDnsClientEnabled=0`; Brave `TorDisabled=1` if the
  threat model includes it), Firefox `policies.json` with
  `DNSOverHTTPS {Enabled: false, Locked: true}`. CE's exact minimal value set is proven live on
  the research VM (`findings/12-network/browser-integration.md` §2 and its Linux notes give the
  Linux policy-file equivalents). No browser extension is needed — CE 10.1.44 ships none live
  (same doc, verdict summary).
- **Attribution — Adapt.** `dns_activity` rows carry `process_id`/`process_name` per query; CE
  resolves them from the Windows UDP owner table at query time (racy — a miss is fatal for the
  request bookkeeping, `findings/12-network/filter-enforcement.md` verdict a). Linux: UDP
  inode→PID via `SOCK_DIAG`/`inet_diag` netlink + `/proc/*/fd`, with `unknown` as the tolerated
  default.
- **Lifecycle — Adapt.** Ref-count activation exactly like `checkForProxySwitch`: the forwarder
  runs while ≥1 signed-in user needs filtering and the "signed out ⇒ web blocked" product
  semantic is one fail-closed policy flag owned by the forwarder
  (`findings/12-network/filter-enforcement.md` §5; the tray "Logout … disables web access"
  semantics in `findings/15-ui/signin-and-settings.md` §5). Fix CE's two traps: the
  `DnsProxyDisable` name is inverted relative to its effect (sticky-ON gate,
  `findings/12-network/filter-enforcement.md` §5) — LustLess config names match their effect;
  and the break-glass path must be **real** — CE's "Filter guardian" dialog is dead UI with no
  trigger site (`findings/12-network/filter-surface.md` §6), leaving users with no working
  escape when the filter broke. LustLess ships a locally-actionable, polkit-authenticated,
  audited override wired to the health state machine.
- **Health — Adapt.** Keep per-lookup counters + latency (`client_cleanbrowsing_success/
  _problem` shape, `findings/12-network/filter-enforcement.md` §7) and CE's outage machine
  (`DohLookupStatus`: outage → periodic test packets (`error-recovery`) → recovery timer) so
  filter breakage is observable and fail-closed is a deliberate state. Replace CE's
  telemetry-only `covenanteyesfilter.com/healthcheck` probe (`findings/12-network/filter-surface.md`
  §6) with a local probe whose failure feeds the break-glass UI above.
- **Config storage.** Per-user filter config (`over_https_url`, level, fallback IPs) and the
  domain-override lists live in the encrypted per-user store (§5) — matching CE's placement in
  `ce-user-file` (`findings/12-network/filter-enforcement.md` verdict c).

### 4. Local IPC + dashboard

**Decision: Adapt — same vocabulary, better transport and authentication.**

- **Transport — Adapt.** CE's two fixed-slot mmap queues (`ce_user_event_message_queue`
  10×256 B UI→service, `ce_service_event_message_queue` 10×512 B service→UI;
  `findings/02-artifacts/event-queue.md`, `findings/13-service-ipc/service-ipc.md` §2) become
  one Unix domain socket per session (reverse channel = same socket or a paired one), with
  `SO_PEERCRED` giving uid/pid for peer authorization. This directly fixes CE's worst local
  flaw: the `127.0.0.1:48867` server has **no authentication of any kind**, and
  `/local/user/:u:/keys.:d:` hands out the user's API key/secret to anything that can connect
  (`findings/13-service-ipc/service-ipc.md` §1) — LustLess never serves credentials over a
  local route.
- **Wire format — Adapt verbatim.** Keep the 1-byte code + payload framing and the code
  vocabulary: `0x43 COLLECT_DEBUG_LOGS`, `0x4c USER_LOGOUT`, `0x4d SEND_METRICS`, `0x51 QUIT`,
  `0x52 SET_WINDOWS_REGISTRY`→ `SET_CLIENT_CONFIG` (same code; registry semantics die with
  Windows), `0x53 USER_SETTINGS_CHANGE`, `0x54 SEND_TELEMETRY`, `0x55` empty-poll sentinel,
  unknown code → log-and-ignore (`findings/13-service-ipc/service-ipc.md` §2 table). Keep the
  back-channel `NOTIFICATION` (code 2) with bounded retries (2×6×100 ms equivalent). Keep the
  "new instance prims the queue with `QUIT`/`IgnoreMe` to flush stale peers" trick
  (`FUN_14023cb50`, §2) or replace it with connection-lifecycle semantics — either is fine as
  long as stale-IPC reset is explicit.
- **Dashboard — Skip-by-default / optional.** CE's local dashboard (10 routes: dashboard,
  about, antivirus, per-user settings, DNS settings, DNS-activity log, status, internal
  commands, keys, static CSS — `findings/13-service-ipc/service-ipc.md` §1 route table) is a
  good information architecture and is worth keeping optionally. Live evidence backs the
  optionality: CE's own listener took **zero** clients across 57.6 min of capture with the UI
  running — the surface is dormant unless a human drives it
  (`findings/03-runtime/api-trace.md` §c). If shipped: bind loopback,
  authenticate with a daemon-issued session token, and drop the keys route entirely. Content is
  embedded/templated like CE's (no on-disk asset dir needed).
- **Policy state — Adapt.** Replace the `CE_SPYMapObj` shared-memory policy block + window
  messages `0x401–0x407`/`0x428` + `ceFilterCheckReply%d` slots
  (`findings/15-ui/ui-architecture.md` §4b) with a read-only policy snapshot served over the
  socket. The flag set is worth keeping as data: `has_accountability`, `has_filtering`,
  `has_screen_accountability`, `has_url_accountability`, `has_dns_filtering`, `has_url_filtering`,
  `can_override`, `is_panicked` + username (`findings/12-network/filter-surface.md` §1d offset
  map).

### 5. State stores

**Decision: Adapt — `ce-file` shape verbatim, `ce-user-file` crypto fixed.**

- **Outbox DB — Adapt verbatim.** One plain SQLite file (WAL, 0600, daemon-owned) with CE's
  schema shape: event tables `logins`, `dns_activity`, `circumventions`, `switch_users` each
  carrying `(status, status_changed_at, created_at)`, `(username, status, …)` indexes for the
  hot "this user's rows in this sync state" query, ISO-8601 UTC timestamps + separate
  `timezone_offset`, and the `metrics` namespace with 3600 s buckets, `bucket_current` age
  counter, JSON `tags` with `INDEXED/CARDINAL/INCIDENTAL` annotations and JSON `fields`
  (`findings/02-artifacts/local-db.md` — full schema there). The state machine is kept exactly:
  `insert → queued → sending → sent` with a min-age claim gate and a stale-`sending` reaper
  (`findings/13-service-ipc/service-ipc.md` §4; `findings/16-updater/upload-protocol.md` §4);
  metrics rows are born `collecting` and roll to `queued` when the bucket ages out.
- **Settings DB — Adapt with real key management.** `ce-user-file` is SQLCipher 4
  (AES-256-CBC per page + HMAC-SHA512 page MAC + PBKDF2-HMAC-SHA512, 4 KiB pages —
  `findings/13-service-ipc/service-ipc.md` §5; container shape `findings/02-artifacts/user-file.md`),
  holding `user_info`, `user_dns_filter`, `global_domain_overrides`, `custom_domain_overrides`,
  `api_credentials` (`findings/12-network/filter-enforcement.md` verdict c). Keep the encrypted
  store and the table set; **replace the key**. CE's passphrase `AN0ther$uper$ecretKEY4This` is
  XOR-obfuscated in the binary with an 8-byte keystream and was recovered byte-by-byte
  (`findings/13-service-ipc/service-ipc.md` §5) — a hardcoded key protects nothing against a
  local attacker. LustLess keys the DB from the OS: Secret Service/`libsecret` per-user entry
  or a TPM-sealed per-install key, with a keyfile fallback of strictly 0600 under
  `/var/lib/lustless`. Same schema-evolution practice as CE (lazy `ALTER TABLE` migrations in
  the daemon, `findings/12-network/filter-enforcement.md` §4).
- **Do not copy** the plaintext `password` column in `api_credentials`
  (`findings/16-updater/upload-protocol.md` §2) — see §6.

### 6. Upload protocol

**Decision: Adapt — one daemon, one outbox, seven REST routes; privacy model kept; auth
modernized.**

- **Topology — Adapt verbatim.** Exactly CE's shape
  (`findings/16-updater/upload-protocol.md` §3–§4): one uploader in `lustlessd`, one outbox,
  batch 100 rows per request, per-user batching for the activity log, invalid records dropped
  instead of failing the batch, `queued→sending→sent` with claim + reaper, server-requested
  throttling persisted as a resume-not-before timestamp (`ApiTelemetryResumeTime` analog), a
  purely local bookkeeping tick (CE: 600 s steady / 60 s retry — the observed 601 s heartbeat,
  `findings/03-runtime/network-capture.md`; live-validated by `findings/03-runtime/api-trace.md`
  §b: zero network events at the tick, while `LastTelemetryUploadAt` moved only on a real upload
  at 10:23:34) distinct from upload completion stamps, and a `(server_time, local_ticks)` clock
  anchor refreshed hourly from `status/time` with system-time fallback (CE's `ServerTimeManager`,
  `findings/16-updater/upload-protocol.md` §4) used for all event timestamps so offline-tolerant
  uploads stay consistent. The uplink follows the same split — fresh connect per exchange,
  rotated activity-driven (~301 s apart during upload bursts, each preceded by a same-process
  loopback self-pair; `findings/03-runtime/api-trace.md` §c) — so dial per exchange rather than
  holding a keep-alive.
- **Routes — Adapt.** Seven-route-equivalent REST over HTTPS:
  `activity_log` (POST, **the** upload: `webActivityRecord`, `loginActivityRecord`,
  `circumventionRecord`, `switchUserActivityRecord`, `installActivityRecord` — the complete
  record vocabulary, `findings/16-updater/upload-protocol.md` §5), `metrics`, `logs/store`
  (support event log — ship behind a debug toggle), `telemetry/store`, `status/time`,
  `status/ping`, `client_update` (consumed by §9). Keep the shared envelope
  `{"<recordType>": {"client": {architecture, platform, platformVersion, version}, "timestamp": …}}`
  and the `utc_datetime_created` key (§5).
- **Privacy model — keep it; it is a feature.** CE's comm-service uploader carries **no
  screenshot, thumbnail, image byte, or classifier score, ever** — proven by complete record-key
  enumeration and the absence of any encoder/multipart path in that uploader
  (`findings/16-updater/upload-protocol.md` §6; the verdict stands for this uploader).
  ⚠ evidence correction (scope): CE as a whole does upload screen-derived data — classifier score
  batches (scores, labels, hashes, and a `baseBlurredImage` field) ride the classifier's `ht.dat`
  proxy channel to `https://eyesonapi.cvnt.net/images`, executed by the UI process outside the
  comm service (`findings/10-classifier/classifier-internals-client.md` §4;
  `findings/10-classifier/bundle-formats.md` §3). What LustLess adopts below is its **own,
  stricter** invariant, unchanged by that finding: reports contain activity records only. If
  screen-derived evidence (e.g. flagged-window metadata) is ever uploaded, it becomes a
  **first-class record type in the schema with explicit consent**, not a hidden side channel
  (same doc, Linux notes) — see Open items for the pending policy decision.
- **Auth — Adapt.** Replace HTTP Basic (CE: `Authorization: Basic` with the per-user
  `user_key`/`user_secret` pair from `api_credentials`, no pinning, no tokens —
  `findings/16-updater/upload-protocol.md` §2) with per-device credentials presented as
  **revocable Bearer tokens**: an OIDC-style sign-in flow issues a device token to `lustlessd`,
  which refreshes/rotates it server-side and stores it in the encrypted settings DB (§5). Never
  store the account password (CE's `password` column is a lesson, §2). TLS with normal CA
  validation (CE does the same, sans pinning); SPKI pinning is optional hardening for our own
  backend. Keep the small outbound-domain allowlist concept for any link-opening surface, kept
  distinct from the update-download allowlist (§9; `findings/16-updater/upload-protocol.md` §1).
- **Self-metrics — Adapt.** CE wraps every HTTP call in a tracking client that counts
  `client_api_success`/`client_api_problem` with host/route/status tags (§5 metric catalog) —
  cheap fleet observability; keep it.

### 7. Watchdog / persistence / anti-tamper

**Decision: Adapt — systemd replaces SCM + the session-polling watchdog; tamper protection
becomes package ownership plus a documented toggle.**

- **Service supervision — Adapt.** CE's resilience is configuration-level: SCM
  `FailureActions` RESTART ×3 @ 1 s (never reset), `CanStop=false`, service SDDL, and
  registry-protected `ImagePath`/`FailureActions` (`findings/14-watchdog/watchdog.md` §1/§8/§12;
  `findings/01-dynamic-recon/live-surface.md` §d). Linux: `lustlessd.service` with
  `Restart=on-failure`, `StartLimitIntervalSec`/`StartLimitBurst` matching the 3-in-1 s budget,
  `After=network-online.target`, and `RestartSec`; a second unit pair covers the classifier
  (or `Restart=` on a `lustless-classifier.service` the daemon drives).
- **Per-session agents — Adapt.** VSWD polls `WTSEnumerateSessionsExA` once per second and
  relaunches `VictoryShield.exe` into any interactive session lacking it via
  `CreateProcessAsUser` on the session's explorer token (`findings/14-watchdog/watchdog.md`
  §2–§4). Linux: per-user systemd services (`lustless-agent.service`, wanted by the graphical
  session target) with logind event-driven session tracking (`sd-login`/D-Bus
  `SessionNew`/`SessionRemoved`) — same supervision semantics without a 1 Hz poll or a
  token-stealing spawn path. Keep CE's identity discipline: declare "running" only for a
  **canonical-path-matching** process (§3 full-path check), never a name match alone.
- **Crash back-off — Adapt verbatim.** Per-user `last_crash_at` + "no relaunch within 10
  minutes" suppress window read by the supervisor, crash total counter, and >3 restarts ⇒ stop
  auto-restart and escalate to a human-visible message
  (`findings/14-watchdog/watchdog.md` §5/§7; the `RestartVSClientOnly.exe` budget
  `CMP …, 3`). Both counters live in per-user state written by the restart helper and cleared on
  healthy start (`findings/16-updater/crash-reporting.md` §5).
- **Tamper protection — Adapt to package-manager reality; Skip the protector machinery.** CE's
  `VSWD.dll` Registry Protector rewrites 22 registry values from compiled-in constants with a
  1 s debounced repair loop, and the Folder Protector locks the install dir with deny-delete
  ACLs watched by `FileSystemWatcher` (`findings/14-watchdog/protectors.md`). On Linux the
  package manager already owns `/usr` integrity (root-owned, checksummed by dpkg) — **skip**
  re-implementing value-protectors. What must NOT be copied: the hidden
  `disableFileProtection`/`disableRegistryProtection` exports and the SCM custom commands 243
  ("protections off + stop") / 176 (`Environment.Exit(3011)`) that silently disarm everything
  (`findings/14-watchdog/watchdog.md` §10; `findings/14-watchdog/protectors.md` exports
  section). LustLess's disarming path is one **documented, polkit-gated, audit-logged** action
  (`org.lustless.disable-protection`) usable by the admin and by uninstall — visible in docs,
  visible in the journal. Like CE, ship **no** process-level anti-kill
  (`findings/14-watchdog/watchdog.md` §12: VSWD terminates nothing foreign) — Skip; resilience
  is unit policy, not rootkit-adjacent behavior.
- **Uninstall hygiene — Adapt.** CE's order is worth copying
  (`findings/16-updater/updater.md` §6, `findings/02-artifacts/logs.md` installer logs): flush
  pending uploads → stop services with a bounded stop → remove components → reverse config
  (DNS redirect, browser policies) → migrate state to a `PreviousConfiguration` backup → remove
  units. No ARP-entry sabotage (`CleanupRegistryUninstallValues`, `findings/14-watchdog/watchdog.md`
  §12) — Skip; a Linux package that removes itself cleanly is the anti-tamper story.

### 8. UI

**Decision: Build a thin GTK tray app + web dashboard; Adapt CE's flows and gating semantics.**

- **Shell — Build.** CE's UI is an MFC tray application: one hidden controller window, a
  `Shell_NotifyIcon` status icon, modal dialogs, a single-instance mutex
  (`VictoryShieldIsRunning`), and XAML only inside the sign-in dialog
  (`findings/15-ui/ui-architecture.md` §1–§2). Linux: `lustless-agent` as a GTK +
  libayatana-appindicator tray app (status color/icon, menu: sign in/out, switch user, open
  dashboard, view activity, refresh settings, collect diagnostics, check for updates — CE's
  menu resource, §1), single-instance via an abstract-socket lock or `GApplication`.
  **Skip** XAML/WinRT entirely; **skip** any embedded browser — CE itself embeds none (§3: zero
  WebView2 references; every URL goes through one `ShellExecuteW` helper). LustLess opens URLs
  in the default browser the same way (`xdg-open`).
- **Rich UI — web dashboard.** Sign-in, settings (filter level, blocking toggles, device list),
  and activity views live in the authenticated local dashboard (§4) rather than native dialogs —
  the CE dashboard already carries settings, DNS activity and status pages
  (`findings/13-service-ipc/service-ipc.md` §1), and the tray's "Go to dashboard" already points
  at a browser (`findings/15-ui/ui-architecture.md` §3).
- **Sign-in — Adapt the flow, fix the credential path.** Keep CE's UX: username + password,
  "switch user" (state `SWITCHING_USER`, `switch_users` row), and "confirm your password" before
  sensitive settings changes (`findings/15-ui/signin-and-settings.md` §1/§3 — the
  `passwordConfirmWorker` telemetry vocabulary). Fix the architecture: CE hands the plaintext
  password to the UI host, stores derived credentials in a local DB, and publishes identity via
  shared memory (§3, Linux notes there). LustLess: credentials go once over the authenticated
  UDS to `lustlessd`, which performs the sign-in (or browser OIDC) and **holds the session**
  (mode-0600 token store); the UI never sees long-lived secrets. Failure texts (bad credentials /
  no services / disabled account / no connection, `translateLoginFailure` §3) map 1:1.
- **Session gating — Adapt.** WTS session notifications (`WTSRegisterSessionNotification`,
  events 5–8 logon/logoff/lock/unlock gating capture —
  `findings/15-ui/signin-and-settings.md` §4) become logind D-Bus `Lock`/`Unlock`/
  `SessionNew`/`SessionRemoved` signals driving the same rules: capture only while unlocked and
  display on. Keep CE's product semantic that Screen Accountability keeps working while signed
  out (dialog text, §5) and that **sign-out cuts web access** ("Signing out will disconnect you
  from the Internet", §5) — enforced by the forwarder's fail-closed flag (§3), not by the UI.
- **Policy ownership — Adapt.** In CE the UI is the policy state machine (`LOGGED_OUT |
  LOGGING_IN | LOGGED_IN | SWITCHING_USER`, §5/`findings/15-ui/ui-architecture.md` §6) and the
  service re-reads state after `USER_SETTINGS_CHANGE`. In LustLess `lustlessd` owns state; the
  agent's events (`USER_LOGOUT`, `USER_SETTINGS_CHANGE`) are notifications only, and the
  filtered/policy snapshot is served read-only over IPC (§4).

### 9. Updater

**Decision: Adapt the channel; Build real signature verification.**

- **Feed — Adapt.** CE decides updates server-side via `getClientUpdate`
  (`POST /v1/desktop_client_update`, request: app name/version/branch/sha/OS/arch/device id +
  user list; response `payload.recommendation ∈ {now, later, none}` + `payload.critical` +
  download link) through a WinSparkle fork's appcast callback, checked daily (86,400 s)
  (`findings/16-updater/updater.md` §2). LustLess keeps that exact decision shape — one JSON
  endpoint, `recommendation` is the whole policy, **no client-side version comparison** (the
  server's `now` is trusted for ordering, not integrity) — minus WinSparkle: a small updater
  module in `lustlessd`.
- **Signing — Build; this is CE's lesson.** The shipped WinSparkle fork contains full OpenSSL
  DSA support (`win_sparkle_set_dsa_pub_pem`, `Missing DSA signature!`, `Invalid update
  signature`), yet the client **never configures a key** — the live registry has no
  `DSAPub`/`DSAPEM`, so the downloaded installer is trusted by HTTPS + host allowlist alone
  (`findings/16-updater/updater.md` §5). LustLess **verifies an ed25519/minisign signature on
  every update payload** against a public key shipped in the package before anything is applied;
  the download-URL allowlist (CE restricts to `covenanteyes.com`/`cvnt.net`, §2) stays as a
  second, independent layer.
- **Delivery/apply — Adapt.** On Zorin OS: a signed apt repository carrying `.deb` updates
  (signature verified by the daemon before it ever invokes package tooling), with the
  recommendation enum mapping to apply-now (critical), notify (later), or nothing. Keep CE's
  silent-upgrade discipline: **critical-only** for unattended apply and a
  `disable_silent_upgrade` admin flag with a short (1 day) grace window
  (`DisableSilentUpgrade`/`SilentUpgradeDisabledAt`, `findings/16-updater/updater.md` §4).
  Keep CE's upgrade transaction order (`findings/16-updater/updater.md` §6 + Linux notes):
  flush uploads → stop services (bounded) → apply → migrate state to `PreviousConfiguration` →
  fresh version-encoded state dir (`…v010.001.044`-style naming aids rollback) → restart units.
- **Skip** CE's reboot UX entirely: no forced reboots, no third-party-driver disabling (the
  Trend Micro TDI dialog is the fossil of that — `findings/16-updater/updater.md` §7/§9;
  Linux notes).

### 10. Crash reporting + diagnostics

**Decision: Adapt — keep the pipeline shape, fix the payload.**

- **Crash pipeline — Adapt.** CE: BugSplat (`database=covenant-eyes-10-1`) minidump + a zip of
  logs built by the bundled Info-ZIP, 5 MB/file and 19 MB total caps, then a restart helper
  (`findings/16-updater/crash-reporting.md` §1–§3). LustLess: `coredumpctl`/Crashpad-style
  minidump + zipped journald/config logs with the same caps (or better: compress + redact),
  uploaded through the §6 uploader as a distinct crash channel. **Do not copy the attachment
  default:** CE attaches the **entire local activity database** (`ce-file`/`ce-user-file`) to
  every crash report (Linux notes, same doc) — for an accountability client that is a privacy
  landmine; LustLess uploads logs + a sanitized state summary only, anything more behind
  explicit consent.
- **Restart + counters — Adapt verbatim.** Dedicated `lustless-restart-helper
  --RestartRequestFrom=<ver> --pid=<n>` with a single-instance lock and the ≤3-restart budget
  then human escalation (`findings/16-updater/crash-reporting.md` §5;
  `findings/14-watchdog/watchdog.md` §7); the crash-at/crash-since contract read by the
  supervisor (§7) and an accumulator flushed as a `client_crash{type, count}` metric at next
  startup. Classify crash types (CE ships `crash_type=GENERIC` today — §5).
- **Test hooks — Adapt.** Keep CE's support/QA affordances as **documented** debug flags: a
  `crashatonce=true` self-crash switch and a config-driven `ForceCrash*` kill-switch
  (`findings/16-updater/crash-reporting.md` §4; `ForceCrashCommService` in
  `findings/13-service-ipc/service-ipc.md` §8) — they made CE's crash path testable and cost
  nothing.
- **Diagnostics — Adapt.** CE's shape is exactly right: the privileged service delegates
  collection to a helper (`vs-config.exe --collect-debug -lvs-config.log`) on queue code `0x43`,
  with human-readable progress notifications on the back-channel ("Diagnostics are being
  collected…" / "We've finished collecting diagnostics")
  (`findings/13-service-ipc/service-ipc.md` §2). LustLess: `lustlessctl collect-debug` (or
  `lustlessd`-spawned helper) bundling logs, versions, sanitized config, DB integrity check and
  the crash-counter state, progress over IPC, output optionally attached to a support ticket.
  Keep the metric trigger pair (`collect_diagnostics_in_progress`, `automatic` vs manual).

### 11. Packaging for Zorin OS

**Decision: Build — `.deb` + systemd units + maintainer scripts; no kernel component.**

- **No kernel modules — proven unnecessary.** CE 10.1.44's entire observable surface is pure
  user mode: `CEA.sys` is a stock Microsoft binary, zero WFP filters/callouts, zero Winsock
  LSP/NSP, no minifilter, no CE certificates, no firewall rules
  (`findings/01-dynamic-recon/live-surface.md` §a–§f verdicts; `re/INVENTORY.md` §3). The Linux
  equivalent therefore needs no DKMS, no eBPF-for-enforcement, no kernel patches — a user-mode
  forwarder + daemons reproduce the full surface (this is the "pure-user-mode verdict" the
  mapping rests on).
- **Package layout.** `lustless` (or split `lustless-daemon` / `lustless-agent`) shipping:
  `lustlessd.service` (system unit), `lustless-agent.service` (user unit, wanted by the
  graphical session target), `lustless-classifier.service` if kept separate, the binaries,
  `/usr/share/lustless/` model manifest + bundle(s) (§2), polkit action for the protection
  toggle (§7), and browser managed-policy files (§3).
- **`postinst`.** Enable + start units; configure DNS redirection (resolved/NM dispatcher or
  drop-in pointing system DNS at `127.0.0.2`); install the Chrome/Edge/Brave managed policies
  and Firefox `policies.json` DoH lockdown; register the polkit rule; create the state dir
  (`/var/lib/lustless`, 0700) and per-user state location. **`prerm`/`postrm`:** reverse all of
  the above in CE's documented order (§7 uninstall hygiene), leaving a `PreviousConfiguration`
  state backup and the version-encoded state dir naming for rollback
  (`findings/16-updater/updater.md` §6 + Linux notes).
- **State/log placement.** System state under `/var/lib/lustless`; per-user classifier state
  keyed by uid (CE keys by SID — `findings/02-artifacts/classifier-data.md`); logs to journald
  with CE's tag taxonomy as structured fields (`Classifier`, `pdl-edi`, `bundleManager` → our
  equivalents), which subsumes CE's per-PID log files for the daemon side while the classifier
  keeps its own `<PID>.log` for support bundles (§2).

---

## Open items

Decisions deferred, with exact scope. Nothing else in this document is pending.

**Status (2026-10-11 sync — classifier-internals + bundle-formats passes landed):**

- Item 1: **RESOLVED** by `findings/10-classifier/classifier-internals-classifier.md` (a: named-event wake + `ss/su/pc/hr` message folders + `rr/pp/dd` state markers; c: full message vocabulary incl. `cs`/`ht`, score batches flow through the ht.dat request proxy; d: `experimentChancePerScreenshot_pct` gates the Victory-vs-Experimental upload channel), `classifier-internals-client.md` (transport = file-mediated request proxy, `hr.dat` answers; UI "analyzed" counter counts captures), and `bundle-formats.md` (b: crypto + all six roles proven — `b1/b2/b3` = scoring-model shards, `sw` = Snowball NLP data, `j1` = JS/duktape bundle, `mn` = manifest).
- Item 2: in progress — model selection is part of the LustLess classifier implementation (tracked in `docs/impl/CONTRACTS.md` §7).
- Item 3: still open — verification scheduled against the Zorin/Ubuntu-family testbed (Wayland portal capture permission).
- Item 4: **RESOLVED** — invariant ratified as the deliberately-stricter LustLess choice: no screen-derived data on ANY channel (CE's score batches leave via the ht.dat proxy per `classifier-internals-client.md`; LustLess keeps records-only everywhere). Flagged-window metadata rides CE's existing `circumventionRecord` behind `upload.circumvention_records`.
- Item 5: still open — protocol mechanics decided (§3); shipped default = CleanBrowsing-family adult-filter endpoint pending redistribution-terms review.

1. **Classifier internals (classifier-internals pass lands after this document).** Scope:
   (a) screenstate-consumption semantics — does the classifier watch ready-marker folders and
   how it treats `doNotScore` windows / `apps[]` rects; (b) plaintext formats and keying of the
   six `*.dat.enc` roles (`b1/b2/b3/j1/mn/sw` — which role is the scoring model) and the
   `bundleManager`/`pdl-edi` bundle format (`nxu.dat` nextUpdate, `bmdat` cache, `ht.dat` hash
   tables, `su.dat`); (c) the classifier→client message types (`cs/ht/pp/dd/re4*`) and how
   scores reach the client/UI ("Analyzed… in the last N minutes");
   (d) the `pdl-edi` "Experimental chance" experiment-gating semantics. Evidence base so far:
   `findings/10-classifier/capture-pipeline.md` §2 (its file table was then partly inferred;
   the classifier-internals pass has since landed and resolves most of (a)–(d) — status in
   `## Inference audit log`) + §4,
   `findings/02-artifacts/enc-data.md`, `findings/02-artifacts/classifier-data.md`, and the
   `findings/13-service-ipc/service-ipc.md` / `findings/16-updater/upload-protocol.md` negatives
   (no model handling in the client/uploader). **Blocks:** the final classifier→daemon record
   shapes, the model-bundle sync protocol details, and item 4 below.
2. **LustLess's own scoring model.** CE's model blobs are CE's intellectual property and their
   plaintext is unrecovered (item 1b). Scope: select/obtain a clean-room screen-content
   classification model (e.g. an open NSFW/image classifier), define its training/eval harness
   and accuracy bar, then express it in the `<id>-<role>` bundle + plaintext manifest mechanics
   fixed in §2. Only the transport/manifest mechanics are decided here; the model choice is a
   separate work item.
3. **Wayland unattended capture permission.** Scope: verify on Zorin OS (GNOME/Mutter) whether
   `xdg-desktop-portal` ScreenCast can hold a persistent, prompt-free permission for periodic
   capture by a background agent (portal RemoteDesktop/screencast token persistence, or
   restoring the session on login); if not, decide the default capture path (X11 `XShmGetImage`
   where the session is XWayland/X11, XDG portal with a one-time grant, or a documented
   compositor-specific path). **Blocks:** the default backend selection in §1 on Wayland
   sessions; the file-transaction pipeline is unaffected.
4. **Screen-derived upload policy.** Scope: either formally ratify the §6 invariant "no
   screen-derived data ever leaves the device", or define a first-class, consent-gated record
   type for flagged-window/score evidence (fields, retention, consent UX) — informed by what the
   classifier actually produces (item 1c). CE's comm-service uploader proves the
   records-only baseline is workable (`findings/16-updater/upload-protocol.md` §6).
5. **DoH upstream choice for a shipped product.** Scope: evaluate a CleanBrowsing-family
   resolver's terms/rate limits for redistribution versus self-hosting an RPZ-style blocklist
   resolver; pick the shipped default endpoint set and the `clear_browsing_level`-style level →
   endpoint mapping. Protocol mechanics (RFC 8484 dual-resolution, RPZ marker handling) are
   decided in §3 and unaffected; only the default endpoint/level table is open.

## Inference audit log

Every original inference tag site in this document, with its verdict. Inline verdict forms:
`[VERIFIED: <cite>]`, `[INFERENCE — unresolved: <what is missing; last examined …>]`, plus
`⚠ evidence correction` where new evidence contradicted or scoped the tagged claim. (The header
line describing the tagging scheme was rewritten to this audited form; it is not a tag site.)

| # | Site | Original claim | Verdict | Evidence |
|---|---|---|---|---|
| 1 | §2 "On-device scoring" | CE's backend-visible "screen accountability" signal arrives via a channel outside the comm service, plausibly the classifier's templated HTTP reverse channel | **verified** (+ refined) — it is a file-mediated request proxy: the classifier (no socket/pipe/HTTP import at all) authors `ht.dat` request templates, `VictoryShield.exe` executes them with its own libcurl and answers via `hr.dat`; score batches ride it to the backend | `re/findings/10-classifier/classifier-internals-client.md` TL;DR 1 + §2/§4 (Linux-mapping verdict section) |
| 2 | §2 "Model bundles" | the loaded-file-id→file mapping was left as inference (CE never logs ids) | **corrected** — the mapping is recovered: id = first 80 bits of the SHA-512 of the shipped `.dat.enc` file; all six roles proven (`b1/b2/b3` scoring-model shards, `sw` Snowball NLP data, `j1` JS bundle, `mn` manifest); at-rest scheme recovered as AES-CBC with hardcoded IVs | `re/findings/10-classifier/bundle-formats.md` §1, §2.1–§2.2 |
| 3 | §2 "What is NOT decided here" + Open items 1 tag ("partly inferred" file table) | classifier→client message semantics and the capture-pipeline §2 file table pending the classifier-internals pass | **corrected** — the pass landed: inbound vocabulary `{ss,su,pc,hr}.dat`, outbound `{cs,ht}.dat`, `rr/pp/dd` state markers, `re4*.dat` GC-exemption tokens, `nxu.dat` = `{"nextUpdate_sec":…}`, `experimentChancePerScreenshot_pct` = victory/experimental channel routing; still open from Open item 1: the `doNotScore` consumer site, the `re4*.dat` creator, production `/v1/member/sensor/config/pdlEdi` values | `re/findings/10-classifier/classifier-internals-client.md` §2; `re/findings/10-classifier/classifier-internals-classifier.md` §(a), §C-2, §C-4, §(d) |
| 4 | §2 + §6 "no images and no scores — ever" (claim, not a tag) | CE never uploads classifier scores | **corrected (scope)** — true of the comm-service outbox only (`re/findings/16-updater/upload-protocol.md` §6 stands for that uploader); CE as a whole uploads score batches through the `ht.dat` proxy: captured descriptor POSTs `https://eyesonapi.cvnt.net/images` with `CE_BASIC` auth, `images[]` carrying `evaluationData`/`splicedResult`/`label`/hashes/`baseBlurredImage` | `re/findings/10-classifier/classifier-internals-client.md` §4; `re/findings/10-classifier/bundle-formats.md` §3 |

Design decisions were not changed by this audit: §2/§6 keep the "classify locally" choice and the
records-only upload invariant as LustLess's own, stricter policy — only the CE-side factual claims
were scoped. Effect on Open items: item 1 is mostly answered (rows 2–3; remaining scope listed in
row 3); item 4's factual basis changed (row 4) but its policy question — ratify the invariant or
define a consent-gated screen-derived record type — remains open as written.
