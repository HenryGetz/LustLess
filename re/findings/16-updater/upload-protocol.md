# 16-updater — remote backend protocol (VictoryShieldCommService.exe)

Scope: the **remote** HTTP API surface of `VictoryShieldCommService.exe` (image base
`0x140000000`, 22,545 fn): HTTP/TLS stack, auth, endpoint catalog, upload lifecycle
(outbox → API), payload formats, and a verdict on what Screen Accountability data leaves
the machine. Non-goals: local IPC/queue/state-store mechanics (ServiceIpcPass), DoH /
filter enforcement (FilterEnforcementPass). Cross-refs: `../02-artifacts/local-db.md`
(ce-file schema + outbox), `../02-artifacts/logs.md` (log tags/cadences),
`updater.md` (getClientUpdate decision policy + silent upgrade),
`../12-network/filter-surface.md` (per-user settings GETs), `../10-classifier/capture-pipeline.md`
(screenstate file handoff), `../03-runtime/network-capture.md` (live 601 s heartbeat).

## What it does

The comm service is the client's **only network uploader**. It speaks a JSON-over-HTTPS
API to `api.cvnt.net` through a statically-linked **libcurl** wrapped by CE's
`HttpApiLibrary` (`ApiTelemetry.cpp`, `ApiSendQueue.cpp`, `ApiSendMetricsQueue.cpp`,
`ApiSendLoggingQueue.cpp`, `ApiReportInstall.cpp`, `ApiClientUpdate.cpp` — source-path
strings `0x1409b2840`, `0x1409c67e0`, `0x1409c6940`, `0x1409c6a10`, `0x1409b2ae0`,
`0x1409c7c10`). Seven routes exist: server time, ping, activity-log upload, metrics
upload, log upload, telemetry upload, and client-update check. Everything user-relevant
(DNS/web activity, logins, circumvention interruptions, user switches, install reports)
goes through one batched outbox in the local SQLite (`ce-file` tables with a
`queued → sending → sent` status machine), flushed by a dedicated
`ApiActivityLoggingThread`. Auth is HTTP Basic with a per-user key/secret pair stored in
the local `api_credentials` SQLite table. **No screenshot, thumbnail, score, or any image
data is uploaded by this binary** — see the verdict in Mechanism §6.

## Mechanism

### 1. HTTP/TLS stack

- **Client library: statically linked libcurl.** CE wrapper `curlCommunicate` (RTTI
  `.{AV}<lambda_1>@?1??curlCommunicate@@YA?AUHttpResponse@@AEAUCurlSession@@…` `0x140a9bc50`),
  log strings `communicate with CURL via HTTP to ` (`0x1409a9890`) and
  `Failed to send HTTP request with curl: ` (`0x1409a98e0`). The curl cookie/HSTS/alt-svc
  cache banners are present (`0x140896030`, `0x140898210`, `0x140898030`), as are curl's
  `Authorization: Basic %s` / `Bearer` header formats (`0x140898e98`, `0x140898eb8`).
  (Boost.Beast is used only for the DoH client and the loopback dashboard; cppnetlib
  `async_connection.hpp` `0x1409aba20` serves `http://localhost:48867`.)
- **TLS**: libcurl is built with **both OpenSSL and schannel** backends (OpenSSL
  `ssl\record\…` strings `0x14096a298`+; schannel strings `0x14089c8c0`+); the binary's
  own CRYPT32 imports include `CertOpenSystemStoreW`, `CertGetCertificateChain`,
  **`CertVerifyCertificateChainPolicy`** (IAT `0x140a7a1c0`/`0x140a7a1a0`/`0x140a7a1d0`,
  baseline imports table). There is **no certificate pinning configured by CE code**:
  curl's pinning machinery strings exist (`SSL public key does not match pinned public
  key` `0x14089a858`) but no CE-owned pin/hash constant or `CURLOPT_PINNEDPUBLICKEY`
  setup was found in the CE source regions — trust is the default CA-chain validation
  [INFERENCE].
- **Base URI**: `https://` (`0x14099cda8`) + `api.cvnt.net` (`0x14099cdd8`), built by
  `FUN_1401727b0` (two xrefs; `staging.api.cvnt.net` `0x14099cdc0` is the alternate host
  [INFERENCE: selectable via the shared `ClientapiDomainRoot` setting, a dead value name
  documented in `updater.md` §9f]). Live traffic confirms exactly this one host:port
  (`../03-runtime/network-capture.md`).
- **Request envelope / instrumentation**: every call passes
  `TelemetryTrackingHttpClient::communicate` (`0x1409a92d0`) which tags the call
  (`addTagHostAndRoute` `0x1409a93c0`) and records `client_api_success` /
  `client_api_problem` metrics with `host_name` + `http_response_code` tags — this is what
  fills the `metrics` rows seen in `../02-artifacts/local-db.md`. Each call also writes an
  audit row `(username, request, response, process, component, timestamp, … 'sent')`
  (`0x1409af5f0`) that the local dashboard pages through. The HTTP layer logs
  `<HTTP Authentication type=…>` plus ` username='…'` or ` (no credentials)`
  (`0x1409a9460`/`0x1409a9428`/`0x1409a9410`).
- **Host allowlists** (two distinct ones):
  1. *Update-download allowlist* — the same `CeWinsparkle.cpp` code as in
     `VictoryShield.exe` is compiled into the service (strings
     `winsparkle::genericAppcastUpdate` `0x1409c62f0` area, `covenanteyes.com` `0x1409c6410`,
     `cvnt.net` `0x1409c6428`, `Untrusted download domain detected, ignoring: `,
     `Returning (-1): …`, appcast prefix
     `https://covenanteyes.com/files/win/sparkle/appcast-` `0x1409c6630`, WinSparkle regpath
     `SOFTWARE\Covenant Eyes\Victory Shield\WinSparkle`): scheme `https` + host
     `covenanteyes.com`/`cvnt.net` exact-or-dot-suffix. Full behavior in `updater.md` §2
     (the service hosts the daily-check WinSparkle instance — its HKCU is
     `HKU\S-1-5-18\…\WinSparkle`).
  2. *Trusted-outbound-domain allowlist* `FUN_14038d2b0` — returns true iff the host
     suffix-matches one of 22 domains: `covenanteyes.com`, `.cvnt.net`, `helpmece.com`,
     `joinmece.com`, `remotece.com`, `bugsplat.com`, `cleanbrowsing.org`,
     `fastsupport.com`, `assets.cdngetgo.com`, `cdn.getgo.com`, `get.gotoassist.com`,
     `logmeincdn.azureedge.net`, `gstatic.com`, `googleapis.com`, `clients1.google.com`,
     `windowsupdate.com`, `geotrust.com`, `verisign.com`, `a.opmnstr.com`, `.stripe.com`,
     `stripe.network`, `api.bing.com` (matcher `FUN_14035a100`/`FUN_14038e220`; domain
     list block `0x1409c8090`–`0x1409c8400`, `fastsupport.com` `0x1409c8268`). It mixes CE's
     own domains with remote-support tooling (GoToAssist/LogMeIn/joinme/fastsupport),
     BugSplat, the DoH resolver and web-asset/payment hosts — [INFERENCE: gates URLs the
     local dashboard may open/redirect to or that support diagnostics may fetch; it is
     not on the API request path].

### 2. Auth

- **Credential store: SQLite table `api_credentials`** with columns
  `(user_key, user_secret, password, username)` — SQL
  ` SET user_key = ?, user_secret = ?, password = ? WHERE username = ?` (`0x1409b00a0`),
  ` (user_key, user_secret, password, username) VALUES (?, ?, ?, ?)` (`0x1409b00f0`),
  accessors `ApiCredentialsSqliteTable::get` (`0x1409aff28`) and
  `::checkUserCredentials` (`0x1409afff0`; errors
  `Failed to retrieve API credentials for username: ` `0x1409aff70`,
  `Failed to check credentials for user :` `0x1409affc8`). The table is not in the
  captured `ce-file` (`../02-artifacts/local-db.md`) → [INFERENCE: lives in the encrypted
  `ce-user-file` per-user container, `../02-artifacts/user-file.md`].
- **Transmission: HTTP Basic.** `AuthProvidedHttpClient<class CeUser>::communicate`
  (log tag `0x1409ac190`, `FUN_14022ef50`) attaches a `HttpBasicAuthCredentials` entity
  (constructor `FUN_140273870` → `FUN_1402734a0`, drawing two fields from the `CeUser`
  object at `+0x20`/`+0x40` — [INFERENCE: the key/secret pair]); the struct type
  `UserApiKeys` (RTTI `0x140ab4660`, name string `0x1409b0f38`) is that pair. libcurl
  renders it as `%sAuthorization: Basic %s` (`0x140898e98`). No bearer tokens, cookies or
  refresh tokens appear anywhere in the CE code regions (the `Bearer` string at
  `0x140898eb8` is generic curl).
- **How the UI gets the same credentials**: the loopback dashboard route
  `/local/user/:username:/keys.:doctype:` (`0x1409c0078`, handler `FUN_14034b240`)
  returns `{"result": {"records": {"basicAuthentication": {"secret": …, "key": …}},
  "meta": {"status": "Success", …}}}` (sample body `0x1409c00a0`) — i.e. the service hands
  the per-user key/secret to local consumers over `http://localhost:48867`.
  Cross-ref `../15-ui/signin-and-settings.md`: the UI's `AuthProvidedHttpClient<CeUser>`
  (`CE_BASIC`) writes `ce-file` `logins` at sign-in; the service consumes the same table.
- **Login/session rows**: `logins` rows are inserted `status='queued'` with `login_at`
  (SQL `0x1409af860`), closed with ` SET logout_at = ? WHERE username = ? AND logout_at IS
  NULL` (`0x1409af9e0`, writer `FUN_14025aeb0` — no static callers, [INFERENCE: invoked
  through a bound callback on session/logout events]). At service start,
  `resolve open logins` (`FUN_14024a5e0`, tag `0x1409ae5c8`, called from
  `Impl::start` `FUN_14020bea0`) closes rows left open by a crash/restart.
- **Logout (`USER_LOGOUT` 0x4c) → what backend call? None.** The user-event dispatcher
  `UserEventMessageQueueListener::operator()` (`FUN_14023a7a0`,
  `UserSettingsCache.cpp:0x4a`; code→name mapper `FUN_140239c10` maps
  `0x43 COLLECT_DEBUG_LOGS, 0x4c USER_LOGOUT, 0x4d SEND_METRICS, 0x51 QUIT,
  0x52 SET_WINDOWS_REGISTRY, 0x53 USER_SETTINGS_CHANGE, 0x54 SEND_TELEMETRY,
  0x55 UNKNOWN`; strings `0x1409adb08`–`0x1409adb50`) handles `case 0x4c:` by scheduling
  `checkForProxySwitch::<lambda_1>` only — local DNS-proxy state re-evaluation. There is
  **no logout/revoke endpoint in the binary** (the `/v…` string scan returns exactly 7
  paths). The remote effect of a logout is the next activity-log upload carrying
  `loginActivityRecord` rows whose `logout_at` was stamped locally.
- **Re-auth**: `ApiCredentialsSqliteTable::checkUserCredentials` exists in the service,
  but no refresh/re-login flow was found here (the sign-in round trip lives in the UI —
  `../15-ui/signin-and-settings.md`; its "removing bad credentials" handler is at
  `0x1408e05d0` in `VictoryShield.exe`).

### 3. Endpoint catalog

All URL path strings in the binary (exhaustive `/v[0-9]+/` string scan → 7 matches) plus
the local-server routes. Base `https://api.cvnt.net`. URI factories are small
path-concat functions (`FUN_140139ed0` appends the path to the base built by
`FUN_1401727b0`; `FUN_1401d8a80` builds the `Uri`).

| path | method | URI factory (path-string VA) | payload | purpose | trigger / API fn |
|---|---|---|---|---|---|
| `/v1/status/time` | GET `[INFERENCE]` | `FUN_140205ca0` (`0x1409a9d80`) | – | server clock sync; response parsed by `FUN_1401fdea0` ("get server time" `0x1409a9b00`) into a `zoned_time` | hourly `ServerTimeManager::sync` (`FUN_140275fe0`) |
| `/v1/status/ping` | GET `[INFERENCE]` | `FUN_1402061a0` (`0x1409a9dd0`) → `FUN_140355260` | – | API reachability check; `parse HTTP response from PING API` / `Invalid PING response from API` (`0x1409c6be0` block) | registered as a std::function callback (xrefs only from data `0x140afebd4`) `[INFERENCE: liveness pre-flight for the send queues]` |
| `/v2/user/{username}/report/activity_log.json` | POST | `FUN_140205f00` (`0x1409a9d90`; `{username}` substituted via `FUN_140205b20` + `CeUsername`) | `{"records":[…]}` / `{"activityRecords":[…]}` — typed activity records (§5) | **the accountability upload**: web/DNS activity, logins, circumventions, user switches, install reports | `ApiSendQueue::flush` (tag `0x1409c67c0`) + `UserBasedApiActivityLogger::{logActivity,sendLogsForUser,sendLogsForUserInBatches}` (`0x1409b2e90`–`0x1409b2f28`); URI users `FUN_140289880`, `FUN_140290de0` |
| `/v1/metrics` | POST | `FUN_140206b20` (`0x1409a9de0`) | JSON array of metric records (`ignored metrics records: wrong format (not an array or empty)` `0x1409c6870`) | upload `ce-file` `metrics` rollups (1-hour buckets) | `ApiSendMetricsQueue::flush` (`0x1409c6920`), driven by `sendQueuedMetrics` (`0x1409abf08`, "Attempting to send queued metrics.") and `SEND_METRICS` (0x4d) → "send metrics now" (`FUN_1402419f0`) |
| `/v1/logs/store` | POST | `FUN_140206660` (`0x1409a9df0`) | "event logging records" — per-call rows `(username, request, response, process, component, timestamp)` (`0x1409af5f0`) | upload the API request/response event log | `ApiSendLoggingQueue::flush` (`0x1409c69f0`, "flushing event logging send queue"), `sendQueuedLogs` (`FUN_140226db0`, "send queued logs to clientapi server") |
| `/v1/telemetry/store` | POST | `FUN_1402068c0` (`0x1409a9e00`) | telemetry records (`telemetry` table / `TelemetrySqliteTable` `0x1409afad0`; fields `client_type` `0x1409ab1a8`, `device_name` `0x1409ab320`) | upload device/telemetry counters | `sendTelemetryApi` (`0x1409b2888`) via `FUN_140285490`; `Impl::{sendTelemetryData,sendTelemetryDataNow}` (`0x1409ab3d0`/`0x1409aad98`); `SEND_TELEMETRY` (0x54) → `FUN_140146220` |
| `/v1/desktop_client_update` | POST `[INFERENCE]` | `FUN_140206400` (`0x1409a9e18`) | **the `getClientUpdate` request of `updater.md` §2** (`app_name`, `current_app_version`, `device_platform`, `device_os_version`, `branch_name`, `change_set`, `unique_device_id`, `device_cpu_architecture`, `ce_user_names`; response `payload.{recommendation,app_version,app_download_link,…}`) | update recommendation | daily (86,400 s) WinSparkle check hosted in the service; response hook `applyClientUpdateOverrides` `FUN_140387e70` (QA `OverrideFile`/`OverridePercentRank`/`OverrideUtcDateTime`, `unique_device_id` % 101 bucketing) |

Not part of the remote API (cited for completeness): `http://localhost:48867` dashboard
(routes `/internal/status/:username:` `0x1409c0028`, `/local/user/:username:/keys.:doctype:`
`0x1409c0078`, activity-page link `https://victory.covenanteyes.com/#/activity`
`0x1409c0b38`), `blocked.cvnt.net` (`0x1409985f8`, filter block page —
FilterEnforcementPass), and the DoH URL `https://dns.cleanbrowsing.org/doh/adult-filter`
(`0x1409aac38`). Per-user settings GETs `/v2/user/{u}.json` and
`/v2/user/{u}/filter/settings/dns.json` are built inside the shared settings layer (see
`../12-network/filter-surface.md`).

### 4. Upload lifecycle (outbox → API)

**Outbox state machine** (all SQL strings in `SqliteLibrary`; table semantics per
`../02-artifacts/local-db.md`). Event tables `logins`, `dns_activity`, `circumventions`,
`switch_users` are inserted **`'queued'`** (inserts `0x1409af860`, `0x1409afcb0`,
`0x1409b02a0`, `0x1409b0470`), then:

1. **claim** — ` SET status = 'sending', status_changed_at = DATETIME('now') WHERE …`
   (`0x1409ac400`), selecting
   ` WHERE status = 'queued' AND created_at <= DATETIME('now', '-' || ? || ' seconds') ORDER BY …`
   (`0x1409ac460`) — a row is only eligible once it is at least N seconds old
   ([INFERENCE: per-event-type debounce/quiet period]).
2. **mark sent** — ` SET status = 'sent' WHERE …` (`0x1409ac000`) after the API accepts
   the batch; sent rows are browsable
   ` WHERE status = 'sent' ORDER BY id DESC LIMIT ? OFFSET ?` (`0x1409ac048`) for the
   local dashboard.
3. **crash/retry recovery** — stale claims are re-queued:
   ` SET status = 'queued' WHERE …` (`0x1409b2d90`) picking
   ` WHERE status = 'sending' AND status_changed_at < DATETIME('now', '-' || ? || ' seconds') LIMIT ?`
   (`0x1409b2db0`).
4. **record validation before POST** — `ApiSendQueue::removeInvalidRecords`
   (`0x1409c6828`, "remove invalid records from API post", "found invalid record" with
   `webActivityRecord` markers `0x1409c6760`–`0x1409c6790`) drops malformed records
   instead of failing the batch.

**Metrics lifecycle** differs (matches the captured rows): a row is born `collecting`,
accumulates into `bucket_current`
(` SET fields = ?, utc_timestamp = ?, bucket_current = (UNIXEPOCH(DATETIME('now')) -
UNIXEPOCH(created_at)) WHERE username = ? AND metric_name = ? AND bucket_id = ? AND status = ?`
`0x1409aeba0`), then rolls `collecting → queued` when bucket age reaches the threshold
(` SET status = 'queued', … WHERE status = 'collecting' AND metric_name = ?
AND (UNIXEPOCH(DATETIME('now')) - UNIXEPOCH(created_at)) >= ?` `0x1409aeac0`), then
`sent` like the rest (select-by-key `0x1409ae9d0`).

**Batching**: `ApiActivityLoggingThread.cpp` (`0x1409abdd0`) hosts `sendQueuedLogs`
(`FUN_140226db0`, scope `:0x51` — logs "Attempting to send queued logs.", batch size
constant **100** handed to the flusher `FUN_14022a630`) and `sendQueuedMetrics`
(`0x1409abf08`). The activity-log side batches per user
(`UserBasedApiActivityLogger::sendLogsForUserInBatches`, "Batch sent for user '"
`0x1409b2f10` / "Batch failed to send for user '" `0x1409b2eb8` / "Batch saved for user '"
`0x1409b2c20`) using `sqlite::batchWithYield` (RTTI `0x140a9dc80`); a
`UserBasedNullActivityLogger` variant exists (`0x1409b2c38`–`0x1409b2cd8`,
`NullActivityLogger.cpp` `0x1409b2d10`) [INFERENCE: null-object when no user is signed in].

**Triggers**:
- periodic: `ApiActivityLoggingThread` (started from `Impl::start` `FUN_14020bea0`)
  flushes on its own cadence; telemetry/metrics flushes are timer- and event-driven.
- UI events (dispatcher `FUN_14023a7a0`): `SEND_METRICS` (0x4d) → immediate
  "send metrics now" (`FUN_1402419f0`); `SEND_TELEMETRY` (0x54) → immediate telemetry
  flush (`FUN_140146220`); `USER_SETTINGS_CHANGE` (0x53) → "update user settings cache"
  (`FUN_1402427b0`) which re-fetches `/v2/user/…` (FilterEnforcementPass);
  `USER_LOGOUT` (0x4c) → no network.
- service start: `Impl::start` ("starting local communication service") resolves open
  logins, starts the logging thread and the loopback HTTP server ("Starting http
  server").

**Server-driven throttling/backoff** (persisted across runs):
- response-driven: `telemetry records are throttled`,
  `sent event telemetry records with rate limit requested: `,
  `Resource is busy event telemetry records NOT accepted, backoff requested: `
  (`0x1409b2708`–`0x1409b2780`), and the identical trio for `event logging` records
  (`0x1409c69xx`–`0x1409c6axx`) — the API can answer with a rate-limit delay or
  "resource busy, back off".
- persisted in registry settings `ApiTelemetryStatus` / `ApiTelemetryResumeTime`
  (`0x14099cfb0`/`0x14099cf80`; writers
  `ce::sys::settings::api::setTelemetryApiResumeTime` `0x14099cff8`,
  `clearTelemetryResumeTime` `0x14099d050`) — a resume-not-before timestamp, matching the
  live registry (`../02-artifacts/logs.md`).

**The 601 s registry heartbeat (`LastTelemetryUpdateAt`)** — identified:
`Impl::updateTelemetryData` (`FUN_140210ec0`, `LocalCommService.cpp` line 0x193, log
strings `0x1409ab1d0`/`0x1409ab208`) is a local bookkeeping tick that
(a) runs `Impl::updateMetricsSql` (`FUN_14020e310`, "get Sql errors status" →
"Some SQL errors detected: " → `client_internal_error` metric with `error_type`
`SQL(Service)`, `error_description` `SQL Error <N>`, `error_count`),
(b) runs `Impl::updateMetricsCrashes` (`FUN_14020ee40`, "Recovering from service
crashes: " → `client_crash` metric with `crash_type` `GENERIC`, `crash_count`), and
(c) via `FUN_140215600` → `FUN_140211170` writes settings `LastTelemetryUpdateAt`
(`0x14099d2c0`) under log scope "set Telemetry update time" (`0x14099d2f0`, write through
`FUN_14017e1c0`). The scheduler is the self-rescheduling callback `FUN_14021a290`, which
returns the next delay as `60000 ms × (updateTelemetryData succeeded ? 10 : 1)` —
**600,000 ms steady-state, 60,000 ms retry** (`std::chrono::duration<int64,ratio<1,1000>>`
stored at `*param_2`). 600 s scheduled + ~1 s overhead = the **601.0 s** tick series
measured live (`../03-runtime/network-capture.md` §"Telemetry heartbeat cadence"). The
tick is **purely local** — zero packets at tick time (proven live), consistent with (c)
being a registry write. `LastTelemetryUploadAt` ("set Telemetry upload time" `0x14099d310`)
is written by a different function, `FUN_140211660` [INFERENCE: telemetry *upload*
completion], which is why it stayed frozen on the live box.

**Hourly `ServerTimeManager::sync` semantics** — identified:
`ServerTimeManager::sync(bool)` = `FUN_140275fe0` (tag `0x1409b1078`; class RTTI
`0x140ab8268`; ctor takes a `Maybe<zoned_time>()` fetcher + a tick function + an initial
`zoned_time` — RTTI `0x140a9e1b0`). It calls the fetcher at `this+0x40` (the
`/v1/status/time` request; response parsed by `FUN_1401fdea0` "get server time" into
`Maybe<zoned_time>`) and the clock at `this+0x80`:
- fetch ok → log `Server time update success` (`0x1409b1138`) and install a `Baseline`
  functor holding {server time, local ticks} (sync-lambda_1);
- fetch failed → log `Server time update failed, ` (`0x1409b1118`) + (`""` when the bool
  arg is true, `"not "` when false) + `falling back to system time`; when the bool arg is
  true it also logs `Server time fell back to system time` (`0x1409b1158`) and installs
  the system-clock Baseline (sync-lambda_2);
- the Baseline is committed under `Locked<Baseline, shared_mutex>` at `this+0x88`
  (`FUN_140276880`). Return value = server time was available.
So the manager keeps a **(server timestamp, local tick) anchor** and derives "server now"
from the local clock between syncs; the anchor is refreshed **hourly** (log cadence
median 3,600.7 s, `../02-artifacts/logs.md`). Callers: `FUN_140275cb0`
(`ServerTimeManager::{ctor}::<lambda_3_>`, `0x1409b10b8`), `FUN_1402769e0`,
`FUN_1401f47e0`; the exact 3,600 s scheduling constant is not yet pinned (Open
questions).

### 5. Payload formats

All payloads are JSON (JsonCpp — `Value@Json` RTTIs); responses are validated with
`HTTP response must have a JSON content type` (`0x1409a9c80`),
`HTTP response was not valid: status code ` (`0x1409a9c50`),
`api::translateHttpError` (`0x1409a9d48`).

**Activity records** (POST `/v2/user/{username}/report/activity_log.json`). Exactly five
typed record keys exist in the binary (exhaustive `^[a-zA-Z_]+Record$` scan):

| record key | string VA | source table | distinctive fields (column names, `../02-artifacts/local-db.md`) |
|---|---|---|---|
| `webActivityRecord` | `0x1409c6778` | `dns_activity` | `domain`, `process_id`, `process_name`, `ip`, `resolution_type`, `connection_type`, `resolution_datacenter`, `resolution_time_ms` |
| `loginActivityRecord` | `0x1409c7fa0` | `logins` | `login_at`, `logout_at`, `system_user_id`, `system_user_name` |
| `circumventionRecord` | `0x1409c7fb8` | `circumventions` | `interruption_type`, `app_name`, `app_window_title`, `device_id`, `timezone_offset` |
| `switchUserActivityRecord` | `0x1409c8000` | `switch_users` | `switch_from_username` `0x1409c8020`, `switch_to_username` `0x1409c7fd0`, `device_name`, `device_id` |
| `installActivityRecord` | `0x1409b2a80` | install report | `device_uuid` `0x1409b2a60`, `platform`, `platformVersion`, `architecture` (`0x1409b2a98`–`0x1409b2ad0`; log "reporting install") |

Envelope builders add a shared `client` block and timestamp — `FUN_14038b110` (xrefs to
`loginActivityRecord` ×5) writes
`{"<recordType>": {"client": {"architecture": "32"|"64", "platform": "Windows",
"platformVersion": <os version>, "version": "10.1.44"}, "timestamp": <formatted
CETime>}}`; shared key `utc_datetime_created` (`0x1409c7fe8`). Batch envelope keys:
`records` (`0x1409c6790`, `ApiSendQueue::flush`) and `activityRecords` (`0x1409b2a70`,
`ApiReportInstall.cpp` / `UserBasedApiActivityLogger`).
(`urlSafeUsername` is a UI-/classifier-side key — screenstate manifest,
`../10-classifier/capture-pipeline.md`; `ce_user_names` is the `getClientUpdate` request
key — `updater.md` §2. Neither appears in the comm service's upload payloads.)

**Metrics** (POST `/v1/metrics`): one record per `metrics` row — `username`,
`metric_name`, `bucket_id`, `tags`, `fields`, `utc_timestamp`, `bucket_size`,
`bucket_current` (column strings `0x1409ae948`–`0x1409aeb40`). Metric names
(`0x14099a2a8`–`0x14099a420`): `client_startup`, `client_api_success`,
`client_api_problem`, `client_network`, `client_crash`, `client_internal_error`,
`client_screenshot`, `client_block_page_success`/`_problem`,
`client_cleanbrowsing_success`/`_problem`, `client_pdl_http_success`/`_problem`,
`client_pdl_edi_problem`, `client_gui_interactions`, `client_user_experience`.
Tag/field keys: `client_component`, `client_version`, `device_cpu`, `device_id`,
`device_manufacturer`, `device_model`, `mac_address`, `user_id`, `startup_count`,
`startup_type`, `startup_classifier`, `client_pdl_version`, `client_pdl_bundle_version`,
`os_user_language`, `os_user_language_region`, `os_system_language`,
`os_system_language_region`, `os_user_regional_format`, `os_system_regional_format`,
`os_region`, `http_response_code`, `crash_type`, `crash_count`, `error_type`,
`error_description`, `error_count`, `experience_trigger`, `interaction_type`,
`experience_type`, `interaction_count`, `experience_count` (`0x1409a8970`–`0x1409a89e8`,
`0x1409aa900`–`0x1409aaa20`, `0x1409c62c0`–`0x1409c6370`, `0x14099a430`).

**Event logging** (POST `/v1/logs/store`): records shaped like the audit-table row
`(username, request, response, process, component, timestamp)` (`0x1409af5f0`) — request
and response bodies of API calls plus which process/component issued them.

**Telemetry** (POST `/v1/telemetry/store`): records from the `telemetry` table
(`TelemetrySqliteTable::get`/`zeroCounters` `0x1409afbc8`/`0x1409afb28`,
`TelemetryValue` RTTI `0x140ab27d0`), fields `client_type`, `device_name`.
[INFERENCE: device/telemetry counters, distinct from the `metrics` rollups.]

**Client update** (POST `/v1/desktop_client_update`): request/response format documented
in `updater.md` §2 (`getClientUpdate`, `payload.recommendation` now/later/none,
`payload.critical`, `app_download_link`, …).

### 6. Verdict: what Screen Accountability actually uploads (via this binary)

**Nothing visual. The comm service uploads no screenshot, thumbnail, image bytes, or
classifier scores — ever.** Evidence:

1. The complete activity-record vocabulary is the five JSON record keys of §5
   (exhaustive record-key string scan); there is no `screenActivityRecord`,
   `imageActivityRecord`, `score…`, `pdl…` record, or any manifest schema string in the
   binary. The only screen-ish strings are the **metric name** `client_screenshot`
   (`0x14099a2e8` — a counter of captures taken, [INFERENCE: incremented by the UI capture
   path into the shared `metrics` table]) and the tags `client_pdl_version` /
   `client_pdl_bundle_version` / `startup_classifier` (version/health metadata).
2. No image encoder or multipart/form-data builder exists here: `image/png`,
   `image/jpeg`, `.jpeg` (`0x140896570`–`0x1408965a8`) are libcurl's generic
   content-type table strings; no PNG/JPEG compressor, no `Content-Disposition`, no
   `uploadImageBatch`-style string is present in the comm service (that string lives in
   the installer/UI flush path — `updater.md` §6 step 4).
3. The screenstates themselves never reach this process: capture writes PNG `im<N>.dat` +
   `ss.dat` manifest files under `Classifier\<SID>\data\pdl\` and hands them to the local
   classifier via `PdlNotifyARE` (`../10-classifier/capture-pipeline.md`); scoring is
   local. If screen-derived data ever leaves the machine it goes through the
   classifier→client reverse channel's templated HTTP requests
   (`HttpRequestProcessor`, UI binary) — documented as posting **not** screenstates in
   `../10-classifier/capture-pipeline.md`; nothing in the comm service participates in
   that channel except recording `client_pdl_http_success`/`_problem` metrics.

So the remote "Screen Accountability" surface of the comm service is limited to
**aggregate counters** (`client_screenshot`, `client_pdl_*`) plus the account-level
activity records (web/login/circumvention) — while what the *backend* shows as screen
accountability must arrive via a path outside this binary [INFERENCE: the classifier's
templated HTTP channel or an unobserved server-side pipeline; see Open questions].

## Evidence

Addresses below are Ghidra VAs in `VictoryShieldCommService.exe` (base `0x140000000`)
unless another program is named. No functions were renamed.

- **Endpoint URI factories**: `FUN_140205ca0` `/v1/status/time`, `FUN_140205f00`
  `/v2/user/{username}/report/activity_log.json`, `FUN_1402061a0` `/v1/status/ping`,
  `FUN_140206400` `/v1/desktop_client_update`, `FUN_140206660` `/v1/logs/store`,
  `FUN_1402068c0` `/v1/telemetry/store`, `FUN_140206b20` `/v1/metrics`; path strings
  `0x1409a9d80`–`0x1409a9e18`; base builder `FUN_1401727b0` (xrefs to `api.cvnt.net`
  `0x14099cdd8`, `https://` `0x14099cda8`, `staging.api.cvnt.net` `0x14099cdc0`).
- **API layer**: `TelemetryTrackingHttpClient::communicate` `0x1409a92d0`,
  `addTagHostAndRoute` `0x1409a93c0`, `api::translateHttpError` `0x1409a9d48`,
  `curlCommunicate` RTTI `0x140a9bc50`, `communicate with CURL via HTTP to ` `0x1409a9890`;
  `HttpApiLibrary\src\Api{Telemetry,ReportInstall,SendQueue,SendMetricsQueue,SendLoggingQueue,ClientUpdate}.cpp`
  path strings `0x1409b2840`, `0x1409b2ae0`, `0x1409c67e0`, `0x1409c6940`, `0x1409c6a10`,
  `0x1409c7c10`.
- **Auth**: `ApiCredentialsSqliteTable::get` `0x1409aff28`, `::checkUserCredentials`
  `0x1409afff0`, SQL `0x1409b00a0`/`0x1409b00f0`, columns `user_key` `0x1409aed00`,
  `user_secret` `0x1409aff18`, `password` `0x1409affa8`, `api_credentials` `0x1409affb8`;
  `AuthProvidedHttpClient<class CeUser>::communicate` `0x1409ac190` (`FUN_14022ef50`),
  `HttpBasicAuthCredentials` ctor `FUN_140273870` (string `0x1409b0f58`),
  `UserApiKeys` `0x1409b0f38` (RTTI `0x140ab4660`); local keys route `0x1409c0078`
  (handler `FUN_14034b240`, sample `0x1409c00a0`); `logins` SQL `0x1409af860`,
  `0x1409af9e0` (`FUN_14025aeb0`), `0x1409afa20`; `resolve open logins` `FUN_14024a5e0`
  (tag `0x1409ae5c8`) from `Impl::start` `FUN_14020bea0`.
- **Dispatcher**: `UserEventMessageQueueListener::operator()` `FUN_14023a7a0`
  (`UserSettingsCache.cpp:0x4a`), name mapper `FUN_140239c10` (CeUserEventMessageQueue.h,
  `0x1409adb70`), event strings `SEND_METRICS` `0x1409adb08`, `SEND_TELEMETRY`
  `0x1409adb18`, `USER_LOGOUT` `0x1409adb28`, `USER_SETTINGS_CHANGE` `0x1409adb38`,
  `QUIT` `0x1409adb50`, `SET_WINDOWS_REGISTRY`, `COLLECT_DEBUG_LOGS`;
  handlers `FUN_1402419f0` (send metrics now), `FUN_140146220` (telemetry),
  `FUN_1402427b0` (update user settings cache).
- **Outbox SQL**: claim `0x1409ac400`/`0x1409ac460`, done `0x1409ac000`, browse
  `0x1409ac048`, requeue `0x1409b2d90`/`0x1409b2db0`; inserts `0x1409af860` (logins),
  `0x1409afcb0` (dns_activity), `0x1409b02a0` (circumventions), `0x1409b0470`
  (switch_users); metrics `0x1409ae9d0`/`0x1409aeac0`/`0x1409aeba0`; audit row
  `0x1409af5f0`.
- **Queues/loggers**: `ApiSendQueue::flush` `0x1409c67c0`, `::removeInvalidRecords`
  `0x1409c6828`, `ApiSendMetricsQueue::flush` `0x1409c6920`, `ApiSendLoggingQueue::flush`
  `0x1409c69f0`, `sendQueuedLogs` `FUN_140226db0` (`0x1409abdb8`),
  `sendQueuedMetrics` `0x1409abf08`, `ApiActivityLoggingThread.cpp` `0x1409abdd0`,
  `UserBasedApiActivityLogger::*` `0x1409b2e90`–`0x1409b2f28`,
  `UserBasedNullActivityLogger::*` `0x1409b2c38`–`0x1409b2cd8`, `activityRecords`
  `0x1409b2a70`, `records` `0x1409c6790`, record keys `0x1409b2a80`, `0x1409c6778`,
  `0x1409c7fa0`, `0x1409c7fb8`, `0x1409c8000`, `utc_datetime_created` `0x1409c7fe8`,
  `switch_from_username` `0x1409c8020`, `switch_to_username` `0x1409c7fd0`,
  `device_uuid` `0x1409b2a60`; record envelope builder `FUN_14038b110`.
- **Telemetry/heartbeat**: `sendTelemetry` `0x1409b2728`, `sendTelemetryApi`
  `0x1409b2888`, `api::safelySendLoggingAndTelemetry` `0x1409b28c0`, throttle/backoff
  strings `0x1409b2708`–`0x1409b2780`, `Impl::{updateTelemetryData,sendTelemetryData,sendTelemetryDataNow}`
  `0x1409ab1d0`/`0x1409ab3d0`/`0x1409aad98` (`FUN_140210ec0`/`FUN_140211660`/`FUN_14020ca50`),
  timestamp writers `FUN_140211170` ("set Telemetry update time" `0x14099d2f0`,
  `LastTelemetryUpdateAt` `0x14099d2c0`) and `FUN_140211660` ("set Telemetry upload
  time" `0x14099d310`, `LastTelemetryUploadAt` `0x14099d330`), scheduler
  `FUN_14021a290` (`60000 × {1,10}` ms), metrics maintenance `FUN_14020e310`
  (`Impl::updateMetricsSql`) / `FUN_14020ee40` (`Impl::updateMetricsCrashes`).
- **ServerTimeManager**: `FUN_140275fe0` (tag `0x1409b1078`, messages `0x1409b1118`,
  `0x1409b1138`, `0x1409b1158`), response parser `FUN_1401fdea0` ("get server time"
  `0x1409a9b00`), callers `FUN_140275cb0`, `FUN_1402769e0`, `FUN_1401f47e0`, Baseline
  commit `FUN_140276880`.
- **Allowlists**: updater allowlist strings `0x1409c6410`/`0x1409c6428` +
  `Untrusted download domain detected, ignoring: ` (same code as
  `VictoryShield.exe:FUN_14028f280`, see `updater.md` §2); outbound-domain matcher
  `FUN_14038d2b0` (domains `0x1409c8090`–`0x1409c8400`, `fastsupport.com` `0x1409c8268`).
- **Overrides**: `applyClientUpdateOverrides` `FUN_140387e70` (strings `0x1409c7e88`+
  `OverrideFile`/`OverridePercentRank`/`OverrideUtcDateTime`, `date_override`,
  `readJsonfile` `0x1409c7ee8`).
- **Live/log corroboration**: `../02-artifacts/logs.md` (hourly `ServerTimeManager::sync`,
  cadence table, registry telemetry values), `../03-runtime/network-capture.md`
  (601 s `LastTelemetryUpdateAt` series + zero-packet tick; `api.cvnt.net` = single
  endpoint), `../02-artifacts/local-db.md` (`metrics` rows match the §5 metric keys/tags;
  `collecting`/`sent` states match §4).

## Linux-reimplementation notes

- **One uploader, one outbox.** Keep CE's shape: event tables with
  `(status, status_changed_at, created_at)`, a claim step (`queued → sending`) with a
  minimum-age gate, mark-`sent` on server ack, and a stale-`sending` requeue sweep for
  crash recovery. Batch 100 rows per request, per-user batching for the activity log,
  and validate/drop malformed records before POST instead of failing the batch.
- **Endpoints**: one activity-log POST per user carrying typed JSON records
  (`web`/`login`/`circumvention`/`switch`/`install`) with a shared
  `client{arch,platform,platformVersion,version}` + `timestamp` envelope is a clean,
  extensible design — reuse it, but put the screen-accountability evidence you *do*
  choose to upload (e.g. flagged-window metadata) in a first-class record type so the
  policy is explicit in the schema.
- **Auth**: per-user API key/secret pairs in the local DB, sent as HTTP Basic over TLS;
  rotate/re-issue server-side rather than storing the account password (CE stores a
  `password` column — don't copy that). Expose the key to other local components only via
  a loopback socket with the same review bar as the network API (CE serves it on its
  dashboard port).
- **Clock**: keep a `(server_time, local_ticks)` baseline refreshed hourly from a
  `/status/time` endpoint with a system-time fallback; use it for all event timestamps so
  offline-tolerant uploads stay consistent server-side.
- **Telemetry pacing**: a purely local bookkeeping tick (CE: 600 s; faster retry (60 s)
  when the tick fails) that stamps `last_update_at` for health monitoring, separate from
  upload completion stamps; honor server-requested rate limits by persisting a
  `resume_at` timestamp (`ApiTelemetryResumeTime` analog) across restarts.
- **Trust**: CA-chain validation is fine; add real package signing (unlike CE's unused
  DSA wiring, `updater.md` §5). Keep a small, explicit outbound-domain allowlist for any
  link-opening/redirect surface, distinct from the update-download allowlist.
- **Self-metrics**: CE wraps every HTTP call in a tracking client that counts
  `client_api_success`/`client_api_problem` with host/route/status tags — cheap,
  useful; do the same.

## Open questions

1. **Which function posts the activity-log batch and with which envelope** (`records` vs
   `activityRecords`)? Both keys exist (`0x1409c6790` / `0x1409b2a70`) and the URI is used
   from two functions (`FUN_140289880`, `FUN_140290de0`) plus `reportInstall`
   (`FUN_140289000`, tag `0x1409b2b28`); the exact body of `reportInstall` (endpoint:
   activity_log vs `/v1/desktop_client_update`) was not decompiled.
2. **What is `/v1/status/ping`'s caller chain?** `FUN_140355260` has no static callers
   (std::function registration `0x140afebd4`); the pre-flight semantics are [INFERENCE].
3. **HTTP method per endpoint** is [INFERENCE] for `/v1/status/*` (assumed GET) and
   `/v1/desktop_client_update` (assumed POST with JSON body); the queue flushes are POST
   ("API post" wording, `remove invalid records from API post`).
4. **`ServerTimeManager` hourly constant** not located in code (only the log-derived
   3,600.7 s cadence); likewise the `ApiActivityLoggingThread` flush interval.
5. **`FUN_14025aeb0`** (`SET logout_at` writer) has zero static callers — who invokes it
   (bound callback vs. template instantiation) is unverified; likewise whether
   `USER_LOGOUT` closes the login row via that path or only at the next start
   (`resolve open logins`).
6. **`FUN_140211660`** ("set Telemetry upload time") is [INFERENCE] the telemetry upload
   completion path; its exact trigger is unverified (explains the live static
   `LastTelemetryUploadAt`).
7. **Screen Accountability verdict boundary**: this doc proves the *comm service* uploads
   no image data; whether the classifier's templated HTTP channel
   (`../10-classifier/capture-pipeline.md`) ever carries screen-derived metadata to CE
   servers is owned by that pass — final server-side screen-accountability pipeline
   remains [INFERENCE: out of this binary].
8. **`FUN_14038d2b0` allowlist consumer** is identified only as a domain matcher in the
   local-server/diagnostics region; the exact surface it gates (dashboard redirect vs.
   support-diagnostics fetch) is [INFERENCE].
