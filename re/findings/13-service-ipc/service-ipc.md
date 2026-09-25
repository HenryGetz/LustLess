# VictoryShieldCommService.exe — local IPC + state-store surface

Scope: the LOCAL side of `VictoryShieldCommService.exe` (22,545 fn, image base `0x140000000`):
the HTTP server on `127.0.0.1:48867`, the two Boost-style message queues (`ce_user_event_message_queue`,
`ce_service_event_message_queue`), the `ce-file` SQLite outbox writers, the `ce-user-file`
encrypted state container, and the session/user-state machinery (WTS session changes,
user-settings cache, SCM/service lifecycle). Complements `re/findings/00-baseline/VictoryShieldCommService.exe.md`
(metadata/imports), `re/findings/02-artifacts/local-db.md` (`ce-file` schema + outbox pattern),
`re/findings/02-artifacts/event-queue.md` (queue file layout) and `user-file.md` (entropy analysis),
`re/findings/02-artifacts/logs.md` (log tags/cadences), `re/findings/15-ui/*` (UI side of the queues,
`CE_SPYMapObj`, dashboard URL), `re/findings/14-watchdog/watchdog.md` (SCM custom commands 243/176).
Non-goals: backend upload protocol and DoH/filter enforcement (other passes).

All function names/addresses are Ghidra labels in program `VictoryShieldCommService.exe` unless
stated. Source-file/line pairs come from the binary's embedded boost-log record metadata
(`__FILE__`/`__LINE__` triples passed to the log constructors).

## What it does

The comm service is the machine-local hub of the client:

1. **Serves the local web dashboard** on `127.0.0.1:48867` (endpoint singleton built by
   `FUN_1401c3f90` from the string `http://localhost:48867` `0x1409a56f8` + host `127.0.0.1`;
   listen log `Starting service on ` `0x14099a4a8`). The tray "Go to dashboard" browser flow and
   the UI's own libcurl layer both target this server (UiPass).
2. **Consumes the UI→service command queue** `ce_user_event_message_queue` (10 slots × 256 B):
   `UserEventMessageQueueListener::operator ()` (`FUN_14023a7a0`, source
   `LocalCommService\src\UserSettingsCache.cpp`) receives one-byte-code messages and dispatches
   `COLLECT_DEBUG_LOGS(0x43)`, `USER_LOGOUT(0x4c)`, `SEND_METRICS(0x4d)`, `QUIT(0x51)`,
   `SET_WINDOWS_REGISTRY(0x52)`, `USER_SETTINGS_CHANGE(0x53)`, `SEND_TELEMETRY(0x54)`.
3. **Emits service→UI notifications** on `ce_service_event_message_queue` (10 slots × 512 B) via
   `ce::sendClientNotification` (`FUN_14024bf20`, source
   `LocalCommService\src\InterprocessCommunication.cpp`).
4. **Owns the local state stores**: every `ce-file` outbox table (`logins`, `metrics`,
   `dns_activity`, `circumventions`, `switch_users`) is INSERTed/UPDATEd by functions in this
   binary (state machine `collecting → queued → sending → sent`), and the settings/user state
   lives in `ce-user-file` — a **SQLCipher-encrypted SQLite database** whose passphrase is a
   statically embedded constant (crypto verdict in §5).
5. **Tracks sessions/users**: WTS session-change events arrive in the SCM handler
   (`LocalCommServiceAgent::serviceControlHandler`, log tag `0x140999820`); the service maintains
   a user-settings cache (`UserSettingsCache.cpp`) rebuilt from the DBs on `USER_SETTINGS_CHANGE`,
   and closes stale login rows at startup (`resolve open logins`).

## Mechanism

### 1. Local HTTP server on 127.0.0.1:48867

The server is a statically-linked **cpp-netlib** (`boost::network::http::async_server`, boost::asio
IOCP) instance inside the service. Startup chain: `run::<lambda_1>::operator ()` (`FUN_14014c540`,
logs `Starting service on ` `0x14099a4a8`) constructs the service Impl (`FUN_14020b260`, source
`LocalCommService\src\LocalCommService.cpp`; logs "created local communication service
implementation"), stores it in `DAT_140ae50a0`, then `StartServiceCtrlDispatcherW`; service body
`FUN_140145b70` → `serviceRun` (`FUN_140145730`) → `Impl::start` (`FUN_14020bea0`, logs
"Starting http server"/"Terminated http server", listen failure → `"Error listening on provided
port."` `0x1409ab7b0`) → cpp-netlib `server::listen` `FUN_14021b170`: resolver `FUN_14021dd80`
(`getaddrinfo` on host `localhost`, default port string `80` `0x1409ab56c` overridden by the
configured 48867 via `FUN_140146ae0`) → socket `FUN_140208f90` → bind `FUN_140207580` → listen
`FUN_1402078d0` → `async_accept` `FUN_140209420` (accept completion `FUN_140221910` allocates a
per-connection `async_connection` `FUN_14021ca30` (0x12d8 B), starts async read `FUN_140222320`,
and re-arms accept `FUN_140209600`). Request bytes are consumed by the cpp-netlib incremental
parser (`FUN_140220060` stages 2/4/0xe/0x15) in `async_connection::handle_read_data`
(`FUN_14021f6a0`); parse errors get the canned `HTTP/1.0 400 Bad Request …` response
(`FUN_140220c80`, str `0x1409aa3c0`). Threading = `boost::network::utils::basic_thread_pool` +
IOCP completion (server ctor `FUN_140217c10`) — pooled handlers, not thread-per-connection.
(AcceptEx IAT `0x140a7a968` has no direct xrefs because accept goes through boost::asio's
overlapped op [INFERENCE].)

**Dispatch.** `LocalServerHandler::operator()` (`FUN_14034d5b0`) truncates the request destination
at the first `:` (`0x14099db14`), branches on `method == "POST"` (`0x1409a8b04`): POST builds a
`post_request_handler` (`FUN_14034ce10`, reads `content-length`) + async body read (`FUN_14034e5a0`,
4 KiB chunks); everything else goes through `RoutedRequestsManager` (vftable `0x1409c0760`,
ctor `FUN_14034b3e0` registers the route table; `::get` `FUN_14034a3d0`, `::post` `FUN_14034a630`):
each registered handler's `match()` (vtable+0x18) tests the URI (request+0x58) against a cpp-netlib
route template (`:name:` captures extracted into the routed request, `FUN_140349ab0`, read via
`FUN_140233540`), then the handler's `get` (vtable+8) / `post` (vtable+0x10) builds the
`HttpResponse` (`FUN_140277dc0(response, status, HttpContent, MediaType, Charset UTF-8)`) and the
access line `METHOD:status uri` is logged (`FUN_140150d60`). No match → `DefaultNotFoundHandler`
`FUN_14034a230` → 404 `Not Found` (text/plain).

**Route table (complete; registered in `FUN_14034b3e0`):**

| Method | Path (string addr) | Handler (vftable) | Handler fn | Response |
|---|---|---|---|---|
| GET | `/` (`0x14099bad8`) | `ViewHomePageHandler` (`0x1409c0d70`) | `FUN_140354910` | 200 HTML "Dashboard" page (`withinSimplyStyledWebpage` `FUN_14037d220`; nav `FUN_140354410`) |
| GET | `/about` (`0x1409c0064`) | `ViewAboutPageHandler` (`0x1409c0620`) | vtable | 200 HTML "About" page |
| GET | `/antivirus` (`0x1409c0c78`) | `ViewAntivirusHandler` (`0x1409c5b88`) | vtable | 200 HTML antivirus status (WMI AV/FW/antispyware names, strings `0x1409c5900`–`0x1409c5ac8`) |
| GET, POST | `/settings/user/:user-id:` (`0x1409c0048`) | `SystemSettingsHandler` (`0x1409c0948`) | get `FUN_1403589f0`, post `FUN_140358a20` → `FUN_140356ff0` | 200 HTML "Advanced Configuration": checkboxes `no-remember-usernames`, `no-splash-screen`, `no-tray-icon`, `debug-logging`→`EnableDebugLogging`, `events-logging`→`DisableEventLogging`; POST reads form key `set` (`0x1409c1378`) and saves ("Your settings have been saved."); **401** "Unable to determine authorization" (`0x1409c13f0`) only when the local SystemUserID (`FUN_1401c84b0`) can't be resolved |
| GET | `/settings/dns/:id:` (`0x1409c5110`) | `ViewDnsSettingsHandler` | vtable | 200 HTML "Managed DNS Settings" page |
| GET | `/logs/` (`0x1409c006c`) | `ViewDnsActivityHandler` (ctor `FUN_14034b0f0`) | vtable | 200 HTML "Your DNS activity on this computer" |
| GET | `/internal/status/:username:` (`0x1409c0028`) | `UserStatsHandler` (`0x1409c04e8`) | `FUN_140359bd0` | 200 stats page (query arg `since`, else default; render via vtable+0x20) |
| GET | `/internal/command/:command:` (`0x1409c1068`) | `CommandHandler` (`0x1409c0e28`) | `FUN_140355e20` | 200 HTML "Internal Commands"; subcommand map (insert `FUN_1403556a0`): `requeue` = `RequeueWebCommand` (`FUN_140354e70`, "immediately requeues any logs that failed to send"), `test-api-connectivity` = `TestApiConnectivity` (`FUN_140355120`, "performs a test to determine current connectivity status to the Covenant Eyes API") |
| GET | `/local/user/:username:/keys.:doctype:` (`0x1409c0078`) | `UserKeyHandler` (`0x1409c04a8`) | `FUN_14034b240` | 200 `application/json` with a **hard-coded body**: `{"result":{"records":{"basicAuthentication":{"secret":"8d836c161f0a267ba4e392df30041acff36b401b","key":"9259e404154ca1016934d73428385ba75ce51f86"}},"meta":{"status":"Success","executionTime":"0:00:00.013136"}}` |
| GET | `/static/:resource:` (`0x1409c1788`) | `ResourceHandler` (`0x1409c1760`, ctor `FUN_14035b220`) | `FUN_14035b360` | 200 `text/css` for `local.css`; 404 text/plain otherwise |
| any | * (fallback) | `DefaultNotFoundHandler` (`0x1409c0858`) | `FUN_14034a230` | 404 `Not Found` (text/plain) |

Dashboard nav (`FUN_140354410`) links: `/settings/user/` ("Advanced configuration for this
computer"), external `https://victory.covenanteyes.com/#/activity` ("View Activity"),
`/internal/status/` ("Client Status"), `/antivirus`, plus `/settings/dns/` ("Managed DNS
Settings") and `/logs/` ("Your DNS activity on this computer") shown only when the registry value
`DnsProxyDisable` is absent (read via `FUN_14017b9c0`/`FUN_14016ec70`).

**Dashboard assets: embedded.** HTML is assembled at runtime from template strings in the EXE
(doctype/head + `<link rel="stylesheet" href="/static/local.css">` `0x1409c5f20`, header/logo/nav
`0x1409c5c70`, footer `0x1409c61f0`/`0x1409c6190`, per-page title e.g. "Dashboard") by
`withinSimplyStyledWebpage` (`FUN_14037d220`). CSS comes from a **Win32 resource**: the provider
`FUN_140159af0` accepts only the name `local.css` (qword compare) and does
`FindResourceA(NULL, id=0x65 /*101*/, "CSS")` → `LoadResource`/`LockResource`; media type
hard-coded `text`+`css`. No on-disk asset directory and no backend proxying exist.

**Authentication: NONE.** `RoutedRequestsManager` and `LocalServerHandler` never inspect headers;
the only 401 in the server (`FUN_140356ff0`) is "can't tell which Windows user is logged in", not
caller authentication. All `Authorization:`/`Cookie:`/`WWW-Authenticate` strings belong to the
statically-linked libcurl/OpenSSL client stack. Anything that can reach `127.0.0.1:48867` can
read the dashboard/DNS activity and **write** the computer's settings — and `/local/user/:u:/keys.:d:`
hands out the hard-coded `basicAuthentication` key/secret with no check.

**Who connects.** `VictoryShield.exe` (browser "Go to dashboard" + its libcurl layer per UiPass)
and the service itself (endpoint config `FUN_1401c3f90` → `FUN_14014d3f0`, self-client
[INFERENCE: internal self-check]). **Not** the classifier, `VSWD.exe`/`VSWD.dll`, `UWPApp.dll`,
`RestartVS*.exe`, or `vs-config.exe`: string sweeps for `48867|localhost|127.0.0.1` in those
programs return nothing (a stringless numeric-port construction can't be excluded by string
search [INFERENCE: unlikely]). Note the UI binary contains no local route path literals either —
its local requests are runtime-built/shared-code [INFERENCE]; it only carries the URL
`http://localhost:48867` (`VictoryShield.exe` `0x140a49f18`).

### 2. Message-queue IPC (`ce_user_event_message_queue` / `ce_service_event_message_queue`)

**Transport.** Both queues are CE's own fixed-slot message queues realized as memory-mapped files
in the per-version data directory (`C:\ProgramData\CovenantEyes\VictoryShieldv010.001.044\`,
file layout documented in `re/findings/02-artifacts/event-queue.md`: 256-byte superblock +
10 records of `8-byte length + N-byte payload`; N = 256 for the user queue, 512 for the service
queue). The service opens/maps a queue with `FUN_14027afb0` taking `(max_num_msg=10,
max_msg_size=0x100|0x200)` and pops/pushes with `FUN_14027a5d0`/`FUN_14027a4c0`; each operation
maps the file (`MapViewOfFile`, unmap+`CloseHandle` after every message). The parameters
`10 × 0x100` passed by the listener (`FUN_14023a7a0`) and `10 × 0x200` by the notifier
(`FUN_14024bf20`) exactly match the on-disk slot geometry of the two queue files (Boost.Interprocess
`message_queue` semantics — slot = `sizeof(size_type)` header + `max_msg_size` — over a mapped
file; the binary also carries boost's `interprocess\ipc\message_queue.hpp` path string `0x1409b16d0`).

**Wire format.** One message = **1 code byte + payload bytes**. The listener pops the message,
takes `code = (int)(char)msg[0]`, then `memmove`s the rest left by one (`FUN_14081c060`) to get
the payload string. Logs: `"Preparing to receive event message"` (`0x1409adf50`) →
`"Received event message: <NAME> with data <payload>"` (`0x1409adef8`) or
`"Received an unhandled message: <NAME>"` (`0x1409ade78`). The code→name map is
`FUN_140239c10` (enum in `CommonLibrary\inc\CeUserEventMessageQueue.h`, assert at line 0x35):

| code | name (string addr) | note |
|---|---|---|
| `0x43` | `COLLECT_DEBUG_LOGS` (`0x1409adc20`) | |
| `0x4c` | `USER_LOGOUT` (`0x1409adb28`) | |
| `0x4d` | `SEND_METRICS` (`0x1409adb08`) | |
| `0x51` | `QUIT` (`0x1409adb50`, 4-char) | |
| `0x52` | `SET_WINDOWS_REGISTRY` (`0x1409adc08`) | |
| `0x53` | `USER_SETTINGS_CHANGE` (`0x1409adb38`) | |
| `0x54` | `SEND_TELEMETRY` (`0x1409adb18`) | |
| `0x55` | `UNKNOWN` (7-char) | **also the "no message" sentinel** — see below |
| other | `UNRECOGNIZED: <n>` | assert(`false`) then label |

**0x55 identified:** in `FUN_14023a7a0` the receive result defaults to `iVar16 = 0x55` when the
pop returns an empty buffer (`if (local_1e0 != uStack_1d8)` gates the read of the real code), the
`"Received event message"` log is skipped for 0x55, and `case 0x55: break;` is a no-op. So 0x55
is the **poll/empty sentinel + "UNKNOWN" catch-all**: a UI-sent 0x55 and a timeout are both
no-ops. (This matches UiPass, where 0x55 is the default/"UNKNOWN" arm of the UI's send-side name
map and no code 0x55 sender is known.)

**Listener loop** (`FUN_14023a7a0`, tags `UserEventMessageQueueListener::operator ()`,
`::scheduleDnsProxyInitialState`, all from `LocalCommService\src\UserSettingsCache.cpp`): forever
{ log "Preparing to receive…"; map queue; pop message; if global stop-flag (`FUN_1403d1280`) →
log `"UserEventMessageQueueListener thread is terminating"` and exit; log receipt;
switch(code) }. Most handler bodies are wrapped in an interprocess lock pair
(`FUN_140395170`/`FUN_140395200`, error exits `FUN_140395110(5|6)`) around the shared cache/state
objects.

#### Queue-code → handler → side effects (complete table)

| code | handler (in `FUN_14023a7a0`) | side effects |
|---|---|---|
| `0x43` COLLECT_DEBUG_LOGS | `lambda_2` → `FUN_14023c0b0` (log tag `UserEventMessageQueueListener::()::<lambda_2>::()::<lambda_1>::operator ()`) | locks listener+0x108; logs `"Starting collection of debug logs"` (`0x1409adc88`); sends UI notification `"Diagnostics are being collected. This usually takes a few minutes."` via `ce::sendClientNotification` (`FUN_14024bf20`); records metric `collect_diagnostics_in_progress` (trigger `automatic`) via `FUN_14037d930`; **launches `vs-config.exe --collect-debug -lvs-config.log`** (`FUN_140196a90`; arg vector `0x1409add50`-area strings `--collect-debug`, `-lvs-config.log`, exe string `vs-config.exe`); after it returns logs `"Finished collection of debug logs"` (`0x1409addd0`), sends UI notification `"We've finished collecting diagnostics for you! The diagnostic bundle is placed on your Desktop."` (`0x1409add70`), metric `collect_diagnostics_complete` (`0x1409adc68`). Bundle contents are produced by vs-config (shared helpers name `debugLogs.zip` `0x140996d90`, `debugClassLogs.zip` `0x140996da0`, `debugDB.zip` `0x140996db8`, `zip.exe` `0x140996dd0`, filename map `FUN_1401348d0`; DB dumps gathered per table by `EntrySqliteLogGatherer<{Metrics,Circumvention,SwitchUser,Dns,Login}SqliteTable>::getLogs/resolveLogs` `0x1409ac0c8`–`0x1409ac3b8`) |
| `0x4c` USER_LOGOUT | lock `this+0x68`; schedule `scheduleCheckForProxySwitch::<lambda_1>` (vftable label; str `0x1409ae030`) | re-evaluates the DNS-proxy/filter switch after logout (proxy state lives in the filter pass's domain); same guard pattern as 0x4d/0x53 (`this+0xb4` lock word; `FUN_140395110(5)` on lock failure) |
| `0x4d` SEND_METRICS | `FUN_1402419f0(…, "send metrics now"` `0x1409aded0`) | gets the metrics manager (`FUN_1401e5c60`) and calls `FUN_1401e7400(mgr, 1)` = flush the metrics outbox immediately |
| `0x51` QUIT | lock `this+0x10`; if flag `*(char*)(this+0x60) != 0` → return (listener thread terminates); else log `"Ignoring quit message belonging to previous session"` (`0x1409ade98`) | **the service posts this to itself**: `FUN_14023cb50` sends `QUIT` with payload `"IgnoreMe"` on startup (see below); shutdown path logs `"send kill signal to User Event message queue listener"` (`0x1409ae0d8`, from `FUN_14023ca20`) |
| `0x52` SET_WINDOWS_REGISTRY | `FUN_140177960` = `ce::sys::settings::internal::setWindowsRegistry` (`CommonLibrary\src\CeSystemSettings.cpp` line 0x56b) | logs `"set Windows Registry settings: "` + payload, then `FUN_14017f270(payload)` parses/applies the registry-change request. Payload is the serialized settings text produced by the UI's `SET_WINDOWS_REGISTRY` sender [INFERENCE: same dump format as settings refresh] |
| `0x53` USER_SETTINGS_CHANGE | wraps payload string in a `CeUsername`-shaped object; `FUN_1402427b0(…, "update user settings cache")` → `FUN_14023e400`; then schedules `scheduleCheckForProxySwitch` | **rebuilds the user-settings cache** from the DBs (see §4); payload = the settings key/username, e.g. `kckt0717` (log line `Received event message: USER_SETTINGS_CHANGE with data kckt0717`, `re/findings/02-artifacts/logs.md`) |
| `0x54` SEND_TELEMETRY | `FUN_140146220` = `ce::local_comm_service::agent::sendTelemetryData` | calls the telemetry agent's virtual send-now (`DAT_140ae50a0+0x28`); logs `"sendTelemetryData() is called before initialization!"` if the agent singleton is missing, else `"Error sending telemetry from support diagnostics"` on failure (`0x140999d68`) |
| `0x55` | no-op (empty-poll sentinel / `UNKNOWN`) | |
| other | logs `"Received an unhandled message: <NAME>"` | none |

**Back-channel (service→UI)** — `ce::sendClientNotification` = `FUN_14024bf20`
(`LocalCommService\src\InterprocessCommunication.cpp` line 0x52): maps `ce_service_event_message_queue`
(10 × 0x200) and sends message **code 2, log label `NOTIFICATION`** with the payload string;
log line `"Sending (N) NOTIFICATION event message: <payload>"`. Retry: up to 2 outer attempts,
each with up to 6×100 ms sleeps (`ce::async::Thread::mkSleepFor<1000×1/1000>` lambda) between
pops; errors `"Unable to send Client message: retry limit exceeded"` / `"…queue retry limit
exceeded"` (the per-op error handler `FUN_14083a364` logs `"Unable to send Client message (N) …"`).
Observed payloads are human-readable notification texts (diagnostics start/finish above).
The only caller of `FUN_14024bf20` in the binary is the diagnostics handler `FUN_14023c0b0`
(2 call sites `0x14023c37e`, `0x14023c8a5`) [INFERENCE: other notification producers route
through it or the back-channel is used only for diagnostics progress in this build; the UI-side
listener (`ServiceEventMessageQueueListener`) is what displays them].

**Queue creation/priming.** `FUN_14023cb50` opens `ce_user_event_message_queue` with the same
(10, 0x100) geometry and **sends `QUIT`/"IgnoreMe"** into it (`FUN_14027a4c0`, 2 retries × 100 ms)
— a new service instance flushes/wakes any stale listener from a previous session (this is the
origin of the four `QUIT with data IgnoreMe` lines in `major-3600.log`). The consumer-side
"Unable to receive message:" error handler is `FUN_140837f18` (both error handlers take the queue
name via `FUN_14027a0f0`).

### 3. Payload / dump formats (`<UserInfo: …>`)

Queue payloads are opaque strings to the transport. Where structured, they are the **serializer
output of event/state objects** (vtable+8 per the UI-side `sendCommServiceNotification`, UiPass).
The service contains the `UserInfo` serializer `FUN_14027dda0` which emits exactly:

```
<UserInfo: first-name=<s> last-name=<s> user-id=<s> email=<s> active=yes|no panicked=yes|no
 self-override=yes|no accountability=yes|no filtering=yes|no screen-accountability=yes|no
 url-accountability=yes|no url-filtering=yes|no dns-filtering=yes|no>
```

(struct offsets: +0x10 first-name, +0x30 last-name, +0x50/+0x60 user-id, +0x70 email, flags at
+0x90 `active`, +0x91 `self-override`, +0x92 `panicked`, +0x93 `accountability`, +0x94 `filtering`,
+0x95 `screen-accountability`, +0x96 `url-accountability`, +0x97 `url-filtering`, +0x98
`dns-filtering`; closing `>` is `DAT_1409a9184`). `<UserInfo:` `0x1409b1a10`, `" first-name="`
`0x1409b1a00`. The service-side `UserInfo` type is constructed/copied by `FUN_140247130`,
`FUN_14023f400`, `FUN_140253680` (vtable `0x1409ad648`) — i.e. it flows through the settings
cache (`FUN_14023e400`). **No parser for the dump exists in the service** (xrefs of `<UserInfo:`
and ` first-name=` are the serializer only) — the dump is produced by the serializer for
logging/event payloads; the UI parses it (its `<CeUserSettings: >` sibling, str `0x140a3e760` in
`VictoryShield.exe`, is UI-binary-only; the service has no `CeUserSettings` string). For
`USER_SETTINGS_CHANGE` the observed payload is simply the settings key name (`kckt0717`), wrapped
into a `CeUsername`-vtable string object by the 0x53 handler.

### 4. State-store writers (`ce-file` outbox + settings cache)

All SQL is built as `"INSERT INTO " + table-name + columns-fragment` (`INSERT INTO ` `0x1409aec58`)
against `sqlite::` wrappers (vftables `sqlite::OrderedQueryParameters`, `sqlite::Connector`,
`sqlite::Table<…>`, `LogSqliteTable<…>`, `UsernameSqliteTable<…>`). Writers (one per table):

| table | INSERT writer | SQL fragment | initial status |
|---|---|---|---|
| `logins` | `FUN_14025a950` | `0x1409af860` — `(username, system_user_id, system_user_name, timestamp, login_at, logout_at, status, …) VALUES (?,?,?, ?, DATETIME('now'), NULL, 'queued', DATETIME('now'), DATETIME('now'))` (binds `SystemUserID`, `SystemUsername`, `CETime` from the entry) | `queued` |
| `dns_activity` | `FUN_14025f710` | `0x1409afcb0` — 10 bound params + `'queued'` | `queued` |
| `circumventions` | `FUN_140262af0` | `0x1409b02a0` — 7 bound params + `'queued'` | `queued` |
| `switch_users` | `FUN_1402651b0` | `0x1409b0470` — 8 bound params + `'queued'` | `queued` |
| `metrics` (open-bucket accumulate) | `FUN_14024f1e0` | `0x1409aeba0` — `UPDATE … SET fields = ?, utc_timestamp = ?, bucket_current = (UNIXEPOCH(DATETIME('now')) - UNIXEPOCH(created_at)) WHERE username = ? AND metric_name = ? AND bucket_id = ? AND status = ?` | row stays `collecting` |
| `metrics` (insert / bucket close) | insert: `FUN_14024d400` (log tag `MetricsSqliteTable::insertLog` `0x1409ae8f0`; siblings `update entry in metrics table` `0x1409ae9b0`, `finalize entry in metrics table` `0x1409aeb80`, `MetricsSqliteTable::getMetric` `0x1409aea20`); close: `FUN_14024efb0` | `0x1409aeac0` — `UPDATE … SET status = 'queued', status_changed_at = DATETIME('now'), bucket_current = ? WHERE status = 'collecting' AND metric_name = ? AND (UNIXEPOCH(DATETIME('now')) - UNIXEPOCH(created_at)) >= ?` | insert `collecting`; close `collecting → queued` |
| request/response trace table | `FUN_14025a0a0` | `0x1409af5f0` — `(username, request, response, process, component, timestamp, status, …) VALUES (?,?,?,?,?,?,'sent',DATETIME('now'),DATETIME('now'))` | `sent` at insert (support "HTTP Client Tracing" data; table not present in the captured `ce-file`) |

**Outbox state machine** (uniform `status`/`status_changed_at`/`created_at` triple):

```
insert ──► 'queued' ──► 'sending' ──► 'sent'
(metrics: 'collecting' ──(bucket full/age ≥ threshold)──► 'queued')
                     ▲
                     └── stale-'sending' requeue: WHERE status='sending' AND
                         status_changed_at < DATETIME('now','-'||?||' seconds') LIMIT ?
```

- `queued → sending` ("claim for upload"): ` SET status = 'sending', status_changed_at = DATETIME('now') WHERE ` (`0x1409ac400`) — 5 per-table functions `FUN_14028fa20`, `FUN_14028f1c0`, `FUN_14022f540`, `FUN_14028e960`, `FUN_14028e190`.
- `sending → sent` (upload ack): ` SET status = 'sent' WHERE ` (`0x1409ac000`) — 5 per-table functions `FUN_14022fb90`, `FUN_14022d2e0`, `FUN_14022ca40`, `FUN_14022bef0`, `FUN_14022b600`.
- stale-`sending` reaper (`0x1409b2db0`): `FUN_14028d980`, `FUN_14028dd30`, `FUN_14028d220`, `FUN_14028d5d0`.
- read-back of uploaded rows (` WHERE status = 'sent' ORDER BY id DESC LIMIT ? OFFSET ?`, `0x1409ac048`) for reporting.
- `EntrySqliteLogGatherer<{Metrics,Circumvention,SwitchUser,Dns,Login}SqliteTable>::getLogs/resolveLogs`
  (`0x1409ac0c8`–`0x1409ac3b8`) are the per-table gather/resolve pairs driving these transitions;
  `LoginSqliteLogGatherer`/`QueuedLoginSqliteLogGatherer`/`QueuedCircumventionSqliteLogGatherer`
  RTTI at `0x140ab41c8`–`0x140ab5700`. The uploader is `sendQueuedMetrics` (`FUN_140227d50`,
  log "Attempting to send queued metrics." `0x1409abee0` / "Done attempting to send queued
  metrics." `0x1409abf20`; related `Impl::updateMetricsSql` `0x1409ab0b8`,
  `Impl::updateMetricsCrashes` `0x1409ab238`). ("resolve open logins" = close login rows left open by a
  crash/restart — `FUN_14024ad20`, called from `performStartupResolution` `FUN_14024a5e0`,
  source `LocalCommService\src\StartupResolution.cpp`, alongside `deleteOldLogFiles`
  `FUN_14024aad0`.)

**User-settings cache (`UserSettingsCache.cpp`).** `USER_SETTINGS_CHANGE` → `FUN_1402427b0` →
`FUN_14023e400`, which rebuilds, for the `CeUsername` in the payload, the in-memory state from
both SQLite stores (connectors obtained via `this+0x198`/`this+0x1d8`):
`DnsFilter` object (`std::_Ref_count_obj2<DnsFilter>`, `FUN_140246ea0`) published by
`FUN_1402402d0`; a second store row set published by `FUN_140240a40`; `LoginSqliteTable` rows
(`LoginRecordStore`) published by `FUN_140240e40`; then it replaces the cached
`GlobalDomainOverridesSqliteTable` list (object+0x168) and per-user `CustomDomainOverridesSqliteTable`
list (object+0x178) under the interprocess mutex at object+8. Table-name strings `user_info`
(`0x1409aecb0`), `user_dns_filter` (`0x1409b0760`), `global_domain_overrides` (`0x1409b0710`),
`custom_domain_overrides` (`0x1409b07d0`) exist in the service but are **not** in the captured
`ce-file` schema — [INFERENCE] they live in `ce-user-file` (written by the UI's
`UserInfoSqliteTable::set`, service xref string `0x1409aeea0`; `user_dns_filter`/`user_info`
column strings match the UI-side tables of `re/findings/12-network/filter-surface.md`). Which of
the two connectors (`this+0x198`/`this+0x1d8`) is `ce-file` vs `ce-user-file` is [INFERENCE]
(the `LoginSqliteTable` read uses the second one). After the rebuild the same handler schedules
`scheduleCheckForProxySwitch` so the DNS-proxy state re-evaluates against the new settings.

### 5. `ce-user-file` — crypto verdict

**Verdict: `ce-user-file` is a SQLCipher-encrypted SQLite database (SQLCipher 4 amalgamation with
the OpenSSL provider), keyed with the hard-coded passphrase `AN0ther$uper$ecretKEY4This`,
stored in the binary XOR-obfuscated with a repeating 8-byte keystream.**

- SQLCipher is statically linked: `sqlite3_key: db=%p` (`0x140985228`, impl `FUN_14076d750`),
  `sqlite3_key_v2`, `sqlite3_rekey_v2` family (`0x140985240`–`0x140985478`),
  `SELECT sqlcipher_export('migrate');` (`0x1409871b8`),
  `sqlcipher_openssl_cipher: EVP_CipherUpdate returned %d` (`0x140988038`),
  `cipher_ctx_key_derive: deriving hmac key from encryption key using PBKDF2 with %d iterations`
  (`0x140986cc0`), plus full OpenSSL (EVP/SHA/HMAC/PBKDF2) and the SQLCipher error string
  `An error occurred with PRAGMA key or rekey…` (`0x14098a990`). Page size 4096 in the container
  matches SQLCipher defaults over a 4 KiB-page SQLite DB (AES-256-CBC per page + HMAC-SHA512
  page MAC + PBKDF2-HMAC-SHA512 key derivation = SQLCipher 4 defaults [INFERENCE: defaults not
  overridden — no `cipher_page_size`/`kdf_iter` strings found, and `PRAGMA rekey_cipher`/
  `rekey_kdf_iter` are the "no longer supported" stubs of SQLCipher 4]).
- Key source: `FUN_140256700` (the `ce-user-file` opener) copies a 27-byte constant blob to a
  static buffer `DAT_140ae9c98` and calls `FUN_140256570` exactly once to decode it in place,
  then `strlen`s it and hands the resulting string to the DB-open wrapper `FUN_140256490`
  (together with the resolved path of `ce-user-file`, name string `0x140996e30`).
  `FUN_140256570` XORs the buffer with the 8-byte keystream `83 ad c3 4b 1a 47 d6 f8`
  (= little-endian bytes of the immediate `0xf8d6471a4bc3ad83`, applied per byte
  `b[i] ^= (0xf8d6471a4bc3ad83 >> ((i&7)<<3)) & 0xff`; AVX2 loop for the first 24 bytes, scalar
  tail). Decoding the embedded blob
  `c2 e3 f3 3f 72 22 a4 dc f6 dd a6 39 3e 22 b5 8a e6 d9 88 0e 43 73 82 90 ea de c3` yields
  **`AN0ther$uper$ecretKEY4This`** + NUL (verified byte-by-byte).
- The `-shm`/`-wal` name strings `ce-user-file-shm`/`ce-user-file-wal` (`0x140996e00`/`0x140996e18`)
  confirm it is opened as a SQLite DB (WAL), and the observed file is uniformly high-entropy
  4 KiB pages (`re/findings/02-artifacts/user-file.md`) — exactly an encrypted page store.
- Readers/writers: settings cache `FUN_14023e400` (reads `user_info`-family + `DnsFilter` +
  `GlobalDomainOverridesSqliteTable` + `CustomDomainOverridesSqliteTable` + `LoginSqliteTable`
  via `sqlite::Connector`), UI-side `UserInfoSqliteTable::set` (service xref string `0x1409aeea0`),
  RTTI `UserInfoStore` `0x140aaff98`, `UsernameSqliteTable<UserInfoSqliteTableDefinition>`
  `0x140aaf540`, `Table<UserInfoSqliteTableDefinition>` `0x140aafec0`. `ce-file` by contrast is
  opened **without** a key (plaintext SQLite — `re/findings/02-artifacts/local-db.md`).

### 6. `CE_SPYMapObj` — service-side writer verdict

**The comm service never touches `CE_SPYMapObj`/`CE_SPYMutexObj`.** String sweeps of the binary
for `CE_SPYMapObj`, `CE_SPYMutexObj`, `ceFilterCheckReply`, and a case-insensitive `spy` return
no hits (only WMI "Anti-Spyware" strings `0x1409c5900`–`0x1409c5ac8`). The map is created/owned
by the UI (`VictoryShield.exe` `OnCreate`/`setGlobalUserState`, UiPass) and consumed by the
legacy filter components; the service's equivalent state lives in the user-settings cache +
`ce-user-file` (§4–5). [INFERENCE] The service influences the map only indirectly: UI code
re-publishes `setGlobalUserState` after queue events (e.g. `USER_SETTINGS_CHANGE` handling in the
UI) — there is no direct service write.

### 7. Session / user-state machinery

**SCM control handler.** `` `anonymous-namespace'::LocalCommServiceAgent::serviceControlHandler``
= `FUN_1401423d0` (source `LocalCommService\src\LocalCommServiceAgent.cpp`, log tag `0x140999820`;
entry log `"handling a control code for the local communication service: "`). Complete
control-code table (switch on the code; decompiled):

| SCM code | meaning | action (fn / log string) |
|---|---|---|
| 4 | `SERVICE_CONTROL_INTERROGATE` | return 0 |
| 5 | `SERVICE_CONTROL_SHUTDOWN` | logs `"handling a system shutdown command"`, falls through into the stop path |
| `0x80` (128) | custom **stop** | logs `"handling a user-defined stop command"` → `FUN_140140d90` (graceful service stop), return 0 |
| `0x0d` (13) | `SERVICE_CONTROL_POWEREVENT` | log-only: `"Ignoring power event: "` / `"Ignoring power settings change event GUID: "` |
| `0x0e` (14) | `SERVICE_CONTROL_SESSIONCHANGE` | **log-only** — see below |
| `0x82` (130) | custom | `"handling a user-defined stop DNS proxy command"` → `FUN_140140fe0` |
| `0x83` (131) | custom | `"handling a user-defined start DNS proxy command"` → `FUN_140141230` |
| `0x84` (132) | custom | `"handling a user-defined restart DNS proxy command"` → `FUN_140141480` |
| `0xb0` (176) | custom | `"handling a user-defined fail command"` → invokes `serviceControlHandler::<lambda_1>` (std::function target via `FUN_1401406b0`) [INFERENCE: a deliberate failure/crash hook for testing — the direct analog of VSWD's `OnCustomCommand(176)` = `Environment.Exit(3011)`, `re/findings/14-watchdog/watchdog.md`; the lambda body itself was not recovered], return 0 |
| default | — | `"Ignoring command: <n>"`, return `0x78` (120) |

**243/176 verdict:** the comm service implements **176 (0xb0)** (fail command) but **NOT 243
(0xf3)** — 243 (VSWD's "protections off + graceful stop") has no case in `FUN_1401423d0`; its
graceful-stop custom code is `0x80` (128). Its custom vocabulary is otherwise DNS-proxy
start/stop/restart (`0x82`/`0x83`/`0x84`) — consistent with the installer/admin tools driving the
legacy DNS-proxy component through the comm service.

**WTS session-change (0x0e) is observability-only.** The branch logs `Session change event: `
(`0x1409999b8`) with the event name — `WTS_SESSION_LOGON`, `WTS_SESSION_LOGOFF`,
`WTS_SESSION_LOCK`, `WTS_SESSION_UNLOCK`, `WTS_SESSION_TERMINATE` (CE's label for its fifth named
type; standard WTS types 1–8/0xA otherwise map to the ignore arm) — plus `" for session ID: N"`,
and everything else `"Ignoring session change event: <n> for session ID: <id>"` (`0x140999a60`).
No state function is called from the branch (decompile shows only boost-log plumbing between the
log calls): **the service records session transitions in its log and nothing else**; the operative
session gating (capture on/off) lives in the UI (`PdlEdi::setSessionOn`, UiPass) and the
logins/switch_users rows are produced through the settings-cache/login-store path (§4), not from
the WTS handler. Log evidence matches: `Session change event: WTS_SESSION_LOGON for session ID: 1`
plus LOCK×7/UNLOCK×6 in `major-3600.log` (`re/findings/02-artifacts/logs.md`).

**User-settings cache / `kckt0717`.** The cache rebuild is §4's `FUN_14023e400`. The
`USER_SETTINGS_CHANGE` payload is the **settings-key name** of the user whose settings changed —
on this VM `kckt0717` (log `Received event message: USER_SETTINGS_CHANGE with data kckt0717`),
which matches the legacy per-user registry key
`<SID>\SOFTWARE\Covenant Eyes\kckt0717` that the installer deletes as "legacy CE user registry
key" (`upgrade-126428.log`, `re/findings/02-artifacts/logs.md`). [INFERENCE] `kckt0717` is an
obfuscated per-user settings-key identifier that both sides use to name the settings blob; the
service's `CeUsername`-typed wrapper around the payload (0x53 handler) treats it as the user key
for cache lookups. The current settings rows themselves live in `ce-user-file` (`user_info` table
name string `0x1409aecb0`; `UserInfoSqliteTable::set` `0x1409aeea0`; `UserInfoStore` RTTI
`0x140aaff98`), while the legacy registry key is dead weight removed at upgrade.

**`logins`/`switch_users` producers.** The INSERT writers are `FUN_14025a950`/`FUN_1402651b0`
(§4), dispatched as virtual methods of `LoginSqliteTable`/`SwitchUserSqliteTable` (RTTI
`0x140ab2db0`, `0x1409ac258`). Their callers are vtable-mediated (slot refs `0x1409aa8a0`,
`0x140af6c6c`); the evidence-supported triggers are the settings-cache/login-store updates
(`LoginRecordStore` / `FUN_140240e40` publish path in `FUN_14023e400`) and the UI's
sign-in/switch-user flows (UiPass writes `logins` from the UI process too — `handleSuccessfulAuth`
→ `UserLoginSqliteTable`). The service closes rows left open across restarts via
`resolve open logins` (`FUN_14024ad20`, called from `performStartupResolution`) — i.e. `logins`
rows carry `login_at` at insert and get their `logout_at`/status resolved either by the logout
path or at next service start.

### 8. Startup / shutdown sequence

**Startup** (thread/task model):

1. `run::<lambda_1>::operator ()` `FUN_14014c540` (log `Starting service on 127.0.0.1:48867`):
   constructs the service Impl `FUN_14020b260` (0x348 B; "created local communication service
   implementation"; builds the endpoint config singleton `DAT_140ae9ac0` = (`http://localhost:48867`,
   `127.0.0.1`) via `FUN_1401c3f90`), then `StartServiceCtrlDispatcherW(serviceName =
   "VictoryShieldCommService", serviceMain = FUN_140145b70)`.
2. `FUN_140145b70` → `anonymous-namespace::serviceRun` `FUN_140145730` → Impl vtable+8 (blocking
   run) → `Impl::start` `FUN_14020bea0` (`LocalCommService\src\LocalCommService.cpp` line 0x49;
   logs "starting local communication service", "Starting http server" … "Terminated http server").
3. `performStartupResolution` `FUN_14024a5e0` (`LocalCommService\src\StartupResolution.cpp`):
   `resolve open logins` `FUN_14024ad20`, then `deleteOldLogFiles` `FUN_14024aad0`.
4. User-queue priming + listener: `FUN_14023cb50` sends `QUIT`/`"IgnoreMe"` into
   `ce_user_event_message_queue` (flush stale listener), then the
   `UserEventMessageQueueListener` thread runs `FUN_14023a7a0` (§2). Its shutdown is flag-driven
   (`FUN_1403d1280` stop check → "UserEventMessageQueueListener thread is terminating") and it
   also honours `QUIT` messages; the service-side kill signal is sent from `FUN_14023ca20`
   ("send kill signal to User Event message queue listener").
5. Periodic/background workers (evidence in `re/findings/02-artifacts/logs.md` +
   this pass): metrics accumulator/uploader (`MetricsSqliteTable::insertLog` `FUN_14024d400`,
   `sendQueuedMetrics` `FUN_140227d50`, "increment startup metrics" `0x14099a468`), telemetry
   (`ce::local_comm_service::agent::sendTelemetryData` `FUN_140146220`), hourly
   `ServerTimeManager::sync`, daily WinSparkle appcast (updater pass), DNS-proxy monitor threads
   ("DNS Proxy Monitor adapters", 60 s "Removing DNS servers (start)" loop — filter pass's domain).
6. Crash-kill switch: `FUN_140219ec0` reads registry value `ForceCrashCommService` (`0x14099cd78`);
   if set it clears the value and raises a deliberate crash ("Forced crash", non-returning
   `FUN_1403e6780`) — a self-test hook consumed through vtable slots (`0x1409aa678`, `0x140af4e18`).

**Shutdown:** SCM `SHUTDOWN`/custom `0x80` → `FUN_140140d90` (graceful stop; the UI also receives
its own shutdown cues — `QUIT` semantics on the service queue terminate the UI per UiPass); the
queue listener is killed via `FUN_14023ca20` and exits on the stop flag or a session-scoped `QUIT`.
Custom `0xb0` (176) is the deliberate-fail hook (§7).

## Evidence

All addresses are in `VictoryShieldCommService.exe` (Ghidra project `CE`, program open,
read-only) unless noted. Decompiled this pass: `FUN_14023a7a0` (queue listener + switch),
`FUN_140239c10` (code→name), `FUN_14023cb50` (startup QUIT/IgnoreMe send), `FUN_14023c0b0`
(0x43 handler), `FUN_140177960` (0x52 handler), `FUN_1402427b0` + `FUN_14023e400` (0x53 handler →
settings cache rebuild), `FUN_1402419f0` (0x4d), `FUN_140146220` (0x54), `FUN_14024bf20`
(`ce::sendClientNotification`), `FUN_140837f18`/`FUN_14083a364` (queue error handlers),
`FUN_140256700`/`FUN_140256570`/`FUN_140256490` (ce-user-file key + open),
`FUN_14025a950` (logins INSERT), `FUN_14027dda0` (`UserInfo` serializer),
`FUN_14024a5e0` (`performStartupResolution`), `FUN_1401423d0`
(`LocalCommServiceAgent::serviceControlHandler` — full control-code switch),
`FUN_140219ec0` (`ForceCrashCommService` switch), plus (HTTP slice) `FUN_14020b260`/`FUN_14020bea0`
(Impl ctor/start), `FUN_14021b170` (cpp-netlib listen), `FUN_140221910` (accept completion),
`FUN_14021f6a0`/`FUN_140220060` (connection read/parse), `FUN_14034d5b0`
(`LocalServerHandler::operator()`), `FUN_14034a3d0`/`FUN_14034a630` (`RoutedRequestsManager::get/post`),
`FUN_14034b3e0` (route table ctor), handler fns `FUN_140354910`, `FUN_140356ff0`, `FUN_140355e20`,
`FUN_14034b240`, `FUN_14035b360`, `FUN_14034a230`, resource provider `FUN_140159af0`.

Key string addresses: `http://localhost:48867` `0x1409a56f8`; `ce_user_event_message_queue`
`0x1409b1518`; `ce_service_event_message_queue` `0x1409b21a0`; queue names/log strings
`0x1409adef8`/`0x1409ade78`/`0x1409adf50`/`0x1409ae0d8`/`0x1409ade98`; code names
`0x1409adb08`–`0x1409adc20`; task reasons `0x1409aded0` ("send metrics now"),
`0x1409ab390` ("send telemetry data"), `0x1409b27e8` ("send telemetry to clientapi server");
SQL fragments `0x1409ac000`, `0x1409ac048`, `0x1409ac400`, `0x1409aeac0`, `0x1409aeba0`,
`0x1409af5f0`, `0x1409af860`, `0x1409afcb0`, `0x1409b02a0`, `0x1409b0470`, `0x1409b2db0`;
`ce-file`/`ce-user-file` names `0x140996dd8`–`0x140996e30`; SQLCipher strings
`0x140985228`–`0x140985478`, `0x140986cc0`, `0x1409871b8`, `0x140988038`, `0x14098a990`;
diagnostics strings `0x140996d90`–`0x140996dd0`, `0x1409adc20`–`0x1409addd0`, `0x140999d68`.

Cross-checks: queue file layout `re/findings/02-artifacts/event-queue.md`; `ce-file` schema and
`collecting`/`sent` rows `re/findings/02-artifacts/local-db.md`; `ce-user-file` entropy
`re/findings/02-artifacts/user-file.md`; log lines (`QUIT with data IgnoreMe`,
`USER_SETTINGS_CHANGE with data kckt0717`, `USER_LOGOUT with data LogoutEvent`,
`Starting service on 127.0.0.1:48867`, `Session change event: WTS_SESSION_LOGON for session ID: 1`)
`re/findings/02-artifacts/logs.md`; UI-side senders/vocabulary `re/findings/15-ui/*`.

## Linux-reimplementation notes

- Two fixed-capacity queues over a mapped file are replaceable by one Unix domain socket pair (or
  two) with a 1-byte code + payload framing; keep the tiny vocabulary
  (`COLLECT_DEBUG_LOGS/USER_LOGOUT/SEND_METRICS/QUIT/SET_WINDOWS_REGISTRY/USER_SETTINGS_CHANGE/
  SEND_TELEMETRY`) and the "unknown code → log and ignore" behavior. Keep a distinct no-op
  sentinel (CE's 0x55) or use explicit timeouts.
- The outbox state machine (`collecting → queued → sending → sent` with `status_changed_at`
  aging to requeue stuck `sending` rows) is the valuable part: replicate it with a single
  `claim ... WHERE status='queued'` + heartbeat timestamp + reclaim job; keep event inserts
  single-statement and offline-capable.
- Do NOT copy the key management: a hardcoded passphrase in the binary protects nothing against
  a local attacker. For LustLess use OS keyring/kernel keyring or per-install keys with 0600
  permissions; encryption at rest is fine (SQLCipher itself is a reasonable choice), but derive
  the key from something the user holds.
- The "new instance pings the queue with QUIT/IgnoreMe at startup" trick is a cheap way to reset
  stale IPC state across service restarts — keep it (or use SO_PEERCRED + connection lifecycle).
- Diagnostics collection delegated to a separate helper process (`vs-config.exe --collect-debug`)
  with progress notifications over IPC is a good shape: the privileged service doesn't have to
  contain the messy collection logic.

## Open questions

1. HTTP side residuals: the exact URI paths the UI's libcurl layer requests on 48867 (no path
   literals in `VictoryShield.exe`); why `LocalServerHandler` truncates the request destination
   at the first `:` before route matching (`FUN_14034d5b0`); behavior for HTTP methods other than
   GET/POST (only get/post dispatchers exist) [INFERENCE: 404]; `UserStatsHandler` render output
   format (vtable+0x20); `RequeueWebCommand`/`TestApiConnectivity` run bodies; whether the
   48867 listener has any OS-level ACL beyond the 127.0.0.1 bind [INFERENCE: loopback-only by
   name resolution of `localhost`].
2. The `0xb0` (176) "user-defined fail command" lambda body (`serviceControlHandler::<lambda_1>`)
   was not recovered — only its invocation; exact failure semantics (exit code? deliberate
   crash?) [INFERENCE: VSWD-style hard-fail] remain open. Likewise the `0x82`/`0x83`/`0x84`
   DNS-proxy command bodies (`FUN_140140fe0`/`FUN_140141230`/`FUN_140141480`) are cited but their
   internals belong to the filter pass.
3. The `metrics` INSERT statement literal is assembled from `INSERT INTO ` + column strings rather
   than one blob; the writer is pinned by its log tag (`MetricsSqliteTable::insertLog`,
   `FUN_14024d400`) but the exact INSERT text was not extracted.
4. Callers of the per-table writer virtuals are vtable-dispatched (logins writer slot referenced
   only from vtable `0x1409aa8a0`/`0x140af6c6c`); the precise trigger points (which component
   calls `logins` insert on sign-in inside the service) were not traced call-by-call.
5. The request/response trace table (`username, request, response, process, component, …`,
   insert `0x1409af5f0`, `FUN_14025a0a0`) has no table-name literal captured and is absent from
   the captured `ce-file` — where it lives (ce-file vs ce-user-file) and its consumer [INFERENCE:
   the "HTTP Client Tracing" support toggle].
6. Whether any code path sends service-event-queue messages other than `NOTIFICATION` (code 2) —
   only `ce::sendClientNotification` was found; the UI's `QUIT`-terminates-UI behavior (UiPass)
   suggests at least one more producer or a code mapping not visible in this binary.
7. SQLCipher settings beyond defaults (e.g. explicit `cipher_hmac_algorithm`) not observed; the
   keying call site (`sqlite3_key` wrapper) sits inside the generic table-open path and was not
   decompiled end-to-end — the passphrase and codec family are proven, the exact open sequence
   is [INFERENCE].
