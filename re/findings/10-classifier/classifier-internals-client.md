# Classifier→client channel — transport, record shapes, UI signal, backend reach (client side)

Scope: how classifier output reaches the CE client — answered from the **receiving** side:
`VictoryShield.exe` (the capture client / "PDL-EDI" owner, 27,191 fn, image base `0x140000000`)
and `VictoryShieldCommService.exe` (22,545 fn). The classifier binary
(`VictoryShieldClassifier.exe`) is consulted only for bounded negatives and for cross-checks that
pin the channel's other endpoint (classifier pass:
`classifier-internals-classifier.md`). Complements `capture-pipeline.md` §2 (the reverse-channel
file table this pass resolves), `13-service-ipc/service-ipc.md` §1–§2, `15-ui/ui-architecture.md`
§4, `16-updater/upload-protocol.md` §6. Non-goals: scoring/model internals, bundle format,
classifier-side sysCalls (classifier pass).

All function names/addresses are Ghidra labels in program `VictoryShield.exe` unless another
program is named; string VAs are PE-section-mapped against `re/samples/00-baseline/`.

## TL;DR verdicts

1. **Transport = file transactions + named kernel events, nothing else.** The classifier imports
   **no socket, pipe, or HTTP API at all** (PE import scan, §1); its only channel to the client is
   folders under `C:\ProgramData\CovenantEyes\Classifier\<SID>\data\client\<epoch-ms>\` plus the
   wakeup events `ClientNotifyARE`/`ClientNotifyProcARE`. The "templated HTTP reverse channel" of
   `91-linux-mapping.md` §2 is **confirmed** — and refined: the classifier does not speak HTTP; it
   writes *request templates* (`ht.dat`) that `VictoryShield.exe` executes with its own libcurl and
   answers with `hr.dat` response transactions.
2. **Exactly two classifier→client record types are accepted**: `ht.dat` (HTTP request template →
   `HttpRequestProcessor`) and `cs.dat` (current-state/versions → `CurrentStateProcessor`). Router,
   parse sites, and payload fields in §2.
3. **No classifier score ever reaches the UI.** The tray-menu string "*N* screenshots analyzed in
   the last 60 minutes" is fed by the client's own `screenshot_telemetry` **capture counter** in
   `ce-file`, gated on the `has_screen_accountability` policy flag (§3). Scores go classifier→backend
   only, via the reverse channel (§4).
4. **What reaches the comm-service upload path** from the screen-accountability domain is metrics
   and health aggregates only (`client_screenshot`, `client_pdl_version`,
   `client_pdl_bundle_version`, `client_pdl_http_success`/`_problem`, `client_pdl_edi_problem`) —
   `upload-protocol.md` §6 ("no scores/images ever") **stands**, and its "unobserved server-side
   pipeline" alternative resolves: the backend-visible score signal rides the reverse channel,
   executed by the UI process, outside the comm service entirely (§4).

## What it does (orientation)

`VictoryShield.exe` owns both directions of the PDL-EDI file channel: it *produces* screenstate
transactions in `data\pdl\<ts>\{imN.dat, ss.dat, rr.dat}` (proven in `capture-pipeline.md` §2) and
it *consumes* classifier messages from `data\client\<epoch-ms>\`, via the
`ce::pdledi::PdlMessageEngine` (source `PdlMessageEngine.cpp`). Two processors consume the two
accepted record types; one of them (`HttpRequestProcessor`) is a general-purpose **HTTP proxy**:
the classifier hands it fully-formed requests (URL, method, headers, body, auth strategy,
retry policy), the client executes them against the backend with the signed-in user's credentials
and hands the response back as a new transaction folder. The classifier therefore never needs a
network stack — and, per its import table, never got one.

## 1. Transport — VERDICT: file transactions + named events (bounded negative on every alternative)

### 1a. The channel, positively stated

| Direction | artifact | writer → reader | wakeup |
|---|---|---|---|
| classifier → client | folder `…\Classifier\<SID>\data\client\<epoch-ms>\` containing `ht.dat` or `cs.dat` + `rr.dat` (0-byte ready marker) + an optional `re4*.dat` retention token | classifier `ce::FileUtils::createResponseFolder`/`markFolderReady` (classifier pass: `FUN_141991880`/`FUN_1419921d0`) → client `PdlMessageEngine::processFolder` (`FUN_1402eb9a0`, log `"PDL-EDI: Processing ready folder "` `0x1408e0d40`) | classifier `notifyClient` signals named event `ClientNotifyARE`; the client's periodic task `check PDL notifications` (thunk `FUN_1402d6c10`, task table `.rdata 0x1408dfe00` region) waits on `ClientNotifyARE`/`ClientNotifyProcARE` (strings `0x1408dfa48`/`0x1408dfa58`) in `PdlEdi::handlePdlNotifications`, then runs `PdlMessageEngine::processMessages` (`FUN_1402ec3a0`, called from `FUN_1402da730` in the PdlEdi notification path) |
| client → classifier | folder `…\data\pdl\<ts>\` with `hr.dat` (HTTP response, writer `ce::pdledi::createHttpResponseTransaction` `FUN_1402ea860` per `capture-pipeline.md` §2), plus the already-proven `ss.dat`/`su.dat`/`pc.dat` records | client → classifier (classifier-side readers are the pass's scope) | client signals `PdlNotifyARE` (name `0x140a42378`, accessor `FUN_1401adc20`; notify `FUN_1402dd170`) |

Readiness/poison predicates on the client side (both proven by decompilation — they build the
literal filename and test existence):
- `FUN_1401aba50(folder)` — "does `<folder>\rr.dat` exist" (string `rr.dat` built inline);
- `FUN_1401ace80(folder)` — "does `<folder>\dd.dat` exist";
- `processFolder` proceeds **iff `rr.dat` present and `dd.dat` absent** (decompiled control flow of
  `FUN_1402eb9a0`; matches classifier-side `isFolderReady`, classifier pass);
- `dd.dat` is a **done/poison marker written by the client itself** when a folder fails processing:
  `FUN_1401acbe0(folder)` opens `std::ofstream <folder>\dd.dat` (decompiled; called from the
  `processFolder` tail at `0x1402ec348` after the `Invalid` outcome), so the folder is skipped by
  all later scans;
- `re4*.dat` is **not** a readiness signal but a retention token: the literal wildcard
  `re4*.dat` appears once in the binary (`0x140a42288`), consumed by
  `SystemPath::filePatternExists` = `FUN_1401abb50` (`FindFirstFileW` glob, scope
  `"SystemPath::filePatternExists"`, `CommonLibrary\src\SystemPath.cpp` line 0xbf, logs
  `"checking to see if file with pattern exists at "`/`"File pattern could not be found"`) —
  sole caller `PdlEdi::cleanFolders` (`FUN_1402d7820`, classifier pass cross-check): startup GC
  deletes aged/`dd.dat` folders but **retains** folders that still have `rr.dat` or match
  `re4*.dat`. The creator of `re4*.dat` files is unproven (the classifier binary contains no `re4`
  literal) — see Open questions.

### 1b. Bounded negative — every candidate mechanism checked

| mechanism | verdict | evidence |
|---|---|---|
| **Classifier sockets** | **impossible** | PE import table of `VictoryShieldClassifier.exe` (parsed locally from `re/samples/00-baseline/`): **no `WS2_32.dll`, no `WINHTTP.dll`, no `wininet.dll`, no `WSA*`/`socket`/`connect`/`send`/`recv` import anywhere**. Its only KERNEL32 file imports are `CreateFile{A,W}`, `CreateFileMapping{A,W}`, `MapViewOfFile`, `Flush/UnmapViewOfFile`; USER32 contributes only `SendMessageA` |
| **Classifier named pipes** | **impossible** | no `CreateNamedPipe*`/`ConnectNamedPipe` import; no `\\.\pipe` string (full ASCII sweep). The `\\.\pipe\boost_process_auto_pipe_` + `CreateNamedPipeA` + `PeekNamedPipe` strings/imports in `VictoryShield.exe` and `VictoryShieldCommService.exe` are statically-linked **boost::process stdio plumbing** (anonymous-pipe emulation for child-process handles; RTTI `boost::process::windows::detail::async_pipe`), not an IPC surface |
| **Classifier → 127.0.0.1:48867** | **impossible + disproven at the server** | the classifier has no `48867`, `localhost` (only a bare `localhost/` URL-parser residue), or `127.0.0.1` string (sweep) and no socket API to reach it with; the comm service's route table (`service-ipc.md` §1) contains no classifier-facing route, and its only loopback listener is the cpp-netlib server on `127.0.0.1:48867` (`listen FUN_1402078d0`, `async_accept FUN_140209420` — documented there) |
| **Classifier shared memory** | **not a payload channel** | the classifier does import `CreateFileMappingW`/`MapViewOfFile` [INFERENCE: mapping its own model/bundle/data files; no cross-process object name involving the client is derivable]. On the client side the only file mapping is `CE_SPYMapObj` (`ui-architecture.md` §4b) — a 0x50AF8-B policy block written by the UI and carrying flags/username, never classifier payloads (its full initialized layout is enumerated in `ui-architecture.md` §4b) |
| **Message queues (`ce_*_event_message_queue`)** | **not used** | the queues carry only the 8-byte-code UI↔service vocabulary `0x43..0x55` (`service-ipc.md` §2); no screenstate/message payload path exists; the classifier neither imports the queue machinery nor references the queue names |
| **Comm service** | **no classifier surface at all** | string sweeps of `VictoryShieldCommService.exe` for the PDL transaction vocabulary (`ht.dat`/`cs.dat`/`rr.dat`/`PdlNotifyARE`/`data\client`) are negative; its classifier-adjacent content is metric-name constants only (§4) |

So the classifier↔client transport is **files + two named events**, and the classifier is
structurally incapable of any other channel. (The classifier imports `SendMessageA` [INFERENCE:
unused OpenCV/library residue; no client-side `WM_COPYDATA`-style receiver exists in the PdlEdi
path].)

## 2. Record shapes accepted from the classifier (client-side parse sites)

### 2a. Router — `PdlMessageEngine`

`processMessages` (`FUN_1402ec3a0`) enumerates ready folders under the classifier's `data\client\`
tree (directory iteration `FUN_14013fd70`/`FUN_1402cfc40`/`FUN_1401ad890`) and calls
`processFolder` (`FUN_1402eb9a0`) per folder. `processFolder` (readiness gate above) then asks the
**processor generator** `FUN_1402ece10` for a handler: it iterates the folder's directory entries
and dispatches on the **exact filename** (decompiled `memcmp` against `PTR_s_ht_dat_140b29b68` /
`PTR_s_cs_dat_140b29b40`):

| file in folder | processor constructed | ctor | object size |
|---|---|---|---|
| `ht.dat` | `ce::pdledi::HttpRequestProcessor` | `FUN_1402e2320` | 0x78 B |
| `cs.dat` | `ce::pdledi::CurrentStateProcessor` | `FUN_1402ce190` | 0x78 B |
| anything else | none → log `"Message processor could not be generated for "` + folder; folder left in place | — | — |

The processor's `processMessage` (vtable+8) returns 0/1/2 = `MessageGenerated` / `NotGenerated` /
`Invalid` (logged as `"Returning: "` in `processMessages`); `Invalid` → `dd.dat` written, folder
poisoned. `" folder is not a directory"` handles non-directory entries.

### 2b. `cs.dat` — current-state record (`CurrentStateProcessor::processMessage`, `FUN_1402ce450`)

Reads `<folder>\cs.dat` (open `FUN_14017fc40`, read-all `FUN_1401ad400`), parses JSON
(`FUN_140220e60`; parse failure → `"Failed to parse cs.dat"` → `Invalid`), validates
(`"Failed to load/validate cs.dat"` → `Invalid`), then consumes two keys:

| key (string VA) | consumed as | lands in |
|---|---|---|
| `versions` (`0x1408def38`) | PDL version string; logged `"PDL version: "` (`0x1408def68`) | cache file **`version.pdl`** (written via `FUN_1402c7110(handle,"version.pdl",value)` with handle from `FUN_1402b2f30`; [INFERENCE: file/cache writer]) |
| `bundle` (`0x1408def44`) | bundle version string; logged `"PDL bundle version: "` (`0x1408def50`) | cache file **`version.bundle`** (same call pair) |

The two strings are read back from the PdlEdi singleton (`FUN_1402d8f50`) by the periodic
`update telemetry data` task `FUN_1402b0d00`, which records them as metrics
`client_pdl_version` (`0x1408db4b0`) and `client_pdl_bundle_version` (`0x1408db4c8`) into the
**`ce-file` `metrics` table** via the recorder `FUN_14014eeb0` (alongside `os_region`,
`os_system_language`, …) — this task uses the same connector as §3 (`*(view+0x3a8)`).
`processMessage` also calls `FUN_1401ac720(folder)` before parsing (pp.dat-area helper from the
`capture-pipeline.md` §2 table; exact role [INFERENCE]).

### 2c. `ht.dat` — HTTP request record (`HttpRequestProcessor::processMessage`, `FUN_1402e49f0`)

Reads `<folder>\ht.dat`, JSON-parses (failure → `Invalid`), then decodes a **fully-formed HTTP
request template** (all keys as strings in `PdlHttpRequestProcessor.cpp` scope `0x1408e0360`–
`0x1408e0c58`; the identical key set exists in the classifier binary — correlation below):

| field (client string VA) | semantics (proven in `FUN_1402e49f0` unless noted) |
|---|---|
| method | mapped by a thread-init static table to 0..3 = `GET`/`POST`/`PUT`/`DELETE` (`FUN_1402de340` entries, strings `0x140a4d8f0`/`0x140a4d8f4`/`0x140a4d908`/`"DELETE"`); unknown → `"Invalid method is requested"` → `Invalid` |
| `authStrategy` (`0x1408e0978`) | `CE_BASIC` (`0x1408e08c8`) = sign in with the user's `api_credentials` key/secret; `NO_AUTH` (`0x1408e08d8`); missing keys → `"No user keys found for requested authentication"`; unknown → `"Unknown Auth strategy: "` |
| `requestHeaders` (`0x1408e0a08`) | header list applied to the request |
| `requestBody` (`0x1408e04d8`) | request body, post-substitution |
| `requestBodyReplacementStrings` (`0x1408e0a38`) | template substitution table; engine `replaceValues`/`substituteStrings` (`0x1408e06a8`/`0x1408e0740`) with client-side providers: current usernames (`"get user names for pdl update"` `0x1408e0818`), device id (`"Device ID is not available"` `0x1408e0838`), `DEVICE_PLATFORM_STRING`/`DEVICE_VERSION_FAMILY_STRING`/`DEVICE_UNIQUE_ID_STRING` (`0x1408e0308`–`0x1408e0340`); errors `"replaceValues error: Missing replacement for "` (+ array variant), `"Replacement string value is empty!"`, `"Unsupported replacement type detected: "` |
| `requestFriendlyName` (`0x1408e09d0`) | human-readable request label (log `"…"`; invalid → `"Invalid request friendly name"`) |
| `retryPolicy` (`0x1408e03f0`) / `retryWindowSeconds` (`0x1408e0400`) | `"decode retry policy from JSON"`; the computed backoff is `100<<n` s for `n<10` previous attempts else `(n−9)·86400` s (decompiled); `stateTransitions` (`0x1408e08b0`) state is re-scheduled on the PdlEdi singleton (`FUN_1402d8dd0` → `FUN_1402d7f80`) |
| `progressive` (`0x1408e03e0`) | boolean compared during retry decision (`FUN_14013a650`) |
| `responseRawOutputFilename` (`0x1408e0a18`) | alternate filename for the raw response payload inside the response transaction |

Execution: `processGetRequest`/`processPostRequest`/`processPutRequest`/`processDelRequest`
(scopes `0x1408e0438`–`0x1408e0538`; logs `"execute GET for user '<u>'"` etc.) drive the client's
authenticated libcurl layer (`AuthProvidedHttpClient<class CeUser>::communicate`, scope
`0x1408e5210`) — the same HTTP stack the UI uses for backend API and for `localhost:48867`
(`ui-architecture.md` §4d). Response handling `processResponse` (`0x1408e0620`) classifies
`"A recoverable http error occured: "` vs `"An unrecoverable http error occured: "`;
authentication failure invokes `checkForBadAuthentication` (`0x1408e0590`) →
`"Failed to establish authenticated connection, removing bad credentials for <user>"` (the
classifier's requests can therefore **invalidate the stored user credentials**).
The result is written back for the classifier via `ce::pdledi::createPdlHttpResponseJsonfile`
(`0x1408e0be0`): a **`hr.dat`** transaction with schema `./http_response_schema.json`
(`0x1408e0bb8`), `schemaVersion "2.0.0"` (`0x1408e0bd4`) and keys:

| key (string VA) | content |
|---|---|
| `finalHttpStatusCode` (`0x1408e0c10`) | HTTP status of the executed request |
| `responseBody` (`0x1408e0c48`) | raw response body (plus optional `responseRawOutputFilename` payload; IO errors logged `"Unexpected file IO error: "` `0x1408e0c28`) |

Health bookkeeping recorded by this processor into the `ce-file` metrics (names also present as
string constants; recording sites per `capture-pipeline.md` §5):
`client_pdl_http_success` / `client_pdl_http_problem` / `client_pdl_edi_problem`
(`0x140a4d9c0`–`0x140a4d9f0`).

**Cross-correlation (channel purpose).** `VictoryShieldClassifier.exe` contains the byte-identical
JSON key set (`method`, `authStrategy`, `requestBody`, `requestFriendlyName`, `requestHeaders`,
`responseRawOutputFilename`, `retryPolicy`, `retryWindowSeconds`, `progressive`) and generates
`ht.dat` templates in its BundleManager: `generateUpdateCheckRequest`
(classifier `FUN_1418948e0`) targets `https://api.cvnt.net/v1/desktop_client_update` (staging
variant on `staging.api.cvnt.net`), `schemaVersion 2.1.0`, `requestHeaders[0] =
{x-correlation-id, uuid4}`, body `{app_name "PDL Bundle", current_app_version, …}` (classifier
pass). **Score batches** do not have a statically-recoverable template: the classifier's
`uploadVictoryChannel`/`uploadExperimentalChannel` run inside a server-delivered TypeScript bundle
(`"…TS returned error: "` strings; invoked native-side by `processBatches.cpp` `FUN_141867230` with
`{minimumBatchAgeBeforeUploadSeconds}`); the JS calls native `sysCalls::getBatchItems`
(`pdlEventDrivenInterface\pdl-edi\sysCalls\getBatchItems.cpp`; its Json::Exception/PdlException
catch blocks `FUN_14281c0a0`/`FUN_14281c2f0` own the `"Unable to add item from batch to http
upload"` strings and set `errorMessage`; batch keys `batchFolders`/`batchName`/`batchFiles`/
`batchItems`/`itemNames`, cluster `0x142a1ab30`–`0x142a1ada0` — classifier pass), which pulls
scored batch items from `FileBatchStorage` into an "http upload" structure. The classifier has no
way to send them itself — so they necessarily exit as `ht.dat` requests executed by the client
[INFERENCE: strong — `ht.dat` is the only HTTP-request record type the client accepts from the
classifier, and the classifier has no network API]. The observed host set supports this: the only
Covenant Eyes endpoint anywhere in DNS/ETW/pcap state is `api.cvnt.net`
(`03-runtime/network-capture.md` verdict 1).

### 2d. Where classifier output does **not** land

No classifier record is written to any `ce-file` outbox table (`logins`, `dns_activity`,
`circumventions`, `switch_users`, `metrics`, `install_metadata` — captured schema,
`re/samples/data/ce-file`); no score table exists in either state store; `cs.dat`/`ht.dat`
payloads survive only in the classifier's own folders and in the metrics aggregates of §4.

## 3. Score→UI flow — VERDICT: no scores in the UI; the "analyzed" counter counts captures

The tray/context-menu status line is assembled per update by:

1. **Formatter** `FUN_1402c9d50(sink, noun, window, count)` → `"<count> <noun>[s] analyzed in the
   last <window> minute[s]"`, or the sink is fed `"Analyzing..."` (`0x1408dc5a0`) when
   `count == 0` or `window < 1`. Fragments: `" analyzed in the last "` (`0x1408dc580`),
   `" minute"` (`0x1408dc598`), singular/plural `"s"` toggles. (There is no hour variant: the only
   call site passes the fixed window `0x3c` = 60.)
2. **Menu updater** `FUN_1402b72c0(view, ccui)` (an MFC-style CCmdUI handler: vtable+0x18 =
   SetText, vtable+0 = Enable): gated on `FUN_14020ad70()` — which locks `CE_SPYMutexObj` and
   reads `map+0x50AE4` of `CE_SPYMapObj`, i.e. the **`has_screen_accountability`** service flag
   (offset map: `12-network/filter-surface.md` §3d) — reads the counter at **`view+0x4f8`**,
   noun `"screenshot"`, window 60. If the gate is off or the count is empty it clears the item and
   removes menu item **ID 0x8033** via `FUN_1402c6490` (`RemoveMenu` walk, decompiled).
   Sibling updater `FUN_1402b6fd0` renders the companion label `"Screen Accountability"`/
   `"Internet Accountability"` (`0x1408dc538`/`0x1408dc550`) from the same gate.
3. **Counter lifecycle.** `view+0x4f8` is zeroed in the view constructor (`FUN_1402aba30`,
   `VictoryShieldView.cpp` line 0x1e1; the `PdlEdi` singleton pointer sits at `view+0x4f0`,
   `FUN_1402d8dd0`). It is refreshed by the periodic task thunk `FUN_1402b8490` (task-table entry
   `.rdata 0x1408dda80`) → `FUN_1402cba10` (log scope `"record screenshot telemetry"`
   `0x1408dc5c0`; gate re-checked; `now = (int)unix_time()`, `since = now − 0xe10 /*3600 s*/`) →
   wrapper `FUN_1402aafd0` → `FUN_1402b1fd0`: takes the **`ce-file` connector** from
   `*(view+0x3a8)` (a subobject of the ce-file store constructed at `view+0x330` by
   `FUN_14013f840`, which opens the literal string `"ce-file"`), resolves the current username
   (`FUN_1402bece0`), runs `ScreenshotTelemetrySqliteTable::getCountForUserSince` and atomically
   stores the result into `view+0x4f8` via `XCHG qword ptr [RAX],RBX` at `0x1402b214e`
   (disassembly; the "LOCK/UNLOCK" pseudocode).
4. **The data source is a capture counter, not scores.** `screenshot_telemetry` is a `ce-file`
   table (this closes `90-architecture.md` Open question 6 for this table: the store ctor
   `FUN_14013f840` opens `ce-file` and the same `view+0x3a8` connector feeds the metrics
   recorder of §2b); schema `(username, time_stamp, time_stamp_utc)` and the three SQL wrappers
   (string cluster `0x140a3d708`–`0x140a3d928`):

   | method | SQL | site |
   |---|---|---|
   | `setCountForUser` | `INSERT OR IGNORE INTO screenshot_telemetry (username, time_stamp, time_stamp_utc) VALUES (?,?,?)` | `FUN_14014c0f0` |
   | `trimCountForUser` | `DELETE FROM screenshot_telemetry WHERE time_stamp < ? AND username = ?;` | `FUN_14014c3c0` |
   | `getCountForUserSince` | `SELECT COUNT(*) AS count FROM screenshot_telemetry WHERE username = ? AND time_stamp >= ? AND time_stamp <= ?` | `FUN_14014c620` |

   Rows are inserted by the **capture-side tick**: PdlEdi task thunk `FUN_1402d6f90` (task table
   `.rdata 0x1408dfeb0`, log `"update screenshot telemetry database count for user "`) →
   wrapper `FUN_1402d0d40` → worker `FUN_1402d33c0`, which sleeps a jittered
   `((timestamp & 0x1f) + 30)` s (`FUN_140136cc0` duration + `FUN_140213200` wait), inserts one
   row, then trims rows older than the threshold held at `PdlEdi+0x84` (value not pinned). So one
   row = one capture tick (nominal `imageScreenshotInterval_sec`, jittered — `capture-pipeline.md`
   §1), i.e. the menu shows "**N** screenshots **captured** in the last 60 minutes", phrased as
   "analyzed". Consistent negative from the classifier pass: the classifier binary contains zero
   "Analyzed" strings (80,801-string sweep), and no UI code path parses a score value of any kind
   — there is no score consumer in `VictoryShield.exe` (the `cs.dat`/`ht.dat` payloads never touch
   UI state; §2d).

## 4. Backend reach — what classifier-derived data hits the comm-service upload path

Two distinct egresses exist, and only one of them is the comm service:

1. **The reverse channel itself (outside the comm service).** Classifier score batches
   (`uploadVictoryChannel`/`uploadExperimentalChannel`, classifier pass) leave the machine as
   `ht.dat` requests executed by `VictoryShield.exe`'s own libcurl against the templated URL
   (bundle-manager requests proven: `https://api.cvnt.net/v1/desktop_client_update`;
   score-batch URL lives in the server-delivered TS bundle — [INFERENCE] `api.cvnt.net`, the only
   CE host ever observed in DNS/ETW/pcap, `03-runtime/network-capture.md`). The comm service does
   not participate except as the credential owner (`api_credentials` in `ce-user-file`; the
   `CE_BASIC` auth of §2c presents those credentials).
2. **Through the comm-service outbox (aggregates only).** The UI records classifier-adjacent
   metrics into the shared `ce-file` `metrics` table; the comm service flushes metrics rows
   (`sendQueuedMetrics`, `service-ipc.md` §4). The screen-accountability metric set is:
   `client_screenshot` (capture counter — name constants in **both** binaries, `0x140a4da68` /
   comm-service `0x14099a2e8`), `client_pdl_version` / `client_pdl_bundle_version` (§2b),
   `client_pdl_http_success` / `client_pdl_http_problem` / `client_pdl_edi_problem` (§2c),
   `startup_classifier` (comm service only). No score value, image byte, or screenstate field
   appears in any outbox record type (`upload-protocol.md` §5/§6 exhaustive record-key scan; the
   captured `re/samples/data/ce-file` metrics rows are all `client_component=service` because
   Screen Accountability was never active in that window). **Verdict: `upload-protocol.md` §6
   remains correct; what it left as "…or an unobserved server-side pipeline" is the reverse
   channel above.**

## Linux mapping implications (verdict on `91-linux-mapping.md` §2)

The `[INFERENCE]` "CE's backend-visible screen accountability signal arrives … plausibly the
classifier's templated HTTP reverse channel" is **CONFIRMED**, with three refinements the Linux
design should carry:

- The reverse channel is **not** classifier-originated HTTP; it is a **file-mediated request
  proxy**: classifier writes request templates (URL/method/headers/body/auth/retry) into a spool
  directory, the daemon-side component executes them and spools responses back. A Linux
  `lustlessd` should own exactly this proxy role (the CE executor is the *UI* process, which
  LustLess merges into the daemon); `SO_PEERCRED`/0600 spool dirs replace the implicit same-user
  ACLs.
- The classifier process needs **no network stack whatsoever** — a property worth keeping
  verbatim (CE enforced it by import table, not convention).
- Score-upload destinations are **server-delivered configuration** (the TS bundle), not compiled
  constants; only the bundle-manager endpoints are static. A Linux reimplementation should treat
  the score-ingest URL as config, and keep the comm-service-style outbox for the aggregate
  metrics only (the split that makes `upload-protocol.md` §6's privacy model true by
  construction).
- The tray "analyzed" counter ports as a capture counter (`screenshot_telemetry`-style table +
  60-minute `COUNT(*)`), gated on the policy flag — not as a score display.

## Evidence

- Ghidra MCP (program `VictoryShield.exe`), decompiled: `FUN_1402eb9a0` (`PdlMessageEngine::
  processFolder`, readiness polarity + `"PDL-EDI: Processing ready folder "`), `FUN_1402ec3a0`
  (`processMessages`, folder loop + `MessageGenerated/NotGenerated/Invalid` logging), `FUN_1402ece10`
  (filename router; `ht.dat`/`cs.dat` ctor dispatch), `FUN_1402ce450`
  (`CurrentStateProcessor::processMessage`, `versions`/`bundle` → `version.pdl`/`version.bundle`),
  `FUN_1402e49f0` (`HttpRequestProcessor::processMessage`, method map, retry math, auth,
  `progressive`, bad-auth credential removal, `createPdlHttpResponseJsonfile`),
  `FUN_1401aba50`/`FUN_1401ace80`/`FUN_1401acbe0` (rr.dat exists / dd.dat exists / dd.dat writer),
  `FUN_1401abb50` (`SystemPath::filePatternExists("re4*.dat")`), `FUN_1402c9d50` (label formatter),
  `FUN_1402b72c0`/`FUN_1402b6fd0` (menu updaters), `FUN_14020ad70` (gate → `map+0x50ae4`),
  `FUN_1402b1fd0` (count refresh; `XCHG` store at `0x1402b214e`), `FUN_1402cba10` (`record
  screenshot telemetry`, since=now−3600), `FUN_1402b8490` (task thunk, entry `.rdata 0x1408dda80`),
  `FUN_1402d33c0`/`FUN_1402d6f90` (capture tick: jittered insert+trim), `FUN_14014c0f0`/
  `FUN_14014c3c0`/`FUN_14014c620` (screenshot_telemetry SQL), `FUN_1402b0d00` (pdl-version metrics),
  `FUN_14013f840` (ce-file store ctor at `view+0x330`), `FUN_1402aba30` (view ctor: `view+0x4f0`
  PdlEdi, `view+0x4f8`=0), disassembly of `FUN_1402b1fd0` (atomic store), `FUN_1402c6490`
  (`RemoveMenu` id 0x8033).
- Import-table parse (local PE, `re/samples/00-baseline/`): classifier has no WS2_32/WinHTTP/
  WinInet/pipe imports; `CreateNamedPipeA`+`\\.\pipe\boost_process_auto_pipe_` in UI/service =
  boost::process stdio.
- String VAs (`VictoryShield.exe`): message-engine/processor scopes `0x1408dee00`–`0x1408e0d40`;
  menu label cluster `0x1408dc538`–`0x1408dc6c0`; screenshot_telemetry cluster
  `0x140a3d708`–`0x140a3d928`; file vocabulary `0x140a4226c`–`0x140a422d8`;
  metric names `0x1408db4b0`/`0x1408db4c8`/`0x140a4d9c0`–`0x140a4d9f0`/`0x140a4da68`.
- Captured artifacts: `re/samples/data/ce-file` (schema/metrics query), stale folder
  `data\client\1789880113031\{ht.dat, re4…dat}` (no rr.dat — anomaly below).
- Classifier pass cross-check (`classifier-internals-classifier.md`): `createResponseFolder`/
  `markFolderReady`/`notifyClient` (ClientNotifyARE), `isFolderReady` parity, `cleanFolders`
  retention semantics, ht.dat template keys/URLs, TS-bundle score upload. Both agents independently
  observed the stale-folder anomaly (its `re4*.dat` predates the folder's epoch-ms name by ~8 min →
  the folder was altered after creation).

## Open questions

1. **Score-batch request shape.** The URL/body of `uploadVictoryChannel` batches live in the
   server-delivered TypeScript bundle (never collected); the JS→native boundary is pinned at
   `sysCalls::getBatchItems` (classifier `FUN_14281c0a0`/`FUN_14281c2f0` catch blocks; classifier
   pass), which enqueues batch items into an "http upload" structure. The remaining unknown on
   both sides is the structure→`ht.dat` hop: only two proven `ht.dat` writers exist in classifier
   C++ (both BundleManager), so the flush path of the score-batch upload structure into an
   `ht.dat` folder is bounded, not traced (classifier pass Open item #2).
2. **`re4*.dat` creator.** No generator in either binary's proven paths; candidates: a client-side
   claim token or the bundle JS (classifier pass Open item #3).
3. **`hr.dat` response folder wiring.** The `createPdlHttpResponseJsonfile` call is proven, but the
   exact target-folder construction and the subsequent `PdlNotifyARE` signal sit in the elided
   middle of `FUN_1402e49f0` [INFERENCE: a fresh `data\pdl\<ts>\` transaction + `rr.dat`, mirroring
   the client→classifier convention].
4. **Periods of the two view-side periodic tasks** (label refresh thunk `FUN_1402b8490`;
   `update telemetry data` `FUN_1402b0d00`) and the trim threshold at `PdlEdi+0x84` — the generic
   task runner was not pinned (same residual unknown as `capture-pipeline.md` Open questions).
5. **`pp.dat` in the client's flow.** `FUN_1401ac720` (pp.dat-area helper) runs inside
   `CurrentStateProcessor::processMessage` before parsing; classifier-side `pp`=processing/done
   semantics per the classifier pass, but the client-side read/write sites for `pp.dat` are not
   fully mapped.
