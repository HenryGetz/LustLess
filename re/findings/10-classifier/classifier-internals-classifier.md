# Classifier internals — `VictoryShieldClassifier.exe` (classifier process side)

Scope: the on-device classifier process (x86-64, 47,830 functions, image base `0x140000000`,
`.text` `0x140001000`, `.rdata` `0x142a0e000`, `.data` `0x14314b000`) answering the open questions
left by `re/findings/10-classifier/capture-pipeline.md` §Open questions from the **classifier** side:
(a) screenstate-consumption semantics, (c) classifier↔client message vocabulary and where scores
actually go, (d) the `pdl-edi` "Experimental chance" gate, plus the process's logging taxonomy and
the `--model/--data/--cache/--version` CLI contract. Cross-refs: `capture-pipeline.md` (producer
side), `re/findings/02-artifacts/classifier-data.md` (log/artifact samples), `re/findings/02-artifacts/enc-data.md`
(model blobs). Non-goals: the scoring model internals (pornDetection/DNN), the JavaScript bundle
contents (never collected), client-binary internals except where needed to close a loop.

The binary is exceptionally cooperative: it embeds its own build-tree source paths, full pretty
function signatures, and RTTI, so most symbols below are **proven names**, not renames. The
classifier is built from two source trees: `Classifier\src\*.cpp` (process shell: `main.cpp`,
`WindowsApp.cpp`, `LocalDatabase.cpp`, `TelemetryToLocalDb.cpp`, `CircumventionToLocalDb.cpp`,
`WTSUtilImpl.cpp`, `WinMutex.cpp` — string VAs `0x142a11b60`–`0x142a149a0`) and
`pdlEventDrivenInterface\{pdl-edi,bundleManager,helpers,dtApi,scriptEngines,pornDetection,balingbuddy}\…`
(the PDL/EDI engine). Scoring rides on an embedded OpenCV (`ce::FileUtils::imreadEncrypted` returns
`cv::Mat`, `0x142a3ae10`) and a **duktape JavaScript engine** driven by a server-delivered "bundle"
(see §C-3: `jsHook_*`, `sysCalls::*`).

## (a) Screenstate consumption — VERDICT

**The classifier does not poll or watch directories. It waits on the named event `PdlNotifyARE`
(and `CredentialsChangedARE`, `NormalLoggingARE`), and on each wakeup runs
`pdl_edi::PdlMessageEngine::processMessages`, which scans the shared `data\pdl\` tree for folders
that carry an `rr.dat` ready marker, dispatches a per-filetype C++ processor (or a JS hook), and
advances each folder through a `rr.dat → pp.dat → dd.dat` marker state machine.**

### Wake mechanism

- `WindowsApp::WindowsApp(...)` = `FUN_141848000` (`Classifier\src\WindowsApp.cpp`) stores the four
  CLI strings (model/data/cache/version at `this+0x00..0x80`), then registers three named events:
  `FUN_141824600(this+0xa0, "CredentialsChangedARE", "PdlNotifyARE", "NormalLoggingARE")`
  (string VAs: `CredentialsChangedARE` `0x142a13e78`, `PdlNotifyARE` `0x142a13e68`,
  `NormalLoggingARE` `0x142a13e50`). It also creates a hidden message window — window class
  `"CovenantEyesClassifier"`, window title `"ServicePseudoWindow"`, WndProc `FUN_14184d2d0` —
  constructs `TelemetryToLocalDb` and `CircumventionToLocalDb` singletons, subscribes four lambdas
  (`WindowsApp::{ctor}::<lambda_1..4>::operator()(const AppEvent&)`, signatures `0x142a13c00`–
  `0x142a13de0`) to the app-event bus, and records the `startup_classifier` telemetry marker.
- The `PdlNotifyARE` handler is `WindowsApp::{ctor}::<lambda_2>::operator()(const AppEvent&) const`
  = `FUN_141849390` (WindowsApp.cpp line `0x62`, signature embedded): on `AppEvent == 1` it logs
  `"PDL Notify event received"` (string `0x142a13c58`) and calls `FUN_14184caf0` to kick message
  processing. This is the classifier-side counterpart of the client's `PdlEdi::markPdlReady →
  notify` (capture-pipeline §2 step 4): the client sets `PdlNotifyARE` after writing `rr.dat`.
- The reverse direction exists as `WindowsApp::notifyClient(const char *)` (signature `0x142a14490`,
  log scope `"<<PDL->Client Notify callback>>"` `0x142a13ec8`) and `WindowsApp::notifyPdl(void)`
  (`0x142a14368`, failure strings `"Notify PDL failed: "` `0x142a14318` / `"Notify PDL failed (unknown)"`
  `0x142a14390`); the engine-level helper is `void __cdecl pdl_edi::notifyPdl(const std::function<bool(void)>&)`
  (`0x142a15000`, guard string `"Tried to call notifyPdl before/while initializing"` `0x142a14f90`).
  The named events the classifier sets for the client are `ClientNotifyARE`/`ClientNotifyProcARE`
  (`0x142a13b18`/`0x142a13b28`) — matching the two events the client waits on (capture-pipeline §2).
- **No `ReadDirectoryChangesW`/`FindFirstChangeNotification` wakeup exists** in the classifier
  (import/string sweeps negative; only `WaitForSingleObject(Ex)` string hits at `0x142d84f58`).
  The marker files are the protocol; the named event is the only wake. [INFERENCE, strong: no
  directory-watch API is imported or referenced anywhere in the 53 MB image.]

### The message loop

- `pdl_edi::PdlMessageEngine::processMessages(void)` = `FUN_14185cc10` (signature `0x142a15ce0`).
  It honors an early-stop flag from the client — log `"PDL-EDI: client has requested an early stop
  to processMessages()"` (`0x142a15c80`) — and manages per-folder state via the RAII helper
  `PdlMessageEngine::processMessages::RaiiManageFolderState` (signature `0x142a15ba0`). A JS hook
  gets first refusal: `jsHook_processFolder` (`0x142a16da0` source path `jsHooks.cpp`);
  `"PDL-EDI: Folder processed by jsHook_processFolder, skip C++ Message Processor"` (`0x142a16380`).
- `pdl_edi::PdlMessageEngine::processFolder(const boost::filesystem::path&)` = `FUN_14185b750`
  (signature `0x142a162b0`, PdlMessageEngine.cpp line `0x157`): logs
  `"PDL-EDI: Processing ready folder <path>"` (`0x142a16238`), then builds a processor via the
  factory `FUN_141864a90`, which **iterates the folder's files and dispatches on filename**
  (filename normalized via `FUN_14185f2c0` before comparison):
  | file in folder | processor constructed | class (RTTI/signature proven) |
  |---|---|---|
  | `ss.dat` | `FUN_1418703f0` | `pdl_edi::ScreenstateProcessor` (vtable `0x142a19300`) |
  | `su.dat` | `FUN_141864e80` | `pdl_edi::SuggestionProcessor` (RTTI `0x143176b58`) |
  | `pc.dat` | `FUN_1418742b0` | `pdl_edi::PdlConfigProcessor` |
  | `hr.dat` | `FUN_141879c80` | `pdl_edi::HttpResponseProcessor` |
  No match ⇒ processor `null` ⇒ log `"Message processor could not be generated for <folder>"`
  (`0x142a16640`), telemetry name `pdl_circumvention_missing_transaction_type` (written via
  `FUN_141853a20`), result = 1. **`ss/su/pc/hr` are therefore the complete classifier-inbound
  message vocabulary — the client→classifier direction of the transaction folders.**
- Readiness = `bool __cdecl pdl_edi::isFolderReady(const boost::filesystem::path&)` = `FUN_141858570`
  (signature `0x142a157d0`, PdlMessageEngine.cpp lines `0x90`–`0x9a`), which proves the folder
  state machine:
  1. `dd.dat` present ⇒ `"PDL-EDI: Folder was already processed"` (`0x142a15768`) — skip;
  2. `rr.dat` absent but `pp.dat` present ⇒ `"PDL-EDI: Folder <f> was left in a `processing` state,
     marking `done`"` (`0x142a158b0`) — crash-recovery: mark done and skip;
  3. `rr.dat` present ⇒ process.
  The markers are 0-byte files created by `ce::FileUtils::createEmptyFile` (`FUN_141990880`,
  signature `0x142a3a970`) through three thin wrappers: **ready `rr.dat` = `FUN_1419921d0`,
  processing `pp.dat` = `FUN_141992050`, done `dd.dat` = `FUN_141991ed0`** (each appends the fixed
  name to the folder path and calls the creator). So `rr/pp/dd` are *state markers*, not payloads —
  correcting the `[INFERENCE]` rows for `pp.dat`/`dd.dat` in capture-pipeline §2.

### Manifest parsing

- `class Json::Value __cdecl 'anonymous-namespace'::readScreenstateJson(const boost::filesystem::path&)`
  (signature `0x142a193e0`) loads `ss.dat`; then
  `pdl_edi::solomon::ScreenState_t __cdecl pdl_edi::solomon::toScreenState_t(const Json::Value&, const boost::filesystem::path&)`
  = `FUN_141887eb0` (ScreenstateSerializer.cpp line `0x100`, signature `0x142a1bd40`) converts it:
  - throws `"fromFolder - received invalid folder: <f>"` if the folder check fails;
  - throws `"toScreenState_t: Empty screenStateJson parameter"` on empty JSON;
  - **schema check** = `validateSchemaVersion` `FUN_141888b30` (string `0x142a1ba58`):
    reads `schemaVersion` and accepts iff the **first character is `'3'`** (major version 3 — the
    client writes `3.0.0`); anything else throws
    `"validateSchemaVersion: Invalid schema format received <v>"`;
  - `monitors` → `monitorListFromJson` (`FUN_1418878f0`, signature `0x142a1b6f0` =
    `vector<cv::Rect_<int>>`);
  - `apps` → `appListFromJson` = `FUN_141886ad0` (signature `0x142a1b840` =
    `vector<pdl_edi::solomon::WindowInfo_t>`);
  - `images` → `FUN_1418871b0`, whose per-entry rect parser reads **`screenRect`** (`0x142a1b988`);
  - logs `"screenstate.json deserialization time: <n>ms"` (level 5).
- **`apps[]` key consumption is exact** (all inside `FUN_141886ad0`): per array element it reads
  `"name"` (literal `0x142a1ab5c`), `"window_title"` (`0x142a1b798`), `"appRect"` (4 × int32 via
  `FUN_141887ce0`), `"doNotScore"` (bool via `FUN_1422c1160`), into a **0x60-stride struct**
  (`WindowInfo_t`: name `+0x00`, window_title `+0x20`, appRect `+0x40..+0x4c`, doNotScore byte
  `+0x58`). Zero successfully parsed apps ⇒ throw `"No windows/apps parsed successfully, nothing
  to score"` (`0x142a1b950`) — i.e. a screenstate with no usable app entries is rejected whole.

### Scoring flow and `doNotScore` — bounded

- `pdl_edi::ScreenstateProcessor::processMessage(void)` = `FUN_141870ac0` (vtable slot 1 of
  `0x142a19300`; signature `0x142a195e0`, ScreenstateProcessor.cpp lines `0x44`/`0x60`): logs
  `"ScreenstateProcessor::processMessage called for folder: <f>"`; **gates on PDL config** —
  `currentUserSettings().get()` check `FUN_1418634d0`; if no `pc.dat` config has arrived yet it
  records telemetry `pdl_no_pdlconfig_before_screenstate` (`FUN_141853a20`) and does not score.
  Scored results are batched: `"ScreenstateProcessor::batchResponse: added <N> items to batch"`
  (`0x142a19798`) / `"ScreenstateProcessor::batchResponse added item(s) to pdl cache for request: <f>"`
  (`0x142a19830`); an empty batch records telemetry `pdl_batch_response_no_scores` +
  `"Unexpected: No scores to batch: <N>"` (`0x142a19700`).
- The batch store is `pdl_edi::FileBatchStorage` (FileBatchStorage.cpp):
  `makeBatchItemFilename(double, duration)` `0x142a18100`, `getSortValue` `0x142a18260`,
  `getTimeSinceEpoch(path)` = `FUN_14186afa0` (`0x142a18360`) — parses the epoch-ms prefix out of
  batch filenames (errors: `"Unexpected: time since epoch missing from file: "` /
  `"…sentinel missing from file: "`), `garbageCollectMarkedItems` `0x142a18770`,
  `markFileForDeletion` `0x142a18670`, `purgeAllBatchFilesAndFolders` lambda `0x142a18920`.
- Scoring itself is delegated to the **JavaScript bundle** running in duktape
  (`scriptEngines\src\javaScriptContext.cpp` `0x142a213c0`; `dtApi\src\dukApi.cpp` `0x142a21d70`).
  C++ exposes exactly five syscalls (`pdl-edi\sysCalls\pdlScriptSystemCalls.cpp` `0x142a18d80`):
  `sysCalls::scoreImage(const Json::Value&)` (sig `0x142a1a8d0`), `sysCalls::scoreWindowTitle`
  (`FUN_14187ffa0`, sig `0x142a1b010`), `sysCalls::getBatchItems` (`0x142a1acc0`),
  `sysCalls::logMessage` (`0x142a1a9e0`), `sysCalls::toHandle(const cv::Mat*)` (`0x142a18e08`) —
  plus a second binding layer: the **balingbuddy (`bw.`) duktape namespace**
  (`balingbuddy\src\{dukwrap,paramMarshal,cvSizeType,vecbuf}.cpp` `0x142a42850`–`0x142a42d70`),
  which exposes file I/O (`bw.File` with open/read/write/seekg/tellg/seekp/tellp/flush/close/
  is_open/clear_errors), a filesystem namespace (`bw.fs.*` — 13 boost::filesystem-backed free
  functions incl. `create_directories`/`directory_listing`/`remove_all`/`rename`, `bundle-formats.md`
  §1.5), `bw.DecryptFile`, and **`bw.BinarySnowball.classify`** — the JS face of
  the `sw` model (decrypted: `Snowball NLP 2.0`/`rbf` header + word lists + lexicon, per
  `bundle-formats.md` §2.3) [cross-doc cite].
  Model images are decrypted in-process by `ce::FileUtils::imreadEncrypted(path) → cv::Mat`
  (`0x142a3ae10`) — the `.dat.enc` blobs are decoded straight into OpenCV mats. Low-memory mode
  notes: `"ONE-TIME Note: low-memory mode - will unload model after every image score"` (`0x142a1a830`)
  / `…after every window title score` (`0x142a1af50`).
- **`doNotScore` consumption — trail bounded.** The flag is parsed into `WindowInfo_t+0x58`
  (proven above) and the vector is moved into `ScreenState_t` at `+0x20` (tail of `FUN_141887eb0`).
  The read site of the flag is a plain struct-field access with no string/xref anchor; the only
  candidates are the elided middle of `ScreenstateProcessor::processMessage` (`FUN_141870ac0`,
  ScreenstateProcessor.cpp) and/or the duktape bundle that consumes the screenstate via
  `sysCalls::getBatchItems`. Last concrete address examined: `FUN_141870ac0` (elided region
  `0x141871243`–`0x1418721e0`). [INFERENCE: windows flagged `doNotScore` are excluded from
  score batching — the flag's only purpose in the struct — but the exact skip site is unproven.]

## (c) Classifier↔client message types and the score flow

### C-1 Transaction folder mechanics (classifier side)

Every classifier→client message gets its own folder named by **UTC epoch-ms**:
`ce::FileUtils::createResponseFolder(const path&)` = `FUN_141991470` (fileUtils.cpp line `0x8a`,
signature `0x142a3acd0`) appends `_Xtime_get_ticks()/10000` to the base path (`<data>\client`, built
by `FUN_141858340` from the literal `"client"` `0x14314b628`→`0x142a3aff8`), retries ≤3×, then throws
`"Response folder creation failure"` (log `"Could not create response folder"` `0x142a3ac68`).
**This answers capture-pipeline Open question 4: the `data\client\<epoch-ms>` naming is the
classifier's own writer** — the observed `1789880113031` = `2026-09-20T04:55:13.031Z`, exactly the
mtime of the `ht.dat` in it (`classifier-data.md`).
Message write = `FUN_141991880(folder, filename, json)` = createResponseFolder → write payload
(`FUN_1419927d0`) → **mark ready (`rr.dat`, `FUN_1419921d0`)**. The client is then woken via
`WindowsApp::notifyClient` (ClientNotifyARE). Symmetrically, the classifier marks folders it
consumes `pp.dat`/`dd.dat` (§a), which is why `pp`/`dd` appear in the client-side read set too —
they are generic engine state markers present in **both** trees.

### C-2 The complete file vocabulary (classifier-verified)

Pointer table in `.data` `0x14314b5d8`–`0x14314b628` resolves the fixed names:
`ss.dat`(0x…afb0) `ht.dat`(afb8) `hr.dat`(afc0) `su.dat`(afc8) `pc.dat`(afd0) `cs.dat`(afd8)
`rr.dat`(afe0) `pp.dat`(afe8) `dd.dat`(aff0) `client`(aff8).

| file | direction | producer → consumer | payload (proven) |
|---|---|---|---|
| `ss.dat` | client→classifier | client capture (`capture-pipeline` §2) → `ScreenstateProcessor` | screenstate JSON, schema major **3** required (`FUN_141888b30`) |
| `su.dat` | client→classifier | client suggestion txn → `SuggestionProcessor` (`FUN_141864e80`) | JSON key `importantRequest` (`0x142a17a78`) — **encrypted at rest** (AES-128-CBC+PKCS7, crypto context 1; `bundle-formats.md`); logs `"SuggestionProcessor - importantRequest received: <x>"` (`0x142a17a90`) / `"Received an unexpected suggestion request (ignoring): <x>"` (`0x142a17ba0`); telemetry `pdl_suggestion_processor_badjson` (`0x142a17a50`) |
| `pc.dat` | client→classifier | client pdl-config txn → `PdlConfigProcessor` (`FUN_1418742b0`) | remote config JSON; keys consumed by `parsePDLRemoteConfig` = `FUN_1418750a0` (sig `0x142a19b40`): `imageBatchSize_items`, `uploadInterval_sec` (→`minimumTimeBeforeBatchSend`), `initialUploadInterval_sec` (→`afterAppStartTimeBeforeBatchSend`), `experimentChancePerScreenshot_pct` (→`experimentChance`), `areEmailedReportsEnabled`, `untrustedWindowTitleApp[]` (joined `", "`); `parsePDLClientParameters` sig `0x142a1a180` |
| `hr.dat` | client→classifier | client `HttpRequestProcessor` result → `HttpResponseProcessor` (`FUN_141879c80`, processMessage sig `0x142a1a590`) | HTTP result of a classifier request (status + body, capture-pipeline §2 reverse channel) |
| `cs.dat` | classifier→client | `FUN_141867a20` → client `CurrentStateProcessor` | JSON `schemaVersion:"1.0.0"`, `versions.pdl` (key `0x142a17fbc`), `versions.bundle` (from the bundle manager, `FUN_141854940` singleton). The client logs `"PDL version: "`/`"PDL bundle version: "` and bumps `client_pdl_version`/`client_pdl_bundle_version` metrics (capture-pipeline §5) |
| `ht.dat` | classifier→client | BundleManager (`BundleManager.cpp`) → client `HttpRequestProcessor` (executes the HTTP on classifier's behalf) | **HTTP request descriptor JSON** — full key set decompiled: `schemaVersion:"2.1.0"`, `method:"GET"`/`"POST"`, `authStrategy:"NO_AUTH"`, `retryPolicy{type:"progressive", retryWindowSeconds}`, `requestFriendlyName` (`"Download PDL bundle file"` `0x142a1d250` / `"Version update check"` `0x142a1d238`), `url` (`https://api.cvnt.net/v1/desktop_client_update`, staging `https://staging.api.cvnt.net/…` `0x142a3b038`/`0x142a3b068`; prod/staging switch string `0x142a3b028`), `requestBody` (bundle-update variant embeds `current_app_version`/`client_family_version`; template with `${{ DEVICE_UUID }}`-style substitutions and `requestBodyReplacementStrings` in rdata `0x142a1d280`), `responseRawOutputFilename`, `requestHeaders[0]={name:"x-correlation-id", value:<uuid4>}`. **Encrypted at rest** (AES-128-CBC+PKCS7, crypto context 1 — `bundle-formats.md`); a **third producer** exists beyond the two BundleManager writers: the captured `ht.dat` decrypts to a `requestFriendlyName:"Feed Batch Upload"` descriptor (POST, `CE_BASIC`, `url https://eyesonapi.cvnt.net/images`, `requestBody` template with `evaluationData`/`splicedResult`/`label`/image stats) — the score-batch upload written by the JS bundle itself via `bw.File::write` (§C-3, `bundle-formats.md` §3) |
| `rr.dat`/`pp.dat`/`dd.dat` | both | ready / processing / done markers (0-byte) | — |
| `re4*.dat` | **creator bounded** | wildcard literal only in the client (`VictoryShield.exe` `0x140a42288`); see below | — |

The two `ht.dat` writers are proven: `generateFileDownloadRequest(path, url, filename)` =
`FUN_141893de0` (signature `0x142a1dae0`, BundleManager.cpp line `0x65`, log `"Generating file
download request for <url> to <filename>"`) and `generateUpdateCheckRequest(path, PdlManifest, bool)`
= `FUN_1418948e0` (signature `0x142a1d890`, line `0x55`, log `"Generating update check request"`,
fallback log `"Unexpected: cannot get current bundle version, will use hardcoded default"` with
hardcoded `"0.1.0"`). Correlation ids are boost-UUID v4 via BCryptGenRandom
(`FUN_1419935e0`, source `boost\uuid\detail\random_provider_bcrypt.ipp` `0x142a10610`).

### C-3 Where scores go — **not to the client/UI**

- Scored screenstates become **batch items** in `FileBatchStorage` (the `cache\…dat` batch files;
  `ScreenstateProcessor::batchResponse`, §a). Upload is executed by `processBatches.cpp`:
  `` `anonymous-namespace'::processBatchesForVictoryChannel(duration)`` (sig `0x142a17f20`) and
  `processBatchesForExperimentalChannel(duration)` (sig `0x142a17dd0`), plus
  `uploadVictoryChannel` = `FUN_141867230` and its experimental twin (`"uploadExperimentalChannel"`
  `0x142a17c90`; `"uploadExperimentalChannel TS returned error: "` `0x142a17d18`). These C++
  shims build `{minimumBatchAgeBeforeUploadSeconds: N}` and **call JavaScript functions of the same
  name inside the loaded bundle** (`FUN_1418b4e20(ctx, result, "uploadVictoryChannel", args)`;
  result JSON keys `errorMessage` and `uploadGenerated`; "TS" in the log = the bundle is compiled
  TypeScript). [INFERENCE: the bundle orchestrates the upload flow — it decides *what* to send and
  when — while the C++ `getBatchItems` syscall does the actual enqueue into the http-upload queue
  (next bullet); the resulting request envelope is the encrypted `"Feed Batch Upload"` `ht.dat`
  proven by `bundle-formats.md` — next bullet.]
- **The physical transport of score batches — resolved to a JS file write.** Only two `ht.dat`
  request writers exist in decompiled C++ (both BundleManager; exhaustive xrefs to `PTR_s_ht_dat`
  `.data` slot `0x14314b5e0` → string `0x142a3afb8`), and the five pdl `sysCalls::`
  (signature sweep `0x142a18e08`–`0x142a1b010`) contain no file writer — **but the JS sandbox is
  not read-only**: the balingbuddy `bw.*` namespace exposes a full fstream class (`bw.File`
  open/read/write/seek/tell/flush/close) plus `bw.DecryptFile` (`bundle-formats.md` §3). The JS→native enqueue step is
  **`sysCalls::getBatchItems(const Json::Value&)`** (getBatchItems.cpp): its per-item catch blocks are
  `FUN_14281c0a0` (Json::Exception, line `0x32`) and `FUN_14281c2f0` (PdlException, line `0x35`), both
  logging `"Json::Exception|PdlException, Unable to add item from batch to http upload: <ex.what()>"`
  (strings `0x142a1ac30`/`0x142a1ad10`) while setting `errorMessage` on the JS result — i.e. **pulling
  batch items from the store enqueues them into a C++ "http upload" structure**. The batch keys it
  consumes (`batchFolders` `0x142a1ab30`, `batchName` `0x142a1ab40`, `batchFiles` `0x142a1ab50`,
  `timeSinceEpochSec` `0x142a1ab68`, `itemNames` `0x142a1ab80`, `itemName` `0x142a1abb8`,
  `batchItems` `0x142a1ada0`) are read by the main body around `FUN_14187f830` (also the `.dat`
  batch-file reader). The emitted artifact is proven: the captured
  `data\client\1789880113031\ht.dat` decrypts (AES-128-CBC, crypto context 1) to a schema-2.1.0 request
  descriptor `requestFriendlyName:"Feed Batch Upload"`, POST, `authStrategy:"CE_BASIC"`,
  `url https://eyesonapi.cvnt.net/images`, requestBody template with `evaluationData`/`splicedResult`/
  `label`/image stats (`re/findings/10-classifier/bundle-formats.md`), executed by the client's
  `HttpRequestProcessor`. **Emitter (closed, `bundle-formats.md` §3):** since exhaustive
  `PTR_s_ht_dat` xrefs leave no third C++ writer, the bundle writes the descriptor itself with
  `bw.File::write` [INFERENCE, strong] — while the C++ message-write funnel `FUN_141991880`
  remains the path for `ss`/`su`/`pc`/`hr`/`cs` and the two BundleManager `ht.dat`.
  This closes the observed "anomaly": the stale folder (`ht.dat` + `re4*.dat`, **no `rr.dat`**)
  is a pure JS-created folder — the bundle makes the epoch-ms directory itself with
  `bw.fs.create_directories` and writes `ht.dat` with `bw.File::write`, never creating `rr.dat`
  (the ready marker exists only on the `FUN_141991880` funnel path — corroborated by
  `ce::FileUtils::createResponseFolder` `FUN_141991470` having exactly one caller, `FUN_141991880`;
  `bundle-formats.md` §1.5/§3). [cross-doc cite]
  Chain: `FUN_141867230` (native JS entry) → JS `uploadVictoryChannel` → `sysCalls::getBatchItems`
  (native enqueue; catch sites `FUN_14281c0a0`/`FUN_14281c2f0`, main body `FUN_14187f830`) → JS
  serializes the descriptor → `bw.File::write` → encrypted `ht.dat` "Feed Batch Upload" → client
  proxy → `https://eyesonapi.cvnt.net/images`. Score-batch URL/body/writer are **all known**.
- **"Analyzed … in the last N minutes" has no classifier-side producer.** Full client string set:
  `" analyzed in the last "` (`VictoryShield.exe` `0x1408dc580`), `" minute"` (`0x1408dc598`),
  `"Analyzing..."` (`0x1408dc5a0`), consumed only by `FUN_1402c9d50` — a `CVictoryShieldView`
  metrics updater (neighbor strings `"CVictoryShieldView::updateMetricsSql"` `0x1408dc5e0`,
  `"screenshot"`/`"record screenshot telemetry"` `0x1408dc5b0`/`0x1408dc5c0`). The count behind it
  is the **client's own screenshot telemetry** (`screenshot_count`/`screenshot_telemetry` table,
  `FUN_1402d5590`, capture-pipeline §5), not classifier scores [INFERENCE, strong adjacency +
  string-complete negative]: the classifier binary contains **zero** occurrences of "Analyzed"
  (full 80,801-string sweep). Scores flow classifier→backend only; the UI's "analyzed" number is
  capture-count bookkeeping.

### C-4 `re4*.dat` — bounded

- `re4*.dat` is a **literal wildcard** in the client (`0x140a42288`, between `ss.dat` and `dd.dat`
  in the transaction-vocab cluster) used exactly once: `SystemPath::filePatternExists(folder, "re4*.dat")`
  = `FUN_1401abb50` (CommonLibrary\src\SystemPath.cpp line `0xbf`), a `FindFirstFileW` glob. Its
  only caller is `PdlEdi::cleanFolders` = `FUN_1402d7820` (PdlEdi.cpp line `0xad`), the transaction
  folder GC: per subfolder — delete if `dd.dat` present (`FUN_1401ace80`) **and** aged past the
  cutoff (`FUN_1401acf80` = `SystemPath::age >= seconds`), else delete unless (when the flag arg is
  set) the folder still contains `rr.dat` (`FUN_1401aba50`) **or** matches `re4*.dat`. So a folder
  containing a `re4<token>.dat` file is **exempt from cleanup** — a retention/claim marker.
- **The classifier binary contains no `re4` literal and no obvious generator** (rdata sweep for
  `re4` finds only OpenCL `vstore4` kernels; the base62 charset at `0x14315d7e8` is referenced only
  by library code `0x1422ff4d0`/`0x14243a930`). The observed sample
  `re4sHXTJFJHReHXTJFJTR.dat` (0 B, 20-char mixed-case alnum base name, inside the classifier-made
  `data\client\1789880113031\` next to `ht.dat`; `classifier-data.md`) therefore has **no proven
  writer in either binary's C++**. [INFERENCE: created either by the client's
  HttpRequestProcessor while claiming a download-request folder, or by the duktape JS bundle via
  a mechanism not visible in the C++ syscall table; the 20-char name is consistent with a random
  token, not with the UUID generator used for correlation ids.] Anomaly (unexplained): the file's
  mtime (2026-09-19 23:47:24 −05:00) predates its folder's epoch-ms name (23:55:13) by 7m49s.
  Trail ends at the client-side glob `FUN_1401abb50` and the classifier's empty marker factory
  `FUN_141990880`; last concrete address examined on the classifier side: `FUN_141991880`.

## (d) `pdl-edi` "Experimental chance" gating — VERDICT

**"Experimental chance" is a per-user percentage, `experimentChancePerScreenshot_pct`, delivered
in the `pc.dat` PDL remote config, stored in `pdl_edi::CurrentUserSettings`, and it selects
between two score-batch upload paths — the production "victory" channel and an "experimental"
channel. At 0, no experiment runs and the classifier logs the ONE-TIME NOTE once per process.**

- Config key: `experimentChancePerScreenshot_pct` (`0x142a17220`) parsed in
  `pdl_edi::PdlConfigProcessor::parsePDLRemoteConfig` = `FUN_1418750a0` (PdlConfigProcessor.cpp,
  sig `0x142a19b40`): value → `currentUserSettings().set experimentChance(FUN_141863720)`;
  debug log `"experimentChance: " << currentUserSettings().get().experimentChance()` (`0x142a19cc0`).
  If the value is 0 it logs the exact observed line:
  `"ONE-TIME NOTE: Experimental chance set to 0, no experiments will run for this user."`
  (string `0x142a19d30`, quoted variant `0x142a19d90`; xref inside `FUN_1418750a0`).
  This matches every captured run: e.g. `re/samples/runtime/classifier-log-10252.txt` emits it
  10.6 s after start (2026-09-19 00:35:00.179), i.e. during startup config application.
- Consumers: the channel pair `processBatchesForVictoryChannel` /
  `processBatchesForExperimentalChannel` (`0x142a17f20`/`0x142a17dd0`) and their JS entry points
  `"processVictoryChannel"` (`0x142a19990`) / `"processExperimentalChannel"` (`0x142a199c0`, xref
  `FUN_141870810`) with upload twins `uploadVictoryChannel` (`FUN_141867230`) /
  `uploadExperimentalChannel` (`0x142a17c90`). Channel-name literals `"victory"` (`0x142a18488`) /
  `"experimental"` (`0x142a18478`). [INFERENCE: each screenshot's score batch is rolled against
  `experimentChance%` and routed to the experimental backend queue when the roll hits; with chance
  0 all batches use the victory channel. The roll itself lives in the JS bundle, which was never
  collected — the C++ only supplies the percentage.]
- Storage: in-memory `CurrentUserSettings` (`setUser` sig `0x142a17390`), refreshed from each
  incoming `pc.dat`; **no on-disk persistence of the roll exists in the classifier tree** (no
  settings file writer found; the per-SID tree contains only the cache/data dirs,
  `classifier-data.md`). The client re-supplies config per run (its `pc.dat` comes from the
  backend endpoint `/v1/member/sensor/config/pdlEdi`, capture-pipeline §1), which is why the
  ONE-TIME NOTE appears once per process even with no user interaction. Trail ends at the JS
  bundle boundary; last concrete addresses: `FUN_1418750a0` (setter), `FUN_141867230` (channel call).

## Logging taxonomy → code areas

- **Facility**: the snowball **h2olog** "FrontDoor" C logger
  (`snowball\h2o\h2olog\src\FrontDoor_C.cpp` `0x142d76178`, `InitGuard.cpp` `0x142d76420`). The
  severity vocabulary is a 7-token table at `0x142d76374`–`0x142d76394`: **`NON`, `MAR`, `ERR`,
  `WAR`, `INF`, `VER`, `TRA`** — the observed `MAR`/`WAR`/`ERR` in `classifier-logs/*.txt` are
  milestone/error/warning levels of this table.
- **Every log call carries full source location**: (logger-id, full `D:\actions-runner\_work\w\p\x64\…`
  path, line, function name, pretty signature) via the `FUN_1422b9560`/`FUN_1422b9520`/`FUN_1422bcf60`
  family — e.g. `("…\pdl-edi\src\ScreenstateProcessor.cpp", 0x44, "processMessage", "enum
  pdl_edi::MessageResponseResult __cdecl pdl_edi::ScreenstateProcessor::processMessage(void)")`.
- **Tag↔code-area mapping** (1:1 correlation between observed tag and source path in the same log
  record; [INFERENCE] that the formatter derives the tag from the path component):
  | log tag | source dir | files (string VAs) |
  |---|---|---|
  | `Classifier` | `Classifier\src\` | `main.cpp` `0x142a149a0`, `WindowsApp.cpp` `0x142a13b70`, `LocalDatabase.cpp` `0x142a125f0`, `TelemetryToLocalDb.cpp` `0x142a12ba0`, `CircumventionToLocalDb.cpp` `0x142a11b60`, `WTSUtilImpl.cpp` `0x142a134e0`, `WinMutex.cpp` `0x142a136d0` |
  | `pdl-edi` | `pdlEventDrivenInterface\pdl-edi\src\` (+`\sysCalls\`) | `pdl-edi.cpp` `0x142a14f40`, `PdlMessageEngine.cpp` `0x142a154d0`, `PdlMessageProcessor.cpp` `0x142a175d0`, `ScreenstateProcessor.cpp` `0x142a19320`, `ScreenstateSerializer.cpp` `0x142a1b630`, `SuggestionProcessor.cpp` `0x142a17880`, `PdlConfigProcessor.cpp` `0x142a19a50`, `HttpResponseProcessor.cpp` `0x142a1a490`, `FileBatchStorage.cpp` `0x142a18010`, `processBatches.cpp` `0x142a17cc0`, `jsHooks.cpp` `0x142a16da0`, `pdl-edi-settings.cpp` `0x142a172e0`, `ImageObfuscation.cpp` `0x142a1b280`, `PdlJsRawFunctions.cpp` `0x142a18ea0`, sysCalls `0x142a18d80`–`0x142a1b010` |
  | `bundleManager` | `pdlEventDrivenInterface\bundleManager\src\` | `BundleManager.cpp` `0x142a1d7c0`, `BundleFileManager.cpp` `0x142a1f360`, `ManifestCache.cpp` `0x142a20f70` |
- **Local databases** (why the observed startup warns twice): the classifier opens two SQLite
  stores — `logdb.circumventions` (`CREATE TABLE IF NOT EXISTS logdb.circumventions …` `0x142a11ef0`)
  and `userdb.telemetry` (`0x142a13000`) — and at startup attaches the per-user `ce-user-file`
  DB twice ("Could not attach to user database (c)" `0x142a120e8` for circumventions, "(t)"
  `0x142a131d0` for telemetry); failure logs `"SQLite database connect error"` (`0x142a11bb0`) and
  the run continues — the exact pairs seen in every captured log (SQLite error 26 =
  `SQLITE_NOTADB`, classifier-data.md). Tables created by `ce::database::doSqlOrWarn` (sig
  `0x142a12690`).
- Log sink: per-process file under the `\logs\` directory literal (`0x142a14868`), matching the
  observed `Classifier\logs\<PID>.txt` layout (classifier-data.md).

## CLI contract (`--model/--data/--cache/--version [--verbose]`)

- Startup function (main.cpp) = `FUN_14184ff40`: logs `"Command line: " << std::string(GetCommandLineA())`
  (`0x142a14a88`) and `"Classifier v" << options["version"].as<std::string>() << " is starting"`
  (`0x142a14af0`) / `"… is terminating"` (`0x142a14d10`). Options are parsed cxxopts-style
  (option strings `"verbose,v"` with help `"Enable verbose-level logging."` `0x142a148b8`/`0x142a14a40`).
  This function logs all three path options directly from the parsed `options` map:
  `"PDL-EDI data folder path: " << options["data"]` (`0x142a14b70`),
  `"PDL-EDI cache folder path: " << options["cache"]` (`0x142a14be0`),
  `"PDL-EDI model path: " << options["model"]` (`0x142a14c48`) — confirming the exact flag names the
  client builds (`LaunchAndMonitorScreenMonitoring`, capture-pipeline §4).
- The four strings are handed to `WindowsApp::WindowsApp(model, data, cache, version)` (`FUN_141848000`),
  which stores them and initializes the engine (`WindowsApp::initializePdl`, sig `0x142a14218`);
  `--data` becomes the message root (`<data>\pdl` exchange + `<data>\client` outbox, §c),
  `--cache` the batch/bundle state root (`bmdat`/`ssdat`/`tmdat`/`exdat`/`vfdat` folder literals
  `0x142a3b000`–`0x142a3b020`; `nxu.dat` `0x142a1f318`), `--model` the `.dat.enc` directory consumed
  by `ce::FileUtils::imreadEncrypted`.
- Bundle scheduling state (closes classifier-data.md's `nxu.dat` inference): the cache file
  `bmdat\nxu.dat` is written/read by `pdl_edi::bm_priv::BundleFileManager::setNextUpdateTimePoint`/
  `getNextUpdateTimePoint` (sigs `0x142a20000`/`0x142a1fe80`) and contains JSON
  `{"nextUpdate_sec": N}` (`0x142a1fda8`) — the file itself is **encrypted at rest** like the other
  control files (AES-128-CBC, crypto context 1, `bundle-formats.md`); the observed
  `ERR bundleManager: onTimeUpdate error - Unable to read nextUpdate file (might not have been
  created yet)` (`0x142a1fd60`) is the first-run case of `BundleManager::onTimeUpdate` (sig
  `0x142a1e050`; other logs: `"onTimeUpdate: generated update check request"` `0x142a1e1a0`,
  `"onTimeUpdate: set next update timepoint to next update period."` `0x142a1e370`,
  `"Corrupt nextUpdate file"` `0x142a1fdb8`). A built-in **default bundle manifest** is embedded
  (rdata `0x142a1d280`, the POST/NO_AUTH `"PDL Bundle"` request template quoted above) and used by
  `BundleManager::revertToDefaultBundle` (sig `0x142a1f160`) when
  `performBundleIntegrityValidation` (sig `0x142a1f220`) fails.

## Evidence

- Ghidra MCP (11-program project, program `VictoryShieldClassifier.exe`), decompiled:
  `FUN_141848000` (WindowsApp ctor: 3 named events, hidden window, telemetry/circumvention
  singletons, `startup_classifier`), `FUN_141849390` (PdlNotifyARE handler lambda_2), `FUN_14185b750`
  (processFolder), `FUN_141864a90` (ss/su/pc/hr processor factory), `FUN_141858570` (isFolderReady:
  rr/pp/dd semantics), `FUN_141991ed0`/`FUN_141992050`/`FUN_1419921d0` (dd/pp/rr marker writers),
  `FUN_141991470` (createResponseFolder: epoch-ms naming), `FUN_141991880` (write message + mark
  ready), `FUN_141858340` (`data\client` join), `FUN_141867a20` (cs.dat writer), `FUN_141893de0`
  (generateFileDownloadRequest → ht.dat), `FUN_1418948e0` (generateUpdateCheckRequest → ht.dat),
  `FUN_1418750a0` (parsePDLRemoteConfig: experimentChancePerScreenshot_pct + ONE-TIME NOTE),
  `FUN_141867230` (uploadVictoryChannel → JS), `FUN_1418703f0` + vtable `0x142a19300` +
  `FUN_141870ac0` (ScreenstateProcessor), `FUN_141887eb0` (toScreenState_t), `FUN_141886ad0`
  (appListFromJson: name/window_title/appRect/doNotScore), `FUN_141888b30` (validateSchemaVersion:
  major '3'), `FUN_14186afa0` (FileBatchStorage::getTimeSinceEpoch), `FUN_14186c2d0` (batch-file
  filter), `FUN_1419935e0` (boost uuid via BCryptGenRandom).
- Client-side closure queries (program `VictoryShield.exe`): `FUN_1401abb50`
  (SystemPath::filePatternExists `re4*.dat`), `FUN_1402d7820` (PdlEdi::cleanFolders retention
  logic incl. rr.dat/dd.dat/age helpers `FUN_1401aba50`/`FUN_1401ace80`/`FUN_1401acf80`),
  `" analyzed in the last "` xrefs → `FUN_1402c9d50`; `screenshot_count` xrefs → `FUN_1402d5590`.
- Local string analysis of `re/samples/VictoryShieldClassifier.exe` (PE section-mapped VAs, 80,801
  strings): signature/RTTI/source-path table (`0x142a11b60`–`0x142a21d70`), file-name pointer
  table (`0x14314b5d8`–`0x14314b628` resolved via `.data` reads), severity token table
  (`0x142d76374`), default manifest template (`0x142a1d280`), negatives: no `re4` literal, no
  "Analyzed" string, no directory-watch APIs.
- Captured artifacts: `re/samples/data/classifier-logs/*.txt` (14 runs), 
  `re/samples/runtime/classifier-log-10252.txt`, `re/samples/data/classifier-data/` (the
  `data\client\1789880113031\{ht.dat, re4*.dat}` and `data\pdl\…{rr.dat, su.dat}` samples,
  hashes/entropy per classifier-data.md).

## Linux mapping implications (analysis only — no edits to `re/findings/91-linux-mapping.md`)

For §2 ("Classifier") and §1 (handoff) of the Linux mapping:

1. **Confirmed: marker-file state machine is the protocol.** The rr→pp→dd marker triple plus
   epoch-ms response folders is a complete, crash-recoverable transaction protocol (a folder left
   in `processing` is detected and marked done on restart — `isFolderReady` case 2). The Linux
   design should keep exactly this: three 0-byte markers per spool folder, RAII-based state on the
   consumer, and the `dd.dat`-present short-circuit. The named-event wakeup is confirmed to be the
   *only* wake (no directory watches in CE either) — inotify remains a drop-in replacement.
2. **New fact for the manifest decision:** the classifier only validates **major version 3**
   (`validateSchemaVersion` accepts any `3.*`). Schema 3.0.0 reuse (already the plan) is safe, and
   minor-version drift is tolerated by design — worth mirroring (`major==ours` check only).
3. **New fact for the message vocabulary:** the full inbound set is exactly `{ss, su, pc, hr}.dat`
   and the outbound set `{cs, ht}.dat` plus the rr/pp/dd markers; `pp`/`dd`/`rr` are generic
   engine markers, not per-direction types — the earlier client-side `[INFERENCE]` table rows for
   `pp.dat`/`dd.dat` as message payloads should be read as state markers. `ht.dat` is a structured
   HTTP-request descriptor (schema 2.1.0, NO_AUTH, progressive retry, correlation-id header) —
   the Linux classifier↔daemon proxy should adopt the same descriptor shape or a direct socket.
4. **Score routing must not touch the UI.** CE's classifier sends scores **only** to the backend
   (via the client's HTTP proxy); the "Analyzed in the last N minutes" UI counter is client-local
   capture bookkeeping. The Linux design (91 §2/§6) should keep this separation: the tray's
   "analyzed" counter = local capture count, never classifier output.
5. **Experiment gating is a config-key percentage routing batches between two upload channels** —
   trivially portable as a config knob + a roll; CE persists nothing (the value arrives with each
   `pc.dat` config fetch). If LustLess uses A/B at all, storing the roll per user (as 91 §2
   already decides) is a strict improvement over CE's stateless-per-run behavior.
6. **CLI contract confirmed exactly as mapped:** `--model/--data/--cache/--version` (+ `--verbose`)
   parsed at startup, with the model dir consumed only by the scoring path (`imreadEncrypted`), the
   data dir as the message root, and the cache dir holding the bundle state (`nxu.dat` =
   `{"nextUpdate_sec": N}` JSON, not a raw timestamp — 91's "`nxu.dat`-style update-schedule marker"
   can be concretized to a JSON object). CE also encrypts the per-user message/control files
   (`ht`/`su`/`nxu`, and the observed `ht.dat`) at rest with a key derived inside the binary
   (`bundle-formats.md`) — security-through-obscurity that a local attacker with the binary defeats;
   LustLess should either store these plaintext (local attacker model, consistent with 91 §5's
   key-management stance) or use a real OS-held key, not a compiled-in passphrase.
7. **Logging:** the h2olog severity set (`NON/MAR/ERR/WAR/INF/VER/TRA`) and source-location-rich
   records support 91 §2's `<PID>.log` decision; adopting the 3-letter severity codes and
   (file, line, function) fields makes CE support logs diffable against LustLess logs.
8. **JS-bundle architecture discovered (new):** the classifier is scriptable — a server-delivered
   TypeScript/duktape bundle drives message processing (`jsHook_processFolder/processBatches/
   manageBundles`), scoring calls (`scoreImage`/`scoreWindowTitle` syscalls), and batch uploads,
   with a built-in default bundle as fallback and integrity validation + revert. 91 §2 does not
   currently mention this layer; whether to copy the hot-updatable-script design (bundle fetch via
   the daemon's HTTP, integrity-pinned, default fallback) or keep a pure-native classifier is a new
   open decision. The native surface CE's bundles need is the five `sysCalls::` (`scoreImage`,
   `scoreWindowTitle`, `getBatchItems`, `logMessage`, `toHandle`) **plus the balingbuddy `bw.*`
   bindings — `bw.File` fstream, `bw.DecryptFile`, `bw.BinarySnowball.classify`**
   (`bundle-formats.md` §2.3/§3) — note the file-write binding is what lets the bundle emit its
   own `ht.dat` messages (and, with `bw.fs.*`, create/erase the folders: 13 free functions incl.
   `create_directories`, `directory_listing`, `remove_all`, `rename` — `bundle-formats.md` §1.5);
   a LustLess design could instead give JS a narrow message-enqueue API and drop raw fstream
   **and** `bw.fs.*` together, keeping the spool tree native-only. This also reframes CE's
   `"Circumvention: PDL transaction file removed|renamed"` tamper logs (capture-pipeline §2): with
   `bw.fs.remove_all`/`rename` in the bundle, the watcher guards against the bundle itself, not
   just external tampering [INFERENCE].

## Open items (bounded)

1. `doNotScore` read site inside `ScreenstateProcessor::processMessage` (elided region of
   `FUN_141870ac0`) or in the uncollected JS bundle — struct field `WindowInfo_t+0x58` proven,
   consumer not pinned.
2. ~~Score-batch upload emitter + folder creation~~ — **closed by
   `re/findings/10-classifier/bundle-formats.md` §1.5/§3**: no third C++ writer exists (exhaustive
   `PTR_s_ht_dat` xrefs = `FUN_1418948e0`/`FUN_141893de0` only, and `FUN_141991470`'s sole caller
   is `FUN_141991880`); the bundle creates the epoch-ms folder itself (`bw.fs.create_directories`)
   and writes the `"Feed Batch Upload"` descriptor via `bw.File::write`, skipping `rr.dat` by
   construction — full chain in §C-3.
3. Creator of `re4<token>.dat` retention files — no literal/generator in either binary's C++; the
   JS bundle (proven file-write capability via `bw.File`/`bw.fs.*`) or the client remain the
   candidates.
4. ~~High-entropy `ht.dat` artifact reconciliation~~ — **closed by
   `re/findings/10-classifier/bundle-formats.md`**: the per-user message/control files
   (`ht`/`su`/`nxu`) are AES-128-CBC+PKCS7-encrypted at rest (crypto context 1, key/IV derived in
   the classifier at `FUN_141995bc0`/`FUN_141995dc0`/`FUN_141995fe0`), so the 41,760 B blob is the
   encrypted form of the schema-2.1.0 request descriptor JSON, not a response body.
