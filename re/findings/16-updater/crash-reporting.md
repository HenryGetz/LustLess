# 16-updater — BugSplat crash reporting, crash counters, restart escalation

Scope: the crash-reporting pipeline of `VictoryShield.exe` (BugSplat integration, what gets
uploaded, crash → restart handoff, crash counters) with cross-references to
`re/findings/14-watchdog/watchdog.md` (counter read-side + `RestartVS*` behavior — not
duplicated here) and `re/findings/02-artifacts/logs.md`. Update/upgrade mechanics are in
`updater.md`.

## What it does

`VictoryShield.exe` registers a **BugSplat** crash reporter at startup
(`MiniDmpSender` from `BugSplat64.dll`, database **`covenant-eyes-10-1`**, app
**`CovenantEyes64.exe`**, version **`10.1.44`**). On a crash its callback logs the exception,
zips up **all client logs + the SQLite databases** with the bundled `zip.exe`, attaches the
three zips to the BugSplat report (5 MB/file, 19 MB total caps), bumps a telemetry crash
counter, and launches **`RestartVSClientOnly.exe --RestartRequestFrom=10.1.44 --PID=<pid>`**
(the restart escalation chain documented in `watchdog.md` §7: ≤3 restarts, then a "contact
Member Care" dialog). On every successful startup the client reports accumulated crash counts
as a `client_crash` metrics event, clears them, and touches the registry crash counter
(`ClientCrashesAt`/`ClientCrashesSince`) that the VSWD watchdog reads (clear-only — the
incrementing writers are `RestartVS*.exe` and the installer).

## Mechanism

### 1. BugSplat initialization

In `CVictoryShieldApp::InitInstance` = `FUN_1402a47d0` (log tag `CVictoryShieldApp::InitInstance`
@`0x1408d9008`), at the very top:

```
MiniDmpSender::MiniDmpSender(…, …, …, …, NULL, 0x6004);   // ctor IAT call @0x1402a49c3
sender->setCallback(FUN_1402a1a40);                        // @0x1402a4af0
```

The constructed sender lives in global `DAT_140b58318`. Constructor arguments (all assembled
in `FUN_1402a47d0`):

| arg | value | construction evidence |
|---|---|---|
| database | **`covenant-eyes-10-1`** | literal `"covenant-eyes-"` @`0x1408d8ff8` + `FUN_140130070()`=`10` + `-` (`DAT_140a3f794`) + `FUN_140130080()`=`1` |
| app name | **`CovenantEyes64.exe`** | `L"CovenantEyes"` @`0x1408d8fd8` + arch suffix from `FUN_1401a8a00` (`checkIfArm64System`, `CommonLibrary\src\Common.cpp`: resolves `IsWow64Process2`, logs `Platform Native CPU: `, returns `L"64"`/`L"32"`/`L"ARM64"`) + `L".exe"` @`0x1408d8fc8` |
| version | **`10.1.44`** | `FUN_140130030` = literal `"10.1.44"` |
| crash GUID | `NULL` | |
| flags | `0x6004` | [INFERENCE: BugSplat `MDS_*` flag combination] |

The registered callback `FUN_1402a1a40` carries the log tag **`BugSplatExceptionCallback`**
@`0x1408d8e08` (callback type `bool(*)(uint, void*, void*)`, IAT
`?setCallback@MiniDmpSender@@QEAAXP6A_NIPEAX0@Z@Z` @IAT `0x1408d52a0`).

### 2. Crash-handling flow (`BugSplatExceptionCallback` = `FUN_1402a1a40`)

1. **Re-entrancy gate** — static `DAT_140b58528` (`CMP` @`0x1402a1a72`); second entry logs
   `"Crash processing is done - already active"` @`0x1408d8f98` and returns 0.
2. **Callback-id check** — `CMP ECX, 0x50` @`0x1402a1a86`; only code `0x50`
   [INFERENCE: BugSplat's "exception occurred" callback id] proceeds, anything else logs
   `"Crash processing - invalid exception code"` @`0x1408d8f68` and returns.
3. **Telemetry counter +1** — `CALL FUN_1401e5a30(1)` @`0x1402a1d6e` (§5).
4. **Exception logging** — `FUN_1402a7960` maps codes to names via the `EXCEPTION_*` table
   (`EXCEPTION_ACCESS_VIOLATION` @`0x1408d8b88` … `CONTROL_C_EXIT` @`0x1408d8de0`,
   `UNDEFINED code: ` @`0x1408d8df0`); logs `"Process terminating with primary exception: "`
   @`0x1408d8e28` and, for a nested exception, `"Process terminating with secondary exception: "`
   @`0x1408d8e58`.
5. **Build 3 zips + attach** (§3).
6. **Restart escalation** — command line assembled at `0x1402a371f`-`0x1402a37b5`:
   `"--RestartRequestFrom="` @`0x1408d8f28` + `"10.1.44"`, `" --PID="` @`0x1408d8f20` +
   `GetCurrentProcessId()`; then
   `ShellExecuteA(NULL, "open", <ProgramFilesDir>\CE\RestartVSClientOnly.exe, <args>, …)`
   @`0x1402a3802` (path built by `FUN_1401f1a80` = install-dir builder `FUN_1401f1520`
   (`HKLM\Software\Microsoft\Windows\CurrentVersion\ProgramFilesDir` + `"\CE"`) +
   `"RestartVSClientOnly.exe"`).
   **This answers watchdog.md's open item**: the *client crash handler* is what launches
   `RestartVSClientOnly.exe`; that binary then applies the ≤3-restart rule and the
   "Too many restarts" escalation (`watchdog.md` §7). `RestartVS.exe` (full stack: services +
   client) is launched by the shared `MiniDumper::restartAfterCrash` code
   (`watchdog.md` §6; `vs-config.exe FUN_1400c3e40`), which in `VictoryShield.exe` is
   [INFERENCE] reserved for non-BugSplat/legacy paths.
7. **Outcome log** — `"Crash processing is done: "` @`0x1408d8f48` + the `ShellExecuteA`
   return; return 1.

### 3. What a crash report contains (attachments)

Built in the callback under `%TEMP%` by the **bundled `zip.exe`** (Info-ZIP; `zip.exe`
@`0x1408d8ec8`, flag `"-FSr"` @`0x1408d8ebc`, run via process-runner `FUN_1401d4560`), then
attached with `MiniDmpSender::sendAdditionalFile` through wrapper `FUN_1402a3da0`
(`FindFirstFileW`, attach only if file < **0x500000 (5 MB)** and running total < **0x1300000
(19 MB)**; call @`0x1402a3e17`):

| attachment | contents | evidence |
|---|---|---|
| `debugLogs.zip` @`0x1408d8e88` | `<ProgramData>\…\logs`, `…\VictoryShieldInstaller`, `…\ThirdParty`, `…\vs-config\logs` (argv built `0x1402a241a`-`0x1402a25af`; dir getters `FUN_1401c67e0`/`FUN_1401c6980`/`FUN_1401c6a80`/`FUN_1401c76d0`) | the exact trees captured in `re/samples/data/` (`logs`, incl. the comm-service + installer logs of `re/findings/02-artifacts/logs.md`) |
| `debugClassLogs.zip` @`0x1408d8e98` | classifier log dir (`FUN_1401aa970`) [INFERENCE: `re/samples/data/classifier-logs`] | argv `0x1402a283f`-`0x1402a291f` |
| `debugDB.zip` @`0x1408d8eb0` | `ce-file`, `ce-file-shm` @`0x1408d8ed0`, `ce-file-wal` @`0x1408d8ee0`, `ce-user-file`, `ce-user-file-shm` @`0x1408d8ef0`, `ce-user-file-wal` @`0x1408d8f08` (SQLite DBs + WAL/SHM sidecars) | argv `0x1402a2b13`-`0x1402a31d2` |

The minidump itself is generated/transmitted by `BugSplat64.dll` + **`BsSndRpt64.exe`**
(BugSplat's out-of-process sender; no string references from CE code — it is spawned by the
DLL at upload time [INFERENCE: standard BugSplat pipeline]). On-disk payload confirmed
read-only on the VM 2026-09-24 20:47 (`Get-ChildItem 'C:\Program Files\CE'`):
`BugSplat64.dll` 646,592 B, `BugSplatRc64.dll` 181,184 B, **`BsSndRpt64.exe` 380,864 B**,
`zip.exe` 301,504 B. So a crash report = minidump + up to ~19 MB of **client logs and the
full local activity databases** — the same content the installer backups keep.

**Upload endpoint** (BugSplat vendor code, quoted verbatim with VAs; UTF-16 strings):

| string | file | VA |
|---|---|---|
| `https://www.bugsplat.com` | `BsSndRpt64.exe` (base `0x140000000`) | `0x140021e50` |
| `api/getCrashUploadUrl.php` | `BsSndRpt64.exe` | `0x140021e88` |
| `api/commitS3CrashUpload.php` | `BsSndRpt64.exe` | `0x140022150` |
| `post/post_form.php` | `BsSndRpt64.exe` | `0x140023890` |
| `commitS3CrashUpload succeeded.  Database: %s, appName: %s, appVersion: %s` | `BsSndRpt64.exe` | `0x1400223a0` |
| `.bugsplat.com/api/fullDumpFlag?database=` (+ `https://` `0x180079b68`) | `BugSplat64.dll` (base `0x180000000`) | `0x180079b10` |
| `Software\BugSplat` / `Software\BugSplat\%s\%s\%s` (registry config: `PostDomain` `0x140023440`, `PostSubDomain` `0x140023478`) | both | `0x180079988` / `0x1800799b0` (`BsSndRpt64.exe` `0x1400233e0`) |
| `BugSplatHD64.exe -p %ld -c "%s" -a "%s" -v "%s"` (helper spawn template) | `BugSplat64.dll` | `0x18007a320` |
| `Exiting after crash, BugSplat network access disabled` | `BugSplat64.dll` | `0x180079fe0` |

i.e. the report goes to the **BugSplat SaaS** (`https://www.bugsplat.com`,
`<subdomain>.bugsplat.com` [INFERENCE: `PostSubDomain`+`PostDomain` default `bugsplat.com`])
with `database=covenant-eyes-10-1`: first `api/getCrashUploadUrl.php` (get an S3 upload URL),
then the dump is POSTed to S3, then `api/commitS3CrashUpload.php` commits it
(`…Database: %s, appName: %s, appVersion: %s` = `covenant-eyes-10-1`, `CovenantEyes64.exe`,
`10.1.44` from §1). `api/fullDumpFlag?database=` remotely controls whether full dumps are
allowed.

### 4. Deliberate-crash triggers (support/QA)

1. **`crashatonce=true` command-line switch** (string `@0x1408d92c8`, xref `0x1402a5e4c` in
   `InitInstance`): when parsed value equals `"true"`, the code executes an integer
   **self-divide of the zero global `DAT_140b5852c`** → `EXCEPTION_INT_DIVIDE_BY_ZERO`
   straight through the BugSplat path.
2. **`ForceCrashClient` setting** (`L"ForceCrashClient"` @`0x140a48458`): `FUN_1402c1540`
   (reached via dispatch thunk `FUN_1402b84b0`, handler table xref `0x1408ddaf0`) reads the
   value from the settings store (`FUN_1401e1270`/`FUN_1401e94c0`); if truthy it raises the
   fatal `"Forced crash"` @`0x1408dbc20` via noreturn `FUN_1404e9250` [INFERENCE: throw/abort
   with that message], which BugSplat then reports. A store-driven support kill-switch.
3. No `crashatonce`/`Forced crash` machinery exists in `RestartVS*.exe`/`vs-config.exe`
   (local sweep) — test crashes are client-side only.

### 5. Crash counters (writer side; reader side = `watchdog.md` §5)

Three distinct stores:

**a. Registry `ClientCrashesAt`/`ClientCrashesSince`** (the watchdog contract):
`ce::sys::settings::updateCrashStatistics` = `FUN_1401e2770` (tag @`0x140a48560`, log
`"updateCrashStatistics for "` @`0x140a485a8`) → state machine `FUN_1401e2c70` building
`<prefix>CrashesAt`/`<prefix>CrashesSince` (`CrashesAt` @`0x140a3bba8`, `CrashesSince`
@`0x140a3bc10`; prefixes `"Client"`/`"CommService"` @`0x140a3bb90`…) with window-based reset
and `%Y-%m-%dT%H:%M:%S` stamps — same shared code as `RestartVS.exe FUN_14002df80`
(watchdog.md §5). `ce::sys::settings::updateClientCrashStatistics` = `FUN_1401e25a0`
(tag @`0x140a485d8`) fixes the prefix to `"Client"`.

In `VictoryShield.exe` the **only** call site is the startup-telemetry updater
`FUN_1402b0d00` with **crashed-now = 0** (and window arg `0x165a0bc00`):
`FUN_1401e25a0(now, 0x165a0bc00, crashed=false)` — i.e. the client only **re-arms/clears**
the counter (resets `ClientCrashesSince` once the window has passed); it never increments.
**Increments (crashed-now=1) come from `RestartVS.exe`/`RestartVSClientOnly.exe` and the
installer** (`logs.md:272-273` `updateCrashStatistics for Client`), exactly as
`watchdog.md` §5 inferred. The `CommService` prefix has **no caller inside
VictoryShield.exe** — the `CommServiceCrashesAt/…Since` pair is written by service-side
binaries [INFERENCE: `VictoryShieldCommService.exe`, out of scope here]. Live values on the
VM (2026-09-24, `reg query HKCU\SOFTWARE\Covenant Eyes\Victory Shield`): `ClientCrashesAt
REG_SZ 2025-11-10T20:03:54.9051886`, `ClientCrashesSince REG_BINARY 00000000` — one
fresh-install-era crash stamp, counter zeroed.

**b. Telemetry-store counters `ClientCrashes`/`ServiceCrashes`** (`L"ClientCrashes"`
@`0x140a488b8`, `L"ServiceCrashes"` @`0x140a488d8`):
`ce::sys::settings::telemetry::updateProcessCrashes` = `FUN_1401e5a30` (tag @`0x140a48968`)
takes a signed delta, selects `"client"` vs `"service"` by
`ProcessIdToSessionId(GetCurrentProcessId())==0`, logs `"update <client|service> crashes by
<n>"`, and clamps `current + delta ≥ 0` (lambda `FUN_1401e5f40`, key xrefs
`0x1401e6053`/`0x1401e605a`; getter `FUN_1401ee410`, `processCrashes` = `FUN_1401e5720`
returns `Maybe<int>`). The BugSplat callback does `+1` at crash time.

**c. Metrics event** — `CVictoryShieldView::updateMetricsCrashes` = `FUN_1402ca270`, called
from the startup chain right after the counter clear:
1. read count `N` (`FUN_1401e5720`); `N < 1` → return;
2. log `"Recovering from client crashes: "` @`0x1408dc678` + `N`;
3. emit metrics event **`client_crash`** @`0x140a4d998` with attributes **`crash_type`**
   @`0x1408d9b28` = **`"GENERIC"`** @`0x1408dc6a0` and **`crash_count`** @`0x1408d9b08` = `N`;
4. `FUN_1401e5a30(-N)` — zero the accumulator.

So `ClientCrashes` is an accumulator: **+1 per crash, reported once as
`client_crash{crash_type=GENERIC, crash_count=N}` on the next successful start, then reset.**

### 6. Which binaries carry the integration

| binary | BugSplat? | evidence |
|---|---|---|
| `VictoryShield.exe` | **yes** | 4 BugSplat64.dll imports (IAT `0x1408d5288`-`0x1408d52a0`); `BugSplatExceptionCallback` @`0x1408d8e08`; RTTI `MiniDmpSender` @`0x140b17ad3`+ |
| `VictoryShieldCommService.exe` | **yes** | `re/findings/00-baseline/VictoryShieldCommService.exe.md` (BugSplat64.dll 4 imports); the comm-service logs also show `No recent crashes detected, initializing crash handler` (`logs.md`) — owned by another pass |
| `RestartVS.exe` / `RestartVSClientOnly.exe` / `vs-config.exe` / `VSWD.*` | no | zero BugSplat imports/strings in local sweeps; VSWD is a pure counter reader (`watchdog.md`) |
| `BsSndRpt64.exe` | helper | ships on disk (`C:\Program Files\CE`, 380,864 B, listing 2026-09-24) with `BugSplat64.dll`/`BugSplatRc64.dll`; spawned by the DLL at upload time [INFERENCE] |

## Evidence

All VAs are in `VictoryShield.exe` (base `0x140000000`, Ghidra program + identical local
sample `re/samples/00-baseline/VictoryShield.exe`):

- `FUN_1402a47d0` `CVictoryShieldApp::InitInstance` (ctor @`0x1402a49c3`, setCallback
  @`0x1402a4af0`, `crashatonce` @`0x1402a5e4c`), `FUN_1402a1a40` `BugSplatExceptionCallback`,
  `FUN_1402a3da0` attachment wrapper, `FUN_1402a1a00` dtor site, `FUN_1401f1a80`/`FUN_1401f1520`
  restart-target path builder, `FUN_1402c1540`/`FUN_1401e1270` `ForceCrashClient`,
  `FUN_1402b84b0` dispatch thunk (table @`0x1408ddaf0`), `FUN_1401e2770`/`FUN_1401e2c70`/
  `FUN_1401e25a0` registry counters, `FUN_1401e5a30`/`FUN_1401e5f40`/`FUN_1401ee410`/
  `FUN_1401e5720` telemetry counters, `FUN_1402ca270` `updateMetricsCrashes`,
  `FUN_1402b0d00` startup telemetry.
- Strings: `"covenant-eyes-"` `0x1408d8ff8`, `L"CovenantEyes"` `0x1408d8fd8`, `L".exe"`
  `0x1408d8fc8`, `BugSplatExceptionCallback` `0x1408d8e08`, `debugLogs.zip` `0x1408d8e88`,
  `debugClassLogs.zip` `0x1408d8e98`, `debugDB.zip` `0x1408d8eb0`, `-FSr` `0x1408d8ebc`,
  `zip.exe` `0x1408d8ec8`, `ce-file-shm/-wal`, `ce-user-file-shm/-wal` `0x1408d8ed0`-`0x1408d8f08`,
  ` --PID=` `0x1408d8f20`, `--RestartRequestFrom=` `0x1408d8f28`, `Crash processing is done: `
  `0x1408d8f48`, `Crash processing - invalid exception code` `0x1408d8f68`,
  `Crash processing is done - already active` `0x1408d8f98`, `crashatonce` `0x1408d92c8`,
  `Forced crash` `0x1408dbc20`, `crash_count`/`crash_type` `0x1408d9b08`/`0x1408d9b28`,
  `client_crash` `0x140a4d998`, `ClientCrashes`/`ServiceCrashes` `0x140a488b8`/`0x140a488d8`,
  `updateCrashStatistics` `0x140a48560`, `updateClientCrashStatistics` `0x140a485d8`,
  `updateProcessCrashes` `0x140a48968`, `Recovering from client crashes: ` `0x1408dc678`,
  `CrashesAt`/`CrashesSince`/`CommService` `0x140a3bba8`/`0x140a3bc10`/`0x140a3bb90`.
- Cross-refs: `re/findings/14-watchdog/watchdog.md` §5-§8 (read side + `RestartVS*` restart
  counts and escalation dialog), `re/findings/02-artifacts/logs.md` (installer
  `updateCrashStatistics for Client`; comm-service `No recent crashes detected, initializing
  crash handler`), `re/findings/00-baseline/VictoryShieldCommService.exe.md` (BugSplat in the
  service).
- On-disk (VM, read-only `Get-ChildItem 'C:\Program Files\CE'`, 2026-09-24 20:47):
  `BugSplat64.dll` 646,592; `BugSplatRc64.dll` 181,184; `BsSndRpt64.exe` 380,864;
  `zip.exe` 301,504. Vendor-string VAs in those two files as tabulated in §3 (PE-parsed
  UTF-16 with section-mapped VAs; `BugSplat64.dll` base `0x180000000`, `BsSndRpt64.exe`
  base `0x140000000`). Live registry (`reg query HKCU\SOFTWARE\Covenant Eyes\Victory Shield`):
  `ClientCrashesAt = 2025-11-10T20:03:54.9051886`, `ClientCrashesSince = 00000000`.

## Linux-reimplementation notes

- Crash pipeline = structured minidump (Linux: coredump + `coredumpctl`/`minidump` via
  Breakpad-equivalent) + **zipped logs + state DB** attached, then a restart helper. Keep
  CE's caps (5 MB/file, 19 MB total) or better: compress + redact.
- **Do not copy the payload default**: CE uploads the *entire local activity database*
  (`ce-file`/`ce-user-file`) with every crash report — for an accountability client that is a
  privacy landmine. Upload only logs + a sanitized state summary, and gate anything else
  behind explicit consent.
- Restart policy worth copying: dedicated restart helper with `--RestartRequestFrom=<ver>
  --PID=<pid>`, a shared single-instance mutex, and a **restart budget (≤3)** with a human
  escalation dialog afterwards; feed a "crashed at" timestamp + counter into the watchdog so
  auto-relaunch backs off (CE: 10 min).
- Counter design worth copying: split (a) registry "crashed at/since" contract read by the
  supervisor (written by the *restart helper*, cleared by the client on healthy start after a
  window), and (b) an accumulator reported as one `client_crash{count=N}` metric at next
  startup and then reset. `crash_type=GENERIC` today — a clean-room client should classify.
- Test hooks worth copying: a cmdline `crashatonce=true` self-crash and a config-driven
  `ForceCrashClient` kill-switch for support.

## Open questions

1. **BugSplat flags `0x6004`** — exact `MDS_*` semantics not decoded (no BugSplat headers
   locally) [INFERENCE: enables minidump + some attachment/UX options].
2. **Upload protocol details** — server strings are now pinned (§3: `https://www.bugsplat.com`
   + `api/getCrashUploadUrl.php` → S3 → `api/commitS3CrashUpload.php`, `database=
   covenant-eyes-10-1`); the exact request bodies and the `fullDumpFlag` server policy are
   vendor-side and out of scope (backend reporting protocol belongs to the later pass).
3. **`MiniDumper::restartAfterCrash` vs the BugSplat callback** — both paths exist in the
   shared CE code; the BugSplat callback (→ `RestartVSClientOnly.exe`) is the one wired to
   crashes in `VictoryShield.exe`, while `restartAfterCrash` (→ `RestartVS.exe`) is visible
   in `vs-config.exe`/`RestartVS.exe`. Which production crashes trigger the latter
   (if any) is [INFERENCE] only — likely none in the BugSplat flow.
4. The `0x165a0bc00` window argument passed to `updateClientCrashStatistics` at startup:
   value = 6,000,000,000 [INFERENCE: 10 minutes in 100 ns ticks — matches VSWD's 10-minute
   back-off], unit not pinned by code evidence.
