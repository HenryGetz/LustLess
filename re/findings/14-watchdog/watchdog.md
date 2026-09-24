# VSWD watchdog — session supervision, relaunch, crash counters, restart utilities

Scope: `VSWD.exe`, `VSWD.dll` (and, for call-site tracing only, read-only `vs-config.exe`),
`RestartVS.exe`, `RestartVSClientOnly.exe`, `ProcessPrivileges.dll`. Builds on
`re/findings/00-baseline/{VSWD.exe,VSWD.dll,RestartVS.exe,RestartVSClientOnly.exe,ProcessPrivileges.dll}.md`
(no metadata duplication — this doc goes deeper into behavior).

Method-name/VA citation convention: VSWD.* are CIL assemblies; Ghidra lists the managed methods at
their method RVAs (`VSWD.dll` image base `0x10000000`, `VSWD.exe` `0x00400000`), and the IL bodies
were disassembled from the local samples `re/samples/00-baseline/VSWD.dll|.exe` (dnfile/dncil IL
dump). "IL @0x…" below means the method body at that VA. Native functions in
`RestartVS*.exe`/`vs-config.exe` are cited by Ghidra function address.

## What it does

`VSWD.exe` is the SCM entry for the `VSWD` service; the entire implementation lives in
`VSWD.dll` (assembly name `VSWD` 10.1.44.0, "WatchdogServiceLibrary"), whose
`WatchdogService.ProtectionService` (a `ServiceBase`) is run by `VSWD.exe`
(`WatchdogService.Program::Main` IL @0x00404c83: `ServiceBase.Run(new ServiceBase[]{ new ProtectionService() })`).
The service:

1. polls Windows Terminal Services **once per second** (`WTSEnumerateSessionsExA`) for user
   sessions and relaunches `VictoryShield.exe` into any interactive session that lacks it,
   via `CreateProcessAsUser` using the session's `explorer.exe` primary token;
2. suppresses relaunch for 10 minutes after a recorded client crash (crash counters read from the
   session user's `Software\Covenant Eyes\Victory Shield` registry key);
3. runs the Registry/Folder Protectors (see `protectors.md`) and an MSI-uninstall-key cleanup;
4. exposes the `disableFileProtection`/`disableRegistryProtection` entry points and SCM custom
   commands used by `vs-config.exe`/the installer to turn protections off.

`RestartVS.exe` (full stack: services + client) and `RestartVSClientOnly.exe` (client only) are
**not** launched by VSWD — no `RestartVS` string exists in `VSWD.exe`/`VSWD.dll`. They are launched
by the client-side crash handler (`MiniDumper::restartAfterCrash`) and the admin tooling (below).

## Mechanism

### 1. Service wiring and startup

- `ProtectionService::.ctor` (IL @0x1000246f): creates a one-shot `System.Timers.Timer`
  (`startWatching`), `ProcessorArchitecture`, and `registrySettingsToProtect_` (capacity 4).
- `InitializeComponent` (IL @0x10002da5): `ServiceName = "VSWD"`, **`CanStop = false`**, `CanShutdown
  = true`, `AutoLog = false`. (SCM STOP is therefore refused; only custom commands/shutdown work —
  this pairs with the service SDDL from `01-dynamic-recon`.)
- `OnStart` (IL @0x100029ac): hooks `StartWatching_Elapsed` on the timer with `Interval = 100`,
  `AutoReset = false`, enables it — all startup work is deferred 100 ms after SCM start.
- `StartWatching_Elapsed` (IL @0x10002a04): EventLog source = `ServiceName`, log = `Application`
  (creates source if missing); logs `"Service starting up, System: [<arch>]"`, then
  `CleanupRegistryUninstallValues` → `ProtectRegistrySettings` → `ProtectFolders` →
  `MonitorProcess`; stops the timer; logs `"Startup complete"`. (`InitEventLog` @0x10002868
  registers source `"WatchdogLibrary"` in `Application`.)
- `MonitorProcess` (IL @0x10002ccc): `pmon_ = new ProcessMonitor(cePath); pmon_.Start();` where
  `cePath = AppDomain.CurrentDomain.BaseDirectory + "VictoryShield.exe"` and
  `cePathQuoted = "\"…\""`, both set in `ProtectionService::.cctor` (IL @0x10002dc8) — i.e.
  `c:\Program Files\CE\VictoryShield.exe` on the shipping layout.
- `OnStop` (IL @0x10002cec): logs `"Service is stopping"`, `RemoveAll` over both protector lists
  (lambdas `b__45_0/1` match everything → disposes all protectors). `OnShutdown` (IL @0x10002d64):
  logs `"Service is shutting down"` and reuses `OnCustomCommand(243)` (below) before
  `base.OnShutdown` — protections are explicitly lifted on system shutdown.

### 2. Session discovery — polling, not notifications

- `ProcessMonitor::GetActiveSessions` (IL @0x10004328) P/Invokes **`WTSEnumerateSessionsExA`**
  (`wtsapi32`), marshals `WTS_SESSION_INFO_1A` (fields used: `SessionId`, `pSessionName`,
  `pHostName`, `pUserName`, `pDomainName`, `pFarmName`, `State`), frees with `WTSFreeMemory`.
  A session is "active" if `State` is `WTSActive` (0) **or** `WTSConnected` (1) **and**
  `pUserName` is non-null/non-empty.
- The full P/Invoke set (dnfile `ImplMap`, `re/samples/00-baseline/VSWD.dll`) contains
  `WTSEnumerateSessionsExA`, `WTSQuerySessionInformation`, `WTSFreeMemory`,
  `WTSGetActiveConsoleSessionId` — **no** `WTSRegisterSessionNotification`/`WTSWaitSystemEvent`:
  session discovery is pure 1-second polling.
- `ProcessMonitor::Start` (IL @0x10004200) spawns a background thread (`MonitorThread`
  @0x10004414: `Thread.Sleep(1000)` once, then `ThreadLoop`) and registers
  `Microsoft.Win32.SystemEvents.SessionEnded += OnSystemSessionEnded` (logs
  `"OnSystemSessionEnded called"`; `Stop` unregisters and joins the thread).

### 3. The relaunch loop (`ProcessMonitor::ThreadLoop`, IL @0x10004608)

Loop cadence: tail of loop is `_eventTerminate.WaitOne(1000, true)`; if signaled → return,
else next iteration — a **1-second polling loop**.

Per iteration:

1. `GetActiveSessions()` → map to session-id list (`<ThreadLoop>b__23_0` @0x10004b2c).
2. If the id set changed vs `_lastSessionIds`: log
   `"Sessions change from [a, b] to [c, d]"`; log `"Session info:"` with per-session
   `Session ID/Session name/Host name/User name/Domain name/Farm name/State` (or
   `"No active sessions detected"` when the list is empty).
3. `procs = Process.GetProcessesByName("VictoryShield")`
   (`Path.GetFileNameWithoutExtension(_processFileName)`).
4. For each session id `s` (skipping `s == 0`):
   - `inSession = procs.Where(p => p.SessionId == s)` (`b__3` @0x10004b4e) then
     `.Where(<ThreadLoop>b__23_4)` @0x10004af5 — **full-path identity check**:
     `Path.GetFullPath(p.MainModule.FileName) == Path.GetFullPath(_processFileName)`
     (`String.Equals(…, 5)` = OrdinalIgnoreCase). A process merely *named* `VictoryShield.exe`
     in another directory does not satisfy the watchdog.
   - `explorers = Process.GetProcessesByName("explorer").Where(p => p.SessionId == s)` (`b__5`).
   - **Relaunch condition** (IL @0x10004608 offsets 0x326–0x336):
     `inSession.Length == 0 && s > 0 && explorers.Length != 0 &&
      !CheckIfCECrashedRecently(s)`.
   - On trigger: log `"Re-launching CE process under session <s>"`, then
     `WindowsServiceLaunchingExe.NativeMethods::LaunchProcess("\"" + _processFileName + "\"", s)`
     — the **command line is the quoted executable path, no arguments**. Exceptions are logged
     `"WindowsServiceLaunchingExe exception: <msg>"`.

So the client is (re)started only into logged-in sessions with a shell (`explorer.exe` present),
one instance per session, and only when its on-disk path is the canonical install path.

### 4. Launch pipeline (`WindowsServiceLaunchingExe.NativeMethods`, IL @0x1000216c–0x1000244d)

`LaunchProcess(cmdLine, sessionId)` @0x10002248:
1. `GetTokenAndSessionId(sessionId, out token)` @0x1000216c: takes `explorer` processes
   (`" prerequisite error 1"` if none), filters to explorer in `sessionId`
   (`"<caller> prerequisite error 2 for session <s>"`), uses the first one's PID →
   `GetPrimaryToken` @0x100022a0: `OpenProcessToken(proc.Handle, TOKEN_DUPLICATE=2)` +
   `DuplicateTokenEx(token, 11 /*TOKEN_ASSIGN_PRIMARY|DUPLICATE|QUERY*/, SecurityImpersonation,
   TokenPrimary)`; logs `"OpenProcessToken Error: {0}"` / `"DuplicateTokenEx Error: {0}"` and
   throws; failure to obtain a token logs `"<caller> prerequisite error 3"`.
2. `GetEnvironmentBlock(token, inherit=false)` @0x1000233c: `CreateEnvironmentBlock`
   (`"CreateEnvironmentBlock Error: {0}"` on failure).
3. `LaunchProcessAsUser(cmdLine, token, env)` @0x10002378: `CreateProcessAsUser(token, NULL,
   cmdLine, …, bInheritHandles=TRUE, dwCreationFlags=CREATE_UNICODE_ENVIRONMENT (0x400), env,
   NULL, STARTUPINFO{ cb, lpDesktop = NULL, dwFlags = 0x41 (STARTF_USESHOWWINDOW |
   STARTF_FORCEONFEEDBACK), wShowWindow = SW_SHOWNORMAL })`; on failure throws
   `"CreateProcessAsUser Error: {0}"`. `LaunchProcess` then `DestroyEnvironmentBlock`.

### 5. Crash counters (`ClientCrashesAt` / `ClientCrashesSince`)

**Storage**: value names `ClientCrashesAt` (string, round-trip timestamp) and `ClientCrashesSince`
under `Software\Covenant Eyes\Victory Shield` **in the target user's profile hive** (HKCU), i.e.
one counter per user. Read by VSWD via `RegQueryValueEx` on a key opened with
`RegOpenKeyEx(hProfile, "Software\Covenant Eyes\Victory Shield", 0, KEY_QUERY_VALUE)` where
`hProfile` is the `LoadUserProfile` handle of the session's user
(`CheckIfCECrashedRecently` IL @0x10004510).

`static CheckIfCECrashedRecently(UInt32 sessionId) → bool` (IL @0x10004510):
1. `GetTokenAndSessionId(sessionId, out token)` — failure → return false (relaunch allowed).
2. `WTSQuerySessionInformation(hServer=0, sessionId, WTSUserName=5)` → user name
   (`"Check crash prerequisite error 1"` → false).
3. `LoadUserProfile(token, PROFILEINFO{ lpUserName, dwFlags=PI_NOUI=1 })`
   (`"Check crash prerequisite error 2"` → false).
4. `RegOpenKeyEx(hProfile, …)` (`"Check crash prerequisite error 3"` → false).
5. `GetCrashCount(key)` @0x100044c8 — `RegQueryValueEx("ClientCrashesSince")` into a
   `StringBuilder`; **as compiled it returns `StringBuilder.get_Chars(0)`** — the UTF-16 code of
   the value's first character (e.g. `'5'` → 53). The only caller tests `!= 0`, so the value is
   effectively a **non-empty flag**: "a crash has been recorded". [INFERENCE: the source intended
   to parse an integer; any non-empty `ClientCrashesSince` counts as crashed.]
6. `GetLastCrashedTime(key)` @0x1000445c — `RegQueryValueEx("ClientCrashesAt")`,
   `DateTime.TryParseExact(…, "yyyy-MM-ddTHH:mm:ss.FFFFFFF", RoundtripKind).ToUniversalTime()`.
7. Returns `DateTime.UtcNow < lastCrash.AddMinutes(10)` — i.e. **"crashed within the last 10
   minutes"**. ThreadLoop then *skips* the relaunch for that tick (checked again every second, so
   the practical back-off is "no relaunch until 10 min after `ClientCrashesAt`").

**Writers**: nothing in VSWD writes these values. `RestartVS.exe` embeds the shared
`ce::sys::settings::updateCrashStatistics` (below) which writes
`{prefix}CrashesAt`/`{prefix}CrashesSince` with `prefix = "Client"`; the installer logs
`updateCrashStatistics for Client` while writing/clearing them
(`re/findings/02-artifacts/logs.md:272-273`). [INFERENCE: `VictoryShield.exe` (off-limits)
updates its own crash counter on crash/startup — VSWD is a pure reader.]

### 6. `RestartVS.exe` (full stack)

`actualMain` = `FUN_140007110` (Ghidra `RestartVS.exe` @0x140007110):
- single-instance mutex **`RestartVSIsRunning`** (strings @0x1402fb970…0x1402fba90; log
  `"Successfully locked RestartVSIsRunning"`, `"RestartVS must be already running."`,
  `"Failed to lock RestartVSIsRunning mutex, exiting."`);
- restarts the two services (`FUN_1400278d0` called with the 4-char name `"VSWD"` at
  `DAT_1402fb908` and `"VictoryShieldCommService"` @0x1402fb…; the shared
  `ce::service::restartService` logs `"Restarting <name> service to fail to restart"`
  @0x1402fe3a0), then `FUN_140028c90` (client-process restart); logs
  `"Restart completed successfully."`/`"failed."` + `" You may close this window."`;
- updates the client crash counter via `ce::sys::settings::updateCrashStatistics`
  (`FUN_14002dbf0` @0x14002dbf0, log `"updateCrashStatistics for "` @0x1403027a0,
  `"update … crash counter"` @0x1403027d8, tag `ce::sys::settings::updateCrashStatistics`
  @0x1403027e8, source `CommonLibrary\src\CeSystemSettings.cpp:562`).

`updateCrashStatistics::<lambda_1>::operator()` = `FUN_14002df80` @0x14002df80 — the counter
state machine (args: name-prefix, crashed-now flag, timestamp, window duration, flag):
- reads `{prefix}CrashesSince` and `{prefix}CrashesAt` (built as prefix + `"CrashesSince"` /
  `"CrashesAt"`, strings @0x1402fbed0/0x1402fbf98; prefixes `"Client"` @0x1402fbf48 and
  `"CommService"` @0x1402fbf58 → values `ClientCrashesAt/Since`,
  `CommServiceCrashesAt/Since` [INFERENCE for the CommService pair]),
- if `CrashesAt + window < now` (window passed by caller) it **resets `CrashesSince` to 0**,
- on `crashed-now`: writes `CrashesAt` = timestamp formatted **`"%Y-%m-%dT%H:%M:%S"`**
  (ISO-8601 without offset; note VSWD's `TryParseExact` accepts the longer
  `"yyyy-MM-ddTHH:mm:ss.FFFFFFF"` form of the same shape), increments and rewrites
  `CrashesSince`;
- the settings store is chosen by process context: session 0 → machine settings (`"Victory Shield"`
  key under HKLM), user session → per-user settings (`FUN_14002c110`/`FUN_14002bd10`/
  `FUN_14002bbc0` branches on `ProcessIdToSessionId(GetCurrentProcessId())`).

`MiniDumper::restartAfterCrash` (visible in `vs-config.exe` `FUN_1400c3e40` @0x1400c3e40 —
same code+strings exist in `RestartVS.exe`: message @0x140305640, tag @0x1403055c0):
if the app name equals `"VictoryShield"`, show
`MessageBoxA("Victory Shield has encountered an unexpected problem and will now restart.")`,
then `ShellExecuteA("open", <…>\RestartVS.exe)` (path built by `FUN_1400320a0` @0x1400320a0,
string `"RestartVS.exe"` @0x140393de8) and logs `"Result from ShellExecute = "`.
[INFERENCE: the same handler compiled into `VictoryShield.exe` is the production launcher of
`RestartVS.exe` after a client crash; in `vs-config.exe` the `"VictoryShield"` name test makes it
dormant. `vs-config.exe` also contains `ce::watchdog_service::backdoorStop`/`::uninstall` and a
process-name whitelist including `RestartVS.exe`, `VSWD.exe`, `CEWD.exe`, `VictoryShieldCommService.exe`
(strings @0x14038…e.g. `RestartVS.exe` @0x140393de8).]

### 7. `RestartVSClientOnly.exe` (client only)

Client-side counterpart: no SCM imports (baseline), shared `RestartVSIsRunning` mutex with
`RestartVS.exe` (mutual exclusion, log `"RestartVS is already running"` @0x14031e1c8). Its
`actualMain` = `FUN_1400066b0` @0x1400066b0 parses CLI options via `boost::program_options`:

- `--RestartRequestFrom <revision>` (`"Specify restart from a client revision"` @0x14031e158,
  option name `"RestartRequestFrom"` @0x14031e180) — which client build requested the restart;
- a PID option (`"Specify Process ID of Client that crashed"`; option-name string at
  `DAT_14031e1c4`) — the crashed client process.

Flow: logs `"RestartVSClientOnly version: "`, `"VS Process owner: … System user: …"`,
`"Restart count: <n>"` (@0x14031e1e8, logged at `0x140007c7c` with the counter value). Then
(`0x140007d08`): **`CMP R12D, 0x3; JLE` — restart count ≤ 3 ⇒ restart the client**
(log `"Client restart "` @0x14031e3c8 @0x14000870c); **count > 3 ⇒ escalation**:
log `"Too many restarts, Client is not restarted automatically!"` (@0x14031e1f8, site
`0x140007ec0`) and `MessageBoxW` (flags `0x10010`) with
`"We've detected several restarts.…Contact Member Care: +1 989.720.8000,
info@covenanteyes.com, helpforum.covenanteyes.com"` (caption `"Victory Shield"`,
string @0x14031e240, dialog site `0x140007fe0`). Without `--RestartRequestFrom` it logs
`"Started manually"` (`0x1400089b1`). The counter itself comes from the same shared
`updateCrashStatistics` code (`"CrashesSince"` @0x14031e5c0, `"CrashesAt"` @0x14031e670, refs at
`0x14003787f/0x140037a7d/0x140037d2d`).

### 8. Interplay with SCM recovery (double-restart protection)

- The `FailureActions` REG_BINARY that VSWD *protects* for both services (embedded blob,
  `VSWD.dll` VA `0x10002130` area — see `protectors.md`) decodes to `dwResetPeriod = 0xFFFFFFFF`
  (never reset), `cActions = 3`, each `SC_ACTION_RESTART` with `Delay = 1000 ms` —
  **RESTART ×3 @1 s** for *service* crashes, matching the established live-surface fact.
- The two supervisors act on different processes: SCM restarts `VSWD.exe` itself; VSWD restarts
  `VictoryShield.exe`. There is **no code in VSWD that queries SCM/service state** (no
  `QueryServiceStatus` in the P/Invoke table) — no explicit handshake. Coordination is implicit:
  (a) VSWD only relaunches when the session has *no* identity-matching client process, so a
  SCM-spawned VSWD cannot duplicate a running client; (b) the 10-minute crash window suppresses
  relaunch storms; (c) `RestartVS*` share the `RestartVSIsRunning` mutex; (d) `CanStop=false` +
  service SDDL + protected `FailureActions`/`ImagePath` keep the supervisor itself alive.
  [INFERENCE: the only "double restart" hazard is VSWD relaunching the client while the client's
  own `MiniDumper::restartAfterCrash` fires `RestartVSClientOnly`; the mutex + crash counters
  (both paths funnel through `updateCrashStatistics("Client")`) are what damp it.]

### 9. IPC / shared state between VSWD and the comm service

String sweeps over `VSWD.exe`, `VSWD.dll`, `RestartVS.exe`, `RestartVSClientOnly.exe`,
`ProcessPrivileges.dll` (UTF-16 + ASCII, local samples) find **no** `127.0.0.1`, `48867`,
`ce_user_event_message_queue`, named-pipe, socket, or named-event strings in these binaries.
The watchdog's touchpoints are:

- **Registry** — the shared contract: `Software\Covenant Eyes\Victory Shield`
  (`ClientCrashesAt/…Since`), plus the service keys it protects;
- **SCM** — service start/stop and custom commands (below);
- **Windows Event Log** — `Application` log, sources `VSWD`/`WatchdogLibrary`;
- **Process creation** — `CreateProcessAsUser` into user sessions.

The `ce_user_event_message_queue`/`127.0.0.1:48867` vocabulary belongs to
`VictoryShieldCommService`/UI (out of scope here).

### 10. Admin toggle: custom commands + `vs-config.exe` call sites

`ProtectionService::OnCustomCommand(int)` IL @0x10002944 (ignored while the 100 ms startup timer
is still armed):

| command | action |
|---|---|
| **243** | `UnprotectRegistry()` (all RegistryProtectors `Enabled=false`) + `UnprotectFiles()` (FolderProtector.Disable + `FolderUnprotector.UnprotectFolderSecurity` = Everyone-full-control ACL restore) + `pmon_.Stop()` + log `"Requested command completed"` + `ServiceBase.Stop()` — graceful "protections off, stop". Also invoked internally by `OnShutdown`. |
| **176** | `Environment.Exit(3011)` — hard self-kill with exit code 3011. |

`vs-config.exe` disables protection **out of process** via the `VSWD.dll` exports:
`FUN_14008e690` @0x14008e690 (`DynamicLib::makeSafely("VSWD.dll")` — log prefix `"load library: "`,
then `GetProcAddress("disableFileProtection")` called as `fn(&oneBSTR, 1)` and
`GetProcAddress("disableRegistryProtection")` called as `fn(sixBSTRs, 6)`); callers:
`FUN_140018d30` @0x140018d30 (`disableWatchdogProtection`, `VSConfig\src\main.cpp:259`, log
`"removing watchdog protection"`) and wrapper `FUN_1402fd1a8` @0x1402fd1a8
(`CALL 0x14008e690`, returns 0). See `protectors.md` for export semantics.

### 11. Uninstall / removal flow (cross-ref `re/findings/02-artifacts/logs.md`)

- Installer/upgrade stops the watchdog with `stopAtAllCosts` (60,000 ms timeout, poll loop) and
  (re)installs/uninstalls old-generation services `CovenantEyesCommService`/`CEWD` →
  `VictoryShieldCommService`/`VSWD` (logs.md §"Component inventory";
  `DependOnService` logged as `RpcSs, SamSs, EventLog, ProfSvc` for the watchdog — exactly the
  list VSWD itself protects).
- `vs-config.exe`'s `ce::watchdog_service` module: `backdoorStop` ("Stopping watchdog service at
  all costs", "Watchdog stopped at …", "Watchdog failed to stop when asked nicely"),
  `uninstall` ("uninstalling watchdog service", "failed to stop watchdog service kindly",
  "failed to stop watchdog service mercilessly", "uninstall the legacy watchdog service" —
  strings near `VSWD.dll` @0x140398950); `ce::local_comm_service::stopAndVerify` ("Waiting for
  Comm Service to stop: …", "Comm Service binary is … still locked!") handles the comm-service
  binary lock.
- Before files can be deleted, `disableWatchdogProtection` (via the `VSWD.dll` exports) lifts the
  install-dir ACL; then service delete + file removal proceed (logs.md).
- `CleanupRegistryUninstallValues` (below) keeps the ARP entry non-modifiable.

### 12. Self-protection specifics (watchdog half)

- **Run-key behavior** — there is no Run-key *cleanup/deletion* in VSWD. The Run value is
  **protected**: `HKLM\…\Run` / `"Victory Shield"` and `HKLM\…\Explorer\StartupApproved\Run` /
  `"Victory Shield"` are two of the 22 protected registry values (restored verbatim on any
  change; `protectors.md`). The routine the baseline called "Run-key cleanup" is actually
  `CleanupRegistryUninstallValues` IL @0x10002ab4, which runs **unconditionally at every service
  start** and deletes the values `WindowsInstaller` and `ModifyPath` from
  `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{5AC5ED2E-2936-4B54-A429-703F9034938E}`
  (errors logged `"Failed registry cleanup: "`). Effect: the MSI "Change/Repair" entry loses its
  modify path — ARP can uninstall but not repair/modify. [INFERENCE: this stops users re-running
  the MSI to tamper with the install; it is not autostart-related.]
- **ACL enforcement** — Folder Protector locks `C:\Program Files\CE\` (Everyone deny
  delete/delete-child + allow read; full details in `protectors.md`). The RegistryProtector ACL
  machinery (`ProtectSubkey`/`SetRules`/`TakeOwnership`) exists but is **not exercised by the
  default wiring** (all 22 protectors are value-level, i.e. non-empty value names; the ACL path
  runs only for an empty value name) [INFERENCE: dead/optional path — open question].
- **Process protection** — none: VSWD does not guard itself or other CE processes against kill.
  Its resilience is configuration-level (`CanStop=false`, service SDDL, `FailureActions`
  RESTART×3@1s, registry-protected `ImagePath`/`ObjectName`/`FailureActions`, restart supervision
  of the client). `RestartVSClientOnly.exe` identifies the client by module path and PID, but
  terminates nothing foreign.
- **`ProcessPrivileges.dll` usage** — `VSWD.exe` references assembly `ProcessPrivileges 1.5.7.0`
  (dnfile `AssemblyRef`); `VSWD.dll` compiles the same code in-tree (namespace
  `ProcessPrivileges`: `PrivilegeEnabler` @0x10003bfd, `ProcessExtensions` @0x10005386,
  `Privileges` @0x1000569c). Usage sites in these binaries are **token-privilege toggles for ACL
  work only**: `RegistryProtector::ProtectSubkey/UnProtectSubkey` (privilege set
  `SeTakeOwnershipPrivilege, SeBackupPrivilege, SeRestorePrivilege` — enum values (29, 2, 22),
  embedded array `0x10002160`) and `FileUtilities.FolderUtilities::TakeOwnership`
  (`SeTakeOwnershipPrivilege` = enum 29). No `SeDebugPrivilege` use, no process manipulation in
  these binaries.

## Evidence

- Ghidra MCP (project `CE`, programs `VSWD.dll`, `VSWD.exe`, `RestartVS.exe`,
  `RestartVSClientOnly.exe`, `vs-config.exe`): method/function listings and addresses as cited
  above; `disassemble_bytes` of `VSWD.dll` `0x100101ee–0x10010204` (export thunks), `vs-config.exe`
  `0x1402fd1a8` (wrapper), `RestartVSClientOnly.exe` `0x140007b40–0x140007edf`
  (`CMP R12D, 0x3; JLE 0x140008000` at `0x140007d08`; `"Restart count: "` log call at
  `0x140007c7c`; `"Too many restarts…"` at `0x140007ec7`).
- IL disassembly of `re/samples/00-baseline/VSWD.dll`/`VSWD.exe` (dnfile+dncil):
  `ProcessMonitor::ThreadLoop` @0x10004608 (`_eventTerminate.WaitOne(1000, true)` loop tail;
  relaunch branch `LaunchProcess("\""…, sessionId)`), `GetActiveSessions` @0x10004328
  (`WTSEnumerateSessionsExA` call), `CheckIfCECrashedRecently` @0x10004510
  (`WTSQuerySessionInformation(…,5)`, `LoadUserProfile`, `RegOpenKeyEx(hProfile, …)`,
  `AddMinutes(10)` comparison), `GetCrashCount` @0x100044c8 (`get_Chars(0)` return),
  `GetLastCrashedTime` @0x1000445c (`TryParseExact("yyyy-MM-ddTHH:mm:ss.FFFFFFF")`),
  `WindowsServiceLaunchingExe.NativeMethods` @0x1000216c–0x1000244d (`OpenProcessToken(…,2)`,
  `DuplicateTokenEx(…,11,1,1)`, `CreateProcessAsUser(…,0x400,…)`),
  `ProtectionService::{OnStart,StartWatching_Elapsed,OnCustomCommand,OnShutdown,.cctor,
  CleanupRegistryUninstallValues}` @0x100029ac/0x10002a04/0x10002944/0x10002d64/0x10002dc8/0x10002ab4,
  `WatchdogService.Program::Main` @0x00404c83 (`VSWD.exe`).
- `re/samples/00-baseline/VSWD.dll` dnfile `ImplMap` (P/Invoke table — WTS/registry/advapi32 sets)
  and `AssemblyRef` (`VSWD.exe` → `ProcessPrivileges 1.5.7.0`).
- Managed string addresses (VA-mapped, `re/samples/00-baseline/VSWD.dll`):
  `"Re-launching CE process under session "` @0x1000d770, `"CreateProcessAsUser Error: {0}"`
  @0x1000cef6, `"ClientCrashesAt"` @0x1000d440, `"ClientCrashesSince"` @0x1000d498.
- `RestartVS.exe` strings: `RestartVSIsRunning` @0x1402fb970, `CrashesSince` @0x1402fbed0,
  `CrashesAt` @0x1402fbf98, `Client`/`CommService` @0x1402fbf48/@0x1402fbf58,
  `ce::sys::settings::updateClientCrashStatistics` @0x140302770,
  `ce::sys::settings::updateCrashStatistics` @0x1403027e8, `ce::service::restartService`
  @0x1402fe380, `MiniDumper::restartAfterCrash` @0x1403055c0, restart message @0x140305640.
- `RestartVSClientOnly.exe` strings: `RestartRequestFrom` @0x14031e180,
  `"Specify restart from a client revision"` @0x14031e158, `"Restart count: "` @0x14031e1e8,
  `"Too many restarts, Client is not restarted automatically!"` @0x14031e1f8, support dialog
  @0x14031e240, `"Client restart "` @0x14031e3c8, `"RestartVS is already running"` @0x14031e1c8.
- `vs-config.exe`: `VSWD.dll` @0x140398950, `disableFileProtection` @0x1403989a0,
  `disableRegistryProtection` @0x1403989b8, `RestartVS.exe` @0x140393de8; functions
  `FUN_14008e690` (export caller), `FUN_140018d30` (`disableWatchdogProtection`),
  `FUN_1400320a0` (RestartVS path builder), `FUN_1400c3e40` (`MiniDumper::restartAfterCrash`).
- `re/findings/02-artifacts/logs.md:205-212` (service install/stop inventory,
  `DependOnService = RpcSs, SamSs, EventLog, ProfSvc`), `:272-273` (`ClientCrashesAt/Since`
  written/cleared around client start, `updateCrashStatistics for Client`).

## Linux-reimplementation notes

- The supervision loop is trivially portable: a 1 Hz poll of `loginctl` sessions (or
  `sd-login`'s seat/session signals — event-driven would be an improvement over CE's polling),
  one agent per active graphical session, launched with that session's user credentials
  (`systemd --user` instance or a small `setuid`-less spawn helper). Identity-check the agent
  binary by canonical path (CE's `MainModule.FileName` check) before declaring "running".
- Back-off: a single `last_crash_at` timestamp + "do not restart within N minutes" state (CE:
  10 min, per-user) plus a monotonically counted crash total with escalation (CE: >3 ⇒ no
  auto-restart + user-facing support prompt). Persist both per user (CE uses HKCU; a
  per-user state file or the service DB suffices).
- The relaunch command line is just the quoted executable path — no hidden args; keep the
  supervisor's launch spec declarative and auditable.
- CE has *no* IPC between watchdog and comm service — the registry is the contract. A cleaner
  design for LustLess would be one supervisor owning both, or a documented unix socket; but the
  CE design note worth keeping is: **supervisor never trusts process names alone** and
  **self-protection is configuration-level (service/ACL/registry), not process-level**.
- Crash-handler UX: CE's `RestartVSClientOnly` pattern (crash handler passes `--RestartRequestFrom
  <rev> --pid <n>`; tool updates counters; >3 → tell the human) maps to a
  `lustless-restart-helper` invoked by the agent's own crash handler.

## Open questions

- Which component writes `ClientCrashesAt/ClientCrashesSince` at runtime (`VictoryShield.exe`
  presumed — off-limits to this pass). The exact window passed to
  `updateCrashStatistics` by each caller (VSWD's read side is fixed at 10 min; the write-side
  window is a parameter not yet pinned).
- The exact strings passed to `disableRegistryProtection` by `vs-config.exe` (six `std::wstring`
  buffers at `DAT_14041f288/…` are runtime-initialized; likely the 4 protected keys + legacy
  `CEWD`/`CovenantEyesCommService` keys [INFERENCE]).
- What calls `OnCustomCommand(176)` (Environment.Exit(3011)) in production — installer kill
  switch? No caller visible in these binaries.
- Who launches `RestartVSClientOnly.exe` exactly (presumably the UI client's crash handler;
  `RestartRequestFrom` values observed in code but the producer is off-limits).
- The intended semantics of `GetCrashCount`'s `StringBuilder.get_Chars(0)` return (bug vs
  single-digit values) — see [INFERENCE] above.
- `RestartVSClientOnly.exe` was still under auto-analysis during this pass (function count
  climbing); `FUN_1400066b0` decompiles include EH-continuation merging and one output capture
  was elided mid-function — the threshold (`CMP R12D, 3` @0x140007d08) and the count source
  (`updateCrashStatistics` copy @`0x140037xxx`) were verified from disassembly, but the middle
  of `FUN_1400066b0` (option handling around `RestartRequestFrom`) deserves a re-read once
  analysis is final.
