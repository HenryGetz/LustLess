# 03 — Runtime process / file / registry / IPC observation (Victory Shield v10.1.44)

## What it does

Passive, time-boxed observation of the live Covenant Eyes ("Victory Shield") stack on the Windows VM: which processes exist and how they were launched, what file/registry state moves during an idle few-minute window, and what local IPC surface is exposed. Findings for the LustLess clean-room client:

- Exactly **two** CE processes run continuously: `VictoryShieldCommService.exe` (the privileged communication service) and `VSWD.exe` (a second auto-start service, watchdog by name/role). Both are direct children of `services.exe`, started at install time and never restarted since.
- `VictoryShield.exe` (UI) is **not** running in this window (console sits at `LogonUI.exe`); it auto-starts per user logon via `HKLM\...\Run\Victory Shield`. `VictoryShieldClassifier.exe` and `vs-config.exe` are not running either.
- The classifier is a separate per-user process launched with an explicit command line (model/data/cache paths); the pre-upgrade log shows `CovenantEyesClassifier.exe --version=10.1.1 --model="C:\Program Files\CE\data" --data=<per-SID>\data --cache=<per-SID>\cache`. The binary was renamed `VictoryShieldClassifier.exe` in the 2026-09-21 v10.1.44 upgrade.
- During a 20m41s idle window, **zero** files under `C:\ProgramData\CovenantEyes\**` changed (31/31 identical size+mtime, including `ce-file`). The only live state movement is the registry key `HKLM\SOFTWARE\Covenant Eyes\Victory Shield`, written at 13:11:23 and 13:21:24 (~10-minute cadence).
- IPC surface: one loopback TCP listener `127.0.0.1:48867` owned by the comm service (accepts connections — verified with one byte-less connect/close), two backend TCP sockets to `208.185.195.49:443` owned by the same PID, and **no** CE-named named pipes.

All times are VM-local CDT (UTC−05:00) unless suffixed `Z` (UTC). Observer commands ran over SSH as `dolphin` (admin).

---

## Method

### Tooling inventory (run first)

```
Get-Command procmon,procmon64,procexp,procexp64,autoruns  -> none found
Get-Command pktmon,netsh,wpr,logman                       -> C:\WINDOWS\system32\{PktMon,netsh,wpr,logman}.exe
where.exe procmon64 / procmon                             -> not found
Sysinternals leftovers                                    -> none (only unrelated C:\Tools\ExcelMcp)
winget --version -> 1.29.290      choco --version -> 2.7.4
```

Procmon is trivially obtainable: `Procmon64.exe` was downloaded from `https://live.sysinternals.com/Procmon64.exe` to `C:\Users\dolphin\Procmon64.exe` (2,237,208 bytes, mtime 13:01:21). **It was not executed this window** — deferred by explicit orchestrator decision (see Limitations). No Procmon artifacts exist; the deferred pass should run it with a filter on `VictoryShield*|VSWD*|vs-config.exe|RestartVS*`.

### Actually used

| Tool | Purpose | Notes |
|---|---|---|
| `Get-CimInstance Win32_Process` (one query) | process map: PID/PPID/Session/CommandLine/CreationDate | one WMI call; per-process `GetOwner` method invocations were **avoided** (they OOM'd mid-episode) |
| `tasklist /v`, `tasklist /fo csv /nh` | process list + memory working sets | pathologically slow on this box (45–88 s) |
| `sc.exe qc` / `sc.exe queryex` | service config: binPath, start type, deps, service account, live PID | `sc` bare is aliased to `Set-Content` in PowerShell — must call `sc.exe` |
| `cmd /c dir`, `type`, `findstr` | binary inventory, log excerpts | |
| PowerShell `Get-ChildItem -Recurse` + `ConvertTo-Json` | file snapshots of `C:\ProgramData\CovenantEyes\**` at T0/T1 | |
| small `.ps1` with `RegQueryInfoKey` P/Invoke (`re/samples/runtime/getreg.ps1`) | registry key `LastWriteTime` | needed because PowerShell 5.1's registry provider returns `null` for `LastWriteTime` on this image (verified: `(Get-Item 'HKLM:\SOFTWARE').LastWriteTime` → "method on null-valued expression") |
| `[System.IO.Directory]::GetFiles('\\.\pipe\')` | named-pipe enumeration | |
| `wevtutil qe System ... /f:text`, `Get-WinEvent -FilterHashtable` | System/Application/SCM events | |
| `netstat -ano` | TCP/UDP endpoints with owning PID | used instead of `Get-NetTCPConnection`/`Get-NetUDPEndpoint` (CIM cmdlets, avoided under OOM conditions) |
| `System.Net.Sockets.TcpClient` | one connect/close to `127.0.0.1:48867`, zero bytes sent | |

### Limitations (explicit)

1. **Memory-pressure episode during the window (observer-caused, documented for honesty).** Concurrent activity on the VM — a `pktmon` capture session reserving up to **384 MB** (peer agent, torn down mid-window), a Ghidra headless JVM that died with a native `OutOfMemoryError` on the 11 GB box, and **6 `mcp-excel.exe` processes (~235–305 MB each, pre-existing)** — pushed the box into paging. Symptoms observed and captured: PowerShell CLR load failures (`0x800705af`, `HRESULT 0x80004005`), `WBEM_E_OUT_OF_MEMORY` from `Invoke-CimMethod`, `Thread failed to start`, and System-log entries `"Windows - Out of Virtual Memory"` (13:04:28) and `"powershell.exe - System Error : A new guard page for the stack cannot be created"` (13:04:47) (`re/samples/runtime/eventlog-system-window.txt`, Event[5..6]). The box recovered ~13:15.
2. **Procmon deferred.** Per orchestrator directive, no Procmon kernel driver/capture this window (stability during the thrash; the binary is staged on the VM for a later pass). Consequence: no per-write file/registry attribution, no stack data. Everything below rests on snapshots (mtime/size deltas, key `LastWriteTime`), event logs, and netstat/pipe enumeration.
3. **Window length.** Target ≤15 min; actual T0 `2026-09-24T13:01:48.351-05:00` → T1 `2026-09-24T13:22:29.507-05:00` = **20m41s** (`re/samples/runtime/timestamps.txt`), stretched by the thrash (commands that normally take 3 s took 60–120 s or timed out).
4. **Registry timestamps** required P/Invoke (`RegQueryInfoKey`); the provider workaround is in `re/samples/runtime/getreg.ps1`.
5. **`tasklist` is the slow tool** on this box (45–88 s, one timeout at 60 s); the end-of-window process state is therefore taken from `netstat -ano` + `sc.exe queryex` + a second file snapshot rather than a third full `tasklist`.
6. **ALPC endpoints are not enumerable from userland** (no supported enumeration API without ETW/kernel tooling) — left as an open question.
7. **Named-pipe ownership** cannot be attributed to a process from userland without opening each pipe; only the name list was captured.
8. `wevtutil /f:text` prints event times in **local time with a bogus `Z` suffix** (known quirk); quoted event times below are local.
9. Loose regexes are misleading: filtering pipes with `CE|VS` (case-insensitive) hit `LSM_API_service`, `srvsvc`, `TermSrv_API_service`, `Ctx_WinStation_API_service` — all substring false positives inside `…service`/`srvsvc`. The strict pass (`Covenant|Victory|VSWD|CEA|CE[_-]|VS[_-]`) found nothing; both lists are in `re/samples/runtime/pipes-t0.txt` provenance (full list, 116 entries).
10. SSH session noise: my own `powershell.exe -c "..."` command lines contain the strings `Covenant|Victory|VSWD`, so naive command-line greps match the observers. Only the two rows in the Process map below are CE processes.

---

## Evidence

### Process map (start and end of window — identical)

Both snapshots (`re/samples/runtime/procmap-cim-t0.txt`, `tasklist-t0.csv`, `tasklist-t1.csv`, `netstat-t1.txt`) show exactly two CE processes across the window:

| PID | PPID | Process | Session | Account | Created | Command line |
|---|---|---|---|---|---|---|
| 5616 | 1348 `services.exe` | `VictoryShieldCommService.exe` | 0 | `LocalSystem` (per `sc.exe qc`: `SERVICE_START_NAME: LocalSystem`) | 2026-09-21 00:22:41 | `"C:\Program Files\CE\VictoryShieldCommService.exe"` (no args) |
| 127048 | 1348 `services.exe` | `VSWD.exe` | 0 | `LocalSystem` | 2026-09-21 00:22:45 | `"C:\Program Files\CE\VSWD.exe"` (no args) |

Parent chain: `wininit.exe` 1228 → `services.exe` 1348 → both services (`re/samples/runtime/procs-t0b.json`, full 250-process dump at 13:14). Working sets: comm service ~38 MB, VSWD ~80–87 MB (`tasklist-t0.csv`).

Service configuration (`re/samples/runtime/services-sc-t0.txt`):

```
SERVICE_NAME: VictoryShieldCommService
  TYPE: 10 WIN32_OWN_PROCESS   START_TYPE: 2 AUTO_START
  BINARY_PATH_NAME: c:\Program Files\CE\VictoryShieldCommService.exe
  DEPENDENCIES: RpcSs, SamSs, ProfSvc, Afd, Tcpip, nsi, Dhcp, Dnscache
  SERVICE_START_NAME: LocalSystem
SERVICE_NAME: VSWD
  TYPE: 10 WIN32_OWN_PROCESS   START_TYPE: 2 AUTO_START
  BINARY_PATH_NAME: c:\Program Files\CE\VSWD.exe
  DEPENDENCIES: RpcSs, SamSs, EventLog, ProfSvc
  SERVICE_START_NAME: LocalSystem
```
Both report `STATE: 4 RUNNING (NOT_STOPPABLE, NOT_PAUSABLE, ACCEPTS_SHUTDOWN)`.

**Not running at any point in the window:** `VictoryShield.exe`, `VictoryShieldClassifier.exe`, `vs-config.exe`, `RestartVS*.exe` — absent from `tasklist-t0.csv` (13:07), `procs-t0b.json` (13:14) and `tasklist-t1.csv` (~13:22).

**How the UI is launched:** `reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"` →
```
Victory Shield    REG_SZ    "C:\Program Files\CE\VictoryShield.exe"
```
No scheduled tasks match Victory/Covenant/VSWD (`schtasks /query /fo csv | findstr /i ...` → empty); `HKCU\...\Run` has no CE entry. The console currently shows `LogonUI.exe` and no `explorer.exe` (`tasklist-t0.csv`) — no interactive desktop session, hence no UI process. [INFERENCE] the UI starts via the Run key at user logon.

**How the classifier is launched:** its per-PID log records the launch line as its first entry (`re/samples/runtime/classifier-log-10252.txt`, session of 2026-09-19 00:34:49):

```
Classifier: Command line: "C:\Program Files\CE\CovenantEyesClassifier.exe" --version=10.1.1
  --model="C:\Program Files\CE\data"
  --data=C:\ProgramData\CovenantEyes\Classifier\S-1-5-21-2224134039-3417563983-3831536026-1001\data
  --cache=C:\ProgramData\CovenantEyes\Classifier\S-1-5-21-2224134039-3417563983-3831536026-1001\cache
Classifier: Classifier v10.1.1 is starting
Classifier: Could not attach to user database SQLite error: 26   (×2)
pdl-edi: ONE-TIME NOTE: Experimental chance set to 0, no experiments will run for this user.
```

So: explicit `--version`, a shared model dir (`C:\Program Files\CE\data`, see below) and **per-user-SID** `--data`/`--cache` dirs; it also "attaches to user database" (SQLite) at startup. This launch contract independently matches the one recovered by the log-analysis pass (`re/findings/02-artifacts/logs.md`) — no live classifier process existed in this window to compare against, but the two evidence lines agree. The current on-disk binary is `VictoryShieldClassifier.exe` (52,962,752 B) — renamed from `CovenantEyesClassifier.exe` during the 2026-09-21 upgrade (`VictoryShieldInstaller\logs\upgrade-126428.log`, mtime 2026-09-21T05:23:36Z). Classifier logs/caches show **no classifier activity after 2026-09-19/20**, i.e. none since the upgrade, and none in this window (no user session). [INFERENCE] the classifier is spawned per user session on demand, by either the comm service or the UI; parent not observable without Procmon.

Model data consumed via `--model="C:\Program Files\CE\data"` (`re/samples/runtime/progmfiles-ce-dir-t0.txt`):

```
805b3533c9a731909930-b3.dat.enc   2,323,104    83b568cc34e776439494-b1.dat.enc   2,323,104
d8b85cbaabaf6c1e7b15-b2.dat.enc   2,323,104    a076283f3318c8ea4de0-sw.dat.enc     901,200
cea3215e9378de852a41-j1.dat.enc     187,248    f160caa8342747d04d8f-mn.dat.enc       1,248
```
(6 encrypted `*.dat.enc` files, 8,059,008 B total, dated 2026-03-25.)

Service lifecycle from event logs (`Get-WinEvent` SCM filter; quoted from raw output):

```
TimeCreated : 9/21/2026 12:22:40 AM   Id : 7045
  A service was installed in the system.
  Service Name:  VSWD
  Service File Name:  "C:\Program Files\CE\VSWD.exe"
  Service Type:  user mode service    Service Start Type:  auto start    Service Account:  LocalSystem
TimeCreated : 9/21/2026 12:22:40 AM   Id : 7045
  A service was installed in the system.
  Service Name:  Victory Shield Communication Service
  Service File Name:  "C:\Program Files\CE\VictoryShieldCommService.exe"
  Service Type:  user mode service    Service Start Type:  auto start    Service Account:  LocalSystem
```
Process creation timestamps (00:22:41 / 00:22:45) show both services started seconds after install and have been running ever since. No SCM start/stop/crash events for either service appear in the window or in the 60 most recent SCM events.

### File / registry deltas (T0 13:01:48 → T1 13:22:29, 20m41s)

Full before/after dumps: `re/samples/runtime/ce-files-t0.json`, `ce-files-t1.json` (31 files each; programmatic diff = **zero differences**).

| Path (`C:\ProgramData\CovenantEyes\…`) | Size (B) | LastWriteTimeUtc before → after |
|---|---|---|
| `VictoryShieldv010.001.044\ce-file` | 835,584 | `2026-09-24T17:31:34.636Z` → **unchanged** |
| `VictoryShieldv010.001.044\ce-user-file` | 12,288 | `2026-09-21T05:22:40.516Z` → unchanged |
| `VictoryShieldv010.001.044\ce_user_event_message_queue` | 2,896 | `2026-09-21T05:22:45.259Z` → unchanged |
| `VictoryShieldv010.001.044\logs\comm-service\major-5616.log` | 9,318 | `2026-09-24T17:23:47.227Z` → unchanged |
| `VictoryShieldv010.001.044\logs\comm-service\major-5688.log` | 523 | `2026-09-21T05:22:18.431Z` → unchanged |
| `Classifier\logs\<pid>.txt` (16 files, per-PID logs) | 874–1,004 | newest `2026-09-19T05:35:00.179Z` → all unchanged |
| `Classifier\S-1-5-21-…-1001\cache\bmdat\nxu.dat` | 32 | `2026-09-20T02:36:03.512Z` → unchanged |
| `Classifier\S-1-5-21-…-1001\data\client\1789880113031\ht.dat` | 41,760 | `2026-09-20T04:55:13.035Z` → unchanged |
| `Classifier\S-1-5-21-…-1001\data\pdl\2026-09-20T04-55-17.3281948-0\{su,rr}.dat` | 160 / 0 | `2026-09-20T04:55:17.33xZ` → unchanged |
| `PreviousConfiguration\ce-user-file` | 86,016 | `2026-09-20T04:55:21.230Z` → unchanged |
| `ThirdParty\logs\proxy\CovenantEyesProxy.log` | 2,456 | `2026-09-21T05:22:09.986Z` → unchanged |
| `VictoryShieldInstaller\logs\upgrade-126428.log` | 136,142 | `2026-09-21T05:23:36.619Z` → unchanged |
| `WindowsClientv010.001.001\logs\comm-service\major-3600.log` | 574,940 | `2026-09-21T05:22:10.844Z` → unchanged |
| installer logs (`fresh-install-4260.log`, `instnsp-*.log`) | 387–55,973 | 2025-11-11 / 2026-09-21 → unchanged |

Notes: the comm-service log name embeds the service PID (`major-5616.log` = current PID 5616; `major-5688.log`, `major-3600.log` = earlier instances/versions). `ce-file`'s last on-disk flush is **2026-09-24 17:31:34.636Z (12:31:34 local)** — ~30 min **before** the window opened; it did not move during the window despite the live service (Main's separate pass observed flushes within seconds under activity — the divergence tracks activity level: this window had no user session).

Registry key timestamps (P-Invoke readouts at two points inside the window; raw: `re/samples/runtime/reg-t0-readout.txt`, `reg-t1.txt`):

| Key (HKLM) | readout #1 (between 13:11–13:22) | readout #2 (13:23–13:25) | Movement |
|---|---|---|---|
| `SOFTWARE\Covenant Eyes\Victory Shield` | `2026-09-24T13:11:23.4252048-05:00` | `2026-09-24T13:21:24.4487159-05:00` | **written during window**, ~10 min cadence |
| `SOFTWARE\Covenant Eyes` | `2026-09-21T00:21:51.4127083-05:00` | same | none (install-time) |
| `SOFTWARE\WOW6432Node\Covenant Eyes` | `2026-09-21T00:21:51.4106708-05:00` | same | none (install-time) |
| `SOFTWARE\WOW6432Node\Covenant Eyes, Inc.` | `2025-11-10T20:03:53.8050929-06:00` | same | none (2025-era legacy leftover) |
| `SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\CovenantEyes.exe` | `2025-11-10T20:03:45.9764994-06:00` | same | none (legacy `CovenantEyes.exe` registration) |
| `SYSTEM\CurrentControlSet\Services\VictoryShieldCommService` | `2026-09-21T00:22:46.3599346-05:00` | same | none |
| `SYSTEM\CurrentControlSet\Services\VSWD` | `2026-09-21T00:22:46.3401798-05:00` | same | none |

Because readout #1 already showed `13:11:23.425` (a time after the window opened at 13:01:48), at least **two** writes to `Victory Shield` occurred inside the window (13:11:23 and 13:21:24). This corroborates the earlier baseline note that CE telemetry timestamps update on a minutes-scale cadence; here measured at ~10 min while idle.

### Event logs during the window

- **Service Control Manager:** zero events referencing Victory/CE/VSWD during the window (System-log pull `re/samples/runtime/eventlog-system-window.txt` covers 12:45–13:15+; SCM-filtered `Get-WinEvent` over the 60 most recent SCM events returned only the two 7045 install events of 9/21 quoted above).
- **Application log** (400 most recent events within 7 days): zero events matching `Victory|VSWD|Covenant|BugSplat` — the bundled BugSplat crash reporter (`BsSndRpt64.exe`, `BugSplat64.dll` in `C:\Program Files\CE`) has filed nothing recently.
- System log during the window shows only observer-side noise (`Microsoft-Windows-Configuration-Change-Monitor` ID 1 entries and the two OOM popups quoted in Method) — nothing CE-generated.

### IPC surface

| Channel | Endpoint | Owner | Evidence |
|---|---|---|---|
| TCP listen | `127.0.0.1:48867` LISTENING | PID 5616 `VictoryShieldCommService.exe` | `netstat -ano` at 13:00 and ~13:22 (`netstat-t0.txt` via `tasklist`-era capture, `netstat-t1.txt`); service log line `CRIT\|09-21 00:22:44.903729\|0x0001ed28\|run::<lambda_1>::operator ()\|Starting service on 127.0.0.1:48867` (`re/samples/runtime/svclog-findstr.txt`) |
| TCP outbound | `10.0.0.21:55148 → 208.185.195.49:443` CLOSE_WAIT, `10.0.0.21:55210 → 208.185.195.49:443` CLOSE_WAIT | PID 5616 | `netstat-t0.txt`, `netstat-t1.txt` (endpoint ownership only; flow analysis is the network task's scope) |
| UDP | none owned by 5616/127048 | — | no UDP rows for either PID in either snapshot. NB: the prior surface note "UDP-ish bound `0.0.0.0:55210/55148`" is a **misreading** — 55148/55210 are the *local TCP ports* of the two backend sockets |
| Named pipes | 116 pipes present; **0** matching `Covenant\|Victory\|VSWD\|CEA\|CE[_-]\|VS[_-]` | — | `pipes-t0.txt` (full list) |
| ALPC | not enumerable from userland | — | open question |

Probe (single, harmless; nothing sent):

```
$ c = New-Object System.Net.Sockets.TcpClient; $c.Connect("127.0.0.1",48867); ...; $c.Close()
CONNECTED=True ELAPSED_MS=20 LOCAL=127.0.0.1:55708
CLOSED_NO_SEND
```
T1 `netstat` retains the kernel-side trace of that probe: `TCP 127.0.0.1:55708 127.0.0.1:48867 TIME_WAIT 0`. The listener accepts and holds TCP connections from loopback.

---

## Synthesis

**Lifecycle — who launches whom.**
Both CE services are SCM auto-start `WIN32_OWN_PROCESS` services running as `LocalSystem`, children of `services.exe` (siblings, not chained: VSWD's PID is *not* the comm service's parent). They were installed 2026-09-21 00:22:40 and started within ~5 s; nothing has restarted them since (process CreationDates + absence of SCM events). The UI (`VictoryShield.exe`) is user-session software auto-started by `HKLM\...\Run\Victory Shield` at logon. The classifier is a per-user, on-demand process with an explicit model/data/cache command line; its per-PID log proves the argument pattern and that it talks SQLite to the "user database". `vs-config.exe` and `RestartVS*.exe` were never observed running — [INFERENCE] they are configuration/update helpers invoked transiently. VSWD [INFERENCE] is the watchdog ("VS Watchdog"): it runs from install, ~80 MB resident, and shares only `VSWD.dll`-style naming with nothing else observable; no restart event exercised its supervision logic during the window.

**What touches which state (idle, no user session).** In 20m41s: nothing under `C:\ProgramData\CovenantEyes\` was written; the only state movement was `HKLM\SOFTWARE\Covenant Eyes\Victory Shield` at 13:11:23 and 13:21:24. Combined with `ce-file`'s 12:31:34 flush (before the window) and the comm-service log's 12:23:47 last line, the pattern is: the comm service keeps a **registry heartbeat/telemetry marker on a ~10-minute cadence**, while the SQLite state (`ce-file`), the event queue (`ce_user_event_message_queue`) and logs advance only when there is something to record [INFERENCE — activity-correlated flush; the window had no interactive session (`LogonUI.exe` on console), so classifier/UI-driven writes are absent]. Per-PID log naming (`major-<pid>.log`, `Classifier\logs\<pid>.txt`) is a deliberate lifecycle breadcrumb scheme.

Cross-check against the known periodic writers from the log-analysis pass (`re/findings/02-artifacts/logs.md`) makes the zero-delta result *expected*, not anomalous:

| Expected periodic writer | Cadence | In my 20m41s window? |
|---|---|---|
| `ServerTimeManager::sync` | ~3600 s (hourly) | not due — window shorter than the cadence |
| WinSparkle appcast check (`WinSparkle.dll`, `C:\Program Files\CE`) | ~86400 s (daily) | not due |
| metrics rows flushed into `ce-file` | within seconds of collection | no collection in window (no user session) — consistent with unchanged `ce-file` |
| DNS-server-removal enforcement loop (10.1.1-era) | 60 s | dormant here (`DnsProxyDisable=1`) — consistent with zero writes |

The ~10-minute registry write is thus the *only* sub-hour periodic state movement visible while idle.

The internal IPC message vocabulary reported from the comm-service logs (`QUIT`, `USER_SETTINGS_CHANGE`, `USER_LOGOUT`, plus WTS session-change events — see `re/findings/02-artifacts/logs.md`) fits the shapes observed here [INFERENCE]: `ce_user_event_message_queue` (state file, unchanged while no session events occur) is the likely queue carrying user-session events, and the WTS session-change hook explains why UI (Run key) and classifier (per-SID dirs) are per-logon artifacts. None of those names appeared in the named-pipe namespace (116 pipes, zero CE matches), which is consistent with the queue being file-based and the inter-component channel being the TCP loopback socket.

**IPC implications.** The single `127.0.0.1:48867` listener, bound and logged at service start and owned by the privileged comm service, is the local API through which user-session components (UI, classifier, `vs-config`) reach the service [INFERENCE]; the same process also owns the two backend TLS sockets, making it the sole network agent on this host [INFERENCE limited to endpoint ownership]. The absence of CE named pipes means clients address it over TCP loopback rather than `\\.\pipe\…`. The listener accepted my byte-less connection without complaint and left no persistent artifacts — consistent with a length-prefixed or blocking request protocol that waits for a first message [INFERENCE].

---

## Open questions

1. **Who spawns the classifier, and with what v10.1.44 command line?** The evidence line comes from the pre-upgrade `CovenantEyesClassifier.exe` (v10.1.1). The renamed `VictoryShieldClassifier.exe` has not run since the upgrade. Needs an interactive session + Procmon/process-creation capture.
2. **VSWD's supervision loop** — what it monitors, its restart policy, and its IPC to the comm service. No trigger occurred in-window.
3. **ALPC endpoints** of both services — not enumerable from userland; would need ETW/kernel tooling or the deferred Procmon pass (Procmon records ALPC/RPC activity).
4. **Protocol on `127.0.0.1:48867`** — wire format is out of scope here (network/protocol RE belongs to the network task).
5. **`ce-file` flush cadence under real activity** — this idle window showed no writes; a window with an active UI session is needed (and is where Procmon pays off).
6. **Classifier "SQLite error: 26" at attach** — happens at classifier startup against the user database; is it a transient lock contention or a mode-of-operation detail?
7. **Deferred Procmon pass** should capture: file/registry write attribution for the ~10-min `Victory Shield` key write, who handles connections on 48867, and any `RestartVS`/`vs-config` invocation paths.

---

## Linux-reimplementation notes (brief)

- Architecture map: privileged daemon (network + state writes) + a peer watchdog service, with per-user UI and per-user classifier as unprivileged helpers. On Linux: one system daemon (`systemd` system service), one watchdog unit (`Restart=on-failure` or a dedicated supervisor), UI/classifier as systemd **user** services. The watchdog-as-separate-auto-start-service shape (not a child of the daemon) survives supervisor death independently — worth copying.
- Replace loopback TCP with a Unix domain socket in `/run` and authenticate peers with `SO_PEERCRED` instead of loopback+port.
- Heartbeat/telemetry marker: a small state entry rewritten on a ~10-minute cadence (observable liveness for the backend); use `sd_notify(WATCHDOG=1)` or a timestamped file. Keep the *event-busy* state (the `ce-file` analog) flushed on activity, not on a timer.
- Classifier as a separate process, launched per user session, with explicit `--model` (shared, read-only) and per-user `--data`/`--cache` directories (XDG state/cache dirs). Pin the model version on the command line (`--version=…`).
- Per-PID log files (`major-<pid>.log`, `<pid>.txt`) are cheap and make lifecycle forensics trivial after crashes — adopt the naming.
- Autostart UI via XDG autostart `.desktop` (per-user logon) rather than a system-wide equivalent of the HKLM Run key.

---

## Evidence index (raw captures in `re/samples/runtime/`)

| File | Produced by |
|---|---|
| `ce-files-t0.json` / `ce-files-t1.json` | `Get-ChildItem 'C:\ProgramData\CovenantEyes' -Recurse -Force -File \| … ConvertTo-Json` at 13:01:48 / 13:22:29 |
| `timestamps.txt` | window bounds (`Get-Date -Format o` at T0/T1) |
| `procs-t0b.json` | `Get-CimInstance Win32_Process` full dump (13:14) |
| `procmap-cim-t0.txt` | CE-filtered process rows + parents (command/quote lines) |
| `tasklist-t0.csv` / `tasklist-t1.csv` | `tasklist /fo csv /nh` at ~13:07 / ~13:22 |
| `netstat-t0.txt` / `netstat-t1.txt` | `netstat -ano` at 13:00 / ~13:23 |
| `services-sc-t0.txt` | `sc.exe qc` + `sc.exe queryex` × 2 services |
| `reg-t0-readout.txt` / `reg-t1.txt` | `getreg.ps1` (RegQueryInfoKey P/Invoke) two readouts |
| `getreg.ps1` | the registry-timestamp script itself |
| `pipes-t0.txt` | `[System.IO.Directory]::GetFiles('\\.\pipe\')` (116 entries) |
| `eventlog-system-window.txt` | `wevtutil qe System … timediff ≤ 30 min` window pull |
| `progmfiles-ce-dir-t0.txt` | `cmd /c dir "C:\Program Files\CE"` + `dir "…\CE\data"` |
| `classifier-log-10252.txt` | `type C:\ProgramData\CovenantEyes\Classifier\logs\10252.txt` (verbatim) |
| `svclog-findstr.txt` | `findstr /i /n "classif … launch start" …\comm-service\major-5616.log` (verbatim, line numbers included) |
