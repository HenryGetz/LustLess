# 03 — Live API/process tracing of the running CE stack (Procmon + native snapshots), v10.1.44

## What it does

Live, process-filtered tracing of the running Covenant Eyes "Victory Shield" v10.1.44 stack on the
research VM — closing the "Runtime process and API tracing" owed by `process-observation.md` (that
pass deferred Procmon). One bounded Procmon window (CE-process filter, destructive) plus a 5 s
side-band observer (netstat / file-tree / registry / process snapshots) attribute, with PID +
timestamp + result:

- **(a)** the real v10.1.44 classifier launch contract (command line, parent PID/identity,
  relaunch-supervision behavior),
- **(b)** the PID that writes `HKLM\SOFTWARE\Covenant Eyes\Victory Shield\LastTelemetryUpdateAt`
  at the ~601 s tick, and what else moves at tick time,
- **(c)** which processes connect to `127.0.0.1:48867`, when and how often,
- **(d)** the live screenstate chain under `C:\ProgramData\CovenantEyes\Classifier\<SID>\data\` —
  transaction-folder cadence, writer/reader/deleter PIDs for `im<N>.dat`/`ss.dat`/`rr.dat` and the
  reverse-channel `client\<epoch>\{ht,re4,…}.dat` files,
- **(e)** which PID/operation writes the `ce-file` SQLite DB during the window (metrics-flush
  correlation).

All times are VM-local CDT (UTC−05:00) unless suffixed `Z`/`UTC`. Procmon's PML stores UTC; CSV/PML
excerpts below are re-rendered local. Observer commands ran over SSH as `dolphin` (admin).
[INFERENCE] markers denote inference; every other claim is backed by a quoted row.

---

## Method

### Tooling (exact versions/flags)

| tool | version / path | role |
|---|---|---|
| `Procmon64.exe` | **4.11**, `C:\Users\dolphin\Procmon64.exe` (2,237,208 B, staged by the prior pass) | kernel capture, process+path filtered |
| `ce.pmc` filter config | `C:\Users\dolphin\rt\ce.pmc` (2,825 B) | Procmon `/LoadConfig` filters (see below) |
| `procmon-parser` | PyPI 0.4.0 (local Python 3.12, `/tmp/pmpm`) | builds `.pmc`, parses `.pml` → CSV extracts (no GUI export needed) |
| `observer.ps1` | `C:\Users\dolphin\rt\observer.ps1` (copy in `re/samples/runtime/observer.ps1`) | 5 s side-band snapshots → `rt\snap.txt` |
| `getreg.ps1` | `C:\Users\dolphin\rt\getreg.ps1` (from the process-observation pass) | registry key `LastWriteTime` via `RegQueryInfoKey` (PS 5.1 provider returns null) |
| `netstat -ano`, `query session`, `Get-CimInstance Win32_Process`, `Get-Process` | Windows inbox | connection/session/process snapshots |

### Procmon invocation (exact command lines)

First run of Procmon (EULA accepted with `/AcceptEula`); capture is started by launching **without**
`/NoConnect`:

```
C:\Users\dolphin\Procmon64.exe /AcceptEula /Quiet /Minimized /LoadConfig C:\Users\dolphin\rt\ce.pmc /BackingFile C:\Users\dolphin\rt\api-trace.pml
```

started detached (see Limitations #1) via:

```
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine="C:\Users\dolphin\Procmon64.exe /AcceptEula /Quiet /Minimized /LoadConfig C:\Users\dolphin\rt\ce.pmc /BackingFile C:\Users\dolphin\rt\api-trace.pml"}
```

stop attempted at window end with `C:\Users\dolphin\Procmon64.exe /Terminate` (see the window
table and Limitations #6 for how that actually played out — force-kill + stream recovery).

Procmon 4.11's documented CLI (strings recovered from the binary: `/AcceptEula /BackingFile /LoadConfig /Minimized /NoConnect /NoFilter /OpenLog /Quiet /SaveAs /Terminate /WaitForIdle …`) has **no**
`/ProcessName`-style include option, so process filtering is delivered by `/LoadConfig` with a
generated `.pmc`.

### `ce.pmc` construction (CE-only, destructive)

Built programmatically (the `.pmc` format is RE-documented in `procmon-parser/docs/PMC Format.md`;
base = the repo's real Procmon 4.1-exported default configuration fixture `raw_config_full_procmon_41`):

```python
cfg = loads_configuration(base_pmc_bytes)          # 20 default options + 22 default EXCLUDE rules
ours = [Rule('Process_Name', 'begins_with', p, 'include')
        for p in ('VictoryShield', 'VSWD', 'vs-config', 'RestartVS', 'CovenantEyes')]
cfg['FilterRules'] = ours + list(cfg['FilterRules'])
cfg['DestructiveFilter'] = 1                        # drop non-matching events at capture time
cfg['Logfile'] = ''                                 # backing file supplied via /BackingFile
dump_configuration(cfg, open('ce.pmc', 'wb'))       # 2,825 B
```

The five `Process_Name … include` rules sit on the **same column**, which Procmon ORs (verified
empirically — the trial capture contains events from all four running CE PIDs simultaneously);
`DestructiveFilter=1` makes every non-CE event never reach the log.

**Pre-flight trial** (40 s, same switches, `trial.pml`): 3,067 events, exactly 4 distinct processes
(`VictoryShieldCommService.exe` 5616 = 1,881 ev, `VictoryShield.exe` 128096 = 1,024, `VSWD.exe`
127048 = 122, `VictoryShieldClassifier.exe` 191248 = 40) → filter verified, PML size 1,474,299 B.

### Capture window + side-band observer (as executed)

| | window 1 | window 2 |
|---|---|---|
| Procmon start (TSTART) | `2026-09-27T09:33:28.9183985-05:00` | `10:09:07` (instance alive, **captured zero events** — see note) |
| stop | `/Terminate` attempts 09:50:40 (ssh) + 10:01:13 (WMI) **not delivered**; all four Procmon instances force-killed at `2026-09-27T10:30:31.6600517-05:00` | same force-kill (`stop2.ps1`, `rt\window.txt`) |
| backing file | `C:\Users\dolphin\rt\api-trace.pml` — final size **536,870,912 B**, recovered stream `09:33:29.162 → 10:31:03.192` (**57.6 min, 1,063,077 events**) | `C:\Users\dolphin\rt\api-trace2.pml` — 134,217,728 B preallocation, mtime frozen at creation `10:09:07`, **0 events** |
| side-band | `observer.ps1 -Minutes 19` → `rt\snap.txt`: 1,200 rows, `09:33:30.474 → OBSERVER END 09:52:32.940` (211 ticks) | same file, second run appends: 1,207 rows `10:10:32.852 → OBSERVER END 10:29:35.674` (213 ticks) |

**Window 2 captured nothing**: Procmon's kernel session is global (one `PROCMON25` filter-driver
consumer), and window 1's still-running instance kept it; the second instance only allocated its
backing file (mtime never advanced past creation). All Procmon evidence therefore comes from
window 1's stream — which, because the intended early stop never took, fortunately covers the
whole run through the final force-kill.

Side-band observer (each loop = one `Start-Sleep 5`; row format `<iso-ts> KIND …` appended to
`snap.txt`):

- every tick (~5 s): `netstat -ano` rows containing `48867` (**NET**), recursive listings of
  `…\Classifier\<SID>\data\pdl\` and `…\data\client\` (**DIR**/**FILE**, with mtimes),
- every 3rd tick (~15 s): `Get-CimInstance Win32_Process` filtered to
  `^(VictoryShield|VSWD|vs-config|RestartVS|CovenantEyes)` (**PROC**, with PPID/CreationDate/cmdline)
  and the heartbeat registry readout (**REG**: key `LastWriteTime` via `getreg.ps1` + the
  `LastTelemetryUpdateAt`/value text).

### Snapshot commands used for session/process context (exact)

```
query session                                   # session states (locked? disconnected?)
Get-Process LogonUI,explorer | Select Name,Id,SessionId   # per-session lock-shell presence
Get-CimInstance Win32_Process | Where Name -match '^(VictoryShield|VSWD|…)'   # PPID chains
Copy-Item …\logs\vs\major-128096.log, …\Classifier\logs\*.txt → rt\           # log pulls (read-only)
```

### PML close anomaly and recovery of the raw stream (important for reproducibility)

The window-1 capture was stopped with `/Terminate` issued from a *different* ssh call than the one
that launched Procmon. The signal was not delivered (see Limitations #6): capture kept running,
and the eventual forced stop left `api-trace.pml` **without its trailer tables** — header fields
`number_of_events`/`events_offsets_array`/`process_table`/`strings_table` all zero, which
`procmon-parser` rejects with its (Procmon-derived) message *"PML was not closed cleanly during
capture and is corrupt."*

The events region itself is intact and **self-describing**, so the stream was recovered directly
(`re/samples/runtime/recov-unclean-pml.py`, ~200 lines on top of `procmon-parser`):

1. sequentially walk records from header `events_offset` (0x3A8); each record is
   `CommonEventStruct`(0x34) + `depth×8` stack + `details_size` detail bytes; validate each record
   (event class enum, `EventClassOperation[op]` lookup, capture timestamp inside the window) and
   skip a trailing `u16`-lengthed extra-detail block / resync on desync;
2. detail strings are **inline** in each record (paths, registry data, process PIDs) — the *only*
   lost table is `process_idx → {pid, name}`; Procmon emitted no `Process Defined` events, so the
   map was reconstructed by **TID voting**: the clean 40 s `api-trace-trial.pml` (closed properly)
   yields `tid → (pid, process)` for the same four long-lived processes; each index's TID set votes —
   on the full run: `idx210 → 5616` (8/150 known), `idx228 → 128096` (10/39), `idx211 → 127048`
   (2/32), `idx262 → 191248` (1/1); one stray index (1 event, no votes — walk-tail artifact,
   Ghidra path) dropped;
3. output: `re/samples/runtime/api-trace-w1-rows.csv.gz` — **1,063,077 rows, 09:33:29.162 →
   10:31:03.192** (57.6 min; the first 09:55 snapshot yielded 402,966 rows and the final
   post-kill 536,870,912 B file the full stream).

Cross-checks that the reconstruction is sound: (i) exactly 5 process indices for a 5-name include
filter (4 CE + 1 tail artifact); (ii) every attributed index's op/path profile matches its
process's role (the `ce-file`-scanning index resolves to the comm service, the
`ce-service-event-message_queue` index to the UI, etc.); (iii) the `LastTelemetryUpdateAt`
RegSetValue rows land within 10 ms of the observer's independent registry `LastWriteTime`
readouts (e.g. row 10:17:58.575 vs readout 10:17:58.606); (iv) window-1 TID sets are
supersets/subsets of the trial's per-process TIDs.

### Limitations (up front)

1. **Processes started by an ssh command die when the ssh session closes** (Windows OpenSSH kills
   the session job) — observed: the first launch attempt's Procmon+observer PIDs vanished ~85 s
   after the ssh call returned, leaving no PML. Fix: start via `Win32_Process.Create` (WMI parent,
   outside the sshd job); `/Terminate` issued from a later ssh call works (Procmon's control is
   session-0 global).
2. Procmon's own driver install + first-launch happened inside this window (first `procmon64.exe`
   execution on this VM ever — `HKCU\Software\Sysinternals` was empty).
3. The PML holds only CE-process events (destructive filter) — attribution for **non-CE** 48867
   clients rests on `netstat` snapshots, which are 5 s-sampled (sub-5 s connections can be missed).
4. Session 1 was **WTS-locked for the entire run** (never unlocked — the orchestrator's RDP
   reconnect did not arrive within the ~35 min budget); the screenstate chain's gated-off
   behavior is the measured verdict (d), and the live cadence table is deferred to Open
   questions per orchestrator instruction.
5. `Procmon64.exe /OpenLog … /SaveAs` was **not** used for the main conversion: `procmon-parser`
   converts PML→CSV locally, avoiding an in-RAM GUI export on an 11 GB box shared with Ghidra.
   (One attempt was made on the unclean log — `/OpenLog C:\Users\dolphin\rt\api-trace.pml /SaveAs
   w1.csv` — and produced nothing: Procmon itself refuses unclean logs, same as the parser.)
6. **`/Terminate` only works from the window station that owns the Procmon instance.** Launched
   and terminated inside *one* ssh call (the pre-flight trial), Procmon closed cleanly (1,474,299 B
   compacted log). When the launch happened via `Win32_Process.Create` and `/Terminate` from a
   later ssh call (twice: 09:50:40 ssh-context, 10:01:13 WMI-context), the signal never took:
   capture kept writing (mtime probes were misread as "stopped" because NTFS flushes lazily —
   the file's real end-of-stream was the scp moment, 09:55:32). Consequence: window 1's PML lacks
   its close trailer → recovered per the subsection above; window 2 was therefore stopped with
   `/Terminate` *attempted* + force-kill fallback, and both PMLs are parsed via the recovery path
   if needed. The raw logs remain on the VM (see Evidence index).
7. The observer copy on the VM predates the `-Minutes`/`-OutPath` parameterization, so window 2's
   `observer.ps1 -Minutes 60 -OutPath snap2.txt` ran with **defaults** (19 min from 10:10:31,
   appending to the same `snap.txt`) — its 1,207 rows cover 10:10:32 → 10:29:35 and are what the
   Evidence cites for the second half; no `snap2.txt` exists.

---

## Evidence

### Window bounds and state

| | value | source |
|---|---|---|
| window 1 TSTART | `2026-09-27T09:33:28.9183985-05:00` | `rt\window.txt` |
| terminate issued (never delivered) | `09:50:40` (TEND line written `09:50:48.3841045`), again `10:01:13` | `rt\window.txt` |
| final stop | all four Procmon instances force-killed `2026-09-27T10:30:31.6600517-05:00` (`stop2.ps1`) | `rt\window.txt` |
| effective Procmon span | `09:33:29.162 → 10:31:03.192` (57.6 min, 1,063,077 recovered events) | `api-trace-w1-rows.csv.gz` |
| observer side-band | run 1: 211 ticks `09:33:30 → 09:52:32`; run 2: 213 ticks `10:10:32 → 10:29:35` | `snap.txt` (`OBSERVER END` ×2) |
| session state throughout | session 1 `Disc`, `LogonUI.exe` PID 396500 in session 1 (locked) | `query session`, `Get-Process LogonUI` @09:36:06, @09:49:06, @10:03:42, @10:24:02, @10:30:31 |
| memory | free 8,553,684 KB (T0) → 7,807,760 KB (end) — no pressure episode | `Win32_OperatingSystem.FreePhysicalMemory` |

### (a) Classifier launch contract — v10.1.44

**Command line (v10.1.44, real, two independent sources):**

CIM snapshot at `09:31:16` (`rt\base.txt`, `Get-CimInstance Win32_Process`):

```
PROC VictoryShieldClassifier.exe pid=191248 ppid=128096 created=9/25/2026 9:38:57 PM
  cmd="C:\Program Files\CE\VictoryShieldClassifier.exe" --version=10.1.44 --model="C:\Program Files\CE\data"
  --data=C:\ProgramData\CovenantEyes\Classifier\S-1-5-21-2224134039-3417563983-3831536026-1001\data
  --cache=C:\ProgramData\CovenantEyes\Classifier\S-1-5-21-2224134039-3417563983-3831536026-1001\cache
```

Classifier's own log first line (`C:\ProgramData\CovenantEyes\Classifier\logs\191248.txt`, identical
text):

```
2026/09/25 21:38:57.377 MAR Classifier: Command line: "C:\Program Files\CE\VictoryShieldClassifier.exe" --version=10.1.44 --model="C:\Program Files\CE\data" --data=…\data --cache=…\cache
2026/09/25 21:38:57.380 MAR Classifier: Classifier v10.1.44 is starting
```

The v10.1.44 contract is **shape-identical** to the v10.1.1 line in `process-observation.md`
(`--version` bumped 10.1.1→10.1.44, binary renamed `CovenantEyesClassifier.exe`→
`VictoryShieldClassifier.exe`); everything else (`--model` shared install dir, per-SID
`--data`/`--cache`) is unchanged.

**Parent identity:**

| PID | PPID | parent process | evidence |
|---|---|---|---|
| 191248 `VictoryShieldClassifier.exe` | **128096** | `VictoryShield.exe` (the UI) | baseline CIM `ppid=128096` @09:31:16 (constant across all 568 observer PROC samples through 10:29:35) |
| 128096 `VictoryShield.exe` | **127048** | **`VSWD.exe`** (the watchdog service!) | baseline CIM `ppid=127048`, observer PROC rows n=568 unchanged |
| 127048 `VSWD.exe` | 1348 | `services.exe` | baseline CIM |

So the live spawn chain is **`services.exe → VSWD.exe → VictoryShield.exe → VictoryShieldClassifier.exe`**.
The UI's parent being **VSWD** (not `explorer.exe`/the `HKLM\…\Run` key) is a deviation from the
`process-observation.md` inference that the Run key is how the UI starts: [INFERENCE] VSWD launches
(or relaunches) the UI directly and the Run key is a second, logon-time path.

**Relaunch-supervision behavior:**

- Historical, same binary: `logs\vs\major-149356.log` (a *failed* second UI instance on
  9/25 15:20:47, 48 s after the current UI's start) shows the duplicate-launch guard:
  `Failed to create the VictoryShieldIsRunning mutex…` / `Victory Shield is probably already
  running.` / `Process is terminating` — [INFERENCE] VSWD's supervisor attempted a second launch
  while one was alive; the mutex made it exit immediately.
- Classifier restarts by the UI (per-PID logs): `145044.txt` ends `2026/09/25 16:06:03.256 …
  Classifier v10.1.44 is terminating` and `268008.txt` starts `2026/09/25 16:06:03.750` (**0.5 s
  later**); `268008.txt` ends `2026/09/25 21:38:57.226 … terminating` and `191248.txt` starts
  `2026/09/25 21:38:57.377` (**0.15 s later**) — sub-second replacement, consistent with the
  5 s `LaunchAndMonitorScreenMonitoring` relaunch poll catching the death within one poll
  (capture-pipeline §4: `LaunchAndMonitorScreenMonitoring` = `FUN_1402f0a90`).
- In-window negative across the full 57.6-min run: the four CE PIDs never changed — **568
  observer PROC samples** (284 per side-band run, 15 s spacing, 09:33:30 → 10:29:35, exactly 4
  distinct signatures) — and the Procmon process-class rows are **332 total: 167 `Thread Create`
  + 165 `Thread Exit`, ZERO `Process Create`/`Process Exit`/`Process Defined`**
  (`re/samples/runtime/api-trace-a-process-events.csv`), e.g.
  `09:33:54.217 pid=127048 Thread_Exit Thread ID=406728`. The relaunch supervisor never had a
  death to react to during the run.

### (b) Registry heartbeat attribution — `LastTelemetryUpdateAt`

**Who writes it: PID 5616 `VictoryShieldCommService.exe`.** The heartbeat `RegSetValue` rows
(excerpt; all 15 `RegSetValue` events of the run — 6 × `LastTelemetryUpdateAt`, 6 × UI
`ClientCrashesSince`, 3 × upload trio — are in `re/samples/runtime/api-trace-b-registry-tick.csv`
and tabulated below):

```
09:37:54.790 pid=5616 RegSetValue HKLM\SOFTWARE\Covenant Eyes\Victory Shield\LastTelemetryUpdateAt
             Type=REG_SZ; Length=76; Data=2026-09-27T14:37:55.3250000 UTC +0000
09:47:55.724 pid=5616 RegSetValue HKLM\SOFTWARE\Covenant Eyes\Victory Shield\LastTelemetryUpdateAt
             Type=REG_SZ; Length=76; Data=2026-09-27T14:47:56.2590000 UTC +0000
09:34:50.606 pid=128096 RegSetValue HKCU\Software\Covenant Eyes\Victory Shield\ClientCrashesSince  Data=00 00 00 00
09:44:51.741 pid=128096 RegSetValue HKCU\…\ClientCrashesSince  Data=00 00 00 00
09:54:52.810 pid=128096 RegSetValue HKCU\…\ClientCrashesSince  Data=00 00 00 00
```

**Tick series — full 57.6-min run, same writer, dead regular:**

| # | RegSetValue row (CDT) | value written | Δ prev |
|---|---|---|---|
| 1 | 09:37:54.790 | `2026-09-27T14:37:55.3250000 UTC` | (prev = 09:27:54.305 baseline) |
| 2 | 09:47:55.724 | `14:47:56.259` | 600.934 s |
| 3 | 09:57:56.628 | `14:57:57.163` | 600.904 s |
| 4 | 10:07:57.597 | `15:07:58.132` | 600.969 s |
| 5 | 10:17:58.575 | `15:17:59.111` | 600.978 s |
| 6 | 10:27:59.534 | `15:28:00.089` | 600.959 s |

Five in-window intervals: **600.90–600.98 s (mean 600.95 s)** — the ≈601 s series of
`network-capture.md` with per-PID attribution. The value string runs a **constant ≈+0.54 s ahead**
of the Procmon event time [INFERENCE: value stamped from the server-synced clock, event timestamped
from the local clock]. The observer's independent key-`LastWriteTime` reads land on the same
instants (`api-trace-snap.txt`: `10:18:03.766 REG … = 2026-09-27T10:17:58.6058607`,
`10:28:14.937 REG … = 10:27:59.5708202`).

A **second, independent 601 s writer** (previously subsumed in the "key moves every ~10 min"
observation of `process-observation.md`): the **UI (128096)** writes
`HKCU\Software\Covenant Eyes\Victory Shield\ClientCrashesSince = 00 00 00 00` every
**601.07–601.14 s** (09:34:50.606, 09:44:51.741, 09:54:52.810, 10:04:53.925, 10:14:55.025,
10:24:56.097) — a UI-local tick ~0.14 s slower than the service's, on its own key hive.

**The tick is not the only write — one real telemetry *upload* was captured (10:23:34):**

```
10:23:34.771 pid=5616 RegSetValue HKLM\…\ApiTelemetryStatus      Type=REG_SZ  Data=success
10:23:34.778 pid=5616 RegSetValue HKLM\…\ApiTelemetryResumeTime   Type=REG_SZ  Data=(empty)
10:23:34.778 pid=5616 RegSetValue HKLM\…\LastTelemetryUploadAt    Type=REG_SZ  Data=2026-09-27T15:23:34.2890000 UTC +0000
```

clustered with `Disconnect :50805` (`.346`) → loopback self-pair (`.346`) → `Connect 10.0.0.21:51070
-> 208.185.195.49:443` (`.597`) and a 39-`WriteFile` `ce-file` burst in minute 10:23 — i.e. **the
first real upload event since 2026-09-20** (both `network-capture.md`'s "LTU frozen" open question
and `process-observation.md`'s "upload row frozen" resolved: it *does* move, on upload success,
written by the comm service with `ApiTelemetryStatus=success`). No other `LastTelemetryUploadAt`
write occurred in 57.6 min.

**Surrounding tick behavior (±2 s around each `LastTelemetryUpdateAt` write)** — the tick is a
full local bookkeeping pass, not a single value write (aggregated rows, `api-trace-b-registry-tick.csv`):

- registry: `RegCreateKey` + `RegOpenKey` ×10 + `RegQueryKey HKLM` ×11 + `RegSetInfoKey` ×11 on
  `HKLM\SOFTWARE\Covenant Eyes\Victory Shield`, `RegQueryValue` of
  `ClientapiDomainRo…`, `EnableDebugLogging`, `HttpClientTracing`, **`ForceCrashCommService`**,
  **`ServiceCrashes`**, **`SqlErrors`** — exactly the inputs of `Impl::updateMetricsSql` /
  `Impl::updateMetricsCrashes` (`upload-protocol.md` §: "get Sql errors status" → "Some SQL errors
  detected: ", crash counters) — then **`RegFlushKey HKLM\SOFTWARE\Covenant Eyes\Victory Shield`**
  (×1 per tick) and the `LastTelemetryUpdateAt` `RegSetValue`.
- SQLite: at the 09:47:55 tick the comm service performed **5,593 `ReadFile` on `ce-file`** plus
  56 `CreateFile`/73 `LockFile`/14 `CreateFileMapping` within ±2 s (metrics/crash scan over the DB),
  `ReadFile ce-user-file-wal Offset=774616`, and at the 09:37:54 tick a
  `CreateFile ce_user_event_message_queue Disposition=Create`.
- registry hive flush: `FlushBuffersFile C:\Windows\System32\config\SOFTWARE.LOG1` + 2× `WriteFile`
  (the SOFTWARE hive checkpoint the key write triggers).
- **zero network events at either tick** (full network timeline below has nothing within ±2 s of
  09:37:54/09:47:55) — corroborating `network-capture.md`'s "zero-packet tick" with per-PID data.
- other CE processes at the tick only emit their routine profiling samples (VSWD/UI/classifier
  `Thread_Profiling`), i.e. **the tick is exclusively the comm service's.**
- Consistency check across all five ticks (`api-trace-b-registry-tick.csv`, ±3 s contexts for
  09:37/09:47/09:57/10:07/10:17/10:23/10:27): every tick has exactly one
  `RegQueryValue SqlErrors`, one `RegSetValue LastTelemetryUpdateAt`, one `RegFlushKey`, and
  **zero network rows** — but the massive `ce-file` scan (5,593 `ReadFile`) appears **only at
  09:47:55**; later ticks read zero `ce-file` pages. [INFERENCE] the metrics SQL scan is
  conditional on pending rows — the 09:43–09:53 upload burst supplied them.

### (c) `127.0.0.1:48867` clients — none during the run

- Procmon network rows across the **full 57.6-min run: 259; ZERO involve port 48867** (no
  `Connect`, no `Accept`; `re/samples/runtime/api-trace-c-network.csv`).
- Observer `netstat -ano` sampled every 5 s (211 rows 09:33–09:52 + 213 rows 10:10–10:29,
  `api-trace-snap.txt`): the only 48867 row in *every* sample is
  `NET TCP 127.0.0.1:48867 0.0.0.0:0 LISTENING 5616` — the comm service's listener, never a
  single `ESTABLISHED` peer.
- Verdict: **in a locked-idle session, no process connects to the local API** — consistent with
  `service-ipc.md` §1 (dashboard/UI-libcurl are the expected clients; nobody is driving them);
  the accept path went unexercised for the whole run.
- What *did* connect (same extract, for contrast):
  - **5616 → backend `208.185.195.49:443`**: a fresh connection every **301 s** during the
    metrics-upload burst — `:50691` 09:43:31.859, `:50743` 09:48:32.906, `:50805` 09:53:33.908
    (three cycles, then **silent until 10:23**) — each preceded ~75–250 ms earlier by a
    **loopback self-connect pair of the same PID** (`Connect 127.0.0.1:50687 -> 127.0.0.1:50686`
    + `Accept …` + 9-byte send / 1-byte reply / `Disconnect`, e.g. 09:43:31.562); activity
    resumes 10:23:34.597 / 10:24:37.456 / 10:28:37.897 around the telemetry upload (verdict b).
  - **128096 UI → `69.41.14.75:80`** every **900 s**: Connect at 09:37:07.131, 09:52:07.967,
    10:07:08.815, 10:22:09.614 (138 B sent / 222 B received), each preceded ~0.6 s earlier by the
    UI's own loopback self-pair (09:37:06.708 `127.0.0.1:50586->50585`, both endpoints pid
    128096) — [INFERENCE] periodic HTTP task (WinSparkle/appcast-like; host unknown).
  - **128096 UI → `208.185.195.49:443`** at 10:20:36.398, 10:20:44.716, 10:22:09.234 — the UI
    talking to the CE API directly (new observation; rides the same loopback-pair pattern),
    alongside 36 `WriteFile ce-file` bursts at 10:20 — [INFERENCE] UI-side metric/log upload.

### (d) Live screenstate chain — **gated off: session 1 has been WTS-locked since 2026-09-25 21:56:25**

The chain is *measurable as a negative*, over the **whole 57.6-min run**:

- **Zero classifier-tree file events.** The recovered stream (**1,063,077 rows**, 09:33:29 →
  10:31:03) contains **0 events whose path is under `C:\ProgramData\CovenantEyes\Classifier\`** —
  not even a `CreateFile` on `data\pdl\` (the `handlePdlFileNotifications` directory watch was
  armed long ago on a persistent handle, so re-arms produce no events). Empty extract:
  `re/samples/runtime/api-trace-d-classifier-tree.csv` (header only).
- **Zero transaction folders.** Observer every 5 s across both side-band runs (424 ticks total):
  only ever `DIR 1790391375374 mtime=2026-09-25T21:56:15` (the stale `data\client\` batch); no
  `pdl\…` directory appears at any sample through **10:29:30** (`api-trace-snap.txt`, both
  `OBSERVER END` markers). Disk agrees: `pdl\` was empty at baseline 09:31:16
  (`api-trace-base.txt` has no `PDLDIR` rows).
- **Why: the session gate.** `major-128096.log` (UI log) shows the lock and no unlock:
  `CRIT|09-25 21:56:25.xxx|…|CVictoryShieldView::OnWtsSessionChange|A user has locked session ID: 1`
  — last WTS event in the log (next lines are hourly `ServerTimeManager::sync`), and
  `query session` shows `dolphin 1 Disc` with **`LogonUI.exe` PID 396500 inside session 1**
  (checked 09:36:06, 09:49:06, 10:03:42, 10:24:02, and finally at stop `10:30:31.660`, recorded
  in `api-trace-window.txt`) = locked for the entire run. Per `capture-pipeline.md`,
  `OnWtsSessionChange(7)` → `setSessionOn(false)` → `isDisplayOn()` false → the capture lambda
  early-outs with `*param_2 = 5000` (**5 000 ms retry, no transaction folder**) — so
  **zero** `im<N>.dat`/`ss.dat`/`rr.dat` and zero reverse-channel files can be produced while
  locked, exactly as observed.
- **The 5 s retry itself is visible live**, in the UI's own log: the out-of-memory burst of
  `CreateToolhelp32Snapshot` failures (the classifier-liveness enumeration, `findProcessesRunningWithOwner`)
  between `09-27 00:33:50.722` and `00:37:06.877` fires at 5–6 s spacing
  (00:35:14.711, 00:35:19.793, 00:35:24.879, 00:35:29.970, 00:35:35.066, 00:35:40.157,
  00:35:45.256, 00:35:50.364, 00:35:55.462, 00:36:00.567, … — mean Δ ≈ 5.06 s over 27
  consecutive samples) — **the gate-false retry cadence measured from production logs**, matching
  the static RE value 5 000 ms in `capture-pipeline.md` (`FUN_1402d3600`: `*param_2 = 5000`,
  early-out when `FUN_1402d7f00` gate false). Full log excerpt:
  `re/samples/runtime/vs-128096.log` (line numbers from `type`).
- Also for the record: no `VictoryShield`/classifier folder *creation* attempts appear in the
  19,049-row registry extract or anywhere else in the stream — the gate short-circuits *before*
  `createTransactionFolder` (consistent with the static order of checks).
- **Observed historical cadence inputs (not live):** the only surviving pdl folder from an
  unlocked period is `2026-09-20T04-55-17.3281948-0` (prior passes; since cleaned) and
  `data\client\1790391375374` (epoch-ms `2026-09-25T21:56:15.374`, written 10 s before the lock).
  The measured-under-activity interval table is deferred to Open questions #1 (the orchestrator's
  RDP reconnect did not arrive before the 10:30:31 stop; follow-up capture will fill it).

### (e) `ce-file` write attribution

All `WriteFile`/`FlushBuffersFile` on `ce-file*` in window 1 (`api-trace-e-cefile-writes.csv`,
minute-bucketed):

| minute (CDT) | writer PID | WriteFile | FlushBuffersFile | correlate |
|---|---|---|---|---|
| 09:37 | 128096 UI | 3 | 1 | UI's 15-min HTTP cycle (see c) → its own metric rows |
| 09:38 | 5616 comm svc | 3 | 1 | post-tick bookkeeping |
| 09:43 | 5616 comm svc | 18 | 4 | **metrics row `client_api_success` id725 `created_at 2026-09-27 14:43:39` = 09:43:39 — burst at `09:43:39.619`–`.620` (4 row-pairs + 20,480 B WAL checkpoint), second-level exact** |
| 09:48 | 5616 comm svc | 15 | 3 | **metrics id726 `created_at … 14:48:40` → burst at `09:48:40.033` (4 row-pairs + checkpoint), exact** |
| 09:52 | 128096 UI | 11 | 1 | UI cycle #2 (09:52:07 HTTP) |
| 09:53 | 5616 comm svc | 9 | 3 | 301 s API cycle #3 |
| 10:07 | 128096 UI | 3 | 1 | UI cycle #3 (10:07:08 HTTP) |
| 10:20 | 128096 UI | 36 | 2 | UI→backend TLS burst (10:20:36/44, see c) |
| 10:21 | 5616 comm svc | 3 | 1 | bookkeeping |
| 10:22 | 128096 UI | 11 | 1 | UI cycle #4 (10:22:09 HTTP) |
| **10:23** | **5616 comm svc** | **39** | **3** | **telemetry upload: `LastTelemetryUploadAt`/`ApiTelemetryStatus=success` written 10:23:34.77x, fresh TLS connect 10:23:34.597 (verdict b) — metrics rows marked `sent`** |
| 10:24 | 5616 comm svc | 11 | 1 | follow-on API cycle (connect 10:24:37) |
| 10:28 | 5616 comm svc | 13 | 3 | post-tick (10:27:59) + API cycle (connect 10:28:37) |

Sample rows (exact):

```
09:43:39.619 pid=5616 WriteFile ce-file-wal Offset=609792 Length=24
09:43:39.620 pid=5616 FlushBuffersFile ce-file-wal
09:43:39.620 pid=5616 WriteFile ce-file-wal Offset=606208 Length=20480 I/O Flags=Non-cached, Paging I/O, Synchronous
09:48:40.033 pid=5616 WriteFile ce-file-wal Offset=638632 Length=24   (… 4 more pairs …)
09:48:40.033 pid=5616 FlushBuffersFile ce-file-wal
09:48:40.033 pid=5616 WriteFile ce-file-wal Offset=634880 Length=20480 Non-cached…
```

Read-side scale (context for the 276 k `ReadFile`s in the extract): the comm service re-opens and
scans `ce-file`/`-wal`/`-shm` in bursts (56 `CreateFile` + 5,593 `ReadFile` inside one 2-s tick
window at 09:47:55) — SQLite access under WAL mode; `ce-file-journal` open attempts return
`3221225524` (`OBJECT_NAME_NOT_FOUND` — journal absent = normal for WAL). The UI also writes
(`ce_user_event_message_queue` create/open around the tick; `ce-user-file` locked reads). The
mid-window DB copy (`api-trace-ce-file-snapshot`, 2,891,776 B + `-wal`) shows `metrics` at 726
rows with the two exact-second correlations above (`status_changed_at`/`created_at` columns).

---

## Synthesis — one full observed cycle (09:47:55 → 09:48:40), and the chain that was gated

Everything below is window-1 data, all times CDT, cross-checked against
`capture-pipeline.md` (expected flow), `upload-protocol.md` (601 s tick internals) and
`service-ipc.md` (48867).

| t | pid | what | evidence row |
|---|---|---|---|
| 09:47:55.722–.723 | 5616 | `ce-user-file-wal` read (`Offset=774616`), user-file lock/unlock churn — the tick's DB reads begin | recovered stream, ±0.25 s block |
| 09:47:55.723 | 5616 | `RegCreateKey HKLM\SOFTWARE\Covenant Eyes\Victory Shield` (REG_OPENED_EXISTING) | `…b-registry-tick.csv` |
| **09:47:55.724** | **5616** | **`RegSetValue …\LastTelemetryUpdateAt = 2026-09-27T14:47:56.2590000 UTC`** | quoted in (b) |
| 09:47:55.7xx | 5616 | `RegQueryValue` `SqlErrors`, `ServiceCrashes`, `ForceCrashCommService`, `EnableDebugLogging`, `HttpClientTracing`, `ClientapiDomainRo…` → metrics/crash inputs (`updateMetricsSql`/`updateMetricsCrashes`) | (b) tick context |
| 09:47:55.7xx | 5616 | `RegFlushKey` + `FlushBuffersFile C:\Windows\System32\config\SOFTWARE.LOG2` (registry hive flush) | (b) tick context |
| 09:47:53–57 (±2 s) | 5616 | **5,593 × `ReadFile ce-file`** + 56 `CreateFile` + 73 `LockFile` — metrics scan over SQLite/WAL | (b)/(e) tick context |
| (no network at tick) | — | zero TCP rows within ±2 s — the tick is purely local | full network extract (c) |
| 09:48:32.607 | 5616 | loopback self-connect pair `127.0.0.1:50737↔50738`, 9 B → 1 B → `Disconnect` | (c) |
| 09:48:32.906 | 5616 | `Connect 10.0.0.21:50743 -> 208.185.195.49:443` (fresh backend TLS; prior conn `:50691` disconnected 09:48:32.608) | (c) |
| 09:48:32.980–33.042 | 5616 | `Send` 741 B, 80 B, 1494 B / `Receive` 260 B, 287 B, 794 B — metrics upload exchange | (c) |
| **09:48:40.033** | **5616** | **4 metric rows inserted: `WriteFile ce-file-wal` ×8 (4× [24 B frame + 4096 B page]) + `FlushBuffersFile` + 20,480 B non-cached checkpoint** — matches `metrics.created_at = 2026-09-27 14:48:40` exactly | (e) |

**And the upload-triggering activity the assignment asked for (10:23:34, same run):**

| t | pid | what |
|---|---|---|
| 10:23:34.346 | 5616 | `Disconnect 10.0.0.21:50805 -> 208.185.195.49:443` (idle backend conn) + loopback self-pair `51065↔51064` (9 B/1 B) |
| 10:23:34.597 | 5616 | `Connect 10.0.0.21:51070 -> 208.185.195.49:443` — new TLS for the upload |
| 10:23:34.771/.778 | 5616 | `RegSetValue ApiTelemetryStatus = success`, `ApiTelemetryResumeTime = (empty)`, `LastTelemetryUploadAt = 2026-09-27T15:23:34.289 UTC` |
| minute 10:23 | 5616 | **39 × `WriteFile ce-file-wal` + 3 flushes** — metrics rows transitioning to `sent` |
| 10:24:37.456 | 5616 | next `Connect -> 208.185.195.49:443` (upload-exchange continuation) |

This is the complete answer to "any upload-triggering activity": the 601 s *tick* stayed local,
the *upload* is a separate event (first since 2026-09-20) with its own connection, status values,
and DB write burst — all by PID 5616.

**Confirmations vs `capture-pipeline.md`/`upload-protocol.md`:**
- ✅ 601 s self-rescheduling tick (`FUN_14021a290`: 60000×10 ms) — measured **600.90–600.98 s**
  over five consecutive in-window intervals.
- ✅ tick writes `LastTelemetryUpdateAt` and runs metrics/crash maintenance
  (`updateMetricsSql`/`updateMetricsCrashes`) — the `SqlErrors`/`ServiceCrashes` queries and the
  5.6 k-row `ce-file` scan are exactly those inputs; `RegFlushKey` after the value write.
- ✅ tick produces **zero packets at the tick instant** (network-capture's finding) — now with
  PID attribution.
- ✅ metrics land in `ce-file` seconds after the API exchange, written by the same PID (5616),
  `created_at` matching to the second.
- ✅ `LastTelemetryUploadAt`/`ApiTelemetryStatus` **do** move — on a real upload (10:23:34),
  written by the comm service; resolves `network-capture.md` open question #6 (their window
  simply never contained an upload).
- ⚠ **Deviations / not observed as specified:**
  - the **capture → `ss.dat` → classifier-read → reverse-message chain** never ran: gate closed
    by the WTS lock (verdict d) — `capture-pipeline.md`'s expectations are matched only in their
    *negative* form (zero folder creations, zero classifier-tree events), plus the gate's 5 s
    retry cadence.
  - backend connections rotate every **301 s** but only during activity bursts (three cycles
    09:43/48:53, then 30 min of silence, resumed 10:23–10:28 around the upload) — the 301 s
    spacing is an activity-cycle period, not a global keep-alive.
  - **no 48867 traffic at all** across 57.6 min — `service-ipc.md`'s expected UI/dashboard
    clients are absent because the session is locked; the listener's accept path went
    unexercised.

## Linux-reimplementation notes

- **Gate your capture daemon on the session, and log the gate.** The WTS-lock gate worked exactly
  as designed (zero captures while locked, silent 5 s retry) — but it is *invisible* except
  through error bursts. On Linux: gate on logind's `LockedHint`/`Active` *and* emit a throttled
  log line when gated, so a silent idle machine is diagnosable from logs alone.
- **Timestamp-value convention:** CE stores `LastTelemetryUpdateAt` as a REG_SZ
  `"…T…Z UTC +0000"` *and* the key's own `LastWriteTime` tracks it — writing a formatted string
  value (not FILETIME) makes the heartbeat readable from any language without P/Invoke quirks.
  Copy that: an ISO-8601 UTC string + fs/registry mtime as a redundant channel.
- **Split bookkeeping from transport:** the 601 s local tick (metrics SQL scan + crash counters +
  heartbeat stamp) versus a separate ~301 s upload cycle with fresh connections. Porting advice:
  keep the watchdog tick purely local (must never block on network), and make uploads their own
  self-rescheduling loop with per-attempt connections (CE's server closes after each exchange —
  don't hold long-lived sockets you must resurrect).
- **Self-connect wakeup pattern** (9 B → 1 B loopback pair before each API call, same PID both
  ends): on Linux just use an `eventfd`/`socketpair`/`SOCK_DGRAM` to yourself — or skip it
  entirely; it is an artifact of a generic IPC helper, worth not copying.
- **DB-writer attribution discipline:** every `ce-file` write burst maps to a *cause* (metric
  insert at API success, tick scan, queue touch). Keep that causality legible in your schema
  (e.g. `created_at` = time of cause, not time of flush) — the exact-second correlation in (e)
  is what made the chain provable.
- **Observability for RE:** per-PID log files (`major-<pid>.log`, `<pid>.txt`) + a self-reporting
  command line as the log's first line made verdict (a) possible with zero tooling; do the same
  (`argv` line at start, PID-suffixed logs) — it's cheap and forensic-grade.

## Open questions

1. **Measured capture cadence under activity (owed cadence table).** Session 1 stayed locked for
   the whole run — no RDP reconnect arrived before the stop at `2026-09-27T10:30:31.660`
   (orchestrator's ~35-min budget expired), so the `pdl/<ts>` folder-creation cadence could not be
   measured live. What *is* pinned: the gate-false retry = **5.06 s mean over 27 samples** (UI log
   burst, verdict d) and the static contract (`capture-pipeline.md`: interval =
   `imageScreenshotInterval_sec ± imageScreenshotIntervalVariance_pct`, 5 000/40 000/60 000 ms
   fallbacks). Follow-up capture after unlock will fill the ≥3-interval table
   (`im<N>.dat`/`ss.dat`/`rr.dat` writers, classifier reads, `data\client\` reverse-channel writes
   are already primed as exact filters for that run — `ce.pmc` + `recov-unclean-pml.py` are ready).
2. **Why the UI writes `HKCU\…\ClientCrashesSince = 0` every 601 s** on its own (independent of
   the comm service's HKLM tick; six in-window samples, 601.07–601.14 s). [INFERENCE]
   crash-counter reset for the *UI* process on the same scheduler shape as the service's
   telemetry tick.
3. **The loopback self-connect (9 B/1 B) immediately before each backend/API call** — same PID on
   both ends, ports ephemeral, never 48867. Wire-level purpose unknown (wakeup handshake? local
   proxy probe?). Needs a decode of the 9 bytes (a follow-up Procmon window with a known payload
   moment, or the network pass).
4. **`69.41.14.75:80` (UI, every 900 s, 138 B request / 222 B response)** — which host/endpoint?
   [INFERENCE] an update/appcast or telemetry HTTP check; no SNI (plain HTTP) and no DNS cache
   hit in this run.
5. **The 301 s spacing of backend reconnects** (09:43:31 → 09:48:32 → 09:53:33 exactly, then a
   30-min quiet gap, resuming 10:23/10:24/10:28) — is 301 s a per-upload-exchange timeout
   (server closes, client re-dials) or a client scheduling period? It stopped and started with
   *activity*, and the `metrics.status_changed_at = 'sent'` stamps coincide with the connect
   seconds (14:43:31/14:48:32/14:53:33), so [INFERENCE] each 301 s unit = one metrics-exchange
   generation, not a global keep-alive.
6. **Procmon `/Terminate` cross-window-station behavior** (Limitations #6) — is the signal a
   window message (FindWindow-scoped) or a named event with an ACL oddity? Reproducible: WMI-launched
   instance ignores ssh-launched `/Terminate`; same-call launch+terminate works.
7. Left for the follow-up unlock run: classifier `Process Create`-attributed relaunch observation
   (in-window PIDs never changed), and any `RestartVS*`/`vs-config*` invocation paths (none seen;
   filters were armed for them).

---

## Evidence index (raw captures)

**On the VM (`C:\Users\dolphin\rt\`, untouched after the run):**

| file | size | content |
|---|---|---|
| `api-trace.pml` | 536,870,912 B | window-1 capture (unclean close — needs `recov-unclean-pml.py`), events 09:33:29→10:31:03 |
| `api-trace2.pml` | 134,217,728 B | window-2 preallocation shell, **0 events** |
| `trial.pml` | deleted before window 1 (`Remove-Item …\*.pml`); clean copy preserved in samples (1,474,299 B) — filter proof + TID→PID source |
| `ce.pmc`, `observer.ps1`, `stop2.ps1`, `probe.ps1` | small | tooling |
| `snap.txt`, `base.txt`, `window.txt`, `vs-128096.log`, `cllogs\*.txt`, `db\ce-file*` | small | side-band + logs + DB snapshot |

**In `re/samples/runtime/` (all prefixed `api-trace-`):**

| file | rows / content |
|---|---|
| `api-trace-w1-rows.csv.gz` | **1,063,077** recovered events with PID (full run) |
| `api-trace-b-registry-tick.csv` | 19,049 — all `RegSet*` on CE keys + ±3 s contexts of all 7 tick/upload moments |
| `api-trace-c-network.csv` | 259 — every network event (zero 48867) |
| `api-trace-e-cefile-writes.csv` | 26,768 — `ce-file*` CreateFile/WriteFile/Flush |
| `api-trace-a-process-events.csv` | 332 — process-class rows (no lifecycle events) |
| `api-trace-d-classifier-tree.csv` | **0 rows** (header only) — the gate verdict |
| `api-trace-snap.txt` | 2,408 — both observer runs (NET/DIR/FILE/PROC/REG every 5–15 s) |
| `api-trace-base.txt`, `api-trace-window.txt` | baseline snapshot; launch/stop record incl. final force-kill |
| `api-trace-trial.pml` | clean trial capture (filter + TID evidence) |
| `api-trace-ce-file-snapshot` | mid-run SQLite DB copy (metrics table) |
| `recov-unclean-pml.py`, `analyze-pml.py`, `ce.pmc`, `observer.ps1` | the tooling that produced the extracts |
| `vs-128096.log`, `145044.txt`, `191248.txt`, `268008.txt`, … | UI log + all 17 classifier per-PID logs |

**Final VM state:** no `Procmon64.exe` processes remain (force-killed 10:30:31; force-kill of
*our* tracer only — no CE process was signalled, no CE file/registry/DB modified; the only CE-side
reads were file copies into `rt\`); session 1 untouched (still locked, `LogonUI` 396500, same four
CE PIDs with unchanged parents); observer scripts exited (`OBSERVER END ticks=213`); verified at
`2026-09-27T10:58:24` — disk free 22 GB, RAM free ≈7.8 GB (no pressure episode at any point).


