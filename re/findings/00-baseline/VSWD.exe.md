# VSWD.exe — baseline

## What it does

The **VSWD Windows service executable** (Victory Shield WatchDog). Installs/hosts the CE services, watches user sessions, and **relaunches CE processes (`VictoryShield.exe`) into each interactive session** via `CreateProcessAsUser`. Runs the Registry Protector and Folder Protector ("RP"/"FP" startup) that monitor CE's registry keys/files and auto-repair tampering ("Anomaly Detected. Repairing […]"). Tracks client crash counts, cleans up Run-key autostarts, and knows the service registration data for both `VSWD` and `VictoryShieldCommService`. The binary is a .NET (CIL) executable shipped with an `asInvoker` manifest.

## Mechanism

### Metadata

| Field | Value | Source |
|---|---|---|
| Source path | `C:\Program Files\CE\VSWD.exe` (108,992 bytes) | VM file |
| Language | `x86:LE:32:default` (x86, 32-bit PE), Compiler `cli` (.NET CIL assembly with native bootstrap stub) — [INFERENCE] IL-only AnyCPU assembly: runs as a 64-bit process on x64 hosts (its companion `VSWD.dll` is x64-only) | Ghidra `load_program`, `get_program_options` |
| Image base | `0x00400000` | PE optional header (local sample), consistent with Ghidra addresses |
| Functions | 110 (post-analysis; analysis time 132.2 s) | Ghidra `analysis_status`, `get_program_options` |
| PE TimeDateStamp | `1783516687` → 2026-07-08 13:18:07 UTC (CE 10.1.44 build session) | PE header `e_lfanew+8` |
| Authenticode signer | `CN="Covenant Eyes, Inc.", O="Covenant Eyes, Inc.", L=Owosso, S=…` | `Get-AuthenticodeSignature` |
| MD5 / SHA256 | `8240b32b8b6e65aa7d346e3435515fa0` / `1f7de6afe0878fa8c22b8549945da330d9092816b382c578711ef30f21c7080d` | Ghidra `get_program_options` |
| PDB | `VSWD.pdb`, RSDS GUID `1c8bbc6f-e469-48fc-8db6-c12f034e30f8`, age 1 | Ghidra `get_program_options` |
| Version info | CompanyName `Covenant Eyes`; FileDescription/ProductName `VSWD`; FileVersion `10.1.44`; Assembly Version `10.1.44.0`; Copyright `Copyright 2026 Covenant Eyes` | Ghidra `get_program_options` |
| Build stamp (embedded) | `July 08, 2026` / `20260708060657`, version `10.1.44`, commit `4222d5a90`, branch `master` | managed strings `0x0040b48f`–`0x0040b4f8` |

### Imports grouped by DLL

Native PE import table — 1 import (Ghidra `list_imports` = 1; `list_external_locations`):

| DLL | Import | IAT address |
|---|---|---|
| **MSCOREE.DLL** | `_CorExeMain` (CLR hosting entry) | `0x0000bdbc` |

Managed layer: API error-format strings show the P/Invoke surface — `DuplicateTokenEx`, `OpenProcessToken`, `CreateEnvironmentBlock`, `CreateProcessAsUser` (session-launch pipeline; [INFERENCE] advapi32/userenv/kernel32 interop) plus file/registry watching (FileSystemWatcher/registry-change handlers per `OnChanged(`/`OnRegChanged[` strings). No native networking/crypto imports; comms live in `VictoryShieldCommService.exe` per the service description string.

Category scan: **service control present** — the binary both configures the `VSWD`/`VictoryShieldCommService` services (registry value names `Start`, `Type`, `WOW64`, `ErrorControl`, `ObjectName`, `FailureActions`, `DependOnService`, `ImagePath`, `Description`, `Security`) and runs as one. Process-launch/injection-adjacent: `CreateProcessAsUser` + `DuplicateTokenEx` (launches in user sessions, not injection). No IOCTL, no GDI/screenshot, no browser APIs.

### Exports (Ghidra `list_exports`)

| Export | Address | Note |
|---|---|---|
| `entry` | `0x0040bdda` | PE entry |
| `MethodDefHdr_Tiny_00404c83` | `0x00404c83` | Ghidra analysis label (CIL method header), not a real export |

### Representative strings (with addresses)

Ghidra `list_strings` (native data, 3 total):

| Address | String | Category |
|---|---|---|
| `0x0040bdbe` | `_CorExeMain` | import name |
| `0x0040bdca` | `mscoree.dll` | import DLL name |
| `0x004199c8` | embedded manifest XML (`requestedExecutionLevel level="asInvoker"`, identity `MyApplication.app`) | manifest |

Managed metadata strings (UTF-16; VA mapped from `re/samples/00-baseline/VSWD.exe`):

| Address | String | Category |
|---|---|---|
| `0x0040a0e6` | `Software\Covenant Eyes\Victory Shield` | registry key (settings) |
| `0x0040ab37` | `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VSWD` | registry key (own service) |
| `0x0040abac` | `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VictoryShieldCommService` | registry key (sibling service) |
| `0x0040aa00` | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` | registry key (autostart cleanup) |
| `0x0040aa83` | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run` | registry key (autostart cleanup) |
| `0x0040a8dd` | `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{5AC5ED2E-2936-4B54-A429-703F9034938E}` | registry key (MSI product GUID) |
| `0x0040a6d0` | `c:\Program Files\CE\VSWD.exe` | service ImagePath |
| `0x0040a780` | `c:\Program Files\CE\VictoryShieldCommService.exe` | service ImagePath |
| `0x0040a70a` | `Communicates between Victory Shield processes and servers.` | service description |
| `0x0040a5ae` / `0x0040a6b2` / `0x0040a61e` | `Victory Shield` / `VSWD` / `LocalSystem` | service name / short name / account |
| `0x0040ad22` | `VictoryShield.exe` | watched/relaunched client process |
| `0x0040ad46`–`0x0040ada6` | `RpcSs`, `SamSs`, `EventLog`, `ProfSvc`, `Tcpip`, `Dhcp`, `Dnscache` | service dependency list |
| `0x00409b1a` | `CreateProcessAsUser Error: {0}` | log format (session launch) |
| `0x00409a66` / `0x00409a9e` / `0x00409ad6` | `DuplicateTokenEx Error: {0}` / `OpenProcessToken Error: {0}` / `CreateEnvironmentBlock Error: {0}` | log formats |
| `0x0040a314` | `Re-launching CE process under session ` | log format (watchdog action) |
| `0x00409b62` | `Monitoring thread is already running` | log string |
| `0x0040a512` / `0x0040a55e` | `Anomaly Detected.  Repairing [` / `OnRegChanged[` | log formats (Registry Protector repair) |
| `0x0040a4dc` / `0x0040a3ec` | `Enable Registry Protector(` / `Fail Enable Folder Protector(` | log formats (protectors) |
| `0x00409fe4` / `0x0040a03c` | `ClientCrashesAt` / `ClientCrashesSince` | crash-tracking value names |
| `0x0040a174` / `0x0040ac78` / `0x0040aca0` | `TL startup complete` / `RP startup complete` / `FP startup complete` | startup log markers |
| `0x0040a1e2`–`0x0040a2c4` | `Session info:` … `  State: ` | session-change logging |
| `0x0040997e` | `explorer` | token source for user-session launch |

No URLs/IPs, no named pipes, no mutex names in this binary's strings.

## Evidence

- Ghidra MCP (project `CE`, program `VSWD.exe`): `get_program_options("Program Information")` (30 options), `list_imports` (1), `list_external_locations` (`MSCOREE.DLL!_CorExeMain` @ `0x0000bdbc`), `list_exports` (2), `list_strings` (3) — addresses as tabulated.
- VM command output (2026-09-24): `VSWD.exe | ts=1783516687 | 2026-07-08 13:18:07Z | signer=CN="Covenant Eyes, Inc.", O="Covenant Eyes, Inc.", L=Owosso, S…`
- Local sample `re/samples/00-baseline/VSWD.exe` (scp'd, 108,992 B); managed UTF-16 strings extracted and VA-mapped by a PE section-table script (offset→RVA→VA), output captured 2026-09-24.
- Checkpoint: `C:\Users\dolphin\ghidra-ckpt\VSWD.exe.gzf` (380,447 B) + project `CE:/VSWD.exe` (saved).

## Linux-reimplementation notes

Maps onto a supervised daemon pair: (a) a **systemd unit** (analog of the VSWD service) that keeps the agent alive and restarts it per user session (`CreateProcessAsUser` ≈ `systemd --user` instance or a session-scoped supervisor); (b) **file/registry tamper repair** ≈ a watcher over `/etc/lustless/` config with restore-on-change (Registry/Folder Protector). `DependOnService` ≈ systemd `After=`/`Requires=`. Crash counters (`ClientCrashesAt/Since`) ≈ systemd `Restart=` + `NRestarts` or a small state file. [INFERENCE] The Registry Protector's repair loop is the anti-tamper core; LustLess should decide openly (and document) whether it wants equivalent self-protection.
