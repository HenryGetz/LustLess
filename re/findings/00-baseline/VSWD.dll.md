# VSWD.dll — baseline

## What it does

**WatchdogServiceLibrary** — the native (C++/CLI, mixed-mode x64) implementation of the VSWD watchdog, shared with `VSWD.exe`. Implements session watching + `CreateProcessAsUser` relaunch of `VictoryShield.exe`, the Registry Protector / Folder Protector tamper-repair loops, service-registration data for `VSWD` and `VictoryShieldCommService`, crash counters, and Windows privilege manipulation (embedded `Se*` privilege tables + advapi32 interop). Notably exports **`disableFileProtection`** and **`disableRegistryProtection`** — native entry points letting other CE components switch the protections off (e.g., during upgrade/uninstall).

## Mechanism

### Metadata

| Field | Value | Source |
|---|---|---|
| Source path | `C:\Program Files\CE\VSWD.dll` (127,424 bytes) | VM file |
| Language | `x86:LE:64:default` (x86-64, little-endian) — PE machine `0x8664`, image base `0x10000000` | Ghidra `load_program`; PE header (local sample) |
| Compiler | `visualstudio:unknown` (mixed-mode native + CIL) | Ghidra `get_program_options` |
| Functions | analyzed (analysis time 20.3 s) | Ghidra `get_program_options` "Analysis Times" |
| PE TimeDateStamp | `1783516694` → 2026-07-08 13:18:14 UTC | PE header `e_lfanew+8` |
| Authenticode signer | `CN="Covenant Eyes, Inc.", O="Covenant Eyes, Inc.", L=Owosso, S=…` | `Get-AuthenticodeSignature` |
| MD5 / SHA256 | `0791c03fad83ffeeb69589c6729f6a42` / `9ec0f894cadb82bf7d4c9a3b8218ae7ea06fc7cb283882ec172c27e8c848b7b9` | Ghidra `get_program_options` |
| PDB | none recorded in Ghidra options (unlike the other CE binaries) | Ghidra `get_program_options` |
| Version info | CompanyName `Covenant Eyes`; Comments/FileDescription/ProductName `WatchdogServiceLibrary`; FileVersion `10.1.44`; Assembly Version `10.1.44.0`; InternalName/OriginalFilename `VSWD.dll` | Ghidra `get_program_options` |
| Build stamp (embedded) | `July 08, 2026` / `20260708060657`, `10.1.44`, commit `4222d5a90`, branch `master` | managed strings `0x1000ee19`–`0x1000ee80` |

### Imports grouped by DLL

Native PE import table — 1 import (Ghidra `list_imports` = 1; `list_external_locations`):

| DLL | Import | IAT address |
|---|---|---|
| **MSCOREE.DLL** | `_CorDllMain` (CLR hosting entry for the mixed-mode assembly) | `0x00010250` |

Managed/interop layer (strings, VA-mapped): P/Invoke target DLL names **`advapi32.dll`** (`0x1000f581`) and **`kernel32.dll`** (`0x1000f59a`); API names evidenced by log formats: `DuplicateTokenEx`, `OpenProcessToken`, `CreateEnvironmentBlock`, `CreateProcessAsUser` (`0x1000cef6`).

Category scan: process-launch (session-scoped `CreateProcessAsUser`, token work via `Se*` table incl. `SeDebugPrivilege` @ `0x1000e354`, `SeTcbPrivilege` @ `0x1000e74a`), service-control (service registry schema strings), file/registry protection. **No** networking, **no** crypto, **no** IOCTL, **no** GDI/screenshot, **no** browser APIs.

### Exports (Ghidra `list_exports`, 5 entries = 3 named + 2 ordinal aliases)

| Export | Address | Note |
|---|---|---|
| `disableFileProtection` | `0x100101ee` | turns OFF the Folder Protector |
| `disableRegistryProtection` | `0x100101fa` | turns OFF the Registry Protector |
| `entry` | `0x1001026e` | PE entry |

### Representative strings (with addresses)

Ghidra `list_strings` (native data, 5 total):

| Address | String | Category |
|---|---|---|
| `0x10010252` | `_CorDllMain` | import name |
| `0x1001025e` | `mscoree.dll` | import DLL name |
| `0x1001204c` | `disableFileProtection` | export name |
| `0x10012062` | `disableRegistryProtection` | export name |
| `0x1001207c` | `\VSWD.dll` | self-path fragment |

Managed/mixed metadata strings (UTF-16, VA-mapped from `re/samples/00-baseline/VSWD.dll`):

| Address | String | Category |
|---|---|---|
| `0x1000d542` | `Software\Covenant Eyes\Victory Shield` | registry key (settings) |
| `0x1000df13` | `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VSWD` | registry key (own service) |
| `0x1000df88` | `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VictoryShieldCommService` | registry key (sibling service) |
| `0x1000dddc` | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` | registry key (autostart cleanup) |
| `0x1000de5f` | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run` | registry key (autostart cleanup) |
| `0x1000dcb9` | `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{5AC5ED2E-2936-4B54-A429-703F9034938E}` | registry key (MSI product GUID) |
| `0x1000daac` | `c:\Program Files\CE\VSWD.exe` | service ImagePath |
| `0x1000db5c` | `c:\Program Files\CE\VictoryShieldCommService.exe` | service ImagePath |
| `0x1000dae6` | `Communicates between Victory Shield processes and servers.` | service description |
| `0x1000d98a` / `0x1000da8e` / `0x1000d9fa` | `Victory Shield` / `VSWD` / `LocalSystem` | service name / short name / account |
| `0x1000e0fe` | `VictoryShield.exe` | watched/relaunched client |
| `0x1000e122`–`0x1000e182` | `RpcSs`, `SamSs`, `EventLog`, `ProfSvc`, `Tcpip`, `Dhcp`, `Dnscache` | service dependencies |
| `0x1000cef6` | `CreateProcessAsUser Error: {0}` | log format |
| `0x1000d770` | `Re-launching CE process under session ` | log format (watchdog action) |
| `0x1000d8ee` / `0x1000d93a` | `Anomaly Detected.  Repairing [` / `OnRegChanged[` | log formats (Registry Protector repair) |
| `0x1000d8b8` / `0x1000d3c0` | `Enable Registry Protector(` / `Fail Enable Folder Protector(` | log formats (protectors) |
| `0x1000d440` / `0x1000d498` | `ClientCrashesAt` / `ClientCrashesSince` | crash-tracking value names |
| `0x1000e19e`–`0x1000e7f4` | full `Se*Privilege` name table (35 entries) | privilege manipulation |
| `0x1000f581` / `0x1000f59a` | `advapi32.dll` / `kernel32.dll` | P/Invoke targets |

No URLs/IPs, no named pipes, no mutex names.

## Evidence

- Ghidra MCP (project `CE`, program `VSWD.dll`): `get_program_options("Program Information")` (27 options), `list_imports` (1), `list_external_locations` (`MSCOREE.DLL!_CorDllMain` @ `0x00010250`), `list_exports` (5), `list_strings` (5) — addresses as tabulated.
- VM command output (2026-09-24): `VSWD.dll | ts=1783516694 | 2026-07-08 13:18:14Z | signer=CN="Covenant Eyes, Inc.", …`
- Local sample `re/samples/00-baseline/VSWD.dll` (scp'd, 127,424 B); UTF-16 strings extracted and VA-mapped via PE section table (2026-09-24).
- Checkpoint: `C:\Users\dolphin\ghidra-ckpt\VSWD.dll.gzf` (493,279 B) + project `CE:/VSWD.dll` (saved).

## Linux-reimplementation notes

This is the implementation behind the VSWD service (see `VSWD.exe.md` for the operational picture). For LustLess: the protectors' repair loop ≈ a config-integrity watcher; `disableFileProtection`/`disableRegistryProtection` exports show CE designed the protections to be administratively switchable — a LustLess equivalent should expose a documented, privileged toggle rather than hidden exports [INFERENCE]. The `Se*` manipulation has no Linux analog needed (capabilities only).
