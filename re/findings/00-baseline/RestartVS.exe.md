# RestartVS.exe — baseline

## What it does

**"Restart Victory Shield"** — the full restart utility for the CE client stack: stops/starts the CE Windows services (full SCM surface including `CreateServiceW`/`DeleteService`/`ChangeServiceConfigW`), enumerates processes (`CreateToolhelp32Snapshot`), finds lock-holders via the **Restart Manager** (`RmStartSession`/`RmRegisterResources`/`RmGetList`/`RmEndSession`), obtains user-session tokens (`WTSQueryUserToken`) and relaunches CE processes (`CreateProcessA`, `WTSGetActiveConsoleSessionId`), and manipulates the CE registry keys (including hive `RegLoadKeyW`/`RegUnLoadKeyW`). Same CommonLibrary/Boost stack and registry-key set as `vs-config.exe`, including the **legacy service names** (`CEWD`, `CovenantEyesCommService`).

## Mechanism

### Metadata

| Field | Value | Source |
|---|---|---|
| Source path | `C:\Program Files\CE\RestartVS.exe` (3,731,392 bytes) | VM file |
| Language | `x86:LE:64:default` (x86-64, machine `0x8664`), Compiler `visualstudio:unknown` — native C++ (MFC + Boost), RTTI present | Ghidra `get_program_options`; PE header |
| Image base | `0x140000000` | Ghidra `list_open_programs` |
| PE TimeDateStamp | `1783517353` → 2026-07-08 13:29:13 UTC | PE header `e_lfanew+8` |
| Authenticode signer | `CN="Covenant Eyes, Inc.", O="Covenant Eyes, Inc.", L=Owosso, S=…` | `Get-AuthenticodeSignature` |
| MD5 / SHA256 | `b4f1b21d41ea61e5582c024128cff5cc` / `2eb92ba37ab87d65d9158321173a75b5009cf82c5cf14e30c3c973d60da899c7` | Ghidra `get_program_options` |
| PDB | `RestartVS.pdb`, RSDS GUID `7315a0f3-ee77-49a7-8c3a-f38171ef8e65`, age 1 | Ghidra `get_program_options` |
| Version info | CompanyName `Covenant Eyes`; FileDescription `Restart Victory Shield`; ProductName `Victory Shield`; FileVersion `10.1.44`; InternalName/OriginalFilename `RestartVS.exe` | Ghidra `get_program_options` |

### Imports grouped by DLL

688 imports across 18 DLLs (PE import table of `re/samples/00-baseline/RestartVS.exe`, parsed per DLL).

| DLL | # | Notable APIs |
|---|---|---|
| **USER32.dll** | 226 | MFC windowing (`SetWindowsHookExA`, `CreateWindowExA`, `MessageBoxA`…) |
| **KERNEL32.dll** | 206 | `CreateProcessA` (IAT `0x14034e3b8`), `TerminateProcess` (`0x14034e3d8`), `OpenProcess` (`0x14034e3e0`), `CreateToolhelp32Snapshot` (`0x14034e3e8`) + `Process32First/Next`, `ProcessIdToSessionId` (`0x14034e3f0`), `WTSGetActiveConsoleSessionId` (`0x14034e400`), `CreateThread`, `ResumeThread`, `SetThreadPriority`, `SetEnvironmentVariableW` |
| **GDI32.dll** | 97 | MFC drawing |
| **ADVAPI32.dll** | 56 | **Service control**: `OpenSCManagerW` (`0x14034da70`), `OpenServiceW`, `StartServiceW` (`0x14034da40`), `ControlService` (`0x14034da48`), `DeleteService` (`0x14034da58`), `ChangeServiceConfigW` (`0x14034da38`)/`ChangeServiceConfig2W` (`0x14034da60`), `QueryServiceConfigA`, `QueryServiceStatus(Ex)`, `SetServiceObjectSecurity`, SDDL `ConvertStringSecurityDescriptorToSecurityDescriptorW` (`0x14034da28`). **Registry**: `RegDeleteTreeW` (`0x14034d970`), **`RegLoadKeyW` (`0x14034db18`) / `RegUnLoadKeyW` (`0x14034db10`)**, `RegNotifyChangeKeyValue` (`0x14034dad0`), `RegCreateKeyExA/W`, `RegSetValueExA`, `RegQueryValueExA/W`. **Tokens/ACL**: `OpenProcessToken`, `GetTokenInformation`, `LookupPrivilegeValueA`, `GetSecurityInfo`/`SetSecurityInfo`, `SetEntriesInAclA`, `SetSecurityDescriptorDacl/Sacl` |
| **gdiplus.dll** | 22 | GDI+ |
| **ole32.dll** | 20 / OLEAUT32 13 | COM/OLE |
| **UxTheme.dll** | 12 | visual styles |
| **SHELL32.dll** | 10 | `ShellExecuteA`, `SHGetFolderPathW`, `SHGetPathFromIDListA` |
| **SHLWAPI.dll** | 7 | path helpers |
| **RstrtMgr.DLL** | 4 | **Restart Manager**: `RmStartSession` (IAT `0x14034e588`), `RmEndSession` (`0x14034e590`), `RmGetList` (`0x14034e598`), `RmRegisterResources` (`0x14034e5a0`) |
| **WTSAPI32.dll** | 1 | **`WTSQueryUserToken`** (IAT `0x14034ee10`) — obtain a user-session token (service→user-process launch) |
| **WS2_32.dll** | 2 | sockets by ordinal (`#115`, `#116`) |
| WINSPOOL.DRV / OLEACC / IMM32 / MSIMG32 / WINMM | 3/3/3/2/1 | MFC support |

Category scan: **service control — yes**; **process enumeration/termination — yes**; **user-token acquisition — yes** (`WTSQueryUserToken` + `OpenProcessToken` + `LookupPrivilegeValueA`); registry hive load/unload — yes; no crypto APIs; no screenshot/GDI capture; no browser APIs.

### Exports (Ghidra `list_exports`)

| Export | Address |
|---|---|
| `entry` | `0x140212e50` |
| `tls_callback_0` | `0x140213250` |
| `tls_callback_1` | `0x140225bb0` |

### Representative strings (with addresses)

UTF-16 strings VA-mapped from `re/samples/00-baseline/RestartVS.exe`:

| Address | String | Category |
|---|---|---|
| `0x1402fe060` | `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VSWD` | registry key (service) |
| `0x1402fe0e0` | `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CEWD` | registry key (LEGACY service name) |
| `0x1402fe160` | `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VictoryShieldCommService` | registry key (service) |
| `0x1402fe200` | `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CovenantEyesCommService` | registry key (LEGACY service name) |
| `0x1402fdf10` | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` | registry key (autostart) |
| `0x1402fdfa0` | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run` | registry key (autostart) |
| `0x1402fbf48` / `0x1402fbf58` / `0x1402fbf98` / `0x1402fbed0` | `Client`, `CommService`, `CrashesAt`, `CrashesSince` | state/crash value names |
| `0x1403024e0` / `0x140302538` / `0x140302588` | `DnsAddresses`, `DnsFromDhcp`, `ProxyAddress` | network config value names |
| `0x1403041d8` | `root\CIMv2` | WMI namespace |
| `0x1403977a4` | `Restart Victory Shield` | version-resource description |
| `0x140397824` | `RestartVS.exe` | version resource |

No URLs/IPs, no named pipes, no mutex names in the string set.

## Evidence

- Ghidra MCP (project `CE`, program `RestartVS.exe`): `get_program_options("Program Information")` (26 options), `list_exports` (3) — addresses as tabulated. (`analysis_status`/fn count recorded in INDEX.md.)
- Local sample `re/samples/00-baseline/RestartVS.exe` (scp'd, 3,731,392 B): PE import table parsed per DLL (688 imports / 18 DLLs) with IAT addresses; UTF-16 strings VA-mapped via the PE section table.
- VM command output (2026-09-24): `RestartVS.exe | ts=1783517353 | 2026-07-08 13:29:13Z | signer=CN="Covenant Eyes, Inc.", …`

## Linux-reimplementation notes

A "restart everything cleanly" utility: systemd equivalent is `systemctl restart lustless*` plus a session-aware relaunch helper (loginctl sessions → spawn per-session agent) [INFERENCE]. `WTSQueryUserToken` ≈ launching user processes via systemd user units rather than token duplication. Restart Manager lock-holder lookup ≈ checking `lsof`/`fuser` before upgrading binaries. The legacy service-name strings suggest CE ships migration logic from older versions — a LustLess installer should handle its own upgrade path explicitly.
