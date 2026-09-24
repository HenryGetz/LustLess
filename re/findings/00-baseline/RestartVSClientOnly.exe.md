# RestartVSClientOnly.exe — baseline

## What it does

**"Restart Victory Shield Client Only"** — restarts only the user-mode CE client processes (e.g. `VictoryShield.exe` in each session), *without* touching the CE Windows services (unlike `RestartVS.exe`, it imports **no SCM service APIs**). Enumerates sessions (`WTSEnumerateSessionsA`), acquires user-session tokens (`WTSQueryUserToken`), enumerates processes and their modules (`CreateToolhelp32Snapshot`, `PSAPI!EnumProcessModules`/`GetModuleFileNameExW`), terminates and relaunches (`TerminateProcess`, `CreateProcessA`). Includes a user-facing "restart loop" message with **Covenant Eyes support contacts** (phone/email/help forum) when several restarts are detected.

## Mechanism

### Metadata

| Field | Value | Source |
|---|---|---|
| Source path | `C:\Program Files\CE\RestartVSClientOnly.exe` (3,974,080 bytes) | VM file |
| Language | `x86:LE:64:default` (x86-64, machine `0x8664`), Compiler `visualstudio:unknown` — native C++ (MFC + Boost + jsoncpp), RTTI present | Ghidra `get_program_options`; PE header |
| Image base | `0x140000000` | Ghidra `list_open_programs` |
| PE TimeDateStamp | `1783517385` → 2026-07-08 13:29:45 UTC | PE header `e_lfanew+8` |
| Authenticode signer | `CN="Covenant Eyes, Inc.", O="Covenant Eyes, Inc.", L=Owosso, S=…` | `Get-AuthenticodeSignature` |
| MD5 / SHA256 | `c8f73492154ce9492c7c015a5bdcc899` / `97673012273482451b060e28b006ef659bd1056c713b4fa5d77e8b9659d78919` | Ghidra `get_program_options` |
| PDB | `RestartVSClientOnly.pdb`, RSDS GUID `30bcfe5b-4c8d-4ea0-a626-561351f24100`, age 1 | Ghidra `get_program_options` |
| Version info | CompanyName `Covenant Eyes`; FileDescription `Restart Victory Shield Client Only`; ProductName `Victory Shield`; FileVersion `10.1.44` | Ghidra `get_program_options` |

### Imports grouped by DLL

662 imports across 19 DLLs (PE import table of `re/samples/00-baseline/RestartVSClientOnly.exe`, parsed per DLL).

| DLL | # | Notable APIs |
|---|---|---|
| **USER32.dll** | 220 | MFC windowing |
| **KERNEL32.dll** | 201 | `CreateProcessA` (IAT `0x140376d18`), `TerminateProcess` (`0x140376cd8`), `OpenProcess` (`0x140376cf0`), `CreateToolhelp32Snapshot` (`0x140376cf8`) + `Process32First/Next`, `ProcessIdToSessionId` (`0x140376c20`), `WTSGetActiveConsoleSessionId` (`0x140376d10`), `CreateThread`, `ResumeThread`, `SetEnvironmentVariableW` |
| **GDI32.dll** | 97 | MFC drawing |
| **ADVAPI32.dll** | 38 | Registry + identity only (**no service-control APIs**): **`RegLoadKeyW` (IAT `0x1403764a8`) / `RegUnLoadKeyW` (`0x1403764a0`)**, `RegDeleteTreeW` (`0x140376490`), `RegNotifyChangeKeyValue` (`0x140376460`), `RegCreateKeyExW`, `RegEnumKeyExW`/`RegEnumValueW`, `RegSetValueExW`, `RegFlushKey`; `OpenProcessToken`, `GetTokenInformation`, `LookupPrivilegeValueA`, `AdjustTokenPrivileges`, `GetUserNameW`, `LookupAccountSidW`, `ConvertSidToStringSidW`, `GetSecurityInfo`/`SetSecurityInfo`, `SetEntriesInAclA` |
| **gdiplus.dll** / **ole32.dll** | 22 / 22 | GDI+, COM/OLE (WMI) |
| **UxTheme.dll** / **OLEAUT32.dll** | 12 / 12 | styles / OLE automation |
| **SHELL32.dll** | 10 | `ShellExecuteW`, `SHGetSpecialFolderLocation`, `SHGetPathFromIDListW` |
| **SHLWAPI.dll** | 7 | path helpers (`StrFormatKBSizeW`) |
| **WTSAPI32.dll** | 4 | `WTSEnumerateSessionsA` (IAT `0x1403777a8`), `WTSFreeMemory` (`0x1403777b0`), **`WTSQueryUserToken` (`0x1403777b8`)**, `WTSQuerySessionInformationW` (`0x1403777c0`) |
| **PSAPI.DLL** | 2 | **`EnumProcessModules` (IAT `0x140376f50`), `GetModuleFileNameExW` (`0x140376f58`)** — module-level process inspection (identifies loaded CE modules before restart) |
| **WS2_32.dll** | 2 | sockets by ordinal (`#115`, `#116`) |
| OLEACC / IMM32 / WINSPOOL / MSIMG32 / WINMM / SHFOLDER | 3/3/3/2/1/1 | MFC support |

Category scan: process enumeration/termination — yes; user-token acquisition — yes; **service control — none** (the defining difference vs `RestartVS.exe`); registry hive load/unload — yes; no crypto, no screenshot capture, no browser APIs.

### Exports (Ghidra `list_exports`)

| Export | Address |
|---|---|
| `entry` | `0x14021b560` |
| `tls_callback_0` | `0x14021b700` |
| `tls_callback_1` | `0x14023f320` |

### Representative strings (with addresses)

UTF-16 strings VA-mapped from `re/samples/00-baseline/RestartVSClientOnly.exe`:

| Address | String | Category |
|---|---|---|
| `0x14031e240` | `We've detected several restarts.` | user-facing restart-loop message |
| `0x14031e284` | `Let us help you resolve this problem!` | support message |
| `0x14031e2d2` | `Contact Member Care:` | support message |
| `0x14031e2fc` | `+1 989.720.8000` | **support phone** |
| `0x14031e31c` | `info@covenanteyes.com` | **support email** |
| `0x14031e348` | `helpforum.covenanteyes.com` | **support URL** |
| `0x140322c40` | `root\CIMv2` | WMI namespace |
| `0x140322c58` / `0x140322cb8` | `win32_computersystem` / `win32_processor` | WMI inventory classes |
| `0x140324158` / `0x1403241b0` / `0x140324200` | `DnsAddresses`, `DnsFromDhcp`, `ProxyAddress` | network config value names |
| `0x14031e5c0`–`0x14031e670` | `CrashesSince`, `Client`, `CommService`, `CrashesAt` | state/crash value names |
| `0x140326d28` / `0x140326e28` | `SELECT * FROM ` / `get WMI property: ` | WMI query/log formats |
| `0x140327100` | `D:\actions-runner\_work\w\p\x64\snowball\dataFormats\json\jsoncpp\jsoncpp.cpp` | build path — CE internal `snowball` library (JSON) |
| `0x1402e8cb0` | `SOFTWARE\` | registry root fragment |
| `0x1403c27a4` | `Restart Victory Shield Client Only` | version-resource description |

No named pipes, no mutex names; `helpforum.covenanteyes.com` above is the only URL-like string.

## Evidence

- Ghidra MCP (project `CE`, program `RestartVSClientOnly.exe`): `get_program_options("Program Information")` (26 options), `list_exports` (3) — addresses as tabulated. (Fn count in INDEX.md.)
- Local sample `re/samples/00-baseline/RestartVSClientOnly.exe` (scp'd, 3,974,080 B): PE import table parsed per DLL (662 imports / 19 DLLs) with IAT addresses; UTF-16 strings VA-mapped via the PE section table.
- VM command output (2026-09-24): `RestartVSClientOnly.exe | ts=1783517385 | 2026-07-08 13:29:45Z | signer=CN="Covenant Eyes, Inc.", …`

## Linux-reimplementation notes

Session-scoped client restart only — no service management. LustLess analog: `systemctl --user restart lustless-agent` per session. The "several restarts" detection + support-contact dialog is UX for crash loops; a Linux client could log + notify instead [INFERENCE: the message implies CE counts client restarts (crash counters `CrashesAt`/`CrashesSince`) and escalates to user support after a threshold].
