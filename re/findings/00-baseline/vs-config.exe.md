# vs-config.exe — baseline

## What it does

The **Victory Shield configuration / diagnostics tool** — a native C++ MFC GUI (ribbon, Office-2007-style framework toolbars) that manages the CE installation: creates/starts/stops/deletes the CE Windows services via the full SCM API, reads and writes CE settings in the registry (including hive load/unload), queries WMI (`root\CIMv2` inventory + `root\SecurityCenter2` AV/antispyware/firewall state), inspects DNS/proxy configuration, and manages upgrade flags. CLI switches `--interactive` and `-lvs-config.log` (logging). Also knows the **legacy service names** (`CEWD`, `CovenantEyesCommService`) alongside current ones (`VSWD`, `VictoryShieldCommService`).

> **Browser-integration surface (previously unobserved):** the string block at `0x14038d8f0`–`0x14038e10e` contains `--interactive`, `-lvs-config.log`, then **`firefox-integrated-extension@covenanteyes.com`** (`0x14038ddb0`) followed by `update_url` (`0x14038e10e`) — evidence that CE manages a **Firefox WebExtension** (extension ID + update-URL plumbing, [INFERENCE] likely Firefox enterprise policy/ExtensionSettings or an extension manifest fragment). Live recon found the Edge profile clean; Firefox may be a legacy or uninstalled path on this VM.

## Mechanism

### Metadata

| Field | Value | Source |
|---|---|---|
| Source path | `C:\Program Files\CE\vs-config.exe` (4,554,176 bytes) | VM file |
| Language | `x86:LE:64:default` (x86-64, machine `0x8664`), Compiler `visualstudio:unknown` — native C++ (MFC + Boost.Log + jsoncpp), RTTI present | Ghidra `get_program_options`; PE header |
| Image base | `0x140000000` | Ghidra `list_open_programs` |
| Functions | 13,287 (post-analysis) | Ghidra `analysis_status` |
| PE TimeDateStamp | `1783516996` → 2026-07-08 13:23:16 UTC | PE header `e_lfanew+8` |
| Authenticode signer | `CN="Covenant Eyes, Inc.", O="Covenant Eyes, Inc.", L=Owosso, S=…` | `Get-AuthenticodeSignature` |
| MD5 / SHA256 | `d374b7ad9e03f45de2398dbb1c16a878` / `bd9186c70d4a0c0f20e0551b9bb41bb3f270885db07a38bcfc28ca7aa2c3c12d` | Ghidra `get_program_options` |
| PDB | `vs-config.pdb`, RSDS GUID `7bde8641-70c8-46f6-b734-3ba58050bcae`, age 1 | Ghidra `get_program_options` |
| Version info | CompanyName `Covenant Eyes`; FileDescription `VS Config`; ProductName `Victory Shield`; FileVersion `10.1.44` | Ghidra `get_program_options` |
| Toolchain traces | Boost headers under `D:\actions-runner\_work\w\p\x64\.icebox\boost\sysroot\x64-microsoft-windows\…` (GitHub Actions build), `CommonLibrary\inc\CeMemory.h`, jsoncpp `snowball\dataFormats\json\jsoncpp` | strings (see below) |

### Imports grouped by DLL

720 imports across 21 DLLs (PE import table of `re/samples/00-baseline/vs-config.exe`, parsed per DLL; Ghidra `list_external_locations` cross-checks IAT addresses, e.g. SHLWAPI `PathStripToRootA` @ IAT `0x003fb46a`).

| DLL | # | Notable APIs |
|---|---|---|
| **KERNEL32.dll** | 234 | `CreateProcessA/W`, `TerminateProcess`, `TerminateThread`, `OpenProcess`, `CreateToolhelp32Snapshot` + `Process32First/Next` + `Thread32First/Next` (process/thread enumeration), `ProcessIdToSessionId`, `QueueUserAPC`, `GetQueuedCompletionStatus`/`PostQueuedCompletionStatus`, `DuplicateHandle`, `ExpandEnvironmentStringsA`, `SetEnvironmentVariableW` |
| **USER32.dll** | 226 | MFC windowing incl. `SetWindowsHookExA`, `CallNextHookEx`, `CreateWindowExA`, `MessageBoxA`, `WinHelpA` |
| **GDI32.dll** | 97 | MFC drawing |
| **ADVAPI32.dll** | 53 | **Registry**: `RegCreateKeyExW`, `RegDeleteTreeW` (IAT `0x1403f9d58`), **`RegLoadKeyW` (IAT `0x1403f9d70`) / `RegUnLoadKeyW` (IAT `0x1403f9d68`)** — registry *hive file* load/unload (offline hive manipulation), `RegNotifyChangeKeyValue` (IAT `0x1403f9d30`, change watching), `RegQueryInfoKeyW`, `RegEnumKeyExW`/`RegEnumValueW`, `RegSetValueExW`, `RegFlushKey`. **Service control (full SCM)**: `CreateServiceW` (IAT `0x1403f9dd8`), `DeleteService` (`0x1403f9e08`), `ChangeServiceConfigW` (`0x1403f9e28`)/`ChangeServiceConfig2W` (`0x1403f9e00`), `ControlService` (`0x1403f9e18`), `StartServiceW` (`0x1403f9e20`), `OpenSCManagerW` (`0x1403f9df0`), `OpenServiceW`, `QueryServiceConfigA`, `QueryServiceStatus(Ex)`, `SetServiceObjectSecurity`, `ConvertStringSecurityDescriptorToSecurityDescriptorW` (SDDL, `0x1403f9e38`). **Tokens/identity**: `OpenProcessToken`, `GetTokenInformation`, `LookupPrivilegeValueA`, `AdjustTokenPrivileges`, `GetUserNameW`, `LookupAccountSidW`, `LookupAccountNameW`, `ConvertSidToStringSidW` |
| **gdiplus.dll** | 22 | GDI+ (UI imagery) |
| **ole32.dll** | 22 | COM/OLE (MFC + WMI access) |
| **OLEAUT32.dll** | 13 | OLE automation (by ordinal) — WMI property marshaling |
| **UxTheme.dll** | 12 | visual styles |
| **SHELL32.dll** | 10 | `SHGetSpecialFolderPathW`, `SHGetSpecialFolderLocation`, `ShellExecuteA` |
| **SHLWAPI.dll** | 6 | `PathStripToRootA`, `PathFindFileNameA`, `PathRemoveFileSpecW`, `StrFormatKBSizeA` |
| **RstrtMgr.DLL** | 4 | **Restart Manager**: `RmStartSession`, `RmRegisterResources`, `RmGetList`, `RmEndSession` (find processes holding files / coordinate restarts) |
| **WTSAPI32.dll** | 3 | **Terminal Services**: `WTSEnumerateSessionsA`, `WTSQuerySessionInformationW`, `WTSFreeMemory` |
| **WS2_32.dll** | 2 | sockets (imported by ordinal `#115`, `#116`) |
| **NETAPI32.dll** | 2 | `NetUserEnum`, `NetApiBufferFree` (local user enumeration) |
| **USERENV.dll** | 1 | `GetProfilesDirectoryW` |
| WINSPOOL.DRV / OLEACC.dll / IMM32.dll / MSIMG32.dll / WINMM.dll / SHFOLDER.dll | 3/3/3/2/1/1 | printing, accessibility (matches `acc*` property strings), IME, alpha blend, multimedia, folders |

Category scan: **service control — yes (complete SCM surface)**; **process enumeration/termination — yes** (Toolhelp + `TerminateProcess` + `OpenProcess`); session enumeration — yes; registry hive load/unload — yes; networking — minimal (2 ordinal winsock imports); **no crypto APIs** in the native import table; no screenshot/GDI capture (GDI/GDI+ here is UI); no browser APIs (the Firefox extension ID below is a configuration target, not an API).

### Exports (Ghidra `list_exports`)

| Export | Address |
|---|---|
| `entry` | `0x14023f880` |
| `tls_callback_0` | `0x14027f8c0` |
| `tls_callback_1` | `0x1402dffe0` |

### Representative strings (with addresses)

Ghidra-defined strings + UTF-16 extraction from `re/samples/00-baseline/vs-config.exe` (VAs mapped via PE section table):

| Address | String | Category |
|---|---|---|
| `0x14038ddb0` | **`firefox-integrated-extension@covenanteyes.com`** | **Firefox WebExtension ID** (browser integration) |
| `0x14038e10e` | `update_url` | extension update-manifest fragment (adjacent to the extension ID) |
| `0x14038d8f0` / `0x14038d910` | `--interactive` / `-lvs-config.log` | CLI switches (same string block as the extension ID) |
| `0x14038c84e` | `troot\SecurityCenter2` (partial) | **WMI namespace `root\SecurityCenter2`** (AV/AS/FW enumeration) |
| `0x140398030` | `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VSWD` | registry key (service) |
| `0x1403980b0` | `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CEWD` | registry key (LEGACY service name) |
| `0x1403982f0` | `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VictoryShieldCommService` | registry key (service) |
| `0x140398390` | `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CovenantEyesCommService` | registry key (LEGACY service name) |
| `0x140398130` | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` | registry key (autostart) |
| `0x1403981c0` | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run` | registry key (autostart) |
| `0x14038c84e` | `troot\SecurityCenter2` (partial) | WMI namespace |
| `0x14038c880`–`0x14038c8f0` | `AntiVirusProduct`, `AntiSpywareProduct`, `FirewallProduct` | WMI security-center classes |
| `0x140393bc8` / `0x140393b98` / `0x140393c20` | `root\CIMv2` / `win32_computersystem` / `win32_processor` | WMI inventory |
| `0x140394978` | `EnableDebugLogging` | settings value name |
| `0x1403949e8` | `AllowSecureSearch` | settings value name |
| `0x140394a48` | `DnsProxyDisable` | settings value name |
| `0x140394a68` / `0x140394ab6` | `DisableSilentUpgrade` / `SilentUpgradeDisabledAt` | settings value names |
| `0x140394ae8` | `DisabledComponents` | settings value name |
| `0x140394750` / `0x140394768` / `0x140394848` | `DnsFromDhcp` / `DnsAddresses` / `ProxyAddress` | network config value names |
| `0x14038c338`–`0x14038c3a8` | `Client`, `CrashesSince`, `CrashesAt`, `CommService` | crash/state value names |
| `0x14038fcde` | `D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)…` | SDDL security descriptor |
| `0x14038fa58` / `0x14038fa78` | `ProgramFilesDir` / `C:\Progra~1` | path logic |
| `0x140399f66` / `0x14039a060` | `SELECT * FROM ` / `get WMI property: ` | WMI query/log formats |
| `0x14038e6fe` | `D:\actions-runner\_work\w\p\x64\.icebox\boost\sysroot\…\boost\smart_ptr\shared_ptr.hpp` | build path (Boost) |

No URLs/IPs, no named pipes, no mutex names found in the string set.

## Evidence

- Ghidra MCP (project `CE`, program `vs-config.exe`): `analysis_status` (analyzed, 13,287 functions), `get_program_options("Program Information")` (27 options), `list_external_locations` (200-row page sampled: SHLWAPI/USER32 with IAT addresses), `list_exports` (3).
- Local sample `re/samples/00-baseline/vs-config.exe` (scp'd, 4,554,176 B): PE import table parsed per DLL (720 imports / 21 DLLs — groupings and names as tabulated) and UTF-16 strings VA-mapped via the PE section table.
- VM command output (2026-09-24): `vs-config.exe | ts=1783516996 | 2026-07-08 13:23:16Z | signer=CN="Covenant Eyes, Inc.", …`
- Checkpoint: `C:\Users\dolphin\ghidra-ckpt\vs-config.exe.gzf` (24,827,796 B) + project `CE:/vs-config.exe` (saved). Note: analysis completed on the second attempt; the first attempt died with the JVM (see INDEX.md Infra notes).

## Linux-reimplementation notes

This is a management plane, not runtime enforcement: service lifecycle (SCM) ≈ systemd unit management; settings registry ≈ a config file (`/etc/lustless/config`); WMI SecurityCenter queries have no Linux analog [INFERENCE: used to detect competing security software / report environment]; Restart Manager ≈ `lsof`-style lock-holder lookup before upgrades; `NetUserEnum` ≈ `getpwent` (account list for multi-user config). LustLess likely needs only a CLI/daemon config surface — the full MFC GUI has no porting value.
