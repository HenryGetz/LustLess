# VictoryShield.exe — baseline

## What it does

The **Victory Shield user-mode client** (tray application / "filter guardian"): sign-in/sign-out UI for the Victory Shield service, settings ("preferences"), upgrade flow (WinSparkle auto-updater), monitoring status, support-diagnostics/support-code dialogs, and installer flow. Talks to the sibling services, launches processes in user sessions, watches session changes (`WTSRegisterSessionNotification`), does real networking (Winsock) and certificate handling (CryptoAPI/CERT32 incl. PFX import), renders via Direct3D/D2D, and ships crash reporting (BugSplat `MiniDmpSender`). Strings show web-access gating ("Logout of the Victory Shield service -- disables web access"), a "filter" surface ("Filter guardian", "technical issues with the filter"), and third-party AV conflict handling (Trend Micro TDI disable + reboot notice).

## Mechanism

### Metadata

| Field | Value | Source |
|---|---|---|
| Source path | `C:\Program Files\CE\VictoryShield.exe` (12,571,584 bytes) | VM file |
| Language | `x86:LE:64:default` (x86-64, machine `0x8664`), Compiler `visualstudio:unknown` — native C++ (MFC + D2D/DWrite + icu), RTTI present | Ghidra `get_program_options`; PE header |
| Image base | `0x140000000` | Ghidra `list_open_programs` |
| PE TimeDateStamp | `1783517730` → 2026-07-08 13:35:30 UTC | PE header `e_lfanew+8` |
| Authenticode signer | `CN="Covenant Eyes, Inc.", O="Covenant Eyes, Inc.", L=Owosso, S=…` | `Get-AuthenticodeSignature` |
| MD5 / SHA256 | `2043e00926796432e13e16726965e155` / `6f0d8b9badaa35351c7fc61a9340da5563ef3c8db5fcee83da17855ccf3aa62c` | Ghidra `get_program_options` |
| PDB | `VictoryShield.pdb`, RSDS GUID `598ceacf-cd0e-48af-96d5-be30b4f14887`, age 1 | Ghidra `get_program_options` |
| Version info | CompanyName `Covenant Eyes`; FileDescription/ProductName `Victory Shield`; FileVersion `10.1.44`; OriginalFilename `VictoryShield.exe` | Ghidra `get_program_options` |

### Imports grouped by DLL

951 imports across 72 DLLs (PE import table of `re/samples/00-baseline/VictoryShield.exe`, parsed per DLL). Highlights:

| DLL | # | Notable APIs |
|---|---|---|
| **USER32.dll** | 241 | MFC/tray UI |
| **KERNEL32.dll** | 170 | `CreateProcessA` (IAT `0x140b157c8`), `TerminateProcess` (`0x140b15770`), `SuspendThread`/`ResumeThread`/`TerminateThread`, `CreateToolhelp32Snapshot` + `Process32*/Thread32*`, `OpenProcess`, `ProcessIdToSessionId`, `WTSGetActiveConsoleSessionId`, file APIs (`ReplaceFileA`, `MoveFileA`, `LockFile`, `SetFileTime`…) |
| **GDI32.dll** | 116 | drawing |
| **ADVAPI32.dll** | 80 | **Service control**: `OpenSCManagerW` (IAT `0x140b14d40`), `DeleteService` (`0x140b14d58`), `ControlService` (`0x140b14d68`), `StartServiceW` (`0x140b14d70`), `ChangeServiceConfigW/2W`, `QueryServiceConfigA`, `SetServiceObjectSecurity`, SDDL (`ConvertStringSecurityDescriptorToSecurityDescriptorW`). **Registry**: `RegLoadKeyW` (`0x140b14d10`)/`RegUnLoadKeyW` (`0x140b14cf8`), `RegDeleteTreeW`, `RegNotifyChangeKeyValue` (`0x140b14e98`). **CryptoAPI**: `CryptAcquireContextW` (`0x140b14f70`), `CryptSignHashW` (`0x140b14ee0`), `CryptDecrypt` (`0x140b14ee8`), `CryptExportKey` (`0x140b14ef0`), `CryptCreateHash` (`0x140b14f58`), `CryptGenRandom` (`0x140b14f10`). **Event log**: `ReportEventW` (`0x140b14f18`), `RegisterEventSourceW` (`0x140b14f20`). **Tokens**: `OpenProcessToken`, `OpenThreadToken`, `GetTokenInformation`, `LookupPrivilegeValueA`, `AdjustTokenPrivileges` |
| **WS2_32.dll** | 43 | **Winsock**: `getaddrinfo` (IAT `0x140b16440`), `freeaddrinfo`, `inet_pton` (`0x140b163b8`)/`inet_ntop`, `WSAEventSelect`, `WSAEnumNetworkEvents`, `WSAIoctl`, `WSAWaitForMultipleEvents` (+ many by-ordinal) |
| **ole32.dll** / **gdiplus.dll** | 23 / 22 | COM/OLE, GDI+ |
| **CRYPT32.dll** | 19 | **Certificates**: `CertOpenSystemStoreW` (IAT `0x140b14fd8`), `CertGetCertificateChain` (`0x140b14fd0`), `CryptQueryObject` (`0x140b14fe8`), **`PFXImportCertStore` (`0x140b15010`)**, `CertAddCertificateContextToStore`, `CertFindCertificateInStore`, `CryptDecodeObjectEx`, `CryptStringToBinaryW` |
| **OLEAUT32.dll** | 17 | OLE automation |
| **WinSparkle.dll** | 10 | **auto-updater**: `win_sparkle_init` (IAT `0x140b16528`), `win_sparkle_set_appcast_url` (`0x140b16500`), `win_sparkle_set_registry_path` (`0x140b16518`), `win_sparkle_check_update_with_ui` (`0x140b16538`), `win_sparkle_set_update_check_interval`, `win_sparkle_set_last_check_time`, `win_sparkle_set_alternate_appcast_callback` |
| **WTSAPI32.dll** | 7 | `WTSRegisterSessionNotification` (IAT `0x140b164b8`), `WTSUnRegisterSessionNotification`, `WTSQueryUserToken` (`0x140b164c0`), `WTSQuerySessionInformationA/W`, `WTSEnumerateSessionsA`, `WTSFreeMemory` |
| **BugSplat64.dll** | 4 | **crash reporting**: `MiniDmpSender` ctor/dtor, `sendAdditionalFile`, `setCallback` |
| **RstrtMgr.DLL** | 4 | Restart Manager (`RmStartSession`/`RmRegisterResources`/`RmGetList`/`RmEndSession`) |
| **bcrypt.dll** | 1 | `BCryptGenRandom` (IAT `0x140b16b18`) |
| **IPHLPAPI.DLL** | 1 | `GetAdaptersInfo` (IAT `0x140b15410`) |
| **d3d11.dll / d3d9.dll / dxgi.dll** | 1/1/1 | `D3D11CreateDevice` (`0x140b16b28`), `Direct3DCreate9` (`0x140b16b38`), `CreateDXGIFactory1` (`0x140b16b68`) — GPU/DXGI init ([INFERENCE] UI rendering or overlay) |
| **PSAPI.DLL** | 1 | `GetModuleBaseNameA` |
| api-ms-win-* sets (40+ DLLs) | ~120 | UCRT/API-set plumbing |
| SHELL32 (13), UxTheme (12), SHLWAPI (7), WINSPOOL (4), OLEACC (3), IMM32 (3), dwmapi (3), MSIMG32 (2), WINMM (1) | | shell/UI support |

Category scan: **networking — yes (Winsock)**; **crypto — yes (CryptoAPI + CRYPT32 cert chains + bcrypt)**; **process launch/termination — yes**; **service control — yes (SCM)**; session monitoring — yes; GDI/D3D rendering — yes (UI, not screenshot capture); browser APIs — none native (web access is gated server-side per strings).

### Exports (Ghidra `list_exports`)

| Export | Address |
|---|---|
| `entry` | `0x1404a86f0` |
| `tls_callback_0` | `0x1404a83a0` |
| `tls_callback_1` | `0x1404d92a0` |
| `tls_callback_2` | `0x1404a8270` |

### Representative strings (with addresses)

UTF-16 strings VA-mapped from `re/samples/00-baseline/VictoryShield.exe` (1,212 total; selected):

| Address | String | Category |
|---|---|---|
| `0x140a49c60` | `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CovenantEyesCommService` | registry key (LEGACY service name) |
| `0x140a49d00` | `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VictoryShieldCommService` | registry key (service) |
| `0x140a49da0` / `0x140a49e20` | `…\Services\CEWD` / `…\Services\VSWD` | registry keys (legacy / current watchdog) |
| `0x140a49b00` / `0x140a49a40` | `…\Windows\CurrentVersion\Run` / `…\Explorer\StartupApproved\Run` | registry keys (autostart) |
| `0x140a4868e` | `VictoryShieldFirstRunDone` | first-run state value name |
| `0x140a488d8` | `ServiceCrashes` | crash-counter value name |
| `0x140a3bb90` / `0x140a3bba8` / `0x140a3bc10` | `CommService`, `CrashesAt`, `CrashesSince` | state value names |
| `0x140a48268` / `0x140a48280` / `0x140a483c0` | `DnsFromDhcp`, `DnsAddresses`, `ProxyAddress` | network config value names |
| `0x140a48620` / `0x140a48728` | `DisableSilentUpgrade`, `DnsProxyDisable` | settings value names |
| `0x140c03f5e` / `0x140c03ff4` | `Filter guardian - Victory Shield` / `Victory Shield is currently experiencing technical issues with the filter. ` | **web-filter UI surface** |
| `0x140c0847e` | `Configure the Victory Shield service#Login to the Victory Shield service;Logout of the Victory Shield service -- disables web access` | tray menu — **web-access gating** |
| `0x140c0433c` | `Trend Micro's TDI driver has been disabled because it conflicts with Victory Shield.  Your computer will reboot in 30 seconds.` | **third-party AV conflict handling** |
| `0x140c03ab6` / `0x140c03bfe` | `Upgrade - Victory Shield` / `Upgrade status - Victory Shield` | updater UI |
| `0x140c044b6` / `0x140c04a9e` | `Support diagnostics - Victory Shield` / `Support code - Victory Shield` | support UI |
| `0x140c08188` | `Administrative Mode%Sign in to the Victory Shield service&Sign out of the Victory Shield service&Change your Victory Shield preferences About Victory Shield for Windows` | tray menu definition |
| `0x140c03a28` | `(c) Covenant Eyes, 2000 - 2025` | about box |
| `0x1409bbf50` | `Intel Hardware Cryptographic Service Provider` | CryptoAPI provider name |
| `0x1408d8fd8` | `CovenantEyes` | namespace/mutex-family prefix |
| `0x140a42540` | `root\CIMv2` | WMI namespace |

## Evidence

- Ghidra MCP (project `CE`, program `VictoryShield.exe`): `get_program_options("Program Information")` (26 options), `list_exports` (4) — addresses as tabulated. (Fn count in INDEX.md.)
- Local sample `re/samples/00-baseline/VictoryShield.exe` (scp'd, 12,571,584 B): PE import table parsed per DLL (951 imports / 72 DLLs) with IAT addresses; UTF-16 strings (1,212) VA-mapped via the PE section table.
- VM command output (2026-09-24): `VictoryShield.exe | ts=1783517730 | 2026-07-08 13:35:30Z | signer=CN="Covenant Eyes, Inc.", …`

## Linux-reimplementation notes

This is the "face + policy enforcement" of the client: tray UI, auth, updates, and web-access gating. LustLess mapping: a small status/tray (or headless) daemon + config; "Login/Logout disables web access" ≈ toggling a filtering proxy/dns policy [INFERENCE: the actual filtering is a separate surface — the strings mention "filter guardian" and DNS proxy settings]. WinSparkle ≈ distro package updates; BugSplat ≈ coredump+report pipeline; cert/PFX handling ≈ TLS pinning material management. The Trend Micro TDI conflict string shows CE actively disabling competing kernel drivers — LustLess must never do this [INFERENCE: aggressive conflict resolution is out of scope for an ethical client].
