# VictoryShieldCommService.exe — baseline

## What it does

The **Victory Shield communication service** — a true Windows service (`StartServiceCtrlDispatcherW` / `RegisterServiceCtrlHandlerExW` / `SetServiceStatus`) described in CE's own service registration as "Communicates between Victory Shield processes and servers." (see `VSWD.exe.md`). It is the network backend: full Winsock client/server (TCP+UDP, `AcceptEx`), **DHCP/DNS configuration monitoring** (`dhcpcsvc!DhcpRequestParams`/`DhcpRegisterParamChange`, `IPHLPAPI` route/interface change notifiers + UDP table), TLS/certificate-chain validation (`CertVerifyCertificateChainPolicy`), CryptoAPI signing/decryption, auto-update checks (WinSparkle), crash reporting (BugSplat), session inspection (WTS), and process module inspection (PSAPI). Writes Event Log entries and knows a `ForceCrashCommService` debug value name.

## Mechanism

### Metadata

| Field | Value | Source |
|---|---|---|
| Source path | `C:\Program Files\CE\VictoryShieldCommService.exe` (24,101,824 bytes) | VM file |
| Language | `x86:LE:64:default` (x86-64, machine `0x8664`), Compiler `visualstudio:unknown` — native C++ | PE header |
| Image base | `0x140000000` | PE header |
| PE TimeDateStamp | `1783517812` → 2026-07-08 13:36:52 UTC | PE header `e_lfanew+8` |
| Authenticode signer | `CN="Covenant Eyes, Inc.", O="Covenant Eyes, Inc.", L=Owosso, S=…` | `Get-AuthenticodeSignature` |
| MD5 / SHA256 | `40ae5b657fedda5aab0c74d2e107d510` / `5a4345390c12fe58c55da0cd619307451c9abe2a0b03a452b15be69624c0eb84` | local hash of `re/samples/00-baseline/VictoryShieldCommService.exe` |
| PDB | `VictoryShieldCommService.pdb`, RSDS GUID `2ffa272a-0d13-4d8f-a55d-4caab41db06a`, age 1 (build path `D:\actions-runner\_work\w\p\x64\main\dist\x64\Release\…`) | PE debug directory |
| Version info | CompanyName `Covenant Eyes`; FileDescription `Victory Shield Comm Service` (`0x1416f62e4`); ProductName `Victory Shield`; FileVersion `10.1.44` | strings / version resource |

### Imports grouped by DLL

423 imports across 17 DLLs (PE import table of the local sample, parsed per DLL).

| DLL | # | Notable APIs |
|---|---|---|
| **KERNEL32.dll** | 228 | `CreateProcessA` (IAT `0x140a7a288`), `TerminateProcess` (`0x140a7a308`), `CreateToolhelp32Snapshot` + `Process32*`, `OpenProcess`, `ProcessIdToSessionId`, `WTSGetActiveConsoleSessionId`, file APIs (`CreateFileW`, `MoveFileExW`, `MapViewOfFile`…), threadpool (`CreateThreadpoolWork`/`SubmitThreadpoolWork`) |
| **ADVAPI32.dll** | 73 | **Service host**: `StartServiceCtrlDispatcherW` (IAT `0x140a79f78`), `RegisterServiceCtrlHandlerExW` (`0x140a79f88`), `SetServiceStatus` (`0x140a79f80`). **Service management**: `CreateServiceW` (`0x140a79fb8`), `DeleteService` (`0x140a79f70`), `StartServiceW` (`0x140a79f58`), `ControlService` (`0x140a79f60`), `OpenSCManagerW` (`0x140a79fa0`), `ChangeServiceConfigW/2W`, `QueryServiceConfigA`, `SetServiceObjectSecurity`, SDDL. **CryptoAPI**: `CryptAcquireContextW` (`0x140a79ee0`), `CryptSignHashW` (`0x140a79fe8`), `CryptDecrypt` (`0x140a79ff0`), `CryptExportKey` (`0x140a79ff8`), `CryptCreateHash` (`0x140a7a058`), `CryptGenRandom` (`0x140a79fd8`). **Event log**: `ReportEventW` (`0x140a7a018`), `RegisterEventSourceW` (`0x140a7a020`). **Registry**: `RegLoadKeyW` (`0x140a7a0c0`)/`RegUnLoadKeyW` (`0x140a7a0b8`), `RegDeleteTreeW`, `RegNotifyChangeKeyValue` (`0x140a7a078`). **Tokens/ACL**: `GetTokenInformation`, `LookupAccountNameW`, `GetSecurityInfo`/`SetSecurityInfo`, `SetEntriesInAclA` |
| **WS2_32.dll** | 52 | **Winsock full stack**: `WSASocketW` (IAT `0x140a7ab50`), `WSASend`/`WSARecv` (`0x140a7ab90`/`0x140a7ab20`), `WSASendTo`/`WSARecvFrom` (UDP, `0x140a7aa40`/`0x140a7aa30`), `getaddrinfo` (`0x140a7ab48`), `inet_pton` (`0x140a7aa88`), `WSAAddressToStringW`/`WSAStringToAddressW`, `WSAEventSelect`/`WSAEnumNetworkEvents`, `WSAIoctl` |
| **CRYPT32.dll** | 21 | **Certificates/TLS**: `CertOpenSystemStoreW` (IAT `0x140a7a1c0`), `CertGetCertificateChain` (`0x140a7a1a0`), **`CertVerifyCertificateChainPolicy` (`0x140a7a1d0`)**, `PFXImportCertStore` (`0x140a7a158`), `CryptQueryObject` (`0x140a7a188`), `CertAddEncodedCertificateToStore`, `CertGetNameStringW`, `CryptDecodeObjectEx` |
| **WinSparkle.dll** | 8 | auto-updater: `win_sparkle_init` (IAT `0x140a7ac18`), `win_sparkle_set_appcast_url` (`0x140a7abe8`), `win_sparkle_set_registry_path` (`0x140a7ac20`), update-check config |
| **IPHLPAPI.DLL** | 6 | **network monitoring**: `GetAdaptersAddresses` (IAT `0x140a7a210`), `GetAdaptersInfo` (`0x140a7a218`), `GetExtendedUdpTable` (`0x140a7a220`), `NotifyIpInterfaceChange` (`0x140a7a208`), `NotifyRouteChange2` (`0x140a7a228`), `CancelMibChangeNotify2` |
| **dhcpcsvc.DLL** | 5 | **DHCP config**: `DhcpCApiInitialize` (IAT `0x140a7ac58`), `DhcpRequestParams` (`0x140a7ac50`), `DhcpRegisterParamChange` (`0x140a7ac48`), `DhcpDeRegisterParamChange`, `DhcpCApiCleanup` |
| **MSWSOCK.dll** | 2 | **`AcceptEx` (IAT `0x140a7a968`), `GetAcceptExSockaddrs` (`0x140a7a970`)** — scalable TCP accept |
| **ole32.dll / OLEAUT32.dll** | 5 / 3 | COM |
| **BugSplat64.dll** | 4 | `MiniDmpSender` crash reporting |
| **RstrtMgr.DLL** | 4 | Restart Manager |
| **WTSAPI32.dll** | 4 | `WTSEnumerateSessionsA`, `WTSQueryUserToken` (IAT `0x140a7abc8`), `WTSQuerySessionInformationW`, `WTSFreeMemory` |
| **PSAPI.DLL** | 2 | `EnumProcessModules`, `GetModuleBaseNameA` |
| **bcrypt.dll** | 1 | `BCryptGenRandom` (IAT `0x140a7ac30`) |
| **SHFOLDER.dll** | 1 | `SHGetFolderPathW` |

Category scan: **networking — yes (the network core)**; **crypto — yes (CryptoAPI + CRYPT32 chain policy + bcrypt)**; **service control/hosting — yes**; **DHCP/DNS config — yes**; process launch/inspection — yes; no screenshot/GDI capture; no browser APIs.

### Exports

None — the PE has no export table (service binary).

### Representative strings (with addresses)

UTF-16 strings VA-mapped from `re/samples/00-baseline/VictoryShieldCommService.exe` (1,304 total; selected):

| Address | String | Category |
|---|---|---|
| `0x14099cd78` | `ForceCrashCommService` | **debug/kill-switch value name** |
| `0x140996ed0` | `CovenantEyesCommService` | legacy service name string |
| `0x1409a5390` | `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VictoryShieldCommService` | registry key (own service) |
| `0x1409a5640` | `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CovenantEyesCommService` | registry key (LEGACY service name) |
| `0x1409a5430` / `0x1409a54b0` | `…\Services\CEWD` / `…\Services\VSWD` | registry keys (legacy / watchdog) |
| `0x1409a52e0` / `0x1409a5530` | `…\Windows\CurrentVersion\Run` / `…\Explorer\StartupApproved\Run` | registry keys (autostart) |
| `0x1409c5966` | `root\SecurityCenter2` | WMI namespace (AV/FW enumeration) |
| `0x1409a4fe8` / `0x1409a5020` | `root\CIMv2` / `Model` | WMI inventory |
| `0x14099c6a8` / `0x14099c700` / `0x14099c750` | `DnsAddresses`, `DnsFromDhcp`, `ProxyAddress` | network config value names |
| `0x14099d0f0` / `0x14099d188` | `DnsProxyDisable`, `DisableSilentUpgrade` | settings value names |
| `0x140997528` / `0x1409974a8` / `0x140997500` / `0x14099d3e0` | `CommService`, `CrashesSince`, `CrashesAt`, `ServiceCrashes` | state/crash value names |
| `0x14099d278` | `DependOnService` | service config value name |
| `0x1408c80a0` | `Intel Hardware Cryptographic Service Provider` | CryptoAPI provider name |
| `0x1408a8e10` | `Service-0x` | log-format fragment |
| `0x1416f62e4` | `Victory Shield Comm Service` | version-resource description |

No URLs/IPs, named pipes, or mutex names in the string set.

## Evidence

- Ghidra MCP (project `CE`, program `VictoryShieldCommService.exe`): imported and auto-analyzed (fn count in INDEX.md).
- Local sample `re/samples/00-baseline/VictoryShieldCommService.exe` (scp'd, 24,101,824 B): PE import table parsed per DLL (423 imports / 17 DLLs) with IAT addresses; UTF-16 strings (1,304) VA-mapped; MD5/SHA256 and RSDS PDB record read from the PE (hashes/identity as tabulated).
- VM command output (2026-09-24): `VictoryShieldCommService.exe | ts=1783517812 | 2026-07-08 13:36:52Z | signer=CN="Covenant Eyes, Inc.", …`

## Linux-reimplementation notes

This maps to the LustLess **network daemon**: HTTPS client to the accountability server (their endpoint host is documented in the dynamic-recon findings), plus local IPC to the client UI. Linux equivalents: `res_init`/netlink route+addr notifications instead of IPHLPAPI change notifiers; DHCP option reads via `udhcpc` hooks or `systemd-networkd` D-Bus instead of `dhcpcsvc`; TLS via OpenSSL/rustls with pinned CA (the CRYPT32 chain-policy call is their TLS trust path [INFERENCE]); `SO_REUSEPORT` accept loops instead of `AcceptEx`. `ForceCrashCommService` is a self-test trigger — a LustLess analog should be an explicit, logged debug switch.
