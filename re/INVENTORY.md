# INVENTORY — Covenant Eyes "Victory Shield" v10.1.44 (Windows)

Observed surface of the installed Covenant Eyes client on the research VM
(`DESKTOP-6LK4SCA`, Windows 10/11-class, admin user `dolphin`). Compiled from live
enumeration 2026-09-24. All claims are backed by the cited enumeration output; role
labels are `[INFERENCE]` until RE passes confirm them.

## 1. Product identification

| Field | Value |
|---|---|
| Marketing/internal product | **Victory Shield** (Covenant Eyes) — the modern CE Windows client |
| Version | 10.1.44 (FileVersion `10.1.44` on all first-party binaries) |
| Install mode | `upgrade` (`HKLM\SOFTWARE\Covenant Eyes\Victory Shield\InstallMode`) — upgraded over legacy "WindowsClient" v10.1.1 (data dirs for both remain) |
| Older classifier identity | logs show `C:\Program Files\CE\CovenantEyesClassifier.exe --version=10.1.1...` (v10.1.1 era) |
| Install dir | `C:\Program Files\CE\` |
| Runtime data | `C:\ProgramData\CovenantEyes\` |

## 2. First-party binaries (`C:\Program Files\CE\`)

| File | Size (B) | Role `[INFERENCE]` | RE status |
|---|---|---|---|
| `VictoryShieldClassifier.exe` | 52,962,752 | Screen-activity capture + ML classification ("Screen Accountability") | pending |
| `VictoryShieldCommService.exe` | 24,101,824 | Windows service: comms, telemetry upload, local IPC endpoint | pending |
| `VictoryShield.exe` | 12,571,584 | Main client UI (XAML Islands + WebView2) | pending |
| `vs-config.exe` | 4,554,176 | Config/diagnostic CLI | pending |
| `RestartVSClientOnly.exe` | 3,974,080 | Restart helper (client only) | pending |
| `RestartVS.exe` | 3,731,392 | Restart helper (full stack) | pending |
| `UWPApp.dll` | 482,240 | XAML/UWP UI logic | pending |
| `ProcessPrivileges.dll` | 34,240 | Privilege manipulation helper (v1.5.7.0, "Process Privileges") | pending |
| `VSWD.dll` | 127,424 | Watchdog service library ("WatchdogServiceLibrary") | pending |
| `VSWD.exe` | 108,992 | Watchdog service host | pending |
| `App.xbf` / `SignInControl.xbf` | 548 / 15,534 | Compiled XAML UI (sign-in control) | pending |

Hashes: `re/samples/MANIFEST.sha256` (generated after pull). Third-party/redist (not RE
targets): VC/MFC 14.x runtime DLLs, `Microsoft.Toolkit.Win32.UI.XamlHost.dll`,
`Microsoft.Web.WebView2.Core.dll`, `WinSparkle.dll` 0.7.7 (updater), `BugSplat64.dll` +
`BugSplatRc64.dll` + `BsSndRpt64.exe` (crash reporting), `zip.exe` 3.0 (Info-ZIP),
`ICON1.ICO`, `license.txt`.

## 3. Kernel component

| File | Size (B) | Notes |
|---|---|---|
| `C:\Windows\System32\drivers\CEA.sys` | 108,016 | Present on disk. **Not** a minifilter (`fltmc filters` shows none CE-related). Service registration/state, WFP-callout status, and IOCTL surface TBD (LiveDynamicRecon) |

## 4. Services & processes

| Service | Display name | Start | State | Binary |
|---|---|---|---|---|
| `VictoryShieldCommService` | Victory Shield Communication Service | Auto | Running (PID 5616 at recon) | `c:\Program Files\CE\VictoryShieldCommService.exe` |
| `VSWD` | VSWD | Auto | Running (PID 127048 at recon) | `c:\Program Files\CE\VSWD.exe` |

No other first-party services matched. Kernel driver service key for `CEA.sys` not yet
located (mild anomaly — resolved by LiveDynamicRecon).

## 5. Registry (`HKLM\SOFTWARE\Covenant Eyes\Victory Shield`)

| Value | Type | Meaning `[INFERENCE]` |
|---|---|---|
| `InstallMode` | SZ `upgrade` | Upgraded from legacy WindowsClient |
| `DnsProxyDisable` | BIN `01000000` | DNS-proxy feature disabled (feature flag) |
| `FirstRunDone` | BIN `01000000` | First-run completed |
| `LastTelemetryUpdateAt` / `LastTelemetryUploadAt` | SZ ISO timestamps | Telemetry poll/upload cadence evidence |
| `ApiTelemetryStatus` / `ApiTelemetryResumeTime` | SZ | API telemetry state machine |
| `NetworkStatus\{GUID}` | keys | Per-adapter tracking: `Description`, `IfName`, `IfType`, `ConnType` (e.g. `ethernet`, `other_vpn` for Tailscale), `IpSupport` (`v4v6`), `OpStatus`, `LastActivatedTime` — network-change watcher |

## 6. Filesystem (`C:\ProgramData\CovenantEyes\`)

| Path | Contents |
|---|---|
| `VictoryShieldv010.001.044\` | Current-version state: `ce-file` (SQLite DB, 835,584 B), `ce-user-file` (12,288 B), `ce_user_event_message_queue` (2,896 B), `logs\comm-service\major-<pid>.log` |
| `WindowsClientv010.001.001\` | Legacy version logs (`comm-service\major-3600.log`, 574,940 B) |
| `PreviousConfiguration\ce-user-file` | Prior per-user state (86,016 B) |
| `Classifier\logs\<pid>.txt` | Classifier process logs (14 files) |
| `Classifier\<SID>\cache\bmdat\nxu.dat`, `cache\ssdat\`, `data\client\<epoch>\ht.dat` + `re4sHXT*`, `data\pdl\<ISO-ts>*` | Per-user classifier caches/data (formats TBD) |
| `WindowsClientInstaller\logs\` | `fresh-install-4260.log`, `instnsp-5648.log`, `instnsp-8740.log` (suggests Winsock NSP install step) |
| `VictoryShieldInstaller\logs\upgrade-126428.log` | Upgrade log |
| `ThirdParty\logs\proxy\CovenantEyesProxy.log` | Log of legacy "Redirector V3.0.0.48 (Licensed to: Covenant Eyes)" — cert/service/COM cleanup component run from installer Temp GUID dirs |

## 7. Data stores

| Store | Format | Notes |
|---|---|---|
| `ce-file` | **SQLite 3** | Tables include `dns_activity` (id, username, domain, process_id, status, …), `circumventions` (id, username, interruption_type, …) — local activity/event DB |
| `ce-user-file` | binary/encrypted-looking (high entropy) | Per-user account state `[INFERENCE]` |
| `ce_user_event_message_queue` | binary, 2,896 B | Event queue `[INFERENCE]` |
| `C:\Program Files\CE\data\*.dat.enc` (6) | encrypted blobs | `805b3533c9a731909930-b3` / `83b568cc34e776439494-b1` / `d8b85cbaabaf6c1e7b15-b2` (2,323,104 B each), `a076283f3318c8ea4de0-sw` (901,200 B), `cea3215e9378de852a41-j1` (187,248 B), `f160caa8342747d04d8f-mn` (1,248 B). Suffix tokens `-b1/-b2/-b3/-j1/-mn/-sw` TBD |

## 8. Network

| Observation | Evidence |
|---|---|
| Backend `208.185.195.49:443` (HTTPS) | Two sockets from `VictoryShieldCommService` (PID 5616) in `CloseWait` at recon |
| Local IPC listen `127.0.0.1:48867` | PID 5616 — client↔service endpoint `[INFERENCE]` |
| UDP-ish bound `0.0.0.0:55210`, `0.0.0.0:55148` | PID 5616, dynamic ports |
| `DnsProxyDisable` flag exists | DNS-proxy capability exists in product (disabled here) |
| No machine root cert found matching Covenant/CEA | `certutil -store root` clean at recon |

## 9. Explicitly absent / negative results

- No CE minifilter (`fltmc filters` — system filters only).
- No CE Winsock LSP/NSP in catalog at recon time (legacy `instnsp` installer step implies one existed in older builds).
- Edge extension `jmjflgjpcpepeafmmgdpfkogkghcpiha` ("Edge relevant text changes" v1.2.1, update_url = Edge store) — almost certainly a Microsoft Store extension, **not** CE; final verdict in `findings/01-dynamic-recon/live-surface.md`.
- No CE entries in scheduled tasks at recon filter.

## 10. Open questions

1. What exactly is `CEA.sys` (WFP callout? NDIS? DNS proxy hook?) and its IOCTL interface.
2. How screen capture is performed (which process, which APIs: GDI/DXGI/Desktop Duplication) and how the classifier consumes frames.
3. Local IPC protocol on `127.0.0.1:48867` (+ any named pipes/ALPC).
4. Upload protocol to backend (endpoints, auth, payloads — screenshots vs events).
5. `.dat.enc` format and keying; `ce-user-file` container format.
6. Anti-tamper posture: service DACLs, watchdog loop, uninstall protection.
7. What the legacy Redirector/proxy component does in current installs (active or cleanup-only).
