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

## 3. Kernel component — NONE (pure user-mode)

**Victory Shield 10.1.44 ships no kernel driver.** `CEA.sys`
(`C:\Windows\System32\drivers\`, 108,016 B) was a false lead: it is the stock Microsoft
"Event Aggregation Kernel Mode Library" (`EventAggregation.sys`, 10.0.26100.9444) — SHA256
`c82628cc…a95b9f` byte-identical to the WinSxS `amd64_microsoft-windows-eventaggregation_…`
copy, Microsoft OS-catalog-signed, no SCM service, no INF, no device object. No `*.sys`
exists under `C:\Program Files\CE\` or `C:\ProgramData\CovenantEyes\`; no CE WFP
filters/callouts/providers, no Winsock LSP/NSP, no minifilter. All monitoring/filtering is
**user-mode** — evidence: `findings/01-dynamic-recon/live-surface.md` §a–c.

## 4. Services & processes

| Service | Display name | Start | State | Binary |
|---|---|---|---|---|
| `VictoryShieldCommService` | Victory Shield Communication Service | Auto | Running (PID 5616 at recon) | `c:\Program Files\CE\VictoryShieldCommService.exe` |
| `VSWD` | VSWD | Auto | Running (PID 127048 at recon) | `c:\Program Files\CE\VSWD.exe` |

Persistence is three prongs: (1) both services Auto-start as LocalSystem with SCM recovery
RESTART ×3 @1 s (infinite window); (2) HKLM `Run` value "Victory Shield" → `VictoryShield.exe`;
(3) watchdog loop `[INFERENCE]`: `VSWD.exe`+`VSWD.dll` ("WatchdogServiceLibrary") relaunch via
`RestartVS.exe` / `RestartVSClientOnly.exe`. Anti-tamper: service SDDL grants STOP only to
SYSTEM/Administrators/Power Users (Authenticated users get QUERY/STATUS/START only); install dir
`C:\Program Files\CE` = Everyone DENY delete/delete-child + RX. Uninstall entry:
`WOW6432Node\{5AC5ED2E-2936-4B54-A429-703F9034938E}` = "Victory Shield" (Covenant Eyes, Inc.,
10.1.44, InstallShield `-removeonly`). Zero scheduled tasks; no AppInit/IFEO hooks —
`findings/01-dynamic-recon/live-surface.md` §d.

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
| `ce-file` | **SQLite 3** (WAL, 4096 B pages) | Tables `install_metadata`, `logins`, `metrics`, `circumventions`, `switch_users`, `dns_activity` + sync-outbox pattern (`status`/`status_changed_at`/`created_at`) — full schema: `findings/02-artifacts/local-db.md` |
| `ce-user-file` | encrypted page-aligned container (3×4096 B; 21×4096 B in `PreviousConfiguration`) | Uniform ~7.95 bits/byte entropy, per-file IV/key `[INFERENCE]` — `findings/02-artifacts/user-file.md` |
| `ce_user_event_message_queue` | binary, 2,896 B | Fixed-slot mmap-style queue: superblock + 10 × (8 B length + 256 B payload) — `findings/02-artifacts/event-queue.md` |
| `C:\Program Files\CE\data\*.dat.enc` (6) | **classifier model blobs**, encrypted | `<20hex>-<suffix>.dat.enc`, suffix ∈ {b1,b2,b3,j1,mn,sw} (hex-prefix = content id, suffix = stable role); all sizes %16==0, entropy ≥7.99; loaded via `CovenantEyesClassifier.exe --model=C:\Program Files\CE\data`; b1/b2/b3 share a 9,584-byte identical prefix — `findings/02-artifacts/enc-data.md` |

## 8. Network

| Observation | Evidence |
|---|---|
| Backend `208.185.195.49:443` (HTTPS) | Two sockets from `VictoryShieldCommService` (PID 5616) in `CloseWait` at recon |
| Local IPC listen TCP `127.0.0.1:48867` | PID 5616; service log line "Starting service on 127.0.0.1:48867"; single probe connect/close (20 ms, zero bytes); **zero CE named pipes** of 116 — `findings/03-runtime/process-observation.md` |
| Two TCP backend sockets, local ephemeral ports 55210/55148 → `208.185.195.49:443` | PID 5616 (earlier "UDP-ish" note was a misread of `Get-NetTCPConnection`'s Bound state — they are TCP) — `findings/03-runtime/process-observation.md` |
| Telemetry ingest `api.cvnt.net`, cluster `slc_1b` | `metrics` rows in `ce-file` (`host_name`, `ce_cluster` tags) — `findings/02-artifacts/local-db.md` |
| Per-adapter user-mode DNS proxy on `127.0.0.2` (10.1.1-era logs): "DNS Filter/User server(s)" upstreams `fec0:0:0:ffff::1-3`, 60 s DNS-server-removal enforcement loop | `findings/02-artifacts/logs.md`; 10.1.44 runs here with `DnsProxyDisable=1` (capability present, disabled `[INFERENCE]`) |
| `DnsProxyDisable` flag exists | DNS-proxy capability exists in product (disabled here) |
| No machine root cert found matching Covenant/CEA | `certutil -store root` clean at recon |

## 9. Explicitly absent / negative results

- **No kernel component at all**: no minifilter, no WFP filters/callouts/providers (85 registered callouts all Microsoft), no Winsock LSP/NSP (28 catalog + 10 namespace entries all Microsoft), no driver service (live-surface §a–c).
- **No network config effects**: winhttp direct (no proxy), WinINET `ProxyEnable=0`, hosts stock, zero CE firewall rules among 527, only NRPT rule is Tailscale MagicDNS (live-surface §e).
- **Zero CE certificates** in machine stores root/ca/my/disallowed/authroot (live-surface §f) — the legacy Redirector cert-service is gone.
- Edge extension `jmjflgjpcpepeafmmgdpfkogkghcpiha` = Microsoft "Edge relevant text changes" — **confirmed unrelated** to CE (webstore button-label rewrites only; zero network/storage/CE strings) (live-surface §g).
- Zero scheduled tasks; no AppInit_DLLs/IFEO hooks.
- Legacy 10.1.1 network stack is **removed** by the 10.1.44 upgrade: Winsock NSP `nmNsp.dll` + LSP `nmSvc.dll`/`nmsvTree.dll` ("LSP Index binary" registry values, `WSCUnInstallNameSpace`), IE extension COM classes, and the `CovenantEyesProxy.exe` (Redirector V3.0.0.48) proxy — installer inventory in `findings/02-artifacts/logs.md`.

## 10. Open questions

1. DNS observation mechanism: 10.1.1-era logs prove a per-adapter user-mode DNS proxy (`127.0.0.2`) feeding `dns_activity`; confirm the 10.1.44 code path (proxy disabled here via `DnsProxyDisable=1`) and how `circumventions` window events are captured (SetWinEventHook?) — pin down in StaticRE.
2. How screen capture is performed (which process, which APIs: GDI/DXGI/Desktop Duplication) and how the classifier consumes frames.
3. Local IPC protocol on TCP `127.0.0.1:48867` (no named pipes/ALPC observed at runtime) — message framing unknown; wave B service RE → `findings/13-service-ipc/`.
4. Upload protocol to backend (endpoints, auth, payloads — screenshots vs events).
5. `.dat.enc` model-blob internals: role split (b1/b2/b3/j1/mn/sw) and encrypted container known; keying/derivation and plaintext formats still open. `ce-user-file` container crypto.
6. Watchdog loop internals (VSWD ↔ RestartVS*.exe protocol, self-protection enforcement) — surface known (live-surface §d); mechanism in wave B.
7. What the legacy Redirector/proxy component does in current installs (active or cleanup-only).
