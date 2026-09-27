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
`findings/01-dynamic-recon/live-surface.md` §d. Tamper-repair deep-dive: `findings/14-watchdog/`
(RP: 22 value-protectors over 4 keys via `RegNotifyChangeKeyValue` + 1 s debounced rewrite from
compiled-in constants; FP: install-dir ACL deny-delete + FileSystemWatcher on ACL changes;
relaunch = 1 s session polling + `CreateProcessAsUser` via explorer token; >3 crashes/10 min →
give-up + support dialog).

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
| `ce-user-file` | **SQLCipher-encrypted SQLite** (AES-256-CBC + HMAC-SHA512 page MAC + PBKDF2-HMAC-SHA512) | Hardcoded passphrase `AN0ther$uper$ecretKEY4This` (XOR-obfuscated in-binary, keystream `83 ad c3 4b 1a 47 d6 f8`); `ce-file` is plaintext — `findings/13-service-ipc/service-ipc.md` |
| `ce_user_event_message_queue` | binary, 2,896 B | Fixed-slot mmap-style queue: superblock + 10 × (8 B length + 256 B payload) — `findings/02-artifacts/event-queue.md` |
| `C:\Program Files\CE\data\*.dat.enc` (6) | **classifier model blobs**, encrypted | `<20hex>-<suffix>.dat.enc`, suffix ∈ {b1,b2,b3,j1,mn,sw} (hex-prefix = content id, suffix = stable role); all sizes %16==0, entropy ≥7.99; loaded via `CovenantEyesClassifier.exe --model=C:\Program Files\CE\data`; b1/b2/b3 share a 9,584-byte identical prefix — `findings/02-artifacts/enc-data.md` |

## 8. Network

| Observation | Evidence |
|---|---|
| Backend `api.cvnt.net` = `208.185.195.49:443` (HTTPS) — the product's ONLY remote endpoint | Two parallel persistent TCP connections from `VictoryShieldCommService.exe` (PID 5616); pairs cycle over time (55148/55210 → 55724/55875), each shadowed by a same-port `0.0.0.0` Bound socket (pre-connect bind `[INFERENCE]`); rotation is **activity-driven ~301 s** with a loopback self-pair before each connect — `findings/03-runtime/{network-capture,api-trace}.md` |
| Local IPC listen TCP `127.0.0.1:48867` | PID 5616; service log line "Starting service on 127.0.0.1:48867"; single probe connect/close (20 ms, zero bytes); **zero CE named pipes** of 116 — `findings/03-runtime/process-observation.md` |
| Two TCP backend sockets, local ephemeral ports 55210/55148 → `208.185.195.49:443` | PID 5616 (earlier "UDP-ish" note was a misread of `Get-NetTCPConnection`'s Bound state — they are TCP) — `findings/03-runtime/process-observation.md` |
| Telemetry ingest `api.cvnt.net`, cluster `slc_1b` | `metrics` rows in `ce-file` (`host_name`, `ce_cluster` tags) — `findings/02-artifacts/local-db.md` |
| Per-adapter user-mode DNS proxy on `127.0.0.2` (10.1.1-era logs): "DNS Filter/User server(s)" upstreams `fec0:0:0:ffff::1-3`, 60 s DNS-server-removal enforcement loop | `findings/02-artifacts/logs.md`; 10.1.44 runs here with `DnsProxyDisable=1` (capability present, disabled `[INFERENCE]`) |
| 601 s registry heartbeat (`LastTelemetryUpdateAt`) | **Local bookkeeping only** — tick 18:41:26.766 UTC captured live: zero packets, zero socket events (11m24s capture, 3 pktmon segments, no CE TLS handshake/SNI in any window); **live writer + real upload attributed**: PID 5616, ticks 600.90–600.98 s apart, zero network at tick, and a real telemetry upload at 10:23:34 (TLS + `ApiTelemetryStatus=success`) — `findings/03-runtime/{network-capture,api-trace}.md` |
| Update API `getClientUpdate` (JSON: recommendation now/later/none + critical + download links) | WinSparkle fork's alternate appcast callback; nominal feed `https://covenanteyes.com/files/win/sparkle/appcast-10.1.44-master-4222d5a90.xml`; download host allowlist `covenanteyes.com`/`cvnt.net`; DSA support exists but no key configured (trust = HTTPS+allowlist); silent upgrade = session-0 + critical-only + `DisableSilentUpgrade` 1-day re-enable — `findings/16-updater/updater.md` |
| Backend REST `/v2/user/{username}.json`, `/v2/user/{u}/filter/settings/dns.json` | `CeUserSettings` services flags + DNS-filter resolver config (CleanBrowsing DoH default) — `findings/12-network/filter-surface.md` |
| Backend REST catalog (7 routes incl. `/v1/status/{time,ping}`, `/v1/logs/store`, `/v1/telemetry/store`, `/v1/metrics`, `/v2/user/{u}/report/activity_log.json`) | HTTP Basic (`api_credentials` key/secret), libcurl, no cert pinning; activity records only — **no images ever** — `findings/16-updater/upload-protocol.md` |
| `DnsProxyDisable` flag exists | DNS-proxy capability exists in product (disabled here) |
| No machine root cert found matching Covenant/CEA | `certutil -store root` clean at recon |

## 9. Explicitly absent / negative results

- **No kernel component at all**: no minifilter, no WFP filters/callouts/providers (85 registered callouts all Microsoft), no Winsock LSP/NSP (28 catalog + 10 namespace entries all Microsoft), no driver service (live-surface §a–c).
- **No network config effects**: winhttp direct (no proxy), WinINET `ProxyEnable=0`, hosts stock, zero CE firewall rules among 527, only NRPT rule is Tailscale MagicDNS (live-surface §e).
- **Zero CE certificates** in machine stores root/ca/my/disallowed/authroot (live-surface §f) — the legacy Redirector cert-service is gone.
- Edge extension `jmjflgjpcpepeafmmgdpfkogkghcpiha` = Microsoft "Edge relevant text changes" — **confirmed unrelated** to CE (webstore button-label rewrites only; zero network/storage/CE strings) (live-surface §g).
- Zero scheduled tasks; no AppInit_DLLs/IFEO hooks.
- Browser extension integration is **REMOVED** in 10.1.44: Firefox extension + Chrome force-install (`bfegkegffcbgpfmemahhkgnbkocmbain`) exist only as uninstall cleanup in `vs-config` (`VsDestroyer.cpp`); the active browser surface is **DoH lockdown policy** (Edge/Chrome/Brave `DnsOverHttpsMode=off`, Brave `TorDisabled=1`, Firefox `DNSOverHTTPS Locked=1`) — `findings/12-network/browser-integration.md`.
- Legacy 10.1.1 network stack is **removed** by the 10.1.44 upgrade: Winsock NSP `nmNsp.dll` + LSP `nmSvc.dll`/`nmsvTree.dll` ("LSP Index binary" registry values, `WSCUnInstallNameSpace`), IE extension COM classes, and the `CovenantEyesProxy.exe` (Redirector V3.0.0.48) proxy — installer inventory in `findings/02-artifacts/logs.md`.
- Filter guardian dialog is **dead UI** in 10.1.44 (resource #215 ships, nothing constructs it; message map 0x401–0x428 fully enumerated) — `findings/12-network/filter-surface.md`.

## 10. Open questions

1. DNS/URL filtering — ANSWERED IN FULL: settings flow `/v2/user/{u}.json` → `CeUserSettings` → `user_info` → `CE_SPYMapObj`; resolver config `/v2/user/{u}/filter/settings/dns.json` (UI writes; service consumes) → `user_dns_filter` in SQLCipher `ce-user-file` (default `https://dns.cleanbrowsing.org/doh/adult-filter`); enforcement = **the DnsProxy family** (`DnsProxyRequest::processDnsRequest`, 15-code `resolution_type`): custom override → `blocked.cvnt.net` synthetic answer, global override → BlockedGlobal, CleanBrowsing RPZ (`cleanbrowsing.rpz.noc.org`) → BlockedFilter; DoH via custom Boost.Beast RFC-8484 client (not curl); attribution via `GetExtendedUdpTable` PID lookup → `dns_activity`; `has_url_filtering` is DNS-level only (nothing URL-specific); `DnsProxyDisable=1` is a sticky-ON gate (naming inverted), activated only while ≥1 signed-in filtering user (`checkForProxySwitch`) — `findings/12-network/filter-enforcement.md`.
2. Screen capture: **DXGI Desktop Duplication** in `VictoryShield.exe` (`Win32DxgiCapture`; all monitors, stitched + per-monitor, HDR tone-map; DX9 fallback). Scheduler: periodic PdlEdi task, interval from backend `/v1/member/sensor/config/pdlEdi` (jittered, fallbacks 5/40/60 s), gated on display/session/classifier-alive. **Handoff: file transactions** `Classifier\<SID>\data\pdl\<ts>\{im<N>.dat (PNG), ss.dat (JSON manifest schema 3.0.0), rr.dat ready-marker}` + `PdlNotifyARE` event; reverse messages `cs/ht/pp/dd/re4*` classifier→client. Restrictions = `GetWindowDisplayAffinity`/`DwmGetWindowAttribute` (OS window state): circumvention logged, window captured with `doNotScore:true`. `circumventions` producer FOUND (`findings/12-network/filter-surface.md`). Classifier-internal consumption/models → `findings/10-classifier/` (capture side: `capture-pipeline.md`).
3. IPC: **Boost.Interprocess message queues** — `ce_user_event_message_queue` (UI→service: 1 code byte + payload; handlers: 0x43 COLLECT_DEBUG_LOGS → `vs-config --collect-debug`, 0x4c USER_LOGOUT → proxy-switch check, 0x4d SEND_METRICS → flush, 0x51 QUIT (session-guarded), 0x52 SET_WINDOWS_REGISTRY, 0x53 USER_SETTINGS_CHANGE → settings-cache rebuild, 0x54 SEND_TELEMETRY, 0x55 = empty-poll sentinel) + `ce_service_event_message_queue` (10×512 B; code 2 = NOTIFICATION text) back-channel; legacy `CE_SPYMapObj` shared memory + window messages 0x401–0x407/0x428. TCP `127.0.0.1:48867` = cpp-netlib server with 10 routes (`/`, `/about`, `/antivirus`, `/settings/user/:id:`, `/settings/dns/:id:`, `/logs/`, `/internal/status/:u:`, `/internal/command/{requeue,test-api-connectivity}`, `/local/user/:u:/keys.:doctype:`, `/static/:res:`) — **no authentication: any local process can read the API keys** — `findings/13-service-ipc/service-ipc.md`.
4. Upload protocol — ANSWERED: 7 REST routes on `api.cvnt.net` (`/v1/status/time`, `/v1/status/ping`, `/v1/desktop_client_update`, `/v1/logs/store`, `/v1/telemetry/store`, `/v1/metrics`, `/v2/user/{u}/report/activity_log.json`), HTTP Basic with per-user key/secret (`api_credentials` SQLite table), libcurl + OpenSSL/schannel, **no cert pinning**; outbox `queued`→`sending`→`sent` (batch 100, stale requeue, server throttle in `ApiTelemetryResumeTime`); **comm service uploads NO image/screenshot bytes ever** — 5 activity record types + counter metrics only; 601 s heartbeat = `Impl::updateTelemetryData` (local-only), hourly `ServerTimeManager::sync` = `/v1/status/time` — `findings/16-updater/upload-protocol.md`. Classifier-side HTTP (bundle fetch/upload) → classifier pass.
5. `.dat.enc` model-blob internals: role split (b1/b2/b3/j1/mn/sw) and encrypted container known; keying/derivation and plaintext formats still open (classifier pass). `ce-user-file` — ANSWERED: SQLCipher SQLite, hardcoded passphrase (`findings/13-service-ipc/service-ipc.md`; structural evidence `findings/02-artifacts/user-file.md`).
6. Watchdog loop internals — DONE: 1 s session polling, explorer-token `CreateProcessAsUser` relaunch, crash counters + 10-min suppress window, >3 restarts → give-up/support dialog, SCM cmds 243/176 (`findings/14-watchdog/`).
7. Legacy Redirector/proxy — ANSWERED: cleanup-only (`CovenantEyesProxy.exe /UnregServer` from installer temp dirs; cert deletion fails; component removed in 10.1.44) — `findings/02-artifacts/logs.md` + `findings/16-updater/updater.md`.
