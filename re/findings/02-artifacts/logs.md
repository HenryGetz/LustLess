# Logs — comm-service, installers, and legacy proxy

## What it does

Eight log files survive under `C:\ProgramData\CovenantEyes\`, covering three component families:

1. **Comm service** (`VictoryShieldCommService` / formerly `CovenantEyesCommService`) —
   `logs\comm-service\major-<PID>.log` per service process. Documents the local IPC endpoint,
   the DNS-proxy enforcement loop, server-time sync cadence, and the WinSparkle auto-update check
   that drove the 10.1.1 → 10.1.44 upgrade.
2. **Installers** (`fresh-install-4260.log`, `upgrade-126428.log`, `instnsp-*.log`) — verbose
   `TRAC`/`INFO`/`ERRR` traces of the InstallShield-style custom DLL (`CCEInstallApp` /
   `CISCustomDLLApp`). These give a complete component inventory: services, binaries, registry
   values, browser integration, NSP/LSP handling, hosts-file and DoH management, classifier
   model/user data.
3. **Legacy third-party proxy** (`ThirdParty\logs\proxy\CovenantEyesProxy.log`) — the bundled
   "Redirector V3.0.0.48 (Licensed to: Covenant Eyes)" component, run only to unregister itself
   (cert/service/COM/registry cleanup) during both installs.

All copies in `re/samples/data/logs/`:

| VM path | file | size | lines | sha256 |
|---|---|---|---|---|
| `VictoryShieldv010.001.044\logs\comm-service\` | `major-5616.log` | 9,318 | 100 | `3aae7a0c4116cda10e17cc174f6f3272ae0167ae32a6eb5308f8ffb4ccdbbe8f` |
| `VictoryShieldv010.001.044\logs\comm-service\` | `major-5688.log` | 523 | 5 | `7c3f4ac12b8d880a970fef21294d6e1f77d34edb6f5267f856023cd8063e8bee` |
| `WindowsClientv010.001.001\logs\comm-service\` | `major-3600.log` | 574,940 | 4,738 | `fa7764b1c107303ce2f88b8cfc4c6d374bc6135f894071b6ee3a2b377baa5800` |
| `WindowsClientInstaller\logs\` | `fresh-install-4260.log` | 55,973 | 601 | `eb448ce523afc0d7551e077c3415c5da57f303bb91beed796392f2d7bb766a48` |
| `WindowsClientInstaller\logs\` | `instnsp-5648.log` | 387 | 4 | `e644e98ecd2137c5f8114f6acf7340fdf94db8dfffe1012909f63d5a6dd98c7e` |
| `WindowsClientInstaller\logs\` | `instnsp-8740.log` | 387 | 4 | `df676434777ab2eedd83c6afc1d2657a61f125c6c349827fe9fc74a923a5428c` |
| `VictoryShieldInstaller\logs\` | `upgrade-126428.log` | 136,142 | 1,349 | `551a273f26388d5e1e3e8021e4356098ca6cfbfbbba4a4455ef586330f0aba1e` |
| `ThirdParty\logs\proxy\` | `CovenantEyesProxy.log` | 2,456 | 36 | `769157a87df60c9247673ae47c3a4cb2a91246cd810a2abf78d7960d967dab7f` |

(`instnsp-8740.log` content is dated 2025-11-10 → the fresh install; `instnsp-5648.log` content is
dated 2026-09-21 → the upgrade. Sizes confirmed on VM via `dir` 2026-09-24.)

## Mechanism

### Comm-service logs (`major-*.log`)

Line format (all three files):

```
SEV|MM-DD HH:MM:SS.ffffff|0x<thread-id>|<tag>|<message>
```

- Severities seen: `CRIT`, `TRAC`, `INFO`, `ERRR`. In `major-3600.log` the census is
  CRIT 4,729 / TRAC 9 — `CRIT` is used as the default level even for routine lines (e.g. hourly
  sync successes) [INFERENCE: with "Detailed logging … disabled" (a real toggle, see
  `setAdvancedDetailedLoggingEnabled` lines) only the always-on level is written, and that level is
  labelled CRIT].
- Tag = function/scope name (C++): `main`, `run::<lambda_1>::operator ()`, `ServerTimeManager::sync`,
  `winsparkle::genericAppcastUpdate`, `UserEventMessageQueueListener::operator ()`,
  `LocalCommServiceAgent::serviceControlHandler`, `DNS Proxy Monitor adapters`,
  `DnsProxyRequest::handleDnsTimeout`, `enforceDNSSettingsPeriodically for IPV4/IPV6`, …
- File per service process (`major-<PID>.log`); the UI client used the same scheme under
  `logs\ce\` (old names `major-5764/7632/7820/8008.log` seen being deleted by the upgrade).

#### Messages

Internal event-queue messages received by `UserEventMessageQueueListener` (complete set in
`major-3600.log`; sender is another CE component [INFERENCE]):

```
TRAC|09-18 16:09:50.762459|0x000013f8|UserEventMessageQueueListener::operator ()|Received event message: QUIT with data IgnoreMe
TRAC|09-18 16:10:52.522445|0x000013f8|UserEventMessageQueueListener::operator ()|Received event message: USER_SETTINGS_CHANGE with data kckt0717
TRAC|09-19 00:32:10.152244|0x000013f8|UserEventMessageQueueListener::operator ()|Received event message: USER_LOGOUT with data LogoutEvent
```

Census: `QUIT/IgnoreMe` ×4, `USER_SETTINGS_CHANGE/kckt0717` ×2, `USER_LOGOUT/LogoutEvent` ×1.
`kckt0717` is not a random token: the upgrade log deletes the legacy user settings key
`USERS:S-1-5-21-2224134039-3417563983-3831536026-1001\SOFTWARE\Covenant Eyes\kckt0717`
(`upgrade-126428.log:1151`), so the message names the settings key whose values changed
[INFERENCE: `kckt…` = obfuscated user-settings key name].

Session changes arrive via the service control handler:

```
CRIT|09-18 16:10:29.365442|0x00000e14|`anonymous-namespace'::LocalCommServiceAgent::serviceControlHandler|Session change event: WTS_SESSION_LOGON for session ID: 1
```

(`WTS_SESSION_LOCK` ×7, `WTS_SESSION_UNLOCK` ×6 in the census.)

Before an upgrade, the installer sends window messages to the running UI to flush pending work
(`upgrade-126428.log:103-110`):

```
TRAC|09-21 00:21:56.207810|0x0001ef08|uploadImageBatch|Begin
INFO|09-21 00:21:56.207810|0x0001ef08|ce::sendWindowMessages|Sending Window messages for VictoryShield.exe
TRAC|09-21 00:21:56.249837|0x0001ef08|ce::sendWindowMessages|Returning false
TRAC|09-21 00:21:56.249837|0x0001ef08|uploadImageBatch|Returning false
```

[INFERENCE: `uploadImageBatch` = flush/upload of queued screenshot-or-image batches before killing
the UI; here it no-ops because no `VictoryShield.exe` is running.]

#### Endpoints

- Local IPC endpoint, bound at service start (`major-3600.log:5`, `major-5616.log`):

```
CRIT|09-18 16:09:50.713309|0x00000e14|run::<lambda_1>::operator ()|Starting service on 127.0.0.1:48867
CRIT|09-21 00:22:44.903729|0x0001ed28|run::<lambda_1>::operator ()|Starting service on 127.0.0.1:48867
```

- DNS proxy listener, one per adapter, on loopback alias `127.0.0.2`:

```
CRIT|09-18 16:10:56.202543|0x000015e8|DNS Proxy Monitor adapters |Starting DNS Proxy server for 127.0.0.2 on adapter {37217669-42DA-4657-A55B-0D995D328250}
```

- Two upstream resolver groups are distinguished in timeouts ("DNS Filter server(s)" = CE's
  filtering resolvers; "DNS User server(s)" = the user/system resolvers, seen as
  `fec0:0:0:ffff::1, fec0:0:0:ffff::2, fec0:0:0:ffff::3`):

```
CRIT|09-18 16:11:29.135854|0x000015ec|DnsProxyRequest::handleDnsTimeout|Failed to receive response from DNS Filter server(s) for A:fonts.googleapis.com Request #1 - timed out
CRIT|09-18 16:11:29.135854|0x000015ec|DnsProxyRequest::handleDnsTimeout|Failed to receive response from fec0:0:0:ffff::1, fec0:0:0:ffff::2, fec0:0:0:ffff::3 DNS User server(s) for A:fonts.googleapis.com Request #1 - timed out
```

  (Real user lookups are visible: `fonts.googleapis.com`, `www.gstatic.com`, `storage.googleapis.com`,
  `accounts.youtube.com`, `dns.msftnc…`, … with retry counters `Request #1…#35`.)
- Server time: `ServerTimeManager::sync` — [INFERENCE] a network call to the CE backend
  (project-level observation: 208.185.195.49:443); the log only records success/failure.
- Update feed: WinSparkle appcast (`winsparkle::genericAppcastUpdate`) — see cadence below.

#### Auth

No tokens, credentials, or login lines appear in any comm-service log. The only "auth" artifacts in
the whole corpus are the installer's attempts to stop/uninstall a legacy service literally named
`Auth Service` (never installed on this VM; `fresh-install-4260.log:270-277`,
`upgrade-126428.log:204-222`):

```
CRIT|09-21 00:22:10.056522|0x0001ef08|CeSystemError<unsigned long>::CeSystemError|System error: OpenServiceW: Auth Service (error code 1060)
ERRR|09-21 00:22:10.056522|0x0001ef08||failed to stop auth service at all costs: System error: OpenServiceW: Auth Service (error code 1060)
```

[INFERENCE: authentication to the CE backend happens in the UI client / other component; the comm
service logs only "Server time update success" for its own backend calls.]

#### Cadence

Measured over the whole logs (timestamps parsed per line):

| activity | count | cadence | evidence |
|---|---|---|---|
| `ServerTimeManager::sync` ("Server time update success") | 86 in `major-5616.log` | **hourly** — median gap 3,600.7 s (min 3,600.0 / max 3,601.6); first 09-21 00:22:45, last 09-24 12:23:47 | `major-5616.log` |
| `winsparkle::genericAppcastUpdate` | daily | **24 h** — gaps 86,403.6 s; e.g. 09-22 00:22:49, 09-23 00:22:52, 09-24 00:22:56 (plus the 09-21 00:08:51 hit in `major-3600.log`) | both logs |
| `Removing DNS servers (start)` (monitor thread) | 563 in `major-3600.log` | **exactly 60.0 s** between consecutive entries (one out-of-order pair −3,539 s from two writer threads) | `major-3600.log` |
| DNS query retry timeouts | 60 lines | per-query retries with incrementing `Request #N` seconds apart | `major-3600.log` |

Appcast result lines (`major-5616.log`, `major-3600.log`) — the appcast carries version + channel
flags (`automatic`, `critical`):

```
CRIT|09-22 00:22:49.059677|0x0001f044|winsparkle::genericAppcastUpdate|Returning (0): Update none,  - automatic, critical
CRIT|09-21 00:08:51.442216|0x000019a4|winsparkle::genericAppcastUpdate|Returning (1): Update now, 10.1.44 - automatic, critical
```

That 09-21 00:08 "Update now, 10.1.44" line is what triggered the silent upgrade 13 minutes later
(`upgrade-126428.log`: `Install mode: silent`, package
`C:\WINDOWS\TEMP\Update-e3a2e57c-…\VictoryShield-installer-10.1.44-master-4222d5a90.exe`).

Service lifecycles:

- `major-3600.log` (old client, `WindowsClientv010.001.001\logs\comm-service\`):
  run 1 starts 09-18 16:09:45 (`Victory Shield Comm Service version: 10.1.1`, `Windows 10.0.26200 64`),
  restarts 09-20 00:08:38, ends 09-21 00:22:10 with `QUIT` as the upgrade begins.
- `major-5688.log`: a 10.1.44 process at 09-21 00:22:15 that logs startup and nothing else —
  it never reached "Starting service on 127.0.0.1:48867" [INFERENCE: superseded/killed during the
  upgrade's stop-everything window].
- `major-5616.log`: the surviving 10.1.44 service (PID 5616 — still running at collection):
  `Victory Shield Comm Service version: 10.1.44`, `Windows 11.0.26200.9457 64`,
  `No recent crashes detected, initializing crash handler`, then hourly syncs to now.

DNS-proxy teardown on start (registry `DnsProxyDisable=1` is written by the upgrade — see inventory
— [INFERENCE] explaining "already destroyed"):

```
CRIT|09-18 16:09:51.730270|0x00000f94|UserEventMessageQueueListener::deactivateDnsProxy|Deactivating DNS proxy
CRIT|09-18 16:09:51.734335|0x00000f94|`anonymous-namespace'::Impl::stopDnsProxy|DNS Proxy already destroyed
CRIT|09-18 16:10:55.145127|0x00000d7c|UserEventMessageQueueListener::activateDnsProxy|Activating DNS proxy
```

### Installer logs — explicit component inventory

Two installs are captured: **fresh install 2025-11-10 20:03–20:04** ("Installing Victory Shield
version 10.1.1", package `VictoryShieldWindows.exe`, Product GUID
`{5AC5ED2E-2936-4B54-A429-703F9034938E}`, installer DLL `10.1.1 (274a47a3)`, target
`C:\Program Files\CE`) and **silent upgrade 2026-09-21 00:21–00:23** ("Upgrading from Victory
Shield version 10.01.001 to Victory Shield version 10.1.44", installer DLL `10.1.44 (4222d5a90)`,
mutex `Global\VictoryShieldInstallerDLLIsInUse`, upgrade package
`VictoryShield-installer-10.1.44-master-4222d5a90.exe`).

**Component inventory** (every item below is a registered/removed component or system change as
traced in `fresh-install-4260.log` + `upgrade-126428.log` + `instnsp-*.log`):

- **Windows services registered**
  - `CovenantEyesCommService` (10.1.1) — `installing from C:\Program Files\CE\CovenantEyesCommService.exe`,
    `DependOnService = RpcSs, SamSs, ProfSvc, Afd, Tcpip, nsi, Dhcp, Dnscache` (`fresh-install-4260.log:495-504`).
  - `CEWD` (10.1.1 watchdog) — `installing from C:\Program Files\CE\CEWD.exe`,
    `DependOnService = RpcSs, SamSs, EventLog, ProfSvc` (`fresh-install-4260.log:505-514`).
  - `VictoryShieldCommService` (10.1.44) — `installing from C:\Program Files\CE\VictoryShieldCommService.exe`,
    same 8 dependencies (`upgrade-126428.log:1285-1294`).
  - `VSWD` (10.1.44 watchdog) — `installing from C:\Program Files\CE\VSWD.exe`,
    `DependOnService = RpcSs, SamSs, EventLog, ProfSvc` (`upgrade-126428.log:1295-1304`).
  - All four services: `startup type: 2` (auto).
- **Windows services removed**
  - `Auth Service` — attempted both installs; `OpenServiceW: Auth Service (error code 1060)` = never
    installed here (legacy CE service name kept in the uninstaller).
  - `CovenantEyesCommService` / `VictoryShieldCommService` / `CEWD` / `VSWD` — old-generation
    services stopped (`stopAtAllCosts`, 60,000 ms timeout, poll loop) and uninstalled during each
    cutover.
- **Kernel/other drivers** — no driver install/registration appears in any log. The upgrade removes
  unnamed legacy proxy driver files via `DeleteFileAfterReboot`:
  `TRAC|09-21 00:22:39.648494|…|traceLog|Deleting Proxy drivers` followed by 7×
  `DeleteFileAfterReboot` (`upgrade-126428.log:1024-1038`; file names not logged). The kernel driver
  `CEA.sys` is **not** referenced in any of these logs [INFERENCE: installed by a mechanism outside
  this corpus — open question for the driver task].
- **Certificates** — only via the legacy proxy: `Trying to delete cert` →
  `COperationsManager::DeleteCertService - Service not installed!` →
  `Reverting to local uninstall!` → `Delete cert failed!` (`CovenantEyesProxy.log`, both runs).
  No cert registration is logged anywhere [INFERENCE: the old HTTPS-certificate of the legacy
  proxy; its deletion fails on this VM].
- **COM classes** — legacy proxy COM server unregistration (self-run `/UnregServer`):
  `Trying to remove COM server entries`, `Trying to remove manual COM server entries`
  (`CovenantEyesProxy.log`). No CLSIDs are logged; no new COM registration in either install.
- **Browser extensions/integration**
  - IE extensions unregistered at `C:\Program Files\CE\extensions\ie\x86` and `…\ie\x64`
    (`fresh-install-4260.log:341-353`, `upgrade-126428.log:273-285`).
  - Firefox extension removal attempted; failed with `RegQueryValueExW (error code 2)`
    (`upgrade-126428.log:286-295`).
  - Secure-DNS (DoH) disabled in four browsers: `Disabling Microsoft Edge settings`,
    `Disabling Brave settings`, `Disabling Firefox settings`, `Disabling Google Chrome settings`
    (`fresh-install-4260.log:369-375`).
  - Browsers force-closed at install: `chrome.exe`, `firefox.exe`, `msedge.exe`, `brave.exe`
    (`fresh-install-4260.log:61-168`).
- **Winsock NSP / LSP**
  - NSP uninstall helper (`instnsp-8740.log`, fresh install; `instnsp-5648.log`, upgrade) —
    full content of both is identical modulo timestamps/threads:

    ```
    TRAC|11-10 20:03:43.591347|0x00000e98|nspUninstall|Begin
    TRAC|11-10 20:03:43.593369|0x00000e98|nspUninstall|Error 10022 encountered during NSP uninstallation process (WSCUnInstallNameSpace).
    TRAC|11-10 20:03:43.595384|0x00000e98|nspUninstall|Error 10022 encountered during NSP uninstallation process (WSCUnInstallNameSpace32).
    TRAC|11-10 20:03:43.599412|0x00000e98|nspUninstall|Done
    ```

    Both the 64-bit and 32-bit catalog entries are targeted; error 10022 (`WSAEINVAL`) both times
    [INFERENCE: no NSP was registered at uninstall time — the helper removes the legacy provider
    and is a no-op on current installs].
  - LSP removal phase `LSP_UnInstalling begin … end` in both install logs
    (`fresh-install-4260.log:354-363`, `upgrade-126428.log:296-305`), which also kills the CE UI
    process first.
  - Legacy NSP/LSP binaries removed via rename-then-delete-after-reboot:
    `C:\WINDOWS\SysWOW64\nmNsp.dll` (the Winsock namespace provider DLL [INFERENCE]),
    `C:\Program Files (x86)\CE\nmSvc.dll`, `C:\Program Files (x86)\CE\nmsvTree.dll`
    (`fresh-install-4260.log`, `upgrade-126428.log:441-455`).
  - Registry values `LSP Index binary` (19 bytes `3f 2a 2d e1 0c 12 c2 2c 28 db a2 21 28 51 3e ce e5 ae d4`),
    `LSP Index binary length` (=19), `Time binary`, `Time binary length` — per-user values migrated
    by the upgrade (`upgrade-126428.log:1140-1175`) [INFERENCE: state of the legacy LSP/NSP
    subsystem kept for migration/cleanup].
- **Firewall rules** — **none**. No `netsh`, `advfirewall`, or firewall-rule operation appears in
  any of the 8 logs (grep over the corpus).
- **Scheduled tasks** — **none**. No `schtasks`/Task Scheduler operation appears in any log;
  autostart is done with a registry Run-style value and two services.
- **Registry values written/removed** (all observed names):
  - Autostart: value `[Victory Shield] = "C:\Program Files\CE\VictoryShield.exe"` plus an enablement
    binary `[0x02,0,0,0,0,0,0,0,0,0,0,0]` (fresh install set the same pair to
    `"C:\Program Files\CE\CovenantEyes.exe"`) — `upgrade-126428.log:1065-1074`.
  - `[ServicesPipeTimeout] = 120000` (SCM timeout, `fresh-install-4260.log:436-439`).
  - Crash stats: `[ClientCrashesAt]`, `[ClientCrashesSince]` (written/cleared around client start;
    `updateCrashStatistics for Client`).
  - `[auto log] = 1`, `[FirstRunDone] = 1`, `[SystemVersionOverride]` (read; absent),
    `[AllowSecureSearch]` (read; absent), `[DisableSilentUpgrade]`, `[SilentUpgradeDisabledAt]`
    (removed; absent).
  - Telemetry: `[LastTelemetryUpdateAt]`, `[LastTelemetryUploadAt]` (values like
    `2026-09-21T05:21:53.8737993 UTC +0000`), `[ApiTelemetryStatus] = "success"`,
    `[ApiTelemetryResumeTime] = ""` (`upgrade-126428.log:1183-1229`).
  - `[InstallMode] = "upgrade"` — kept, not migrated ("Skipping migration of [InstallMode], a value
    already exists", `upgrade-126428.log:1163`).
  - `[DnsProxyDisable] = 1` written at migration (`upgrade-126428.log:1171`).
  - Per-user key `USERS:<SID>\SOFTWARE\Covenant Eyes\kckt0717` — deleted as "legacy CE user registry
    key" (`upgrade-126428.log:1151`).
  - "CE Proxy registry key" — deleted by `uninstallProxyService`
    (`fresh-install-4260.log:257-265`).
- **Files/binaries managed** — install dir `C:\Program Files\CE`: UI `CovenantEyes.exe` →
  `VictoryShield.exe`, helper `CovenantEyesHelper.exe`, classifier `CovenantEyesClassifier.exe` →
  `VictoryShieldClassifier.exe`, comm service `CovenantEyesCommService.exe` →
  `VictoryShieldCommService.exe`, watchdog `CEWD.exe` → `VSWD.exe`, legacy
  `CovenantEyesProxy.exe`, `CovenantEyesAdaptiveUI.exe` (removed), `data\*.dat.enc` (model data,
  see `enc-data.md`), `extensions\ie\{x86,x64}` (IE). Removed after reboot:
  `C:\Program Files (x86)\CE\{nmSvc.dll,nmsvTree.dll}`, `C:\WINDOWS\SysWOW64\nmNsp.dll`.
- **SQLite databases created** — `createDatabaseFiles` builds the per-version ProgramData dir with
  `ce-user-file` and `ce-file`:
  `C:\ProgramData\CovenantEyes\WindowsClientv010.001.001\ce-user-file` + `\ce-file` (fresh,
  `fresh-install-4260.log:441-494`) and
  `C:\ProgramData\CovenantEyes\VictoryShieldv010.001.044\ce-user-file` + `\ce-file` (upgrade,
  `upgrade-126428.log:1230-1284`).
- **Classifier state managed** — `RemoveClassifierModelData` destroys `C:\Program Files\CE\data`
  incl. all six `*.dat.enc` (see `enc-data.md`); `RemoveClassifierAppData` scans every profile's
  `AppData\Local\CovenantEyes` and destroys it (`fresh-install-4260.log:169-…`,
  `upgrade-126428.log:970-992`).
- **System settings changed** — `disableIPv6`/`ce::sys::preferIpV4`; `disableBrowserSecureDns`
  (Edge/Brave/Firefox/Chrome); `revertHostsFile` (the client manages `hosts`, reverted at upgrade;
  `upgrade-126428.log:1017-1023`); `enableSafeBootNetworking` (networking in safe boot);
  `flushDns` via `C:\WINDOWS\system32\ipconfig.exe /flushdns` (both installs).
- **Auto-updater** — `initWinsparkle` runs in both installs; the comm service checks the appcast
  daily and can launch `VictoryShield-installer-<ver>-master-<sha>.exe` silently (observed above).

### Legacy proxy log — `Redirector V3.0.0.48 (Licensed to: Covenant Eyes)`

Full content of both runs is quoted here (36 lines total). Run 1 — 2025-11-10 20:03:24, launched by
the fresh installer from a user temp dir; run 2 — 2026-09-21 00:22:09, launched by the upgrade from
`C:\WINDOWS\TEMP`:

```
11/10/25 20:03:24, Redirector started (V3.0.0.48)
11/10/25 20:03:24, Licensed to: Covenant Eyes
11/10/25 20:03:24, Path and params: C:\Users\dolphin\AppData\Local\Temp\{0A3E35A3-1CE9-42A6-8F35-B067CF515129}\{5AC5ED2E-2936-4B54-A429-703F9034938E}\CovenantEyesProxy /UnregServer
11/10/25 20:03:24, Current directory is: C:\Users\dolphin\AppData\Local\Temp\{0A3E35A3-…}\{5AC5ED2E-…}
11/10/25 20:03:24, Time since boot: 14158562
11/10/25 20:03:24, PID: 1996
11/10/25 20:03:24, String library passed MT test
11/10/25 20:03:24, OS: Windows 10 64bit
11/10/25 20:03:24, UAC is elevated, this is good
11/10/25 20:03:24, Trying to delete cert
11/10/25 20:03:24, *** Error *** COperationsManager::DeleteCertService - Service not installed!
11/10/25 20:03:24, COperationsManager::DeleteCertService - Reverting to local uninstall!
11/10/25 20:03:24, *** Error *** Delete cert failed!
11/10/25 20:03:24, *** Error *** COperationsManager::DeleteINIFile - Service not installed!
11/10/25 20:03:24, Trying to remove registry entries
11/10/25 20:03:24, Trying to remove service
11/10/25 20:03:24, Trying to remove COM server entries
11/10/25 20:03:25, Trying to remove manual COM server entries
```

Run 2 is identical except `09/21/26 00:22:09`, `Path and params: C:\WINDOWS\TEMP\{7B8A1336-1131-4210-8C99-EAA0699B9E38}\{5AC5ED2E-2936-4B54-A429-703F9034938E}\CovenantEyesProxy /UnregServer`,
`PID: 126896`.

What the component is and what its cleanup does:

- `CovenantEyesProxy` is the executable name; its self-identification is **"Redirector V3.0.0.48"**,
  a licensed third-party component ("Licensed to: Covenant Eyes"), clearly distinct from CE's own
  code (own string library, `COperationsManager`, own log format `MM/DD/YY HH:MM:SS, msg`).
  [INFERENCE] this is the legacy local web-proxy/"redirector" engine that pre-V10 CE clients used
  for HTTP interception/filtering; in the 10.x Victory Shield line it is dead code kept for
  uninstall hygiene — the installer only ever runs `CovenantEyesProxy.exe /UnregServer` (never a
  proxy server mode) and then deletes the binary.
- `/UnregServer` cleanup sequence, in order: **cert deletion** (tries a dedicated
  `DeleteCertService` service first, falls back to a local uninstall, fails here both times —
  [INFERENCE] the old HTTPS MITM cert store entry), **INI file deletion** (via the same service
  pattern — fails, "Service not installed!"), **registry entries removal**, **service removal**,
  **COM server entries removal**, **manual COM server entries removal** (i.e. both the
  self-registered and hand-written COM registrations).
- The two runs are invoked by the CE installer at uninstall/cleanup time from its temp extraction
  dir (same Product GUID `{5AC5ED2E-…}` as the installer support dir). The CE installer
  additionally deletes `CovenantEyesProxy.exe` itself and the "CE Proxy registry key"
  (`fresh-install-4260.log:257-265`).

## Evidence

All excerpts above are verbatim from `re/samples/data/logs/` (hash table at the top). Key line
anchors: `major-3600.log:5,12-18,40-41,4606-4738`; `major-5616.log:1-100`;
`fresh-install-4260.log:239-265,270-307,341-375,427-549`; `upgrade-126428.log:27-56,101-154,199-305,306-427,433-460,1017-1079,1080-1229,1230-1349`;
`instnsp-5648.log:1-4`; `instnsp-8740.log:1-4`; `CovenantEyesProxy.log:1-36`.

Open questions / gaps:

- No firewall-rule and no scheduled-task activity is logged at all — either they don't exist in
  this product or they happen outside these logs [INFERENCE: likely the former; the client achieves
  persistence via services + a Run-style registry value].
- The kernel driver `CEA.sys` install/update path is not in this corpus.
- The legacy proxy's cert deletion failed twice ("Delete cert failed!"); whether a stale cert
  remains in the machine store was not checked (read-only scope).

## Linux-reimplementation notes (brief)

- Log line contract worth copying: `level|timestamp µs|tid|tag|message` — cheap to parse, and tags
  as function names make a component's behavior reconstructable from logs alone.
- Replace the Windows-specific enforcement pieces with Linux equivalents of the *behaviors*:
  resolver pinning (systemd-resolved/NetworkManager dispatcher instead of per-adapter "Removing DNS
  servers" loops), DoH disable per browser (prefs files), `hosts` management (with a guaranteed
  revert on uninstall — CE does `revertHostsFile` on upgrade), and a per-user state dir keyed by uid.
- Update checking: a daily appcast-style check with `critical`/`automatic` flags and a silent
  installer handoff is simple and adequate; record server time sync separately (hourly) for log
  correlation.
- Installer hygiene checklist derived from the above: stop everything → flush pending uploads →
  remove old services/NSP/extensions → replace model data → migrate registry-equivalent config →
  create DBs → register services with explicit dependencies → start client. Keep that order.
