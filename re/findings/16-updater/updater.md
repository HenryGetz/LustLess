# 16-updater — WinSparkle auto-update, silent upgrades, and settings flags

Scope: `VictoryShield.exe` (WinSparkle wiring + upgrade UX) and `vs-config.exe` (settings
flags), cross-referenced with `re/findings/02-artifacts/logs.md` (comm-service + installer
logs). Crash reporting is separate: `crash-reporting.md`. Anti-tamper/SCM recovery is
`re/findings/14-watchdog/watchdog.md`; backend telemetry protocol belongs to a later pass.

## What it does

Victory Shield self-updates through a **forked WinSparkle** (`WinSparkle.dll`, 2,278,336 B on
disk, built from `C:\source\winsparkle\` with bundled wxWidgets + OpenSSL) that is *not* used
as a generic appcast consumer: the client registers an **alternate appcast callback** that
replaces the appcast fetch with a **CE backend API call (`getClientUpdate`)** returning a JSON
`recommendation` (`now` / `later` / `none`), version, download links and a `critical` flag.
Update checks run **every 24 h** (86,400 s — the comm-service logs show 86,403 s gaps starting
at service start); in **session 0** (the comm service) only `critical` recommendations are
acted on and a `DisableSilentUpgrade` flag can suppress the silent install path. The download
URL must be `https` on `covenanteyes.com` or `cvnt.net`; **no DSA public key is configured**
even though the DLL supports DSA signature verification. A server-recommended update leads to
the installer package `VictoryShield-installer-<ver>-<branch>-<sha>.exe` being downloaded to
`%WINDIR%\TEMP\Update-<guid>\` and run **silently elevated**, which performs the
stop-everything → migrate → replace-services upgrade observed 2026-09-21 (10.1.1 → 10.1.44).

## Mechanism

### 1. WinSparkle wiring (`VictoryShield.exe`)

Init entry point is `FUN_140291e10` (log-source file `D:\actions-runner\_work\w\p\x64\WinsparkleLibrary\CeWinsparkle.cpp`, string `0x140a52320`), called from
`CVictoryShieldView::OnCreate` (`FUN_1402b3600`, `Client/VictoryShieldView.cpp`
(`0x1408dbda8`), scope-name string `0x1408dbf48`) at `0x1402b3a4f`:

```
0x1402b3a4f  MOV  EDX, 0x15f90          ; 86400 = update-check interval, seconds
0x1402b3a54  LEA  RCX, [FUN_1402c3960]  ; appcast callback
0x1402b3a5b  CALL FUN_140291e10         ; WinSparkle init
```

`FUN_140291e10(callback, interval)` performs, in order (all calls visible in its decompile):

| call | value | evidence |
|---|---|---|
| `win_sparkle_set_registry_path` | `"SOFTWARE\Covenant Eyes\Victory Shield\WinSparkle"` (0x30 chars) | string `0x140a52608`; the path is relative to the **running account's HKCU** — live state on the box is under the LocalSystem profile: `HKU\S-1-5-18\SOFTWARE\Covenant Eyes\Victory Shield\WinSparkle` = `CheckForUpdates REG_SZ 1`, `LastCheckTime REG_SZ 1790227376` (= 2026-09-24 05:22:56Z), `UpdateInterval REG_SZ 86400` (reg query 2026-09-24) — proof that the **comm service** hosts the WinSparkle instance that performs the daily checks (its HKCU is the SYSTEM profile) |
| `win_sparkle_set_appcast_url` | `https://covenanteyes.com/files/win/sparkle/appcast-10.1.44-master-4222d5a90.xml` | built at runtime, below |
| `win_sparkle_set_automatic_check_for_updates` | `1` | decompile |
| `win_sparkle_set_last_check_time` | `now` (Unix time) via `FUN_14050be8c` (`GetSystemTimeAsFileTime` − 116444736000000000 / 10^7) | decompile |
| `win_sparkle_set_update_check_interval` | `86400` (0x15f90 from the call site) | disassembly above |
| `FUN_140292350` → `win_sparkle_set_app_details` | `"Covenant Eyes"`, `"Victory Shield"`, `"10.1.44"` | `FUN_140292350` decompile |
| `win_sparkle_set_alternate_appcast_callback` | `FUN_1402c3960` = `CVictoryShieldView::handleWinSparkleAppcastUpdate` (`Client/VictoryShieldView.cpp:0x9dc`, scope-name string `0x1408dd138`) | decompile |
| `win_sparkle_init` | | decompile |

**Appcast URL construction** (`FUN_140291e10`; constants: prefix
`https://covenanteyes.com/files/win/sparkle/appcast-` @`0x140a525d0` (0x33 chars), separator
`-` @`0x140a3f794`, suffix `.xml` @`0x140a523d0`; literals `"10.1.44"`, `"master"` (branch),
`"4222d5a90"` (change set) in-code):

```
appcast_url = "https://covenanteyes.com/files/win/sparkle/appcast-"
              + "10.1.44" + "-" + "master" + "-" + "4222d5a90" + ".xml"
            = "https://covenanteyes.com/files/win/sparkle/appcast-10.1.44-master-4222d5a90.xml"
```

The naming matches the installer package `VictoryShield-installer-10.1.44-master-4222d5a90.exe`
(`upgrade-126428.log:49`): the feed is **per-build** (`appcast-<version>-<branch>-<sha>.xml`),
i.e. "what should this exact build upgrade to". Branch (`master`) is the channel; there is no
language parameter (`win_sparkle_set_lang`/`set_langid` exist in the DLL but are not called by
the client — PE import table of `re/samples/00-baseline/VictoryShield.exe` lists exactly 10
`win_sparkle_*` imports: `init`, `cleanup`, `check_update_with_ui`,
`set_automatic_check_for_updates`, `set_appcast_url`, `set_update_check_interval`,
`set_registry_path`, `set_alternate_appcast_callback`, `set_app_details`,
`set_last_check_time`).

Because `set_alternate_appcast_callback` is registered, WinSparkle's own appcast download/parse
is bypassed; the appcast URL is effectively [INFERENCE] only a fallback/identifier.

### 2. The update check is a CE API call, not an XML appcast

The callback chain is `CVictoryShieldView::handleWinSparkleAppcastUpdate` (`FUN_1402c3960`,
thin logging wrapper, 9 parameters) → `winsparkle::genericAppcastUpdate` (`FUN_14028f560`,
log-tag string `winsparkle::genericAppcastUpdate` @`0x140a52368`, source
`WinsparkleLibrary\CeWinsparkle.cpp`). `FUN_14028f560` ignores any appcast XML and builds an
HTTP request via `HttpApiLibrary\src\ApiClientUpdate.cpp` (string `0x140a4efd0`) with operation
name **`getClientUpdate`** (string `0x140a4f098`) and a JSON body of device/build fields
(request-key strings at `0x140a4ee…`):

| JSON key | source |
|---|---|
| `app_name` | client name |
| `current_app_version` | running version (`10.1.44`) |
| `device_platform` | platform |
| `device_os_version` | OS version |
| `branch_name` | `master` |
| `change_set` | `4222d5a90` |
| `unique_device_id` | `Default-Device-Id` header/token; logs "Unique Device is NOT created yet, but needed for client update" (`0x140a4f058`) when absent |
| `device_cpu_architecture` | arch |
| `ce_user_names` | list of local CE user names (`FUN_140248c30` "get user names for client update") |

The response is parsed by `FUN_140246fd0` (`ClientUpdate(HttpResponse const&)`) into
7 strings + 1 bool from the JSON object `payload`:

| response JSON | struct field | note |
|---|---|---|
| `payload.recommendation` | string | `now` (`0x140a4ef08`) / `later` (`0x140a4eee0`) / `none` (`0x140a499e8`) |
| `payload.app_version` | version | logged in the decision line |
| `payload.app_download_link` | download URL | installer package URL |
| `payload.release_notes_page_link` | release notes URL | |
| `payload.download_page_link` | web browser URL | |
| `payload.app_name` | title | |
| (hardcoded) | description | `"Most recent updates to Victory Shield"` (`0x140a4ee18`) |
| `payload.critical` | bool | gates the session-0 (silent) path |

If `recommendation` is neither `now` nor `later`, `FUN_140246fd0` returns with all fields empty
(the fields are only parsed for `now`/`later`). Other strings in the block
(`applyClientUpdateOverrides` `0x140a4ee40`, `date_override` `0x140a4efb8`, `readJsonfile`
`0x140a4f120`, `Could not read file as json` `0x140a4f0e8`, three GUIDs
`5ee102b0-/f51102b0-/b41102b0-dfed-11eb-a383-b32532406870` @`0x140a4ee60`-`0x140a4eeb8`)
show a local JSON override mechanism used for testing/QA [INFERENCE].

**Download-URL trust check** — `FUN_14028f280` (uriparser-based):
1. parse the URL (`URL without protocol: ` error path, `Uri::parseUri` strings @`0x140a499e8` block);
2. scheme must be exactly `https`;
3. host must match `covenanteyes.com` (string `0x140a52390`) or `cvnt.net` (`0x140a523a8`)
   via `FUN_140201cd0`: true iff host `==` the domain (`FUN_1401467f0`) **or** host ends with
   `"." + domain` (`FUN_140201ea0` after prepending `.`) — so `files.covenanteyes.com` passes,
   `evileyes.com` does not.
Return 1 = trusted. On failure the callback logs
`Returning (-1): Untrusted download domain detected, ignoring: <url>` (string `0x140a524f0`)
and drops the update. This domain allowlist is the **only** download-integrity control in the
CE path (see §5).

### 3. Update decision and UX

Decision logic in `FUN_14028f560` (disassembly `0x140290480`–`0x140290700`; `BL` at
`[RSP+0x40]` = "manual check" flag, callback param 1; `FUN_14013a650` = `std::string` compare):

```
if recommendation == "now":                 -> return 1 (update)         [0x140290508/0x14029051d]
elif BL (manual check) and recommendation == "later": -> return 1         [0x14029052c/0x140290541]
elif recommendation == "none" or "later" (automatic): -> return 0 (none) [0x140290547/0x140290586]
else:                                       -> return -1 (error)         [0x14029057c]
```

The decision line is logged on both paths in the format

```
Returning (<rc>): Update <decision>, <version> - <automatic|manual>, <critical|not critical>
```

built at `0x1402905d5`–`0x1402906bf` (` - manual` `0x140a52558` / ` - automatic` `0x140a52568`
chosen by the manual flag; `not critical` `0x140a523d8` / `critical` `0x140a406c8` chosen by
the response critical bool at `[RBP+0xc00]`). Observed lines (`re/findings/02-artifacts/logs.md`):

```
CRIT|09-21 00:08:51.442216|0x000019a4|winsparkle::genericAppcastUpdate|Returning (1): Update now, 10.1.44 - automatic, critical
CRIT|09-22 00:22:49.059677|0x0001f044|winsparkle::genericAppcastUpdate|Returning (0): Update none,  - automatic, critical
```

i.e. `now` + version `10.1.44` + automatic check + critical → install; `none` + empty version
→ no action. Each field also has a length guard in the callback ("Client Update version is
truncated" `0x140a52530`, "…downloadUrl…" `0x140a52498`, "…releaseNotesUrl…" `0x140a524c0`,
"…title…" `0x140a52470`, "…description…" `0x140a52400`, "…webBrowserUrl…" `0x140a52440`).

UX surfaces (MFC dialog resources in `VictoryShield.exe` `.rsrc`, DLGTEMPLATEEX):
- **dialog 197** `0x140c03a98` "Upgrade - Victory Shield" — buttons `Next >>`, `Finish`,
  `Cancel`, `Reboot` (upgrade wizard; `Reboot` completes an upgrade that needs a restart).
- **dialog 203** `0x140c03be0` "Upgrade status - Victory Shield" — `Progress1`/`Progress2`
  (`msctls_progress32`) + `Cancel` (download/install progress).
- WinSparkle's own dialogs (strings in `WinSparkle.dll`): "Would you like to download our new
  version (%s) now?", "Downloading update...", "Launching the installer...". The tray also has
  "Check for &updates" (string `0x140c03892`) → `win_sparkle_check_update_with_ui` (manual
  check, the ` - manual` channel of the decision line), and a "Checking for Software
  Updates..." static (`0x140c03efc`).

### 4. Silent-upgrade gating (`DisableSilentUpgrade` / `SilentUpgradeDisabledAt`)

At the top of `FUN_14028f560` (before any network call):

```
inSession0 = FUN_1401cc540()               // ProcessIdToSessionId(GetCurrentProcessId()) == 0
disable    = FUN_1401e4210()               // reads setting "DisableSilentUpgrade" (wstring, 0x14 chars)
if (inSession0 && disable) {
    disabledAt = ce::sys::settings::getSilentUpgradeDisabledTime()   // RTTI @0x140b32200,
                                                                   // "get Silent Upgrade Disable time" @0x140a48748
    days = (now - disabledAt) / 86'400'000'000 (100 ns ticks)        // FUN_140291df0 adds the remainder
    if (days > 0)  log "Silent upgrades have been disabled for <N>" (strings 0x140a52578/FUN_140292540)
                   and CONTINUE with the update check;
    else           log "Returning (0): silent upgrade are disabled " (0x140a525a0) and return 0;
}
```

So `DisableSilentUpgrade` only suppresses the **session-0** (service) update path, and only
while `SilentUpgradeDisabledAt` is **less than a day old**; older disables are logged and then
ignored [INFERENCE: a "remind me later" grace window of 1 day]. On the success path the
callback's last out-param (a `'1'`/`'0'` char at `*param_9`, `0x1402904e5` region writes it
before the tail) is `'1'` only when **inSession0 AND response `critical`**; when
`inSession0 && !critical` the flow jumps to the no-update epilogue (`0x1402906f5 → 0x140291ab1`):
**in the service, only critical updates install**. In an interactive session the flag is
`'0'` and the WinSparkle UI flow decides. The installer itself clears both flags on upgrade —
`upgrade-126428.log:1061-1063` ("failed to remove 'DisableSilentUpgrade' /
'SilentUpgradeDisabledAt' … error code 2" = values were absent here).

**Who sets the flag**: `vs-config.exe` has a dedicated **`disableSilentUpgrade`** command
(`FUN_1400198e0`, `VSConfig\src\main.cpp:0x117`, log scope `disableSilentUpgrade`): it logs
`"disabling silent upgrade"`, takes `_Xtime_get_ticks()` (now), calls `FUN_1400594c0(1)`
[INFERENCE: `setDisableSilentUpgrade(1)` → writes `DisableSilentUpgrade=1`], and writes the
current `CETime` via `FUN_140060f70` with the log tag `"set Silent Upgrade Disable time"`
(string `0x140394a98`) → **`SilentUpgradeDisabledAt = now`**. That is the admin/support
switch behind the runtime gate; the reader on the client side is `FUN_1401e4210`
(`L"DisableSilentUpgrade"`) and `ce::sys::settings::getSilentUpgradeDisabledTime`
(RTTI `0x140b32200`). `vs-config.exe`'s read-side counterpart is
`ce::sys::settings::allowSecureSearch` = `FUN_140059300` (reads `L"AllowSecureSearch"`,
0x11 chars, through the settings lens `FUN_140056bd0`/`FUN_14005f930`, returns the bool byte,
default 0).

### 5. Signature verification: DLL yes, integration no

`WinSparkle.dll` (fetched from `C:\Program Files\CE\WinSparkle.dll` 2026-09-24; copied to
analysis host for export/PE/string parsing) is a WinSparkle fork with **OpenSSL DSA support**:
exports include `win_sparkle_set_dsa_pub_pem`, and strings include
`http://www.andymatuschak.org/xml-namespaces/sparkle#dsaSignature`,
`Missing DSA signature!`, `Invalid update signature`, `Cannot read DSA public key from PEM`,
`.?AVBadSignatureException@winsparkle@@`, config value names `DSAPEM`/`DSAPub` (registry) and
`UpdateTempDir` (download-dir override). However **the client never configures a DSA key**:
`win_sparkle_set_dsa_pub_pem` is not in VictoryShield.exe's import table (10 `win_sparkle_*`
imports listed in §1) and no `DSAPub`/`DSAPEM` value is written by the installer (no such
value name appears in `upgrade-126428.log`/`fresh-install-4260.log` registries inventory in
`re/findings/02-artifacts/logs.md`). The update payload is therefore trusted by
**transport + server** (HTTPS, CE backend response) and the **`https`+domain allowlist** of
§2 — there is no client-side signature check on the downloaded installer in the CE
integration [INFERENCE: DSA verification would engage only if an admin pre-provisioned
`DSAPUB`/`DSAPEM` under `HKLM\SOFTWARE\Covenant Eyes\Victory Shield\WinSparkle`; nothing in
the product does]. Direct confirmation: the live WinSparkle state key
(`HKU\S-1-5-18\SOFTWARE\Covenant Eyes\Victory Shield\WinSparkle`, reg query 2026-09-24)
contains only `CheckForUpdates`, `LastCheckTime`, `UpdateInterval` — **no `DSAPub`/`DSAPEM`
value exists**.

### 6. Silent upgrade run-of-show: 10.1.1 → 10.1.44 (2026-09-21 00:08 → 00:23)

Full component inventory is in `re/findings/02-artifacts/logs.md` ("Installer logs"); the
update-specific sequence (all quotes `re/samples/data/logs/upgrade-126428.log`, 136,142 lines):

1. **00:08:51** — comm service (10.1.1, `major-3600.log`) logs
   `Returning (1): Update now, 10.1.44 - automatic, critical`.
2. **~00:21** — WinSparkle has downloaded the package to
   `C:\WINDOWS\TEMP\Update-e3a2e57c-5ea5-4a04-bace-4291101d4602\VictoryShield-installer-10.1.44-master-4222d5a90.exe`
   (`upgrade-126428.log:49`) [INFERENCE: the `Update-<guid>` directory is created by
   WinSparkle's downloader (`UpdateTempDir`/`GetTempPathW` strings in the DLL); the 13-minute
   gap between decision and install is unexplained — see Open questions].
3. **00:21:52** — installer runs **elevated** (`ce::isElevated|Process ID: 126428 … elevated
   (admin) privileges`, `upgrade-126428.log:1320`), from a fresh extraction dir
   `C:\WINDOWS\TEMP\{5E0CB312-2D57-4D84-BD37-564758CF4C1D}\`, and logs its identity:
   `Loading installer DLL 10.1.44 (4222d5a90)`, mutex
   `Global\VictoryShieldInstallerDLLIsInUse`, `Using Target Directory: "C:\Program Files\CE"`,
   `Using Support Directory: "C:\WINDOWS\TEMP\{7B8A1336-…}\{5AC5ED2E-2936-4B54-A429-703F9034938E}\"`,
   `Using Product GUID: "{5AC5ED2E-2936-4B54-A429-703F9034938E}"`, **`Install mode: silent`**,
   `OnSetUpdateMode end - Update`, `Installed CE version: 10.01.001`,
   `Installer CE version: 10.1.44` (`upgrade-126428.log:27-56`).
   The same GUID `{5AC5ED2E-2936-4B54-A429-703F9034938E}` is the InstallShield product; its
   UninstallString is
   `"C:\Program Files (x86)\InstallShield Installation Information\{5AC5ED2E-…}\setup.exe" -runfromtemp -l0x0409 -removeonly`
   (`re/findings/01-dynamic-recon/live-surface.md` §d) — `-removeonly` is the InstallShield
   maintenance-mode flag used for uninstall; the upgrade instead runs the *new* package with a
   silent flag [INFERENCE: `-s`/equivalent passed by the WinSparkle installer handoff or
   detected by the wrapper; the log only records `Install mode: silent`].
4. **Pre-install flush** — `ce::sendWindowMessages|Sending Window messages for VictoryShield.exe`
   (asks the running UI to flush pending uploads; `uploadImageBatch`, `upgrade-126428.log:103-110`).
5. **Teardown** (in order): watchdog `ce::watchdog_service::stopAtAllCosts` (118-147),
   `DeleteFileAfterReboot` (staged deletes), legacy proxy self-uninstall
   (`uninstallProxyService` → `CovenantEyesProxy /UnregServer`, "CE Proxy registry key"
   deleted, 190-198), `uninstallAllCeServices` → stops/uninstalls `Auth Service` (absent,
   error 1060), `CovenantEyesCommService`→`VictoryShieldCommService` and `CEWD`→`VSWD`
   service pairs with `stopAtAllCosts` (60,000 ms timeout) (199-267), LSP/NSP removal
   (`LSP_UnInstalling begin…end`, 296-305) and legacy binaries staged for
   post-reboot delete (441-460, incl. `C:\WINDOWS\SysWOW64\nmNsp.dll`).
6. **Data migration** — `preserveCeUserData` copies old state from
   `C:\ProgramData\CovenantEyes\WindowsClientv010.001.001\` to
   `C:\ProgramData\CovenantEyes\PreviousConfiguration\` (487-669), settings values are
   migrated/deleted per `logs.md` (incl. per-user `…\SOFTWARE\Covenant Eyes\kckt0717` delete,
   `DnsProxyDisable=1` write, `DisableSilentUpgrade`/`SilentUpgradeDisabledAt` removal attempt,
   `InstallMode=upgrade` kept, `SystemVersionOverride` read-but-absent at `upgrade-126428.log:99`),
   and `createDatabaseFiles` builds the fresh
   `C:\ProgramData\CovenantEyes\VictoryShieldv010.001.044\{ce-file,ce-user-file}` — the
   data-dir name **encodes the version** (`WindowsClientv010.001.001` →
   `VictoryShieldv010.001.044`).
7. **Cutover** — new services `VictoryShieldCommService` + `VSWD` registered (deps logged,
   `upgrade-126428.log:1285-1304`), UI renamed `CovenantEyes.exe` → `VictoryShield.exe`,
   autostart Run value rewritten to `VictoryShield.exe` (`upgrade-126428.log:1065-1074`), and
   the new comm service starts at 00:22:44 (`major-5616.log`).

### 7. Reboot path and legacy driver cleanup

- Files that cannot be deleted while running are registered for **deletion after reboot**
  (`DeleteFileAfterReboot` ×24 in `upgrade-126428.log` — incl. the 7 calls after
  `Deleting Proxy drivers` at `:1024`; ×8 in `fresh-install-4260.log`; shared helper
  `destroyPathAfterReboot` / "devoting file to destruction after reboot: " strings
  `0x140a3fc10` / `0x140a3fc28` in VictoryShield.exe). The observed upgrade did **not**
  require or trigger a reboot (service restarts immediately).
- The reboot-in-30-seconds UI is dialog resource **217** (`0x140c042b0`, caption
  "Monitoring - Victory Shield") containing the static text
  `Trend Micro's TDI driver has been disabled because it conflicts with Victory Shield.  Your computer will reboot in 30 seconds.`
  (string `0x140c0433c`) with buttons `Reboot` and `Continue` (`0x140c04458`/`0x140c04484`).
  No TDI driver names (`tmtdi`, `TmPfw`, `tmactmon`, …) exist in any CE binary or in any
  install log (string scan of all `re/samples/00-baseline/*`; logs.md finds no driver
  registration at all), so the *disabling* itself is not in this product generation — the
  message is written in past tense [INFERENCE: legacy relic from pre-V10 clients that
  uninstalled Trend Micro's TDI filter driver; the dialog and its 30-second auto-reboot
  countdown survive as resource/UX code]. The code that instantiates dialog 217 was not
  located (MFC loads it by resource ID; no direct string xrefs).

### 8. Settings flags read/written around upgrades

Registry locations: machine settings under `HKLM\SOFTWARE\Covenant Eyes\Victory Shield`,
per-user under `HKCU/HKU\<SID>\SOFTWARE\Covenant Eyes\Victory Shield` (same value names; the
settings library chooses machine-vs-user by session id — `re/findings/14-watchdog/watchdog.md`
§6 documents the same mechanism for the crash counters). WinSparkle keeps its own state under
`<HKCU-of-the-running-account>\SOFTWARE\Covenant Eyes\Victory Shield\WinSparkle`
(`win_sparkle_set_registry_path`; for the comm service that is
`HKU\S-1-5-18\…\WinSparkle` — `CheckForUpdates`/`LastCheckTime`/`UpdateInterval`; fork-specific
values `DSAPub`/`DSAPEM`/`UpdateTempDir` would live there but are absent).
Live registry snapshot (VM, `reg query`, 2026-09-24):
`HKLM\SOFTWARE\Covenant Eyes\Victory Shield` = `InstallMode REG_SZ upgrade`,
`DnsProxyDisable REG_BINARY 01000000`, `FirstRunDone REG_BINARY 01000000`,
`LastTelemetryUpdateAt/LastTelemetryUploadAt REG_SZ … UTC +0000`,
`ApiTelemetryStatus success`, `ApiTelemetryResumeTime ""`;
`HKCU\SOFTWARE\Covenant Eyes\Victory Shield` = `ClientCrashesAt REG_SZ
2025-11-10T20:03:54.9051886`, `ClientCrashesSince REG_BINARY 00000000`, `auto log`, `FirstRunDone`,
`LSP Index binary (length)`.

| value name | where | semantics | evidence |
|---|---|---|---|
| `DisableSilentUpgrade` | `…\Victory Shield` | bool: suppress the session-0 silent update path for 1 day | read: `FUN_1401e4210` (VictoryShield.exe, `L"DisableSilentUpgrade"`); write: vs-config `disableSilentUpgrade` command `FUN_1400198e0` (via `FUN_1400594c0(1)`); string `0x140394a68`; installer tries to remove it (`upgrade-126428.log:1061`) |
| `SilentUpgradeDisabledAt` | `…\Victory Shield` | timestamp of when silent upgrade was disabled; expiry base for the 1-day window | write: vs-config `FUN_1400198e0` → `FUN_140060f70` ("set Silent Upgrade Disable time" `0x140394a98`); read: `ce::sys::settings::getSilentUpgradeDisabledTime` (RTTI `0x140b32200`, "get Silent Upgrade Disable time" `0x140a48748`); strings `0x140a48768`/`0x140394ab8`; installer removal `upgrade-126428.log:1063` |
| `AllowSecureSearch` | `…\Victory Shield` | bool read by `ce::sys::settings::allowSecureSearch` = vs-config `FUN_140059300` (returns value byte, default 0); read-but-absent during upgrade (`logs.md` registry inventory) | vs-config string `0x1403949e8`, tag `0x140394a10` |
| `DnsProxyDisable` | `…\Victory Shield` | bool: disable the DNS-proxy enforcement; written `=1` by the upgrade migration (`upgrade-126428.log:1171`) | strings `0x140a48728` (VictoryShield.exe) / `0x140394a48` (vs-config) |
| `EnableDebugLogging` | `…\Victory Shield` | bool: verbose logging toggle (vs-config `configDebugLogging` toggles + offers process restart) | `0x140a48480` / `0x140394978`; vs-config `FUN_14001ad50` (§9) |
| `DisabledComponents` (OS value) | `HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters` | Windows IPv6-disable bitmask; read for health display, written/restored by `ce::sys::preferIpV4`/`revertIpV4` | vs-config `0x140394ae8` + `FUN_140059b00`/`FUN_1400aa370` (§9) |
| `IPv6DisabledComponents` | `…\Victory Shield` | backup of the OS `DisabledComponents` taken before IPv6 disable; restored on revert | vs-config `0x140399e20` (§9) |
| `SystemVersionOverride` | `…\Victory Shield` | version override read at install/upgrade; absent by default | `upgrade-126428.log:99` |
| `InstallMode` | `…\Victory Shield` | `upgrade`/`fresh` marker written by the installer ("Skipping migration of [InstallMode], a value already exists") | `0x140a487c0`, `upgrade-126428.log:1163` |
| `ForceCrashClient` | `…\Victory Shield` | debug: force a client crash (see `crash-reporting.md`) | `0x140a48458` |
| `auto log` | `…\Victory Shield` | logging flag written `=1` at install | `0x140a48608`, `logs.md` inventory |
| `FirstRunDone` / `VictoryShieldFirstRunDone` | `…\Victory Shield` (Run-adjacent) | first-run marker written `=1` | `0x140a48708` / `0x140a48690`, `0x140a48690` "VictoryShieldFirstRunDone" |
| `ClientCrashesAt`/`ClientCrashesSince`, `CommServiceCrashesAt`/`…Since` | `…\Victory Shield` (HKCU per user / HKLM session-0) | crash counters — see `crash-reporting.md` + `watchdog.md` | `0x140a3bb90`-`0x140a3bc10`, watchdog.md §6 |
| `ClientCrashes` / `ServiceCrashes` | settings/telemetry store fields (`…\Victory Shield` family) | accumulated crash counts (`updateProcessCrashes`, reported then zeroed at startup) — `crash-reporting.md` §5b | `0x140a488b8`/`0x140a488d8` |
| `DnsFromDhcp`, `DnsAddresses`, `ProxyAddress` | `HKLM\SOFTWARE\Covenant Eyes\Victory Shield\NetworkInterfaces\{IPv4\|IPv6}\<adapterId>` | per-adapter saved DNS/proxy state (vs-config `NetworkAdaptersSettingsImpl::*`; distinct from the comm-service's `NetworkStatus\{adapter-GUID}` tree, which holds `Description/IfName/IfType/ConnType/IpSupport/OpStatus/LastActivatedTime`) | `0x140a48268`-`0x140a483c0`, vs-config `0x140394750`-`0x140394890` + `FUN_140058xxx` (§9) |
| `DependOnService`, `DisplayVersion` | `SYSTEM\CurrentControlSet\Services\…`, Uninstall key | service dependency list / product version (read during install/upgrade) | `0x140a48888`/`0x140a489c8` |
| `LSP Index binary`, `LSP Index binary length`, `Time binary`, `Time binary length` | per-user `…\Covenant Eyes\kckt0717` (legacy) | migrated/deleted at upgrade | `upgrade-126428.log:1140-1175` |
| `LastTelemetryUpdateAt`, `LastTelemetryUploadAt`, `ApiTelemetryStatus`, `ApiTelemetryResumeTime` | `…\Victory Shield` | telemetry pacing values written by the installer (`logs.md`) | `upgrade-126428.log:1183-1229` |

`vs-config.exe` reads/writes the same value names through the shared
`CommonLibrary\src\CeSystemSettings.cpp` (string `0x1403949a0`) and its settings lens
(`reg::makeRegistryLens`, RTTI `0x140403fa0`+; `CeWinRegistry.cpp` `0x14039a450`), selecting
machine (`HKLM\SOFTWARE\Covenant Eyes\Victory Shield`) vs per-user (`HKCU/HKU\<SID>\…`) stores
by `ProcessIdToSessionId` like the rest of the CE settings library (watchdog.md §5).
Offline per-user editing loads profile hives with `RegLoadKeyW`/`RegUnLoadKeyW`
(strings `NTUSER.DAT` `0x140394b80`, `.DEFAULT\Software` `0x140394660`, `userAppRemove`
`0x140394b10`, "CE user registry path did not exist at " `0x140394b30`); the removal side is
`ce::sys::settings::allCeRegistySettingsRemove` (`0x140394d78`; "Removing Default User's CE
registry settings" `0x140394c28`, "Removing ALL User's CE registry settings" `0x140394d18`,
"Removing ALL Local Machine CE registry settings" `0x140394da8`). See also
`re/findings/02-artifacts/logs.md` "Registry values written/removed" for the installer-side
inventory.

### 9. `vs-config.exe` settings catalog (complete)

All registry value names `vs-config.exe` reads/writes/deletes, with hive + path, type,
direction and function-level evidence (string VA + referencing function VA; verified via
Ghidra xrefs/decompiles plus a full-image reference scan). `R`/`W`/`D` = read/write/delete.

**Hive binding** — all `ce::sys::settings` key builders in vs-config use hive-enum **0 =
`HKEY_LOCAL_MACHINE`** (`FUN_140056bd0` disassembly `XOR EDI,EDI` before
`FUN_140056ac0(dest, 0)`; `reg::Key::toString` `FUN_1400b1c70` maps 0=`LOCAL_MACHINE:`,
1=`CURRENT_USER:`, 2=`USERS:`; out-of-range aborts with the string `"horror"` @`0x140394684`).
So vs-config's settings surface is **`HKLM\SOFTWARE\Covenant Eyes\Victory Shield`**; per-user
hives are only touched through `RegLoadKeyW` of `<profile>\NTUSER.DAT` under `HKEY_USERS`
(offline mount → mutate → `RegUnLoadKeyW`; load-failure logs "Failed to load registry file at "
`0x140394b58`). Client/watchdog binaries choose machine-vs-user stores by process session
(`watchdog.md` §5) — that branch is not in vs-config.

**9a. CE product settings — `HKLM\SOFTWARE\Covenant Eyes\Victory Shield`**

| value | type | R/W | semantics | evidence |
|---|---|---|---|---|
| `EnableDebugLogging` | REG_DWORD bool (default 0) | R+W | debug logging toggle; `configDebugLogging` reads state, writes new, optionally restarts VS processes | `0x140394978`; `FUN_14001ad50` (sites 0x14001ada6/0x14001b073), read `FUN_1400214d0` |
| `DnsProxyDisable` | REG_DWORD bool (lens default 1) | R+W | 1 = DNS proxy disabled; written by `ce::local_comm_service::disableDnsProxy`/`enableDnsProxy` ("stop/start dns proxy") and by the upgrade migration | `0x140394a48`; W `FUN_14008ff00`(=1)/`FUN_14008f9e0`(=0); read `FUN_1400214d0` |
| `DisableSilentUpgrade` | REG_DWORD bool | R+W+D | silent-upgrade opt-out; set by `disableSilentUpgrade` (`FUN_1400198e0`→`FUN_1400594c0(1)`), **deleted to re-enable** (`FUN_1400594c0(0)`→`FUN_140055ef0`; also `revertSilentUpgrade` `FUN_140019c90`) | `0x140394a68`; sites 0x1400594f1, 0x140019faa, status `FUN_140018420` |
| `SilentUpgradeDisabledAt` | REG_SZ timestamp (UtcDateTime) [INFERENCE] | W+D | when silent upgrade was disabled ("set Silent Upgrade Disable time") | `0x140394ab8`; writer `FUN_140059620` (site 0x14005971e) ← `FUN_140060f70`; delete `FUN_140019c90` |
| `AllowSecureSearch` | REG_DWORD bool (default 0) | R | `ce::sys::settings::allowSecureSearch()` = stored bool or 0 | `0x1403949e8`; `FUN_140059300` (site 0x140059331) |
| `IPv6DisabledComponents` | REG_DWORD | R+W+D | backup of OS `DisabledComponents` before IPv6 disable; restored by `revertIpV4` ("revert IPv6 setting") then removed | `0x140399e20`; `FUN_1400aa370` (sites 0x1400aa3f5/0x1400aa4cd) |
| `DnsFromDhcp` | REG_DWORD bool | R+W | per-adapter DHCP-DNS flag (`NetworkAdaptersSettingsImpl::isDnsFromDhcp`/`setIsDnsFromDhcp`) under `…\Victory Shield\NetworkInterfaces\{IPv4\|IPv6}\<adapterId>` | `0x140394750`; R `FUN_140058420`, W `FUN_140058310`; key builders `FUN_140057bf0`/`FUN_140057ff0` (`IPv4`/`IPv6` @`0x140394744`/`0x14039473c`) |
| `DnsAddresses` | REG_SZ (joined list) [INFERENCE] | R+W | saved static DNS servers (`getDnsHosts`/`setDnsHosts`), same per-adapter key | `0x140394768`; R `FUN_1400580e0`, W `FUN_1400585c0` |
| `ProxyAddress` | REG_SZ | R+W | saved proxy (`getProxyAddress`/`setProxyAddress`) | `0x140394848`; R `FUN_140058730`, W `FUN_140058960` |
| *(adapter subtree)* | key | D | `removeAdapterId` deletes a configured adapter ("Removing adapter id (start/complete)") | `FUN_140058dd0` (sites 0x140058ea6/0x1400590b6) |

**9b. OS/system values vs-config touches**

| value | hive + path | R/W | semantics | evidence |
|---|---|---|---|---|
| `DisabledComponents` | HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters | R+W | Windows IPv6 bitmask; read for the health line, written by `preferIpV4`, restored by `revertIpV4` | `0x140394ae8` (read `FUN_140059b00`), `0x140399e38` (write `FUN_1400aa370`) |
| `NameServer` | HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\<adapter> (+ `Tcpip6`) | W | `ce::restoreDnsConfigFor` writes the saved server list back | `0x140398e58`; `FUN_140093d00` |
| `DependOnService` | HKLM\SYSTEM\CurrentControlSet\Services\<svc> | W | `ce::sys::settings::setServiceDependencies` (4-dep `RpcSs SamSs EventLog ProfSvc` or 8-dep list; CE service keys `VSWD`/`CEWD`/`VictoryShieldCommService`/`CovenantEyesCommService`) | `0x140394fd0`; `FUN_14005dca0` |
| `DisplayVersion`, `UBR` | HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion | R | Windows version display for the "OS: …" health line | `0x140395000`/`0x140395020`; `FUN_140046d20` |
| `ProgramFilesDir` | HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion | R | Program Files resolution (fallback `C:\Progra~1` @`0x14038fa78`) | `0x14038fa58`; `FUN_140031a60`/`FUN_140031bd0` |

**9c. Browser secure-DNS (DoH) policy values** — written by `ce::sys::disableBrowserSecureDns`
(`FUN_1400a85a0`, tag @`0x140399c60`), removed by `revertBrowserSecureDns` (`FUN_1400a8f70`),
checked by `checkIfSecureDnsIsDisabled` (`FUN_1400a98c0`):

| value | key | written as | evidence |
|---|---|---|---|
| `BuiltInDnsClientEnabled` | HKLM\SOFTWARE\Policies\Microsoft\Edge\ | `0` | `0x140399ba8` (site 0x1400a87f7) |
| `DnsOverHttpsMode` | Edge\ / Google\Chrome\ / BraveSoftware\Brave\ | `off` (`0x140399ba4`) | `0x140399b90` (sites 0x1400a8831/0x1400a8ef4/0x1400a8a64) |
| `TorDisabled` | BraveSoftware\Brave\ | `1` (anti-circumvention) | `0x140399c10` (site 0x1400a8a83) |
| `Locked` | Mozilla\Firefox\DNSOverHTTPS\ | `1` (policy lock) | `0x140399be4` (site 0x1400a8c96) |
| `Enabled` | Mozilla\Firefox\DNSOverHTTPS\ | `0` | `0x140394ff0` (site 0x1400a8cb9) — note: Mozilla's documented name is `EnabledMode` [unverified effectiveness] |

**9d. Autostart values** (checked/deleted by vs-config, written by the installer):
`Victory Shield` (REG_SZ under `HKLM\…\CurrentVersion\Run` + 12-byte enablement of the same
name under `…\Explorer\StartupApproved\Run`), legacy `Covenant Eyes` (same pair, HKLM + every
user hive incl. `.DEFAULT`), legacy `NMSVC` (Run) — deletion logs
"Removing autostart registry value for Victory Shield" @`0x140394ba8`, "…enablement…" @`0x140394c60`
/@`0x140394ca0`, "…for Covenant Eyes" @`0x140394ce0`.

**9e. Wholesale key deletions** (`VsDestroyer` + `ce::sys::settings::allCeRegistySettingsRemove`
`FUN_14005b210`): the Uninstall entries
`Software\Microsoft\Windows\CurrentVersion\Uninstall\{5AC5ED2E-2936-4B54-A429-703F9034938E}`
(+ Wow6432Node), `SOFTWARE\Covenant Eyes, Inc.` @`0x14038bc20`, `Software\CovenantEyesProxy`
@`0x14038bc40`/`0x14038bcc8`, `Software\SOFTWARE\Covenant Eyes` trees @`0x14038bcb0`/`0x14038b668`,
`SOFTWARE\Victory Shield` @`0x140394b90`, plus per-user Run/StartupApproved values — per-user via
the NTUSER.DAT mount described above.

**9f. Read-only diagnostics**: `collect-debug` dumps `HKLM\SOFTWARE\Covenant Eyes`
(`0x14038d210`) and `HKCU\SOFTWARE\Covenant Eyes` (`0x14038d238`) via `reg.exe`; the Registry
Protector's watch list references the Run/StartupApproved keys and the four CE service keys
(`0x140398030`-`0x140398390`).

**Dead in vs-config (do not attribute R/W to it)**: the value-name strings
`Client`/`CrashesSince`/`CrashesAt`/`CommService` (`0x14038c338`-`0x14038c3a8`) and
`OverrideFile`/`SqlErrors`/`OverridePercentRank`/`OverrideUtcDateTime`/`HttpClientTracing`/
`ClientapiDomainRoot` (`0x14038c2a8`-`0x14038c320`) have **zero code references** (Ghidra xrefs
= 0, plus full-image reference scan) — statically-linked remnants of the shared settings code.
`InstallMode`, `FirstRunDone`, `auto log`, `SystemVersionOverride`, `ForceCrashClient`,
`LastTelemetryUpdateAt`, `LastTelemetryUploadAt`, `ApiTelemetryStatus`, `ApiTelemetryResumeTime`,
`ServicesPipeTimeout`, `LSP Index binary` do **not exist** in vs-config's string set at all —
those are installer/client/service-side (rows in §8). The crash-counter contract is owned by
`RestartVS*.exe` (writer) and `VSWD` (reader) per `watchdog.md` §5 and `crash-reporting.md` §5.

## Evidence

Addresses (Ghidra `VictoryShield.exe`, image base `0x140000000`):

- `FUN_140291e10` — WinSparkle init (`CeWinsparkle.cpp`), `FUN_140292350` —
  `win_sparkle_set_app_details`, `FUN_1402c3960` —
  `CVictoryShieldView::handleWinSparkleAppcastUpdate`, `FUN_14028f560` —
  `winsparkle::genericAppcastUpdate` (decision region disassembled `0x140290480`-`0x140290700`),
  `FUN_140246fd0` — `ClientUpdate` JSON parse, `FUN_14028f280` — download-domain allowlist,
  `FUN_1401cc540` — `session==0`, `FUN_1401e4210` — `DisableSilentUpgrade` read,
  `FUN_14050be8c` — FILETIME→Unix time, `FUN_1402b3600` — `CVictoryShieldView::OnCreate`
  (call site `0x1402b3a4f`-`0x1402b3a5b`).
- Strings: appcast prefix `0x140a525d0`, separator `0x140a3f794`, suffix `.xml` `0x140a523d0`,
  registry path `0x140a52608`, log tag `0x140a52368`, trusted domains `0x140a52390`
  (`covenanteyes.com`) / `0x140a523a8` (`cvnt.net`), decision strings `0x140a4ef08` (`now`) /
  `0x140a4eee0` (`later`) / `0x140a499e8` (`none`), ` - manual` `0x140a52558` /
  ` - automatic` `0x140a52568`, `Returning (0): Update ` `0x140a523e8` /
  `Returning (1): Update ` `0x140a52428` / `Returning (-1): error` `0x140a523b8`,
  `Silent upgrades have been disabled for ` `0x140a52578`,
  `Returning (0): silent upgrade are disabled ` `0x140a525a0`, `getClientUpdate` `0x140a4f098`,
  `ApiClientUpdate.cpp` `0x140a4efd0`, `Most recent updates to Victory Shield` `0x140a4ee18`.
- Dialog resources: DLGTEMPLATEEX 197 `0x140c03a98`, 203 `0x140c03be0`, 217 `0x140c042b0`
  (TDI text `0x140c0433c`) — parsed from the `.rsrc` section (`0x140bc1000`-`0x140c0a9b0`) of
  `re/samples/00-baseline/VictoryShield.exe`.
- `WinSparkle.dll` (`C:\Program Files\CE\WinSparkle.dll`, 2,278,336 B, fetched 2026-09-24):
  32 exports incl. `win_sparkle_set_dsa_pub_pem`; strings
  `http://www.andymatuschak.org/xml-namespaces/sparkle#dsaSignature`,
  `#installerArguments`, `Missing DSA signature!`, `Invalid update signature`,
  `Cannot read DSA public key from PEM`, `DSAPEM`, `DSAPub`, `UpdateTempDir`,
  `Launching the installer.`, `Would you like to download our new version (%s) now?`.
- Logs: `re/samples/data/logs/upgrade-126428.log:27-56,99,103-110,118-153,190-267,296-305,441-460,487-669,1061-1063,1285-1304,1320`;
  `re/samples/data/logs/major-3600.log` + `major-5616.log` (appcast cadence + decision lines,
  summarized in `re/findings/02-artifacts/logs.md` "Cadence"/"Appcast result lines");
  `re/findings/01-dynamic-recon/live-surface.md` §d (UninstallString `-removeonly` GUID).

## Linux-reimplementation notes

- The update channel design is small and portable: a per-build feed name
  (`appcast-<version>-<branch>-<sha>`) or — better — one JSON endpoint that takes
  `{app, version, branch, sha, os, arch}` and returns `{recommendation: now|later|none,
  version, download_url, critical}`. The `recommendation` enum is the whole decision policy;
  do version comparison server-side as CE does (the client performs **no** local version
  compare — `now` is trusted from the server).
- Keep a **download-URL allowlist** (scheme + domains) exactly as `FUN_14028f280` does, but
  add real signature verification (minisign/ed25519 over the package) — CE ships DSA machinery
  in its WinSparkle fork yet never enables it; a clean-room client should not repeat that.
- Schedule: one check per 24 h anchored at process start (CE pins `last_check_time = now` at
  init and uses interval 86400 s); server time sync is a separate hourly concern
  (`re/findings/02-artifacts/logs.md`).
- Silent-apply policy: only `critical` updates apply without user action in a headless/system
  context; a `disable_silent_upgrade` flag with a *short* grace window (CE: 1 day) is enough
  to let an admin pause auto-updates.
- Upgrade transaction hygiene (copy CE's order): flush pending uploads → stop watchdog and
  services (bounded "at all costs" stop) → remove legacy components → stage post-reboot file
  deletes → migrate state to a `PreviousConfiguration` backup → create fresh per-version state
  dir (`…/VictoryShieldv010.001.044/` naming = version-encoded data dirs, good for
  side-by-side rollback) → register/replace service units → start. Record
  `install_mode=upgrade` and keep an explicit product GUID for uninstall.
- Do **not** copy the reboot UX: no forced reboots, no disabling third-party drivers (the TDI
  dialog is the fossil of exactly that behavior).

## Open questions

1. **Who launches the installer with which flags?** The log only shows `Install mode: silent`
   and an elevated wrapper; the silent flag is [INFERENCE] passed by the WinSparkle fork's
   installer handoff (fork exports `win_sparkle_set_user_run_installer_callback`, unused by
   the client) or embedded in the package wrapper. The 13-minute gap between the 00:08:51
   "Update now" decision and the 00:21:52 install start is unexplained by logs —
   [INFERENCE: download time for the ~100 MB payload, or a UI prompt wait in the interactive
   session]. No UI session activity is logged.
2. **`critical` token on `Update none` lines**: the 09-22 `Update none,  - automatic,
   critical` line prints `critical` although no update was parsed; `FUN_140246fd0` only fills
   the `critical` field for `recommendation` `now`/`later` — [INFERENCE] the flag is
   stale/uninitialized for `none`, or the outer function reads `payload.critical`
   independently (the middle of `FUN_14028f560` is ~40 KB and elided by the decompiler bridge;
   the field-copy region was not fully recovered).
3. ~~`FUN_140201cd0` matching~~ — resolved: exact-or-dot-suffix match (see §2).
4. **Dialog 217 trigger**: the code path that opens the TDI/reboot dialog (resource 217) was
   not located (MFC resource-ID loading; no string xrefs). Its 30-second countdown and the
   actual `Reboot` action (presumably `ExitWindowsEx`/shutdown) are unverified.
5. **`getClientUpdate` endpoint host** is not referenced by name in `VictoryShield.exe`
   (`HttpClient`/`Uri` plumbing is generic; `re/findings/02-artifacts/logs.md` puts CE backend
   traffic on `api.cvnt.net`) — the exact URL/route is owned by the later backend pass.
6. The `5ee102b0-/f51102b0-/b41102b0-dfed-11eb-a383-b32532406870` GUIDs next to
   `applyClientUpdateOverrides`/`recommendation` were not decoded (likely per-channel override
   identifiers for the QA override file).
