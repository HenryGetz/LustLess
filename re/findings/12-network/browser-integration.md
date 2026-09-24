# Browser integration surface (10.1.44)

Scope: the `firefox-integrated-extension@covenanteyes.com` string and everything it touches in `vs-config.exe`, the Chromium/IE extension mechanisms in the same code, the browser secure-DNS (DoH) policy management, and a live-VM verdict on what browser integration actually exists in 10.1.44. Companions: `filter-surface.md` (filter enforcement), `re/findings/16-updater/updater.md` §9c (DoH policy settings catalog), `re/findings/02-artifacts/logs.md` (installer browser-integration log lines). Non-goals: updater/UI internals.

## What it does

**VERDICT summary:**
- **(a) Firefox extension — LEGACY, absent on this box.** The extension ID `firefox-integrated-extension@covenanteyes.com` exists in `vs-config.exe` only inside **removal** code (`InstallLibrary\src\BrowserExtensions.cpp`): it deletes the registration value from `HKLM\SOFTWARE\Mozilla\Firefox\Extensions` (both registry views) and destroys the extension directory it points at. The live VM has **no Firefox** (no install dir, no `%APPDATA%\Mozilla`, no profiles) and the registration value is **absent** (key `HKLM\SOFTWARE\Mozilla\Firefox\Extensions` exists but is empty); the 10.1.44 upgrade log confirms the removal attempted and found nothing (`RegQueryValueExW (error code 2)`, `upgrade-126428.log:286-295`).
- **(b) Chromium force-install — ABSENT on this box; mechanism exists only as uninstall cleanup.** vs-config can write `Software\Policies\Google\Chrome\ExtensionInstallForcelist` (machine GPO) and remove the external-extension key `SOFTWARE\Google\Chrome\Extensions\bfegkegffcbgpfmemahhkgnbkocmbain` — but the only caller in the binary passes the Registry.pol delete-marker `**del.1`, i.e. it **clears** the force-install entry. Live: no `ExtensionInstallForcelist`/`ExtensionSettings` values exist for Edge, Chrome, or Brave; no Chrome or Firefox is installed (browsers on the box: Edge + Brave). The *install* side (if it ever ran) belongs to the installer DLL (`CISCustomDLLApp`), which is not in the analyzed set.
- The only browser integration **active** in 10.1.44 is **secure-DNS (DoH) lockdown**: `ce::sys::disableBrowserSecureDns` writes per-browser policy values (present live: Edge `BuiltInDnsClientEnabled=0`, `DnsOverHttpsMode=off`; Chrome `DnsOverHttpsMode=off`; Brave `DnsOverHttpsMode=off`, `TorDisabled=1`; Firefox `DNSOverHTTPS\Locked=1`, `Enabled=0`), i.e. CE forces all browsers off DoH so its DNS-level filter cannot be bypassed.
- `VictoryShield.exe` and `UWPApp.dll` contain **zero** browser-extension strings (negative result): no Firefox/Chrome/Edge extension IDs, no `ExtensionInstallForcelist`, no WebView2 (`15-ui/ui-architecture.md` §3). All browser handling lives in `vs-config.exe` (management plane) + the installer.

## Mechanism

### 1. `vs-config.exe` — `InstallLibrary\src\BrowserExtensions.cpp` (all removal)

String block `0x14038dd80`–`0x14038e320` (source path `D:\actions-runner\_work\w\p\x64\InstallLibrary\src\BrowserExtensions.cpp` `0x14038de10`), consumed by `removeBrowserExtensions` = **`FUN_14000b3b0`** (`VSConfig\src\VsDestroyer.cpp` line 0xAB, log "removing browser extensions" `0x14038bad0`), which runs, in order: Firefox (both registry views) → Chrome → IE CLSID → IE regsvr32. Call chain (Ghidra callers, each one-caller-deep): `FUN_14000cb80` (VsDestroyer sequence, bound from the `remove-vs` task table `0x14038d380`) → `FUN_14000b3b0` → wrappers `FUN_14002e030`/`FUN_14002e210`/`FUN_14002e7c0`/`FUN_14002e9a0`/`FUN_14002ed60` → implementations below.

**Firefox — `RemoveFirefoxExtension` (two variants):**
- `FUN_14002be30` ("remove Firefox extension") and `FUN_14002c0a0` ("remove Firefox extension (without redirection)" `0x14038de98`) are near-identical: they build the key path **`SOFTWARE\Mozilla\Firefox\Extensions`** (`0x14038dd80`, 0x23 chars), open it via two different registry helpers (`FUN_1400b1db0` vs `FUN_1400b1e80(out, 0, key)` — [INFERENCE: default vs explicit-WOW64-view open, hence "without redirection"]), then twice use the value name **`firefox-integrated-extension@covenanteyes.com`** (UTF-16 `0x14038ddb0`, 0x2D chars):
  1. `key->getValue(name)` (vtable+8) → read string data (vtable+0x20) → hand the path to `FUN_1400358e0(path, 0)` [INFERENCE: `destroyPath`-family — deletes the extension directory the registration value points at; the `destroyPath`/`destroying file:` strings are at `0x14038f030`/`0x14038ef20`];
  2. `key->removeValue(name)` (vtable+0x30) — deletes the registration value.
- This is the classic pre-74 Firefox mechanism: `HKLM\SOFTWARE\Mozilla\Firefox\Extensions` = value `"<extension-id>"` → `"<path to extension dir>"`; Firefox imports it at first run. Nothing in the analyzed binaries *creates* this value (install side = installer DLL, not analyzed).

**Chrome — `RemoveChromeExtension` = `FUN_14002cf70` (decompiled):**
1. `FUN_14002c320(empty, "**del.1")` → `updateChromeGroupPolicy` (log "install Google Chrome GPO" `0x14038df98`, reused for removal) → `FUN_14002c4d0` (decompiled): `RegCreateKeyExA(hKey, "Software\\Policies\\Google\\Chrome\\ExtensionInstallForcelist", …)` on the **machine GPO root** (opened via `OpenLocalMachineGPO`/`GetRegistryKey(GPO_SECTION_MACHINE)` helpers, strings `0x14038e510`/`0x14038e528`), then `RegDeleteValueA(key, "1")` (fixed 1-char name at `DAT_14038ba00` = `"1"`) and `RegSetValueExA(key, "**del.1", REG_SZ, "", 0)` — the Registry.pol **`**del.<name>`** marker that removes force-install entry `1` when the policy is applied. Errors log "Unable to create policy key"/"Unable to set policy key" (`0x14038df40`/`0x14038df60`).
2. Opens **`SOFTWARE\Google\Chrome\Extensions\bfegkegffcbgpfmemahhkgnbkocmbain`** (`0x14038e0c0`) and deletes its **`update_url`** value (UTF-16 `0x14038e10e`) — the "external extensions" auto-install registration (value `update_url` pointing at a hosted update manifest) for CE's Chrome Web Store extension ID `bfegkegffcbgpfmemahhkgnbkocmbain`.
- So the **known Chrome extension ID is `bfegkegffcbgpfmemahhkgnbkocmbain`** (evidence: registry-key string above) [INFERENCE: the Covenant Eyes Web Store listing]. vs-config only ever *removes* both registrations; `updateChromeGroupPolicy`'s write primitive is generic (name+data pair) but its single call site passes the delete marker.

**IE — `RemoveIEExtension` + `UnregisterIEExtensions`:**
- `RemoveIEExtension` (`FUN_14002e9a0` wrapper): deletes value **`{927BD2E1-2287-49D2-AE71-95F492CE662E}`** (`0x14038e198`) under `SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Ext\CLSID` (`0x14038e158`; "failed to delete IE extension CLSID" `0x14038e1f0`).
- `UnregisterIEExtensions` (`FUN_14002ed60` wrapper): runs `regsvr32.exe` (`0x14038e260`) on the COM DLLs in `\CE\extensions\ie\x86\` and `\CE\extensions\ie\x64\` (`0x14038e2b8`/`0x14038e2d0`, module stem `ceie` `0x14038e270`) — matches the installer log "IE extensions unregistered at `C:\Program Files\CE\extensions\ie\x86` and `…\ie\x64`" (`fresh-install-4260.log:341-353`, `upgrade-126428.log:273-285`).
- `manageInternetExplorerEPM` ("disable IE EPM policy" `0x14038e0a8`): writes `Isolation`/`PMIL` (`0x14038dff0`/`0x14038dffc`) under `Software\Policies\Microsoft\Internet Explorer\Main` (`0x14038dfb8`) — disables IE Enhanced Protected Mode so the CE BHO keeps working [INFERENCE from value names].

### 2. Browser secure-DNS (DoH) lockdown — the active integration

`ce::sys::disableBrowserSecureDns` (`FUN_1400a85a0`, tag `0x140399c60`, "disable browser secure dns" `0x140399c40`; vs-config tasks `disable-secure-dns` `0x14038d440` / `revert-secure-dns` `0x14038d458`) and its revert/check siblings are catalogued in `re/findings/16-updater/updater.md` §9c; the values are:

| value | key | written as | live on VM (2026-09-24) |
|---|---|---|---|
| `BuiltInDnsClientEnabled` | `HKLM\SOFTWARE\Policies\Microsoft\Edge\` | `0` | **`0x0` present** |
| `DnsOverHttpsMode` | `Edge\`, `Google\Chrome\`, `BraveSoftware\Brave\` | `off` | **`off` present in all three** |
| `TorDisabled` | `BraveSoftware\Brave\` | `1` (anti-circumvention) | **`0x1` present** |
| `Locked` | `Mozilla\Firefox\DNSOverHTTPS\` | `1` (policy lock) | **`0x1` present** |
| `Enabled` | `Mozilla\Firefox\DNSOverHTTPS\` | `0` | **`0x0` present** |

Log lines "Disabling Microsoft Edge settings / Disabling Brave settings / Disabling Firefox settings / Disabling Google Chrome settings" (`fresh-install-4260.log:369-375`) and browsers force-closed at install (`chrome.exe`, `firefox.exe`, `msedge.exe`, `brave.exe`, `fresh-install-4260.log:61-168`) corroborate. Purpose [INFERRED from `filter-surface.md`]: browsers must not bypass the DNS-level filter via their own DoH resolvers; Brave's Tor mode is disabled as a general circumvention vector. This is the *only* browser-side enforcement CE still performs in 10.1.44.

### 3. Live VM state (2026-09-24, read-only)

| probe | result |
|---|---|
| `dir "C:\Program Files\Mozilla Firefox"` / `(x86)` | **not present** (no Firefox install) |
| `dir "C:\Users\dolphin\AppData\Roaming\Mozilla"` | **not present** (no profiles, no `extensions\` dir) |
| `reg query HKLM\SOFTWARE\Mozilla\Firefox\Extensions` | **key exists, empty** — extension registration value absent (matches upgrade log `RegQueryValueExW (error code 2)`) |
| `reg query HKLM\SOFTWARE\Policies\Mozilla\Firefox` | only subkey `DNSOverHTTPS` (`Locked=1`, `Enabled=0`) — no `ExtensionSettings`/`Extensions` policies; no `policies.json` possible (no Firefox dir) |
| `reg query HKLM\SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist` / `ExtensionSettings` | **absent** (ERROR: not found) |
| `reg query HKLM\SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallForcelist` / `ExtensionSettings` | **absent** |
| `reg query HKLM\SOFTWARE\Policies\BraveSoftware\Brave\ExtensionInstallForcelist` | **absent** |
| `reg query HKLM\SOFTWARE\Google\Chrome\Extensions` (+ `WOW6432Node`) | **absent** (no `bfegke…` external-extension key) |
| `reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Ext\CLSID` | **absent** (IE BHO registration gone) |
| `dir "C:\Program Files\CE\extensions"` | **absent** (IE extension DLLs already unregistered/removed by the upgrade) |
| browsers installed | **Edge** (`C:\Program Files (x86)\Microsoft\EdgeCore\153.0.4234.48`) + **Brave** (`C:\Program Files\BraveSoftware`); **no Google Chrome**, **no Firefox** |

### 4. Negative results in the other analyzed binaries

- `VictoryShield.exe`: string sweep for `firefox|chrome|edge|brave|mozilla|extension|forcelist|update_url` over `vs_str.txt` (34,793 VA-tagged strings) yields only unrelated hits (OpenSSL X509 "extensions", sqlite `load_extension`, `Software\...\Policies\Explorer/Network/Comdlg32` MFC paths). No browser-extension ID, no policy path, no extension API. It only opens URLs in the default browser (`openUrlBestWay`, `15-ui/ui-architecture.md` §3).
- `UWPApp.dll`: nothing (XAML sign-in control only; grep of `uwp_str.txt` for browser/DNS/filter terms: no hits besides PNG base64).

## Evidence

- Ghidra MCP (project `CE`, program `vs-config.exe`), decompiled: `FUN_14000b3b0` (`removeBrowserExtensions`, VsDestroyer.cpp — ordered removal chain), `FUN_14002be30`/`FUN_14002c0a0` (Firefox value+dir removal ×2 registry views), `FUN_14002cf70` (`RemoveChromeExtension`: `**del.1` GPO write + `update_url` delete), `FUN_14002c320` (`updateChromeGroupPolicy` log wrapper), `FUN_14002c4d0` (`RegCreateKeyExA` on `ExtensionInstallForcelist` + `RegDeleteValueA("1")` + `RegSetValueExA("**del.1","")`); xrefs: extension-ID string `0x14038ddb0` → `FUN_14002be30`/`FUN_14002c0a0`; `SOFTWARE\Mozilla\Firefox\Extensions` `0x14038dd80` → same; `ExtensionInstallForcelist` `0x14038dec8` → `FUN_14002c4d0`; Chrome key `0x14038e0c0` → `FUN_14002cf70`; caller chain each exactly one level (`get_function_callers`).
- vs-config strings (VA map from `re/samples/00-baseline/vs-config.exe`): `0x14038dd80` (`SOFTWARE\Mozilla\Firefox\Extensions`), `0x14038ddb0` (Firefox ext ID), `0x14038de10` (BrowserExtensions.cpp), `0x14038de60`–`0x14038de98` (RemoveFirefoxExtension + log names), `0x14038dec8` (`Software\Policies\Google\Chrome\ExtensionInstallForcelist`), `0x14038df08`–`0x14038df98` (`updateChromeGroupPolicy` + errors), `0x14038dfb8`–`0x14038e0a8` (IE EPM), `0x14038e0c0`/`0x14038e10e` (`bfegkegffcbgpfmemahhkgnbkocmbain` + `update_url`), `0x14038e128`/`0x14038e140` (RemoveChromeExtension), `0x14038e158`–`0x14038e300` (IE CLSID/regsvr32), `0x14038e510`–`0x14038e550` (GPO API), `0x14038bab8`/`0x14038bad0` (`removeBrowserExtensions`), `0x14038d380` (`remove-vs`), `0x14038d440`/`0x14038d458` (`disable-secure-dns`/`revert-secure-dns`), `0x140399aa8`–`0x140399e00` (DoH policy keys + "Disabling … settings" logs); `DAT_14038ba00` = `"1"`.
- VM (2026-09-24, `reg`/`dir` natives): registry/file results tabulated in §3; DoH policy values as listed in §2.
- Installer logs: `re/findings/02-artifacts/logs.md` §"Browser extensions/integration" (IE unregister, Firefox removal error 2, DoH disable ×4, browser kill list).
- Negative sweeps: `grep` of `vs_str.txt`/`uwp_str.txt` (VA-tagged string dumps of VictoryShield.exe/UWPApp.dll) for browser/extension terms — no relevant hits.

## Linux-reimplementation notes

- No browser extension is needed for a LustLess-style client: CE 10.1.44 itself ships none that is live (the Firefox/Chrome/IE pieces are uninstall leftovers of older products). Prefer resolver-level enforcement + optional browser-policy hardening.
- The one pattern worth porting is the **DoH lockdown**: if your enforcement is DNS-based, manage browser policies so browsers cannot re-route DNS (Chrome/Edge/Brave: `DnsOverHttpsMode=off` via `/etc/opt/chrome/policies/managed/…`; Firefox: `policies.json` with `DNSOverHTTPS {Enabled:false, Locked:true}`), and disable Brave Tor-like bypass modes if your threat model includes them. CE's exact policy values are a proven minimal set.
- If an extension is ever wanted for URL-level visibility, ship it as a proper WebExtension per browser with enterprise policy install (`ExtensionInstallForcelist`/`ExtensionSettings`/Firefox `ExtensionSettings`) — CE's legacy registry mechanisms (`Mozilla\Firefox\Extensions` values, `Google\Chrome\Extensions\<id>\update_url`) are deprecated on modern browsers and should not be copied.

## Open questions

- Install-side registration: which component *created* the Firefox extension value / Chrome forcelist entry in older versions — the installer DLL (`CISCustomDLLApp`/`CCEInstallApp`, not in the analyzed set) or a CE server-side installer package? The analyzed binaries only remove.
- Chrome extension `bfegkegffcbgpfmemahhkgnbkocmbain`: its Web Store listing/permissions and whether any CE version actually force-installed it (no `ExtensionInstallForcelist` evidence on this box) — answerable from the installer package or CE release notes, not from these binaries.
- Whether the IE BHO (`ceie` DLL, CLSID `{927BD2E1-2287-49D2-AE71-95F492CE662E}`) ever performed URL capture for `has_url_accountability` (its binary shipped under `C:\Program Files\CE\extensions\ie\` is already removed on the VM; if an older sample is obtained, that is a separate archaeology task).
- `manageInternetExplorerEPM`'s exact `Isolation`/`PMIL` value payload semantics [INFERENCE recorded in §1].

MUST be answered from `VictoryShieldCommService.exe` once analyzed (relevance to this pass): confirm that **URL filtering/`has_url_accountability` enforcement needs no browser extension at all** — i.e. the service family performs it at the resolver/connection level (and/or via the `global_domain_overrides`/`custom_domain_overrides` tables), which is the premise behind shipping zero live browser integration in 10.1.44; and whether the service ever manages browser policy/extension state itself (vs-config and the installer are the only known writers).
