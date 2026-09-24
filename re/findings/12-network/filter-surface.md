# Filter state machine, health checks, and enforcement surface (10.1.44)

Scope: the DNS/URL filtering state model (`has_dns_filtering`/`has_url_filtering`/`user_dns_filter` and where each lives), the UI toggle path (`handleDnsFilterServiceSwitch` → queue code `0x53`), the filtering-relevant settings row, the `testDnsBlocking` health check, the "Filter guardian" dialog verdict (closes `15-ui/signin-and-settings.md` open question), and how `circumventions` events are produced. Companions: `browser-integration.md`, `re/findings/15-ui/ui-architecture.md` (IPC/`CE_SPYMapObj` mechanics), `re/findings/16-updater/updater.md` §9 (vs-config settings catalog), `re/findings/02-artifacts/local-db.md`/`logs.md`. Non-goals: CommService/classifier internals (explicitly deferred, see Open questions).

## What it does

10.1.44 web filtering is a **user-mode, resolver-level filter**: per-user policy delivered by the CE backend (`/v2/user/{username}.json` service flags + `/v2/user/{username}/filter/settings/dns.json` filter config + domain-override lists), cached locally in SQLite (`user_info`, `user_dns_filter`, `global_domain_overrides`, `custom_domain_overrides`), published into `CE_SPYMapObj` for peer components, and enforced by the comm-service family against a **CleanBrowsing DoH** resolver (`https://dns.cleanbrowsing.org/doh/adult-filter` default). The UI binary (`VictoryShield.exe`) owns the state machine, the settings refresh, the health probe (`http://covenanteyesfilter.com/healthcheck`), and the `circumventions` writer; it does **not** resolve or intercept user DNS (the legacy 10.1.1 local DNS proxy is gone/disabled: `DnsProxyDisable=1`, no port-53 listener — `re/findings/03-runtime/network-capture.md`). The "Filter guardian" break-glass dialog ships in the resources but is **dead UI** in this build (see §6).

## Mechanism

### 1. Where the state lives

**a) Backend → in-memory `CeUserSettings` object.** Service flags arrive in `/v2/user/{username}.json` (endpoint template `0x140a4f8e0`; "get generic user information for user '" `0x140a4fc38`) under a `services` object with keys `accountability`, `filter`, `screen accountability`, `url accountability`, `url filtering`, `dns filtering`, `enabled` (`0x140a4fed8`–`0x140a4ff38`) plus `firstName`/`lastName` (`0x140a4ff50`/`0x140a4ff60`). They deserialize ("deserialize has_dns_filtering" `0x140a3e498`, "deserialize has_url_filtering" `0x140a3e4b8`, likewise `has_screen_accountability`/`has_url_accountability`) into the user-settings object whose `UserInfo` part is embedded at `+0x10` (proved below). Field layout of `UserInfo` (from the `<UserInfo: …>` dumper `FUN_14020c600`, decompiled):

| `UserInfo` offset | bool/string | label in dump | `CeUserSettings` offset |
|---|---|---|---|
| `+0x10` | string | `first-name=` | `+0x20` |
| `+0x30` | string | `last-name=` | `+0x40` |
| `+0x50` (string at `+0x60`, cap 0x10) | string | `user-id=` | `+0x60` |
| `+0x70` | string | `email=` | `+0x80` |
| `+0x90` | bool | `active=` (`is_active`) | `+0xA0` |
| `+0x91` | bool | `self-override` (`can_override`) | `+0xA1` |
| `+0x92` | bool | `panicked=` (`is_panicked`) | `+0xA2` |
| `+0x93` | bool | `accountability=` (`has_accountability`) | `+0xA3` |
| `+0x94` | bool | `filtering=` (`has_filtering`) | `+0xA4` |
| `+0x95` | bool | `screen-accountability=` (`has_screen_accountability`) | `+0xA5` |
| `+0x96` | bool | `url-accountability=` (`has_url_accountability`) | `+0xA6` |
| `+0x97` | bool | **`url-filtering=` (`has_url_filtering`)** | `+0xA7` |
| `+0x98` | bool | **`dns-filtering=` (`has_dns_filtering`)** | `+0xA8` |

**b) SQLite tables.** The same flags persist via `UserInfoSqliteTable::set` ("Storing user information for user:" `0x140a3e528`) into table **`user_info`** — column names `first_name`, `last_name`, `is_active`, `can_override`, `timezone`, `has_filtering`, `has_screen_accountability`, `is_panicked`, `has_accountability`, `has_url_filtering`, `has_url_accountability`, `has_dns_filtering` (type `TINYINT`) at `0x140a3e380`–`0x140a3e4d8`. The filter config persists in table **`user_dns_filter`** (`UserDnsFilterSqliteTable`, `UserDnsFilterSqliteTable::set` `0x140a3d5f0`, `SELECT * FROM … WHERE username = ?` `0x140a3d5b8`):

| column | meaning | string VA |
|---|---|---|
| `username` | CE user key | `0x140a3d5b8` (WHERE clause) |
| `over_https_url` | DoH resolver endpoint ("deserialize over_https_url" `0x140a3d5d0`) | `0x140a3d598` |
| `clear_browsing_level` | CleanBrowsing level (`clean_browsing_level` JSON key `0x140a4fd10`; display names "Adult Filter" `0x140a4fd28`, "Family Filter" `0x140a4fcd0`) | `0x140a3d560` |
| `ipv4_primary` / `ipv4_secondary` | plain-DNS fallback servers | `0x140a3d550` / `0x140a3d588` |
| `ipv6_primary` / `ipv6_secondary` | plain-DNS fallback servers | `0x140a3d578` / `0x140a3d5a8` |

Default when absent: `https://dns.cleanbrowsing.org/doh/adult-filter` (`0x140a3d510`; materialized as a global `std::string` by static-init `FUN_14012c880` and 35 sibling initializers, all xrefs to that VA are static inits) and — per the migration log — level "Standard Blocking" ("No DoH URL found. Setting CleanBrowing DoH level to Standard Blocking" `0x1408e2e30`, in `FUN_1403002f0` = `migrateUserSettings` DNS-filter migration, "Migrating DNS Filter settings for user " `0x1408e2e00`). Client-side level vocabulary: "Standard Blocking" `0x140a4fd38`, "Strong Blocking" `0x140a4fce0`, "Blocking Enabled" `0x140a4fcf0`; the tray shows "Blocking level set to " + level ("get blocking level" worker, `FUN_1402b6bd0`) or "Add filtering" (`0x1408dc4d8`) when no filtering service.

**c) Which database.** Two SQLite databases exist: **`ce-file`** (`0x140a4bf10`) and **`ce-user-file`** (`0x140a4bf18`), both opened by the central opener `FUN_1402a1a40` (`CommonLibrary\src\CentralDataDirectory.cpp`, `0x140a46a10`; WAL/SHM companion names `ce-file-shm/-wal`, `ce-user-file-shm/-wal` `0x1408d8ed0`–`0x1408d8f08`). The live `ce-file` schema contains `install_metadata`, `logins`, `metrics`, `circumventions`, `switch_users`, `dns_activity` (`re/findings/02-artifacts/local-db.md`) but **not** `user_info`/`pdl_info`/`user_dns_filter`/`user_login`/`screenshot_telemetry`/`telemetry`/`global_domain_overrides`/`custom_domain_overrides` — all of which have table classes in VictoryShield.exe's SqliteLibrary. [INFERENCE] Those per-user tables belong to `ce-user-file`, whose on-disk form is the encrypted container documented in `re/findings/02-artifacts/user-file.md` (12,288 B, no SQLite magic — encrypted at rest). Confirmed schema-level facts only for `ce-file`; the `ce-user-file` table binding is an open question for the CommService pass.

**d) `CE_SPYMapObj` flag mapping (closes the UiPass open question).** `CVictoryShieldView::setGlobalUserState` = `FUN_1402c6d00` (decompiled), under mutex `CE_SPYMutexObj`, writes byte flags from the settings object into the map (map base = `view+0x118`):

| map offset | source | semantics |
|---|---|---|
| `+0x19C` | settings `+0xA3` | `has_accountability` |
| `+0x1A0` | settings `+0xA4` | `has_filtering` |
| `+0x1A4` | settings `+0xA1` | `can_override` (self-override) |
| `+0x1A8` | constant 0 (dword) | — |
| `+0x1B0` | settings `+0xA2` | `is_panicked` |
| `+0x50AE4` | settings `+0xA5` | `has_screen_accountability` |
| `+0x50AE8` | settings `+0xA6` | `has_url_accountability` |
| `+0x50AEC` | settings `+0xA8` | **`has_dns_filtering`** |
| `+0x50AF0` | settings `+0xA7` | **`has_url_filtering`** |
| `+0x28` | user object's `vtable+8` string (strncpy, 0xFE) | signed-in username |
| `+0x18` | settings `+0x60` (strncpy, 0x10) | `user-id` |

After the writes it signals the peer object at `view+0x328` (vtable+8). Failure path logs "Could not obtain mutex or invalid global data pointer" (`0x1408dc300`).

### 2. UI toggle path — `handleDnsFilterServiceSwitch` → `USER_SETTINGS_CHANGE` (0x53)

Settings refresh (per `15-ui/signin-and-settings.md` §3: `updateUserSettings`/`updateUserSettingsWorker` `0x1408e1770`/`0x1408e17e8`, `StoreUserSettingsManager::…::refreshUserSettings` `0x140a50420`) produces an old→new settings pair; the diff handler **`FUN_1403197c0`** (decompiled; called from the refresh worker) compares field-by-field and fires side effects only on change:

- `has_screen_accountability` (`+0xA5`) flip, **or** content change of the sub-object at settings `+0x1F8` vs old `+0x1F0` (vtable+0x10 compare) → updates map `+0x50AE4` and calls **`CVictoryShieldView::handleScreenAccountabilityServiceSwitch` = `FUN_1402c1b80`** (name string `0x1408dc380`; xref-verified) — reconfigures PDL/screen capture ("Configured PDL due to service switch" `0x1408dc3c0`).
- `has_dns_filtering` (`+0xA8`) flip, **or** content change of the sub-objects at settings `+0xB8`/`+0x188`/`+0x1C0` vs old `+0xB0`/`+0x180`/`+0x1B8` [INFERENCE: the `user_dns_filter` config and the custom/global domain-override lists] → updates map `+0x50AEC` and calls **`CVictoryShieldView::handleDnsFilterServiceSwitch` = `FUN_1402c0bf0`** (VictoryShieldView.cpp line 0x4F6; name string `0x1408dc3f8`).

`FUN_1402c0bf0` sends the event through `ce::sendCommServiceNotification` (`FUN_1402cc780(event, 0x53)` → `FUN_1402cc960`): the event object is **serialized by its `vtable+8`** into a payload string, the code maps to the name `USER_SETTINGS_CHANGE`, and the pair is enqueued on Boost.Interprocess queue `ce_user_event_message_queue` (3-attempt retry; log `"Sending (N) <NAME> event message data: <payload>"` `0x1408deb28`, name string `0x1408dea40`). **Payload = the serialized settings/event string** — the `<UserInfo: …>`/`<CeUserSettings: >`-style dump of the new settings (dump format `FUN_14020c600`; `<CeUserSettings: >` `0x140a3e760`); the receiving comm service re-reads authoritative state from the DB/shared map. [INFERENCE on the exact event class; the serialization call site is `FUN_1402cc780`'s `vtable+8` invoke.] The sibling `USER_LOGOUT` (0x4c) and the rest of the code vocabulary are in `ui-architecture.md` §4a.

### 3. Filter provisioning (backend → `user_dns_filter`)

`FUN_14025f270` ("get DNS Filter information for user '" `0x140a4fd58`) issues the authenticated GET **`/v2/user/{username}/filter/settings/dns.json`** (endpoint `0x140a4f970`) through `AuthProvidedHttpClient` and parses the response with the callback `FUN_14025e4d0`, whose RTTI is literally `GenericDnsFilter(const HttpResponse&)` — the parsed `GenericDnsFilter` (DoH URL + resolver IPs + `clean_browsing_level`) is stored by `UserDnsFilterSqliteTable::set` ("Storing user DNS Filter information for user:" `0x140a3d650`, "Failed to store user DNS Filter information: " `0x140a3d620`; writer call sites `FUN_1401600e0` (settings stash) and `FUN_1403002f0` (migration)). Domain-override lists come from **`/v2/client/filter/settings/domains.json`** (`0x140a4f8a8`, global) and **`/v2/user/{username}/filter/settings/domains.json`** (`0x140a4f910`, per-user) with incremental sync `?from_version=` (`0x140a4f8d0`; "Processed N additions and M removals from the custom domain override list from version V" `0x140a4fa10`; parsers `apiUserCustomDomainOverridesHelpers::parser` `0x140a4fa70`, `apiGlobalDomainOverridesHelpers::parser` `0x140a4fe50`) into tables `global_domain_overrides`/`custom_domain_overrides` (`GlobalDomainOverridesSqliteTable::add` `0x140a3efc0`, `CustomDomainOverridesSqliteTable::add` `0x140a3f0d8`, both with `getVersion`).

### 4. Enforcement path from the analyzed binaries

- **CleanBrowsing/DoH references (complete list in analyzed set):** VictoryShield.exe — default endpoint `https://dns.cleanbrowsing.org/doh/adult-filter` (`0x140a3d510`) + `user_dns_filter.over_https_url` plumbing (§1b); a full statically-linked **libcurl DoH client** (curl `lib/doh.c` strings: `DoH request %s` `0x1409707d8`, `a DoH request is completed, %u to go` `0x1409707b0`, `Failed to encode DoH packet [%d]` `0x1409707e8`, `Content-Type: application/dns-message` `0x140970810`, `[DoH] A: %u.%u.%u.%u` `0x140970850`, `[DoH] TTL: %u seconds` `0x140970838`, `CNAME: %s` `0x140970888`, `Could not DoH-resolve: %s` `0x1409708a0`). vs-config.exe — none (only browser DoH-*policy* management, `browser-integration.md`). UWPApp.dll — none.
- **No local resolver in 10.1.44**: `DnsProxyDisable=1` live (`re/findings/03-runtime/network-capture.md`), no port-53/NRPT/WFP footprint (`re/findings/01-dynamic-recon/live-surface.md`), and the legacy 10.1.1 proxy (loopback `127.0.0.2`, "DNS Filter server(s)"/"DNS User server(s)" timeouts, `DnsProxyRequest::handleDnsTimeout`, `enforceDNSSettingsPeriodically` — `re/findings/02-artifacts/logs.md`) is only referenced as a teardown path ("Deactivating DNS proxy" / "DNS Proxy already destroyed"). [INFERENCE] Actual query interception for `has_dns_filtering` users is performed by the comm-service family (deferred), driving resolution through the `over_https_url` DoH endpoint and recording `dns_activity` rows (`domain`, `process_id`, `process_name`, `ip`, `resolution_type`, `resolution_datacenter`, `resolution_time_ms` — `local-db.md`).
- `has_url_filtering` enforcement (URL-level block/allow using the domain-override tables) has **no implementation in the analyzed binaries** — negative result; deferred to CommService.

### 5. Filtering-relevant settings row

Registry surface `HKLM\SOFTWARE\Covenant Eyes\Victory Shield` (vs-config settings lens = HKLM only, `re/findings/16-updater/updater.md` §9 hive binding). Catalog rows below are cited from UpdaterPass §9a and extended only where filtering-relevant:

| value | type | semantics | evidence |
|---|---|---|---|
| `DnsProxyDisable` | REG_DWORD bool (lens default 1) | **1 = the (legacy) DNS-proxy enforcement is off**; written by `ce::local_comm_service::disableDnsProxy`/`enableDnsProxy` ("stop/start dns proxy" — `FUN_14008ff00`(=1)/`FUN_14008f9e0`(=0)) and set `=1` by the 10.1.1→10.1.44 upgrade migration (`upgrade-126428.log:1171`). Live value `01000000` ⇒ proxy off; 10.1.44 filtering does not depend on it | vs-config `0x140394a48`, read `FUN_1400214d0`; VictoryShield.exe `0x140a48728`; live reg |
| `AllowSecureSearch` | REG_DWORD bool (default 0) | read-only getter `ce::sys::settings::allowSecureSearch` = `FUN_140059300` (returns stored byte or 0); **sole consumer is the uninstall/destroy sequence `FUN_14000cb80`** (xref-verified 2026-09-24) [INFERENCE: gates whether browser "secure search" (HTTPS-search) settings are left in place/restored at removal — exact behavior inside the destroy sequence not decompiled; semantics for runtime filtering not visible in any analyzed binary] | vs-config `0x1403949e8`, tag `0x140394a10`; callers: `FUN_14000cb80` only |
| `DnsFromDhcp` / `DnsAddresses` / `ProxyAddress` | per-adapter under `…\Victory Shield\NetworkInterfaces\{IPv4\|IPv6}\<adapterId>` | saved original DNS/proxy config for restore (`restoreDnsConfigFor` writes `NameServer` back) — the backup half of the 10.1.1 DNS-pinning enforcement | `0x140394750`/`0x140394768`/`0x140394848`; UpdaterPass §9a/§9b |
| *(per-user DB)* `user_dns_filter.over_https_url`, `.clear_browsing_level`, `.ipv4_primary/secondary`, `.ipv6_primary/secondary` | SQLite | the actual filter configuration consumed by the resolver path (§1b/§3) | `0x140a3d540`–`0x140a3d5a8` |
| *(config.ini)* `dns-popup-disabled`, `filter-popup-enabled` | ini bools | UI popup gates (read by `FUN_140265410`) [INFERENCE: remnants tied to the dead Filter-guardian popups, §6] | `0x140a501a0`/`0x140a501b8` |

Browser-side DoH lockdown registry values (Edge/Chrome/Brave/Firefox policy keys) are catalogued in `browser-integration.md` §2 and are part of the same filtering posture.

### 6. Health check — `testDnsBlocking` — and the "Filter guardian" verdict

**`CVictoryShieldView::testDnsBlocking` = `FUN_1402c91a0`** (VictoryShieldView.cpp line 0x7FF): (1) checks the logged-in state (`FUN_1402c45c0` at `this+0x490`, the ProgramState lock region) and a blocking-service predicate (`FUN_1401e35d0` → `vtable+0x10`); (2) if a blocking service is active, schedules "process metrics for DNS blocking test" (`FUN_1402aade0(view, …, 3, 1)`) and the worker **`testDnsBlocking::<lambda_1>::operator()` = `FUN_1402b1aa0`** runs: it logs "Logged in with blocking service, checking if blocking is functioning correctly." (`0x1408dcc40`), builds an endpoint for **`http://covenanteyesfilter.com/healthcheck`** (`0x1408dcc90`, built via `FUN_1402008b0`), and performs one GET through the PDL HTTP client (`view+0x3C0` vtable+0x10), feeding a `std::map<std::string, CEMetricsEntry>` metrics bag. Telemetry metric names `client_cleanbrowsing_problem` (`0x140a4da48`) / `client_cleanbrowsing_success` (`0x140a4da80`) are registered (static init `FUN_140129ba0`, sites `0x140129c7f`/`0x140129caf`). **No retry loop, no dialog, no user-visible failure UX exists in the UI binary** — a failed check only becomes a metric/telemetry event. The success expectations of the healthcheck URL (what a "blocked" vs "unfiltered" answer looks like) are not determinable from the client code [INFERENCE: the URL is served by CE and is expected to fail-resolution or block when filtering is healthy; exact criterion deferred to CommService/backend].

**"Filter guardian" — VERDICT: dead UI in 10.1.44; no trigger site exists.** The dialog ships as RT_DIALOG resource **#215** (DLGTEMPLATE at `0x140c03f40`, 878 B; title "Filter guardian - Victory Shield" `0x140c03f5e`; body "Victory Shield is currently experiencing technical issues with the filter. " `0x140c03ff4` and "If you would like to continue with an unfiltered internet connection, please enter your filter guardian username and password." `0x140c040ac`; buttons Continue (control ID **1080**), Logout (**1082**); edits Username (**1083**), Password (**1009**, `ES_PASSWORD`); labels `Username:` 1084 / `Password:` 1085). Exhaustive negative evidence that nothing constructs it:

1. The resource ID 215 (`0xD7`) appears **nowhere in code**: full `.text` scans for `mov r32/r8d/r9d, 0xd7`, 16-bit immediates, `push`, and every `d7 00 00 00` dword (197 hits, all branch displacements/stack slots/MFC internals); no dialog-ID table in `.rdata`/`.data` (all dword-0xd7 occurrences are LCID/font/crypto tables).
2. No MFC data-exchange binds its controls: the only application `DoDataExchange` (`0x1402cc3a0`) binds control IDs `0x408/0x453/0x457` (a different dialog); no message-map entries with `BN_CLICKED` IDs 1080/1082 exist anywhere in `.rdata` (searched).
3. No dialog-field plumbing in app code: `GetDlgItem` callers are all MFC internals; `SetDlgItemTextA`, `EndDialog`, `CreateDialogIndirectParamA` have no code references at all (imports only).
4. The complete `CVictoryShieldView` window-message map (`.rdata` entries at `0x1408db6a0`–`0x1408dbba0`, 32-byte entries `{msg, f2, f3, pfn}`) accounts for every filter-related message: see table below. **None of them opens the guardian dialog.**

| window msg | handler | behavior |
|---|---|---|
| `0x401` | `FUN_1402b68f0` = `CVictoryShieldView::OnSpyHookAPI` | logs "OnSpyHookAPI is no longer in use!" (`0x1408dc0f0`), returns 0 — **dead legacy** |
| `0x402`, `0x404`, `0x407` | *(none)* | accepted by UIPI filter (`ChangeWindowMessageFilter`, `OnCreate` `FUN_1402b3600`) but no handler → DefWindowProc |
| `0x403` | `FUN_1402b4ad0` = `OnEndSessionCustom` | calls `FUN_1402beba0` (logoff cleanup) |
| `0x405` | `FUN_1402b4e30` = `OnForceLogout` | force-logout path |
| `0x406` | `FUN_1402b4cc0` = `OnFilterCheck` | posts `ce::event::StartLogin` (sign-in UI) |
| `0x428` | `FUN_140131e50` | **stub `return 0;`** (acknowledged, ignored) |
| `0x432`–`0x438` | `FUN_1402b65e0`/`0x1402b68a0`/`0x1402b6740`/`0x1402b6630`/`0x1402b6790`/`0x1402b6b80`/`0x1402b3260` | thin forwarders to view events (e.g. `0x435` → `createBundleUpdateRequestASAP` `0x1402c3ce0`) |
| `0x4a` (WM_COPYDATA) | `FUN_140130080` | stub `return 1;` |
| `0x218` (WM_POWERBROADCAST) / `0x2b1` (WM_WTSSESSION_CHANGE) | `FUN_1402b5df0` / `FUN_1402b7580` | power / session handling |

So neither "health-check failure" nor "filter-component window message" can show the dialog: the health path is metrics-only and the message handlers are login/logout/forwarders/stubs. The dialog text describes what break-glass *would* do — a designated "filter guardian" enters username+password → "Continue with an unfiltered internet connection"; "Logout" instead (which blocks web access per the tray semantics) — but no code performs either. [INFERENCE: the flow is a retired DNS-proxy-era feature; the template and the `filter-popup-enabled`/`dns-popup-disabled` `config.ini` flags (`0x140a501b8`/`0x140a501a0`, read by `FUN_140265410`) are remnants.]

### 7. How `circumventions` events are produced

**Producer = the UI binary's screen-capture path, via window enumeration at capture time (not hooks).**

- Window list: the statically-linked `ScreenCaptureLibrary` enumerates windows per capture (`ce::screencapture::WindowsScreen::getWindowList`, name string `0x140a50c08`; window enumeration helper `FUN_14027c4f0` calls `GetWindowTextA`; accessor singleton `FUN_14027b2c0`). Entries (stride 0x90) carry a capture-restricted flag (`+0x28`), window title (`+0x30`), and app name (`+0x50`).
- Detection: **`FUN_1402ed5f0`** (log scope `ce::pdledi::captureScreen`) walks the window list; for each window whose capture-restricted flag is set it logs "Possible circumvention: Screen capture is restricted for App: `<app>` with Window Title: `<title>`" (`0x1408e1050`) and calls `FUN_1402c66a0(view, "windows-screen-recording-not-allowed", title, app)`.
- Recording: **`FUN_1402c66a0`** ("record telemetry for circumvention" `0x1408dcf88`) builds a `CECircumventionEntry` (Ghidra vftable label `CECircumventionEntry`; `CETime` timestamp + username + `interruption_type` + `app_window_title` + `app_name`) and enqueues it at `view+0x93` (`CircumventionSqliteLogsQueue`/`QueuedActivityLogger<UCECircumventionEntry>` RTTI at `0x140b3b098`–`0x140b3b298`), then schedules the telemetry worker. The queue is drained by `CircumventionSqliteTable` (`LogSqliteTable<UCECircumventionEntry, CircumventionSqliteTableDefinition>` RTTI `0x140b543e8`–`0x140b54560`) into the `circumventions` table (`interruption_type`, `app_name`, `app_window_title`, `device_id`, `timestamp`, `timezone_offset` — `local-db.md`) with flush helper "log Circumventions" (`FUN_140263b70`, `0x140a50010`). One observed `interruption_type` value: **`windows-screen-recording-not-allowed`** (string inside `FUN_1402ed5f0`). Related family: "Circumvention: PDL transaction file removed/renamed/unknown action" (`0x1408dfc40`–`0x1408dfcc0`, PDL transaction tamper watch).
- **Negatives (explicit):** `SetWinEventHook` is **not imported** by any analyzed binary; `SetWindowsHookExA`/`UnhookWindowsHookEx`/`CallNextHookEx` are used only by the MFC framework (`AfxInitThread` CBT hook `0x140328228` + three MFC-internal callers `0x14031d8a0`/`0x1403805b8`/`0x14039e7fc`); `GetForegroundWindow` callers are all MFC modal-loop logic (`FUN_1403b33d4`, `_AfxHandleSetCursor`); the legacy spy-hook message handler `OnSpyHookAPI` is dead ("no longer in use"). There is **no window-title polling loop** outside the per-capture window list in `VictoryShield.exe`, `vs-config.exe`, `UWPApp.dll`. Whether `VictoryShieldCommService.exe`/`VictoryShieldClassifier.exe` add other `circumventions` writers is deferred to those passes.

## Evidence

- Ghidra MCP (project `CE`, program `VictoryShield.exe`), decompiled: `FUN_14020c600` (`<UserInfo:>` dumper — field offsets/labels), `FUN_1402c6d00` (`setGlobalUserState` map writes), `FUN_1403197c0` (settings diff → service-switch side effects + `CE_SPYMutexObj` writes at `+0x19C`/`+0x1A0`/`+0x50AE4`/`+0x50AEC`), `FUN_1402c0bf0` (`handleDnsFilterServiceSwitch` → `FUN_1402cc780(...,0x53)`), `FUN_1402cc780` (payload = `event->vtable+8` serialization → `FUN_1402cc960`), `FUN_1402c1b80` (`handleScreenAccountabilityServiceSwitch`, name xref `0x1408dc380`), `FUN_1402c91a0` + `FUN_1402b1aa0` (`testDnsBlocking` + lambda; healthcheck GET), `FUN_14025f270` (dns.json fetch, `GenericDnsFilter` parser callback `FUN_14025e4d0`), `FUN_14012c880` (CleanBrowsing default static-init), `FUN_1402b6bd0` ("Blocking level set to "/"get blocking level"/"Add filtering" menu handler), `FUN_1402ed5f0` + `FUN_1402c66a0` (circumvention detect+record, `CECircumventionEntry`), `FUN_1402b68f0` (`OnSpyHookAPI` dead), `FUN_1402b4ad0` (`OnEndSessionCustom`), `FUN_140131e50`/`FUN_140130080` (0x428 / WM_COPYDATA stubs).
- Message map parse: `.rdata` `0x1408db6a0`–`0x1408dbba0` of `re/samples/00-baseline/VictoryShield.exe` (32-byte entries; handler pointers cross-checked with `get_xrefs_to`).
- String evidence (VictoryShield.exe VAs): `0x140a3d510` (CleanBrowsing DoH), `0x140a3d540`–`0x140a3d5a8` (`user_dns_filter` columns), `0x140a3d5f0`/`0x140a3d620`/`0x140a3d650` (`UserDnsFilterSqliteTable`), `0x140a3e380`–`0x140a3e528` (`user_info` columns, `UserInfoSqliteTable::set`), `0x140a3e498`–`0x140a3e500` (deserializers), `0x140a3ef98`/`0x140a3f0d8` (domain-override tables), `0x140a4f8a8`/`0x140a4f910`/`0x140a4f970` (filter API endpoints), `0x140a4fd10`–`0x140a4fd38` (`clean_browsing_level` + names), `0x140a4fed8`–`0x140a4ff38` (`services` JSON keys), `0x1408dcc90` (healthcheck URL), `0x1408dcc40` ("Logged in with blocking service…"), `0x1408dcce8` ("process metrics for DNS blocking test"), `0x140a4da48`/`0x140a4da80` (cleanbrowsing metrics), `0x140a501a0`/`0x140a501b8` (ini flags), `0x1408e2e00`/`0x1408e2e30` (DNS-filter migration), `0x1408e1050`/`0x1408dcf88`/`0x140a50010` (circumvention), `0x1409707b0`–`0x1409708d8` (libcurl DoH), `0x1408d8ed0`–`0x1408d8f08`/`0x140a4bf10`/`0x140a4bf18` (DB names), `0x1408deb28`/`0x1408dea40` (queue send log/`USER_SETTINGS_CHANGE`).
- Dialog resource: RT_DIALOG #215 at `0x140c03f40` (parsed from `.rsrc` of `re/samples/00-baseline/VictoryShield.exe`; control IDs Continue 1080 / Logout 1082 / Username 1083 / Password 1009).
- VM (2026-09-24): `HKLM\SOFTWARE\Covenant Eyes\Victory Shield\DnsProxyDisable = 01000000`; no port-53 listener (`re/findings/03-runtime/network-capture.md`); `ce-file` schema (`re/findings/02-artifacts/local-db.md`).
- Cross-refs: `re/findings/15-ui/ui-architecture.md` §4 (queue codes, `CE_SPYMapObj` creation `FUN_1402b3600`), `signin-and-settings.md` §5 (logout gating, health-check summary), `re/findings/16-updater/updater.md` §9a/§9c (settings catalog, browser DoH policy), `re/findings/02-artifacts/logs.md` (10.1.1 DNS-proxy vocabulary).

## Linux-reimplementation notes

- State model: keep per-user service flags (`dns_filtering`/`url_filtering`/`accountability`/…) and filter config (resolver URL, level, fallback IPs, domain-override lists with versioned incremental sync) in one local DB owned by the daemon; publish a read-only policy snapshot to peers (CE's `CE_SPYMapObj` is just a cached copy — a socket/DBus property is cleaner than shared memory).
- Enforcement: resolver-level filtering via DoH (CleanBrowsing adult-filter family is a drop-in) is directly portable; pin the DoH endpoint per user from server config with a sane default and plain-DNS fallbacks. Do not resurrect CE's 10.1.1 port-53 proxy or per-adapter "Removing DNS servers" loops — on Linux do resolver pinning via systemd-resolved/NetworkManager and log resolved names (`dns_activity` equivalent) in the daemon.
- Health check: keep a periodic probe of a filter-controlled name, but make failure **locally actionable** (CE's `covenanteyesfilter.com/healthcheck` only feeds telemetry; its break-glass dialog is dead code). A LustLess "filter guardian" equivalent should be an audited local override — and if shipped, actually wired to the health path.
- The `circumventions` model maps well: at capture time note windows that deny capture (Wayland/X11 have no exact `WDA_EXCLUDEFROMCAPTURE` analog — treat portal refusals/black surfaces as the trigger) and log `app_name`+`window_title`+interruption-type rows. No event hooks needed — CE's only source is the capture-time window list.

## Open questions

MUST be answered from `VictoryShieldCommService.exe` once analyzed:
1. **DoH resolver internals** — who actually issues the CleanBrowsing DoH queries for `has_dns_filtering` users (curl `CURLOPT_DOH_URL` with `over_https_url`?), how `ipv4/ipv6_primary/secondary` are used, and how resolutions are attributed to `process_id`/`process_name` for `dns_activity`.
2. **`user_dns_filter` (and `user_info`/`pdl_info`) table writer/owner** — which process creates them and in which DB (confirm/refute the `ce-user-file` binding); who is the authority on `UserDnsFilterSqliteTable::set` from the service side.
3. **URL-filtering enforcement** — how `has_url_filtering` + `global_domain_overrides`/`custom_domain_overrides` are applied (hosts file? resolver policy? proxy?), incl. the logout "web access off" enforcement point (`USER_LOGOUT` handling vs `CE_SPYMapObj` clearing).
4. **Healthcheck semantics** — the expected result of `http://covenanteyesfilter.com/healthcheck` under healthy vs broken filtering, retry cadence, and what consumes `client_cleanbrowsing_problem` server-side.
5. `0x432`–`0x438` message payloads (`FUN_1402c3c10`/`FUN_1402c3b40`/`FUN_1402c3ce0` targets) — what the comm service sends on these channels.

Client-binary residue (lower priority): whether the `filter-popup-enabled`/`dns-popup-disabled` ini flags gate anything besides remnants of the dead guardian dialog; the exact `CeUserSettings` event class serialized into the `0x53` payload.
