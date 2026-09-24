# Live Windows surface — dynamic recon (SSH only, no Ghidra)

**Host:** `DESKTOP-6LK4SCA`, Windows 11 build 26100.9444, SSH as `dolphin@100.99.219.44` (PowerShell default shell).
**Collected:** 2026-09-24. All commands below were run live over SSH; excerpts are verbatim.

## What it does (summary)

Victory Shield 10.1.44 on this machine is a **pure user-mode product**: two auto-start LocalSystem
services (`VictoryShieldCommService`, `VSWD`), one HKLM `Run` entry for the tray/UI, an InstallShield
uninstall entry, and ACL hardening on `C:\Program Files\CE`. There is **no kernel driver, no WFP
callout or filter, no Winsock LSP/namespace provider, no proxy setting, no hosts-file entry, no
firewall rule, no scheduled task, and no certificate** belonging to Covenant Eyes anywhere on the
live system. The file `C:\Windows\System32\drivers\CEA.sys`, previously assumed to be a CE kernel
driver, is **not** a CE component at all — it is byte-identical to the stock Windows
`microsoft-windows-eventaggregation` component ("Event Aggregation Kernel Mode Library", Microsoft
Corporation) and is not registered with the SCM. The Edge extension
`jmjflgjpcpepeafmmgdpfkogkghcpiha` is a genuine Microsoft Store-frontend text extension, unrelated
to CE.

**Explicit verdicts (required):**

- **CEA.sys driver kind:** *none of the above* — not a WFP callout driver, not NDIS, not CE's. It is
  the stock Microsoft Windows "Event Aggregation Kernel Mode Library" (`EventAggregation.sys`),
  hash-identical to the WinSxS servicing copy, not registered as a service and not loaded.
  **CE ships no kernel driver on this system.**
- **WFP filtering by CE:** **NONE.** Zero CE filters, callouts, providers or sublayers in the full
  `netsh wfp show state`/`show filters` dumps.
- **Edge extension `jmjflgjpcpepeafmmgdpfkogkghcpiha`:** **UNRELATED** — Microsoft's "Edge relevant
  text changes" Chrome-Web-Store button-label rewriter; no CE strings, no network I/O, no access
  outside `chrome.google.com/webstore/*` and `chromewebstore.google.com/*`.

---

## a. CEA.sys driver

### Mechanism / findings

There is **no service named `CEA`** (any case) and **no driver service of any name pointing at
CEA.sys**. The binary itself is a stock Windows file:

- Version resource: `FileDescription: Event Aggregation Kernel Mode Library`,
  `InternalName`/`OriginalFilename: EventAggregation.sys`, `CompanyName: Microsoft Corporation`,
  `10.0.26100.9444 (WinBuild.160101.0800)`, `ProductName: Microsoft Windows Operating System`.
- SHA256 of `C:\Windows\System32\drivers\CEA.sys` equals SHA256 of the WinSxS servicing copy in
  `amd64_microsoft-windows-eventaggregation_31bf3856ad364e35_10.0.26100.9444_none_497c1fcbcd26d303\CEA.sys`.
- Catalog-signed by Microsoft as an OS binary (`CN=Microsoft Windows`, issuer `Microsoft Windows
  Production PCA 2011`, `SignatureType: Catalog`, `IsOSBinary: True`, `Status: Valid`) and its ACL is
  the stock system-file ACL (`NT SERVICE\TrustedInstaller:(F)`, others `(RX)`).
- No PnP device binds to a `CEA` service; `fltmc` shows no CE minifilter; there is no `cea.inf` and
  no `cea` entry in `HKLM\SYSTEM\DriverDatabase\DriverInfFiles`.
- No `*.sys` files at all under `C:\Program Files\CE` or `C:\ProgramData\CovenantEyes` → CE 10.1.44
  ships **no** kernel-mode component.

Device interface: `\\.\CEA`, `\\.\CE`, `\\.\CEA0`, `\\.\VictoryShield`, `\\.\CEA.sys`, `\\.\Nsi` all
fail to open ("Could not find file"); no CE symbolic link / device object exposes itself. [INFERENCE]
With no CE driver present, no device interface can exist; the probes confirm nothing named like CE is
reachable from user mode.

Note: `reg query HKLM\SYSTEM\CurrentControlSet\Control\Class /s /f "CEA"` returns exactly one hit —
`{c30ecea0-11ef-4ef9-b02e-6af81e6e65c0}` (WSDPrintDevice) — a GUID-substring false positive, not CE.

### Evidence

```
PS> sc.exe query CEA ; sc.exe qc CEA
[SC] EnumQueryServicesStatus:OpenService FAILED 1060:
The specified service does not exist as an installed service.
(same 1060 for sc qc cea / EventAggregation / eventaggregation)

PS> reg query "HKLM\SYSTEM\CurrentControlSet\Services\CEA" /s
ERROR: The system was unable to find the specified registry key or value.

PS> reg query "HKLM\SYSTEM\CurrentControlSet\Services" /s /f "CEA.sys" /d
End of search: 0 match(es) found.        (also 0 for /f "EventAggregation", /f "Covenant")

PS> driverquery /fo csv | Select-String "CEA|Covenant|Victory"      -> (empty)
PS> Get-CimInstance Win32_SystemDriver | ? { $_.PathName -match "CEA|Covenant|Victory" }  -> (empty)

PS> (Get-Item C:\Windows\System32\drivers\CEA.sys).VersionInfo | fl *
FileDescription : Event Aggregation Kernel Mode Library
InternalName    : EventAggregation.sys
OriginalFilename: EventAggregation.sys
CompanyName     : Microsoft Corporation
FileVersion     : 10.0.26100.9444 (WinBuild.160101.0800)

PS> Get-FileHash C:\Windows\System32\drivers\CEA.sys
SHA256  C82628CC7E768B28C3FF57C429E7735D345A0611BE07E529188058B6ECA95B9F
PS> Get-FileHash "C:\Windows\WinSxS\amd64_microsoft-windows-eventaggregation_...9444_...\
                  497c1fcbcd26d303\CEA.sys"
SHA256  C82628CC7E768B28C3FF57C429E7735D345A0611BE07E529188058B6ECA95B9F

PS> Get-AuthenticodeSignature C:\Windows\System32\drivers\CEA.sys | fl
SignerCertificate : [Subject] CN=Microsoft Windows, O=Microsoft Corporation...
                    [Issuer]  CN=Microsoft Windows Production PCA 2011...
Status            : Valid        SignatureType : Catalog        IsOSBinary : True

PS> icacls C:\Windows\System32\drivers\CEA.sys
NT SERVICE\TrustedInstaller:(F)   BUILTIN\Administrators:(RX)   NT AUTHORITY\SYSTEM:(RX)
BUILTIN\Users:(RX)   APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(RX) ...

PS> New-Object IO.FileStream("\\.\CEA","Open","Read","ReadWrite")
Exception ...: "Could not find file '\\.\CEA'."        (same for \\.\CE, \\.\CEA0, \\.\VictoryShield)

PS> Get-ChildItem "C:\Program Files\CE","C:\ProgramData\CovenantEyes" -Recurse -Filter "*.sys"  -> (empty)
PS> Test-Path C:\Windows\INF\cea.inf      -> False
PS> reg query "HKLM\SYSTEM\DriverDatabase\DriverInfFiles" /s /f "cea"   -> 0 match(es)
```

### Verdict — a

**CEA.sys is not a Covenant Eyes artifact.** It is the in-box Windows component
`microsoft-windows-eventaggregation` ("Event Aggregation Kernel Mode Library"). It is neither a WFP
callout driver nor an NDIS/filter driver for CE — it is a stock Microsoft file that happens to be
named `CEA.sys`. No CE kernel driver exists on this system; the earlier "CEA.sys kernel driver"
surface note is a misidentification. [INFERENCE] CE 10.x gets its screen-name/network-activity data
entirely in user mode (services + local SQLite + HTTPS egress).

---

## b. WFP posture

### Mechanism / findings

Full WFP state and filter tables were dumped and scanned. `netsh wfp show callouts` and
`netsh wfp show providers` **do not exist in this build's netsh** ("The following command was not
found"), but `wfp_state.xml` contains the complete per-layer callout and provider listings anyway.

Result: **no CE presence of any kind.** `Select-String "CEA|Covenant|Victory"` over all three XML
files matches only GUID substrings (`filterKey {111b6b8b-ceab-…}`, `{a92f7fa5-…3ceaa46083a9}`,
`{…-da2bd216cead}`, `{a0eb74da-…-8e313698ceaa}`, `{d4cea826-…}`, and a `sessionKey {…f36aceaf}`) —
none of these is a name, description, provider or callout identifier. Programmatic parse of both
dumps:

- providers (all Microsoft in-box): `FWPM_PROVIDER_MPSSVC_WF` (1582 refs), `FWPM_PROVIDER_MPSSVC_WSH`,
  `FWPM_PROVIDER_MPSSVC_APP_ISOLATION`, `FWPM_PROVIDER_MPSSVC_EDP`,
  `FWPM_PROVIDER_MPSSVC_TENANT_RESTRICTIONS`, `FWPM_PROVIDER_IKEEXT`, `FWPM_PROVIDER_TCP_TEMPLATES`,
  `FWPM_PROVIDER_TCP_CHIMNEY_OFFLOAD`, `FWPM_PROVIDER_IPSEC_DOSP_CONFIG`, plus a handful of GUID
  providers used by `windefend_*`/store components. [INFERENCE] the GUID providers are Microsoft
  components (their filters/callouts are named `windefend_*`, "Windows Firewall: callout", NDU/…
  built-ins), not CE.
- callouts (85 total, all built-in): `FWPM_CALLOUT_IPSEC_*`, `FWPM_CALLOUT_EDGE_TRAVERSAL_*`,
  `FWPM_CALLOUT_WFP_TRANSPORT_LAYER_V{4,6}_SILENT_DROP`, `windefend_stream_v4/v6`, NDU flow/mac
  callouts, "Windows Firewall: callout", "Interface Binding Callout".
- sublayers: `FWPM_SUBLAYER_MPSSVC_WF`, `_TEREDO`, `_QUARANTINE`, `_APP_ISOLATION`, `_WSH`, IPsec
  sublayers — nothing else.
- Zero occurrences of `Covenant`, `Victory`, `VictoryShield`, `VSWD` as text anywhere in the dumps.

### Evidence

```
PS> netsh wfp show state file=C:\Users\dolphin\wfp_state.xml
Data collection successful; output = C:\Users\dolphin\wfp_state.xml
PS> netsh wfp show filters file=C:\Users\dolphin\wfp_filters.xml
Data collection successful; output = C:\Users\dolphin\wfp_filters.xml
PS> netsh wfp show callouts file=... / netsh wfp show providers file=...
The following command was not found: wfp show callouts file=... .

PS> Select-String -Path wfp_state.xml,wfp_filters.xml,wfp_netevents.xml -Pattern "CEA|Covenant|Victory"
wfp_state.xml   L45    <sessionKey>{443ba67a-0eac-47ac-8e17-f7d5f36aceaf}</sessionKey>
                L10580 <filterKey>{111b6b8b-ceab-4dea-9a40-617e8ea56ee0}</filterKey>
                L14265 <filterKey>{a92f7fa5-7c42-49d5-bff2-3ceaa46083a9}</filterKey>
                L70309 <filterKey>{79270b5d-a838-487a-ada7-da2bd216cead}</filterKey>
                L84368 <filterKey>{a0eb74da-93df-41a9-bdbc-8e313698ceaa}</filterKey>
                L94464 <filterKey>{d4cea826-a134-4f34-8bb6-ccca2b963182}</filterKey>
(all 6 = GUID hex substrings "cea*" inside random GUIDs; wfp_netevents.xml: 0 matches)

Local parse of the dumps (Python, re/samples/data/wfp_state.xml):
providerKeys: {FWPM_PROVIDER_MPSSVC_WF: 1582, FWPM_PROVIDER_MPSSVC_WSH: 167, ...}
callout count: 85   distinct names: "WFP Built-in IPsec …", "windefend_stream_v4", …
Covenant -> 0   Victory -> 0   VictoryShield -> 0   VSWD -> 0
```

Dumps persisted locally: `re/samples/data/wfp_state.xml` (4,298,856 B),
`re/samples/data/wfp_filters.xml` (3,271,387 B), `re/samples/data/wfp_netevents.xml` (214,176 B).

### Verdict — b

**No WFP filtering by Covenant Eyes.** No CE filters, callouts, providers or sublayers at any layer
(ALE, transport, stream, …). Every registered callout/provider is a Windows built-in. CE 10.1.44 does
its "screen name / network activity" attribution without WFP.

---

## c. Winsock catalog

### Mechanism / findings

Both catalogs (native + 32-bit) are stock: 28 catalog entries (14 base service providers mirrored:
Hyper-V RAW, AF_UNIX, MSAFD Tcpip/UDP/RAW v4+v6, RSVP TCP/UDP v4+v6, MSAFD L2CAP/RfComm Bluetooth)
and 10 namespace entries (5 mirrored: E-mail Naming Shim Provider, Tcpip, NTDS, nlasvc NLA,
Bluetooth Namespace). There is **no layered service provider, no protocol chain of length > 1, and no
CE namespace provider** — `Select-String "CEA|Covenant|Victory|instnsp|Layered"` over the catalog
matches nothing but the literal text "Protocol Chain Length: 1". The legacy installer's `instnsp`
namespace-provider step left nothing behind.

### Evidence

```
PS> netsh winsock show catalog | Select-String "Description:|Entry Type:"
Entry Type:  Base Service Provider          Description: Hyper-V RAW
Entry Type:  Base Service Provider          Description: AF_UNIX
Entry Type:  Base Service Provider          Description: MSAFD Tcpip [TCP/IPv6]
... (MSAFD Tcpip [UDP/IPv6], [RAW/IPv6], [TCP/IP], [UDP/IP], [RAW/IP],
     RSVP TCPv6/TCP/UDPv6/UDP Service Provider, MSAFD L2CAP [Bluetooth], MSAFD RfComm [Bluetooth])
Entry Type:  Base Service Provider (32)     Description: <same 14 mirrored>
Name Space Provider Entry     Description: E-mail Naming Shim Provider
Name Space Provider Entry     Description: Tcpip
Name Space Provider Entry     Description: NTDS
Name Space Provider Entry     Description: @%SystemRoot%\system32\nlasvc.dll,-1000
Name Space Provider Entry     Description: Bluetooth Namespace
Name Space Provider Entry (32) Description: <same 5 mirrored>

PS> netsh winsock show catalog | Select-String "CEA|Covenant|Victory|instnsp|Layered"
(only "Protocol Chain Length: 1" lines matched, via the word "Chain"; zero CE hits)
Catalog Entry ID count: 28   (all "Protocol Chain Length: 1")
```

### Verdict — c

**No CE Winsock presence.** No LSP, no namespace provider (instnsp's product is gone or was never
installed on this image), no catalog chain modification.

---

## d. Persistence / anti-tamper

### Mechanism / findings

| Vector | State |
|---|---|
| Scheduled tasks | **none** — full Unicode scan of `C:\Windows\System32\Tasks\**` for `Covenant|VictoryShield|Victory Shield|VSWD|RestartVS|Program Files\CE` returns 0 files (also nothing named Victory/Covenant/VS beyond unrelated Windows tasks) |
| HKLM Run | `Victory Shield = "C:\Program Files\CE\VictoryShield.exe"` (the only CE autostart) |
| HKLM WOW6432Node Run / HKCU Run / RunOnce (all 4) | empty / absent |
| AppInit_DLLs | empty, `LoadAppInit_DLLs=0`, `AppCertDlls` absent (both 64/32-bit views) |
| IFEO | 51 subkeys, all stock/third-party tools (notepad, sshd, tailscale, …) — **no CE entries** |
| Uninstall entry | `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\{5AC5ED2E-2936-4B54-A429-703F9034938E}` — DisplayName **"Victory Shield"**, 10.1.44, Publisher "Covenant Eyes, Inc." (this is the entry a "Covenant"-only DisplayName filter misses) |
| File ACL `C:\Program Files\CE` | `Everyone:(OI)(CI)(DENY)(DE,DC)` + `Everyone:(OI)(CI)(RX)` — nobody (incl. admins, until the ACL is edited) can delete/rename in place; standard users can only read+execute |

**Service DACLs** (identical for both services, `sc sdshow`):

```
D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWRPLORC;;;AU)
  (A;;CCLCSWRPLORC;;;SU)(A;;CCLCSWRPWPDTLOCRRC;;;PU)(A;;CCLCSWRPLORC;;;IU)
S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)
```

Decoded access masks (SID translation run live):
`NT AUTHORITY\SYSTEM 0x201fd` (start+stop+config-query…), `BUILTIN\Administrators 0xf01ff` (full),
`BUILTIN\Power Users 0x201fd` (start+stop; legacy group, effectively empty),
`Authenticated Users / NT AUTHORITY\SERVICE / INTERACTIVE 0x2009d`
(**QUERY_CONFIG, QUERY_STATUS, ENUMERATE_DEPENDENTS, START, INTERROGATE — no STOP, no CHANGE_CONFIG**).

So: **only LocalSystem, Administrators and (legacy) Power Users can stop or reconfigure the services;
ordinary users can start them but not stop them.** Killing the service *process* is likewise admin-only
(services run as LocalSystem), and even then SCM recovery re-launches it.

**Restart behavior** (`sc qfailure` on both):
`RESET_PERIOD: INFINITE`, `FAILURE_ACTIONS: RESTART -- Delay = 1000 ms` ×3. No start/stop triggers
(`sc qtriggerinfo`: "has not registered for any start or stop triggers").

**Watchdog role** (file metadata, `C:\Program Files\CE\`):

```
VSWD.exe       | VSWD                         | Covenant Eyes
VSWD.dll       | WatchdogServiceLibrary       | Covenant Eyes
RestartVS.exe          | Restart Victory Shield               | Covenant Eyes
RestartVSClientOnly.exe| Restart Victory Shield Client Only   | Covenant Eyes
```

`VSWD` service: Auto, LocalSystem, deps `RpcSs, SamSs, EventLog, ProfSvc`.
`VictoryShieldCommService`: Auto, LocalSystem, deps `RpcSs, SamSs, ProfSvc, Afd, Tcpip, nsi, Dhcp, Dnscache`,
binary `c:\Program Files\CE\VictoryShieldCommService.exe`.

### Evidence

```
PS> Get-ScheduledTask | ? { $_.TaskName -match "Victory|Covenant|..." }   -> only Windows noise
PS> Get-ChildItem C:\Windows\System32\Tasks -Recurse -File | Select-String `
      -Pattern "Covenant|VictoryShield|Victory Shield|VSWD|RestartVS|Program Files.CE"  -> (empty)
PS> reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
    Victory Shield    REG_SZ    "C:\Program Files\CE\VictoryShield.exe"
PS> reg query ...Run (WOW6432Node / HKCU) ...RunOnce (x4)   -> all empty or absent
PS> sc.exe qc VictoryShieldCommService
    START_TYPE : 2 AUTO_START    BINARY_PATH_NAME : c:\Program Files\CE\VictoryShieldCommService.exe
    SERVICE_START_NAME : LocalSystem
PS> sc.exe qfailure VictoryShieldCommService   (and VSWD)
    RESET_PERIOD (in seconds): INFINITE
    FAILURE_ACTIONS: RESTART -- Delay = 1000 milliseconds.  (x3)
PS> icacls "C:\Program Files\CE"
    Everyone:(OI)(CI)(DENY)(DE,DC)
    Everyone:(OI)(CI)(RX)
PS> reg query "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall" /s /f "Victory"
    DisplayName      : Victory Shield
    DisplayVersion   : 10.1.44
    Publisher        : Covenant Eyes, Inc.
    InstallLocation  : C:\Program Files\CE
    UninstallString  : "C:\Program Files (x86)\InstallShield Installation
                       Information\{5AC5ED2E-2936-4B54-A429-703F9034938E}\setup.exe"
                       -runfromtemp -l0x0409 -removeonly
```

### Verdict — d

Persistence is **three prongs**: (1) both services Auto-start as LocalSystem with SCM
restart-on-failure (3×1 s, infinite window); (2) `HKLM\...\Run` starts the UI (`VictoryShield.exe`)
at logon; (3) `VSWD` ("WatchdogServiceLibrary") plus the `RestartVS*.exe` helpers exist to re-launch
the client. [INFERENCE] VSWD watches the client processes and invokes `RestartVS.exe` /
`RestartVSClientOnly.exe` when one dies — consistent with its name, its library's name, and the two
"Restart Victory Shield" binaries; the exact watch targets are not observable from config alone.
Anti-tamper is modest: service stop is admin-only by DACL, and the install dir denies delete to
everyone. No tasks, no IFEO/AppInit, no other Run keys.

---

## e. Network configuration effects

### Mechanism / findings

The system's network configuration is **untouched by CE**:

- WinHTTP: `Direct access (no proxy server)`.
- WinINET (HKCU): `ProxyEnable = 0x0`, no `ProxyServer`/`AutoConfigURL` values present; HKLM
  `Internet Settings` has no proxy values at all.
- `hosts` file: the stock Microsoft sample, zero mappings.
- Firewall: 527 rules scanned via `netsh advfirewall firewall show rule name=all` — zero matches for
  `Covenant|VictoryShield|VSWD|RestartVS|Program Files\CE`; the raw rule store
  (`HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules` and
  `PersistentFirewallRules`) also contains no `Covenant|Victory|VSWD|[\\/]CE[\\/]` path. (CE egress is
  therefore default-allowed outbound, not rule-granted.)
- DNS client: `Dnscache` is stock (AUTO_START, `svchost -k NetworkService -p`, running). Resolvers are
  DHCP `10.0.0.1` (Ethernet) and Tailscale `100.100.100.100` / `fd7a:115c:a1e0::53`. The single NRPT
  rule present is Tailscale's MagicDNS catch-all (`Namespace {.}` → `100.100.100.100,
  fd7a:115c:a1e0::53`), not CE.
- CE's own registry (`HKLM\SOFTWARE\Covenant Eyes\Victory Shield`) shows it *observes* the network
  rather than reconfiguring it: `DnsProxyDisable = 01 00 00 00`, `InstallMode = upgrade`,
  telemetry timestamps, and a `NetworkStatus` subkey per adapter
  (`{37217669-…} Tailscale Tunnel / IfName Tailscale / IfType 53 / ConnType other_vpn`,
  `{4A33EE81-…} Red Hat VirtIO Ethernet Adapter / IfType 6 / ConnType ethernet`, each with
  `IpSupport v4v6`, `OpStatus`, `LastActivatedTime`).

### Evidence

```
PS> netsh winhttp show proxy
Current WinHTTP proxy settings:    Direct access (no proxy server).
PS> reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
    ProxyEnable    REG_DWORD    0x0        (no ProxyServer value)
PS> Get-Content C:\Windows\System32\drivers\etc\hosts
# Copyright (c) 1993-2009 Microsoft Corp. ... (stock sample, no entries)
PS> netsh advfirewall firewall show rule name=all | Select-String `
      "Covenant|VictoryShield|VSWD|RestartVS|Program Files.CE"      -> (0 matches of 527 rules)
PS> reg query "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" ^
      | Select-String "Covenant|Victory|VSWD|RestartVS|[\\\\/]CE[\\\\/]"   -> (0 matches)
PS> netsh interface ip show dns
    Tailscale : Statically Configured DNS Servers: 100.100.100.100
    Ethernet  : DNS servers configured through DHCP: 10.0.0.1
PS> Get-DnsClientNrptRule | fl Name,Namespace,NameServers
    Name        : {5abe529b-675b-4486-8459-25a634dacc23}
    Namespace   : {.}
    NameServers : {100.100.100.100, fd7a:115c:a1e0::53}     <- Tailscale MagicDNS, not CE
PS> reg query "HKLM\SOFTWARE\Covenant Eyes\Victory Shield"
    InstallMode       REG_SZ     upgrade
    DnsProxyDisable   REG_BINARY 01000000
    LastTelemetryUpdateAt REG_SZ 2026-09-24T18:01:22.8670000 UTC +0000
    NetworkStatus\{37217669-42DA-4657-A55B-0D995D328250} : Description=Tailscale Tunnel ...
    NetworkStatus\{4A33EE81-CA4A-46D9-8D67-FFF7973BE4D8} : Description=Red Hat VirtIO Ethernet Adapter ...
```

### Verdict — e

**No network config effects from CE.** No proxy (WinHTTP/WinINET), no hosts edits, no firewall rules,
no CE DNS redirection (the only NRPT rule is Tailscale's MagicDNS catch-all). `DnsProxyDisable=1`
shows the (configurable) local DNS-proxy feature is off in this install. CE's network footprint is
limited to its services' own sockets and per-adapter status tracking recorded in its registry key.

---

## f. Certificates

### Mechanism / findings

All five machine stores scanned for `Covenant|Victory` (the legacy Redirector log's "cert service
deleted" refers to a component that is gone): **zero CE-related certificates remain anywhere in the
machine stores.** Store sizes are small (`root` 13, `ca` 3, `my` 0, `disallowed` 0, `authroot` 20
entries), consistent with a clean lab image; no `Covenant Eyes` issuer/subject, no `CEA`/`Victory`
CN.

### Evidence

```
PS> certutil -store root        | Select-String "Covenant|Victory"   -> (empty)
PS> certutil -store ca          | Select-String "Covenant|Victory"   -> (empty)
PS> certutil -store my          | Select-String "Covenant|Victory"   -> (empty)
PS> certutil -store disallowed  | Select-String "Covenant|Victory"   -> (empty)
PS> certutil -store authroot    | Select-String "Covenant|Victory"   -> (empty)

entry counts: root: 13   ca: 3   my: 0   disallowed: 0   authroot: 20
```

[INFERENCE] The old Redirector-era certificate service (and any trust anchor it installed) was
removed by the upgrade to Victory Shield 10.x; nothing re-installs certificates today.

### Verdict — f

**No CE certificates remain** in `root`, `ca`, `my`, `disallowed`, or `authroot`. There is no
CE-pinned trust anchor on the live system.

---

## g. Edge extension `jmjflgjpcpepeafmmgdpfkogkghcpiha` — verdict

### Mechanism / findings

Files (5): `manifest.json`, `content.js` (9,815 B), `content_new.js` (10,388 B),
`_metadata/computed_hashes.json`, `_metadata/verified_contents.json` (CRX "publisher"+"webstore"
signature over tree hashes). Manifest: MV3, `"name": "Edge relevant text changes"`,
`"description": "Edge relevant text changes on select websites to improve user experience and
precisely surfaces the action they want to take."`, `"update_url":
"https://edge.microsoft.com/extensionwebstorebase/v1/crx"` (Edge Add-ons update endpoint), and the
only content-script matches are `https://chrome.google.com/webstore/*` (`content.js`) and
`https://chromewebstore.google.com/*` (`content_new.js`).

The scripts are minified bundles whose entire payload is: localized button-label strings ("Add to
Chrome", "Added to Chrome", "Get", "Remove from Chrome", "Install Chrome" — ~50 languages), DOM text
rewriting on `div.webstore-test-button-label`/`button`, a `MutationObserver`, and event names
`Microsoft.Extensions.CwsPageEvents`, `Microsoft.Extensions.CwsCtaUpdateSuccessState` /
`NewCwsCtaUpdateSuccessState`, plus telemetry-ish markers `CWS_PAGE_LOADED`,
`NEW_CWS_PAGE_LOADED`, `NEW_CWS_PROMOTIONAL_DIALOG_SHOWN`, `NEW_DIALOG_IMPACTED_USER`, … The only URL
referenced is `https://www.google.com/chrome`. Counts across both files: `fetch(` 0, `XMLHttpRequest`
0, `WebSocket` 0, `chrome.runtime` 0, `chrome.storage` 0, `localStorage` 0, `postMessage` 0, `eval(`
0. Zero occurrences of `Covenant`, `Victory`, or accountability-related strings.

So it rewrites the Chrome Web Store CTA buttons (and promotional dialog text) inside Edge — e.g.
adjusting what the "Add to Chrome" button says when viewed from Edge — and reports those UI states to
Edge-internal handlers via `Microsoft.Extensions.*` events.

### Evidence

```
C:\Users\dolphin\AppData\Local\Microsoft\Edge\User Data\Default\Extensions\
    jmjflgjpcpepeafmmgdpfkogkghcpiha\1.2.1_0\manifest.json
   "name": "Edge relevant text changes",
   "description": "Edge relevant text changes on select websites to improve user experience ...",
   "update_url": "https://edge.microsoft.com/extensionwebstorebase/v1/crx",
   "content_scripts": [ { "js": ["content.js"],     "matches": ["https://chrome.google.com/webstore/*"] },
                        { "js": ["content_new.js"], "matches": ["https://chromewebstore.google.com/*"] } ]

content.js / content_new.js string inventory (abridged, see re/samples/data/edge-ext/):
   "Add to Chrome", "Added to Chrome", "Get", "Remove", "Install Chrome", ... (localized)
   "CWS_PAGE_LOADED", "NEW_CWS_PAGE_LOADED", "NEW_CWS_PROMOTIONAL_DIALOG_SHOWN",
   "NEW_CWS_PROMOTIONAL_MESSAGE_SHOWN", "NEW_DIALOG_IMPACTED_USER", "OLD_DIALOG_IMPACTED_USER",
   "Microsoft.Extensions.CwsPageEvents", "Microsoft.Extensions.CwsCtaUpdateSuccessState",
   "div.webstore-test-button-label", "MutationObserver", "innerText", "https://www.google.com/chrome"
   network/storage APIs: none (fetch/XHR/WebSocket/chrome.runtime/chrome.storage/localStorage = 0 hits)

_metadata/verified_contents.json: payload = item_id jmjflgjpcpepeafmmgdpfkogkghcpiha v1.2.1,
   treehash of content.js/content_new.js/manifest.json, signatures kid="publisher" and kid="webstore"
```

Local copies: `re/samples/data/edge-ext/{manifest.json,content.js,content_new.js,verified_contents.json}`.

### Verdict — g

**Unrelated to Covenant Eyes.** This is Microsoft's own "Edge relevant text changes" component
distributed via the Edge Add-ons store (`edge.microsoft.com/extensionwebstorebase/v1/crx` update
URL), whose sole job is localizing/adjusting Chrome Web Store CTA text on the two Web Store domains.
It has no CE strings, no network exfiltration, no storage access, and no page access outside the Web
Store. It is part of the noise on this machine, not part of the CE product.

---

## Linux-reimplementation notes (brief)

1. **No kernel component is required to reproduce Victory Shield 10.x behavior.** CE accomplishes its
   observable surface in user mode; a Linux port can stay entirely in user space (service daemon +
   watcher + CLI/UI) with no eBPF/netfilter/LSP equivalents. The only privileged elements are process
   supervision and install-dir ACLs.
2. **Supervision model to copy:** two auto-start services as root with SCM-style restart-on-failure
   (3 restarts, 1 s delay, infinite reset), a watchdog service (`VSWD`/"WatchdogServiceLibrary") plus
   relaunch helper binaries (`RestartVS*.exe`), and a per-user autostart for the UI. On Linux:
   `systemd` units with `Restart=always`/`RestartSec=1` + a small watchdog unit; UI via
   XDG autostart. Restrict `systemctl stop` to root (default) to mirror the service DACL.
3. **Install layout to copy:** single root-owned directory (deny delete to non-root →
   root-owned dir with `chmod a-w`, or immutable bit), an uninstall record in the package database
   (the Windows entry is an InstallShield `{5AC5ED2E-…}` "Victory Shield" record under WOW6432Node),
   and product state under `/var/lib/...` mirroring `HKLM\SOFTWARE\Covenant Eyes\Victory Shield`
   (`InstallMode`, `DnsProxyDisable`, per-adapter `NetworkStatus` cache, telemetry timestamps).
4. **Network posture:** do nothing to system networking — no proxy, no hosts edits, no firewall rules,
   no DNS interception (CE runs with `DnsProxyDisable=1` here). Connectivity status should be observed
   (adapters, up/down) rather than modified. Egress to the backend (208.185.195.49:443 in the known
   surface) uses ordinary outbound sockets.
5. **Browser extension:** if a LustLess browser piece is ever needed, the CE product shows it is not
   required; and the Edge extension on this box is a cautionary example of unrelated components
   sitting next to the product — attribute artifacts by behavior, not by directory proximity.
