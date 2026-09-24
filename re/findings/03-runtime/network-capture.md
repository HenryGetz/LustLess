# Runtime network capture — CE "Victory Shield" v10.1.44

## What it does

Victory Shield's network face is a single actor: `VictoryShieldCommService.exe`
(PID 5616 at capture time) holds two long-lived TCP connections to the Covenant
Eyes backend `api.cvnt.net` = `208.185.195.49:443`, and listens on loopback
`127.0.0.1:48867` for in-machine clients. Across three bounded passive captures
(pktmon, full packets + TCPIP/DNS ETW, 2026-09-24 18:02:58–18:43:16 UTC, 11m24s
total) the CE stack was **completely network-silent**: zero packets to/from
`208.185.195.49`, zero new connections, zero DNS queries, zero loopback clients.
The only remote endpoint CE ever uses is the single backend; no update server, no
classifier-data CDN, no separate auth endpoint, no OCSP traffic was observed.
The ~601 s `LastTelemetryUpdateAt` registry heartbeat ticks on a strictly
periodic timer — one tick (18:41:26.766) fell **inside** the capture and produced
zero CE packets and zero socket events, proving the heartbeat is a purely local
bookkeeping write. The two backend connections were observed cycling to a new
ephemeral-port pair (55148/55210 → 55724/55875) between observation points — not
at a tick — and each connection is shadowed by a same-port unconnected `Bound`
socket. All application payloads are TLS-encrypted and were **not** decryptable
with available tooling (no MITM attempted); SNI was extracted from plaintext
ClientHellos — no CE SNI appears because CE opened no connections in any window.

## Method

### Tooling inventory (VM, admin PowerShell, 2026-09-24)

```
PS> Get-Command pktmon,netsh,tshark,dumpcap,wpr -ErrorAction SilentlyContinue
Name       Source
----       ------
PktMon.exe C:\WINDOWS\system32\PktMon.exe
netsh.exe  C:\WINDOWS\system32\netsh.exe
wpr.exe    C:\WINDOWS\system32\wpr.exe
```

- **pktmon** — present (built into Windows 10 1809+ / 11). This build rejects
  `pktmon --help` (`Unknown command '--help'`); the syntax is `pktmon help`,
  `pktmon start help`, `pktmon etl2pcap help` … `pktmon filter list` → `None`
  (no pre-existing filters; none were added — capture was unfiltered on purpose).
- **netsh trace** — present as fallback; **not used** (pktmon worked).
- **wpr** — present; unused.
- **tshark / dumpcap** — NOT installed on the VM; no Wireshark install
  (`C:\Program Files\Wireshark` absent). Offline analysis used the workstation's
  `/usr/bin/tshark` on an exported pcapng.
- `netsh winhttp show proxy` → "Direct access (no proxy server)."
- CE DNS-proxy posture reads (see Evidence): `HKLM\...\Victory Shield\DnsProxyDisable`,
  `Get-DnsClientServerAddress`, port-53 listener check.

### Capture configuration

One `pktmon` session per segment, started and stopped by this agent only. No
service, driver, process, or registry state was modified; nothing was captured
that this agent did not start.

```
pktmon start --capture --comp all --pkt-size 0 --file-size 256 \
  --trace -p Microsoft-Windows-TCPIP -p Microsoft-Windows-DNS-Client \
  -f C:\Users\dolphin\ce-netcap\ce-netcap.etl
```

- `--capture --comp all --pkt-size 0` — packet capture on all components,
  **entire** packet logged (`--pkt-size 0` = full packet; default is 128 B
  headers-only), so TLS ClientHello (plaintext SNI) and DNS payloads survive.
- `--trace -p Microsoft-Windows-TCPIP -p Microsoft-Windows-DNS-Client` —
  same-ETL socket-level events (with **PID attribution**) and DNS-client query
  events (query name + client PID).
- No filters: the VM is nearly idle, and an unfiltered capture also covers
  loopback-adjacent behavior and admits non-CE traffic for contrast.

### Window and segments (all times UTC)

| Segment | Start | Stop | Duration | Artifacts |
|---|---|---|---|---|
| A | 18:02:58 (first frame / session-start enum at 18:02:58.43) | 18:10:09.9 | 6m12s | `ce-netcap.etl` 7.3 MB → `ce-netcap.pcapng` 11.5 MB (50,786 frames), `ce-netcap.txt` 112 MB |
| B | 18:10:11.2 | 18:11:37.1 | 1m26s | `ce-netcap-b.etl` 40 KB → `ce-netcap-b.pcapng` 168 B (0 frames), `ce-netcap-b.txt` 51 KB |
| C (tail) | 18:40:30.3 | 18:43:16.5 | 2m46s | `ce-netcap-c.etl` 417 KB → `ce-netcap-c.pcapng` 457 KB, `ce-netcap-c.txt` 4.6 MB |

Total observed 11m24s across three bounded sessions (each ≤15 min budget). Segment C
is the "tail window": started deliberately to cover the next 601 s telemetry tick
(observed at 18:41:26.766 — inside the segment) and stopped ~2 min after it.
The A/B mid-window restart is a methodology artifact: at 18:10:06 the VM came
under severe memory pressure (Ghidra OOM, PowerShell CLR load failures) and this
capture's circular buffer was a contributor (pktmon reported 165 MB reserved); it
was restarted with `--file-size 64` to shrink the buffer (pktmon paradoxically
reported 384 MB) and then **torn down at 18:11:34 on a coordination hold** — all
segments flushed with "No events lost". Segment B captured zero packets and zero
socket events between 18:10:11 and 18:11:34 (the only log lines are stop-time
events); the machine was globally quiet in that interval. Segment C used the
agreed lighter config (`--pkt-size 512 --file-size 64`; pktmon reported 229 MB)
and ran concurrently with other agents' tooling under a strict abort-on-OOM
condition (no OOM symptoms occurred).

Sixty-second snapshots (PID-filtered `Get-NetTCPConnection` / `Get-NetUDPEndpoint`
/ `Get-DnsClientCache` / registry timestamps) were taken at T0 18:02:30 (pre-start),
T+1 18:03:34, T+2 18:05:26, T+3 18:06:40, T+4 18:07:58, T+5 18:09:36, a
post-hold read at 18:11:34, socket probes at 18:29:5x / 18:38:27, tick-window
socket+registry snapshots at 18:40:49 (pre-tick), 18:41:59 (post-tick), 18:43:11
(final), and registry checks at 18:21:30. Script:
`C:\Users\dolphin\ce-netcap\snap.ps1` (copy in `re/samples/runtime/snap.ps1`);
log: `re/samples/runtime/netcap-snapshots.log`; tick-window evidence:
`re/samples/runtime/netcap-segc-tick-window.txt`.

### What this can and cannot see

| Can see | Cannot see |
|---|---|
| Packet headers + full bytes on all NDIS components (incl. remote + LAN) | TLS application payloads — encrypted; not decryptable without keys; **no root CA / MITM was installed** (forbidden by task) |
| Plaintext **SNI/ALPN in TLS ClientHello**, DNS wire messages | HTTP/2 or API semantics inside TLS; QUIC crypto (none observed) |
| TCPIP ETW: every socket event with **PID** (connect/accept/close/state/send) | Which CE module (comm service vs. embedded library) originates a call |
| DNS-Client ETW: query name + querying PID (incl. cache-only lookups) | Cache state before the window; DNS over HTTPS payloads (Windows DoH is itself TLS) |
| **Loopback TCP is visible in TCPIP ETW but NOT in pktmon packet capture** (NDIS-only; the 8089 loopback flow proves loopback events exist while no loopback frames appear in the pcap) | UDP senders via `Get-NetUDPEndpoint` (no remote state) — covered by ETW/packets instead |

### Analysis commands (workstation, `/usr/bin/tshark` on exported pcapng)

```
tshark -r ce-netcap.pcapng -q -z conv,tcp -z conv,udp
tshark -r ce-netcap.pcapng -Y "tls.handshake.type == 1" -T fields \
  -e frame.time -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport \
  -e tls.handshake.version -e tls.handshake.extensions_server_name \
  -e tls.handshake.extensions_alpn_str
tshark -r ce-netcap.pcapng -Y dns -T fields -e frame.time -e dns.qry.name ...
tshark -r ce-netcap.pcapng -Y "tcp.port == 48867 or udp.port == 55210 or udp.port == 55148"
```

Raw captures remain on the VM at `C:\Users\dolphin\ce-netcap\` (ETL + pcapng +
etl2txt dumps; the 112 MB text dump stayed on the VM, grepped remotely). Small
filtered excerpts are in `re/samples/runtime/` (gitignored): `netcap-snapshots.log`,
`netcap-etw-ce-events.txt`, `netcap-sni.tsv`, `netcap-tcp-convs.txt`.

## Evidence

### Endpoint timeline — CE processes

CE processes during the window (from `Get-Process | Where-Object { $_.Path -like
"*\CE\*" }`, every snapshot): **PID 5616 `VictoryShieldCommService.exe`** and
**PID 127048 `VSWD.exe`**. `VictoryShield.exe` (UI), `VictoryShieldClassifier.exe`,
and `vs-config.exe` were **not running**.

| t (UTC) | PID | Process | dest:port (local src) | State / event | DNS name | Class | Evidence |
|---|---|---|---|---|---|---|---|
| ≤18:02:30 (pre-window) | 5616 | VictoryShieldCommService.exe | 208.185.195.49:443 (10.0.0.21:**55148**) | established before window; `CLOSE_WAIT` for entire window; **0 packets during window** | api.cvnt.net | **telemetry** | T0–T+5 snapshots; ETW `TCP: connection 0xFFFFDD82B3010010 (local=10.0.0.21:55148 remote=208.185.195.49:443) exists. State = CloseWaitState , PID = 5616` @18:02:58.4292008 |
| ≤18:02:30 (pre-window) | 5616 | VictoryShieldCommService.exe | 208.185.195.49:443 (10.0.0.21:**55210**) | same; `CLOSE_WAIT` throughout; 0 packets | api.cvnt.net | **telemetry** | same event list, second line @18:02:58.42921610 |
| 18:02:58–18:11:37 (segs A+B) | 5616, 127048 | both | — | **no connections opened/closed, no bytes sent/received** | — | — | pcap: zero frames with 208.185.195.49 or CE ports; ETW: the two "exists" events above are the *only* CE-PID events in 112 MB of log (`PID = 5616` ⇒ 2 hits, `PID = 127048` ⇒ 0); snapshots show only the two `CLOSE_WAIT` rows + the listener |
| 18:11:37–18:29:5x (unobserved gap) | 5616 | VictoryShieldCommService.exe | 208.185.195.49:443 (10.0.0.21:**55724** and **55875**) | **connection pair cycled**: old 55148/55210 sockets gone, new pair present (each + same-port `Bound` shadow); instant of connect/close unobserved; already `CLOSE_WAIT` when first seen 18:29:5x; 0 packets in seg C | api.cvnt.net (same IP; DNS not re-queried) | **telemetry** | `Get-NetTCPConnection -State Bound` @18:29:5x (55724/55875 `Bound`, PID 5616); full table @18:38:27; seg-C session-start enum: `TCP: connection 0xFFFFDD82B3010010 (local=10.0.0.21:55875 remote=208.185.195.49:443) exists. State = CloseWaitState , PID = 5616` @18:40:30.0811571 (and 55724 twin @18:40:30.0811633) |
| 18:21:24.806 | n/a | registry heartbeat (not a network event; capture not running) | — | `LastTelemetryUpdateAt` write | — | **telemetry** | registry read @18:21:30 = `2026-09-24T18:21:24.8060000 UTC` |
| 18:31:25.866 | n/a | registry heartbeat | — | `LastTelemetryUpdateAt` write (not captured; capture off) | — | **telemetry** | registry value read @18:38:27 |
| 18:40:30.3–18:43:16.5 (seg C) | 5616, 127048 | both | — | **no sockets touched, no bytes**, incl. across the tick below | — | — | seg-C ETW: `PID = 5616` ⇒ 2 (session-start enum only), `PID = 127048` ⇒ 0, `208.185.195.49` ⇒ 2 (same lines), `48867` ⇒ 0, `cvnt` ⇒ 0; pcap: zero frames to/from backend or CE ports |
| **18:41:26.766** | n/a | registry heartbeat **captured live** | — | tick write with **zero CE packets / zero socket events / no socket-state change** (snapshots 18:40:49 → 18:41:59 identical) | — | **telemetry** | `netcap-segc-tick-window.txt`; registry value changed 18:31:25.866 → 18:41:26.766 between the two snapshots |

Classification reasoning: `api.cvnt.net` is the Covenant Eyes API (DNS-cache data:
`api.cvnt.net → 208.185.195.49`); the key is named `LastTelemetryUpdateAt` /
`ApiTelemetryStatus: success` in `HKLM\SOFTWARE\Covenant Eyes\Victory Shield`,
so the endpoint carries the telemetry channel. `[INFERENCE]` A single host:port
for everything suggests auth/config traffic is multiplexed over the same TLS
connection rather than using separate `auth`/`update`/`classifier-data` endpoints
— no other CE hostname exists in the DNS cache, the DNS-Client ETW log, or any
SNI (all three searched: `cvnt` matches 30 lines, all `api.cvnt.net`).

**Update servers / classifier CDN / OCSP: explicit negative.** No WinSparkle-style
feed host, no `*.cvnt.net` besides `api.cvnt.net`, no Akamai/CDN fetches, and no
`*.lencr.org`/`*.pki.goog` OCSP/CRL traffic during the window (the latter two
appeared only as *pre-window* cache residue from earlier OCSP checks:
`x1.c.lencr.org`, `yr.c.lencr.org`, `c.pki.goog` with ~2–150 s TTL, expired
before/during the window).

### DNS behavior

- **No DNS wire queries for CE names during the window.** The only DNS protocol
  packets in the capture are Windows WPAD lookups (`wpad.tail2694c9.ts.net` via
  100.100.100.100 at 18:07:38–41); `api.cvnt.net` was already cached from before
  the window (`Get-DnsClientCache` at T0: TTL 66372 s ≈ 18 h remaining →
  `208.185.195.49`).
- Windows resolves other names over **DoH** in this configuration — the 60 s
  cadence of ClientHellos with SNI `cloudflare-dns.com` (1.1.1.1:443, ALPN
  `h2,http/1.1`) carries the OS's DNS; that is why `settings-win.data.microsoft.com`
  appears in the cache diff (T+3→T+4) without any port-53 packets.
- **Observer footprint (disclosed):** the DNS-Client ETW log contains 5
  `api.cvnt.net` cache lookups at 18:03:37.804, 18:05:32.388, 18:06:44.091,
  18:08:02.183, 18:09:39.565 — each 3–6 s after one of *this agent's*
  `Get-DnsClientCache` snapshot calls (client PIDs 797824/796920/796932 are
  transient ssh-spawned PowerShell processes, never 5616/127048), and each
  answered from cache (`returned 0 with results 208.185.195.49;`). CE's own
  processes issued **no** DNS queries in the window.

### TLS reality check

- Application payloads are **TLS-encrypted and were not decryptable** with
  available tooling (no keys, no key-log, no endpoint instrumentation). No root
  CA was installed and the traffic was not MITM'd (explicitly out of scope).
- SNI **is** recoverable from the full-packet capture because ClientHello is
  plaintext before the key exchange. 18 ClientHellos were captured (all in
  segment A; segments B and C contained none — no handshakes at all) —
  `re/samples/runtime/netcap-sni.tsv`:

| t (UTC) | dest:port | SNI | ALPN | owner |
|---|---|---|---|---|
| 18:04:59–18:09:59 (7×) | 1.1.1.1:443 | `cloudflare-dns.com` | h2,http/1.1 | Windows DoH resolver (non-CE) |
| 18:07:03, 18:08:03, 18:09:03 | 209.177.158.246:443 | `derp12d.tailscale.com` | (none) | Tailscale DERP keepalives (non-CE) |
| 18:07:56 | 57.155.101.212:443 | `settings-win.data.microsoft.com` | h2,http/1.1 | Windows telemetry (non-CE) |
| 18:08:59 | 20.42.73.30:443 | `mobile.events.data.microsoft.com` | (none) | Windows telemetry (non-CE) |
| 18:04:59, 18:09:59 | 184.25.59.11 / 23.51.25.94 :443 | `catalog.gamepass.com` | h2,http/1.1 | Xbox/GamePass background (non-CE) |

- **CE SNI: explicit negative.** No ClientHello with any CE server name exists in
  any segment — consistent with CE opening zero connections throughout. The
  SNI a CE handshake would carry is therefore **not directly observed**;
  `[INFERENCE]` it is `api.cvnt.net` (the only CE hostname anywhere in DNS
  state). Record-layer version of observed handshakes: `0x0303` (TLS 1.2).
- Long-lived TLS flows without a captured ClientHello (handshake predates the
  window; non-CE per SNI/PID evidence): 10.0.0.21:49670→199.165.136.100:443
  (828 frames), 10.0.0.21:65533→192.200.0.112:443, 23.94.251.174:443 (a Tailscale
  DERP node — also seen on UDP/3478 STUN), 20.59.87.227:443. None is
  208.185.195.49 and none appears in CE-PID socket events.

### Local traffic

- **`127.0.0.1:48867`** — `LISTENING`, owner PID 5616 in every snapshot; **zero
  clients** in all capture windows: the snapshot filter (`LocalPort -eq 48867 -or
  RemotePort -eq 48867`, all processes) matched only the listener, and the TCPIP
  ETW logs contain zero genuine 48867 events (seg A's 2 raw grep hits are
  timestamp false positives `13:03:51.048867600` / `13:09:06.448867000`; seg C:
  zero). Independent confirmation from the runtime-observability pass
  (`re/findings/03-runtime/process-observation.md`): the listener accepts
  byte-less connect/close with no banner; the CE install owns **zero named
  pipes** among the 116 system pipes; only 2 CE processes exist (comm service +
  VSWD). `[INFERENCE]` The listener serves the CE UI (`VictoryShield.exe`) and
  companion tools when they run; none were running here.
- **The 55148/55210 (later 55724/55875) ports are TCP local ports of the two
  backend sockets — not a UDP surface.** CE PIDs own **no UDP endpoints at all**:
  `Get-NetUDPEndpoint` (CE PIDs) returns **empty** in every snapshot and
  `netstat -ano` shows no UDP rows. The earlier shared-inventory note "UDP-ish
  bound 0.0.0.0:55210/55148" is a `Get-NetTCPConnection` `Bound`-state
  misreading; the rows are TCP:
  ```
  TCP    10.0.0.21:55148        208.185.195.49:443     CLOSE_WAIT      5616
  TCP    10.0.0.21:55210        208.185.195.49:443     CLOSE_WAIT      5616
  TCP    127.0.0.1:48867        0.0.0.0:0              LISTENING       5616
  ```
  (`netstat -ano | Select-String "55210|55148|48867|208.185.195.49"` @18:03:5x.)
  The ports are ordinary ephemeral-range locals of the service's two uplink
  sockets and advanced across socket generations (55148→55724, 55210→55875),
  consistent with dynamic port allocation (adopted from the
  runtime-observability pass).
- **Dedicated note — the same-port `Bound` shadow socket.** Every backend
  connection row is accompanied by an *unconnected* `0.0.0.0:<same port>` socket
  in `Bound` state owned by the same PID (5616) — e.g. 55724 and 55875 both show
  the shape at 18:29:5x, 18:38:27, and throughout segment C; the old 55148/55210
  pair showed it at T0–T+5:
  ```
  0.0.0.0:55875   0.0.0.0:0           Bound      5616
  10.0.0.21:55875 208.185.195.49:443  CloseWait  5616
  ```
  `[INFERENCE]` Pre-connect binding pattern of the service's HTTP client stack
  (bind `0.0.0.0:port`, then connect) and/or a Windows listing quirk (bound
  endpoint shown separately from the connection). The shape is stable across
  socket generations, so it is structural to the client stack, not a leak.
- **No non-CE client ever touched 48867/55148/55210/55724/55875** (socket tables +
  packet capture + ETW agree across all segments). Other loopback traffic exists
  but is unrelated: `127.0.0.1:55613↔127.0.0.1:8089` (transient PIDs
  795908/797268, agent-harness tooling) @18:11:34 in seg B.
- WinHTTP: direct access, no proxy. **Explicit cross-check** (no contradiction
  with the runtime-observability pass): zero UDP/53 and zero `127.0.0.2`
  DNS-proxy activity in any segment — see "CE DNS-interception surface" below.

### CE DNS-interception surface (present but disabled)

Cross-ref: `re/findings/02-artifacts/logs.md` documents that 10.1.1-era CE ran a
per-adapter user-mode DNS proxy on `127.0.0.2` with upstream "DNS Filter/User
server(s)" `fec0:0:0:ffff::1-3` and a 60 s DNS-server-removal enforcement loop.
On this 10.1.44 box the proxy is **off**, and the capture agrees on every axis:

| Check | Result | Evidence |
|---|---|---|
| `DnsProxyDisable` | **1** (value `{1,0,0,0}`) | `Get-ItemProperty "HKLM:\SOFTWARE\Covenant Eyes\Victory Shield"` |
| `127.0.0.2` listeners | none | `Get-NetUDPEndpoint`/`Get-NetTCPConnection` (CE PIDs every 60 s; port-53 check below) |
| Any port-53 listener (any process) | **none** (UDP and TCP empty) | `Get-NetUDPEndpoint \| Where LocalPort -eq 53`, ditto TCP |
| ETW mentions of `127.0.0.2` / `fec0:0:0:ffff` / `DNS Filter` / `DNS User` in window | **0 / 0 / 0 / 0** | `Select-String` over 112 MB `ce-netcap.txt` |
| DNS server reassignment churn (the 60 s enforcement loop) | none observed | snapshot DNS server config stable; no such packets/events |
| Residue | loopback interface still lists the proxy's upstreams | `Get-DnsClientServerAddress`: `Loopback Pseudo-Interface 1, IPv6 → fec0:0:0:ffff::1, fec0:0:0:ffff::2, fec0:0:0:ffff::3` |

Active resolvers in use are ordinary: Tailscale → `100.100.100.100` /
`fd7a:115c:a1e0::53`, Ethernet → `10.0.0.1` (matches the only wire DNS seen,
the WPAD queries to 100.100.100.100). `[INFERENCE]` The `fec0:0:0:ffff::1-3`
entries on the loopback pseudo-interface are configuration residue of the CE
DNS-proxy machinery (exact match to logs.md's upstream list) left behind with the
proxy disabled; nothing serves them. Caveat: these placeholders also appear on
some stock Windows installs, so this is corroborating rather than conclusive
attribution.

### Telemetry heartbeat cadence (registry)

`HKLM\SOFTWARE\Covenant Eyes\Victory Shield`, key `LastTelemetryUpdateAt`
(self-reported tick timestamps; reads show the latest write only):

| sampled at (UTC) | `LastTelemetryUpdateAt` | `LastTelemetryUploadAt` |
|---|---|---|
| 18:00:35 | 17:51:21.916 | 2026-09-20T04:35:45.0989784 (static all day) |
| 18:02:30 … 18:09:36 (7 samples, 60 s apart) | 18:01:22.867 (unchanged) | static |
| 18:21:30 | 18:21:24.806 | static |
| 18:38:27 | 18:31:25.866 | static |
| 18:40:49 (pre-tick) | 18:31:25.866 | static |
| 18:41:59 (post-tick) / 18:43:11 | **18:41:26.766** | static |

Tick series: 17:51:21.916 → 18:01:22.867 (Δ 600.95 s) → ~18:11:23.8 (Δ ≈601 s;
inferred from the period — its value was overwritten before any read) →
18:21:24.806 (Δ 601.0 s) → 18:31:25.866 (Δ 601.06 s) → 18:41:26.766
(Δ 600.90 s). **The timer is strictly periodic at ≈601 s (10m01s)**; the earlier
"20m02s gap" was two ticks, the first simply overwritten.

Cross-correlation with TCP state (evidence: `netcap-segc-tick-window.txt`):

- The 18:41:26.766 tick fell **inside** segment C (18:40:30–18:43:16) and
  produced **zero CE packets, zero CE socket events, and no socket-state change**
  (snapshots 18:40:49 → 18:41:59 identical) — the heartbeat write is **purely
  local bookkeeping**, not a network poll. This also matches seg A/B: the
  18:01:22.867 tick (1–8 min before those segments) left the two connections in
  `CLOSE_WAIT` with zero bytes transferred for the whole window.
- The backend-socket **cycling** (55148/55210 → 55724/55875, plus fresh `Bound`
  shadows) occurred in the 18:11:37–18:29:5x observation gap — **not** at any
  captured tick — and the new pair was already `CLOSE_WAIT` at first sighting
  (the remote side closes after each exchange). `[INFERENCE]` Reconnects are
  lazy/event-driven (channel needed again, or dead-socket reaping), not
  tick-driven.
- `LastTelemetryUploadAt` remained frozen at 2026-09-20T04:35:45 in every read.

## Synthesis

1. **One endpoint, two sockets.** The entire CE remote surface in this build is
   `api.cvnt.net:443` (`208.185.195.49`), carried on exactly two TCP connections
   from ephemeral local ports (55148/55210 → 55724/55875 across generations)
   (PID 5616). No update server,
   no classifier-data CDN, no separate auth host, no OCSP traffic in-window —
   and a short window can miss slow cadences: 10.1.1-era logs
   (`re/findings/02-artifacts/logs.md`) show an **hourly**
   `ServerTimeManager::sync` and a **daily** WinSparkle appcast (the mechanism
   that silently upgraded the product to 10.1.44), so "none in 11m24s" is
   expected, not proof of absence. `[INFERENCE]` A single host:port for
   everything suggests auth/config traffic is multiplexed over the same TLS
   connection rather than using separate `auth`/`update`/`classifier-data`
   endpoints — no other CE hostname exists in the DNS cache, the DNS-Client ETW
   log, or any SNI. `[INFERENCE]` The two parallel connections likely split
   roles (e.g. events vs. commands) or provide reconnect redundancy.
2. **The 601 s heartbeat is local; network activity is separate.** Across
   11m24s of capture the comm service transferred **zero** bytes on the wire,
   and a full tick (18:41:26.766) passed inside the capture with no packets and
   no socket events. The only CE network lifecycle observed is connection
   **cycling** — a fresh socket pair per generation (55148/55210 → 55724/55875),
   remote side closing after each exchange (`CLOSE_WAIT` residue) — which is
   event-driven, not timer-driven. Expect bursts at uploads/config pulls, not a
   fixed short-interval poll.
3. **DNS is cache-first.** `api.cvnt.net` carried an ~18 h TTL and was resolved
   from cache; CE issued no DNS queries in the window. OS-level resolution in
   this environment runs over DoH (`cloudflare-dns.com`), which is why plain
   port-53 captures would see almost nothing — relevant for Linux-side observers.
4. **Local IPC is dormant without the UI.** The comm service's `127.0.0.1:48867`
   listener had no clients while `VictoryShield.exe` wasn't running; the
   55210/55148 sockets are uplink-side TCP, not a UDP protocol.
5. **All payloads TLS.** Everything CE would send is inside TLS to one hostname;
   without endpoint cooperation a Linux client's traffic is equally opaque to
   passive observers — the same SNI/DNS/flow-metadata layer is the only passive
   surface, which this capture demonstrates end-to-end (SNI extraction works on
   full-packet captures).

## Linux-reimplementation notes (brief)

- Model the uplink as **one TLS endpoint** (`api.cvnt.net:443`) with two parallel
  connections per generation (new ephemeral local ports on reconnect; server
  closes after each exchange). Expect long idle periods with zero traffic.
- Keep the only IPC surface a loopback listener owned by the comm daemon; UI
  components attach on demand.
- Heartbeat/bookkeeping timestamps update on a strictly periodic 601 s timer
  with **no network I/O** (observed live); do not equate "heartbeat" with
  "network poll". Uplink sockets are per-generation (new pair on reconnect,
  server closes after each exchange).
- Client-side DNS caching (long TTL, cache-first) is part of the observed
  behavior; emit clear SNI (`api.cvnt.net`) if passive-debuggability parity is
  desired.
- No separate update/classifier endpoints observed in idle state — fetch such
  data on-demand over the same or a config-specified endpoint.

## Open questions

1. **What triggers the backend-connection cycling?** One cycle was observed
   (55148/55210 → 55724/55875 in the 18:11:37–18:29:5x gap, already `CLOSE_WAIT`
   at first sighting). It is not tick-driven; a longer capture would show the
   interval and whether CE or the server initiates each generation.
2. **Why two parallel connections to the same host:port**, with independent
   lifecycles and per-connection `Bound` shadow sockets? Role split (events vs.
   commands) vs. redundancy — needs longer observation or binary RE.
3. **Who closes first, and when does CE reap `CLOSE_WAIT` sockets?** Both
   generations sat half-open indefinitely after the remote FIN. Lazy close,
   intentional hold, or leak?
4. When do **update checks (WinSparkle appcast), classifier-data fetches, and
   OCSP/CRL checks** actually occur? 10.1.1-era logs
   (`re/findings/02-artifacts/logs.md`) show hourly `ServerTimeManager::sync` and
   daily appcast cadences — far longer than this window (which is consistent
   with seeing none).
5. What is the **protocol on 48867** (listener only; byte-less accept/close per
   `process-observation.md`, no client in window)? [INFERENCE] local IPC for
   UI/tools; wire format unknown.
6. Why is `LastTelemetryUploadAt` frozen at **2026-09-20T04:35:45** while
   `ApiTelemetryStatus` says `success`? [INFERENCE] "upload" is a distinct,
   rare event (accounting payload), not the frequent heartbeat.
7. Are the two backend sockets actually **TLS sessions to `api.cvnt.net`**
   (SNI unobservable — no handshake in any window)? Would be confirmed by
   catching a reconnect with a capture running.
