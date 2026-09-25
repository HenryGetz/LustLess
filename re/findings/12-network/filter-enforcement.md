# DNS/URL filter ENFORCEMENT internals — VictoryShieldCommService.exe (10.1.44)

Scope: enforcement-side internals of the filter in `VictoryShieldCommService.exe` (the `DnsProxy`
family, the DoH resolver, `dns_activity` attribution, `user_dns_filter`/domain-override DB binding,
`DnsProxyDisable` + DNS-server management, and the cleanbrowsing telemetry). Answers the five open
questions of `filter-surface.md` §Open questions (1–4; #5 is ServiceIpcPass scope). Non-goals:
client-side filter state flow (done, `filter-surface.md`), backend upload protocol, IPC transports.
All addresses are VAs in `VictoryShieldCommService.exe` (image base `0x140000000`, Ghidra project
`CE`); function names are Ghidra `FUN_…` labels mapped to CE's own log-scope/RTTI names below.

## What it does

**The 10.1.1 "legacy DNS proxy" is not gone — it is the enforcement engine of 10.1.44.** The
comm service statically contains the full `DnsProxy` module (`D:\…\x64\DnsProxy\src\{DnsProxyServer,
DnsProxySocket, DnsProxy, DnsProxyRequest, DohLookupStatus, DnsPhysicalAdapterStore}.cpp`), and it
is the *only* enforcement point in the product: a per-adapter user-mode DNS proxy that (1) has the
machine's DNS servers pointed at its own loopback listener (`127.0.0.2`), (2) resolves every query
**twice** — once through the per-user CleanBrowsing filter path (DoH, RFC 8484, via a custom
Boost.Beast `DnsHttpClient`) and once through the user's own resolvers ("user path"), (3) picks the
answer according to a per-query decision tree that consults the `custom_domain_overrides` /
`global_domain_overrides` tables and the CleanBrowsing block marker, synthesizing block answers
locally when needed, and (4) records every query to `ce-file.dns_activity` with `process_id` /
`process_name` attributed **at query time from the Windows UDP owner table** (`GetExtendedUdpTable`
`MIB_UDPTABLE_OWNER_PID`, client source port → PID).

There is **no URL/HTTP content inspection anywhere in the service** — `has_url_filtering` has no
enforcement consumer; "URL filtering" is realized purely as DNS-level domain overrides plus
CleanBrowsing category filtering selected by `user_dns_filter.clear_browsing_level` /
`over_https_url`. The proxy runs only while at least one "DNS proxy user" is signed in
(`UserEventMessageQueueListener::checkForProxySwitch` ref-counts them), and per-lookup health is
reported as `client_cleanbrowsing_success`/`client_cleanbrowsing_problem` metrics into
`ce-file.metrics`; the `covenanteyesfilter.com/healthcheck` probe does **not** exist in the service
(it stays UI-side, `filter-surface.md` §6).

### Explicit verdicts (assignment acceptance criteria)

**(a) DoH query issuer + `dns_activity` attribution.** The issuer is the service's own
**`DnsHttpClient`** (custom async HTTPS client on Boost.Beast/Boost.Asio `ssl_stream`), driven by
`DnsProxySocket::sendDohRequest` = **`FUN_1402d7f50`** (completion lambda `FUN_1402d8fc0`); the
request is an RFC 8484 DoH **GET `?dns=<wire-query>`** (literal `"?dns="` `0x1409b9db8`) over TLS to
port 443 (literal `"443"` `0x140a8ca08`) at the per-user `over_https_url` (default
`https://dns.cleanbrowsing.org/doh/adult-filter`, `0x1409aac38`). It is **not** curl
`CURLOPT_DOH_URL` (libcurl + its `doh.c` are statically linked — `Content-Type: application/dns-message`
`0x1408a1490`, `DoH request %s` `0x1408a1458` — but no curl DoH call site exists on this path; the
request plumbing is the `DnsHttpClient::RequestOp<…sendDohRequest…>` RTTI family `0x1409ba270`+)
and **not** WinHTTP/WinINet (neither DLL is imported). Attribution: at packet arrival,
`DnsProxyServer::handleDnsPacketUnsafe` (**`FUN_1402990e0`**) resolves `getPidFromUdpPort(port,
isV6)` → **`FUN_14038c7d0`** (scans `GetExtendedUdpTable` v4 `FUN_14038c2d0` / v6 `FUN_14038c550`
OWNER_PID rows for `ntohs(dwLocalPort) == client source port`, returns `dwOwningPid`; fatal
`"Unable to find a PID owning v4 UDP port "` on miss), then the process name via **`FUN_1401d6e70`**
(PSAPI `EnumProcessModules`+`GetModuleBaseNameA` `FUN_1401d8320`, default `"unknown"`). PID+name
ride on the `DnsProxyRequest` (identity struct at `request+0x41b8`, first dword = PID) and are
written by **`DnsProxyRequest::logDnsActivity` = `FUN_1402b9ba0`** into a `CEDnsEntry`
(`std::_Ref_count_obj2<CEDnsEntry>` `0x140ab…`) pushed on `DnsSqliteLogsQueue`
(`QueuedActivityLogger<UCEDnsEntry>` RTTI `0x140abb9f8`/`0x140abba38`) → `DnsSqliteTable::insert`
**`FUN_14025f710`** → `ce-file.dns_activity` INSERT with `status='queued'` (SQL literal `0x1409afcb0`).
So `dns_activity` rows come from the proxy's per-query log step, keyed to the querying process by
the UDP port owner table — no ETW, no hooks, no WFP.

**(b) What enforces `has_url_filtering`.** Nothing URL-specific: `has_url_filtering` (and
`has_dns_filtering`) are only settings fields in the service (deserialize `FUN_140253680`
`"deserialize has_url_filtering"` `0x1409aee68`, `user_info` columns via `UserInfoSqliteTable::set`
`FUN_140254d10`; no other consumers — xref-complete for `0x1409aed60`). All enforcement is the DNS
decision tree in `DnsProxyRequest::processDnsRequest` (**`FUN_1402ba390`**), whose per-query
`resolution_type` verdict (mapper `FUN_1402b9a10`) is:

| code | `resolution_type` | trigger (evidence) |
|---|---|---|
| 0xb | `BlockedCustom` | custom-override verdict `request+0x41a0 == 1` → `overrideForBlocking` `FUN_1402bde10`, log `Proxy blocking (C) override activated for ` `0x1409b57a8` |
| 10 | `BlockedGlobal` | global-override verdict `request+0x41a4 == 1` → `overrideForBlocking`, log `Proxy blocking (G) override activated for ` `0x1409b5778` |
| 9 | `BlockedFilter` | `overrideForCleanBrowsingBlocking` `FUN_1402bd500` says the upstream CleanBrowsing answer is a block (RPZ marker `cleanbrowsing.rpz.noc.org` `0x1409b52b8`) → answer rewritten via `overrideForBlocking`, log `Proxy blocking (CB) override activated for ` `0x1409b5720` |
| 5 / 4 | `UnrestrictedAllowCustom` / `UnrestrictedAllowGlobal` | override verdict `== 0` (explicit allow) |
| 1 / 6 | `UnrestrictedFiltered` / `UnrestrictedUnknown` | clean filter answer / flag path |
| 8 | `SafeSearchEnforced` | safe-search domain-list hit (`request+0x4188` map; log `No domain list entries for domain ` `0x1409b…`) — response taken from the filter-side answer (`local_2a7=1` switches the response endpoint) |
| 2 / 3 | `UnrestrictedUnFiltered` / `UnrestrictedAlwaysAllowable` | no filter socket (`request+0x41e0 == 0`) or always-allowable predicate `FUN_14038d2b0` |
| 7 | `UnrestrictedOutage` | DoH/filter outage state |
| 12–15 | `TimedOut`/`TimedOutFilter`/`TimedOutSystem`/`Failed` | upstream failure paths |

`overrideForBlocking` (`FUN_1402bde10`) works on the wire answer: parses the question
(`FUN_1402c03f0`), zeroes ANCOUNT/NSCOUNT/ARCOUNT, appends **synthesized RRs** built from the
matched override's answer addresses (`request+0x40a8` for A / `+0x40c0` for AAAA) plus, for A
queries, a CNAME to **`blocked.cvnt.net`** (`0x1409985f8`; name encoder `FUN_1402b5610`), and clears
the RCODE to NOERROR. I.e. domain overrides are answered **locally by the DNS proxy** — the browser
resolves "blocked" domains to a CE-controlled answer, which is what then produces the block page
served from CE infra (`blocked.cvnt.net`), not a URL layer.

**(c) DB binding for `user_dns_filter`.** `user_dns_filter`, `global_domain_overrides`,
`custom_domain_overrides` live in **`ce-user-file`** (the SQLCipher-encrypted per-user DB), while
`dns_activity`/`metrics`/`logins`/… live in **`ce-file`** (plaintext). Proof: the service opens the
two DBs with different key material — `FUN_140256910` (name `"ce-file"` `0x140996dd8`) passes an
**empty** key to the connector builder `FUN_140256490`, while `FUN_140256700` (name `"ce-user-file"`
`0x140996e30`) passes a **hard-coded key string** (24-byte blob `0xdca422723ff3e3c2…` materialized by
the magic-static `FUN_140256570` at `DAT_140ae9c98`) — matching SQLCipher (`sqlite3_key_v2`
`0x140985240`, `sqlcipher_page_cipher` strings) and matching the live DBs (ce-file is readable
SQLite with exactly the six ce-file tables; `local-db.md`). The filter-config loader
**`FUN_14023e400`** (via `FUN_1402427b0` ← `scheduleDnsProxyInitialState` `FUN_14023a7a0`) reads
`UserDnsFilterSqliteTable::get` = **`FUN_140268ba0`** (`SELECT * FROM user_dns_filter WHERE
username = ?`) and the two override tables **on one connector** (manager `+0x1d8`) and
`LoginSqliteTable` (ce-file `logins`) on the other (`+0x198`) — consistent with
`user_dns_filter`/overrides being in ce-user-file (absent from the live ce-file schema) and `logins`
being in ce-file (present). **The service never writes these tables**: exhaustive string-xref audit
of the table-name literals shows only `SELECT` + schema-migration sites —
`user_dns_filter` `0x1409b0760` → 3 refs (`FUN_140268ba0` get, `FUN_140243a50`/`FUN_1402446c0`
`ALTER TABLE user_dns_filter ADD …`), `global_domain_overrides` `0x1409b0710` → 3 refs
(`FUN_1402678f0` get + 2 ALTERs), `custom_domain_overrides` `0x1409b07d0` → same shape (get
`FUN_140269260`); contrast `dns_activity` `0x1409afc28` → 12 refs (incl. INSERT `FUN_14025f710`).
The **writer is `VictoryShield.exe`** (`UserDnsFilterSqliteTable::set`, `filter-surface.md` §3 call
sites). The service does **not** fetch `/v2/user/{u}/filter/settings/dns.json` itself (its only
`/v2/` endpoint string is `/v2/user/{username}/report/activity_log.json` `0x1409a9d90`); what it
consumes is (1) the ce-user-file tables above and (2) the serialized settings payload delivered on
the UI→service queue (`deserialize has_dns_filtering` `0x1409aedd0` etc. in `FUN_140253680` →
`UserInfoSqliteTable::set` `FUN_140254d10`).

## Mechanism

### 1. Query path end-to-end

1. **DNS redirection.** A `DnsSettingsManager` (logs `DNS settings manager [` `0x1409b4a98`,
   `enforce DNS settings` = `FUN_1402ab9f0`, `Adding DNS server addresses: ` `0x1409b4c38`,
   `DNS settings changed and got intercepted by the DNS Proxy` `0x1409b4bc8`) keeps the managed
   adapters' DNS pointed at the proxy's chosen listen address — `DnsProxy::getAvailableLocalHostAddress`
   / `selectLocalAddress` (`0x1409b42c0`/`0x1409b4328`, ` localhost address to use: ` `0x1409b4290`)
   with the constant `127.0.0.2` (`0x1409b4c60`, `0x140a8c9c8`). The local dashboard page
   "Managed DNS Settings" (`0x1409c0ca8`, HTML `0x1409c5130` "Victory Shield sets your IPv4 and IPv6
   DNS server addresses for the following network adapters that we manage:") surfaces exactly this.
2. **Packet arrival** — `DnsProxyServer::handleDnsPacketUnsafe` `FUN_1402990e0`: resolves the client
   identity (`get PID from UDP port <port>`, `FUN_14038ca30` executor wrapping `FUN_14038c7d0`;
   then `FUN_1401d6e70` for the name), logs `<family> <adapter> activity on UDP port <port> used by
   PID <pid>(<name>)`, builds the per-adapter upstream lists (adapter → `NetworkAdapter::Id` map
   `FUN_1402b12c0` at server `+0x424`, defaults `DAT_140ae3c28`/`DAT_140ae3c70`), logs
   `DNS Proxy to DNS Filter addresses: <filter> and DNS User addresses: <user> for CE user <user>`
   (`0x1409b3cf0`), and constructs a `DnsProxyRequest` (0x4248-byte object; ctor `FUN_1402b5e30`,
   marshalled by `FUN_1402a5d70`; the 22-arg ctor copies client sockaddr (`+0x3c..0x54`, client port
   at `+0x3e`), 0x2000-byte packet buffer (`+0x20a0`), queried domain (`+0x4160` — the string logged
   as "resolution for <domain>"), family int (`+0x2068`), identity
   shared_ptr (`+0x41b8`), queue (`+0x41c8`), sockets (`+0x41d8/0x41e0/0x41e8`); the CE username is
   a separate string field on the request, exact offset unresolved).
   Requests are queued on the server (`+0x42e` list) and armed with a timeout timer
   (`DnsProxyRequest::handleDnsTimeout` `0x1409b5a18`; 10.1.1 log exemplar in `logs.md`).
3. **Dual resolution.** Each request carries a *filter* socket and a *user* socket
   (`DnsProxySocket`: `sendDohRequest` `FUN_1402d7f50` for the DoH/filter path,
   `sendSocketRequest` `0x1409b9c58` (`DnsProxySocket - send to DNS server ` `0x1409b9c80`) for
   plain-UDP upstreams); the closing log line reports both:
   `DNS resolution for <domain> … Response endpoint: … Request #N took <t>ms (user: <tu>ms, filter: <tf>ms)`.
   `connection_type` for `dns_activity` is `"UDP"`/`"DoH"`/`"undefined"` (`request+0x21e8+0x10`
   selector in `FUN_1402ba390`).
4. **Decision + response.** `processDnsRequest` `FUN_1402ba390` computes the `resolution_type`
   (table above), optionally rewrites the answer (`overrideForBlocking` `FUN_1402bde10` /
   `overrideForCleanBrowsingBlocking` `FUN_1402bd500`), picks the response endpoint (`local_2a7`
   selects user vs filter answer), logs, and calls `logDnsActivity` `FUN_1402b9ba0` which formats
   `PID: <pid>(<name>) resolution for <domain> via <IPv4|IPv6> port #<p> … resolution type: <type>`
   and enqueues the `CEDnsEntry`.

### 2. DoH resolver internals (verdict a detail)

- **Client**: `DnsHttpClient` — RTTI names spell the implementation:
  `DnsHttpClient::RequestOp<async_request<lambda>(std::string const&, std::string const&,
  std::string const&, unsigned int, IpAddress::IpVersion, lambda&&)>` with stages
  `initiate / on_connected / on_sent / on_response / checked` plus a `ReconnectOp`
  (`on_resolved/on_ready/…`) (`0x1409ba270`–`0x1409bd760`), built on
  `boost::beast::flat_stream<asio::ssl::stream<beast::tcp_stream>>` (same RTTI blob). So: async
  HTTPS (asio ssl), request target assembled with the `"?dns="` literal (`0x1409b9db8`) — RFC 8484
  GET [INFERENCE: base64url payload per RFC 8484 §4.1.1; the encoder body not decompiled].
- **URL source**: the request object keeps the endpoint string at `request+0x2098`
  (`cleanbrowsing_doh_url` metric tag reads exactly this field in `FUN_1402ddd90`) — the
  `user_dns_filter.over_https_url` value, defaulted to `https://dns.cleanbrowsing.org/doh/adult-filter`
  (`0x1409aac38`; row mapper `FUN_140268060` calls `"deserialize over_https_url"` `FUN_140268d90`).
- **Pool**: per-endpoint `DnsHttpClient` pool (max 5, `if (4 < count) skip create`;
  `DoH http client added to pool: <endpoint> (N) pool size: P` `0x1409b9d78`); the request is handed
  to the least-loaded client (`Sending DoH request #<n> to Http Pool <endpoint> … queue size: Q`
  `0x1409b9d50`).
- **Answer intake** (completion `FUN_1402d8fc0`): parses the DNS response header RCODE into
  `request+0x2160` (`(flags >> 8) & 0xf`), HTTP status into `request+0x2164`
  (`DoH lookup failed: Invalid response: <code>…` `0x1409b9e38`), extracts the
  **`X-CB-Location`** response header (`s_X_CB_Location_140a8cef0` compared against the header list)
  into `request+0x2140` — that value is the `cleanbrowsing_datacenter` tag (CleanBrowsing's serving
  POP). RCODE 0/3 (NOERROR/NXDOMAIN) counts as DoH success (`FUN_1402ddc30(request, 1, 0)`),
  transport failure `FUN_1402ddc30(request, 0, 1)`, invalid response `(request, 0, 0)`.
- **`user_dns_filter` field usage**: `over_https_url` → DoH endpoint (above);
  `ipv4_primary/ipv4_secondary`/`ipv6_primary/ipv6_secondary` → the plain-DNS upstream address
  lists of the `DnsFilter` object (row mapper `FUN_140268060` packs them as two 2-entry lists and
  calls the `DnsFilter` ctor `FUN_140282d50(out, clear_browsing_level, over_https_url, ipv4_list,
  ipv6_list)`); they are the "DNS Filter addresses" the proxy forwards to on the filter socket when
  not using DoH (`DnsProxySocket::sendSocketRequest`; `DnsProxy::updateServerLists` `FUN_14029fb60`
  maintains the per-adapter lists, `Found DNS server address: ` `0x1409b1ae0`,
  ` DNS servers are available for ` `0x1409b4d08`). `clear_browsing_level` is metadata/display
  (UI shows "Blocking level set to …"); the effective filter strength is the DoH URL itself
  [INFERENCE: level→URL selection happens server-side; the service only stores/displays the pair —
  its only use is the row mapper]. Defaults: the service ships
  `2001:4860:4860::8888`/`2001:4860:4860::8844` (`0x1409b3740`/`0x1409b36b8`, Google DNS) as
  fallback constants for the address store.

### 3. `dns_activity` write path (verdict a detail)

- Entry construction: `logDnsActivity` `FUN_1402b9ba0` builds a `CEDnsEntry` via `FUN_14025eef0`
  with (domain from `request+0x4160`, PID `**(request+0x41b8)`, process name
  (lookup `FUN_1401d6e70`, default `"unknown"`), `CETime`, connection-type string, IP string
  (`FUN_1402b9a10` renders), resolution time ms = `(now - request+0x2060)/10000`, plus the
  resolution-type string). The `resolution_type` column stores the vocabulary above
  (e.g. `BlockedCustom`), `resolution_datacenter` = the `X-CB-Location` value.
- Insert: `DnsSqliteTable` `LogSqliteTable<UCEDnsEntry, DnsSqliteTableDefinition>`
  (`0x140ab56b0`), `DnsSqliteLogsQueue` (`0x140abba38`), INSERT literal `0x1409afcb0` —
  `…VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'queued', DATETIME('now'), DATETIME('now'))`.
- Outbox: upload gatherers `EntrySqliteLogGatherer<class DnsSqliteTable>::getLogs/resolveLogs`
  (`0x1409ac2e8`/`0x1409ac320`) with the claim statement `" SET status = 'sending',
  status_changed_at = DATETIME('now') WHERE "` (`0x1409ac400`); index
  `dns_activity_matching (username, status, process_name, datetime_created)` is the hot query
  (` (username, status, process_name, datetime_created)` `0x1409afe60`). Status lifecycle observed:
  `queued` → `sending` → [INFERENCE: `sent`, mirroring `metrics`' `collecting`→`sent`].
- Dashboard read-back: `ViewDnsActivityHandler` (RTTI `0x140adb218`) serves
  `SELECT domain,process_id,process_name,ip,resolution_type,connection_type,resolution_datacenter,
  resolution_time_ms,datetime_created FROM <t> ORDER BY datetime_created DESC LIMIT 500`
  (`0x1409c5530`/`0x1409c5500`) through the `http://localhost:48867` web UI, fronted by an
  in-memory `DnsActivityCache` (`0x140a9f570`).

### 4. Filter-config consumption and caching (verdict c detail)

- `UserEventMessageQueueListener::scheduleDnsProxyInitialState` (`FUN_14023a7a0`, source
  `LocalCommService\src\UserSettingsCache.cpp`) triggers the config load chain
  (`FUN_1402427b0` → `FUN_14023e400`) which, per username: reads `user_dns_filter` (get
  `FUN_140268ba0`) into a `DnsFilter` (`std::_Ref_count_obj2<DnsFilter>` `0x140ab6ad0`) cached in
  `UserSettingsCache` (manager `+0x168` keyed by `CeUsername`), reads **all** rows of
  `global_domain_overrides` (`FUN_1402678f0`, no username filter — global) into `+0x168`-region
  list, and per-user `custom_domain_overrides` (`FUN_140269260`) into `+0x178`; also refreshes the
  active-login set from ce-file `logins` (`LoginSqliteTable`, `SystemUserID` records) and the
  API-credentials/user-info side tables. `UserSettingsCache::Impl::pruneDnsFilterInactiveUsers`
  (`0x1409ae280`) evicts filters for inactive users.
- `DnsProxyRequest::getDomainOverrides` (`FUN_1402b8250`, log `Acquired DNS domain overrides for `
  `0x1409b5398` / `Unexpected issue with accessing DNS domain overrides for ` `0x1409b5358`) fetches
  the two override sets at request time and stamps the tri-state verdicts into
  `request+0x41a0` (custom: 0=allow,1=block,2=n/a) and `request+0x41a4` (global), initialized to 2
  in the ctor.
- Schema migrations exist in the service: `ALTER TABLE user_dns_filter ADD <col> <type>`
  (`FUN_140243a50`) and sibling helpers (`FUN_1402446c0`, `FUN_140243fa0`, `FUN_140244a40`) —
  the service evolves the ce-user-file schema lazily.

### 5. Proxy lifecycle, `DnsProxyDisable`, and "logout disables web access"

- **Ref-counted by user**: `UserEventMessageQueueListener::checkForProxySwitch` = **`FUN_14023dd50`**
  (UserSettingsCache.cpp:274) reads ce-file `logins`, merges the cache, counts non-`"None"`
  users (`FUN_140239f80` excludes the sentinel username `"None"` `0x140997ad8`), logs
  `Current number of active DNS proxy users: <n>` (`0x1409ae318`), then
  `n == 0 → deactivateDnsProxy(force=0)` else `activateDnsProxy()`.
- **`DnsProxyDisable` semantics (registry `HKLM\SOFTWARE\Covenant Eyes\Victory Shield`)**:
  - `UserEventMessageQueueListener::activateDnsProxy` = **`FUN_14023d410`** (UserSettingsCache.cpp:248):
    reads `DnsProxyDisable` (wide literal, default **1**) and **runs `"Activating DNS proxy"` +
    `"start dns proxy direct"` (`FUN_140242110`) only when the value == 1**.
  - `UserEventMessageQueueListener::deactivateDnsProxy` = **`FUN_14023d8a0`** (:261): runs
    `"Deactivating DNS proxy"` + `"stop dns proxy direct"` (`FUN_140242460`) only when
    **value == 0 OR the force parameter is set**.
  - Verdict: with the live value `DnsProxyDisable = 1` (`01000000`), activation is permitted and the
    user-count-driven stop is a no-op — i.e. **`1` behaves as "the DNS proxy cannot be disabled"**
    (sticky-on; only a forced stop can tear it down). The name is inverted relative to the observed
    gating; vs-config's `disableDnsProxy`(→1)/`enableDnsProxy`(→0) writers (`filter-surface.md` §5)
    use the opposite labeling [INFERENCE: the flag historically meant "the 10.1.1 proxy-disable
    switch is itself disabled"; treat `1 = proxy runs and is not torn down` as the operative
    semantics].
  - Down the stack: `ce::local_comm_service::agent::startDnsProxy/stopDnsProxy/restartDnsProxy`
    (`0x140999cc8`/`0x140999c68`/`0x140999548`, plus user-defined command handlers
    `handling a user-defined stop/start/restart DNS proxy command` `0x140999920`–`0x140999980`) →
    `Impl::startDnsProxy/stopDnsProxy` (`0x1409ab018`/`0x1409aaf48`) with a bounded destruction
    thread (`DNS Proxy destruction thread is taking longer than allotted time` `0x1409aaf80`,
    `DNS Proxy already destroyed` `0x1409ab108`).
- **Logout → "web access off"**: on logout the signed-in-user count drops to 0 →
  `checkForProxySwitch` calls `deactivateDnsProxy(0)`; with `DnsProxyDisable=1` the stop is
  suppressed, so the proxy keeps listening with zero users [INFERENCE: it then answers from an
  empty policy — the fail-closed "no web while signed out" the tray advertises
  (`signin-and-settings.md`); this is consistent with the 10.1.1 timeout logs and the dead-filter
  "Filter guardian" break-glass text]. If the stop *is* taken (value 0/forced), the adapter DNS
  redirection is what remains — `Removing DNS servers (start/complete)` `0x1409b4270`/`0x1409b4090`
  and `reset DNS settings` `0x14099a838` are the teardown writes.

### 6. DNS-server management and the `fec0:0:0:ffff::1-3` residue

- The service owns the adapter-DNS write path: registry backups under
  `HKLM\SOFTWARE\Covenant Eyes\Victory Shield\NetworkInterfaces\{IPv4|IPv6}\<adapterId>`
  (`NameServer` `0x1409a5818`, `DnsAddresses` `0x14099c6a8`), restore logs
  `restoring DNS configuration for adapter <id>` `0x1409a5948` /
  `restoring DNS configuration for ALL network adapters` `0x1409a5a28` /
  `removing adaptor settings` `0x1409a59e8`, plus the enforcement loop `enforce DNS settings`
  (`FUN_1402ab9f0`) and change interception (`DNS settings changed and got intercepted by the DNS
  Proxy` `0x1409b4bc8`); `DnsPhysicalAdapterStore.cpp` keeps the per-adapter state
  (`Removing server (erase/shutdown) for IPv4/IPv6 adapter: ` `0x1409b40e8`–`0x1409b4228`).
- **`fec0:0:0:ffff::1-3`: zero references in 10.1.44's comm service** — exhaustive scan of
  `re/samples/00-baseline/VictoryShieldCommService.exe` found no `fec0` ASCII/UTF-16 string and no
  16-byte `fec0:0:0:ffff::` binary pattern (only a base64 false positive). The 10.1.44 listener
  address is `127.0.0.2`; the fec0 trio appears only in 10.1.1-era logs as the *user-side upstreams*
  (`logs.md`: `Failed to receive response from fec0:0:0:ffff::1, … DNS User server(s)`) and as
  residue on `Loopback Pseudo-Interface 1`'s IPv6 DNS list (`network-capture.md`). Verdict: the
  residue is **10.1.1 configuration left behind; 10.1.44 neither writes nor reads it** — cleanup
  would only occur through the restore path (`restoring DNS configuration for …`), which writes back
  the saved `DnsAddresses`/`NameServer` values [INFERENCE: if the 10.1.1-era backup captured fec0
  values, restoring could reintroduce them; unverified].

### 7. Health + enforcement telemetry (cleanbrowsing metrics)

- **The service never references `covenanteyesfilter.com`/`healthcheck`** (string search = 0 hits);
  the UI's `testDnsBlocking` probe remains the only healthcheck (`filter-surface.md` §6).
- The service's own health signal is per-DoH-lookup metrics emitted by **`FUN_1402ddd90`**
  (the `DohLookupStatus` reporter, called from the DoH completion path):
  - name: `client_cleanbrowsing_success` (`0x14099a2a8`) or `client_cleanbrowsing_problem`
    (`0x14099a2c8`);
  - indexed tags: `cleanbrowsing_datacenter` (`0x1409b9aa8`, = `X-CB-Location`),
    `cleanbrowsing_doh_url` (`0x1409b9a90`, = `over_https_url`); on failure additionally
    `dns_rcode` (`0x1409b9a50`… `0x1409987d0`), `doh_response_code` (`0x1409b9a68`), and
    `doh_request_reason` = `"typical"` / `"error-recovery"` (`0x1409b9a50`, chosen by the
    `DohLookupStatus` object flag at `+0x78`);
  - fields: `success_count=1` + `latency` (ms) on success; `error_count=1` or `timeout_count=1` on
    failure (`0x1409987b0`/`0x1409987e0`/`0x1409987a0`);
  - sink: `MetricsSqliteTable` upsert (`FUN_1401e63a0`) on **ce-file** (the reporter opens
    `FUN_140256910` explicitly) — rows land in `ce-file.metrics` and follow the normal
    `collecting`/`sent` outbox (`Metrics::Metrics(bool)` `FUN_1401e5e60` wires the
    `MetricsSqliteLogsQueue`/`QueuedActivityLogger<CEMetricsEntry>`).
- **Outage machine** (this is the service-side "filter health"): `DohLookupStatus`
  (`DohLookupStatus.cpp` `0x1409b5dc0`) implements `startOutage` (`0x1409b5d48`),
  `updateForFilterOutage` (`0x1409b5d68`), `isTimeToSendTestPacket` (`0x1409b5d90`),
  `cancelOutageTimer` (`0x1409b5e28`), `endOutage` (`0x1409b5ef0`), `manageOutageRecovery`
  (`0x1409b5f10`), `purgeLookupQueues` (`0x1409b5f38`), `startOutageRecoveryTimer`
  (`0x1409b5f60`): during an outage it periodically sends **test packets** through the DoH path
  (`doh_request_reason = "error-recovery"`) and while broken the decision tree emits
  `UnrestrictedOutage` (code 7) / falls back to the user's resolvers. UI-side healthcheck results
  feed the same metric names through the UI's own metrics pipeline [INFERENCE: server-side
  aggregation of `client_cleanbrowsing_problem` is a backend concern (not client-reachable);
  client-side it is just another `metrics` row].

## Evidence

Ghidra MCP (project `CE`, program `VictoryShieldCommService.exe`; decompiled unless noted):

- **DnsProxy core**: `FUN_1402990e0` (`DnsProxyServer::handleDnsPacketUnsafe` — identity, upstream
  lists, request creation, queueing, timeout arm), `FUN_1402b5e30` (DnsProxyRequest ctor: field
  layout `+0x3c` sockaddr, `+0x3e` client port, `+0x2060` start ticks, `+0x2068` family,
  `+0x20a0` 8 KiB packet, `+0x2080` answer size, `+0x2098` DoH URL, `+0x20e8/0x20f0` username,
  `+0x2120` request #, `+0x2130` DohLookupStatus, `+0x2140` X-CB-Location, `+0x2160` RCODE,
  `+0x2164` HTTP status, `+0x21e8/0x2208` answer buffer, `+0x2210` metrics queue,
  `+0x4160` domain, `+0x4180` qtype, `+0x4188` safe-search map, `+0x4198` request #, `+0x41a0/+0x41a4`
  custom/global verdicts, `+0x41a8` filter-state obj (`+0x78` flag), `+0x41b8` identity (dword PID),
  `+0x41c8` dns queue, `+0x41d8/0x41e0/0x41e8` sockets, `+0x40a8/+0x40c0` override A/AAAA answers),
  `FUN_1402ba390` (processDnsRequest — full decision tree, `(C)`/`(G)`/`(CB)` branches,
  `local_2a0[0]` = resolution code, `local_2a7` = response endpoint selector),
  `FUN_1402bde10` (overrideForBlocking — synthetic answers, `blocked.cvnt.net` CNAME),
  `FUN_1402bd500` (overrideForCleanBrowsingBlocking), `FUN_1402b8250` (getDomainOverrides),
  `FUN_1402b9a10` (resolution_type vocabulary switch), `FUN_1402b9ba0` (logDnsActivity),
  `FUN_14029fb60` (DnsProxy::updateServerLists — partially reviewed),
  `FUN_14029df50` (removeServers), `FUN_1402ab9f0` (enforce DNS settings).
- **DoH**: `FUN_1402d7f50` (DnsProxySocket::sendDohRequest — pool ≤5, `?dns=` request build,
  least-loaded client pick, `isTimeToSendTestPacket` inlined), `FUN_1402d8fc0`
  (completion lambda — RCODE/HTTP parse, `X-CB-Location` extract, success/timeout flags),
  `FUN_1402ddc30` (DohLookupStatus update), `FUN_1402ddd90` (metrics emitter).
  RTTI: `DnsHttpClient::RequestOp/ReconnectOp…` `0x1409ba270`–`0x1409bd760`,
  `boost::beast::…ssl_stream…` `0x140abc120`/`0x140abca70`. Literals: `"?dns="` `0x1409b9db8`,
  `"443"` `0x140a8ca08`, CleanBrowsing default `0x1409aac38`.
- **Attribution**: `FUN_14038c2d0` (`GetExtendedUdpTable` v4 `MIB_UDPTABLE_OWNER_PID` snapshot,
  error tag `GetExtendedUdpTableV4`), `FUN_14038c550` (v6), `FUN_14038c7d0` (port→PID scan +
  `Unable to find a PID owning v4/v6 UDP port `), `FUN_14038ce60` (thin resolver wrapper),
  `getPidFromUdpPort` lambda named inside `FUN_1402990e0`, `FUN_1401d6e70` (PID→name, default
  `"unknown"`), `FUN_1401d8320` (PSAPI module name). IAT `GetExtendedUdpTable` real slot
  `0x14085f340` (PE import parse of the local sample; note `00-baseline/…CommService…md` IAT
  addresses are off by section mapping).
- **DB binding**: `FUN_140256910` (ce-file open, empty key; name `0x140996dd8`), `FUN_140256700`
  (ce-user-file open, key blob `0xdca422723ff3e3c2…` via `FUN_140256570` magic-static at
  `DAT_140ae9c98`; name `0x140996e30`), `FUN_140256490`/`FUN_140269680` (connector config/ctor),
  `FUN_14023e400` (filter-config loader: `user_dns_filter`+overrides on `+0x1d8` connector,
  `LoginSqliteTable` on `+0x198`), `FUN_140268ba0` (`SELECT * FROM user_dns_filter WHERE username = ?`),
  `FUN_140268060` (row→`DnsFilter` mapper: `clear_browsing_level`,`ipv4_primary`,`ipv4_secondary`,
  `ipv6_primary`,`ipv6_secondary`,`over_https_url`), `FUN_140243a50`/`FUN_1402446c0`/`FUN_140243fa0`/
  `FUN_140244a40` (ALTER TABLE migrations), `FUN_14025f710` (dns_activity INSERT `0x1409afcb0`),
  `FUN_140254d10` (UserInfoSqliteTable::set), `FUN_140253680`/`FUN_140254a70` (settings deserialize).
  SQLCipher strings `0x140985240` (`sqlite3_key_v2`), `0x140984d30`+; RTTI table inventory
  `0x140ab65a0`–`0x140ab7ae0` (`UserDnsFilterSqliteTable`, `Global/CustomDomainOverridesSqliteTable`,
  `DnsSqliteTable`, `MetricsSqliteTable`, `LoginSqliteTable`, `UserInfoSqliteTable`,
  `TelemetrySqliteTable`, `ApiCredentialsSqliteTable`, `UserLoginSqliteTable`,
  `HttpClientTracingSqliteTable`, `InstallMetadataSqliteTable`, `CircumventionSqliteTable`,
  `SwitchUserSqliteTable`).
  String-xref audit (get_xrefs_to): `user_dns_filter` `0x1409b0760` → 3 code refs (get + 2 ALTERs);
  `global_domain_overrides` `0x1409b0710` → 3; `dns_activity` `0x1409afc28` → 12 (incl. INSERT).
- **Lifecycle**: `FUN_14023dd50` (checkForProxySwitch — user count + activate/deactivate dispatch),
  `FUN_14023d410` (activateDnsProxy: `DnsProxyDisable==1` gate), `FUN_14023d8a0`
  (deactivateDnsProxy: `==0 || force` gate), `FUN_140242110`/`FUN_140242460` (start/stop direct),
  `FUN_14023a7a0` (scheduleDnsProxyInitialState), `FUN_140239f80` (sentinel-user predicate,
  `"None"` `0x140997ad8`), `FUN_14023cd60` (`Failed to check for DNS Proxy switch` wrapper).
- **Strings (selected)**: `blocked.cvnt.net` `0x1409985f8`/`0x1409986a8`, `cleanbrowsing.rpz.noc.org`
  `0x1409b52b8`, `X-CB-Location` (`s_X_CB_Location_140a8cef0`), override logs `0x1409b5720`/`0x1409b5778`/`0x1409b57a8`,
  `DNS Proxy to DNS Filter addresses: ` `0x1409b3cf0`, ` user DNS address(es) to Proxy to for Adapter: `
  `0x1409b3d18`, `Current number of active DNS proxy users: ` `0x1409ae318`, metric names
  `0x14099a2a8`/`0x14099a2c8`, metric tags `0x1409b9a50`–`0x1409b9aa8`, dns_activity SQL
  `0x1409afcb0`/`0x1409afe60`, outbox claim `0x1409ac400`, DNS-config strings `0x1409a5818`/`0x14099c6a8`/
  `0x1409a5948`/`0x1409a5a28`/`0x1409b47a8`/`0x1409b4bc8`/`0x1409b4c38`, `127.0.0.2` `0x1409b4c60`/`0x140a8c9c8`,
  dashboard `0x1409c0ca8`/`0x1409c5130`, `ViewDnsActivityHandler`/`DnsActivityCache` RTTI
  `0x140adb218`/`0x140a9f570`, SELECT for dashboard `0x1409c5530`.
- **Negative evidence**: string search of `VictoryShieldCommService.exe` for
  `healthcheck|covenanteyesfilter` = 0 matches; `fec0` = 0 matches (ASCII + raw16-byte pattern scan
  of `re/samples/00-baseline/VictoryShieldCommService.exe`); `dns.json|domains.json|filter/settings`
  = 0 matches (only `/v2/user/{username}/report/activity_log.json` `0x1409a9d90`); `WinHTTP`/`WinINet`
  not in the 17-DLL import table (`00-baseline` doc).
- Cross-refs: `re/findings/12-network/filter-surface.md` (state model, UI side, open questions),
  `re/findings/02-artifacts/local-db.md` (ce-file schema/outbox), `logs.md` (10.1.1 DnsProxyRequest
  log exemplars), `re/findings/03-runtime/network-capture.md` (live: no port-53 listener at capture,
  fec0 residue location).

## Linux-reimplementation notes

- The architecture to copy is exactly the 10.1.44 one, minus the Windows DNS-server pinning: a
  local DNS forwarder (systemd-resolved/DNS stub or a small daemon on 127.0.0.2:53) that resolves
  each query via DoH to a per-user CleanBrowsing-class endpoint (RFC 8484 GET is trivial with
  hickory-dns or `https://` + `?dns=`), with the user's original resolvers as a parallel/second
  path and an explicit per-query verdict. CE's `resolution_type` vocabulary (15 codes, §verdict b)
  is a good schema for the `dns_activity` rows; keep `blocked.<your-domain>` as the synthetic
  CNAME for block answers so a block page can be served.
- Attribution: replicate `getPidFromUdpPort` with `SOCK_DIAG`/`inet_diag` netlink (UDP inode → PID
  via `/proc/*/fd`), or simply run the resolver as the system stub and drop `process_id` to the
  conntrack owner; CE's port-table lookup is racy (a client can close the socket before the lookup,
  and CE treats a miss as fatal `"Unable to find a PID owning v4 UDP port"`).
- DoH client: a plain HTTPS client with a small per-endpoint connection pool (CE: ≤5 clients,
  least-loaded dispatch) is enough — no libcurl DoH needed. Keep the `X-CB-Location`-style response
  header as a `resolution_datacenter` tag; it made CE's fleet debugging possible.
- Config: store `user_dns_filter` (endpoint URL + fallback IPs + level) and the two override lists
  in the daemon's own DB; CE's split (config in an encrypted per-user DB, event outbox in a plain
  one) is Windows-era baggage — one SQLite with a sane permission model suffices. Do keep the
  outbox (`queued → sending → sent`) and `(username, status, …)` indexes.
- Telemetry: emit per-lookup counters (`success_count`/`error_count`/`timeout_count`) + latency with
  the resolver URL and datacenter tags — CE's `client_cleanbrowsing_*` shape is fine; drive an
  explicit outage state machine (CE's `DohLookupStatus`: outage → timed test packets → recovery
  timer) so filter breakage is observable and fail-closed behavior is a deliberate choice, not an
  accident.
- Lifecycle: gate the forwarder on "≥1 user needs filtering" like CE's `checkForProxySwitch`, but
  make the fail-closed semantics explicit and locally overridable (CE's sticky-on
  `DnsProxyDisable=1` + dead "Filter guardian" dialog left users with no working break-glass).

## Open questions

1. `DnsProxy::updateServerLists` (`FUN_14029fb60`) not fully decompiled: the exact mapping of
   `DnsFilter.ipv4/ipv6_primary/secondary` vs. the adapter's own resolvers into the "DNS Filter" vs
   "DNS User" lists (and when the DoH transport is preferred over `sendSocketRequest`) is
   [INFERENCE]-level above; the log strings and the `DnsFilter` ctor are the anchors.
2. `DnsProxyDisable` naming inversion (§5): confirm against `vs-config.exe`'s
   `ce::local_comm_service::disableDnsProxy/enableDnsProxy` byte semantics before treating `1` as
   "sticky-on" in any spec; the two binaries' labels disagree.
3. Exact cadences: `checkForProxySwitch` rescan interval (driven from
   `UserEventMessageQueueListener` events + a scheduler whose interval was not decompiled),
   `DohLookupStatus` outage timer values, and the `enforce DNS settings` loop period (the 10.1.1
   logs suggest 60 s; unverified for 10.1.44).
4. The RFC 8484 payload encoder (base64url vs POST body) inside `DnsProxySocket::sendDohRequest`
   — request-target assembly seen (`"?dns="`) but the encoder body not decompiled
   [INFERENCE: GET + base64url].
5. What the proxy answers while zero users are signed in (the fail-closed claim in §5 is
   [INFERENCE]; verifying needs a live capture with a signed-out session).
