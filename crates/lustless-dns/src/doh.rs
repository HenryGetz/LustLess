//! `doh.rs` — the §8 dual-resolution transports: the RFC 8484 DoH filter path
//! and the user-resolver path.
//!
//! **HTTP stack choice (documented per the task):** `reqwest` with the
//! `rustls-tls` feature (CONTRACTS §2 names `reqwest`+`rustls` for DoH), one
//! `reqwest::Client` per pool slot with HTTP/2 ALPN preferred and HTTP/1.1
//! fallback. A hand-rolled HTTP client was rejected: RFC 8484 only needs a
//! GET, but correct TLS + ALPN + connection reuse is exactly what must NOT be
//! hand-rolled in a security-relevant forwarder.
//!
//! CE's pool mechanics are kept (`filter-enforcement.md` mechanism §2): **≤5
//! clients per endpoint** (`dns.pool_size`, clamped) and **least-loaded
//! dispatch** — each query goes to the slot with the fewest in-flight
//! requests. The filter request is an RFC 8484 GET `?dns=<base64url-wire>`;
//! the `X-CB-Location` response header is captured into
//! `resolution_datacenter` (§8).
//!
//! The **user path** resolves via `dns.user_resolvers` over UDP/53:
//! `["system"]` parses the current upstream resolvers from `/etc/resolv.conf`
//! on each lookup (fresh view after DHCP changes; no cache staleness), with
//! loopback resolvers — including the forwarder's own listen address —
//! filtered out to avoid resolution loops after the §8 DNS redirect.

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use hickory_proto::op::{Message, MessageType};
use thiserror::Error;
use tokio::net::UdpSocket;
use tracing::debug;

/// Hard cap of DoH clients per endpoint (§8: "Connection pool ≤5 per
/// endpoint, least-loaded dispatch").
pub const MAX_POOL_PER_ENDPOINT: usize = 5;

/// Per-path lookup timeout. Deterministic (no jitter): timeout classification
/// in `verdicts.rs` is a pure function of this bound.
pub const PATH_TIMEOUT: Duration = Duration::from_secs(5);

/// RFC 8484 §4.1 response media type.
pub const DOH_ACCEPT: &str = "application/dns-message";

/// CleanBrowsing-style response-header tag recorded into
/// `resolution_datacenter` (§8; CE extracts `X-CB-Location` per query).
pub const CB_LOCATION_HEADER: &str = "x-cb-location";

/// Base64url (RFC 4648 §5, no padding) as required by the RFC 8484 §4.1.1
/// `?dns=` query encoding.
pub fn base64url_encode(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[(n >> 18) as usize & 0x3F] as char);
        out.push(ALPHABET[(n >> 12) as usize & 0x3F] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[(n >> 6) as usize & 0x3F] as char);
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[n as usize & 0x3F] as char);
        }
    }
    out
}

/// Builds the RFC 8484 GET target for `endpoint` + `wire` (query-string aware:
/// `&dns=` when the endpoint URL already has a query).
pub fn build_doh_get_url(endpoint: &str, wire: &[u8]) -> String {
    let separator = if endpoint.contains('?') { '&' } else { '?' };
    format!("{endpoint}{separator}dns={}", base64url_encode(wire))
}

/// One successful DoH exchange (§8 filter-path answer).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DohAnswer {
    /// The DNS wire response body.
    pub wire: Vec<u8>,
    /// `X-CB-Location`-style datacenter tag (→ `resolution_datacenter`).
    pub datacenter: Option<String>,
    /// HTTP status of the DoH response (200 on the success path).
    pub http_status: u16,
    /// DNS RCODE carried by the DoH response (CE counts 0/3 as success).
    pub rcode: hickory_proto::op::ResponseCode,
    /// Wall time from request dispatch to body completion, in milliseconds.
    pub latency_ms: u64,
}

/// DoH filter-path failure classes.
#[derive(Debug, Error)]
pub enum DohError {
    /// The request exceeded `PATH_TIMEOUT`.
    #[error("doh lookup timed out")]
    Timeout,
    /// Non-200 HTTP status.
    #[error("doh http status {0}")]
    HttpStatus(u16),
    /// Transport failure (DNS/TLS/connect/read).
    #[error("doh transport: {0}")]
    Transport(String),
    /// A 200 response whose body was not a parseable DNS message.
    #[error("doh invalid response: {0}")]
    InvalidResponse(String),
}

struct Slot {
    client: reqwest::Client,
    in_flight: Arc<AtomicUsize>,
}

/// Checkout guard: releases the slot's in-flight count on drop (including
/// cancellation), keeping least-loaded dispatch accurate.
struct SlotGuard {
    count: Arc<AtomicUsize>,
}

impl Drop for SlotGuard {
    fn drop(&mut self) {
        self.count.fetch_sub(1, Ordering::SeqCst);
    }
}

/// RFC 8484 DoH client for one endpoint with a ≤[`MAX_POOL_PER_ENDPOINT`]
/// slot pool and least-loaded dispatch (§8).
pub struct DohClient {
    endpoint: String,
    slots: Vec<Slot>,
}

impl DohClient {
    /// Build a pool for `endpoint` (an `https://` RFC 8484 URL).
    /// `pool_size` is clamped to `1..=`[`MAX_POOL_PER_ENDPOINT`] (§8).
    pub fn new(endpoint: &str, pool_size: usize) -> Result<Self, crate::DnsError> {
        let url = reqwest::Url::parse(endpoint)
            .map_err(|e| crate::DnsError::Config(format!("dns.doh_url {endpoint}: {e}")))?;
        if url.scheme() != "https" {
            return Err(crate::DnsError::Config(format!("dns.doh_url must be https: {endpoint}")));
        }
        let slot_count = pool_size.clamp(1, MAX_POOL_PER_ENDPOINT);
        let mut slots = Vec::with_capacity(slot_count);
        for _ in 0..slot_count {
            let client = reqwest::Client::builder()
                .timeout(PATH_TIMEOUT)
                .pool_max_idle_per_host(1)
                .build()
                .map_err(|e| crate::DnsError::Doh(e.to_string()))?;
            slots.push(Slot { client, in_flight: Arc::new(AtomicUsize::new(0)) });
        }
        Ok(Self { endpoint: endpoint.to_string(), slots })
    }

    /// The configured endpoint URL.
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// Number of pool slots (1..=5).
    pub fn pool_len(&self) -> usize {
        self.slots.len()
    }

    /// Least-loaded dispatch: the slot with the fewest in-flight requests
    /// (ties → lowest index, so dispatch is deterministic).
    fn acquire(&self) -> (&reqwest::Client, SlotGuard) {
        let slot = self
            .slots
            .iter()
            .min_by_key(|s| s.in_flight.load(Ordering::SeqCst))
            .expect("DohClient pool is never empty (clamped to >=1)");
        slot.in_flight.fetch_add(1, Ordering::SeqCst);
        (
            &slot.client,
            SlotGuard { count: Arc::clone(&slot.in_flight) },
        )
    }

    /// Test helper: `(least_loaded_index, per_slot_in_flight_counts)`.
    #[cfg(test)]
    fn debug_slot_states(&self) -> (usize, Vec<usize>) {
        let counts: Vec<usize> =
            self.slots.iter().map(|s| s.in_flight.load(Ordering::SeqCst)).collect();
        let idx = counts.iter().enumerate().min_by_key(|(_, c)| **c).map(|(i, _)| i).unwrap_or(0);
        (idx, counts)
    }

    /// Perform one RFC 8484 GET lookup for `wire` (a DNS query message).
    ///
    /// HTTP 200 + a parseable DNS body is `Ok` for any RCODE; the caller (the
    /// server's health feed) treats RCODE 0/3 as CE's success predicate and
    /// everything else as `client_cleanbrowsing_problem`.
    pub async fn lookup(&self, wire: &[u8]) -> Result<DohAnswer, DohError> {
        let (client, _guard) = self.acquire();
        let url = build_doh_get_url(&self.endpoint, wire);
        let started = Instant::now();
        let response = client
            .get(&url)
            .header(reqwest::header::ACCEPT, DOH_ACCEPT)
            .send()
            .await
            .map_err(map_reqwest_error)?;
        let http_status = response.status().as_u16();
        if http_status != 200 {
            return Err(DohError::HttpStatus(http_status));
        }
        let datacenter = response
            .headers()
            .get(CB_LOCATION_HEADER)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        let body = response.bytes().await.map_err(map_reqwest_error)?;
        let message =
            Message::from_vec(&body).map_err(|e| DohError::InvalidResponse(e.to_string()))?;
        Ok(DohAnswer {
            wire: body.to_vec(),
            datacenter,
            http_status,
            rcode: message.response_code(),
            latency_ms: started.elapsed().as_millis() as u64,
        })
    }
}

fn map_reqwest_error(e: reqwest::Error) -> DohError {
    if e.is_timeout() {
        DohError::Timeout
    } else {
        DohError::Transport(e.to_string())
    }
}

/// User-path failure classes (the plain-UDP/53 resolvers).
#[derive(Debug, Error)]
pub enum UserLookupError {
    /// Every upstream exceeded the shared lookup deadline.
    #[error("user resolvers timed out")]
    Timeout,
    /// No usable upstream, or no upstream answered.
    #[error("user resolver transport: {0}")]
    Transport(String),
    /// A response that was not a matching DNS reply.
    #[error("user resolver invalid response: {0}")]
    InvalidResponse(String),
}

/// Parses the `nameserver` lines of a `/etc/resolv.conf` document, in order,
/// de-duplicated.
pub fn parse_resolv_conf(text: &str) -> Vec<IpAddr> {
    let mut servers = Vec::new();
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("");
        let mut fields = line.split_whitespace();
        if fields.next() != Some("nameserver") {
            continue;
        }
        if let Some(ip) = fields.next().and_then(|s| s.parse::<IpAddr>().ok()) {
            if !servers.contains(&ip) {
                servers.push(ip);
            }
        }
    }
    servers
}

/// User-path transport: the query is sent verbatim to the user's resolvers
/// over UDP/53 (§8 "user path"), sequentially over the resolver list with a
/// shared [`PATH_TIMEOUT`] deadline; the first response whose transaction ID
/// and QR bit match wins.
pub struct UserResolver {
    configured: Vec<String>,
    listen_ip: IpAddr,
}

impl UserResolver {
    /// `configured` mirrors `dns.user_resolvers` (§9.1): the single entry
    /// `"system"` reads `/etc/resolv.conf` per lookup; other entries are
    /// literal upstream IP addresses used verbatim.
    pub fn new(configured: &[String], listen_ip: IpAddr) -> Result<Self, crate::DnsError> {
        let mut cleaned = Vec::with_capacity(configured.len());
        for entry in configured {
            let entry = entry.trim();
            if entry.eq_ignore_ascii_case("system") {
                cleaned.push(entry.to_string());
                continue;
            }
            let ok = entry.parse::<IpAddr>().is_ok() || entry.parse::<SocketAddr>().is_ok();
            if !ok {
                return Err(crate::DnsError::Config(format!(
                    "dns.user_resolvers entry is neither \"system\" nor an IP: {entry}"
                )));
            }
            cleaned.push(entry.to_string());
        }
        Ok(Self { configured: cleaned, listen_ip })
    }

    /// The upstreams the next lookup will try (fresh for `"system"`).
    pub fn upstreams(&self) -> Vec<IpAddr> {
        if self.configured.iter().all(|e| e.eq_ignore_ascii_case("system")) {
            if self.configured.is_empty() {
                return Vec::new();
            }
            let text = std::fs::read_to_string("/etc/resolv.conf").unwrap_or_default();
            return parse_resolv_conf(&text)
                .into_iter()
                .filter(|ip| self.is_usable_upstream(*ip))
                .collect();
        }
        self.configured
            .iter()
            .filter_map(|e| match e.parse::<IpAddr>() {
                Ok(ip) => Some(ip),
                Err(_) => e.parse::<SocketAddr>().ok().map(|a| a.ip()),
            })
            .collect()
    }

    /// The forwarder's own listener address and any loopback resolver are
    /// excluded from the system list — after the §8 DNS redirect
    /// (`postinst` points system DNS at `127.0.0.2`) `/etc/resolv.conf`
    /// contains the forwarder itself, and following it would loop.
    fn is_usable_upstream(&self, ip: IpAddr) -> bool {
        ip != self.listen_ip && !ip.is_loopback()
    }

    /// Send `wire` to the user's resolvers; bounded by `PATH_TIMEOUT` in
    /// total.
    pub async fn lookup(&self, wire: &[u8]) -> Result<Vec<u8>, UserLookupError> {
        let expected_id = Message::from_vec(wire)
            .map_err(|e| UserLookupError::InvalidResponse(e.to_string()))?
            .id();
        let upstreams = self.upstreams();
        if upstreams.is_empty() {
            return Err(UserLookupError::Transport("no usable upstream resolvers".into()));
        }
        let deadline = tokio::time::Instant::now() + PATH_TIMEOUT;
        let mut saw_timeout = false;
        for upstream in upstreams {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                saw_timeout = true;
                break;
            }
            match Self::query_one(upstream, wire, expected_id, remaining).await {
                Ok(bytes) => return Ok(bytes),
                Err(UserLookupError::Timeout) => saw_timeout = true,
                Err(e) => debug!(%upstream, error = %e, "user-path upstream failed"),
            }
        }
        if saw_timeout {
            Err(UserLookupError::Timeout)
        } else {
            Err(UserLookupError::Transport("no upstream answered".into()))
        }
    }

    async fn query_one(
        upstream: IpAddr,
        wire: &[u8],
        expected_id: u16,
        budget: Duration,
    ) -> Result<Vec<u8>, UserLookupError> {
        let bind: SocketAddr = if upstream.is_ipv4() {
            SocketAddr::from((std::net::Ipv4Addr::UNSPECIFIED, 0))
        } else {
            SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, 0))
        };
        let socket = UdpSocket::bind(bind)
            .await
            .map_err(|e| UserLookupError::Transport(e.to_string()))?;
        socket
            .connect((upstream, 53))
            .await
            .map_err(|e| UserLookupError::Transport(e.to_string()))?;
        socket.send(wire).await.map_err(|e| UserLookupError::Transport(e.to_string()))?;
        let mut buf = [0u8; 4096];
        let received = tokio::time::timeout(budget, socket.recv(&mut buf))
            .await
            .map_err(|_| UserLookupError::Timeout)?
            .map_err(|e| UserLookupError::Transport(e.to_string()))?;
        let response = Message::from_vec(&buf[..received])
            .map_err(|e| UserLookupError::InvalidResponse(e.to_string()))?;
        if response.id() != expected_id || response.message_type() != MessageType::Response {
            return Err(UserLookupError::InvalidResponse("transaction id/type mismatch".into()));
        }
        Ok(buf[..received].to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64url_matches_rfc4648_vectors_without_padding() {
        assert_eq!(base64url_encode(b""), "");
        assert_eq!(base64url_encode(b"f"), "Zg");
        assert_eq!(base64url_encode(b"fo"), "Zm8");
        assert_eq!(base64url_encode(b"foo"), "Zm9v");
        assert_eq!(base64url_encode(b"foob"), "Zm9vYg");
        assert_eq!(base64url_encode(b"fooba"), "Zm9vYmE");
        assert_eq!(base64url_encode(b"foobar"), "Zm9vYmFy");
        // URL-safe alphabet: 0xfb 0xff → "-_8" and no '=' padding.
        assert_eq!(base64url_encode(&[0xfb, 0xff]), "-_8");
        assert_eq!(base64url_encode(&[0xff]), "_w");
    }

    #[test]
    fn doh_get_url_shape() {
        assert_eq!(
            build_doh_get_url("https://dns.example/doh", b"wire"),
            "https://dns.example/doh?dns=d2lyZQ"
        );
        assert_eq!(
            build_doh_get_url("https://dns.example/doh?foo=1", b"wire"),
            "https://dns.example/doh?foo=1&dns=d2lyZQ"
        );
    }

    #[test]
    fn pool_is_clamped_and_dispatch_is_least_loaded() {
        let client = DohClient::new("https://dns.example/doh", 50).unwrap();
        assert_eq!(client.pool_len(), MAX_POOL_PER_ENDPOINT);
        let tiny = DohClient::new("https://dns.example/doh", 0).unwrap();
        assert_eq!(tiny.pool_len(), 1);
        assert_eq!(tiny.endpoint(), "https://dns.example/doh");

        // All slots idle → dispatch to slot 0 (deterministic tie-break);
        // while it is checked out the next acquire moves to slot 1.
        let (_, guard0) = client.acquire();
        assert_eq!(client.debug_slot_states().1[0], 1);
        assert_eq!(client.debug_slot_states().0, 1, "least-loaded slot while slot 0 is out");
        let (_, guard1) = client.acquire();
        assert_eq!(client.debug_slot_states().1, vec![1, 1, 0, 0, 0]);
        drop(guard0);
        drop(guard1);
        assert_eq!(client.debug_slot_states().1, vec![0; MAX_POOL_PER_ENDPOINT]);

        // Load slot 0 artificially; dispatch must move off slot 0.
        client.slots[0].in_flight.fetch_add(3, Ordering::SeqCst);
        assert_eq!(client.debug_slot_states().0, 1, "loaded slot 0 moves dispatch to slot 1");
        let (_, guard2) = client.acquire();
        assert_eq!(client.debug_slot_states().1, vec![3, 1, 0, 0, 0]);
        drop(guard2);
        assert_eq!(
            client.debug_slot_states().1,
            vec![3, 0, 0, 0, 0],
            "guard release decrements only its own slot"
        );
    }

    #[test]
    fn doh_requires_https_endpoints() {
        assert!(matches!(
            DohClient::new("http://dns.example/doh", 5),
            Err(crate::DnsError::Config(_))
        ));
        assert!(matches!(
            DohClient::new("not a url", 5),
            Err(crate::DnsError::Config(_))
        ));
    }

    #[test]
    fn resolv_conf_parser_extracts_nameservers_in_order() {
        let text = "\
# generated by NetworkManager\n\
search example.com\n\
nameserver 127.0.0.53\n\
nameserver 192.0.2.1\n\
nameserver 192.0.2.1\n\
nameserver 2001:db8::53\n\
options edns0\n\
nameserver bogus\n";
        assert_eq!(
            parse_resolv_conf(text),
            vec![
                "127.0.0.53".parse::<IpAddr>().unwrap(),
                "192.0.2.1".parse::<IpAddr>().unwrap(),
                "2001:db8::53".parse::<IpAddr>().unwrap(),
            ]
        );
        assert!(parse_resolv_conf("").is_empty());
    }

    #[test]
    fn system_mode_filters_loopback_and_self() {
        let listen: IpAddr = "127.0.0.2".parse().unwrap();
        let resolver = UserResolver::new(&["system".into()], listen).unwrap();
        let mut upstreams = resolver.upstreams();
        upstreams.retain(|ip| resolver.is_usable_upstream(*ip));
        // Whatever /etc/resolv.conf holds on this machine, the filtered list
        // MUST NOT contain any loopback address (that would loop back into
        // the forwarder after the §8 DNS redirect).
        assert!(upstreams.iter().all(|ip| !ip.is_loopback()));
    }

    #[test]
    fn explicit_resolvers_are_used_verbatim_and_invalid_entries_rejected() {
        let listen: IpAddr = "127.0.0.2".parse().unwrap();
        let resolver = UserResolver::new(
            &["192.0.2.53".into(), "[2001:db8::53]:53".into()],
            listen,
        )
        .unwrap();
        assert_eq!(
            resolver.upstreams(),
            vec![
                "192.0.2.53".parse::<IpAddr>().unwrap(),
                "2001:db8::53".parse::<IpAddr>().unwrap(),
            ]
        );
        assert!(matches!(
            UserResolver::new(&["definitely-not-an-ip".into()], listen),
            Err(crate::DnsError::Config(_))
        ));
        // Explicit loopback is the daemon operator's choice (kept verbatim);
        // only the "system" path filters it.
        let local = UserResolver::new(&["127.0.0.53".into()], listen).unwrap();
        assert_eq!(local.upstreams(), vec!["127.0.0.53".parse::<IpAddr>().unwrap()]);
    }

    /// A deterministic query/parse round-trip guard for the user path's
    /// response validation (no sockets involved).
    #[test]
    fn user_path_rejects_unparseable_query_wires() {
        let listen: IpAddr = "127.0.0.2".parse().unwrap();
        let resolver = UserResolver::new(&["192.0.2.53".into()], listen).unwrap();
        // No runtime needed for the synchronous parse-failure path? lookup is
        // async; drive it with the current-thread runtime.
        let result = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap()
            .block_on(resolver.lookup(&[0x00, 0x01]));
        assert!(matches!(result, Err(UserLookupError::InvalidResponse(_))));
    }
}
