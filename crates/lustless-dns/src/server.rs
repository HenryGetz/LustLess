//! `server.rs` — the §8 forwarder: tokio UDP + TCP DNS listeners on
//! `dns.listen` (default `127.0.0.2:53`) with the per-query dual-resolution
//! flow (CE `DnsProxyServer::handleDnsPacketUnsafe` +
//! `DnsProxyRequest::processDnsRequest`, `filter-enforcement.md` §1):
//!
//! 1. parse the client query (malformed → DNS FORMERR, never a panic);
//! 2. attribute the querying process from the client's UDP source port (§8);
//! 3. resolve in parallel through the DoH filter path and the user path;
//! 4. feed the health machine (§8 / §14 `client_cleanbrowsing_*`);
//! 5. compute the §8 verdict (overrides, RPZ marker, safe-search, outage,
//!    timeouts, fail-closed);
//! 6. pick the response endpoint, synthesize a block answer if required (§8);
//! 7. emit a [`DnsActivityRow`] via the [`ActivitySink`];
//! 8. answer the client — a dead query degrades to SERVFAIL within
//!    [`doh::PATH_TIMEOUT`], never a hang, never a panic.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RData, RecordType};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::watch;
use tokio::time::{interval, MissedTickBehavior};
use tracing::{debug, warn};

use crate::attribution::{Attribution, ProcessAttributor};
use crate::block::synthesize_block_answer;
use crate::doh::{DohAnswer, DohClient, DohError, UserLookupError, UserResolver};
use crate::health::{DnsHealth, FilterState};
use crate::verdicts::{decide, OverrideVerdict, PathOutcome, ResponseEndpoint, Verdict};
use crate::{ActivitySink, DnsActivityRow, DnsError, EngineMutex, HealthSink};

/// §9.1 default `dns.listen`.
pub const DEFAULT_LISTEN: &str = "127.0.0.2:53";
/// §9.1 default `dns.doh_url` (filter path).
pub const DEFAULT_DOH_URL: &str = "https://dns.cleanbrowsing.org/doh/adult-filter";
/// Domain probed by `error-recovery` test packets during an outage (§8).
pub const PROBE_DOMAIN: &str = "example.com";
/// Probe-loop tick (the test-packet timer is paced inside the health machine).
pub const PROBE_TICK: Duration = Duration::from_secs(5);
/// Idle timeout for one TCP DNS exchange.
pub const TCP_IO_TIMEOUT: Duration = Duration::from_secs(5);

/// `[dns]` settings (CONTRACTS §9.1, keys verbatim; names match their effect).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsSettings {
    /// Whether the daemon starts the forwarder at all.
    pub enabled: bool,
    /// Listener address for UDP + TCP (§8: `127.0.0.2:53`).
    pub listen: String,
    /// RFC 8484 DoH endpoint of the filter path (§8).
    pub doh_url: String,
    /// User-path resolvers; `"system"` parses `/etc/resolv.conf` per lookup.
    pub user_resolvers: Vec<String>,
    /// Whether the daemon starts the block-page HTTP server (§8).
    pub block_page: bool,
    /// Synthetic CNAME host of block answers and the block-page vhost (§8).
    pub block_page_host: String,
    /// "Signed out ⇒ web blocked" fail-closed policy flag (§8 lifecycle).
    pub fail_closed_when_signed_out: bool,
    /// DoH connections per endpoint, clamped to ≤5 (§8).
    pub pool_size: usize,
}

impl Default for DnsSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            listen: DEFAULT_LISTEN.to_string(),
            doh_url: DEFAULT_DOH_URL.to_string(),
            user_resolvers: vec!["system".to_string()],
            block_page: true,
            block_page_host: crate::block::DEFAULT_BLOCK_HOST.to_string(),
            fail_closed_when_signed_out: true,
            pool_size: crate::doh::MAX_POOL_PER_ENDPOINT,
        }
    }
}

/// Per-domain policy the engine consults per query (CE's
/// `getDomainOverrides` + safe-search/always-allowable request maps,
/// `filter-enforcement.md` verdict b). The daemon implements this over the
/// §6.2 settings DB; [`DomainListPolicy`] is the in-memory implementation
/// used for tests and daemon bootstrap.
pub trait PolicyProvider: Send + Sync {
    /// The account username activity rows are attributed to.
    fn username(&self) -> String;
    /// Custom-override tri-state for `domain`.
    fn custom_override(&self, domain: &str) -> OverrideVerdict;
    /// Global-override tri-state for `domain`.
    fn global_override(&self, domain: &str) -> OverrideVerdict;
    /// Whether `domain` hit the safe-search domain list (§8 code 8).
    fn safe_search_domain_hit(&self, domain: &str) -> bool;
    /// Whether `domain` matches the always-allowable predicate (§8 code 3).
    fn always_allowable(&self, domain: &str) -> bool;
}

/// Suffix-matching in-memory [`PolicyProvider`]: entries match the domain
/// itself or any subdomain (`ads.example.com` matches an `example.com`
/// entry), case-insensitively; the longest entry wins.
#[derive(Debug, Clone, Default)]
pub struct DomainListPolicy {
    username: String,
    custom: std::collections::HashMap<String, OverrideVerdict>,
    global: std::collections::HashMap<String, OverrideVerdict>,
    safe_search: std::collections::HashSet<String>,
    always_allowable: std::collections::HashSet<String>,
}

impl DomainListPolicy {
    /// Sets the attributed username.
    pub fn set_username(&mut self, username: impl Into<String>) -> &mut Self {
        self.username = username.into();
        self
    }

    /// Sets/overwrites the custom-override verdict for `domain`.
    pub fn set_custom_override(&mut self, domain: &str, verdict: OverrideVerdict) -> &mut Self {
        self.custom.insert(domain.to_ascii_lowercase(), verdict);
        self
    }

    /// Sets/overwrites the global-override verdict for `domain`.
    pub fn set_global_override(&mut self, domain: &str, verdict: OverrideVerdict) -> &mut Self {
        self.global.insert(domain.to_ascii_lowercase(), verdict);
        self
    }

    /// Adds a safe-search list entry.
    pub fn add_safe_search_domain(&mut self, domain: &str) -> &mut Self {
        self.safe_search.insert(domain.to_ascii_lowercase());
        self
    }

    /// Adds an always-allowable list entry.
    pub fn add_always_allowable_domain(&mut self, domain: &str) -> &mut Self {
        self.always_allowable.insert(domain.to_ascii_lowercase());
        self
    }
}

fn domain_matches_entry(domain: &str, entry: &str) -> bool {
    domain == entry || domain.ends_with(&format!(".{entry}"))
}

fn longest_override_match(
    map: &std::collections::HashMap<String, OverrideVerdict>,
    domain: &str,
) -> OverrideVerdict {
    map.iter()
        .filter(|(entry, _)| domain_matches_entry(domain, entry))
        .max_by_key(|(entry, _)| entry.len())
        .map(|(_, verdict)| *verdict)
        .unwrap_or(OverrideVerdict::NotApplicable)
}

fn list_hit(set: &std::collections::HashSet<String>, domain: &str) -> bool {
    set.iter().any(|entry| domain_matches_entry(domain, entry))
}

impl PolicyProvider for DomainListPolicy {
    fn username(&self) -> String {
        self.username.clone()
    }

    fn custom_override(&self, domain: &str) -> OverrideVerdict {
        longest_override_match(&self.custom, &domain.to_ascii_lowercase())
    }

    fn global_override(&self, domain: &str) -> OverrideVerdict {
        longest_override_match(&self.global, &domain.to_ascii_lowercase())
    }

    fn safe_search_domain_hit(&self, domain: &str) -> bool {
        list_hit(&self.safe_search, &domain.to_ascii_lowercase())
    }

    fn always_allowable(&self, domain: &str) -> bool {
        list_hit(&self.always_allowable, &domain.to_ascii_lowercase())
    }
}

/// The §8 DNS forwarder engine.
pub struct DnsServer {
    settings: DnsSettings,
    doh: Option<DohClient>,
    user: UserResolver,
    attributor: ProcessAttributor,
    policy: Arc<dyn PolicyProvider>,
    filter_state: Arc<EngineMutex<FilterState>>,
    health: Arc<EngineMutex<DnsHealth>>,
    sink: Arc<dyn ActivitySink>,
    block_host: Name,
}

impl DnsServer {
    /// Build the engine. Fails only on invalid `dns.*` configuration (§9.1);
    /// no sockets are bound here (that happens in [`DnsServer::run`]).
    pub fn new(
        settings: DnsSettings,
        sink: Arc<dyn ActivitySink>,
        health_sink: Arc<dyn HealthSink>,
        policy: Arc<dyn PolicyProvider>,
    ) -> Result<Self, DnsError> {
        let listen: SocketAddr = settings
            .listen
            .parse()
            .map_err(|e| DnsError::Config(format!("dns.listen {}: {e}", settings.listen)))?;
        let doh = if settings.doh_url.trim().is_empty() {
            None
        } else {
            Some(DohClient::new(&settings.doh_url, settings.pool_size)?)
        };
        let user = UserResolver::new(&settings.user_resolvers, listen.ip())?;
        let block_host = Name::from_ascii(&settings.block_page_host)?;
        let health = DnsHealth::new(&settings.doh_url, Some(health_sink));
        let fail_closed = settings.fail_closed_when_signed_out;
        Ok(Self {
            settings,
            doh,
            user,
            attributor: ProcessAttributor::new(),
            policy,
            filter_state: Arc::new(EngineMutex::new(FilterState::new(fail_closed))),
            health: Arc::new(EngineMutex::new(health)),
            sink,
            block_host,
        })
    }

    /// The shared lifecycle state the daemon drives (§8 ref-counting:
    /// `activate_user`/`deactivate_user` on sign-in/out).
    pub fn filter_state(&self) -> Arc<EngineMutex<FilterState>> {
        Arc::clone(&self.filter_state)
    }

    /// The shared health feed (daemon read-back for §9 `filter.health`).
    pub fn health(&self) -> Arc<EngineMutex<DnsHealth>> {
        Arc::clone(&self.health)
    }

    /// The configured listener address.
    pub fn listen_addr(&self) -> Result<SocketAddr, DnsError> {
        self.settings
            .listen
            .parse()
            .map_err(|e| DnsError::Config(format!("dns.listen {}: {e}", self.settings.listen)))
    }

    /// Binds UDP + TCP on `dns.listen`, spawns the query loops and the
    /// outage probe loop, and runs until `shutdown` flips to `true` (or the
    /// watch sender is dropped) — the daemon owns the lifecycle (§8).
    pub async fn run(self, mut shutdown: watch::Receiver<bool>) -> Result<(), DnsError> {
        let listen = self.listen_addr()?;
        let udp = Arc::new(UdpSocket::bind(listen).await?);
        let tcp = TcpListener::bind(listen).await?;
        let local = udp.local_addr()?;
        let this = Arc::new(self);

        let mut udp_task = tokio::spawn(udp_loop(Arc::clone(&this), Arc::clone(&udp), local));
        let mut tcp_task = tokio::spawn(tcp_loop(Arc::clone(&this), tcp, local));
        let probe_task = tokio::spawn(probe_loop(Arc::clone(&this)));

        tokio::select! {
            biased;
            _ = shutdown.changed() => {}
            joined = &mut udp_task => {
                tcp_task.abort();
                probe_task.abort();
                return flatten_join(joined);
            }
            joined = &mut tcp_task => {
                udp_task.abort();
                probe_task.abort();
                return flatten_join(joined);
            }
        }
        udp_task.abort();
        tcp_task.abort();
        probe_task.abort();
        Ok(())
    }

    /// Handles one datagram/stream payload; `None` means "drop silently"
    /// (nothing parseable to answer). Never panics.
    pub(crate) async fn process_datagram(
        self: Arc<Self>,
        data: &[u8],
        client: SocketAddr,
        local: SocketAddr,
    ) -> Option<Vec<u8>> {
        if data.len() < 12 {
            debug!(len = data.len(), %client, "dropping undersized DNS packet");
            return None;
        }
        let query = match Message::from_vec(data) {
            Ok(message) => message,
            Err(e) => {
                warn!(%client, error = %e, "malformed DNS query");
                return Some(error_response(data, ResponseCode::FormErr));
            }
        };
        if query.message_type() != MessageType::Query || query.queries().is_empty() {
            return Some(error_response(data, ResponseCode::FormErr));
        }
        Some(
            self.process_query(&query, data, client, local, Instant::now())
                .await,
        )
    }

    async fn process_query(
        self: Arc<Self>,
        query: &Message,
        wire: &[u8],
        client: SocketAddr,
        local: SocketAddr,
        started: Instant,
    ) -> Vec<u8> {
        let question = &query.queries()[0];
        let domain = question.name().to_utf8().to_ascii_lowercase();

        // §8 lifecycle fail-closed flag (zero signed-in users ⇒ block all).
        let fail_closed_block = self.filter_state.lock().fail_closed_blocks_web();
        let filter_outage = self.health.lock().is_outage();

        // §8 fail-closed answers immediately: with no signed-in user there is
        // nothing to decide per upstream, so never make the client wait on
        // DoH/user paths (which may themselves be unreachable). This runs
        // *before* attribution on purpose: attribution is a netlink dump whose
        // 2 s I/O timeout would otherwise be added to every lookup on a
        // machine that is signed out — i.e. to every lookup right after
        // install — and a blanket block has no per-process decision to make.
        if fail_closed_block {
            let attribution = Attribution::default();
            let verdict = decide(&crate::verdicts::VerdictInput {
                fail_closed_block: true,
                custom: self.policy.custom_override(&domain),
                global: self.policy.global_override(&domain),
                safe_search_hit: self.policy.safe_search_domain_hit(&domain),
                always_allowable: self.policy.always_allowable(&domain),
                filter_outage,
                filter_path_configured: self.doh.is_some(),
                filter: PathOutcome::Failure,
                user: PathOutcome::Failure,
            });
            let served = synthesize_block_answer(wire, &self.block_host)
                .unwrap_or_else(|_| error_response(wire, ResponseCode::ServFail));
            let row = build_activity_row(
                self.policy.username(),
                domain,
                &attribution,
                &verdict,
                &served,
                None,
                started.elapsed().as_millis() as i64,
            );
            if let Err(e) = self.sink.log_query(row) {
                warn!(error = %e, "dns activity sink failed");
            }
            return served;
        }

        // §8 attribution: the client's UDP source port → socket owner.
        let attribution: Attribution = self.attributor.attribute(client.port(), local.ip());

        // §8 dual resolution: filter (DoH) path and user path in parallel.
        // During a known outage the filter path is skipped outright: it would
        // only pay its full timeout again before the user path answers.
        let (filter_result, user_result) = tokio::join!(
            async {
                match (&self.doh, filter_outage) {
                    (Some(_), true) => None,
                    (Some(doh), false) => Some(doh.lookup(wire).await),
                    (None, _) => None,
                }
            },
            self.user.lookup(wire),
        );
        let (filter_outcome, datacenter) = match filter_result {
            None => (PathOutcome::Failure, None),
            Some(result) => {
                let (outcome, dc) = self.observe_doh(
                    result,
                    Instant::now(),
                    crate::health::DohRequestReason::Typical,
                );
                (outcome, dc)
            }
        };
        let user_outcome = match user_result {
            Ok(bytes) => PathOutcome::Answer(bytes),
            Err(UserLookupError::Timeout) => PathOutcome::Timeout,
            Err(_) => PathOutcome::Failure,
        };

        // §8 decision tree.
        let verdict = decide(&crate::verdicts::VerdictInput {
            fail_closed_block,
            custom: self.policy.custom_override(&domain),
            global: self.policy.global_override(&domain),
            safe_search_hit: self.policy.safe_search_domain_hit(&domain),
            always_allowable: self.policy.always_allowable(&domain),
            filter_outage,
            filter_path_configured: self.doh.is_some(),
            filter: filter_outcome.clone(),
            user: user_outcome.clone(),
        });
        debug!(
            %domain,
            resolution_type = verdict.resolution_type.as_str(),
            endpoint = ?verdict.endpoint,
            "dns verdict"
        );

        // §8 response: synthesize a block answer, pass the chosen endpoint's
        // answer through, or degrade to SERVFAIL.
        let served: Vec<u8> = if verdict.block {
            let upstream: &[u8] = filter_outcome
                .answer_bytes()
                .or_else(|| user_outcome.answer_bytes())
                .unwrap_or(wire);
            match synthesize_block_answer(upstream, &self.block_host) {
                Ok(bytes) => bytes,
                Err(e) => {
                    warn!(%domain, error = %e, "block synthesis failed; answering SERVFAIL");
                    error_response(wire, ResponseCode::ServFail)
                }
            }
        } else {
            let endpoint_answer = match verdict.endpoint {
                ResponseEndpoint::Filter => filter_outcome.answer_bytes(),
                ResponseEndpoint::User => user_outcome.answer_bytes(),
                ResponseEndpoint::Local => None,
            };
            match endpoint_answer {
                Some(bytes) => patch_txid(bytes, query.id())
                    .unwrap_or_else(|| error_response(wire, ResponseCode::ServFail)),
                None => error_response(wire, ResponseCode::ServFail),
            }
        };

        // §8 row write through the sink (daemon → §6.1 outbox, status='queued').
        let row = build_activity_row(
            self.policy.username(),
            domain,
            &attribution,
            &verdict,
            &served,
            datacenter,
            started.elapsed().as_millis() as i64,
        );
        if let Err(e) = self.sink.log_query(row) {
            warn!(error = %e, "dns activity sink failed");
        }
        served
    }

    /// Feeds the health machine + sink for one DoH outcome (§8/§14) and
    /// returns the verdict-engine path outcome plus the datacenter tag.
    fn observe_doh(
        &self,
        result: Result<DohAnswer, DohError>,
        now: Instant,
        reason: crate::health::DohRequestReason,
    ) -> (PathOutcome, Option<String>) {
        let mut health = self.health.lock();
        match result {
            Ok(answer) => {
                let rcode_ok =
                    matches!(answer.rcode, ResponseCode::NoError | ResponseCode::NXDomain);
                if rcode_ok {
                    health.record_doh_success(
                        answer.datacenter.clone(),
                        answer.latency_ms,
                        reason,
                        now,
                    );
                } else {
                    health.record_doh_error(
                        answer.datacenter.clone(),
                        Some(answer.http_status),
                        Some(u16::from(answer.rcode) as i32),
                        reason,
                        now,
                    );
                }
                (PathOutcome::Answer(answer.wire), answer.datacenter)
            }
            Err(DohError::Timeout) => {
                health.record_doh_timeout(reason, now);
                (PathOutcome::Timeout, None)
            }
            Err(DohError::HttpStatus(status)) => {
                health.record_doh_error(None, Some(status), None, reason, now);
                (PathOutcome::Failure, None)
            }
            Err(e) => {
                health.record_doh_error(None, None, None, reason, now);
                debug!(error = %e, "doh lookup failed");
                (PathOutcome::Failure, None)
            }
        }
    }
}

fn flatten_join(
    joined: Result<Result<(), DnsError>, tokio::task::JoinError>,
) -> Result<(), DnsError> {
    joined.map_err(|e| DnsError::Task(e.to_string()))?
}

async fn udp_loop(
    this: Arc<DnsServer>,
    socket: Arc<UdpSocket>,
    local: SocketAddr,
) -> Result<(), DnsError> {
    let mut buf = [0u8; 4096];
    loop {
        let (received, client) = socket.recv_from(&mut buf).await?;
        let data = buf[..received].to_vec();
        let this = Arc::clone(&this);
        let socket = Arc::clone(&socket);
        tokio::spawn(async move {
            if let Some(response) = this.process_datagram(&data, client, local).await {
                if let Err(e) = socket.send_to(&response, client).await {
                    debug!(%client, error = %e, "udp reply failed");
                }
            }
        });
    }
}

async fn tcp_loop(
    this: Arc<DnsServer>,
    listener: TcpListener,
    local: SocketAddr,
) -> Result<(), DnsError> {
    loop {
        let (stream, _peer) = listener.accept().await?;
        let this = Arc::clone(&this);
        tokio::spawn(async move {
            if let Err(e) = handle_tcp_conn(this, stream, local).await {
                debug!(error = %e, "tcp dns exchange failed");
            }
        });
    }
}

async fn handle_tcp_conn(
    this: Arc<DnsServer>,
    mut stream: TcpStream,
    local: SocketAddr,
) -> std::io::Result<()> {
    let mut length_buffer = [0u8; 2];
    if tokio::time::timeout(TCP_IO_TIMEOUT, stream.read_exact(&mut length_buffer))
        .await
        .is_err()
    {
        return Ok(());
    }
    let length = u16::from_be_bytes(length_buffer) as usize;
    if length < 12 {
        return Ok(());
    }
    let mut buffer = vec![0u8; length];
    if tokio::time::timeout(TCP_IO_TIMEOUT, stream.read_exact(&mut buffer))
        .await
        .is_err()
    {
        return Ok(());
    }
    let client = stream.peer_addr().unwrap_or(local);
    if let Some(response) = this.process_datagram(&buffer, client, local).await {
        let mut framed = Vec::with_capacity(response.len() + 2);
        framed.extend_from_slice(&(response.len() as u16).to_be_bytes());
        framed.extend_from_slice(&response);
        tokio::time::timeout(TCP_IO_TIMEOUT, stream.write_all(&framed))
            .await
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::TimedOut, "tcp reply timeout")
            })??;
        stream.flush().await?;
    }
    Ok(())
}

/// The outage probe loop (§8 "outage state → periodic `error-recovery` test
/// packets → recovery timer"): while the health machine reports an outage and
/// a test packet is due, one DoH probe is sent with the CE
/// `doh_request_reason = "error-recovery"` tag; between probes it advances
/// the recovery timer.
async fn probe_loop(this: Arc<DnsServer>) {
    let Some(doh) = this.doh.as_ref() else {
        return;
    };
    let mut tick = interval(PROBE_TICK);
    tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
    loop {
        tick.tick().await;
        let now = Instant::now();
        if !this.health.lock().should_send_test_packet(now) {
            this.health.lock().manage_outage_recovery(now);
            continue;
        }
        this.health.lock().note_test_packet_sent(now);
        let wire = match build_probe_query() {
            Ok(wire) => wire,
            Err(e) => {
                warn!(error = %e, "dns probe query build failed");
                continue;
            }
        };
        let result = doh.lookup(&wire).await;
        this.observe_doh(
            result,
            Instant::now(),
            crate::health::DohRequestReason::ErrorRecovery,
        );
    }
}

/// One A-query for [`PROBE_DOMAIN`] used by `error-recovery` test packets.
pub(crate) fn build_probe_query() -> Result<Vec<u8>, DnsError> {
    static NEXT_ID: AtomicU32 = AtomicU32::new(1);
    let id = (NEXT_ID.fetch_add(1, Ordering::Relaxed) & 0xFFFF) as u16;
    let mut message = Message::new();
    message.set_id(id);
    message.set_message_type(MessageType::Query);
    message.set_op_code(OpCode::Query);
    message.set_recursion_desired(true);
    message.add_query(Query::query(Name::from_ascii(PROBE_DOMAIN)?, RecordType::A));
    Ok(message.to_vec()?)
}

/// Error-response synthesis for malformed/dead queries: the question and ID
/// of the client query are echoed when parseable; otherwise a bare 12-byte
/// header with the raw transaction ID.
pub(crate) fn error_response(query: &[u8], code: ResponseCode) -> Vec<u8> {
    let id = u16::from_be_bytes([
        query.first().copied().unwrap_or(0),
        query.get(1).copied().unwrap_or(0),
    ]);
    let out = match Message::from_vec(query) {
        Ok(parsed) => {
            let mut message = Message::new();
            message.set_id(parsed.id());
            message.set_message_type(MessageType::Response);
            message.set_op_code(OpCode::Query);
            message.set_recursion_desired(parsed.recursion_desired());
            message.set_response_code(code);
            for question in parsed.queries() {
                message.add_query(question.clone());
            }
            message
        }
        Err(_) => {
            let mut message = Message::new();
            message.set_id(id);
            message.set_message_type(MessageType::Response);
            message.set_op_code(OpCode::Query);
            message.set_response_code(code);
            message
        }
    };
    out.to_vec().unwrap_or_default()
}

/// Rewrites the transaction ID of a pass-through answer to the client's ID
/// (DoH/user upstreams echo the embedded query's ID, which we control).
pub(crate) fn patch_txid(answer: &[u8], id: u16) -> Option<Vec<u8>> {
    let mut message = Message::from_vec(answer).ok()?;
    message.set_id(id);
    message.to_vec().ok()
}

/// The first address record of the served answer (the `ip` column, §6.1).
pub(crate) fn first_answer_address(served: &[u8]) -> Option<String> {
    let message = Message::from_vec(served).ok()?;
    for record in message.answers() {
        match record.data() {
            RData::A(a) => return Some(a.0.to_string()),
            RData::AAAA(aaaa) => return Some(aaaa.0.to_string()),
            _ => {}
        }
    }
    None
}

/// The `connection_type` string of a response endpoint (CE vocabulary:
/// `"DoH"` / `"UDP"` / `"undefined"`).
pub(crate) fn connection_type_for(endpoint: ResponseEndpoint) -> &'static str {
    match endpoint {
        ResponseEndpoint::Filter => "DoH",
        ResponseEndpoint::User => "UDP",
        ResponseEndpoint::Local => "undefined",
    }
}

/// Assembles the §6.1 `dns_activity` row for one query.
pub(crate) fn build_activity_row(
    username: String,
    domain: String,
    attribution: &Attribution,
    verdict: &Verdict,
    served: &[u8],
    datacenter: Option<String>,
    elapsed_ms: i64,
) -> DnsActivityRow {
    DnsActivityRow {
        username,
        domain,
        process_id: attribution.process_id,
        process_name: attribution.process_name.clone(),
        datetime_created: now_iso8601_utc(),
        ip: first_answer_address(served),
        resolution_type: verdict.resolution_type.as_str().to_string(),
        connection_type: Some(connection_type_for(verdict.endpoint).to_string()),
        resolution_datacenter: datacenter,
        resolution_time_ms: elapsed_ms,
    }
}

fn now_iso8601_utc() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::health::HealthEvent;
    use crate::verdicts::VerdictType;
    use hickory_proto::op::ResponseCode;

    struct NullSink;
    impl ActivitySink for NullSink {
        fn log_query(&self, _row: DnsActivityRow) -> Result<(), DnsError> {
            Ok(())
        }
    }
    impl HealthSink for NullSink {
        fn record_lookup(&self, _event: HealthEvent) {}
    }

    fn settings() -> DnsSettings {
        DnsSettings::default()
    }

    fn server() -> DnsServer {
        DnsServer::new(
            settings(),
            Arc::new(NullSink),
            Arc::new(NullSink),
            Arc::new(DomainListPolicy::default()),
        )
        .expect("default settings are valid")
    }

    fn query_wire() -> Vec<u8> {
        let mut message = Message::new();
        message.set_id(0xABCD);
        message.set_message_type(MessageType::Query);
        message.set_op_code(OpCode::Query);
        message.set_recursion_desired(true);
        message.add_query(Query::query(
            Name::from_ascii("example.com").unwrap(),
            RecordType::A,
        ));
        message.to_vec().unwrap()
    }

    #[test]
    fn default_settings_match_s9_1() {
        let defaults = DnsSettings::default();
        assert!(defaults.enabled);
        assert_eq!(defaults.listen, "127.0.0.2:53");
        assert_eq!(
            defaults.doh_url,
            "https://dns.cleanbrowsing.org/doh/adult-filter"
        );
        assert_eq!(defaults.user_resolvers, vec!["system".to_string()]);
        assert!(defaults.block_page);
        assert_eq!(defaults.block_page_host, "blocked.lustless.local");
        assert!(defaults.fail_closed_when_signed_out);
        assert_eq!(defaults.pool_size, 5);
    }

    #[test]
    fn server_builds_from_defaults_and_exposes_lifecycle_state() {
        let server = server();
        assert_eq!(
            server.listen_addr().unwrap(),
            "127.0.0.2:53".parse::<SocketAddr>().unwrap()
        );
        let state = server.filter_state();
        assert_eq!(state.lock().active_user_count(), 0);
        assert!(state.lock().fail_closed_blocks_web());
        assert_eq!(
            server.health().lock().health(),
            crate::health::FilterHealth::Healthy
        );
    }

    #[test]
    fn invalid_configuration_is_rejected() {
        let bad = DnsSettings {
            listen: "not-an-addr".into(),
            ..settings()
        };
        assert!(matches!(
            DnsServer::new(
                bad,
                Arc::new(NullSink),
                Arc::new(NullSink),
                Arc::new(DomainListPolicy::default())
            ),
            Err(DnsError::Config(_))
        ));
        let bad_host = DnsSettings {
            block_page_host: "bad host!".into(),
            ..settings()
        };
        assert!(matches!(
            DnsServer::new(
                bad_host,
                Arc::new(NullSink),
                Arc::new(NullSink),
                Arc::new(DomainListPolicy::default())
            ),
            Err(DnsError::Proto(_))
        ));
    }

    #[test]
    fn malformed_input_gets_formerr_header_never_a_panic() {
        // Not even a header: dropped (nothing to answer into).
        assert!(error_response(&[0x00], ResponseCode::FormErr).len() >= 12);
        // Header-shaped garbage: bare FORMERR with the raw txid preserved.
        let garbage = [
            0x12, 0x34, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let response = error_response(&garbage, ResponseCode::FormErr);
        assert_eq!(response.len(), 12);
        assert_eq!(u16::from_be_bytes([response[0], response[1]]), 0x1234);
        let parsed = Message::from_vec(&response).unwrap();
        assert_eq!(parsed.message_type(), MessageType::Response);
        assert_eq!(parsed.response_code(), ResponseCode::FormErr);
        assert!(parsed.queries().is_empty());
    }

    #[test]
    fn servfail_echoes_the_client_question() {
        let wire = query_wire();
        let response = error_response(&wire, ResponseCode::ServFail);
        let parsed = Message::from_vec(&response).unwrap();
        assert_eq!(parsed.id(), 0xABCD);
        assert_eq!(parsed.response_code(), ResponseCode::ServFail);
        assert_eq!(parsed.queries().len(), 1);
        assert_eq!(parsed.queries()[0].name().to_utf8(), "example.com.");
        assert_eq!(parsed.queries()[0].query_type(), RecordType::A);
        assert!(parsed.answers().is_empty());
    }

    #[test]
    fn patch_txid_rewrites_the_transaction_id() {
        let wire = query_wire();
        let answer = error_response(&wire, ResponseCode::NoError);
        let patched = patch_txid(&answer, 0x1111).unwrap();
        assert_eq!(Message::from_vec(&patched).unwrap().id(), 0x1111);
        assert!(patch_txid(&[0xFF; 3], 1).is_none());
    }

    #[test]
    fn connection_type_vocabulary() {
        assert_eq!(connection_type_for(ResponseEndpoint::Filter), "DoH");
        assert_eq!(connection_type_for(ResponseEndpoint::User), "UDP");
        assert_eq!(connection_type_for(ResponseEndpoint::Local), "undefined");
    }

    #[test]
    fn first_answer_address_extraction() {
        let host = Name::from_ascii("blocked.lustless.local").unwrap();
        let block = synthesize_block_answer(&query_wire(), &host).unwrap();
        assert_eq!(first_answer_address(&block).as_deref(), Some("127.0.0.2"));
        // A question-only wire has no address.
        assert_eq!(first_answer_address(&query_wire()), None);
        assert_eq!(first_answer_address(&[0xFF; 4]), None);
    }

    #[test]
    fn activity_row_shape() {
        let attribution = Attribution {
            process_id: 4242,
            process_name: "firefox".into(),
        };
        let verdict = Verdict {
            resolution_type: VerdictType::BlockedCustom,
            endpoint: ResponseEndpoint::Local,
            block: true,
        };
        let host = Name::from_ascii("blocked.lustless.local").unwrap();
        let served = synthesize_block_answer(&query_wire(), &host).unwrap();
        let row = build_activity_row(
            "alice".into(),
            "example.com".into(),
            &attribution,
            &verdict,
            &served,
            Some("lax".into()),
            17,
        );
        assert_eq!(row.username, "alice");
        assert_eq!(row.domain, "example.com");
        assert_eq!(row.process_id, 4242);
        assert_eq!(row.process_name, "firefox");
        assert!(
            row.datetime_created.ends_with('Z'),
            "{}",
            row.datetime_created
        );
        assert_eq!(row.ip.as_deref(), Some("127.0.0.2"));
        assert_eq!(row.resolution_type, "BlockedCustom");
        assert_eq!(row.connection_type.as_deref(), Some("undefined"));
        assert_eq!(row.resolution_datacenter.as_deref(), Some("lax"));
        assert_eq!(row.resolution_time_ms, 17);
    }

    #[test]
    fn probe_query_is_a_well_formed_example_com_a_query() {
        let first = build_probe_query().unwrap();
        let second = build_probe_query().unwrap();
        let parsed = Message::from_vec(&first).unwrap();
        assert_eq!(parsed.message_type(), MessageType::Query);
        assert_eq!(parsed.queries().len(), 1);
        assert_eq!(
            parsed.queries()[0].name().to_utf8(),
            format!("{PROBE_DOMAIN}.")
        );
        assert_eq!(parsed.queries()[0].query_type(), RecordType::A);
        assert!(parsed.recursion_desired());
        assert_ne!(
            Message::from_vec(&second).unwrap().id(),
            parsed.id(),
            "probe ids must not collide"
        );
    }

    #[test]
    fn domain_list_policy_matching() {
        let mut policy = DomainListPolicy::default();
        policy
            .set_username("alice")
            .set_custom_override("example.com", OverrideVerdict::Block)
            .set_global_override("tracker.net", OverrideVerdict::Allow)
            .add_safe_search_domain("search.example")
            .add_always_allowable_domain("school.edu");
        assert_eq!(policy.username(), "alice");

        assert_eq!(
            policy.custom_override("example.com"),
            OverrideVerdict::Block
        );
        assert_eq!(
            policy.custom_override("ads.example.com"),
            OverrideVerdict::Block
        );
        assert_eq!(
            policy.custom_override("EXAMPLE.COM"),
            OverrideVerdict::Block
        );
        assert_eq!(
            policy.custom_override("notexample.com"),
            OverrideVerdict::NotApplicable
        );
        assert_eq!(
            policy.global_override("a.b.tracker.net"),
            OverrideVerdict::Allow
        );
        assert!(policy.safe_search_domain_hit("images.search.example"));
        assert!(!policy.safe_search_domain_hit("search.example.evil.com"));
        assert!(policy.always_allowable("portal.school.edu"));

        // Longest suffix wins.
        policy.set_custom_override("ads.example.com", OverrideVerdict::Allow);
        assert_eq!(
            policy.custom_override("ads.example.com"),
            OverrideVerdict::Allow
        );
        assert_eq!(
            policy.custom_override("x.ads.example.com"),
            OverrideVerdict::Allow
        );
        assert_eq!(
            policy.custom_override("other.example.com"),
            OverrideVerdict::Block
        );
    }

    #[test]
    fn unknown_ip_is_the_tolerated_row_default() {
        let attribution = Attribution::default();
        let verdict = Verdict {
            resolution_type: VerdictType::TimedOut,
            endpoint: ResponseEndpoint::User,
            block: false,
        };
        let row = build_activity_row(
            String::new(),
            "example.com".into(),
            &attribution,
            &verdict,
            &[],
            None,
            5000,
        );
        assert_eq!(row.process_id, crate::UNKNOWN_PROCESS_ID);
        assert_eq!(row.process_name, crate::UNKNOWN_PROCESS_NAME);
        assert_eq!(row.ip, None);
        assert_eq!(row.resolution_type, "TimedOut");
        assert_eq!(row.connection_type.as_deref(), Some("UDP"));
        assert_eq!(row.resolution_time_ms, 5000);
    }

    /// An in-process end-to-end flow of the pure decision surfaces: verdict →
    /// served bytes → row, using locally constructed messages only (no
    /// sockets, no network — §16).
    #[test]
    fn blocked_query_flow_serves_the_synthesized_answer() {
        let server = server();
        let query = query_wire();
        let parsed = Message::from_vec(&query).unwrap();
        // Simulate the daemon fail-closed state (no signed-in users).
        assert!(server.filter_state.lock().fail_closed_blocks_web());
        let verdict = decide(&crate::verdicts::VerdictInput {
            fail_closed_block: true,
            custom: OverrideVerdict::NotApplicable,
            global: OverrideVerdict::NotApplicable,
            safe_search_hit: false,
            always_allowable: false,
            filter_outage: false,
            filter_path_configured: true,
            filter: PathOutcome::Answer(query.clone()),
            user: PathOutcome::Answer(query.clone()),
        });
        assert!(verdict.block);
        let served = synthesize_block_answer(&query, &server.block_host).unwrap();
        assert_eq!(Message::from_vec(&served).unwrap().id(), parsed.id());
        assert_eq!(first_answer_address(&served).as_deref(), Some("127.0.0.2"));
    }
}
