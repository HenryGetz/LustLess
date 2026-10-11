//! `lustless-dns` — the DNS forwarder engine (CONTRACTS §8).
//!
//! Clean-room Linux reimplementation of the Covenant Eyes "Victory Shield"
//! 10.1.44 DNS enforcement surface (`re/findings/12-network/filter-enforcement.md`):
//!
//! | module | contract section |
//! |---|---|
//! | [`server`] | §8 forwarder: tokio UDP+TCP listener on `dns.listen`, per-query dual-resolution flow |
//! | [`doh`] | §8 transports: RFC 8484 DoH filter path (pool ≤5/endpoint, least-loaded) + user-resolver path |
//! | [`verdicts`] | §8 verdict table — CE's 15 `resolution_type` codes kept verbatim |
//! | [`block`] | §8 block-answer synthesis (`overrideForBlocking` mechanics) + loopback block page |
//! | [`attribution`] | §8 per-query process attribution (`SOCK_DIAG`/`inet_diag` + `/proc`) |
//! | [`health`] | §8 health machine (`client_cleanbrowsing_*` counters, outage → test packets → recovery) and [`FilterState`] lifecycle |
//!
//! **Interface inversion (CONTRACTS §3):** this crate MUST NOT depend on
//! `lustless-core`. It defines its own [`DnsActivityRow`] (field semantics per
//! §6.1 `dns_activity`), the [`ActivitySink`] trait through which rows leave the
//! engine (the daemon implements it over the §6.1 outbox, born
//! `status='queued'`), and the [`HealthSink`] trait for the §14
//! `client_cleanbrowsing_success`/`client_cleanbrowsing_problem` metrics.

use thiserror::Error;

pub mod attribution;
pub mod block;
pub mod doh;
pub mod health;
pub mod server;
pub mod verdicts;

pub use attribution::{
    Attribution, NetlinkProcDiag, ProcessAttributor, UdpOwnerLookup, UNKNOWN_PROCESS_ID,
    UNKNOWN_PROCESS_NAME,
};
pub use block::{
    default_block_page_html, synthesize_block_answer, BlockError, BlockPageServer,
    DEFAULT_BLOCK_HOST,
};
pub use doh::{
    base64url_encode, build_doh_get_url, parse_resolv_conf, DohAnswer, DohClient, DohError,
    UserLookupError, UserResolver, MAX_POOL_PER_ENDPOINT, PATH_TIMEOUT,
};
pub use health::{
    DnsHealth, DohRequestReason, FilterHealth, FilterState, HealthEvent, LookupOutcome,
    OutageMachine, METRIC_CLEANBROWSING_PROBLEM, METRIC_CLEANBROWSING_SUCCESS,
    REASON_ERROR_RECOVERY, REASON_TYPICAL,
};
pub use server::{DnsServer, DnsSettings, PolicyProvider, DomainListPolicy};
pub use verdicts::{
    answer_is_filter_block, decide, OverrideVerdict, PathOutcome, ResponseEndpoint, Verdict,
    VerdictInput, VerdictType, RPZ_BLOCK_MARKER,
};

/// A `dns_activity` row as emitted by the forwarder (CONTRACTS §6.1/§8).
///
/// Column semantics follow the verbatim `ce-file` schema
/// (`re/findings/02-artifacts/local-db.md`): the daemon's [`ActivitySink`]
/// implementation formats the typed fields into the TEXT columns of the
/// `dns_activity` table (e.g. `process_id`/`resolution_time_ms` become decimal
/// strings) and inserts with `status='queued'` per §6.1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsActivityRow {
    /// Account username of the signed-in user this query is attributed to
    /// (CE account username; empty when no user is signed in).
    pub username: String,
    /// Queried domain, lowercased, no trailing dot.
    pub domain: String,
    /// Attributing process id from the UDP socket owner (§8 attribution);
    /// [`UNKNOWN_PROCESS_ID`] (0) is the tolerated default.
    pub process_id: i64,
    /// Attributing process name from `/proc/<pid>/comm`; `"unknown"` is the
    /// tolerated default (§8).
    pub process_name: String,
    /// Query time, ISO-8601 UTC (§6.1, e.g. `2026-10-11T12:34:56Z`).
    pub datetime_created: String,
    /// First address record of the served answer, if any.
    pub ip: Option<String>,
    /// `resolution_type` verdict — one of the §8 15-code vocabulary
    /// (see [`verdicts::VerdictType::as_str`]).
    pub resolution_type: String,
    /// `connection_type` of the response endpoint: `"DoH"`, `"UDP"` or
    /// `"undefined"` (local block synthesis / failure paths — CE vocabulary,
    /// `filter-enforcement.md` mechanism §1.3).
    pub connection_type: Option<String>,
    /// `X-CB-Location`-style DoH response-header tag captured on the filter
    /// path (§8; CE's CleanBrowsing serving POP).
    pub resolution_datacenter: Option<String>,
    /// End-to-end resolution time in milliseconds.
    pub resolution_time_ms: i64,
}

/// Sink through which the engine emits `dns_activity` rows (CONTRACTS §8
/// "Row write"); the daemon implements this over the §6.1 outbox.
pub trait ActivitySink: Send + Sync {
    /// Record one per-query activity row. Errors are logged by the engine and
    /// never fail the DNS response itself.
    fn log_query(&self, row: DnsActivityRow) -> Result<(), DnsError>;
}

/// Per-lookup metric sink (CONTRACTS §8 health machine / §14 metric taxonomy).
///
/// Receives one [`health::HealthEvent`] per DoH filter-path lookup with the
/// `client_cleanbrowsing_success` or `client_cleanbrowsing_problem` metric
/// name; the daemon maps it into the §6.1 `metrics` tables.
pub trait HealthSink: Send + Sync {
    /// Record one per-lookup health/metrics event.
    fn record_lookup(&self, event: health::HealthEvent);
}

/// The single error type of this crate (one `thiserror` enum for all modules).
#[derive(Debug, Error)]
pub enum DnsError {
    /// DNS wire codec failure (hickory-proto parse/serialize).
    #[error("dns wire codec: {0}")]
    Proto(#[from] hickory_proto::ProtoError),

    /// Filesystem/socket failure (listeners, `/proc`, netlink, resolv.conf).
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// Block-answer synthesis failure (`block.rs`); degrades to SERVFAIL.
    #[error("block synthesis: {0}")]
    Block(#[from] block::BlockError),

    /// Invalid engine configuration (`dns.*` values, CONTRACTS §9.1).
    #[error("dns config: {0}")]
    Config(String),

    /// DoH transport/HTTP failure outside a per-query lookup (client build).
    #[error("doh: {0}")]
    Doh(String),

    /// A spawned listener task exited abnormally.
    #[error("dns server task failed: {0}")]
    Task(String),

    /// A client query could not be parsed or violated engine expectations.
    #[error("invalid dns query: {0}")]
    InvalidQuery(String),
}

/// A `parking_lot::Mutex` — guards are held only for short, non-`await`
/// critical sections (§8 engine state), per the workspace locking rule
/// (no poisoning, no unwrap boilerplate).
pub type EngineMutex<T> = parking_lot::Mutex<T>;
