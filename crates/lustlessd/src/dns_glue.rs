//! DNS forwarder lifecycle — CONTRACTS §8 (engine, `ActivitySink` row write,
//! `HealthSink` metrics, ref-counted `FilterState`, block page) feeding §9
//! (`filter.health` / `filter.fail_closed` in the policy snapshot).
//!
//! `spawn` builds the `lustless_dns::DnsServer` over three daemon-owned
//! implementations and drives it until shutdown:
//!
//! * [`OutboxActivitySink`] — per-query `dns_activity` rows born
//!   `status='queued'` (§6.1/§8),
//! * [`MetricHealthSink`] — the §14 `client_cleanbrowsing_success/problem`
//!   metrics with CE's §8 tags,
//! * [`DnsDomainPolicy`] — the §6.2 override lists cached by `DaemonState`
//!   (§8 verdicts 0xb/10/5/4),
//!
//! plus the §8 block page on `<listen-ip>:80` and a 1 s tick mirroring the
//! health machine into `FilterState` for §9.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;

use lustless_core::db::DnsActivityRow as CoreDnsActivityRow;
use lustless_core::metrics::{AggTag, Aggregation, MetricName};
use lustless_dns::server::{DnsServer, DnsSettings, PolicyProvider as DnsPolicyProvider};
use lustless_dns::{
    ActivitySink, BlockPageServer, DnsActivityRow, DnsError, HealthEvent, HealthSink,
    LookupOutcome, OverrideVerdict,
};

use crate::state::{guard, DaemonState};

/// §9 `filter.health` mirror cadence (the engine updates its machine per
/// lookup; the snapshot reads `FilterState`).
const HEALTH_SYNC_TICK: Duration = Duration::from_secs(1);

/// Suffix match for the §8 list predicates (domain itself or any subdomain,
/// case-insensitive — the same rule as `lustless_dns::DomainListPolicy`).
fn list_hit(list: &std::collections::HashSet<String>, domain: &str) -> bool {
    let domain = domain.to_ascii_lowercase();
    list.iter()
        .any(|entry| domain == *entry || domain.ends_with(&format!(".{entry}")))
}

/// §8 "Row write": one `dns_activity` row per query, born `status='queued'`
/// (§6.1 shape verbatim). Engine- or DB-side failures are logged and never
/// fail the DNS response itself.
pub struct OutboxActivitySink {
    state: Arc<DaemonState>,
}

impl OutboxActivitySink {
    /// Builds the sink over the shared daemon state.
    pub fn new(state: Arc<DaemonState>) -> Self {
        OutboxActivitySink { state }
    }

    /// Maps an engine row onto the §6.1 columns (decimal strings for the
    /// numeric columns, per `db::DnsActivityRow`).
    fn core_row(&self, row: DnsActivityRow) -> CoreDnsActivityRow {
        let username = if row.username.is_empty() {
            self.state.username()
        } else {
            row.username
        };
        CoreDnsActivityRow {
            username,
            domain: row.domain.trim_end_matches('.').to_ascii_lowercase(),
            process_id: Some(row.process_id.to_string()),
            process_name: row.process_name,
            datetime_created: row.datetime_created,
            ip: row.ip,
            resolution_type: row.resolution_type,
            connection_type: row.connection_type,
            resolution_datacenter: row.resolution_datacenter,
            resolution_time_ms: Some(row.resolution_time_ms.to_string()),
        }
    }
}

impl ActivitySink for OutboxActivitySink {
    fn log_query(&self, row: DnsActivityRow) -> Result<(), DnsError> {
        let core = self.core_row(row);
        let mut outbox = guard(&self.state.outbox);
        match outbox.insert_dns_activity(&core) {
            Ok(_) => Ok(()),
            Err(err) => {
                tracing::error!("dns_activity insert failed: {err}");
                Err(DnsError::Task(format!("outbox dns_activity insert: {err}")))
            }
        }
    }
}

/// §8 health machine feed: one §14 `client_cleanbrowsing_*` metric per DoH
/// filter-path lookup (CE tags `cleanbrowsing_datacenter`, `doh_url`,
/// `doh_request_reason`).
pub struct MetricHealthSink {
    state: Arc<DaemonState>,
}

impl MetricHealthSink {
    /// Builds the sink over the shared daemon state.
    pub fn new(state: Arc<DaemonState>) -> Self {
        MetricHealthSink { state }
    }
}

impl HealthSink for MetricHealthSink {
    fn record_lookup(&self, event: HealthEvent) {
        let metric = if event.metric == lustless_dns::METRIC_CLEANBROWSING_SUCCESS {
            MetricName::ClientCleanbrowsingSuccess
        } else {
            MetricName::ClientCleanbrowsingProblem
        };
        let tags = [
            AggTag {
                aggregation: Aggregation::Indexed,
                name: "cleanbrowsing_datacenter".to_string(),
                value: event.datacenter.unwrap_or_else(|| "none".to_string()),
            },
            AggTag {
                aggregation: Aggregation::Cardinal,
                name: "doh_url".to_string(),
                value: event.doh_url.clone(),
            },
            AggTag {
                aggregation: Aggregation::Indexed,
                name: "doh_request_reason".to_string(),
                value: event.request_reason.to_string(),
            },
        ];
        let mut fields = vec![DaemonState::counter_field("lookup_count", 1)];
        if let LookupOutcome::Success { latency_ms } = event.outcome {
            fields.push(DaemonState::counter_field("latency_ms", latency_ms));
        }
        let username = self.state.username();
        if let Err(err) = self
            .state
            .record_metric_tagged(&username, metric, &tags, &fields)
        {
            tracing::warn!("cleanbrowsing metric failed: {err}");
        }
    }
}

/// §8 per-domain policy: the cached §6.2 override lists of the signed-in
/// user (refreshed by `DaemonState::refresh_domain_lists` on sign-in/out and
/// IPC `0x64`).
///
/// The safe-search (§8 code 8) and always-allowable (code 3) lists have no
/// server-sync path in this deployment (§9.1 defines no key for them), so
/// they start empty and those two verdicts stay dormant until a sync path
/// populates the daemon's cached lists.
pub struct DnsDomainPolicy {
    state: Arc<DaemonState>,
}

impl DnsDomainPolicy {
    /// Builds the policy over the shared daemon state.
    pub fn new(state: Arc<DaemonState>) -> Self {
        DnsDomainPolicy { state }
    }
}

impl DnsPolicyProvider for DnsDomainPolicy {
    fn username(&self) -> String {
        self.state.username()
    }

    fn custom_override(&self, domain: &str) -> OverrideVerdict {
        let lists = self.state.domain_lists();
        lists
            .custom
            .get(&domain.to_ascii_lowercase())
            .copied()
            .unwrap_or(OverrideVerdict::NotApplicable)
    }

    fn global_override(&self, domain: &str) -> OverrideVerdict {
        let lists = self.state.domain_lists();
        lists
            .global
            .get(&domain.to_ascii_lowercase())
            .copied()
            .unwrap_or(OverrideVerdict::NotApplicable)
    }

    fn safe_search_domain_hit(&self, domain: &str) -> bool {
        list_hit(&self.state.domain_lists().safe_search, domain)
    }

    fn always_allowable(&self, domain: &str) -> bool {
        list_hit(&self.state.domain_lists().always_allowable, domain)
    }
}

/// The §8 block page address: the listener's IP on port 80 (the synthesized
/// A/AAAA records point blocked-name at `127.0.0.2`, §8).
fn block_page_addr(listen: &str) -> Option<SocketAddr> {
    let parsed: SocketAddr = listen.parse().ok()?;
    Some(SocketAddr::new(parsed.ip(), 80))
}

/// Starts the §8 forwarder, the loopback block page and the health mirror;
/// resolves on shutdown (or immediately when `dns.enabled=false`).
pub async fn spawn(state: Arc<DaemonState>, shutdown: watch::Receiver<bool>) {
    let cfg = state.config();
    if !cfg.dns.enabled {
        tracing::info!("dns: forwarder disabled by dns.enabled=false");
        return;
    }
    let settings = DnsSettings {
        enabled: true,
        listen: cfg.dns.listen.clone(),
        doh_url: cfg.dns.doh_url.clone(),
        user_resolvers: cfg.dns.user_resolvers.clone(),
        block_page: cfg.dns.block_page,
        block_page_host: cfg.dns.block_page_host.clone(),
        fail_closed_when_signed_out: cfg.dns.fail_closed_when_signed_out,
        pool_size: cfg.dns.pool_size as usize,
    };
    let server = match DnsServer::new(
        settings,
        Arc::new(OutboxActivitySink::new(Arc::clone(&state))),
        Arc::new(MetricHealthSink::new(Arc::clone(&state))),
        Arc::new(DnsDomainPolicy::new(Arc::clone(&state))),
    ) {
        Ok(server) => server,
        Err(err) => {
            tracing::error!("dns: engine build failed: {err}");
            return;
        }
    };
    let filter_state = server.filter_state();
    let health = server.health();
    state.attach_dns(Arc::clone(&filter_state), Arc::clone(&health));

    // §8 block page (needs root for port 80; a bind failure degrades to
    // "blocked answers resolve but the page 404s" — logged, never fatal).
    if cfg.dns.block_page {
        match block_page_addr(&cfg.dns.listen) {
            Some(addr) => match BlockPageServer::bind(addr, &cfg.dns.block_page_host).await {
                Ok(block_page) => {
                    tracing::info!(
                        "dns: block page on {addr} (host {})",
                        cfg.dns.block_page_host
                    );
                    tokio::spawn(async move {
                        if let Err(err) = block_page.run().await {
                            tracing::warn!("dns: block page stopped: {err}");
                        }
                    });
                }
                Err(err) => tracing::warn!("dns: block page bind failed: {err}"),
            },
            None => tracing::warn!(
                "dns: cannot derive block page address from {}",
                cfg.dns.listen
            ),
        }
    }

    // §9 mirror: DnsHealth → FilterState.health once per second.
    let mirror_state = filter_state.clone();
    let mirror_health = health.clone();
    let mut mirror_shutdown = shutdown.clone();
    let mirror = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = mirror_shutdown.changed() => break,
                _ = tokio::time::sleep(HEALTH_SYNC_TICK) => {
                    let snapshot = mirror_health.lock().health();
                    mirror_state.lock().set_health(snapshot);
                }
            }
        }
    });

    tracing::info!("dns: forwarder listening on {}", cfg.dns.listen);
    match server.run(shutdown.clone()).await {
        Ok(()) => tracing::info!("dns: forwarder stopped"),
        Err(err) => tracing::error!("dns: forwarder failed: {err}"),
    }
    mirror.abort();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::test_util::test_state;
    use lustless_net::Control;
    use serde_json::json;

    #[test]
    fn domain_policy_serves_cached_override_lists() {
        let ts = test_state();
        let state = &ts.state;
        // Signed out: empty lists.
        let policy = DnsDomainPolicy::new(Arc::clone(state));
        assert_eq!(
            policy.custom_override("example.com"),
            OverrideVerdict::NotApplicable
        );

        state.set_sign_in_uid_hint(1000);
        state.sign_in("alice", "pw").expect("sign-in");
        state
            .set_override("example.com", "block")
            .expect("override");

        assert_eq!(
            policy.custom_override("example.com"),
            OverrideVerdict::Block
        );
        assert_eq!(
            policy.custom_override("EXAMPLE.COM"),
            OverrideVerdict::Block,
            "case-insensitive"
        );
        assert_eq!(
            policy.custom_override("unrelated.test"),
            OverrideVerdict::NotApplicable
        );
        assert_eq!(
            policy.global_override("anything"),
            OverrideVerdict::NotApplicable
        );
        // No server-synced lists in this deployment (§9.1): dormant paths.
        assert!(!policy.safe_search_domain_hit("google.com"));
        assert!(!policy.always_allowable("example.com"));
        assert_eq!(policy.username(), "alice");

        // Sign-out clears the cache.
        state.sign_out().expect("sign-out");
        assert_eq!(
            policy.custom_override("example.com"),
            OverrideVerdict::NotApplicable
        );
    }

    #[test]
    fn activity_sink_inserts_queued_rows() {
        let ts = test_state();
        let state = &ts.state;
        state.set_sign_in_uid_hint(1000);
        state.sign_in("alice", "pw").expect("sign-in");

        let sink = OutboxActivitySink::new(Arc::clone(state));
        sink.log_query(DnsActivityRow {
            username: String::new(), // engine had no signed-in user at build time
            domain: "example.test".into(),
            process_id: 4242,
            process_name: "firefox".into(),
            datetime_created: "2026-10-11T10:00:00Z".into(),
            ip: Some("192.0.2.1".into()),
            resolution_type: "UnrestrictedFiltered".into(),
            connection_type: Some("DoH".into()),
            resolution_datacenter: Some("fra1".into()),
            resolution_time_ms: 37,
        })
        .expect("insert");

        // Username attribution falls back to the signed-in session.
        let rows = guard(&state.outbox)
            .dns_activity_readback(10)
            .expect("readback");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["domain"], json!("example.test"));
        assert_eq!(rows[0]["resolution_time_ms"], json!("37"));
        assert_eq!(rows[0]["process_id"], json!("4242"));

        // Born `status='queued'` (§6.1/§8 row lifecycle).
        let conn = rusqlite::Connection::open_with_flags(
            state.outbox_path(),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .expect("open");
        let (username, status): (String, String) = conn
            .query_row(
                "SELECT username, status FROM dns_activity WHERE domain = 'example.test'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("row");
        assert_eq!(username, "alice");
        assert_eq!(status, "queued");
    }

    #[test]
    fn health_sink_records_cleanbrowsing_metrics() {
        let ts = test_state();
        let state = &ts.state;
        let sink = MetricHealthSink::new(Arc::clone(state));

        sink.record_lookup(HealthEvent {
            metric: lustless_dns::METRIC_CLEANBROWSING_SUCCESS,
            datacenter: Some("fra1".into()),
            doh_url: "https://dns.example/doh".into(),
            request_reason: lustless_dns::REASON_TYPICAL,
            outcome: LookupOutcome::Success { latency_ms: 42 },
        });
        sink.record_lookup(HealthEvent {
            metric: lustless_dns::METRIC_CLEANBROWSING_PROBLEM,
            datacenter: None,
            doh_url: "https://dns.example/doh".into(),
            request_reason: lustless_dns::REASON_ERROR_RECOVERY,
            outcome: LookupOutcome::Timeout,
        });

        let conn = rusqlite::Connection::open_with_flags(
            state.outbox_path(),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .expect("open");
        let success: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM metrics WHERE metric_name = 'client_cleanbrowsing_success'",
                [],
                |row| row.get(0),
            )
            .expect("success count");
        let problem: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM metrics WHERE metric_name = 'client_cleanbrowsing_problem'",
                [],
                |row| row.get(0),
            )
            .expect("problem count");
        assert_eq!((success, problem), (1, 1));
        // CE's §8 datacenter tag landed in the bucket_id JSON.
        let bucket: String = conn
            .query_row(
                "SELECT bucket_id FROM metrics WHERE metric_name = 'client_cleanbrowsing_success'",
                [],
                |row| row.get(0),
            )
            .expect("bucket");
        assert!(bucket.contains("client_component"), "{bucket}");
    }

    #[test]
    fn block_page_address_uses_the_listener_ip_on_port_80() {
        assert_eq!(
            block_page_addr("127.0.0.2:53"),
            Some("127.0.0.2:80".parse().expect("addr"))
        );
        assert_eq!(block_page_addr("not-an-addr"), None);
    }
}
