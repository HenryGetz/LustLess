//! `health.rs` — filter-path health and forwarder lifecycle (CONTRACTS §8).
//!
//! Mirrors CE's `DohLookupStatus` machinery (`filter-enforcement.md` §7):
//! per-lookup counters as `client_cleanbrowsing_success` /
//! `client_cleanbrowsing_problem` metrics (§14 taxonomy) handed to a
//! [`HealthSink`], an outage state machine (outage → periodic `error-recovery`
//! test packets → recovery timer), and the [`FilterState`] lifecycle the
//! daemon exposes through the §9 policy snapshot (`filter.health`) —
//! ref-counted activation (`active_user_count`) plus the fail-closed
//! "signed out ⇒ web blocked" policy flag owned by the forwarder (§8).

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::HealthSink;

/// §14 metric name (CE taxonomy, byte-exact).
pub const METRIC_CLEANBROWSING_SUCCESS: &str = "client_cleanbrowsing_success";
/// §14 metric name (CE taxonomy, byte-exact).
pub const METRIC_CLEANBROWSING_PROBLEM: &str = "client_cleanbrowsing_problem";
/// CE `doh_request_reason` tag value for ordinary lookups.
pub const REASON_TYPICAL: &str = "typical";
/// CE `doh_request_reason` tag value for outage-recovery test packets.
pub const REASON_ERROR_RECOVERY: &str = "error-recovery";

/// Consecutive problems that flip healthy → outage.
pub const DEFAULT_PROBLEM_THRESHOLD: u32 = 3;
/// Cadence of `error-recovery` test packets during an outage.
pub const DEFAULT_PROBE_INTERVAL: Duration = Duration::from_secs(30);
/// Success window after which `Recovering` returns to `Healthy`.
pub const DEFAULT_RECOVERY_GRACE: Duration = Duration::from_secs(60);

/// `doh_request_reason` tag (CE: `"typical"` / `"error-recovery"`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DohRequestReason {
    /// An ordinary client-driven lookup.
    Typical,
    /// An outage-recovery test packet.
    ErrorRecovery,
}

impl DohRequestReason {
    /// The CE metric tag value.
    pub fn as_str(self) -> &'static str {
        match self {
            DohRequestReason::Typical => REASON_TYPICAL,
            DohRequestReason::ErrorRecovery => REASON_ERROR_RECOVERY,
        }
    }
}

/// Outcome of one DoH lookup, as CE records it into the metrics fields
/// (`success_count`/`error_count`/`timeout_count` + `latency`, §7).
#[derive(Debug, Clone, PartialEq)]
pub enum LookupOutcome {
    /// HTTP 200 + DNS RCODE NOERROR/NXDOMAIN — CE's success predicate.
    Success {
        /// Request-to-body latency in milliseconds.
        latency_ms: u64,
    },
    /// Non-success: HTTP/transport failure or a refusing RCODE.
    Error {
        /// HTTP status, when one was received.
        http_status: Option<u16>,
        /// DNS RCODE carried by a refusal response, when present.
        dns_rcode: Option<i32>,
    },
    /// The lookup exceeded its timeout.
    Timeout,
}

/// One per-lookup health/metrics event delivered to the [`HealthSink`]
/// (§8 health machine, §14 metric taxonomy).
#[derive(Debug, Clone, PartialEq)]
pub struct HealthEvent {
    /// `client_cleanbrowsing_success` or `client_cleanbrowsing_problem`.
    pub metric: &'static str,
    /// CE tag `cleanbrowsing_datacenter` (the `X-CB-Location` value).
    pub datacenter: Option<String>,
    /// CE tag `cleanbrowsing_doh_url` (the configured `dns.doh_url`).
    pub doh_url: String,
    /// CE tag `doh_request_reason`: `"typical"` / `"error-recovery"`.
    pub request_reason: &'static str,
    /// The structured outcome (metrics fields).
    pub outcome: LookupOutcome,
}

/// Filter health as exposed to the daemon (§9 `PolicySnapshot.filter.health`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterHealth {
    /// Filter path operating normally.
    Healthy,
    /// An outage ended on a successful probe; the recovery timer is running.
    Recovering,
    /// Filter path is down; verdicts fall back to the user path (§8 code 7).
    Outage,
}

impl FilterHealth {
    /// Lowercase status string for the policy snapshot / dashboard.
    pub fn as_str(self) -> &'static str {
        match self {
            FilterHealth::Healthy => "healthy",
            FilterHealth::Recovering => "recovering",
            FilterHealth::Outage => "outage",
        }
    }
}

/// The outage state machine (CE `DohLookupStatus`: `startOutage`,
/// `isTimeToSendTestPacket`, `manageOutageRecovery`, `endOutage`).
///
/// Pure over an injected [`Instant`] clock — deterministic under test (§16).
#[derive(Debug, Clone)]
pub struct OutageMachine {
    state: FilterHealth,
    consecutive_problems: u32,
    problem_threshold: u32,
    probe_interval: Duration,
    recovery_grace: Duration,
    next_probe_at: Option<Instant>,
    recovery_until: Option<Instant>,
}

impl Default for OutageMachine {
    fn default() -> Self {
        Self::new(
            DEFAULT_PROBLEM_THRESHOLD,
            DEFAULT_PROBE_INTERVAL,
            DEFAULT_RECOVERY_GRACE,
        )
    }
}

impl OutageMachine {
    /// `problem_threshold` consecutive failures enter an outage;
    /// `probe_interval` paces `error-recovery` test packets;
    /// `recovery_grace` is the success window of `Recovering`.
    pub fn new(problem_threshold: u32, probe_interval: Duration, recovery_grace: Duration) -> Self {
        Self {
            state: FilterHealth::Healthy,
            consecutive_problems: 0,
            problem_threshold: problem_threshold.max(1),
            probe_interval,
            recovery_grace,
            next_probe_at: None,
            recovery_until: None,
        }
    }

    /// The current health state.
    pub fn state(&self) -> FilterHealth {
        self.state
    }

    /// `true` while the filter path is in the outage state (§8 code 7 input).
    pub fn is_outage(&self) -> bool {
        self.state == FilterHealth::Outage
    }

    /// Feeds one lookup result (CE `DohLookupStatus::update` semantics).
    pub fn record_lookup(&mut self, success: bool, now: Instant) {
        match self.state {
            FilterHealth::Healthy => {
                if success {
                    self.consecutive_problems = 0;
                } else {
                    self.consecutive_problems += 1;
                    if self.consecutive_problems >= self.problem_threshold {
                        self.start_outage(now);
                    }
                }
            }
            FilterHealth::Outage => {
                if success {
                    self.enter_recovering(now);
                }
            }
            FilterHealth::Recovering => {
                if success {
                    self.manage_outage_recovery(now);
                } else {
                    self.start_outage(now);
                }
            }
        }
    }

    /// CE `startOutage`: enter the outage state and arm the test-packet timer.
    pub fn start_outage(&mut self, now: Instant) {
        self.state = FilterHealth::Outage;
        self.consecutive_problems = 0;
        self.recovery_until = None;
        self.next_probe_at = Some(now + self.probe_interval);
    }

    /// CE `endOutage`: back to healthy, all timers/counters cleared.
    pub fn end_outage(&mut self) {
        self.state = FilterHealth::Healthy;
        self.consecutive_problems = 0;
        self.next_probe_at = None;
        self.recovery_until = None;
    }

    /// CE `isTimeToSendTestPacket`: an `error-recovery` probe is due.
    pub fn is_time_to_send_test_packet(&self, now: Instant) -> bool {
        self.state == FilterHealth::Outage && self.next_probe_at.is_some_and(|at| now >= at)
    }

    /// CE `startOutageRecoveryTimer` side of a probe dispatch: re-pace the
    /// test-packet timer.
    pub fn note_test_packet_sent(&mut self, now: Instant) {
        if self.state == FilterHealth::Outage {
            self.next_probe_at = Some(now + self.probe_interval);
        }
    }

    /// CE `manageOutageRecovery`: a sustained success window ends the outage.
    pub fn manage_outage_recovery(&mut self, now: Instant) {
        if self.state == FilterHealth::Recovering
            && self.recovery_until.is_some_and(|until| now >= until)
        {
            self.end_outage();
        }
    }

    /// CE `cancelOutageTimer`.
    pub fn cancel_outage_timer(&mut self) {
        self.next_probe_at = None;
        self.recovery_until = None;
    }

    fn enter_recovering(&mut self, now: Instant) {
        self.state = FilterHealth::Recovering;
        self.next_probe_at = None;
        self.recovery_until = Some(now + self.recovery_grace);
    }
}

/// The forwarder's health feed: outage machine + per-lookup metric events
/// (§8 "per-lookup counters … outage state → periodic `error-recovery` test
/// packets → recovery timer").
pub struct DnsHealth {
    machine: OutageMachine,
    sink: Option<Arc<dyn HealthSink>>,
    doh_url: String,
    successes: u64,
    problems: u64,
}

impl DnsHealth {
    /// `doh_url` is recorded as the CE `cleanbrowsing_doh_url` tag; `sink`
    /// receives every [`HealthEvent`].
    pub fn new(doh_url: &str, sink: Option<Arc<dyn HealthSink>>) -> Self {
        Self::with_machine(doh_url, sink, OutageMachine::default())
    }

    /// Same, with a caller-tuned machine.
    pub fn with_machine(
        doh_url: &str,
        sink: Option<Arc<dyn HealthSink>>,
        machine: OutageMachine,
    ) -> Self {
        Self {
            machine,
            sink,
            doh_url: doh_url.to_string(),
            successes: 0,
            problems: 0,
        }
    }

    /// Records one successful filter lookup (RCODE 0/3, §7).
    pub fn record_doh_success(
        &mut self,
        datacenter: Option<String>,
        latency_ms: u64,
        reason: DohRequestReason,
        now: Instant,
    ) {
        self.emit(
            datacenter,
            LookupOutcome::Success { latency_ms },
            reason,
            now,
        );
    }

    /// Records one failed filter lookup (HTTP/transport error or refusing
    /// RCODE).
    pub fn record_doh_error(
        &mut self,
        datacenter: Option<String>,
        http_status: Option<u16>,
        dns_rcode: Option<i32>,
        reason: DohRequestReason,
        now: Instant,
    ) {
        self.emit(
            datacenter,
            LookupOutcome::Error {
                http_status,
                dns_rcode,
            },
            reason,
            now,
        );
    }

    /// Records one timed-out filter lookup.
    pub fn record_doh_timeout(&mut self, reason: DohRequestReason, now: Instant) {
        self.emit(None, LookupOutcome::Timeout, reason, now);
    }

    fn emit(
        &mut self,
        datacenter: Option<String>,
        outcome: LookupOutcome,
        reason: DohRequestReason,
        now: Instant,
    ) {
        let success = matches!(outcome, LookupOutcome::Success { .. });
        if success {
            self.successes += 1;
        } else {
            self.problems += 1;
        }
        self.machine.record_lookup(success, now);
        if let Some(sink) = &self.sink {
            sink.record_lookup(HealthEvent {
                metric: if success {
                    METRIC_CLEANBROWSING_SUCCESS
                } else {
                    METRIC_CLEANBROWSING_PROBLEM
                },
                datacenter,
                doh_url: self.doh_url.clone(),
                request_reason: reason.as_str(),
                outcome,
            });
        }
    }

    /// Current filter health (§9 `filter.health`).
    pub fn health(&self) -> FilterHealth {
        self.machine.state()
    }

    /// `true` while the filter path is down (§8 code 7 verdict input).
    pub fn is_outage(&self) -> bool {
        self.machine.is_outage()
    }

    /// An `error-recovery` test packet is due (probe loop gate).
    pub fn should_send_test_packet(&self, now: Instant) -> bool {
        self.machine.is_time_to_send_test_packet(now)
    }

    /// Note that a probe was dispatched (re-paces the probe timer).
    pub fn note_test_packet_sent(&mut self, now: Instant) {
        self.machine.note_test_packet_sent(now);
    }

    /// Advance the recovery timer (opportunistic tick).
    pub fn manage_outage_recovery(&mut self, now: Instant) {
        self.machine.manage_outage_recovery(now);
    }

    /// `(successes, problems)` since start — the §8 per-lookup counters.
    pub fn counters(&self) -> (u64, u64) {
        (self.successes, self.problems)
    }

    /// The underlying machine (tuning/introspection).
    pub fn machine(&self) -> &OutageMachine {
        &self.machine
    }
}

/// Forwarder lifecycle state (§8 "Lifecycle"): ref-counted signed-in users
/// that need filtering, the fail-closed policy flag, and the health snapshot.
#[derive(Debug, Clone)]
pub struct FilterState {
    active_users: BTreeSet<String>,
    fail_closed_when_signed_out: bool,
    health: FilterHealth,
}

impl FilterState {
    /// `fail_closed_when_signed_out` is the §9.1 `dns.fail_closed_when_signed_out`
    /// flag ("signed out ⇒ web blocked"), owned by the forwarder (§8).
    pub fn new(fail_closed_when_signed_out: bool) -> Self {
        Self {
            active_users: BTreeSet::new(),
            fail_closed_when_signed_out,
            health: FilterHealth::Healthy,
        }
    }

    /// Activates filtering for `username` (idempotent — CE's
    /// `checkForProxySwitch` ref-counts unique users). Returns the count.
    pub fn activate_user(&mut self, username: &str) -> usize {
        self.active_users.insert(username.to_string());
        self.active_users.len()
    }

    /// Deactivates `username`; returns the remaining count.
    pub fn deactivate_user(&mut self, username: &str) -> usize {
        self.active_users.remove(username);
        self.active_users.len()
    }

    /// Number of users whose filtering keeps the forwarder active (§8).
    pub fn active_user_count(&self) -> usize {
        self.active_users.len()
    }

    /// The active usernames (sorted).
    pub fn active_usernames(&self) -> Vec<String> {
        self.active_users.iter().cloned().collect()
    }

    /// `true` when at least one user needs filtering.
    pub fn is_active(&self) -> bool {
        !self.active_users.is_empty()
    }

    /// The §8 fail-closed predicate: block all web traffic while signed out.
    pub fn fail_closed_blocks_web(&self) -> bool {
        self.fail_closed_when_signed_out && self.active_users.is_empty()
    }

    /// The configured fail-closed flag.
    pub fn fail_closed_when_signed_out(&self) -> bool {
        self.fail_closed_when_signed_out
    }

    /// Updates the fail-closed flag (daemon, on config reload).
    pub fn set_fail_closed_when_signed_out(&mut self, fail_closed: bool) {
        self.fail_closed_when_signed_out = fail_closed;
    }

    /// The health snapshot exposed to the daemon (§9 `filter.health`).
    pub fn health(&self) -> FilterHealth {
        self.health
    }

    /// Refreshes the health snapshot from the live machine.
    pub fn set_health(&mut self, health: FilterHealth) {
        self.health = health;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct RecordingSink {
        events: crate::EngineMutex<Vec<HealthEvent>>,
    }

    impl crate::HealthSink for RecordingSink {
        fn record_lookup(&self, event: HealthEvent) {
            self.events.lock().push(event);
        }
    }

    fn t0() -> Instant {
        Instant::now()
    }

    /// healthy → outage → recovering → healthy, with injected clock.
    #[test]
    fn outage_machine_full_cycle() {
        let mut machine = OutageMachine::new(3, Duration::from_secs(30), Duration::from_secs(60));
        let now = t0();
        assert_eq!(machine.state(), FilterHealth::Healthy);
        assert!(!machine.is_outage());

        // Two problems are not yet an outage; a success resets the streak.
        machine.record_lookup(false, now);
        machine.record_lookup(false, now);
        assert_eq!(machine.state(), FilterHealth::Healthy);
        machine.record_lookup(true, now);
        machine.record_lookup(false, now);
        machine.record_lookup(false, now);
        machine.record_lookup(false, now);
        assert_eq!(machine.state(), FilterHealth::Outage);
        assert!(machine.is_outage());

        // Probe pacing: nothing due immediately after entering the outage.
        assert!(!machine.is_time_to_send_test_packet(now));
        let probe_due = now + Duration::from_secs(30);
        assert!(machine.is_time_to_send_test_packet(probe_due));
        machine.note_test_packet_sent(probe_due);
        assert!(!machine.is_time_to_send_test_packet(probe_due));
        assert!(machine.is_time_to_send_test_packet(probe_due + Duration::from_secs(30)));

        // A successful probe opens the recovery window.
        machine.record_lookup(true, probe_due);
        assert_eq!(machine.state(), FilterHealth::Recovering);
        assert!(!machine.is_outage());
        // Still inside the grace window: not healthy yet.
        machine.manage_outage_recovery(probe_due + Duration::from_secs(10));
        assert_eq!(machine.state(), FilterHealth::Recovering);
        // Grace elapsed with sustained success → healthy.
        machine.manage_outage_recovery(probe_due + Duration::from_secs(60));
        assert_eq!(machine.state(), FilterHealth::Healthy);
        assert!(!machine.is_outage());
    }

    #[test]
    fn failed_probe_keeps_outage_and_failure_during_recovery_reopens_it() {
        let mut machine = OutageMachine::new(1, Duration::from_secs(30), Duration::from_secs(60));
        let now = t0();
        machine.record_lookup(false, now);
        assert!(machine.is_outage());

        // Failing probe: still an outage.
        let probe = now + Duration::from_secs(30);
        assert!(machine.is_time_to_send_test_packet(probe));
        machine.note_test_packet_sent(probe);
        machine.record_lookup(false, probe);
        assert!(machine.is_outage());

        // Success opens recovery; a relapse during the grace window re-enters
        // the outage with a fresh probe timer.
        machine.record_lookup(true, probe);
        assert_eq!(machine.state(), FilterHealth::Recovering);
        machine.record_lookup(false, probe + Duration::from_secs(5));
        assert!(machine.is_outage());
        assert!(!machine.is_time_to_send_test_packet(probe + Duration::from_secs(5)));
    }

    #[test]
    fn cancel_timer_silences_probes_until_next_outage() {
        let mut machine = OutageMachine::default();
        let now = t0();
        machine.start_outage(now);
        assert!(machine.is_time_to_send_test_packet(now + DEFAULT_PROBE_INTERVAL));
        machine.cancel_outage_timer();
        assert!(!machine.is_time_to_send_test_packet(now + DEFAULT_PROBE_INTERVAL * 10));
        // end_outage clears everything deterministically.
        machine.end_outage();
        assert_eq!(machine.state(), FilterHealth::Healthy);
        machine.record_lookup(false, now);
        assert_eq!(machine.state(), FilterHealth::Healthy, "threshold 3");
    }

    #[test]
    fn health_sink_receives_ce_metric_names_and_tags() {
        let sink = Arc::new(RecordingSink {
            events: crate::EngineMutex::new(Vec::new()),
        });
        let mut health = DnsHealth::new(
            "https://dns.cleanbrowsing.org/doh/adult-filter",
            Some(sink.clone()),
        );
        let now = t0();
        health.record_doh_success(Some("lax".into()), 42, DohRequestReason::Typical, now);
        health.record_doh_timeout(DohRequestReason::ErrorRecovery, now);
        health.record_doh_error(
            Some("iad".into()),
            Some(503),
            None,
            DohRequestReason::Typical,
            now,
        );

        let events = sink.events.lock().clone();
        assert_eq!(events.len(), 3);
        assert_eq!(events[0].metric, "client_cleanbrowsing_success");
        assert_eq!(events[0].request_reason, "typical");
        assert_eq!(events[0].datacenter.as_deref(), Some("lax"));
        assert_eq!(
            events[0].doh_url,
            "https://dns.cleanbrowsing.org/doh/adult-filter"
        );
        assert_eq!(events[0].outcome, LookupOutcome::Success { latency_ms: 42 });
        assert_eq!(events[1].metric, "client_cleanbrowsing_problem");
        assert_eq!(events[1].request_reason, "error-recovery");
        assert_eq!(events[1].outcome, LookupOutcome::Timeout);
        assert_eq!(
            events[2].outcome,
            LookupOutcome::Error {
                http_status: Some(503),
                dns_rcode: None
            }
        );
        assert_eq!(health.counters(), (1, 2));
        assert_eq!(
            health.health(),
            FilterHealth::Healthy,
            "threshold not reached"
        );
    }

    #[test]
    fn health_without_sink_still_tracks_machine() {
        let mut health = DnsHealth::new("https://x/doh", None);
        let now = t0();
        for _ in 0..DEFAULT_PROBLEM_THRESHOLD {
            health.record_doh_timeout(DohRequestReason::Typical, now);
        }
        assert!(health.is_outage());
        assert_eq!(health.health(), FilterHealth::Outage);
        assert_eq!(health.counters(), (0, u64::from(DEFAULT_PROBLEM_THRESHOLD)));
    }

    #[test]
    fn health_event_equality_is_deterministic() {
        let a = HealthEvent {
            metric: METRIC_CLEANBROWSING_SUCCESS,
            datacenter: None,
            doh_url: "u".into(),
            request_reason: REASON_TYPICAL,
            outcome: LookupOutcome::Success { latency_ms: 1 },
        };
        let b = a.clone();
        assert_eq!(a, b);
        assert_eq!(DohRequestReason::Typical.as_str(), "typical");
        assert_eq!(DohRequestReason::ErrorRecovery.as_str(), "error-recovery");
    }

    /// §8 lifecycle: ref-counted activation + fail-closed semantics.
    #[test]
    fn filter_state_ref_counts_users_idempotently() {
        let mut state = FilterState::new(true);
        assert_eq!(state.active_user_count(), 0);
        assert!(state.fail_closed_blocks_web());
        assert!(!state.is_active());

        assert_eq!(state.activate_user("alice"), 1);
        assert_eq!(state.activate_user("alice"), 1, "idempotent per user");
        assert_eq!(state.activate_user("bob"), 2);
        assert!(!state.fail_closed_blocks_web());

        assert_eq!(state.deactivate_user("alice"), 1);
        assert!(!state.fail_closed_blocks_web());
        assert_eq!(state.deactivate_user("bob"), 0);
        assert!(state.fail_closed_blocks_web());
        assert_eq!(state.deactivate_user("nobody"), 0);
        assert_eq!(state.active_usernames(), Vec::<String>::new());
    }

    #[test]
    fn filter_state_fail_closed_flag_is_configurable() {
        let mut state = FilterState::new(false);
        assert!(!state.fail_closed_blocks_web());
        state.set_fail_closed_when_signed_out(true);
        assert!(state.fail_closed_blocks_web());
        state.activate_user("alice");
        assert!(!state.fail_closed_blocks_web());
    }

    #[test]
    fn filter_state_carries_health_snapshot() {
        let mut state = FilterState::new(true);
        assert_eq!(state.health(), FilterHealth::Healthy);
        state.set_health(FilterHealth::Outage);
        assert_eq!(state.health(), FilterHealth::Outage);
        assert_eq!(FilterHealth::Outage.as_str(), "outage");
        assert_eq!(FilterHealth::Recovering.as_str(), "recovering");
        assert_eq!(FilterHealth::Healthy.as_str(), "healthy");
    }
}
