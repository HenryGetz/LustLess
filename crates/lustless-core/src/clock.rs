//! Clock anchor — CONTRACTS §10 ("a `(server_time, local_ticks)` clock anchor
//! refreshed hourly from `status/time` (system-time fallback)").
//!
//! The daemon refreshes the anchor from `GET /v1/status/time` about once an
//! hour (evidence: `upload-protocol.md` §4, `ServerTimeManager::sync` —
//! "Server time update success/failed … falling back to system time").
//! Between refreshes "server now" is derived from the local monotonic clock;
//! until the first successful fetch (or after a failed one) the anchor is
//! built from the system clock. Event timestamps rendered for upload records
//! (§10) go through [`ClockAnchor::now_iso8601`].

use std::time::{Instant, SystemTime, UNIX_EPOCH};

use time::format_description::StaticFormatDescription;
use time::macros::format_description;
use time::OffsetDateTime;

/// `YYYY-MM-DDTHH:MM:SSZ` — the ISO-8601 UTC stamp used for every event
/// timestamp of the outbox (§6.1) and record envelope (§10).
const ISO_8601: StaticFormatDescription =
    format_description!("[year]-[month]-[day]T[hour]:[minute]:[second]Z");

/// The `(server_time, local_ticks)` anchor of §10.
///
/// `server_time` is captured once per sync; `local_ticks` is the monotonic
/// reading (`Instant`) taken at the same moment. `now` is interpolated from
/// the monotonic clock between syncs, so a wall-clock step cannot rewind or
/// jump record timestamps mid-cycle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClockAnchor {
    /// Unix seconds reported by `/v1/status/time` (or the system clock for a
    /// fallback anchor).
    server_time_unix: i64,
    /// Monotonic reading paired with `server_time_unix`.
    local_ticks: Instant,
    /// `true` while anchored to the server clock; `false` in system-time
    /// fallback (§10).
    server_anchored: bool,
}

impl ClockAnchor {
    /// Builds an anchor from a successful `/v1/status/time` response
    /// (`server_time` in unix seconds).
    pub fn from_server_time(server_time_unix: i64) -> Self {
        ClockAnchor {
            server_time_unix,
            local_ticks: Instant::now(),
            server_anchored: true,
        }
    }

    /// Builds the system-time fallback anchor (§10): server time unknown, so
    /// the system wall clock is trusted directly.
    pub fn system() -> Self {
        ClockAnchor {
            server_time_unix: system_unix(),
            local_ticks: Instant::now(),
            server_anchored: false,
        }
    }

    /// Installs a fresh `(server_time, local_ticks)` pair — the hourly refresh
    /// of §10.
    pub fn refresh_from_server_time(&mut self, server_time_unix: i64) {
        self.server_time_unix = server_time_unix;
        self.local_ticks = Instant::now();
        self.server_anchored = true;
    }

    /// Drops back to the system clock after a failed `/v1/status/time` fetch
    /// ("falling back to system time", `upload-protocol.md` §4).
    pub fn fall_back_to_system_time(&mut self) {
        *self = ClockAnchor::system();
    }

    /// Whether the anchor currently tracks the server clock (as opposed to
    /// the system-time fallback).
    pub fn is_server_anchored(&self) -> bool {
        self.server_anchored
    }

    /// Current time in unix seconds, interpolated through the anchor.
    pub fn now_unix(&self) -> i64 {
        self.server_time_unix + self.local_ticks.elapsed().as_secs() as i64
    }

    /// Current time rendered as ISO-8601 UTC (`YYYY-MM-DDTHH:MM:SSZ`) — the
    /// timestamp used by upload records (§10) and event rows (§6.1).
    pub fn now_iso8601(&self) -> String {
        iso8601_utc(self.now_unix())
    }
}

/// Current system time in unix seconds (no anchor; used for the fallback and
/// for comparison in tests).
pub fn system_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Renders a unix timestamp as ISO-8601 UTC (`YYYY-MM-DDTHH:MM:SSZ`, §6.1/§10).
/// Returns an empty string for timestamps outside time's supported year range
/// (±9999), which never occurs for event data.
pub fn iso8601_utc(unix: i64) -> String {
    match OffsetDateTime::from_unix_timestamp(unix) {
        Ok(dt) => dt.format(&ISO_8601).unwrap_or_default(),
        Err(_) => String::new(),
    }
}

/// The machine's current UTC offset as `±HH:MM` — the separate
/// `timezone_offset` string stored beside every UTC event timestamp (§6.1) so
/// dashboards can render local time.
///
/// Falls back to `+00:00` when the local offset cannot be determined
/// (`time::error::IndeterminateOffset`, e.g. after threads were spawned).
pub fn local_timezone_offset() -> String {
    match OffsetDateTime::now_local() {
        Ok(now) => {
            // `UtcOffset` displays as `±HH:MM:SS`; offsets with a seconds
            // component are exotic, `±HH:MM` is the canonical form we store.
            let rendered = now.offset().to_string();
            rendered.get(..6).unwrap_or("+00:00").to_string()
        }
        Err(_) => "+00:00".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_timestamps_render_iso8601_utc() {
        assert_eq!(iso8601_utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(iso8601_utc(1_700_000_000), "2023-11-14T22:13:20Z");
    }

    #[test]
    fn iso8601_shape() {
        let stamp = iso8601_utc(1_500_000_000);
        assert_eq!(stamp.len(), 20);
        assert_eq!(&stamp[10..11], "T");
        assert!(stamp.ends_with('Z'));
    }

    #[test]
    fn server_anchor_holds_its_baseline() {
        let anchor = ClockAnchor::from_server_time(1_700_000_000);
        assert!(anchor.is_server_anchored());
        let now = anchor.now_unix();
        assert!((1_700_000_000..=1_700_000_005).contains(&now), "now={now}");
        assert!(anchor.now_iso8601().starts_with("2023-11-14"));
    }

    #[test]
    fn system_fallback_and_refresh() {
        let anchor = ClockAnchor::system();
        assert!(!anchor.is_server_anchored());
        let drift = (anchor.now_unix() - system_unix()).abs();
        assert!(drift <= 2, "system anchor drift {drift}s");

        let mut anchor = anchor;
        anchor.refresh_from_server_time(1_700_000_000);
        assert!(anchor.is_server_anchored());
        let now = anchor.now_unix();
        assert!((1_700_000_000..=1_700_000_005).contains(&now), "now={now}");

        anchor.fall_back_to_system_time();
        assert!(!anchor.is_server_anchored());
        assert!((anchor.now_unix() - system_unix()).abs() <= 2);
    }

    #[test]
    fn timezone_offset_shape() {
        let offset = local_timezone_offset();
        assert_eq!(offset.len(), 6, "offset={offset}");
        assert!(offset.starts_with('+') || offset.starts_with('-'), "{offset}");
        assert_eq!(&offset[3..4], ":");
    }
}
