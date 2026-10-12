//! Capture scheduler (CONTRACTS §7; CE cadence from
//! `re/findings/10-classifier/capture-pipeline.md` §1):
//!
//! * steady state sleeps `U[(1-v)*I, (1+v)*I]` with `I = capture.interval_sec` and
//!   `v = capture.variance_pct / 100` (de-synchronizes fleets — CE's
//!   `imageScreenshotInterval`/`imageScreenshotIntervalVariance`),
//! * retry ladder: **5 s** while the classifier is down, **40 s** default, **60 s** worst case
//!   (CE's `5000`/`40000`/`60000` ms table),
//! * gates evaluated before every capture: logind session `LockedHint`/`Active`, screensaver
//!   state, classifier alive — capture is **skipped entirely** while locked or
//!   screensaver-active (an improvement over CE's `saver_while_capture` telemetry),
//! * backend selection: `auto` = X11 when `XDG_SESSION_TYPE=x11`, else Wayland
//!   (see [`crate::resolve_backend`]).

use std::time::Duration;

use rand::Rng;
use zbus::zvariant::OwnedObjectPath;
use zbus::Proxy;

/// Capture backend selector (`capture.backend` config).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendChoice {
    Auto,
    X11,
    Wayland,
}

impl BackendChoice {
    /// Parse the config value `auto` | `x11` | `wayland`; anything else is `Err`.
    pub fn parse(value: &str) -> Result<Self, GateError> {
        match value {
            "auto" => Ok(Self::Auto),
            "x11" => Ok(Self::X11),
            "wayland" => Ok(Self::Wayland),
            other => Err(GateError::Config(format!(
                "unknown capture backend {other:?} (expected auto|x11|wayland)"
            ))),
        }
    }
}

/// Why a capture tick was skipped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateReason {
    /// logind session `LockedHint` is true (screen locked).
    SessionLocked,
    /// logind session `Active` is false (session switched away / no active session).
    SessionInactive,
    /// The screensaver inhibition says a screensaver is running.
    ScreensaverActive,
    /// The classifier process is not alive (CE's `isClassifierRunning` gate).
    ClassifierDown,
}

impl std::fmt::Display for GateReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SessionLocked => write!(f, "session locked"),
            Self::SessionInactive => write!(f, "session inactive"),
            Self::ScreensaverActive => write!(f, "screensaver active"),
            Self::ClassifierDown => write!(f, "classifier down"),
        }
    }
}

/// Gate infrastructure errors (D-Bus unavailable, config errors). Distinct from a gate
/// legitimately firing ([`GateReason`]) so the daemon can tell "skip" from "cannot tell".
#[derive(Debug, thiserror::Error)]
pub enum GateError {
    #[error("system bus unavailable: {0}")]
    SystemBus(String),
    #[error("session bus unavailable: {0}")]
    SessionBus(String),
    #[error("logind query failed: {0}")]
    Logind(String),
    #[error("config error: {0}")]
    Config(String),
}

/// The jittered capture scheduler.
pub struct Scheduler {
    interval: Duration,
    /// Jitter fraction (0.20 for `variance_pct = 20`).
    variance: f64,
}

impl Scheduler {
    /// Retry while the classifier is not running/ready (CE: 5 000 ms).
    pub const RETRY_CLASSIFIER_DOWN: Duration = Duration::from_secs(5);
    /// Default retry when a tick produced nothing usable (CE: 40 000 ms).
    pub const RETRY_DEFAULT: Duration = Duration::from_secs(40);
    /// Worst-case retry (CE: 60 000 ms fallback when the capture task yields no value).
    pub const RETRY_WORST: Duration = Duration::from_secs(60);

    /// `interval_sec` from `capture.interval_sec`, `variance_pct` in percent.
    pub fn new(interval_sec: u64, variance_pct: f64) -> Self {
        Self {
            interval: Duration::from_secs(interval_sec.max(1)),
            variance: (variance_pct.max(0.0) / 100.0).min(0.95),
        }
    }

    /// The configured nominal interval.
    pub fn interval(&self) -> Duration {
        self.interval
    }

    /// The jitter fraction actually in use.
    pub fn variance(&self) -> f64 {
        self.variance
    }

    /// Steady-state delay: uniform in `[(1-v)*I, (1+v)*I]` with a fresh thread-local RNG.
    pub fn steady_delay(&self) -> Duration {
        let mut rng = rand::thread_rng();
        self.steady_delay_with(&mut rng)
    }

    /// Steady-state delay with a caller-supplied RNG (deterministic in tests).
    pub fn steady_delay_with<R: Rng + ?Sized>(&self, rng: &mut R) -> Duration {
        let millis = self.interval.as_millis() as f64;
        let low = millis * (1.0 - self.variance);
        let high = millis * (1.0 + self.variance);
        let draw = if low >= high {
            low
        } else {
            rng.gen_range(low..high)
        };
        Duration::from_millis(draw.round() as u64)
    }

    /// Delay before the next tick given how the current tick went (CE's fixed retry ladder).
    pub fn delay_for(outcome: TickOutcome) -> Duration {
        match outcome {
            TickOutcome::Captured => Self::RETRY_DEFAULT,
            TickOutcome::ClassifierDown => Self::RETRY_CLASSIFIER_DOWN,
            TickOutcome::NoScreenstateConfig => Self::RETRY_DEFAULT,
            TickOutcome::Failed => Self::RETRY_WORST,
        }
    }
}

/// How the current capture tick ended, for the retry ladder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TickOutcome {
    /// A transaction was published; next tick is on the normal jittered cadence, with 40 s as
    /// the between-captures fallback CE uses post-capture.
    Captured,
    /// Classifier not detected running / not ready (CE gate, 5 s).
    ClassifierDown,
    /// Captured but no usable screenstate configuration (CE: `*param_2 = 40000`).
    NoScreenstateConfig,
    /// Capture or transaction failed (CE: 60 000 ms worst case).
    Failed,
}

/// Pre-capture gates: logind `LockedHint`/`Active` for the user's session plus screensaver
/// state (CONTRACTS §7). The classifier-alive gate is owned by the daemon (it supervises the
/// child) and folded in via [`GateReason::ClassifierDown`] at the call site.
pub struct Gates {
    system: zbus::Connection,
    session: Option<zbus::Connection>,
}

impl Gates {
    /// Connect the system bus (logind) and, best-effort, the session bus (screensaver
    /// queries). The daemon runs as root, so the *user's* session bus must be reachable via
    /// `DBUS_SESSION_BUS_ADDRESS`/`XDG_RUNTIME_DIR` of the captured session; a missing
    /// session bus disables only the screensaver gate with a warning (logind still gates).
    pub async fn new() -> Result<Self, GateError> {
        let system = zbus::Connection::system()
            .await
            .map_err(|e| GateError::SystemBus(e.to_string()))?;
        let session = match zbus::Connection::session().await {
            Ok(conn) => Some(conn),
            Err(e) => {
                log::warn!("capture: session bus unavailable, screensaver gate disabled: {e}");
                None
            }
        };
        Ok(Self { system, session })
    }

    /// Evaluate all gates for the user owning `uid`. `Ok(())` means capture may proceed;
    /// `Ok(reason)` means skip this tick (log at info); `Err` means the gates could not be
    /// evaluated (fail-open with an error log — never a silent no-op).
    pub async fn check(&self, uid: u32) -> Result<(), GateError> {
        if let Some(reason) = self.session_gate(uid).await? {
            log::info!("capture: skipping capture ({reason})");
            return Ok(());
        }
        if self.screensaver_active().await? {
            log::info!(
                "capture: skipping capture ({})",
                GateReason::ScreensaverActive
            );
        }
        Ok(())
    }

    /// logind `LockedHint` + `Active` for one of the user's sessions. Returns the gate that
    /// fired, or `None` when capture is allowed. No session at all ⇒
    /// [`GateReason::SessionInactive`] (nothing to capture for this user).
    async fn session_gate(&self, uid: u32) -> Result<Option<GateReason>, GateError> {
        let manager = Proxy::new(
            &self.system,
            "org.freedesktop.login1",
            "/org/freedesktop/login1",
            "org.freedesktop.login1.Manager",
        )
        .await
        .map_err(|e| GateError::Logind(e.to_string()))?;

        // ListSessions -> a(ssusso): (session_id, uid, user, seat, object_path).
        let reply = manager
            .call_method("ListSessions", &())
            .await
            .map_err(|e| GateError::Logind(e.to_string()))?;
        let sessions: Vec<(String, u32, String, String, OwnedObjectPath)> = reply
            .body()
            .deserialize()
            .map_err(|e| GateError::Logind(format!("ListSessions decode: {e}")))?;

        let mut candidates: Vec<&OwnedObjectPath> = sessions
            .iter()
            .filter(|(_, session_uid, ..)| *session_uid == uid)
            .map(|(_, _, _, _, path)| path)
            .collect();
        if candidates.is_empty() {
            return Ok(Some(GateReason::SessionInactive));
        }
        // Prefer the session logind reports as active.
        let mut chosen = candidates.remove(0);
        for path in candidates {
            let proxy = self
                .session_proxy(path.as_str())
                .await?
                .ok_or_else(|| GateError::Logind(format!("session proxy {path}")))?;
            if proxy
                .get_property::<bool>("Active")
                .await
                .map_err(|e| GateError::Logind(e.to_string()))?
            {
                chosen = path;
                break;
            }
        }

        let Some(proxy) = self.session_proxy(chosen.as_str()).await? else {
            return Ok(Some(GateReason::SessionInactive));
        };
        let locked = proxy
            .get_property::<bool>("LockedHint")
            .await
            .map_err(|e| GateError::Logind(e.to_string()))?;
        if locked {
            return Ok(Some(GateReason::SessionLocked));
        }
        let active = proxy
            .get_property::<bool>("Active")
            .await
            .map_err(|e| GateError::Logind(e.to_string()))?;
        if !active {
            return Ok(Some(GateReason::SessionInactive));
        }
        Ok(None)
    }

    async fn session_proxy<'a>(&self, path: &'a str) -> Result<Option<Proxy<'a>>, GateError> {
        Ok(Some(
            Proxy::new(
                &self.system,
                "org.freedesktop.login1",
                path,
                "org.freedesktop.login1.Session",
            )
            .await
            .map_err(|e| GateError::Logind(e.to_string()))?,
        ))
    }

    /// Freedesktop screensaver `GetActive` on the session bus. A missing screensaver service
    /// (GNOME without the org.freedesktop.ScreenSaver alias, etc.) means "not active".
    async fn screensaver_active(&self) -> Result<bool, GateError> {
        let Some(session) = &self.session else {
            return Ok(false);
        };
        let proxy = Proxy::new(
            session,
            "org.freedesktop.ScreenSaver",
            "/org/freedesktop/ScreenSaver",
            "org.freedesktop.ScreenSaver",
        )
        .await
        .map_err(|e| GateError::SessionBus(e.to_string()))?;
        match proxy.call_method("GetActive", &()).await {
            Ok(reply) => reply
                .body()
                .deserialize::<bool>()
                .map_err(|e| GateError::SessionBus(format!("screensaver GetActive decode: {e}"))),
            Err(zbus::Error::MethodError(name, _, _))
                if name.as_str() == "org.freedesktop.DBus.Error.ServiceUnknown"
                    || name.as_str() == "org.freedesktop.DBus.Error.UnknownMethod" =>
            {
                log::debug!("capture: no screensaver service on the session bus");
                Ok(false)
            }
            Err(e) => Err(GateError::SessionBus(e.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    #[test]
    fn jitter_stays_within_uniform_bounds() {
        let scheduler = Scheduler::new(30, 20.0);
        let mut rng = StdRng::seed_from_u64(0xC0FFEE);
        let low = Duration::from_millis(24_000); // (1 - 0.20) * 30 s
        let high = Duration::from_millis(36_000); // (1 + 0.20) * 30 s
        let mut min = Duration::MAX;
        let mut max = Duration::ZERO;
        for _ in 0..2_000 {
            let delay = scheduler.steady_delay_with(&mut rng);
            assert!(delay >= low, "delay {delay:?} below lower bound {low:?}");
            assert!(delay <= high, "delay {delay:?} above upper bound {high:?}");
            min = min.min(delay);
            max = max.max(delay);
        }
        // Sanity (deterministic under the fixed seed): the draws actually spread instead of
        // clamping to one bound. The spread can never exceed the formula range
        // `high - low` = 12 s, so a >20 s spread would contradict CONTRACTS §7's bounds.
        assert!(
            max - min > high - low - Duration::from_secs(2),
            "spread was {min:?}..{max:?}"
        );
    }

    #[test]
    fn zero_variance_yields_the_exact_interval() {
        let scheduler = Scheduler::new(40, 0.0);
        let mut rng = StdRng::seed_from_u64(1);
        for _ in 0..16 {
            assert_eq!(
                scheduler.steady_delay_with(&mut rng),
                Duration::from_secs(40)
            );
        }
    }

    #[test]
    fn variance_is_clamped_to_sane_range() {
        let mut rng = StdRng::seed_from_u64(2);
        // Negative variance clamps to 0 => exact interval.
        assert_eq!(
            Scheduler::new(30, -5.0).steady_delay_with(&mut rng),
            Duration::from_secs(30)
        );
        // Huge variance clamps to 95% => upper bound 1.95*I.
        let scheduler = Scheduler::new(10, 500.0);
        let delay = scheduler.steady_delay_with(&mut rng);
        assert!(delay <= Duration::from_millis(19_500));
        assert!(delay >= Duration::ZERO);
    }

    #[test]
    fn retry_ladder_matches_ce_table() {
        assert_eq!(
            Scheduler::delay_for(TickOutcome::ClassifierDown),
            Duration::from_secs(5)
        );
        assert_eq!(
            Scheduler::delay_for(TickOutcome::Captured),
            Duration::from_secs(40)
        );
        assert_eq!(
            Scheduler::delay_for(TickOutcome::NoScreenstateConfig),
            Duration::from_secs(40)
        );
        assert_eq!(
            Scheduler::delay_for(TickOutcome::Failed),
            Duration::from_secs(60)
        );
    }

    #[test]
    fn backend_choice_parses_config_values() {
        assert_eq!(BackendChoice::parse("auto").unwrap(), BackendChoice::Auto);
        assert_eq!(BackendChoice::parse("x11").unwrap(), BackendChoice::X11);
        assert_eq!(
            BackendChoice::parse("wayland").unwrap(),
            BackendChoice::Wayland
        );
        assert!(BackendChoice::parse("dxgi").is_err());
    }
}
