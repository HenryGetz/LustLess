//! `dashboard.rs` — the §13 dashboard: an embedded `axum` server on
//! `127.0.0.1:<daemon.dashboard_port>`, token-authenticated, with embedded
//! HTML templates (no external assets, no build step).
//!
//! Pages: status, sign-in/out (POST → [`Control`]), settings (filter level +
//! domain overrides via [`Control`]), the DNS-activity log (the CE
//! `ViewDnsActivityHandler` query — [`Outbox::dns_activity_readback`], 500
//! rows) and the diagnostics trigger. Mutations are POST + redirect; every
//! page renders the current [`PolicySnapshot`].
//!
//! **No keys route of any kind** (§13): CE's `/local/user/:username:/
//! keys.:doctype:` handed the per-user API credential pair to any local
//! caller (`re/findings/13-service-ipc/service-ipc.md` §1) — the single
//! anti-pattern this dashboard exists to not repeat. The only credential
//! surface is the short-lived token store of `tokens.rs`.
//!
//! Token auth accepts `?t=<token>` (the agent appends it when opening the
//! browser) or `Authorization: Bearer <token>`; unknown/expired tokens get
//! 401 (§13).

use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};

use axum::extract::{Form, Query, Request, State};
use axum::http::StatusCode;
use axum::middleware::{self, Next};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::Router;
use lustless_core::clock::{system_unix, ClockAnchor};
use lustless_core::config::LustlessConfig;
use lustless_core::db::{Outbox, DASHBOARD_READ_LIMIT};
use lustless_core::policy::PolicySnapshot;
use serde::Deserialize;
use serde_json::Value;
use tracing::{error, info};

use crate::tokens::TokenStore;
use crate::uploader::{lock_outbox, read_clock};
use crate::{Control, PolicyProvider};

/// Shared state of the dashboard handlers.
#[derive(Clone)]
pub(crate) struct DashboardState {
    /// Live policy snapshot source (§9).
    pub(crate) policy: Arc<dyn PolicyProvider>,
    /// Daemon control surface (sign-in/out, filter, diagnostics).
    pub(crate) control: Arc<dyn Control>,
    /// Outbox for the DNS-activity read-back page.
    pub(crate) outbox: Arc<Mutex<Outbox>>,
    /// Dashboard token registry (§13).
    pub(crate) tokens: Arc<TokenStore>,
    /// Clock anchor for rendered timestamps (§10).
    pub(crate) clock: Arc<RwLock<ClockAnchor>>,
}

/// Serves the dashboard until the future is dropped (cancellation) or the
/// listener dies. A disabled dashboard or a bind failure parks this branch
/// without failing `NetServices::run` — the uploader and updater must never
/// go down with the dashboard.
pub(crate) async fn serve(cfg: Arc<LustlessConfig>, state: DashboardState) {
    if !cfg.daemon.dashboard_enabled {
        info!("dashboard disabled by configuration");
        std::future::pending::<()>().await;
        return;
    }
    let addr = format!("127.0.0.1:{}", cfg.daemon.dashboard_port);
    match tokio::net::TcpListener::bind(&addr).await {
        Ok(listener) => {
            info!("dashboard listening on http://{addr}");
            if let Err(err) = axum::serve(listener, router(state)).await {
                error!("dashboard server error: {err}");
            }
        }
        Err(err) => error!("dashboard bind failed on {addr}: {err}"),
    }
    std::future::pending::<()>().await;
}

/// The dashboard route table. There is no `/keys` route — not under
/// `/local`, not anywhere (§13).
pub(crate) fn router(state: DashboardState) -> Router {
    Router::new()
        .route("/", get(status_page))
        .route("/sign-in", get(sign_in_page).post(sign_in_submit))
        .route("/sign-out", post(sign_out_submit))
        .route("/settings", get(settings_page))
        .route("/settings/level", post(level_submit))
        .route("/settings/override", post(override_submit))
        .route("/activity", get(activity_page))
        .route("/diagnostics", post(diagnostics_submit))
        .layer(middleware::from_fn_with_state(state.clone(), auth))
        .with_state(state)
}

/// Token middleware: every request is validated (single-use is NOT
/// required); unknown or expired tokens are 401.
async fn auth(State(state): State<DashboardState>, request: Request, next: Next) -> Response {
    match extract_token(&request).and_then(|token| state.tokens.validate(&token, system_unix())) {
        Some(_uid) => next.run(request).await,
        None => (StatusCode::UNAUTHORIZED, "unauthorized").into_response(),
    }
}

/// Extracts the token from `?t=` (first occurrence) or the Bearer header.
fn extract_token(request: &Request) -> Option<String> {
    if let Some(query) = request.uri().query() {
        for pair in query.split('&') {
            if let Some(value) = pair.strip_prefix("t=") {
                return Some(percent_decode(value));
            }
        }
    }
    request
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(|value| value.trim().to_string())
}

/// Minimal percent-decoder for the query token (tokens are hex; this only
/// matters for hand-built URLs).
fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).ok();
            if let Some(byte) = hex.and_then(|hex| u8::from_str_radix(hex, 16).ok()) {
                out.push(byte);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).to_string()
}

/// Percent-encodes one query-string value.
fn percent_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        let safe = byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~');
        if safe {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// HTML-escapes one interpolation value.
fn esc(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

async fn status_page(State(state): State<DashboardState>) -> Html<String> {
    let snapshot = state.policy.snapshot();
    let now = read_clock(&state.clock).now_iso8601();
    let mut rows = String::new();
    let mut row = |label: &str, value: &str| {
        rows.push_str(&format!(
            "<tr><th>{}</th><td>{}</td></tr>",
            esc(label),
            esc(value)
        ));
    };
    row("Account", snapshot.username_or("(signed out)"));
    row("Session state", &format!("{:?}", snapshot.state));
    row("Signed in", if snapshot.signed_in { "yes" } else { "no" });
    row(
        "Filtering",
        if snapshot.has_filtering { "yes" } else { "no" },
    );
    row(
        "DNS filtering",
        if snapshot.has_dns_filtering {
            "yes"
        } else {
            "no"
        },
    );
    row(
        "Accountability",
        if snapshot.has_accountability {
            "yes"
        } else {
            "no"
        },
    );
    row(
        "Screen accountability",
        if snapshot.has_screen_accountability {
            "yes"
        } else {
            "no"
        },
    );
    row("Filter level", &snapshot.filter.level);
    row("Filter health", &snapshot.filter.health);
    row(
        "Fail closed (signed out ⇒ web blocked)",
        if snapshot.filter.fail_closed {
            "yes"
        } else {
            "no — fail-open OVERRIDE ACTIVE"
        },
    );
    row(
        "Can override blocks",
        if snapshot.can_override { "yes" } else { "no" },
    );
    row("Panicked", if snapshot.is_panicked { "yes" } else { "no" });
    row(
        "Capture active",
        if snapshot.capture.active { "yes" } else { "no" },
    );
    row("Capture backend", &snapshot.capture.backend);
    row(
        "Last screenstate",
        snapshot
            .capture
            .last_screenstate_at
            .as_deref()
            .unwrap_or("(none)"),
    );
    row(
        "Server-anchored clock",
        if read_clock(&state.clock).is_server_anchored() {
            "yes"
        } else {
            "no (system time)"
        },
    );
    row("Daemon time (UTC)", &now);
    Html(layout(
        "Status",
        &snapshot,
        &format!("<h2>Status</h2><table class=\"kv\">{rows}</table>"),
    ))
}

#[derive(Deserialize)]
pub(crate) struct SignInForm {
    username: String,
    password: String,
}

async fn sign_in_page(
    State(state): State<DashboardState>,
    Query(params): Query<HashMap<String, String>>,
) -> Html<String> {
    let snapshot = state.policy.snapshot();
    let error = params
        .get("error")
        .map(|message| format!("<p class=\"error\">{}</p>", esc(message)));
    let body = format!(
        "<h2>Sign in</h2>{}\
         <form method=\"post\" action=\"/sign-in\" class=\"stack\">\
         <label>Account username <input name=\"username\" required></label>\
         <label>Password <input name=\"password\" type=\"password\" required></label>\
         <button type=\"submit\">Sign in</button></form>",
        error.unwrap_or_default()
    );
    Html(layout("Sign in", &snapshot, &body))
}

async fn sign_in_submit(
    State(state): State<DashboardState>,
    Form(form): Form<SignInForm>,
) -> Response {
    match state.control.sign_in(&form.username, &form.password) {
        Ok(_) => Redirect::to("/?notice=signed-in").into_response(),
        Err(err) => {
            Redirect::to(&format!("/sign-in?error={}", percent_encode(&err))).into_response()
        }
    }
}

async fn sign_out_submit(State(state): State<DashboardState>) -> Response {
    match state.control.sign_out() {
        Ok(_) => Redirect::to("/?notice=signed-out").into_response(),
        Err(err) => {
            Redirect::to(&format!("/sign-in?error={}", percent_encode(&err))).into_response()
        }
    }
}

async fn settings_page(
    State(state): State<DashboardState>,
    Query(params): Query<HashMap<String, String>>,
) -> Html<String> {
    let snapshot = state.policy.snapshot();
    let notice = params
        .get("notice")
        .map(|message| format!("<p class=\"notice\">{}</p>", esc(message)))
        .unwrap_or_default();
    let level = &snapshot.filter.level;
    let level_option = |value: &str| {
        let selected = if level == value { " selected" } else { "" };
        format!("<option value=\"{value}\"{selected}>{value}</option>")
    };
    let body = format!(
        "<h2>Settings</h2>{notice}\
         <h3>Blocking level</h3>\
         <form method=\"post\" action=\"/settings/level\" class=\"inline\">\
         <select name=\"level\">{}{}{}</select>\
         <button type=\"submit\">Save</button></form>\
         <h3>Domain override</h3>\
         <form method=\"post\" action=\"/settings/override\" class=\"stack\">\
         <label>Domain <input name=\"domain\" placeholder=\"example.org\" required></label>\
         <label>Verdict <select name=\"verdict\">\
         <option value=\"allow\">allow</option>\
         <option value=\"block\">block</option>\
         <option value=\"na\">no override (remove)</option>\
         </select></label>\
         <button type=\"submit\">Apply override</button></form>",
        level_option("Standard Blocking"),
        level_option("Strong Blocking"),
        level_option("Blocking Enabled"),
    );
    Html(layout("Settings", &snapshot, &body))
}

#[derive(Deserialize)]
pub(crate) struct LevelForm {
    level: String,
}

async fn level_submit(
    State(state): State<DashboardState>,
    Form(form): Form<LevelForm>,
) -> Response {
    match state.control.set_filter_level(&form.level) {
        Ok(_) => Redirect::to("/settings?notice=saved").into_response(),
        Err(err) => {
            Redirect::to(&format!("/settings?error={}", percent_encode(&err))).into_response()
        }
    }
}

#[derive(Deserialize)]
pub(crate) struct OverrideForm {
    domain: String,
    verdict: String,
}

async fn override_submit(
    State(state): State<DashboardState>,
    Form(form): Form<OverrideForm>,
) -> Response {
    if !matches!(form.verdict.as_str(), "allow" | "block" | "na") {
        return Redirect::to("/settings?error=invalid+verdict").into_response();
    }
    match state.control.set_override(&form.domain, &form.verdict) {
        Ok(_) => Redirect::to("/settings?notice=saved").into_response(),
        Err(err) => {
            Redirect::to(&format!("/settings?error={}", percent_encode(&err))).into_response()
        }
    }
}

async fn activity_page(State(state): State<DashboardState>) -> Html<String> {
    let snapshot = state.policy.snapshot();
    let rows = match lock_outbox(&state.outbox).dns_activity_readback(DASHBOARD_READ_LIMIT) {
        Ok(rows) => rows,
        Err(err) => {
            error!("dns activity read-back failed: {err}");
            Vec::new()
        }
    };
    let mut table = String::from(
        "<table class=\"grid\"><thead><tr>\
         <th>Domain</th><th>Process</th><th>IP</th><th>Verdict</th>\
         <th>Path</th><th>Datacenter</th><th>ms</th><th>When (UTC)</th>\
         </tr></thead><tbody>",
    );
    if rows.is_empty() {
        table.push_str("<tr><td colspan=\"8\">(no DNS activity recorded)</td></tr>");
    }
    for row in &rows {
        let cell = |key: &str| -> String {
            match row.get(key) {
                Some(Value::String(value)) if !value.is_empty() => esc(value),
                Some(Value::Number(value)) => esc(&value.to_string()),
                _ => "-".to_string(),
            }
        };
        table.push_str(&format!(
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            cell("domain"),
            cell("process_name"),
            cell("ip"),
            cell("resolution_type"),
            cell("connection_type"),
            cell("resolution_datacenter"),
            cell("resolution_time_ms"),
            cell("datetime_created"),
        ));
    }
    table.push_str("</tbody></table>");
    let body = format!("<h2>Your DNS activity on this computer</h2>{table}");
    Html(layout("DNS activity", &snapshot, &body))
}

async fn diagnostics_submit(State(state): State<DashboardState>) -> Response {
    match state.control.collect_debug() {
        Ok(_) => Redirect::to("/?notice=diagnostics").into_response(),
        Err(err) => Redirect::to(&format!("/?error={}", percent_encode(&err))).into_response(),
    }
}

// ---------------------------------------------------------------------------
// Templates (embedded; no external assets)
// ---------------------------------------------------------------------------

trait UsernameOr {
    /// The username or a fallback display value.
    fn username_or<'a>(&'a self, fallback: &'a str) -> &'a str;
}

impl UsernameOr for PolicySnapshot {
    fn username_or<'a>(&'a self, fallback: &'a str) -> &'a str {
        if self.username.trim().is_empty() {
            fallback
        } else {
            &self.username
        }
    }
}

const STYLE: &str = r#"
body { font-family: system-ui, sans-serif; margin: 0; color: #1b2733; background: #f6f8fa; }
header { background: #22364a; color: #fff; padding: 0.8rem 1.2rem; }
header img.logo { height: 1.5rem; vertical-align: middle; margin-right: 0.6rem; }
header a { color: #cfe0f2; margin-right: 1rem; text-decoration: none; }
main { max-width: 60rem; margin: 1rem auto; padding: 0 1rem; }
.policy { background: #e8eef5; border: 1px solid #c4d2e0; border-radius: 6px; padding: 0.6rem 1rem; font-size: 0.9rem; margin-bottom: 1rem; }
table.kv th { text-align: left; padding: 0.2rem 1rem 0.2rem 0; vertical-align: top; }
table.kv td { padding: 0.2rem 0; }
table.grid { border-collapse: collapse; width: 100%; background: #fff; }
table.grid th, table.grid td { border: 1px solid #d3dae2; padding: 0.3rem 0.5rem; text-align: left; font-size: 0.85rem; }
.stack label { display: block; margin: 0.5rem 0; }
.stack input, .stack select { display: block; margin-top: 0.2rem; padding: 0.3rem; width: 20rem; max-width: 100%; }
.inline select { padding: 0.3rem; }
button { padding: 0.4rem 0.9rem; margin-top: 0.4rem; }
.error { color: #a4262c; font-weight: 600; }
.notice { color: #107c10; }
form.diagnose { display: inline; }
"#;

/// The CE shield mark (88×94 PNG, `packaging/assets/lustless-mark.png` —
/// provenance in `packaging/assets/README.md`) as a `data:` URI, encoded
/// once per process. The dashboard stays asset-free over HTTP: the bytes
/// are compiled into the binary.
static LOGO_DATA_URI: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
    use base64::Engine as _;
    let png = include_bytes!("../../../packaging/assets/lustless-mark.png");
    format!(
        "data:image/png;base64,{}",
        base64::engine::general_purpose::STANDARD.encode(png)
    )
});

/// Renders one page: nav + the §9 policy strip + the page body. Every page
/// carries the current `PolicySnapshot` (§13).
fn layout(title: &str, snapshot: &PolicySnapshot, body: &str) -> String {
    format!(
        "<!DOCTYPE html><html><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
         <title>LustLess — {title}</title><style>{STYLE}</style></head>\
         <body><header><img class=\"logo\" src=\"{logo}\" alt=\"LustLess\">\
         <a href=\"/\">Status</a><a href=\"/sign-in\">Sign in</a>\
         <a href=\"/settings\">Settings</a><a href=\"/activity\">DNS activity</a>\
         <form method=\"post\" action=\"/sign-out\" class=\"diagnose\">\
         <button type=\"submit\">Sign out</button></form>\
         <form method=\"post\" action=\"/diagnostics\" class=\"diagnose\">\
         <button type=\"submit\">Collect diagnostics</button></form></header>\
         <main><div class=\"policy\">Account: <strong>{account}</strong> · \
         State: <strong>{state}</strong> · Filter: <strong>{level}</strong> \
         ({health}) · Capture: <strong>{capture}</strong>{fail_closed_note}</div>\
         {body}</main></body></html>",
        logo = LOGO_DATA_URI.as_str(),
        account = esc(snapshot.username_or("(signed out)")),
        state = esc(&format!("{:?}", snapshot.state)),
        level = esc(&snapshot.filter.level),
        health = esc(&snapshot.filter.health),
        capture = if snapshot.capture.active {
            "active"
        } else {
            "inactive"
        },
        fail_closed_note = if snapshot.filter.fail_closed {
            String::new()
        } else {
            " · <strong>fail-open override ACTIVE</strong>".to_string()
        },
        body = body,
    )
}

// ---------------------------------------------------------------------------
// Tests (CONTRACTS §16: local mock server on 127.0.0.1, no network beyond
// loopback)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_mocks::{temp_dir, MockControl, MockPolicy};
    use crate::uploader::lock_outbox;
    use lustless_core::db::DnsActivityRow;

    fn test_state(dir: &std::path::Path) -> (DashboardState, Arc<MockControl>, Arc<TokenStore>) {
        let outbox = Arc::new(Mutex::new(Outbox::open(&dir.join("outbox.db")).unwrap()));
        {
            let mut outbox = lock_outbox(&outbox);
            outbox
                .insert_dns_activity(&DnsActivityRow {
                    username: "alice".to_string(),
                    domain: "example.org".to_string(),
                    process_id: Some("42".to_string()),
                    process_name: "browser".to_string(),
                    datetime_created: "2026-10-11T10:00:00Z".to_string(),
                    ip: Some("192.0.2.1".to_string()),
                    resolution_type: "BlockedCustom".to_string(),
                    connection_type: Some("DoH".to_string()),
                    resolution_datacenter: None,
                    resolution_time_ms: Some("9".to_string()),
                })
                .unwrap();
        }
        let control = Arc::new(MockControl::default());
        let tokens = Arc::new(TokenStore::default());
        let state = DashboardState {
            policy: Arc::new(MockPolicy::with_username("alice")),
            control: control.clone(),
            outbox,
            tokens: tokens.clone(),
            clock: Arc::new(RwLock::new(ClockAnchor::system())),
        };
        (state, control, tokens)
    }

    async fn spawn_app(state: DashboardState) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, router(state)).await.unwrap();
        });
        format!("http://{addr}")
    }

    fn no_redirect_client() -> reqwest::Client {
        reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap()
    }

    #[tokio::test]
    async fn missing_and_bad_tokens_are_401() {
        let dir = temp_dir("dash-401");
        let (state, _control, tokens) = test_state(&dir);
        let base = spawn_app(state).await;
        let client = no_redirect_client();

        // No token at all.
        let response = client.get(format!("{base}/")).send().await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        // Unknown token via query and header.
        let response = client
            .get(format!("{base}/?t=deadbeef"))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let response = client
            .get(format!("{base}/"))
            .header("Authorization", "Bearer deadbeef")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        // Expired token (issued 601 s ago with the standard 600 s TTL).
        let expired = tokens.issue_with_ttl(1000, system_unix() - 601, 600);
        let response = client
            .get(format!("{base}/?t={expired}"))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        // Mutations require the token too.
        let response = client
            .post(format!("{base}/sign-out"))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn valid_token_grants_pages_via_query_and_header() {
        let dir = temp_dir("dash-ok");
        let (state, _control, tokens) = test_state(&dir);
        let base = spawn_app(state).await;
        let client = no_redirect_client();
        let token = tokens.issue(1000, system_unix());

        let response = client
            .get(format!("{base}/?t={token}"))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.text().await.unwrap();
        assert!(body.contains("alice"), "policy snapshot rendered");
        assert!(body.contains("Status"));

        let response = client
            .get(format!("{base}/settings"))
            .header("Authorization", format!("Bearer {token}"))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(response.text().await.unwrap().contains("Blocking level"));
    }

    #[tokio::test]
    async fn mutations_post_and_redirect_to_control() {
        let dir = temp_dir("dash-post");
        let (state, control, tokens) = test_state(&dir);
        let base = spawn_app(state).await;
        let client = no_redirect_client();
        let token = tokens.issue(1000, system_unix());

        let response = client
            .post(format!("{base}/sign-in?t={token}"))
            .form(&[("username", "alice"), ("password", "pw")])
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(
            response.headers().get("location").unwrap(),
            "/?notice=signed-in"
        );

        let response = client
            .post(format!("{base}/settings/level?t={token}"))
            .form(&[("level", "Strong Blocking")])
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);

        let response = client
            .post(format!("{base}/settings/override?t={token}"))
            .form(&[("domain", "example.org"), ("verdict", "block")])
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);

        let response = client
            .post(format!("{base}/diagnostics?t={token}"))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);

        let calls = control.calls();
        assert!(calls.iter().any(|call| call == "sign_in:alice"));
        assert!(calls
            .iter()
            .any(|call| call == "set_filter_level:Strong Blocking"));
        assert!(calls
            .iter()
            .any(|call| call == "set_override:example.org:block"));
        assert!(calls.iter().any(|call| call == "collect_debug"));
    }

    #[tokio::test]
    async fn sign_out_posts_and_redirects() {
        let dir = temp_dir("dash-signout");
        let (state, control, tokens) = test_state(&dir);
        let base = spawn_app(state).await;
        let client = no_redirect_client();
        let token = tokens.issue(1000, system_unix());
        let response = client
            .post(format!("{base}/sign-out?t={token}"))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert!(control.calls().iter().any(|call| call == "sign_out"));
    }

    #[tokio::test]
    async fn activity_page_renders_dns_rows() {
        let dir = temp_dir("dash-activity");
        let (state, _control, tokens) = test_state(&dir);
        let base = spawn_app(state).await;
        let client = no_redirect_client();
        let token = tokens.issue(1000, system_unix());
        let body = client
            .get(format!("{base}/activity?t={token}"))
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        assert!(body.contains("example.org"));
        assert!(body.contains("BlockedCustom"));
        assert!(body.contains("Your DNS activity on this computer"));
    }

    #[tokio::test]
    async fn no_keys_route_exists() {
        // §13: CE's credential-exposure route must not exist in any form.
        let dir = temp_dir("dash-nokeys");
        let (state, _control, tokens) = test_state(&dir);
        let base = spawn_app(state).await;
        let client = no_redirect_client();
        let token = tokens.issue(1000, system_unix());
        for path in [
            "/local/user/alice/keys.json",
            "/local/user/alice/keys.txt",
            "/keys",
            "/api_credentials",
        ] {
            let response = client
                .get(format!("{base}{path}?t={token}"))
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::NOT_FOUND, "path {path}");
        }
    }
}
