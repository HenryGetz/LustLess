//! Human- and machine-readable rendering of the §5 replies for `status`,
//! `policy`, and `dns-activity` (`--json` prints the reply as JSON with the
//! `ok` envelope stripped).

use serde_json::{json, Value};

use lustless_core::policy::PolicySnapshot;

/// Prints the machine form: the reply object without the `ok` envelope.
fn print_json(reply: &Value) {
    let mut stripped = reply.clone();
    if let Some(object) = stripped.as_object_mut() {
        object.remove("ok");
    }
    match serde_json::to_string_pretty(&stripped) {
        Ok(text) => println!("{text}"),
        Err(err) => eprintln!("lustlessctl: cannot render JSON: {err}"),
    }
}

/// `status` (0x61): version, uptime, filter health, policy state, dashboard URL.
pub fn render_status(reply: &Value, json: bool) {
    if json {
        print_json(reply);
        return;
    }
    let status = reply.get("status").cloned().unwrap_or(json!({}));
    let s = |key: &str| {
        status
            .get(key)
            .map(|v| match v {
                Value::String(text) => text.clone(),
                Value::Bool(flag) => flag.to_string(),
                Value::Number(number) => number.to_string(),
                other => other.to_string(),
            })
            .unwrap_or_else(|| "unknown".to_string())
    };
    println!("lustlessd {}", s("version"));
    println!(
        "  uptime:       {}",
        status
            .get("uptime_sec")
            .and_then(Value::as_u64)
            .map(|secs| format!("{secs}s"))
            .unwrap_or_else(|| "unknown".to_string())
    );
    let signed_in = status
        .get("signed_in")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let username = status
        .get("username")
        .and_then(Value::as_str)
        .filter(|u| !u.is_empty());
    println!(
        "  state:        {}{}",
        s("state"),
        match (signed_in, username) {
            (true, Some(name)) => format!(" (signed in as {name})"),
            (true, None) => " (signed in)".to_string(),
            (false, _) => String::new(),
        }
    );
    println!(
        "  filter:       {} — {} (fail-closed: {})",
        s("filter_level"),
        s("filter_health"),
        s("fail_closed")
    );
    println!(
        "  capture:      {} (backend {})",
        if status
            .get("capture_active")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            "active"
        } else {
            "inactive"
        },
        status
            .get("backend")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
    );
    println!("  analyzed:     {}", s("analyzed_count"));
    println!(
        "  dashboard:    {}",
        reply
            .get("dashboard_url")
            .and_then(Value::as_str)
            .filter(|url| !url.is_empty())
            .unwrap_or("(disabled)")
    );
}

/// `policy` (0x60): the §9 `PolicySnapshot` fields.
pub fn render_policy(reply: &Value, json: bool) {
    if json {
        print_json(reply);
        return;
    }
    let Some(policy) = reply.get("policy") else {
        println!("(daemon returned no policy snapshot)");
        return;
    };
    match serde_json::from_value::<PolicySnapshot>(policy.clone()) {
        Ok(snapshot) => {
            println!("username:               {}", snapshot.username);
            println!("signed_in:              {}", snapshot.signed_in);
            println!("state:                  {:?}", snapshot.state);
            println!("has_accountability:     {}", snapshot.has_accountability);
            println!("has_filtering:          {}", snapshot.has_filtering);
            println!(
                "has_screen_accountability: {}",
                snapshot.has_screen_accountability
            );
            println!(
                "has_url_accountability: {}",
                snapshot.has_url_accountability
            );
            println!("has_dns_filtering:      {}", snapshot.has_dns_filtering);
            println!("has_url_filtering:      {}", snapshot.has_url_filtering);
            println!("can_override:           {}", snapshot.can_override);
            println!("is_panicked:            {}", snapshot.is_panicked);
            println!("filter.level:           {}", snapshot.filter.level);
            println!("filter.fail_closed:     {}", snapshot.filter.fail_closed);
            println!("filter.health:          {}", snapshot.filter.health);
            println!("capture.active:         {}", snapshot.capture.active);
            println!("capture.backend:        {}", snapshot.capture.backend);
            println!(
                "capture.last_screenstate_at: {}",
                snapshot
                    .capture
                    .last_screenstate_at
                    .unwrap_or_else(|| "never".to_string())
            );
        }
        Err(err) => {
            // Fall back to the raw snapshot if the core type drifted.
            eprintln!("lustlessctl: policy snapshot does not match the core type ({err})");
            match serde_json::to_string_pretty(policy) {
                Ok(text) => println!("{text}"),
                Err(err) => eprintln!("lustlessctl: cannot render policy: {err}"),
            }
        }
    }
}

/// `dns-activity` (0x62): the CE `ViewDnsActivityHandler` read-back rows.
pub fn render_dns_activity(reply: &Value, json: bool) {
    if json {
        print_json(reply);
        return;
    }
    let rows = reply
        .get("rows")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let scope = reply.get("scope").and_then(Value::as_str).unwrap_or("self");
    if rows.is_empty() {
        println!("No DNS activity recorded (scope: {scope}).");
        return;
    }
    println!(
        "{:<20} {:<30} {:<24} {:<28} {:<8}",
        "created", "domain", "process", "verdict", "ms"
    );
    for row in &rows {
        let s = |key: &str| {
            row.get(key)
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string()
        };
        println!(
            "{:<20} {:<30} {:<24} {:<28} {:<8}",
            truncate(&s("datetime_created"), 19),
            truncate(&s("domain"), 30),
            truncate(&s("process_name"), 24),
            truncate(&s("resolution_type"), 28),
            s("resolution_time_ms")
        );
    }
    println!("{} row(s), scope: {scope}", rows.len());
}

fn truncate(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        text.to_string()
    } else {
        let cut: String = text.chars().take(max.saturating_sub(1)).collect();
        format!("{cut}…")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn status_reply() -> Value {
        json!({
            "ok": true,
            "status": {
                "version": "0.1.0",
                "username": "alice",
                "signed_in": true,
                "state": "LOGGED_IN",
                "capture_active": true,
                "backend": "x11",
                "filter_level": "Standard Blocking",
                "filter_health": "healthy",
                "fail_closed": true,
                "analyzed_count": 12
            },
            "dashboard_url": "http://127.0.0.1:8760/?t=abc"
        })
    }

    #[test]
    fn json_output_strips_the_ok_envelope() {
        let mut printed = Vec::new();
        print_json_to(&status_reply(), &mut printed);
        let text = String::from_utf8(printed).expect("utf8");
        assert!(!text.contains("\"ok\""));
        assert!(text.contains("\"status\""));
        assert!(text.contains("\"dashboard_url\""));
    }

    /// Same as [`print_json`] but to a buffer, for tests.
    fn print_json_to(reply: &Value, out: &mut Vec<u8>) {
        let mut stripped = reply.clone();
        if let Some(object) = stripped.as_object_mut() {
            object.remove("ok");
        }
        out.extend_from_slice(serde_json::to_string_pretty(&stripped).unwrap().as_bytes());
    }

    #[test]
    fn status_reply_renders_without_panicking_on_missing_fields() {
        // Render paths are exercised through the public functions; they must
        // tolerate sparse replies.
        render_status(&json!({"ok": true}), false);
        render_status(&status_reply(), false);
        render_policy(&json!({"ok": true}), false);
        render_dns_activity(&json!({"ok": true, "rows": []}), false);
        render_dns_activity(
            &json!({
                "ok": true,
                "scope": "self",
                "rows": [
                    {
                        "datetime_created": "2026-10-11T10:15:00Z",
                        "domain": "example.com",
                        "process_id": "4242",
                        "process_name": "firefox",
                        "ip": "93.184.216.34",
                        "resolution_type": "UnrestrictedFiltered",
                        "connection_type": "udp",
                        "resolution_datacenter": "dc1",
                        "resolution_time_ms": "42"
                    }
                ]
            }),
            false,
        );
    }

    #[test]
    fn policy_snapshot_from_the_core_type_renders() {
        let snapshot = PolicySnapshot {
            username: "alice".into(),
            signed_in: true,
            state: lustless_core::policy::UserState::LoggedIn,
            has_accountability: true,
            has_filtering: true,
            has_screen_accountability: false,
            has_url_accountability: false,
            has_dns_filtering: true,
            has_url_filtering: false,
            can_override: true,
            is_panicked: false,
            filter: lustless_core::policy::FilterPolicy {
                level: "Standard Blocking".into(),
                fail_closed: true,
                health: "healthy".into(),
            },
            capture: lustless_core::policy::CapturePolicy {
                active: true,
                backend: "x11".into(),
                last_screenstate_at: Some("2026-10-11T10:15:00Z".into()),
            },
        };
        let reply = json!({"ok": true, "policy": snapshot});
        render_policy(&reply, false);
        render_policy(&reply, true);
    }
}
