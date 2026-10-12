//! Hand-rolled argument parser for `lustlessctl` (CONTRACTS §5) — the
//! subcommand surface is small and closed, so a full clap dependency would be
//! dead weight. Every subcommand maps onto its §5 wire code in
//! [`Command::wire_request`], which the unit tests pin as a table.

use lustless_core::wire::Code;

/// `flush` default deadline — the exact `prerm` contract of CONTRACTS §11:
/// `timeout 10 /usr/bin/lustlessctl flush` (§5 0x69 default deadline 10).
pub const DEFAULT_FLUSH_DEADLINE_SECS: u64 = 10;

/// Upper bound mirrored from the daemon's own clamp on `deadline_sec` (§5).
pub const MAX_FLUSH_DEADLINE_SECS: u64 = 300;

/// Default `dns-activity --limit` (the dashboard read-back default of §8).
pub const DEFAULT_DNS_ACTIVITY_LIMIT: u32 = 50;

/// One parsed invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// `status [--json]` — IPC 0x61.
    Status {
        /// Machine-readable output.
        json: bool,
    },
    /// `policy [--json]` — IPC 0x60.
    Policy {
        /// Machine-readable output.
        json: bool,
    },
    /// `dns-activity [--limit N] [--json]` — IPC 0x62.
    DnsActivity {
        /// Row limit (`--limit`, default [`DEFAULT_DNS_ACTIVITY_LIMIT`]).
        limit: u32,
        /// Machine-readable output.
        json: bool,
    },
    /// `set-filter-level <level>` — IPC 0x63 (CE's blocking-level vocabulary).
    SetFilterLevel {
        /// One of the three CE levels the daemon accepts (§9 `filter.level`).
        level: String,
    },
    /// `set-override <domain> allow|block|na` — IPC 0x64.
    SetOverride {
        /// Domain the override applies to.
        domain: String,
        /// Tri-state verdict: `allow` | `block` | `na` (§6.2 vocabulary).
        verdict: String,
    },
    /// `signin <username>` — IPC 0x65; password is read from the terminal
    /// without echo (never an argument, never logged).
    SignIn {
        /// CE account username.
        username: String,
    },
    /// `signout` — IPC 0x66.
    SignOut,
    /// `collect-debug` — IPC 0x43.
    CollectDebug,
    /// `update-check` — IPC 0x67.
    UpdateCheck,
    /// `flush [--deadline SECS]` — IPC 0x69, root only (§5/§11 prerm).
    Flush {
        /// Drain deadline in seconds (default [`DEFAULT_FLUSH_DEADLINE_SECS`],
        /// clamped to 1..=[`MAX_FLUSH_DEADLINE_SECS`] like the daemon does).
        deadline: u64,
    },
    /// `break-glass <reason>` — re-executes itself through `pkexec` as
    /// `break-glass-internal` (polkit `org.lustless.break-glass` gate, §5 0x68).
    BreakGlass {
        /// Human-readable reason recorded in the daemon's journald audit line.
        reason: String,
    },
    /// `break-glass-internal <reason>` — hidden; runs as root under pkexec and
    /// sends IPC 0x68.
    BreakGlassInternal {
        /// Human-readable reason (verbatim from the caller).
        reason: String,
    },
    /// `config show` — prints the loaded §9.1 config and its source path.
    ConfigShow,
    /// `--help` / `-h` / `help`.
    Help,
    /// `--version` / `-V`.
    Version,
}

/// Parse failure: message plus whether the usage banner should accompany it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    /// Human-readable problem description.
    pub message: String,
    /// Whether to print [`USAGE`] (true for syntax errors, false for e.g.
    /// `--help` requests that never reach the parser).
    pub usage: bool,
}

impl ParseError {
    fn new(message: impl Into<String>) -> Self {
        ParseError {
            message: message.into(),
            usage: true,
        }
    }
}

/// Full usage banner (also used for `--help`).
pub const USAGE: &str = "\
lustlessctl — LustLess admin/diagnostics CLI (CONTRACTS §5)

USAGE:
    lustlessctl status [--json]
    lustlessctl policy [--json]
    lustlessctl dns-activity [--limit N] [--json]
    lustlessctl set-filter-level <level>
    lustlessctl set-override <domain> allow|block|na
    lustlessctl signin <username>
    lustlessctl signout
    lustlessctl collect-debug
    lustlessctl update-check
    lustlessctl flush [--deadline SECS]        (default 10 — the prerm contract)
    lustlessctl break-glass <reason>           (asks polkit, then runs as root)
    lustlessctl config show
    lustlessctl --help | --version

EXIT CODES:
    0  success (flush also exits 0 on a partial drain)
    1  error (bad arguments, or a {\"ok\":false} daemon reply)
    2  daemon unreachable (cannot connect to the IPC socket)";

impl Command {
    /// Parses `args` (argv without the program name).
    pub fn parse(args: &[String]) -> Result<Command, ParseError> {
        let Some((first, rest)) = args.split_first() else {
            return Err(ParseError::new("missing subcommand"));
        };
        match first.as_str() {
            "help" | "--help" | "-h" => Ok(Command::Help),
            "--version" | "-V" => Ok(Command::Version),
            "status" => Ok(Command::Status {
                json: take_json_flag(rest)?,
            }),
            "policy" => Ok(Command::Policy {
                json: take_json_flag(rest)?,
            }),
            "dns-activity" => {
                let mut json = false;
                let mut limit = DEFAULT_DNS_ACTIVITY_LIMIT;
                let mut iter = rest.iter();
                while let Some(arg) = iter.next() {
                    match arg.as_str() {
                        "--json" => json = true,
                        "--limit" => {
                            let value = iter
                                .next()
                                .ok_or_else(|| ParseError::new("--limit needs a value"))?;
                            limit = value.parse::<u32>().map_err(|_| {
                                ParseError::new(format!("invalid --limit value: {value}"))
                            })?;
                            if limit == 0 {
                                return Err(ParseError::new("--limit must be at least 1"));
                            }
                        }
                        other => {
                            return Err(ParseError::new(format!("unexpected argument: {other}")))
                        }
                    }
                }
                Ok(Command::DnsActivity { limit, json })
            }
            "set-filter-level" => {
                let level = one_positional(rest, "set-filter-level <level>")?;
                Ok(Command::SetFilterLevel { level })
            }
            "set-override" => {
                let mut iter = rest.iter();
                let domain = iter
                    .next()
                    .ok_or_else(|| ParseError::new("set-override needs a domain"))?;
                let verdict = iter
                    .next()
                    .ok_or_else(|| ParseError::new("set-override needs a verdict"))?;
                if iter.next().is_some() {
                    return Err(ParseError::new("set-override takes exactly two arguments"));
                }
                if !matches!(verdict.as_str(), "allow" | "block" | "na") {
                    return Err(ParseError::new(format!(
                        "invalid verdict `{verdict}` — expected allow, block, or na"
                    )));
                }
                Ok(Command::SetOverride {
                    domain: domain.clone(),
                    verdict: verdict.clone(),
                })
            }
            "signin" => Ok(Command::SignIn {
                username: one_positional(rest, "signin <username>")?,
            }),
            "signout" => {
                expect_no_args(rest, "signout")?;
                Ok(Command::SignOut)
            }
            "collect-debug" => {
                expect_no_args(rest, "collect-debug")?;
                Ok(Command::CollectDebug)
            }
            "update-check" => {
                expect_no_args(rest, "update-check")?;
                Ok(Command::UpdateCheck)
            }
            "flush" => {
                let mut deadline = DEFAULT_FLUSH_DEADLINE_SECS;
                let mut iter = rest.iter();
                while let Some(arg) = iter.next() {
                    match arg.as_str() {
                        "--deadline" => {
                            let value = iter
                                .next()
                                .ok_or_else(|| ParseError::new("--deadline needs a value"))?;
                            deadline = value.parse::<u64>().map_err(|_| {
                                ParseError::new(format!("invalid --deadline value: {value}"))
                            })?;
                            if !(1..=MAX_FLUSH_DEADLINE_SECS).contains(&deadline) {
                                return Err(ParseError::new(format!(
                                    "--deadline must be within 1..={MAX_FLUSH_DEADLINE_SECS}"
                                )));
                            }
                        }
                        other => {
                            return Err(ParseError::new(format!("unexpected argument: {other}")))
                        }
                    }
                }
                Ok(Command::Flush { deadline })
            }
            "break-glass" => Ok(Command::BreakGlass {
                reason: one_positional(rest, "break-glass <reason>")?,
            }),
            "break-glass-internal" => Ok(Command::BreakGlassInternal {
                reason: one_positional(rest, "break-glass-internal <reason>")?,
            }),
            "config" => match rest {
                [show] if show == "show" => Ok(Command::ConfigShow),
                [other, ..] => Err(ParseError::new(format!(
                    "unknown config subcommand `{other}` — expected `config show`"
                ))),
                [] => Err(ParseError::new("expected `config show`")),
            },
            other => Err(ParseError::new(format!("unknown subcommand `{other}`"))),
        }
    }

    /// The §5 wire request this command performs, or `None` for commands that
    /// are not plain request/reply (help, version, config show, the pkexec
    /// `break-glass` front, and `signin`, whose payload carries a
    /// terminal-read password).
    pub fn wire_request(&self) -> Option<(Code, serde_json::Value)> {
        use serde_json::json;
        match self {
            Command::Status { .. } => Some((Code::StatusGet, json!({}))),
            Command::Policy { .. } => Some((Code::PolicyGet, json!({}))),
            Command::DnsActivity { limit, .. } => {
                Some((Code::DnsActivityQuery, json!({ "limit": limit })))
            }
            Command::SetFilterLevel { level } => {
                Some((Code::FilterSetLevel, json!({ "level": level })))
            }
            Command::SetOverride { domain, verdict } => Some((
                Code::FilterSetOverrides,
                json!({ "domain": domain, "verdict": verdict }),
            )),
            Command::SignOut => Some((Code::SignOut, json!({}))),
            Command::CollectDebug => Some((Code::CollectDebugLogs, json!({}))),
            Command::UpdateCheck => Some((Code::UpdateCheck, json!({}))),
            Command::Flush { deadline } => {
                Some((Code::FlushOutbox, json!({ "deadline_sec": deadline })))
            }
            Command::BreakGlassInternal { reason } => {
                Some((Code::BreakGlass, json!({ "reason": reason })))
            }
            Command::SignIn { .. }
            | Command::BreakGlass { .. }
            | Command::ConfigShow
            | Command::Help
            | Command::Version => None,
        }
    }
}

fn one_positional(rest: &[String], shape: &str) -> Result<String, ParseError> {
    match rest {
        [only] => Ok(only.clone()),
        [] => Err(ParseError::new(format!(
            "missing argument — expected {shape}"
        ))),
        _ => Err(ParseError::new(format!(
            "too many arguments — expected {shape}"
        ))),
    }
}

fn expect_no_args(rest: &[String], name: &str) -> Result<(), ParseError> {
    match rest {
        [] => Ok(()),
        [other, ..] => Err(ParseError::new(format!(
            "{name} takes no arguments (got `{other}`)"
        ))),
    }
}

fn take_json_flag(rest: &[String]) -> Result<bool, ParseError> {
    match rest {
        [] => Ok(false),
        [flag] if flag == "--json" => Ok(true),
        [other, ..] => Err(ParseError::new(format!("unexpected argument: {other}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Result<Command, ParseError> {
        Command::parse(&args.iter().map(|s| s.to_string()).collect::<Vec<_>>())
    }

    #[test]
    fn subcommand_table_parses_every_documented_invocation() {
        let cases: &[(&[&str], Command)] = &[
            (&["status"], Command::Status { json: false }),
            (&["status", "--json"], Command::Status { json: true }),
            (&["policy"], Command::Policy { json: false }),
            (&["policy", "--json"], Command::Policy { json: true }),
            (
                &["dns-activity"],
                Command::DnsActivity {
                    limit: DEFAULT_DNS_ACTIVITY_LIMIT,
                    json: false,
                },
            ),
            (
                &["dns-activity", "--limit", "25"],
                Command::DnsActivity {
                    limit: 25,
                    json: false,
                },
            ),
            (
                &["dns-activity", "--limit", "5", "--json"],
                Command::DnsActivity {
                    limit: 5,
                    json: true,
                },
            ),
            (
                &["set-filter-level", "Strong Blocking"],
                Command::SetFilterLevel {
                    level: "Strong Blocking".to_string(),
                },
            ),
            (
                &["set-override", "example.com", "block"],
                Command::SetOverride {
                    domain: "example.com".to_string(),
                    verdict: "block".to_string(),
                },
            ),
            (
                &["set-override", "example.org", "allow"],
                Command::SetOverride {
                    domain: "example.org".to_string(),
                    verdict: "allow".to_string(),
                },
            ),
            (
                &["set-override", "example.net", "na"],
                Command::SetOverride {
                    domain: "example.net".to_string(),
                    verdict: "na".to_string(),
                },
            ),
            (
                &["signin", "alice"],
                Command::SignIn {
                    username: "alice".to_string(),
                },
            ),
            (&["signout"], Command::SignOut),
            (&["collect-debug"], Command::CollectDebug),
            (&["update-check"], Command::UpdateCheck),
            (
                &["break-glass", "maintenance window"],
                Command::BreakGlass {
                    reason: "maintenance window".to_string(),
                },
            ),
            (
                &["break-glass-internal", "maintenance window"],
                Command::BreakGlassInternal {
                    reason: "maintenance window".to_string(),
                },
            ),
            (&["config", "show"], Command::ConfigShow),
            (&["--help"], Command::Help),
            (&["-h"], Command::Help),
            (&["help"], Command::Help),
            (&["--version"], Command::Version),
        ];
        for (args, expected) in cases {
            assert_eq!(
                &parse(args).unwrap_or_else(|_| panic!("{}", args.join(" "))),
                expected,
                "{args:?}"
            );
        }
    }

    #[test]
    fn flush_defaults_to_the_prerm_deadline_of_10() {
        assert_eq!(
            parse(&["flush"]).expect("flush"),
            Command::Flush { deadline: 10 },
            "the §11 prerm contract is `timeout 10 lustlessctl flush`"
        );
        assert_eq!(
            Command::Flush {
                deadline: DEFAULT_FLUSH_DEADLINE_SECS
            }
            .wire_request(),
            Some((Code::FlushOutbox, serde_json::json!({"deadline_sec": 10})))
        );
    }

    #[test]
    fn flush_honours_and_validates_the_deadline_flag() {
        assert_eq!(
            parse(&["flush", "--deadline", "42"]).expect("flush"),
            Command::Flush { deadline: 42 }
        );
        assert!(parse(&["flush", "--deadline", "0"]).is_err());
        assert!(parse(&["flush", "--deadline", "301"]).is_err());
        assert!(parse(&["flush", "--deadline"]).is_err());
        assert!(parse(&["flush", "now"]).is_err());
    }

    #[test]
    fn invalid_invocations_error() {
        assert!(parse(&[]).is_err());
        assert!(parse(&["bogus"]).is_err());
        assert!(parse(&["status", "--yaml"]).is_err());
        assert!(parse(&["policy", "extra"]).is_err());
        assert!(parse(&["dns-activity", "--limit", "0"]).is_err());
        assert!(parse(&["dns-activity", "--limit", "x"]).is_err());
        assert!(parse(&["set-filter-level"]).is_err());
        assert!(parse(&["set-override", "example.com"]).is_err());
        assert!(parse(&["set-override", "example.com", "maybe"]).is_err());
        assert!(parse(&["signin"]).is_err());
        assert!(parse(&["signin", "alice", "extra"]).is_err());
        assert!(parse(&["signout", "--json"]).is_err());
        assert!(parse(&["config"]).is_err());
        assert!(parse(&["config", "edit"]).is_err());
    }

    #[test]
    fn wire_request_table_matches_the_contract_section_5_codes() {
        let table: &[(&[&str], Code)] = &[
            (&["status"], Code::StatusGet),
            (&["policy"], Code::PolicyGet),
            (&["dns-activity"], Code::DnsActivityQuery),
            (
                &["set-filter-level", "Standard Blocking"],
                Code::FilterSetLevel,
            ),
            (
                &["set-override", "a.example", "block"],
                Code::FilterSetOverrides,
            ),
            (&["signout"], Code::SignOut),
            (&["collect-debug"], Code::CollectDebugLogs),
            (&["update-check"], Code::UpdateCheck),
            (&["flush"], Code::FlushOutbox),
            (&["break-glass-internal", "why"], Code::BreakGlass),
        ];
        for (args, code) in table {
            let command = parse(args).unwrap_or_else(|_| panic!("{}", args.join(" ")));
            let (actual, _) = command
                .wire_request()
                .unwrap_or_else(|| panic!("{args:?} has no plain wire request"));
            assert_eq!(actual, *code, "{args:?}");
        }
        // Connection-scope codes of §5 stay client-side assembled.
        assert!(parse(&["signin", "alice"])
            .unwrap()
            .wire_request()
            .is_none());
        assert!(parse(&["break-glass", "why"])
            .unwrap()
            .wire_request()
            .is_none());
        assert!(parse(&["config", "show"]).unwrap().wire_request().is_none());
    }

    #[test]
    fn wire_payloads_carry_the_contract_fields() {
        use serde_json::json;
        assert_eq!(
            parse(&["dns-activity", "--limit", "9"])
                .unwrap()
                .wire_request(),
            Some((Code::DnsActivityQuery, json!({"limit": 9})))
        );
        assert_eq!(
            parse(&["set-filter-level", "Blocking Enabled"])
                .unwrap()
                .wire_request(),
            Some((Code::FilterSetLevel, json!({"level": "Blocking Enabled"})))
        );
        assert_eq!(
            parse(&["set-override", "news.example", "allow"])
                .unwrap()
                .wire_request(),
            Some((
                Code::FilterSetOverrides,
                json!({"domain": "news.example", "verdict": "allow"})
            ))
        );
        assert_eq!(
            parse(&["break-glass-internal", "dns outage"])
                .unwrap()
                .wire_request(),
            Some((Code::BreakGlass, json!({"reason": "dns outage"})))
        );
    }
}
