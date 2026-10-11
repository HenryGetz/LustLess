//! `lustlessctl` — LustLess admin/diagnostics CLI (CONTRACTS §5).
//!
//! One Unix-stream request per invocation against `/run/lustless/lustlessd.sock`
//! (path from the §9.1 config, `LUSTLESS_CONFIG` override for tests). Exit
//! codes: 0 ok / 1 error / 2 daemon-unreachable; `flush` exits 0 on a partial
//! drain (§5/§11 prerm contract).

mod args;
mod ipc;
mod render;

use std::io::{IsTerminal, Write};
use std::os::fd::{AsRawFd, BorrowedFd};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use serde_json::json;

use lustless_core::config::LustlessConfig;
use lustless_core::wire::Code;

use args::{Command, USAGE};
use ipc::IpcError;

/// Installed path of this binary — `break-glass` re-executes it through
/// `pkexec` by absolute path (§5 0x68 polkit split).
const INSTALLED_CTL_PATH: &str = "/usr/bin/lustlessctl";

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    match Command::parse(&argv) {
        Ok(Command::Help) => {
            println!("{USAGE}");
            ExitCode::SUCCESS
        }
        Ok(Command::Version) => {
            println!("lustlessctl {}", lustless_core::LUSTLESS_VERSION);
            ExitCode::SUCCESS
        }
        Ok(command) => match run(&command) {
            Ok(()) => ExitCode::SUCCESS,
            Err(AppError::Unreachable(message)) => {
                eprintln!("lustlessctl: {message}");
                ExitCode::from(2)
            }
            Err(AppError::Failed(message)) => {
                eprintln!("lustlessctl: {message}");
                ExitCode::FAILURE
            }
        },
        Err(err) => {
            eprintln!("lustlessctl: {}\n", err.message);
            if err.usage {
                eprintln!("{USAGE}");
            }
            ExitCode::FAILURE
        }
    }
}

/// Top-level command failure, mapped onto the exit-code contract.
enum AppError {
    /// Exit code 2 — the daemon could not be reached over its socket.
    Unreachable(String),
    /// Exit code 1 — arguments fine, but the operation failed.
    Failed(String),
}

impl From<IpcError> for AppError {
    fn from(err: IpcError) -> Self {
        match err {
            IpcError::Unreachable(message) => AppError::Unreachable(message),
            other => AppError::Failed(other.to_string()),
        }
    }
}

fn config_path() -> PathBuf {
    std::env::var_os("LUSTLESS_CONFIG")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/etc/lustless/lustless.toml"))
}

fn socket_path() -> PathBuf {
    PathBuf::from(LustlessConfig::load(&config_path()).daemon.socket_path)
}

fn run(command: &Command) -> Result<(), AppError> {
    match command {
        Command::Status { json } => {
            let reply = send_plain(command)?;
            render::render_status(&reply, *json);
            Ok(())
        }
        Command::Policy { json } => {
            let reply = send_plain(command)?;
            render::render_policy(&reply, *json);
            Ok(())
        }
        Command::DnsActivity { json, .. } => {
            let reply = send_plain(command)?;
            render::render_dns_activity(&reply, *json);
            Ok(())
        }
        Command::SetFilterLevel { level } => {
            let reply = send_plain(command)?;
            println!(
                "Filter level set to {}.",
                reply
                    .get("level")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or(level)
            );
            Ok(())
        }
        Command::SetOverride { domain, verdict } => {
            send_plain(command)?;
            match verdict.as_str() {
                "na" => println!("Override cleared for {domain}."),
                other => println!("Override set: {domain} → {other}."),
            }
            Ok(())
        }
        Command::SignIn { username } => {
            // The password never appears in argv or a log (§5 0x65).
            let password = read_password()?;
            let reply = ipc::request(
                &socket_path(),
                Code::SignIn,
                json!({ "username": username, "password": password }),
            )?;
            println!("Signed in as {username} (session token held by lustlessd).");
            if let Some(url) = reply.get("dashboard_url").and_then(serde_json::Value::as_str) {
                if !url.is_empty() {
                    println!("Dashboard: {url}");
                }
            }
            Ok(())
        }
        Command::SignOut => {
            send_plain(command)?;
            println!("Signed out — web access is blocked until sign-in (fail-closed).");
            Ok(())
        }
        Command::CollectDebug => {
            let (code, payload) = plain_request(command)?;
            let (reply, notifications) = ipc::request_collect(
                &socket_path(),
                code,
                payload,
                ipc::DEFAULT_READ_TIMEOUT,
            )?;
            for payload in &notifications {
                print_notification(payload);
            }
            if reply
                .get("started")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false)
            {
                println!("Diagnostics collection started; progress will follow in the agent.");
            } else {
                println!("Diagnostics collection requested.");
            }
            Ok(())
        }
        Command::UpdateCheck => {
            let reply = send_plain(command)?;
            match reply.get("recommendation") {
                Some(recommendation) => {
                    let label = recommendation
                        .get("recommendation")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("none");
                    let version = recommendation
                        .get("version")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("?");
                    let critical = recommendation
                        .get("critical")
                        .and_then(serde_json::Value::as_bool)
                        .unwrap_or(false);
                    match label {
                        "now" => println!(
                            "Update recommended now: version {version} (critical: {critical})."
                        ),
                        "later" => println!("Update available: version {version}; apply at your convenience."),
                        _ => println!("No update recommended."),
                    }
                }
                None => println!("No update recommendation available."),
            }
            Ok(())
        }
        Command::Flush { deadline } => {
            // The §11 prerm contract: bounded by the daemon-side deadline;
            // the read budget is deadline + slack so a slow-but-working drain
            // still returns "ok" (partial flushes are ok, §5).
            let (code, payload) = plain_request(command)?;
            let read_timeout = Duration::from_secs(deadline.saturating_add(15));
            let (reply, _) = ipc::request_collect(&socket_path(), code, payload, read_timeout)?;
            let flushed = reply
                .get("flushed")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0);
            println!("Flushed {flushed} queued record(s) within {deadline}s (partial is ok).");
            Ok(())
        }
        Command::BreakGlass { reason } => run_break_glass(reason),
        Command::BreakGlassInternal { reason } => {
            send_plain(command)?;
            println!(
                "Break-glass applied for `{reason}` — filtering is temporarily fail-open on this host."
            );
            Ok(())
        }
        Command::ConfigShow => {
            show_config();
            Ok(())
        }
        Command::Help | Command::Version => Ok(()),
    }
}

/// The §5 frame for a plain request/reply command (`args::Command::wire_request`,
/// pinned by the parser's mapping-table test).
fn plain_request(command: &Command) -> Result<(Code, serde_json::Value), AppError> {
    command
        .wire_request()
        .ok_or_else(|| AppError::Failed(format!("internal: {command:?} has no plain wire request")))
}

fn send_plain(command: &Command) -> Result<serde_json::Value, AppError> {
    let (code, payload) = plain_request(command)?;
    Ok(ipc::request(&socket_path(), code, payload)?)
}

/// §5 0x68 front door: polkit auth happens here (pkexec), the root-only wire
/// code is sent by the `break-glass-internal` re-execution.
fn run_break_glass(reason: &str) -> Result<(), AppError> {
    let status = std::process::Command::new("pkexec")
        .arg(INSTALLED_CTL_PATH)
        .arg("break-glass-internal")
        .arg(reason)
        .status()
        .map_err(|err| {
            AppError::Failed(format!("cannot launch pkexec ({err}) — is policykit-1 installed?"))
        })?;
    if status.success() {
        Ok(())
    } else {
        Err(AppError::Failed(format!(
            "break-glass cancelled or failed (pkexec exit status {status})"
        )))
    }
}

/// `config show`: loads the §9.1 config and prints source path, warnings, and
/// the effective configuration.
fn show_config() {
    let path = config_path();
    println!("config source: {}", path.display());
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            println!("(file missing — using the documented defaults, CONTRACTS §9.1)");
            println!();
            print_effective(&LustlessConfig::default(), &[]);
            return;
        }
        Err(err) => {
            println!("(unreadable: {err} — using defaults)");
            print_effective(&LustlessConfig::default(), &[]);
            return;
        }
    };
    let (config, warnings) = LustlessConfig::parse_document(&text);
    print_effective(&config, &warnings);
}

fn print_effective(config: &LustlessConfig, warnings: &[String]) {
    for warning in warnings {
        println!("warning: {warning}");
    }
    match toml::to_string_pretty(config) {
        Ok(text) => print!("{text}"),
        Err(err) => println!("(cannot serialize config: {err})"),
    }
}

fn print_notification(payload: &serde_json::Value) {
    let level = payload
        .get("level")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("info");
    let message = payload
        .get("message")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    if !message.is_empty() {
        eprintln!("[{level}] {message}");
    }
}

/// Reads the sign-in password from stdin without echo when stdin is a
/// terminal (§5 0x65 — the password is never an argument and never logged);
/// a piped stdin is read verbatim.
fn read_password() -> Result<String, AppError> {
    let stdin = std::io::stdin();
    use std::io::BufRead;
    eprint!("Password: ");
    let _ = std::io::stderr().flush();
    let mut password = String::new();
    if stdin.is_terminal() {
        // The guard restores the termios state on drop, including on error.
        let _guard = EchoOff::disable()
            .map_err(|err| AppError::Failed(format!("cannot disable terminal echo ({err})")))?;
        stdin
            .lock()
            .read_line(&mut password)
            .map_err(|err| AppError::Failed(format!("password read failed: {err}")))?;
    } else {
        stdin
            .lock()
            .read_line(&mut password)
            .map_err(|err| AppError::Failed(format!("password read failed: {err}")))?;
    }
    let trimmed = password.trim_end_matches(['\n', '\r']).to_string();
    if trimmed.is_empty() {
        return Err(AppError::Failed("empty password".to_string()));
    }
    Ok(trimmed)
}

/// Disables `ECHO` on the controlling terminal for the guarded lifetime
/// (restored on drop).
struct EchoOff {
    fd: BorrowedFd<'static>,
    original: nix::sys::termios::Termios,
}

impl EchoOff {
    fn disable() -> Result<Self, nix::errno::Errno> {
        use nix::sys::termios::{tcgetattr, tcsetattr, LocalFlags, SetArg};
        // stdin lives for the whole process; borrowing its raw fd does not
        // take ownership (no double-close on drop).
        let fd = unsafe { BorrowedFd::borrow_raw(std::io::stdin().as_raw_fd()) };
        let original = tcgetattr(fd)?;
        let mut quiet = tcgetattr(fd)?;
        quiet.local_flags &= !LocalFlags::ECHO;
        tcsetattr(fd, SetArg::TCSANOW, &quiet)?;
        Ok(EchoOff { fd, original })
    }
}

impl Drop for EchoOff {
    fn drop(&mut self) {
        use nix::sys::termios::{tcsetattr, SetArg};
        let _ = tcsetattr(self.fd, SetArg::TCSANOW, &self.original);
    }
}
