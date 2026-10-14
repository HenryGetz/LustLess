//! Outbox DB (`/var/lib/lustless/outbox.db`) — CONTRACTS §6.1.
//!
//! The `ce-file` schema is reproduced **verbatim** from
//! `re/findings/02-artifacts/local-db.md` §Evidence ("Full schema (verbatim)":
//! six tables + two indexes; `sqlite_sequence` is omitted because SQLite
//! creates it itself for `AUTOINCREMENT` tables). Plus the LustLess `telemetry`
//! table of §6.1. Plain SQLite (no key), WAL journal mode, mode 0600,
//! daemon-owned (§4/§6.1).
//!
//! Row lifecycle (§6.1, evidence `upload-protocol.md` §4):
//! `insert (queued) → claim (sending) → mark_sent (sent)`; stale `sending`
//! claims (older than five minutes) are reaped back to `queued`; a min-age
//! gate keeps rows newer than one upload cycle out of a claim; invalid records
//! are dropped, never failing a batch. Timestamps: ISO-8601 UTC event columns
//! supplied by the caller plus SQLite `DATETIME('now')` (UTC) for the
//! `(status, status_changed_at, created_at)` triple; tables that carry one
//! store the separate `timezone_offset` string (§6.1).

use std::path::Path;

use rusqlite::{params, params_from_iter, Connection, OptionalExtension};
use serde_json::{Map, Value};

use crate::CoreError;

/// Batch size of one upload request — §10: batch **100** rows/request
/// (`upload-protocol.md` §4: batch size constant 100).
pub const DEFAULT_BATCH_LIMIT: u32 = 100;

/// Min-age gate in seconds (§6.1): rows younger than one upload cycle are not
/// claimable (`upload-protocol.md` §4: `created_at <= DATETIME('now', '-' || ?
/// || ' seconds')`).
pub const DEFAULT_MIN_AGE_SECS: i64 = 30;

/// Stale-claim threshold in seconds (§6.1): a `sending` row claimed more than
/// five minutes ago is reaped back to `queued`.
pub const STALE_SENDING_SECS: i64 = 300;

/// Dashboard read-back limit (§8: the `ViewDnsActivityHandler` query,
/// `LIMIT 500 DESC`).
pub const DASHBOARD_READ_LIMIT: u32 = 500;

/// The `ce-file` schema, verbatim from `local-db.md` §Evidence (order kept;
/// executed only for tables that do not exist yet).
const CE_SCHEMA: &[(&str, &str)] = &[
    (
        "install_metadata",
        "CREATE TABLE install_metadata (key TEXT  COLLATE NOCASE,value TEXT,PRIMARY KEY(key));",
    ),
    (
        "logins",
        "CREATE TABLE logins (id INTEGER PRIMARY KEY AUTOINCREMENT,username TEXT KEY COLLATE NOCASE,system_user_id TEXT KEY,system_user_name TEXT,timestamp TEXT,login_at TEXT,logout_at TEXT,status TEXT KEY,status_changed_at TEXT,created_at TEXT);",
    ),
    (
        "metrics",
        "CREATE TABLE metrics (id INTEGER PRIMARY KEY AUTOINCREMENT,username TEXT COLLATE NOCASE,metric_name TEXT KEY,bucket_id TEXT KEY COLLATE NOCASE,tags TEXT,fields TEXT,utc_timestamp TEXT KEY,bucket_size INTEGER,bucket_current INTEGER,status TEXT,status_changed_at TEXT,created_at TEXT);",
    ),
    (
        "circumventions",
        "CREATE TABLE circumventions (id INTEGER PRIMARY KEY AUTOINCREMENT,username TEXT COLLATE NOCASE,interruption_type TEXT,app_name TEXT,app_window_title TEXT,device_id TEXT,timestamp TEXT KEY,timezone_offset TEXT,status TEXT,status_changed_at TEXT,created_at TEXT);",
    ),
    (
        "switch_users",
        "CREATE TABLE switch_users (id INTEGER PRIMARY KEY AUTOINCREMENT,username TEXT KEY COLLATE NOCASE,switch_user_from TEXT,switch_user_to TEXT,timestamp TEXT,timezone_offset TEXT,device_name TEXT,device_id TEXT,status TEXT,status_changed_at TEXT,created_at TEXT);",
    ),
    (
        "dns_activity",
        "CREATE TABLE dns_activity (id INTEGER PRIMARY KEY AUTOINCREMENT,username TEXT COLLATE NOCASE,domain TEXT,process_id TEXT,process_name TEXT KEY,datetime_created TEXT KEY,ip TEXT,resolution_type TEXT,connection_type TEXT,resolution_datacenter TEXT,resolution_time_ms TEXT,status TEXT,status_changed_at TEXT,created_at TEXT);",
    ),
];

/// The two partial indexes of `local-db.md` §Evidence, verbatim.
const CE_INDEXES: &[(&str, &str)] = &[
    (
        "circumventions_matching",
        "CREATE INDEX circumventions_matching ON circumventions (username, status, interruption_type);",
    ),
    (
        "dns_activity_matching",
        "CREATE INDEX dns_activity_matching ON dns_activity (username, status, process_name, datetime_created);",
    ),
];

/// The LustLess `telemetry` table of §6.1 (documented deviation: CE's
/// `telemetry` columns were unrecovered; this is the LustLess shape).
const TELEMETRY_SCHEMA: &str = "CREATE TABLE IF NOT EXISTS telemetry (id INTEGER PRIMARY KEY AUTOINCREMENT, client_type TEXT, device_name TEXT, name TEXT, value TEXT, utc_timestamp TEXT, status TEXT, status_changed_at TEXT, created_at TEXT);";

/// The event tables of the outbox that live through the §6.1 lifecycle
/// (`metrics` is handled separately by [`crate::metrics::MetricSink`], which
/// keeps CE's `collecting → queued → sent` path without a `sending` state).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EventTable {
    /// `logins` (§6.1).
    Logins,
    /// `dns_activity` (§6.1).
    DnsActivity,
    /// `circumventions` (§6.1).
    Circumventions,
    /// `switch_users` (§6.1).
    SwitchUsers,
    /// `telemetry` — the LustLess addition of §6.1.
    Telemetry,
}

impl EventTable {
    /// Every event table of the §6.1 outbox.
    pub const ALL: [EventTable; 5] = [
        EventTable::Logins,
        EventTable::DnsActivity,
        EventTable::Circumventions,
        EventTable::SwitchUsers,
        EventTable::Telemetry,
    ];

    /// The SQL table name (§6.1).
    pub const fn as_str(self) -> &'static str {
        match self {
            EventTable::Logins => "logins",
            EventTable::DnsActivity => "dns_activity",
            EventTable::Circumventions => "circumventions",
            EventTable::SwitchUsers => "switch_users",
            EventTable::Telemetry => "telemetry",
        }
    }

    /// Predicate used by [`Outbox::drop_invalid`]: rows whose required
    /// columns are NULL/empty are invalid records and are dropped, never
    /// failing the batch (§6.1, `upload-protocol.md` §4).
    fn invalid_predicate(self) -> &'static str {
        match self {
            EventTable::Logins | EventTable::Circumventions | EventTable::SwitchUsers => {
                "(username IS NULL OR TRIM(username) = '')"
            }
            EventTable::DnsActivity => {
                "(username IS NULL OR TRIM(username) = '' \
                    OR domain IS NULL OR TRIM(domain) = '')"
            }
            EventTable::Telemetry => "(name IS NULL OR TRIM(name) = '')",
        }
    }
}

/// A `logins` row as inserted by the session watcher (§6.1 columns).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginRow {
    /// CE account username.
    pub username: String,
    /// OS account id mapped to the CE account.
    pub system_user_id: Option<String>,
    /// OS account name mapped to the CE account.
    pub system_user_name: Option<String>,
    /// Event timestamp, ISO-8601 UTC (§6.1).
    pub timestamp: String,
    /// Session login time, ISO-8601 UTC.
    pub login_at: String,
    /// Session logout time, ISO-8601 UTC; `None` while open.
    pub logout_at: Option<String>,
}

/// A `dns_activity` row as written by the DNS forwarder (§6.1/§8 columns).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsActivityRow {
    /// CE account username.
    pub username: String,
    /// Queried domain.
    pub domain: String,
    /// Attributing process id (`"unknown"` tolerated default, §8).
    pub process_id: Option<String>,
    /// Attributing process name (`"unknown"` tolerated default, §8).
    pub process_name: String,
    /// Query time, ISO-8601 UTC (§6.1).
    pub datetime_created: String,
    /// Answer address.
    pub ip: Option<String>,
    /// `resolution_type` verdict vocabulary (§8 table).
    pub resolution_type: String,
    /// Connection type of the query.
    pub connection_type: Option<String>,
    /// `X-CB-Location`-style response-header tag (§8).
    pub resolution_datacenter: Option<String>,
    /// Resolution time in milliseconds.
    pub resolution_time_ms: Option<String>,
}

/// A `circumventions` row (§6.1/§7 columns).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CircumventionRow {
    /// CE account username.
    pub username: String,
    /// Kind of interruption (e.g. §6.3 tamper signal).
    pub interruption_type: String,
    /// Application name.
    pub app_name: String,
    /// Window title at the time of the event.
    pub app_window_title: Option<String>,
    /// Device id (see [`crate::ids::new_device_id`]).
    pub device_id: String,
    /// Event timestamp, ISO-8601 UTC (§6.1).
    pub timestamp: String,
    /// Separate local timezone offset string (§6.1).
    pub timezone_offset: String,
}

/// A `switch_users` row (§6.1 columns).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwitchUserRow {
    /// Username switched away from.
    pub username: String,
    /// `switch_user_from` column.
    pub switch_user_from: String,
    /// `switch_user_to` column.
    pub switch_user_to: String,
    /// Event timestamp, ISO-8601 UTC (§6.1).
    pub timestamp: String,
    /// Separate local timezone offset string (§6.1).
    pub timezone_offset: String,
    /// Device name.
    pub device_name: Option<String>,
    /// Device id.
    pub device_id: String,
}

/// A `telemetry` row — the LustLess shape of §6.1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TelemetryRow {
    /// Client type (e.g. `daemon`, `agent`).
    pub client_type: String,
    /// Device name.
    pub device_name: String,
    /// Telemetry name.
    pub name: String,
    /// Telemetry value.
    pub value: String,
    /// Sample time, ISO-8601 UTC (§6.1).
    pub utc_timestamp: String,
}

/// One row claimed for upload: the table, the primary key, and the full row
/// as a JSON object (column name → value, SQL `NULL` → `null`) from which the
/// §10 record builders are fed.
#[derive(Debug, Clone, PartialEq)]
pub struct ClaimedRow {
    /// Table the row came from.
    pub table: EventTable,
    /// `id` primary key — pass to [`Outbox::mark_sent`] / [`Outbox::drop_invalid`].
    pub id: i64,
    /// The row's `username` column (batching key, per-user batches §10);
    /// `None` for `telemetry`, which has no username column.
    pub username: Option<String>,
    /// The row's `created_at` (SQLite `DATETIME('now')` format, UTC).
    pub created_at: String,
    /// All columns of the row.
    pub columns: Value,
}

/// The plain-SQLite outbox of §6.1.
#[derive(Debug)]
pub struct Outbox {
    conn: Connection,
}

impl Outbox {
    /// Opens (creating if needed) the outbox at `path` with mode 0600 (§4),
    /// enables WAL (§6.1), and creates the verbatim `ce-file` schema plus the
    /// §6.1 `telemetry` table. `install_metadata.db_created_at` is seeded once
    /// (mirrors the captured `ce-file`, `local-db.md` §Evidence).
    pub fn open(path: &Path) -> Result<Self, CoreError> {
        use std::os::unix::fs::OpenOptionsExt;
        use std::os::unix::fs::PermissionsExt;

        let permissions = std::fs::Permissions::from_mode(0o600);
        // Create the file first so it is born 0600 (§4/§6.1), then enforce
        // the mode on pre-existing files as well.
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(path)?;
        std::fs::set_permissions(path, permissions.clone())?;

        let conn = Connection::open(path)?;
        let journal: String = conn.query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))?;
        if journal != "wal" {
            return Err(CoreError::JournalMode(journal));
        }

        for (name, ddl) in CE_SCHEMA {
            if !object_exists(&conn, "table", name)? {
                conn.execute_batch(ddl)?;
            }
        }
        for (name, ddl) in CE_INDEXES {
            if !object_exists(&conn, "index", name)? {
                conn.execute_batch(ddl)?;
            }
        }
        if !object_exists(&conn, "table", "telemetry")? {
            conn.execute_batch(TELEMETRY_SCHEMA)?;
        }

        // Seed `db_created_at` once (ISO-8601 UTC, matching the captured
        // row); idempotent via the primary key.
        conn.execute(
            "INSERT OR IGNORE INTO install_metadata (\"key\", value) VALUES ('db_created_at', ?1)",
            params![iso_now(&conn)?],
        )?;

        // WAL/SHMP sidecars are created on the first write above; they must
        // not be world-readable either (best effort — they may already be
        // checkpointed away).
        for suffix in ["-wal", "-shm"] {
            let mut sidecar = path.as_os_str().to_owned();
            sidecar.push(suffix);
            let _ = std::fs::set_permissions(std::path::Path::new(&sidecar), permissions.clone());
        }

        Ok(Self { conn })
    }

    /// Reads an `install_metadata` value (§6.1).
    pub fn install_metadata(&self, key: &str) -> Result<Option<String>, CoreError> {
        Ok(self
            .conn
            .query_row(
                "SELECT value FROM install_metadata WHERE \"key\" = ?1 COLLATE NOCASE",
                params![key],
                |row| row.get(0),
            )
            .optional()?)
    }

    /// Writes an `install_metadata` value (§6.1).
    pub fn set_install_metadata(&mut self, key: &str, value: &str) -> Result<(), CoreError> {
        self.conn.execute(
            "INSERT INTO install_metadata (\"key\", value) VALUES (?1, ?2) \
             ON CONFLICT(\"key\") DO UPDATE SET value = excluded.value",
            params![key, value],
        )?;
        Ok(())
    }

    /// Inserts a `logins` row, born `status='queued'` (§6.1). Returns the row
    /// id.
    pub fn insert_login(&mut self, row: &LoginRow) -> Result<i64, CoreError> {
        self.conn.execute(
            "INSERT INTO logins (username, system_user_id, system_user_name, timestamp, login_at, logout_at, status, status_changed_at, created_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'queued', DATETIME('now'), DATETIME('now'))",
            params![
                row.username,
                row.system_user_id,
                row.system_user_name,
                row.timestamp,
                row.login_at,
                row.logout_at,
            ],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Inserts a `dns_activity` row, born `status='queued'` with the §6.1
    /// `…VALUES (?, …, 'queued', DATETIME('now'), DATETIME('now'))` literal
    /// shape (evidence `filter-enforcement.md` §3). Returns the row id.
    pub fn insert_dns_activity(&mut self, row: &DnsActivityRow) -> Result<i64, CoreError> {
        self.conn.execute(
            "INSERT INTO dns_activity (username, domain, process_id, process_name, datetime_created, ip, resolution_type, connection_type, resolution_datacenter, resolution_time_ms, status, status_changed_at, created_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, 'queued', DATETIME('now'), DATETIME('now'))",
            params![
                row.username,
                row.domain,
                row.process_id,
                row.process_name,
                row.datetime_created,
                row.ip,
                row.resolution_type,
                row.connection_type,
                row.resolution_datacenter,
                row.resolution_time_ms,
            ],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Inserts a `circumventions` row, born `status='queued'` (§6.1).
    /// Returns the row id.
    pub fn insert_circumvention(&mut self, row: &CircumventionRow) -> Result<i64, CoreError> {
        self.conn.execute(
            "INSERT INTO circumventions (username, interruption_type, app_name, app_window_title, device_id, timestamp, timezone_offset, status, status_changed_at, created_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'queued', DATETIME('now'), DATETIME('now'))",
            params![
                row.username,
                row.interruption_type,
                row.app_name,
                row.app_window_title,
                row.device_id,
                row.timestamp,
                row.timezone_offset,
            ],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Inserts a `switch_users` row, born `status='queued'` (§6.1). Returns
    /// the row id.
    pub fn insert_switch_user(&mut self, row: &SwitchUserRow) -> Result<i64, CoreError> {
        self.conn.execute(
            "INSERT INTO switch_users (username, switch_user_from, switch_user_to, timestamp, timezone_offset, device_name, device_id, status, status_changed_at, created_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'queued', DATETIME('now'), DATETIME('now'))",
            params![
                row.username,
                row.switch_user_from,
                row.switch_user_to,
                row.timestamp,
                row.timezone_offset,
                row.device_name,
                row.device_id,
            ],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Inserts a `telemetry` row (§6.1 LustLess table), born
    /// `status='queued'`. Returns the row id.
    pub fn insert_telemetry(&mut self, row: &TelemetryRow) -> Result<i64, CoreError> {
        self.conn.execute(
            "INSERT INTO telemetry (client_type, device_name, name, value, utc_timestamp, status, status_changed_at, created_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, 'queued', DATETIME('now'), DATETIME('now'))",
            params![
                row.client_type,
                row.device_name,
                row.name,
                row.value,
                row.utc_timestamp,
            ],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Claims up to `limit` rows of one event table for upload: the oldest
    /// `queued` rows that are at least `min_age_secs` old flip to
    /// `status='sending'` (§6.1 claim; evidence `upload-protocol.md` §4) and
    /// are returned with their full columns.
    ///
    /// The claim happens per record table — CE's gatherers are per-table
    /// (`EntrySqliteLogGatherer<TABLE>`) and batching is per user on top
    /// (§10). Default arguments: [`DEFAULT_BATCH_LIMIT`] /
    /// [`DEFAULT_MIN_AGE_SECS`].
    pub fn claim_batch(
        &mut self,
        table: EventTable,
        limit: u32,
        min_age_secs: i64,
    ) -> Result<Vec<ClaimedRow>, CoreError> {
        let tx = self.conn.transaction()?;

        // Select (oldest first) …
        let select = format!(
            "SELECT id FROM {} WHERE status = 'queued' \
             AND created_at <= DATETIME('now', '-' || ?1 || ' seconds') \
             ORDER BY id LIMIT ?2",
            table.as_str()
        );
        let ids: Vec<i64> = {
            let mut stmt = tx.prepare(&select)?;
            let rows = stmt.query_map(params![min_age_secs, limit], |row| row.get(0))?;
            rows.collect::<Result<Vec<_>, _>>()?
        };
        if ids.is_empty() {
            // Nothing claimed: the transaction rolls back harmlessly.
            return Ok(Vec::new());
        }
        let placeholders = vec!["?"; ids.len()].join(",");

        // … then flip exactly those rows to 'sending' (§6.1 claim SQL).
        let update = format!(
            "UPDATE {} SET status = 'sending', status_changed_at = DATETIME('now') \
             WHERE id IN ({})",
            table.as_str(),
            placeholders
        );
        tx.execute(&update, params_from_iter(ids.iter()))?;

        // Read the claimed rows back so the caller sees the committed state.
        let read = format!(
            "SELECT * FROM {} WHERE id IN ({}) ORDER BY id",
            table.as_str(),
            placeholders
        );
        let mut stmt = tx.prepare(&read)?;
        let names: Vec<String> = stmt.column_names().into_iter().map(String::from).collect();
        let rows = stmt.query_map(params_from_iter(ids.iter()), |row| {
            row_to_value(row, &names)
        })?;
        let mut claimed = Vec::with_capacity(ids.len());
        for value in rows {
            let columns = value?;
            let id = columns
                .get("id")
                .and_then(Value::as_i64)
                .expect("row id is an integer");
            let username = columns
                .get("username")
                .and_then(Value::as_str)
                .map(String::from);
            let created_at = columns
                .get("created_at")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            claimed.push(ClaimedRow {
                table,
                id,
                username,
                created_at,
                columns,
            });
        }
        // The statements borrow the transaction; release them before commit.
        drop(stmt);
        tx.commit()?;
        Ok(claimed)
    }

    /// Acknowledges a batch: `sending → sent` after the API accepted it
    /// (§6.1 ack). Returns the number of rows updated.
    pub fn mark_sent(&mut self, table: EventTable, ids: &[i64]) -> Result<usize, CoreError> {
        mark_ids_sent(&self.conn, table.as_str(), ids)
    }

    /// Crash/retry recovery (§6.1): moves `sending` rows whose claim is older
    /// than `stale_secs` (default [`STALE_SENDING_SECS`] = 5 minutes) back to
    /// `queued`, over all event tables. Returns the number of re-queued rows.
    ///
    /// The evidence UPDATE carries a `LIMIT ?` (`upload-protocol.md` §4);
    /// reaping is a purely local state change, so this drains everything in
    /// one pass — the same end state as repeated limited runs.
    pub fn reap_stale_sending(&mut self, stale_secs: i64) -> Result<usize, CoreError> {
        let mut total = 0usize;
        for table in EventTable::ALL {
            let sql = format!(
                "UPDATE {} SET status = 'queued', status_changed_at = DATETIME('now') \
                 WHERE status = 'sending' \
                 AND status_changed_at < DATETIME('now', '-' || ?1 || ' seconds')",
                table.as_str()
            );
            total += self.conn.execute(&sql, params![stale_secs])?;
        }
        Ok(total)
    }

    /// Drops invalid records from a claimed batch (§6.1, evidence
    /// `ApiSendQueue::removeInvalidRecords`): rows whose required columns are
    /// NULL/empty are **deleted**, never failing the batch. Returns the number
    /// of dropped rows.
    pub fn drop_invalid(&mut self, table: EventTable, ids: &[i64]) -> Result<usize, CoreError> {
        if ids.is_empty() {
            return Ok(0);
        }
        let placeholders = vec!["?"; ids.len()].join(",");
        let sql = format!(
            "DELETE FROM {} WHERE id IN ({}) AND {}",
            table.as_str(),
            placeholders,
            table.invalid_predicate()
        );
        Ok(self.conn.execute(&sql, params_from_iter(ids.iter()))?)
    }

    /// Deletes rows by id regardless of content — the §10 uploader's
    /// deterministic-4xx path. `drop_invalid` only removes rows that are
    /// *locally* known to be unusable, so using it for a server rejection
    /// matched nothing and left the batch to be re-claimed forever.
    pub fn delete_rows(&mut self, table: EventTable, ids: &[i64]) -> Result<usize, CoreError> {
        if ids.is_empty() {
            return Ok(0);
        }
        let placeholders = vec!["?"; ids.len()].join(",");
        let sql = format!(
            "DELETE FROM {} WHERE id IN ({})",
            table.as_str(),
            placeholders
        );
        Ok(self.conn.execute(&sql, params_from_iter(ids.iter()))?)
    }

    /// The dashboard read-back query of §8 — `ViewDnsActivityHandler`:
    /// `SELECT domain,process_id,process_name,ip,resolution_type,
    /// connection_type,resolution_datacenter,resolution_time_ms,
    /// datetime_created FROM dns_activity ORDER BY datetime_created DESC
    /// LIMIT 500` — as JSON objects (use [`DASHBOARD_READ_LIMIT`] for the §8
    /// default).
    pub fn dns_activity_readback(&self, limit: u32) -> Result<Vec<Value>, CoreError> {
        const QUERY: &str = "SELECT domain,process_id,process_name,ip,resolution_type,connection_type,resolution_datacenter,resolution_time_ms,datetime_created FROM dns_activity ORDER BY datetime_created DESC LIMIT ?1";
        let mut stmt = self.conn.prepare(QUERY)?;
        let names: Vec<String> = stmt.column_names().into_iter().map(String::from).collect();
        let rows = stmt.query_map(params![limit], |row| row_to_value(row, &names))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    pub(crate) fn conn(&self) -> &Connection {
        &self.conn
    }

    pub(crate) fn conn_mut(&mut self) -> &mut Connection {
        &mut self.conn
    }
}

/// Shared `… SET status = 'sent', status_changed_at = DATETIME('now') WHERE id
/// IN (…)` ack (§6.1), used by the event tables and by
/// [`crate::metrics::MetricSink::mark_sent`].
pub(crate) fn mark_ids_sent(
    conn: &Connection,
    table: &str,
    ids: &[i64],
) -> Result<usize, CoreError> {
    if ids.is_empty() {
        return Ok(0);
    }
    let placeholders = vec!["?"; ids.len()].join(",");
    let sql = format!(
        "UPDATE {table} SET status = 'sent', status_changed_at = DATETIME('now') \
         WHERE id IN ({placeholders})"
    );
    Ok(conn.execute(&sql, params_from_iter(ids.iter()))?)
}

/// Whether a table/index exists (`sqlite_master`), for idempotent schema
/// creation of the verbatim DDL (§6.1).
fn object_exists(conn: &Connection, kind: &str, name: &str) -> Result<bool, CoreError> {
    let count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = ?1 AND name = ?2",
        params![kind, name],
        |row| row.get(0),
    )?;
    Ok(count > 0)
}

/// Current UTC time as ISO-8601 (`…Z`), derived from SQLite's
/// `DATETIME('now')` so DB timestamps share one clock (§6.1).
pub(crate) fn iso_now(conn: &Connection) -> Result<String, CoreError> {
    let raw: String = conn.query_row("SELECT DATETIME('now')", [], |row| row.get(0))?;
    Ok(format!("{}Z", raw.replace(' ', "T")))
}

/// Converts one result row into a JSON object keyed by column name
/// (`NULL` → `null`, blobs as lowercase hex).
fn row_to_value(row: &rusqlite::Row<'_>, names: &[String]) -> Result<Value, rusqlite::Error> {
    let mut object = Map::with_capacity(names.len());
    for (index, name) in names.iter().enumerate() {
        let value = match row.get_ref(index)? {
            rusqlite::types::ValueRef::Null => Value::Null,
            rusqlite::types::ValueRef::Integer(number) => Value::from(number),
            rusqlite::types::ValueRef::Real(number) => Value::from(number),
            rusqlite::types::ValueRef::Text(text) => {
                Value::String(String::from_utf8_lossy(text).into_owned())
            }
            rusqlite::types::ValueRef::Blob(bytes) => Value::String(crate::ids::to_hex(bytes)),
        };
        object.insert(name.clone(), value);
    }
    Ok(Value::Object(object))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::TempDir;
    use serde_json::json;

    fn open(tag: &str) -> (TempDir, Outbox) {
        let dir = TempDir::new(tag);
        let outbox = Outbox::open(&dir.path().join("outbox.db")).expect("open outbox");
        (dir, outbox)
    }

    fn dns_row(domain: &str) -> DnsActivityRow {
        DnsActivityRow {
            username: "alice".into(),
            domain: domain.into(),
            process_id: Some("4321".into()),
            process_name: "firefox".into(),
            datetime_created: "2026-10-11T12:00:00Z".into(),
            ip: Some("192.0.2.10".into()),
            resolution_type: "BlockedCustom".into(),
            connection_type: Some("dns".into()),
            resolution_datacenter: Some("slc_1b".into()),
            resolution_time_ms: Some("12".into()),
        }
    }

    fn status_of(outbox: &Outbox, table: &str, id: i64) -> String {
        outbox
            .conn()
            .query_row(
                &format!("SELECT status FROM {table} WHERE id = ?1"),
                params![id],
                |row| row.get(0),
            )
            .expect("row exists")
    }

    fn backdate(outbox: &Outbox, table: &str, id: i64, seconds: i64) {
        outbox
            .conn()
            .execute(
                &format!("UPDATE {table} SET created_at = DATETIME('now', '-' || ?2 || ' seconds') WHERE id = ?1"),
                params![id, seconds],
            )
            .expect("backdate");
    }

    #[test]
    fn schema_pragmas_and_permissions_match_contract() {
        let dir = TempDir::new("schema");
        let path = dir.path().join("outbox.db");
        let outbox = Outbox::open(&path).expect("open");

        // §6.1: all six `ce-file` tables + the LustLess telemetry table.
        for table in [
            "install_metadata",
            "logins",
            "metrics",
            "circumventions",
            "switch_users",
            "dns_activity",
            "telemetry",
        ] {
            let count: i64 = outbox
                .conn()
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
                    params![table],
                    |row| row.get(0),
                )
                .expect("sqlite_master");
            assert_eq!(count, 1, "table {table} missing");
        }
        // §6.1: both partial indexes.
        for index in ["circumventions_matching", "dns_activity_matching"] {
            let count: i64 = outbox
                .conn()
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name = ?1",
                    params![index],
                    |row| row.get(0),
                )
                .expect("sqlite_master");
            assert_eq!(count, 1, "index {index} missing");
        }

        // The DDL is verbatim: an independently transcribed line of
        // `local-db.md` §Evidence must equal the constant we execute (catches
        // accidental edits of the schema block).
        assert_eq!(
            CE_SCHEMA[0].1,
            "CREATE TABLE install_metadata (key TEXT  COLLATE NOCASE,value TEXT,PRIMARY KEY(key));"
        );
        assert_eq!(
            CE_SCHEMA[5].1,
            "CREATE TABLE dns_activity (id INTEGER PRIMARY KEY AUTOINCREMENT,username TEXT COLLATE NOCASE,domain TEXT,process_id TEXT,process_name TEXT KEY,datetime_created TEXT KEY,ip TEXT,resolution_type TEXT,connection_type TEXT,resolution_datacenter TEXT,resolution_time_ms TEXT,status TEXT,status_changed_at TEXT,created_at TEXT);"
        );
        // What SQLite stored equals what we executed (sqlite_master omits the
        // trailing semicolon of the verbatim Evidence DDL).
        let stored: String = outbox
            .conn()
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'logins'",
                [],
                |row| row.get(0),
            )
            .expect("stored ddl");
        assert_eq!(stored, CE_SCHEMA[1].1.trim_end_matches(';'));

        // §6.1: WAL journal mode.
        let journal: String = outbox
            .conn()
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))
            .expect("journal");
        assert_eq!(journal, "wal");

        // §4/§6.1: mode 0600 …
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "outbox must be 0600");

        // … and the outbox stays a *plain* SQLite file (§4 "plain SQLite
        // outbox"): SQLCipher without a key must pass pages through.
        let bytes = std::fs::read(&path).expect("read header");
        assert_eq!(
            &bytes[..16],
            b"SQLite format 3\0",
            "outbox must be plaintext"
        );

        // `db_created_at` seeded once, ISO-8601 UTC (§6.1 evidence).
        let created = outbox
            .install_metadata("db_created_at")
            .expect("read metadata")
            .expect("db_created_at exists");
        assert!(created.ends_with('Z'), "{created}");
        assert_eq!(created.len(), 20, "{created}");
    }

    #[test]
    fn lifecycle_queued_claim_sent_with_min_age_gate() {
        let (_dir, mut outbox) = open("lifecycle");
        let id = outbox
            .insert_dns_activity(&dns_row("example.test"))
            .unwrap();

        // Rows are born 'queued' (§6.1).
        assert_eq!(status_of(&outbox, "dns_activity", id), "queued");

        // Min-age gate: a fresh row is not claimable (§6.1, 30 s).
        let claim = outbox
            .claim_batch(
                EventTable::DnsActivity,
                DEFAULT_BATCH_LIMIT,
                DEFAULT_MIN_AGE_SECS,
            )
            .unwrap();
        assert!(
            claim.is_empty(),
            "row younger than the min-age gate claimed"
        );

        // Backdate past the gate and claim.
        backdate(&outbox, "dns_activity", id, 60);
        let claimed = outbox
            .claim_batch(
                EventTable::DnsActivity,
                DEFAULT_BATCH_LIMIT,
                DEFAULT_MIN_AGE_SECS,
            )
            .unwrap();
        assert_eq!(claimed.len(), 1);
        let row = &claimed[0];
        assert_eq!(row.table, EventTable::DnsActivity);
        assert_eq!(row.id, id);
        assert_eq!(row.username.as_deref(), Some("alice"));
        assert_eq!(row.created_at.len(), "YYYY-MM-DD HH:MM:SS".len());
        assert_eq!(row.columns["status"], json!("sending"));
        assert_eq!(row.columns["domain"], json!("example.test"));
        assert_eq!(
            row.columns["datetime_created"],
            json!("2026-10-11T12:00:00Z")
        );
        assert_eq!(status_of(&outbox, "dns_activity", id), "sending");

        // Already-claimed rows are not claimable again.
        let again = outbox
            .claim_batch(
                EventTable::DnsActivity,
                DEFAULT_BATCH_LIMIT,
                DEFAULT_MIN_AGE_SECS,
            )
            .unwrap();
        assert!(again.is_empty());

        // Ack: sending → sent (§6.1).
        let updated = outbox.mark_sent(EventTable::DnsActivity, &[id]).unwrap();
        assert_eq!(updated, 1);
        assert_eq!(status_of(&outbox, "dns_activity", id), "sent");
    }

    #[test]
    fn stale_sending_rows_are_reaped_to_queued() {
        let (_dir, mut outbox) = open("reaper");
        let id = outbox
            .insert_dns_activity(&dns_row("example.test"))
            .unwrap();
        backdate(&outbox, "dns_activity", id, 60);
        outbox
            .claim_batch(
                EventTable::DnsActivity,
                DEFAULT_BATCH_LIMIT,
                DEFAULT_MIN_AGE_SECS,
            )
            .unwrap();
        assert_eq!(status_of(&outbox, "dns_activity", id), "sending");

        // A claim younger than five minutes is left alone (§6.1).
        assert_eq!(outbox.reap_stale_sending(STALE_SENDING_SECS).unwrap(), 0);
        assert_eq!(status_of(&outbox, "dns_activity", id), "sending");

        // Age the claim past five minutes → reaped to 'queued'.
        outbox
            .conn()
            .execute(
                "UPDATE dns_activity SET status_changed_at = DATETIME('now', '-400 seconds') WHERE id = ?1",
                params![id],
            )
            .unwrap();
        assert_eq!(outbox.reap_stale_sending(STALE_SENDING_SECS).unwrap(), 1);
        assert_eq!(status_of(&outbox, "dns_activity", id), "queued");

        // The reaped row is claimable again (crash-retry path, §6.1).
        let claimed = outbox
            .claim_batch(
                EventTable::DnsActivity,
                DEFAULT_BATCH_LIMIT,
                DEFAULT_MIN_AGE_SECS,
            )
            .unwrap();
        assert_eq!(claimed.len(), 1);
    }

    #[test]
    fn invalid_records_are_dropped_without_failing_the_batch() {
        let (_dir, mut outbox) = open("drop-invalid");
        let mut bad = dns_row("");
        bad.username = "alice".into();
        let bad_id = outbox.insert_dns_activity(&bad).unwrap();
        let good_id = outbox.insert_dns_activity(&dns_row("good.test")).unwrap();
        backdate(&outbox, "dns_activity", bad_id, 60);
        backdate(&outbox, "dns_activity", good_id, 60);

        let claimed = outbox
            .claim_batch(
                EventTable::DnsActivity,
                DEFAULT_BATCH_LIMIT,
                DEFAULT_MIN_AGE_SECS,
            )
            .unwrap();
        assert_eq!(claimed.len(), 2);

        // §6.1: drop the invalid record (empty domain), keep the batch alive.
        let dropped = outbox
            .drop_invalid(EventTable::DnsActivity, &[bad_id])
            .unwrap();
        assert_eq!(dropped, 1);
        let remaining: i64 = outbox
            .conn()
            .query_row("SELECT COUNT(*) FROM dns_activity", [], |row| row.get(0))
            .unwrap();
        assert_eq!(remaining, 1);
        assert_eq!(status_of(&outbox, "dns_activity", good_id), "sending");

        // The valid record still acks normally.
        outbox
            .mark_sent(EventTable::DnsActivity, &[good_id])
            .unwrap();
        assert_eq!(status_of(&outbox, "dns_activity", good_id), "sent");

        // Empty ids are a no-op.
        assert_eq!(
            outbox.drop_invalid(EventTable::DnsActivity, &[]).unwrap(),
            0
        );
        assert_eq!(outbox.mark_sent(EventTable::DnsActivity, &[]).unwrap(), 0);
    }

    #[test]
    fn dashboard_readback_is_the_section_8_query() {
        let (_dir, mut outbox) = open("readback");
        let mut older = dns_row("older.test");
        older.datetime_created = "2026-10-11T10:00:00Z".into();
        outbox.insert_dns_activity(&older).unwrap();
        let mut mid = dns_row("mid.test");
        mid.datetime_created = "2026-10-11T11:00:00Z".into();
        outbox.insert_dns_activity(&mid).unwrap();
        let mut newest = dns_row("newest.test");
        newest.datetime_created = "2026-10-11T12:00:00Z".into();
        newest.process_id = None;
        newest.ip = None;
        outbox.insert_dns_activity(&newest).unwrap();

        let rows = outbox.dns_activity_readback(DASHBOARD_READ_LIMIT).unwrap();
        assert_eq!(DASHBOARD_READ_LIMIT, 500, "§8 LIMIT 500");
        assert_eq!(rows.len(), 3);
        // ORDER BY datetime_created DESC.
        assert_eq!(rows[0]["datetime_created"], json!("2026-10-11T12:00:00Z"));
        assert_eq!(rows[1]["datetime_created"], json!("2026-10-11T11:00:00Z"));
        assert_eq!(rows[2]["datetime_created"], json!("2026-10-11T10:00:00Z"));

        // Exactly the §8 column list.
        let object = rows[0].as_object().expect("object");
        assert_eq!(object.len(), 9);
        for column in [
            "domain",
            "process_id",
            "process_name",
            "ip",
            "resolution_type",
            "connection_type",
            "resolution_datacenter",
            "resolution_time_ms",
            "datetime_created",
        ] {
            assert!(object.contains_key(column), "missing §8 column {column}");
        }
        // NULL columns map to JSON null.
        assert_eq!(rows[0]["process_id"], Value::Null);
        assert_eq!(rows[0]["ip"], Value::Null);

        // LIMIT is honored.
        let rows = outbox.dns_activity_readback(2).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0]["datetime_created"], json!("2026-10-11T12:00:00Z"));
    }

    #[test]
    fn remaining_event_tables_carry_their_columns() {
        let (_dir, mut outbox) = open("tables");

        let login_id = outbox
            .insert_login(&LoginRow {
                username: "alice".into(),
                system_user_id: Some("1000".into()),
                system_user_name: Some("alice".into()),
                timestamp: "2026-10-11T10:00:00Z".into(),
                login_at: "2026-10-11T10:00:00Z".into(),
                logout_at: None,
            })
            .unwrap();
        let circ_id = outbox
            .insert_circumvention(&CircumventionRow {
                username: "alice".into(),
                interruption_type: "pdl_transaction_removed".into(),
                app_name: "evilapp".into(),
                app_window_title: Some("Secret".into()),
                device_id: "0123456789abcdef0123456789abcdef".into(),
                timestamp: "2026-10-11T10:05:00Z".into(),
                timezone_offset: "-05:00".into(),
            })
            .unwrap();
        let switch_id = outbox
            .insert_switch_user(&SwitchUserRow {
                username: "alice".into(),
                switch_user_from: "alice".into(),
                switch_user_to: "bob".into(),
                timestamp: "2026-10-11T10:10:00Z".into(),
                timezone_offset: "-05:00".into(),
                device_name: Some("workstation".into()),
                device_id: "0123456789abcdef0123456789abcdef".into(),
            })
            .unwrap();
        let telemetry_id = outbox
            .insert_telemetry(&TelemetryRow {
                client_type: "daemon".into(),
                device_name: "workstation".into(),
                name: "uptime_seconds".into(),
                value: "42".into(),
                utc_timestamp: "2026-10-11T10:15:00Z".into(),
            })
            .unwrap();

        // All born 'queued' (§6.1).
        assert_eq!(status_of(&outbox, "logins", login_id), "queued");
        assert_eq!(status_of(&outbox, "circumventions", circ_id), "queued");
        assert_eq!(status_of(&outbox, "switch_users", switch_id), "queued");
        assert_eq!(status_of(&outbox, "telemetry", telemetry_id), "queued");

        // Separate timezone_offset stored beside UTC (§6.1).
        let tz: String = outbox
            .conn()
            .query_row(
                "SELECT timezone_offset FROM circumventions WHERE id = ?1",
                params![circ_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(tz, "-05:00");

        // NULL columns stay NULL.
        let logout: Option<String> = outbox
            .conn()
            .query_row(
                "SELECT logout_at FROM logins WHERE id = ?1",
                params![login_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(logout, None);

        // The telemetry table claims/acks through the same lifecycle.
        backdate(&outbox, "telemetry", telemetry_id, 60);
        let claimed = outbox
            .claim_batch(
                EventTable::Telemetry,
                DEFAULT_BATCH_LIMIT,
                DEFAULT_MIN_AGE_SECS,
            )
            .unwrap();
        assert_eq!(claimed.len(), 1);
        assert_eq!(
            claimed[0].username, None,
            "telemetry has no username column"
        );
        assert_eq!(claimed[0].columns["value"], json!("42"));
        outbox
            .mark_sent(EventTable::Telemetry, &[telemetry_id])
            .unwrap();
        assert_eq!(status_of(&outbox, "telemetry", telemetry_id), "sent");
    }

    #[test]
    fn reopen_is_idempotent_and_keeps_state() {
        let dir = TempDir::new("reopen");
        let path = dir.path().join("outbox.db");

        let created_at = {
            let mut outbox = Outbox::open(&path).expect("first open");
            outbox
                .insert_dns_activity(&dns_row("example.test"))
                .expect("insert");
            outbox
                .install_metadata("db_created_at")
                .expect("read")
                .expect("seeded")
        };

        // Reopen: same schema, same db_created_at (never re-seeded), state kept.
        let outbox = Outbox::open(&path).expect("second open");
        assert_eq!(
            outbox.install_metadata("db_created_at").unwrap().unwrap(),
            created_at
        );
        let count: i64 = outbox
            .conn()
            .query_row("SELECT COUNT(*) FROM dns_activity", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn install_metadata_upserts() {
        let (_dir, mut outbox) = open("metadata");
        outbox.set_install_metadata("k", "v1").unwrap();
        assert_eq!(outbox.install_metadata("k").unwrap().as_deref(), Some("v1"));
        outbox.set_install_metadata("k", "v2").unwrap();
        assert_eq!(outbox.install_metadata("k").unwrap().as_deref(), Some("v2"));
        assert_eq!(outbox.install_metadata("absent").unwrap(), None);
        // Keys are case-insensitive (COLLATE NOCASE, verbatim schema).
        assert_eq!(outbox.install_metadata("K").unwrap().as_deref(), Some("v2"));
    }
}
