//! Per-user settings DB (`/var/lib/lustless/<uid>/settings.db`) over
//! SQLCipher — CONTRACTS §6.2.
//!
//! # Crypto choice (documented per CONTRACTS §2/§6.2)
//!
//! Two options were on the table: rusqlite's `sqlcipher` feature (link the
//! system libsqlcipher) or a minimal hand-rolled FFI to `sqlite3_key`. This
//! crate instead uses rusqlite's **`bundled-sqlcipher`** feature, which
//! compiles SQLCipher 4 into the binary, because:
//!
//! * the workspace builds one rusqlite — feature unification means a
//!   system-`sqlcipher` link would also become the *outbox's* SQLite. With
//!   `bundled-sqlcipher` both databases share one runtime while keeping their
//!   contract-split behavior: the settings DB is keyed via
//!   `PRAGMA key = 'x…'`, the outbox (§6.1) never sets a key and SQLCipher
//!   passes its pages through unchanged — a plain `SQLite format 3` file, as
//!   §4 requires (asserted by the outbox's unit test);
//! * no system `libsqlcipher-dev`/link-time dependency: any host can build
//!   and test the crate (§2's `libsqlcipher-dev` build dependency is
//!   replaced by the bundled compile — documented deviation);
//! * no unsafe FFI of our own: the key is applied through SQLCipher's SQL
//!   interface.
//!
//! SQLCipher 4's defaults preserve the crypto shape of §6.2 — per-page
//! AES-256-CBC + HMAC-SHA512 and PBKDF2-HMAC-SHA512 key derivation. Key
//! management is ours: the per-install keyfile `settings.key` (0600, 32 random
//! bytes, load-or-create) of §6.2/§4; optional libsecret/TPM sealing remains
//! the documented extension point. Lazy `ALTER TABLE` migrations like CE
//! (`filter-enforcement.md` verdict c) are exposed as
//! [`SettingsDb::ensure_column`].
//!
//! # Deviation (§6.2)
//!
//! `api_credentials` has **no `password` column** (CE's plaintext `password`
//! is deliberately not reproduced) and no HTTP-Basic `user_key`/`user_secret`
//! either: it stores `device_token`/`refresh_token` only (§10 Bearer auth).

use std::path::Path;

use rand::RngCore;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};

use crate::CoreError;

/// Length of the `settings.key` keyfile in bytes (§6.2: 32 random bytes).
pub const KEY_LEN: usize = 32;

/// Default DoH endpoint when `user_dns_filter.over_https_url` is absent —
/// evidence: `filter-surface.md` §1b (default when absent), also the §9.1
/// `dns.doh_url` sample value.
pub const DEFAULT_DOH_URL: &str = "https://dns.cleanbrowsing.org/doh/adult-filter";

/// Default blocking level when none is stored — evidence: `filter-surface.md`
/// §1b (`migrateUserSettings`: "No DoH URL found. Setting CleanBrowing DoH
/// level to Standard Blocking"). CE's client-side level vocabulary is
/// `Standard Blocking` / `Strong Blocking` / `Blocking Enabled`.
pub const DEFAULT_FILTER_LEVEL: &str = "Standard Blocking";

/// Schema of the §6.2 table set. The DDL is ours (CE's `ce-user-file` was an
/// opaque encrypted blob — its exact DDL is unrecovered,
/// `user-file.md` §Open questions); the column vocabulary follows
/// `filter-surface.md` §1b/`filter-enforcement.md` verdict c and the §6.2
/// table list. `api_credentials` deliberately has no `password` column (§6.2).
const SETTINGS_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS user_info (username TEXT PRIMARY KEY COLLATE NOCASE, first_name TEXT, last_name TEXT, is_active INTEGER NOT NULL DEFAULT 0, can_override INTEGER NOT NULL DEFAULT 0, timezone TEXT, has_filtering INTEGER NOT NULL DEFAULT 0, has_screen_accountability INTEGER NOT NULL DEFAULT 0, is_panicked INTEGER NOT NULL DEFAULT 0, has_accountability INTEGER NOT NULL DEFAULT 0, has_url_filtering INTEGER NOT NULL DEFAULT 0, has_url_accountability INTEGER NOT NULL DEFAULT 0, has_dns_filtering INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS user_dns_filter (username TEXT PRIMARY KEY COLLATE NOCASE, over_https_url TEXT NOT NULL, level TEXT NOT NULL, ipv4_primary TEXT, ipv4_secondary TEXT, ipv6_primary TEXT, ipv6_secondary TEXT);
CREATE TABLE IF NOT EXISTS global_domain_overrides (domain TEXT PRIMARY KEY COLLATE NOCASE, verdict TEXT NOT NULL CHECK (verdict IN ('allow', 'block', 'na')));
CREATE TABLE IF NOT EXISTS custom_domain_overrides (username TEXT NOT NULL COLLATE NOCASE, domain TEXT NOT NULL COLLATE NOCASE, verdict TEXT NOT NULL CHECK (verdict IN ('allow', 'block', 'na')), PRIMARY KEY (username, domain));
CREATE TABLE IF NOT EXISTS api_credentials (username TEXT PRIMARY KEY COLLATE NOCASE, device_token TEXT NOT NULL, refresh_token TEXT);
"#;

/// Tri-state domain-override verdict (§6.2 `custom_domain_overrides`, §5 code
/// 0x64 payload `{"domain","verdict":"allow"|"block"|"na"}`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    /// Always allow the domain (§8: `UnrestrictedAllowCustom`/`…Global`).
    Allow,
    /// Always block the domain (§8: `BlockedCustom`/`BlockedGlobal`).
    Block,
    /// No override — fall through to the filter path (§6.2 "na").
    Na,
}

impl Verdict {
    /// The stored/wire string (`allow` / `block` / `na`).
    pub const fn as_str(self) -> &'static str {
        match self {
            Verdict::Allow => "allow",
            Verdict::Block => "block",
            Verdict::Na => "na",
        }
    }
}

/// `user_info` row (§6.2; column vocabulary from `filter-surface.md` §1b —
/// the `UserInfoSqliteTable::set` columns, stored as 0/1 integers where CE
/// used `TINYINT`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserInfo {
    /// CE account username (row key).
    pub username: String,
    /// First name.
    pub first_name: Option<String>,
    /// Last name.
    pub last_name: Option<String>,
    /// Account active.
    pub is_active: bool,
    /// Self-override allowed (§9 `can_override`).
    pub can_override: bool,
    /// IANA timezone of the user.
    pub timezone: Option<String>,
    /// Service flag (§9).
    pub has_filtering: bool,
    /// Service flag (§9).
    pub has_screen_accountability: bool,
    /// Panic flag (§9).
    pub is_panicked: bool,
    /// Service flag (§9).
    pub has_accountability: bool,
    /// Service flag (§9).
    pub has_url_filtering: bool,
    /// Service flag (§9).
    pub has_url_accountability: bool,
    /// Service flag (§9).
    pub has_dns_filtering: bool,
}

/// `user_dns_filter` row (§6.2: `over_https_url`, `level`,
/// `ipv4_primary/secondary`, `ipv6_primary/secondary`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserDnsFilter {
    /// CE account username (row key).
    pub username: String,
    /// DoH resolver endpoint of the filter path (§8).
    pub over_https_url: String,
    /// Blocking level; CE vocabulary, see [`DEFAULT_FILTER_LEVEL`].
    pub level: String,
    /// Plain-DNS fallback server (IPv4 primary).
    pub ipv4_primary: Option<String>,
    /// Plain-DNS fallback server (IPv4 secondary).
    pub ipv4_secondary: Option<String>,
    /// Plain-DNS fallback server (IPv6 primary).
    pub ipv6_primary: Option<String>,
    /// Plain-DNS fallback server (IPv6 secondary).
    pub ipv6_secondary: Option<String>,
}

impl UserDnsFilter {
    /// The filter configuration a fresh user starts with — CE's defaults when
    /// no row exists (`filter-surface.md` §1b: default DoH URL + level
    /// "Standard Blocking").
    pub fn default_for(username: &str) -> Self {
        UserDnsFilter {
            username: username.to_string(),
            over_https_url: DEFAULT_DOH_URL.to_string(),
            level: DEFAULT_FILTER_LEVEL.to_string(),
            ipv4_primary: None,
            ipv4_secondary: None,
            ipv6_primary: None,
            ipv6_secondary: None,
        }
    }
}

/// One row of `global_domain_overrides` / `custom_domain_overrides` (§6.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DomainOverride {
    /// Domain the override applies to.
    pub domain: String,
    /// Tri-state verdict (§6.2).
    pub verdict: Verdict,
}

/// `api_credentials` row (§6.2): `device_token`/`refresh_token` only — no
/// password, no HTTP-Basic key pair (§10 Bearer auth).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiCredentials {
    /// CE account username (row key).
    pub username: String,
    /// Revocable device Bearer token (§10).
    pub device_token: String,
    /// Refresh token, if issued.
    pub refresh_token: Option<String>,
}

/// The encrypted per-user settings DB of §6.2.
#[derive(Debug)]
pub struct SettingsDb {
    conn: Connection,
}

impl SettingsDb {
    /// Opens (creating if needed) `db_path` with mode 0600 (§4), loading or
    /// creating the 32-byte `settings.key` keyfile (0600, §6.2) beside it,
    /// keying the connection, and creating the §6.2 table set.
    ///
    /// A wrong key fails fast: the post-key `sqlite_master` probe returns
    /// `SQLITE_NOTADB` for a wrongly-keyed SQLCipher database.
    pub fn open(db_path: &Path, key_path: &Path) -> Result<Self, CoreError> {
        use std::os::unix::fs::OpenOptionsExt;
        use std::os::unix::fs::PermissionsExt;

        let permissions = std::fs::Permissions::from_mode(0o600);
        let key = load_or_create_key(key_path)?;

        // Create the DB file born 0600, then enforce the mode (§4).
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .open(db_path)?;
        std::fs::set_permissions(db_path, permissions.clone())?;

        let conn = Connection::open(db_path)?;
        // SQLCipher: the key must be set before touching any page. Hex form
        // needs no escaping.
        conn.execute_batch(&format!("PRAGMA key = 'x{}';", crate::ids::to_hex(&key)))?;
        // Key verification (wrong key → "file is not a database").
        conn.query_row("SELECT count(*) FROM sqlite_master", [], |_row| Ok(()))?;

        let journal: String = conn.query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))?;
        if journal != "wal" {
            return Err(CoreError::JournalMode(journal));
        }
        conn.execute_batch(SETTINGS_SCHEMA)?;

        // WAL sidecars must not be world-readable either (best effort).
        for suffix in ["-wal", "-shm"] {
            let mut sidecar = db_path.as_os_str().to_owned();
            sidecar.push(suffix);
            let _ = std::fs::set_permissions(std::path::Path::new(&sidecar), permissions.clone());
        }
        Ok(Self { conn })
    }

    /// Lazy `ALTER TABLE` migration helper (§6.2: "Lazy `ALTER TABLE`
    /// migrations like CE").
    ///
    /// Ensures `table` has `column` declared as `decl` (e.g. `"TEXT"` or
    /// `"INTEGER NOT NULL DEFAULT 0"`), adding it with `ALTER TABLE … ADD
    /// COLUMN` when missing. Returns `true` when a column was added.
    ///
    /// `table`/`column` must match `[A-Za-z0-9_]+` and `decl` may only contain
    /// `[A-Za-z0-9_ '(),.-]` — identifiers cannot be parameterized, so
    /// anything else is rejected with [`CoreError::InvalidIdentifier`].
    pub fn ensure_column(
        &mut self,
        table: &str,
        column: &str,
        decl: &str,
    ) -> Result<bool, CoreError> {
        check_ident(table)?;
        check_ident(column)?;
        check_decl(decl)?;

        let mut present = false;
        {
            let mut stmt = self.conn.prepare(&format!("PRAGMA table_info({table})"))?;
            let mut rows = stmt.query([])?;
            while let Some(row) = rows.next()? {
                let name: String = row.get(1)?;
                if name == column {
                    present = true;
                    break;
                }
            }
        }
        if present {
            return Ok(false);
        }
        self.conn
            .execute_batch(&format!("ALTER TABLE {table} ADD COLUMN {column} {decl}"))?;
        Ok(true)
    }

    /// Stores a `user_info` row (upsert, §6.2).
    pub fn set_user_info(&mut self, info: &UserInfo) -> Result<(), CoreError> {
        self.conn.execute(
            "INSERT INTO user_info (username, first_name, last_name, is_active, can_override, timezone, has_filtering, has_screen_accountability, is_panicked, has_accountability, has_url_filtering, has_url_accountability, has_dns_filtering) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13) ON CONFLICT(username) DO UPDATE SET first_name = excluded.first_name, last_name = excluded.last_name, is_active = excluded.is_active, can_override = excluded.can_override, timezone = excluded.timezone, has_filtering = excluded.has_filtering, has_screen_accountability = excluded.has_screen_accountability, is_panicked = excluded.is_panicked, has_accountability = excluded.has_accountability, has_url_filtering = excluded.has_url_filtering, has_url_accountability = excluded.has_url_accountability, has_dns_filtering = excluded.has_dns_filtering",
            params![
                info.username,
                info.first_name,
                info.last_name,
                info.is_active,
                info.can_override,
                info.timezone,
                info.has_filtering,
                info.has_screen_accountability,
                info.is_panicked,
                info.has_accountability,
                info.has_url_filtering,
                info.has_url_accountability,
                info.has_dns_filtering,
            ],
        )?;
        Ok(())
    }

    /// Reads a `user_info` row (§6.2).
    pub fn get_user_info(&self, username: &str) -> Result<Option<UserInfo>, CoreError> {
        let info = self
            .conn
            .query_row(
                "SELECT username, first_name, last_name, is_active, can_override, timezone, has_filtering, has_screen_accountability, is_panicked, has_accountability, has_url_filtering, has_url_accountability, has_dns_filtering FROM user_info WHERE username = ?1",
                params![username],
                |row| {
                    Ok(UserInfo {
                        username: row.get(0)?,
                        first_name: row.get(1)?,
                        last_name: row.get(2)?,
                        is_active: row.get(3)?,
                        can_override: row.get(4)?,
                        timezone: row.get(5)?,
                        has_filtering: row.get(6)?,
                        has_screen_accountability: row.get(7)?,
                        is_panicked: row.get(8)?,
                        has_accountability: row.get(9)?,
                        has_url_filtering: row.get(10)?,
                        has_url_accountability: row.get(11)?,
                        has_dns_filtering: row.get(12)?,
                    })
                },
            )
            .optional()?;
        Ok(info)
    }

    /// Stores a `user_dns_filter` row (upsert, §6.2).
    pub fn set_dns_filter(&mut self, filter: &UserDnsFilter) -> Result<(), CoreError> {
        self.conn.execute(
            "INSERT INTO user_dns_filter (username, over_https_url, level, ipv4_primary, ipv4_secondary, ipv6_primary, ipv6_secondary) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7) ON CONFLICT(username) DO UPDATE SET over_https_url = excluded.over_https_url, level = excluded.level, ipv4_primary = excluded.ipv4_primary, ipv4_secondary = excluded.ipv4_secondary, ipv6_primary = excluded.ipv6_primary, ipv6_secondary = excluded.ipv6_secondary",
            params![
                filter.username,
                filter.over_https_url,
                filter.level,
                filter.ipv4_primary,
                filter.ipv4_secondary,
                filter.ipv6_primary,
                filter.ipv6_secondary,
            ],
        )?;
        Ok(())
    }

    /// Reads a `user_dns_filter` row (§6.2); `None` when the user has no row
    /// yet (use [`UserDnsFilter::default_for`]).
    pub fn get_dns_filter(&self, username: &str) -> Result<Option<UserDnsFilter>, CoreError> {
        let filter = self
            .conn
            .query_row(
                "SELECT username, over_https_url, level, ipv4_primary, ipv4_secondary, ipv6_primary, ipv6_secondary FROM user_dns_filter WHERE username = ?1",
                params![username],
                |row| {
                    Ok(UserDnsFilter {
                        username: row.get(0)?,
                        over_https_url: row.get(1)?,
                        level: row.get(2)?,
                        ipv4_primary: row.get(3)?,
                        ipv4_secondary: row.get(4)?,
                        ipv6_primary: row.get(5)?,
                        ipv6_secondary: row.get(6)?,
                    })
                },
            )
            .optional()?;
        Ok(filter)
    }

    /// Inserts/updates a global (all-users) domain override (§6.2).
    pub fn set_global_override(&mut self, domain: &str, verdict: Verdict) -> Result<(), CoreError> {
        self.conn.execute(
            "INSERT INTO global_domain_overrides (domain, verdict) VALUES (?1, ?2) ON CONFLICT(domain) DO UPDATE SET verdict = excluded.verdict",
            params![domain, verdict.as_str()],
        )?;
        Ok(())
    }

    /// Removes a global domain override (§6.2). Returns whether a row was
    /// removed.
    pub fn delete_global_override(&mut self, domain: &str) -> Result<bool, CoreError> {
        let changed = self
            .conn
            .execute("DELETE FROM global_domain_overrides WHERE domain = ?1", params![domain])?;
        Ok(changed > 0)
    }

    /// Lists all global domain overrides (§6.2), domain-ordered.
    pub fn list_global_overrides(&self) -> Result<Vec<DomainOverride>, CoreError> {
        let mut stmt = self
            .conn
            .prepare("SELECT domain, verdict FROM global_domain_overrides ORDER BY domain")?;
        let rows = stmt.query_map([], override_row)?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    /// Inserts/updates a per-user domain override (§6.2).
    pub fn set_custom_override(
        &mut self,
        username: &str,
        domain: &str,
        verdict: Verdict,
    ) -> Result<(), CoreError> {
        self.conn.execute(
            "INSERT INTO custom_domain_overrides (username, domain, verdict) VALUES (?1, ?2, ?3) ON CONFLICT(username, domain) DO UPDATE SET verdict = excluded.verdict",
            params![username, domain, verdict.as_str()],
        )?;
        Ok(())
    }

    /// Removes a per-user domain override (§6.2). Returns whether a row was
    /// removed.
    pub fn delete_custom_override(
        &mut self,
        username: &str,
        domain: &str,
    ) -> Result<bool, CoreError> {
        let changed = self.conn.execute(
            "DELETE FROM custom_domain_overrides WHERE username = ?1 AND domain = ?2",
            params![username, domain],
        )?;
        Ok(changed > 0)
    }

    /// Lists one user's domain overrides (§6.2), domain-ordered.
    pub fn list_custom_overrides(&self, username: &str) -> Result<Vec<DomainOverride>, CoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT domain, verdict FROM custom_domain_overrides WHERE username = ?1 ORDER BY domain",
        )?;
        let rows = stmt.query_map(params![username], override_row)?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    /// Stores `api_credentials` (upsert, §6.2 — tokens only, never a
    /// password).
    pub fn set_api_credentials(&mut self, credentials: &ApiCredentials) -> Result<(), CoreError> {
        self.conn.execute(
            "INSERT INTO api_credentials (username, device_token, refresh_token) VALUES (?1, ?2, ?3) ON CONFLICT(username) DO UPDATE SET device_token = excluded.device_token, refresh_token = excluded.refresh_token",
            params![
                credentials.username,
                credentials.device_token,
                credentials.refresh_token
            ],
        )?;
        Ok(())
    }

    /// Reads `api_credentials` (§6.2).
    pub fn get_api_credentials(
        &self,
        username: &str,
    ) -> Result<Option<ApiCredentials>, CoreError> {
        let credentials = self
            .conn
            .query_row(
                "SELECT username, device_token, refresh_token FROM api_credentials WHERE username = ?1",
                params![username],
                |row| {
                    Ok(ApiCredentials {
                        username: row.get(0)?,
                        device_token: row.get(1)?,
                        refresh_token: row.get(2)?,
                    })
                },
            )
            .optional()?;
        Ok(credentials)
    }

    /// Signs out locally by clearing the stored tokens (§6.2/§10). Returns
    /// whether a row was removed.
    pub fn clear_api_credentials(&mut self, username: &str) -> Result<bool, CoreError> {
        let changed = self
            .conn
            .execute("DELETE FROM api_credentials WHERE username = ?1", params![username])?;
        Ok(changed > 0)
    }
}

/// Loads the 32-byte `settings.key` (§6.2) or creates it with 32 random bytes
/// at mode 0600 (§4). Existing files are re-used (and re-normalized to 0600).
pub fn load_or_create_key(path: &Path) -> Result<Vec<u8>, CoreError> {
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::fs::PermissionsExt;

    match std::fs::read(path) {
        Ok(key) => checked_key(key, path),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            let mut key = [0u8; KEY_LEN];
            rand::thread_rng().fill_bytes(&mut key);

            let mut options = std::fs::OpenOptions::new();
            options.write(true).create_new(true).mode(0o600);
            match options.open(path) {
                Ok(mut file) => {
                    use std::io::Write;
                    file.write_all(&key)?;
                    file.sync_all()?;
                    // Force 0600 independent of the creating process's umask.
                    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
                    Ok(key.to_vec())
                }
                Err(create_err) if create_err.kind() == std::io::ErrorKind::AlreadyExists => {
                    // Lost a create race: load the winner's key (§6.2
                    // load-or-create).
                    checked_key(std::fs::read(path)?, path)
                }
                Err(create_err) => Err(create_err.into()),
            }
        }
        Err(err) => Err(err.into()),
    }
}

/// Validates a loaded keyfile: exactly [`KEY_LEN`] bytes, enforced mode 0600.
fn checked_key(key: Vec<u8>, path: &Path) -> Result<Vec<u8>, CoreError> {
    if key.len() != KEY_LEN {
        return Err(CoreError::KeyFile(format!(
            "{}: expected {KEY_LEN} bytes, found {}",
            path.display(),
            key.len()
        )));
    }
    std::fs::set_permissions(
        path,
        <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o600),
    )?;
    Ok(key)
}

/// Identifier validation for [`SettingsDb::ensure_column`] (identifiers cannot
/// be SQL-parameterized).
fn check_ident(name: &str) -> Result<(), CoreError> {
    if name.is_empty()
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_')
    {
        return Err(CoreError::InvalidIdentifier(name.to_string()));
    }
    Ok(())
}

/// Declaration validation for [`SettingsDb::ensure_column`]: type/constraint
/// words only.
fn check_decl(decl: &str) -> Result<(), CoreError> {
    if decl.is_empty()
        || !decl.chars().all(|c| {
            c.is_ascii_alphanumeric()
                || matches!(c, ' ' | '_' | '(' | ')' | '\'' | ',' | '.' | '-')
        })
    {
        return Err(CoreError::InvalidIdentifier(decl.to_string()));
    }
    Ok(())
}

/// Maps one `(domain, verdict)` row (§6.2).
fn override_row(row: &rusqlite::Row<'_>) -> Result<DomainOverride, rusqlite::Error> {
    let domain: String = row.get(0)?;
    let verdict: String = row.get(1)?;
    let verdict = match verdict.as_str() {
        "allow" => Verdict::Allow,
        "block" => Verdict::Block,
        "na" => Verdict::Na,
        other => {
            return Err(rusqlite::Error::FromSqlConversionFailure(
                1,
                rusqlite::types::Type::Text,
                Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("unknown verdict {other:?}"),
                )),
            ))
        }
    };
    Ok(DomainOverride { domain, verdict })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::TempDir;
    use std::os::unix::fs::PermissionsExt;

    struct Harness {
        _dir: TempDir,
        db: SettingsDb,
        key_path: std::path::PathBuf,
        db_path: std::path::PathBuf,
    }

    fn open(tag: &str) -> Harness {
        let dir = TempDir::new(tag);
        let db_path = dir.path().join("settings.db");
        let key_path = dir.path().join("settings.key");
        let db = SettingsDb::open(&db_path, &key_path).expect("open settings db");
        Harness {
            _dir: dir,
            db,
            key_path,
            db_path,
        }
    }

    fn table_columns(db: &SettingsDb, table: &str) -> Vec<String> {
        let mut stmt = db
            .conn
            .prepare(&format!("PRAGMA table_info({table})"))
            .expect("table_info");
        let rows = stmt
            .query_map([], |row| row.get::<_, String>(1))
            .expect("rows");
        rows.collect::<Result<Vec<_>, _>>().expect("columns")
    }

    fn table_exists(db: &SettingsDb, table: &str) -> bool {
        db.conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
                params![table],
                |row| row.get::<_, i64>(0),
            )
            .expect("sqlite_master")
            > 0
    }

    #[test]
    fn open_creates_key_db_and_section_6_2_tables() {
        let harness = open("open");

        // Key file: exactly 32 bytes, mode 0600 (§6.2/§4).
        let key = std::fs::read(&harness.key_path).expect("key file");
        assert_eq!(key.len(), KEY_LEN);
        let key_mode = std::fs::metadata(&harness.key_path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(key_mode, 0o600, "settings.key must be 0600");

        // DB file: mode 0600 (§4) and *encrypted* (not a plaintext SQLite
        // header — SQLCipher with a key, §6.2).
        let db_mode = std::fs::metadata(&harness.db_path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(db_mode, 0o600, "settings.db must be 0600");
        let header = std::fs::read(&harness.db_path).expect("db file");
        assert!(
            header.len() >= 16 && &header[..16] != b"SQLite format 3\0",
            "settings.db must not be a plaintext SQLite file"
        );

        // §6.2 table set.
        for table in [
            "user_info",
            "user_dns_filter",
            "global_domain_overrides",
            "custom_domain_overrides",
            "api_credentials",
        ] {
            assert!(table_exists(&harness.db, table), "missing table {table}");
        }

        // §6.2 deviation: api_credentials carries tokens only — no `password`
        // column (and no CE Basic-auth key pair).
        assert_eq!(
            table_columns(&harness.db, "api_credentials"),
            vec!["username", "device_token", "refresh_token"]
        );
    }

    #[test]
    fn key_is_loaded_not_regenerated_across_opens() {
        let dir = TempDir::new("key-reuse");
        let db_path = dir.path().join("settings.db");
        let key_path = dir.path().join("settings.key");

        let first = load_or_create_key(&key_path).expect("create");
        assert_eq!(first.len(), KEY_LEN);
        let second = load_or_create_key(&key_path).expect("load");
        assert_eq!(first, second, "existing key must be re-used");

        // And the DB opens again with the persisted key.
        drop(SettingsDb::open(&db_path, &key_path).expect("reopen"));
        // A short keyfile is rejected (§6.2: 32 bytes).
        std::fs::write(&key_path, [0u8; 8]).expect("short key");
        let err = load_or_create_key(&key_path).unwrap_err();
        assert!(matches!(err, CoreError::KeyFile(_)), "{err:?}");
    }

    #[test]
    fn wrong_key_is_rejected() {
        let dir = TempDir::new("wrong-key");
        let db_path = dir.path().join("settings.db");
        let key_path = dir.path().join("settings.key");

        drop(SettingsDb::open(&db_path, &key_path).expect("first open"));
        // Overwrite the keyfile with different (32-byte) material.
        std::fs::write(&key_path, [7u8; KEY_LEN]).expect("wrong key");
        let err = SettingsDb::open(&db_path, &key_path).unwrap_err();
        assert!(matches!(err, CoreError::Db(_)), "wrong key must fail: {err:?}");
    }

    #[test]
    fn user_info_round_trips() {
        let mut harness = open("user-info");
        let info = UserInfo {
            username: "alice".into(),
            first_name: Some("Al".into()),
            last_name: Some("Ice".into()),
            is_active: true,
            can_override: false,
            timezone: Some("America/Chicago".into()),
            has_filtering: true,
            has_screen_accountability: false,
            is_panicked: false,
            has_accountability: true,
            has_url_filtering: true,
            has_url_accountability: false,
            has_dns_filtering: true,
        };
        assert!(harness.db.get_user_info("alice").unwrap().is_none());
        harness.db.set_user_info(&info).expect("insert");
        assert_eq!(harness.db.get_user_info("alice").unwrap(), Some(info.clone()));

        // Upsert updates in place.
        let mut changed = info.clone();
        changed.is_panicked = true;
        changed.first_name = None;
        harness.db.set_user_info(&changed).expect("update");
        assert_eq!(harness.db.get_user_info("alice").unwrap(), Some(changed));

        // Other users are independent; lookups are case-insensitive (key
        // COLLATE NOCASE).
        assert!(harness.db.get_user_info("bob").unwrap().is_none());
        assert!(harness.db.get_user_info("ALICE").unwrap().is_some());
    }

    #[test]
    fn dns_filter_defaults_and_round_trip() {
        let mut harness = open("dns-filter");
        // No row yet (§6.2/§1b defaults available for a fresh user).
        assert!(harness.db.get_dns_filter("alice").unwrap().is_none());
        let fresh = UserDnsFilter::default_for("alice");
        assert_eq!(fresh.over_https_url, DEFAULT_DOH_URL);
        assert_eq!(fresh.level, DEFAULT_FILTER_LEVEL);

        let mut filter = fresh;
        filter.level = "Strong Blocking".into();
        filter.ipv4_primary = Some("1.1.1.1".into());
        filter.ipv6_primary = Some("2606:4700::1111".into());
        harness.db.set_dns_filter(&filter).expect("insert");
        assert_eq!(
            harness.db.get_dns_filter("alice").unwrap(),
            Some(filter.clone())
        );

        filter.level = "Standard Blocking".into();
        harness.db.set_dns_filter(&filter).expect("update");
        assert_eq!(
            harness.db.get_dns_filter("alice").unwrap().unwrap().level,
            "Standard Blocking"
        );
        assert!(harness.db.get_dns_filter("bob").unwrap().is_none());
    }

    #[test]
    fn overrides_enforce_the_tri_state() {
        let mut harness = open("overrides");
        // Global list (no username column — read by the forwarder for everyone).
        harness
            .db
            .set_global_override("ads.example", Verdict::Block)
            .unwrap();
        harness
            .db
            .set_global_override("ok.example", Verdict::Allow)
            .unwrap();
        harness
            .db
            .set_global_override("neutral.example", Verdict::Na)
            .unwrap();
        // Upsert flips a verdict in place.
        harness
            .db
            .set_global_override("ads.example", Verdict::Allow)
            .unwrap();
        let globals = harness.db.list_global_overrides().unwrap();
        assert_eq!(
            globals,
            vec![
                DomainOverride {
                    domain: "ads.example".into(),
                    verdict: Verdict::Allow
                },
                DomainOverride {
                    domain: "neutral.example".into(),
                    verdict: Verdict::Na
                },
                DomainOverride {
                    domain: "ok.example".into(),
                    verdict: Verdict::Allow
                },
            ]
        );
        assert!(harness.db.delete_global_override("ads.example").unwrap());
        assert!(!harness.db.delete_global_override("ads.example").unwrap());

        // Per-user overrides.
        harness
            .db
            .set_custom_override("alice", "games.example", Verdict::Block)
            .unwrap();
        harness
            .db
            .set_custom_override("alice", "news.example", Verdict::Na)
            .unwrap();
        harness
            .db
            .set_custom_override("bob", "games.example", Verdict::Allow)
            .unwrap();
        let alice = harness.db.list_custom_overrides("alice").unwrap();
        assert_eq!(
            alice,
            vec![
                DomainOverride {
                    domain: "games.example".into(),
                    verdict: Verdict::Block
                },
                DomainOverride {
                    domain: "news.example".into(),
                    verdict: Verdict::Na
                },
            ]
        );
        assert_eq!(
            harness.db.list_custom_overrides("bob").unwrap(),
            vec![DomainOverride {
                domain: "games.example".into(),
                verdict: Verdict::Allow
            }]
        );
        assert!(harness
            .db
            .delete_custom_override("alice", "games.example")
            .unwrap());
        assert_eq!(harness.db.list_custom_overrides("alice").unwrap().len(), 1);

        // The CHECK constraint rejects anything outside allow/block/na (§6.2).
        let err = harness
            .db
            .conn
            .execute(
                "INSERT INTO global_domain_overrides (domain, verdict) VALUES ('bad.example', 'maybe')",
                [],
            )
            .unwrap_err();
        assert!(matches!(err, rusqlite::Error::SqliteFailure(_, _)), "{err:?}");
    }

    #[test]
    fn credentials_round_trip_tokens_only() {
        let mut harness = open("credentials");
        let credentials = ApiCredentials {
            username: "alice".into(),
            device_token: "device-token-value".into(),
            refresh_token: Some("refresh-token-value".into()),
        };
        assert!(harness.db.get_api_credentials("alice").unwrap().is_none());
        harness
            .db
            .set_api_credentials(&credentials)
            .expect("insert");
        assert_eq!(
            harness.db.get_api_credentials("alice").unwrap(),
            Some(credentials.clone())
        );

        // Rotation overwrites both tokens.
        let mut rotated = credentials.clone();
        rotated.device_token = "rotated-device".into();
        rotated.refresh_token = None;
        harness.db.set_api_credentials(&rotated).expect("rotate");
        assert_eq!(
            harness.db.get_api_credentials("alice").unwrap(),
            Some(rotated)
        );

        // Sign-out clears the row (§10 SIGN_OUT → no stored credential).
        assert!(harness.db.clear_api_credentials("alice").unwrap());
        assert!(!harness.db.clear_api_credentials("alice").unwrap());
        assert!(harness.db.get_api_credentials("alice").unwrap().is_none());
    }

    #[test]
    fn ensure_column_is_the_lazy_migration_helper() {
        let mut harness = open("migrations");

        // First run adds the column, second run is a no-op (§6.2 lazy ALTER).
        assert!(harness
            .db
            .ensure_column("user_info", "nickname", "TEXT")
            .unwrap());
        assert!(!harness
            .db
            .ensure_column("user_info", "nickname", "TEXT")
            .unwrap());
        assert!(table_columns(&harness.db, "user_info").contains(&"nickname".to_string()));

        // The added column is usable immediately.
        let info = UserInfo {
            username: "alice".into(),
            first_name: None,
            last_name: None,
            is_active: true,
            can_override: true,
            timezone: None,
            has_filtering: false,
            has_screen_accountability: false,
            is_panicked: false,
            has_accountability: false,
            has_url_filtering: false,
            has_url_accountability: false,
            has_dns_filtering: false,
        };
        harness.db.set_user_info(&info).unwrap();
        assert!(harness.db.get_user_info("alice").unwrap().is_some());

        // Hostile identifiers/declarations are rejected (they cannot be
        // parameterized).
        let err = harness
            .db
            .ensure_column("user_info; DROP TABLE user_info", "x", "TEXT")
            .unwrap_err();
        assert!(matches!(err, CoreError::InvalidIdentifier(_)), "{err:?}");
        let err = harness
            .db
            .ensure_column("user_info", "x; DROP TABLE user_info", "TEXT")
            .unwrap_err();
        assert!(matches!(err, CoreError::InvalidIdentifier(_)), "{err:?}");
        let err = harness
            .db
            .ensure_column("user_info", "x", "TEXT; DROP TABLE user_info")
            .unwrap_err();
        assert!(matches!(err, CoreError::InvalidIdentifier(_)), "{err:?}");

        // The hostile attempt left the table intact.
        assert!(table_exists(&harness.db, "user_info"));
    }
}
