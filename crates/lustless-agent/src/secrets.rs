//! Session-token storage for the agent (CONTRACTS §13: "stores its session
//! token in the user keyring via libsecret when available").
//!
//! The "libsecret when available" contract is implemented against the
//! freedesktop **Secret Service** D-Bus API (`org.freedesktop.secrets`) — the
//! service that GNOME Keyring / KWallet's secret-service bridge expose and
//! the endpoint libsecret itself speaks — via zbus, so the agent needs no
//! libsecret build dependency. "Available" is decided at runtime: if the
//! session bus or the secret service cannot serve the store operation, the
//! token falls back to a 0600 file under `XDG_RUNTIME_DIR` (cleared on
//! sign-out). Tokens are never logged.

use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

/// Attribute key marking our items in the keyring.
const SCHEMA_ATTR: &str = "xdg:schema";
/// The schema value (reverse-DNS, like libsecret schemas).
const SCHEMA_VALUE: &str = "org.lustless.SessionToken";
/// Application attribute so keyring UIs group our items.
const APP_ATTR: &str = "application";
/// The agent's application id (§13 `GApplication` id).
const APP_VALUE: &str = "org.lustless.agent";
/// Service attribute.
const SERVICE_ATTR: &str = "service";
const SERVICE_VALUE: &str = "lustless";

/// Where a token ended up — for the operator-facing log line (never the
/// token itself).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    /// The desktop keyring (Secret Service).
    Keyring,
    /// The 0600 runtime file fallback.
    File,
}

/// Sanitizes a username into a safe file-name component (no path traversal).
fn file_component(username: &str) -> String {
    let cleaned: String = username
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') {
                c
            } else {
                '_'
            }
        })
        .collect();
    if cleaned.is_empty() {
        "_".to_string()
    } else {
        cleaned
    }
}

/// The fallback token file: `$XDG_RUNTIME_DIR/lustless-agent/session-token-<user>`
/// (0600 in a 0700 directory — `XDG_RUNTIME_DIR` itself is 0700, §4 spirit).
pub fn token_file(username: &str) -> PathBuf {
    let base = std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
        .join("lustless-agent");
    base.join(format!("session-token-{}", file_component(username)))
}

fn write_token_file(path: &PathBuf, token: &str) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
    }
    let mut file = {
        use std::os::unix::fs::OpenOptionsExt;
        OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?
    };
    // `mode` only applies at creation — enforce it for pre-existing files too.
    file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    file.write_all(token.as_bytes())?;
    file.flush()
}

fn read_token_file(path: &PathBuf) -> Option<String> {
    let mut file = std::fs::File::open(path).ok()?;
    let mut token = String::new();
    file.read_to_string(&mut token).ok()?;
    let token = token.trim().to_string();
    if token.is_empty() {
        None
    } else {
        Some(token)
    }
}

/// Stores the sign-in token (§5 0x65 reply). Tries the Secret Service first;
/// falls back to the 0600 file. Returns which backend won (for logging — the
/// token itself never leaves this module's callers unreturned).
pub fn store(username: &str, token: &str) -> Backend {
    match secret_service::store(username, token) {
        Ok(()) => Backend::Keyring,
        Err(err) => {
            tracing::debug!(target: "agent", "secret service unavailable for store ({err}); using the 0600 runtime file");
            let path = token_file(username);
            if let Err(err) = write_token_file(&path, token) {
                tracing::error!(target: "agent", "token file write failed: {err}");
            }
            Backend::File
        }
    }
}

/// Loads the stored token: Secret Service first, then the file fallback.
pub fn load(username: &str) -> Option<String> {
    match secret_service::load(username) {
        Ok(Some(token)) => Some(token),
        Ok(None) => read_token_file(&token_file(username)),
        Err(err) => {
            tracing::debug!(target: "agent", "secret service unavailable for load ({err}); trying the runtime file");
            read_token_file(&token_file(username))
        }
    }
}

/// Removes the token from both backends (sign-out, §5 0x66).
pub fn clear(username: &str) {
    if let Err(err) = secret_service::clear(username) {
        tracing::debug!(target: "agent", "secret service unavailable for clear ({err})");
    }
    let path = token_file(username);
    if let Err(err) = std::fs::remove_file(&path) {
        if err.kind() != std::io::ErrorKind::NotFound {
            tracing::warn!(target: "agent", "token file removal failed: {err}");
        }
    }
}

/// The `org.freedesktop.secrets` client (the libsecret-equivalent path).
mod secret_service {
    use std::collections::HashMap;

    use zbus::zvariant::{Dict, OwnedObjectPath, OwnedValue, Signature, Value};

    use super::{APP_ATTR, APP_VALUE, SCHEMA_ATTR, SCHEMA_VALUE, SERVICE_ATTR, SERVICE_VALUE};

    const SERVICE: &str = "org.freedesktop.secrets";
    const OBJECT: &str = "/org/freedesktop/secrets";
    const IFACE_SERVICE: &str = "org.freedesktop.secrets.Service";
    const IFACE_ITEM: &str = "org.freedesktop.secrets.Item";
    const COLLECTION: &str = "/org/freedesktop/secrets/aliases/default";

    fn attrs(username: &str) -> HashMap<String, String> {
        let mut attrs = HashMap::new();
        attrs.insert(SCHEMA_ATTR.to_string(), SCHEMA_VALUE.to_string());
        attrs.insert(APP_ATTR.to_string(), APP_VALUE.to_string());
        attrs.insert(SERVICE_ATTR.to_string(), SERVICE_VALUE.to_string());
        attrs.insert("username".to_string(), username.to_string());
        attrs
    }

    /// Opens a "plain" session — the §13/Secret-Spec path libsecret uses.
    ///
    /// The spec's input for `plain` is an empty variant; the variant always
    /// wraps *something* on this codec, so we send the emptiest legal value
    /// (an empty byte array). Implementations that validate strictly reject
    /// it, which surfaces as an error here and triggers the documented file
    /// fallback — never a failure of the agent itself.
    fn open_session(conn: &zbus::blocking::Connection) -> Result<OwnedObjectPath, String> {
        let service = zbus::blocking::Proxy::new(conn, SERVICE, OBJECT, IFACE_SERVICE)
            .map_err(|err| err.to_string())?;
        let empty_array = Value::Array(zbus::zvariant::Array::new(&Signature::U8));
        let (session, _result): (OwnedObjectPath, OwnedValue) = service
            .call(
                "OpenSession",
                &("plain", Value::Value(Box::new(empty_array))),
            )
            .map_err(|err| err.to_string())?;
        Ok(session)
    }

    fn search_items(
        conn: &zbus::blocking::Connection,
        username: &str,
    ) -> Result<Vec<OwnedObjectPath>, String> {
        let service = zbus::blocking::Proxy::new(conn, SERVICE, OBJECT, IFACE_SERVICE)
            .map_err(|err| err.to_string())?;
        let attributes = Value::Dict(Dict::from(attrs(username)));
        let (mut unlocked, locked): (Vec<OwnedObjectPath>, Vec<OwnedObjectPath>) = service
            .call("SearchItems", &attributes)
            .map_err(|err| err.to_string())?;
        if !locked.is_empty() {
            let (opened, _still): (Vec<OwnedObjectPath>, Vec<OwnedObjectPath>) = service
                .call("Unlock", &locked)
                .map_err(|err| err.to_string())?;
            unlocked.extend(opened);
        }
        Ok(unlocked)
    }

    fn item_proxy<'a>(
        conn: &'a zbus::blocking::Connection,
        path: &'a OwnedObjectPath,
    ) -> Result<zbus::blocking::Proxy<'a>, String> {
        zbus::blocking::Proxy::new(conn, SERVICE, path.as_str(), IFACE_ITEM)
            .map_err(|err| err.to_string())
    }

    pub fn store(username: &str, token: &str) -> Result<(), String> {
        let conn = zbus::blocking::Connection::session().map_err(|err| err.to_string())?;
        let session = open_session(&conn)?;
        // Replace semantics: drop any previous item for these attributes.
        for path in search_items(&conn, username)? {
            let item = item_proxy(&conn, &path)?;
            let _: OwnedValue = item.call("Delete", &()).map_err(|err| err.to_string())?;
        }
        let mut properties: HashMap<String, Value> = HashMap::new();
        properties.insert(
            "label".to_string(),
            Value::from(format!("LustLess session token ({username})")),
        );
        properties.insert(
            "attributes".to_string(),
            Value::Dict(Dict::from(attrs(username))),
        );
        let secret = (
            session,
            Vec::<u8>::new(),
            token.as_bytes().to_vec(),
            "text/plain".to_string(),
        );
        let collection: OwnedObjectPath = COLLECTION
            .try_into()
            .map_err(|err: zbus::zvariant::Error| err.to_string())?;
        let service = zbus::blocking::Proxy::new(&conn, SERVICE, OBJECT, IFACE_SERVICE)
            .map_err(|err| err.to_string())?;
        let _: OwnedObjectPath = service
            .call("CreateItem", &(collection, properties, secret, true))
            .map_err(|err| err.to_string())?;
        Ok(())
    }

    pub fn load(username: &str) -> Result<Option<String>, String> {
        let conn = zbus::blocking::Connection::session().map_err(|err| err.to_string())?;
        let session = open_session(&conn)?;
        let items = search_items(&conn, username)?;
        let Some(path) = items.into_iter().next() else {
            return Ok(None);
        };
        let service = zbus::blocking::Proxy::new(&conn, SERVICE, OBJECT, IFACE_SERVICE)
            .map_err(|err| err.to_string())?;
        let reply: OwnedValue = service
            .call("GetSecrets", &(vec![path.clone()], session))
            .map_err(|err| err.to_string())?;
        let Value::Dict(secrets) = &*reply else {
            return Err("GetSecrets returned no dict".to_string());
        };
        let needle = path.as_str();
        let secret = secrets
            .iter()
            .find(|(key, _)| matches!(key, Value::ObjectPath(p) if p.as_str() == needle))
            .map(|(_, value)| value);
        let Some(Value::Structure(fields)) = secret else {
            return Ok(None);
        };
        // Secret struct: (session o, params ay, value ay, content_type s).
        match fields.fields().get(2) {
            Some(Value::Array(bytes)) => {
                let token: Vec<u8> = bytes
                    .inner()
                    .iter()
                    .map(|value| match value {
                        Value::U8(byte) => Ok(*byte),
                        _ => Err("non-byte element in secret value"),
                    })
                    .collect::<Result<_, _>>()
                    .map_err(|err| err.to_string())?;
                String::from_utf8(token)
                    .map(Some)
                    .map_err(|err| format!("secret is not UTF-8: {err}"))
            }
            _ => Ok(None),
        }
    }

    pub fn clear(username: &str) -> Result<(), String> {
        let conn = zbus::blocking::Connection::session().map_err(|err| err.to_string())?;
        for path in search_items(&conn, username)? {
            let item = item_proxy(&conn, &path)?;
            let _: OwnedValue = item.call("Delete", &()).map_err(|err| err.to_string())?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt;

    /// Isolates `XDG_RUNTIME_DIR` for the file backend. Env vars are
    /// process-global, so every env-touching test serializes on this lock.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    struct RuntimeDirGuard {
        previous: Option<std::ffi::OsString>,
        _lock: std::sync::MutexGuard<'static, ()>,
    }

    impl RuntimeDirGuard {
        fn enter(dir: &std::path::Path) -> Self {
            let lock = ENV_LOCK.lock().unwrap_or_else(|err| err.into_inner());
            let previous = std::env::var_os("XDG_RUNTIME_DIR");
            std::env::set_var("XDG_RUNTIME_DIR", dir);
            RuntimeDirGuard {
                previous,
                _lock: lock,
            }
        }
    }

    impl Drop for RuntimeDirGuard {
        fn drop(&mut self) {
            match &self.previous {
                Some(previous) => std::env::set_var("XDG_RUNTIME_DIR", previous),
                None => std::env::remove_var("XDG_RUNTIME_DIR"),
            }
        }
    }

    #[test]
    fn token_file_is_0600_and_round_trips() {
        let dir = tempfile::tempdir().expect("tempdir");
        let _guard = RuntimeDirGuard::enter(dir.path());
        let path = token_file("alice");
        write_token_file(&path, "s3cret-token").expect("write");
        let mode = std::fs::metadata(&path).expect("metadata").mode() & 0o777;
        assert_eq!(mode, 0o600, "token file must be 0600");
        let dir_mode = std::fs::metadata(path.parent().expect("parent"))
            .expect("dir metadata")
            .mode()
            & 0o777;
        assert_eq!(dir_mode, 0o700, "token dir must be 0700");
        assert_eq!(read_token_file(&path).as_deref(), Some("s3cret-token"));
    }

    #[test]
    fn rewrite_forces_0600_even_on_a_world_readable_leftover() {
        let dir = tempfile::tempdir().expect("tempdir");
        let _guard = RuntimeDirGuard::enter(dir.path());
        let path = token_file("alice");
        std::fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
        // Plant a permissive leftover file, then store over it.
        std::fs::write(&path, "old").expect("plant");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("chmod");
        write_token_file(&path, "new-token").expect("rewrite");
        let mode = std::fs::metadata(&path).expect("metadata").mode() & 0o777;
        assert_eq!(mode, 0o600, "rewrite must restore 0600");
        assert_eq!(read_token_file(&path).as_deref(), Some("new-token"));
    }

    #[test]
    fn usernames_are_sanitized_in_file_names() {
        let path = token_file("../../etc/passwd");
        let name = path
            .file_name()
            .expect("file name")
            .to_string_lossy()
            .into_owned();
        assert!(!name.contains('/'), "no separators may survive");
        assert!(name.starts_with("session-token-"));
        assert_eq!(token_file(""), token_file("_"));
    }

    #[test]
    fn load_falls_back_to_the_file_when_the_keyring_is_absent() {
        let dir = tempfile::tempdir().expect("tempdir");
        let _guard = RuntimeDirGuard::enter(dir.path());
        let path = token_file("bob");
        write_token_file(&path, "file-token").expect("write");
        // With no session bus in the test environment the Secret Service
        // path fails and `load` must land on the file.
        assert_eq!(load("bob").as_deref(), Some("file-token"));
    }

    #[test]
    fn clear_removes_the_file_backend() {
        let dir = tempfile::tempdir().expect("tempdir");
        let _guard = RuntimeDirGuard::enter(dir.path());
        let path = token_file("carol");
        write_token_file(&path, "token").expect("write");
        assert!(path.exists());
        clear("carol");
        assert!(!path.exists(), "clear must remove the token file");
        assert!(load("carol").is_none());
    }

    #[test]
    fn empty_token_file_reads_as_none() {
        let dir = tempfile::tempdir().expect("tempdir");
        let _guard = RuntimeDirGuard::enter(dir.path());
        let path = token_file("dave");
        write_token_file(&path, "   ").expect("write");
        assert_eq!(read_token_file(&path), None);
    }

    #[test]
    fn store_reports_the_file_backend_when_no_keyring_exists() {
        let dir = tempfile::tempdir().expect("tempdir");
        let _guard = RuntimeDirGuard::enter(dir.path());
        // No session bus in the test environment → the keyring probe fails
        // and store lands on the documented fallback.
        let backend = store("erin", "token");
        assert_eq!(backend, Backend::File);
        assert_eq!(load("erin").as_deref(), Some("token"));
    }
}
