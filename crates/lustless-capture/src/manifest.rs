//! Screenstate manifest, schema 3.0.0 (CONTRACTS §6.3; key set verbatim from
//! `re/findings/10-classifier/capture-pipeline.md` §2).
//!
//! The producer (`lustlessd` capture loop) serializes this into `manifest.json` inside a spool
//! transaction folder; the classifier deserializes it and accepts any manifest whose
//! `schemaVersion` starts with `'3'` (CE's `validateSchemaVersion` semantics — major-version
//! compatibility, minor drift tolerated).

use serde::{Deserialize, Serialize};

/// Current schema version written by LustLess.
pub const SCHEMA_VERSION_3_0_0: &str = "3.0.0";

/// A rectangle `[x, y, width, height]` serialized as a plain 4-element JSON integer array
/// (CE's `screenRect`/`appRect` encoding).
pub type Rect = [i32; 4];

/// Top-level screenstate manifest.
///
/// Key names are mixed-case exactly as CE writes them (`schemaVersion`/`urlSafeUsername` camel,
/// `datetime_created`/`local_utc_offset`/`window_title`/`appRect`/`doNotScore` snake) — the
/// classifier tooling contract is the key set, not a style convention.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScreenstateManifest {
    /// Schema version string; must start with `'3'` for the consumer to accept.
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    /// Percent-encoded (url-safe) username produced by
    /// `lustless_core::ids::url_safe_username` (interface pin).
    #[serde(rename = "urlSafeUsername")]
    pub url_safe_username: String,
    /// Capture instant, ISO-8601 UTC (`2026-10-11T12:00:00.000000Z`).
    pub datetime_created: String,
    /// Local UTC offset of the capturing machine, e.g. `+02:00` / `-05:00` (CE stores the
    /// offset separately from the UTC timestamp).
    pub local_utc_offset: String,
    /// One entry per captured monitor image (`im<N>.png`), with the monitor's rectangle in
    /// virtual-screen coordinates.
    pub images: Vec<ImageEntry>,
    /// Monitor rectangles in virtual-screen coordinates (`[x, y, width, height]`), parallel
    /// to `images`.
    pub monitors: Vec<Rect>,
    /// Enumerated application windows (Wayland: one synthetic entry per monitor).
    pub apps: Vec<AppEntry>,
    /// Device identity payload.
    #[serde(rename = "clientPayload")]
    pub client_payload: ClientPayload,
}

/// One captured image reference.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ImageEntry {
    /// File name inside the transaction folder (`im0.png`, `im1.png`, …).
    pub filename: String,
    /// `[x, y, width, height]` in virtual-screen coordinates.
    #[serde(rename = "screenRect")]
    pub screen_rect: Rect,
}

/// One application window entry.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AppEntry {
    /// Application name.
    pub name: String,
    /// Window title (may be empty on Wayland, where compositors expose no titles).
    pub window_title: String,
    /// `[x, y, width, height]` in virtual-screen coordinates.
    #[serde(rename = "appRect")]
    pub app_rect: Rect,
    /// Restricted/protected surface: the classifier must exclude this region from scoring
    /// (CONTRACTS §7 — captured and flagged, never aborted). Written only when `true`, like
    /// CE (`FUN_1402ed3a0`).
    #[serde(rename = "doNotScore", skip_serializing_if = "Option::is_none", default)]
    pub do_not_score: Option<bool>,
}

impl AppEntry {
    /// True when this entry must be excluded from scoring.
    pub fn is_do_not_score(&self) -> bool {
        self.do_not_score.unwrap_or(false)
    }
}

/// `clientPayload` object.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ClientPayload {
    /// Device identity.
    pub device: Device,
}

/// Device identity inside `clientPayload`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Device {
    /// Stable per-install device UUID (the daemon's `clientPayload.device.device_uuid`).
    #[serde(rename = "device_uuid")]
    pub device_uuid: String,
}

/// Manifest validation errors.
#[derive(Debug, thiserror::Error, PartialEq)]
pub enum ManifestError {
    #[error("manifest schema version {0:?} is not 3.x")]
    UnsupportedSchema(String),
    #[error("manifest has no monitor entries")]
    NoMonitors,
    #[error("image entry {0:?} references missing file")]
    MissingImage(String),
}

impl ScreenstateManifest {
    /// Create a manifest with the current schema version and the given parts.
    pub fn new(
        url_safe_username: String,
        datetime_created: String,
        local_utc_offset: String,
        images: Vec<ImageEntry>,
        monitors: Vec<Rect>,
        apps: Vec<AppEntry>,
        device_uuid: String,
    ) -> Self {
        Self {
            schema_version: SCHEMA_VERSION_3_0_0.to_string(),
            url_safe_username,
            datetime_created,
            local_utc_offset,
            images,
            monitors,
            apps,
            client_payload: ClientPayload {
                device: Device { device_uuid },
            },
        }
    }

    /// CE-compatible schema gate: accept any `3.*` (the classifier only checks the major
    /// character — `validateSchemaVersion`, `classifier-internals-classifier.md` §a).
    pub fn validate_schema_major(&self) -> Result<(), ManifestError> {
        if self.schema_version.starts_with('3') {
            Ok(())
        } else {
            Err(ManifestError::UnsupportedSchema(
                self.schema_version.clone(),
            ))
        }
    }

    /// Structural validation: schema major, at least one monitor, and every `images[].filename`
    /// paired with a monitor rect.
    pub fn validate(&self) -> Result<(), ManifestError> {
        self.validate_schema_major()?;
        if self.monitors.is_empty() {
            return Err(ManifestError::NoMonitors);
        }
        if self.images.len() != self.monitors.len() {
            return Err(ManifestError::MissingImage(
                "images/monitors length mismatch".to_string(),
            ));
        }
        for image in &self.images {
            if image.filename.is_empty() {
                return Err(ManifestError::MissingImage(image.filename.clone()));
            }
        }
        Ok(())
    }

    /// Serialize to the JSON text written as `manifest.json`.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    /// Parse `manifest.json` text. Unknown keys are ignored (serde default), matching CE's
    /// JsonCpp parser tolerance for minor-version additions.
    pub fn from_json(text: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(text)
    }
}

/// Build the filename-compatible timestamp used for transaction folder names
/// (`%Y-%m-%dT%H-%M-%S.%7f`, colons replaced by `-`, matching CE's
/// `FilenameCompatibleDateTimeFormatter`, `capture-pipeline.md` §2 step 1).
pub fn transaction_timestamp(now: chrono::DateTime<chrono::Utc>) -> String {
    let base = now.format("%Y-%m-%dT%H-%M-%S").to_string();
    let micros = now.timestamp_subsec_micros();
    format!("{base}.{micros:06}")
}

/// Format the local UTC offset for `local_utc_offset` (e.g. `+02:00`, `-05:00`, `Z` → `+00:00`).
pub fn local_utc_offset(now: chrono::DateTime<chrono::FixedOffset>) -> String {
    now.format("%:z").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> ScreenstateManifest {
        ScreenstateManifest::new(
            "alice".to_string(),
            "2026-10-11T12:00:00.000000Z".to_string(),
            "+00:00".to_string(),
            vec![ImageEntry {
                filename: "im0.png".to_string(),
                screen_rect: [0, 0, 1920, 1080],
            }],
            vec![[0, 0, 1920, 1080]],
            vec![
                AppEntry {
                    name: "firefox".to_string(),
                    window_title: "News".to_string(),
                    app_rect: [10, 10, 800, 600],
                    do_not_score: None,
                },
                AppEntry {
                    name: "secret-vault".to_string(),
                    window_title: "Protected".to_string(),
                    app_rect: [900, 0, 1020, 1080],
                    do_not_score: Some(true),
                },
            ],
            "9f0d5f2e-device-uuid".to_string(),
        )
    }

    #[test]
    fn round_trip_preserves_exact_key_set() {
        let manifest = sample();
        let json = manifest.to_json().unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        let obj = parsed.as_object().unwrap();
        let mut keys: Vec<&str> = obj.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            vec![
                "apps",
                "clientPayload",
                "datetime_created",
                "images",
                "local_utc_offset",
                "monitors",
                "schemaVersion",
                "urlSafeUsername",
            ]
        );
        assert_eq!(
            parsed["images"][0]["screenRect"],
            serde_json::json!([0, 0, 1920, 1080])
        );
        let app = &parsed["apps"][1];
        assert_eq!(app["name"], "secret-vault");
        assert_eq!(app["window_title"], "Protected");
        assert_eq!(app["appRect"], serde_json::json!([900, 0, 1020, 1080]));
        assert_eq!(app["doNotScore"], true);
        assert_eq!(parsed["clientPayload"]["device"]["device_uuid"], "9f0d5f2e-device-uuid");
        // doNotScore omitted entirely when absent (CE writes the key only when true).
        assert!(parsed["apps"][0].get("doNotScore").is_none());

        let back = ScreenstateManifest::from_json(&json).unwrap();
        assert_eq!(back, manifest);
    }

    #[test]
    fn round_trip_tolerates_unknown_keys_and_minor_schema_drift() {
        let json = r#"{
            "schemaVersion": "3.1.0",
            "urlSafeUsername": "bob",
            "datetime_created": "2026-10-11T12:00:00.000000Z",
            "local_utc_offset": "-05:00",
            "images": [{"filename": "im0.png", "screenRect": [0,0,640,480], "futureKey": 7}],
            "monitors": [[0,0,640,480]],
            "apps": [{"name": "xterm", "window_title": "shell", "appRect": [0,0,100,100], "doNotScore": false}],
            "clientPayload": {"device": {"device_uuid": "u", "extra": {"nested": true}}},
            "unknownTopLevel": [1,2,3]
        }"#;
        let manifest = ScreenstateManifest::from_json(json).unwrap();
        manifest.validate_schema_major().unwrap();
        manifest.validate().unwrap();
        assert_eq!(manifest.url_safe_username, "bob");
        assert_eq!(manifest.monitors[0], [0, 0, 640, 480]);
        assert!(!manifest.apps[0].is_do_not_score());
        assert_eq!(manifest.images[0].screen_rect, [0, 0, 640, 480]);
    }

    #[test]
    fn schema_gate_rejects_non_3x() {
        let mut manifest = sample();
        manifest.schema_version = "2.9.0".to_string();
        assert_eq!(
            manifest.validate_schema_major(),
            Err(ManifestError::UnsupportedSchema("2.9.0".to_string()))
        );
    }

    #[test]
    fn validation_requires_monitors_and_image_pairing() {
        let mut manifest = sample();
        manifest.monitors.clear();
        assert_eq!(manifest.validate(), Err(ManifestError::NoMonitors));

        let mut manifest = sample();
        manifest.images.push(ImageEntry {
            filename: "im1.png".to_string(),
            screen_rect: [1920, 0, 1920, 1080],
        });
        assert!(matches!(
            manifest.validate(),
            Err(ManifestError::MissingImage(_))
        ));
    }

    #[test]
    fn transaction_timestamp_is_filename_safe() {
        let ts = transaction_timestamp(chrono::Utc::now());
        assert!(!ts.contains(':'), "colons would break the folder name: {ts}");
        assert!(ts.contains('T') && ts.contains('-') && ts.contains('.'));
        assert_eq!(ts.len(), "2026-10-11T12-00-00.000000".len());
    }
}
