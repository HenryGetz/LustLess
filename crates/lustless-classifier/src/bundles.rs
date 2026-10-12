//! Model-bundle manager + per-user state trees (CONTRACTS §7 "Bundle
//! layout", §4, §6.3).
//!
//! The bundle ships **Covenant Eyes' production classifier artifacts
//! byte-identical** (`AUTHORIZATION.md` at the repo root authorizes their
//! use): the `b1`/`b2`/`b3` shards of the `ensem_3cls-6.1.2` ensemble, the
//! `sw` word/feature model, and the CE bundle manifest `mn` — all encrypted
//! at rest exactly as CE ships them (`re/findings/10-classifier/
//! bundle-formats.md` §1: AES-256-CBC + PKCS#7, no IV prefix, no MAC;
//! context-0 key derivation + fixed IV recovered and verified there).
//!
//! Bundle layout at `--model` (§4 `/usr/share/lustless/models/`):
//!
//! ```text
//! manifest.json                        roles, versions, sha512 per artifact
//! <sha512>-scorer.dat.enc ×3           the three ensemble shards
//! <sha512>-labels.dat.enc              the word/feature model
//! <sha512>-calibration.json            threshold config (ours, plaintext)
//! <sha512>-mn.dat.enc                  CE bundle manifest (optional)
//! ```
//!
//! The CONTRACTS §7 role mapping holds: `scorer` → the three `bN` shards,
//! `labels` → `sw`, `calibration` → threshold config, and an `mn` entry (the
//! upstream CE manifest) is accepted when present and cross-checked against
//! the shipped artifacts.
//!
//! [`load`] verifies every artifact's sha512 **and** its content-id (CE
//! scheme: first 80 bits of the file's SHA-512, `bundle-formats.md` §2.1),
//! decrypts every `.dat.enc` payload with the documented context-0 scheme,
//! and fails closed (caller exits 1 + `bye`) on any mismatch. The artifact
//! *id* logged at startup is CE's `<20 hex>-<role>` shape.
//!
//! Per-user trees (CE `classifier-data.md` "Per-SID directory layout",
//! `91-linux-mapping.md` §2 "Per-user state — Adapt"):
//! * `--data` — `<data>/pdl/<ISO-ts>` work batches: the §6.3 spool
//!   transactions the daemon writes and this process consumes,
//! * `--cache` — small control files in the CE `bmdat` namespace plus the
//!   `<pid>.log` fallback directory (`bmdat/last-result.json`, written
//!   after every consumed batch and read back at startup for support logs).

use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use aes::Aes256;
use cbc::cipher::block_padding::Pkcs7;
use cbc::cipher::{BlockDecryptMut, KeyIvInit};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};

/// The bundle manifest file inside `--model`.
pub const MANIFEST_FILE: &str = "manifest.json";
/// Supported manifest `schemaVersion` major (our format, v1).
const MANIFEST_SCHEMA_MAJOR: char = '1';
/// Length of the content id prefix in an artifact id (CE: 20 hex chars =
/// first 80 bits of the file's SHA-512, `bundle-formats.md` §2.1).
const ID_PREFIX_LEN: usize = 20;

/// Context-0 AES-256 key (`bundle-formats.md` §1.2): `SHA-256(XOR-0x50(
/// fixed assembly of 32-char pool literals))`, recovered and verified against
/// every shipped sample.
const CTX0_KEY: [u8; 32] = [
    0xed, 0x53, 0x76, 0x45, 0xf9, 0xcc, 0xc3, 0xd6, 0x2d, 0x30, 0x1d, 0xe9, 0x3d, 0xa1, 0x32, 0xa5,
    0x01, 0xb5, 0x87, 0xda, 0xae, 0xd9, 0x25, 0x8c, 0xcf, 0xd4, 0x9c, 0x07, 0x3a, 0xcf, 0x42, 0xe6,
];
/// Context-0 fixed IV (`bundle-formats.md` §1.2).
const CTX0_IV: [u8; 16] = *b"vWzM6BntW18W4gwq";

/// Decrypt one context-0 artifact: AES-256-CBC + strict PKCS#7 strip.
/// Any non-block-aligned input or invalid pad fails closed — there is no MAC,
/// so the sha512 content check above is the only integrity layer (§1.6).
fn decrypt_ctx0(ciphertext: &[u8]) -> Option<Vec<u8>> {
    type Aes256CbcDec = cbc::Decryptor<Aes256>;
    Aes256CbcDec::new_from_slices(&CTX0_KEY, &CTX0_IV)
        .ok()
        .and_then(|dec| dec.decrypt_padded_vec_mut::<Pkcs7>(ciphertext).ok())
}

/// Artifact roles required by §7, mapped onto CE's shipped roles.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// One of the three `ensem_3cls-6.1.2` ensemble shards (`b1`/`b2`/`b3`).
    Scorer,
    /// The word/feature model (`sw`).
    Labels,
    /// Threshold calibration (our generated JSON).
    Calibration,
    /// The upstream CE bundle manifest (`mn`), accepted when present.
    #[serde(alias = "mn")]
    UpstreamManifest,
}

impl Role {
    /// Every role with a multiplicity bound: `(role, minimum, maximum)`.
    pub const BOUNDS: [(Role, usize, usize); 4] = [
        (Role::Scorer, 3, 3),
        (Role::Labels, 1, 1),
        (Role::Calibration, 1, 1),
        (Role::UpstreamManifest, 0, 1),
    ];

    /// Lowercase role token (manifest + file names).
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Scorer => "scorer",
            Role::Labels => "labels",
            Role::Calibration => "calibration",
            Role::UpstreamManifest => "mn",
        }
    }

    /// File extension of the role's shipped artifact.
    pub fn ext(self) -> &'static str {
        match self {
            Role::Scorer | Role::Labels | Role::UpstreamManifest => "dat.enc",
            Role::Calibration => "json",
        }
    }

    /// Whether the artifact ships CE-encrypted (context 0).
    pub fn encrypted(self) -> bool {
        !matches!(self, Role::Calibration)
    }
}

/// One `artifacts[]` entry of the manifest.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ArtifactEntry {
    /// Required role.
    pub role: Role,
    /// Artifact version (model id for shards, file header for `sw`).
    pub version: String,
    /// Lowercase hex sha512 of the shipped artifact file.
    pub sha512: String,
    /// File name inside `--model`: `<sha512>-<role>.<ext>`.
    pub file: String,
}

/// Provenance block of the manifest (surfaced in startup logs and the §5
/// diagnostics `versions.txt`, which embeds `manifest.json`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ModelInfo {
    /// Model identity, e.g. `ensem_3cls-6.1.2`.
    pub name: String,
    /// Upstream bundle version the artifacts were shipped in.
    pub revision: String,
    /// License / authorization note.
    pub license: String,
    /// Provenance reference.
    pub source: String,
}

/// The bundle manifest (`models/manifest.json`, generated by
/// `fetch-model.sh`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BundleManifest {
    /// Manifest format version; must be `1.x`.
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    /// Bundle version (logged at startup).
    #[serde(rename = "bundleVersion")]
    pub bundle_version: String,
    /// Upstream provenance.
    pub model: ModelInfo,
    /// Content-addressed artifacts, multiplicities per [`Role::BOUNDS`].
    pub artifacts: Vec<ArtifactEntry>,
}

/// A validated artifact ready for use (encrypted payloads carry their
/// decrypted plaintext as well).
#[derive(Debug, Clone, PartialEq)]
pub struct Artifact {
    /// Its role.
    pub role: Role,
    /// Version from the manifest.
    pub version: String,
    /// sha512 from the manifest (verified against the file bytes).
    pub sha512: String,
    /// Content id: `<sha512[..20]>-<role>` (CE `<id>-<role>` shape).
    pub id: String,
    /// Path of the verified shipped file.
    pub path: PathBuf,
    /// File bytes; for encrypted roles the **decrypted** plaintext
    /// (calibration keeps its plaintext JSON).
    pub plaintext: Vec<u8>,
}

/// A fully hash-validated, decrypted bundle.
#[derive(Debug, Clone)]
pub struct LoadedBundle {
    /// Bundle version from the manifest.
    pub bundle_version: String,
    /// Upstream provenance.
    pub model: ModelInfo,
    /// The three ensemble shards (b1/b2/b3), manifest order.
    pub scorer_shards: Vec<Artifact>,
    /// Verified word/feature model artifact.
    pub labels: Artifact,
    /// Verified calibration artifact (plaintext JSON).
    pub calibration: Artifact,
    /// Verified upstream CE manifest, when present.
    pub upstream_manifest: Option<Artifact>,
}

impl LoadedBundle {
    /// Every artifact in canonical order (scorer shards, labels,
    /// calibration, upstream manifest).
    pub fn artifacts(&self) -> Vec<&Artifact> {
        let mut all: Vec<&Artifact> = self.scorer_shards.iter().collect();
        all.push(&self.labels);
        all.push(&self.calibration);
        if let Some(mn) = &self.upstream_manifest {
            all.push(mn);
        }
        all
    }

    /// Content-addressed artifact ids in canonical order — the §7
    /// `hello {model_ids}` payload.
    pub fn ids(&self) -> Vec<String> {
        self.artifacts().iter().map(|a| a.id.clone()).collect()
    }
}

/// Bundle / state-tree failures. Every variant is fail-closed (§7).
#[derive(Debug, thiserror::Error)]
pub enum BundleError {
    #[error("model manifest missing: {0}")]
    ManifestMissing(PathBuf),
    #[error("model manifest unreadable at {path}: {source}")]
    ManifestIo {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("model manifest parse failed: {0}")]
    ManifestParse(#[from] serde_json::Error),
    #[error("model manifest schema {0} is not supported (want {MANIFEST_SCHEMA_MAJOR}.x)")]
    UnsupportedSchema(String),
    #[error("model manifest must list {expected} {role} artifacts, found {found}")]
    RoleCount {
        role: &'static str,
        expected: usize,
        found: usize,
    },
    #[error("artifact {0}: sha512 is not 128 lowercase hex characters")]
    InvalidSha512(&'static str),
    #[error("artifact {role}: file {found} is not the content-addressed name {expected}")]
    FilenameMismatch {
        role: &'static str,
        expected: String,
        found: String,
    },
    #[error("artifact {role} missing: {path}")]
    ArtifactMissing { role: &'static str, path: PathBuf },
    #[error("artifact {role} hash mismatch: manifest {expected}, file {actual}")]
    HashMismatch {
        role: &'static str,
        expected: String,
        actual: String,
    },
    #[error("artifact {role} failed to decrypt (context-0 AES-256-CBC + PKCS#7): {reason}")]
    DecryptFailed { role: &'static str, reason: String },
    #[error("upstream manifest cross-check failed: {0}")]
    UpstreamMismatch(String),
    #[error("state tree {path}: {source}")]
    Tree {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("control file {path}: {source}")]
    Control {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("control file {path} is not valid JSON: {source}")]
    ControlParse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
}

fn is_sha512_hex(value: &str) -> bool {
    value.len() == 128
        && value
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Stream a file through SHA-512 (artifacts are up to a few MB).
fn sha512_file(path: &Path) -> io::Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = Sha512::new();
    io::copy(&mut file, &mut hasher)?;
    Ok(format!("{:x}", hasher.finalize()))
}

/// Load `model_dir/manifest.json`, verify every artifact hash + content-id
/// and decrypt the CE payloads (§7: validate at startup; missing/corrupt
/// ⇒ `Err`, never a degraded mode).
pub fn load(model_dir: &Path) -> Result<LoadedBundle, BundleError> {
    let path = model_dir.join(MANIFEST_FILE);
    let text = match fs::read_to_string(&path) {
        Ok(text) => text,
        Err(source) if source.kind() == io::ErrorKind::NotFound => {
            return Err(BundleError::ManifestMissing(path));
        }
        Err(source) => return Err(BundleError::ManifestIo { path, source }),
    };
    let manifest: BundleManifest = serde_json::from_str(&text)?;
    if !manifest.schema_version.starts_with(MANIFEST_SCHEMA_MAJOR) {
        return Err(BundleError::UnsupportedSchema(manifest.schema_version));
    }

    // Multiplicity bounds per role; `Role` is a closed enum, so unknown
    // roles fail at deserialization.
    let mut counts: HashMap<Role, usize> = HashMap::new();
    for entry in &manifest.artifacts {
        *counts.entry(entry.role).or_insert(0) += 1;
    }
    for (role, min, max) in Role::BOUNDS {
        let found = counts.get(&role).copied().unwrap_or(0);
        if found < min || found > max {
            return Err(BundleError::RoleCount {
                role: role.as_str(),
                expected: min,
                found,
            });
        }
    }

    let mut validated: Vec<Artifact> = Vec::with_capacity(manifest.artifacts.len());
    for entry in &manifest.artifacts {
        validated.push(validate_artifact(model_dir, entry)?);
    }

    let mut take = |role: Role| -> Artifact {
        let index = validated
            .iter()
            .position(|a| a.role == role)
            .expect("role bounds checked above");
        validated.remove(index)
    };
    let scorer_shards: Vec<Artifact> = (0..3).map(|_| take(Role::Scorer)).collect();
    let labels = take(Role::Labels);
    let calibration = take(Role::Calibration);
    let upstream_manifest = if counts.get(&Role::UpstreamManifest).copied().unwrap_or(0) == 1 {
        Some(take(Role::UpstreamManifest))
    } else {
        None
    };

    let bundle = LoadedBundle {
        bundle_version: manifest.bundle_version,
        model: manifest.model,
        scorer_shards,
        labels,
        calibration,
        upstream_manifest,
    };
    crosscheck_upstream_manifest(&bundle)?;
    Ok(bundle)
}

/// Verify one artifact: sha512 shape, content-addressed file name, presence,
/// byte-exact sha512, and context-0 decryption for CE payloads.
fn validate_artifact(model_dir: &Path, entry: &ArtifactEntry) -> Result<Artifact, BundleError> {
    let role = entry.role.as_str();
    if !is_sha512_hex(&entry.sha512) {
        return Err(BundleError::InvalidSha512(role));
    }
    let expected = format!("{}-{role}.{}", entry.sha512, entry.role.ext());
    if entry.file != expected {
        return Err(BundleError::FilenameMismatch {
            role,
            expected,
            found: entry.file.clone(),
        });
    }
    let path = model_dir.join(&entry.file);
    if !path.is_file() {
        return Err(BundleError::ArtifactMissing { role, path });
    }
    let actual = sha512_file(&path).map_err(|source| BundleError::Control {
        path: path.clone(),
        source,
    })?;
    if actual != entry.sha512 {
        return Err(BundleError::HashMismatch {
            role,
            expected: entry.sha512.clone(),
            actual,
        });
    }
    let shipped = fs::read(&path).map_err(|source| BundleError::Control {
        path: path.clone(),
        source,
    })?;
    let plaintext = if entry.role.encrypted() {
        decrypt_ctx0(&shipped).ok_or_else(|| BundleError::DecryptFailed {
            role,
            reason: "bad IV/padding after hash-verified read".to_string(),
        })?
    } else {
        shipped
    };
    Ok(Artifact {
        role: entry.role,
        version: entry.version.clone(),
        sha512: entry.sha512.clone(),
        id: format!("{}-{role}", &entry.sha512[..ID_PREFIX_LEN]),
        path,
        plaintext,
    })
}

/// When the upstream CE manifest (`mn`) ships, its plaintext
/// `files[].sha512_hash` list is the authority for the shipped CE payloads:
/// every shipped encrypted artifact must appear there byte-exact
/// (`bundle-formats.md` §2.1), else fail closed.
fn crosscheck_upstream_manifest(bundle: &LoadedBundle) -> Result<(), BundleError> {
    let Some(mn) = &bundle.upstream_manifest else {
        return Ok(());
    };
    let parsed: serde_json::Value = serde_json::from_slice(&mn.plaintext)
        .map_err(|err| BundleError::UpstreamMismatch(format!("mn plaintext is not JSON: {err}")))?;
    let mut upstream: Vec<String> = Vec::new();
    if let Some(files) = parsed.get("files").and_then(|v| v.as_array()) {
        for file in files {
            if let Some(hash) = file.get("sha512_hash").and_then(|v| v.as_str()) {
                upstream.push(hash.to_ascii_lowercase());
            }
        }
    }
    if upstream.is_empty() {
        return Err(BundleError::UpstreamMismatch(
            "mn plaintext carries no files[].sha512_hash entries".to_string(),
        ));
    }
    for artifact in bundle
        .scorer_shards
        .iter()
        .chain(std::iter::once(&bundle.labels))
    {
        if !upstream.contains(&artifact.sha512) {
            return Err(BundleError::UpstreamMismatch(format!(
                "shipped {} artifact {} is absent from the upstream manifest",
                artifact.role.as_str(),
                artifact.id
            )));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Per-user trees + control files
// ---------------------------------------------------------------------------

/// Create (and keep private) the CE-shaped per-user trees:
/// `<data>/pdl` work batches, `<cache>/bmdat` control files,
/// `<cache>/logs` `<pid>.log` fallback — all 0700 (§4).
pub fn ensure_user_tree(data_dir: &Path, cache_dir: &Path) -> Result<(), BundleError> {
    private_dir(data_dir)?;
    private_dir(&data_dir.join("pdl"))?;
    private_dir(cache_dir)?;
    private_dir(&cache_dir.join("bmdat"))?;
    private_dir(&cache_dir.join("logs"))?;
    Ok(())
}

fn private_dir(path: &Path) -> Result<(), BundleError> {
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)
        .map_err(|source| BundleError::Tree {
            path: path.to_path_buf(),
            source,
        })?;
    // Enforce 0700 even on pre-existing dirs (create_dir_all defaults and
    // umask may have produced 0755).
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|source| {
        BundleError::Tree {
            path: path.to_path_buf(),
            source,
        }
    })
}

/// What the previous run's last consumed batch was — the LustLess control
/// file in the CE `bmdat` namespace (CE's `nxu.dat` analog, see module docs).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LastResult {
    /// `result.batch_ts` of the last emitted batch.
    pub batch_ts: String,
    /// Windows scored in that batch.
    pub analyzed_count: u64,
    /// Flagged windows in that batch.
    pub flagged: u64,
    /// Top score of that batch.
    pub top_score: f64,
    /// RFC 3339 stamp of when the batch was consumed.
    pub finished_at: String,
}

/// `<cache>/bmdat/last-result.json`.
pub fn last_result_path(cache_dir: &Path) -> PathBuf {
    cache_dir.join("bmdat").join("last-result.json")
}

/// Atomically write the control file (0600, temp-then-rename like the §6.3
/// spool markers).
pub fn write_last_result(cache_dir: &Path, result: &LastResult) -> Result<(), BundleError> {
    let path = last_result_path(cache_dir);
    let tmp = path.with_extension("json.tmp");
    let json = serde_json::to_vec(result).map_err(|source| BundleError::ControlParse {
        path: path.clone(),
        source,
    })?;
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)
        .map_err(|source| BundleError::Control {
            path: tmp.clone(),
            source,
        })?;
    file.write_all(&json)
        .and_then(|()| file.sync_all())
        .map_err(|source| BundleError::Control {
            path: tmp.clone(),
            source,
        })?;
    drop(file);
    fs::rename(&tmp, &path).map_err(|source| BundleError::Control {
        path: path.clone(),
        source,
    })
}

/// Read the control file; `Ok(None)` when absent, `Err` when corrupt (the
/// caller logs and continues — the bundle itself is what fails closed).
pub fn read_last_result(cache_dir: &Path) -> Result<Option<LastResult>, BundleError> {
    let path = last_result_path(cache_dir);
    let text = match fs::read_to_string(&path) {
        Ok(text) => text,
        Err(source) if source.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(source) => return Err(BundleError::Control { path, source }),
    };
    let parsed =
        serde_json::from_str(&text).map_err(|source| BundleError::ControlParse { path, source })?;
    Ok(Some(parsed))
}

#[cfg(test)]
mod tests {
    use super::*;

    use aes::Aes256;
    use cbc::cipher::block_padding::Pkcs7;
    use cbc::cipher::{BlockEncryptMut, KeyIvInit};

    type Aes256CbcEnc = cbc::Encryptor<Aes256>;

    /// Encrypt with the production context-0 parameters (tests pin the real
    /// scheme; plaintexts are synthetic).
    fn encrypt_ctx0(plaintext: &[u8]) -> Vec<u8> {
        Aes256CbcEnc::new_from_slices(&CTX0_KEY, &CTX0_IV)
            .unwrap()
            .encrypt_padded_vec_mut::<Pkcs7>(plaintext)
    }

    fn sha512(bytes: &[u8]) -> String {
        format!("{:x}", Sha512::digest(bytes))
    }

    const SHARD_HEADER: &str = "ensem_3cls-6.1.2,157.0,143.0,135.0,84.3,84.4,87.6";
    const SW_HEADER: &str = "Snowball NLP 2.0\nrbf\nsynthetic\n";

    fn model_info() -> ModelInfo {
        ModelInfo {
            name: "ensem_3cls-6.1.2".to_string(),
            revision: "1.12.3".to_string(),
            license: "Covenant Eyes production model (AUTHORIZATION.md)".to_string(),
            source: "CE Victory Shield 10.1.44 shipped bundle".to_string(),
        }
    }

    /// Write a valid synthetic bundle into `dir`; returns the manifest.
    fn write_valid_bundle(dir: &Path) -> BundleManifest {
        let calibration = br#"{"schemaVersion":"1.0.0","threshold":0.46662}"#;
        let mut artifacts = Vec::new();
        let mut upstream_hashes: Vec<String> = Vec::new();
        for (role, plaintext) in [
            (
                Role::Scorer,
                format!("{SHARD_HEADER}\nsynthetic-shard-a").into_bytes(),
            ),
            (
                Role::Scorer,
                format!("{SHARD_HEADER}\nsynthetic-shard-b").into_bytes(),
            ),
            (
                Role::Scorer,
                format!("{SHARD_HEADER}\nsynthetic-shard-c").into_bytes(),
            ),
            (Role::Labels, SW_HEADER.as_bytes().to_vec()),
        ] {
            let shipped = encrypt_ctx0(&plaintext);
            let sha512 = sha512(&shipped);
            upstream_hashes.push(sha512.clone());
            let file = format!("{sha512}-{}.{}", role.as_str(), role.ext());
            fs::write(dir.join(&file), &shipped).unwrap();
            artifacts.push(ArtifactEntry {
                role,
                version: "6.1.2".to_string(),
                sha512,
                file,
            });
        }
        // The upstream manifest lists exactly the shipped CE payloads —
        // the cross-check in `load` demands that.
        let files: String = upstream_hashes
            .iter()
            .map(|hash| format!(r#"{{"download_link":"https://example.invalid/{hash}.dat.enc","sha512_hash":"{hash}"}}"#))
            .collect::<Vec<_>>()
            .join(",");
        let mn_plaintext =
            format!(r#"{{"schemaVersion":"1.0.0","bundleVersion":"1.12.3","files":[{files}]}}"#);
        let shipped = encrypt_ctx0(mn_plaintext.as_bytes());
        let mn_hash = sha512(&shipped);
        let file = format!("{mn_hash}-mn.dat.enc");
        fs::write(dir.join(&file), &shipped).unwrap();
        artifacts.push(ArtifactEntry {
            role: Role::UpstreamManifest,
            version: "1.12.3".to_string(),
            sha512: mn_hash,
            file,
        });
        let sha512 = sha512(calibration);
        let file = format!("{sha512}-calibration.json");
        fs::write(dir.join(&file), calibration).unwrap();
        artifacts.push(ArtifactEntry {
            role: Role::Calibration,
            version: "1.0.0".to_string(),
            sha512,
            file,
        });
        let manifest = BundleManifest {
            schema_version: "1.0.0".to_string(),
            bundle_version: "1.12.3".to_string(),
            model: model_info(),
            artifacts,
        };
        fs::write(
            dir.join(MANIFEST_FILE),
            serde_json::to_string_pretty(&manifest).unwrap(),
        )
        .unwrap();
        manifest
    }

    #[test]
    fn valid_bundle_loads_decrypts_and_logs_ce_shaped_ids() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = write_valid_bundle(dir.path());

        let bundle = load(dir.path()).expect("valid bundle");
        assert_eq!(bundle.bundle_version, "1.12.3");
        assert_eq!(bundle.model, model_info());

        assert_eq!(bundle.scorer_shards.len(), 3);
        for shard in &bundle.scorer_shards {
            assert!(shard.plaintext.starts_with(SHARD_HEADER.as_bytes()));
            assert!(shard.path.is_file());
            assert_eq!(
                shard.id,
                format!(
                    "{}-scorer",
                    &manifest
                        .artifacts
                        .iter()
                        .find(|a| a.sha512 == shard.sha512)
                        .unwrap()
                        .sha512[..ID_PREFIX_LEN]
                ),
                "CE id format: sha512[:20]-role"
            );
        }
        assert_eq!(bundle.labels.plaintext, SW_HEADER.as_bytes());
        assert!(bundle
            .calibration
            .plaintext
            .starts_with(b"{\"schemaVersion\""));
        assert!(bundle.upstream_manifest.is_some());

        // Canonical id order: scorer shards, labels, calibration, mn.
        let ids = bundle.ids();
        assert_eq!(ids.len(), 6);
        assert!(ids[3].ends_with("-labels"));
        assert!(ids[4].ends_with("-calibration"));
        assert!(ids[5].ends_with("-mn"));
    }

    #[test]
    fn missing_manifest_fails() {
        let dir = tempfile::tempdir().unwrap();
        assert!(matches!(
            load(dir.path()),
            Err(BundleError::ManifestMissing(_))
        ));
    }

    #[test]
    fn unparsable_manifest_fails() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join(MANIFEST_FILE), "{not json").unwrap();
        assert!(matches!(
            load(dir.path()),
            Err(BundleError::ManifestParse(_))
        ));
    }

    #[test]
    fn unsupported_manifest_schema_fails() {
        let dir = tempfile::tempdir().unwrap();
        let mut manifest = write_valid_bundle(dir.path());
        manifest.schema_version = "2.0.0".to_string();
        fs::write(
            dir.path().join(MANIFEST_FILE),
            serde_json::to_string_pretty(&manifest).unwrap(),
        )
        .unwrap();
        assert!(matches!(
            load(dir.path()),
            Err(BundleError::UnsupportedSchema(v)) if v == "2.0.0"
        ));
    }

    #[test]
    fn wrong_scorer_count_fails() {
        let dir = tempfile::tempdir().unwrap();
        let mut manifest = write_valid_bundle(dir.path());
        let drop_sha = manifest.artifacts[2].sha512.clone();
        manifest.artifacts.retain(|a| a.sha512 != drop_sha);
        fs::write(
            dir.path().join(MANIFEST_FILE),
            serde_json::to_string_pretty(&manifest).unwrap(),
        )
        .unwrap();
        assert!(matches!(
            load(dir.path()),
            Err(BundleError::RoleCount {
                role: "scorer",
                expected: 3,
                found: 2
            })
        ));
    }

    #[test]
    fn duplicate_labels_fail() {
        let dir = tempfile::tempdir().unwrap();
        let mut manifest = write_valid_bundle(dir.path());
        let labels = manifest
            .artifacts
            .iter()
            .find(|a| a.role == Role::Labels)
            .unwrap()
            .clone();
        manifest.artifacts.push(labels);
        fs::write(
            dir.path().join(MANIFEST_FILE),
            serde_json::to_string_pretty(&manifest).unwrap(),
        )
        .unwrap();
        assert!(matches!(
            load(dir.path()),
            Err(BundleError::RoleCount {
                role: "labels",
                expected: 1,
                found: 2
            })
        ));
    }

    #[test]
    fn unknown_role_fails_at_parse() {
        let dir = tempfile::tempdir().unwrap();
        write_valid_bundle(dir.path());
        let text = fs::read_to_string(dir.path().join(MANIFEST_FILE))
            .unwrap()
            .replace("\"calibration\"", "\"weapon\"");
        fs::write(dir.path().join(MANIFEST_FILE), text).unwrap();
        assert!(matches!(
            load(dir.path()),
            Err(BundleError::ManifestParse(_))
        ));
    }

    #[test]
    fn malformed_sha_fails() {
        let dir = tempfile::tempdir().unwrap();
        let mut manifest = write_valid_bundle(dir.path());
        manifest.artifacts[0].sha512 = "NOT-A-HASH".to_string();
        fs::write(
            dir.path().join(MANIFEST_FILE),
            serde_json::to_string_pretty(&manifest).unwrap(),
        )
        .unwrap();
        assert!(matches!(
            load(dir.path()),
            Err(BundleError::InvalidSha512("scorer"))
        ));
    }

    #[test]
    fn non_content_addressed_file_name_fails() {
        let dir = tempfile::tempdir().unwrap();
        let mut manifest = write_valid_bundle(dir.path());
        manifest.artifacts[0].file = "shard.dat.enc".to_string();
        fs::write(
            dir.path().join(MANIFEST_FILE),
            serde_json::to_string_pretty(&manifest).unwrap(),
        )
        .unwrap();
        assert!(matches!(
            load(dir.path()),
            Err(BundleError::FilenameMismatch { role: "scorer", .. })
        ));
    }

    #[test]
    fn missing_artifact_file_fails() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = write_valid_bundle(dir.path());
        let labels_file = manifest
            .artifacts
            .iter()
            .find(|a| a.role == Role::Labels)
            .unwrap()
            .file
            .clone();
        fs::remove_file(dir.path().join(labels_file)).unwrap();
        assert!(matches!(
            load(dir.path()),
            Err(BundleError::ArtifactMissing { role: "labels", .. })
        ));
    }

    #[test]
    fn corrupted_artifact_fails_hash_check() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = write_valid_bundle(dir.path());
        let labels = manifest
            .artifacts
            .iter()
            .find(|a| a.role == Role::Labels)
            .unwrap()
            .clone();
        // Flip one byte of the shipped labels artifact.
        let mut bytes = fs::read(dir.path().join(&labels.file)).unwrap();
        bytes[0] ^= 0x01;
        fs::write(dir.path().join(&labels.file), bytes).unwrap();
        match load(dir.path()) {
            Err(BundleError::HashMismatch {
                role: "labels",
                expected,
                actual,
            }) => {
                assert_eq!(expected, labels.sha512);
                assert_ne!(actual, labels.sha512);
            }
            other => panic!("expected labels HashMismatch, got {other:?}"),
        }
    }

    #[test]
    fn hash_swalling_corruption_fails_to_decrypt() {
        // Rebuild a manifest whose recorded sha512 matches random bytes:
        // the content-id check passes but context-0 decryption must fail
        // closed (no MAC layer exists — bundle-formats.md §1.6).
        let dir = tempfile::tempdir().unwrap();
        let mut manifest = write_valid_bundle(dir.path());
        let entry = manifest
            .artifacts
            .iter_mut()
            .find(|a| a.role == Role::Scorer)
            .unwrap();
        let garbage = vec![0x5au8; 64];
        let sha512 = sha512(&garbage);
        let file = format!("{sha512}-scorer.dat.enc");
        fs::write(dir.path().join(&file), &garbage).unwrap();
        entry.sha512 = sha512;
        entry.file = file;
        fs::write(
            dir.path().join(MANIFEST_FILE),
            serde_json::to_string_pretty(&manifest).unwrap(),
        )
        .unwrap();
        assert!(matches!(
            load(dir.path()),
            Err(BundleError::DecryptFailed { role: "scorer", .. })
        ));
    }

    #[test]
    fn upstream_manifest_mismatch_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let mut manifest = write_valid_bundle(dir.path());
        // Replace the synthetic mn (empty files[]) with one that lists a
        // foreign hash for every file — the shipped artifacts must then be
        // rejected.
        let foreign = "0".repeat(128);
        let mn_plaintext = format!(
            "{{\"schemaVersion\":\"1.0.0\",\"bundleVersion\":\"1.12.3\",\"files\":[{{\"download_link\":\"https://example/-b1.dat.enc\",\"sha512_hash\":\"{foreign}\"}}]}}"
        );
        let old_file = manifest
            .artifacts
            .iter()
            .find(|a| a.role == Role::UpstreamManifest)
            .unwrap()
            .file
            .clone();
        let shipped = encrypt_ctx0(mn_plaintext.as_bytes());
        let sha512 = sha512(&shipped);
        let file = format!("{sha512}-mn.dat.enc");
        fs::write(dir.path().join(&file), &shipped).unwrap();
        fs::remove_file(dir.path().join(old_file)).ok();
        let mn_entry = manifest
            .artifacts
            .iter_mut()
            .find(|a| a.role == Role::UpstreamManifest)
            .unwrap();
        mn_entry.sha512 = sha512;
        mn_entry.file = file;
        fs::write(
            dir.path().join(MANIFEST_FILE),
            serde_json::to_string_pretty(&manifest).unwrap(),
        )
        .unwrap();
        assert!(matches!(
            load(dir.path()),
            Err(BundleError::UpstreamMismatch(_))
        ));
    }

    #[test]
    fn ensure_user_tree_creates_private_dirs() {
        let dir = tempfile::tempdir().unwrap();
        let data = dir.path().join("spool").join("tester");
        let cache = dir.path().join("state").join("cache");

        ensure_user_tree(&data, &cache).expect("tree setup");
        for path in [
            data.clone(),
            data.join("pdl"),
            cache.clone(),
            cache.join("bmdat"),
            cache.join("logs"),
        ] {
            assert!(path.is_dir(), "{} should exist", path.display());
            let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o700, "{} should be 0700", path.display());
        }

        // Idempotent: a second run succeeds and keeps the modes.
        ensure_user_tree(&data, &cache).expect("second tree setup");
    }

    #[test]
    fn last_result_control_file_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let cache = dir.path().join("cache");
        fs::create_dir_all(cache.join("bmdat")).unwrap();

        assert_eq!(read_last_result(&cache).unwrap(), None);

        let result = LastResult {
            batch_ts: "2026-10-11T11:59:00.000000Z".to_string(),
            analyzed_count: 3,
            flagged: 1,
            top_score: 0.97,
            finished_at: "2026-10-11T12:00:00.000Z".to_string(),
        };
        write_last_result(&cache, &result).expect("write");
        assert_eq!(read_last_result(&cache).unwrap(), Some(result));

        // Corrupt control file surfaces as an error (logged, not fatal).
        fs::write(last_result_path(&cache), "{oops").unwrap();
        assert!(matches!(
            read_last_result(&cache),
            Err(BundleError::ControlParse { .. })
        ));
    }
}
