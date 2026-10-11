//! ONNX scoring engine (CONTRACTS §7 "Scoring model": a clean-room,
//! open-licensed NSFW/image classifier in ONNX — see `MODEL.md` for the
//! model card, provenance, published metrics and the exact preprocessing
//! spec this module implements).
//!
//! Deterministic input pipeline (documented in `MODEL.md`):
//! RGB8 crop → bilinear resize to [`INPUT_WIDTH`]×[`INPUT_HEIGHT`] →
//! rescale `1/255` → normalize `(x − 0.5) / 0.5` → CHW `f32`, batch 1 →
//! single ONNX `run` → softmax over the logits → score = P(positive label).
//!
//! The threshold comes from the `calibration` bundle role (default
//! [`DEFAULT_THRESHOLD`]); `--threshold` overrides it. Unit tests exercise
//! the preprocessing/parsing with synthetic tensors only — no real model is
//! loaded in tests.

use std::fs;
use std::io;
use std::path::PathBuf;

use image::imageops::{self, FilterType};
use image::RgbImage;
use ort::session::builder::GraphOptimizationLevel;
use ort::session::Session;
use ort::value::Tensor;
use serde::Deserialize;

use crate::bundles::LoadedBundle;

/// Model input width in pixels (ViT patch grid 384/16 = 24).
pub const INPUT_WIDTH: u32 = 384;
/// Model input height in pixels.
pub const INPUT_HEIGHT: u32 = 384;
/// Threshold used when the calibration artifact carries none (§7).
pub const DEFAULT_THRESHOLD: f64 = 0.8;
/// Fallback positive label when the calibration artifact omits `positiveLabel`.
const DEFAULT_POSITIVE_LABEL: &str = "nsfw";

/// Scoring failures. The caller treats these as fail-closed (§7): the
/// process exits non-zero and the daemon's relaunch budget takes over.
#[derive(Debug, thiserror::Error)]
pub enum ScoreError {
    #[error("artifact {path} unreadable: {source}")]
    ArtifactIo {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("labels artifact invalid: {0}")]
    Labels(String),
    #[error("calibration artifact invalid: {0}")]
    Calibration(String),
    #[error("onnx runtime error: {0}")]
    Ort(#[from] ort::Error),
    #[error("model produced no usable logits")]
    NoLogits,
    #[error("positive class index {index} out of range for {len} logits")]
    LogitIndex { index: usize, len: usize },
}

// ---------------------------------------------------------------------------
// Bundle-role parsing
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct CalibrationFile {
    #[serde(rename = "positiveLabel", default = "default_positive_label")]
    positive_label: String,
    #[serde(default)]
    threshold: Option<f64>,
}

fn default_positive_label() -> String {
    DEFAULT_POSITIVE_LABEL.to_string()
}

/// Parse the `calibration` artifact: `(positive label, threshold)` with
/// §7 defaults (`nsfw`, [`DEFAULT_THRESHOLD`]) for absent fields.
pub fn parse_calibration(json: &str) -> Result<(String, f64), ScoreError> {
    let file: CalibrationFile =
        serde_json::from_str(json).map_err(|err| ScoreError::Calibration(err.to_string()))?;
    if file.positive_label.is_empty() {
        return Err(ScoreError::Calibration(
            "positiveLabel must not be empty".to_string(),
        ));
    }
    let threshold = file.threshold.unwrap_or(DEFAULT_THRESHOLD);
    if !threshold.is_finite() || !(0.0..=1.0).contains(&threshold) {
        return Err(ScoreError::Calibration(format!(
            "threshold {threshold} is outside 0.0..=1.0"
        )));
    }
    Ok((file.positive_label, threshold))
}

#[derive(Deserialize)]
struct LabelsFile {
    id2label: std::collections::HashMap<String, String>,
}

/// Parse the `labels` artifact (an upstream `config.json` with `id2label`)
/// and resolve the logit index of `positive_label` (case-insensitive).
pub fn positive_label_index(json: &str, positive_label: &str) -> Result<usize, ScoreError> {
    let file: LabelsFile =
        serde_json::from_str(json).map_err(|err| ScoreError::Labels(err.to_string()))?;
    if file.id2label.is_empty() {
        return Err(ScoreError::Labels("id2label is empty".to_string()));
    }
    let mut parsed: Vec<(usize, String)> = Vec::with_capacity(file.id2label.len());
    for (key, name) in file.id2label {
        let id: usize = key
            .parse()
            .map_err(|_| ScoreError::Labels(format!("id2label key {key:?} is not an index")))?;
        parsed.push((id, name));
    }
    parsed.sort_by_key(|(id, _)| *id);
    parsed
        .iter()
        .find(|(_, name)| name.eq_ignore_ascii_case(positive_label))
        .map(|(id, _)| *id)
        .ok_or_else(|| {
            let names: Vec<&str> = parsed.iter().map(|(_, name)| name.as_str()).collect();
            ScoreError::Labels(format!(
                "no label {positive_label:?} in id2label {names:?}"
            ))
        })
}

// ---------------------------------------------------------------------------
// Deterministic preprocessing + softmax (MODEL.md)
// ---------------------------------------------------------------------------

/// Build the model input tensor: bilinear (Triangle ≈ PIL
/// `Resampling.BILINEAR`, the upstream `ViTFeatureExtractor` resample) resize
/// to [`INPUT_WIDTH`]×[`INPUT_HEIGHT`], rescale `1/255`, normalize
/// `(x − 0.5) / 0.5`, laid out CHW in `f32` (batch dimension added by
/// [`Scorer::score_image`]). Pure over a synthetic tensor — unit-testable
/// without a model.
pub fn preprocess(image: &RgbImage) -> Vec<f32> {
    let resized = imageops::resize(image, INPUT_WIDTH, INPUT_HEIGHT, FilterType::Triangle);
    let plane = (INPUT_WIDTH * INPUT_HEIGHT) as usize;
    let mut out = vec![0.0f32; 3 * plane];
    for (x, y, pixel) in resized.enumerate_pixels() {
        let index = y as usize * INPUT_WIDTH as usize + x as usize;
        let [r, g, b] = pixel.0;
        out[index] = (r as f32 / 255.0 - 0.5) / 0.5;
        out[plane + index] = (g as f32 / 255.0 - 0.5) / 0.5;
        out[2 * plane + index] = (b as f32 / 255.0 - 0.5) / 0.5;
    }
    out
}

/// Numerically stable softmax over the model logits (f64 accumulation).
pub fn class_probabilities(logits: &[f32]) -> Vec<f64> {
    if logits.is_empty() {
        return Vec::new();
    }
    let max = logits
        .iter()
        .map(|value| f64::from(*value))
        .fold(f64::NEG_INFINITY, f64::max);
    let exps: Vec<f64> = logits
        .iter()
        .map(|value| (f64::from(*value) - max).exp())
        .collect();
    let sum: f64 = exps.iter().sum();
    if sum > 0.0 {
        exps.iter().map(|value| value / sum).collect()
    } else {
        // Degenerate (all logits non-finite upstream of the guard): uniform.
        vec![1.0 / logits.len() as f64; logits.len()]
    }
}

// ---------------------------------------------------------------------------
// The scorer
// ---------------------------------------------------------------------------

/// What the consumer drives. Production uses [`Scorer`]; tests inject fakes.
pub trait ImageScorer {
    /// Score one RGB crop in `0..=1` (P(positive label)).
    fn score_image(&mut self, image: &RgbImage) -> Result<f64, ScoreError>;
    /// Flag threshold: `score >= threshold()` ⇒ flagged (§7).
    fn threshold(&self) -> f64;
}

/// The ONNX-backed [`ImageScorer`].
pub struct Scorer {
    session: Session,
    /// Logit index of the positive (NSFW) label.
    positive_index: usize,
    threshold: f64,
    threshold_source: &'static str,
}

impl Scorer {
    /// Verify-and-load: the bundle is already hash-validated by
    /// [`crate::bundles::load`]; this reads the labels/calibration roles and
    /// commits the ONNX session (CPU execution provider, default ort
    /// download — see `MODEL.md` "Runtime").
    pub fn open(
        bundle: &LoadedBundle,
        threshold_override: Option<f64>,
    ) -> Result<Self, ScoreError> {
        let labels_json = fs::read_to_string(&bundle.labels.path).map_err(|source| {
            ScoreError::ArtifactIo {
                path: bundle.labels.path.clone(),
                source,
            }
        })?;
        let calibration_json =
            fs::read_to_string(&bundle.calibration.path).map_err(|source| {
                ScoreError::ArtifactIo {
                    path: bundle.calibration.path.clone(),
                    source,
                }
            })?;

        let (positive_label, calibrated) = parse_calibration(&calibration_json)?;
        let (threshold, threshold_source) = match threshold_override {
            Some(overridden) => (overridden, "--threshold override"),
            None => (calibrated, "calibration artifact"),
        };
        let positive_index = positive_label_index(&labels_json, &positive_label)?;

        let session = Session::builder()?
            .with_optimization_level(GraphOptimizationLevel::Level3)?
            .with_deterministic_compute(true)?
            .commit_from_file(&bundle.scorer.path)?;

        Ok(Self {
            session,
            positive_index,
            threshold,
            threshold_source,
        })
    }

    /// Where the active threshold came from (startup log, §14).
    pub fn threshold_source(&self) -> &'static str {
        self.threshold_source
    }
}

impl ImageScorer for Scorer {
    fn score_image(&mut self, image: &RgbImage) -> Result<f64, ScoreError> {
        let data = preprocess(image);
        let tensor = Tensor::from_array((
            [
                1usize,
                3,
                INPUT_HEIGHT as usize,
                INPUT_WIDTH as usize,
            ],
            data.into_boxed_slice(),
        ))?;
        let outputs = self.session.run(ort::inputs![tensor])?;
        let (_shape, logits) = outputs[0].try_extract_tensor::<f32>()?;
        if logits.is_empty() || logits.iter().any(|value| !value.is_finite()) {
            return Err(ScoreError::NoLogits);
        }
        if self.positive_index >= logits.len() {
            return Err(ScoreError::LogitIndex {
                index: self.positive_index,
                len: logits.len(),
            });
        }
        Ok(class_probabilities(logits)[self.positive_index])
    }

    fn threshold(&self) -> f64 {
        self.threshold
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use image::Rgb;

    const PLANE: usize = (INPUT_WIDTH * INPUT_HEIGHT) as usize;

    #[test]
    fn preprocess_is_chw_normalized_and_full_size() {
        // Synthetic constant tensor: every pixel (0, 255, 128).
        let image = RgbImage::from_pixel(4, 4, Rgb([0, 255, 128]));
        let data = preprocess(&image);

        assert_eq!(data.len(), 3 * PLANE, "one 384x384 plane per channel");
        // R = 0 → -1.0, G = 255 → +1.0 across the whole plane.
        assert!((data[0] - -1.0).abs() < 1e-6);
        assert!((data[PLANE - 1] - -1.0).abs() < 1e-6);
        assert!((data[PLANE] - 1.0).abs() < 1e-6);
        assert!((data[2 * PLANE - 1] - 1.0).abs() < 1e-6);
        // B = 128 → (128/255 - 0.5) / 0.5 ≈ 0.00392, proving channel planes
        // (CHW) rather than interleaved pixels (HWC).
        let expected_b = (128.0f32 / 255.0 - 0.5) / 0.5;
        assert!((data[2 * PLANE] - expected_b).abs() < 1e-6);
        assert!((data[3 * PLANE - 1] - expected_b).abs() < 1e-6);
    }

    #[test]
    fn preprocess_resizes_arbitrary_inputs_to_model_input() {
        for (w, h) in [(1, 1), (2, 7), (640, 360), (1920, 1080)] {
            let image = RgbImage::from_pixel(w, h, Rgb([10, 20, 60]));
            let data = preprocess(&image);
            assert_eq!(data.len(), 3 * PLANE, "input {w}x{h}");
        }
    }

    #[test]
    fn preprocess_maps_gradients_monotonically_after_resize() {
        // Horizontal ramp in R: resize must preserve left-to-right order.
        let mut image = RgbImage::new(16, 4);
        for (x, _y, pixel) in image.enumerate_pixels_mut() {
            *pixel = Rgb([(x * 16).min(255) as u8, 0, 0]);
        }
        let data = preprocess(&image);
        assert!(
            data[INPUT_WIDTH as usize - 1] > data[0],
            "upscaled ramp must still rise left→right"
        );
    }

    #[test]
    fn softmax_is_stable_and_normalized() {
        let probs = class_probabilities(&[0.0, 0.0]);
        assert!((probs[0] - 0.5).abs() < 1e-12);
        assert!((probs[1] - 0.5).abs() < 1e-12);

        let probs = class_probabilities(&[0.0, 3f32.ln()]);
        assert!((probs[0] - 0.25).abs() < 1e-6);
        assert!((probs[1] - 0.75).abs() < 1e-6);

        // Large logit spread must not overflow to NaN.
        let probs = class_probabilities(&[1000.0, -1000.0]);
        assert_eq!(probs, vec![1.0, 0.0]);

        assert!(class_probabilities(&[]).is_empty());
    }

    #[test]
    fn calibration_defaults_and_validation() {
        // Explicit values win.
        assert_eq!(
            parse_calibration(r#"{"threshold":0.9,"positiveLabel":"NSFW"}"#).unwrap(),
            ("NSFW".to_string(), 0.9)
        );
        // §7 defaults for absent fields.
        assert_eq!(
            parse_calibration("{}").unwrap(),
            (DEFAULT_POSITIVE_LABEL.to_string(), DEFAULT_THRESHOLD)
        );
        // Positive label absent but threshold present.
        assert_eq!(
            parse_calibration(r#"{"threshold":0.55}"#).unwrap(),
            (DEFAULT_POSITIVE_LABEL.to_string(), 0.55)
        );
        // Out-of-range / non-numeric thresholds fail closed.
        assert!(matches!(
            parse_calibration(r#"{"threshold":1.5}"#),
            Err(ScoreError::Calibration(_))
        ));
        assert!(matches!(
            parse_calibration(r#"{"threshold":"high"}"#),
            Err(ScoreError::Calibration(_))
        ));
        assert!(matches!(
            parse_calibration(r#"{"positiveLabel":""}"#),
            Err(ScoreError::Calibration(_))
        ));
        assert!(matches!(
            parse_calibration("not json"),
            Err(ScoreError::Calibration(_))
        ));
    }

    #[test]
    fn labels_resolve_positive_index_case_insensitively() {
        let config = r#"{"id2label":{"0":"sfw","1":"nsfw"},"label2id":{"nsfw":"1","sfw":"0"}}"#;
        assert_eq!(positive_label_index(config, "nsfw").unwrap(), 1);
        assert_eq!(positive_label_index(config, "NSFW").unwrap(), 1);
        assert_eq!(positive_label_index(config, "sfw").unwrap(), 0);

        // Non-contiguous ids resolve to the id itself, not the position.
        let sparse = r#"{"id2label":{"0":"safe","7":"explicit"}}"#;
        assert_eq!(positive_label_index(sparse, "explicit").unwrap(), 7);

        assert!(matches!(
            positive_label_index(config, "porn"),
            Err(ScoreError::Labels(_))
        ));
        assert!(matches!(
            positive_label_index(r#"{"id2label":{}}"#, "nsfw"),
            Err(ScoreError::Labels(_))
        ));
        assert!(matches!(
            positive_label_index(r#"{"id2label":{"x":"nsfw"}}"#, "nsfw"),
            Err(ScoreError::Labels(_))
        ));
        assert!(matches!(
            positive_label_index("nope", "nsfw"),
            Err(ScoreError::Labels(_))
        ));
    }
}
