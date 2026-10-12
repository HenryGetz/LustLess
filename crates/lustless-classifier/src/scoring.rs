//! CE ensemble scoring engine (CONTRACTS §7 "Scoring model"; upstream
//! authorization: `AUTHORIZATION.md`).
//!
//! Pipeline, mirroring the recovered production flow (the `j1` bundle's
//! `computeScores`/`getVictoryEvaluatorScores`/`getSplicedScore` and the
//! `scoreImage`/`scoreWindowTitle` syscalls):
//!
//! 1. per window crop: bilinear-resize to [`INPUT_WIDTH`]×[`INPUT_HEIGHT`],
//!    normalize per channel with the shard-header parameters
//!    `(pixel − mean[c]) / std[c]`, layout NCHW `f32`;
//! 2. evaluate the three `ensem_3cls-6.1.2` shard graphs → one softmax triple
//!    `(class_a, class_b, class_c)` each (`MODEL.md` "Shard format");
//! 3. fold the three raw triples through the ensemble thresholds
//!    (`imageOnlyThresholds` / `withWindowTitleThresholds`) into a discrete
//!    class + relative strength (module `threeClassScore` semantics);
//! 4. splice the image decision with the window-title class through the
//!    15-row category table into one linear value in `[0, 100_000]`
//!    (`cleanest` → 0, `dirtiest` → 100,000), reported as
//!    `score = linear / 100_000`.
//!
//! Window titles are preprocessed exactly as the bundle does
//! (`fixAndFilterWindowTitle`): leet-speak normalization, repeated-token
//! cleanup, then a filter (non-context strings, all-symbol words,
//! Shannon-entropy bounds). An absent/filtered title selects the no-title
//! variants of the thresholds and category rows.
//!
//! Threshold source: the `calibration` artifact (default
//! [`DEFAULT_THRESHOLD`] = the first suggestive category base, 46 662 /
//! 100 000); `--threshold` overrides it. Unit tests evaluate synthetic
//! graphs/models only — the shipped artifacts are exercised by
//! `fetch-model.sh` + the startup fail-closed checks in `bundles::load`.
#[allow(unused_imports)] // used by the cfg(test) fixtures only
use std::path::PathBuf;

use image::imageops::{self, FilterType};
use image::RgbImage;
use serde::Deserialize;

use crate::bundles::LoadedBundle;
use crate::nlp::{NlpError, SnowballNlp, TitleClass};
use crate::onnx::{Model, OnnxError, Tensor};

/// Model input width in pixels (the shard graphs' fixed spatial size).
pub const INPUT_WIDTH: u32 = 224;
/// Model input height in pixels.
pub const INPUT_HEIGHT: u32 = 224;
/// Threshold used when the calibration artifact carries none (§7): the
/// first `SUGGESTIVE` category base (7 × 6 666) / 100 000, i.e. exactly the
/// point where the spliced score becomes flagged in CE's own semantics.
pub const DEFAULT_THRESHOLD: f64 = 46_662.0 / 100_000.0;

/// Evaluator-name prefix the JS bundle requires on the three image models
/// (`ENSEM_3CLS_EVAL_NAME`).
const EVALUATOR_PREFIX: &str = "ensem_3cls";

/// Scoring failures. The caller treats these as fail-closed (§7): the
/// process exits non-zero and the daemon's relaunch budget takes over.
#[derive(Debug, thiserror::Error)]
pub enum ScoreError {
    #[error("shard header invalid: {0}")]
    ShardHeader(String),
    #[error("shard model invalid: {0}")]
    Model(#[from] OnnxError),
    #[error("word model invalid: {0}")]
    Nlp(#[from] NlpError),
    #[error("calibration artifact invalid: {0}")]
    Calibration(String),
    #[error("crop has zero area")]
    EmptyCrop,
}

// ---------------------------------------------------------------------------
// Calibration artifact
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct CalibrationFile {
    #[serde(default)]
    threshold: Option<f64>,
}

/// Parse the `calibration` artifact: the flag threshold with the §7 default
/// ([`DEFAULT_THRESHOLD`]) when the field is absent.
pub fn parse_calibration(json: &str) -> Result<f64, ScoreError> {
    let file: CalibrationFile =
        serde_json::from_str(json).map_err(|err| ScoreError::Calibration(err.to_string()))?;
    let threshold = file.threshold.unwrap_or(DEFAULT_THRESHOLD);
    if !threshold.is_finite() || !(0.0..=1.0).contains(&threshold) {
        return Err(ScoreError::Calibration(format!(
            "threshold {threshold} is outside 0.0..=1.0"
        )));
    }
    Ok(threshold)
}

// ---------------------------------------------------------------------------
// Shard header + preprocessing
// ---------------------------------------------------------------------------

/// The `<model id>,<mean r>,<mean g>,<mean b>,<std r>,<std g>,<std b>` first
/// line of every shard (all three carry the identical header).
#[derive(Debug, Clone, PartialEq)]
pub struct ShardHeader {
    /// Evaluator/model id, e.g. `ensem_3cls-6.1.2`.
    pub model_id: String,
    /// Per-channel normalization means (pixel scale).
    pub mean: [f64; 3],
    /// Per-channel normalization scales (pixel scale, > 0).
    pub std: [f64; 3],
}

/// Split a decrypted shard into (header, protobuf body) and parse the
/// header. Fails closed on a missing/non-ensemble id or invalid numbers.
pub fn split_shard(plaintext: &[u8]) -> Result<(ShardHeader, &[u8]), ScoreError> {
    let newline = plaintext
        .iter()
        .position(|b| *b == b'\n')
        .ok_or_else(|| ScoreError::ShardHeader("no header line".into()))?;
    let header_bytes = &plaintext[..newline];
    let header = std::str::from_utf8(header_bytes)
        .map_err(|err| ScoreError::ShardHeader(format!("non-UTF-8 header: {err}")))?;
    let mut parts = header.split(',');
    let model_id = parts
        .next()
        .ok_or_else(|| ScoreError::ShardHeader("empty header".into()))?
        .to_string();
    if !model_id.starts_with(EVALUATOR_PREFIX) {
        return Err(ScoreError::ShardHeader(format!(
            "evaluator {model_id:?} does not start with {EVALUATOR_PREFIX:?}"
        )));
    }
    let mut numbers = [0.0f64; 6];
    for (slot, part) in numbers.iter_mut().zip(parts) {
        *slot = part
            .parse::<f64>()
            .map_err(|err| ScoreError::ShardHeader(format!("bad number {part:?}: {err}")))?;
    }
    let mean = [numbers[0], numbers[1], numbers[2]];
    let std = [numbers[3], numbers[4], numbers[5]];
    if mean.iter().chain(std.iter()).any(|v| !v.is_finite()) || std.iter().any(|v| *v <= 0.0) {
        return Err(ScoreError::ShardHeader(
            "mean/std not finite (std must be > 0)".into(),
        ));
    }
    Ok((
        ShardHeader {
            model_id,
            mean,
            std,
        },
        &plaintext[newline + 1..],
    ))
}

/// Build the model input tensor: bilinear resize to
/// [`INPUT_WIDTH`]×[`INPUT_HEIGHT`] (the production path resizes with
/// OpenCV's default bilinear filter), per-channel `(pixel − mean) / std`
/// from the shard header, laid out NCHW in `f32`.
pub fn preprocess(crop: &RgbImage, header: &ShardHeader) -> Result<Tensor, ScoreError> {
    if crop.width() == 0 || crop.height() == 0 {
        return Err(ScoreError::EmptyCrop);
    }
    let resized = imageops::resize(crop, INPUT_WIDTH, INPUT_HEIGHT, FilterType::Triangle);
    let plane = (INPUT_WIDTH * INPUT_HEIGHT) as usize;
    let mut data = vec![0.0f32; 3 * plane];
    for (index, pixel) in resized.pixels().enumerate() {
        let [r, g, b] = pixel.0;
        data[index] = ((f64::from(r) - header.mean[0]) / header.std[0]) as f32;
        data[plane + index] = ((f64::from(g) - header.mean[1]) / header.std[1]) as f32;
        data[2 * plane + index] = ((f64::from(b) - header.mean[2]) / header.std[2]) as f32;
    }
    Ok(Tensor {
        dims: vec![1, 3, INPUT_HEIGHT as usize, INPUT_WIDTH as usize],
        data,
    })
}

// ---------------------------------------------------------------------------
// Ensemble decision (the bundle's `threeClassScore` module)
// ---------------------------------------------------------------------------

/// One shard's softmax triple: `(class_a, class_b, class_c)`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ClassTriple {
    /// First output (the "clean"-side class).
    pub class_a: f64,
    /// Second output (the "suggestive"-side class).
    pub class_b: f64,
    /// Third output (the "explicit"-side class).
    pub class_c: f64,
}

/// The five discrete image classes of the ensemble decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageClass {
    HighlyClean,
    Clean,
    Suggestive,
    HighlySuggestive,
    Explicit,
}

/// How the explicit-side check combines the three shards.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DirtyCalc {
    /// `min(class_c) >= dirty`.
    MinimumGreaterEqual,
    /// `median(class_c) > dirty`.
    MedianGreater,
}

#[derive(Debug, Clone, Copy)]
struct Thresholds {
    highly_clean: f64,
    highly_suggestive_max_median_a: f64,
    highly_suggestive_min_max_b: f64,
    suggestive_max_median_a: f64,
    suggestive_min_median_b: f64,
    dirty: f64,
    dirty_calc: DirtyCalc,
}

/// `imageOnlyThresholds` from the bundle (no usable window title).
const IMAGE_ONLY_THRESHOLDS: Thresholds = Thresholds {
    highly_clean: 0.6,
    highly_suggestive_max_median_a: 0.00001,
    highly_suggestive_min_max_b: 0.00009,
    suggestive_max_median_a: 0.05,
    suggestive_min_median_b: 0.8,
    dirty: 0.999,
    dirty_calc: DirtyCalc::MinimumGreaterEqual,
};

/// `withWindowTitleThresholds` from the bundle (title present ⇒ the final
/// category table re-weights, so the image gate is relaxed).
const WITH_TITLE_THRESHOLDS: Thresholds = Thresholds {
    highly_clean: 0.6,
    highly_suggestive_max_median_a: 0.00001,
    highly_suggestive_min_max_b: 0.00009,
    suggestive_max_median_a: 0.05,
    suggestive_min_median_b: 0.8,
    dirty: 0.78,
    dirty_calc: DirtyCalc::MedianGreater,
};

fn median3(a: f64, b: f64, c: f64) -> f64 {
    b.max(a.min(c)).min(a.max(c))
}

/// Given `value` in `[min, max]`, its proportional location in `0..=1`.
fn scale0to1(value: f64, min: f64, max: f64) -> f64 {
    if max - min == 0.0 {
        return 0.0;
    }
    ((value - min) / (max - min)).clamp(0.0, 1.0)
}

/// Discrete ensemble decision + strength.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct EnsembleDecision {
    /// Discrete class.
    pub image_class: ImageClass,
    /// Class-relative strength in `0..=1`.
    pub strength: f64,
}

/// Fold the three shard triples through the threshold set (the bundle's
/// `finalScoreUsingThreshold`). Deterministic deviation: the bundle returns
/// a random strength for `HighlyClean` (feed-diversification); scores never
/// leave the device here, so the strongest-clean value 1.0 is used.
fn ensemble_decision(scores: &[ClassTriple; 3], t: &Thresholds) -> EnsembleDecision {
    let median_a = median3(scores[0].class_a, scores[1].class_a, scores[2].class_a);
    let values_b = [scores[0].class_b, scores[1].class_b, scores[2].class_b];
    let values_c = [scores[0].class_c, scores[1].class_c, scores[2].class_c];
    let median_b = median3(values_b[0], values_b[1], values_b[2]);
    let median_c = median3(values_c[0], values_c[1], values_c[2]);

    if median_a > t.highly_clean {
        return EnsembleDecision {
            image_class: ImageClass::HighlyClean,
            strength: 1.0,
        };
    }
    match t.dirty_calc {
        DirtyCalc::MedianGreater => {
            if median_c > t.dirty {
                return EnsembleDecision {
                    image_class: ImageClass::Explicit,
                    strength: scale0to1(median_c, t.dirty, 1.0),
                };
            }
        }
        DirtyCalc::MinimumGreaterEqual => {
            let min_c = values_c.iter().copied().fold(f64::INFINITY, f64::min);
            if min_c >= t.dirty {
                return EnsembleDecision {
                    image_class: ImageClass::Explicit,
                    strength: scale0to1(min_c, t.dirty, 1.0),
                };
            }
        }
    }
    let max_b = values_b.iter().copied().fold(f64::NEG_INFINITY, f64::max);
    if median_a < t.highly_suggestive_max_median_a && max_b > t.highly_suggestive_min_max_b {
        return EnsembleDecision {
            image_class: ImageClass::HighlySuggestive,
            strength: 1.0 - scale0to1(median_a, 0.0, t.highly_suggestive_max_median_a),
        };
    }
    if median_a < t.suggestive_max_median_a && median_b > t.suggestive_min_median_b {
        return EnsembleDecision {
            image_class: ImageClass::Suggestive,
            strength: scale0to1(median_b, t.suggestive_min_median_b, 1.0),
        };
    }
    EnsembleDecision {
        image_class: ImageClass::Clean,
        strength: scale0to1(median_a, 0.0, t.highly_clean),
    }
}

/// Linear step constants of the 15-row category table
/// (`STEP_TO_NEXT_CATEGORY` / `RANGE_PER_CATEGORY`).
const NUM_CATEGORIES: u64 = 15;
const STEP: u64 = 100_000 / NUM_CATEGORIES; // 6_666 (floor)
const RANGE: u64 = STEP - 1; // 6_665

/// The category table rows, verbatim from the bundle (order matters: the
/// first `SUGGESTIVE`/`EXPLICIT` rows define the label thresholds).
/// `(image class, title class, base value, invert strength, final label)`.
const CATEGORY_TABLE: [(ImageClass, Option<TitleClass>, u64, bool, SpliceLabel); 15] = [
    (
        ImageClass::HighlyClean,
        Some(TitleClass::Unflagged),
        0,
        true,
        SpliceLabel::Unflagged,
    ),
    (
        ImageClass::HighlyClean,
        None,
        STEP,
        true,
        SpliceLabel::Unflagged,
    ),
    (
        ImageClass::Clean,
        Some(TitleClass::Unflagged),
        2 * STEP,
        true,
        SpliceLabel::Unflagged,
    ),
    (
        ImageClass::Clean,
        None,
        3 * STEP,
        true,
        SpliceLabel::Unflagged,
    ),
    (
        ImageClass::HighlyClean,
        Some(TitleClass::Explicit),
        4 * STEP,
        true,
        SpliceLabel::Unflagged,
    ),
    (
        ImageClass::Clean,
        Some(TitleClass::Explicit),
        5 * STEP,
        true,
        SpliceLabel::Unflagged,
    ),
    // split between safe unflagged (above) and unsafe unflagged (below)
    (
        ImageClass::Explicit,
        Some(TitleClass::Unflagged),
        6 * STEP,
        false,
        SpliceLabel::Unflagged,
    ),
    (
        ImageClass::Suggestive,
        Some(TitleClass::Unflagged),
        7 * STEP,
        false,
        SpliceLabel::Suggestive,
    ),
    (
        ImageClass::HighlySuggestive,
        Some(TitleClass::Unflagged),
        8 * STEP,
        false,
        SpliceLabel::Suggestive,
    ),
    (
        ImageClass::Suggestive,
        None,
        9 * STEP,
        false,
        SpliceLabel::Suggestive,
    ),
    (
        ImageClass::HighlySuggestive,
        None,
        10 * STEP,
        false,
        SpliceLabel::Suggestive,
    ),
    (
        ImageClass::Suggestive,
        Some(TitleClass::Explicit),
        11 * STEP,
        false,
        SpliceLabel::Suggestive,
    ),
    (
        ImageClass::HighlySuggestive,
        Some(TitleClass::Explicit),
        12 * STEP,
        false,
        SpliceLabel::Suggestive,
    ),
    (
        ImageClass::Explicit,
        None,
        13 * STEP,
        false,
        SpliceLabel::Explicit,
    ),
    (
        ImageClass::Explicit,
        Some(TitleClass::Explicit),
        14 * STEP,
        false,
        SpliceLabel::Explicit,
    ),
];

/// The three final labels of the splice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpliceLabel {
    Unflagged,
    Suggestive,
    Explicit,
}

/// Splice one ensemble decision with the title class into the linear value
/// (the bundle's `spliceScores`).
fn splice(decision: EnsembleDecision, title_class: Option<TitleClass>) -> (u64, SpliceLabel) {
    let (base, invert, label) = CATEGORY_TABLE
        .iter()
        .find(|(image, title, ..)| *image == decision.image_class && *title == title_class)
        .map(|(_, _, base, invert, label)| (*base, *invert, *label))
        .expect("every (image class, title class) combination is covered");
    let mut strength = decision.strength.clamp(0.0, 1.0);
    if invert {
        strength = 1.0 - strength;
    }
    let linear = (base as f64 + RANGE as f64 * strength) as u64;
    (linear.min(99_999), label)
}

// ---------------------------------------------------------------------------
// Window-title preprocessing (the bundle's `fixAndFilterWindowTitle`)
// ---------------------------------------------------------------------------

/// Shannon entropy of the character distribution.
fn shannon_entropy(text: &str) -> f64 {
    if text.is_empty() {
        return 0.0;
    }
    let mut counts: Vec<(char, u64)> = Vec::new();
    for ch in text.chars() {
        match counts.iter_mut().find(|(c, _)| *c == ch) {
            Some((_, n)) => *n += 1,
            None => counts.push((ch, 1)),
        }
    }
    let total = text.chars().count() as f64;
    -counts
        .iter()
        .map(|(_, n)| {
            let p = *n as f64 / total;
            p * p.log2()
        })
        .sum::<f64>()
}

/// Strings that carry no content signal on their own (bundle `nonContext`).
const NON_CONTEXT: [&str; 14] = [
    "google chrome",
    "google search",
    "pdf",
    "word",
    "videoplayer",
    "document",
    "chat",
    "vlc media player",
    "onedrive",
    "unknown title",
    "window",
    "photo booth",
    "remote play",
    "photos",
];

/// Entropy acceptance window (bundle `MIN_ENTROPY`/`MAX_ENTROPY`).
const MIN_ENTROPY: f64 = 1.55;
const MAX_ENTROPY: f64 = 5.55;

/// Drop non-content titles: `true` ⇒ filter out (upstream
/// `filterWindowTitle`).
fn filter_window_title(title: &str) -> bool {
    // `underscoresToSpaces`: lowercased, then each underscore *run*
    // collapses to a single space. Every remaining check sees this text.
    let lowered = title.to_lowercase();
    let mut spaced = String::with_capacity(lowered.len());
    let mut in_underscore_run = false;
    for ch in lowered.chars() {
        if ch == '_' {
            if !in_underscore_run {
                spaced.push(' ');
            }
            in_underscore_run = true;
        } else {
            spaced.push(ch);
            in_underscore_run = false;
        }
    }
    // `stripNonAlphaChars`: drop symbols before the non-context comparison.
    let stripped: String = spaced
        .trim()
        .chars()
        .filter(|ch| ch.is_ascii_lowercase() || ch.is_whitespace())
        .collect::<String>()
        .trim()
        .to_string();
    if NON_CONTEXT.contains(&stripped.as_str()) {
        return true;
    }
    // `allWordsHaveNonAlpha`: every word must contain a digit or one of
    // `@#$%^&`. Words split on runs of whitespace/`;`/`,`; a leading or
    // trailing `;`/`,` (whitespace is trimmed first) yields an empty
    // word, which fails the digit test and keeps the title.
    let text = spaced.trim();
    let boundary_empty = text.is_empty()
        || text.starts_with(';')
        || text.starts_with(',')
        || text.ends_with(';')
        || text.ends_with(',');
    if !boundary_empty
        && text
            .split(|ch: char| ch.is_whitespace() || ch == ';' || ch == ',')
            .filter(|w| !w.is_empty())
            .all(|w| {
                w.chars()
                    .any(|ch| ch.is_ascii_digit() || "@#$%^&".contains(ch))
            })
    {
        return true;
    }
    // Entropy bounds (computed on the underscore-spaced text).
    let entropy = shannon_entropy(&spaced);
    !(MIN_ENTROPY..=MAX_ENTROPY).contains(&entropy)
}

/// Replace in-word symbols with their letters (upstream `replaceSymbols`:
/// only the inner characters are rewritten; word edges are preserved).
fn replace_symbols(word: &str) -> String {
    // (ordered) symbol → letter pairs of the upstream `leetMap`; grouped
    // upstream entries are flattened in their listed order.
    const LEET: [(&str, &str); 12] = [
        ("@", "a"),
        ("6", "b"),
        ("(", "c"),
        ("3", "e"),
        ("||", "ll"),
        ("11", "ll"),
        ("|", "l"),
        ("!", "i"),
        ("0", "o"),
        ("5", "s"),
        ("$", "s"),
        ("+", "t"),
    ];
    let chars: Vec<char> = word.chars().collect();
    if chars.len() <= 2 {
        return word.to_string();
    }
    let mut inner: String = chars[1..chars.len() - 1].iter().collect();
    for (symbol, letter) in LEET {
        inner = inner.replace(symbol, letter);
    }
    format!("{}{}{}", chars[0], inner, chars[chars.len() - 1])
}

/// Known-misspelling correction table (upstream `targetWordMap`, applied
/// as literal replacements after symbol normalization, in the upstream
/// group order).
const SPELLING_FIXES: [(&str, &str); 20] = [
    ("shrot", "short"),
    ("shtro", "short"),
    ("shtor", "short"),
    ("v*deo", "video"),
    ("vid*o", "video"),
    ("vidoe", "video"),
    ("vdieo", "video"),
    ("*ideo", "video"),
    ("v*doe", "video"),
    ("p*rn", "porn"),
    ("pron", "porn"),
    ("pirn", "porn"),
    ("s^x", "sex"),
    ("sxe", "sex"),
    ("s*x", "sex"),
    ("h#t", "hot"),
    ("hto", "hot"),
    ("h*t", "hot"),
    ("seh", "she"),
    ("rou", "our"),
];

/// Normalize leet-speak titles (upstream `normalizeLeetSpeak`).
fn normalize_leet_speak(title: &str) -> String {
    let lowered = title.to_lowercase();
    // Words = runs that do not contain whitespace or `;,:-`.
    let mut out = String::with_capacity(lowered.len());
    let mut word = String::new();
    for ch in lowered.chars() {
        if ch.is_whitespace() || matches!(ch, ';' | ',' | ':' | '-') {
            out.push_str(&replace_symbols(&word));
            word.clear();
            out.push(ch);
        } else {
            word.push(ch);
        }
    }
    out.push_str(&replace_symbols(&word));
    for (wrong, right) in SPELLING_FIXES {
        out = out.replace(wrong, right);
    }
    out
}

/// Upstream `fixAndFilterWindowTitle`: empty in ⇒ empty out; otherwise
/// leet-normalize, then drop filtered titles to the empty string. The
/// underscore-to-space conversion exists only inside the filter's checks —
/// a kept title preserves its original underscores.
fn fix_and_filter_window_title(title: &str) -> String {
    if title.is_empty() {
        return String::new();
    }
    let normalized = normalize_leet_speak(title);
    if filter_window_title(&normalized) {
        String::new()
    } else {
        normalized
    }
}

// ---------------------------------------------------------------------------
// The scorer
// ---------------------------------------------------------------------------

/// What the consumer drives. Production uses [`Scorer`]; tests inject fakes.
pub trait WindowScorer {
    /// Score one window crop + title into `0..=1` (spliced linear /
    /// 100 000). An empty/filtered title uses the no-title decision paths.
    fn score_window(&mut self, crop: &RgbImage, window_title: &str) -> Result<f64, ScoreError>;
    /// Flag threshold: `score >= threshold()` ⇒ flagged (§7).
    fn threshold(&self) -> f64;
}

/// One loaded shard (graph + normalization header).
struct Shard {
    model: Model,
    header: ShardHeader,
}

/// The CE-ensemble-backed [`WindowScorer`].
pub struct Scorer {
    shards: Vec<Shard>,
    nlp: SnowballNlp,
    threshold: f64,
    threshold_source: &'static str,
}

impl Scorer {
    /// Verify-and-load: the bundle is already hash-validated + decrypted by
    /// [`crate::bundles::load`]; this parses the three shard graphs, the
    /// word model and the calibration artifact.
    pub fn open(
        bundle: &LoadedBundle,
        threshold_override: Option<f64>,
    ) -> Result<Self, ScoreError> {
        let mut shards = Vec::with_capacity(bundle.scorer_shards.len());
        let mut model_id: Option<String> = None;
        for artifact in &bundle.scorer_shards {
            let (header, body) = split_shard(&artifact.plaintext)?;
            match &model_id {
                None => model_id = Some(header.model_id.clone()),
                Some(seen) if *seen == header.model_id => {}
                Some(seen) => {
                    return Err(ScoreError::ShardHeader(format!(
                        "shard {} carries model id {:?}, expected {seen:?}",
                        artifact.id, header.model_id
                    )));
                }
            }
            let model = Model::parse(body)?;
            shards.push(Shard { model, header });
        }
        let nlp = SnowballNlp::parse(&bundle.labels.plaintext)?;
        let calibrated = parse_calibration(
            std::str::from_utf8(&bundle.calibration.plaintext)
                .map_err(|err| ScoreError::Calibration(err.to_string()))?,
        )?;
        let (threshold, threshold_source) = match threshold_override {
            Some(overridden) => (overridden, "--threshold override"),
            None => (calibrated, "calibration artifact"),
        };
        Ok(Self {
            shards,
            nlp,
            threshold,
            threshold_source,
        })
    }

    /// Where the active threshold came from (startup log, §14).
    pub fn threshold_source(&self) -> &'static str {
        self.threshold_source
    }

    /// The full per-window decision (score + splice label + title class),
    /// exposed for tests and logging.
    pub fn evaluate(
        &mut self,
        crop: &RgbImage,
        window_title: &str,
    ) -> Result<(f64, SpliceLabel), ScoreError> {
        let fixed_title = fix_and_filter_window_title(window_title);
        let title_class = if fixed_title.is_empty() {
            None
        } else {
            Some(self.nlp.score(&fixed_title).class)
        };

        let mut triples = [ClassTriple {
            class_a: 0.0,
            class_b: 0.0,
            class_c: 0.0,
        }; 3];
        // All shards share the header parameters (identical header line,
        // id-validated at open) — the crop is normalized once.
        let input = preprocess(crop, &self.shards[0].header)?;
        for (slot, shard) in triples.iter_mut().zip(&self.shards) {
            let output = shard.model.run(input.clone())?;
            let values = &output.data;
            if values.len() != 3 || values.iter().any(|v| !v.is_finite()) {
                return Err(ScoreError::ShardHeader(format!(
                    "model output has {} non-triple values",
                    values.len()
                )));
            }
            *slot = ClassTriple {
                class_a: f64::from(values[0]),
                class_b: f64::from(values[1]),
                class_c: f64::from(values[2]),
            };
        }

        let thresholds = match title_class {
            Some(_) => &WITH_TITLE_THRESHOLDS,
            None => &IMAGE_ONLY_THRESHOLDS,
        };
        let decision = ensemble_decision(&triples, thresholds);
        let (linear, label) = splice(decision, title_class);
        Ok((linear as f64 / 100_000.0, label))
    }
}

impl WindowScorer for Scorer {
    fn score_window(&mut self, crop: &RgbImage, window_title: &str) -> Result<f64, ScoreError> {
        self.evaluate(crop, window_title).map(|(score, _)| score)
    }

    fn threshold(&self) -> f64 {
        self.threshold
    }
}

#[cfg(test)]
pub(crate) mod testutil {
    //! Synthetic shard/word-model builders shared with the consumer tests.

    use crate::onnx::testutil::{attr_int, len_field, node, tensor, u64_field, value_info};

    /// A shard whose head is constant across crops: `GAP → Flatten → Gemm`
    /// with a zero weight matrix and the given class logits as bias, then
    /// `Softmax`.
    pub fn synthetic_shard(model_id: &str, logits: [f32; 3]) -> Vec<u8> {
        let mut graph = Vec::new();
        len_field(
            &mut graph,
            1,
            &node("GlobalAveragePool", "gap", &["x"], "z", &[]),
        );
        len_field(&mut graph, 1, &node("Flatten", "flat", &["z"], "f", &[]));
        len_field(
            &mut graph,
            1,
            &node(
                "Gemm",
                "gemm",
                &["f", "cw", "cb"],
                "logits",
                &[attr_int("transB", 0)],
            ),
        );
        len_field(
            &mut graph,
            1,
            &node("Softmax", "sm", &["logits"], "out", &[]),
        );
        len_field(&mut graph, 5, &tensor("cw", &[3, 3], &[0.0; 9]));
        len_field(&mut graph, 5, &tensor("cb", &[3], &logits));
        len_field(&mut graph, 11, &value_info("x"));
        len_field(&mut graph, 12, &value_info("out"));

        let mut model = Vec::new();
        u64_field(&mut model, 1, 6);
        len_field(&mut model, 7, &graph);

        let mut shard = Vec::new();
        shard.extend_from_slice(
            format!("{model_id},157.0,143.0,135.0,84.32674546073743,84.45116932286965,87.61278445523804\n")
                .as_bytes(),
        );
        shard.extend_from_slice(&model);
        shard
    }

    /// A minimal word model: 160 stopwords, vocabulary `alpha` → feature 0,
    /// one strong negative row ⇒ any title containing "alpha" is explicit.
    pub fn synthetic_sw() -> Vec<u8> {
        fn put_u32(out: &mut Vec<u8>, value: u32) {
            out.extend_from_slice(&value.to_le_bytes());
        }
        fn put_f32(out: &mut Vec<u8>, value: f32) {
            out.extend_from_slice(&value.to_le_bytes());
        }
        fn put_f64(out: &mut Vec<u8>, value: f64) {
            out.extend_from_slice(&value.to_le_bytes());
        }

        let mut out = Vec::new();
        out.extend_from_slice(b"Snowball NLP 2.0\nrbf\n");
        for i in 0..160 {
            out.extend_from_slice(format!("stopword{i}\n").as_bytes());
        }
        out.push(b'\n');
        out.extend_from_slice(b"alpha\n");
        put_u32(&mut out, 0);
        for i in 1..160 {
            out.extend_from_slice(format!("filler{i}\n").as_bytes());
            put_u32(&mut out, i as u32);
        }
        out.push(b'\n');
        put_u32(&mut out, 160);
        for i in 0..160 {
            put_f64(&mut out, if i == 0 { 1.0 } else { 0.0 });
        }
        let triples = 167usize;
        put_u32(&mut out, (triples * 3) as u32);
        for t in 0..triples {
            put_f32(&mut out, t as f32);
            put_f32(&mut out, 0.0);
            put_f32(&mut out, 1.0);
        }
        put_u32(&mut out, triples as u32);
        for t in 0..triples {
            put_f32(&mut out, if t == 0 { -2.0 } else { 0.0 });
        }
        put_u32(&mut out, triples as u32);
        for t in 0..triples {
            put_u32(&mut out, t as u32);
        }
        put_f32(&mut out, -0.5);
        put_f32(&mut out, 1.0);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use image::{Rgb, RgbImage};

    fn triple(a: f64, b: f64, c: f64) -> ClassTriple {
        ClassTriple {
            class_a: a,
            class_b: b,
            class_c: c,
        }
    }

    #[test]
    fn shard_header_parses_and_rejects_foreign_ids() {
        let bytes = b"ensem_3cls-6.1.2,157.0,143.0,135.0,84.3,84.4,87.6\nBINARY";
        let (header, body) = split_shard(bytes).expect("header");
        assert_eq!(header.model_id, "ensem_3cls-6.1.2");
        assert_eq!(header.mean, [157.0, 143.0, 135.0]);
        assert_eq!(header.std, [84.3, 84.4, 87.6]);
        assert_eq!(body, b"BINARY");

        assert!(matches!(
            split_shard(b"other_model-1.0,1,2,3,4,5,6\n"),
            Err(ScoreError::ShardHeader(_))
        ));
        assert!(matches!(
            split_shard(b"ensem_3cls-6.1.2,1,2,3,4,5,0\n"),
            Err(ScoreError::ShardHeader(_))
        ));
        assert!(matches!(
            split_shard(b"ensem_3cls-6.1.2,1,2,3,4,5,x\n"),
            Err(ScoreError::ShardHeader(_))
        ));
        assert!(matches!(
            split_shard(b"no-newline"),
            Err(ScoreError::ShardHeader(_))
        ));
    }

    #[test]
    fn calibration_defaults_and_validation() {
        assert_eq!(parse_calibration("{}").unwrap(), DEFAULT_THRESHOLD);
        assert_eq!(parse_calibration(r#"{"threshold":0.9}"#).unwrap(), 0.9);
        assert!(matches!(
            parse_calibration(r#"{"threshold":1.5}"#),
            Err(ScoreError::Calibration(_))
        ));
        assert!(matches!(
            parse_calibration(r#"{"threshold":"high"}"#),
            Err(ScoreError::Calibration(_))
        ));
        assert!(matches!(
            parse_calibration("not json"),
            Err(ScoreError::Calibration(_))
        ));
    }

    #[test]
    fn ensemble_thresholds_pick_expected_classes() {
        // All-sharp class_a ⇒ HighlyClean (median > 0.6).
        let decision = ensemble_decision(&[triple(0.9, 0.05, 0.05); 3], &IMAGE_ONLY_THRESHOLDS);
        assert_eq!(decision.image_class, ImageClass::HighlyClean);

        // All-sharp class_c ⇒ Explicit via the minimum rule.
        let decision = ensemble_decision(&[triple(0.05, 0.05, 0.9995); 3], &IMAGE_ONLY_THRESHOLDS);
        assert_eq!(decision.image_class, ImageClass::Explicit);

        // One dissenting shard blocks the minimum rule but not the median
        // rule (with-title thresholds).
        let mixed = [
            triple(0.05, 0.05, 0.9995),
            triple(0.05, 0.05, 0.9995),
            triple(0.5, 0.4, 0.1),
        ];
        assert_eq!(
            ensemble_decision(&mixed, &IMAGE_ONLY_THRESHOLDS).image_class,
            ImageClass::Clean
        );
        assert_eq!(
            ensemble_decision(&mixed, &WITH_TITLE_THRESHOLDS).image_class,
            ImageClass::Explicit
        );

        // Suggestive band: tiny class_a, dominant class_b.
        let decision = ensemble_decision(&[triple(0.01, 0.9, 0.02); 3], &IMAGE_ONLY_THRESHOLDS);
        assert_eq!(decision.image_class, ImageClass::Suggestive);

        // Highly-suggestive band: near-zero class_a, any class_b above the
        // sliver bound.
        let decision = ensemble_decision(&[triple(0.0, 0.001, 0.0); 3], &IMAGE_ONLY_THRESHOLDS);
        assert_eq!(decision.image_class, ImageClass::HighlySuggestive);

        // Plain clean fallback.
        let decision = ensemble_decision(&[triple(0.55, 0.3, 0.15); 3], &IMAGE_ONLY_THRESHOLDS);
        assert_eq!(decision.image_class, ImageClass::Clean);
    }

    #[test]
    fn splice_table_matches_category_bases() {
        let clean = EnsembleDecision {
            image_class: ImageClass::HighlyClean,
            strength: 1.0,
        };
        // Inverted strength: 1.0 ⇒ 0 extra ⇒ base 0 without a title.
        assert_eq!(splice(clean, None), (STEP, SpliceLabel::Unflagged));
        assert_eq!(
            splice(clean, Some(TitleClass::Unflagged)),
            (0, SpliceLabel::Unflagged)
        );

        let explicit = EnsembleDecision {
            image_class: ImageClass::Explicit,
            strength: 1.0,
        };
        // EXPLICIT without a title sits in the "unsafe unflagged" band
        // (base 13·6666 = 86 658 here, still below full strength range).
        assert_eq!(
            splice(explicit, None),
            (13 * STEP + RANGE, SpliceLabel::Explicit)
        );

        // Suggestive label threshold: 46 662 — exactly DEFAULT_THRESHOLD.
        let suggestive = EnsembleDecision {
            image_class: ImageClass::Suggestive,
            strength: 0.0,
        };
        let (linear, label) = splice(suggestive, Some(TitleClass::Unflagged));
        assert_eq!(linear, 7 * STEP);
        assert_eq!(label, SpliceLabel::Suggestive);
        assert_eq!(linear as f64 / 100_000.0, DEFAULT_THRESHOLD);

        // EXPLICIT + UNFLAGGED title lands below the suggestive threshold:
        // "unsafe unflagged" ⇒ not flagged, per the category table.
        let (linear, label) = splice(explicit, Some(TitleClass::Unflagged));
        assert!(linear as f64 / 100_000.0 < DEFAULT_THRESHOLD);
        assert_eq!(label, SpliceLabel::Unflagged);
    }

    #[test]
    fn title_pipeline_filters_and_normalizes() {
        // Non-context titles collapse to empty.
        assert_eq!(fix_and_filter_window_title("Google Chrome"), "");
        // Repeated words are NOT deduplicated upstream (no such step
        // exists): "photos - Photos" maps to "photos - photos", which
        // has a non-digit word and sits inside the entropy window, so
        // it is kept.
        assert_eq!(
            fix_and_filter_window_title("photos - Photos"),
            "photos - photos"
        );
        assert_eq!(fix_and_filter_window_title(""), "");
        // All-symbol / digit-soup words are dropped.
        assert_eq!(fix_and_filter_window_title("5!$+ $$"), "");
        // Very low-entropy titles are dropped.
        assert_eq!(fix_and_filter_window_title("aaaaaaaaaaaa"), "");
        // Underscore runs convert to spaces only inside the filter's
        // checks: "google_search" matches the non-context list and is
        // dropped; "google_search__pies" is kept with its original
        // underscores.
        assert_eq!(fix_and_filter_window_title("google_search"), "");
        assert_eq!(
            fix_and_filter_window_title("google_search__pies"),
            "google_search__pies"
        );

        // The leet step rewrites only a word's interior, so the trailing
        // symbol of "vdi30" survives (maps to "vdie0") and the
        // digit-bearing word is dropped. A word the correction table
        // rescues is kept: "vdieo" maps to "video".
        assert_eq!(fix_and_filter_window_title("vdi30"), "");
        assert_eq!(fix_and_filter_window_title("vdieo"), "video");
    }

    #[test]
    fn synthetic_crop_produces_numeric_three_class_decisions() {
        use super::testutil;
        use crate::bundles::{Artifact, ModelInfo};

        fn artifact(role: crate::bundles::Role, plaintext: Vec<u8>) -> Artifact {
            Artifact {
                role,
                version: "test".to_string(),
                sha512: "0".repeat(128),
                id: format!("{}-{}", "0".repeat(20), role.as_str()),
                path: PathBuf::from("/nonexistent"),
                plaintext,
            }
        }

        // Three identical shards: strong class_a bias (all-clean image).
        let clean_shard = testutil::synthetic_shard("ensem_3cls-6.1.2", [6.0, 0.0, -6.0]);
        let bundle_clean = LoadedBundle {
            bundle_version: "test".to_string(),
            model: ModelInfo {
                name: "ensem_3cls-6.1.2".to_string(),
                revision: "test".to_string(),
                license: "test".to_string(),
                source: "test".to_string(),
            },
            scorer_shards: (0..3)
                .map(|_| artifact(crate::bundles::Role::Scorer, clean_shard.clone()))
                .collect(),
            labels: artifact(crate::bundles::Role::Labels, testutil::synthetic_sw()),
            calibration: artifact(
                crate::bundles::Role::Calibration,
                br#"{"schemaVersion":"1.0.0"}"#.to_vec(),
            ),
            upstream_manifest: None,
        };
        let mut scorer = Scorer::open(&bundle_clean, None).expect("open");
        let crop = RgbImage::from_pixel(16, 16, Rgb([200, 180, 160]));
        let (score, label) = scorer.evaluate(&crop, "").expect("score");
        assert!((0.0..=1.0).contains(&score));
        // median class_a ≈ 0.9975 > 0.6 ⇒ HighlyClean ⇒ base 6 666.
        assert_eq!(label, SpliceLabel::Unflagged);
        assert!((score - 6_666.0 / 100_000.0).abs() < 1e-6);
        assert!(score < scorer.threshold(), "clean crop is not flagged");

        // Strong class_b bias: Suggestive band ⇒ flagged.
        let sugg_shard = testutil::synthetic_shard("ensem_3cls-6.1.2", [-6.0, 0.0, -6.0]);
        let bundle_sugg = LoadedBundle {
            scorer_shards: (0..3)
                .map(|_| artifact(crate::bundles::Role::Scorer, sugg_shard.clone()))
                .collect(),
            ..bundle_clean.clone()
        };
        let mut scorer = Scorer::open(&bundle_sugg, None).expect("open");
        let (score, label) = scorer.evaluate(&crop, "").expect("score");
        assert_eq!(label, SpliceLabel::Suggestive);
        assert!(score >= scorer.threshold(), "score {score} flagged");
        // median_b ≈ 0.9975 ⇒ strength ≈ 0.9874; base 9·6666.
        assert!(score > 0.6 && score < 0.7, "score {score}");

        // The same crop with a vocabulary-hitting title flips to the
        // with-title thresholds (image gate relaxed, explicit check on the
        // median): the title word model drags the decision via the category
        // table's explicit-title rows.
        let (titled, titled_label) = scorer.evaluate(&crop, "alpha").expect("score");
        assert!(titled > 0.0);
        assert_ne!(titled_label, SpliceLabel::Unflagged);
    }
}
