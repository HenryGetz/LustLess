//! Window-title feature model (`sw`) — parser + native evaluator.
//!
//! Format recovered from the shipped artifact and the classifier's own
//! loader (`cv::pn::BinarySnowballNLPClassifier`, `pornDetection/src/
//! binarySnowball.cpp`, decompiled read-only):
//!
//! ```text
//! line   "Snowball NLP 2.0"        magic (must match exactly)
//! line   "rbf"                     kernel marker (must match exactly)
//! line×  stopwords                 until an empty line (loader: ≥ 151)
//! pair×  <word> \n <u32 LE id>     vocabulary, terminated by an empty line
//!                                  (loader: ≥ 151; ids < vocabulary size)
//! u32 LE count (= vocabulary size)
//! f64 LE × count                    per-feature values (added on each hit)
//! u32 LE items (500..=200000, items % 3 == 0)
//! (f32 alpha, f32 feature id, f32 weight) × items   sparse rows, grouped
//!                                  by alpha (= row index, gaps allowed)
//! u32 LE rows                      (== max alpha + 1)
//! f32 × rows                       per-row coefficients
//! u32 LE rows                      (repeated count)
//! i32 × rows                       row indices into the kernel table
//! f32 rho                          decision offset (used negated)
//! f32 gamma                        kernel scale (used negated: exp(-γ·d²))
//! ```
//!
//! Evaluation (matches `BinarySnowballNLPAlgorithm::predict` +
//! `SvmRbf` decompilation and the `bw.BinarySnowball.classify` semantics the
//! JS bundle consumes):
//!
//! 1. lowercase the title, split on whitespace and `- . / :`;
//! 2. drop tokens containing digits or symbol characters, drop stopwords;
//! 3. stem the survivors with the Snowball **English** algorithm (the
//!    loader instantiates libstemmer `"english"` — same algorithm as the
//!    `rust-stemmers` crate);
//! 4. feature vector `x` (dense, vocabulary size): for every remaining stem
//!    present in the vocabulary, `x[id] += value[id]` (repeat hits add up);
//! 5. L2-normalize `x`;
//! 6. decision `= -rho + Σ_i coef[i] · exp(-γ · ‖x - row[idx[i]]‖²)` with the
//!    sparse-row distance `‖x - row‖² = ‖x‖² + Σ w² - 2 Σ x[f]·w`;
//! 7. class = `EXPLICIT` when the decision is ≤ 0, else `UNFLAGGED`; the
//!    raw decision value is reported alongside (the JS bundle forwards both
//!    as `model_scores.class` / `model_scores.scores[0]`).

use std::collections::{HashMap, HashSet};

use rayon::prelude::*;
use rust_stemmers::{Algorithm, Stemmer};

/// The magic header line the loader validates (`Bad NLP file version`).
const MAGIC: &str = "Snowball NLP 2.0";
/// The kernel marker the loader validates (`Unknown kernel type`).
const KERNEL: &str = "rbf";
/// Loader invariants (`stopWords_.size() > MIN_STOPWORDS`,
/// `vectorVocabList_.size() > MIN_VOCAB`).
const MIN_ENTRIES: usize = 0x97;
/// Loader bounds for the sparse-row item count (`loadSupportVectors`).
const MIN_SV_ITEMS: usize = 500;
const MAX_SV_ITEMS: usize = 200_000;

/// Parse failures (fail-closed: the caller aborts scoring).
#[derive(Debug, thiserror::Error)]
pub enum NlpError {
    #[error("sw: missing line {0:?}")]
    MissingLine(&'static str),
    #[error("sw: {0}")]
    Format(String),
    #[error("sw: item count {0} out of range")]
    CountRange(u64),
}

/// Title classification result of the word model.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TitleClass {
    /// Decision > 0.
    Unflagged,
    /// Decision ≤ 0.
    Explicit,
}

/// One title scoring result (mirrors the `nlp_wintitle-1.0.0` evaluator).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct TitleScore {
    /// Discrete class.
    pub class: TitleClass,
    /// Raw decision value.
    pub decision: f64,
}

/// One sparse support-vector row: (feature id, weight).
struct Row {
    entries: Vec<(u32, f32)>,
    /// `Σ weight²` (precomputed at load, as the CE loader does).
    norm2: f64,
}

/// The parsed word/feature model.
pub struct SnowballNlp {
    stopwords: HashSet<String>,
    /// Stemmed word → (feature id, feature value).
    vocab: HashMap<String, (u32, f64)>,
    /// Number of features (= vocabulary size).
    features: usize,
    rows: Vec<Row>,
    coefficients: Vec<f32>,
    row_indices: Vec<u32>,
    rho: f32,
    gamma: f32,
    stemmer: Stemmer,
}

struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    /// Read one `\n`-terminated line (without the delimiter).
    fn line(&mut self) -> Result<Option<&'a str>, NlpError> {
        if self.pos >= self.bytes.len() {
            return Ok(None);
        }
        let rest = &self.bytes[self.pos..];
        let end = rest
            .iter()
            .position(|b| *b == b'\n')
            .ok_or_else(|| NlpError::Format("unterminated line".into()))?;
        let line = std::str::from_utf8(&rest[..end])
            .map_err(|_| NlpError::Format("non-UTF-8 line".into()))?;
        self.pos += end + 1;
        Ok(Some(line))
    }

    fn u32_le(&mut self) -> Result<u32, NlpError> {
        let end = self
            .pos
            .checked_add(4)
            .ok_or_else(|| NlpError::Format("truncated u32".into()))?;
        let bytes = self
            .bytes
            .get(self.pos..end)
            .ok_or_else(|| NlpError::Format("truncated u32".into()))?;
        self.pos = end;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn f32_le(&mut self) -> Result<f32, NlpError> {
        Ok(f32::from_bits(self.u32_le()?))
    }

    fn f64_le(&mut self) -> Result<f64, NlpError> {
        let end = self
            .pos
            .checked_add(8)
            .ok_or_else(|| NlpError::Format("truncated f64".into()))?;
        let bytes = self
            .bytes
            .get(self.pos..end)
            .ok_or_else(|| NlpError::Format("truncated f64".into()))?;
        self.pos = end;
        let mut buf = [0u8; 8];
        buf.copy_from_slice(bytes);
        Ok(f64::from_le_bytes(buf))
    }
}

impl SnowballNlp {
    /// Parse the decrypted `sw` plaintext.
    pub fn parse(bytes: &[u8]) -> Result<Self, NlpError> {
        let mut c = Cursor { bytes, pos: 0 };

        if c.line()? != Some(MAGIC) {
            return Err(NlpError::MissingLine(MAGIC));
        }
        if c.line()? != Some(KERNEL) {
            return Err(NlpError::MissingLine(KERNEL));
        }

        let mut stopwords = HashSet::new();
        loop {
            let line = c
                .line()?
                .ok_or_else(|| NlpError::Format("no stopword terminator".into()))?;
            if line.is_empty() {
                break;
            }
            stopwords.insert(line.to_string());
        }
        if stopwords.len() < MIN_ENTRIES {
            return Err(NlpError::Format(format!(
                "{} stopwords (< {MIN_ENTRIES})",
                stopwords.len()
            )));
        }

        // Vocabulary: `<word>\n<u32 LE id>` until an empty line.
        let mut words: Vec<(String, u32)> = Vec::new();
        loop {
            let word = c
                .line()?
                .ok_or_else(|| NlpError::Format("no vocab terminator".into()))?;
            if word.is_empty() {
                break;
            }
            words.push((word.to_string(), c.u32_le()?));
        }
        if words.len() < MIN_ENTRIES {
            return Err(NlpError::Format(format!(
                "{} vocabulary entries (< {MIN_ENTRIES})",
                words.len()
            )));
        }
        let features = words.len();
        let mut vocab: HashMap<String, (u32, f64)> = HashMap::with_capacity(features);
        for (word, id) in &words {
            if *id as usize >= features {
                return Err(NlpError::Format(format!("feature id {id} >= {features}")));
            }
            vocab.insert(word.clone(), (*id, 0.0));
        }

        // Per-feature values, indexed by feature id (the CE loader reads
        // them into a plain array and the vectorizer indexes it by id).
        let value_count = c.u32_le()? as usize;
        if value_count != features {
            return Err(NlpError::Format(format!(
                "value count {value_count} != vocabulary size {features}"
            )));
        }
        let mut values = vec![0.0f64; features];
        for slot in &mut values {
            *slot = c.f64_le()?;
        }
        for entry in vocab.values_mut() {
            entry.1 = values[entry.0 as usize];
        }

        // Sparse rows: `items` f32 triples, grouped by alpha (= row index).
        let items = c.u32_le()? as usize;
        if !(MIN_SV_ITEMS..=MAX_SV_ITEMS).contains(&items) || !items.is_multiple_of(3) {
            return Err(NlpError::CountRange(items as u64));
        }
        let triples = items / 3;
        let mut alphas = Vec::with_capacity(triples);
        let mut sparse: Vec<(u32, f32)> = Vec::with_capacity(triples);
        for _ in 0..triples {
            let alpha = c.f32_le()? as u32;
            let feature = c.f32_le()? as u32;
            let weight = c.f32_le()?;
            if feature as usize >= features {
                return Err(NlpError::Format(format!(
                    "sparse feature {feature} >= {features}"
                )));
            }
            alphas.push(alpha);
            sparse.push((feature, weight));
        }

        // Rows are laid out in alpha order; gaps become empty rows (the CE
        // loader inserts placeholder rows for skipped alpha indices).
        let rows_count = c.u32_le()? as usize;
        let max_alpha = alphas.iter().copied().max().unwrap_or(0) as usize;
        if rows_count != max_alpha + 1 {
            return Err(NlpError::Format(format!(
                "row count {rows_count} != max alpha + 1 ({})",
                max_alpha + 1
            )));
        }
        let mut rows: Vec<Row> = (0..rows_count)
            .map(|_| Row {
                entries: Vec::new(),
                norm2: 0.0,
            })
            .collect();
        for (alpha, (feature, weight)) in alphas.iter().copied().zip(sparse) {
            let row = &mut rows[alpha as usize];
            row.entries.push((feature, weight));
        }
        for row in &mut rows {
            row.norm2 = row
                .entries
                .iter()
                .map(|(_, w)| f64::from(*w) * f64::from(*w))
                .sum();
        }

        let coefficients: Vec<f32> = (0..rows_count)
            .map(|_| c.f32_le())
            .collect::<Result<_, _>>()?;
        let row_count_check = c.u32_le()? as usize;
        if row_count_check != rows_count {
            return Err(NlpError::Format(format!(
                "index count {row_count_check} != row count {rows_count}"
            )));
        }
        let mut row_indices = Vec::with_capacity(rows_count);
        for _ in 0..rows_count {
            let index = c.u32_le()? as i32;
            if index < 0 || index as usize >= rows_count {
                return Err(NlpError::Format(format!(
                    "row index {index} out of range {rows_count}"
                )));
            }
            row_indices.push(index as u32);
        }
        let rho = c.f32_le()?;
        let gamma = c.f32_le()?;
        if !gamma.is_finite() || gamma <= 0.0 {
            return Err(NlpError::Format(format!("bad gamma {gamma}")));
        }

        Ok(Self {
            stopwords,
            vocab,
            features,
            rows,
            coefficients,
            row_indices,
            rho,
            gamma,
            stemmer: Stemmer::create(Algorithm::English),
        })
    }

    /// Tokenize + stem a title the way the classifier's NLP stage does
    /// (module-level pipeline description, steps 1–3).
    fn stems(&self, title: &str) -> Vec<String> {
        let lowered = title.to_lowercase();
        let mut out = Vec::new();
        for token in
            lowered.split(|ch: char| ch.is_whitespace() || matches!(ch, '-' | '.' | '/' | ':'))
        {
            if token.is_empty() {
                continue;
            }
            // Drop tokens containing digits or symbol characters
            // (`[\d]` and the punctuation-class filters in the loader).
            if !token.chars().all(|ch| ch.is_alphabetic()) {
                continue;
            }
            if self.stopwords.contains(token) {
                continue;
            }
            let stem = self.stemmer.stem(token).into_owned();
            if self.stopwords.contains(&stem) {
                continue;
            }
            out.push(stem);
        }
        out
    }

    /// Score one window title (steps 4–7 of the module pipeline).
    pub fn score(&self, title: &str) -> TitleScore {
        let mut x = vec![0.0f64; self.features];
        for stem in self.stems(title) {
            if let Some(&(id, value)) = self.vocab.get(&stem) {
                x[id as usize] += value;
            }
        }
        let norm_sq: f64 = x.iter().map(|v| v * v).sum();
        if norm_sq != 0.0 {
            let inv = norm_sq.sqrt().recip();
            for value in &mut x {
                *value *= inv;
            }
        }

        // Kernel per sparse row; the decision sums coefs[i] · K[row_indices[i]].
        let kernels: Vec<f32> = self
            .rows
            .par_iter()
            .map(|row| {
                if row.entries.is_empty() {
                    return 0.0;
                }
                let dot: f64 = row
                    .entries
                    .iter()
                    .map(|(feature, weight)| x[*feature as usize] * f64::from(*weight))
                    .sum();
                let dist_sq = norm_sq + row.norm2 - 2.0 * dot;
                (-f64::from(self.gamma) * dist_sq.max(0.0)).exp() as f32
            })
            .collect();
        let mut decision = f64::from(-self.rho);
        for (coefficient, index) in self.coefficients.iter().zip(&self.row_indices) {
            decision += f64::from(*coefficient) * f64::from(kernels[*index as usize]);
        }
        TitleScore {
            class: if decision <= 0.0 {
                TitleClass::Explicit
            } else {
                TitleClass::Unflagged
            },
            decision,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Triples in the sparse support-vector block; the fixture layout (and
    /// the item-count bounds test) are keyed off this.
    const TRIPLES: usize = 167;

    fn put_u32(out: &mut Vec<u8>, value: u32) {
        out.extend_from_slice(&value.to_le_bytes());
    }

    fn put_f32(out: &mut Vec<u8>, value: f32) {
        out.extend_from_slice(&value.to_le_bytes());
    }

    fn put_f64(out: &mut Vec<u8>, value: f64) {
        out.extend_from_slice(&value.to_le_bytes());
    }

    /// Build a small synthetic `sw` plaintext: 160 stopwords, a 160-word
    /// vocabulary, one dense-ish row set.
    fn synthetic_sw() -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(b"Snowball NLP 2.0\nrbf\n");
        for i in 0..160 {
            out.extend_from_slice(format!("stopword{i}\n").as_bytes());
        }
        out.push(b'\n');
        // Vocabulary: "alpha" (feature 0), "beta" (feature 1), then filler.
        out.extend_from_slice(b"alpha\n");
        put_u32(&mut out, 0);
        out.extend_from_slice(b"beta\n");
        put_u32(&mut out, 1);
        for i in 2..160 {
            out.extend_from_slice(format!("filler{i}\n").as_bytes());
            put_u32(&mut out, i as u32);
        }
        out.push(b'\n');
        put_u32(&mut out, 160); // value count == vocabulary size
        for i in 0..160 {
            put_f64(&mut out, if i < 2 { 1.0 } else { 0.001 * i as f64 });
        }
        // 501 items = 167 triples: row 0 = {(0, 1.0)} weights; remaining
        // triples fill rows 1..166 with feature 1.
        let triples = TRIPLES;
        put_u32(&mut out, (triples * 3) as u32);
        for t in 0..triples {
            put_f32(&mut out, t as f32); // alpha = row index
            put_f32(&mut out, if t == 0 { 0.0 } else { 1.0 });
            put_f32(&mut out, 1.0);
        }
        put_u32(&mut out, triples as u32); // row count == max alpha + 1
        for t in 0..triples {
            // Coefficients: strongly negative on row 0, positive elsewhere.
            put_f32(&mut out, if t == 0 { -1.0 } else { 0.01 });
        }
        put_u32(&mut out, triples as u32); // index count
        for t in 0..triples {
            put_u32(&mut out, t as u32);
        }
        put_f32(&mut out, -0.5); // rho → decision offset +0.5
        put_f32(&mut out, 1.0); // gamma
        out
    }

    #[test]
    fn parses_and_scores_a_synthetic_model() {
        let model = SnowballNlp::parse(&synthetic_sw()).expect("parse");

        // "alpha" maps to feature 0 with value 1.0; the single big-
        // coefficient row matches it exactly (dist²≈0 ⇒ K≈1) and drags the
        // decision negative ⇒ Explicit. (A repeated hit would L2-rescale the
        // feature back to 1.0 as well; the exact-match row still dominates.)
        let score = model.score("alpha");
        assert_eq!(score.class, TitleClass::Explicit);
        assert!(score.decision <= 0.0, "decision {}", score.decision);

        // An out-of-vocabulary title leaves x = 0: K_j = exp(-γ·‖row‖²) is
        // small, decision ≈ -rho > 0 ⇒ Unflagged.
        let clean = model.score("nothing relevant here");
        assert_eq!(clean.class, TitleClass::Unflagged);
        assert!(clean.decision > 0.0);
    }

    #[test]
    fn stopwords_and_non_alphabetic_tokens_are_dropped() {
        let model = SnowballNlp::parse(&synthetic_sw()).expect("parse");
        // A title that is only a stopword behaves like an empty title.
        assert_eq!(model.score("stopword5"), model.score(""),);
        // Digit/symbol-laden tokens never reach the vocabulary.
        assert_eq!(model.score("alpha2"), model.score(""));
        assert_eq!(model.score("a!pha"), model.score(""));
    }

    #[test]
    fn bad_magic_and_kernel_fail() {
        let mut bytes = synthetic_sw();
        bytes[0] = b'X';
        assert!(matches!(
            SnowballNlp::parse(&bytes),
            Err(NlpError::MissingLine(MAGIC))
        ));

        let mut bytes = synthetic_sw();
        let at = bytes
            .windows(4)
            .position(|w| w == b"rbf\n")
            .expect("kernel marker");
        bytes[at] = b'p';
        assert!(matches!(
            SnowballNlp::parse(&bytes),
            Err(NlpError::MissingLine(KERNEL))
        ));
    }

    #[test]
    fn truncated_payload_fails_closed() {
        let bytes = synthetic_sw();
        let truncated = &bytes[..bytes.len() - 4];
        assert!(SnowballNlp::parse(truncated).is_err());
    }

    #[test]
    fn item_count_bounds_are_enforced() {
        let mut bytes = synthetic_sw();
        // The count sits right before the sparse items; everything after
        // them is fixed by the fixture layout: 3 f32 items per triple,
        // then the row count, one f32 coefficient per row, the index
        // count, one u32 index per row, rho, gamma.
        let tail = TRIPLES * 12 + 4 + TRIPLES * 4 + 4 + TRIPLES * 4 + 4 + 4;
        let marker = bytes.len() - tail - 4;
        assert_eq!(
            &bytes[marker..marker + 4],
            &((TRIPLES * 3) as u32).to_le_bytes()
        );
        // Corrupt the sparse item count to an out-of-range value.
        bytes[marker] = 0x02;
        bytes[marker + 1] = 0;
        assert!(matches!(
            SnowballNlp::parse(&bytes),
            Err(NlpError::CountRange(_))
        ));
    }
}
