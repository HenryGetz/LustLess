# LustLess scoring model

Model card for the `lustless-classifier` scorer bundle (CONTRACTS §7
"Scoring model").

## Choice

| | |
|---|---|
| model | **Covenant Eyes' production numeric feature-scoring ensemble**, `ensem_3cls-6.1.2`, as shipped in Covenant Eyes Victory Shield 10.1.44 |
| architecture | three parallel evaluator shards (`b1`/`b2`/`b3`), each a compact convolutional graph (`Conv`/`Clip`/`Add`/`GlobalAveragePool`/`Flatten`/`Gemm`/`Softmax`) with a 3-value softmax output, folded by a median/minimum threshold stage and a 15-row category table into one linear score; plus a word-feature RBF model (`sw`) that contributes a window-title class to the same table |
| provenance | the CE 10.1.44 shipped bundle, staged byte-identical by `fetch-model.sh` from `re/samples/data/enc/` (CE CDN fallback) |
| authorization | **`AUTHORIZATION.md` at the repository root** — upstream (Covenant Eyes) written authorization covers use of these artifacts in this build; the clean-room requirement is waived for the classifier model and bundle data |
| shipped artifacts | three `scorer` shards (2,323,104 B each, encrypted), one `labels` word model (901,200 B, encrypted), one `mn` CE bundle manifest (1,248 B, encrypted), one generated `calibration` JSON (plaintext) |

Why: first-party-quality parity with the CE Windows product — same numeric
decisions, same thresholds, same title semantics — with every format
recovered and verified against the shipped samples
(`re/findings/10-classifier/bundle-formats.md`,
`classifier-internals-classifier.md`, and read-only decompilation notes in
`MODEL.md` "Recovered formats").

## Bundle layout (CONTRACTS §7)

`./fetch-model.sh` stages and verifies everything into `models/` (git-ignored
except `models/.gitignore`); `packaging/build-deb.sh` installs the directory
as `/usr/share/lustless/models/`:

```text
models/manifest.json                  roles, versions, sha512 per artifact (generated last)
models/<sha512>-scorer.dat.enc ×3     the ensemble shards (CE b1/b2/b3, byte-identical)
models/<sha512>-labels.dat.enc        the word/feature model (CE sw, byte-identical)
models/<sha512>-calibration.json      threshold + rationale (ours, plaintext)
models/<sha512>-mn.dat.enc            the CE bundle manifest (byte-identical)
```

Role mapping (§7): `scorer` → the three `bN` shards, `labels` → `sw`,
`calibration` → threshold config; `mn` (the upstream CE manifest) is accepted
when present and cross-checked — every shipped encrypted artifact must appear
in the decrypted `mn` `files[].sha512_hash` list. The pins live as constants
in `fetch-model.sh`; at startup `bundles::load` re-verifies every sha512,
every content-id (CE scheme: first 80 bits of the file's SHA-512 — the
artifact ids logged at startup are that `<20 hex>-<role>` form) and every
context-0 decryption, and **fails closed** (exit non-zero, `bye` on the pipe)
on any mismatch.

## At-rest encryption (bundle-formats.md §1)

The `.dat.enc` payloads ship exactly as CE encrypts them: AES-256-CBC +
PKCS#7, no IV prefix, no MAC ("context 0"). Key and IV are the recovered
static constants of §1.2 (key = `SHA-256(XOR-0x50(pooled literals))`,
IV = `vWzM6BntW18W4gwq`); `bundles.rs` holds both and decrypts once at
startup. The scheme is obfuscation, not protection (no integrity layer) —
which is why the sha512/content-id checks around it are mandatory.

## Shard format (recovered)

Each decrypted shard is one header line plus an ONNX `ModelProto`:

```text
ensem_3cls-6.1.2,<mean r>,<mean g>,<mean b>,<std r>,<std g>,<std b>\n<protobuf>
```

* the six header numbers are the per-channel normalization parameters used
  by the production input path (`157.0,143.0,135.0` / `84.3267…,84.4512…,
  87.6128…` — mean and standard deviation in pixel scale),
* the graph: input `input.1` `[1,3,224,224]` `f32`; 101 nodes (52 `Conv`
  incl. depthwise grouped 3×3, 35 `Clip` ReLU6 clamps, 10 residual `Add`,
  one `GlobalAveragePool`, `Flatten`, `Gemm` head, `Softmax`); output `[1,3]`,
* the three output values are the per-shard triple `(class_a, class_b,
  class_c)`; the ensemble consumes all three shards' triples together,
* the graph op set is closed — unknown ops fail closed at parse time
  (`onnx.rs` implements exactly the seven ops above).

## Word-model format (recovered, `sw`)

The decrypted `labels` artifact (`Snowball NLP 2.0` / `rbf`) is parsed per
the classifier's own loader (`cv::pn::BinarySnowballNLPClassifier`): stop
word list, a 2,500-entry stemmed-word vocabulary with feature ids, per-
feature `f64` values, sparse support rows (`(row, feature, weight)`
triples), per-row coefficients + row indices, and the RBF parameters
`rho`/`gamma`. Title evaluation (mirroring
`BinarySnowballNLPAlgorithm::predict`): lowercase → split on whitespace and
`- . / :` → drop digit/symbol-laden and stop words → Snowball English stem
(libstemmer algorithm, ported via `rust-stemmers`) → accumulate per-hit
feature values → L2-normalize → decision `= -rho + Σ coef[i] ·
exp(-γ·‖x − row‖²)` → class `EXPLICIT` iff the decision ≤ 0 (else
`UNFLAGGED`); the raw decision rides along as the score value. Full field
layout: `nlp.rs` module docs.

## Scoring pipeline (recovered, `scoring.rs`)

Per window (`computeScores`/`getVictoryEvaluatorScores`/`getSplicedScore`
semantics from the `j1` bundle, implemented natively):

1. crop by `apps[].appRect` (largest-intersection monitor image,
   full-frame fallback; `doNotScore` windows skipped — `consumer.rs`),
2. resize the crop to 224×224 (bilinear), normalize
   `(pixel − mean[c]) / std[c]` from the shard header, NCHW `f32`,
3. evaluate all three shards → three `(class_a, class_b, class_c)` triples,
4. fold through the ensemble thresholds (`imageOnlyThresholds` vs
   `withWindowTitleThresholds`, selected by whether a usable title exists):
   median of `class_a` above 0.6 ⇒ highly-clean; explicit-side check
   (minimum ≥ 0.999 without a title, median > 0.78 with) ⇒ explicit;
   near-zero median `class_a` + any `class_b` sliver ⇒ highly-suggestive;
   median `class_a` < 0.05 + median `class_b` > 0.8 ⇒ suggestive; else clean,
5. splice the discrete class with the title class
   (`UNFLAGGED`/`EXPLICIT`/absent) through the 15-row category table into a
   linear value `[0, 100_000]` (category bases `k·6666` + up to `6665·strength`,
   strength inverted for the clean classes),
6. report `score = linear / 100_000`.

Deterministic deviations from the bundle, both documented in code:
`HighlyClean` strength is fixed at 1.0 (the bundle uses a random value to
diversify the uploaded feed; no score leaves the device here), and the
title preprocessor drops the bundle's `fixAndFilterWindowTitle` telemetry
logging. The title pipeline itself is ported verbatim: leet-speak
normalization (interior symbol rewrite per word, then the misspelling
table), then the non-context / all-symbol-word / entropy filters, with
underscore runs converted to spaces inside the filter checks only (a
kept title preserves its underscores). No upload/network logic from the
bundle is ported — the records-only invariant of §7 holds unmodified.

## Threshold rationale

`flagged = score >= threshold`, threshold from the `calibration` artifact,
overridable with `--threshold`.

**Default 0.46662** = 46 662 / 100 000 = the base of the first `SUGGESTIVE`
category row (7 × 6 666) — exactly the boundary at which CE's own splice
labels a window suggestive-or-worse. A flagged window becomes a
`circumventions` record (uploaded by default, §7 `upload.circumvention_records`),
so the default mirrors the vendor's own flag boundary rather than a softer
one. Note the table's "unsafe unflagged" band: an explicit-side image class
with a clean title sits at base 6 × 6 666 = 39 996, below the flag line —
that is CE's design, preserved verbatim.

## Performance expectations

Per window: three forward passes over ~2.3 MB graphs at 224×224 plus one
RBF evaluation over ~17 k sparse rows. The runtime (`onnx.rs`/`rayon`)
parallelizes over conv output channels; on the Zorin Lite target class
expect well under a second per window shard on any CPU the CE Windows
product already ran on. Scoring is local-only: no image, crop, title or
score ever leaves the device (§7 ratified invariant — strictly stricter
than CE's own `ht.dat` score upload).

## Runtime

Pure Rust: hand-rolled protobuf reader (no generic ONNX dependency), RustCrypto
AES-256-CBC (`aes`/`cbc`), `rayon` for deterministic per-channel
parallelism (fixed reduction order ⇒ reproducible results), `rust-stemmers`
(same libstemmer algorithms CE embeds). No ONNX Runtime, no network
downloads at build or run time; the `.deb` needs no extra `Depends` for
scoring.
