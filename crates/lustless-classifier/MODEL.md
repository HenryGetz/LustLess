# LustLess scoring model

Model card for the `lustless-classifier` scorer bundle (CONTRACTS §7
"Scoring model": a clean-room, open-licensed NSFW/image-content classifier
in ONNX, selected and documented by this file).

## Choice

| | |
|---|---|
| model | **`AdamCodd/vit-base-nsfw-detector`** — ViT-base/16 at 384×384, 2-class (`sfw` / `nsfw`) image classifier |
| architecture | `ViTForImageClassification`, fine-tuned from [`google/vit-base-patch16-384`](https://huggingface.co/google/vit-base-patch16-384) (ImageNet-21k pretrain, 384px) |
| provenance | <https://huggingface.co/AdamCodd/vit-base-nsfw-detector>, pinned to revision `8587de998f441aac03fdd57a85d2e4cb808c7d64` |
| license | **Apache-2.0** (model card `license:` front matter; the `google/vit-base-patch16-384` base is Apache-2.0 as well) |
| shipped artifact | `onnx/model_quantized.onnx` —88,500,985 bytes, sha256 `432763a6899ebc418c55f784b98f90565e5fc694c778d2ffcb0294b12f6a7404` (uint8 dynamic quantization, ORT-standard quant ops, float32 input/output) |
| alternatives considered | `Falconsai/nsfw_image_detection` (Apache-2.0, eval acc 0.980375, but ships no ONNX — PyTorch/TF only) and `Marqo/nsfw-image-detection-384` (Apache-2.0, published acc 98.56%, ViT-tiny, but ships only safetensors). This model ships ONNX directly *and* publishes an eval matrix, so `fetch-model.sh` needs no conversion step. |

Why this model: it is distributable under an OSI license, ships ONNX in the
repo (no conversion toolchain in the fetch path), publishes held-out metrics
with a confusion matrix, and is widely used (787k downloads on the Hub).

## Published metrics (model card)

Eval set (~2 800 images; confusion matrix `[[1076, 37], [60, 1627]]`):

| metric | value |
|---|---|
| accuracy | **0.9654** |
| AUC | 0.9948 |
| loss | 0.0937 |
| false-SFW rate (NSFW predicted SFW) | 60 / 1 687 ≈ 3.6 % |
| false-NSFW rate (SFW predicted NSFW) | 37 / 1 113 ≈ 3.3 % |

Training: ~25 000 real images (photos, drawings), lr 3e-5, batch 32, 1 epoch,
seed 42. The card does not name the training/eval dataset (no dataset license
to inherit beyond the model's own Apache-2.0).

Caveats stated by the card and relevant here:

* **Generative images**: accuracy drops to 0.86 on AI-generated images
  (F1 0.8654, AUC 0.9376, precision 0.8350, recall 0.8980). Screenshots of
  generative-image output therefore score with that error rate.
* **Restrictive by design**: "sexy" content (e.g. cleavage) is *intended* to
  score NSFW.
* **Quantization**: the card notes quantized ONNX "slightly reduce[s] the
  model's accuracy" without a number; we ship the uint8 quantized variant for
  CPU/memory footprint (88 MB vs 344 MB fp32) on the Zorin Lite target class.
  The quoted metrics are the fp32 eval numbers.

## Bundle layout (CONTRACTS §7)

`./fetch-model.sh` downloads and verifies everything into `models/` (git-ignored
except `models/.gitignore`); `packaging/build-deb.sh` installs the directory as
`/usr/share/lustless/models/`:

```text
models/manifest.json                  roles, versions, sha256 per artifact (generated last)
models/<sha256>-scorer.onnx           ONNX model
models/<sha256>-labels.json           id2label map (upstream onnx/config.json)
models/<sha256>-calibration.json      positiveLabel + threshold + rationale
```

The pins live as constants in `fetch-model.sh`; `lustless-classifier` re-hashes
every artifact against `manifest.json` at startup and **fails closed** (exit
non-zero, `bye` on the pipe) on any missing or corrupt file.

## Preprocessing (deterministic, implemented in `scoring.rs`)

Applied to every window crop exactly as follows — unit-tested on synthetic
tensors in `scoring::tests`, no model needed:

1. decode the crop as RGB8 (`image` crate, 8-bit channels);
2. resize to **384 × 384** with the bilinear triangle filter
   (`image::imageops::FilterType::Triangle`, the Rust analogue of the
   upstream `ViTFeatureExtractor`'s `resample: 2` = PIL
   `Resampling.BILINEAR`; `size: {height: 384, width: 384}`, no center crop);
3. rescale each channel by `1/255`;
4. normalize each channel as `(x − 0.5) / 0.5` (upstream `image_mean =
   image_std = [0.5, 0.5, 0.5]`);
5. lay out **NCHW** `f32` with batch 1: `[1, 3, 384, 384]`, channel planes
   R then G then B;
6. run the ONNX graph — the engine binds the graph's **first input
   positionally** and reads the **first output** (no hard-coded tensor
   names), taking `logits[1 × 2]`;
7. `score = softmax(logits)[index of "nsfw"]` (stable f64 softmax; the label
   index is resolved case-insensitively from the `labels` artifact, so the
   `sfw`/`nsfw` positions are data, not code).

The whole path is deterministic: fixed resize filter, fixed arithmetic order,
`with_deterministic_compute(true)` on the session, no random augmentations.

## Threshold rationale

`flagged = score >= threshold`, where the threshold comes from the
`calibration` artifact (`positiveLabel`, `threshold`, `rationale`) and can be
overridden per run with `--threshold=<0..1>`.

**Default 0.8** (also the code default if a calibration file omits the field):

* A flagged window becomes a `circumventions` record — an *accusatory*,
  uploaded-by-default signal (§7 `upload.circumvention_records`). Precision
  matters more than recall, so we require high confidence rather than the
  raw argmax decision (which for a 2-class softmax is 0.5).
* The classifier is trained to be restrictive (borderline content scores
  NSFW by design), so low thresholds over-flag ordinary SFW screenshots —
  the false-positive base rate (≈3.3 % at 0.5) multiplies across every
  window of every capture.
* At 0.8 we keep only high-confidence positives; with softmax peakedness on
  a 2-logit head this retains the bulk of true positives while suppressing
  borderline flags. The card's threshold-vs-precision/recall trade-off is
  the intended tuning axis.

Deployment tuning: edit `threshold` in the calibration artifact (then rerun
`./fetch-model.sh`, which regenerates its hash into `manifest.json`) or pass
`--threshold` at spawn; the daemon logs which source was active at startup.

## Runtime (`ort` configuration — packaging notes)

* bindings: `ort =2.0.0-rc.13` (wraps **ONNX Runtime 1.28.0**), features =
  ort defaults with `tls-native` swapped for `tls-rustls` so the build-time
  binary download uses ring/rustls (no OpenSSL needed on the build host;
  `packaging/build-deb.sh` also installs `libssl-dev`, so either works).
* **Build** downloads the prebuilt ORT binaries (`download-binaries`) — the
  build host needs network access, like the rest of the pinned toolchain.
* **Linkage: static.** `ort-sys` links `libonnxruntime.a`
  (`cargo:rustc-link-lib=static=onnxruntime`) unless `ORT_PREFER_DYNAMIC_LINK`
  is set — the shipped `lustless-classifier` needs **no `libonnxruntime.so`**
  at runtime. Runtime `.so` requirements are only glibc + `libstdc++.so.6`
  (both present on every supported target; the `.deb` needs no extra
  `Depends` for scoring).
* Session configuration: CPU execution provider (no CUDA/OpenVINO features),
  `GraphOptimizationLevel::Level3`, deterministic compute, one session per
  process, `&mut self` inference (sequential per window).
* Scoring is local-only: no image, crop or score ever leaves the device
  (§7 ratified invariant — strictly stricter than CE's `ht.dat` score
  upload).
