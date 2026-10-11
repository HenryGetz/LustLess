#!/usr/bin/env bash
#
# Fetch the LustLess scorer model bundle into models/ (CONTRACTS §7:
# `manifest.json` + content-addressed `<sha256>-<role>.<ext>` artifacts).
#
# Model:   AdamCodd/vit-base-nsfw-detector (Apache-2.0), pinned to the
#          immutable revision below; see MODEL.md for the model card,
#          published metrics, preprocessing spec and threshold rationale.
# Trust:   every download is verified against the sha256 pins in this script
#          before it lands in models/; models/manifest.json (generated last)
#          re-states those pins for the runtime check in bundles::load.
# Offline: artifacts that already verify are kept (resume-safe: partial
#          downloads continue with curl --continue-at -, corrupt files are
#          deleted and re-fetched).
#
# Usage:   ./fetch-model.sh
# Output:  models/manifest.json
#          models/<sha256>-scorer.onnx        (ONNX model)
#          models/<sha256>-labels.json        (id2label map)
#          models/<sha256>-calibration.json   (threshold calibration)

set -euo pipefail

# --- Pinned upstream -------------------------------------------------------

REPO="AdamCodd/vit-base-nsfw-detector"
REVISION="8587de998f441aac03fdd57a85d2e4cb808c7d64"
BASE_URL="https://huggingface.co/${REPO}/resolve/${REVISION}"

# sha256 of the pinned artifacts (Hugging Face Git-LFS object ids, verified
# again below after every download).
SCORER_SOURCE="onnx/model_quantized.onnx"
SCORER_SHA256="432763a6899ebc418c55f784b98f90565e5fc694c778d2ffcb0294b12f6a7404"
LABELS_SOURCE="onnx/config.json"
LABELS_SHA256="5f54e0e96c0b5b77caba7e79aebe0b4fa5c154cabf6df65eb1b939ae8b265cfa"

BUNDLE_VERSION="${REVISION:0:8}" # 8587de99
CALIBRATION_VERSION="1.0.0"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODELS_DIR="${SCRIPT_DIR}/models"

# --- Helpers ---------------------------------------------------------------

command -v curl >/dev/null || { echo "fetch-model.sh: curl is required" >&2; exit 1; }
command -v sha256sum >/dev/null || { echo "fetch-model.sh: sha256sum is required" >&2; exit 1; }
mkdir -p "${MODELS_DIR}"

sha256_file() { sha256sum "$1" | awk '{ print $1 }'; }

# fetch_verified <url> <sha256> <destination>
# Keep an existing verified file; otherwise download (resuming any partial
# .part) and verify — a mismatch deletes the download and fails the script.
fetch_verified() {
    local url="$1" sha="$2" dest="$3"
    local tmp="${dest}.part"
    if [ -f "${dest}" ]; then
        if [ "$(sha256_file "${dest}")" = "${sha}" ]; then
            echo "ok        $(basename "${dest}")"
            return 0
        fi
        echo "re-fetch  $(basename "${dest}") (existing file failed verification)" >&2
        rm -f "${dest}"
    fi
    echo "download  ${url}"
    curl --fail --location --retry 5 --retry-delay 2 \
        --continue-at - --output "${tmp}" "${url}"
    local got
    got="$(sha256_file "${tmp}")"
    if [ "${got}" != "${sha}" ]; then
        rm -f "${tmp}"
        {
            echo "fetch-model.sh: sha256 mismatch for ${url}"
            echo "  want ${sha}"
            echo "  got  ${got}"
        } >&2
        exit 1
    fi
    mv "${tmp}" "${dest}"
}

# --- Artifacts -------------------------------------------------------------

SCORER_DEST="${MODELS_DIR}/${SCORER_SHA256}-scorer.onnx"
LABELS_DEST="${MODELS_DIR}/${LABELS_SHA256}-labels.json"

fetch_verified "${BASE_URL}/${SCORER_SOURCE}" "${SCORER_SHA256}" "${SCORER_DEST}"
fetch_verified "${BASE_URL}/${LABELS_SOURCE}" "${LABELS_SHA256}" "${LABELS_DEST}"

# Calibration is ours (generated, deterministic): threshold + rationale for
# the scorer (MODEL.md "Threshold rationale").
CAL_TMP="${MODELS_DIR}/.calibration.json.part"
cat > "${CAL_TMP}" <<'EOF'
{
  "schemaVersion": "1.0.0",
  "positiveLabel": "nsfw",
  "threshold": 0.8,
  "rationale": "Score is the model's P(nsfw). 0.8 flags only high-confidence NSFW: the model card trains a restrictive classifier (borderline-sexy content scores NSFW) and a flagged window becomes an accusatory circumvention record, so the default favours precision over recall. Published eval accuracy 0.9654 (AUC 0.9948); tune per deployment or override with --threshold."
}
EOF
CAL_SHA256="$(sha256_file "${CAL_TMP}")"
CAL_DEST="${MODELS_DIR}/${CAL_SHA256}-calibration.json"
mv "${CAL_TMP}" "${CAL_DEST}"

# Drop artifacts from older pins so the bundle dir ships exactly three files.
for stale in "${MODELS_DIR}"/*-scorer.onnx "${MODELS_DIR}"/*-labels.json \
    "${MODELS_DIR}"/*-calibration.json; do
    [ -f "${stale}" ] || continue
    case "${stale}" in
        "${SCORER_DEST}" | "${LABELS_DEST}" | "${CAL_DEST}") ;;
        *)
            echo "prune    $(basename "${stale}") (stale artifact)"
            rm -f "${stale}"
            ;;
    esac
done

# --- Manifest (written last, only after every artifact verifies) -----------

cat > "${MODELS_DIR}/manifest.json" <<EOF
{
  "schemaVersion": "1.0.0",
  "bundleVersion": "${BUNDLE_VERSION}",
  "model": {
    "name": "${REPO}",
    "revision": "${REVISION}",
    "license": "Apache-2.0",
    "source": "https://huggingface.co/${REPO}"
  },
  "artifacts": [
    {
      "role": "scorer",
      "version": "${BUNDLE_VERSION}",
      "sha256": "${SCORER_SHA256}",
      "file": "$(basename "${SCORER_DEST}")"
    },
    {
      "role": "labels",
      "version": "${BUNDLE_VERSION}",
      "sha256": "${LABELS_SHA256}",
      "file": "$(basename "${LABELS_DEST}")"
    },
    {
      "role": "calibration",
      "version": "${CALIBRATION_VERSION}",
      "sha256": "${CAL_SHA256}",
      "file": "$(basename "${CAL_DEST}")"
    }
  ]
}
EOF

echo "model bundle ready in ${MODELS_DIR}:"
echo "  manifest.json          bundle v${BUNDLE_VERSION}"
echo "  $(basename "${SCORER_DEST}")  scorer"
echo "  $(basename "${LABELS_DEST}")  labels"
echo "  $(basename "${CAL_DEST}")  calibration"
echo "packaging/build-deb.sh installs this directory as /usr/share/lustless/models/."
