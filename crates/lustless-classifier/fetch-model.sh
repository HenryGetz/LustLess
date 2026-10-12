#!/usr/bin/env bash
#
# Stage the CE classifier bundle into models/ (CONTRACTS §7: `manifest.json`
# + content-addressed `<sha512>-<role>.<ext>` artifacts).
#
# Source:   the pulled CE samples in re/samples/data/enc/ (byte-identical
#           production artifacts; use authorized for this build).
# Verify:   every artifact is pinned below by its full SHA-512 (which also
#           matches CE's own content-id scheme: filename prefix = first 80
#           bits of the SHA-512, bundle-formats.md §2.1).
# Fallback: when a sample is absent locally, the file is downloaded from the
#           CE CDN instead — the same URLs the `mn` plaintext lists
#           (https://www.covenanteyes.com/files/pdl/<id>-<role>.dat.enc,
#           recovered in bundle-formats.md §2.1) — and verified against the
#           identical pin before it lands. Offline builds need only the
#           samples directory.
# Runtime:  `lustless-classifier` re-verifies every sha512 + content-id +
#           context-0 decryption at startup and fails closed (§7).
#
# Usage:   ./fetch-model.sh   (SAMPLES_DIR=/path overrides the sample dir)
# Output:  models/manifest.json
#          models/<sha512>-scorer.dat.enc   ×3  ensemble shards
#          models/<sha512>-labels.dat.enc       word/feature model
#          models/<sha512>-calibration.json     threshold config (generated)
#          models/<sha512>-mn.dat.enc           CE bundle manifest

set -euo pipefail

# --- Pinned CE artifacts (sha512 of the shipped .dat.enc files) -----------

CDN_BASE="https://www.covenanteyes.com/files/pdl"
BUNDLE_VERSION="1.12.3" # from the mn plaintext
MODEL_ID="ensem_3cls-6.1.2"
CALIBRATION_VERSION="1.0.0"

# <role> <ce file name> <sha512>
SHARD_B1_SHA512="83b568cc34e77643949439e34eaeae1c79e02907b69f7c900b1bd6fff7a8533b806304a59fb795aaa66dbe1caeb0df1b2af547065a919822929aa692ab1a9fb3"
SHARD_B2_SHA512="d8b85cbaabaf6c1e7b151d973e472a40e833dd0c0c9f3aed0039905e4d44977bfb0da191a6927f9f5e7154f91b9787b6ba4116f34a479c1434e62a4c0fe73ab5"
SHARD_B3_SHA512="805b3533c9a73190993085b0146db85800669999e708e8645eed4d87b0715e4a1fd61ba6b27a5ec8358df391dcf25b37c171b2597f2d70b81e3481ef25311c53"
LABELS_SW_SHA512="a076283f3318c8ea4de0ef8339425fcd7ce7a58d54805ca4f87449d2cc9ea86dd2e7eac5138cd70e7c6790606c128ecc65174206e7e018c1c80f14385115ce61"
MN_SHA512="f160caa8342747d04d8faa111b20aa6f13e5baf884008c3c760f4fdb7fcedd02cf95a3e8e6bafccf5551b91df7119027eb61ed6537ed8f1eebdf9e1149255dba"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
MODELS_DIR="${SCRIPT_DIR}/models"
SAMPLES_DIR="${SAMPLES_DIR:-${REPO_ROOT}/re/samples/data/enc}"

# --- Helpers ---------------------------------------------------------------

command -v sha512sum >/dev/null || { echo "fetch-model.sh: sha512sum is required" >&2; exit 1; }
mkdir -p "${MODELS_DIR}"

sha512_file() { sha512sum "$1" | awk '{ print $1 }'; }

# stage <ce file name> <sha512> <role>
# Copy from the samples dir, else download from the CDN; either way the
# pinned sha512 is verified before the content-addressed file lands.
stage() {
    local ce_name="$1" sha="$2" role="$3"
    local dest="${MODELS_DIR}/${sha}-${role}.dat.enc"
    if [ -f "${dest}" ] && [ "$(sha512_file "${dest}")" = "${sha}" ]; then
        echo "ok        $(basename "${dest}")"
        return 0
    fi
    local src="${SAMPLES_DIR}/${ce_name}"
    local tmp="${dest}.part"
    if [ -f "${src}" ]; then
        echo "copy      ${ce_name} -> ${role}"
        cp "${src}" "${tmp}"
    else
        local url="${CDN_BASE}/${ce_name}"
        echo "download  ${url}"
        command -v curl >/dev/null || {
            echo "fetch-model.sh: ${src} absent and curl unavailable for ${url}" >&2
            exit 1
        }
        curl --fail --location --retry 5 --retry-delay 2 --output "${tmp}" "${url}"
    fi
    local got
    got="$(sha512_file "${tmp}")"
    if [ "${got}" != "${sha}" ]; then
        rm -f "${tmp}"
        {
            echo "fetch-model.sh: sha512 mismatch for ${ce_name}"
            echo "  want ${sha}"
            echo "  got  ${got}"
        } >&2
        exit 1
    fi
    mv "${tmp}" "${dest}"
}

# --- Artifacts -------------------------------------------------------------

stage "83b568cc34e776439494-b1.dat.enc" "${SHARD_B1_SHA512}" "scorer"
stage "d8b85cbaabaf6c1e7b15-b2.dat.enc" "${SHARD_B2_SHA512}" "scorer"
stage "805b3533c9a731909930-b3.dat.enc" "${SHARD_B3_SHA512}" "scorer"
stage "a076283f3318c8ea4de0-sw.dat.enc" "${LABELS_SW_SHA512}" "labels"
stage "f160caa8342747d04d8f-mn.dat.enc" "${MN_SHA512}" "mn"

# Calibration is ours (generated, deterministic): the threshold at which the
# spliced CE score becomes flagged (MODEL.md "Threshold rationale").
CAL_TMP="${MODELS_DIR}/.calibration.json.part"
cat > "${CAL_TMP}" <<'EOF'
{
  "schemaVersion": "1.0.0",
  "threshold": 0.46662,
  "rationale": "Score is the CE spliced linear score / 100000. 0.46662 = 46662/100000 = the base of the first SUGGESTIVE category row in the ensemble's 15-row category table, i.e. exactly the point where CE itself labels a window suggestive-or-worse. A flagged window becomes an uploaded circumvention record, so the default mirrors CE's own flag boundary rather than a softer one; tune per deployment or override with --threshold."
}
EOF
CAL_SHA512="$(sha512_file "${CAL_TMP}")"
CAL_DEST="${MODELS_DIR}/${CAL_SHA512}-calibration.json"
mv "${CAL_TMP}" "${CAL_DEST}"

# Drop artifacts from older pins so the bundle dir ships exactly six files.
for stale in "${MODELS_DIR}"/*-scorer.dat.enc "${MODELS_DIR}"/*-labels.dat.enc \
    "${MODELS_DIR}"/*-calibration.json "${MODELS_DIR}"/*-mn.dat.enc; do
    [ -f "${stale}" ] || continue
    case "${stale}" in
        "${MODELS_DIR}/${SHARD_B1_SHA512}-scorer.dat.enc" | \
        "${MODELS_DIR}/${SHARD_B2_SHA512}-scorer.dat.enc" | \
        "${MODELS_DIR}/${SHARD_B3_SHA512}-scorer.dat.enc" | \
        "${MODELS_DIR}/${LABELS_SW_SHA512}-labels.dat.enc" | \
        "${MODELS_DIR}/${MN_SHA512}-mn.dat.enc" | \
        "${CAL_DEST}") ;;
        *)
            echo "prune    $(basename "${stale}") (stale artifact)"
            rm -f "${stale}"
            ;;
    esac
done

# --- Manifest (written last, only after every artifact verifies) -----------

MODEL_INFO_JSON="$(cat <<EOF
{
  "name": "${MODEL_ID}",
  "revision": "${BUNDLE_VERSION}",
  "license": "Covenant Eyes production classifier, used under upstream authorization for this build",
  "source": "Covenant Eyes Victory Shield 10.1.44 shipped bundle (re/samples/data/enc)"
}
EOF
)"

cat > "${MODELS_DIR}/manifest.json" <<EOF
{
  "schemaVersion": "1.0.0",
  "bundleVersion": "${BUNDLE_VERSION}",
  "model": ${MODEL_INFO_JSON},
  "artifacts": [
    {
      "role": "scorer",
      "version": "${MODEL_ID}",
      "sha512": "${SHARD_B1_SHA512}",
      "file": "${SHARD_B1_SHA512}-scorer.dat.enc"
    },
    {
      "role": "scorer",
      "version": "${MODEL_ID}",
      "sha512": "${SHARD_B2_SHA512}",
      "file": "${SHARD_B2_SHA512}-scorer.dat.enc"
    },
    {
      "role": "scorer",
      "version": "${MODEL_ID}",
      "sha512": "${SHARD_B3_SHA512}",
      "file": "${SHARD_B3_SHA512}-scorer.dat.enc"
    },
    {
      "role": "labels",
      "version": "Snowball NLP 2.0",
      "sha512": "${LABELS_SW_SHA512}",
      "file": "${LABELS_SW_SHA512}-labels.dat.enc"
    },
    {
      "role": "calibration",
      "version": "${CALIBRATION_VERSION}",
      "sha512": "${CAL_SHA512}",
      "file": "${CAL_SHA512}-calibration.json"
    },
    {
      "role": "mn",
      "version": "${BUNDLE_VERSION}",
      "sha512": "${MN_SHA512}",
      "file": "${MN_SHA512}-mn.dat.enc"
    }
  ]
}
EOF

echo "model bundle ready in ${MODELS_DIR}:"
echo "  manifest.json                     bundle v${BUNDLE_VERSION}"
echo "  ${SHARD_B1_SHA512:0:12}…-scorer.dat.enc   ensemble shard b1"
echo "  ${SHARD_B2_SHA512:0:12}…-scorer.dat.enc   ensemble shard b2"
echo "  ${SHARD_B3_SHA512:0:12}…-scorer.dat.enc   ensemble shard b3"
echo "  ${LABELS_SW_SHA512:0:12}…-labels.dat.enc   word/feature model"
echo "  ${CAL_SHA512:0:12}…-calibration.json   threshold config"
echo "  ${MN_SHA512:0:12}…-mn.dat.enc           CE bundle manifest"
echo "packaging/build-deb.sh installs this directory as /usr/share/lustless/models/."
