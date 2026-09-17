#!/usr/bin/env bash
# Regenerates OSCAL control catalogs and system security plans (SSPs) from
# info.standards.tech.gov.sg. Runs from any directory.
#
# Everything is generated into a staging directory and only moved into
# <skill>/data/control-catalog/<family>/ and <skill>/data/ssp/ once every document
# succeeds, so a failed run never leaves a mix of old and new files. A document
# that shrinks (fewer controls than the existing file) blocks the update unless
# ALLOW_SHRINK=1 is set.
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." >/dev/null && pwd -P)"
PYTHON="${ROOT}/.venv/bin/python"
EXTRACT="${ROOT}/tool/extract_oscal/extract_oscal.py"
REQUIREMENTS="${ROOT}/tool/extract_oscal/requirements.txt"
OUT_ROOT="${ROOT}/skills/im8-controls/data"
BASE_URL="https://info.standards.tech.gov.sg"

if [[ ! -x "${PYTHON}" ]]; then
    echo "[ERROR] ${PYTHON} not found; create the venv first." >&2
    exit 1
fi

# Keep the venv in line with the hash-pinned lockfile.
if command -v uv >/dev/null 2>&1; then
    uv pip sync --quiet --require-hashes --python "${PYTHON}" -- "${REQUIREMENTS}"
else
    echo "[WARNING] uv not found; skipping venv sync against ${REQUIREMENTS}" >&2
fi

mkdir -p -- "${OUT_ROOT}"
STAGING="$(mktemp -d "${OUT_ROOT}/.staging.XXXXXX")"
trap 'rm -rf -- "${STAGING}"' EXIT

failures=0
outputs=()  # generated files, relative to OUT_ROOT

count_controls() {
    "${PYTHON}" - "$1" <<'EOF'
import json, sys
doc = json.load(open(sys.argv[1], encoding="utf-8"))
if "catalog" in doc:
    print(len(doc["catalog"]["groups"][0]["controls"]))
else:
    print(len(doc["system-security-plan"]["control-implementation"]["implemented-requirements"]))
EOF
}

# fetch_set <site path> <output dir under data/> <slug>...
fetch_set() {
    local site_path="$1" out_dir="$2"
    shift 2
    mkdir -p -- "${STAGING}/${out_dir}"
    local slug
    for slug in "$@"; do
        if "${PYTHON}" "${EXTRACT}" "${BASE_URL}/${site_path}/${slug}/" -o "${STAGING}/${out_dir}/${slug}.json"; then
            outputs+=("${out_dir}/${slug}.json")
        else
            echo "[ERROR] ${site_path}/${slug} failed" >&2
            failures=$((failures + 1))
        fi
    done
}

check_shrink() {
    local rel new_count old_count
    for rel in "${outputs[@]}"; do
        [[ -f "${OUT_ROOT}/${rel}" ]] || continue
        new_count="$(count_controls "${STAGING}/${rel}")"
        old_count="$(count_controls "${OUT_ROOT}/${rel}")"
        if (( new_count < old_count )); then
            echo "[ERROR] ${rel}: controls dropped from ${old_count} to ${new_count}" >&2
            failures=$((failures + 1))
        fi
    done
}

fetch_set control-catalog/cybersecurity control-catalog/cybersecurity \
    ac as br cs ck dp dc ga hr is lm ns rs sd pm st sc
fetch_set control-catalog/dss control-catalog/dss \
    bd pr tx tl uu wo wp wr wu
fetch_set ssp ssp \
    low-risk-cloud low-risk-on-premises medium-risk-cloud high-risk-cloud gen-ai dss-others dss-high sandbox

if (( failures == 0 )) && [[ "${ALLOW_SHRINK:-0}" != "1" ]]; then
    check_shrink
fi

if (( failures > 0 )); then
    echo "[ERROR] ${failures} problem(s); existing files left unchanged." >&2
    exit 1
fi

for rel in "${outputs[@]}"; do
    mkdir -p -- "$(dirname -- "${OUT_ROOT}/${rel}")"
    mv -f -- "${STAGING}/${rel}" "${OUT_ROOT}/${rel}"
done
echo "[INFO] All ${#outputs[@]} documents generated and published to ${OUT_ROOT}."
