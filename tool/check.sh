#!/usr/bin/env bash
# Runs the quality and security checks on every Python and shell script in the
# repo. Runs from any directory; exits non-zero if any check fails.
#
#   Lint  pylint (Python), shellcheck (shell)
#   SAST  bandit (Python); shellcheck also flags unsafe shell patterns
#   SCA   pip-audit against the hash-pinned tool/extract_oscal/requirements.txt
#   Data  tool/check_data.py parses the generated OSCAL JSON and asserts every
#         control keeps its id, statement and profile level
#
# Usage: ./tool/check.sh
#
# Needs uv and python3: each tool runs through uvx at a pinned version, so results
# do not depend on what is installed locally. pip-audit queries the PyPI advisory
# database, so the SCA check needs network access. The data check is standard
# library only and runs on the local python3.
set -uo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." >/dev/null && pwd -P)"
cd "${ROOT}" || exit 1

PYLINT_VERSION="4.0.8"
BANDIT_VERSION="1.9.4"
PIP_AUDIT_VERSION="2.10.1"
SHELLCHECK_PY_VERSION="0.11.0.1"

if ! command -v uvx >/dev/null 2>&1; then
    echo "[ERROR] uvx not found; install uv (https://docs.astral.sh/uv/)." >&2
    exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
    echo "[ERROR] python3 not found; needed for the data check." >&2
    exit 1
fi

# Tracked files only, so .venv/ and staging folders are never scanned.
PY_FILES=()
while IFS= read -r f; do PY_FILES+=("$f"); done < <(git ls-files '*.py')
SH_FILES=()
while IFS= read -r f; do SH_FILES+=("$f"); done < <(git ls-files '*.sh')

FAILED=()

run() {
    local name="$1"
    shift
    echo "==> ${name}"
    if "$@"; then
        echo "[PASS] ${name}"
    else
        echo "[FAIL] ${name}"
        FAILED+=("${name}")
    fi
    echo
}

# pylint imports the modules it checks, so it runs with the extractor's dependencies.
run "lint: pylint (Python)" \
    uvx --with-requirements tool/extract_oscal/requirements.txt "pylint@${PYLINT_VERSION}" \
    --rcfile .pylintrc "${PY_FILES[@]}"

run "lint: shellcheck (shell)" \
    uvx --from "shellcheck-py==${SHELLCHECK_PY_VERSION}" shellcheck "${SH_FILES[@]}"

run "SAST: bandit (Python)" \
    uvx "bandit@${BANDIT_VERSION}" --quiet "${PY_FILES[@]}"

run "SCA: pip-audit (tool/extract_oscal/requirements.txt)" \
    uvx "pip-audit@${PIP_AUDIT_VERSION}" --strict --require-hashes --disable-pip \
    -r tool/extract_oscal/requirements.txt

run "data: OSCAL fields (skills/im8-controls/data)" \
    python3 tool/check_data.py

if ((${#FAILED[@]})); then
    echo "[ERROR] ${#FAILED[@]} check(s) failed:" >&2
    printf '  - %s\n' "${FAILED[@]}" >&2
    exit 1
fi
echo "All checks passed."
