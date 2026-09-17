#!/usr/bin/env bash
# Packages the im8-controls skill as a portable zip (default: <repo>/im8-controls.zip)
# for Claude Code (~/.claude/skills), claude.ai or Claude Desktop. Runs from any directory.
#
# Usage: ./package-skill.sh [output.zip]
#
# The skill is validated first (SKILL.md frontmatter, bundled data, script smoke
# test), so a broken skill is never packaged. Refresh the data beforehand with
# tool/fetch-control-catalog.sh.
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null && pwd -P)"
SKILL_NAME="im8-controls"
SKILL_DIR="${ROOT}/skills/${SKILL_NAME}"
OUTPUT="${1:-${ROOT}/${SKILL_NAME}.zip}"

# Expected bundle, kept in line with tool/fetch-control-catalog.sh.
EXPECTED_CATALOGS=26
EXPECTED_SSPS=8

die() {
    echo "[ERROR] $*" >&2
    exit 1
}

command -v python3 >/dev/null 2>&1 || die "python3 not found"
command -v zip >/dev/null 2>&1 || die "zip not found"
[[ -f "${SKILL_DIR}/SKILL.md" ]] || die "${SKILL_DIR}/SKILL.md not found"

# Frontmatter: name must match the folder; description is required and capped at 1024 characters.
python3 - "${SKILL_DIR}/SKILL.md" "${SKILL_NAME}" <<'EOF'
import re, sys
text = open(sys.argv[1], encoding="utf-8").read()
m = re.match(r"---\n(.*?)\n---\n", text, re.S)
if not m:
    sys.exit("[ERROR] SKILL.md has no YAML frontmatter")
fields = dict(line.split(":", 1) for line in m.group(1).splitlines() if ":" in line)
fields = {k.strip(): v.strip() for k, v in fields.items()}
if fields.get("name") != sys.argv[2]:
    sys.exit(f"[ERROR] SKILL.md name '{fields.get('name')}' does not match folder '{sys.argv[2]}'")
if not re.fullmatch(r"[a-z0-9-]{1,64}", fields["name"]):
    sys.exit("[ERROR] SKILL.md name must be lowercase letters, digits and hyphens (max 64)")
desc = fields.get("description", "")
if not desc or len(desc) > 1024:
    sys.exit(f"[ERROR] SKILL.md description must be 1-1024 characters (got {len(desc)})")
EOF

catalogs="$(find "${SKILL_DIR}/data/control-catalog" -name '*.json' 2>/dev/null | wc -l | tr -d ' ')"
ssps="$(find "${SKILL_DIR}/data/ssp" -name '*.json' 2>/dev/null | wc -l | tr -d ' ')"
(( catalogs == EXPECTED_CATALOGS )) || die "expected ${EXPECTED_CATALOGS} catalog files, found ${catalogs}; run tool/fetch-control-catalog.sh"
(( ssps == EXPECTED_SSPS )) || die "expected ${EXPECTED_SSPS} SSP files, found ${ssps}; run tool/fetch-control-catalog.sh"

# Smoke test: every file parses and the lookups the skill documents work.
python3 "${SKILL_DIR}/scripts/im8.py" list >/dev/null || die "im8.py list failed"
python3 "${SKILL_DIR}/scripts/im8.py" control as-5 wo-2 >/dev/null || die "im8.py control failed"

# Build in a staging copy so the zip holds a single top-level <skill>/ folder
# without caches or OS junk, then swap it into place.
STAGING="$(mktemp -d)"
trap 'rm -rf -- "${STAGING}"' EXIT
rsync -a --exclude '__pycache__' --exclude '*.pyc' --exclude '.DS_Store' --exclude '.staging.*' \
    "${SKILL_DIR}/" "${STAGING}/${SKILL_NAME}/"
(cd -- "${STAGING}" && zip -qrX "${STAGING}/${SKILL_NAME}.zip" "${SKILL_NAME}")

mkdir -p -- "$(dirname -- "${OUTPUT}")"
mv -f -- "${STAGING}/${SKILL_NAME}.zip" "${OUTPUT}"

size="$(du -h "${OUTPUT}" | cut -f1 | tr -d ' ')"
echo "[INFO] Packaged ${SKILL_NAME} (${catalogs} catalogs, ${ssps} SSPs) to ${OUTPUT} (${size})."
