# Agent instructions

Rules for any coding agent (Claude Code, Codex, Cursor, etc.) in this repo.

## Project

Turns Singapore Government IM8 standards from [info.standards.tech.gov.sg](https://info.standards.tech.gov.sg) into an agent skill (`im8-controls`) that answers control questions from official data:

1. **Extract** the published pages (26 control catalogs, 8 SSP templates) into [OSCAL](https://pages.nist.gov/OSCAL/) JSON.
2. **Bundle** the JSON with a query script and `SKILL.md` into a self-contained skill.
3. **Package** it as `im8-controls.zip` for Claude Code, claude.ai, Claude Desktop or chatgpt.com.

**Tech stack:** Python 3, Bash, [uv](https://docs.astral.sh/uv/) (venv, hash-pinned deps, `uvx` for checks), GitHub Actions (runs `tool/check.sh`).

| Path | Purpose |
|---|---|
| `skills/im8-controls/` | The shipped skill: `SKILL.md`, `scripts/im8.py` (query CLI), `data/` (generated OSCAL JSON) |
| `tool/fetch-control-catalog.sh` | Regenerates all of `data/` via `tool/extract_oscal/extract_oscal.py` |
| `tool/check.sh` | Lint, SAST and SCA checks |
| `package-skill.sh` | Validates the skill and builds the zip |

Only read `README.md` if you need install steps, usage examples or design rationale.

## One task at a time

- Finish the current task, including its checks, before starting the next.
- Keep unrelated changes out. Report other issues you notice instead of fixing them.
- If asked for several things, confirm the order, then do and report each in turn.

## Definition of done

If you added or changed any `*.py`, `*.sh`, `tool/extract_oscal/requirements*` or
`skills/im8-controls/data/` file, run:

```sh
./tool/check.sh
```

The task is done only when it prints `All checks passed.` and exits 0. It checks files tracked by git, so `git add` (or `git add -N`) new files first.

| Check | Tool | Scope |
|---|---|---|
| Lint | pylint | tracked `*.py` (config in `.pylintrc`) |
| Lint | shellcheck | tracked `*.sh` |
| SAST | bandit | tracked `*.py` |
| SCA | pip-audit | `tool/extract_oscal/requirements.txt` |
| Data | `tool/check_data.py` | generated OSCAL JSON in `skills/im8-controls/data/` |

If a check fails:

- **Fix the cause.** Don't suppress findings (`# pylint: disable`, `# nosec`, `# shellcheck disable=`, `--ignore-vuln`) or loosen `.pylintrc` or `tool/check.sh`. For a genuine false positive, suppress only that line, comment why, and tell the user.
- **Data check fails:** the published pages changed shape. Fix `tool/extract_oscal/extract_oscal.py` and regenerate; never patch `data/` by hand.
- **Vulnerable dependency:** raise the floor in `requirements.in` with a comment naming the CVE, then run `uv pip compile --generate-hashes requirements.in -o requirements.txt` in `tool/extract_oscal/`.
- **Can't run the checks** (no `uv`, no network): say so. Never claim they passed.

In your final report, give the result of each check.

## Other rules

- `skills/im8-controls/scripts/im8.py` ships in the skill zip, so it must use only the Python 3 standard library.
- Don't hand-edit `skills/im8-controls/data/`. Regenerate it with `./tool/fetch-control-catalog.sh`.
- After changing anything under `skills/im8-controls/`, run `./package-skill.sh "$TMPDIR/im8-controls.zip"` to confirm the skill still validates.
