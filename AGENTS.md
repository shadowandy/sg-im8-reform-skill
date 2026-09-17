# Agent instructions

These rules apply to any coding agent (Claude Code, Codex, Cursor, etc.) working in this repo. See `README.md` for what the repo does and how it is laid out.

## Definition of done

Before you mark a task as done, run the checks whenever you have added or changed any Python (`*.py`) or shell (`*.sh`) file, or `tool/extract_oscal/requirements*`:

```sh
./tool/check.sh
```

The task is done only when the script ends with `All checks passed.` and exits 0. It runs:

| Check | Tool | Scope |
|---|---|---|
| Lint | pylint | every tracked `*.py` (config in `.pylintrc`) |
| Lint | shellcheck | every tracked `*.sh` |
| SAST | bandit | every tracked `*.py` |
| SCA | pip-audit | `tool/extract_oscal/requirements.txt` |

The script scans files tracked by git, so run `git add` (or `git add -N`) on new files first, or they will be skipped.

If a check fails:

- **Fix the cause.** Don't silence it by adding `# pylint: disable`, `# nosec`, `# shellcheck disable=`, pip-audit `--ignore-vuln`, or by loosening `.pylintrc` or `tool/check.sh`. If a finding really is a false positive, suppress only that line, add a comment that explains why, and tell the user.
- **Vulnerable dependency (SCA):** raise the floor in `requirements.in` with a comment naming the CVE, then regenerate the lock with `uv pip compile --generate-hashes requirements.in -o requirements.txt` (run in `tool/extract_oscal/`).
- **Can't run the checks** (no `uv`, no network for pip-audit): say so plainly in your final report. Never claim the checks passed.

In your final report, state that the checks ran and give the result for each one.

## Other rules

- `skills/im8-controls/scripts/im8.py` must use only the Python 3 standard library, because it ships inside the skill zip.
- Don't hand-edit `skills/im8-controls/data/`. Regenerate it with `./tool/fetch-control-catalog.sh`.
- If you change anything under `skills/im8-controls/`, also run `./package-skill.sh "$TMPDIR/im8-controls.zip"` to confirm that the skill still validates.
