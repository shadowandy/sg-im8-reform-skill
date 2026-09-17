# Agent instructions

Rules for any coding agent (Claude Code, Codex, Cursor, etc.) in this repo. See `README.md` for what the repo does and how it is laid out.

## One task at a time

- Finish the current task, including its checks, before starting the next.
- Keep unrelated changes out. Report other issues you notice instead of fixing them.
- If asked for several things, confirm the order, then do and report each in turn.

## Definition of done

If you added or changed any `*.py`, `*.sh` or `tool/extract_oscal/requirements*` file, run:

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

If a check fails:

- **Fix the cause.** Don't suppress findings (`# pylint: disable`, `# nosec`, `# shellcheck disable=`, `--ignore-vuln`) or loosen `.pylintrc` or `tool/check.sh`. For a genuine false positive, suppress only that line, comment why, and tell the user.
- **Vulnerable dependency:** raise the floor in `requirements.in` with a comment naming the CVE, then run `uv pip compile --generate-hashes requirements.in -o requirements.txt` in `tool/extract_oscal/`.
- **Can't run the checks** (no `uv`, no network): say so. Never claim they passed.

In your final report, give the result of each check.

## Other rules

- `skills/im8-controls/scripts/im8.py` ships in the skill zip, so it must use only the Python 3 standard library.
- Don't hand-edit `skills/im8-controls/data/`. Regenerate it with `./tool/fetch-control-catalog.sh`.
- After changing anything under `skills/im8-controls/`, run `./package-skill.sh "$TMPDIR/im8-controls.zip"` to confirm the skill still validates.
