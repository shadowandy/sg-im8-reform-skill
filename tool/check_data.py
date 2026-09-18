#!/usr/bin/env python3
"""
check_data.py - assert the generated OSCAL JSON keeps the fields the skill reads.

Parses every file under skills/im8-controls/data/ and checks the output contract
documented in tool/extract_oscal/extract_oscal.py, so a silent change in the page
markup that drops a field is caught before the data is shipped:

  catalog: catalog.groups[0].controls[] - every control has a non-empty "id" in
           the file's family and a non-empty part named "statement".
  SSP:     ...control-implementation.implemented-requirements[] - every entry has
           a non-empty "control-id" that resolves to a catalog control, and a
           "profile-level" prop whose value is 0, 1 or 2.

Standard library only. Usage: ./tool/check_data.py [DATA_DIR]
Prints one line per problem and exits 1; exits 0 when the data is complete.
"""
import json
import sys
from pathlib import Path

LEVELS = {"0", "1", "2"}
ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "skills" / "im8-controls" / "data"


def load(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def prop(obj, name):
    if not isinstance(obj, dict):
        return None
    return next((p.get("value") for p in obj.get("props", []) if p.get("name") == name), None)


def nonempty(value):
    return isinstance(value, str) and value.strip() != ""


def rel(path):
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


def check_catalog(path, problems):
    """Check one catalog file; return the set of control IDs it defines."""
    ids = set()
    try:
        group = load(path)["catalog"]["groups"][0]
        controls = group["controls"]
    except (KeyError, IndexError, TypeError, ValueError) as exc:
        problems.append(f"{rel(path)}: no catalog.groups[0].controls ({exc})")
        return ids
    if not controls:
        problems.append(f"{rel(path)}: catalog has zero controls")
    for i, control in enumerate(controls):
        where = f"{rel(path)}: control #{i + 1}"
        control_id = control.get("id") if isinstance(control, dict) else None
        if not nonempty(control_id):
            problems.append(f"{where}: missing 'id'")
            continue
        where = f"{rel(path)}: {control_id}"
        if control_id.split("-")[0] != path.stem:
            problems.append(f"{where}: 'id' is not in family '{path.stem}'")
        ids.add(control_id)
        statement = next(
            (p.get("prose") for p in control.get("parts", []) if p.get("name") == "statement"), None
        )
        if not nonempty(statement):
            problems.append(f"{where}: missing part named 'statement'")
    return ids


def check_ssp(path, catalog_ids, problems):
    try:
        reqs = load(path)["system-security-plan"]["control-implementation"]["implemented-requirements"]
    except (KeyError, TypeError, ValueError) as exc:
        problems.append(f"{rel(path)}: no control-implementation.implemented-requirements ({exc})")
        return
    if not reqs:
        problems.append(f"{rel(path)}: SSP has zero implemented requirements")
    for i, req in enumerate(reqs):
        where = f"{rel(path)}: requirement #{i + 1}"
        control_id = req.get("control-id") if isinstance(req, dict) else None
        if not nonempty(control_id):
            problems.append(f"{where}: missing 'control-id'")
            continue
        where = f"{rel(path)}: {control_id}"
        if control_id not in catalog_ids:
            problems.append(f"{where}: 'control-id' is not in any catalog")
        level = prop(req, "profile-level")
        if level is None:
            problems.append(f"{where}: missing 'profile-level' prop")
        elif level not in LEVELS:
            problems.append(f"{where}: 'profile-level' is {level!r}, not one of {sorted(LEVELS)}")


def main(argv):
    data = Path(argv[1]).resolve() if len(argv) > 1 else DATA
    catalogs = sorted((data / "control-catalog").glob("*/*.json"))
    ssps = sorted((data / "ssp").glob("*.json"))
    problems = []
    if not catalogs:
        problems.append(f"{rel(data / 'control-catalog')}: no catalog files found")
    if not ssps:
        problems.append(f"{rel(data / 'ssp')}: no SSP files found")

    catalog_ids = set()
    for path in catalogs:
        catalog_ids |= check_catalog(path, problems)
    for path in ssps:
        check_ssp(path, catalog_ids, problems)

    if problems:
        for problem in problems:
            print(f"[ERROR] {problem}", file=sys.stderr)
        return 1
    print(f"{len(catalog_ids)} controls in {len(catalogs)} catalogs and {len(ssps)} SSPs have id, statement and level.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
