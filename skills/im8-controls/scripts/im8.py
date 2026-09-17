#!/usr/bin/env python3
"""Query the IM8 OSCAL control catalogs and SSP templates bundled with this skill.

Standard library only. Output is compact Markdown meant to be read by an agent.

  im8.py list                              SSP templates and catalog families
  im8.py index [cybersecurity|dss] [FAM]   control IDs and titles
  im8.py control ID [ID ...]               full text of controls, with SSP levels
  im8.py search TERM [TERM ...]            controls whose title/text match all terms
  im8.py ssp NAME [--level N] [--family F] controls and levels in an SSP
  im8.py compare SSP_A SSP_B               controls whose level or presence differs
"""
import argparse
import json
import re
import sys
from functools import cache
from pathlib import Path

DATA = Path(__file__).resolve().parent.parent / "data"
CATALOG_DIR = DATA / "control-catalog"
SSP_DIR = DATA / "ssp"
PARAM_RE = re.compile(r"\{\{\s*insert:\s*param,\s*([\w-]+)\s*\}\}")


def fail(msg):
    print(f"error: {msg}", file=sys.stderr)
    sys.exit(1)


@cache
def load(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def catalog_files():
    """Yield (domain, family, path) for every catalog file."""
    for domain_dir in sorted(p for p in CATALOG_DIR.iterdir() if p.is_dir()):
        for path in sorted(domain_dir.glob("*.json")):
            yield domain_dir.name, path.stem, path


def ssp_names():
    return sorted(p.stem for p in SSP_DIR.glob("*.json"))


def controls(path):
    return load(path)["catalog"]["groups"][0]["controls"]


def prop(obj, name):
    return next((p["value"] for p in obj.get("props", []) if p["name"] == name), None)


def part(control, name):
    return next((p.get("prose", "") for p in control.get("parts", []) if p["name"] == name), "")


def find_control(control_id):
    control_id = control_id.lower()
    family = control_id.split("-")[0]
    for domain, fam, path in catalog_files():
        if fam == family:
            for c in controls(path):
                if c["id"] == control_id:
                    return domain, path, c
    return None


def ssp_requirements(name):
    path = SSP_DIR / f"{name}.json"
    if not path.exists():
        fail(f"unknown SSP '{name}'. Available: {', '.join(ssp_names())}")
    return load(path)["system-security-plan"]["control-implementation"]["implemented-requirements"]


def ssp_levels(name):
    return {r["control-id"]: prop(r, "profile-level") for r in ssp_requirements(name)}


def render_params(text, params):
    labels = {p["id"]: p.get("label", p["id"]) for p in params}
    return PARAM_RE.sub(lambda m: f"[{m.group(1)}: {labels.get(m.group(1), '?')}]", text)


def sort_key(control_id):
    fam, _, num = control_id.partition("-")
    return (fam, int(num) if num.isdigit() else 0)


def cmd_list(_args):
    print("## SSP templates\n")
    print("| SSP | Title | Controls | Level 0 / 1 / 2 |")
    print("|---|---|---|---|")
    for name in ssp_names():
        doc = load(SSP_DIR / f"{name}.json")["system-security-plan"]
        levels = list(ssp_levels(name).values())
        counts = " / ".join(str(levels.count(l)) for l in ("0", "1", "2"))
        title = doc["metadata"]["title"].replace("System Security Plan - ", "")
        print(f"| {name} | {title} | {len(levels)} | {counts} |")
    print("\n## Catalog families\n")
    print("| Domain | Family | Title | Controls |")
    print("|---|---|---|---|")
    for domain, fam, path in catalog_files():
        group = load(path)["catalog"]["groups"][0]
        print(f"| {domain} | {fam} | {group['title']} | {len(group['controls'])} |")


def cmd_index(args):
    for domain, fam, path in catalog_files():
        if args.domain and domain != args.domain:
            continue
        if args.family and fam != args.family.lower():
            continue
        items = " · ".join(f"{c['id']} {c['title']}" for c in controls(path))
        print(f"- **{fam}** ({domain}): {items}")


def cmd_control(args):
    all_levels = {name: ssp_levels(name) for name in ssp_names()}
    for i, control_id in enumerate(args.ids):
        found = find_control(control_id)
        if not found:
            fail(f"control '{control_id}' not found")
        domain, path, c = found
        params = c.get("params", [])
        if i:
            print("\n---\n")
        group = load(path)["catalog"]["groups"][0]["title"]
        print(f"## {c['id']} {c['title']}")
        print(f"Catalog: {domain} / {group} (last modified {(prop(c, 'last-modified') or '?')[:10]})\n")
        print(f"**Statement:** {render_params(part(c, 'statement'), params)}\n")
        if part(c, "guidance"):
            print(f"**Recommendations:** {part(c, 'guidance')}\n")
        for name, label in (("risk-statement", "Risk statement"), ("rationale", "Rationale")):
            if prop(c, name):
                print(f"**{label}:** {prop(c, name)}\n")
        if params:
            print("**Parameters:**")
            for p in params:
                guide = " ".join(g.get("prose", "") for g in p.get("guidelines", []))
                print(f"- `{p['id']}` ({p.get('class', '?')}) {p.get('label', '')}: {guide}")
            print()
        levels = [f"{n}: L{lv[c['id']]}" for n, lv in all_levels.items() if c["id"] in lv]
        print("**Level in SSPs:** " + (", ".join(levels) if levels else "not in any SSP template"))


def cmd_search(args):
    terms = [t.lower() for t in args.terms]
    hits = 0
    for domain, _fam, path in catalog_files():
        for c in controls(path):
            text = " ".join([c["title"], part(c, "statement"), part(c, "guidance"),
                             prop(c, "risk-statement") or "", prop(c, "rationale") or ""]).lower()
            if all(t in text for t in terms):
                in_title = all(t in c["title"].lower() for t in terms)
                print(f"- {c['id']} {c['title']} ({domain}){' [title match]' if in_title else ''}")
                hits += 1
    if not hits:
        print("No matches. Try fewer or shorter terms, or run `index` and scan titles.")


def cmd_ssp(args):
    rows = ssp_requirements(args.name)
    print("| Control | Title | Level |\n|---|---|---|")
    n = 0
    for r in rows:
        level = prop(r, "profile-level")
        if args.level is not None and level != args.level:
            continue
        if args.family and not r["control-id"].startswith(args.family.lower() + "-"):
            continue
        flag = " (has params)" if "Parameters to set" in r.get("remarks", "") else ""
        print(f"| {r['control-id']} | {prop(r, 'control-title')}{flag} | {level} |")
        n += 1
    print(f"\n{n} control(s)")


def cmd_compare(args):
    a, b = ssp_levels(args.a), ssp_levels(args.b)
    print(f"| Control | {args.a} | {args.b} |\n|---|---|---|")
    n = 0
    for cid in sorted(set(a) | set(b), key=sort_key):
        if a.get(cid) != b.get(cid):
            print(f"| {cid} | {a.get(cid, '—')} | {b.get(cid, '—')} |")
            n += 1
    print(f"\n{n} difference(s); '—' means the control is not in that SSP")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list").set_defaults(func=cmd_list)
    p = sub.add_parser("index")
    p.add_argument("domain", nargs="?", choices=["cybersecurity", "dss"])
    p.add_argument("family", nargs="?")
    p.set_defaults(func=cmd_index)
    p = sub.add_parser("control")
    p.add_argument("ids", nargs="+")
    p.set_defaults(func=cmd_control)
    p = sub.add_parser("search")
    p.add_argument("terms", nargs="+")
    p.set_defaults(func=cmd_search)
    p = sub.add_parser("ssp")
    p.add_argument("name")
    p.add_argument("--level", choices=["0", "1", "2"])
    p.add_argument("--family")
    p.set_defaults(func=cmd_ssp)
    p = sub.add_parser("compare")
    p.add_argument("a")
    p.add_argument("b")
    p.set_defaults(func=cmd_compare)
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
