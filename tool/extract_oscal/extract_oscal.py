#!/usr/bin/env python3
"""
extract_oscal.py - Hardened OSCAL extraction script.

Converts a page from info.standards.tech.gov.sg (fetched over HTTPS from an
allowlisted host, or read from a local HTML file) into OSCAL 1.1.2 JSON:

* /control-catalog/<family>/<slug>/ -> OSCAL catalog
* /ssp/<slug>/                      -> OSCAL system security plan
"""

from __future__ import annotations

import argparse
import copy
import ipaddress
import json
import logging
import os
import re
import socket
import sys
import tempfile
import uuid
from collections.abc import Iterable
from datetime import datetime, timedelta, timezone
from email.message import Message
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup, Tag

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

DEFAULT_ALLOWED_HOSTS: frozenset[str] = frozenset({"info.standards.tech.gov.sg"})
SITE_BASE = "https://info.standards.tech.gov.sg"
DEFAULT_SOURCE_BASES = {
    "catalog": f"{SITE_BASE}/control-catalog/cybersecurity/",
    "ssp": f"{SITE_BASE}/ssp/",
}
# Repo layout: <root>/tool/extract_oscal/extract_oscal.py -> <root>/skills/im8-controls/data/{control-catalog,ssp}/
DATA_DIR = Path(__file__).resolve().parents[2] / "skills" / "im8-controls" / "data"
CATALOG_OUTPUT_DIR = DATA_DIR / "control-catalog"
SSP_OUTPUT_DIR = DATA_DIR / "ssp"
# Namespace for props that are not defined by NIST OSCAL.
PROP_NS = f"{SITE_BASE}/ns/oscal"
MAX_SIZE_BYTES = 10 * 1024 * 1024
MAX_REDIRECTS = 5
SGT = timezone(timedelta(hours=8))

CATALOG_DOMAINS = {
    "cybersecurity": "Cybersecurity",
    "dss": "Digital Service Standards",
}
KNOWN_SECTIONS = frozenset(
    {"Control Statement", "Control Recommendations", "Risk Statement", "Rationale", "Parameters"}
)
INLINE_TAGS = ["a", "abbr", "b", "code", "em", "i", "mark", "small", "span", "strong", "sub", "sup", "u"]
KNOWN_SSP_CHARACTERISTICS = frozenset({"name", "description", "security sensitivity level"})
KNOWN_SSP_CONTROL_META = frozenset({"group", "profile level"})

MONTHS = {
    name: index
    for index, name in enumerate(
        ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"],
        start=1,
    )
}

# All patterns below are written so that each scan is bounded by the next
# delimiter character, keeping matching linear on hostile input.
INSERT_PARAM_RE = re.compile(r"\[\s*insert:\s*param,([^\[\]]+)\]")
# SSP pages use the short form "[as-5_prm_1]".
BARE_PARAM_RE = re.compile(r"\[\s*([A-Za-z0-9]+-\d+_prm_\d+)\s*\]")
CONTROL_HEADING_RE = re.compile(r"^([A-Za-z0-9]+)-(\d+):\s*(.+)$")
GROUP_HEADING_RE = re.compile(r"^([A-Za-z0-9]+):\s*(.*)$")
GROUP_COUNT_RE = re.compile(r"\((\d+)\)\s*$")
PARAM_CLASS_RE = re.compile(r"\(([^()]+)\)\s*$")
LAST_UPDATED_RE = re.compile(r"Last updated\s+(\d{1,2})\s+([A-Za-z]+)\s+(\d{4})")
HSPACE_RE = re.compile(r"[ \t]+")
CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f-\x9f]")


class FetchError(Exception):
    """Raised when the source document cannot be safely loaded."""


def _s(value: object) -> str:
    """Escapes control characters so untrusted values cannot forge log lines."""
    return CONTROL_CHARS_RE.sub(lambda m: f"\\x{ord(m.group()):02x}", str(value))


def is_remote(target: str) -> bool:
    return urlparse(target).scheme.lower() in {"http", "https"}


def _ensure_public_host(host: str) -> None:
    """Rejects hosts that resolve to private, loopback, link-local or reserved addresses.

    Note: requests resolves the name again when connecting, so this does not fully
    defeat DNS rebinding; the host allowlist is the primary control.
    """
    try:
        infos = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    except socket.gaierror as e:
        raise FetchError(f"Cannot resolve host {host}: {e}") from e
    for info in infos:
        ip = ipaddress.ip_address(info[4][0].split("%", 1)[0])
        if not ip.is_global:
            raise FetchError(f"Host {host} resolves to non-public address {ip}")


def validate_url(url: str, allowed_hosts: frozenset[str]) -> None:
    parsed = urlparse(url)
    if parsed.scheme.lower() != "https":
        raise FetchError(f"Only https URLs are allowed: {url}")
    if parsed.username or parsed.password:
        raise FetchError("URLs with embedded credentials are not allowed.")
    try:
        port = parsed.port
    except ValueError as e:
        raise FetchError(f"Invalid port in URL: {url}") from e
    if port not in (None, 443):
        raise FetchError(f"Non-standard port not allowed: {url}")
    host = (parsed.hostname or "").lower()
    if host not in allowed_hosts:
        raise FetchError(f"Host not in allowlist: {host or '(none)'}")
    _ensure_public_host(host)


def _charset_from_content_type(content_type: str | None) -> str | None:
    if not content_type:
        return None
    msg = Message()
    msg["content-type"] = content_type
    charset = msg.get_param("charset")
    return charset if isinstance(charset, str) else None


def fetch_url(
    url: str,
    allowed_hosts: frozenset[str],
    max_size_bytes: int = MAX_SIZE_BYTES,
) -> tuple[bytes, str | None]:
    """Fetches a URL, validating every redirect hop. Returns (body, declared charset)."""
    headers = {
        "User-Agent": "GovTech-OSCAL-Converter/1.0",
        "Accept": "text/html,application/xhtml+xml",
    }
    try:
        with requests.Session() as session:
            # Ignore ~/.netrc credentials and proxy settings from the environment.
            session.trust_env = False
            session.headers.update(headers)
            for _ in range(MAX_REDIRECTS + 1):
                validate_url(url, allowed_hosts)
                with session.get(url, timeout=(5, 30), stream=True, allow_redirects=False) as resp:
                    if resp.is_redirect:
                        url = urljoin(url, resp.headers.get("Location", ""))
                        continue
                    resp.raise_for_status()
                    body = bytearray()
                    # iter_content yields decompressed bytes, so the limit also
                    # guards against compression bombs.
                    for chunk in resp.iter_content(chunk_size=65536):
                        body += chunk
                        if len(body) > max_size_bytes:
                            raise FetchError(f"Payload exceeds maximum size limit ({max_size_bytes} bytes).")
                    return bytes(body), _charset_from_content_type(resp.headers.get("Content-Type"))
            raise FetchError(f"Too many redirects (>{MAX_REDIRECTS}).")
    except requests.RequestException as e:
        raise FetchError(f"HTTP fetch failure: {e}") from e


def read_local(target: str, max_size_bytes: int = MAX_SIZE_BYTES) -> bytes:
    resolved_path = Path(target).resolve()
    if not resolved_path.is_file():
        raise FetchError(f"File does not exist: {resolved_path}")
    # Bounded read: no gap between a size check and the read.
    with resolved_path.open("rb") as f:
        data = f.read(max_size_bytes + 1)
    if len(data) > max_size_bytes:
        raise FetchError(f"File exceeds maximum size limit ({max_size_bytes} bytes).")
    return data


def sanitize_filename(name: str) -> str:
    """Strips characters that are hazardous for filesystem operations."""
    sanitized = re.sub(r"[^A-Za-z0-9_.-]", "_", name)
    return sanitized.strip("._") or "catalog"


def slug_from_url(url: str) -> str:
    return sanitize_filename(urlparse(url).path.rstrip("/").split("/")[-1])


def family_from_url(url: str) -> str:
    """Returns the catalog family path segment after /control-catalog/ (e.g. "dss")."""
    parts = [p for p in urlparse(url).path.split("/") if p]
    if "control-catalog" in parts:
        index = parts.index("control-catalog") + 1
        if index < len(parts) - 1:
            return sanitize_filename(parts[index].lower())
    return "cybersecurity"


def doc_type_from_url(url: str) -> str:
    """Returns "ssp" for /ssp/... pages, otherwise "catalog"."""
    parts = [p for p in urlparse(url).path.split("/") if p]
    return "ssp" if parts and parts[0].lower() == "ssp" else "catalog"


def domain_from_url(url: str) -> str:
    """Names the catalog family, e.g. "Digital Service Standards" for dss."""
    family = family_from_url(url)
    return CATALOG_DOMAINS.get(family, family.replace("-", " ").replace("_", " ").title())


def _normalize_insert_param(match: re.Match[str]) -> str:
    return f"{{{{ insert: param, {match.group(1).strip()} }}}}"


def _prose_from(elem: Tag) -> str:
    # Work on a detached deep copy so the source tree is not mutated; this is
    # much cheaper than serialising and re-parsing the element.
    holder = BeautifulSoup("", "html.parser")
    holder.append(copy.copy(elem))

    # Inline markup must not introduce word breaks (".<a>gov.sg</a>" -> ".gov.sg"),
    # so unwrap it and merge the adjacent strings before extracting text.
    for inline in holder.find_all(INLINE_TAGS):
        inline.unwrap()
    holder.smooth()

    for lst in holder.find_all(["ul", "ol"]):
        bullets = [
            f"* {li.get_text(' ', strip=True)}"
            for li in lst.find_all("li", recursive=False)
        ]
        lst.replace_with("\n" + "\n".join(bullets))

    raw = holder.get_text(" ", strip=True)
    normalized = BARE_PARAM_RE.sub(_normalize_insert_param, INSERT_PARAM_RE.sub(_normalize_insert_param, raw))
    lines = [HSPACE_RE.sub(" ", line).strip() for line in normalized.split("\n")]
    return "\n".join(line for line in lines if line)


def clean_prose(elems: Iterable[Tag]) -> str:
    """Converts HTML nodes into markdown-compliant OSCAL prose."""
    return "\n".join(p for p in (_prose_from(e) for e in elems) if p)


def _parse_params(elems: list[Tag]) -> list[dict[str, Any]]:
    """Parses the first table found within the Parameters section only."""
    table: Tag | None = None
    for el in elems:
        table = el if el.name == "table" else el.find("table")
        if table:
            break
    if not table:
        return []

    params: list[dict[str, Any]] = []
    for row in table.find_all("tr")[1:]:
        cols = row.find_all(["td", "th"])
        if len(cols) < 3:
            continue
        p_id = cols[0].get_text(strip=True)
        p_type_raw = cols[1].get_text(strip=True)
        p_desc = cols[2].get_text(strip=True)

        cls_match = PARAM_CLASS_RE.search(p_type_raw)
        if cls_match:
            p_class = cls_match.group(1).strip()
            p_label = p_type_raw[: cls_match.start()].strip()
        else:
            p_class, p_label = "str", p_type_raw.strip()

        params.append({
            "id": p_id,
            "class": p_class,
            "label": p_label,
            "guidelines": [{"prose": p_desc}],
        })
    return params


def _parse_last_updated(soup: BeautifulSoup) -> datetime | None:
    node = soup.find(string=LAST_UPDATED_RE)
    if not node:
        return None
    match = LAST_UPDATED_RE.search(str(node))
    if not match:
        return None
    day, month_name, year = match.groups()
    # Month lookup is locale-independent, unlike strptime's %B.
    month = MONTHS.get(month_name[:3].lower())
    if month is None:
        logger.warning("Unrecognised month in 'Last updated' date: %s", _s(month_name))
        return None
    try:
        return datetime(int(year), month, int(day), tzinfo=SGT)
    except ValueError:
        logger.warning("Invalid 'Last updated' date: %s", _s(match.group(0)))
        return None


def _resolve_published(soup: BeautifulSoup, override: datetime | None) -> tuple[str, str]:
    """Returns (last-modified timestamp, version) from the override, the page, or now."""
    published = override or _parse_last_updated(soup)
    if published is None:
        published = datetime.now(SGT).replace(microsecond=0)
        logger.warning(
            "No 'Last updated' date found; using current time. Output will not be reproducible "
            "(pass --last-modified to pin it)."
        )
    return published.isoformat(timespec="seconds"), published.strftime("%Y.%m.%d")


def _collect_sections(
    heading: Tag, section_tag: str, stop_tags: frozenset[str]
) -> tuple[list[Tag], dict[str, list[Tag]]]:
    """Groups the siblings after a control heading by their section headings.

    Returns (elements before the first section heading, {section title: elements}),
    so multi-paragraph sections are captured in full.
    """
    preamble: list[Tag] = []
    sections: dict[str, list[Tag]] = {}
    current: str | None = None
    for sib in heading.next_siblings:
        if not isinstance(sib, Tag):
            continue
        if sib.name in stop_tags:
            break
        if sib.name == section_tag:
            current = sib.get_text(strip=True)
            sections.setdefault(current, [])
        elif current is None:
            preamble.append(sib)
        else:
            sections[current].append(sib)
    return preamble, sections


def _warn_unknown(names: Iterable[str], known: frozenset[str], seen: set[str], what: str, where: str) -> None:
    for name in set(names) - known - seen:
        seen.add(name)
        logger.warning("Ignoring unrecognised %s %r (first seen in %s)", what, _s(name), _s(where))


def _key_values(ul: Tag) -> dict[str, str]:
    """Parses a "<li><b>Key:</b> value</li>" list into {lowercased key: value}."""
    values: dict[str, str] = {}
    for li in ul.find_all("li"):
        key, sep, value = li.get_text(" ", strip=True).partition(":")
        if sep:
            values[HSPACE_RE.sub(" ", key).strip().lower()] = HSPACE_RE.sub(" ", value).strip()
    return values


# One linear pass over the page; splitting it further would scatter the HTML-to-OSCAL mapping.
# pylint: disable-next=too-many-locals
def parse_catalog(
    html_content: bytes | str,
    source_url: str,
    encoding: str | None = None,
    last_modified_override: datetime | None = None,
) -> dict[str, Any]:
    soup = BeautifulSoup(html_content, "html.parser", from_encoding=encoding)

    h1 = soup.find("h1")
    catalog_title = h1.get_text(strip=True) if h1 else "Control Catalog"

    slug = slug_from_url(source_url).upper()
    group_id = slug.lower()

    last_modified, version = _resolve_published(soup, last_modified_override)

    catalog_uuid = str(uuid.uuid5(uuid.NAMESPACE_URL, source_url))
    resource_uuid = str(uuid.uuid5(uuid.NAMESPACE_URL, source_url + "#resource"))

    domain = domain_from_url(source_url)

    controls: list[dict[str, Any]] = []
    unknown_sections: set[str] = set()

    for h2 in soup.find_all("h2"):
        match = CONTROL_HEADING_RE.match(h2.get_text(strip=True))
        if not match:
            continue

        prefix, num, title = match.group(1).lower(), match.group(2), match.group(3).strip()
        ctrl_id = f"{prefix}-{num}"

        _, sections = _collect_sections(h2, "h3", frozenset({"h2"}))
        _warn_unknown(sections, KNOWN_SECTIONS, unknown_sections, "section", ctrl_id)

        statement = clean_prose(sections.get("Control Statement", []))
        guidance = clean_prose(sections.get("Control Recommendations", []))
        params = _parse_params(sections.get("Parameters", []))

        # Cybersecurity catalogs use "Risk Statement"; DSS catalogs use "Rationale".
        props: list[dict[str, str]] = []
        if "Risk Statement" in sections or "Rationale" not in sections:
            props.append({"name": "risk-statement", "value": clean_prose(sections.get("Risk Statement", []))})
        if "Rationale" in sections:
            props.append({"name": "rationale", "value": clean_prose(sections["Rationale"])})
        props.append({"name": "last-modified", "value": last_modified})

        control: dict[str, Any] = {
            "id": ctrl_id,
            "title": title,
            "props": props,
            "links": [
                {
                    "href": f"#{resource_uuid}",
                    "rel": "source",
                    "text": f"{catalog_title} Control Catalog",
                }
            ],
            "parts": [
                {"id": f"{ctrl_id}_smt", "name": "statement", "prose": statement},
                {"id": f"{ctrl_id}_gdn", "name": "guidance", "prose": guidance},
            ],
        }
        if params:
            control["params"] = params

        controls.append(control)

    return {
        "catalog": {
            "uuid": catalog_uuid,
            "metadata": {
                "title": f"{domain} Control Catalog - {catalog_title}",
                "last-modified": last_modified,
                "version": version,
                "oscal-version": "1.1.2",
                "props": [
                    {"name": "keywords", "value": f"IM8, GovTech, Singapore, {domain.lower()}, {catalog_title}"},
                    {"name": "abbreviation", "value": slug},
                    {"name": "source", "value": source_url},
                ],
            },
            "groups": [{"id": group_id, "title": catalog_title, "controls": controls}],
            "back-matter": {
                "resources": [
                    {
                        "uuid": resource_uuid,
                        "title": f"{catalog_title} — Singapore Government ICT&SS Policy Reform",
                        "description": f"Official {catalog_title} control catalog page.",
                        "rlinks": [{"href": source_url}],
                    }
                ]
            },
        }
    }


def _catalog_family(prefix: str) -> str:
    """Finds which generated catalog family holds <prefix>.json; defaults to cybersecurity."""
    for candidate in sorted(CATALOG_OUTPUT_DIR.glob(f"*/{prefix}.json")):
        return candidate.parent.name
    return "cybersecurity"


# One linear pass over the page; splitting it further would scatter the HTML-to-OSCAL mapping.
# pylint: disable-next=too-many-locals,too-many-branches,too-many-statements
def parse_ssp(
    html_content: bytes | str,
    source_url: str,
    encoding: str | None = None,
    last_modified_override: datetime | None = None,
) -> dict[str, Any]:
    """Converts an SSP template page into an OSCAL system-security-plan.

    The page lists the baseline's selected controls grouped by catalog
    (h2 "AS: Application Security (15)" > h3 "AS-1: ..." > h4 sections).
    """
    soup = BeautifulSoup(html_content, "html.parser", from_encoding=encoding)

    def make_uuid(suffix: str) -> str:
        return str(uuid.uuid5(uuid.NAMESPACE_URL, f"{source_url}#{suffix}"))

    h1 = soup.find("h1")
    plan_title = h1.get_text(strip=True) if h1 else "System Security Plan"
    intro_elem = h1.find_next("p") if h1 else None
    intro = clean_prose([intro_elem]) if intro_elem else ""
    last_modified, version = _resolve_published(soup, last_modified_override)

    ssp_uuid = str(uuid.uuid5(uuid.NAMESPACE_URL, source_url))
    source_resource_uuid = make_uuid("resource")
    component_uuid = make_uuid("component-this-system")

    # System characteristics: "<h2>System Characteristics</h2><ul><li><b>Name:</b> ...".
    characteristics: dict[str, str] = {}
    chars_heading = soup.find("h2", string=lambda t: bool(t) and t.strip() == "System Characteristics")
    if chars_heading:
        preamble, _ = _collect_sections(chars_heading, "h3", frozenset({"h2"}))
        for el in preamble:
            if el.name == "ul":
                characteristics.update(_key_values(el))
    else:
        logger.warning("No 'System Characteristics' section found.")
    _warn_unknown(characteristics, KNOWN_SSP_CHARACTERISTICS, set(), "system characteristic", "System Characteristics")

    system_name = characteristics.get("name") or plan_title
    system_description = characteristics.get("description") or intro or system_name
    sensitivity = characteristics.get("security sensitivity level", "")

    implemented: list[dict[str, Any]] = []
    catalog_resources: dict[str, dict[str, Any]] = {}
    expected_counts: dict[str, int] = {}
    actual_counts: dict[str, int] = {}
    unknown_sections: set[str] = set()
    unknown_meta: set[str] = set()
    group: str | None = None

    for heading in soup.find_all(["h2", "h3"]):
        text = heading.get_text(strip=True)

        if heading.name == "h2":
            group = None
            match = GROUP_HEADING_RE.match(text)
            if not match:
                continue
            group = match.group(1).lower()
            rest = match.group(2)
            count_match = GROUP_COUNT_RE.search(rest)
            group_title = rest[: count_match.start()].strip() if count_match else rest.strip()
            if count_match:
                expected_counts[group] = int(count_match.group(1))
            family = _catalog_family(group)
            catalog_resources[group] = {
                "uuid": make_uuid(f"catalog-{group}"),
                "title": f"{group_title} Control Catalog",
                "rlinks": [
                    {"href": f"../control-catalog/{family}/{group}.json", "media-type": "application/json"},
                    {"href": f"{SITE_BASE}/control-catalog/{family}/{group}/", "media-type": "text/html"},
                ],
            }
            continue

        match = CONTROL_HEADING_RE.match(text)
        if group is None or not match:
            continue
        ctrl_id = f"{match.group(1).lower()}-{match.group(2)}"
        ctrl_title = match.group(3).strip()
        if match.group(1).lower() != group:
            logger.warning("Control %s listed under group %s", _s(ctrl_id), _s(group.upper()))
        actual_counts[group] = actual_counts.get(group, 0) + 1

        preamble, sections = _collect_sections(heading, "h4", frozenset({"h2", "h3"}))
        _warn_unknown(sections, KNOWN_SECTIONS, unknown_sections, "section", ctrl_id)
        meta: dict[str, str] = {}
        for el in preamble:
            if el.name == "ul":
                meta.update(_key_values(el))
        _warn_unknown(meta, KNOWN_SSP_CONTROL_META, unknown_meta, "control attribute", ctrl_id)

        statement = clean_prose(sections.get("Control Statement", []))
        remarks = [
            f"{label}:\n{prose}"
            for label, prose in (
                ("Control Recommendations", clean_prose(sections.get("Control Recommendations", []))),
                ("Risk Statement", clean_prose(sections.get("Risk Statement", []))),
                ("Rationale", clean_prose(sections.get("Rationale", []))),
            )
            if prose
        ]
        # The page defines parameters but gives no values, so they cannot be
        # expressed as set-parameters; list them for the agency to fill in.
        param_ids = [p["id"] for p in _parse_params(sections.get("Parameters", []))]
        if param_ids:
            remarks.append("Parameters to set:\n" + "\n".join(f"* {p}" for p in param_ids))

        props = [{"name": "control-title", "ns": PROP_NS, "value": ctrl_title}]
        if meta.get("profile level"):
            props.append({"name": "profile-level", "ns": PROP_NS, "value": meta["profile level"]})

        requirement: dict[str, Any] = {
            "uuid": make_uuid(f"requirement-{ctrl_id}"),
            "control-id": ctrl_id,
            "props": props,
            "links": [{"href": f"#{catalog_resources[group]['uuid']}", "rel": "reference"}],
            "by-components": [
                {
                    "component-uuid": component_uuid,
                    "uuid": make_uuid(f"by-component-{ctrl_id}"),
                    "description": statement or f"Implement {ctrl_id.upper()}: {ctrl_title}.",
                }
            ],
        }
        if remarks:
            requirement["remarks"] = "\n\n".join(remarks)
        implemented.append(requirement)

    for grp, expected in expected_counts.items():
        if actual_counts.get(grp, 0) != expected:
            logger.warning(
                "Group %s heading lists %d controls but %d were parsed.",
                _s(grp.upper()), expected, actual_counts.get(grp, 0),
            )

    system_characteristics: dict[str, Any] = {
        "system-ids": [{"identifier-type": "http://ietf.org/rfc/rfc4122", "id": ssp_uuid}],
        "system-name": system_name,
        "description": system_description,
    }
    if sensitivity:
        system_characteristics["security-sensitivity-level"] = sensitivity
    system_characteristics.update({
        "system-information": {
            "information-types": [
                {
                    "uuid": make_uuid("information-type-default"),
                    "title": f"Information classified {sensitivity}" if sensitivity else "System information",
                    "description": "Placeholder information type from the template; replace with the "
                                   "system's actual information types and impact levels.",
                    "confidentiality-impact": {"base": "low"},
                    "integrity-impact": {"base": "low"},
                    "availability-impact": {"base": "low"},
                }
            ]
        },
        "status": {
            "state": "other",
            "remarks": "Template baseline; agencies customise it into a system-specific SSP.",
        },
        "authorization-boundary": {
            "description": "Not defined by the template; agencies must describe the system's authorisation boundary.",
        },
    })

    return {
        "system-security-plan": {
            "uuid": ssp_uuid,
            "metadata": {
                "title": f"System Security Plan - {plan_title}",
                "last-modified": last_modified,
                "version": version,
                "oscal-version": "1.1.2",
                "props": [
                    {"name": "keywords", "value": f"IM8, GovTech, Singapore, SSP, {plan_title}"},
                    {"name": "source", "ns": PROP_NS, "value": source_url},
                ],
                "roles": [{"id": "system-owner", "title": "System Owner"}],
                **({"remarks": intro} if intro else {}),
            },
            "import-profile": {
                "href": f"#{source_resource_uuid}",
                "remarks": "No OSCAL profile is published for this baseline; the selected controls are listed "
                           "on the source page and resolve against the catalogs in back-matter.",
            },
            "system-characteristics": system_characteristics,
            "system-implementation": {
                "users": [
                    {
                        "uuid": make_uuid("user-system-owner"),
                        "title": "System Owner",
                        "role-ids": ["system-owner"],
                    }
                ],
                "components": [
                    {
                        "uuid": component_uuid,
                        "type": "this-system",
                        "title": system_name,
                        "description": system_description,
                        "status": {"state": "other", "remarks": "Template component."},
                    }
                ],
            },
            "control-implementation": {
                "description": intro or f"Controls selected for {plan_title}.",
                "implemented-requirements": implemented,
            },
            "back-matter": {
                "resources": [
                    {
                        "uuid": source_resource_uuid,
                        "title": f"{plan_title} System Security Plan template",
                        "description": f"Official {plan_title} SSP template page.",
                        "rlinks": [{"href": source_url, "media-type": "text/html"}],
                    },
                    *catalog_resources.values(),
                ]
            },
        }
    }


def write_atomic(path: Path, text: str, force: bool = False) -> None:
    """Writes via a temp file and rename so a failure never leaves a partial file."""
    if path.exists() and not force:
        raise FileExistsError(f"Output already exists (use --force to overwrite): {path}")
    fd, tmp_name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        # mkstemp creates 0600; apply normal umask-derived permissions instead.
        umask = os.umask(0)
        os.umask(umask)
        os.chmod(tmp_name, 0o666 & ~umask)
        os.replace(tmp_name, path)
    except BaseException:
        Path(tmp_name).unlink(missing_ok=True)
        raise


def _parse_date_arg(value: str) -> datetime:
    try:
        return datetime.strptime(value, "%Y-%m-%d").replace(tzinfo=SGT)
    except ValueError as e:
        raise argparse.ArgumentTypeError("expected YYYY-MM-DD") from e


# Mostly argparse setup plus one dispatch per document type.
# pylint: disable-next=too-many-statements
def main() -> None:
    parser = argparse.ArgumentParser(
        description="Convert a control catalog or SSP template page into OSCAL JSON format."
    )
    parser.add_argument("source", help="Target https URL or local HTML file path.")
    parser.add_argument(
        "-o",
        "--output",
        help="Destination JSON path (default in the repo: skills/im8-controls/data/control-catalog/<family>/<slug>.json "
             "for catalogs, skills/im8-controls/data/ssp/<slug>.json for SSPs).",
    )
    parser.add_argument(
        "--type",
        choices=["catalog", "ssp"],
        help="Document type (default: inferred from the source URL; catalog for local files).",
    )
    parser.add_argument(
        "--source-url",
        help="Canonical source URL recorded in the catalog (defaults to the fetched URL, "
             "or a URL derived from the local file name).",
    )
    parser.add_argument(
        "--last-modified",
        type=_parse_date_arg,
        help="Publication date (YYYY-MM-DD, SGT) overriding the date found on the page.",
    )
    parser.add_argument(
        "--allow-host",
        action="append",
        default=[],
        metavar="HOST",
        help="Additional hostname allowed for fetching (repeatable).",
    )
    parser.add_argument("-f", "--force", action="store_true", help="Overwrite an existing output file.")
    args = parser.parse_args()

    allowed_hosts = DEFAULT_ALLOWED_HOSTS | {h.lower() for h in args.allow_host}

    try:
        if is_remote(args.source):
            html_content, encoding = fetch_url(args.source, allowed_hosts)
            source_url = args.source_url or args.source
        else:
            html_content, encoding = read_local(args.source), None
            if args.source_url:
                source_url = args.source_url
            else:
                base = DEFAULT_SOURCE_BASES[args.type or "catalog"]
                source_url = f"{base}{sanitize_filename(Path(args.source).stem).lower()}/"
                logger.warning("No --source-url given; assuming %s", _s(source_url))
    except FetchError as e:
        logger.error("Failed to load source: %s", _s(e))
        sys.exit(1)

    parsed_source = urlparse(source_url)
    if parsed_source.scheme != "https" or not parsed_source.netloc:
        logger.error("Source URL must be an absolute https URL: %s", _s(source_url))
        sys.exit(1)

    doc_type = args.type or doc_type_from_url(source_url)
    slug = slug_from_url(source_url).lower()

    if doc_type == "ssp":
        document = parse_ssp(html_content, source_url, encoding, args.last_modified)
        count = len(document["system-security-plan"]["control-implementation"]["implemented-requirements"])
        default_out = SSP_OUTPUT_DIR / f"{slug}.json"
    else:
        document = parse_catalog(html_content, source_url, encoding, args.last_modified)
        count = len(document["catalog"]["groups"][0]["controls"])
        default_out = CATALOG_OUTPUT_DIR / family_from_url(source_url) / f"{slug}.json"

    if count == 0:
        logger.error("No controls found in source; refusing to write an empty %s.", doc_type)
        sys.exit(2)

    if args.output:
        out_path = Path(args.output).resolve()
    else:
        out_path = default_out
        out_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        write_atomic(out_path, json.dumps(document, indent=2, ensure_ascii=False) + "\n", args.force)
        logger.info("Successfully output %d controls to %s", count, _s(out_path))
    except OSError as e:
        logger.error("File write error: %s", _s(e))
        sys.exit(1)


if __name__ == "__main__":
    main()
