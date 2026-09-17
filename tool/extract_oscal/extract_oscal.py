#!/usr/bin/env python3
"""
extract_oscal.py - convert one info.standards.tech.gov.sg page into OSCAL 1.1.2 JSON.

  /control-catalog/<family>/<slug>/ -> catalog
  /ssp/<slug>/                      -> system-security-plan

Source is an https URL on an allowlisted host, or a saved HTML file.
Pipeline: load -> parse_catalog / parse_ssp -> write_atomic. tool/fetch-control-catalog.sh
runs this once per page (-o into a staging folder) and then publishes all files together.

Page structure (live site, March 2026 release):

  Catalog page                          SSP page
  <h1>Application Security</h1>         <h1>Generative AI</h1>
  <h2>AS-1: Input Validation</h2>       <h2>System Characteristics</h2><ul><li>Name: ...
    <h3>Control Statement</h3> <p>...   <h2>GA: Generative AI (8)</h2>      (group, count)
    <h3>Control Recommendations</h3>      <h3>GA-1: Overseas-hosted ...</h3>
    <h3>Risk Statement</h3> (or           <ul><li>Group: ...<li>Profile level: 0
        Rationale on DSS pages)           <h4>Control Statement</h4> ...
    <h3>Parameters</h3> <table>           <h4>Parameters</h4> <table>
  "Last updated 24 March 2026"          "Last updated 24 March 2026"

  Parameter tables: ID | Type | Description, e.g.
  "as-5_prm_1 | number of characters (int) | The minimum length of a password."
  Prose references "[insert: param, as-5_prm_1]" (catalog) and "[as-5_prm_1]" (SSP)
  both become "{{ insert: param, as-5_prm_1 }}".

Markup drift: unknown headings and attributes are logged and skipped; a page with
zero controls is never written (exit 2).

Output contract, read by skills/im8-controls/scripts/im8.py (change both together):
  catalog: catalog.groups[0].controls[] with id, title, params[] (id, label,
           guidelines[].prose), parts[] named "statement"/"guidance", and props
           named "risk-statement"/"rationale".
  SSP:     system-security-plan.control-implementation.implemented-requirements[]
           with control-id, a "profile-level" prop, and remarks containing the
           literal "Parameters to set" when the control has parameters.

Determinism: UUIDs are uuid5 of the source URL and timestamps come from "Last updated"
(or --last-modified), so an unchanged page gives a byte-identical file.

Security (page HTML and HTTP responses are untrusted):
  * Fetch: https only, host allowlist, public IPs only, no env credentials/proxies,
    every redirect re-validated, size cap after decompression, timeouts.
  * Parse: html.parser; all regexes linear-time; logged values escaped with _s().
  * Write: temp file + fsync + rename, never a partial file.

Exit codes: 0 success, 1 load/validation/write failure, 2 no controls found.
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
# Guesses the page URL for a local file given without --source-url.
DEFAULT_SOURCE_BASES = {
    "catalog": f"{SITE_BASE}/control-catalog/cybersecurity/",
    "ssp": f"{SITE_BASE}/ssp/",
}
DATA_DIR = Path(__file__).resolve().parents[2] / "skills" / "im8-controls" / "data"
CATALOG_OUTPUT_DIR = DATA_DIR / "control-catalog"
SSP_OUTPUT_DIR = DATA_DIR / "ssp"
# Namespace for props that NIST OSCAL does not define.
PROP_NS = f"{SITE_BASE}/ns/oscal"
# Pages are ~100-300 KB; the cap only stops runaway or hostile responses.
MAX_SIZE_BYTES = 10 * 1024 * 1024
MAX_REDIRECTS = 5
# "Last updated" dates are Singapore dates.
SGT = timezone(timedelta(hours=8))

CATALOG_DOMAINS = {
    "cybersecurity": "Cybersecurity",
    "dss": "Digital Service Standards",
}
# Section headings the parsers map to OSCAL (h3 on catalogs, h4 on SSPs). Others are
# logged and ignored; add new ones here and map them in the parsers.
KNOWN_SECTIONS = frozenset(
    {"Control Statement", "Control Recommendations", "Risk Statement", "Rationale", "Parameters"}
)
# Unwrapped before text extraction so inline markup doesn't insert spaces.
INLINE_TAGS = ["a", "abbr", "b", "code", "em", "i", "mark", "small", "span", "strong", "sub", "sup", "u"]
# Expected lowercased "Key:" labels on SSP pages; others are logged and ignored.
KNOWN_SSP_CHARACTERISTICS = frozenset({"name", "description", "security sensitivity level"})
KNOWN_SSP_CONTROL_META = frozenset({"group", "profile level"})

# Keyed by the first three letters, so "Sept" also works.
MONTHS = {
    name: index
    for index, name in enumerate(
        ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"],
        start=1,
    )
}

# Each pattern scans only up to the next delimiter, keeping matching linear on hostile input.
# "[insert: param, as-5_prm_1]" (catalog pages).
INSERT_PARAM_RE = re.compile(r"\[\s*insert:\s*param,([^\[\]]+)\]")
# "[as-5_prm_1]" (SSP pages).
BARE_PARAM_RE = re.compile(r"\[\s*([A-Za-z0-9]+-\d+_prm_\d+)\s*\]")
# "AS-1: Input Validation" -> ("AS", "1", "Input Validation").
CONTROL_HEADING_RE = re.compile(r"^([A-Za-z0-9]+)-(\d+):\s*(.+)$")
# "GA: Generative AI (8)" -> ("GA", "Generative AI (8)").
GROUP_HEADING_RE = re.compile(r"^([A-Za-z0-9]+):\s*(.*)$")
# The "(8)" control count at the end of a group heading.
GROUP_COUNT_RE = re.compile(r"\((\d+)\)\s*$")
# "number of characters (int)" -> "int".
PARAM_CLASS_RE = re.compile(r"\(([^()]+)\)\s*$")
# "Last updated 24 March 2026" -> ("24", "March", "2026").
LAST_UPDATED_RE = re.compile(r"Last updated\s+(\d{1,2})\s+([A-Za-z]+)\s+(\d{4})")
# Horizontal whitespace only; newlines separate list bullets.
HSPACE_RE = re.compile(r"[ \t]+")
# C0/C1 control characters (incl. newline and ANSI escape).
CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f-\x9f]")


class FetchError(Exception):
    """Raised when the source document cannot be safely loaded."""


def _s(value: object) -> str:
    """Escapes control characters so untrusted values cannot forge log lines."""
    return CONTROL_CHARS_RE.sub(lambda m: f"\\x{ord(m.group()):02x}", str(value))


def is_remote(target: str) -> bool:
    """True if the source is a URL. http is included so validate_url rejects it clearly."""
    return urlparse(target).scheme.lower() in {"http", "https"}


def _ensure_public_host(host: str) -> None:
    """Rejects hosts resolving to private, loopback, link-local or reserved addresses.

    requests resolves again when connecting, so DNS rebinding is not fully
    prevented; the host allowlist is the primary control.
    """
    try:
        infos = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    except socket.gaierror as e:
        raise FetchError(f"Cannot resolve host {host}: {e}") from e
    # Check every address: the connection may use any of them.
    for info in infos:
        # Strip any IPv6 zone id ("fe80::1%en0").
        ip = ipaddress.ip_address(info[4][0].split("%", 1)[0])
        if not ip.is_global:
            raise FetchError(f"Host {host} resolves to non-public address {ip}")


def validate_url(url: str, allowed_hosts: frozenset[str]) -> None:
    """Raises FetchError unless url is safe to request. Applied to every redirect hop."""
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
    """Returns the Content-Type charset, or None (the site's usual case; BeautifulSoup then detects it)."""
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
    # The site's CDN returns 403 to the default curl and python-requests User-Agents.
    headers = {
        "User-Agent": "GovTech-OSCAL-Converter/1.0",
        "Accept": "text/html,application/xhtml+xml",
    }
    try:
        with requests.Session() as session:
            # Ignore ~/.netrc credentials and proxy environment variables.
            session.trust_env = False
            session.headers.update(headers)
            # Follow redirects by hand so each hop passes validate_url before it is requested.
            for _ in range(MAX_REDIRECTS + 1):
                validate_url(url, allowed_hosts)
                # stream=True lets the size cap stop reading before the body is buffered.
                with session.get(url, timeout=(5, 30), stream=True, allow_redirects=False) as resp:
                    if resp.is_redirect:
                        url = urljoin(url, resp.headers.get("Location", ""))
                        continue
                    resp.raise_for_status()
                    body = bytearray()
                    # iter_content yields decompressed bytes, so the cap also stops compression bombs.
                    for chunk in resp.iter_content(chunk_size=65536):
                        body += chunk
                        if len(body) > max_size_bytes:
                            raise FetchError(f"Payload exceeds maximum size limit ({max_size_bytes} bytes).")
                    return bytes(body), _charset_from_content_type(resp.headers.get("Content-Type"))
            raise FetchError(f"Too many redirects (>{MAX_REDIRECTS}).")
    except requests.RequestException as e:
        raise FetchError(f"HTTP fetch failure: {e}") from e


def read_local(target: str, max_size_bytes: int = MAX_SIZE_BYTES) -> bytes:
    """Reads a saved HTML page with the same size cap as fetch_url.

    The path is not sandboxed: it comes from the CLI user, not the untrusted page.
    """
    resolved_path = Path(target).resolve()
    if not resolved_path.is_file():
        raise FetchError(f"File does not exist: {resolved_path}")
    # Bounded read instead of stat-then-read, so there is no race.
    with resolved_path.open("rb") as f:
        data = f.read(max_size_bytes + 1)
    if len(data) > max_size_bytes:
        raise FetchError(f"File exceeds maximum size limit ({max_size_bytes} bytes).")
    return data


def sanitize_filename(name: str) -> str:
    """Makes a URL segment safe as a file or folder name: "../x" -> "x", "" -> "catalog"."""
    sanitized = re.sub(r"[^A-Za-z0-9_.-]", "_", name)
    return sanitized.strip("._") or "catalog"


def slug_from_url(url: str) -> str:
    """Returns the last path segment, filename-safe: ".../cybersecurity/as/" -> "as"."""
    return sanitize_filename(urlparse(url).path.rstrip("/").split("/")[-1])


def family_from_url(url: str) -> str:
    """Returns the catalog family path segment after /control-catalog/ (e.g. "dss")."""
    parts = [p for p in urlparse(url).path.split("/") if p]
    if "control-catalog" in parts:
        index = parts.index("control-catalog") + 1
        # A family must be followed by a slug: /control-catalog/dss/wo/ -> "dss",
        # but /control-catalog/as/ -> default.
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
    """Regex callback: rewrites a parameter reference as OSCAL "{{ insert: param, <id> }}" (im8.py relies on it)."""
    return f"{{{{ insert: param, {match.group(1).strip()} }}}}"


def _prose_from(elem: Tag) -> str:
    """Converts one HTML element to plain prose: lists become "* item" lines,
    parameter references are normalised, horizontal whitespace is collapsed."""
    # Detached copy so the source tree is not mutated (cheaper than re-parsing).
    holder = BeautifulSoup("", "html.parser")
    holder.append(copy.copy(elem))

    # Unwrap inline markup and merge strings so ".<a>gov.sg</a>" stays ".gov.sg".
    for inline in holder.find_all(INLINE_TAGS):
        inline.unwrap()
    holder.smooth()

    # These newlines survive get_text() and are the only line breaks in the result.
    for lst in holder.find_all(["ul", "ol"]):
        bullets = [
            f"* {li.get_text(' ', strip=True)}"
            for li in lst.find_all("li", recursive=False)
        ]
        lst.replace_with("\n" + "\n".join(bullets))

    raw = holder.get_text(" ", strip=True)
    # Long form first; the short form cannot match inside the rewritten "{{ ... }}".
    normalized =BARE_PARAM_RE.sub(_normalize_insert_param, INSERT_PARAM_RE.sub(_normalize_insert_param, raw))
    lines = [HSPACE_RE.sub(" ", line).strip() for line in normalized.split("\n")]
    return "\n".join(line for line in lines if line)


def clean_prose(elems: Iterable[Tag]) -> str:
    """Converts a section's elements to OSCAL prose, one line or block per element, dropping empty ones."""
    return "\n".join(p for p in (_prose_from(e) for e in elems) if p)


def _parse_params(elems: list[Tag]) -> list[dict[str, Any]]:
    """Parses the first table in a Parameters section.

    "as-5_prm_1 | number of characters (int) | The minimum length..." ->
    {"id": "as-5_prm_1", "class": "int", "label": "number of characters",
     "guidelines": [{"prose": "The minimum length..."}]}.
    class defaults to "str" when the type has no "(...)" suffix.
    """
    table: Tag | None = None
    for el in elems:
        table = el if el.name == "table" else el.find("table")
        if table:
            break
    if not table:
        return []

    params: list[dict[str, Any]] = []
    # [1:] skips the header row.
    for row in table.find_all("tr")[1:]:
        cols = row.find_all(["td", "th"])
        # Skip malformed rows rather than guess columns.
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
    """Finds "Last updated 24 March 2026" anywhere in the page; None if absent or invalid."""
    node = soup.find(string=LAST_UPDATED_RE)
    if not node:
        return None
    match = LAST_UPDATED_RE.search(str(node))
    if not match:
        return None
    day, month_name, year = match.groups()
    # Locale-independent, unlike strptime's %B.
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
    """Returns (last-modified, version) from the override, the page, or now.

    e.g. ("2026-03-24T00:00:00+08:00", "2026.03.24"). SKILL.md has the agent quote
    the version (metadata.version) as the data version.
    """
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
    """Groups the siblings after a heading by section heading.

    The page is flat (headings and content are siblings), so this walks forward,
    starting a section at each section_tag and stopping at any stop_tags heading.
    Returns (elements before the first section, {section title: elements}).
    """
    preamble: list[Tag] = []
    sections: dict[str, list[Tag]] = {}
    current: str | None = None
    for sib in heading.next_siblings:
        # Skip bare text and whitespace between tags.
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
    """Logs each unknown name once per document (updates seen). Signals site markup changes."""
    for name in set(names) - known - seen:
        seen.add(name)
        logger.warning("Ignoring unrecognised %s %r (first seen in %s)", what, _s(name), _s(where))


def _key_values(ul: Tag) -> dict[str, str]:
    """Parses a "<li><b>Key:</b> value</li>" list into {lowercased key: value}."""
    values: dict[str, str] = {}
    for li in ul.find_all("li"):
        # First colon only, so values may contain colons; items without one are skipped.
        key, sep, value = li.get_text(" ", strip=True).partition(":")
        if sep:
            values[HSPACE_RE.sub(" ", key).strip().lower()] = HSPACE_RE.sub(" ", value).strip()
    return values


# Kept as one pass so the HTML-to-OSCAL mapping stays in one place.
# pylint: disable-next=too-many-locals
def parse_catalog(
    html_content: bytes | str,
    source_url: str,
    encoding: str | None = None,
    last_modified_override: datetime | None = None,
) -> dict[str, Any]:
    """Converts a catalog page (one family, e.g. AS) into an OSCAL catalog with one group.

    encoding is the HTTP charset (None = detect). source_url drives the UUIDs,
    family and domain, so pass the canonical page URL even for a local file.
    """
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

    # Each control is an h2 owning the h3 sections up to the next h2.
    for h2 in soup.find_all("h2"):
        match = CONTROL_HEADING_RE.match(h2.get_text(strip=True))
        if not match:
            continue

        # OSCAL ids are lowercase ("as-1").
        prefix, num, title = match.group(1).lower(), match.group(2), match.group(3).strip()
        ctrl_id = f"{prefix}-{num}"

        _, sections = _collect_sections(h2, "h3", frozenset({"h2"}))
        _warn_unknown(sections, KNOWN_SECTIONS, unknown_sections, "section", ctrl_id)

        statement = clean_prose(sections.get("Control Statement", []))
        guidance = clean_prose(sections.get("Control Recommendations", []))
        params = _parse_params(sections.get("Parameters", []))

        # Cybersecurity pages have "Risk Statement", DSS pages "Rationale". risk-statement
        # is emitted (empty) when neither exists, keeping the control shape stable.
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
            # Part names and _smt/_gdn suffixes follow NIST OSCAL conventions.
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
    """Returns the family folder holding data/control-catalog/<family>/<prefix>.json (default cybersecurity).

    SSP group headings don't name the family. This reads the published data folder,
    not the fetch script's staging folder, so a brand-new family links correctly
    only after a second fetch run.
    """
    for candidate in sorted(CATALOG_OUTPUT_DIR.glob(f"*/{prefix}.json")):
        return candidate.parent.name
    return "cybersecurity"


# Kept as one pass so the HTML-to-OSCAL mapping stays in one place.
# pylint: disable-next=too-many-locals,too-many-branches,too-many-statements
def parse_ssp(
    html_content: bytes | str,
    source_url: str,
    encoding: str | None = None,
    last_modified_override: datetime | None = None,
) -> dict[str, Any]:
    """Converts an SSP template page into an OSCAL system-security-plan.

    OSCAL-required fields the template cannot fill (information types, impact
    levels, authorisation boundary) get labelled placeholders. Full control text
    stays in the catalogs: each requirement carries the statement, the other
    sections and parameter ids in remarks, and a "profile-level" prop.
    """
    soup = BeautifulSoup(html_content, "html.parser", from_encoding=encoding)

    def make_uuid(suffix: str) -> str:
        return str(uuid.uuid5(uuid.NAMESPACE_URL, f"{source_url}#{suffix}"))

    h1 = soup.find("h1")
    plan_title = h1.get_text(strip=True) if h1 else "System Security Plan"
    # The paragraph after the title describes the template.
    intro_elem = h1.find_next("p") if h1 else None
    intro = clean_prose([intro_elem]) if intro_elem else ""
    last_modified, version = _resolve_published(soup, last_modified_override)

    ssp_uuid = str(uuid.uuid5(uuid.NAMESPACE_URL, source_url))
    source_resource_uuid = make_uuid("resource")
    component_uuid = make_uuid("component-this-system")

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
    # Group prefix ("ga") -> back-matter resource for its catalog.
    catalog_resources: dict[str, dict[str, Any]] = {}
    # Heading "(8)" vs parsed count; a mismatch usually means the markup changed.
    expected_counts: dict[str, int] = {}
    actual_counts: dict[str, int] = {}
    unknown_sections: set[str] = set()
    unknown_meta: set[str] = set()
    group: str | None = None

    # Document order: an h2 opens a group; the h3s after it are its controls.
    for heading in soup.find_all(["h2", "h3"]):
        text = heading.get_text(strip=True)

        if heading.name == "h2":
            # Reset first so a non-group h2 (e.g. "System Characteristics") ends the previous group.
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
            # Links to the generated JSON (relative to data/ssp/) and the published page.
            catalog_resources[group] = {
                "uuid": make_uuid(f"catalog-{group}"),
                "title": f"{group_title} Control Catalog",
                "rlinks": [
                    {"href": f"../control-catalog/{family}/{group}.json", "media-type": "application/json"},
                    {"href": f"{SITE_BASE}/control-catalog/{family}/{group}/", "media-type": "text/html"},
                ],
            }
            continue

        # h3: a control, only inside a recognised group.
        match = CONTROL_HEADING_RE.match(text)
        if group is None or not match:
            continue
        ctrl_id = f"{match.group(1).lower()}-{match.group(2)}"
        ctrl_title = match.group(3).strip()
        # Kept under the group it appears in, but flagged.
        if match.group(1).lower() != group:
            logger.warning("Control %s listed under group %s", _s(ctrl_id), _s(group.upper()))
        actual_counts[group] = actual_counts.get(group, 0) + 1

        preamble, sections = _collect_sections(heading, "h4", frozenset({"h2", "h3"}))
        _warn_unknown(sections, KNOWN_SECTIONS, unknown_sections, "section", ctrl_id)
        # "Group / Profile level" list under the control heading.
        meta: dict[str, str] = {}
        for el in preamble:
            if el.name == "ul":
                meta.update(_key_values(el))
        _warn_unknown(meta, KNOWN_SSP_CONTROL_META, unknown_meta, "control attribute", ctrl_id)

        statement = clean_prose(sections.get("Control Statement", []))
        # implemented-requirements have no fields for these, so they go into remarks as labelled blocks.
        remarks = [
            f"{label}:\n{prose}"
            for label, prose in (
                ("Control Recommendations", clean_prose(sections.get("Control Recommendations", []))),
                ("Risk Statement", clean_prose(sections.get("Risk Statement", []))),
                ("Rationale", clean_prose(sections.get("Rationale", []))),
            )
            if prose
        ]
        # The page gives no parameter values, so they can't be set-parameters.
        # im8.py detects parameterised controls by the literal "Parameters to set".
        param_ids = [p["id"] for p in _parse_params(sections.get("Parameters", []))]
        if param_ids:
            remarks.append("Parameters to set:\n" + "\n".join(f"* {p}" for p in param_ids))

        # profile-level is the IM8 level: 0 mandatory, 1 basic hygiene, 2 best practice.
        props = [{"name": "control-title", "ns": PROP_NS, "value": ctrl_title}]
        if meta.get("profile level"):
            props.append({"name": "profile-level", "ns": PROP_NS, "value": meta["profile level"]})

        requirement: dict[str, Any] = {
            "uuid": make_uuid(f"requirement-{ctrl_id}"),
            "control-id": ctrl_id,
            "props": props,
            "links": [{"href": f"#{catalog_resources[group]['uuid']}", "rel": "reference"}],
            # One placeholder "this-system" component, described by the control statement.
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

    # Built in two steps to keep key order stable when security-sensitivity-level is present.
    system_characteristics: dict[str, Any] = {
        "system-ids": [{"identifier-type": "http://ietf.org/rfc/rfc4122", "id": ssp_uuid}],
        "system-name": system_name,
        "description": system_description,
    }
    if sensitivity:
        system_characteristics["security-sensitivity-level"] = sensitivity
    system_characteristics.update({
        # Required by the OSCAL schema; placeholders for agencies to replace.
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
            # Required by OSCAL, but no profile is published; points at the source page instead.
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
    # Same directory so os.replace is atomic; the leading "." hides leftovers from globs.
    fd, tmp_name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        # mkstemp creates 0600; apply umask-based permissions (umask is only readable by setting it).
        umask = os.umask(0)
        os.umask(umask)
        os.chmod(tmp_name, 0o666 & ~umask)
        os.replace(tmp_name, path)
    # BaseException so the temp file is also removed on Ctrl+C.
    except BaseException:
        Path(tmp_name).unlink(missing_ok=True)
        raise


def _parse_date_arg(value: str) -> datetime:
    """argparse type for --last-modified: "2026-03-24" -> midnight SGT on that date."""
    try:
        return datetime.strptime(value, "%Y-%m-%d").replace(tzinfo=SGT)
    except ValueError as e:
        raise argparse.ArgumentTypeError("expected YYYY-MM-DD") from e


# Mostly argparse setup.
# pylint: disable-next=too-many-statements
def main() -> None:
    """CLI entry point: load one page, parse it, write one JSON file."""
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

    # 1. Load. source_url drives UUIDs, document type and default output path.
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

    # Never fetched, but it becomes the document's identity, so it must be absolute https.
    parsed_source = urlparse(source_url)
    if parsed_source.scheme != "https" or not parsed_source.netloc:
        logger.error("Source URL must be an absolute https URL: %s", _s(source_url))
        sys.exit(1)

    # 2. Parse.
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

    # Zero controls usually means changed layout or an error/login page; don't overwrite good data.
    if count == 0:
        logger.error("No controls found in source; refusing to write an empty %s.", doc_type)
        sys.exit(2)

    # 3. Write. An explicit -o folder must exist; the default folder is created.
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
