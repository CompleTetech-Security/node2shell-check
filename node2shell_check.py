#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-CompleteTech-Commercial
# Copyright (c) 2026 CompleteTech LLC. See LICENSING.md.
"""Passive Node2Shell exposure checks and offline runtime assessment. Python 3.10+."""

from __future__ import annotations

import argparse
import base64
import csv
import html
import json
import math
import os
import re
import socket
import sys
import tempfile
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from html.parser import HTMLParser
from http.client import HTTPException
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urljoin, urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

TOOL_VERSION = "1.0.0"
BOT = "Node2ShellChecker"
REDIRECTS = {301, 302, 303, 307, 308}
MAX_BODY = 2 * 1024 * 1024
MAX_ROBOTS = 512 * 1024
MAX_INVENTORY = 4 * 1024 * 1024
MAX_LOGO = 1024 * 1024

NODE2SHELL_RULES_DATE = "2026-10-23"
NODE2SHELL_CVES = ("CVE-2026-111497",)
NODE2SHELL_FIXES = {22: (22, 23, 4), 24: (24, 22, 1), 26: (26, 12, 1)}
NODE2SHELL_SOURCES = (
    "https://nodejs.org/en/blog/vulnerability/october-2026-security-releases",
    "https://nodejs.org/en/blog/release/v22.23.4",
    "https://nodejs.org/en/blog/release/v24.22.1",
    "https://nodejs.org/en/blog/release/v26.12.1",
)


def assess_node2shell(
    node_version="", *, version_candidates=None, node_hint=False,
    build_source="unknown", brotli_version="", brotli_decompress_available=None,
    brotli_block_switch_error=None,
):
    """Assess reported upstream versions without exercising the Brotli decoder.

    Runtime identity, vendor backports, and attacker-controlled input paths are
    not verified. Version strings are evidence, not proof of exploitability or
    remediation. The upstream fix table is a dated offline snapshot.
    """
    result = {
        "node2shell_status": "unknown",
        "node2shell_version_status": "version_not_disclosed",
        "node2shell_fixed_version": "",
        "node2shell_exploitability": "not_tested",
        "node2shell_cves": list(NODE2SHELL_CVES),
        "node2shell_rules_as_of": NODE2SHELL_RULES_DATE,
        "node2shell_sources": list(NODE2SHELL_SOURCES),
        "node2shell_notes": [
            "Metadata assessment only. Runtime identity, vendor backports, input reachability, and exploitability are not verified.",
            "The reported Brotli version alone cannot establish patch status: Node.js cherry-picked this fix without requiring a Brotli version bump.",
        ],
        "node2shell_recommendation": (
            "Verify the deployed Node.js binary and vendor advisory. Review incoming Brotli request parsers, outbound response decompression, and direct Brotli decoder use."
        ),
    }
    notes = result["node2shell_notes"]
    if version_candidates is None:
        values = [node_version]
    elif isinstance(version_candidates, (list, tuple, set, frozenset)):
        values = [node_version, *version_candidates]
    elif isinstance(version_candidates, str):
        values = [node_version, version_candidates]
    else:
        result["node2shell_version_status"] = "unrecognized_or_partial_version"
        notes.append("Version candidates must be strings in a collection; the supplied metadata cannot be compared.")
        return result
    if len(values) > 128:
        result["node2shell_version_status"] = "conflicting_versions"
        notes.append("Too many version candidates were supplied for a single runtime assessment.")
        return result
    if any(value is not None and not isinstance(value, str) for value in values):
        result["node2shell_version_status"] = "unrecognized_or_partial_version"
        notes.append("Non-text version metadata cannot be compared safely.")
        return result
    versions = sorted({value.strip().removeprefix("v") for value in values if value and value.strip()})
    if not versions:
        notes.append(
            "A Node.js-related indicator was observed, but no complete runtime version was reported."
            if node_hint else
            "No complete Node.js version was reported. Missing metadata does not establish that Node.js is absent."
        )
        return result
    if len(versions) != 1:
        result["node2shell_version_status"] = "conflicting_versions"
        notes.append("Conflicting reported Node.js versions: " + ", ".join(value[:128] for value in versions))
        return result

    version = versions[0]
    match = None if len(version) > 128 else re.fullmatch(
        r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", version
    )
    if not match:
        qualified = re.match(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(.+)", version[:128])
        result["node2shell_version_status"] = (
            "qualified_version_unverified" if qualified else "unrecognized_or_partial_version"
        )
        notes.append(
            f"Node.js version {version[:128]!r} is not a plain stable upstream version. Prereleases, package suffixes, and custom builds need vendor verification."
        )
        return result

    parsed = tuple(int(part) for part in match.groups())
    major = parsed[0]
    fixed_tuple = NODE2SHELL_FIXES.get(major)
    fixed = ".".join(str(part) for part in fixed_tuple) if fixed_tuple else ""
    result["node2shell_fixed_version"] = fixed
    source = build_source.strip().lower() if isinstance(build_source, str) else "invalid"
    if source not in {"", "unknown", "upstream", "official", "official_upstream"}:
        result["node2shell_version_status"] = "vendor_build_unverified"
        notes.append(
            "A vendor, distribution, custom, or unrecognized build source was reported. Its upstream version and decoder constants do not verify the applied patch set."
        )
        result["node2shell_recommendation"] = (
            "Verify the exact vendor package or custom build against its security advisory and build provenance; apply the vendor fix or deploy a fixed official Node.js runtime."
        )
        return result
    if not fixed_tuple:
        if major < 26:
            result["node2shell_status"] = "unsupported_runtime"
            result["node2shell_version_status"] = "unsupported_release_line"
            notes.append(
                f"Node.js {major}.x is outside the supported 22.x, 24.x, and 26.x lines in this snapshot. This does not assert that every historical release includes a Brotli decoder."
            )
            result["node2shell_recommendation"] = (
                "Migrate to a supported fixed Node.js release. For extended-support vendor builds, obtain explicit evidence that this CVE is fixed in the deployed package."
            )
        else:
            result["node2shell_version_status"] = "release_line_not_in_rules"
            notes.append(
                f"Node.js {major}.x is not covered by this dated rule snapshot. A numerically newer major version is not assumed to be patched."
            )
        return result

    if brotli_decompress_available is not None and not isinstance(brotli_decompress_available, bool):
        result["node2shell_version_status"] = "runtime_metadata_inconsistent"
        notes.append("Brotli API availability must be true, false, or unknown; the supplied value is invalid.")
        return result
    if brotli_block_switch_error is not None and (
        type(brotli_block_switch_error) is not int or brotli_block_switch_error != -17
    ):
        result["node2shell_version_status"] = "runtime_metadata_inconsistent"
        notes.append("The reported Brotli block-switch error constant does not match the official patched value (-17).")
        return result
    if brotli_decompress_available is False:
        result["node2shell_version_status"] = "brotli_decoder_unavailable"
        notes.append(
            "The supplied metadata reports that the Brotli decompression API is unavailable. This does not verify the binary's patch set or exclude another bundled decoder."
        )
        return result
    if brotli_block_switch_error == -17:
        notes.append(
            "The reported block-switch error constant (-17) is consistent with the upstream fix; constant presence alone is not proof of a complete patch or the deployed runtime identity."
        )
    else:
        notes.append("No Brotli block-switch patch constant was reported; absence of this evidence alone does not establish patch status.")

    if parsed < fixed_tuple:
        if brotli_block_switch_error == -17:
            result["node2shell_version_status"] = "backport_evidence_unverified"
            notes.append(
                f"Node.js {version} is below upstream fix {fixed}, but patch-related metadata is present. A vendor backport or custom build may explain this; verify its provenance."
            )
            return result
        result["node2shell_status"] = "potentially_affected"
        result["node2shell_version_status"] = "below_upstream_fix"
        notes.append(
            f"Reported Node.js {version} is below the {fixed} upstream fix. This is a version-based indication, not a verified vulnerable deployment."
        )
        result["node2shell_recommendation"] = (
            f"Prioritize runtime review and deploy Node.js {fixed} or newer in this release line, or a verified vendor fix. Rebuild affected images and restart services."
        )
    elif brotli_decompress_available is True and brotli_version and brotli_block_switch_error is None:
        result["node2shell_version_status"] = "runtime_metadata_inconsistent"
        notes.append(
            f"Reported Node.js {version} meets the {fixed} version threshold, but detailed decoder metadata lacks the patch constant. Verify the exact binary before accepting it as patched."
        )
    else:
        result["node2shell_status"] = "fixed_version_reported"
        result["node2shell_version_status"] = "at_or_above_upstream_fix"
        notes.append(
            f"Reported Node.js {version} is at or above the {fixed} upstream fix. This is a version-based observation, not independent confirmation of the deployed patch."
        )
        result["node2shell_recommendation"] = (
            "Confirm the reported version belongs to the deployed runtime and that its package contains the fix. Verify rebuilt images and restarted processes against the current vendor advisory."
        )
    return result


class CheckStopped(Exception):
    """The checker cannot safely or usefully continue."""


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def robots_path(value: str) -> str:
    """Compare encoded reserved characters literally, decoding unreserved bytes."""
    value = quote(value, safe="/%!$&'()*+,-.:;=?@_~")
    def decode(match):
        char = chr(int(match.group(1), 16))
        return char if char.isascii() and (char.isalnum() or char in "-._~") else match.group(0).upper()
    return re.sub(r"%([0-9a-fA-F]{2})", decode, value)


class RobotsPolicy:
    """Parse user-agent groups, wildcard/anchor rules and common pacing hints."""

    def __init__(self, body: str, minimum_delay: float):
        groups = []
        agents, directives = [], []
        for line in body.lstrip("\ufeff").splitlines():
            line = line.split("#", 1)[0].strip()
            if ":" not in line:
                continue
            key, value = (part.strip() for part in line.split(":", 1))
            key = key.lower()
            if key == "user-agent":
                if directives:
                    groups.append((agents, directives))
                    agents, directives = [], []
                agents.append(value.lower())
            elif agents:
                directives.append((key, value))
        if agents:
            groups.append((agents, directives))
        selected = []
        best = -1
        for agents, directives in groups:
            specificity = max((0 if a == "*" else len(a) for a in agents if a and (a == "*" or a in BOT.lower())), default=-1)
            if specificity < 0:
                continue
            if specificity > best:
                selected, best = [], specificity
            if specificity == best:
                selected.extend(directives)
        self.rules = []
        self.delay = minimum_delay
        for key, value in selected:
            if key in {"allow", "disallow"} and value:
                path = robots_path(value)
                anchored = path.endswith("$")
                if anchored:
                    path = path[:-1]
                self.rules.append((path, len(path.replace("*", "").encode("utf-8")), key == "allow", anchored))
            elif key in {"crawl-delay", "request-rate"}:
                try:
                    if key == "crawl-delay":
                        delay = float(value)
                    else:
                        count, seconds = map(float, value.split("/"))
                        delay = seconds / count
                    if math.isfinite(delay) and delay >= 0:
                        self.delay = max(self.delay, delay)
                except (ValueError, ZeroDivisionError):
                    pass

    def can_fetch(self, url: str) -> bool:
        parts = urlsplit(url)
        path = robots_path(parts.path or "/")
        if parts.query:
            path += "?" + robots_path(parts.query)
        matches = [(size, allow) for pattern, size, allow, anchored in self.rules if robots_match(pattern, path, anchored)]
        return max(matches)[1] if matches else True


def robots_match(pattern: str, path: str, anchored: bool = False) -> bool:
    """Match robots '*' and terminal '$' without regex backtracking."""
    pieces = pattern.split("*")
    if not path.startswith(pieces[0]):
        return False
    if len(pieces) == 1:
        return not anchored or path == pattern
    position = len(pieces[0])
    for piece in pieces[1:-1]:
        found = path.find(piece, position)
        if found < 0:
            return False
        position = found + len(piece)
    last = pieces[-1]
    if anchored:
        return path.endswith(last) and len(path) - len(last) >= position
    return path.find(last, position) >= 0


def normalize_url(value: str) -> str:
    value = value.strip()
    if "\\" in value:
        raise ValueError("Backslashes are not supported in URLs")
    if not value or any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValueError("URL must not be empty or contain whitespace")
    if "://" not in value:
        value = "https://" + value
    parts = urlsplit(value)
    if parts.scheme.lower() not in {"http", "https"} or not parts.hostname:
        raise ValueError("Only HTTP(S) website URLs are supported")
    if parts.username is not None or parts.password is not None:
        raise ValueError("URLs containing credentials are not supported")
    if parts.hostname and "%" in parts.hostname:
        raise ValueError("Percent escapes and scoped addresses are not supported in URL hosts")
    _ = parts.port  # Validate port before making a request.
    return urlunsplit((parts.scheme.lower(), parts.netloc, parts.path or "/", parts.query, ""))


def origin(url: str) -> str:
    p = urlsplit(url)
    return urlunsplit((p.scheme, p.netloc, "", "", ""))



def redirect_allowed(source: str, target: str) -> bool:
    """Keep redirects on this host (or its www alias), without TLS downgrade."""
    a, b = urlsplit(source), urlsplit(target)
    host_a = (a.hostname or "").lower().removeprefix("www.")
    host_b = (b.hostname or "").lower().removeprefix("www.")
    port_a = a.port or (443 if a.scheme == "https" else 80)
    port_b = b.port or (443 if b.scheme == "https" else 80)
    same_origin_port = a.scheme == b.scheme and port_a == port_b
    upgrade = a.scheme == "http" and b.scheme == "https" and port_a == 80 and port_b == 443
    return host_a == host_b and bool(host_a) and (same_origin_port or upgrade)


def plain_text(value: str) -> str:
    return re.sub(r"[\x00-\x1f\x7f-\x9f]", " ", value)


@dataclass
class Response:
    status: int
    headers: dict[str, str]
    body: str
    truncated: bool


@dataclass
class Result:
    input_url: str
    final_url: str = ""
    source: str = "http"
    status: str = "error"
    fetch_status: str = "blocked"
    http_status: int | None = None
    node_version: str = ""
    node_version_candidates: list[str] = field(default_factory=list)
    node_evidence: list[str] = field(default_factory=list)
    framework_hints: list[str] = field(default_factory=list)
    server: str = ""
    powered_by: str = ""
    title: str = ""
    response_brotli: bool = False
    build_source: str = "unknown"
    brotli_version: str = ""
    brotli_decompress_available: bool | None = None
    brotli_block_switch_error: int | None = None
    platform: str = ""
    architecture: str = ""
    notes: list[str] = field(default_factory=list)
    checked_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    node2shell_status: str = "unknown"
    node2shell_version_status: str = "version_not_disclosed"
    node2shell_fixed_version: str = ""
    node2shell_exploitability: str = "not_tested"
    node2shell_cves: list[str] = field(default_factory=lambda: list(NODE2SHELL_CVES))
    node2shell_rules_as_of: str = NODE2SHELL_RULES_DATE
    node2shell_sources: list[str] = field(default_factory=lambda: list(NODE2SHELL_SOURCES))
    node2shell_notes: list[str] = field(default_factory=list)
    node2shell_recommendation: str = ""


def annotate_node2shell(result: Result) -> None:
    assessment = assess_node2shell(
        result.node_version, version_candidates=result.node_version_candidates,
        node_hint=bool(result.node_evidence), build_source=result.build_source,
        brotli_version=result.brotli_version,
        brotli_decompress_available=result.brotli_decompress_available,
        brotli_block_switch_error=result.brotli_block_switch_error,
    )
    for name, value in assessment.items():
        setattr(result, name, value)


class PageParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.title_parts: list[str] = []
        self.hints: set[str] = set()
        self.in_title = False

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "title":
            self.in_title = True
        if a.get("id") == "__NEXT_DATA__":
            self.hints.add("Next.js HTML marker (may be a static export or a different runtime)")
        for key in ("src", "href"):
            value = a.get(key) or ""
            if "/_next/" in value:
                self.hints.add("Next.js-style asset path (asset not fetched)")
            if "/_nuxt/" in value:
                self.hints.add("Nuxt-style asset path (asset not fetched)")
        if tag == "meta" and (a.get("name") or "").lower() == "generator":
            generator = a.get("content") or ""
            if re.match(r"^(?:Next\.js|Nuxt|Astro)(?:\s|$)", generator, re.I):
                self.hints.add("Framework generator: " + plain_text(generator)[:160])

    def handle_endtag(self, tag):
        if tag == "title":
            self.in_title = False

    def handle_data(self, data):
        if self.in_title:
            self.title_parts.append(data)


def inspect_page(response: Response, result: Result) -> None:
    """Use explicit runtime disclosures only; framework assets remain weak hints."""
    try:
        result.http_status = response.status
        result.fetch_status = "ok" if 200 <= response.status < 300 else "blocked"
        headers = {k.lower(): v for k, v in response.headers.items()}
        result.server = plain_text(headers.get("server", ""))[:2048]
        result.powered_by = plain_text(headers.get("x-powered-by", ""))[:2048]
        candidates = set()
        for header, value in (("Server", headers.get("server", "")), ("X-Powered-By", headers.get("x-powered-by", ""))):
            if re.search(r"(?:^|[\s,;(])(?:node\.js|nodejs|node)(?=/|$|[\s,;)])", value, re.I):
                result.node_evidence.append(f"{header}: {plain_text(value)[:2048]}")
            candidates.update(re.findall(
                r"(?:^|[\s,;(])(?:node\.js|nodejs|node)/(v?[0-9][A-Za-z0-9.+_~:-]*)(?=$|[\s,;()])", value, re.I))
            for framework in ("Express", "Next.js", "Fastify", "Koa", "Nuxt"):
                if re.search(r"(?<![\w.])" + re.escape(framework) + r"(?![\w.])", value, re.I):
                    result.framework_hints.append(f"{header} advertises {framework}; backend runtime is not established")
        for name in ("x-node-version", "x-nodejs-version"):
            if name in headers:
                value = headers[name]
                result.node_evidence.append(f"{name}: {plain_text(value)[:2048]}")
                candidates.update(part.strip() for part in value.split(",") if part.strip())
        result.node_version_candidates = sorted(candidates)
        result.node_version = next(iter(candidates)) if len(candidates) == 1 else ""
        if len(candidates) > 1:
            result.notes.append("Multiple runtime version disclosures require review.")
        encoding = headers.get("content-encoding", "identity").strip().lower()
        result.response_brotli = "br" in [part.strip() for part in encoding.split(",")]
        if result.response_brotli:
            result.notes.append("Brotli response compression is not evidence of Node.js or vulnerable inbound decoding.")
        if response.status in {401, 403, 407, 429, 451}:
            result.status = "blocked"
            result.notes.append(f"HTTP {response.status}; access restriction or rate limit. No retry.")
            return
        if not 200 <= response.status < 300:
            result.status = "error"
            result.notes.append(f"HTTP {response.status}; page inspection skipped.")
            return
        if encoding not in {"", "identity"}:
            result.notes.append("Encoded body not decoded; only response headers inspected.")
        elif any(t in headers.get("content-type", "text/html").lower() for t in ("text/html", "application/xhtml+xml")):
            page = PageParser()
            page.feed(response.body)
            result.title = plain_text(" ".join("".join(page.title_parts).split()))[:500]
            result.framework_hints.extend(sorted(page.hints))
        else:
            result.notes.append("Non-HTML response; only response headers inspected.")
        result.status = "node_detected" if result.node_evidence else "framework_hint" if result.framework_hints else "no_evidence"
        if response.truncated:
            result.notes.append("Page inspection limited to the first 2 MiB.")
        if result.status == "no_evidence":
            result.notes.append("No public Node.js indicators; hidden runtimes cannot be ruled out.")
        result.notes.append("HTTP disclosures do not verify the deployed runtime, every serving instance, or decoder reachability.")
    finally:
        annotate_node2shell(result)


def inventory_result(record: dict, fallback_label: str = "runtime") -> Result:
    allowed = {"schema_version", "runtime", "label", "node_version", "build_source", "brotli_version",
               "brotli_decompress_available", "brotli_block_switch_error", "platform", "architecture"}
    if not isinstance(record, dict) or set(record) - allowed:
        raise ValueError("Each inventory entry must be an object containing only documented fields")
    if type(record.get("schema_version")) is not int or record["schema_version"] != 1:
        raise ValueError("Inventory schema_version must be 1")
    if record.get("runtime", "node") != "node":
        raise ValueError("This checker assesses Node.js; other runtimes require separate vendor guidance")
    if "node_version" not in record:
        raise ValueError("Inventory entry is missing node_version")
    strings = ("label", "node_version", "build_source", "brotli_version", "platform", "architecture")
    for key in strings:
        if key in record and (not isinstance(record[key], str) or len(record[key]) > 512):
            raise ValueError(f"Inventory {key} must be a string of at most 512 characters")
    available = record.get("brotli_decompress_available")
    if available is not None and type(available) is not bool:
        raise ValueError("Inventory brotli_decompress_available must be true, false, or null")
    marker = record.get("brotli_block_switch_error")
    if marker is not None and type(marker) is not int:
        raise ValueError("Inventory brotli_block_switch_error must be an integer or null")
    result = Result(input_url=record.get("label") or fallback_label, source="inventory", status="offline", fetch_status="not_requested")
    for key in strings[1:] + ("brotli_decompress_available", "brotli_block_switch_error"):
        if key in record:
            setattr(result, key, record[key])
    result.node_evidence.append("Operator-supplied inventory; no connection to the assessed runtime was made")
    result.notes.append("Inventory metadata is evidence supplied by the operator, not independent patch verification.")
    annotate_node2shell(result)
    return result


def load_inventory(path: Path) -> list[Result]:
    def unique_object(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError(f"Duplicate inventory key: {key}")
            value[key] = item
        return value

    with Path(path).open("rb") as stream:
        raw = stream.read(MAX_INVENTORY + 1)
    if len(raw) > MAX_INVENTORY:
        raise ValueError("Inventory exceeds the 4 MiB limit")
    data = json.loads(raw.decode("utf-8-sig"), object_pairs_hook=unique_object,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError("Non-finite JSON number")))
    records = data if isinstance(data, list) else [data]
    if not records or len(records) > 10000:
        raise ValueError("Inventory must contain between 1 and 10,000 entries")
    return [inventory_result(record, f"{Path(path).stem}:{index + 1}") for index, record in enumerate(records)]

class Checker:
    def __init__(self, *, timeout=15.0, delay=1.0, contact="", max_crawl_delay=60.0):
        if not (math.isfinite(timeout) and 0 < timeout <= 60):
            raise ValueError("timeout must be finite and in (0, 60]")
        if not (math.isfinite(delay) and 0 < delay <= 60):
            raise ValueError("delay must be finite and in (0, 60]")
        if not contact.isascii() or any(ord(c) < 32 or ord(c) == 127 for c in contact):
            raise ValueError("contact must be ASCII without control characters")
        self.timeout = timeout
        self.delay = delay
        self.max_crawl_delay = max_crawl_delay
        self.user_agent = f"{BOT}/{TOOL_VERSION}" + (f" (+{contact})" if contact else "")
        self.opener = build_opener(ProxyHandler({}), NoRedirect())
        self.last_request: dict[str, float] = {}
        self.robots: dict[str, tuple[RobotsPolicy | None, float, str]] = {}

    def request(self, url: str, limit: int, delay: float | None = None) -> Response:
        site = origin(url)
        wait = max(self.delay, delay or 0) - (time.monotonic() - self.last_request.get(site, -math.inf))
        if wait > 0:
            time.sleep(wait)
        self.last_request[site] = time.monotonic()
        req = Request(url, headers={"User-Agent": self.user_agent, "Accept": "text/html,text/plain;q=0.9,*/*;q=0.1", "Accept-Encoding": "identity"})
        try:
            stream = self.opener.open(req, timeout=self.timeout)
        except HTTPError as exc:
            stream = exc  # Preserve status/headers; never automatically retry.
        with stream:
            chunks = []
            total = 0
            deadline = time.monotonic() + self.timeout
            while total <= limit:
                if time.monotonic() >= deadline:
                    raise TimeoutError("Response body exceeded the read deadline")
                chunk = stream.read1(min(65536, limit + 1 - total))
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
            raw = b"".join(chunks)
            charset = stream.headers.get_content_charset() or "utf-8"
            try:
                body = raw[:limit].decode(charset, errors="replace")
            except LookupError:
                body = raw[:limit].decode("utf-8", errors="replace")
            headers = {k.lower(): ", ".join(stream.headers.get_all(k)) for k in stream.headers.keys()}
            return Response(stream.code, headers, body, len(raw) > limit)

    def policy(self, url: str) -> float:
        site = origin(url)
        if site not in self.robots:
            robot_url = site + "/robots.txt"
            response = None
            seen = set()
            for _ in range(6):
                if robot_url in seen:
                    raise CheckStopped("robots.txt redirect loop; skipping site.")
                seen.add(robot_url)
                response = self.request(robot_url, MAX_ROBOTS)
                if response.status not in REDIRECTS:
                    break
                location = response.headers.get("location")
                if not location:
                    raise CheckStopped("robots.txt redirect without Location; skipping site.")
                target = normalize_url(urljoin(robot_url, location))
                if not redirect_allowed(robot_url, target) or urlsplit(target).path != '/robots.txt':
                    raise CheckStopped("robots.txt redirects outside the permitted host scope; skipping site.")
                robot_url = target
            assert response is not None
            if response.status in {404, 410}:
                self.robots[site] = (None, self.delay, "robots.txt not published")
            elif response.status == 200 and not response.truncated:
                if response.headers.get("content-encoding", "identity").lower() not in {"identity", ""}:
                    raise CheckStopped("Cannot decode robots.txt; skipping site.")
                if re.search(r"<(?:!doctype\s+html|html|head|body)\b", response.body, re.I):
                    raise CheckStopped("robots.txt returned HTML; policy cannot be verified, skipping site.")
                parser = RobotsPolicy(response.body, self.delay)
                self.robots[site] = (parser, parser.delay, "robots.txt checked")
            else:
                raise CheckStopped(f"Cannot verify robots.txt (HTTP {response.status}, truncated={response.truncated}); skipping site.")
        parser, delay, _ = self.robots[site]
        if parser is not None and not parser.can_fetch(url):
            raise CheckStopped("robots.txt disallows this URL for this checker.")
        if delay > self.max_crawl_delay:
            raise CheckStopped(f"robots.txt requires {delay:g}-second request spacing; exceeds the {self.max_crawl_delay:g}-second batch limit. Page not fetched.")
        return delay

    def check(self, value: str) -> Result:
        result = Result(input_url=value)
        try:
            url = normalize_url(value)
            seen = set()
            for _ in range(6):
                result.final_url = url
                if url in seen:
                    raise CheckStopped("Page redirect loop; stopped.")
                seen.add(url)
                delay = self.policy(url)
                response = self.request(url, MAX_BODY, delay)
                result.http_status = response.status
                if response.status not in REDIRECTS:
                    result.notes.append(self.robots[origin(url)][2])
                    inspect_page(response, result)
                    return result
                location = response.headers.get("location")
                if not location:
                    raise CheckStopped("Page redirect without Location; stopped.")
                target = normalize_url(urljoin(url, location))
                if not redirect_allowed(url, target):
                    raise CheckStopped("Redirect outside the original host scope or HTTPS downgrade; stopped.")
                url = target
            raise CheckStopped("Too many page redirects; stopped.")
        except CheckStopped as exc:
            result.status = "blocked"
            result.notes.append(str(exc))
        except (ValueError, URLError, OSError, HTTPException, UnicodeError) as exc:
            result.status = "error"
            cause = exc.reason if isinstance(exc, URLError) else exc
            if isinstance(cause, (TimeoutError, socket.timeout)):
                result.fetch_status = "timeout"
            elif isinstance(cause, socket.gaierror):
                result.fetch_status = "dns_error"
            result.notes.append(str(exc))
        finally:
            annotate_node2shell(result)
        return result


def positive_float(value):
    number = float(value)
    if not math.isfinite(number) or not 0 < number <= 60:
        raise argparse.ArgumentTypeError("must be a finite number greater than zero and at most 60")
    return number


def csv_safe(value):
    if isinstance(value, list):
        value = " | ".join(value)
    # Prevent spreadsheet formulas from untrusted page titles / response fields.
    if isinstance(value, str) and value.lstrip().startswith(("=", "+", "-", "@")):
        return "'" + value
    return value



REPORT_CSS = """
:root{--bg:#F8FAFC;--surface:#FFFFFF;--surface-2:#EEF2FF;--ink:#0F172A;--ink-2:#1E293B;--ink-3:#64748B;--line:#E2E8F0;
--accent:#1E3A8A;--accent-text:#1E3A8A;--on-accent:#FFFFFF;--bad:#B42318;--bad-bg:#FEE4E2;--ok:#067647;--ok-bg:#DCFAE6;--unk:#475467;--unk-bg:#EAECF0}
@media (prefers-color-scheme:dark){:root{--bg:#0F172A;--surface:#1E293B;--surface-2:#273449;--ink:#F1F5F9;--ink-2:#CBD5E1;--ink-3:#94A3B8;
--line:#334155;--accent-text:#93C5FD;--bad:#FDA29B;--bad-bg:#55160C;--ok:#75E0A7;--ok-bg:#053321;--unk:#D0D5DD;--unk-bg:#344054}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 Arial,system-ui,sans-serif}
main{max-width:1080px;margin:0 auto;padding:24px 16px 48px}
header{display:flex;gap:20px;align-items:center;padding:20px 0;border-bottom:3px solid var(--accent);margin-bottom:20px}
header img{height:64px;width:auto;border-radius:8px;background:#F8FAFC;padding:4px}
.eyebrow{font-size:12px;letter-spacing:.12em;font-weight:700;color:var(--accent-text);text-transform:uppercase}
h1{margin:2px 0;font-size:26px}.sub{color:var(--ink-3);margin:0}h2{margin:32px 0 10px;font-size:18px;color:var(--ink-2)}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px}
.tile{background:var(--surface);border:1px solid var(--line);border-radius:10px;padding:14px}
.tile b{display:block;font-size:28px;color:var(--accent-text)}.tile span{color:var(--ink-3);font-size:13px}
.tile.bad b{color:var(--bad)}.tile.ok b{color:var(--ok)}
.wrap{overflow-x:auto}table{width:100%;border-collapse:collapse;background:var(--surface);border:1px solid var(--line)}
table.narrow{max-width:360px}
th{background:var(--accent);color:var(--on-accent);text-align:left;padding:8px 10px;font-size:13px;white-space:nowrap}
td{padding:8px 10px;border-top:1px solid var(--line);vertical-align:top;font-size:14px}tr:nth-child(even) td{background:var(--surface-2)}
td.site{overflow-wrap:anywhere;min-width:200px}td.notes{color:var(--ink-3);font-size:13px;min-width:240px}
code{font:13px Consolas,monospace}
.pill{display:inline-block;padding:2px 10px;border-radius:999px;font-size:12px;font-weight:700;white-space:nowrap}
.pill.unsupported_runtime,.pill.potentially_affected{color:var(--bad);background:var(--bad-bg)}.pill.fixed_version_reported{color:var(--ok);background:var(--ok-bg)}
.pill.unknown{color:var(--unk);background:var(--unk-bg)}
.callout{background:var(--surface);border:1px solid var(--line);border-left:4px solid var(--accent);border-radius:8px;padding:12px 16px;color:var(--ink-2)}
footer{margin-top:40px;padding-top:12px;border-top:1px solid var(--line);color:var(--ink-3);font-size:12px}
a{color:var(--accent-text)}
@media print{body{background:#fff}tr,.tile{break-inside:avoid}}
"""

DEFAULT_LOGO = Path(__file__).resolve().parent / "assets" / "logo.png"
STATUS_ORDER = {"potentially_affected": 0, "unsupported_runtime": 1, "unknown": 2, "fixed_version_reported": 3}
STATUS_LABELS = {"potentially_affected": "Potentially affected", "unsupported_runtime": "Unsupported runtime",
                 "unknown": "Unknown", "fixed_version_reported": "Fixed version reported"}


def logo_data_uri(path) -> str:
    if not path:
        return ""
    try:
        with Path(path).open("rb") as stream:
            data = stream.read(MAX_LOGO + 1)
    except FileNotFoundError:
        return ""
    if len(data) > MAX_LOGO:
        raise ValueError("Logo exceeds the 1 MiB limit")
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        mime = "image/png"
    elif data.startswith(b"\xff\xd8\xff"):
        mime = "image/jpeg"
    elif data.startswith((b"GIF87a", b"GIF89a")):
        mime = "image/gif"
    elif data.startswith(b"RIFF") and data[8:12] == b"WEBP":
        mime = "image/webp"
    else:
        raise ValueError("Logo must be a PNG, JPEG, GIF, or WebP raster image")
    return f"data:{mime};base64,{base64.b64encode(data).decode('ascii')}"


def render_html(rows, *, logo=DEFAULT_LOGO, brand="CompleteTech LLC", generated_at=None, complete=True) -> str:
    def esc(value):
        return html.escape("" if value is None else str(value), quote=True)

    generated_at = generated_at or datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    rows = sorted(rows, key=lambda row: STATUS_ORDER.get(row.get("node2shell_status"), 2))
    counts = {key: sum(row.get("node2shell_status") == key for row in rows) for key in STATUS_ORDER}
    tiles = [("", len(rows), "Inputs assessed"), ("bad", counts["potentially_affected"], "Potentially affected"),
             ("bad", counts["unsupported_runtime"], "Unsupported runtimes"), ("", counts["unknown"], "Unknown"),
             ("ok", counts["fixed_version_reported"], "Fixed version reported")]
    body = []
    for row in rows:
        status = row.get("node2shell_status") if row.get("node2shell_status") in STATUS_ORDER else "unknown"
        details = row.get("node_evidence", []) + row.get("framework_hints", []) + row.get("notes", []) + row.get("node2shell_notes", [])
        detail_html = "".join(f"<li>{esc(note)}</li>" for note in dict.fromkeys(details))
        body.append(
            "<tr>"
            f"<td class='site'>{esc(row.get('final_url') or row.get('input_url'))}</td>"
            f"<td><span class='pill {status}'>{STATUS_LABELS[status]}</span></td>"
            f"<td><code>{esc(row.get('node_version') or '—')}</code></td>"
            f"<td><code>{esc(row.get('node2shell_fixed_version') or '—')}</code></td>"
            f"<td>{esc(row.get('source'))}<br>{esc(row.get('status'))}</td>"
            f"<td>{esc(row.get('http_status') if row.get('http_status') is not None else row.get('fetch_status', '—'))}</td>"
            f"<td class='notes'><p>{esc(row.get('node2shell_recommendation'))}</p>"
            f"<details><summary>Evidence and limitations</summary><ul>{detail_html}</ul></details></td></tr>"
        )
    fixes = "".join(f"<tr><td>{major}.x</td><td><code>{'.'.join(map(str, version))}</code></td></tr>" for major, version in NODE2SHELL_FIXES.items())
    logo_uri = logo_data_uri(logo)
    logo_html = f"<img src='{logo_uri}' alt='{esc(brand)} logo'>" if logo_uri else ""
    tile_html = "".join(f"<div class='tile {cls}'><b>{value}</b><span>{esc(label)}</span></div>" for cls, value, label in tiles)
    sources = " · ".join(f"<a href='{esc(url)}'>{esc(url.rsplit('/', 1)[-1])}</a>" for url in NODE2SHELL_SOURCES)
    incomplete = "" if complete else "<p class='callout'><b>Interrupted run.</b> Only completed inputs are shown. Re-run the unfinished inputs.</p>"
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src data:; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>Node2Shell Exposure Report</title><style>{REPORT_CSS}
details{{max-width:430px}}summary{{cursor:pointer;color:var(--accent-text)}}details ul{{padding-left:18px}}
@media print{{details>summary{{display:none}}details>ul{{display:block}}}}
</style></head><body><main>
<header>{logo_html}<div><div class="eyebrow">{esc(brand)}</div><h1>Node2Shell Exposure Report</h1>
<p class="sub">CVE-2026-111497 · generated {esc(generated_at)} · rules as of {NODE2SHELL_RULES_DATE}</p></div></header>
<p class="callout"><b>Version evidence, not a proof of exploitability.</b> Every result has exploitability <code>not_tested</code>.
Unknown results need investigation. Framework hints and Brotli response compression do not establish a vulnerable decoder.</p>
{incomplete}<div class="tiles">{tile_html}</div>
<h2>Results</h2><div class="wrap"><table><thead><tr><th>Target / runtime</th><th>Assessment</th><th>Node.js reported</th>
<th>Upstream fix</th><th>Evidence source</th><th>Retrieval</th><th>Next step and evidence</th></tr></thead>
<tbody>{''.join(body) or '<tr><td colspan="7">No completed results.</td></tr>'}</tbody></table></div>
<h2>Upstream fix thresholds</h2><div class="wrap"><table class="narrow"><thead><tr><th>Branch</th><th>Fixed in</th></tr></thead><tbody>{fixes}</tbody></table></div>
<h2>Verify the deployed application</h2>
<p>Check the actual Node.js binary in each serving process or container. Upgrade the runtime, rebuild images, restart or redeploy,
then collect metadata again. An updated package lock or a patched workstation does not update a running server.</p>
<p>Review incoming Brotli request parsers, responses fetched from untrusted services, and direct Brotli decompression calls.
Vendor and custom builds require vendor evidence. The Brotli version string alone cannot establish patch status because fixes may be backported.</p>
<footer>{esc(brand)} · node2shell-check {TOOL_VERSION} · {sources}</footer>
</main></body></html>
"""


def write_report(output, rows, *, format="csv", logo=DEFAULT_LOGO, brand="CompleteTech LLC", complete=True):
    if format == "csv":
        writer = csv.DictWriter(output, fieldnames=list(Result.__dataclass_fields__))
        writer.writeheader()
        for row in rows:
            writer.writerow({key: csv_safe(value) for key, value in row.items()})
    elif format == "json":
        json.dump({"tool": "node2shell-check", "tool_version": TOOL_VERSION, "rules_as_of": NODE2SHELL_RULES_DATE,
                   "generated_at": datetime.now(timezone.utc).isoformat(), "complete": complete, "results": rows},
                  output, ensure_ascii=False, indent=2)
        output.write("\n")
    else:
        output.write(render_html(rows, logo=logo, brand=brand, complete=complete))


def save_report(path, rows, *, force=False, **options):
    """Publish a complete file atomically, refusing an existing path by default."""
    if path is None:
        write_report(sys.stdout, rows, **options)
        return
    path = Path(path)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", newline="", dir=path.parent, prefix=".node2shell-", delete=False) as stream:
            temporary = Path(stream.name)
            write_report(stream, rows, **options)
            stream.flush()
            os.fsync(stream.fileno())
        if force:
            os.replace(temporary, path)
        else:
            os.link(temporary, path)  # Atomic no-clobber publication, even if another writer wins the race.
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("urls", nargs="*", help="Authorized website URLs or domains (defaults to HTTPS)")
    parser.add_argument("--version", action="version", version=f"node2shell-check {TOOL_VERSION}")
    parser.add_argument("--input", type=Path, help="UTF-8 file with one authorized URL per line; # comments allowed")
    parser.add_argument("--node-version", action="append", default=[], metavar="VERSION", help="Assess an explicitly supplied Node.js version offline; repeatable")
    parser.add_argument("--inventory", action="append", default=[], type=Path, metavar="FILE", help="Assess offline runtime JSON from collect-runtime.cjs; repeatable")
    parser.add_argument("--format", choices=("csv", "json", "html"), default="csv", help="Output format (default: csv)")
    parser.add_argument("--output", type=Path, help="Save report to a new file; default: stdout")
    parser.add_argument("--force", action="store_true", help="Replace an existing output file explicitly")
    parser.add_argument("--delay", type=positive_float, default=1.0, help="Minimum request spacing per origin, in seconds (default: 1; maximum: 60)")
    parser.add_argument("--timeout", type=positive_float, default=15.0, help="Socket timeout/body read deadline, in seconds (default: 15; maximum: 60)")
    parser.add_argument("--contact", default="", help="Public ASCII contact URL/email included in the descriptive User-Agent")
    parser.add_argument("--logo", type=Path, help="Local PNG/JPEG/GIF/WebP up to 1 MiB for HTML; default: assets/logo.png")
    parser.add_argument("--brand", default="CompleteTech LLC", help="Organization name for the HTML report")
    parser.add_argument("--fail-on-finding", action="store_true", help="Exit 1 for potentially affected or unsupported runtimes (errors still exit 2)")
    args = parser.parse_args(argv)
    if not args.contact.isascii() or any(ord(c) < 32 or ord(c) == 127 for c in args.contact):
        parser.error("--contact must be ASCII without control characters")
    logo = args.logo if args.logo is not None else DEFAULT_LOGO
    urls = list(args.urls)
    offline = []
    try:
        if args.input:
            with args.input.open("rb") as stream:
                raw = stream.read(MAX_INVENTORY + 1)
            if len(raw) > MAX_INVENTORY:
                raise ValueError("URL input file exceeds the 4 MiB limit")
            urls.extend(line.strip() for line in raw.decode("utf-8-sig").splitlines() if line.strip() and not line.lstrip().startswith("#"))
        urls = list(dict.fromkeys(urls))
        for version in args.node_version:
            result = Result(input_url="Node.js " + version, node_version=version, source="version", status="offline", fetch_status="not_requested")
            result.node_evidence.append("Version supplied on the command line; runtime not queried")
            annotate_node2shell(result)
            offline.append(result)
        for path in args.inventory:
            offline.extend(load_inventory(path))
        if not urls and not offline:
            parser.error("provide URLs, --input, --node-version, or --inventory")
        if len(urls) + len(offline) > 10000:
            raise ValueError("A run is limited to 10,000 inputs")
        if args.output:
            sources = [p for p in [args.input, logo, *args.inventory] if p is not None]
            if any(args.output.resolve() == p.resolve() for p in sources):
                raise ValueError("--output must differ from every input and logo file, even with --force")
            if args.output.exists() and not args.force:
                raise ValueError("Output exists; use a new path or explicitly pass --force")
            if not args.output.parent.is_dir():
                raise ValueError("Output directory must already exist")
        if args.format == "html":
            if args.logo is not None and not args.logo.is_file():
                raise ValueError("The specified logo file does not exist")
            logo_data_uri(logo)  # Validate before any network activity.
    except (OSError, ValueError, UnicodeError, RecursionError) as exc:
        parser.error(str(exc))
    rows = []
    complete = True
    try:
        for result in offline:
            rows.append(asdict(result))
        if urls:
            checker = Checker(timeout=args.timeout, delay=args.delay, contact=args.contact)
            for index, url in enumerate(urls):
                result = checker.check(url)
                rows.append(asdict(result))
                print(f"[{index + 1}/{len(urls)}] {plain_text(url)}: {result.node2shell_status} ({result.status})", file=sys.stderr)
    except KeyboardInterrupt:
        complete = False
        print("Interrupted; preserving completed results.", file=sys.stderr)
    try:
        save_report(args.output, rows, force=args.force, format=args.format, logo=logo, brand=args.brand, complete=complete)
    except (OSError, ValueError) as exc:
        print(f"Cannot write report: {exc}", file=sys.stderr)
        return 2
    if not complete:
        return 130
    if any(row["status"] in {"error", "blocked"} for row in rows):
        return 2
    if args.fail_on_finding and any(row["node2shell_status"] in {"potentially_affected", "unsupported_runtime"} for row in rows):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
