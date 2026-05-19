#!/usr/bin/env python3
"""
School ICAP Guard
=================

Single-file ICAP service for Squid/OPNsense deployments:

* ICAP REQMOD and RESPMOD listener.
* ClamAV/clamd scanning over TCP or Unix socket.
* DLP regex and validator rules.
* E2Guardian/DansGuardian-style weighted phrase lists.
* Group policies for common, student, teacher, and custom groups.
* NetBird/Entra-aware identity mapping through trusted proxy headers and a
  local JSON mapping file.
* Built-in dashboard for editing config and phrase files.

The ICAP transport is implemented with the Python standard library. The classic
``pyicap`` package is Python 2-era software; this file keeps the same practical
goal, namely a small Python ICAP service that Squid can call directly.
"""

from __future__ import annotations

import argparse
import collections
import dataclasses
import datetime as _dt
import fnmatch
import hashlib
import html as html_lib
import ipaddress
import json
import logging
import os
import pathlib
import queue
import re
import secrets
import shutil
import socket
import socketserver
import struct
import sys
import tempfile
import threading
import time
import traceback
import urllib.parse
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, BinaryIO


APP_NAME = "SchoolICAPGuard"
APP_VERSION = "0.2.0-single"
BASE_DIR = pathlib.Path(__file__).resolve().parent
CONFIG_DIR = BASE_DIR / "config"
LOG_DIR = BASE_DIR / "logs"
MAX_HEADER_LINE = 65536
MAX_HEADERS_BYTES = 1024 * 1024
DEFAULT_TEXT_SCAN_BYTES = 2 * 1024 * 1024
DEFAULT_BODY_LIMIT = 25 * 1024 * 1024


E2G_CATEGORY_CATALOG: list[dict[str, Any]] = [
    {"key": "adult", "en": "Adult", "nl": "Volwassen inhoud", "default_threshold": 60, "risk": "high"},
    {"key": "pornography", "en": "Pornography", "nl": "Pornografie", "default_threshold": 60, "risk": "high"},
    {"key": "mixed_adult", "en": "Mixed adult", "nl": "Gemengde volwassen inhoud", "default_threshold": 80, "risk": "high"},
    {"key": "nudity", "en": "Nudity", "nl": "Naaktheid", "default_threshold": 70, "risk": "high"},
    {"key": "dating", "en": "Dating", "nl": "Dating", "default_threshold": 80, "risk": "medium"},
    {"key": "gambling", "en": "Gambling", "nl": "Gokken", "default_threshold": 50, "risk": "high"},
    {"key": "games", "en": "Games", "nl": "Games", "default_threshold": 90, "risk": "medium"},
    {"key": "alcohol", "en": "Alcohol", "nl": "Alcohol", "default_threshold": 70, "risk": "medium"},
    {"key": "tobacco", "en": "Tobacco", "nl": "Tabak", "default_threshold": 70, "risk": "medium"},
    {"key": "drugs", "en": "Drugs", "nl": "Drugs", "default_threshold": 60, "risk": "high"},
    {"key": "weapons", "en": "Weapons", "nl": "Wapens", "default_threshold": 60, "risk": "high"},
    {"key": "violence", "en": "Violence", "nl": "Geweld", "default_threshold": 65, "risk": "high"},
    {"key": "hate", "en": "Hate and extremism", "nl": "Haat en extremisme", "default_threshold": 60, "risk": "high"},
    {"key": "aggressive", "en": "Aggressive language", "nl": "Agressieve taal", "default_threshold": 75, "risk": "medium"},
    {"key": "badwords", "en": "Bad words", "nl": "Scheldwoorden", "default_threshold": 80, "risk": "medium"},
    {"key": "conspiracy", "en": "Conspiracy", "nl": "Complottheorieen", "default_threshold": 95, "risk": "medium"},
    {"key": "domainsforsale", "en": "Domains for sale", "nl": "Domeinen te koop", "default_threshold": 110, "risk": "low"},
    {"key": "drugadvocacy", "en": "Drug advocacy", "nl": "Drugsverheerlijking", "default_threshold": 60, "risk": "high"},
    {"key": "googlesearches", "en": "Google searches", "nl": "Google zoekopdrachten", "default_threshold": 90, "risk": "medium"},
    {"key": "gore", "en": "Gore", "nl": "Schokkend geweld", "default_threshold": 55, "risk": "high"},
    {"key": "idtheft", "en": "Identity theft", "nl": "Identiteitsdiefstal", "default_threshold": 55, "risk": "critical"},
    {"key": "illegaldrugs", "en": "Illegal drugs", "nl": "Illegale drugs", "default_threshold": 55, "risk": "high"},
    {"key": "intolerance", "en": "Intolerance", "nl": "Intolerantie", "default_threshold": 60, "risk": "high"},
    {"key": "legaldrugs", "en": "Legal drugs", "nl": "Legale drugs", "default_threshold": 75, "risk": "medium"},
    {"key": "malware", "en": "Malware", "nl": "Malware", "default_threshold": 40, "risk": "critical"},
    {"key": "phishing", "en": "Phishing", "nl": "Phishing", "default_threshold": 45, "risk": "critical"},
    {"key": "spyware", "en": "Spyware", "nl": "Spyware", "default_threshold": 45, "risk": "critical"},
    {"key": "hacking", "en": "Hacking", "nl": "Hacking", "default_threshold": 55, "risk": "high"},
    {"key": "warez", "en": "Warez and piracy", "nl": "Illegale software en piraterij", "default_threshold": 55, "risk": "high"},
    {"key": "proxy", "en": "Proxy avoidance", "nl": "Proxy omzeiling", "default_threshold": 55, "risk": "high"},
    {"key": "anonvpn", "en": "Anonymous VPN", "nl": "Anonieme VPN", "default_threshold": 55, "risk": "high"},
    {"key": "redirector", "en": "Redirectors", "nl": "Redirectors", "default_threshold": 65, "risk": "medium"},
    {"key": "url_shorteners", "en": "URL shorteners", "nl": "URL verkorters", "default_threshold": 80, "risk": "medium"},
    {"key": "filehosting", "en": "File hosting", "nl": "Bestandshosting", "default_threshold": 85, "risk": "medium"},
    {"key": "peer2peer", "en": "Peer to peer", "nl": "Peer-to-peer", "default_threshold": 70, "risk": "medium"},
    {"key": "personals", "en": "Personals", "nl": "Contactadvertenties", "default_threshold": 80, "risk": "medium"},
    {"key": "proxies", "en": "Proxies", "nl": "Proxies", "default_threshold": 55, "risk": "high"},
    {"key": "remote_access", "en": "Remote access", "nl": "Remote toegang", "default_threshold": 70, "risk": "medium"},
    {"key": "ads", "en": "Advertisements", "nl": "Advertenties", "default_threshold": 120, "risk": "low"},
    {"key": "tracking", "en": "Tracking", "nl": "Tracking", "default_threshold": 120, "risk": "low"},
    {"key": "social_networking", "en": "Social networking", "nl": "Sociale media", "default_threshold": 95, "risk": "medium"},
    {"key": "chat", "en": "Chat", "nl": "Chat", "default_threshold": 95, "risk": "medium"},
    {"key": "forums", "en": "Forums", "nl": "Forums", "default_threshold": 110, "risk": "low"},
    {"key": "blogs", "en": "Blogs", "nl": "Blogs", "default_threshold": 110, "risk": "low"},
    {"key": "webmail", "en": "Webmail", "nl": "Webmail", "default_threshold": 95, "risk": "medium"},
    {"key": "audio_video", "en": "Audio and video", "nl": "Audio en video", "default_threshold": 100, "risk": "medium"},
    {"key": "music", "en": "Music", "nl": "Muziek", "default_threshold": 100, "risk": "medium"},
    {"key": "streaming", "en": "Streaming media", "nl": "Streaming media", "default_threshold": 95, "risk": "medium"},
    {"key": "webtv", "en": "Web TV", "nl": "Web TV", "default_threshold": 100, "risk": "medium"},
    {"key": "searchengines", "en": "Search engines", "nl": "Zoekmachines", "default_threshold": 130, "risk": "low"},
    {"key": "shopping", "en": "Shopping", "nl": "Winkelen", "default_threshold": 110, "risk": "low"},
    {"key": "finance", "en": "Finance", "nl": "Financien", "default_threshold": 120, "risk": "low"},
    {"key": "banking", "en": "Banking", "nl": "Bankieren", "default_threshold": 120, "risk": "low"},
    {"key": "news", "en": "News", "nl": "Nieuws", "default_threshold": 140, "risk": "low"},
    {"key": "education", "en": "Education", "nl": "Onderwijs", "default_threshold": 160, "risk": "low"},
    {"key": "kids", "en": "Kids", "nl": "Kinderen", "default_threshold": 160, "risk": "low"},
    {"key": "health", "en": "Health", "nl": "Gezondheid", "default_threshold": 140, "risk": "low"},
    {"key": "medical", "en": "Medical", "nl": "Medisch", "default_threshold": 140, "risk": "low"},
    {"key": "government", "en": "Government", "nl": "Overheid", "default_threshold": 160, "risk": "low"},
    {"key": "legal", "en": "Legal", "nl": "Juridisch", "default_threshold": 150, "risk": "low"},
    {"key": "jobsearch", "en": "Job search", "nl": "Vacatures", "default_threshold": 130, "risk": "low"},
    {"key": "religion", "en": "Religion", "nl": "Religie", "default_threshold": 130, "risk": "low"},
    {"key": "sports", "en": "Sports", "nl": "Sport", "default_threshold": 130, "risk": "low"},
    {"key": "sport", "en": "Sport", "nl": "Sport", "default_threshold": 130, "risk": "low"},
    {"key": "travel", "en": "Travel", "nl": "Reizen", "default_threshold": 130, "risk": "low"},
    {"key": "translation", "en": "Translation", "nl": "Vertaling", "default_threshold": 140, "risk": "low"},
    {"key": "rta", "en": "Restricted to adults label", "nl": "Alleen volwassenen label", "default_threshold": 70, "risk": "high"},
    {"key": "safelabel", "en": "Self rating and safe labels", "nl": "Zelfclassificatie en safe labels", "default_threshold": 100, "risk": "low"},
    {"key": "secretsocieties", "en": "Secret societies", "nl": "Geheime genootschappen", "default_threshold": 100, "risk": "medium"},
    {"key": "upstreamfilter", "en": "Upstream filter", "nl": "Upstream filter", "default_threshold": 100, "risk": "medium"},
    {"key": "warezhacking", "en": "Warez and hacking", "nl": "Illegale software en hacking", "default_threshold": 55, "risk": "high"},
    {"key": "goodphrases", "en": "Good phrases", "nl": "Goede uitzonderingszinnen", "default_threshold": 999, "risk": "allow"},
]


def utc_now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")


def deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    merged = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def safe_json(obj: Any) -> str:
    return json.dumps(obj, indent=2, ensure_ascii=False, sort_keys=True)


def atomic_text_write(path: pathlib.Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", newline="\n", delete=False, dir=str(path.parent)
    ) as tmp:
        tmp.write(content)
        tmp_path = pathlib.Path(tmp.name)
    os.replace(tmp_path, path)


def read_text(path: pathlib.Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def parse_bool(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on", "y"}


def flatten_headers(headers: dict[str, list[str]]) -> dict[str, str]:
    return {k: ", ".join(v) for k, v in headers.items()}


def header_get(headers: dict[str, list[str]], name: str, default: str = "") -> str:
    values = headers.get(name.lower())
    if not values:
        return default
    return values[-1]


def normalize_domain(host: str) -> str:
    host = host.strip().lower()
    if not host:
        return ""
    if host.startswith("[") and "]" in host:
        return host.split("]", 1)[0].strip("[]")
    if ":" in host:
        host = host.split(":", 1)[0]
    return host.rstrip(".")


def slugify_key(value: str) -> str:
    value = value.strip().lower()
    value = re.sub(r"[^a-z0-9_-]+", "_", value)
    value = re.sub(r"_+", "_", value).strip("_")
    if not value:
        raise ValueError("empty name")
    return value


def catalog_entry(category: str) -> dict[str, Any]:
    key = slugify_key(category)
    for entry in E2G_CATEGORY_CATALOG:
        if entry["key"] == key:
            return dict(entry)
    return {
        "key": key,
        "en": key.replace("_", " ").title(),
        "nl": key.replace("_", " ").title(),
        "default_threshold": 80,
        "risk": "custom",
    }


def domain_matches(domain: str, patterns: list[str]) -> bool:
    domain = normalize_domain(domain)
    if not domain:
        return False
    for pattern in patterns:
        pattern = pattern.strip().lower().rstrip(".")
        if not pattern:
            continue
        if pattern.startswith("*."):
            suffix = pattern[1:]
            if domain.endswith(suffix) and domain != pattern[2:]:
                return True
        elif pattern.startswith("."):
            if domain.endswith(pattern) or domain == pattern[1:]:
                return True
        elif "*" in pattern:
            if fnmatch.fnmatch(domain, pattern):
                return True
        elif domain == pattern or domain.endswith("." + pattern):
            return True
    return False


def content_type_base(value: str) -> str:
    return value.split(";", 1)[0].strip().lower()


def looks_textual(content_type: str, body: bytes) -> bool:
    ctype = content_type_base(content_type)
    if not body:
        return True
    if ctype.startswith("text/"):
        return True
    if ctype in {
        "application/json",
        "application/javascript",
        "application/xml",
        "application/x-www-form-urlencoded",
        "image/svg+xml",
    }:
        return True
    sample = body[:4096]
    if b"\x00" in sample:
        return False
    printable = sum(1 for b in sample if b in b"\r\n\t" or 32 <= b < 127)
    return printable / max(1, len(sample)) > 0.82


def decode_body_for_scan(content_type: str, body: bytes, limit: int) -> str:
    if not body:
        return ""
    limited = body[:limit]
    charset_match = re.search(r"charset=([A-Za-z0-9._-]+)", content_type or "", re.I)
    encodings = []
    if charset_match:
        encodings.append(charset_match.group(1))
    encodings.extend(["utf-8", "latin-1"])
    for encoding in encodings:
        try:
            return limited.decode(encoding, errors="replace")
        except LookupError:
            continue
    return limited.decode("utf-8", errors="replace")


def parse_http_headers(raw: bytes) -> tuple[str, dict[str, list[str]], list[tuple[str, str]]]:
    text = raw.decode("iso-8859-1", errors="replace")
    text = text.replace("\r\n", "\n")
    lines = text.split("\n")
    while lines and lines[-1] == "":
        lines.pop()
    start_line = lines[0] if lines else ""
    parsed: dict[str, list[str]] = {}
    ordered: list[tuple[str, str]] = []
    current_name = ""
    current_value = ""
    for line in lines[1:]:
        if not line:
            continue
        if line[0] in " \t" and current_name:
            current_value += " " + line.strip()
            if ordered:
                ordered[-1] = (current_name, current_value)
            parsed[current_name.lower()][-1] = current_value
            continue
        if ":" not in line:
            continue
        current_name, current_value = line.split(":", 1)
        current_name = current_name.strip()
        current_value = current_value.strip()
        ordered.append((current_name, current_value))
        parsed.setdefault(current_name.lower(), []).append(current_value)
    return start_line, parsed, ordered


def build_http_headers(start_line: str, headers: list[tuple[str, str]]) -> bytes:
    lines = [start_line]
    for name, value in headers:
        lines.append(f"{name}: {value}")
    return ("\r\n".join(lines) + "\r\n\r\n").encode("iso-8859-1", errors="replace")


def parse_url_from_request(start_line: str, headers: dict[str, list[str]]) -> tuple[str, str]:
    parts = start_line.split()
    if len(parts) < 2:
        return "", ""
    target = parts[1]
    parsed = urllib.parse.urlsplit(target)
    if parsed.scheme and parsed.netloc:
        return target, normalize_domain(parsed.netloc)
    host = header_get(headers, "host")
    if host:
        scheme = "https" if parts[0].upper() == "CONNECT" or header_get(headers, "x-forwarded-proto") == "https" else "http"
        path = target if target.startswith("/") else "/"
        return f"{scheme}://{host}{path}", normalize_domain(host)
    return target, ""


def parse_icap_headers(stream: BinaryIO) -> dict[str, list[str]]:
    headers: dict[str, list[str]] = {}
    consumed = 0
    current_name = ""
    while True:
        line = stream.readline(MAX_HEADER_LINE)
        if not line:
            break
        consumed += len(line)
        if consumed > MAX_HEADERS_BYTES:
            raise ValueError("ICAP headers too large")
        if line in (b"\r\n", b"\n"):
            break
        text = line.decode("iso-8859-1", errors="replace").rstrip("\r\n")
        if text[:1] in (" ", "\t") and current_name:
            headers[current_name][-1] += " " + text.strip()
            continue
        if ":" not in text:
            continue
        name, value = text.split(":", 1)
        current_name = name.strip().lower()
        headers.setdefault(current_name, []).append(value.strip())
    return headers


def parse_encapsulated(value: str) -> dict[str, int]:
    result: dict[str, int] = {}
    for part in value.split(","):
        if "=" not in part:
            continue
        name, offset = part.split("=", 1)
        name = name.strip().lower()
        try:
            result[name] = int(offset.strip())
        except ValueError:
            continue
    return result


def parse_ip(value: str) -> str:
    value = (value or "").strip()
    if not value:
        return ""
    value = value.split(",", 1)[0].strip()
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return value


@dataclasses.dataclass
class HttpSection:
    start_line: str = ""
    headers: dict[str, list[str]] = dataclasses.field(default_factory=dict)
    ordered_headers: list[tuple[str, str]] = dataclasses.field(default_factory=list)
    raw_header: bytes = b""


@dataclasses.dataclass
class ICAPMessage:
    method: str
    uri: str
    version: str
    headers: dict[str, list[str]]
    req: HttpSection = dataclasses.field(default_factory=HttpSection)
    res: HttpSection = dataclasses.field(default_factory=HttpSection)
    body: bytes = b""
    body_truncated: bool = False
    preview_used: bool = False


@dataclasses.dataclass
class Identity:
    user: str
    source_ip: str
    groups: list[str]
    entra_object_id: str = ""
    entra_groups: list[str] = dataclasses.field(default_factory=list)
    source: str = "fallback"


@dataclasses.dataclass
class ScanContext:
    direction: str
    url: str
    domain: str
    method: str
    content_type: str
    identity: Identity
    icap_headers: dict[str, list[str]]
    http_headers: dict[str, list[str]]
    request_start: str = ""
    response_start: str = ""


@dataclasses.dataclass
class PhraseHit:
    category: str
    phrase: str
    weight: int
    count: int
    source: str
    line: int


@dataclasses.dataclass
class DLPHit:
    name: str
    action: str
    count: int
    weight: int
    sample: str


@dataclasses.dataclass
class ClamResult:
    status: str
    signature: str = ""
    error: str = ""
    scanned: bool = False


@dataclasses.dataclass
class Decision:
    allowed: bool
    reason: str
    status_code: int = 403
    category: str = ""
    policy: str = ""
    incident_id: str = dataclasses.field(default_factory=lambda: secrets.token_hex(8))
    phrase_scores: dict[str, int] = dataclasses.field(default_factory=dict)
    phrase_hits: list[PhraseHit] = dataclasses.field(default_factory=list)
    dlp_hits: list[DLPHit] = dataclasses.field(default_factory=list)
    clam: ClamResult = dataclasses.field(default_factory=lambda: ClamResult(status="skipped"))
    details: dict[str, Any] = dataclasses.field(default_factory=dict)

    def public_reason(self) -> str:
        if self.allowed:
            return "Toegestaan"
        if self.reason == "malware":
            return f"Malware gedetecteerd: {self.clam.signature or 'onbekend'}"
        if self.reason == "dlp":
            return "DLP-regel geactiveerd"
        if self.reason == "phrase":
            return f"Phrase score te hoog: {self.category}"
        if self.reason == "domain":
            return f"Domein geblokkeerd: {self.category}"
        if self.reason == "mime":
            return f"Bestandstype geblokkeerd: {self.category}"
        if self.reason == "oversize":
            return "Object groter dan scanlimiet"
        return self.reason


class EventLogger:
    """
    Persistente logger voor allow/block events.

    Events worden in JSON Lines geschreven naar ``events.jsonl`` en
    bovendien in een ringbuffer in geheugen bewaard voor het dashboard.
    Bij opstart worden de laatste ``max_memory`` regels uit het bestand
    teruggelezen, zodat het dashboard na een restart of NetBird-sync nog
    steeds historische events toont. Corrupte regels worden overgeslagen
    in plaats van de service te crashen.
    """

    def __init__(
        self,
        log_dir: pathlib.Path,
        max_memory: int = 1000,
        max_file_bytes: int = 50 * 1024 * 1024,
    ) -> None:
        self.log_dir = log_dir
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.path = log_dir / "events.jsonl"
        self.max_memory = int(max_memory)
        self.max_file_bytes = int(max_file_bytes)
        self.recent: collections.deque[dict[str, Any]] = collections.deque(maxlen=self.max_memory)
        self.lock = threading.Lock()
        self.stats: collections.Counter[str] = collections.Counter()
        self.load_errors: list[str] = []
        self._load_existing()

    def _load_existing(self) -> None:
        if not self.path.exists():
            return
        try:
            self._rotate_if_needed()
        except OSError as exc:
            self.load_errors.append(f"rotate failed: {exc}")
        try:
            with self.path.open("r", encoding="utf-8", errors="replace") as fh:
                lines = fh.readlines()
        except OSError as exc:
            self.load_errors.append(f"read failed: {exc}")
            return
        # totale stats over hele bestand bijhouden
        for raw in lines:
            raw = raw.strip()
            if not raw:
                continue
            try:
                event = json.loads(raw)
            except json.JSONDecodeError:
                continue
            self.stats["total"] += 1
            self.stats[event.get("action", "unknown")] += 1
        # alleen de laatste max_memory in geheugen plaatsen (jongste eerst)
        tail = lines[-self.max_memory :]
        for raw in tail:
            raw = raw.strip()
            if not raw:
                continue
            try:
                event = json.loads(raw)
            except json.JSONDecodeError as exc:
                self.load_errors.append(f"corrupt line skipped: {exc}")
                continue
            self.recent.appendleft(event)

    def _rotate_if_needed(self) -> None:
        try:
            size = self.path.stat().st_size
        except OSError:
            return
        if size <= self.max_file_bytes:
            return
        rotated = self.path.with_suffix(".jsonl." + _dt.datetime.now().strftime("%Y%m%d-%H%M%S") + ".old")
        try:
            os.replace(self.path, rotated)
        except OSError as exc:
            self.load_errors.append(f"rotate failed: {exc}")

    def emit(self, event: dict[str, Any]) -> None:
        event.setdefault("ts", utc_now())
        line = json.dumps(event, ensure_ascii=False, sort_keys=True)
        with self.lock:
            self.recent.appendleft(event)
            self.stats["total"] += 1
            self.stats[event.get("action", "unknown")] += 1
            try:
                with self.path.open("a", encoding="utf-8") as fh:
                    fh.write(line + "\n")
            except OSError as exc:
                logging.error("event log write failed: %s", exc)

    def all_events(self) -> list[dict[str, Any]]:
        """Lees ALLE events uit events.jsonl. Voor de logspagina."""
        if not self.path.exists():
            return []
        events: list[dict[str, Any]] = []
        try:
            with self.path.open("r", encoding="utf-8", errors="replace") as fh:
                for raw in fh:
                    raw = raw.strip()
                    if not raw:
                        continue
                    try:
                        events.append(json.loads(raw))
                    except json.JSONDecodeError:
                        continue
        except OSError as exc:
            logging.error("event log read failed: %s", exc)
        return events

    def snapshot(self) -> dict[str, Any]:
        with self.lock:
            return {
                "stats": dict(self.stats),
                "recent": list(self.recent),
                "log_path": str(self.path),
                "load_errors": list(self.load_errors),
            }


class ClamAVClient:
    def __init__(self, config: dict[str, Any]) -> None:
        self.config = config

    def enabled(self) -> bool:
        return bool(self.config.get("enabled", True))

    def scan(self, body: bytes) -> ClamResult:
        if not self.enabled():
            return ClamResult(status="disabled", scanned=False)
        if not body:
            return ClamResult(status="empty", scanned=False)
        max_bytes = int(self.config.get("max_scan_bytes", DEFAULT_BODY_LIMIT))
        if len(body) > max_bytes:
            return ClamResult(status="skipped_oversize", scanned=False)
        timeout = float(self.config.get("timeout_seconds", 30))
        try:
            if self.config.get("unix_socket"):
                sock: socket.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                sock.connect(str(self.config["unix_socket"]))
            else:
                host = str(self.config.get("host", "127.0.0.1"))
                port = int(self.config.get("port", 3310))
                sock = socket.create_connection((host, port), timeout=timeout)
            with sock:
                sock.sendall(b"zINSTREAM\0")
                for offset in range(0, len(body), 1024 * 1024):
                    chunk = body[offset : offset + 1024 * 1024]
                    sock.sendall(struct.pack("!I", len(chunk)))
                    sock.sendall(chunk)
                sock.sendall(struct.pack("!I", 0))
                response = sock.recv(4096).decode("utf-8", errors="replace").strip()
        except Exception as exc:  # noqa: BLE001 - the caller decides fail-open/fail-closed.
            return ClamResult(status="error", error=str(exc), scanned=False)
        if " FOUND" in response:
            signature = response.split(":", 1)[-1].replace("FOUND", "").strip()
            return ClamResult(status="found", signature=signature, scanned=True)
        if response.endswith("OK") or " OK" in response:
            return ClamResult(status="ok", scanned=True)
        return ClamResult(status="unknown", error=response, scanned=True)


class PhraseRule:
    def __init__(
        self,
        category: str,
        phrase: str,
        weight: int,
        source: str,
        line: int,
        regex: re.Pattern[str],
    ) -> None:
        self.category = category
        self.phrase = phrase
        self.weight = weight
        self.source = source
        self.line = line
        self.regex = regex

    def scan(self, text: str) -> PhraseHit | None:
        matches = self.regex.findall(text)
        if not matches:
            return None
        return PhraseHit(
            category=self.category,
            phrase=self.phrase,
            weight=self.weight,
            count=len(matches),
            source=self.source,
            line=self.line,
        )


class PhraseEngine:
    WEIGHT_RE = re.compile(r"^\s*(?:\{([+-]?\d+)\}|\[([+-]?\d+)\]|([+-]?\d+)\s*[:;])\s*")
    TAG_RE = re.compile(r"<([^<>]+)>")

    def __init__(self, phrase_root: pathlib.Path, config: dict[str, Any]) -> None:
        self.phrase_root = phrase_root
        self.config = config
        self.rules: list[PhraseRule] = []
        self.load_errors: list[str] = []
        self.load()

    def load(self) -> None:
        self.rules.clear()
        self.load_errors.clear()
        if not self.phrase_root.exists():
            return
        extensions = tuple(self.config.get("extensions", [".weightedphraselist", ".phraselist", ".txt"]))
        for path in sorted(self.phrase_root.rglob("*")):
            if not path.is_file():
                continue
            if path.suffix.lower() not in extensions:
                continue
            try:
                self._load_file(path)
            except Exception as exc:  # noqa: BLE001
                self.load_errors.append(f"{path}: {exc}")

    def _category_for_file(self, path: pathlib.Path) -> str:
        rel = path.relative_to(self.phrase_root)
        if len(rel.parts) > 1:
            return rel.parts[0].lower()
        return path.stem.split(".", 1)[0].lower()

    def _load_file(self, path: pathlib.Path) -> None:
        category = self._category_for_file(path)
        current_category = category
        default_weight = int(self.config.get("default_weight", 10))
        for line_no, raw in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            line = raw.strip()
            if not line:
                continue
            if line.startswith("#"):
                list_cat = re.search(r"listcategory\s*:\s*[\"']?([^\"']+)", line, re.I)
                if list_cat:
                    current_category = re.sub(r"\W+", "_", list_cat.group(1).strip().lower()).strip("_")
                continue
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            weight = default_weight
            match = self.WEIGHT_RE.match(line)
            if match:
                weight = int(next(g for g in match.groups() if g is not None))
                line = line[match.end() :].strip()
            tag_values = [item.strip() for item in self.TAG_RE.findall(line) if item.strip()]
            if tag_values:
                if len(tag_values) == 1:
                    phrases = tag_values
                elif self.config.get("match_individual_tags", False):
                    phrases = tag_values
                else:
                    phrases = [" ".join(tag_values)]
            else:
                phrases = [line.strip("<> ")]
            for phrase in phrases:
                regex = self._compile_phrase(phrase)
                if regex:
                    self.rules.append(
                        PhraseRule(
                            category=current_category,
                            phrase=phrase,
                            weight=weight,
                            source=str(path.relative_to(self.phrase_root)),
                            line=line_no,
                            regex=regex,
                        )
                    )

    def _compile_phrase(self, phrase: str) -> re.Pattern[str] | None:
        phrase = re.sub(r"\s+", " ", phrase.strip().lower())
        if not phrase:
            return None
        words = phrase.split(" ")
        parts = []
        for word in words:
            escaped = re.escape(word).replace(r"\*", r"[\w-]*")
            parts.append(escaped)
        body = r"[\W_]+".join(parts)
        pattern = rf"(?<![\w]){body}(?![\w])"
        try:
            return re.compile(pattern, re.IGNORECASE | re.UNICODE)
        except re.error as exc:
            self.load_errors.append(f"invalid phrase regex for {phrase!r}: {exc}")
            return None

    def scan(self, text: str) -> tuple[dict[str, int], list[PhraseHit]]:
        scores: collections.Counter[str] = collections.Counter()
        hits: list[PhraseHit] = []
        if not text or not self.rules:
            return {}, []
        for rule in self.rules:
            hit = rule.scan(text)
            if not hit:
                continue
            scores[hit.category] += hit.weight * hit.count
            hits.append(hit)
        return dict(scores), hits


class DLPValidator:
    CARD_RE = re.compile(r"\b(?:\d[ -]?){13,19}\b")
    IBAN_RE = re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b", re.I)
    BELGIAN_RRN_RE = re.compile(r"\b\d{2}[.\- ]?\d{2}[.\- ]?\d{2}[.\- ]?\d{3}[.\- ]?\d{2}\b")

    @staticmethod
    def luhn(candidate: str) -> bool:
        digits = [int(ch) for ch in re.sub(r"\D", "", candidate)]
        if len(digits) < 13 or len(digits) > 19:
            return False
        total = 0
        parity = len(digits) % 2
        for idx, digit in enumerate(digits):
            if idx % 2 == parity:
                digit *= 2
                if digit > 9:
                    digit -= 9
            total += digit
        return total % 10 == 0

    @staticmethod
    def iban(candidate: str) -> bool:
        compact = re.sub(r"\s+", "", candidate).upper()
        if len(compact) < 15 or len(compact) > 34:
            return False
        rearranged = compact[4:] + compact[:4]
        digits = ""
        for char in rearranged:
            if char.isdigit():
                digits += char
            elif "A" <= char <= "Z":
                digits += str(ord(char) - 55)
            else:
                return False
        remainder = 0
        for char in digits:
            remainder = (remainder * 10 + int(char)) % 97
        return remainder == 1

    @staticmethod
    def belgian_rrn(candidate: str) -> bool:
        digits = re.sub(r"\D", "", candidate)
        if len(digits) != 11:
            return False
        base = int(digits[:9])
        check = int(digits[9:])
        if 97 - (base % 97) == check:
            return True
        return 97 - (int("2" + digits[:9]) % 97) == check

    @classmethod
    def builtin_matches(cls, kind: str, text: str) -> list[str]:
        if kind == "credit_card_luhn":
            return [m.group(0) for m in cls.CARD_RE.finditer(text) if cls.luhn(m.group(0))]
        if kind == "iban":
            return [m.group(0) for m in cls.IBAN_RE.finditer(text) if cls.iban(m.group(0))]
        if kind == "belgian_rrn":
            return [m.group(0) for m in cls.BELGIAN_RRN_RE.finditer(text) if cls.belgian_rrn(m.group(0))]
        return []


class DLPEngine:
    def __init__(self, dlp_config: dict[str, Any]) -> None:
        self.rules = dlp_config.get("rules", [])
        self.errors: list[str] = []
        for rule in self.rules:
            if rule.get("enabled", True) and rule.get("pattern"):
                try:
                    rule["_compiled"] = re.compile(str(rule["pattern"]), re.I | re.M)
                except re.error as exc:
                    self.errors.append(f"{rule.get('name', 'unnamed')}: {exc}")

    def scan(self, text: str, groups: list[str]) -> tuple[int, list[DLPHit]]:
        score = 0
        hits: list[DLPHit] = []
        if not text:
            return score, hits
        group_set = set(groups)
        for rule in self.rules:
            if not rule.get("enabled", True):
                continue
            applies_to = set(rule.get("groups", []))
            if applies_to and not (applies_to & group_set):
                continue
            matches: list[str] = []
            if rule.get("builtin"):
                matches = DLPValidator.builtin_matches(str(rule["builtin"]), text)
            elif rule.get("_compiled"):
                matches = [m.group(0) for m in rule["_compiled"].finditer(text)]
            min_matches = int(rule.get("min_matches", 1))
            if len(matches) < min_matches:
                continue
            weight = int(rule.get("weight", 50))
            score += weight * len(matches)
            sample = ", ".join(self._redact(m) for m in matches[:3])
            hits.append(
                DLPHit(
                    name=str(rule.get("name", "unnamed")),
                    action=str(rule.get("action", "block")),
                    count=len(matches),
                    weight=weight,
                    sample=sample,
                )
            )
        return score, hits

    @staticmethod
    def _redact(value: str) -> str:
        value = re.sub(r"\s+", " ", value.strip())
        if len(value) <= 8:
            return value[:1] + "***"
        return value[:4] + "***" + value[-2:]


class IdentityResolver:
    def __init__(self, config: dict[str, Any], users: dict[str, Any]) -> None:
        self.config = config
        self.users = users

    def resolve(self, icap_headers: dict[str, list[str]], http_headers: dict[str, list[str]]) -> Identity:
        source_ip = self._first_header(icap_headers, self.config.get("client_ip_headers", []))
        source_ip = parse_ip(source_ip)
        username = self._first_header(icap_headers, self.config.get("username_headers", []))
        if not username:
            username = self._first_header(http_headers, self.config.get("http_username_headers", []))
        username = urllib.parse.unquote(username or "").strip()
        entra_object_id = self._first_header(http_headers, self.config.get("entra_object_headers", []))
        entra_group_header = self._first_header(http_headers, self.config.get("entra_group_headers", []))
        entra_groups = self._split_group_header(entra_group_header)
        groups: list[str] = []
        source = "fallback"

        ip_map = self.users.get("ip_map", {})
        if source_ip and source_ip in ip_map:
            mapped = ip_map[source_ip]
            if isinstance(mapped, str):
                username = username or mapped
                user_obj = self.users.get("users", {}).get(mapped, {})
                groups.extend(user_obj.get("groups", []))
            elif isinstance(mapped, dict):
                username = username or mapped.get("user", "")
                groups.extend(mapped.get("groups", []))
            source = "ip_map"

        if username:
            user_obj = self.users.get("users", {}).get(username.lower()) or self.users.get("users", {}).get(username)
            if user_obj:
                groups.extend(user_obj.get("groups", []))
                entra_object_id = entra_object_id or user_obj.get("entra_object_id", "")
                entra_groups.extend(user_obj.get("entra_groups", []))
                source = "user_map"

        entra_object_map = self.users.get("entra_object_map", {})
        if entra_object_id and entra_object_id in entra_object_map:
            mapped = entra_object_map[entra_object_id]
            if isinstance(mapped, dict):
                username = username or mapped.get("user", "")
                groups.extend(mapped.get("groups", []))
            source = "entra_object_map"

        group_map = self.config.get("entra_group_map", {})
        for group_id in entra_groups:
            mapped = group_map.get(group_id) or group_map.get(group_id.lower())
            if mapped:
                if isinstance(mapped, list):
                    groups.extend(mapped)
                else:
                    groups.append(str(mapped))
                source = "entra_group_header"

        if not groups:
            default_group = str(self.config.get("default_group", "")).strip()
            if default_group:
                groups.append(default_group)
        groups = sorted({g for g in groups if g})
        if not username:
            username = f"ip:{source_ip}" if source_ip else "anonymous"
        return Identity(
            user=username,
            source_ip=source_ip,
            groups=groups,
            entra_object_id=entra_object_id,
            entra_groups=sorted(set(entra_groups)),
            source=source,
        )

    @staticmethod
    def _first_header(headers: dict[str, list[str]], names: list[str]) -> str:
        for name in names:
            value = header_get(headers, name)
            if value:
                return value
        return ""

    @staticmethod
    def _split_group_header(value: str) -> list[str]:
        if not value:
            return []
        cleaned = value.replace(";", ",")
        return [item.strip().lower() for item in cleaned.split(",") if item.strip()]


class PolicyEngine:
    def __init__(
        self,
        config: dict[str, Any],
        phrase_engine: PhraseEngine,
        dlp_engine: DLPEngine,
        clamav: ClamAVClient,
    ) -> None:
        self.config = config
        self.policies = config.get("policies", {})
        self.common = config.get("common_policy", {})
        self.phrase_engine = phrase_engine
        self.dlp_engine = dlp_engine
        self.clamav = clamav

    def applicable_policies(self, groups: list[str]) -> list[tuple[str, dict[str, Any]]]:
        result = [("common", self.common)]
        for group in groups:
            policy = self.policies.get(group)
            if policy:
                result.append((group, policy))
        if len(result) == 1:
            fallback = str(self.config.get("identity", {}).get("default_group", "")).strip()
            if fallback and fallback in self.policies:
                result.append((fallback, self.policies[fallback]))
        return result

    def evaluate(self, context: ScanContext, body: bytes) -> Decision:
        policies = self.applicable_policies(context.identity.groups)
        policy_names = [name for name, _ in policies]

        # ------------------------------------------------------------------
        # STAP 1: Allowlist heeft ALTIJD prioriteit boven blacklist/UT1.
        # Een handmatig toegelaten domein overrulet altijd blacklist en
        # UT1-categorieen. Dit komt eerst, zodat er nooit een conflict is.
        # ------------------------------------------------------------------
        allowed_domains = self._list_union(policies, "allowed_domains")
        allow_bypasses = any(
            bool(policy.get("allow_domains_bypass_content", True))
            for _, policy in policies
        )
        domain_is_allowed = domain_matches(context.domain, allowed_domains) if context.domain else False
        if domain_is_allowed and allow_bypasses:
            return Decision(
                True,
                "allowlist_override",
                category=context.domain,
                policy=",".join(policy_names),
                details={"matched_allowlist": True},
            )

        settings = self.config.get("settings", {}) or {}
        webfilter_on = bool(settings.get("webfilter_enabled", True))
        domain_blocking_on = bool(settings.get("domain_blocking_enabled", True))
        weighted_phrases_on = bool(settings.get("weighted_phrases_enabled", False))
        dlp_master_on = bool(settings.get("dlp_enabled", True))
        antivirus_master_on = bool(settings.get("antivirus_enabled", True))

        body_limit = self._min_int(policies, "max_body_bytes", DEFAULT_BODY_LIMIT)
        if len(body) > body_limit:
            action = self._first_value(policies, "oversize_action", "allow").lower()
            if action == "block":
                return Decision(False, "oversize", policy=",".join(policy_names), details={"limit": body_limit})

        blocked_domains = self._list_union(policies, "blocked_domains")
        hard_blocked_domains = self._list_union(policies, "hard_blocked_domains")

        if domain_blocking_on and webfilter_on and not domain_is_allowed:
            if domain_matches(context.domain, hard_blocked_domains):
                return Decision(False, "domain", category=context.domain, policy="common")
            if domain_matches(context.domain, blocked_domains):
                return Decision(False, "domain", category=context.domain, policy=",".join(policy_names))

        bypass_content = domain_is_allowed  # allowlist mag verdere scans overslaan

        blocked_mime = self._list_union(policies, "blocked_mime_types")
        ctype = content_type_base(context.content_type)
        if webfilter_on and ctype and any(fnmatch.fnmatch(ctype, pattern.lower()) for pattern in blocked_mime):
            return Decision(False, "mime", category=ctype, policy=",".join(policy_names))

        clam_result = ClamResult(status="skipped")
        malware_policy_enabled = any(policy.get("malware", True) for _, policy in policies)
        if antivirus_master_on and malware_policy_enabled and body:
            clam_result = self.clamav.scan(body)
            if clam_result.status == "found":
                return Decision(False, "malware", policy=",".join(policy_names), clam=clam_result)
            if clam_result.status == "error":
                fail_open = bool(self.config.get("clamav", {}).get("fail_open", False))
                if not fail_open:
                    return Decision(
                        False,
                        "malware",
                        status_code=502,
                        policy=",".join(policy_names),
                        clam=clam_result,
                        details={"error": clam_result.error},
                    )

        if bypass_content:
            return Decision(True, "allowed_domain", policy=",".join(policy_names), clam=clam_result)

        # ------------------------------------------------------------------
        # DLP: scan UITSLUITEND op POST/PUT/PATCH request body via REQMOD.
        # DLP is bedoeld voor data die de gebruiker zelf VERSTUURT
        # (formulier, upload, POST body). Het mag dus NIET blokkeren omdat
        # gevoelige tekst in een URL of op een gewone webpagina staat.
        # Daarom kijken we hier niet naar response body of headers.
        # ------------------------------------------------------------------
        if dlp_master_on:
            dlp_body_text = self._dlp_scan_text(context, body)
            if dlp_body_text:
                dlp_enabled = any(policy.get("dlp_enabled", True) for _, policy in policies)
                if dlp_enabled:
                    dlp_score, dlp_hits = self.dlp_engine.scan(dlp_body_text, context.identity.groups)
                    threshold = self._min_int(policies, "dlp_score_threshold", 50)
                    has_block_hit = any(hit.action == "block" for hit in dlp_hits)
                    if dlp_hits and has_block_hit and dlp_score >= threshold:
                        return Decision(
                            False,
                            "dlp",
                            policy=",".join(policy_names),
                            dlp_hits=dlp_hits,
                            clam=clam_result,
                            details={"score": dlp_score, "threshold": threshold},
                        )

        # Webfilter phrase scoring (los van DLP). Alleen actief als
        # weighted_phrases globaal aan staat.
        if webfilter_on and weighted_phrases_on:
            scan_text = self._webfilter_scan_text(context, body)
            if scan_text:
                phrase_scores, phrase_hits = self.phrase_engine.scan(scan_text)
                phrase_decision = self._phrase_decision(policies, phrase_scores, phrase_hits)
                if phrase_decision:
                    phrase_decision.policy = ",".join(policy_names)
                    phrase_decision.clam = clam_result
                    return phrase_decision

        return Decision(True, "clean", policy=",".join(policy_names), clam=clam_result)

    def _dlp_scan_text(self, context: ScanContext, body: bytes) -> str:
        """
        Geef de tekst terug die DLP mag bekijken.

        DLP is per definitie alleen geldig op data die de client VERSTUURT.
        Dus: enkel REQMOD, enkel methodes met een body (POST/PUT/PATCH),
        en enkel het body-gedeelte. Geen URL, geen response, geen headers.
        """
        if context.direction.lower() != "reqmod":
            return ""
        method = (context.method or "").upper()
        if method not in {"POST", "PUT", "PATCH"}:
            return ""
        if not body:
            return ""
        if not looks_textual(context.content_type, body):
            return ""
        text_limit = int(self.config.get("scan", {}).get("text_scan_bytes", DEFAULT_TEXT_SCAN_BYTES))
        return decode_body_for_scan(context.content_type, body, text_limit)

    def _webfilter_scan_text(self, context: ScanContext, body: bytes) -> str:
        """Tekstbron voor webfilter/phrase scoring. Dit mag URL, request en
        response data combineren - dit is content filtering, geen DLP."""
        parts = [context.url, context.domain, context.request_start, context.response_start]
        for name, values in context.http_headers.items():
            if name in {"authorization", "cookie", "set-cookie"}:
                continue
            parts.extend(values)
        if looks_textual(context.content_type, body):
            text_limit = int(self.config.get("scan", {}).get("text_scan_bytes", DEFAULT_TEXT_SCAN_BYTES))
            parts.append(decode_body_for_scan(context.content_type, body, text_limit))
        return "\n".join(part for part in parts if part)

    def _phrase_decision(
        self,
        policies: list[tuple[str, dict[str, Any]]],
        phrase_scores: dict[str, int],
        phrase_hits: list[PhraseHit],
    ) -> Decision | None:
        if not phrase_scores:
            return None
        for name, policy in policies:
            thresholds = policy.get("phrase_thresholds", {})
            for category, threshold in thresholds.items():
                score = phrase_scores.get(category, 0)
                if score >= int(threshold):
                    return Decision(
                        False,
                        "phrase",
                        category=category,
                        policy=name,
                        phrase_scores=phrase_scores,
                        phrase_hits=[hit for hit in phrase_hits if hit.category == category][:10],
                        details={"score": score, "threshold": int(threshold)},
                    )
            total_threshold = policy.get("phrase_total_threshold")
            if total_threshold is not None:
                total = sum(max(0, score) for score in phrase_scores.values())
                if total >= int(total_threshold):
                    return Decision(
                        False,
                        "phrase",
                        category="total",
                        policy=name,
                        phrase_scores=phrase_scores,
                        phrase_hits=phrase_hits[:10],
                        details={"score": total, "threshold": int(total_threshold)},
                    )
        return None

    @staticmethod
    def _list_union(policies: list[tuple[str, dict[str, Any]]], key: str) -> list[str]:
        items: list[str] = []
        for _, policy in policies:
            for value in policy.get(key, []):
                if value not in items:
                    items.append(value)
        return items

    @staticmethod
    def _min_int(policies: list[tuple[str, dict[str, Any]]], key: str, default: int) -> int:
        values = []
        for _, policy in policies:
            if key in policy:
                values.append(int(policy[key]))
        return min(values) if values else default

    @staticmethod
    def _first_value(policies: list[tuple[str, dict[str, Any]]], key: str, default: str) -> str:
        for _, policy in policies:
            if key in policy:
                return str(policy[key])
        return default


class ConfigStore:
    def __init__(self, config_dir: pathlib.Path) -> None:
        self.config_dir = config_dir
        self.lock = threading.RLock()
        self.config: dict[str, Any] = {}
        self.users: dict[str, Any] = {}
        self.dlp: dict[str, Any] = {}
        self.phrase_engine: PhraseEngine | None = None
        self.dlp_engine: DLPEngine | None = None
        self.policy_engine: PolicyEngine | None = None
        self.identity_resolver: IdentityResolver | None = None
        self.clamav: ClamAVClient | None = None
        self.version = ""
        self.ensure_defaults()
        self.reload()

    @property
    def config_path(self) -> pathlib.Path:
        return self.config_dir / "config.json"

    @property
    def users_path(self) -> pathlib.Path:
        return self.config_dir / "users.json"

    @property
    def dlp_path(self) -> pathlib.Path:
        return self.config_dir / "dlp_rules.json"

    @property
    def phrase_root(self) -> pathlib.Path:
        return self.config_dir / "phrases"

    def ensure_defaults(self) -> None:
        """
        Zorg dat config/users/dlp bestaan en dat elke categorie een MAP
        heeft onder ``config/phrases/``. We maken bewust GEEN actieve
        phraselists meer aan. De mappen worden behouden zodat de beheerder
        later zelf eigen phrase lists kan droppen in de juiste folder.

        Bestaande default-bestanden (english.weightedphraselist /
        dutch.weightedphraselist met onze auto-generated seeds) worden bij
        upgrade veilig hernoemd naar ``.disabled`` zodat ze niet meer geladen
        worden door de PhraseEngine, maar de data blijft op disk als backup.
        """
        self.config_dir.mkdir(parents=True, exist_ok=True)
        self.phrase_root.mkdir(parents=True, exist_ok=True)
        if not self.config_path.exists():
            config = default_config()
            config["server"]["dashboard_token"] = secrets.token_urlsafe(24)
            atomic_text_write(self.config_path, safe_json(config) + "\n")
        if not self.users_path.exists():
            atomic_text_write(self.users_path, safe_json(default_users()) + "\n")
        if not self.dlp_path.exists():
            atomic_text_write(self.dlp_path, safe_json(default_dlp_rules()) + "\n")
        for entry in E2G_CATEGORY_CATALOG:
            key = entry["key"]
            category_dir = self.phrase_root / key
            category_dir.mkdir(parents=True, exist_ok=True)
            for name in ("english.weightedphraselist", "dutch.weightedphraselist"):
                target = category_dir / name
                if target.exists():
                    self._maybe_disable_legacy_default(target)

    def _maybe_disable_legacy_default(self, path: pathlib.Path) -> None:
        """
        Hernoem oude auto-generated weighted phrase lists naar .disabled.

        We herkennen ze aan de typische marker-zinnen die door eerdere
        versies werden geschreven. Eigen lijsten van de gebruiker worden
        NOOIT aangeraakt. We doen dit hoogstens 1 keer per file.
        """
        try:
            head = path.read_text(encoding="utf-8", errors="replace").splitlines()[:6]
        except OSError:
            return
        snippet = "\n".join(head).lower()
        markers = (
            "auto-generated default",
            "auto-generated default english",
            "auto-generated default dutch",
        )
        if not any(marker in snippet for marker in markers):
            return  # geen legacy file, niets doen
        disabled = path.with_suffix(path.suffix + ".disabled")
        try:
            if disabled.exists():
                disabled = path.with_name(path.name + "." + _dt.datetime.now().strftime("%Y%m%d-%H%M%S") + ".disabled")
            os.replace(path, disabled)
            logging.info("Disabled legacy phrase file: %s -> %s", path, disabled.name)
        except OSError as exc:
            logging.warning("Could not disable legacy phrase file %s: %s", path, exc)

    def reload(self) -> None:
        with self.lock:
            user_config = json.loads(read_text(self.config_path))
            self.config = deep_merge(default_config(), user_config)
            self.users = json.loads(read_text(self.users_path))
            self.dlp = json.loads(read_text(self.dlp_path))
            self.phrase_engine = PhraseEngine(self.phrase_root, self.config.get("phrase_lists", {}))
            self.dlp_engine = DLPEngine(self.dlp)
            self.clamav = ClamAVClient(self.config.get("clamav", {}))
            self.identity_resolver = IdentityResolver(self.config.get("identity", {}), self.users)
            self.policy_engine = PolicyEngine(self.config, self.phrase_engine, self.dlp_engine, self.clamav)
            self.version = self._calculate_version()

    def _calculate_version(self) -> str:
        digest = hashlib.sha256()
        for path in sorted(self.config_dir.rglob("*")):
            if path.is_file():
                digest.update(str(path.relative_to(self.config_dir)).encode())
                digest.update(path.read_bytes())
        return digest.hexdigest()[:16]

    def istag(self) -> str:
        return f'"{APP_NAME}-{self.version}"'

    def list_files(self) -> list[dict[str, Any]]:
        files = []
        for path in sorted(self.config_dir.rglob("*")):
            if not path.is_file():
                continue
            rel = path.relative_to(self.config_dir).as_posix()
            if not self.is_editable(rel):
                continue
            files.append(
                {
                    "path": rel,
                    "size": path.stat().st_size,
                    "mtime": _dt.datetime.fromtimestamp(path.stat().st_mtime).isoformat(timespec="seconds"),
                }
            )
        return files

    def is_editable(self, rel: str) -> bool:
        suffixes = {
            ".json",
            ".txt",
            ".conf",
            ".phraselist",
            ".weightedphraselist",
            ".list",
        }
        try:
            path = self.resolve_file(rel)
        except ValueError:
            return False
        return path.is_file() and path.suffix.lower() in suffixes

    def resolve_file(self, rel: str) -> pathlib.Path:
        rel = urllib.parse.unquote(rel).replace("\\", "/").lstrip("/")
        path = (self.config_dir / rel).resolve()
        root = self.config_dir.resolve()
        if root != path and root not in path.parents:
            raise ValueError("path outside config dir")
        return path

    def read_file(self, rel: str) -> str:
        path = self.resolve_file(rel)
        if not self.is_editable(rel):
            raise ValueError("file is not editable")
        return read_text(path)

    def save_file(self, rel: str, content: str) -> None:
        path = self.resolve_file(rel)
        root = self.config_dir.resolve()
        if root != path and root not in path.parents:
            raise ValueError("path outside config dir")
        if path.suffix.lower() == ".json":
            json.loads(content)
        if path.exists():
            backup_dir = self.config_dir / ".backups"
            backup_dir.mkdir(exist_ok=True)
            stamp = _dt.datetime.now().strftime("%Y%m%d-%H%M%S")
            backup_name = f"{path.name}.{stamp}.bak"
            shutil.copy2(path, backup_dir / backup_name)
        atomic_text_write(path, content)
        self.reload()

    def _save_json_path(self, path: pathlib.Path, data: dict[str, Any]) -> None:
        with self.lock:
            if path.exists():
                backup_dir = self.config_dir / ".backups"
                backup_dir.mkdir(exist_ok=True)
                stamp = _dt.datetime.now().strftime("%Y%m%d-%H%M%S")
                shutil.copy2(path, backup_dir / f"{path.name}.{stamp}.bak")
            atomic_text_write(path, safe_json(data) + "\n")
            self.reload()

    def save_config_data(self, data: dict[str, Any]) -> None:
        self._save_json_path(self.config_path, data)

    def save_users_data(self, data: dict[str, Any]) -> None:
        self._save_json_path(self.users_path, data)

    def save_dlp_data(self, data: dict[str, Any]) -> None:
        self._save_json_path(self.dlp_path, data)

    def ensure_phrase_category(self, category: str) -> pathlib.Path:
        key = slugify_key(category)
        entry = catalog_entry(key)
        path = self.phrase_root / key / "dashboard.weightedphraselist"
        if not path.exists():
            content = (
                f"#listcategory: \"{key}\"\n"
                f"# {entry['en']} / {entry['nl']}\n"
                "# Voeg weighted phrases toe, bijvoorbeeld:\n"
                "# {50}<voorbeeld zin>\n"
                "# {-30}<veilige context>\n"
            )
            atomic_text_write(path, content)
            self.reload()
        return path

    def phrase_category_counts(self) -> dict[str, int]:
        counts: collections.Counter[str] = collections.Counter()
        if self.phrase_engine:
            for rule in self.phrase_engine.rules:
                counts[rule.category] += 1
        return dict(counts)

    def status(self) -> dict[str, Any]:
        with self.lock:
            return {
                "app": APP_NAME,
                "version": APP_VERSION,
                "config_version": self.version,
                "icap": {
                    "host": self.config.get("server", {}).get("icap_host"),
                    "port": self.config.get("server", {}).get("icap_port"),
                },
                "dashboard": {
                    "host": self.config.get("server", {}).get("dashboard_host"),
                    "port": self.config.get("server", {}).get("dashboard_port"),
                },
                "clamav": self.config.get("clamav", {}),
                "phrase_rules": len(self.phrase_engine.rules if self.phrase_engine else []),
                "phrase_categories": sorted(self.phrase_category_counts()),
                "phrase_errors": self.phrase_engine.load_errors if self.phrase_engine else [],
                "dlp_rules": len(self.dlp.get("rules", [])),
                "dlp_errors": self.dlp_engine.errors if self.dlp_engine else [],
                "editable_files": self.list_files(),
            }


class ICAPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(
        self,
        server_address: tuple[str, int],
        store: ConfigStore,
        events: EventLogger,
    ) -> None:
        self.store = store
        self.events = events
        super().__init__(server_address, ICAPHandler)


class ICAPHandler(socketserver.StreamRequestHandler):
    server: ICAPServer

    def handle(self) -> None:
        while True:
            try:
                message = self._read_message()
                if message is None:
                    return
                close_after = header_get(message.headers, "connection").lower() == "close"
                self._dispatch(message)
                if close_after:
                    return
            except (BrokenPipeError, ConnectionAbortedError, ConnectionResetError):
                return
            except Exception as exc:  # noqa: BLE001
                if isinstance(exc, OSError) and getattr(exc, "winerror", None) in {10053, 10054}:
                    return
                logging.exception("ICAP handler error: %s", exc)
                try:
                    self._send_icap_error(500, "ICAP processing error")
                except Exception:  # noqa: BLE001
                    return
                return

    def _read_message(self) -> ICAPMessage | None:
        raw_line = self.rfile.readline(MAX_HEADER_LINE)
        if not raw_line:
            return None
        while raw_line in (b"\r\n", b"\n"):
            raw_line = self.rfile.readline(MAX_HEADER_LINE)
            if not raw_line:
                return None
        line = raw_line.decode("iso-8859-1", errors="replace").strip()
        parts = line.split()
        if len(parts) != 3:
            raise ValueError(f"bad ICAP request line: {line!r}")
        method, uri, version = parts
        headers = parse_icap_headers(self.rfile)
        message = ICAPMessage(method=method.upper(), uri=uri, version=version, headers=headers)
        if message.method == "OPTIONS":
            return message
        enc = parse_encapsulated(header_get(headers, "encapsulated"))
        preview = header_get(headers, "preview")
        message.preview_used = bool(preview)
        sections = sorted(enc.items(), key=lambda item: item[1])
        header_sections = [name for name in ("req-hdr", "res-hdr") if name in enc]
        for name in header_sections:
            offset = enc[name]
            next_offsets = [value for sec_name, value in sections if value > offset]
            length = min(next_offsets) - offset if next_offsets else 0
            raw = self.rfile.read(length) if length > 0 else b""
            section = HttpSection(raw_header=raw)
            section.start_line, section.headers, section.ordered_headers = parse_http_headers(raw)
            if name == "req-hdr":
                message.req = section
            else:
                message.res = section
        body_key = ""
        for candidate in ("req-body", "res-body", "opt-body"):
            if candidate in enc:
                body_key = candidate
                break
        if body_key:
            max_store = int(self.server.store.config.get("server", {}).get("max_body_bytes", DEFAULT_BODY_LIMIT)) + 1
            body, truncated = self._read_body_chunks(max_store, message.preview_used)
            message.body = body
            message.body_truncated = truncated
        return message

    def _read_body_chunks(self, max_store: int, preview: bool) -> tuple[bytes, bool]:
        body = bytearray()
        truncated = False
        ieof, part_truncated = self._read_chunk_sequence(body, max_store)
        truncated = truncated or part_truncated
        if preview and not ieof:
            self.wfile.write(b"ICAP/1.0 100 Continue\r\n\r\n")
            self.wfile.flush()
            _, part_truncated = self._read_chunk_sequence(body, max_store)
            truncated = truncated or part_truncated
        return bytes(body), truncated

    def _read_chunk_sequence(self, body: bytearray, max_store: int) -> tuple[bool, bool]:
        truncated = False
        ieof = False
        while True:
            line = self.rfile.readline(MAX_HEADER_LINE)
            if not line:
                raise ValueError("unexpected EOF while reading ICAP chunk")
            header = line.decode("iso-8859-1", errors="replace").strip()
            if not header:
                continue
            size_part, *extensions = header.split(";")
            try:
                size = int(size_part, 16)
            except ValueError as exc:
                raise ValueError(f"invalid ICAP chunk size: {header!r}") from exc
            if any(ext.strip().lower() == "ieof" for ext in extensions):
                ieof = True
            if size == 0:
                self._read_chunk_trailers()
                return ieof, truncated
            chunk = self.rfile.read(size)
            crlf = self.rfile.read(2)
            if len(chunk) != size or crlf not in (b"\r\n", b"\n"):
                raise ValueError("malformed ICAP chunk")
            remaining = max_store - len(body)
            if remaining > 0:
                body.extend(chunk[:remaining])
            if len(chunk) > remaining:
                truncated = True

    def _read_chunk_trailers(self) -> None:
        while True:
            line = self.rfile.readline(MAX_HEADER_LINE)
            if not line or line in (b"\r\n", b"\n"):
                return

    def _dispatch(self, message: ICAPMessage) -> None:
        if message.method == "OPTIONS":
            self._send_options()
            return
        if message.method not in {"REQMOD", "RESPMOD"}:
            self._send_icap_error(405, "Method not allowed")
            return
        context = self._build_context(message)
        store = self.server.store
        assert store.policy_engine is not None
        decision = store.policy_engine.evaluate(context, message.body)
        self._log_decision(message, context, decision)
        if decision.allowed:
            if "204" in header_get(message.headers, "allow"):
                self._send_no_adaptation()
            else:
                self._send_original(message)
            return
        self._send_block_page(context, decision)

    def _build_context(self, message: ICAPMessage) -> ScanContext:
        if message.method == "REQMOD":
            url, domain = parse_url_from_request(message.req.start_line, message.req.headers)
            http_headers = message.req.headers
            content_type = header_get(message.req.headers, "content-type")
            request_start = message.req.start_line
            response_start = ""
        else:
            url, domain = parse_url_from_request(message.req.start_line, message.req.headers)
            http_headers = dict(message.req.headers)
            http_headers.update(message.res.headers)
            content_type = header_get(message.res.headers, "content-type")
            request_start = message.req.start_line
            response_start = message.res.start_line
        http_method = message.req.start_line.split(" ", 1)[0].upper() if message.req.start_line else ""
        resolver = self.server.store.identity_resolver
        assert resolver is not None
        identity = resolver.resolve(message.headers, http_headers)
        return ScanContext(
            direction=message.method.lower(),
            url=url,
            domain=domain,
            method=http_method,
            content_type=content_type,
            identity=identity,
            icap_headers=message.headers,
            http_headers=http_headers,
            request_start=request_start,
            response_start=response_start,
        )

    def _send_options(self) -> None:
        store = self.server.store
        config = store.config.get("server", {})
        preview = int(config.get("preview_bytes", 4096))
        headers = [
            "ICAP/1.0 200 OK",
            f"Date: {self._date_header()}",
            f"Server: {APP_NAME}/{APP_VERSION}",
            f"ISTag: {store.istag()}",
            "Methods: REQMOD, RESPMOD",
            "Service: School ICAP Guard",
            "Allow: 204",
            f"Preview: {preview}",
            "Transfer-Preview: *",
            "Options-TTL: 60",
            "Max-Connections: 100",
            "Encapsulated: null-body=0",
            "",
            "",
        ]
        self.wfile.write("\r\n".join(headers).encode("iso-8859-1"))
        self.wfile.flush()

    def _send_no_adaptation(self) -> None:
        headers = [
            "ICAP/1.0 204 No Content",
            f"Date: {self._date_header()}",
            f"Server: {APP_NAME}/{APP_VERSION}",
            f"ISTag: {self.server.store.istag()}",
            "Encapsulated: null-body=0",
            "",
            "",
        ]
        self.wfile.write("\r\n".join(headers).encode("iso-8859-1"))
        self.wfile.flush()

    def _send_original(self, message: ICAPMessage) -> None:
        if message.method == "REQMOD":
            req = message.req.raw_header
            if message.body:
                encapsulated = f"req-hdr=0, req-body={len(req)}"
            else:
                encapsulated = f"req-hdr=0, null-body={len(req)}"
            headers = self._icap_200_headers(encapsulated)
            self.wfile.write(headers + req)
            if message.body:
                self._write_chunk(message.body)
                self._write_chunk(b"")
        else:
            res = message.res.raw_header
            if message.body:
                encapsulated = f"res-hdr=0, res-body={len(res)}"
            else:
                encapsulated = f"res-hdr=0, null-body={len(res)}"
            headers = self._icap_200_headers(encapsulated)
            self.wfile.write(headers + res)
            if message.body:
                self._write_chunk(message.body)
                self._write_chunk(b"")
        self.wfile.flush()

    def _send_block_page(self, context: ScanContext, decision: Decision) -> None:
        body = render_block_page(context, decision)
        try:
            reason = HTTPStatus(decision.status_code).phrase
        except ValueError:
            reason = "Blocked"
        response_headers = [
            f"HTTP/1.1 {decision.status_code} {reason}",
            "Content-Type: text/html; charset=utf-8",
            f"Content-Length: {len(body)}",
            "Cache-Control: no-store",
            "Pragma: no-cache",
            "Connection: close",
            f"X-ICAP-Incident: {decision.incident_id}",
            "",
            "",
        ]
        http_header = "\r\n".join(response_headers).encode("utf-8")
        encapsulated = f"res-hdr=0, res-body={len(http_header)}"
        self.wfile.write(self._icap_200_headers(encapsulated))
        self.wfile.write(http_header)
        self._write_chunk(body)
        self._write_chunk(b"")
        self.wfile.flush()

    def _icap_200_headers(self, encapsulated: str) -> bytes:
        headers = [
            "ICAP/1.0 200 OK",
            f"Date: {self._date_header()}",
            f"Server: {APP_NAME}/{APP_VERSION}",
            f"ISTag: {self.server.store.istag()}",
            f"Encapsulated: {encapsulated}",
            "",
            "",
        ]
        return "\r\n".join(headers).encode("iso-8859-1")

    def _send_icap_error(self, code: int, message: str) -> None:
        headers = [
            f"ICAP/1.0 {code} {message}",
            f"Date: {self._date_header()}",
            f"Server: {APP_NAME}/{APP_VERSION}",
            "Connection: close",
            "Encapsulated: null-body=0",
            "",
            "",
        ]
        self.wfile.write("\r\n".join(headers).encode("iso-8859-1"))
        self.wfile.flush()

    def _write_chunk(self, data: bytes) -> None:
        self.wfile.write(f"{len(data):X}\r\n".encode("ascii"))
        if data:
            self.wfile.write(data)
        self.wfile.write(b"\r\n")

    @staticmethod
    def _date_header() -> str:
        return _dt.datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S GMT")

    def _log_decision(self, message: ICAPMessage, context: ScanContext, decision: Decision) -> None:
        event = {
            "incident_id": decision.incident_id,
            "action": "allow" if decision.allowed else "block",
            "reason": decision.reason,
            "public_reason": decision.public_reason(),
            "policy": decision.policy,
            "method": message.method,
            "url": context.url,
            "domain": context.domain,
            "user": context.identity.user,
            "source_ip": context.identity.source_ip,
            "groups": context.identity.groups,
            "identity_source": context.identity.source,
            "content_type": context.content_type,
            "body_bytes": len(message.body),
            "body_truncated": message.body_truncated,
            "clam": dataclasses.asdict(decision.clam),
            "phrase_scores": decision.phrase_scores,
            "phrase_hits": [dataclasses.asdict(hit) for hit in decision.phrase_hits[:5]],
            "dlp_hits": [dataclasses.asdict(hit) for hit in decision.dlp_hits[:5]],
            "details": decision.details,
        }
        self.server.events.emit(event)


def block_reason_meta(decision: Decision) -> dict[str, str]:
    if decision.reason == "malware":
        return {
            "label": "ClamAV Antivirus",
            "tone": "danger",
            "title": "Malware geblokkeerd",
            "summary": "ClamAV heeft een schadelijk bestand of verdachte payload gevonden.",
        }
    if decision.reason == "dlp":
        return {
            "label": "Data Loss Prevention",
            "tone": "warning",
            "title": "Gevoelige data geblokkeerd",
            "summary": "Een DLP-regel werd geactiveerd om datalekken te voorkomen.",
        }
    if decision.reason in {"phrase", "domain", "mime", "oversize"}:
        return {
            "label": "Web Filter",
            "tone": "filter",
            "title": "Webcontent geblokkeerd",
            "summary": "De website, categorie, phrase score of bestandstype valt onder een webfilterpolicy.",
        }
    return {
        "label": "Policy",
        "tone": "neutral",
        "title": "Verkeer geblokkeerd",
        "summary": "Deze aanvraag is door de ingestelde policy tegengehouden.",
    }


def render_block_explanation(decision: Decision) -> str:
    rows: list[str] = []
    if decision.reason == "malware":
        rows.append(("Scanner", "ClamAV Antivirus"))
        rows.append(("Detectie", decision.clam.signature or "Onbekende malware signature"))
        if decision.clam.error:
            rows.append(("Scanner fout", decision.clam.error))
    elif decision.reason == "dlp":
        rows.append(("Module", "Data Loss Prevention"))
        for hit in decision.dlp_hits[:5]:
            rows.append((hit.name, f"{hit.count} match(es), sample: {hit.sample}"))
        if decision.details:
            rows.append(("DLP score", f"{decision.details.get('score', '?')} / {decision.details.get('threshold', '?')}"))
    elif decision.reason == "phrase":
        rows.append(("Module", "Web Filter phrase scoring"))
        rows.append(("Categorie", decision.category or "onbekend"))
        if decision.details:
            rows.append(("Score", f"{decision.details.get('score', '?')} / {decision.details.get('threshold', '?')}"))
        for hit in decision.phrase_hits[:5]:
            rows.append((f"Phrase: {hit.category}", f"{hit.phrase} ({hit.weight} x {hit.count})"))
    elif decision.reason == "domain":
        rows.append(("Module", "Web Filter domeinlijst"))
        rows.append(("Geblokkeerd domein", decision.category or "onbekend"))
    elif decision.reason == "mime":
        rows.append(("Module", "Web Filter bestandstype"))
        rows.append(("Content-Type", decision.category or "onbekend"))
    elif decision.reason == "oversize":
        rows.append(("Module", "Web Filter scanlimiet"))
        if decision.details:
            rows.append(("Limiet", f"{decision.details.get('limit', '?')} bytes"))
    else:
        rows.append(("Policy reden", decision.public_reason()))
    if not rows:
        return ""
    items = "\n".join(
        f"        <dt>{html_lib.escape(str(label))}</dt><dd>{html_lib.escape(str(value))}</dd>"
        for label, value in rows
    )
    return f"""      <section class="details">
        <h2>Waarom?</h2>
        <dl>
{items}
        </dl>
      </section>"""


def render_block_page(context: ScanContext, decision: Decision) -> bytes:
    meta = block_reason_meta(decision)
    title = html_lib.escape(meta["title"])
    reason = html_lib.escape(decision.public_reason())
    summary = html_lib.escape(meta["summary"])
    label = html_lib.escape(meta["label"])
    tone = html_lib.escape(meta["tone"])
    user = html_lib.escape(context.identity.user)
    groups = html_lib.escape(", ".join(context.identity.groups))
    domain = html_lib.escape(context.domain or context.url)
    incident = html_lib.escape(decision.incident_id)
    policy = html_lib.escape(decision.policy)
    url = html_lib.escape(context.url)
    explanation = render_block_explanation(decision)
    body = f"""<!doctype html>
<html lang="nl">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{title}</title>
  <style>
    :root {{
      color-scheme: light dark;
      font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      background: #eef2f5;
      color: #17202a;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      min-height: 100vh;
      display: grid;
      place-items: center;
      padding: 28px 16px;
      background: #eef2f5;
      color: #17202a;
    }}
    main {{
      width: min(860px, 100%);
      background: #ffffff;
      border: 1px solid #d5dde6;
      border-radius: 8px;
      overflow: hidden;
      box-shadow: 0 24px 70px rgba(15, 23, 42, .14);
    }}
    .topbar {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 16px;
      padding: 14px 18px;
      border-bottom: 1px solid #d5dde6;
      background: #f7fafc;
    }}
    .brand {{ font-weight: 800; color: #203040; letter-spacing: 0; }}
    .badge {{
      display: inline-flex;
      align-items: center;
      min-height: 32px;
      padding: 6px 10px;
      border-radius: 6px;
      border: 1px solid #b9c7d6;
      font-size: 14px;
      font-weight: 800;
      white-space: nowrap;
    }}
    .badge.danger {{ background: #fff0ee; border-color: #e6a39a; color: #9f1d13; }}
    .badge.warning {{ background: #fff7df; border-color: #e0bd57; color: #735300; }}
    .badge.filter {{ background: #e8f4ef; border-color: #8bc2a8; color: #11643d; }}
    .badge.neutral {{ background: #edf2f7; border-color: #c8d3df; color: #334155; }}
    .hero {{ padding: 28px; border-left: 8px solid #11643d; }}
    .hero.danger {{ border-left-color: #b42318; }}
    .hero.warning {{ border-left-color: #b7791f; }}
    .hero.filter {{ border-left-color: #168251; }}
    .hero.neutral {{ border-left-color: #52616f; }}
    h1 {{ margin: 0; font-size: 30px; line-height: 1.15; letter-spacing: 0; }}
    .summary {{ margin: 10px 0 0; color: #405065; font-size: 17px; line-height: 1.5; }}
    .reason {{
      margin: 18px 0 0;
      padding: 12px 14px;
      border: 1px solid #d5dde6;
      border-radius: 8px;
      background: #f8fafc;
      font-size: 18px;
      font-weight: 750;
    }}
    .content {{
      display: grid;
      grid-template-columns: minmax(260px, .9fr) minmax(280px, 1.1fr);
      gap: 18px;
      padding: 0 28px 26px;
    }}
    section {{ min-width: 0; }}
    h2 {{ margin: 0 0 12px; font-size: 15px; text-transform: uppercase; letter-spacing: .08em; color: #5a6878; }}
    dl {{ display: grid; grid-template-columns: 145px minmax(0, 1fr); gap: 9px 14px; margin: 0; }}
    dt {{ font-weight: 800; color: #405065; }}
    dd {{ margin: 0; word-break: break-word; color: #17202a; }}
    .url {{ color: #0f4f76; }}
    footer {{
      display: flex;
      justify-content: space-between;
      gap: 12px;
      padding: 14px 18px;
      border-top: 1px solid #d5dde6;
      color: #65758a;
      background: #f7fafc;
      font-size: 13px;
    }}
    @media (max-width: 720px) {{
      body {{ padding: 16px; }}
      .topbar, footer {{ align-items: flex-start; flex-direction: column; }}
      .hero {{ padding: 22px; }}
      .content {{ grid-template-columns: 1fr; padding: 0 22px 22px; }}
      dl {{ grid-template-columns: 1fr; gap: 4px; }}
      h1 {{ font-size: 25px; }}
    }}
    @media (prefers-color-scheme: dark) {{
      :root, body {{ background: #10141b; color: #eef3f8; }}
      main {{ background: #18212b; border-color: #344051; }}
      .topbar, footer {{ background: #202a36; border-color: #344051; }}
      .brand, dd {{ color: #eef3f8; }}
      .summary, dt, h2, footer {{ color: #a9b6c7; }}
      .reason {{ background: #111923; border-color: #344051; }}
      .url {{ color: #9bd7ff; }}
      .badge.danger {{ background: #3a1715; border-color: #7f2a23; color: #ffb4aa; }}
      .badge.warning {{ background: #33270c; border-color: #745b16; color: #ffe08a; }}
      .badge.filter {{ background: #102b22; border-color: #2f7756; color: #9de5bf; }}
      .badge.neutral {{ background: #253140; border-color: #52616f; color: #d8e2ec; }}
    }}
  </style>
</head>
<body>
  <main>
    <div class="topbar">
      <div class="brand">School ICAP Guard</div>
      <div class="badge {tone}">Type blokkering: {label}</div>
    </div>
    <section class="hero {tone}">
      <h1>{title}</h1>
      <p class="summary">{summary}</p>
      <p class="reason">{reason}</p>
    </section>
    <div class="content">
      <section>
        <h2>Incident</h2>
        <dl>
          <dt>Incident ID</dt><dd>{incident}</dd>
          <dt>Domein</dt><dd>{domain}</dd>
          <dt>URL</dt><dd class="url">{url}</dd>
          <dt>Gebruiker</dt><dd>{user}</dd>
          <dt>Groepen</dt><dd>{groups}</dd>
          <dt>Policy</dt><dd>{policy}</dd>
        </dl>
      </section>
{explanation}
    </div>
    <footer>
      <span>Auteursrechten &copy; 2026 Youness Banali El Khattabi</span>
      <span>Neem contact op met IT en vermeld het Incident ID.</span>
    </footer>
  </main>
</body>
</html>"""
    return body.encode("utf-8")


class DashboardServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(
        self,
        server_address: tuple[str, int],
        store: ConfigStore,
        events: EventLogger,
    ) -> None:
        self.store = store
        self.events = events
        super().__init__(server_address, DashboardHandler)


def policy_target(config: dict[str, Any], target: str) -> tuple[str, dict[str, Any]]:
    target = slugify_key(target or "all")
    if target in {"all", "common", "alle"}:
        config.setdefault("common_policy", {})
        return "all", config["common_policy"]
    policies = config.setdefault("policies", {})
    if target not in policies:
        raise ValueError(f"onbekende groep: {target}")
    return target, policies[target]


def split_groups(value: Any) -> list[str]:
    if isinstance(value, list):
        raw = value
    else:
        raw = str(value or "").replace(";", ",").split(",")
    return sorted({slugify_key(str(item)) for item in raw if str(item).strip()})


def clean_domain_pattern(value: str) -> str:
    value = value.strip().lower()
    if "://" in value:
        parsed = urllib.parse.urlsplit(value)
        value = parsed.netloc or parsed.path
    value = value.split("/", 1)[0].strip()
    value = value.rstrip(".")
    if not value:
        raise ValueError("domein is leeg")
    if not re.match(r"^\*?\.?[a-z0-9][a-z0-9.*_-]*(?::\d+)?$", value):
        raise ValueError("ongeldig domein of wildcard patroon")
    return value


def editable_config(store: ConfigStore) -> dict[str, Any]:
    return deep_merge(default_config(), json.loads(read_text(store.config_path)))


def editable_users(store: ConfigStore) -> dict[str, Any]:
    return json.loads(read_text(store.users_path))


def editable_dlp(store: ConfigStore) -> dict[str, Any]:
    return json.loads(read_text(store.dlp_path))


def dashboard_policy_snapshot(store: ConfigStore, events: EventLogger) -> dict[str, Any]:
    config = store.config
    users = store.users
    counts = store.phrase_category_counts()
    policy_keys = set(config.get("common_policy", {}).get("phrase_thresholds", {}).keys())
    for policy in config.get("policies", {}).values():
        policy_keys.update(policy.get("phrase_thresholds", {}).keys())
    category_keys = {entry["key"] for entry in E2G_CATEGORY_CATALOG} | set(counts) | policy_keys
    categories = []
    phrase_dirs = {path.name for path in store.phrase_root.iterdir() if path.is_dir()} if store.phrase_root.exists() else set()
    groups = sorted(config.get("policies", {}).keys())
    for key in sorted(category_keys):
        entry = catalog_entry(key)
        thresholds = {"all": config.get("common_policy", {}).get("phrase_thresholds", {}).get(key)}
        for group in groups:
            thresholds[group] = config.get("policies", {}).get(group, {}).get("phrase_thresholds", {}).get(key)
        categories.append(
            {
                **entry,
                "thresholds": thresholds,
                "phrase_file": key in phrase_dirs,
                "phrase_rules": counts.get(key, 0),
            }
        )

    domain_rows = []
    for list_name in ("blocked_domains", "hard_blocked_domains", "allowed_domains"):
        for domain in config.get("common_policy", {}).get(list_name, []):
            domain_rows.append({"target": "all", "label": "Alle groepen", "list": list_name, "domain": domain})
    for group in groups:
        policy = config.get("policies", {}).get(group, {})
        for list_name in ("blocked_domains", "allowed_domains"):
            for domain in policy.get(list_name, []):
                domain_rows.append({"target": group, "label": group, "list": list_name, "domain": domain})

    event_snapshot = events.snapshot()
    public_dlp = {"rules": []}
    for rule in store.dlp.get("rules", []):
        public_dlp["rules"].append({key: value for key, value in rule.items() if not key.startswith("_")})
    return {
        "status": store.status(),
        "summary": {
            "groups": len(groups),
            "users": len(users.get("users", {})),
            "netbird_ips": len(users.get("ip_map", {})),
            "categories": len(categories),
            "active_category_blocks": sum(
                1
                for item in categories
                for value in item["thresholds"].values()
                if value is not None
            ),
            "blocked_domains": sum(1 for row in domain_rows if row["list"] in {"blocked_domains", "hard_blocked_domains"}),
            "dlp_rules": len(store.dlp.get("rules", [])),
            "events": event_snapshot.get("stats", {}).get("total", 0),
        },
        "groups": groups,
        "policies": {
            "all": config.get("common_policy", {}),
            **config.get("policies", {}),
        },
        "categories": categories,
        "domains": domain_rows,
        "users": users.get("users", {}),
        "ip_map": users.get("ip_map", {}),
        "entra_group_map": config.get("identity", {}).get("entra_group_map", {}),
        "dlp": public_dlp,
        "events": event_snapshot,
        "editable_files": store.list_files(),
    }


def dashboard_update_category(store: ConfigStore, data: dict[str, Any]) -> dict[str, Any]:
    config = editable_config(store)
    category = slugify_key(str(data.get("category", "")))
    target, policy = policy_target(config, str(data.get("target", "all")))
    thresholds = policy.setdefault("phrase_thresholds", {})
    enabled = parse_bool(str(data.get("enabled", "true")), True)
    if enabled:
        entry = catalog_entry(category)
        threshold = int(data.get("threshold") or entry.get("default_threshold", 80))
        thresholds[category] = threshold
        if parse_bool(str(data.get("create_phrase_file", "true")), True):
            store.ensure_phrase_category(category)
    else:
        thresholds.pop(category, None)
    store.save_config_data(config)
    return {"ok": True, "target": target, "category": category, "enabled": enabled}


def dashboard_update_domain(store: ConfigStore, data: dict[str, Any]) -> dict[str, Any]:
    config = editable_config(store)
    domain = clean_domain_pattern(str(data.get("domain", "")))
    target, policy = policy_target(config, str(data.get("target", "all")))
    list_name = str(data.get("list", "blocked_domains"))
    if list_name not in {"blocked_domains", "hard_blocked_domains", "allowed_domains"}:
        raise ValueError("ongeldige domeinlijst")
    if target != "all" and list_name == "hard_blocked_domains":
        list_name = "blocked_domains"
    domains = policy.setdefault(list_name, [])
    action = str(data.get("action", "add")).lower()
    if action == "remove":
        policy[list_name] = [item for item in domains if item != domain]
    else:
        if domain not in domains:
            domains.append(domain)
            domains.sort()
    store.save_config_data(config)
    return {"ok": True, "target": target, "list": list_name, "domain": domain, "action": action}


def dashboard_update_group(store: ConfigStore, data: dict[str, Any]) -> dict[str, Any]:
    config = editable_config(store)
    group = slugify_key(str(data.get("group", "")))
    policies = config.setdefault("policies", {})
    action = str(data.get("action", "add")).lower()
    if action == "delete":
        # Geen vaste basisgroepen meer; alle groepen mogen verwijderd
        # worden. NetBird sync zal ze opnieuw aanmaken als de groep
        # nog bestaat in NetBird.
        policies.pop(group, None)
    else:
        template = slugify_key(str(data.get("copy_from", "")) or "common")
        if template == "common":
            base = config.get("common_policy", {})
        else:
            base = policies.get(template) or config.get("common_policy", {}) or {}
        policies.setdefault(group, json.loads(json.dumps(base)))
    store.save_config_data(config)
    return {"ok": True, "group": group, "action": action}


def dashboard_update_user(store: ConfigStore, data: dict[str, Any]) -> dict[str, Any]:
    users = editable_users(store)
    users.setdefault("users", {})
    users.setdefault("ip_map", {})
    action = str(data.get("action", "save")).lower()
    username = str(data.get("user", "")).strip().lower()
    ip_value = str(data.get("ip", "")).strip()
    groups = split_groups(data.get("groups", ""))
    if action == "delete":
        if username:
            users["users"].pop(username, None)
        if ip_value:
            users["ip_map"].pop(parse_ip(ip_value), None)
    else:
        if not username:
            raise ValueError("gebruiker is verplicht")
        user_obj = users["users"].setdefault(username, {})
        user_obj["groups"] = groups
        entra_object_id = str(data.get("entra_object_id", "")).strip()
        entra_groups = [item.strip().lower() for item in str(data.get("entra_groups", "")).replace(";", ",").split(",") if item.strip()]
        if entra_object_id:
            user_obj["entra_object_id"] = entra_object_id
        if entra_groups:
            user_obj["entra_groups"] = entra_groups
        if ip_value:
            users["ip_map"][parse_ip(ip_value)] = {"user": username, "groups": groups}
    store.save_users_data(users)
    return {"ok": True, "user": username, "ip": ip_value, "action": action}


def dashboard_update_dlp(store: ConfigStore, data: dict[str, Any]) -> dict[str, Any]:
    dlp = editable_dlp(store)
    index = int(data.get("index", -1))
    rules = dlp.setdefault("rules", [])
    if index < 0 or index >= len(rules):
        raise ValueError("ongeldige DLP regel")
    action = str(data.get("action", "toggle")).lower()
    if action == "delete":
        rules.pop(index)
    else:
        rules[index]["enabled"] = parse_bool(str(data.get("enabled", "true")), True)
    store.save_dlp_data(dlp)
    return {"ok": True, "index": index, "action": action}


# Toegelaten master-toggles voor /api/settings.
KNOWN_SETTINGS: tuple[str, ...] = (
    "webfilter_enabled",
    "domain_blocking_enabled",
    "weighted_phrases_enabled",
    "dlp_enabled",
    "antivirus_enabled",
    "logging_enabled",
    "netbird_sync_enabled",
)


def dashboard_get_settings(store: ConfigStore) -> dict[str, Any]:
    settings = dict(store.config.get("settings", {}) or {})
    clamav = dict(store.config.get("clamav", {}) or {})
    common = dict(store.config.get("common_policy", {}) or {})
    return {
        "settings": {key: bool(settings.get(key, True)) for key in KNOWN_SETTINGS},
        "clamav_fail_open": bool(clamav.get("fail_open", False)),
        "allow_domains_bypass_content": bool(common.get("allow_domains_bypass_content", True)),
    }


def dashboard_update_settings(store: ConfigStore, data: dict[str, Any]) -> dict[str, Any]:
    config = editable_config(store)
    settings = config.setdefault("settings", {})
    for key in KNOWN_SETTINGS:
        if key in data:
            settings[key] = parse_bool(str(data[key]), True)
    if "clamav_fail_open" in data:
        config.setdefault("clamav", {})["fail_open"] = parse_bool(str(data["clamav_fail_open"]), False)
    if "allow_domains_bypass_content" in data:
        config.setdefault("common_policy", {})["allow_domains_bypass_content"] = parse_bool(
            str(data["allow_domains_bypass_content"]), True
        )
    store.save_config_data(config)
    return dashboard_get_settings(store)


def _parse_ts(value: str) -> float:
    if not value:
        return 0.0
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        return _dt.datetime.fromisoformat(text).timestamp()
    except ValueError:
        return 0.0


def filter_events(
    events: list[dict[str, Any]],
    *,
    user: str = "",
    ip: str = "",
    domain: str = "",
    category: str = "",
    action: str = "",
    status: str = "",
    incident_id: str = "",
    q: str = "",
    date_from: str = "",
    date_to: str = "",
    limit: int = 500,
) -> list[dict[str, Any]]:
    """Server-side filter helper voor de logspagina."""
    user_l = user.strip().lower()
    ip_l = ip.strip().lower()
    domain_l = domain.strip().lower()
    category_l = category.strip().lower()
    action_l = action.strip().lower()
    status_l = status.strip().lower()
    incident_l = incident_id.strip().lower()
    q_l = q.strip().lower()
    ts_from = _parse_ts(date_from) if date_from else 0.0
    ts_to = _parse_ts(date_to) if date_to else 0.0

    out: list[dict[str, Any]] = []
    for event in reversed(events):  # nieuwste eerst
        if user_l and user_l not in str(event.get("user", "")).lower():
            continue
        if ip_l and ip_l not in str(event.get("source_ip", "")).lower():
            continue
        if domain_l:
            haystack = (str(event.get("domain", "")) + " " + str(event.get("url", ""))).lower()
            if domain_l not in haystack:
                continue
        if category_l:
            cat_match = category_l in str(event.get("details", {}).get("category", "")).lower() or \
                category_l in str(event.get("reason", "")).lower()
            for hit in event.get("phrase_hits", []) or []:
                if category_l in str(hit.get("category", "")).lower():
                    cat_match = True
                    break
            if not cat_match:
                continue
        if action_l and action_l != str(event.get("action", "")).lower():
            continue
        if status_l and status_l != str(event.get("reason", "")).lower():
            continue
        if incident_l and incident_l not in str(event.get("incident_id", "")).lower():
            continue
        if q_l:
            blob = json.dumps(event, ensure_ascii=False).lower()
            if q_l not in blob:
                continue
        if ts_from or ts_to:
            ts_value = _parse_ts(str(event.get("ts", "")))
            if ts_from and ts_value < ts_from:
                continue
            if ts_to and ts_value > ts_to:
                continue
        out.append(event)
        if len(out) >= limit:
            break
    return out


def dashboard_logs_payload(store: ConfigStore, events: EventLogger, params: dict[str, list[str]]) -> dict[str, Any]:
    def first(name: str, default: str = "") -> str:
        return params.get(name, [default])[0]

    all_events = events.all_events()
    limit_raw = first("limit", "500")
    try:
        limit = max(1, min(5000, int(limit_raw)))
    except ValueError:
        limit = 500
    filtered = filter_events(
        all_events,
        user=first("user"),
        ip=first("ip"),
        domain=first("domain"),
        category=first("category"),
        action=first("action"),
        status=first("status"),
        incident_id=first("incident_id"),
        q=first("q"),
        date_from=first("from"),
        date_to=first("to"),
        limit=limit,
    )
    return {
        "events": filtered,
        "total_on_disk": len(all_events),
        "filtered_count": len(filtered),
        "log_path": str(events.path),
    }


def dashboard_event_detail(events: EventLogger, incident_id: str) -> dict[str, Any]:
    incident_id = (incident_id or "").strip().lower()
    if not incident_id:
        raise ValueError("incident_id is verplicht")
    for event in events.all_events():
        if str(event.get("incident_id", "")).lower() == incident_id:
            return event
    raise ValueError("event niet gevonden")


def dashboard_user_detail(store: ConfigStore, events: EventLogger, user_id: str) -> dict[str, Any]:
    user_id = (user_id or "").strip().lower()
    users = store.users.get("users", {})
    user_obj = users.get(user_id) or users.get(user_id.lower()) or {}
    ip_entries: list[dict[str, Any]] = []
    for ip, mapping in (store.users.get("ip_map", {}) or {}).items():
        mapped_user = mapping.get("user") if isinstance(mapping, dict) else mapping
        if str(mapped_user or "").lower() == user_id:
            ip_entries.append({"ip": ip, "groups": (mapping.get("groups") if isinstance(mapping, dict) else []) or []})

    groups = list(user_obj.get("groups", []) or [])
    if not groups:
        for entry in ip_entries:
            groups.extend(entry.get("groups", []))
    groups = sorted({g for g in groups if g})

    user_events = [event for event in events.all_events() if str(event.get("user", "")).lower() == user_id]
    user_events.sort(key=lambda e: _parse_ts(str(e.get("ts", ""))), reverse=True)
    allowed = sum(1 for e in user_events if e.get("action") == "allow")
    blocked = sum(1 for e in user_events if e.get("action") == "block")
    reason_counter: collections.Counter[str] = collections.Counter()
    domain_counter: collections.Counter[str] = collections.Counter()
    category_counter: collections.Counter[str] = collections.Counter()
    for event in user_events:
        if event.get("action") == "block":
            reason_counter[str(event.get("reason", "unknown"))] += 1
            domain_counter[str(event.get("domain", "?"))] += 1
            cat = event.get("details", {}).get("category") or event.get("reason", "")
            category_counter[str(cat or "?")] += 1

    config_policies = store.config.get("policies", {}) or {}
    matched_policies = {group: config_policies.get(group, {}) for group in groups if group in config_policies}

    return {
        "user": user_id,
        "name": user_obj.get("name", ""),
        "email": user_id if "@" in user_id else "",
        "groups": groups,
        "entra_object_id": user_obj.get("entra_object_id", ""),
        "entra_groups": user_obj.get("entra_groups", []) or [],
        "netbird_user_id": user_obj.get("netbird_user_id", ""),
        "netbird_peer_ids": user_obj.get("netbird_peer_ids", []) or [],
        "netbird_hostnames": user_obj.get("netbird_hostnames", []) or [],
        "ips": ip_entries,
        "policies": matched_policies,
        "stats": {
            "total": len(user_events),
            "allowed": allowed,
            "blocked": blocked,
            "top_block_reasons": reason_counter.most_common(10),
            "top_blocked_domains": domain_counter.most_common(10),
            "top_blocked_categories": category_counter.most_common(10),
        },
        "recent_events": user_events[:50],
    }


def dashboard_services_status(store: ConfigStore, events: EventLogger) -> dict[str, Any]:
    settings = store.config.get("settings", {}) or {}
    icap_cfg = store.config.get("server", {}) or {}
    clam_cfg = store.config.get("clamav", {}) or {}
    snapshot = events.snapshot()
    users_meta = (store.users.get("meta", {}) or {}) if isinstance(store.users, dict) else {}
    last_sync_unix = users_meta.get("synced_at_unix")
    last_sync_iso = ""
    if isinstance(last_sync_unix, (int, float)) and last_sync_unix > 0:
        last_sync_iso = _dt.datetime.fromtimestamp(last_sync_unix, tz=_dt.timezone.utc).isoformat(timespec="seconds")
    icap_status = "running"
    try:
        with socket.create_connection((str(icap_cfg.get("icap_host") or "127.0.0.1"), int(icap_cfg.get("icap_port") or 13440)), timeout=1):
            icap_status = "running"
    except OSError:
        icap_status = "unreachable"

    clam_status = "disabled"
    if settings.get("antivirus_enabled", True) and clam_cfg.get("enabled", True):
        try:
            if clam_cfg.get("unix_socket"):
                sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                sock.settimeout(1)
                sock.connect(str(clam_cfg["unix_socket"]))
                sock.sendall(b"PING\0")
                pong = sock.recv(16)
                sock.close()
                clam_status = "running" if pong.startswith(b"PONG") else "error"
            else:
                with socket.create_connection((str(clam_cfg.get("host", "127.0.0.1")), int(clam_cfg.get("port", 3310))), timeout=1) as sock:
                    sock.sendall(b"zPING\0")
                    pong = sock.recv(16)
                    clam_status = "running" if pong.startswith(b"PONG") else "error"
        except OSError:
            clam_status = "unreachable"

    return {
        "services": [
            {
                "key": "icap",
                "label": "ICAP service",
                "status": icap_status,
                "detail": f"{icap_cfg.get('icap_host')}:{icap_cfg.get('icap_port')}",
            },
            {
                "key": "webfilter",
                "label": "Web filter",
                "status": "running" if settings.get("webfilter_enabled", True) else "disabled",
                "detail": "Content filtering en domeinblokkering",
            },
            {
                "key": "domain_blocking",
                "label": "Domain blocking",
                "status": "running" if settings.get("domain_blocking_enabled", True) else "disabled",
                "detail": "Block/allowlist + UT1",
            },
            {
                "key": "phrases",
                "label": "Weighted phrases",
                "status": "running" if settings.get("weighted_phrases_enabled", False) else "disabled",
                "detail": f"{len(store.phrase_engine.rules) if store.phrase_engine else 0} actieve regels",
            },
            {
                "key": "dlp",
                "label": "DLP",
                "status": "running" if settings.get("dlp_enabled", True) else "disabled",
                "detail": f"{len(store.dlp.get('rules', []))} DLP regels",
            },
            {
                "key": "antivirus",
                "label": "Antivirus / ClamAV",
                "status": clam_status,
                "detail": clam_cfg.get("unix_socket") or f"{clam_cfg.get('host')}:{clam_cfg.get('port')}",
            },
            {
                "key": "logging",
                "label": "Logging",
                "status": "running" if settings.get("logging_enabled", True) else "disabled",
                "detail": f"{snapshot['stats'].get('total', 0)} events totaal",
            },
            {
                "key": "netbird",
                "label": "NetBird sync",
                "status": "running" if settings.get("netbird_sync_enabled", True) else "disabled",
                "detail": f"Laatste sync: {last_sync_iso or 'onbekend'}",
            },
            {
                "key": "config",
                "label": "Config",
                "status": "running",
                "detail": f"Versie {store.version}",
            },
        ],
        "last_sync_iso": last_sync_iso,
        "phrase_load_errors": list(store.phrase_engine.load_errors) if store.phrase_engine else [],
        "dlp_load_errors": list(store.dlp_engine.errors) if store.dlp_engine else [],
        "event_load_errors": snapshot.get("load_errors", []),
    }


def dashboard_charts_data(store: ConfigStore, events: EventLogger) -> dict[str, Any]:
    """Aggregeer recent events tot grafiek-data voor de homepage."""
    all_events = events.all_events()
    if not all_events:
        return {
            "totals": {"allow": 0, "block": 0},
            "hourly": [],
            "daily": [],
            "top_categories": [],
            "top_users": [],
            "top_domains": [],
        }
    now = _dt.datetime.now(_dt.timezone.utc)
    hour_buckets: dict[str, dict[str, int]] = {}
    day_buckets: dict[str, dict[str, int]] = {}
    cat_counter: collections.Counter[str] = collections.Counter()
    user_counter: collections.Counter[str] = collections.Counter()
    domain_counter: collections.Counter[str] = collections.Counter()
    allow_count = 0
    block_count = 0
    for event in all_events:
        ts = _parse_ts(str(event.get("ts", "")))
        if not ts:
            continue
        moment = _dt.datetime.fromtimestamp(ts, tz=_dt.timezone.utc)
        action = event.get("action", "unknown")
        if action == "allow":
            allow_count += 1
        elif action == "block":
            block_count += 1
        if (now - moment).total_seconds() <= 24 * 3600:
            hkey = moment.strftime("%Y-%m-%d %H:00")
            slot = hour_buckets.setdefault(hkey, {"allow": 0, "block": 0})
            slot[action] = slot.get(action, 0) + 1
        if (now - moment).total_seconds() <= 30 * 24 * 3600:
            dkey = moment.strftime("%Y-%m-%d")
            slot = day_buckets.setdefault(dkey, {"allow": 0, "block": 0})
            slot[action] = slot.get(action, 0) + 1
        if action == "block":
            cat = str(event.get("details", {}).get("category") or event.get("reason") or "onbekend")
            cat_counter[cat] += 1
            user_counter[str(event.get("user", "anoniem"))] += 1
            domain_counter[str(event.get("domain", "?"))] += 1

    hourly = [
        {"bucket": key, "allow": value.get("allow", 0), "block": value.get("block", 0)}
        for key, value in sorted(hour_buckets.items())
    ]
    daily = [
        {"bucket": key, "allow": value.get("allow", 0), "block": value.get("block", 0)}
        for key, value in sorted(day_buckets.items())
    ]
    return {
        "totals": {"allow": allow_count, "block": block_count},
        "hourly": hourly,
        "daily": daily,
        "top_categories": cat_counter.most_common(10),
        "top_users": user_counter.most_common(10),
        "top_domains": domain_counter.most_common(10),
    }


def dashboard_home_summary(store: ConfigStore, events: EventLogger) -> dict[str, Any]:
    base = dashboard_policy_snapshot(store, events)
    settings = store.config.get("settings", {}) or {}
    services = dashboard_services_status(store, events)
    charts = dashboard_charts_data(store, events)
    snapshot = base["events"]
    base["summary"]["weighted_phrases_enabled"] = bool(settings.get("weighted_phrases_enabled", False))
    base["summary"]["phrases_rules"] = len(store.phrase_engine.rules) if store.phrase_engine else 0
    base["summary"]["weighted_phrases"] = base["summary"]["phrases_rules"] if settings.get("weighted_phrases_enabled", False) else 0
    base["summary"]["block_events"] = snapshot.get("stats", {}).get("block", 0)
    base["summary"]["allow_events"] = snapshot.get("stats", {}).get("allow", 0)
    base["summary"]["events_total"] = snapshot.get("stats", {}).get("total", 0)
    base["settings"] = {key: bool(settings.get(key, True)) for key in KNOWN_SETTINGS}
    base["services"] = services["services"]
    base["last_sync_iso"] = services["last_sync_iso"]
    base["charts"] = charts
    base["recent_events"] = snapshot.get("recent", [])[:25]
    base["recent_blocks"] = [event for event in snapshot.get("recent", []) if event.get("action") == "block"][:10]
    return base


def trigger_netbird_sync() -> dict[str, Any]:
    """
    Veilige hook om NetBird sync vanaf het dashboard te triggeren.

    We schakelen alleen door naar het systeem als er een omgevings-flag
    ``SCHOOL_ICAP_NETBIRD_SYNC_CMD`` aanwezig is. Anders rapporteren we
    501 zodat de UI weet dat de backend de actie niet uitvoert. Dit
    voorkomt dat het dashboard zonder beveiliging systemctl-commands kan
    uitvoeren.
    """
    cmd = os.environ.get("SCHOOL_ICAP_NETBIRD_SYNC_CMD", "").strip()
    if not cmd:
        return {
            "ok": False,
            "status": 501,
            "message": (
                "NetBird sync trigger is niet geconfigureerd. Zet "
                "SCHOOL_ICAP_NETBIRD_SYNC_CMD in de service-omgeving "
                "naar bv. 'systemctl start netbird-users-sync.service' "
                "om dit veilig te activeren."
            ),
        }
    import shlex
    import subprocess
    try:
        completed = subprocess.run(
            shlex.split(cmd),
            check=False,
            capture_output=True,
            text=True,
            timeout=120,
        )
        return {
            "ok": completed.returncode == 0,
            "status": 200 if completed.returncode == 0 else 500,
            "returncode": completed.returncode,
            "stdout": completed.stdout[-2000:],
            "stderr": completed.stderr[-2000:],
        }
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "status": 500, "message": str(exc)}


class DashboardHandler(BaseHTTPRequestHandler):
    server: DashboardServer

    def log_message(self, fmt: str, *args: Any) -> None:
        logging.info("dashboard %s - %s", self.address_string(), fmt % args)

    def do_GET(self) -> None:
        try:
            parsed = urllib.parse.urlsplit(self.path)
            if parsed.path == "/login":
                self._send_html(render_login())
                return
            if not self._authenticated(parsed):
                self._redirect("/login")
                return
            if parsed.path in ("/", "/home", "/users", "/policies", "/domains", "/categories",
                               "/phrases", "/dlp", "/services", "/logs", "/settings", "/test", "/files"):
                self._send_html(render_dashboard_app())
            elif parsed.path == "/api/status":
                self._send_json(self.server.store.status())
            elif parsed.path == "/api/events":
                self._send_json(self.server.events.snapshot())
            elif parsed.path == "/api/policy":
                self._send_json(dashboard_policy_snapshot(self.server.store, self.server.events))
            elif parsed.path == "/api/home":
                self._send_json(dashboard_home_summary(self.server.store, self.server.events))
            elif parsed.path == "/api/services":
                self._send_json(dashboard_services_status(self.server.store, self.server.events))
            elif parsed.path == "/api/settings":
                self._send_json(dashboard_get_settings(self.server.store))
            elif parsed.path == "/api/logs":
                params = urllib.parse.parse_qs(parsed.query)
                self._send_json(dashboard_logs_payload(self.server.store, self.server.events, params))
            elif parsed.path == "/api/event":
                params = urllib.parse.parse_qs(parsed.query)
                self._send_json(dashboard_event_detail(self.server.events, params.get("incident_id", [""])[0]))
            elif parsed.path == "/api/user":
                params = urllib.parse.parse_qs(parsed.query)
                self._send_json(dashboard_user_detail(self.server.store, self.server.events, params.get("id", [""])[0]))
            elif parsed.path == "/api/files":
                self._send_json({"files": self.server.store.list_files()})
            elif parsed.path == "/api/file":
                params = urllib.parse.parse_qs(parsed.query)
                rel = params.get("path", [""])[0]
                self._send_json({"path": rel, "content": self.server.store.read_file(rel)})
            elif parsed.path == "/edit":
                params = urllib.parse.parse_qs(parsed.query)
                rel = params.get("path", ["config.json"])[0]
                self._send_html(render_editor(rel, self.server.store.read_file(rel)))
            else:
                self.send_error(404)
        except Exception as exc:  # noqa: BLE001
            self._send_json({"error": str(exc), "trace": traceback.format_exc()}, status=500)

    def do_POST(self) -> None:
        try:
            parsed = urllib.parse.urlsplit(self.path)
            if parsed.path == "/login":
                length = int(self.headers.get("Content-Length", "0"))
                data = urllib.parse.parse_qs(self.rfile.read(length).decode("utf-8", errors="replace"))
                token = data.get("token", [""])[0]
                if self._token_ok(token):
                    self.send_response(302)
                    self.send_header("Location", "/")
                    self.send_header("Set-Cookie", f"guard_token={urllib.parse.quote(token)}; HttpOnly; SameSite=Strict; Path=/")
                    self.end_headers()
                else:
                    self._send_html(render_login(error="Ongeldig token"), status=403)
                return
            if not self._authenticated(parsed):
                self._send_json({"error": "unauthorized"}, status=401)
                return
            if parsed.path == "/api/reload":
                self.server.store.reload()
                self._send_json({"ok": True, "status": self.server.store.status()})
            elif parsed.path == "/api/policy/category":
                self._send_json(dashboard_update_category(self.server.store, self._read_json_body()))
            elif parsed.path == "/api/policy/domain":
                self._send_json(dashboard_update_domain(self.server.store, self._read_json_body()))
            elif parsed.path == "/api/policy/group":
                self._send_json(dashboard_update_group(self.server.store, self._read_json_body()))
            elif parsed.path == "/api/users/manage":
                self._send_json(dashboard_update_user(self.server.store, self._read_json_body()))
            elif parsed.path == "/api/dlp/rule":
                self._send_json(dashboard_update_dlp(self.server.store, self._read_json_body()))
            elif parsed.path == "/api/settings":
                self._send_json(dashboard_update_settings(self.server.store, self._read_json_body()))
            elif parsed.path == "/api/sync/netbird":
                self._send_json(trigger_netbird_sync())
            elif parsed.path == "/save":
                length = int(self.headers.get("Content-Length", "0"))
                form = urllib.parse.parse_qs(self.rfile.read(length).decode("utf-8", errors="replace"))
                rel = form.get("path", [""])[0]
                content = form.get("content", [""])[0]
                self.server.store.save_file(rel, content)
                self._redirect(f"/edit?path={urllib.parse.quote(rel)}")
            elif parsed.path == "/api/test":
                self._handle_test()
            else:
                self.send_error(404)
        except Exception as exc:  # noqa: BLE001
            self._send_json({"error": str(exc), "trace": traceback.format_exc()}, status=500)

    def _read_json_body(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0"))
        payload = self.rfile.read(length).decode("utf-8", errors="replace")
        if not payload.strip():
            return {}
        if payload.strip().startswith("{"):
            return json.loads(payload)
        return {k: v[0] for k, v in urllib.parse.parse_qs(payload).items()}

    def _handle_test(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        payload = self.rfile.read(length).decode("utf-8", errors="replace")
        data = json.loads(payload) if payload.strip().startswith("{") else {
            k: v[0] for k, v in urllib.parse.parse_qs(payload).items()
        }
        headers = {"host": [urllib.parse.urlsplit(data.get("url", "")).netloc]}
        identity = Identity(
            user=data.get("user", "test-user"),
            source_ip=data.get("source_ip", "127.0.0.1"),
            groups=[g.strip() for g in data.get("groups", "student").split(",") if g.strip()],
            source="dashboard-test",
        )
        http_method = str(data.get("http_method", "POST")).upper()
        context = ScanContext(
            direction=data.get("direction", "reqmod"),
            url=data.get("url", ""),
            domain=normalize_domain(urllib.parse.urlsplit(data.get("url", "")).netloc),
            method=http_method,
            content_type=data.get("content_type", "text/plain"),
            identity=identity,
            icap_headers={},
            http_headers=headers,
            request_start=f"{http_method} {data.get('url', '/')} HTTP/1.1",
        )
        body = data.get("body", "").encode("utf-8")
        if str(data.get("skip_clamav", "on")).lower() in {"on", "true", "1", "yes"}:
            store = self.server.store
            clamav = ClamAVClient({"enabled": False})
            assert store.phrase_engine is not None
            assert store.dlp_engine is not None
            engine = PolicyEngine(store.config, store.phrase_engine, store.dlp_engine, clamav)
        else:
            engine = self.server.store.policy_engine
            assert engine is not None
        decision = engine.evaluate(context, body)
        self._send_json(
            {
                "allowed": decision.allowed,
                "reason": decision.reason,
                "public_reason": decision.public_reason(),
                "policy": decision.policy,
                "phrase_scores": decision.phrase_scores,
                "phrase_hits": [dataclasses.asdict(hit) for hit in decision.phrase_hits],
                "dlp_hits": [dataclasses.asdict(hit) for hit in decision.dlp_hits],
                "clam": dataclasses.asdict(decision.clam),
                "details": decision.details,
            }
        )

    def _authenticated(self, parsed: urllib.parse.SplitResult) -> bool:
        params = urllib.parse.parse_qs(parsed.query)
        token = params.get("token", [""])[0]
        if token and self._token_ok(token):
            return True
        auth = self.headers.get("Authorization", "")
        if auth.lower().startswith("bearer ") and self._token_ok(auth.split(None, 1)[1]):
            return True
        cookie = self.headers.get("Cookie", "")
        for part in cookie.split(";"):
            if "=" not in part:
                continue
            name, value = part.strip().split("=", 1)
            if name == "guard_token" and self._token_ok(urllib.parse.unquote(value)):
                return True
        return False

    def _token_ok(self, token: str) -> bool:
        expected = os.environ.get("SCHOOL_ICAP_DASHBOARD_TOKEN") or str(
            self.server.store.config.get("server", {}).get("dashboard_token", "")
        )
        return bool(expected) and secrets.compare_digest(token, expected)

    def _send_json(self, payload: dict[str, Any], status: int = 200) -> None:
        data = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _send_html(self, html: str, status: int = 200) -> None:
        data = html.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _redirect(self, location: str) -> None:
        self.send_response(302)
        self.send_header("Location", location)
        self.end_headers()


def render_login(error: str = "") -> str:
    error_html = f'<p class="error">{html_lib.escape(error)}</p>' if error else ""
    return f"""<!doctype html>
<html lang="nl" data-theme="auto">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Aanmelden | School ICAP Guard</title>
  <style>{DASHBOARD_CSS}</style>
</head>
<body class="login-body">
  <main class="login-card">
    <div class="login-brand">
      <div class="brand-mark">SI</div>
      <div>
        <h1>School ICAP Guard</h1>
        <p>Beheerdersdashboard</p>
      </div>
    </div>
    {error_html}
    <form method="post" action="/login">
      <label class="field">
        <span>Dashboard token</span>
        <input name="token" type="password" autocomplete="current-password" autofocus>
      </label>
      <button type="submit" class="primary">Aanmelden</button>
    </form>
    <footer class="login-footer">
      <span>Copyright &copy; 2026 Youness Banali El Khattabi</span>
    </footer>
  </main>
</body>
</html>"""


def render_editor(path: str, content: str) -> str:
    escaped_path = html_lib.escape(path)
    escaped_content = html_lib.escape(content)
    return f"""<!doctype html>
<html lang="nl" data-theme="auto">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{escaped_path} | Editor</title>
  <style>{DASHBOARD_CSS}</style>
</head>
<body>
  <header class="topbar">
    <div class="brand">
      <span class="brand-mark">SI</span>
      <div class="brand-text">
        <strong>School ICAP Guard</strong>
        <small>Bestand bewerken: {escaped_path}</small>
      </div>
    </div>
    <nav class="topbar-actions">
      <a class="btn" href="/">Terug naar dashboard</a>
      <button class="btn" onclick="toggleTheme()">Thema</button>
    </nav>
  </header>
  <main class="content">
    <section class="panel editor-panel">
      <header class="panel-head">
        <h2>{escaped_path}</h2>
        <p class="hint">Wijzigingen worden veilig opgeslagen met automatische backup in <code>.backups/</code>.</p>
      </header>
      <form method="post" action="/save" class="editor">
        <input type="hidden" name="path" value="{escaped_path}">
        <textarea name="content" spellcheck="false">{escaped_content}</textarea>
        <div class="actions">
          <button type="submit" class="primary">Opslaan en herladen</button>
          <a class="btn" href="/">Annuleer</a>
        </div>
      </form>
    </section>
  </main>
  <footer class="page-footer">
    <span>Copyright &copy; 2026 Youness Banali El Khattabi</span>
  </footer>
  <script>
    function toggleTheme() {{
      const root = document.documentElement;
      const cur = root.getAttribute('data-theme') || 'auto';
      const next = cur === 'dark' ? 'light' : (cur === 'light' ? 'auto' : 'dark');
      root.setAttribute('data-theme', next);
      try {{ localStorage.setItem('sig-theme', next); }} catch (_) {{}}
    }}
    try {{ const t = localStorage.getItem('sig-theme'); if (t) document.documentElement.setAttribute('data-theme', t); }} catch (_) {{}}
  </script>
</body>
</html>"""


def render_dashboard_app() -> str:
    """Multi-page SPA. Server stuurt deze HTML voor /, /home, /users, /logs, ..."""
    return DASHBOARD_HTML.replace("__DASHBOARD_CSS__", DASHBOARD_CSS).replace("__DASHBOARD_JS__", DASHBOARD_JS)


DASHBOARD_HTML = """<!doctype html>
<html lang="nl" data-theme="auto">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>School ICAP Guard</title>
  <style>__DASHBOARD_CSS__</style>
</head>
<body>
  <aside class="sidebar" id="sidebar">
    <div class="brand">
      <span class="brand-mark">SI</span>
      <div class="brand-text">
        <strong>School ICAP Guard</strong>
        <small>Webfilter &amp; security console</small>
      </div>
    </div>
    <nav class="side-nav" id="side-nav">
      <a data-route="/home"><span class="ic">⌂</span>Dashboard</a>
      <a data-route="/logs"><span class="ic">⧉</span>Logs &amp; events</a>
      <a data-route="/users"><span class="ic">✩</span>Gebruikers</a>
      <a data-route="/policies"><span class="ic">☰</span>Policies &amp; groepen</a>
      <a data-route="/domains"><span class="ic">⌖</span>Domeinen</a>
      <a data-route="/categories"><span class="ic">▣</span>Categorieen</a>
      <a data-route="/phrases"><span class="ic">¶</span>Weighted phrases</a>
      <a data-route="/dlp"><span class="ic">⛈</span>DLP</a>
      <a data-route="/services"><span class="ic">⚡</span>Services</a>
      <a data-route="/settings"><span class="ic">⚙</span>Instellingen</a>
      <a data-route="/test"><span class="ic">▶</span>Policy test</a>
      <a data-route="/files"><span class="ic">☲</span>Bestanden</a>
    </nav>
    <div class="side-foot">
      <button class="btn" id="theme-toggle">Thema wisselen</button>
      <small>Copyright &copy; 2026<br>Youness Banali El Khattabi</small>
    </div>
  </aside>
  <main class="content">
    <header class="topbar">
      <button class="hamburger" id="hamburger" aria-label="Menu">☰</button>
      <div class="page-title">
        <h1 id="page-title">Dashboard</h1>
        <p class="hint" id="page-sub"></p>
      </div>
      <div class="topbar-actions">
        <button class="btn" id="reload-btn">Config herladen</button>
        <a class="btn" href="/login">Uitloggen</a>
      </div>
    </header>
    <section id="view" class="view"></section>
    <footer class="page-footer">
      <span>Copyright &copy; 2026 Youness Banali El Khattabi</span>
      <span id="status-foot"></span>
    </footer>
  </main>
  <div id="toast" class="toast" hidden></div>
  <script>__DASHBOARD_JS__</script>
</body>
</html>"""


DASHBOARD_CSS = r"""
:root {
  --bg: #f4f6fb;
  --surface: #ffffff;
  --surface-2: #f8fafc;
  --surface-3: #eef2f7;
  --border: #d8dee8;
  --text: #0f172a;
  --text-muted: #5a6677;
  --primary: #1f3a8a;
  --primary-2: #2451c7;
  --primary-text: #ffffff;
  --ok: #168251;
  --ok-bg: #e6f4ec;
  --warn: #b7791f;
  --warn-bg: #fff4d6;
  --danger: #b42318;
  --danger-bg: #fdecea;
  --info: #0f4f76;
  --info-bg: #e7f1f7;
  --shadow: 0 18px 48px rgba(13, 27, 64, 0.10);
  --radius: 10px;
  --radius-sm: 6px;
  --font: 'Inter', ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
  color-scheme: light;
  font-family: var(--font);
}

html[data-theme="dark"] {
  --bg: #0c111a;
  --surface: #161e2c;
  --surface-2: #1a2333;
  --surface-3: #20293c;
  --border: #2c3a55;
  --text: #e8eef7;
  --text-muted: #98a4ba;
  --primary: #5b8def;
  --primary-2: #88aaff;
  --primary-text: #0c111a;
  --ok: #5ed6a1;
  --ok-bg: #103626;
  --warn: #f5c969;
  --warn-bg: #3a2c0c;
  --danger: #ff8a7d;
  --danger-bg: #3a1612;
  --info: #9bd7ff;
  --info-bg: #122b3c;
  --shadow: 0 24px 56px rgba(0, 0, 0, 0.5);
  color-scheme: dark;
}

@media (prefers-color-scheme: dark) {
  html[data-theme="auto"] {
    --bg: #0c111a;
    --surface: #161e2c;
    --surface-2: #1a2333;
    --surface-3: #20293c;
    --border: #2c3a55;
    --text: #e8eef7;
    --text-muted: #98a4ba;
    --primary: #5b8def;
    --primary-2: #88aaff;
    --primary-text: #0c111a;
    --ok: #5ed6a1;
    --ok-bg: #103626;
    --warn: #f5c969;
    --warn-bg: #3a2c0c;
    --danger: #ff8a7d;
    --danger-bg: #3a1612;
    --info: #9bd7ff;
    --info-bg: #122b3c;
    --shadow: 0 24px 56px rgba(0, 0, 0, 0.5);
    color-scheme: dark;
  }
}

* { box-sizing: border-box; }
html, body { margin: 0; padding: 0; height: 100%; background: var(--bg); color: var(--text); font-family: var(--font); -webkit-font-smoothing: antialiased; }
body { display: grid; grid-template-columns: 260px 1fr; min-height: 100vh; }
a { color: inherit; text-decoration: none; }

/* SIDEBAR */
.sidebar {
  position: sticky; top: 0; align-self: start;
  width: 260px; height: 100vh;
  background: var(--surface);
  border-right: 1px solid var(--border);
  display: flex; flex-direction: column; gap: 18px;
  padding: 18px 14px;
  z-index: 10;
}
.brand { display: flex; align-items: center; gap: 10px; }
.brand-mark {
  width: 38px; height: 38px; border-radius: 9px;
  background: linear-gradient(135deg, var(--primary), var(--primary-2));
  color: var(--primary-text); display: grid; place-items: center;
  font-weight: 800; letter-spacing: -0.5px; font-size: 14px;
}
.brand-text strong { display: block; font-size: 14px; }
.brand-text small { color: var(--text-muted); font-size: 11px; }

.side-nav { display: flex; flex-direction: column; gap: 2px; margin-top: 4px; }
.side-nav a {
  display: flex; align-items: center; gap: 10px;
  padding: 9px 11px; border-radius: 8px;
  color: var(--text-muted); font-weight: 600; font-size: 14px;
  cursor: pointer; transition: background 0.15s, color 0.15s;
}
.side-nav a:hover { background: var(--surface-2); color: var(--text); }
.side-nav a.active { background: var(--surface-3); color: var(--text); }
.side-nav a.active .ic { color: var(--primary); }
.side-nav .ic {
  width: 22px; height: 22px; display: inline-grid; place-items: center;
  border-radius: 6px; font-size: 13px; color: var(--text-muted);
  background: var(--surface-2);
}
.side-foot { margin-top: auto; display: grid; gap: 10px; }
.side-foot small { color: var(--text-muted); font-size: 11px; line-height: 1.5; }

/* CONTENT */
.content { display: flex; flex-direction: column; min-width: 0; }
.topbar {
  position: sticky; top: 0; z-index: 5;
  display: flex; align-items: center; gap: 16px;
  padding: 14px 22px;
  background: var(--surface);
  border-bottom: 1px solid var(--border);
}
.topbar .page-title { flex: 1; min-width: 0; }
.topbar h1 { margin: 0; font-size: 18px; font-weight: 700; letter-spacing: -0.2px; }
.topbar .hint { margin: 1px 0 0; font-size: 12px; color: var(--text-muted); }
.topbar-actions { display: flex; gap: 8px; flex-wrap: wrap; }
.hamburger { display: none; }

.view { padding: 22px; display: flex; flex-direction: column; gap: 18px; flex: 1; }

/* BUTTONS */
.btn, button.btn, button[type="submit"], a.btn {
  display: inline-flex; align-items: center; gap: 6px;
  padding: 8px 14px; border-radius: var(--radius-sm);
  border: 1px solid var(--border); background: var(--surface-2); color: var(--text);
  font: 600 13px var(--font); cursor: pointer; transition: background 0.15s, border-color 0.15s, transform 0.05s;
}
.btn:hover, button[type="submit"]:hover { background: var(--surface-3); }
.btn.primary, button.primary, button[type="submit"].primary {
  background: var(--primary); border-color: var(--primary); color: var(--primary-text);
}
.btn.primary:hover, button.primary:hover { background: var(--primary-2); border-color: var(--primary-2); }
.btn.danger, .danger-btn {
  background: var(--danger-bg); border-color: var(--danger); color: var(--danger);
}
.btn.danger:hover, .danger-btn:hover { filter: brightness(0.95); }
.btn.ghost { background: transparent; }
.btn:active { transform: translateY(1px); }
.btn:disabled { opacity: 0.55; cursor: not-allowed; }

/* PANELS */
.panel {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 18px;
  box-shadow: var(--shadow);
  display: flex; flex-direction: column; gap: 12px;
  min-width: 0;
}
.panel h2, .panel-head h2 { margin: 0; font-size: 15px; font-weight: 700; }
.panel-head { display: flex; justify-content: space-between; align-items: flex-start; gap: 12px; }
.panel-head .hint { margin: 4px 0 0; }
.hint { color: var(--text-muted); font-size: 13px; line-height: 1.45; margin: 0; }

/* GRID HELPERS */
.grid { display: grid; gap: 14px; }
.grid.cards-6 { grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); }
.grid.cards-4 { grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); }
.grid.cards-3 { grid-template-columns: repeat(auto-fit, minmax(290px, 1fr)); }
.grid.cards-2 { grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); }
.grid.list { grid-template-columns: 1fr; gap: 8px; }
.grid.two-cols { grid-template-columns: minmax(0, 1.2fr) minmax(0, 1fr); }

/* CARDS */
.kpi {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 16px;
  display: flex; flex-direction: column; gap: 4px;
  position: relative;
  box-shadow: var(--shadow);
}
.kpi .label { color: var(--text-muted); font-size: 12px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; }
.kpi .value { font-size: 26px; font-weight: 700; letter-spacing: -0.3px; }
.kpi .sub { color: var(--text-muted); font-size: 12px; }
.kpi.ok { border-left: 4px solid var(--ok); }
.kpi.danger { border-left: 4px solid var(--danger); }
.kpi.warn { border-left: 4px solid var(--warn); }
.kpi.info { border-left: 4px solid var(--primary); }

/* BADGES */
.badge {
  display: inline-flex; align-items: center; gap: 6px;
  padding: 3px 9px; border-radius: 999px;
  font-size: 12px; font-weight: 700; letter-spacing: 0.02em;
  border: 1px solid transparent; line-height: 1.6;
}
.badge.ok { background: var(--ok-bg); color: var(--ok); border-color: var(--ok); }
.badge.danger { background: var(--danger-bg); color: var(--danger); border-color: var(--danger); }
.badge.warn { background: var(--warn-bg); color: var(--warn); border-color: var(--warn); }
.badge.info { background: var(--info-bg); color: var(--info); border-color: var(--info); }
.badge.neutral { background: var(--surface-3); color: var(--text-muted); border-color: var(--border); }
.dot { width: 8px; height: 8px; border-radius: 50%; display: inline-block; }
.dot.ok { background: var(--ok); }
.dot.danger { background: var(--danger); }
.dot.warn { background: var(--warn); }
.dot.neutral { background: var(--text-muted); }

/* TABLES */
.table-wrap { width: 100%; overflow-x: auto; border: 1px solid var(--border); border-radius: var(--radius); }
table.data { width: 100%; border-collapse: collapse; min-width: 600px; }
table.data th, table.data td {
  text-align: left; padding: 10px 12px; border-bottom: 1px solid var(--border);
  font-size: 13px; vertical-align: top;
}
table.data th { background: var(--surface-2); font-weight: 700; color: var(--text-muted); font-size: 12px; text-transform: uppercase; letter-spacing: 0.04em; }
table.data tbody tr:hover { background: var(--surface-2); }
table.data tbody tr:last-child td { border-bottom: 0; }
table.data td.mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 12px; }
table.data td.right { text-align: right; }
table.data td.actions { white-space: nowrap; text-align: right; }

/* FORMS */
.field { display: grid; gap: 5px; font-size: 13px; font-weight: 600; color: var(--text-muted); }
.field input, .field select, .field textarea {
  width: 100%; padding: 9px 11px;
  border: 1px solid var(--border); border-radius: var(--radius-sm);
  background: var(--surface-2); color: var(--text); font: 13px var(--font);
}
.field input:focus, .field select:focus, .field textarea:focus {
  outline: none; border-color: var(--primary); box-shadow: 0 0 0 3px rgba(91, 141, 239, 0.18);
  background: var(--surface);
}
.field textarea { min-height: 110px; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
form.row, form.inline-form { display: grid; grid-template-columns: repeat(auto-fit, minmax(190px, 1fr)); gap: 12px; align-items: end; }
form.row button, form.inline-form button { min-height: 38px; }
.actions { display: flex; gap: 8px; flex-wrap: wrap; }
.check { display: inline-flex; align-items: center; gap: 8px; font-weight: 600; cursor: pointer; }
.check input { width: 18px; height: 18px; }

/* LOGIN */
.login-body {
  display: grid; place-items: center; min-height: 100vh; padding: 24px;
  background: linear-gradient(155deg, rgba(31,58,138,0.18), rgba(36,81,199,0.08));
  grid-template-columns: 1fr;
}
.login-card {
  width: min(420px, 100%);
  background: var(--surface); border: 1px solid var(--border); border-radius: 14px;
  padding: 28px; box-shadow: var(--shadow);
  display: grid; gap: 18px;
}
.login-brand { display: flex; align-items: center; gap: 12px; }
.login-brand h1 { margin: 0; font-size: 18px; }
.login-brand p { margin: 2px 0 0; color: var(--text-muted); font-size: 12px; }
.login-card form { display: grid; gap: 14px; }
.login-footer { color: var(--text-muted); font-size: 11px; text-align: center; border-top: 1px solid var(--border); padding-top: 12px; }
.error { background: var(--danger-bg); color: var(--danger); padding: 9px 12px; border-radius: 8px; border: 1px solid var(--danger); font-size: 13px; }

/* EDITOR */
.editor-panel { display: flex; flex-direction: column; gap: 12px; }
.editor textarea {
  width: 100%; min-height: 60vh; resize: vertical;
  background: var(--surface-2); color: var(--text);
  border: 1px solid var(--border); border-radius: var(--radius-sm);
  padding: 14px; font: 13px/1.55 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
}
.editor .actions { margin-top: 10px; }

/* EVENT LIST */
.event-row {
  display: grid; grid-template-columns: 110px 1fr auto; gap: 12px;
  align-items: center; padding: 10px 12px;
  border: 1px solid var(--border); border-radius: var(--radius-sm);
  background: var(--surface-2);
}
.event-row .ts { font-size: 12px; color: var(--text-muted); font-family: ui-monospace, monospace; }
.event-row .meta { color: var(--text-muted); font-size: 12px; }
.event-row .meta strong { color: var(--text); font-weight: 600; }
.event-row .actions-col { display: flex; gap: 6px; }

/* SETTINGS TOGGLE */
.toggle { position: relative; display: inline-block; width: 42px; height: 24px; }
.toggle input { opacity: 0; width: 0; height: 0; }
.toggle .slider {
  position: absolute; inset: 0; background: var(--border); border-radius: 24px;
  transition: background 0.15s; cursor: pointer;
}
.toggle .slider:before {
  content: ""; position: absolute; left: 3px; top: 3px;
  width: 18px; height: 18px; border-radius: 50%; background: var(--surface);
  transition: transform 0.15s; box-shadow: 0 2px 6px rgba(0,0,0,0.2);
}
.toggle input:checked + .slider { background: var(--primary); }
.toggle input:checked + .slider:before { transform: translateX(18px); }
.setting-row {
  display: grid; grid-template-columns: 1fr auto; gap: 14px; align-items: center;
  padding: 12px 14px; border: 1px solid var(--border); border-radius: var(--radius-sm); background: var(--surface-2);
}
.setting-row .label { font-weight: 600; font-size: 14px; }
.setting-row .sub { color: var(--text-muted); font-size: 12px; margin-top: 2px; }

/* CHARTS */
.chart-card { display: flex; flex-direction: column; gap: 10px; min-height: 200px; }
.chart-card h3 { margin: 0; font-size: 13px; font-weight: 700; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.04em; }
.chart-card svg { width: 100%; height: 200px; overflow: visible; }
.chart-card .legend { display: flex; gap: 12px; flex-wrap: wrap; font-size: 12px; color: var(--text-muted); }
.bar-list { display: grid; gap: 8px; }
.bar-list .bar-row { display: grid; grid-template-columns: minmax(0, 1.2fr) minmax(120px, 2fr) 40px; gap: 10px; align-items: center; font-size: 12px; }
.bar-list .bar { background: var(--surface-3); border-radius: 4px; height: 14px; overflow: hidden; position: relative; }
.bar-list .bar > div { height: 100%; background: linear-gradient(90deg, var(--primary), var(--primary-2)); border-radius: 4px; }
.bar-list .label { color: var(--text); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.bar-list .count { text-align: right; color: var(--text-muted); font-variant-numeric: tabular-nums; }

/* EMPTY STATES */
.empty {
  text-align: center; color: var(--text-muted); padding: 28px 18px;
  border: 1px dashed var(--border); border-radius: var(--radius-sm);
  background: var(--surface-2);
}
.empty strong { display: block; font-size: 15px; color: var(--text); margin-bottom: 4px; }

/* TOAST */
.toast {
  position: fixed; right: 18px; bottom: 18px; z-index: 99;
  max-width: min(420px, calc(100vw - 36px));
  padding: 12px 16px; border-radius: 10px;
  background: var(--surface); color: var(--text);
  border: 1px solid var(--border); box-shadow: var(--shadow);
  font-weight: 600; font-size: 13px;
}
.toast.ok { border-color: var(--ok); color: var(--ok); }
.toast.error { border-color: var(--danger); color: var(--danger); }

/* FOOTER */
.page-footer {
  padding: 12px 22px; border-top: 1px solid var(--border);
  display: flex; justify-content: space-between; gap: 12px;
  color: var(--text-muted); font-size: 12px;
  background: var(--surface);
}

/* DETAIL/PILLS */
.pill-row { display: flex; flex-wrap: wrap; gap: 6px; }
.pill { background: var(--surface-3); color: var(--text); padding: 3px 9px; border-radius: 999px; font-size: 12px; font-weight: 600; border: 1px solid var(--border); }
.kvlist { display: grid; grid-template-columns: 150px 1fr; gap: 6px 14px; font-size: 13px; }
.kvlist dt { color: var(--text-muted); font-weight: 600; }
.kvlist dd { margin: 0; word-break: break-word; }

/* CATEGORY LIST */
.category-list { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 10px; }
.category-item {
  background: var(--surface-2); border: 1px solid var(--border); border-radius: var(--radius-sm);
  border-left: 4px solid var(--border); padding: 12px;
  display: grid; gap: 8px;
}
.category-item.active { border-left-color: var(--ok); background: var(--ok-bg); }
.category-item.risk-high.active, .category-item.risk-critical.active { border-left-color: var(--danger); background: var(--danger-bg); }
.category-item.risk-medium.active { border-left-color: var(--warn); background: var(--warn-bg); }
.category-item .title { font-weight: 700; }
.category-item .sub { color: var(--text-muted); font-size: 12px; }
.category-item .row { display: flex; gap: 6px; align-items: center; flex-wrap: wrap; }
.category-item .threshold-input { max-width: 80px; }

/* RESPONSIVE */
@media (max-width: 1100px) {
  .grid.two-cols { grid-template-columns: 1fr; }
}
@media (max-width: 880px) {
  body { grid-template-columns: 1fr; }
  .sidebar {
    position: fixed; left: -280px; top: 0; height: 100vh;
    transition: left 0.25s; box-shadow: var(--shadow);
  }
  .sidebar.open { left: 0; }
  .hamburger { display: inline-flex; }
}
"""


DASHBOARD_JS = r"""
(function() {
  'use strict';

  const view = document.getElementById('view');
  const sidebar = document.getElementById('sidebar');
  const sideNav = document.getElementById('side-nav');
  const pageTitle = document.getElementById('page-title');
  const pageSub = document.getElementById('page-sub');
  const toastEl = document.getElementById('toast');
  let toastTimer = null;

  const ROUTES = {
    '/': renderHome,
    '/home': renderHome,
    '/users': renderUsers,
    '/policies': renderPolicies,
    '/domains': renderDomains,
    '/categories': renderCategories,
    '/phrases': renderPhrases,
    '/dlp': renderDLP,
    '/services': renderServices,
    '/logs': renderLogs,
    '/settings': renderSettings,
    '/test': renderTest,
    '/files': renderFiles,
  };

  const TITLES = {
    '/home': ['Dashboard', 'Overzicht van het systeem'],
    '/users': ['Gebruikers', 'NetBird- en lokale gebruikers'],
    '/policies': ['Policies', 'Groepsbeleid en regels'],
    '/domains': ['Domeinen', 'Blocklist en allowlist beheer'],
    '/categories': ['Categorieen', 'Webfilter categorie thresholds'],
    '/phrases': ['Weighted phrases', 'Beheer weighted phrase lists'],
    '/dlp': ['Data Loss Prevention', 'DLP regels en gevoelige data'],
    '/services': ['Services', 'Status van alle modules'],
    '/logs': ['Logs en events', 'Geschiedenis van blocks en allows'],
    '/settings': ['Instellingen', 'Master-toggles voor alle modules'],
    '/test': ['Policy test', 'Test scan-flows zonder live verkeer'],
    '/files': ['Bestanden', 'Geavanceerde bewerker voor config bestanden'],
  };

  // ---------- helpers ----------
  function esc(value) {
    return String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  }
  function fmtTs(value) {
    if (!value) return '';
    try {
      const d = new Date(value);
      if (isNaN(d.getTime())) return value;
      return d.toLocaleString('nl-BE', { year:'numeric', month:'2-digit', day:'2-digit', hour:'2-digit', minute:'2-digit', second:'2-digit' });
    } catch (_) { return value; }
  }
  function fmtNum(n) {
    if (n === null || n === undefined) return '0';
    return Number(n).toLocaleString('nl-BE');
  }
  function api(url, opts) {
    return fetch(url, opts || {}).then(async (res) => {
      const text = await res.text();
      let data; try { data = text ? JSON.parse(text) : {}; } catch (_) { data = { error: text }; }
      if (!res.ok) throw new Error(data.error || res.statusText);
      return data;
    });
  }
  function post(url, body) {
    return api(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body || {}) });
  }
  function toast(message, ok) {
    if (!message) return;
    toastEl.textContent = message;
    toastEl.className = 'toast ' + (ok === false ? 'error' : 'ok');
    toastEl.hidden = false;
    if (toastTimer) clearTimeout(toastTimer);
    toastTimer = setTimeout(() => { toastEl.hidden = true; }, 3800);
  }
  function el(tag, attrs, ...children) {
    const n = document.createElement(tag);
    if (attrs) for (const k in attrs) {
      if (k === 'class') n.className = attrs[k];
      else if (k === 'html') n.innerHTML = attrs[k];
      else if (k.startsWith('on') && typeof attrs[k] === 'function') n.addEventListener(k.slice(2), attrs[k]);
      else n.setAttribute(k, attrs[k]);
    }
    for (const c of children) { if (c == null) continue; if (typeof c === 'string') n.appendChild(document.createTextNode(c)); else n.appendChild(c); }
    return n;
  }
  function badge(label, kind) { return `<span class="badge ${kind || 'neutral'}">${esc(label)}</span>`; }
  function emptyState(title, hint) {
    return `<div class="empty"><strong>${esc(title)}</strong>${hint ? `<span>${esc(hint)}</span>` : ''}</div>`;
  }
  function svgBar(values, opts) {
    opts = opts || {};
    const width = opts.width || 600;
    const height = opts.height || 200;
    const pad = { l: 36, r: 12, t: 14, b: 28 };
    const max = Math.max(1, ...values.flatMap(v => [v.allow || 0, v.block || 0]));
    const barW = (width - pad.l - pad.r) / Math.max(1, values.length);
    let bars = '';
    values.forEach((v, i) => {
      const x = pad.l + i * barW;
      const aH = ((v.allow || 0) / max) * (height - pad.t - pad.b);
      const bH = ((v.block || 0) / max) * (height - pad.t - pad.b);
      const aY = height - pad.b - aH;
      const bY = height - pad.b - bH;
      const w = Math.max(2, barW - 6);
      bars += `<rect x="${x + 1}" y="${aY}" width="${w/2}" height="${aH}" fill="var(--ok)" rx="2"/>`;
      bars += `<rect x="${x + 1 + w/2}" y="${bY}" width="${w/2}" height="${bH}" fill="var(--danger)" rx="2"/>`;
    });
    const yLabels = [0, max * 0.5, max].map((y, idx) => {
      const yy = height - pad.b - (y / max) * (height - pad.t - pad.b);
      return `<text x="${pad.l - 6}" y="${yy + 3}" text-anchor="end" font-size="9" fill="var(--text-muted)">${fmtNum(Math.round(y))}</text>`;
    }).join('');
    const xLabels = values.length <= 12
      ? values.map((v, i) => {
        const x = pad.l + i * barW + barW/2;
        const label = (v.bucket || '').slice(-5);
        return `<text x="${x}" y="${height - 10}" text-anchor="middle" font-size="9" fill="var(--text-muted)">${esc(label)}</text>`;
      }).join('')
      : '';
    return `<svg viewBox="0 0 ${width} ${height}" preserveAspectRatio="none">${bars}${yLabels}${xLabels}</svg>`;
  }
  function svgDonut(allow, block) {
    const total = (allow || 0) + (block || 0);
    if (!total) return '<svg viewBox="0 0 120 120"><circle cx="60" cy="60" r="46" fill="none" stroke="var(--border)" stroke-width="14"/></svg>';
    const aFrac = allow / total;
    const c = 2 * Math.PI * 46;
    const aLen = aFrac * c;
    return `<svg viewBox="0 0 120 120">
      <circle cx="60" cy="60" r="46" fill="none" stroke="var(--surface-3)" stroke-width="14"/>
      <circle cx="60" cy="60" r="46" fill="none" stroke="var(--ok)" stroke-width="14" stroke-dasharray="${aLen} ${c - aLen}" transform="rotate(-90 60 60)"/>
      <text x="60" y="58" text-anchor="middle" font-size="18" font-weight="700" fill="var(--text)">${Math.round(aFrac*100)}%</text>
      <text x="60" y="74" text-anchor="middle" font-size="10" fill="var(--text-muted)">allowed</text>
    </svg>`;
  }
  function barList(items, max) {
    if (!items || !items.length) return emptyState('Geen data', 'Geen events om te tonen.');
    const maxV = Math.max(1, ...items.map(i => i[1] || i.count || 0));
    const rows = items.slice(0, max || 8).map(item => {
      const label = item[0] || item.label || '?';
      const val = item[1] || item.count || 0;
      const pct = Math.round((val / maxV) * 100);
      return `<div class="bar-row">
        <span class="label" title="${esc(label)}">${esc(label)}</span>
        <span class="bar"><div style="width: ${pct}%"></div></span>
        <span class="count">${fmtNum(val)}</span>
      </div>`;
    }).join('');
    return `<div class="bar-list">${rows}</div>`;
  }

  // ---------- router ----------
  function setActiveLink(path) {
    sideNav.querySelectorAll('a').forEach(a => {
      a.classList.toggle('active', a.dataset.route === path);
    });
    const t = TITLES[path] || TITLES['/home'];
    pageTitle.textContent = t[0];
    pageSub.textContent = t[1];
  }
  function navigate(path, replace) {
    if (!ROUTES[path]) {
      // try matching dynamic /users/:id
      if (path.startsWith('/users/')) {
        const id = decodeURIComponent(path.slice('/users/'.length));
        if (replace) history.replaceState({}, '', path); else history.pushState({}, '', path);
        sidebar.classList.remove('open');
        setActiveLink('/users');
        return renderUserDetail(id);
      }
      path = '/home';
    }
    if (replace) history.replaceState({}, '', path); else history.pushState({}, '', path);
    sidebar.classList.remove('open');
    setActiveLink(path);
    view.innerHTML = '<div class="empty">Laden…</div>';
    ROUTES[path]().catch(err => {
      view.innerHTML = `<div class="empty error"><strong>Fout</strong><span>${esc(err.message || err)}</span></div>`;
    });
  }

  sideNav.addEventListener('click', (ev) => {
    const a = ev.target.closest('a[data-route]');
    if (!a) return;
    ev.preventDefault();
    navigate(a.dataset.route);
  });
  window.addEventListener('popstate', () => navigate(location.pathname, true));

  document.getElementById('hamburger').addEventListener('click', () => sidebar.classList.toggle('open'));
  document.getElementById('reload-btn').addEventListener('click', async () => {
    try { await post('/api/reload', {}); toast('Configuratie herladen', true); navigate(location.pathname, true); }
    catch (e) { toast(e.message, false); }
  });
  document.getElementById('theme-toggle').addEventListener('click', () => {
    const cur = document.documentElement.getAttribute('data-theme') || 'auto';
    const next = cur === 'dark' ? 'light' : (cur === 'light' ? 'auto' : 'dark');
    document.documentElement.setAttribute('data-theme', next);
    try { localStorage.setItem('sig-theme', next); } catch (_) {}
    toast('Thema: ' + next, true);
  });
  try { const t = localStorage.getItem('sig-theme'); if (t) document.documentElement.setAttribute('data-theme', t); } catch (_) {}

  // ---------- VIEW: HOME ----------
  async function renderHome() {
    const data = await api('/api/home');
    const s = data.summary || {};
    const charts = data.charts || {};
    const services = data.services || [];
    const recent = data.recent_events || [];
    const blocks = data.recent_blocks || [];

    const kpis = [
      { label: 'Gebruikers', value: fmtNum(s.users), sub: `${fmtNum(s.netbird_ips || 0)} NetBird IPs`, kind: 'info' },
      { label: 'Policies', value: fmtNum(s.groups), sub: 'Groepen', kind: 'info' },
      { label: 'Geblokkeerde domeinen', value: fmtNum(s.blocked_domains), sub: 'in blocklist', kind: 'danger' },
      { label: 'Categorieen', value: fmtNum(s.categories), sub: `${fmtNum(s.active_category_blocks || 0)} actief`, kind: 'info' },
      { label: 'DLP regels', value: fmtNum(s.dlp_rules), sub: 'totaal geladen', kind: 'warn' },
      { label: 'Events totaal', value: fmtNum(s.events_total || s.events || 0), sub: `${fmtNum(s.block_events || 0)} blocks`, kind: s.block_events ? 'danger' : 'ok' },
    ];
    if (s.weighted_phrases_enabled) {
      kpis.push({ label: 'Weighted phrases', value: fmtNum(s.phrases_rules || 0), sub: 'actieve regels', kind: 'warn' });
    }

    const kpiHtml = kpis.map(k => `
      <div class="kpi ${k.kind}">
        <span class="label">${esc(k.label)}</span>
        <span class="value">${esc(k.value)}</span>
        <span class="sub">${esc(k.sub)}</span>
      </div>`).join('');

    const servicesHtml = services.map(svc => `
      <div class="setting-row">
        <div>
          <div class="label">${esc(svc.label)}</div>
          <div class="sub">${esc(svc.detail || '')}</div>
        </div>
        <div>${badge(svc.status, svc.status === 'running' ? 'ok' : (svc.status === 'disabled' ? 'neutral' : 'danger'))}</div>
      </div>`).join('') || emptyState('Geen services', '');

    const blocksHtml = blocks.length ? blocks.map(e => `
      <tr>
        <td class="mono">${esc((e.ts || '').slice(11, 19))}</td>
        <td><strong>${esc(e.user || 'anoniem')}</strong><br><span class="hint">${esc(e.source_ip || '')}</span></td>
        <td><strong>${esc(e.domain || '')}</strong><br><span class="hint">${esc(e.reason || '')}</span></td>
        <td>${badge(e.action, e.action === 'block' ? 'danger' : 'ok')}</td>
      </tr>`).join('') : `<tr><td colspan="4">${emptyState('Geen blocks geregistreerd', 'Nog geen activity sinds start.')}</td></tr>`;

    view.innerHTML = `
      <section class="grid cards-6">${kpiHtml}</section>
      <section class="grid cards-2">
        <div class="panel chart-card">
          <h3>Allowed vs blocked</h3>
          <div style="display: flex; gap: 18px; align-items: center;">
            <div style="width: 160px; height: 160px;">${svgDonut(charts.totals?.allow || 0, charts.totals?.block || 0)}</div>
            <div class="kvlist">
              <dt>Toegelaten</dt><dd>${fmtNum(charts.totals?.allow || 0)}</dd>
              <dt>Geblokkeerd</dt><dd>${fmtNum(charts.totals?.block || 0)}</dd>
              <dt>Totaal</dt><dd>${fmtNum((charts.totals?.allow || 0) + (charts.totals?.block || 0))}</dd>
            </div>
          </div>
        </div>
        <div class="panel chart-card">
          <h3>Blocks per dag (30d)</h3>
          ${charts.daily && charts.daily.length ? svgBar(charts.daily) : emptyState('Geen trafficdata beschikbaar', '')}
          <div class="legend"><span><span class="dot ok"></span> Allow</span><span><span class="dot danger"></span> Block</span></div>
        </div>
      </section>
      <section class="grid cards-3">
        <div class="panel"><h2>Top geblokkeerde categorieen</h2>${barList(charts.top_categories, 8)}</div>
        <div class="panel"><h2>Meest actieve gebruikers</h2>${barList(charts.top_users, 8)}</div>
        <div class="panel"><h2>Top geblokkeerde domeinen</h2>${barList(charts.top_domains, 8)}</div>
      </section>
      <section class="grid two-cols">
        <div class="panel">
          <header class="panel-head"><h2>Service status</h2></header>
          <div class="grid list">${servicesHtml}</div>
        </div>
        <div class="panel">
          <header class="panel-head">
            <div>
              <h2>Laatste blocks</h2>
              <p class="hint">Snelle blik op de meest recente block-events.</p>
            </div>
            <a class="btn" data-route="/logs" href="/logs">Alle logs</a>
          </header>
          <div class="table-wrap">
            <table class="data">
              <thead><tr><th>Tijd</th><th>Gebruiker</th><th>Domein</th><th>Status</th></tr></thead>
              <tbody>${blocksHtml}</tbody>
            </table>
          </div>
        </div>
      </section>
      <section class="grid cards-3">
        <div class="panel">
          <h2>Snelle acties</h2>
          <div class="actions">
            <a class="btn primary" data-route="/users" href="/users">Gebruikers</a>
            <a class="btn" data-route="/domains" href="/domains">Domeinen</a>
            <a class="btn" data-route="/policies" href="/policies">Policies</a>
            <a class="btn" data-route="/settings" href="/settings">Instellingen</a>
          </div>
        </div>
      </section>
    `;
    bindRouteLinks();
  }

  // ---------- VIEW: USERS ----------
  async function renderUsers() {
    const data = await api('/api/policy');
    const users = data.users || {};
    const ipMap = data.ip_map || {};
    const ipByUser = {};
    Object.entries(ipMap).forEach(([ip, mapping]) => {
      const u = (typeof mapping === 'string') ? mapping : (mapping && mapping.user);
      if (!u) return;
      (ipByUser[u] = ipByUser[u] || []).push(ip);
    });

    const rows = Object.entries(users).map(([user, obj]) => {
      const groups = (obj.groups || []).map(g => `<span class="pill">${esc(g)}</span>`).join(' ');
      const ips = (ipByUser[user] || []).map(ip => `<span class="pill">${esc(ip)}</span>`).join(' ');
      return `<tr>
        <td><strong>${esc(user)}</strong></td>
        <td class="mono">${esc(obj.netbird_user_id || obj.entra_object_id || '')}</td>
        <td><div class="pill-row">${groups || '<span class="hint">geen</span>'}</div></td>
        <td><div class="pill-row">${ips || '<span class="hint">geen</span>'}</div></td>
        <td class="actions">
          <a class="btn" href="/users/${encodeURIComponent(user)}" data-route="/users/${encodeURIComponent(user)}">Details</a>
          <button class="btn danger" data-action="user-delete" data-user="${esc(user)}">Verwijder</button>
        </td>
      </tr>`;
    }).join('');

    view.innerHTML = `
      <section class="panel">
        <header class="panel-head">
          <div>
            <h2>Gebruikers</h2>
            <p class="hint">NetBird sync vult deze lijst automatisch. Voeg hier ook lokale gebruikers toe of pas groepen aan.</p>
          </div>
        </header>
        <form id="user-form" class="row">
          <label class="field"><span>Gebruiker</span><input name="user" placeholder="naam@school.be" required></label>
          <label class="field"><span>Groepen</span><input name="groups" placeholder="teacher, byod"></label>
          <label class="field"><span>NetBird IP</span><input name="ip" placeholder="100.64.x.x"></label>
          <label class="field"><span>Entra object id</span><input name="entra_object_id" placeholder="optioneel"></label>
          <button type="submit" class="primary">Opslaan</button>
        </form>
      </section>
      <section class="panel">
        <header class="panel-head"><h2>${fmtNum(Object.keys(users).length)} gebruikers</h2></header>
        <input id="user-search" class="field" placeholder="Zoek op naam, email, groep, IP" style="padding: 9px 11px; border-radius: 6px; border: 1px solid var(--border); background: var(--surface-2); color: var(--text); width: 100%;">
        <div class="table-wrap">
          <table class="data">
            <thead><tr><th>Gebruiker</th><th>ID</th><th>Groepen</th><th>IP / NetBird</th><th></th></tr></thead>
            <tbody id="user-tbody">${rows || `<tr><td colspan="5">${emptyState('Geen gebruikers gevonden', 'Voer een NetBird sync uit of voeg er hieronder een toe.')}</td></tr>`}</tbody>
          </table>
        </div>
      </section>
    `;
    bindRouteLinks();
    document.getElementById('user-form').addEventListener('submit', async (ev) => {
      ev.preventDefault();
      const fd = Object.fromEntries(new FormData(ev.target).entries());
      try { await post('/api/users/manage', { ...fd, action: 'save' }); toast('Gebruiker opgeslagen', true); navigate('/users', true); }
      catch (e) { toast(e.message, false); }
    });
    view.querySelectorAll('[data-action="user-delete"]').forEach(btn => {
      btn.addEventListener('click', async () => {
        if (!confirm('Gebruiker ' + btn.dataset.user + ' verwijderen?')) return;
        try { await post('/api/users/manage', { user: btn.dataset.user, action: 'delete' }); toast('Verwijderd', true); navigate('/users', true); }
        catch (e) { toast(e.message, false); }
      });
    });
    const search = document.getElementById('user-search');
    if (search) {
      search.addEventListener('input', () => {
        const q = search.value.toLowerCase();
        view.querySelectorAll('#user-tbody tr').forEach(tr => {
          tr.style.display = tr.textContent.toLowerCase().includes(q) ? '' : 'none';
        });
      });
    }
  }

  async function renderUserDetail(userId) {
    view.innerHTML = '<div class="empty">Laden…</div>';
    const data = await api('/api/user?id=' + encodeURIComponent(userId));
    const stats = data.stats || {};
    const ips = (data.ips || []).map(ip => `<span class="pill">${esc(ip.ip)} (${(ip.groups||[]).join(', ') || 'geen groep'})</span>`).join(' ') || '<span class="hint">geen IPs</span>';
    const groups = (data.groups || []).map(g => `<span class="pill">${esc(g)}</span>`).join(' ') || '<span class="hint">geen groepen</span>';
    const policies = Object.keys(data.policies || {});
    const recent = (data.recent_events || []).map(e => `
      <tr>
        <td class="mono">${esc((e.ts || '').slice(0, 19).replace('T', ' '))}</td>
        <td>${badge(e.action, e.action === 'block' ? 'danger' : 'ok')}</td>
        <td><strong>${esc(e.domain || '')}</strong><br><span class="hint">${esc(e.url || '')}</span></td>
        <td>${esc(e.reason || '')}</td>
        <td>${esc((e.details && e.details.category) || '')}</td>
        <td>${esc(e.policy || '')}</td>
      </tr>`).join('');

    view.innerHTML = `
      <section class="panel">
        <header class="panel-head">
          <div>
            <h2>${esc(data.user)}</h2>
            <p class="hint">${esc(data.name || '')}${data.email ? ' · ' + esc(data.email) : ''}</p>
          </div>
          <div><a class="btn" data-route="/users" href="/users">Terug naar gebruikerslijst</a></div>
        </header>
        <dl class="kvlist">
          <dt>Groepen</dt><dd><div class="pill-row">${groups}</div></dd>
          <dt>IP-adressen</dt><dd><div class="pill-row">${ips}</div></dd>
          <dt>Toegepaste policies</dt><dd>${policies.length ? policies.map(p => `<span class="pill">${esc(p)}</span>`).join(' ') : '<span class="hint">enkel common policy</span>'}</dd>
          <dt>NetBird user id</dt><dd class="mono">${esc(data.netbird_user_id || '-')}</dd>
          <dt>NetBird peers</dt><dd>${(data.netbird_peer_ids || []).join(', ') || '<span class="hint">-</span>'}</dd>
          <dt>NetBird hostnames</dt><dd>${(data.netbird_hostnames || []).join(', ') || '<span class="hint">-</span>'}</dd>
          <dt>Entra object id</dt><dd class="mono">${esc(data.entra_object_id || '-')}</dd>
          <dt>Entra groups</dt><dd>${(data.entra_groups || []).join(', ') || '<span class="hint">-</span>'}</dd>
        </dl>
      </section>
      <section class="grid cards-3">
        <div class="kpi info"><span class="label">Totaal events</span><span class="value">${fmtNum(stats.total)}</span><span class="sub">in events.jsonl</span></div>
        <div class="kpi ok"><span class="label">Toegelaten</span><span class="value">${fmtNum(stats.allowed)}</span><span class="sub">allows</span></div>
        <div class="kpi danger"><span class="label">Geblokkeerd</span><span class="value">${fmtNum(stats.blocked)}</span><span class="sub">blocks</span></div>
      </section>
      <section class="grid cards-3">
        <div class="panel"><h2>Top block-redenen</h2>${barList(stats.top_block_reasons, 8)}</div>
        <div class="panel"><h2>Top geblokkeerde domeinen</h2>${barList(stats.top_blocked_domains, 8)}</div>
        <div class="panel"><h2>Top categorieen</h2>${barList(stats.top_blocked_categories, 8)}</div>
      </section>
      <section class="panel">
        <header class="panel-head"><h2>Recente events</h2><p class="hint">Maximaal 50 events. Volledige historiek in <a data-route="/logs" href="/logs">Logs</a>.</p></header>
        <div class="table-wrap">
          <table class="data">
            <thead><tr><th>Tijd</th><th>Actie</th><th>Domein / URL</th><th>Reden</th><th>Categorie</th><th>Policy</th></tr></thead>
            <tbody>${recent || `<tr><td colspan="6">${emptyState('Geen events voor deze gebruiker', '')}</td></tr>`}</tbody>
          </table>
        </div>
      </section>
    `;
    bindRouteLinks();
  }

  // ---------- VIEW: POLICIES ----------
  async function renderPolicies() {
    const data = await api('/api/policy');
    const groups = data.groups || [];
    const policies = data.policies || {};
    const rows = groups.map(group => {
      const p = policies[group] || {};
      const cats = Object.keys(p.phrase_thresholds || {}).length;
      const blockedD = (p.blocked_domains || []).length;
      const allowedD = (p.allowed_domains || []).length;
      const mime = (p.blocked_mime_types || []).length;
      return `<tr>
        <td><strong>${esc(group)}</strong></td>
        <td>${fmtNum(cats)}</td>
        <td>${fmtNum(blockedD)}</td>
        <td>${fmtNum(allowedD)}</td>
        <td>${fmtNum(mime)}</td>
        <td>${badge(p.dlp_enabled ? 'aan' : 'uit', p.dlp_enabled ? 'ok' : 'neutral')}</td>
        <td>${badge(p.malware !== false ? 'aan' : 'uit', p.malware !== false ? 'ok' : 'neutral')}</td>
        <td class="actions"><button class="btn danger" data-action="group-delete" data-group="${esc(group)}">Verwijder</button></td>
      </tr>`;
    }).join('') || `<tr><td colspan="8">${emptyState('Geen policies', 'NetBird sync of dashboard maakt groepen aan.')}</td></tr>`;

    const common = policies.all || data.common_policy || {};
    const commonRows = [
      ['Malware scanning', common.malware !== false ? 'aan' : 'uit'],
      ['DLP scanning', common.dlp_enabled !== false ? 'aan' : 'uit'],
      ['Allow domains bypass content', common.allow_domains_bypass_content ? 'aan' : 'uit'],
      ['Max body bytes', fmtNum(common.max_body_bytes)],
      ['Geblokkeerde MIME types', (common.blocked_mime_types || []).length],
      ['Allowed domains', (common.allowed_domains || []).length],
      ['Blocked domains', (common.blocked_domains || []).length],
      ['Hard blocked domains', (common.hard_blocked_domains || []).length],
    ];

    view.innerHTML = `
      <section class="panel">
        <header class="panel-head">
          <div><h2>Common policy</h2><p class="hint">Geldt voor alle groepen. Allowlist heeft altijd prioriteit.</p></div>
          <a class="btn" href="/edit?path=config.json">Bewerk volledige config</a>
        </header>
        <dl class="kvlist">${commonRows.map(r => `<dt>${esc(r[0])}</dt><dd>${esc(String(r[1]))}</dd>`).join('')}</dl>
      </section>
      <section class="panel">
        <header class="panel-head">
          <div><h2>Groepen / policies</h2><p class="hint">Maak hier eigen groepen aan of pas NetBird-groepen aan. Geen vaste basisgroepen meer.</p></div>
        </header>
        <form id="group-form" class="row">
          <label class="field"><span>Nieuwe groep</span><input name="group" placeholder="staff, byod, guest"></label>
          <label class="field"><span>Kopieer van</span>
            <select name="copy_from">
              <option value="common">Common policy</option>
              ${groups.map(g => `<option value="${esc(g)}">${esc(g)}</option>`).join('')}
            </select>
          </label>
          <button type="submit" class="primary">Groep maken</button>
        </form>
        <div class="table-wrap">
          <table class="data">
            <thead><tr><th>Groep</th><th>Categorieen</th><th>Blocks</th><th>Allowed</th><th>MIME</th><th>DLP</th><th>AV</th><th></th></tr></thead>
            <tbody>${rows}</tbody>
          </table>
        </div>
      </section>
    `;
    document.getElementById('group-form').addEventListener('submit', async (ev) => {
      ev.preventDefault();
      const fd = Object.fromEntries(new FormData(ev.target).entries());
      try { await post('/api/policy/group', { ...fd, action: 'add' }); toast('Groep aangemaakt', true); navigate('/policies', true); }
      catch (e) { toast(e.message, false); }
    });
    view.querySelectorAll('[data-action="group-delete"]').forEach(btn => {
      btn.addEventListener('click', async () => {
        if (!confirm('Groep ' + btn.dataset.group + ' verwijderen?')) return;
        try { await post('/api/policy/group', { group: btn.dataset.group, action: 'delete' }); toast('Verwijderd', true); navigate('/policies', true); }
        catch (e) { toast(e.message, false); }
      });
    });
  }

  // ---------- VIEW: DOMAINS ----------
  async function renderDomains() {
    const data = await api('/api/policy');
    const groups = ['all', ...(data.groups || [])];
    const rows = (data.domains || []).map(d => `
      <tr data-search="${esc((d.domain + ' ' + d.label + ' ' + d.list).toLowerCase())}">
        <td><strong>${esc(d.domain)}</strong></td>
        <td>${esc(d.label)}</td>
        <td>${badge(d.list === 'allowed_domains' ? 'allowlist' : (d.list === 'hard_blocked_domains' ? 'hard block' : 'block'),
          d.list === 'allowed_domains' ? 'ok' : (d.list === 'hard_blocked_domains' ? 'danger' : 'warn'))}</td>
        <td class="actions"><button class="btn danger" data-action="domain-remove" data-domain="${esc(d.domain)}" data-target="${esc(d.target)}" data-list="${esc(d.list)}">Verwijder</button></td>
      </tr>`).join('') || `<tr><td colspan="4">${emptyState('Geen domeinregels', 'Voeg hieronder een regel toe.')}</td></tr>`;

    view.innerHTML = `
      <section class="panel">
        <header class="panel-head">
          <div>
            <h2>Domeinbeheer</h2>
            <p class="hint">Allowlist heeft <strong>altijd</strong> prioriteit boven blocklist en UT1-categorieen.</p>
          </div>
        </header>
        <form id="domain-form" class="row">
          <label class="field"><span>Voor</span>
            <select name="target">${groups.map(g => `<option value="${esc(g)}">${esc(g === 'all' ? 'Alle groepen' : g)}</option>`).join('')}</select>
          </label>
          <label class="field"><span>Actie</span>
            <select name="list">
              <option value="blocked_domains">Blokkeren</option>
              <option value="hard_blocked_domains">Hard block (alle groepen)</option>
              <option value="allowed_domains">Toestaan (allowlist)</option>
            </select>
          </label>
          <label class="field"><span>Domein</span><input name="domain" placeholder="example.com of *.example.com" required></label>
          <button type="submit" class="primary">Toevoegen</button>
        </form>
      </section>
      <section class="panel">
        <header class="panel-head"><h2>Bestaande regels</h2></header>
        <input id="domain-search" class="field" placeholder="Zoek domein, groep, type" style="padding: 9px 11px; border-radius: 6px; border: 1px solid var(--border); background: var(--surface-2); color: var(--text); width: 100%;">
        <div class="table-wrap">
          <table class="data">
            <thead><tr><th>Domein</th><th>Groep</th><th>Type</th><th></th></tr></thead>
            <tbody id="domain-tbody">${rows}</tbody>
          </table>
        </div>
      </section>
    `;
    document.getElementById('domain-form').addEventListener('submit', async (ev) => {
      ev.preventDefault();
      const fd = Object.fromEntries(new FormData(ev.target).entries());
      try { await post('/api/policy/domain', { ...fd, action: 'add' }); toast('Domeinregel toegevoegd', true); navigate('/domains', true); }
      catch (e) { toast(e.message, false); }
    });
    view.querySelectorAll('[data-action="domain-remove"]').forEach(btn => {
      btn.addEventListener('click', async () => {
        try { await post('/api/policy/domain', { domain: btn.dataset.domain, target: btn.dataset.target, list: btn.dataset.list, action: 'remove' }); toast('Verwijderd', true); navigate('/domains', true); }
        catch (e) { toast(e.message, false); }
      });
    });
    document.getElementById('domain-search').addEventListener('input', (ev) => {
      const q = ev.target.value.toLowerCase();
      view.querySelectorAll('#domain-tbody tr').forEach(tr => {
        tr.style.display = (tr.dataset.search || '').includes(q) ? '' : 'none';
      });
    });
  }

  // ---------- VIEW: CATEGORIES ----------
  async function renderCategories() {
    const data = await api('/api/policy');
    const groups = ['all', ...(data.groups || [])];
    const settings = (await api('/api/settings')).settings || {};

    function paint(targetGroup, search) {
      const rows = (data.categories || []).filter(c => {
        if (!search) return true;
        const t = `${c.key} ${c.en} ${c.nl}`.toLowerCase();
        return t.includes(search);
      }).map(c => {
        const direct = c.thresholds[targetGroup] !== null && c.thresholds[targetGroup] !== undefined;
        const inherited = targetGroup !== 'all' && c.thresholds.all !== null && c.thresholds.all !== undefined;
        const value = direct ? c.thresholds[targetGroup] : (c.default_threshold || 80);
        const active = direct || inherited;
        return `<div class="category-item ${active ? 'active' : ''} risk-${esc(c.risk)}" data-cat="${esc(c.key)}">
          <div class="title">${esc(c.nl)} <span class="sub">${esc(c.en)} · ${esc(c.risk)}</span></div>
          <div class="sub">${esc(c.phrase_rules || 0)} phrases${c.phrase_file ? '' : ' · nog geen phrase file'}</div>
          ${inherited ? `<div class="sub"><span class="badge info">overge&euml;rfd van Alle groepen</span></div>` : ''}
          <div class="row">
            <input class="field threshold-input" type="number" min="1" max="999" value="${esc(value)}" style="max-width: 90px; padding: 6px 8px; border-radius: 6px; border: 1px solid var(--border); background: var(--surface); color: var(--text);">
            <button class="btn primary" data-action="cat-on" data-key="${esc(c.key)}">Blokkeer / opslaan</button>
            ${direct ? `<button class="btn danger" data-action="cat-off" data-key="${esc(c.key)}">Deblokkeer</button>` : ''}
          </div>
        </div>`;
      }).join('') || emptyState('Geen categorieen', 'Pas je zoekterm aan.');
      document.getElementById('cat-list').innerHTML = rows;
      bindCatActions();
    }
    function bindCatActions() {
      view.querySelectorAll('[data-action="cat-on"]').forEach(btn => btn.addEventListener('click', async () => {
        const item = btn.closest('.category-item');
        const threshold = item.querySelector('.threshold-input').value;
        try {
          await post('/api/policy/category', { target: document.getElementById('cat-group').value, category: btn.dataset.key, enabled: true, threshold });
          toast('Categorie opgeslagen', true);
          const updated = await api('/api/policy');
          Object.assign(data, updated);
          paint(document.getElementById('cat-group').value, document.getElementById('cat-search').value.toLowerCase());
        } catch (e) { toast(e.message, false); }
      }));
      view.querySelectorAll('[data-action="cat-off"]').forEach(btn => btn.addEventListener('click', async () => {
        try {
          await post('/api/policy/category', { target: document.getElementById('cat-group').value, category: btn.dataset.key, enabled: false });
          toast('Categorie gedeblokkeerd', true);
          const updated = await api('/api/policy');
          Object.assign(data, updated);
          paint(document.getElementById('cat-group').value, document.getElementById('cat-search').value.toLowerCase());
        } catch (e) { toast(e.message, false); }
      }));
    }

    const phrasesNote = settings.weighted_phrases_enabled ? '' : `
      <div class="empty">
        <strong>Weighted phrases staan globaal UIT.</strong>
        <span>Categorie thresholds zijn ingesteld, maar phrase-blocking is pas actief als je weighted phrases inschakelt via Instellingen.</span>
      </div>`;

    view.innerHTML = `
      <section class="panel">
        <header class="panel-head">
          <div><h2>Categorieen</h2><p class="hint">UT1-style categorieen met threshold per groep. Allowlist overrulet altijd.</p></div>
        </header>
        ${phrasesNote}
        <form class="row" onsubmit="return false;">
          <label class="field"><span>Groep</span>
            <select id="cat-group">${groups.map(g => `<option value="${esc(g)}">${esc(g === 'all' ? 'Alle groepen' : g)}</option>`).join('')}</select>
          </label>
          <label class="field"><span>Zoeken</span><input id="cat-search" placeholder="adult, malware, gokken..."></label>
        </form>
      </section>
      <section class="panel">
        <div id="cat-list" class="category-list"></div>
      </section>
    `;
    document.getElementById('cat-group').addEventListener('change', () => paint(document.getElementById('cat-group').value, document.getElementById('cat-search').value.toLowerCase()));
    document.getElementById('cat-search').addEventListener('input', () => paint(document.getElementById('cat-group').value, document.getElementById('cat-search').value.toLowerCase()));
    paint('all', '');
  }

  // ---------- VIEW: PHRASES ----------
  async function renderPhrases() {
    const [policy, settingsRes] = await Promise.all([api('/api/policy'), api('/api/settings')]);
    const settings = settingsRes.settings || {};
    const cats = policy.categories || [];
    const rows = cats.map(c => `
      <tr>
        <td><strong>${esc(c.nl)}</strong><br><span class="hint">${esc(c.en)} · ${esc(c.key)}</span></td>
        <td>${fmtNum(c.phrase_rules || 0)}</td>
        <td>${c.phrase_file ? badge('map aanwezig', 'ok') : badge('geen map', 'neutral')}</td>
        <td><span class="badge ${c.risk === 'critical' || c.risk === 'high' ? 'danger' : (c.risk === 'medium' ? 'warn' : 'neutral')}">${esc(c.risk)}</span></td>
      </tr>`).join('');

    view.innerHTML = `
      <section class="panel">
        <header class="panel-head">
          <div>
            <h2>Weighted phrases</h2>
            <p class="hint">Standaard staan weighted phrases <strong>UIT</strong>. Beheerder zet ze pas aan na het toevoegen van eigen lists.</p>
          </div>
          <div>${badge(settings.weighted_phrases_enabled ? 'globaal aan' : 'globaal uit', settings.weighted_phrases_enabled ? 'ok' : 'neutral')}</div>
        </header>
        <div class="setting-row">
          <div>
            <div class="label">Weighted phrases activeren</div>
            <div class="sub">Bij UIT worden phrase-blocking volledig overgeslagen, ook als categorieen thresholds hebben.</div>
          </div>
          <label class="toggle">
            <input type="checkbox" id="toggle-phrases" ${settings.weighted_phrases_enabled ? 'checked' : ''}>
            <span class="slider"></span>
          </label>
        </div>
      </section>
      <section class="panel">
        <header class="panel-head"><h2>Phrase mappen</h2><p class="hint">Drop eigen <code>.weightedphraselist</code> bestanden in <code>config/phrases/&lt;categorie&gt;/</code>.</p></header>
        <div class="table-wrap">
          <table class="data">
            <thead><tr><th>Categorie</th><th>Actieve regels</th><th>Map</th><th>Risk</th></tr></thead>
            <tbody>${rows || `<tr><td colspan="4">${emptyState('Geen phrases', 'Phrase mappen worden bij init aangemaakt.')}</td></tr>`}</tbody>
          </table>
        </div>
      </section>
    `;
    document.getElementById('toggle-phrases').addEventListener('change', async (ev) => {
      try {
        await post('/api/settings', { weighted_phrases_enabled: ev.target.checked });
        toast('Weighted phrases ' + (ev.target.checked ? 'aan' : 'uit'), true);
      } catch (e) { toast(e.message, false); ev.target.checked = !ev.target.checked; }
    });
  }

  // ---------- VIEW: DLP ----------
  async function renderDLP() {
    const policy = await api('/api/policy');
    const settings = (await api('/api/settings')).settings || {};
    const rules = (policy.dlp && policy.dlp.rules) || [];
    const rows = rules.map((rule, idx) => `
      <tr>
        <td><strong>${esc(rule.name)}</strong></td>
        <td><span class="badge ${rule.enabled ? 'ok' : 'neutral'}">${rule.enabled ? 'actief' : 'uit'}</span></td>
        <td class="mono">${esc(rule.builtin || rule.pattern || '')}</td>
        <td>${(rule.groups || []).length ? (rule.groups || []).map(g => `<span class="pill">${esc(g)}</span>`).join(' ') : '<span class="hint">alle groepen</span>'}</td>
        <td>${esc(rule.action || 'block')}</td>
        <td class="right">${fmtNum(rule.weight)}</td>
        <td class="actions"><button class="btn" data-action="dlp-toggle" data-idx="${idx}" data-enabled="${rule.enabled ? 'false' : 'true'}">${rule.enabled ? 'Uitzetten' : 'Aanzetten'}</button></td>
      </tr>`).join('') || `<tr><td colspan="7">${emptyState('Geen DLP regels', '')}</td></tr>`;

    view.innerHTML = `
      <section class="panel">
        <header class="panel-head">
          <div>
            <h2>Data Loss Prevention</h2>
            <p class="hint">DLP scant <strong>uitsluitend</strong> POST/PUT/PATCH request body via REQMOD. Geen URL, geen response body. Voor verdere fine-tuning bewerk <code>dlp_rules.json</code>.</p>
          </div>
          <div>${badge(settings.dlp_enabled ? 'globaal aan' : 'globaal uit', settings.dlp_enabled ? 'ok' : 'neutral')}</div>
        </header>
        <div class="table-wrap">
          <table class="data">
            <thead><tr><th>Naam</th><th>Status</th><th>Patroon / builtin</th><th>Groepen</th><th>Actie</th><th>Gewicht</th><th></th></tr></thead>
            <tbody>${rows}</tbody>
          </table>
        </div>
        <div class="actions"><a class="btn" href="/edit?path=dlp_rules.json">Geavanceerd bewerken</a></div>
      </section>
    `;
    view.querySelectorAll('[data-action="dlp-toggle"]').forEach(btn => btn.addEventListener('click', async () => {
      try { await post('/api/dlp/rule', { index: parseInt(btn.dataset.idx, 10), enabled: btn.dataset.enabled === 'true' }); toast('DLP regel aangepast', true); navigate('/dlp', true); }
      catch (e) { toast(e.message, false); }
    }));
  }

  // ---------- VIEW: SERVICES ----------
  async function renderServices() {
    const data = await api('/api/services');
    const rows = (data.services || []).map(s => `
      <div class="setting-row">
        <div>
          <div class="label">${esc(s.label)}</div>
          <div class="sub">${esc(s.detail || '')}</div>
        </div>
        <div>${badge(s.status, s.status === 'running' ? 'ok' : (s.status === 'disabled' ? 'neutral' : 'danger'))}</div>
      </div>`).join('');

    const errors = [];
    (data.phrase_load_errors || []).forEach(e => errors.push({ src: 'phrases', msg: e }));
    (data.dlp_load_errors || []).forEach(e => errors.push({ src: 'dlp', msg: e }));
    (data.event_load_errors || []).forEach(e => errors.push({ src: 'events', msg: e }));

    view.innerHTML = `
      <section class="panel">
        <header class="panel-head">
          <div><h2>Service status</h2><p class="hint">Realtime check op alle modules.</p></div>
          <div class="actions">
            <button class="btn" id="btn-reload-cfg">Config herladen</button>
            <button class="btn primary" id="btn-netbird-sync">NetBird sync triggeren</button>
          </div>
        </header>
        <div class="grid list">${rows}</div>
      </section>
      <section class="panel">
        <header class="panel-head"><h2>Foutmeldingen</h2></header>
        ${errors.length ? `<ul class="kvlist">${errors.map(e => `<li><strong>${esc(e.src)}:</strong> ${esc(e.msg)}</li>`).join('')}</ul>` : emptyState('Geen fouten gevonden', 'Alle modules zijn schoon geladen.')}
      </section>
    `;
    document.getElementById('btn-reload-cfg').addEventListener('click', async () => {
      try { await post('/api/reload', {}); toast('Configuratie herladen', true); navigate('/services', true); }
      catch (e) { toast(e.message, false); }
    });
    document.getElementById('btn-netbird-sync').addEventListener('click', async () => {
      try {
        const res = await post('/api/sync/netbird', {});
        if (res.ok) toast('NetBird sync gestart', true);
        else toast(res.message || 'Niet uitgevoerd', false);
      } catch (e) { toast(e.message, false); }
    });
  }

  // ---------- VIEW: LOGS ----------
  async function renderLogs() {
    const params = new URLSearchParams(location.search);
    view.innerHTML = `
      <section class="panel">
        <header class="panel-head">
          <div><h2>Logs &amp; events</h2><p class="hint">Persistent opgeslagen in <code>events.jsonl</code>. Filter resultaten hieronder.</p></div>
        </header>
        <form id="log-filter" class="row">
          <label class="field"><span>Zoek</span><input name="q" placeholder="vrij zoeken"></label>
          <label class="field"><span>Gebruiker</span><input name="user"></label>
          <label class="field"><span>IP</span><input name="ip"></label>
          <label class="field"><span>Domein / URL</span><input name="domain"></label>
          <label class="field"><span>Categorie</span><input name="category"></label>
          <label class="field"><span>Actie</span><select name="action"><option value="">Alles</option><option value="allow">allow</option><option value="block">block</option></select></label>
          <label class="field"><span>Reden</span><input name="status" placeholder="malware, dlp, phrase, domain..."></label>
          <label class="field"><span>Incident</span><input name="incident_id"></label>
          <label class="field"><span>Van</span><input name="from" type="datetime-local"></label>
          <label class="field"><span>Tot</span><input name="to" type="datetime-local"></label>
          <label class="field"><span>Limiet</span><input name="limit" type="number" value="500" min="1" max="5000"></label>
          <button class="btn primary" type="submit">Filteren</button>
        </form>
      </section>
      <section class="panel">
        <header class="panel-head"><h2 id="log-count">Resultaten</h2></header>
        <div id="log-results" class="grid list"><div class="empty">Laden…</div></div>
      </section>
    `;
    const form = document.getElementById('log-filter');
    ['q','user','ip','domain','category','action','status','incident_id','from','to','limit'].forEach(k => {
      if (params.get(k)) form.elements[k].value = params.get(k);
    });
    async function runFilter(ev) {
      if (ev) ev.preventDefault();
      const fd = new FormData(form);
      const qs = new URLSearchParams();
      for (const [k, v] of fd.entries()) if (v) qs.set(k, v);
      const data = await api('/api/logs?' + qs.toString());
      document.getElementById('log-count').textContent = `${fmtNum(data.filtered_count)} van ${fmtNum(data.total_on_disk)} events`;
      const rows = (data.events || []).map(e => {
        const cat = (e.details && e.details.category) || '';
        return `<details class="event-row" style="display: block;"><summary style="display: grid; grid-template-columns: 140px 1fr auto; gap: 12px; cursor: pointer; align-items: center;">
          <span class="ts">${esc(fmtTs(e.ts))}</span>
          <span class="meta">
            <strong>${esc(e.user || 'anoniem')}</strong> → <strong>${esc(e.domain || '')}</strong>
            <br><span class="hint">${esc(e.url || '')}</span>
          </span>
          <span>${badge(e.action, e.action === 'block' ? 'danger' : 'ok')} ${cat ? badge(cat, 'warn') : ''}</span>
        </summary>
        <div style="padding: 10px 14px; background: var(--surface); border-top: 1px solid var(--border); border-radius: 0 0 6px 6px;">
          <dl class="kvlist">
            <dt>Incident ID</dt><dd class="mono">${esc(e.incident_id || '')}</dd>
            <dt>Reden</dt><dd>${esc(e.reason || '')}</dd>
            <dt>Public reason</dt><dd>${esc(e.public_reason || '')}</dd>
            <dt>Policy</dt><dd>${esc(e.policy || '')}</dd>
            <dt>Methode</dt><dd>${esc(e.method || '')}</dd>
            <dt>Source IP</dt><dd class="mono">${esc(e.source_ip || '')}</dd>
            <dt>Groepen</dt><dd>${(e.groups || []).join(', ')}</dd>
            <dt>Content-Type</dt><dd>${esc(e.content_type || '')}</dd>
            <dt>Body bytes</dt><dd>${fmtNum(e.body_bytes)}</dd>
            <dt>ClamAV</dt><dd>${esc((e.clam && e.clam.status) || '')} ${e.clam && e.clam.signature ? '— ' + esc(e.clam.signature) : ''}</dd>
            <dt>Phrase hits</dt><dd>${(e.phrase_hits || []).map(h => `<span class="pill">${esc(h.category)}: ${esc(h.phrase)} ×${esc(h.count)}</span>`).join(' ') || '<span class="hint">geen</span>'}</dd>
            <dt>DLP hits</dt><dd>${(e.dlp_hits || []).map(h => `<span class="pill">${esc(h.name)} ×${esc(h.count)}</span>`).join(' ') || '<span class="hint">geen</span>'}</dd>
            <dt>Details</dt><dd class="mono">${esc(JSON.stringify(e.details || {}))}</dd>
          </dl>
        </div></details>`;
      }).join('') || emptyState('Geen logs gevonden', 'Pas filters aan of voer eerst verkeer door de ICAP service.');
      document.getElementById('log-results').innerHTML = rows;
    }
    form.addEventListener('submit', runFilter);
    runFilter();
  }

  // ---------- VIEW: SETTINGS ----------
  async function renderSettings() {
    const data = await api('/api/settings');
    const settings = data.settings || {};
    const toggles = [
      ['webfilter_enabled', 'Webfilter', 'Master toggle voor content filtering en domeinblokkering.'],
      ['domain_blocking_enabled', 'Domeinblokkering', 'Schakel blocklist/UT1 in of uit. Allowlist blijft altijd doorlopen.'],
      ['weighted_phrases_enabled', 'Weighted phrases', 'Standaard UIT. Zet pas aan na het toevoegen van eigen phrase lists.'],
      ['dlp_enabled', 'Data Loss Prevention', 'DLP scant enkel POST/PUT/PATCH body via REQMOD.'],
      ['antivirus_enabled', 'Antivirus (ClamAV)', 'ClamAV scanning voor request en response body.'],
      ['logging_enabled', 'Logging', 'Persistente event logs naar events.jsonl.'],
      ['netbird_sync_enabled', 'NetBird sync', 'Backend timer-service sync_netbird_users.py.'],
    ];
    const rows = toggles.map(([key, label, sub]) => `
      <div class="setting-row">
        <div>
          <div class="label">${esc(label)}</div>
          <div class="sub">${esc(sub)}</div>
        </div>
        <label class="toggle">
          <input type="checkbox" data-key="${esc(key)}" ${settings[key] ? 'checked' : ''}>
          <span class="slider"></span>
        </label>
      </div>`).join('');

    view.innerHTML = `
      <section class="panel">
        <header class="panel-head">
          <div><h2>Master-toggles</h2><p class="hint">Wijzigingen worden direct opgeslagen in <code>config.json</code>.</p></div>
        </header>
        <div class="grid list">${rows}</div>
      </section>
      <section class="panel">
        <header class="panel-head"><h2>Extra opties</h2></header>
        <div class="setting-row">
          <div><div class="label">Allow domains bypass content</div><div class="sub">Allowlist mag verdere content-scans overslaan. Verzekert dat allowlist boven blocklist staat.</div></div>
          <label class="toggle"><input type="checkbox" id="opt-bypass" ${data.allow_domains_bypass_content ? 'checked' : ''}><span class="slider"></span></label>
        </div>
        <div class="setting-row">
          <div><div class="label">ClamAV fail open</div><div class="sub">Bij scanner fout verkeer toelaten in plaats van blokkeren.</div></div>
          <label class="toggle"><input type="checkbox" id="opt-clam-failopen" ${data.clamav_fail_open ? 'checked' : ''}><span class="slider"></span></label>
        </div>
      </section>
      <section class="panel">
        <header class="panel-head"><h2>Geavanceerd</h2></header>
        <div class="actions">
          <a class="btn" href="/edit?path=config.json">Bewerk config.json</a>
          <a class="btn" href="/edit?path=users.json">Bewerk users.json</a>
          <a class="btn" href="/edit?path=dlp_rules.json">Bewerk dlp_rules.json</a>
        </div>
      </section>
    `;
    view.querySelectorAll('input[type="checkbox"][data-key]').forEach(inp => {
      inp.addEventListener('change', async () => {
        try { await post('/api/settings', { [inp.dataset.key]: inp.checked }); toast(inp.dataset.key + ': ' + (inp.checked ? 'aan' : 'uit'), true); }
        catch (e) { toast(e.message, false); inp.checked = !inp.checked; }
      });
    });
    document.getElementById('opt-bypass').addEventListener('change', async (ev) => {
      try { await post('/api/settings', { allow_domains_bypass_content: ev.target.checked }); toast('Allowlist bypass: ' + (ev.target.checked ? 'aan' : 'uit'), true); }
      catch (e) { toast(e.message, false); ev.target.checked = !ev.target.checked; }
    });
    document.getElementById('opt-clam-failopen').addEventListener('change', async (ev) => {
      try { await post('/api/settings', { clamav_fail_open: ev.target.checked }); toast('ClamAV fail open: ' + (ev.target.checked ? 'aan' : 'uit'), true); }
      catch (e) { toast(e.message, false); ev.target.checked = !ev.target.checked; }
    });
  }

  // ---------- VIEW: TEST ----------
  async function renderTest() {
    view.innerHTML = `
      <section class="panel">
        <header class="panel-head"><h2>Policy test</h2><p class="hint">Simuleer een ICAP-aanvraag zonder live verkeer.</p></header>
        <form id="test-form" class="row">
          <label class="field"><span>URL</span><input name="url" value="https://example.org/"></label>
          <label class="field"><span>Gebruiker</span><input name="user" value=""></label>
          <label class="field"><span>Groepen</span><input name="groups" value=""></label>
          <label class="field"><span>Methode/direction</span>
            <select name="direction"><option value="reqmod">REQMOD</option><option value="respmod">RESPMOD</option></select>
          </label>
          <label class="field"><span>HTTP methode</span>
            <select name="http_method"><option value="POST">POST</option><option value="PUT">PUT</option><option value="PATCH">PATCH</option><option value="GET">GET</option></select>
          </label>
          <label class="field"><span>Content-Type</span><input name="content_type" value="text/plain"></label>
          <label class="check"><input name="skip_clamav" type="checkbox" checked> ClamAV overslaan</label>
          <label class="field" style="grid-column: 1 / -1"><span>Body</span><textarea name="body">casino test</textarea></label>
          <button class="btn primary" type="submit">Run test</button>
        </form>
      </section>
      <section class="panel">
        <header class="panel-head"><h2>Resultaat</h2></header>
        <pre id="test-result" style="background: var(--surface-2); padding: 14px; border-radius: 8px; border: 1px solid var(--border); max-height: 60vh; overflow: auto; font-family: ui-monospace, Consolas, monospace; font-size: 12px;"></pre>
      </section>
    `;
    document.getElementById('test-form').addEventListener('submit', async (ev) => {
      ev.preventDefault();
      const fd = new FormData(ev.target);
      const data = Object.fromEntries(fd.entries());
      if (!fd.has('skip_clamav')) data.skip_clamav = 'off';
      try {
        const res = await fetch('/api/test', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(data) });
        const json = await res.json();
        document.getElementById('test-result').textContent = JSON.stringify(json, null, 2);
      } catch (e) { document.getElementById('test-result').textContent = e.message; }
    });
  }

  // ---------- VIEW: FILES ----------
  async function renderFiles() {
    const data = await api('/api/files');
    const rows = (data.files || []).map(f => `
      <tr>
        <td><a href="/edit?path=${encodeURIComponent(f.path)}"><strong>${esc(f.path)}</strong></a></td>
        <td>${fmtNum(f.size)} bytes</td>
        <td class="mono">${esc(f.mtime)}</td>
        <td class="actions"><a class="btn" href="/edit?path=${encodeURIComponent(f.path)}">Bewerk</a></td>
      </tr>`).join('') || `<tr><td colspan="4">${emptyState('Geen bewerkbare bestanden', '')}</td></tr>`;
    view.innerHTML = `
      <section class="panel">
        <header class="panel-head">
          <div><h2>Bestanden</h2><p class="hint">Configbestanden in <code>config/</code>. Automatische backup bij elke save.</p></div>
        </header>
        <div class="table-wrap">
          <table class="data"><thead><tr><th>Pad</th><th>Grootte</th><th>Gewijzigd</th><th></th></tr></thead><tbody>${rows}</tbody></table>
        </div>
      </section>
    `;
  }

  // Link interception: any <a data-route> inside the view navigates without reload
  function bindRouteLinks() {
    view.querySelectorAll('a[data-route]').forEach(a => a.addEventListener('click', (ev) => {
      ev.preventDefault();
      navigate(a.dataset.route);
    }));
  }
  document.body.addEventListener('click', (ev) => {
    const a = ev.target.closest('a[data-route]');
    if (a && view.contains(a)) {
      ev.preventDefault();
      navigate(a.dataset.route);
    }
  });

  // initial render
  navigate(location.pathname, true);
})();
"""


# Uitgebreide ingebouwde phrase seeds voor alle E2Guardian-categorieën.
# Deze seeds zijn bedoeld als veilige, onderhoudbare basis voor labo/PoC-gebruik.
# Zet officiële of school-specifieke e2guardian/DansGuardian lijsten gewoon in
# config/phrases/<categorie>/ als extra .weightedphraselist-bestanden.
DEFAULT_ENGLISH_PHRASE_SEEDS: dict[str, list[str]] = {
    "adult": ["explicit adult", "adult content", "adult website", "mature content", "sexually explicit", "nsfw content", "adult chat", "adult webcam", "adult dating", "erotic story"],
    "pornography": ["porn", "pornography", "xxx", "sex video", "adult video", "explicit sex", "porn site", "hardcore adult", "adult movie", "cam site"],
    "mixed_adult": ["adult forum", "adult gallery", "erotic images", "adult personals", "adult classifieds", "adult entertainment", "adult jokes", "adult community"],
    "nudity": ["nude", "nudity", "naked", "explicit image", "nude gallery", "nude photo", "naked picture", "bare body"],
    "dating": ["dating", "dating app", "singles near you", "matchmaking", "hookup", "flirt chat", "casual dating", "meet singles"],
    "gambling": ["gambling", "casino", "online casino", "sports betting", "betting odds", "roulette", "blackjack", "poker room", "slot machine", "jackpot"],
    "games": ["online game", "browser game", "gaming portal", "game cheat", "game walkthrough", "free games", "flash game", "multiplayer game"],
    "alcohol": ["alcohol", "beer", "wine", "liquor", "vodka", "whiskey", "cocktail", "happy hour", "brewery", "spirits"],
    "tobacco": ["tobacco", "cigarette", "cigar", "smoking", "vape", "vaping", "nicotine", "e-cigarette", "rolling tobacco"],
    "drugs": ["drugs", "drug use", "drug dealer", "drug recipe", "get high", "narcotics", "drug forum", "pill vendor"],
    "weapons": ["weapon", "firearm", "gun", "knife attack", "ammunition", "explosive", "homemade weapon", "silencer", "rifle", "pistol"],
    "violence": ["violence", "violent video", "fight video", "assault", "brutal attack", "blood fight", "street fight", "graphic violence"],
    "hate": ["hate speech", "extremist", "white supremacy", "neo nazi", "racist propaganda", "terror praise", "violent ideology", "genocide denial"],
    "aggressive": ["aggressive language", "threat", "verbal abuse", "harassment", "bullying", "intimidation", "attack someone", "violent threat"],
    "badwords": ["profanity", "swear words", "offensive language", "curse words", "vulgar language", "insults", "abusive words"],
    "conspiracy": ["conspiracy theory", "false flag", "secret agenda", "deep state", "hoax theory", "cover up", "hidden cabal"],
    "domainsforsale": ["domain for sale", "buy this domain", "this domain is parked", "parking page", "premium domain", "domain marketplace"],
    "drugadvocacy": ["drug legalization", "pro drug", "drug advocacy", "safe drug use", "drug culture", "drug forum", "drug experience"],
    "googlesearches": ["search results", "google search", "did you mean", "people also ask", "related searches", "search query"],
    "gore": ["gore", "graphic injury", "blood and gore", "mutilation", "accident photos", "graphic death", "shock video"],
    "idtheft": ["identity theft", "stolen identity", "credit card dump", "ssn lookup", "phishing kit", "personal data leak", "credential dump"],
    "illegaldrugs": ["illegal drugs", "cocaine", "heroin", "meth", "ecstasy", "mdma", "lsd", "drug market", "buy pills"],
    "intolerance": ["intolerance", "racist content", "discriminatory speech", "religious hatred", "xenophobia", "homophobia", "antisemitism"],
    "legaldrugs": ["prescription drug", "painkiller", "sleeping pills", "legal highs", "pharmacy without prescription", "stimulants", "sedatives"],
    "malware": ["malware", "virus download", "trojan", "payload.exe", "keylogger", "ransomware", "botnet", "disable antivirus", "download crack"],
    "phishing": ["phishing", "verify your account", "password reset link", "account suspended", "login to confirm", "credential harvest", "fake login"],
    "spyware": ["spyware", "stalkerware", "hidden tracker", "monitor phone", "stealth keylogger", "spy app", "remote surveillance"],
    "hacking": ["hacking", "exploit", "sql injection", "xss payload", "password cracker", "bruteforce", "privilege escalation", "reverse shell"],
    "warez": ["warez", "pirated software", "serial key", "keygen", "crack download", "torrent crack", "activation bypass"],
    "proxy": ["proxy avoidance", "bypass proxy", "unblock website", "web proxy", "proxy site", "filter bypass", "circumvent filter"],
    "anonvpn": ["anonymous vpn", "no log vpn", "hide ip", "vpn bypass", "privacy vpn", "stealth vpn", "anonymous browsing"],
    "redirector": ["redirector", "redirect link", "interstitial redirect", "forwarding URL", "tracking redirect", "click redirect"],
    "url_shorteners": ["url shortener", "short link", "bitly", "tinyurl", "shortened url", "link shortener"],
    "filehosting": ["file hosting", "download mirror", "upload files", "file sharing", "free download host", "cloud file link"],
    "peer2peer": ["peer to peer", "p2p", "torrent", "magnet link", "bittorrent", "seeders", "leechers"],
    "personals": ["personals", "personal ads", "dating profile", "meet local", "singles ad", "private contact"],
    "proxies": ["proxies", "open proxy", "proxy list", "socks proxy", "free proxy", "elite proxy", "proxy server"],
    "remote_access": ["remote access", "remote desktop", "rdp", "teamviewer", "anydesk", "vnc", "remote control"],
    "ads": ["advertisement", "ad banner", "sponsored link", "click here ad", "ad network", "marketing pixel", "popup ad"],
    "tracking": ["tracking pixel", "analytics tracker", "third party tracking", "behavioral tracking", "visitor tracking", "fingerprinting"],
    "social_networking": ["social networking", "social media", "facebook", "instagram", "tiktok", "snapchat", "follow me", "share post"],
    "chat": ["chat room", "instant message", "private chat", "live chat", "chat app", "group chat", "message me"],
    "forums": ["forum", "discussion board", "thread", "reply post", "community forum", "user forum"],
    "blogs": ["blog", "blog post", "personal blog", "blog archive", "comments section", "wordpress"],
    "webmail": ["webmail", "inbox", "compose email", "mail login", "email account", "sent mail", "attachments"],
    "audio_video": ["audio video", "watch video", "play video", "stream audio", "media player", "video clip", "movie clip"],
    "music": ["music", "song", "album", "lyrics", "mp3", "stream music", "playlist", "music video"],
    "streaming": ["streaming", "live stream", "watch online", "video streaming", "stream movie", "stream episode"],
    "webtv": ["web tv", "online tv", "tv stream", "watch television", "live channel", "broadcast stream"],
    "searchengines": ["search engine", "search results", "web search", "query results", "search page"],
    "shopping": ["shopping", "add to cart", "checkout", "buy now", "online store", "product page", "discount code"],
    "finance": ["finance", "stock market", "investment", "loan", "credit score", "trading account", "crypto price"],
    "banking": ["banking", "online banking", "bank login", "wire transfer", "account balance", "iban", "bank statement"],
    "news": ["news", "breaking news", "headline", "newspaper", "press release", "journalist", "article"],
    "education": ["education", "school", "lesson", "course", "homework", "student portal", "learning platform"],
    "kids": ["kids", "children", "cartoon", "kids game", "child friendly", "school kids", "nursery"],
    "health": ["health", "wellness", "fitness", "symptoms", "doctor advice", "healthy living", "diet plan"],
    "medical": ["medical", "diagnosis", "medicine", "hospital", "clinic", "patient", "treatment", "medical advice"],
    "government": ["government", "public service", "municipality", "tax office", "official form", "minister", "parliament"],
    "legal": ["legal", "lawyer", "court", "law firm", "contract", "legal advice", "case law"],
    "jobsearch": ["job search", "vacancy", "apply now", "career", "resume", "cover letter", "recruiter"],
    "religion": ["religion", "church", "mosque", "temple", "faith", "prayer", "scripture"],
    "sports": ["sports", "football", "basketball", "tennis", "match score", "league table", "training"],
    "sport": ["sport", "football", "cycling", "running", "match", "team", "competition"],
    "travel": ["travel", "flight", "hotel booking", "vacation", "tourism", "train ticket", "travel guide"],
    "translation": ["translation", "translate", "dictionary", "language tool", "translated text", "machine translation"],
    "rta": ["restricted to adults", "adult rating", "rta label", "mature audience", "age restricted"],
    "safelabel": ["safe label", "self rating", "content rating", "parental guidance", "safe browsing label"],
    "secretsocieties": ["secret society", "hidden order", "masonic lodge", "secret ritual", "occult society"],
    "upstreamfilter": ["upstream filter", "filtered by provider", "blocked by upstream", "content filter notice"],
    "warezhacking": ["warez hacking", "crack exploit", "keygen exploit", "piracy hacking", "illegal software exploit"],
    "goodphrases": ["education", "school project", "medical awareness", "security training", "research purpose", "news report", "awareness campaign"],
}

DEFAULT_DUTCH_PHRASE_SEEDS: dict[str, list[str]] = {
    "adult": ["volwassen inhoud", "expliciete inhoud", "adult website", "seksueel expliciet", "nsfw inhoud", "adult chat", "adult webcam", "erotisch verhaal"],
    "pornography": ["porno", "pornografie", "xxx", "seks video", "adult video", "pornosite", "hardcore adult", "cam site"],
    "mixed_adult": ["adult forum", "adult galerij", "erotische beelden", "adult advertenties", "adult entertainment", "adult community"],
    "nudity": ["naakt", "naaktheid", "naked", "expliciete afbeelding", "naaktfoto", "bloot lichaam"],
    "dating": ["dating", "dating app", "singles", "matchmaking", "flirt chat", "casual dating", "ontmoet singles"],
    "gambling": ["gokken", "casino", "online casino", "sportweddenschappen", "wedkantoor", "roulette", "blackjack", "poker", "slotmachine", "jackpot"],
    "games": ["online spel", "browser game", "gaming portal", "game cheat", "spelletjes", "gratis games", "multiplayer game"],
    "alcohol": ["alcohol", "bier", "wijn", "sterke drank", "vodka", "whisky", "cocktail", "happy hour", "brouwerij"],
    "tobacco": ["tabak", "sigaret", "sigaar", "roken", "vape", "vapen", "nicotine", "e-sigaret", "roltabak"],
    "drugs": ["drugs", "druggebruik", "drugdealer", "drugs recept", "high worden", "verdovende middelen", "drugs forum"],
    "weapons": ["wapen", "vuurwapen", "pistool", "mes aanval", "munitie", "explosief", "zelfgemaakt wapen", "geweer"],
    "violence": ["geweld", "gewelddadige video", "vechtvideo", "aanval", "brutale aanval", "straatvechtpartij", "grafisch geweld"],
    "hate": ["haatspraak", "extremistisch", "witte suprematie", "neonazi", "racistische propaganda", "terreur verheerlijking", "gewelddadige ideologie"],
    "aggressive": ["agressieve taal", "bedreiging", "verbale agressie", "intimidatie", "pesten", "iemand aanvallen", "gewelddadige bedreiging"],
    "badwords": ["scheldwoorden", "vloeken", "beledigende taal", "grove taal", "vulgaire taal", "beledigingen"],
    "conspiracy": ["complottheorie", "valse vlag", "geheime agenda", "deep state", "hoax theorie", "doofpot", "verborgen cabal"],
    "domainsforsale": ["domein te koop", "koop dit domein", "dit domein is geparkeerd", "parkeerpagina", "premium domein"],
    "drugadvocacy": ["drugslegalisatie", "pro drugs", "drugsverheerlijking", "veilig druggebruik", "drugscultuur", "drugs forum"],
    "googlesearches": ["zoekresultaten", "google zoekopdracht", "bedoelde u", "mensen vragen ook", "gerelateerde zoekopdrachten"],
    "gore": ["gore", "grafisch letsel", "bloed en gore", "verminking", "ongeval fotos", "grafische dood", "shock video"],
    "idtheft": ["identiteitsdiefstal", "gestolen identiteit", "creditcard dump", "phishing kit", "persoonlijke data lek", "credential dump"],
    "illegaldrugs": ["illegale drugs", "cocaine", "heroine", "meth", "xtc", "mdma", "lsd", "drugsmarkt", "pillen kopen"],
    "intolerance": ["intolerantie", "racistische inhoud", "discriminerende taal", "religieuze haat", "xenofobie", "homofobie", "antisemitisme"],
    "legaldrugs": ["voorschrift medicijn", "pijnstiller", "slaappillen", "legale drugs", "apotheek zonder voorschrift", "stimulerende middelen"],
    "malware": ["malware", "virus download", "trojan", "payload.exe", "keylogger", "ransomware", "botnet", "antivirus uitschakelen", "crack downloaden"],
    "phishing": ["phishing", "verifieer uw account", "wachtwoord reset link", "account geschorst", "login om te bevestigen", "valse login"],
    "spyware": ["spyware", "stalkerware", "verborgen tracker", "telefoon monitoren", "stealth keylogger", "spionage app"],
    "hacking": ["hacken", "exploit", "sql injection", "xss payload", "wachtwoord kraker", "bruteforce", "privilege escalation", "reverse shell"],
    "warez": ["warez", "illegale software", "serienummer", "keygen", "crack download", "torrent crack", "activatie omzeilen"],
    "proxy": ["proxy omzeiling", "proxy bypass", "website deblokkeren", "web proxy", "proxy site", "filter omzeilen"],
    "anonvpn": ["anonieme vpn", "no log vpn", "ip verbergen", "vpn bypass", "privacy vpn", "stealth vpn", "anoniem browsen"],
    "redirector": ["redirector", "redirect link", "doorverwijzing", "forwarding url", "tracking redirect"],
    "url_shorteners": ["url verkorter", "korte link", "bitly", "tinyurl", "verkorte url", "link shortener"],
    "filehosting": ["bestandshosting", "download mirror", "bestanden uploaden", "bestanden delen", "gratis download host"],
    "peer2peer": ["peer to peer", "p2p", "torrent", "magnet link", "bittorrent", "seeders", "leechers"],
    "personals": ["contactadvertenties", "persoonlijke advertenties", "datingprofiel", "lokale singles", "prive contact"],
    "proxies": ["proxies", "open proxy", "proxy lijst", "socks proxy", "gratis proxy", "elite proxy", "proxyserver"],
    "remote_access": ["remote toegang", "extern bureaublad", "rdp", "teamviewer", "anydesk", "vnc", "remote control"],
    "ads": ["advertentie", "reclamebanner", "gesponsorde link", "klik hier advertentie", "ad network", "marketing pixel", "popup reclame"],
    "tracking": ["tracking pixel", "analytics tracker", "third party tracking", "gedrags tracking", "bezoekers tracking", "fingerprinting"],
    "social_networking": ["sociale media", "sociaal netwerk", "facebook", "instagram", "tiktok", "snapchat", "volg mij", "deel bericht"],
    "chat": ["chatroom", "instant message", "prive chat", "live chat", "chat app", "groepschat", "stuur bericht"],
    "forums": ["forum", "discussiebord", "thread", "reactie plaatsen", "community forum", "gebruikersforum"],
    "blogs": ["blog", "blogpost", "persoonlijke blog", "blogarchief", "reactiesectie", "wordpress"],
    "webmail": ["webmail", "inbox", "email opstellen", "mail login", "email account", "verzonden mail", "bijlagen"],
    "audio_video": ["audio video", "video bekijken", "video afspelen", "audio streamen", "mediaplayer", "videoclip"],
    "music": ["muziek", "lied", "album", "songtekst", "mp3", "muziek streamen", "playlist", "muziekvideo"],
    "streaming": ["streaming", "live stream", "online kijken", "video streaming", "film streamen", "aflevering streamen"],
    "webtv": ["web tv", "online tv", "tv stream", "televisie kijken", "live kanaal", "uitzending stream"],
    "searchengines": ["zoekmachine", "zoekresultaten", "web zoeken", "query resultaten", "zoekpagina"],
    "shopping": ["winkelen", "toevoegen aan winkelwagen", "afrekenen", "nu kopen", "online winkel", "productpagina", "kortingscode"],
    "finance": ["financien", "beurs", "investering", "lening", "kredietscore", "trading account", "crypto prijs"],
    "banking": ["bankieren", "online banking", "bank login", "overschrijving", "rekeningsaldo", "iban", "bankafschrift"],
    "news": ["nieuws", "breaking news", "headline", "krant", "persbericht", "journalist", "artikel"],
    "education": ["onderwijs", "school", "les", "cursus", "huiswerk", "studentenportaal", "leerplatform"],
    "kids": ["kinderen", "kids", "cartoon", "kinderspel", "kindvriendelijk", "schoolkinderen", "kleuters"],
    "health": ["gezondheid", "wellness", "fitness", "symptomen", "doktersadvies", "gezond leven", "dieetplan"],
    "medical": ["medisch", "diagnose", "medicijn", "ziekenhuis", "kliniek", "patient", "behandeling", "medisch advies"],
    "government": ["overheid", "publieke dienst", "gemeente", "belastingdienst", "officieel formulier", "minister", "parlement"],
    "legal": ["juridisch", "advocaat", "rechtbank", "advocatenkantoor", "contract", "juridisch advies", "rechtspraak"],
    "jobsearch": ["vacatures", "job zoeken", "solliciteer nu", "carriere", "cv", "motivatiebrief", "recruiter"],
    "religion": ["religie", "kerk", "moskee", "tempel", "geloof", "gebed", "geschrift"],
    "sports": ["sport", "voetbal", "basketbal", "tennis", "wedstrijdscore", "ranglijst", "training"],
    "sport": ["sport", "voetbal", "wielrennen", "lopen", "wedstrijd", "team", "competitie"],
    "travel": ["reizen", "vlucht", "hotel boeken", "vakantie", "toerisme", "treinticket", "reisgids"],
    "translation": ["vertaling", "vertalen", "woordenboek", "taaltool", "vertaalde tekst", "machinevertaling"],
    "rta": ["alleen volwassenen", "adult rating", "rta label", "volwassen publiek", "leeftijdsbeperking"],
    "safelabel": ["safe label", "zelfclassificatie", "content rating", "ouderlijk toezicht", "veilig browsen label"],
    "secretsocieties": ["geheim genootschap", "verborgen orde", "vrijmetselaarsloge", "geheim ritueel", "occulte vereniging"],
    "upstreamfilter": ["upstream filter", "gefilterd door provider", "geblokkeerd door upstream", "content filter melding"],
    "warezhacking": ["warez hacking", "crack exploit", "keygen exploit", "piraterij hacking", "illegale software exploit"],
    "goodphrases": ["onderwijs", "schoolproject", "medische bewustwording", "security training", "onderzoeksdoel", "nieuwsbericht", "bewustwordingscampagne"],
}


def default_phrase_thresholds(multiplier: float = 1.0) -> dict[str, int]:
    thresholds: dict[str, int] = {}
    for entry in E2G_CATEGORY_CATALOG:
        if entry.get("risk") == "allow":
            continue
        thresholds[entry["key"]] = max(35, int(entry.get("default_threshold", 80) * multiplier))
    return thresholds


def build_default_phrase_file(category: str, language: str) -> str:
    """
    Bouw een LEGE weighted phrase placeholder voor de gegeven categorie.

    Belangrijk: standaard worden er GEEN phrases geactiveerd. De beheerder
    voegt later zelf eigen phrase lists toe. Dit bestand bevat enkel een
    listcategory header en commentaar zodat de structuur duidelijk blijft.
    """
    entry = catalog_entry(category)
    key = entry["key"]
    label_en = entry.get("en", key)
    label_nl = entry.get("nl", key)
    lines = [
        f'#listcategory: "{key}"',
        f"# Weighted phrase placeholder voor categorie: {label_en} / {label_nl}.",
        f"# Standaard zijn er GEEN actieve phrases voor deze categorie.",
        "# Voeg eigen regels toe in de vorm: {weight}<zin of woord>.",
        "# Positief gewicht verhoogt de score (blokkeren), negatief verlaagt.",
        "# Voorbeelden:",
        f"# {{30}}<voorbeeld zin voor {key}>",
        "# {-30}<veilige educatieve context>",
    ]
    return "\n".join(lines).rstrip() + "\n"

def default_config() -> dict[str, Any]:
    return {
        "server": {
            "icap_host": "0.0.0.0",
            "icap_port": 13440,
            "dashboard_host": "127.0.0.1",
            "dashboard_port": 8088,
            "dashboard_token": "change-me",
            "preview_bytes": 4096,
            "max_body_bytes": DEFAULT_BODY_LIMIT,
        },
        # Globale master-toggles. Bewust geplaatst zodat het dashboard ze
        # eenvoudig kan tonen/aanpassen. Weighted phrases staat standaard
        # UIT en moet expliciet aangezet worden door de beheerder.
        "settings": {
            "webfilter_enabled": True,
            "domain_blocking_enabled": True,
            "weighted_phrases_enabled": False,
            "dlp_enabled": True,
            "antivirus_enabled": True,
            "logging_enabled": True,
            "netbird_sync_enabled": True,
        },
        "scan": {
            "text_scan_bytes": DEFAULT_TEXT_SCAN_BYTES,
        },
        "clamav": {
            "enabled": True,
            "host": "127.0.0.1",
            "port": 3310,
            "unix_socket": "",
            "timeout_seconds": 30,
            "max_scan_bytes": DEFAULT_BODY_LIMIT,
            "fail_open": False,
        },
        "phrase_lists": {
            "default_weight": 10,
            "extensions": [".weightedphraselist", ".phraselist", ".txt"],
            "match_individual_tags": False,
        },
        "identity": {
            # Default group wordt enkel gebruikt als er geen NetBird-/Entra
            # info beschikbaar is. Het maakt geen policy aan; gebruikers
            # zonder bekende groep vallen terug op common_policy.
            "default_group": "default",
            "client_ip_headers": ["X-Client-IP", "X-Forwarded-For", "X-Real-IP"],
            "username_headers": ["X-Client-Username", "X-Authenticated-User", "X-Squid-Username"],
            "http_username_headers": ["X-NetBird-User", "X-Authenticated-User"],
            "entra_object_headers": ["X-Entra-Object-Id", "X-MS-CLIENT-PRINCIPAL-ID"],
            "entra_group_headers": ["X-Entra-Groups", "X-MS-CLIENT-PRINCIPAL-GROUPS"],
            "entra_group_map": {},
        },
        "common_policy": {
            "malware": True,
            "dlp_enabled": True,
            "dlp_score_threshold": 60,
            "max_body_bytes": DEFAULT_BODY_LIMIT,
            "oversize_action": "allow",
            # Geen voorbeelddomeinen in default - beheerder vult zelf in.
            "hard_blocked_domains": [],
            "blocked_domains": [],
            "allowed_domains": [],
            # Allowlist moet ALTIJD prioriteit hebben en mag content-scans
            # overslaan. Daarom standaard True.
            "allow_domains_bypass_content": True,
            "blocked_mime_types": [
                "application/x-msdownload",
                "application/x-dosexec",
                "application/vnd.microsoft.portable-executable",
            ],
            # Phrase thresholds zijn standaard leeg. Beheerder activeert
            # ze pas wanneer weighted phrases bewust aanstaat.
            "phrase_thresholds": {},
        },
        # GEEN default student/teacher policies. NetBird-groepen worden via
        # sync_netbird_users.py aangemaakt, en de beheerder maakt zelf
        # eigen groepen aan via het dashboard.
        "policies": {},
    }


def default_users() -> dict[str, Any]:
    return {
        "users": {},
        "ip_map": {},
        "entra_object_map": {},
    }


def default_dlp_rules() -> dict[str, Any]:
    return {
        "rules": [
            {
                "name": "Credit card number",
                "enabled": True,
                "builtin": "credit_card_luhn",
                "weight": 70,
                "min_matches": 1,
                "action": "block",
                "groups": [],
            },
            {
                "name": "Belgian national register number",
                "enabled": True,
                "builtin": "belgian_rrn",
                "weight": 60,
                "min_matches": 1,
                "action": "block",
                "groups": [],
            },
            {
                "name": "IBAN",
                "enabled": True,
                "builtin": "iban",
                "weight": 35,
                "min_matches": 2,
                "action": "block",
                "groups": [],
            },
            {
                "name": "Password leak wording",
                "enabled": True,
                "pattern": "\\b(password|passwd|pwd)\\s*[:=]\\s*\\S{6,}",
                "weight": 40,
                "min_matches": 1,
                "action": "block",
                "groups": [],
            },
        ]
    }


DEFAULT_ADULT_PHRASES = """#listcategory: "adult"
# E2Guardian-style weighted phrase examples. Copy your existing lists into
# config/phrases/<category>/ and reload from the dashboard.
{35}<explicit adult>
{30}<porn>
{30}<xxx>
{20}<adult webcam>
{-40}<essex>
{-40}<breast cancer>
"""


DEFAULT_GAMBLING_PHRASES = """#listcategory: "gambling"
{30}<casino>
{25}<sports betting>
{25}<online slots>
{20}<roulette>
{-30}<probability lesson>
"""


DEFAULT_MALWARE_PHRASES = """#listcategory: "malware"
{50}<download crack>
{50}<keygen>
{35}<disable antivirus>
{35}<payload.exe>
"""


SQUID_EXAMPLE = """# Squid/OPNsense ICAP voorbeeld
# Pas host/port aan naar deze ICAP service.

icap_enable on
icap_preview_enable on
icap_preview_size 4096
icap_send_client_ip on
icap_send_client_username on

icap_service school_req reqmod_precache bypass=0 icap://127.0.0.1:13440/reqmod
adaptation_access school_req allow all

icap_service school_resp respmod_precache bypass=0 icap://127.0.0.1:13440/respmod
adaptation_access school_resp allow all

# Belangrijk voor NetBird/Entra:
# - Laat clients nooit zelf X-NetBird-User/X-Entra-Groups aanleveren.
# - Strip die headers aan de rand en voeg ze enkel toe op een trusted gateway.
"""


def write_extra_defaults(config_dir: pathlib.Path) -> None:
    squid_path = config_dir / "squid-opnsense-example.conf"
    if not squid_path.exists():
        atomic_text_write(squid_path, SQUID_EXAMPLE)


def run_servers(store: ConfigStore, events: EventLogger) -> None:
    server_cfg = store.config.get("server", {})
    icap_addr = (str(server_cfg.get("icap_host", "0.0.0.0")), int(server_cfg.get("icap_port", 13440)))
    dash_addr = (
        str(server_cfg.get("dashboard_host", "127.0.0.1")),
        int(server_cfg.get("dashboard_port", 8088)),
    )
    icap = ICAPServer(icap_addr, store, events)
    dashboard = DashboardServer(dash_addr, store, events)
    threads = [
        threading.Thread(target=icap.serve_forever, name="icap", daemon=True),
        threading.Thread(target=dashboard.serve_forever, name="dashboard", daemon=True),
    ]
    for thread in threads:
        thread.start()
    logging.info("ICAP listening on %s:%s", *icap_addr)
    logging.info("Dashboard listening on http://%s:%s", *dash_addr)
    logging.info("Config version %s, ISTag %s", store.version, store.istag())
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        logging.info("Stopping...")
    finally:
        icap.shutdown()
        dashboard.shutdown()
        icap.server_close()
        dashboard.server_close()


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=APP_NAME)
    parser.add_argument("--config-dir", default=str(CONFIG_DIR), help="Directory with config.json/users.json/dlp_rules.json")
    parser.add_argument("--init", action="store_true", help="Create default config files and exit")
    parser.add_argument("--check", action="store_true", help="Load config and print status")
    parser.add_argument("--serve", action="store_true", help="Run ICAP and dashboard servers")
    parser.add_argument("--log-level", default=os.environ.get("LOG_LEVEL", "INFO"))
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    logging.basicConfig(
        level=getattr(logging, str(args.log_level).upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(message)s",
    )
    config_dir = pathlib.Path(args.config_dir).resolve()
    store = ConfigStore(config_dir)
    write_extra_defaults(config_dir)
    events = EventLogger(LOG_DIR)
    if args.init:
        print(f"Config aangemaakt in {config_dir}")
        print(f"Dashboard token: {store.config.get('server', {}).get('dashboard_token')}")
        return 0
    if args.check:
        print(safe_json(store.status()))
        return 0
    if args.serve or not (args.init or args.check):
        run_servers(store, events)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
