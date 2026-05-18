#!/usr/bin/env python3
"""
School ICAP Guard
=================

Single-file ICAP service for Squid/OPNsense deployments:

* ICAP REQMOD and RESPMOD listener.
* ClamAV/clamd scanning over TCP or Unix socket.
* DLP regex and validator rules.
* E2Guardian/DansGuardian-style weighted phrase lists.
* Group policies for common, NetBird, Entra, and custom groups.
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



def normalize_phrase_policy_defaults(config: dict[str, Any]) -> dict[str, Any]:
    def clean_policy(policy: dict[str, Any]) -> None:
        thresholds = policy.get("phrase_thresholds", {})
        if isinstance(thresholds, dict):
            cleaned: dict[str, int] = {}
            for category, value in thresholds.items():
                try:
                    threshold = int(value)
                except (TypeError, ValueError):
                    continue
                if threshold > 0:
                    cleaned[str(category)] = threshold
            policy["phrase_thresholds"] = cleaned
        else:
            policy["phrase_thresholds"] = {}

        total_threshold = policy.get("phrase_total_threshold")
        try:
            total_threshold_int = int(total_threshold)
        except (TypeError, ValueError):
            total_threshold_int = 0
        if total_threshold_int > 0:
            policy["phrase_total_threshold"] = total_threshold_int
        else:
            policy.pop("phrase_total_threshold", None)

    common = config.setdefault("common_policy", {})
    clean_policy(common)
    for policy in config.setdefault("policies", {}).values():
        if isinstance(policy, dict):
            clean_policy(policy)
    return config


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
    def __init__(self, log_dir: pathlib.Path, max_memory: int = 1000) -> None:
        self.log_dir = log_dir
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.path = log_dir / "events.jsonl"
        self.recent: collections.deque[dict[str, Any]] = collections.deque(maxlen=max_memory)
        self.lock = threading.Lock()
        self.stats = collections.Counter()
        self._load_existing()

    def _load_existing(self) -> None:
        if not self.path.exists():
            return
        loaded: list[dict[str, Any]] = []
        corrupt = 0
        try:
            with self.path.open("r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        event = json.loads(line)
                    except json.JSONDecodeError:
                        corrupt += 1
                        continue
                    if not isinstance(event, dict):
                        corrupt += 1
                        continue
                    loaded.append(event)
                    self.stats["total"] += 1
                    self.stats[event.get("action", "unknown")] += 1
                    if event.get("reason"):
                        self.stats[f"reason:{event['reason']}"] += 1
            for event in loaded[-self.recent.maxlen :]:
                self.recent.appendleft(event)
            if corrupt:
                self.stats["corrupt_lines"] = corrupt
        except OSError as exc:
            self.stats["load_error"] = 1
            logging.warning("Could not load persisted events from %s: %s", self.path, exc)

    def emit(self, event: dict[str, Any]) -> None:
        event.setdefault("ts", utc_now())
        line = json.dumps(event, ensure_ascii=False, sort_keys=True)
        with self.lock:
            self.recent.appendleft(event)
            self.stats["total"] += 1
            self.stats[event.get("action", "unknown")] += 1
            if event.get("reason"):
                self.stats[f"reason:{event['reason']}"] += 1
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(line + "\n")

    def snapshot(self) -> dict[str, Any]:
        with self.lock:
            return {
                "stats": dict(self.stats),
                "recent": list(self.recent),
                "log_path": str(self.path),
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
        if not bool(self.config.get("enabled", False)):
            return
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
            groups.append(str(self.config.get("default_group", "default")))
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
            fallback = self.config.get("identity", {}).get("default_group", "default")
            if fallback in self.policies:
                result.append((fallback, self.policies[fallback]))
        return result

    def evaluate(self, context: ScanContext, body: bytes) -> Decision:
        policies = self.applicable_policies(context.identity.groups)
        policy_names = [name for name, _ in policies]
        webfilter_enabled = any(policy.get("webfiltering_enabled", True) for _, policy in policies)
        domain_blocking_enabled = webfilter_enabled and any(
            policy.get("domain_blocking_enabled", True) for _, policy in policies
        )
        body_limit = self._min_int(policies, "max_body_bytes", DEFAULT_BODY_LIMIT)
        if len(body) > body_limit:
            action = self._first_value(policies, "oversize_action", "allow").lower()
            if action == "block":
                return Decision(False, "oversize", policy=",".join(policy_names), details={"limit": body_limit})

        blocked_domains = self._list_union(policies, "blocked_domains")
        hard_blocked_domains = self._list_union(policies, "hard_blocked_domains")
        allowed_domains = self._list_union(policies, "allowed_domains")
        allow_bypasses = any(bool(policy.get("allow_domains_bypass_content", False)) for _, policy in policies)

        if domain_matches(context.domain, allowed_domains):
            return Decision(
                True,
                "allowed_domain",
                policy=",".join(policy_names),
                details={"allowlist_priority": "allowed domains are evaluated before blocklists"},
            )

        if domain_blocking_enabled and domain_matches(context.domain, hard_blocked_domains):
            return Decision(False, "domain", category=context.domain, policy="common")
        if domain_blocking_enabled and domain_matches(context.domain, blocked_domains):
            return Decision(False, "domain", category=context.domain, policy=",".join(policy_names))

        bypass_content = domain_matches(context.domain, allowed_domains) and allow_bypasses

        blocked_mime = self._list_union(policies, "blocked_mime_types")
        ctype = content_type_base(context.content_type)
        if webfilter_enabled and ctype and any(fnmatch.fnmatch(ctype, pattern.lower()) for pattern in blocked_mime):
            return Decision(False, "mime", category=ctype, policy=",".join(policy_names))

        clam_result = ClamResult(status="skipped")
        malware_enabled = any(policy.get("malware", True) for _, policy in policies)
        if malware_enabled and body:
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

        dlp_text = self._dlp_text(context, body)
        if dlp_text:
            dlp_enabled = any(policy.get("dlp_enabled", True) for _, policy in policies)
            if dlp_enabled:
                dlp_score, dlp_hits = self.dlp_engine.scan(dlp_text, context.identity.groups)
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

        scan_text = self._scan_text(context, body) if webfilter_enabled else ""
        if scan_text and bool(self.config.get("phrase_lists", {}).get("enabled", False)):
            phrase_scores, phrase_hits = self.phrase_engine.scan(scan_text)
            phrase_decision = self._phrase_decision(policies, phrase_scores, phrase_hits)
            if phrase_decision:
                phrase_decision.policy = ",".join(policy_names)
                phrase_decision.clam = clam_result
                return phrase_decision

        return Decision(True, "clean", policy=",".join(policy_names), clam=clam_result)

    def _dlp_text(self, context: ScanContext, body: bytes) -> str:
        if context.direction != "reqmod" or context.method.upper() != "POST":
            return ""
        if not body or not looks_textual(context.content_type, body):
            return ""
        text_limit = int(self.config.get("scan", {}).get("text_scan_bytes", DEFAULT_TEXT_SCAN_BYTES))
        return decode_body_for_scan(context.content_type, body, text_limit)

    def _scan_text(self, context: ScanContext, body: bytes) -> str:
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
        # Maak voor ELKE E2Guardian-categorie standaard zowel Engelse als Nederlandse
        # weighted phrase lists aan. Dit behoudt alle categorieën in de catalogus en
        # zorgt dat de webfiltering direct bruikbaar is na --init. Bestaande files
        # worden nooit overschreven, zodat lokale aanpassingen behouden blijven.
        self._disable_generated_phrase_seeds()
        for entry in E2G_CATEGORY_CATALOG:
            key = entry["key"]
            (self.phrase_root / key).mkdir(parents=True, exist_ok=True)

    def _disable_generated_phrase_seeds(self) -> None:
        for path in self.phrase_root.rglob("*.weightedphraselist"):
            if path.name not in {"english.weightedphraselist", "dutch.weightedphraselist"}:
                continue
            try:
                text = read_text(path)
            except OSError:
                continue
            if "Auto-generated default" not in text:
                continue
            target = path.with_name(path.name + ".disabled")
            if target.exists():
                continue
            path.replace(target)

    def reload(self) -> None:
        with self.lock:
            user_config = json.loads(read_text(self.config_path))
            self.config = normalize_phrase_policy_defaults(deep_merge(default_config(), user_config))
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
        self._save_json_path(self.config_path, normalize_phrase_policy_defaults(data))

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
            common = self.config.get("common_policy", {})
            phrase_cfg = self.config.get("phrase_lists", {})
            identity_cfg = self.config.get("identity", {})
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
                "logging": self.config.get("logging", {"enabled": True}),
                "features": {
                    "webfiltering_enabled": bool(common.get("webfiltering_enabled", True)),
                    "domain_blocking_enabled": bool(common.get("domain_blocking_enabled", True)),
                    "weighted_phrases_enabled": bool(phrase_cfg.get("enabled", False)),
                    "dlp_enabled": bool(common.get("dlp_enabled", True)),
                    "antivirus_enabled": bool(self.config.get("clamav", {}).get("enabled", True)),
                    "logging_enabled": bool(self.config.get("logging", {}).get("enabled", True)),
                    "netbird_sync_enabled": bool(identity_cfg.get("netbird_sync_enabled", False)),
                    "allow_domains_bypass_content": bool(common.get("allow_domains_bypass_content", False)),
                    "clamav_fail_open": bool(self.config.get("clamav", {}).get("fail_open", False)),
                    "dlp_fail_open": bool(common.get("dlp_fail_open", False)),
                    "webfilter_fail_open": bool(common.get("webfilter_fail_open", False)),
                },
                "todos": {
                    "netbird_sync_trigger": "backend hook aanwezig in UI, externe scheduler/script blijft verantwoordelijk",
                    "entra_id_sync": "backend hook gereserveerd voor latere Entra-ID integratie",
                    "service_restart": "bewust geen systemctl-acties vanuit dashboard zonder extra beveiliging",
                },
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
        http_method = (request_start.split() or [""])[0].upper()
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
            req = message.req.raw_header
            res = message.res.raw_header
            res_offset = len(req)
            if message.body:
                encapsulated = f"req-hdr=0, res-hdr={res_offset}, res-body={res_offset + len(res)}"
            else:
                encapsulated = f"req-hdr=0, res-hdr={res_offset}, null-body={res_offset + len(res)}"
            headers = self._icap_200_headers(encapsulated)
            self.wfile.write(headers + req + res)
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
        if not bool(self.server.store.config.get("logging", {}).get("enabled", True)):
            return
        event = {
            "incident_id": decision.incident_id,
            "action": "allow" if decision.allowed else "block",
            "reason": decision.reason,
            "category": decision.category,
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
    recent_events = event_snapshot.get("recent", [])
    user_activity: dict[str, dict[str, int]] = {}
    domain_activity: collections.Counter[str] = collections.Counter()
    category_blocks: collections.Counter[str] = collections.Counter()
    traffic_by_hour: collections.Counter[str] = collections.Counter()
    blocks_by_hour: collections.Counter[str] = collections.Counter()
    for event in recent_events:
        action = str(event.get("action", "unknown"))
        user = str(event.get("user") or "anonymous")
        domain = str(event.get("domain") or "")
        reason = str(event.get("reason") or "")
        category = str(event.get("category") or event.get("details", {}).get("category") or reason)
        bucket = str(event.get("ts") or "")[:13] or "unknown"
        traffic_by_hour[bucket] += 1
        user_activity.setdefault(user, {"allow": 0, "block": 0, "total": 0})
        user_activity[user]["total"] += 1
        user_activity[user][action] = user_activity[user].get(action, 0) + 1
        if domain and action == "block":
            domain_activity[domain] += 1
        if action == "block":
            blocks_by_hour[bucket] += 1
            category_blocks[category] += 1
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
            "allowed_domains": sum(1 for row in domain_rows if row["list"] == "allowed_domains"),
            "phrase_rules": sum(counts.values()) if config.get("phrase_lists", {}).get("enabled", False) else 0,
            "dlp_rules": len(store.dlp.get("rules", [])),
            "events": event_snapshot.get("stats", {}).get("total", 0),
        },
        "analytics": {
            "allowed": event_snapshot.get("stats", {}).get("allow", 0),
            "blocked": event_snapshot.get("stats", {}).get("block", 0),
            "traffic_by_hour": dict(sorted(traffic_by_hour.items())),
            "blocks_by_hour": dict(sorted(blocks_by_hour.items())),
            "top_blocked_domains": domain_activity.most_common(10),
            "top_blocked_categories": category_blocks.most_common(10),
            "top_users": sorted(user_activity.items(), key=lambda item: item[1].get("total", 0), reverse=True)[:10],
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
        policies.pop(group, None)
    else:
        template = slugify_key(str(data.get("copy_from", "all")))
        base = policies.get(template) or config.get("common_policy", {})
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
    groups = split_groups(data.get("groups", "default"))
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


def dashboard_update_setting(store: ConfigStore, data: dict[str, Any]) -> dict[str, Any]:
    config = editable_config(store)
    key = str(data.get("key", "")).strip()
    enabled = parse_bool(str(data.get("enabled", "true")), True)
    common = config.setdefault("common_policy", {})
    mapping = {
        "webfiltering_enabled": ("common_policy", "webfiltering_enabled"),
        "domain_blocking_enabled": ("common_policy", "domain_blocking_enabled"),
        "dlp_enabled": ("common_policy", "dlp_enabled"),
        "allow_domains_bypass_content": ("common_policy", "allow_domains_bypass_content"),
        "dlp_fail_open": ("common_policy", "dlp_fail_open"),
        "webfilter_fail_open": ("common_policy", "webfilter_fail_open"),
        "weighted_phrases_enabled": ("phrase_lists", "enabled"),
        "antivirus_enabled": ("clamav", "enabled"),
        "clamav_fail_open": ("clamav", "fail_open"),
        "logging_enabled": ("logging", "enabled"),
        "netbird_sync_enabled": ("identity", "netbird_sync_enabled"),
    }
    if key not in mapping:
        raise ValueError("onbekende instelling")
    section, config_key = mapping[key]
    target = config.setdefault(section, {})
    target[config_key] = enabled
    if key == "weighted_phrases_enabled" and not enabled:
        common["phrase_thresholds"] = {}
        common["phrase_total_threshold"] = 0
        for policy in config.setdefault("policies", {}).values():
            policy["phrase_thresholds"] = {}
            policy["phrase_total_threshold"] = 0
    store.save_config_data(config)
    return {"ok": True, "key": key, "enabled": enabled}


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
            if parsed.path == "/":
                self._send_html(render_modern_dashboard())
            elif parsed.path == "/api/status":
                self._send_json(self.server.store.status())
            elif parsed.path == "/api/events":
                self._send_json(self.server.events.snapshot())
            elif parsed.path == "/api/policy":
                self._send_json(dashboard_policy_snapshot(self.server.store, self.server.events))
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
            elif parsed.path == "/test":
                self._send_html(render_test_page())
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
                    self.send_header("Set-Cookie", f"guard_token={urllib.parse.quote(token)}; HttpOnly; SameSite=Strict")
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
                self._send_json(dashboard_update_setting(self.server.store, self._read_json_body()))
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
            groups=[g.strip() for g in data.get("groups", "default").split(",") if g.strip()],
            source="dashboard-test",
        )
        context = ScanContext(
            direction=data.get("direction", "reqmod"),
            url=data.get("url", ""),
            domain=normalize_domain(urllib.parse.urlsplit(data.get("url", "")).netloc),
            method=data.get("http_method", "GET").upper(),
            content_type=data.get("content_type", "text/plain"),
            identity=identity,
            icap_headers={},
            http_headers=headers,
            request_start=f"{data.get('http_method', 'GET').upper()} {data.get('url', '/')} HTTP/1.1",
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
    error_html = f"<p class='error'>{html_lib.escape(error)}</p>" if error else ""
    return f"""<!doctype html>
<html lang="nl">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>School ICAP Guard</title>
  <style>{DASHBOARD_CSS}</style>
</head>
<body class="centered">
  <main class="login">
    <h1>School ICAP Guard</h1>
    {error_html}
    <form method="post" action="/login">
      <label>Dashboard token
        <input name="token" type="password" autofocus>
      </label>
      <button type="submit">Aanmelden</button>
    </form>
  </main>
</body>
</html>"""


def render_admin_dashboard() -> str:
    html = """<!doctype html>
<html lang="nl">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>School ICAP Guard</title>
  <style>__DASHBOARD_CSS__</style>
</head>
<body>
  <header>
    <h1>School ICAP Guard</h1>
    <nav>
      <a href="#categories">Categorieen</a>
      <a href="#domains">Domeinen</a>
      <a href="#users">Gebruikers</a>
      <a href="/test">Test</a>
      <a href="/edit?path=config.json">Advanced</a>
    </nav>
  </header>
  <main>
    <section class="summary-grid" id="summary"></section>

    <section class="admin-grid">
      <div class="panel wide-panel" id="categories">
        <div class="panel-head">
          <div>
            <h2>Categorieen per groep</h2>
            <p class="hint">Kies een groep, zoek een categorie in Nederlands of Engels en zet de blokkering aan. De threshold is de phrase score vanaf waar de pagina wordt geblokkeerd.</p>
          </div>
          <button id="reload">Reload</button>
        </div>
        <div class="toolbar">
          <label>Groep
            <select id="category-group"></select>
          </label>
          <label>Zoeken
            <input id="category-search" placeholder="adult, gokken, malware, social...">
          </label>
        </div>
        <div id="category-list" class="category-list"></div>
      </div>

      <div class="panel" id="domains">
        <h2>Domein blokkeren of toelaten</h2>
        <form id="domain-form" class="inline-form">
          <label>Voor
            <select name="target" id="domain-target"></select>
          </label>
          <label>Actie
            <select name="list">
              <option value="blocked_domains">Blokkeren</option>
              <option value="hard_blocked_domains">Hard block alle groepen</option>
              <option value="allowed_domains">Toestaan</option>
            </select>
          </label>
          <label>Domein
            <input name="domain" placeholder="example.com of *.example.com" required>
          </label>
          <button type="submit">Toevoegen</button>
        </form>
        <div id="domain-list" class="list-stack"></div>
      </div>

      <div class="panel">
        <h2>Groepen</h2>
        <form id="group-form" class="inline-form">
          <label>Nieuwe groep
            <input name="group" placeholder="staff, guest, byod..." required>
          </label>
          <label>Kopieer policy van
            <select name="copy_from" id="copy-from-group"></select>
          </label>
          <button type="submit">Groep maken</button>
        </form>
        <div id="group-list" class="list-stack"></div>
      </div>

      <div class="panel" id="users">
        <h2>Gebruikers en NetBird</h2>
        <form id="user-form" class="inline-form">
          <label>Gebruiker
            <input name="user" placeholder="student@domein.be" required>
          </label>
          <label>Groepen
            <input name="groups" placeholder="netbird_staff, byod" value="default">
          </label>
          <label>NetBird IP
            <input name="ip" placeholder="100.64.x.x">
          </label>
          <label>Entra object id
            <input name="entra_object_id" placeholder="optioneel">
          </label>
          <button type="submit">Opslaan</button>
        </form>
        <div id="user-list" class="list-stack"></div>
      </div>

      <div class="panel">
        <h2>DLP regels</h2>
        <div id="dlp-list" class="list-stack"></div>
        <p class="hint"><a href="/edit?path=dlp_rules.json">DLP regels geavanceerd bewerken</a></p>
      </div>

      <div class="panel">
        <h2>Service overzicht</h2>
        <div id="service-summary" class="list-stack"></div>
        <h2 class="spaced">Bestanden</h2>
        <div id="files" class="list-stack"></div>
      </div>

      <div class="panel wide-panel">
        <h2>Recente events</h2>
        <div id="events" class="events-grid"></div>
      </div>
    </section>
  </main>
  <div id="toast" class="toast" hidden></div>
  <script>
    let state = null;
    const $ = (sel) => document.querySelector(sel);

    function esc(value) {
      return String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
    }

    async function api(url, options = {}) {
      const res = await fetch(url, options);
      if (!res.ok) {
        let detail = await res.text();
        try { detail = JSON.parse(detail).error || detail; } catch (_) {}
        throw new Error(detail);
      }
      return res.json();
    }

    async function post(url, body) {
      return api(url, {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(body)
      });
    }

    function toast(message, ok = true) {
      const el = $('#toast');
      el.textContent = message;
      el.className = ok ? 'toast ok' : 'toast error';
      el.hidden = false;
      clearTimeout(window.toastTimer);
      window.toastTimer = setTimeout(() => { el.hidden = true; }, 3500);
    }

    function groupOptions(selected = 'all') {
      const groups = ['all', ...(state?.groups || [])];
      return groups.map(g => {
        const label = g === 'all' ? 'Alle groepen' : g;
        return `<option value="${esc(g)}" ${g === selected ? 'selected' : ''}>${esc(label)}</option>`;
      }).join('');
    }

    function renderSummary() {
      const s = state.summary;
      $('#summary').innerHTML = [
        ['Groepen', s.groups],
        ['Gebruikers', s.users],
        ['NetBird IPs', s.netbird_ips],
        ['Categorie blocks', s.active_category_blocks],
        ['Domeinregels', s.blocked_domains],
        ['DLP regels', s.dlp_rules]
      ].map(([label, value]) => `<div class="stat"><span>${esc(label)}</span><b>${esc(value)}</b></div>`).join('');
    }

    function renderSelectors() {
      const catCurrent = $('#category-group').value || 'student';
      $('#category-group').innerHTML = groupOptions(catCurrent);
      if (!$('#category-group').value) $('#category-group').value = state.groups.includes('student') ? 'student' : 'all';
      $('#domain-target').innerHTML = groupOptions($('#domain-target').value || 'all');
      $('#copy-from-group').innerHTML = (state.groups || []).map(g => `<option value="${esc(g)}">${esc(g)}</option>`).join('');
    }

    function renderCategories() {
      const target = $('#category-group').value || 'all';
      const query = ($('#category-search').value || '').toLowerCase();
      const rows = state.categories.filter(c => {
        const text = `${c.key} ${c.en} ${c.nl}`.toLowerCase();
        return !query || text.includes(query);
      });
      $('#category-list').innerHTML = rows.map(c => {
        const direct = c.thresholds[target] !== null && c.thresholds[target] !== undefined;
        const inherited = target !== 'all' && c.thresholds.all !== null && c.thresholds.all !== undefined;
        const value = direct ? c.thresholds[target] : (c.default_threshold || 80);
        const active = direct || inherited;
        return `<div class="category-item ${active ? 'active' : ''} risk-${esc(c.risk)}" data-category="${esc(c.key)}">
          <div class="category-copy">
            <b>${esc(c.nl)}</b>
            <span>${esc(c.en)} · ${esc(c.key)} · ${esc(c.phrase_rules)} phrases${c.phrase_file ? '' : ' · nog geen phrase file'}</span>
            ${inherited ? '<em>Geblokkeerd via Alle groepen</em>' : ''}
          </div>
          <div class="row-actions">
            <input class="threshold-input" type="number" min="1" max="999" value="${esc(value)}" title="Threshold">
            <button data-action="category-enable" data-category="${esc(c.key)}">Blokkeer/Opslaan</button>
            ${direct ? `<button class="danger-btn" data-action="category-disable" data-category="${esc(c.key)}">Deblokkeer</button>` : ''}
          </div>
        </div>`;
      }).join('');
    }

    function renderDomains() {
      $('#domain-list').innerHTML = (state.domains || []).map(row => {
        const type = row.list === 'allowed_domains' ? 'toegestaan' : (row.list === 'hard_blocked_domains' ? 'hard block' : 'blok');
        return `<div class="list-row">
          <div><b>${esc(row.domain)}</b><span>${esc(row.label)} · ${esc(type)}</span></div>
          <button class="danger-btn" data-action="domain-remove" data-domain="${esc(row.domain)}" data-target="${esc(row.target)}" data-list="${esc(row.list)}">Verwijder</button>
        </div>`;
      }).join('') || '<p class="hint">Nog geen domeinregels.</p>';
    }

    function renderGroups() {
      $('#group-list').innerHTML = (state.groups || []).map(group => {
        const policy = state.policies[group] || {};
        const cats = Object.keys(policy.phrase_thresholds || {}).length;
        const domains = (policy.blocked_domains || []).length;
        return `<div class="list-row">
          <div><b>${esc(group)}</b><span>${cats} categorieen · ${domains} geblokkeerde domeinen · DLP ${policy.dlp_enabled ? 'aan' : 'uit'}</span></div>
          ${group === 'default' ? '' : `<button class="danger-btn" data-action="group-delete" data-group="${esc(group)}">Verwijder</button>`}
        </div>`;
      }).join('');
    }

    function renderUsers() {
      const userRows = Object.entries(state.users || {}).map(([user, obj]) => {
        const ip = Object.entries(state.ip_map || {}).find(([, map]) => map.user === user)?.[0] || '';
        return `<div class="list-row">
          <div><b>${esc(user)}</b><span>${esc((obj.groups || []).join(', '))}${ip ? ' · NetBird ' + esc(ip) : ''}</span></div>
          <button class="danger-btn" data-action="user-delete" data-user="${esc(user)}" data-ip="${esc(ip)}">Verwijder</button>
        </div>`;
      }).join('');
      $('#user-list').innerHTML = userRows || '<p class="hint">Nog geen gebruikers buiten defaults.</p>';
    }

    function renderDlp() {
      const rules = state.dlp.rules || [];
      $('#dlp-list').innerHTML = rules.map((rule, index) => `<div class="list-row">
        <div><b>${esc(rule.name)}</b><span>${rule.enabled ? 'Actief' : 'Uit'} · ${esc(rule.builtin || rule.pattern || '')} · groepen: ${esc((rule.groups || []).join(', ') || 'alle')}</span></div>
        <button data-action="dlp-toggle" data-index="${index}" data-enabled="${rule.enabled ? 'false' : 'true'}">${rule.enabled ? 'Uitzetten' : 'Aanzetten'}</button>
      </div>`).join('');
    }

    function renderService() {
      const st = state.status;
      const rows = [
        ['ICAP', `${st.icap.host}:${st.icap.port}`],
        ['Dashboard', `${st.dashboard.host}:${st.dashboard.port}`],
        ['ClamAV', st.clamav.enabled ? `aan (${st.clamav.unix_socket || st.clamav.host + ':' + st.clamav.port})` : 'uit'],
        ['Phrase rules', st.phrase_rules],
        ['Config versie', st.config_version]
      ];
      $('#service-summary').innerHTML = rows.map(([k, v]) => `<div class="list-row compact"><b>${esc(k)}</b><span>${esc(v)}</span></div>`).join('');
      $('#files').innerHTML = (state.editable_files || []).map(f =>
        `<a class="file" href="/edit?path=${encodeURIComponent(f.path)}">${esc(f.path)} <span>${f.size} bytes</span></a>`
      ).join('');
    }

    function renderEvents() {
      const events = state.events.recent || [];
      $('#events').innerHTML = events.slice(0, 30).map(e =>
        `<div class="event ${esc(e.action)}"><b>${esc(e.action)} / ${esc(e.reason)}</b><span>${esc(e.user)} · ${esc(e.domain)} · ${esc(e.ts)}</span></div>`
      ).join('') || '<p class="hint">Nog geen events sinds start.</p>';
    }

    async function refresh() {
      const selectedGroup = $('#category-group')?.value;
      state = await api('/api/policy');
      renderSummary();
      renderSelectors();
      if (selectedGroup) $('#category-group').value = selectedGroup;
      renderCategories();
      renderDomains();
      renderGroups();
      renderUsers();
      renderDlp();
      renderService();
      renderEvents();
    }

    $('#reload').addEventListener('click', async () => {
      await api('/api/reload', {method: 'POST'});
      await refresh();
      toast('Configuratie herladen');
    });
    $('#category-group').addEventListener('change', renderCategories);
    $('#category-search').addEventListener('input', renderCategories);

    $('#domain-form').addEventListener('submit', async (ev) => {
      ev.preventDefault();
      const data = Object.fromEntries(new FormData(ev.target).entries());
      await post('/api/policy/domain', {...data, action: 'add'});
      ev.target.reset();
      await refresh();
      toast('Domeinregel toegevoegd');
    });

    $('#group-form').addEventListener('submit', async (ev) => {
      ev.preventDefault();
      const data = Object.fromEntries(new FormData(ev.target).entries());
      await post('/api/policy/group', {...data, action: 'add'});
      ev.target.reset();
      await refresh();
      toast('Groep aangemaakt');
    });

    $('#user-form').addEventListener('submit', async (ev) => {
      ev.preventDefault();
      const data = Object.fromEntries(new FormData(ev.target).entries());
      await post('/api/users/manage', {...data, action: 'save'});
      await refresh();
      toast('Gebruiker opgeslagen');
    });

    document.body.addEventListener('click', async (ev) => {
      const btn = ev.target.closest('button[data-action]');
      if (!btn) return;
      const action = btn.dataset.action;
      try {
        if (action === 'category-enable') {
          const row = btn.closest('.category-item');
          const threshold = row.querySelector('.threshold-input').value;
          await post('/api/policy/category', {target: $('#category-group').value, category: btn.dataset.category, enabled: true, threshold});
          toast('Categorieblokkering opgeslagen');
        } else if (action === 'category-disable') {
          await post('/api/policy/category', {target: $('#category-group').value, category: btn.dataset.category, enabled: false});
          toast('Categorie gedeblokkeerd');
        } else if (action === 'domain-remove') {
          await post('/api/policy/domain', {target: btn.dataset.target, domain: btn.dataset.domain, list: btn.dataset.list, action: 'remove'});
          toast('Domeinregel verwijderd');
        } else if (action === 'group-delete') {
          await post('/api/policy/group', {group: btn.dataset.group, action: 'delete'});
          toast('Groep verwijderd');
        } else if (action === 'user-delete') {
          await post('/api/users/manage', {user: btn.dataset.user, ip: btn.dataset.ip, action: 'delete'});
          toast('Gebruiker verwijderd');
        } else if (action === 'dlp-toggle') {
          await post('/api/dlp/rule', {index: btn.dataset.index, enabled: btn.dataset.enabled});
          toast('DLP regel aangepast');
        }
        await refresh();
      } catch (err) {
        toast(err.message, false);
      }
    });

    refresh().catch(err => toast(err.message, false));
  </script>
</body>
</html>"""
    return html.replace("__DASHBOARD_CSS__", DASHBOARD_CSS)


def render_modern_dashboard() -> str:
    html = """<!doctype html>
<html lang="nl">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>School ICAP Guard</title>
  <style>__DASHBOARD_CSS__
__MODERN_CSS__</style>
</head>
<body class="app-shell">
  <aside class="sidebar" id="sidebar">
    <div class="brand">
      <div class="brand-mark">SG</div>
      <div class="brand-copy"><strong>School ICAP Guard</strong><span>Security admin</span></div>
    </div>
    <nav class="side-nav" aria-label="Dashboard navigatie">
      <a href="#dashboard" data-page="dashboard">Overzicht</a>
      <a href="#events" data-page="events">Logs & events</a>
      <a href="#users" data-page="users">Gebruikers</a>
      <a href="#policies" data-page="policies">Policies</a>
      <a href="#domains" data-page="domains">Domeinen</a>
      <a href="#categories" data-page="categories">Categorieen</a>
      <a href="#phrases" data-page="phrases">Weighted phrases</a>
      <a href="#dlp" data-page="dlp">DLP</a>
      <a href="#services" data-page="services">Services</a>
      <a href="#files" data-page="files">Config files</a>
    </nav>
  </aside>
  <div class="app-main">
    <header class="topbar">
      <div class="topbar-left">
        <button class="icon-btn" id="sidebar-toggle" title="Sidebar inklappen">☰</button>
        <div><h1 id="page-title">Overzicht</h1><p id="page-subtitle">Live status en recente security-activiteit</p></div>
      </div>
      <div class="topbar-actions">
        <a class="ghost-btn" href="/test">Policy test</a>
        <button class="ghost-btn" id="theme-toggle">Theme</button>
        <button class="primary-btn" id="reload">Reload</button>
      </div>
    </header>
    <main class="content">
      <section id="page-dashboard" class="page active">
        <div class="metric-grid" id="metrics"></div>
        <div class="status-strip" id="status-strip"></div>
        <div class="dashboard-grid">
          <article class="card span-2"><div class="card-head"><h2>Totaal verkeer</h2><span>recent memory</span></div><canvas id="traffic-chart" height="150"></canvas><p class="empty" id="traffic-empty">Geen trafficdata beschikbaar</p></article>
          <article class="card"><div class="card-head"><h2>Allowed vs blocked</h2><span>ratio</span></div><canvas id="ratio-chart" height="150"></canvas><p class="empty" id="ratio-empty">Geen logs gevonden</p></article>
          <article class="card"><div class="card-head"><h2>Blocks per uur</h2><span>security</span></div><canvas id="blocks-chart" height="150"></canvas><p class="empty" id="blocks-empty">Geen blocks geregistreerd</p></article>
          <article class="card"><div class="card-head"><h2>Top categorieen</h2><span>blocked</span></div><div id="top-categories" class="rank-list"></div></article>
          <article class="card"><div class="card-head"><h2>Actieve gebruikers</h2><span>requests</span></div><div id="top-users" class="rank-list"></div></article>
          <article class="card"><div class="card-head"><h2>Geblokkeerde domeinen</h2><span>top</span></div><div id="top-domains" class="rank-list"></div></article>
          <article class="card span-2"><div class="card-head"><h2>Laatste blocks</h2><a href="#events">Alle events</a></div><div id="latest-blocks" class="event-list"></div></article>
          <article class="card span-2"><div class="card-head"><h2>Snelle acties</h2><span>beheer</span></div><div id="quick-actions" class="toggle-grid"></div></article>
        </div>
      </section>

      <section id="page-events" class="page">
        <div class="card">
          <div class="filter-grid">
            <input id="event-search" placeholder="Zoeken op gebruiker, domein, reden, incident...">
            <input id="event-user" placeholder="Gebruiker">
            <input id="event-ip" placeholder="IP-adres">
            <input id="event-domain" placeholder="Domein/URL">
            <input id="event-category" placeholder="Categorie">
            <select id="event-action"><option value="">Actie</option><option value="allow">Allowed</option><option value="block">Blocked</option></select>
            <input id="event-date" type="date">
            <input id="event-incident" placeholder="Incident ID">
          </div>
          <div class="table-wrap"><table><thead><tr><th>Timestamp</th><th>Status</th><th>Gebruiker</th><th>IP</th><th>Domein/URL</th><th>Categorie</th><th>Policy</th><th>Reden</th><th>Incident</th></tr></thead><tbody id="events-table"></tbody></table></div>
        </div>
        <div class="card detail-card" id="event-detail"><h2>Event details</h2><p class="empty">Selecteer een event om de details te bekijken.</p></div>
      </section>

      <section id="page-users" class="page">
        <div class="split-grid">
          <article class="card">
            <div class="card-head"><h2>Gebruikers</h2><input id="user-search" placeholder="Zoek gebruiker, groep of IP"></div>
            <div id="users-list" class="list-stack"></div>
          </article>
          <article class="card detail-card" id="user-detail"><h2>Gebruikersdetail</h2><p class="empty">Kies links een gebruiker.</p></article>
        </div>
      </section>

      <section id="page-policies" class="page">
        <div class="card">
          <div class="card-head"><h2>Policies en groepen</h2><span>NetBird-groepen en eigen groepen</span></div>
          <form id="group-form" class="inline-form modern-form"><label>Nieuwe groep<input name="group" placeholder="netbird_staff, byod..." required></label><label>Kopieer van<select name="copy_from" id="copy-from-group"></select></label><button class="primary-btn" type="submit">Groep maken</button></form>
          <div id="policy-list" class="policy-grid"></div>
        </div>
      </section>

      <section id="page-domains" class="page">
        <div class="card">
          <div class="card-head"><h2>Domeinblokkering en allowlist</h2><span>Allowlist heeft prioriteit boven blocklists</span></div>
          <form id="domain-form" class="inline-form modern-form"><label>Voor<select name="target" id="domain-target"></select></label><label>Actie<select name="list"><option value="allowed_domains">Toestaan</option><option value="blocked_domains">Blokkeren</option><option value="hard_blocked_domains">Hard block alle groepen</option></select></label><label>Domein<input name="domain" placeholder="example.com of *.example.com" required></label><button class="primary-btn" type="submit">Toevoegen</button></form>
          <input id="domain-search" placeholder="Zoek domeinregel">
          <div class="table-wrap"><table><thead><tr><th>Domein</th><th>Scope</th><th>Type</th><th>Status</th><th>Hits</th><th></th></tr></thead><tbody id="domains-table"></tbody></table></div>
        </div>
      </section>

      <section id="page-categories" class="page">
        <div class="card">
          <div class="card-head"><h2>Categorieen</h2><span>Phrase-blocking blijft uit tot je het expliciet activeert</span></div>
          <div class="toolbar modern-toolbar"><label>Groep<select id="category-group"></select></label><label>Zoeken<input id="category-search" placeholder="adult, malware, social..."></label></div>
          <div id="category-list" class="category-list"></div>
        </div>
      </section>

      <section id="page-phrases" class="page">
        <div class="card">
          <div class="card-head"><h2>Weighted phrases</h2><span>Standaard uitgeschakeld</span></div>
          <div class="notice">Weighted phrases zijn alleen actief wanneer de globale instelling aanstaat en een policy thresholds heeft. Auto-generated seedlijsten worden veilig naar <code>.disabled</code> hernoemd.</div>
          <div id="phrase-list" class="policy-grid"></div>
        </div>
      </section>

      <section id="page-dlp" class="page">
        <div class="card">
          <div class="card-head"><h2>DLP regels</h2><span>Alleen REQMOD + HTTP POST body</span></div>
          <div class="notice">DLP scant geen gewone pagina-inhoud, URL, headers of response bodies. Webfiltering en phrase-scoring blijven apart.</div>
          <div id="dlp-list" class="list-stack"></div>
          <p class="hint"><a href="/edit?path=dlp_rules.json">DLP regels geavanceerd bewerken</a></p>
        </div>
      </section>

      <section id="page-services" class="page">
        <div class="card"><div class="card-head"><h2>Services/status</h2><span>veilige backend hooks</span></div><div id="service-cards" class="service-grid"></div><div id="todo-hooks" class="notice"></div></div>
      </section>

      <section id="page-files" class="page">
        <div class="card"><div class="card-head"><h2>Config bestanden</h2><span>backups bij opslaan</span></div><div id="files" class="file-grid"></div></div>
      </section>
    </main>
    <footer>Copyright © 2026 Youness Banali El Khattabi</footer>
  </div>
  <div id="toast" class="toast" hidden></div>
  <script>
    let state = null;
    let selectedEvent = null;
    let selectedUser = null;
    const pages = {
      dashboard: ['Overzicht', 'Live status en recente security-activiteit'],
      events: ['Logs & events', 'Zoeken, filteren en incidenten bekijken'],
      users: ['Gebruikers', 'NetBird peers, groepen en recente geschiedenis'],
      policies: ['Policies', 'Groepen en toegepaste regels'],
      domains: ['Domeinen', 'Allowlist, blocklist en hard blocks'],
      categories: ['Categorieen', 'UT1/E2Guardian-categorieen en thresholds'],
      phrases: ['Weighted phrases', 'Phrase status en beheer'],
      dlp: ['DLP', 'Body-only datalekpreventie'],
      services: ['Services', 'ICAP, NetBird, DLP, ClamAV en configstatus'],
      files: ['Config files', 'Geavanceerde configuratie']
    };
    const $ = (sel) => document.querySelector(sel);
    const $$ = (sel) => Array.from(document.querySelectorAll(sel));
    const esc = (value) => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
    async function api(url, options = {}) {
      const res = await fetch(url, options);
      if (!res.ok) {
        let detail = await res.text();
        try { detail = JSON.parse(detail).error || detail; } catch (_) {}
        throw new Error(detail);
      }
      return res.json();
    }
    const post = (url, body) => api(url, {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(body)});
    function toast(message, ok = true) {
      const el = $('#toast'); el.textContent = message; el.className = ok ? 'toast ok' : 'toast error'; el.hidden = false;
      clearTimeout(window.toastTimer); window.toastTimer = setTimeout(() => { el.hidden = true; }, 3200);
    }
    function badge(label, tone) { return `<span class="badge ${tone || ''}">${esc(label)}</span>`; }
    function groupOptions(selected = 'all') {
      const groups = ['all', ...(state?.groups || [])];
      return groups.map(g => `<option value="${esc(g)}" ${g === selected ? 'selected' : ''}>${esc(g === 'all' ? 'Alle groepen' : g)}</option>`).join('');
    }
    function pageFromHash() { return (location.hash || '#dashboard').slice(1); }
    function showPage(page) {
      if (!pages[page]) page = 'dashboard';
      $$('.page').forEach(el => el.classList.toggle('active', el.id === `page-${page}`));
      $$('.side-nav a').forEach(a => a.classList.toggle('active', a.dataset.page === page));
      $('#page-title').textContent = pages[page][0];
      $('#page-subtitle').textContent = pages[page][1];
    }
    function metric(label, value, hint) { return `<article class="metric"><span>${esc(label)}</span><strong>${esc(value)}</strong><small>${esc(hint || '')}</small></article>`; }
    function renderMetrics() {
      const s = state.summary, f = state.status.features;
      const rows = [
        metric('Gebruikers', s.users, `${s.netbird_ips} NetBird IPs`),
        metric('Policies', s.groups, 'custom/NetBird groepen'),
        metric('Geblokkeerde domeinen', s.blocked_domains, `${s.allowed_domains} allowed`),
        metric('Categorieen', s.categories, `${s.active_category_blocks} actief`),
        f.weighted_phrases_enabled ? metric('Weighted phrases', s.phrase_rules, 'actieve rules') : '',
        metric('Events', s.events, 'persistent events.jsonl')
      ].filter(Boolean);
      $('#metrics').innerHTML = rows.join('');
    }
    function renderStatusStrip() {
      const st = state.status, f = st.features;
      const items = [
        ['ICAP', true, `${st.icap.host}:${st.icap.port}`],
        ['NetBird sync', f.netbird_sync_enabled, f.netbird_sync_enabled ? 'hook actief' : 'frontend hook/TODO'],
        ['Antivirus', f.antivirus_enabled, st.clamav.fail_open ? 'fail-open' : 'fail-closed'],
        ['DLP', f.dlp_enabled, 'POST body only'],
        ['Webfilter', f.webfiltering_enabled, f.domain_blocking_enabled ? 'domains actief' : 'domains uit'],
        ['Logging', f.logging_enabled, state.events.log_path || 'events.jsonl']
      ];
      $('#status-strip').innerHTML = items.map(([name, ok, hint]) => `<div class="status-pill">${badge(ok ? 'online' : 'uit', ok ? 'ok' : 'muted')}<div><b>${esc(name)}</b><span>${esc(hint)}</span></div></div>`).join('');
    }
    function drawBars(id, data, color) {
      const canvas = document.getElementById(id), empty = document.getElementById(id.replace('-chart', '-empty'));
      const entries = Object.entries(data || {}).slice(-12);
      if (empty) empty.hidden = entries.length > 0;
      if (!canvas || !entries.length) return;
      const dpr = window.devicePixelRatio || 1, rect = canvas.getBoundingClientRect();
      canvas.width = Math.max(320, rect.width) * dpr; canvas.height = 150 * dpr;
      const ctx = canvas.getContext('2d'); ctx.scale(dpr, dpr); ctx.clearRect(0,0,canvas.width,canvas.height);
      const max = Math.max(1, ...entries.map(([,v]) => v)); const w = rect.width / entries.length;
      entries.forEach(([k,v], i) => { const h = (v / max) * 104; ctx.fillStyle = color; ctx.fillRect(i*w + 7, 126-h, Math.max(12, w-14), h); ctx.fillStyle = getComputedStyle(document.body).getPropertyValue('--muted'); ctx.font='11px sans-serif'; ctx.fillText(k.slice(-5), i*w+6, 144); });
    }
    function drawRatio() {
      const c = $('#ratio-chart'), empty = $('#ratio-empty'); const allowed = state.analytics.allowed || 0, blocked = state.analytics.blocked || 0, total = allowed + blocked;
      empty.hidden = total > 0; if (!total) return;
      const dpr = window.devicePixelRatio || 1, rect = c.getBoundingClientRect(); c.width = Math.max(260, rect.width) * dpr; c.height = 150 * dpr;
      const ctx = c.getContext('2d'); ctx.scale(dpr,dpr); const cx = rect.width/2, cy = 75, r = 54; ctx.clearRect(0,0,rect.width,150);
      let start = -Math.PI/2; [[allowed,'#168251'],[blocked,'#b42318']].forEach(([val,color]) => { const end = start + (val/total)*Math.PI*2; ctx.beginPath(); ctx.moveTo(cx,cy); ctx.arc(cx,cy,r,start,end); ctx.closePath(); ctx.fillStyle=color; ctx.fill(); start=end; });
      ctx.fillStyle = getComputedStyle(document.body).getPropertyValue('--text'); ctx.font='700 18px sans-serif'; ctx.textAlign='center'; ctx.fillText(`${Math.round((allowed/total)*100)}% OK`, cx, cy+6);
    }
    function rankList(id, rows, empty) {
      $(id).innerHTML = (rows || []).map(([name, value]) => `<div class="rank-row"><span>${esc(name || 'onbekend')}</span><b>${esc(value.total || value)}</b></div>`).join('') || `<p class="empty">${esc(empty)}</p>`;
    }
    function renderCharts() {
      drawBars('traffic-chart', state.analytics.traffic_by_hour, '#0f6f95');
      drawBars('blocks-chart', state.analytics.blocks_by_hour, '#b42318');
      drawRatio();
      rankList('#top-categories', state.analytics.top_blocked_categories, 'Geen blocks geregistreerd');
      rankList('#top-users', state.analytics.top_users.map(([u,v]) => [u, v.total]), 'Geen gebruikersactiviteit');
      rankList('#top-domains', state.analytics.top_blocked_domains, 'Geen geblokkeerde domeinen');
    }
    function eventReason(e) {
      if (e.reason === 'dlp') return 'DLP-regel op POST body';
      if (e.reason === 'domain') return 'Domeinregel/blocklist';
      if (e.reason === 'phrase') return 'Weighted phrase threshold';
      if (e.reason === 'allowed_domain') return 'Allowlist prioriteit';
      if (e.reason === 'malware') return 'ClamAV detectie';
      return e.public_reason || e.reason || 'Onbekend';
    }
    function filteredEvents() {
      const events = state.events.recent || [];
      const filters = {
        q: $('#event-search')?.value.toLowerCase() || '', user: $('#event-user')?.value.toLowerCase() || '',
        ip: $('#event-ip')?.value.toLowerCase() || '', domain: $('#event-domain')?.value.toLowerCase() || '',
        category: $('#event-category')?.value.toLowerCase() || '', action: $('#event-action')?.value || '',
        date: $('#event-date')?.value || '', incident: $('#event-incident')?.value.toLowerCase() || ''
      };
      return events.filter(e => {
        const hay = JSON.stringify(e).toLowerCase();
        return (!filters.q || hay.includes(filters.q)) && (!filters.user || String(e.user||'').toLowerCase().includes(filters.user)) &&
          (!filters.ip || String(e.source_ip||'').toLowerCase().includes(filters.ip)) && (!filters.domain || (`${e.domain||''} ${e.url||''}`).toLowerCase().includes(filters.domain)) &&
          (!filters.category || (`${e.category||''} ${e.reason||''}`).toLowerCase().includes(filters.category)) && (!filters.action || e.action === filters.action) &&
          (!filters.date || String(e.ts||'').startsWith(filters.date)) && (!filters.incident || String(e.incident_id||'').toLowerCase().includes(filters.incident));
      });
    }
    function renderEvents() {
      const rows = filteredEvents();
      $('#events-table').innerHTML = rows.map((e, i) => `<tr data-event="${i}"><td>${esc(e.ts||'')}</td><td>${badge(e.action || 'unknown', e.action === 'block' ? 'bad' : 'ok')}</td><td>${esc(e.user||'')}</td><td>${esc(e.source_ip||'')}</td><td>${esc(e.domain||e.url||'')}</td><td>${esc(e.category||e.reason||'')}</td><td>${esc(e.policy||'')}</td><td>${esc(eventReason(e))}</td><td><code>${esc(e.incident_id||'')}</code></td></tr>`).join('') || '<tr><td colspan="9" class="empty">Geen logs gevonden</td></tr>';
      selectedEvent = rows[0] || null; renderEventDetail();
    }
    function renderEventDetail() {
      const e = selectedEvent; if (!e) { $('#event-detail').innerHTML = '<h2>Event details</h2><p class="empty">Selecteer een event om de details te bekijken.</p>'; return; }
      const rule = (e.dlp_hits||[])[0]?.name || (e.phrase_hits||[])[0]?.phrase || e.category || e.reason;
      $('#event-detail').innerHTML = `<h2>Event details</h2><dl class="detail-list"><dt>Incident</dt><dd>${esc(e.incident_id)}</dd><dt>Gebruiker</dt><dd>${esc(e.user)}</dd><dt>IP-adres</dt><dd>${esc(e.source_ip)}</dd><dt>URL/domein</dt><dd>${esc(e.url || e.domain)}</dd><dt>Policy</dt><dd>${esc(e.policy)}</dd><dt>Actie</dt><dd>${badge(e.action, e.action === 'block' ? 'bad' : 'ok')}</dd><dt>Waarom</dt><dd>${esc(eventReason(e))}</dd><dt>Regel</dt><dd>${esc(rule || 'n.v.t.')}</dd></dl><pre>${esc(JSON.stringify(e, null, 2))}</pre>`;
    }
    function renderLatestBlocks() {
      const blocks = (state.events.recent || []).filter(e => e.action === 'block').slice(0, 8);
      $('#latest-blocks').innerHTML = blocks.map(e => `<div class="mini-event"><b>${esc(e.domain || e.url || 'onbekend')}</b><span>${esc(e.user)} · ${esc(eventReason(e))} · ${esc(e.ts)}</span></div>`).join('') || '<p class="empty">Geen blocks geregistreerd</p>';
    }
    function renderQuickActions() {
      const f = state.status.features;
      const toggles = [
        ['webfiltering_enabled','Webfiltering'], ['domain_blocking_enabled','Domeinblokkering'], ['weighted_phrases_enabled','Weighted phrases'],
        ['dlp_enabled','DLP'], ['antivirus_enabled','Antivirus'], ['logging_enabled','Logging'], ['netbird_sync_enabled','NetBird sync hook'],
        ['allow_domains_bypass_content','Allow domains bypass content'], ['clamav_fail_open','ClamAV fail-open'], ['dlp_fail_open','DLP fail-open hook'], ['webfilter_fail_open','Webfilter fail-open hook']
      ];
      $('#quick-actions').innerHTML = toggles.map(([key,label]) => `<label class="switch-row"><span>${esc(label)}</span><input type="checkbox" data-setting="${key}" ${f[key] ? 'checked' : ''}></label>`).join('');
    }
    function renderSelectors() {
      const cat = $('#category-group')?.value || 'all';
      $('#category-group').innerHTML = groupOptions(cat); $('#domain-target').innerHTML = groupOptions($('#domain-target').value || 'all');
      $('#copy-from-group').innerHTML = ['all', ...(state.groups || [])].map(g => `<option value="${esc(g)}">${esc(g === 'all' ? 'common_policy' : g)}</option>`).join('');
    }
    function renderPolicies() {
      $('#policy-list').innerHTML = (state.groups || []).map(group => {
        const p = state.policies[group] || {}; const cats = Object.keys(p.phrase_thresholds || {}).length;
        return `<div class="policy-card"><div><h3>${esc(group)}</h3><p>${esc((p.blocked_domains||[]).length)} blocked · ${esc((p.allowed_domains||[]).length)} allowed · ${cats} phrase thresholds</p></div><div>${badge(p.dlp_enabled === false ? 'DLP uit' : 'DLP aan', p.dlp_enabled === false ? 'muted' : 'ok')} ${badge(p.malware === false ? 'AV uit' : 'AV aan', p.malware === false ? 'muted' : 'ok')}</div><button class="danger-btn" data-action="group-delete" data-group="${esc(group)}">Verwijder</button></div>`;
      }).join('') || '<p class="empty">Nog geen groep-policies. NetBird sync of handmatige groepen kunnen ze aanmaken.</p>';
    }
    function renderDomains() {
      const q = ($('#domain-search')?.value || '').toLowerCase();
      const rows = (state.domains || []).filter(r => (`${r.domain} ${r.label} ${r.list}`).toLowerCase().includes(q));
      $('#domains-table').innerHTML = rows.map(r => `<tr><td>${esc(r.domain)}</td><td>${esc(r.label)}</td><td>${badge(r.list === 'allowed_domains' ? 'allowlist' : r.list === 'hard_blocked_domains' ? 'hard block' : 'blocklist', r.list === 'allowed_domains' ? 'ok' : 'bad')}</td><td>${esc(r.list === 'allowed_domains' ? 'prioriteit boven blacklist' : 'actief')}</td><td>${esc((state.events.recent||[]).filter(e => e.domain === r.domain).length)}</td><td><button class="danger-btn" data-action="domain-remove" data-domain="${esc(r.domain)}" data-target="${esc(r.target)}" data-list="${esc(r.list)}">Verwijder</button></td></tr>`).join('') || '<tr><td colspan="6" class="empty">Geen domeinregels gevonden</td></tr>';
    }
    function renderCategories() {
      const target = $('#category-group').value || 'all'; const query = ($('#category-search').value || '').toLowerCase();
      const phraseOn = state.status.features.weighted_phrases_enabled;
      const rows = state.categories.filter(c => (`${c.key} ${c.en} ${c.nl}`).toLowerCase().includes(query));
      $('#category-list').innerHTML = rows.map(c => {
        const direct = c.thresholds[target] !== null && c.thresholds[target] !== undefined; const inherited = target !== 'all' && c.thresholds.all !== null && c.thresholds.all !== undefined;
        const active = phraseOn && (direct || inherited); const value = direct ? c.thresholds[target] : (c.default_threshold || 80);
        return `<div class="category-item ${active ? 'active' : ''} risk-${esc(c.risk)}"><div class="category-copy"><b>${esc(c.nl)}</b><span>${esc(c.en)} · ${esc(c.key)} · ${esc(c.phrase_rules)} phrases · ${phraseOn ? 'engine aan' : 'engine uit'}</span>${inherited ? '<em>Geerfd via alle groepen</em>' : ''}</div><div class="row-actions"><input class="threshold-input" type="number" min="0" max="999" value="${esc(value)}"><button data-action="category-enable" data-category="${esc(c.key)}">Opslaan</button>${direct ? `<button class="danger-btn" data-action="category-disable" data-category="${esc(c.key)}">Uit</button>` : ''}</div></div>`;
      }).join('');
    }
    function renderPhrases() {
      $('#phrase-list').innerHTML = state.categories.map(c => `<div class="policy-card"><div><h3>${esc(c.nl)}</h3><p>${esc(c.key)} · ${esc(c.phrase_rules)} geladen rules · ${c.phrase_file ? 'map aanwezig' : 'lege categorie'}</p></div>${badge(state.status.features.weighted_phrases_enabled && c.phrase_rules ? 'actief mogelijk' : 'uit/leeg', state.status.features.weighted_phrases_enabled && c.phrase_rules ? 'ok' : 'muted')}</div>`).join('');
    }
    function userRows() {
      const users = Object.entries(state.users || {}).map(([user, obj]) => ({user, obj, ips: Object.entries(state.ip_map || {}).filter(([,map]) => map.user === user).map(([ip]) => ip)}));
      const q = ($('#user-search')?.value || '').toLowerCase();
      return users.filter(row => JSON.stringify(row).toLowerCase().includes(q));
    }
    function renderUsers() {
      const rows = userRows(); selectedUser = selectedUser || rows[0]?.user || null;
      $('#users-list').innerHTML = rows.map(row => `<button class="user-row ${selectedUser === row.user ? 'active' : ''}" data-user="${esc(row.user)}"><b>${esc(row.user)}</b><span>${esc((row.obj.groups||[]).join(', ') || 'geen groepen')} ${row.ips.length ? '· ' + esc(row.ips.join(', ')) : ''}</span></button>`).join('') || '<p class="empty">Geen gebruikers gevonden</p>';
      renderUserDetail();
    }
    function renderUserDetail() {
      const user = selectedUser, obj = (state.users || {})[user]; if (!user || !obj) { $('#user-detail').innerHTML = '<h2>Gebruikersdetail</h2><p class="empty">Kies links een gebruiker.</p>'; return; }
      const events = (state.events.recent || []).filter(e => e.user === user); const blocks = events.filter(e => e.action === 'block');
      const ips = Object.entries(state.ip_map || {}).filter(([,map]) => map.user === user).map(([ip]) => ip);
      $('#user-detail').innerHTML = `<h2>${esc(user)}</h2><dl class="detail-list"><dt>Naam</dt><dd>${esc(obj.name || user)}</dd><dt>E-mail</dt><dd>${esc(user)}</dd><dt>IP-adressen</dt><dd>${esc(ips.join(', ') || 'onbekend')}</dd><dt>NetBird peer info</dt><dd>${esc([...(obj.netbird_hostnames||[]), ...(obj.netbird_peer_ids||[])].join(', ') || 'niet beschikbaar')}</dd><dt>Groepen</dt><dd>${esc((obj.groups||[]).join(', ') || 'geen')}</dd><dt>Policies</dt><dd>${esc((obj.groups||[]).filter(g => state.policies[g]).join(', ') || 'common_policy')}</dd><dt>Allowed requests</dt><dd>${events.filter(e => e.action === 'allow').length}</dd><dt>Blocked requests</dt><dd>${blocks.length}</dd></dl><h3>Recente blocks</h3><div class="event-list">${blocks.slice(0,8).map(e => `<div class="mini-event"><b>${esc(e.domain||e.url)}</b><span>${esc(eventReason(e))} · regel: ${esc(e.category||e.reason)}</span></div>`).join('') || '<p class="empty">Geen recente blocks</p>'}</div><h3>Geschiedenis</h3><div class="event-list">${events.slice(0,12).map(e => `<div class="mini-event"><b>${esc(e.action)} · ${esc(e.domain||e.url)}</b><span>${esc(e.ts)} · ${esc(e.policy||'common')}</span></div>`).join('') || '<p class="empty">Geen recente logs</p>'}</div>`;
    }
    function renderDlp() {
      const rules = state.dlp.rules || [];
      $('#dlp-list').innerHTML = rules.map((rule, index) => `<div class="list-row"><div><b>${esc(rule.name)}</b><span>${rule.enabled ? 'Actief' : 'Uit'} · ${esc(rule.builtin || rule.pattern || '')} · groepen: ${esc((rule.groups || []).join(', ') || 'alle')}</span></div><button data-action="dlp-toggle" data-index="${index}" data-enabled="${rule.enabled ? 'false' : 'true'}">${rule.enabled ? 'Uitzetten' : 'Aanzetten'}</button></div>`).join('') || '<p class="empty">Geen DLP regels gevonden</p>';
    }
    function renderServices() {
      const st = state.status, f = st.features;
      const rows = [['ICAP', true, `${st.icap.host}:${st.icap.port}`], ['NetBird sync', f.netbird_sync_enabled, 'UI hook, script/scheduler extern'], ['Webfilter', f.webfiltering_enabled, f.domain_blocking_enabled ? 'domain blocking aan' : 'domain blocking uit'], ['DLP', f.dlp_enabled, 'REQMOD POST body only'], ['Antivirus/ClamAV', f.antivirus_enabled, f.clamav_fail_open ? 'fail-open' : 'fail-closed'], ['Logging', f.logging_enabled, state.events.log_path], ['Config', true, st.config_version]];
      $('#service-cards').innerHTML = rows.map(([name, ok, hint]) => `<div class="service-card"><h3>${esc(name)}</h3>${badge(ok ? 'OK' : 'UIT/TODO', ok ? 'ok' : 'muted')}<p>${esc(hint)}</p></div>`).join('');
      $('#todo-hooks').innerHTML = Object.entries(st.todos || {}).map(([k,v]) => `<p><b>${esc(k)}</b>: ${esc(v)}</p>`).join('');
    }
    function renderFiles() {
      $('#files').innerHTML = (state.editable_files || []).map(f => `<a class="file-tile" href="/edit?path=${encodeURIComponent(f.path)}"><b>${esc(f.path)}</b><span>${esc(f.size)} bytes · ${esc(f.mtime)}</span></a>`).join('') || '<p class="empty">Geen bewerkbare bestanden</p>';
    }
    async function refresh() {
      state = await api('/api/policy');
      renderMetrics(); renderStatusStrip(); renderSelectors(); renderCharts(); renderLatestBlocks(); renderQuickActions(); renderEvents(); renderPolicies(); renderDomains(); renderCategories(); renderPhrases(); renderUsers(); renderDlp(); renderServices(); renderFiles();
    }
    function initPrefs() {
      const collapsed = localStorage.getItem('icap.sidebar.collapsed') === '1';
      document.body.classList.toggle('sidebar-collapsed', collapsed);
      const theme = localStorage.getItem('icap.theme') || 'auto';
      if (theme !== 'auto') document.body.dataset.theme = theme;
    }
    initPrefs(); showPage(pageFromHash());
    window.addEventListener('hashchange', () => showPage(pageFromHash()));
    $('#sidebar-toggle').addEventListener('click', () => { document.body.classList.toggle('sidebar-collapsed'); localStorage.setItem('icap.sidebar.collapsed', document.body.classList.contains('sidebar-collapsed') ? '1' : '0'); });
    $('#theme-toggle').addEventListener('click', () => { const next = document.body.dataset.theme === 'dark' ? 'light' : 'dark'; document.body.dataset.theme = next; localStorage.setItem('icap.theme', next); });
    $('#reload').addEventListener('click', async () => { await api('/api/reload', {method:'POST'}); await refresh(); toast('Configuratie herladen'); });
    ['event-search','event-user','event-ip','event-domain','event-category','event-action','event-date','event-incident'].forEach(id => document.addEventListener('input', ev => { if (ev.target.id === id) renderEvents(); }));
    document.addEventListener('change', async ev => { if (ev.target.matches('input[data-setting]')) { try { await post('/api/settings', {key: ev.target.dataset.setting, enabled: ev.target.checked}); await refresh(); toast('Instelling opgeslagen'); } catch (err) { toast(err.message, false); } } });
    document.addEventListener('click', async ev => {
      const eventRow = ev.target.closest('tr[data-event]'); if (eventRow) { selectedEvent = filteredEvents()[Number(eventRow.dataset.event)]; renderEventDetail(); return; }
      const userRow = ev.target.closest('.user-row'); if (userRow) { selectedUser = userRow.dataset.user; renderUsers(); return; }
      const btn = ev.target.closest('button[data-action]'); if (!btn) return;
      try {
        if (btn.dataset.action === 'domain-remove') await post('/api/policy/domain', {target: btn.dataset.target, domain: btn.dataset.domain, list: btn.dataset.list, action:'remove'});
        if (btn.dataset.action === 'group-delete') await post('/api/policy/group', {group: btn.dataset.group, action:'delete'});
        if (btn.dataset.action === 'category-enable') { const row = btn.closest('.category-item'); await post('/api/policy/category', {target: $('#category-group').value, category: btn.dataset.category, enabled:true, threshold: row.querySelector('.threshold-input').value}); }
        if (btn.dataset.action === 'category-disable') await post('/api/policy/category', {target: $('#category-group').value, category: btn.dataset.category, enabled:false});
        if (btn.dataset.action === 'dlp-toggle') await post('/api/dlp/rule', {index: btn.dataset.index, enabled: btn.dataset.enabled});
        await refresh(); toast('Wijziging opgeslagen');
      } catch (err) { toast(err.message, false); }
    });
    $('#domain-form').addEventListener('submit', async ev => { ev.preventDefault(); try { await post('/api/policy/domain', {...Object.fromEntries(new FormData(ev.target).entries()), action:'add'}); ev.target.reset(); await refresh(); toast('Domeinregel toegevoegd'); } catch (err) { toast(err.message, false); } });
    $('#group-form').addEventListener('submit', async ev => { ev.preventDefault(); try { await post('/api/policy/group', {...Object.fromEntries(new FormData(ev.target).entries()), action:'add'}); ev.target.reset(); await refresh(); toast('Groep aangemaakt'); } catch (err) { toast(err.message, false); } });
    $('#category-group').addEventListener('change', renderCategories); $('#category-search').addEventListener('input', renderCategories); $('#domain-search').addEventListener('input', renderDomains); $('#user-search').addEventListener('input', renderUsers);
    refresh().catch(err => toast(err.message, false));
  </script>
</body>
</html>"""
    return html.replace("__DASHBOARD_CSS__", DASHBOARD_CSS).replace("__MODERN_CSS__", MODERN_DASHBOARD_CSS)


def render_dashboard() -> str:
    return f"""<!doctype html>
<html lang="nl">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>School ICAP Guard</title>
  <style>{DASHBOARD_CSS}</style>
</head>
<body>
  <header>
    <h1>School ICAP Guard</h1>
    <nav>
      <a href="/">Status</a>
      <a href="/edit?path=config.json">Config</a>
      <a href="/edit?path=users.json">Users</a>
      <a href="/edit?path=dlp_rules.json">DLP</a>
      <a href="/test">Test</a>
    </nav>
  </header>
  <main>
    <section class="panel">
      <div class="panel-head">
        <h2>Status</h2>
        <button id="reload">Reload</button>
      </div>
      <pre id="status">laden...</pre>
    </section>
    <section class="grid">
      <div class="panel">
        <h2>Bestanden</h2>
        <div id="files"></div>
      </div>
      <div class="panel">
        <h2>Events</h2>
        <div id="events"></div>
      </div>
    </section>
  </main>
  <script>
    async function getJSON(url) {{
      const res = await fetch(url);
      if (!res.ok) throw new Error(await res.text());
      return res.json();
    }}
    function esc(s) {{
      return String(s ?? '').replace(/[&<>"']/g, c => ({{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}}[c]));
    }}
    async function refresh() {{
      const status = await getJSON('/api/status');
      document.getElementById('status').textContent = JSON.stringify(status, null, 2);
      document.getElementById('files').innerHTML = status.editable_files.map(f =>
        `<a class="file" href="/edit?path=${{encodeURIComponent(f.path)}}">${{esc(f.path)}} <span>${{f.size}} bytes</span></a>`
      ).join('');
      const events = await getJSON('/api/events');
      document.getElementById('events').innerHTML = events.recent.slice(0, 40).map(e =>
        `<div class="event ${{e.action}}"><b>${{esc(e.action)}}/${{esc(e.reason)}}</b><span>${{esc(e.user)}} · ${{esc(e.domain)}} · ${{esc(e.ts)}}</span></div>`
      ).join('');
    }}
    document.getElementById('reload').addEventListener('click', async () => {{
      await fetch('/api/reload', {{method: 'POST'}});
      await refresh();
    }});
    refresh().catch(err => document.getElementById('status').textContent = err);
  </script>
</body>
</html>"""


def render_editor(path: str, content: str) -> str:
    escaped_path = html_lib.escape(path)
    escaped_content = html_lib.escape(content)
    return f"""<!doctype html>
<html lang="nl">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{escaped_path}</title>
  <style>{DASHBOARD_CSS}</style>
</head>
<body>
  <header>
    <h1>{escaped_path}</h1>
    <nav><a href="/">Status</a><a href="/test">Test</a></nav>
  </header>
  <main>
    <form method="post" action="/save" class="editor">
      <input type="hidden" name="path" value="{escaped_path}">
      <textarea name="content" spellcheck="false">{escaped_content}</textarea>
      <div class="actions">
        <button type="submit">Opslaan en reload</button>
        <a class="button" href="/">Terug</a>
      </div>
    </form>
  </main>
</body>
</html>"""


def render_test_page() -> str:
    return f"""<!doctype html>
<html lang="nl">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Policy test</title>
  <style>{DASHBOARD_CSS}</style>
</head>
<body>
  <header>
    <h1>Policy test</h1>
    <nav><a href="/">Status</a><a href="/edit?path=config.json">Config</a></nav>
  </header>
  <main>
    <section class="panel">
      <form id="test-form" class="test-grid">
        <label>URL<input name="url" value="https://example.org/"></label>
        <label>Gebruiker<input name="user" value="student@example.org"></label>
        <label>Groepen<input name="groups" value="default"></label>
        <label>ICAP richting<select name="direction"><option value="reqmod">REQMOD</option><option value="respmod">RESPMOD</option></select></label>
        <label>HTTP methode<select name="http_method"><option value="GET">GET</option><option value="POST">POST</option><option value="PUT">PUT</option></select></label>
        <label>Content-Type<input name="content_type" value="text/plain"></label>
        <label class="check"><input name="skip_clamav" type="checkbox" checked> ClamAV overslaan</label>
        <label class="wide">Body<textarea name="body">casino test</textarea></label>
        <button type="submit">Test policy</button>
      </form>
    </section>
    <section class="panel"><pre id="result"></pre></section>
  </main>
  <script>
    document.getElementById('test-form').addEventListener('submit', async (ev) => {{
      ev.preventDefault();
      const form = new FormData(ev.target);
      const data = Object.fromEntries(form.entries());
      if (!form.has('skip_clamav')) data.skip_clamav = 'off';
      const res = await fetch('/api/test', {{method: 'POST', headers: {{'Content-Type': 'application/json'}}, body: JSON.stringify(data)}});
      document.getElementById('result').textContent = JSON.stringify(await res.json(), null, 2);
    }});
  </script>
</body>
</html>"""


DASHBOARD_CSS = """
:root {
  color-scheme: light dark;
  font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  background: #eef2f5;
  color: #17202a;
}
* { box-sizing: border-box; }
body { margin: 0; min-height: 100vh; background: #eef2f5; color: #17202a; }
body.centered { display: grid; place-items: center; }
header {
  position: sticky; top: 0; z-index: 2;
  display: flex; align-items: center; justify-content: space-between; gap: 20px;
  padding: 14px 22px; background: #ffffff; border-bottom: 1px solid #d8dee6;
}
h1 { margin: 0; font-size: 20px; letter-spacing: 0; }
h2 { margin: 0 0 12px; font-size: 16px; letter-spacing: 0; }
nav { display: flex; gap: 8px; flex-wrap: wrap; }
a, button, .button {
  color: #0f4f76; background: #e7f1f7; border: 1px solid #b9d1df; border-radius: 6px;
  text-decoration: none; padding: 8px 10px; font: inherit; cursor: pointer;
}
button:hover, a:hover, .button:hover { background: #d7eaf5; }
main { width: min(1400px, calc(100vw - 28px)); margin: 18px auto; }
.grid { display: grid; grid-template-columns: minmax(320px, 0.9fr) minmax(360px, 1.1fr); gap: 16px; margin-top: 16px; }
.panel, .login {
  background: #ffffff; border: 1px solid #d8dee6; border-radius: 8px; padding: 16px;
  box-shadow: 0 14px 30px rgba(15, 23, 42, .07);
}
.panel-head { display: flex; align-items: center; justify-content: space-between; gap: 12px; }
pre {
  overflow: auto; max-height: 62vh; margin: 0; padding: 12px; border-radius: 6px;
  background: #15202b; color: #e9f1f7; font-size: 13px; line-height: 1.45;
}
.file { display: flex; justify-content: space-between; gap: 12px; margin: 7px 0; background: #f7fafc; color: #17202a; border-color: #d8dee6; }
.file span { color: #64748b; }
.event { border: 1px solid #d8dee6; border-left-width: 5px; border-radius: 6px; padding: 9px; margin: 7px 0; background: #f7fafc; }
.event.block { border-left-color: #b42318; }
.event.allow { border-left-color: #168251; }
.event span { display: block; color: #536173; margin-top: 3px; word-break: break-word; }
.editor textarea {
  width: 100%; height: calc(100vh - 150px); resize: vertical; border: 1px solid #b9c4d0; border-radius: 8px;
  padding: 12px; background: #101820; color: #f4f7fb; font: 13px/1.45 ui-monospace, SFMono-Regular, Consolas, monospace;
}
.actions { display: flex; gap: 10px; margin-top: 10px; }
.login { width: min(440px, calc(100vw - 28px)); }
label { display: grid; gap: 6px; font-weight: 700; color: #334155; }
.check { display: flex; align-items: center; gap: 8px; }
.check input { width: auto; }
input, textarea, select {
  width: 100%; border: 1px solid #b9c4d0; border-radius: 6px; padding: 10px;
  font: inherit; background: #fff; color: #17202a;
}
.login form, .test-grid { display: grid; gap: 12px; }
.test-grid { grid-template-columns: repeat(2, minmax(220px, 1fr)); }
.wide { grid-column: 1 / -1; }
.test-grid textarea { height: 160px; font-family: ui-monospace, SFMono-Regular, Consolas, monospace; }
.error { color: #b42318; font-weight: 700; }
.summary-grid {
  display: grid;
  grid-template-columns: repeat(6, minmax(130px, 1fr));
  gap: 12px;
  margin-bottom: 16px;
}
.stat {
  min-height: 86px;
  display: grid;
  align-content: center;
  gap: 4px;
  background: #ffffff;
  border: 1px solid #d8dee6;
  border-radius: 8px;
  padding: 14px;
  box-shadow: 0 10px 22px rgba(15, 23, 42, .05);
}
.stat span { color: #64748b; font-size: 13px; font-weight: 750; }
.stat b { font-size: 27px; letter-spacing: 0; }
.admin-grid {
  display: grid;
  grid-template-columns: minmax(360px, 1fr) minmax(360px, 1fr);
  gap: 16px;
}
.wide-panel { grid-column: 1 / -1; }
.hint { color: #64748b; margin: 4px 0 0; line-height: 1.45; }
.toolbar {
  display: grid;
  grid-template-columns: minmax(180px, 260px) minmax(260px, 1fr);
  gap: 12px;
  margin: 14px 0;
}
.inline-form {
  display: grid;
  grid-template-columns: repeat(2, minmax(180px, 1fr));
  gap: 12px;
  align-items: end;
}
.inline-form button { min-height: 42px; }
.category-list {
  display: grid;
  grid-template-columns: repeat(2, minmax(320px, 1fr));
  gap: 10px;
}
.category-item {
  display: grid;
  grid-template-columns: minmax(0, 1fr) auto;
  gap: 12px;
  align-items: center;
  min-height: 92px;
  padding: 12px;
  border: 1px solid #d8dee6;
  border-left-width: 5px;
  border-radius: 8px;
  background: #f8fafc;
}
.category-item.active { background: #eef9f3; border-color: #9fcfb7; border-left-color: #168251; }
.category-item.risk-critical.active, .category-item.risk-high.active { background: #fff4f2; border-color: #e6a39a; border-left-color: #b42318; }
.category-item.risk-medium.active { background: #fff8e6; border-color: #e0bd57; border-left-color: #b7791f; }
.category-copy { min-width: 0; display: grid; gap: 4px; }
.category-copy b { font-size: 15px; }
.category-copy span, .category-copy em { color: #64748b; font-size: 13px; line-height: 1.35; }
.category-copy em { color: #168251; font-style: normal; font-weight: 750; }
.row-actions {
  display: grid;
  grid-template-columns: 88px 1fr;
  gap: 8px;
  align-items: center;
  min-width: 260px;
}
.row-actions .danger-btn { grid-column: 2; }
.threshold-input { text-align: center; }
.danger-btn {
  color: #9f1d13;
  background: #fff0ee;
  border-color: #e6a39a;
}
.danger-btn:hover { background: #ffe2de; }
.list-stack { display: grid; gap: 8px; margin-top: 12px; }
.list-row {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 12px;
  min-height: 56px;
  padding: 10px;
  border: 1px solid #d8dee6;
  border-radius: 8px;
  background: #f8fafc;
}
.list-row div { min-width: 0; }
.list-row span { display: block; margin-top: 3px; color: #64748b; font-size: 13px; word-break: break-word; }
.list-row.compact { min-height: 44px; }
.events-grid { display: grid; grid-template-columns: repeat(2, minmax(260px, 1fr)); gap: 8px; }
.spaced { margin-top: 18px; }
.toast {
  position: fixed;
  right: 18px;
  bottom: 18px;
  max-width: min(460px, calc(100vw - 36px));
  padding: 12px 14px;
  border-radius: 8px;
  border: 1px solid #b9d1df;
  background: #ffffff;
  box-shadow: 0 16px 40px rgba(15, 23, 42, .18);
  font-weight: 750;
  z-index: 10;
}
.toast.ok { border-color: #8bc2a8; color: #11643d; }
.toast.error { border-color: #e6a39a; color: #9f1d13; }
@media (max-width: 800px) {
  header { align-items: flex-start; flex-direction: column; }
  .grid, .test-grid, .admin-grid, .summary-grid, .category-list, .toolbar, .inline-form, .events-grid { grid-template-columns: 1fr; }
  .wide-panel { grid-column: auto; }
  .category-item { grid-template-columns: 1fr; }
  .row-actions { min-width: 0; grid-template-columns: 88px 1fr; }
}
@media (prefers-color-scheme: dark) {
  :root, body { background: #10141b; color: #e9eef5; }
  header, .panel, .login { background: #19212b; border-color: #344052; }
  a, button, .button { background: #253445; border-color: #456073; color: #bde7ff; }
  a:hover, button:hover, .button:hover { background: #304357; }
  label { color: #c3cedb; }
  input, textarea, select { background: #101820; color: #f4f7fb; border-color: #465568; }
  .file, .event, .stat, .category-item, .list-row, .toast { background: #202a36; color: #e9eef5; border-color: #344052; }
  .file span, .event span, .hint, .stat span, .category-copy span, .list-row span { color: #aab7c6; }
  .category-item.active { background: #102b22; border-color: #2f7756; }
  .category-item.risk-critical.active, .category-item.risk-high.active { background: #3a1715; border-color: #7f2a23; }
  .category-item.risk-medium.active { background: #33270c; border-color: #745b16; }
  .danger-btn { background: #3a1715; border-color: #7f2a23; color: #ffb4aa; }
}
"""



# Uitgebreide ingebouwde phrase seeds voor alle E2Guardian-categorieën.
# Deze seeds zijn bedoeld als veilige, onderhoudbare basis voor labo/PoC-gebruik.
# Zet officiële of school-specifieke e2guardian/DansGuardian lijsten gewoon in
# config/phrases/<categorie>/ als extra .weightedphraselist-bestanden.
MODERN_DASHBOARD_CSS = """
:root { --bg:#f4f7fb; --surface:#fff; --surface-2:#eef4f8; --text:#17202a; --muted:#64748b; --line:#d9e2ec; --brand:#0f6f95; --danger:#b42318; --shadow:0 16px 34px rgba(15,23,42,.08); }
body.app-shell { min-height:100vh; overflow-x:hidden; background:var(--bg); color:var(--text); }
.sidebar { position:fixed; inset:0 auto 0 0; width:260px; background:#101820; color:#f4f7fb; border-right:1px solid rgba(255,255,255,.08); z-index:20; transition:width .2s ease, transform .2s ease; }
.brand { display:flex; align-items:center; gap:12px; padding:18px; min-height:74px; }
.brand-mark { display:grid; place-items:center; width:40px; height:40px; border-radius:8px; background:var(--brand); color:white; font-weight:900; }
.brand-copy { display:grid; gap:2px; min-width:0; } .brand-copy span { color:#9fb1c2; font-size:12px; }
.side-nav { display:grid; gap:4px; padding:8px; } .side-nav a { display:block; color:#dce8f2; background:transparent; border:0; padding:10px 12px; border-radius:6px; }
.side-nav a.active, .side-nav a:hover { background:rgba(15,111,149,.24); color:#fff; }
.app-main { margin-left:260px; min-width:0; transition:margin-left .2s ease; }
.topbar { position:sticky; top:0; z-index:12; min-height:74px; display:flex; align-items:center; justify-content:space-between; gap:16px; padding:14px 22px; background:rgba(255,255,255,.92); backdrop-filter:blur(14px); border-bottom:1px solid var(--line); }
.topbar-left,.topbar-actions { display:flex; align-items:center; gap:12px; min-width:0; } .topbar h1 { margin:0; font-size:21px; } .topbar p { margin:2px 0 0; color:var(--muted); }
.icon-btn,.ghost-btn,.primary-btn { min-height:38px; border-radius:6px; border:1px solid var(--line); } .icon-btn { width:40px; padding:0; background:var(--surface); } .ghost-btn { background:var(--surface); color:var(--text); } .primary-btn { background:var(--brand); color:white; border-color:var(--brand); }
.content { width:min(1500px, calc(100vw - 300px)); margin:18px auto; } .page { display:none; } .page.active { display:block; }
.metric-grid { display:grid; grid-template-columns:repeat(6,minmax(130px,1fr)); gap:12px; margin-bottom:14px; }
.metric,.card,.service-card,.policy-card { background:var(--surface); border:1px solid var(--line); border-radius:8px; box-shadow:var(--shadow); }
.metric { min-height:96px; display:grid; align-content:center; gap:3px; padding:15px; } .metric span,.metric small,.card-head span,.service-card p,.policy-card p { color:var(--muted); } .metric strong { font-size:28px; line-height:1; }
.status-strip { display:grid; grid-template-columns:repeat(6,minmax(150px,1fr)); gap:10px; margin-bottom:16px; }
.status-pill { display:flex; align-items:center; gap:9px; padding:10px; background:var(--surface); border:1px solid var(--line); border-radius:8px; min-width:0; } .status-pill span:last-child { display:block; color:var(--muted); font-size:12px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
.dashboard-grid { display:grid; grid-template-columns:repeat(4,minmax(0,1fr)); gap:16px; } .card { padding:16px; min-width:0; } .span-2 { grid-column:span 2; }
.card-head { display:flex; align-items:center; justify-content:space-between; gap:12px; margin-bottom:12px; } .card-head h2 { margin:0; font-size:16px; } canvas { width:100%; max-width:100%; display:block; }
.empty { color:var(--muted); margin:10px 0; } .rank-list,.event-list,.service-grid,.policy-grid,.file-grid,.toggle-grid { display:grid; gap:9px; }
.rank-row,.mini-event,.policy-card,.service-card,.file-tile { padding:11px; border:1px solid var(--line); border-radius:7px; background:var(--surface-2); } .rank-row { display:flex; justify-content:space-between; gap:10px; } .mini-event span,.file-tile span { display:block; color:var(--muted); margin-top:4px; word-break:break-word; }
.badge { display:inline-flex; align-items:center; min-height:24px; border-radius:999px; padding:3px 8px; font-size:12px; font-weight:800; color:#334155; background:#e5edf4; } .badge.ok { color:#0f5132; background:#d9f3e6; } .badge.bad { color:#842029; background:#ffe0dc; } .badge.muted { color:#475569; background:#e5e7eb; }
.filter-grid { display:grid; grid-template-columns:repeat(4,minmax(160px,1fr)); gap:10px; margin-bottom:12px; } .table-wrap { width:100%; overflow-x:auto; border:1px solid var(--line); border-radius:8px; }
table { width:100%; border-collapse:collapse; min-width:900px; background:var(--surface); } th,td { padding:10px; border-bottom:1px solid var(--line); text-align:left; vertical-align:top; } th { color:var(--muted); font-size:12px; text-transform:uppercase; letter-spacing:0; background:var(--surface-2); } tr:hover td { background:rgba(15,111,149,.06); cursor:pointer; }
.detail-card pre { max-height:320px; } .detail-list { display:grid; grid-template-columns:150px minmax(0,1fr); gap:8px 12px; } .detail-list dt { color:var(--muted); font-weight:800; } .detail-list dd { margin:0; min-width:0; word-break:break-word; }
.split-grid { display:grid; grid-template-columns:minmax(300px,420px) minmax(0,1fr); gap:16px; } .user-row { display:grid; width:100%; text-align:left; gap:3px; background:var(--surface-2); color:var(--text); border-color:var(--line); } .user-row.active { outline:2px solid var(--brand); } .user-row span { color:var(--muted); }
.modern-form { margin:10px 0 14px; } .modern-toolbar { margin:0 0 14px; } .policy-grid { grid-template-columns:repeat(2,minmax(260px,1fr)); } .policy-card { display:grid; grid-template-columns:minmax(0,1fr) auto auto; align-items:center; gap:12px; box-shadow:none; }
.service-grid { grid-template-columns:repeat(4,minmax(180px,1fr)); margin-bottom:12px; } .service-card { box-shadow:none; padding:14px; } .toggle-grid { grid-template-columns:repeat(3,minmax(220px,1fr)); }
.switch-row { display:flex; justify-content:space-between; align-items:center; gap:10px; min-height:42px; padding:10px; border:1px solid var(--line); border-radius:7px; background:var(--surface-2); } .switch-row input { width:auto; transform:scale(1.1); }
.notice { padding:12px; border:1px solid #b9d1df; background:#eaf5fb; color:#16445e; border-radius:8px; margin-bottom:14px; } .file-grid { grid-template-columns:repeat(3,minmax(220px,1fr)); } .file-tile { color:var(--text); text-decoration:none; }
footer { padding:18px 22px; color:var(--muted); text-align:center; }
body.sidebar-collapsed .sidebar { width:72px; } body.sidebar-collapsed .brand-copy, body.sidebar-collapsed .side-nav a { font-size:0; } body.sidebar-collapsed .app-main { margin-left:72px; } body.sidebar-collapsed .content { width:min(1500px, calc(100vw - 112px)); }
body[data-theme="dark"], body[data-theme="dark"].app-shell { --bg:#10141b; --surface:#19212b; --surface-2:#202b36; --text:#e9eef5; --muted:#aab7c6; --line:#344052; --shadow:0 16px 34px rgba(0,0,0,.22); } body[data-theme="dark"] .topbar { background:rgba(25,33,43,.92); } body[data-theme="dark"] .notice { background:#142938; color:#bde7ff; border-color:#31566a; } body[data-theme="dark"] input, body[data-theme="dark"] select, body[data-theme="dark"] textarea { background:#101820; color:#f4f7fb; border-color:#465568; }
@media (prefers-color-scheme: dark) { body.app-shell:not([data-theme="light"]) { --bg:#10141b; --surface:#19212b; --surface-2:#202b36; --text:#e9eef5; --muted:#aab7c6; --line:#344052; --shadow:0 16px 34px rgba(0,0,0,.22); } body.app-shell:not([data-theme="light"]) .topbar { background:rgba(25,33,43,.92); } }
@media (max-width:1100px) { .metric-grid,.status-strip { grid-template-columns:repeat(3,minmax(0,1fr)); } .dashboard-grid,.service-grid,.file-grid { grid-template-columns:repeat(2,minmax(0,1fr)); } .filter-grid,.toggle-grid,.policy-grid { grid-template-columns:repeat(2,minmax(0,1fr)); } .span-2 { grid-column:span 2; } }
@media (max-width:820px) { .sidebar { transform:translateX(-100%); width:260px; } body:not(.sidebar-collapsed) .sidebar { transform:translateX(0); } .app-main,body.sidebar-collapsed .app-main { margin-left:0; } .content,body.sidebar-collapsed .content { width:min(100%, calc(100vw - 22px)); } .topbar { align-items:flex-start; flex-direction:column; } .metric-grid,.status-strip,.dashboard-grid,.service-grid,.file-grid,.filter-grid,.toggle-grid,.policy-grid,.split-grid { grid-template-columns:1fr; } .span-2 { grid-column:auto; } .policy-card { grid-template-columns:1fr; } }
"""


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
    entry = catalog_entry(category)
    key = entry["key"]
    seeds = DEFAULT_DUTCH_PHRASE_SEEDS.get(key) if language == "dutch" else DEFAULT_ENGLISH_PHRASE_SEEDS.get(key)
    if not seeds:
        label = entry.get("nl" if language == "dutch" else "en", key)
        seeds = [key.replace("_", " "), str(label).lower()]
    base_weight = 12
    risk = entry.get("risk", "medium")
    if risk in {"critical", "high"}:
        base_weight = 35
    elif risk == "medium":
        base_weight = 20
    elif risk == "allow":
        base_weight = -35
    lines = [
        f'#listcategory: "{key}"',
        f"# Auto-generated default {language} weighted phrase list for {entry.get('en', key)} / {entry.get('nl', key)}.",
        "# Format: {weight}<phrase>. Higher positive weight blocks faster; negative weight lowers score.",
        "# Replace/extend these seeds with your official e2guardian lists if available.",
        "",
    ]
    for phrase in seeds:
        phrase = phrase.strip()
        if not phrase:
            continue
        lines.append(f"{{{base_weight}}}<{phrase}>")
    if key != "goodphrases":
        lines.extend(["", "# Safe educational context exceptions", "{-30}<school project>", "{-30}<security training>", "{-25}<medical awareness>"])
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
        "scan": {
            "text_scan_bytes": DEFAULT_TEXT_SCAN_BYTES,
        },
        "logging": {
            "enabled": True,
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
            "enabled": False,
            "default_weight": 10,
            "extensions": [".weightedphraselist", ".phraselist", ".txt"],
            "match_individual_tags": False,
        },
        "identity": {
            "default_group": "default",
            "netbird_sync_enabled": False,
            "client_ip_headers": ["X-Client-IP", "X-Forwarded-For", "X-Real-IP"],
            "username_headers": ["X-Client-Username", "X-Authenticated-User", "X-Squid-Username"],
            "http_username_headers": ["X-NetBird-User", "X-Authenticated-User"],
            "entra_object_headers": ["X-Entra-Object-Id", "X-MS-CLIENT-PRINCIPAL-ID"],
            "entra_group_headers": ["X-Entra-Groups", "X-MS-CLIENT-PRINCIPAL-GROUPS"],
            "entra_group_map": {},
        },
        "common_policy": {
            "webfiltering_enabled": True,
            "domain_blocking_enabled": True,
            "malware": True,
            "dlp_enabled": True,
            "dlp_score_threshold": 60,
            "dlp_fail_open": False,
            "webfilter_fail_open": False,
            "max_body_bytes": DEFAULT_BODY_LIMIT,
            "oversize_action": "allow",
            "hard_blocked_domains": ["malware.test.invalid"],
            "blocked_domains": [],
            "allowed_domains": ["*.school.example"],
            "allow_domains_bypass_content": False,
            "blocked_mime_types": [
                "application/x-msdownload",
                "application/x-dosexec",
                "application/vnd.microsoft.portable-executable",
            ],
            "phrase_thresholds": {},
        },
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
