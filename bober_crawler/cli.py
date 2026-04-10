#!/usr/bin/env python3
import asyncio
import argparse
from dataclasses import dataclass, field
import difflib
import json
import logging
import time
import re
import secrets
import sys
import xml.etree.ElementTree as ET
from html import escape, unescape
from typing import Dict, List
from urllib.parse import parse_qsl, quote_plus, urljoin, urlparse, unquote
from datetime import datetime

from playwright.async_api import async_playwright, TimeoutError as PlaywrightTimeoutError
from playwright.sync_api import sync_playwright


# ---------------- BROWSER CHECK ----------------

def ensure_browser():
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            browser.close()
    except Exception:
        venv_python = sys.executable
        print("[!] Playwright browser not installed.")
        print("    Run:")
        print(f"    {venv_python} -m playwright install chromium")
        sys.exit(1)


# ---------------- CONFIG ----------------

def build_log_filename(start_url: str):
    p = urlparse(start_url)

    host = (p.hostname or "site").replace(".", "-")

    path = p.path.strip("/")
    if path:
        path = path.replace("/", "_")
    else:
        path = "root"

    ts = datetime.now().strftime("%Y-%m-%d_%H-%M")

    return f"{host}_{path}_{ts}.log"

PROXY_HOST = "127.0.0.1"
PROXY_PORT = 8080
DEFAULT_PROXY_SERVER = f"http://{PROXY_HOST}:{PROXY_PORT}"

DEFAULT_TIMEOUT = 15000
DEFAULT_DELAY = 0.15
DEFAULT_MAX_PAGES = 1000
DEFAULT_MAX_DEPTH = 6
DEFAULT_MAX_MUTATIONS_PER_REQUEST_PROFILE = 1000
DEFAULT_MAX_REACHABILITY_TARGETS = 3
DEFAULT_MAX_SELECT_OPTIONS_PER_FIELD = 5
DEFAULT_STATUS_PROBE_CONFIRMATION_REQUESTS = 2
DEFAULT_SQLI_TIME_DELAY_SECONDS = 3
DEFAULT_SQLI_TIME_THRESHOLD_MS = 2200
DEFAULT_CMDI_TIME_DELAY_SECONDS = 3
DEFAULT_CMDI_TIME_THRESHOLD_MS = 2200
DEFAULT_CORS_TEST_ORIGIN = "https://bober-cors.invalid"
DEFAULT_MAX_DEFERRED_MARKER_SEEDS = 15
DEFAULT_AUDIT_SWEEP_CONCURRENCY = 4
DEFAULT_REACHABILITY_CHECK_CONCURRENCY = 4
MAX_CHECK_CONCURRENCY = 8
ACTIVE_ACTION_WAIT = 1.0
NAVIGATION_WAIT_UNTIL = "commit"
USE_BROWSER_REPLAY_FOR_VULN_CHECKS = True

# recursive trap defaults
DEFAULT_MAX_PARAM_LEN = 200
DEFAULT_MAX_REPEAT_SEGMENTS = 3

NON_HTML_EXTENSIONS = {
    ".7z", ".avi", ".bin", ".bmp", ".bz2", ".doc", ".docx", ".eot",
    ".gif", ".gz", ".ico", ".jpeg", ".jpg", ".m4a", ".m4v", ".mov",
    ".mp3", ".mp4", ".mpeg", ".mpg", ".pdf", ".png", ".rar", ".svg", ".tar",
    ".tgz", ".ttf", ".wav", ".webm", ".webp", ".woff", ".woff2", ".xls",
    ".xlsx", ".xml.gz", ".zip",
}

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36"
)

JSON_SEED_SKIP_STATUSES = {404}
REPLAY_FAILURE_CAPABILITIES = set()
REPLAY_FAILURE_CAPABILITIES_LOGGED = set()

ANSI_RESET = "\033[0m"
ANSI_BOLD = "\033[1m"
ANSI_GREEN = "\033[32m"
ANSI_RED = "\033[31m"
ANSI_YELLOW = "\033[33m"
ANSI_CYAN = "\033[36m"
ANSI_WHITE = "\033[37m"
PAYLOAD_TOKEN_PLACEHOLDER = "__BOBER_TOKEN__"

LOG_MODE_CLEAN = "clean"
LOG_MODE_NORMAL = "normal"
LOG_MODE_DEBUG = "debug"
LOG_MODE_ALIASES = {
    "1": LOG_MODE_CLEAN,
    "2": LOG_MODE_NORMAL,
    "3": LOG_MODE_DEBUG,
    "low": LOG_MODE_CLEAN,
    "medium": LOG_MODE_NORMAL,
    "high": LOG_MODE_DEBUG,
    LOG_MODE_CLEAN: LOG_MODE_CLEAN,
    LOG_MODE_NORMAL: LOG_MODE_NORMAL,
    LOG_MODE_DEBUG: LOG_MODE_DEBUG,
}

PROFILE_DISPLAY_NAMES = {
    "deferred-marker": "STORED INPUT REACHABILITY",
}


class CleanLogFilter(logging.Filter):
    def filter(self, record):
        message = record.getMessage()
        lowered = message.lower()

        if message.startswith("Log file: "):
            return True
        if message.startswith("Visiting: "):
            return True
        if "checks completed:" in lowered:
            return True
        if "checks skipped:" in lowered:
            return True
        if "final audit sweep completed:" in lowered:
            return True
        if "Scan Summary" in message:
            return True

        return False


class ExcludeFileOnlyDetailFilter(logging.Filter):
    def filter(self, record):
        return not getattr(record, "file_only_detail", False)


class FileOnlyDetailFilter(logging.Filter):
    def filter(self, record):
        return bool(getattr(record, "file_only_detail", False))


class CleanLogFormatter(logging.Formatter):
    def format(self, record):
        message = record.getMessage()
        if message.startswith("Visiting: "):
            return message[len("Visiting: "):]
        return message


# ---------------- SCAN MODEL ----------------

BODY_TYPE_URLENCODED = "application/x-www-form-urlencoded"
BODY_TYPE_MULTIPART = "multipart/form-data"
BODY_TYPE_TEXT = "text/plain"
BODY_TYPE_QUERY = "query"

INSERTION_POINT_QUERY = "query"
INSERTION_POINT_BODY = "body"
INSERTION_POINT_HEADER = "header"

TARGET_KIND_PROTECTED_ROUTE = "protected-route"
TARGET_KIND_IN_SCOPE_URL = "in-scope-url"
TARGET_KIND_FILE_PATH = "file-path"
TARGET_KIND_SSRF_SPECIAL = "ssrf-special"
TARGET_KIND_OPEN_REDIRECT = "open-redirect"


@dataclass
class RequestParam:
    name: str
    value: str
    location: str
    encoded: bool = False


@dataclass
class RequestSpec:
    method: str
    url: str
    body_type: str
    params: List[RequestParam]
    origin: str
    metadata: Dict[str, str] = field(default_factory=dict)


@dataclass
class InsertionPoint:
    request_key: str
    name: str
    location: str
    base_value: str


@dataclass
class PayloadPhase:
    name: str
    confidence: str
    detector: str
    payloads: List[str]
    encoded_flags: List[bool] = field(default_factory=list)
    marker: str = ""
    expected_outputs: Dict[str, List[str]] = field(default_factory=dict)


@dataclass
class PayloadProfile:
    name: str
    phases: List[PayloadPhase]


@dataclass
class CheckResult:
    profile_name: str
    request_key: str
    insertion_point: InsertionPoint
    payload: str
    phase_name: str = ""
    confidence: str = ""
    evidence: str = ""
    reflected: bool = False
    request_metadata: Dict[str, str] = field(default_factory=dict)


@dataclass
class DeferredMarkerSeed:
    token: str
    request_key: str
    param_name: str
    param_location: str
    target_url: str


@dataclass
class ProtectedTarget:
    url: str
    route: str
    status: int


@dataclass
class ReachabilityTarget:
    profile_name: str
    kind: str
    value: str
    label: str
    baseline_status: int
    metadata: Dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class CheckPolicy:
    profile_name: str
    prefers_body: bool = False
    insertion_point_tokens: List[str] = field(default_factory=list)
    insertion_point_value_prefixes: List[str] = field(default_factory=list)
    target_kind_weights: Dict[str, int] = field(default_factory=dict)
    target_label_tokens: List[str] = field(default_factory=list)
    target_metadata_priorities: Dict[str, Dict[str, int]] = field(default_factory=dict)


def build_payload_variants(payloads, include_urlencoded=True):
    variants = []
    seen = set()

    for payload in payloads or []:
        candidates = [(payload, False)]
        if include_urlencoded:
            candidates.append((quote_plus(payload, safe=""), True))

        for candidate, encoded in candidates:
            key = (candidate, encoded)
            if key in seen:
                continue
            seen.add(key)
            variants.append((candidate, encoded))

    payload_values = [payload for payload, _ in variants]
    encoded_flags = [encoded for _, encoded in variants]
    return payload_values, encoded_flags


def build_payload_phase(
    name,
    confidence,
    detector,
    raw_payloads,
    include_urlencoded=True,
    marker="",
    expected_outputs=None,
):
    payloads, encoded_flags = build_payload_variants(
        raw_payloads,
        include_urlencoded=include_urlencoded,
    )
    return PayloadPhase(
        name=name,
        confidence=confidence,
        detector=detector,
        payloads=payloads,
        encoded_flags=encoded_flags,
        marker=marker,
        expected_outputs=expected_outputs or {},
    )


XSS_PAYLOADS = PayloadProfile(
    name="xss",
    phases=[
        build_payload_phase(
            name="html-probe",
            confidence="medium",
            detector="raw-html",
            raw_payloads=[
                f'\"><b data-bober-xss="{PAYLOAD_TOKEN_PLACEHOLDER}">x</b>',
            ],
        ),
        build_payload_phase(
            name="xss-proof",
            confidence="high",
            detector="browser-event",
            marker=f"bober-xss:{PAYLOAD_TOKEN_PLACEHOLDER}",
            raw_payloads=[
                f'</script><script>console.log("bober-xss:{PAYLOAD_TOKEN_PLACEHOLDER}")</script>',
                f'\"><svg onload="console.log(\'bober-xss:{PAYLOAD_TOKEN_PLACEHOLDER}\')"></svg>',
                f'<img src=x onerror="console.log(\'bober-xss:{PAYLOAD_TOKEN_PLACEHOLDER}\')">',
            ],
        ),
    ],
)

SSTI_PAYLOADS = PayloadProfile(
    name="ssti",
    phases=[
        build_payload_phase(
            name="template-probe",
            confidence="medium",
            detector="status-500",
            raw_payloads=[
                '${{<%[%\'"}}%\\',
            ],
        ),
        build_payload_phase(
            name="ssti-proof",
            confidence="high",
            detector="evaluated-text",
            raw_payloads=[
                "{{1337*13}}",
                "${11111-123}",
                "<%= 1234 + 321 %>",
            ],
            expected_outputs={
                "{{1337*13}}": ["17381"],
                "${11111-123}": ["10988"],
                "<%= 1234 + 321 %>": ["1555"],
            },
        ),
    ],
)

SQLI_PAYLOADS = PayloadProfile(
    name="sqli",
    phases=[
        build_payload_phase(
            name="sql-error-probe",
            confidence="medium",
            detector="sqli-error",
            raw_payloads=[
                "'",
                '"',
                "')",
                '")',
            ],
        ),
        build_payload_phase(
            name="sql-time-probe",
            confidence="low",
            detector="sqli-time",
            raw_payloads=[
                f"' AND SLEEP({DEFAULT_SQLI_TIME_DELAY_SECONDS})-- ",
                f"1 AND SLEEP({DEFAULT_SQLI_TIME_DELAY_SECONDS})-- ",
                f"'; WAITFOR DELAY '0:0:{DEFAULT_SQLI_TIME_DELAY_SECONDS}'--",
                f"'; SELECT pg_sleep({DEFAULT_SQLI_TIME_DELAY_SECONDS})--",
            ],
        ),
    ],
)

COMMAND_INJECTION_PAYLOADS = PayloadProfile(
    name="command-injection",
    phases=[
        build_payload_phase(
            name="cmd-syntax-probe",
            confidence="medium",
            detector="cmdi-probe",
            raw_payloads=[
                ";",
                "&&",
                "||",
                "|",
                "\n",
                "';",
                '";',
                "')",
                '")',
                "`",
            ],
        ),
        build_payload_phase(
            name="cmd-time-probe",
            confidence="low",
            detector="cmdi-time",
            raw_payloads=[
                f"; sleep {DEFAULT_CMDI_TIME_DELAY_SECONDS}",
                f"&& sleep {DEFAULT_CMDI_TIME_DELAY_SECONDS}",
                f"| sleep {DEFAULT_CMDI_TIME_DELAY_SECONDS}",
                f"\nsleep {DEFAULT_CMDI_TIME_DELAY_SECONDS}",
                f"'; sleep {DEFAULT_CMDI_TIME_DELAY_SECONDS}",
                f'"; sleep {DEFAULT_CMDI_TIME_DELAY_SECONDS}',
                f"`sleep {DEFAULT_CMDI_TIME_DELAY_SECONDS}`",
                f"$(sleep {DEFAULT_CMDI_TIME_DELAY_SECONDS})",
                f"& timeout /T {DEFAULT_CMDI_TIME_DELAY_SECONDS} /NOBREAK",
                f"& ping -n {DEFAULT_CMDI_TIME_DELAY_SECONDS + 1} 127.0.0.1",
                f"\ntimeout /T {DEFAULT_CMDI_TIME_DELAY_SECONDS} /NOBREAK",
                f"\nping -n {DEFAULT_CMDI_TIME_DELAY_SECONDS + 1} 127.0.0.1",
                f"| powershell -Command Start-Sleep -Seconds {DEFAULT_CMDI_TIME_DELAY_SECONDS}",
                f"\npowershell -Command Start-Sleep -Seconds {DEFAULT_CMDI_TIME_DELAY_SECONDS}",
            ],
        ),
    ],
)

XXE_PAYLOADS = PayloadProfile(
    name="xxe",
    phases=[
        build_payload_phase(
            name="xml-parser-probe",
            confidence="medium",
            detector="xxe-parser-error",
            raw_payloads=[
                '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY % sp SYSTEM "http://"> %sp;]><r>x</r>',
            ],
        ),
        build_payload_phase(
            name="xml-entity-file",
            confidence="high",
            detector="xxe-file-disclosure",
            raw_payloads=[
                '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><r>&xxe;</r>',
                '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini">]><r>&xxe;</r>',
            ],
        ),
    ],
)

REFLECTION_PAYLOADS = PayloadProfile(
    name="reflection",
    phases=[
        build_payload_phase(
            name="reflection",
            confidence="low",
            detector="reflection",
            raw_payloads=[
                f"bober-reflect-{PAYLOAD_TOKEN_PLACEHOLDER}",
            ],
        ),
    ],
)


CHECK_POLICIES = {
    "ssrf": CheckPolicy(
        profile_name="ssrf",
        prefers_body=True,
        insertion_point_tokens=[
            "url", "uri", "link", "src", "image", "avatar", "fetch",
            "resource", "callback", "redirect", "webhook", "endpoint",
        ],
        insertion_point_value_prefixes=["http://", "https://", "file://", "dict://", "gopher://"],
        target_kind_weights={
            TARGET_KIND_IN_SCOPE_URL: 20,
            TARGET_KIND_SSRF_SPECIAL: 10,
        },
        target_metadata_priorities={
            "fingerprint_strength": {"strong": 6, "weak": 3, "special": 0},
            "special_type": {
                "metadata": 5,
                "loopback-http": 4,
                "file-passwd": 3,
                "dict-redis": 2,
                "gopher-http": 1,
            },
        },
    ),
    "path-traversal": CheckPolicy(
        profile_name="path-traversal",
        prefers_body=True,
        insertion_point_tokens=[
            "path", "file", "filename", "folder", "dir", "document",
            "template", "include", "download",
        ],
        target_kind_weights={
            TARGET_KIND_FILE_PATH: 10,
        },
    ),
    "file-read": CheckPolicy(
        profile_name="file-read",
        prefers_body=True,
        insertion_point_tokens=[
            "path", "file", "filename", "folder", "dir", "document",
            "template", "include", "download", "read", "load", "page",
        ],
        target_kind_weights={
            TARGET_KIND_FILE_PATH: 12,
        },
        target_metadata_priorities={
            "os_family": {"unix": 2, "windows": 2},
        },
        target_label_tokens=["passwd", "win.ini"],
    ),
    "sqli": CheckPolicy(
        profile_name="sqli",
        prefers_body=True,
        insertion_point_tokens=[
            "id", "user", "username", "email", "login", "password", "pass",
            "passwd", "pwd", "search", "query",
            "filter", "sort", "order", "category", "page", "lang",
        ],
    ),
    "command-injection": CheckPolicy(
        profile_name="command-injection",
        prefers_body=True,
        insertion_point_tokens=[
            "host", "hostname", "ip", "address", "domain", "dns", "ping",
            "query", "lookup", "cmd", "exec", "execute", "run", "cli",
            "path", "file", "folder", "dir",
        ],
    ),
    "xxe": CheckPolicy(
        profile_name="xxe",
        prefers_body=True,
        insertion_point_tokens=[
            "xml", "soap", "saml", "svg", "rss", "atom", "feed",
            "request", "payload", "data", "document", "body",
        ],
        insertion_point_value_prefixes=["<?xml", "<", "%3c", "%3C"],
    ),
    "access-control": CheckPolicy(
        profile_name="access-control",
        prefers_body=True,
        insertion_point_tokens=[
            "url", "path", "route", "redirect", "next", "return",
            "continue", "dest", "destination",
        ],
        target_kind_weights={
            TARGET_KIND_PROTECTED_ROUTE: 10,
        },
        target_label_tokens=["admin", "account", "api", "dashboard"],
    ),
    "open-redirect": CheckPolicy(
        profile_name="open-redirect",
        prefers_body=True,
        insertion_point_tokens=[
            "url", "uri", "redirect", "next", "return", "continue",
            "dest", "destination", "target", "to", "out", "view",
        ],
        insertion_point_value_prefixes=["http://", "https://", "//", "/"],
        target_kind_weights={
            TARGET_KIND_OPEN_REDIRECT: 12,
        },
        target_metadata_priorities={
            "variant_strength": {"absolute": 4, "scheme-relative": 2},
        },
        target_label_tokens=["example.com", "example.org"],
    ),
    "xss": CheckPolicy(
        profile_name="xss",
        insertion_point_tokens=["q", "query", "search", "term", "message", "name", "title", "content", "text"],
    ),
    "reflection": CheckPolicy(
        profile_name="reflection",
        insertion_point_tokens=["q", "query", "search", "term", "message", "name", "title", "content", "text"],
    ),
    "ssti": CheckPolicy(
        profile_name="ssti",
        insertion_point_tokens=["q", "query", "search", "term", "message", "name", "title", "content", "text"],
    ),
}


# ---------------- HELPERS ----------------

def parse_scope(scope_url):
    p = urlparse(scope_url)
    return {
        "scheme": p.scheme,
        "host": p.hostname,
        "path": p.path.rstrip("/") or "/"
    }


def normalize_proxy_server(raw_value):
    value = (raw_value or "").strip()
    if not value:
        raise ValueError("Proxy value cannot be empty")

    if "://" not in value:
        value = f"http://{value}"

    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https", "socks5"}:
        raise ValueError("Proxy scheme must be one of: http, https, socks5")
    if not parsed.hostname or parsed.port is None:
        raise ValueError("Proxy must include host and port")

    return value


def in_scope(url, scope):
    try:
        p = urlparse(url)
    except Exception:
        return False

    if p.scheme != scope["scheme"]:
        return False
    if p.hostname != scope["host"]:
        return False

    return (p.path or "/").startswith(scope["path"])


def is_excluded(url, excluded):
    try:
        path = urlparse(url).path or "/"
    except Exception:
        return False
    return any(path.startswith(p) for p in excluded)


def get_url_depth(url):
    try:
        path = urlparse(url).path or "/"
    except Exception:
        return 0

    return len([part for part in path.split("/") if part])


def exceeds_max_depth(url, max_depth):
    return get_url_depth(url) > max_depth


def is_probably_non_html_asset(url):
    try:
        path = (urlparse(url).path or "").lower()
    except Exception:
        return False

    return any(path.endswith(ext) for ext in NON_HTML_EXTENSIONS)


def strip_url_query_and_fragment(url):
    try:
        parsed = urlparse(url)
    except Exception:
        return url

    return parsed._replace(query="", fragment="").geturl()


def has_control_or_space(value):
    return any(ch.isspace() or ord(ch) < 32 for ch in (value or ""))


CANDIDATE_SOURCE_WEIGHTS = {
    "start-url": 6,
    "seed": 5,
    "header": 5,
    "active-form": 6,
    "active-action": 5,
    "wp-expand": 4,
    "content-dom-attr": 4,
    "content-css-url": 3,
    "content-js-escaped-url": 2,
    "content-text-absolute": 2,
    "content-text-quoted": 1,
}

PROMOTABLE_QUERY_SOURCE_SCORE = 4


def normalize_candidate_source(source):
    source = (source or "unknown").strip().lower()
    return source or "unknown"


def register_candidate_source(candidate_sources, url, source):
    if candidate_sources is None or not url:
        return
    candidate_sources.setdefault(url, set()).add(normalize_candidate_source(source))


def candidate_source_summary(candidate_sources, url):
    if candidate_sources is None:
        return []
    return sorted(candidate_sources.get(url, set()))


def candidate_source_score(source_types):
    return sum(
        CANDIDATE_SOURCE_WEIGHTS.get(source, 0)
        for source in set(source_types or [])
    )


def increment_telemetry_counter(telemetry, key, amount=1):
    if telemetry is None or not key:
        return
    telemetry[key] = telemetry.get(key, 0) + amount


def format_telemetry_summary_lines(telemetry):
    if not telemetry:
        return []

    lines = ["Discovery telemetry:"]
    for key in sorted(telemetry):
        lines.append(f"  {key}={telemetry[key]}")
    return lines


def is_code_like_url_fragment(value):
    value = (value or "").strip()
    if not value:
        return False

    lowered = value.lower()
    suspicious_sequences = (
        r"\s",
        r"\w",
        r"\d",
        "(?:",
        "){",
        "=>",
        "function(",
        "return ",
        ".exec(",
        "null===",
        "attr_name",
        "pascalcase",
    )
    if any(token in lowered for token in suspicious_sequences):
        return True

    if "\\" in value and re.search(r"\\[AbBdDsSwWZfnrtv]", value):
        return True

    if re.search(r"[;{}](?:\s|$)", value) and any(token in value for token in ("=", "(", ")")):
        return True

    if value.count("(") >= 2 and value.count(")") >= 2 and any(token in value for token in ("=", ";", ",")):
        return True

    if re.search(r"\b(?:function|return|const|let|var|null|true|false)\b", lowered):
        return True

    return False


def is_promotable_query_url(url, source_types=None):
    try:
        parsed = urlparse(url)
    except Exception:
        return False

    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return False
    if not parsed.query:
        return False

    path = parsed.path or "/"
    query = parsed.query or ""
    if has_control_or_space(path) or has_control_or_space(query):
        return False

    path_parts = [part for part in unquote(path).split("/") if part]
    query_parts = []
    for item in query.split("&"):
        if not item:
            continue
        if "=" in item:
            name, value = item.split("=", 1)
        else:
            name, value = item, ""
        query_parts.append(unquote(name))
        query_parts.append(unquote(value))

    for candidate in path_parts + query_parts:
        if is_code_like_url_fragment(candidate):
            return candidate_source_score(source_types) >= PROMOTABLE_QUERY_SOURCE_SCORE

    return True


def sanitize_text_candidate(raw, source_type):
    raw = (raw or "").strip()
    if not raw:
        return ""

    if source_type == "js-escaped-url":
        raw = re.sub(r"\\u002[fF]", "/", raw)
        raw = re.sub(r"\\x2[fF]", "/", raw)
        while "\\/" in raw:
            raw = raw.replace("\\/", "/")

    if source_type in {"text-absolute", "js-escaped-url"}:
        raw = raw.rstrip(".,;")

    if source_type in {"text-absolute", "text-quoted", "js-escaped-url"}:
        raw = raw.rstrip("&\\")

    return raw.strip()


def shorten_debug_value(value, limit=140):
    text = (value or "").strip()
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 3)] + "..."


def clamp_check_concurrency(value, maximum=MAX_CHECK_CONCURRENCY):
    return max(1, min(int(value), maximum))


def has_malformed_weak_path_chars(value):
    value = value or ""
    return any(ch in value for ch in '<>"\'`{}*[]()^\\')


def is_html_tag_like_path(path):
    normalized = (path or "").strip().strip("/").lower()
    if not normalized or "/" in normalized:
        return False

    html_like_tokens = {
        "a", "abbr", "article", "aside", "audio", "b", "blockquote", "body",
        "button", "canvas", "code", "dd", "div", "dl", "dt", "em", "figcaption",
        "figure", "footer", "form", "h1", "h2", "h3", "h4", "h5", "h6", "head",
        "header", "html", "i", "iframe", "img", "input", "label", "li", "link",
        "main", "meta", "nav", "ol", "option", "p", "picture", "pre", "script",
        "section", "select", "small", "source", "span", "strong", "style",
        "sub", "summary", "sup", "svg", "table", "tbody", "td", "textarea",
        "th", "thead", "title", "tr", "u", "ul", "video",
    }
    return normalized in html_like_tokens


def is_weak_text_quoted_path(path):
    normalized = (path or "").strip().strip("/")
    lowered = normalized.lower()
    if not normalized:
        return False

    if "/" in normalized:
        return False

    if is_html_tag_like_path(normalized):
        return True

    if len(normalized) == 1 and normalized.isalpha():
        return True

    if len(normalized) <= 3 and re.fullmatch(r"[=,._-]+", normalized):
        return True

    if re.fullmatch(r"[a-z],[a-z]=/?", lowered):
        return True

    if re.fullmatch(r"[a-z][,;]", lowered):
        return True

    if re.fullmatch(r"[a-z]\.[a-z][a-z0-9_]*", lowered):
        return True

    return False


def has_suspicious_weak_path_shape(path):
    normalized = (path or "").strip()
    if not normalized:
        return False

    if "\\" in normalized:
        return True

    if "//" in normalized and normalized not in {"/", "//"}:
        return True

    for segment in [part for part in normalized.split("/") if part]:
        if is_weak_text_quoted_path(segment):
            return True

    return False


def extracted_candidate_rejection_reason(raw, resolved, source_type):
    source_type = (source_type or "").strip().lower()

    if source_type not in {"text-absolute", "text-quoted", "js-escaped-url"}:
        return ""

    raw = sanitize_text_candidate(raw, source_type)
    if not raw:
        return "empty"
    if has_control_or_space(raw):
        return "raw-control-or-space"

    suspicious_chars = sum(raw.count(ch) for ch in "(){};,")
    if suspicious_chars >= 2 and "%" not in raw:
        return "raw-suspicious-punctuation"

    if raw in {"/", "//", "http://", "https://"}:
        return "trivial-raw"

    decoded_raw = unquote(raw)
    if is_code_like_url_fragment(decoded_raw):
        return "raw-code-like"

    try:
        parsed = urlparse(resolved)
    except Exception:
        return "resolved-parse-failed"

    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return "resolved-not-http"

    path = unquote(parsed.path or "/")
    query = unquote(parsed.query or "")
    if has_control_or_space(path) or has_control_or_space(query):
        return "resolved-control-or-space"
    if has_malformed_weak_path_chars(path):
        return "resolved-malformed-path-chars"
    if has_suspicious_weak_path_shape(path):
        return "resolved-suspicious-path-shape"

    weak_parts = [part for part in path.split("/") if part]
    for item in query.split("&"):
        if not item:
            continue
        if "=" in item:
            name, value = item.split("=", 1)
        else:
            name, value = item, ""
        weak_parts.append(name)
        weak_parts.append(value)

    for candidate in weak_parts:
        if is_code_like_url_fragment(candidate):
            return "resolved-code-like"

    if source_type == "text-quoted":
        path_suspicious_chars = sum(path.count(ch) for ch in "(){};,")
        if path_suspicious_chars >= 2 and "%" not in raw:
            return "quoted-path-suspicious-punctuation"
        if is_weak_text_quoted_path(path):
            return "quoted-weak-path"

    return ""


async def navigate_page(page, url, timeout):
    response = await page.goto(url, wait_until=NAVIGATION_WAIT_UNTIL)

    try:
        await page.wait_for_load_state("domcontentloaded", timeout=timeout)
    except PlaywrightTimeoutError:
        logging.debug(
            "Navigation reached %s but DOMContentLoaded did not fire before timeout: %s",
            NAVIGATION_WAIT_UNTIL,
            url,
        )

    return response


def candidate_queue_skip_reason(url, args):
    if not in_scope(url, args.scope):
        return "out-of-scope"
    if is_excluded(url, args.exclude_paths):
        return "excluded"
    if exceeds_max_depth(url, args.max_depth):
        return "max-depth"
    if is_probably_non_html_asset(url):
        return "asset-like"
    if is_recursive_trap(url):
        return "recursive-trap"
    if exceeds_state_token_limit(url, args.state_tokens, args.state_max_repeat):
        return "state-token-limit"
    return None


def _enqueue_single_candidate_url(queue, url, args, source=None, candidate_sources=None, telemetry=None):
    normalized_source = normalize_candidate_source(source)
    skip_reason = candidate_queue_skip_reason(url, args)
    if skip_reason:
        increment_telemetry_counter(telemetry, f"queue.rejected.{skip_reason}")
        increment_telemetry_counter(telemetry, f"queue.rejected.{skip_reason}.{normalized_source}")
        logging.debug("Queue skip (%s): %s", skip_reason, url)
        if source == "header":
            logging.debug("Header target skipped (%s): %s", skip_reason, url)
        return

    register_candidate_source(candidate_sources, url, source)
    increment_telemetry_counter(telemetry, "queue.accepted")
    increment_telemetry_counter(telemetry, f"queue.accepted.{normalized_source}")
    logging.debug("Queue add (%s): %s", normalized_source, url)
    if source == "header":
        logging.debug("Header target queued: %s", url)
    queue.append(url)


def enqueue_candidate_url(queue, url, args, source=None, candidate_sources=None, telemetry=None):
    clean_url = strip_url_query_and_fragment(url)
    if clean_url != url:
        _enqueue_single_candidate_url(
            queue,
            clean_url,
            args,
            source=source,
            candidate_sources=candidate_sources,
            telemetry=telemetry,
        )

    _enqueue_single_candidate_url(
        queue,
        url,
        args,
        source=source,
        candidate_sources=candidate_sources,
        telemetry=telemetry,
    )


def extract_url_candidates(text, base, telemetry=None):
    found = []
    seen = set()
    js_escaped_slash = r"(?:\\\/|\\u002[fF]|\\x2[fF])"

    patterns = [
        ("dom-attr", r'''(?:href|src)\s*=\s*["']([^"' >]+)'''),
        ("css-url", r'''url\(\s*["']?([^"')]+)["']?\s*\)'''),
        ("js-escaped-url", rf'''https?:{js_escaped_slash}{js_escaped_slash}[^\s"'<>]+'''),
        ("text-absolute", r'''https?://[^\s"'<>]+'''),
        ("text-quoted", r'''["']((?:https?://|/)[^"'<>]*?(?:\?[^"'<>]*)?)["']'''),
    ]

    for source_type, pattern in patterns:
        for match in re.findall(pattern, text, flags=re.IGNORECASE):
            increment_telemetry_counter(telemetry, f"extract.{source_type}.seen")
            raw = sanitize_text_candidate(unescape((match or "").strip()), source_type)
            if not raw:
                increment_telemetry_counter(telemetry, f"extract.{source_type}.rejected.empty")
                continue
            try:
                resolved = urljoin(base, raw)
            except Exception:
                increment_telemetry_counter(telemetry, f"extract.{source_type}.rejected.urljoin")
                continue
            rejection_reason = extracted_candidate_rejection_reason(raw, resolved, source_type)
            if rejection_reason:
                increment_telemetry_counter(
                    telemetry,
                    f"extract.{source_type}.rejected.{rejection_reason}",
                )
                continue

            key = (resolved, source_type)
            if key in seen:
                increment_telemetry_counter(telemetry, f"extract.{source_type}.duplicate")
                continue
            seen.add(key)
            increment_telemetry_counter(telemetry, f"extract.{source_type}.accepted")
            logging.debug(
                "Extracted candidate (%s): raw=%s resolved=%s",
                source_type,
                shorten_debug_value(raw),
                resolved,
            )
            found.append((resolved, source_type))

    return found


def extract_header_urls(headers, base_url):
    found = set()
    if not headers:
        return found

    def _add_candidate(candidate):
        candidate = (candidate or "").strip()
        if not candidate:
            return
        try:
            found.add(urljoin(base_url, candidate))
        except Exception:
            return

    link_value = headers.get("link") or headers.get("Link")
    if link_value:
        for candidate in re.findall(r"<([^>]+)>", link_value):
            _add_candidate(candidate)

    for header_name in ("location", "Location", "content-location", "Content-Location", "x-pingback", "X-Pingback", "uri", "URI"):
        header_value = headers.get(header_name)
        if header_value:
            _add_candidate(header_value)

    for header_name in ("refresh", "Refresh"):
        header_value = headers.get(header_name)
        if not header_value:
            continue

        match = re.search(r"url\s*=\s*([^;]+)", header_value, flags=re.IGNORECASE)
        if match:
            _add_candidate(match.group(1).strip().strip("'\""))

    return found


def extract_response_header_urls(resp):
    try:
        status = resp.status
    except Exception:
        status = "?"

    try:
        resource_type = resp.request.resource_type
    except Exception:
        resource_type = "unknown"

    try:
        response_url = resp.url
        header_urls = extract_header_urls(resp.headers, response_url)
    except Exception:
        return set()

    for header_url in header_urls:
        logging.debug(
            "Header-derived target: HTTP %s [%s] %s -> %s",
            status,
            resource_type,
            response_url,
            header_url,
        )

    return header_urls


def build_robots_url(start_url):
    p = urlparse(start_url)
    return f"{p.scheme}://{p.netloc}/robots.txt"


def build_sitemap_url(start_url):
    p = urlparse(start_url)
    return f"{p.scheme}://{p.netloc}/sitemap.xml"


def extract_seed_urls_from_text(text, source_url):
    found = []
    seen = set()

    for line in text.splitlines():
        raw = line.strip()
        if not raw or raw.startswith("#"):
            continue

        match = re.match(r"^[^:#]+:\s*(.+)$", raw)
        if match:
            candidate = match.group(1).strip()
            if not candidate:
                continue
            try:
                resolved = urljoin(source_url, candidate)
            except Exception:
                continue

            if resolved not in seen:
                seen.add(resolved)
                found.append(resolved)

    for url, _ in extract_url_candidates(text, source_url):
        if url not in seen:
            seen.add(url)
            found.append(url)

    return found


def extract_robots_seed_urls(text, source_url):
    found = []
    seen = set()

    for line in text.splitlines():
        raw = line.strip()
        if not raw or raw.startswith("#"):
            continue

        match = re.match(r"(?i)^(disallow|sitemap)\s*:\s*(.+)$", raw)
        if not match:
            continue

        candidate = match.group(2).strip()
        if not candidate:
            continue

        try:
            resolved = urljoin(source_url, candidate)
        except Exception:
            continue

        if resolved not in seen:
            seen.add(resolved)
            found.append(resolved)

    for url, _ in extract_url_candidates(text, source_url):
        if url not in seen:
            seen.add(url)
            found.append(url)

    return found


def xml_local_name(tag):
    if "}" in tag:
        return tag.rsplit("}", 1)[1]
    return tag


def extract_sitemap_seed_urls(text, source_url):
    found = []
    seen = set()

    def _add_candidate(candidate):
        candidate = (candidate or "").strip()
        if not candidate:
            return

        # Sitemap URL values should be URL-like. This blocks CSS/text noise.
        if not (
            candidate.startswith(("http://", "https://", "/"))
            or candidate.endswith((".xml", ".xml.gz"))
        ):
            return

        try:
            resolved = urljoin(source_url, candidate)
        except Exception:
            return

        if resolved not in seen:
            seen.add(resolved)
            found.append(resolved)

    try:
        root = ET.fromstring(text)
        root_name = xml_local_name(root.tag).lower()

        if root_name in {"urlset", "sitemapindex"}:
            for elem in root.iter():
                if xml_local_name(elem.tag).lower() == "loc":
                    _add_candidate(elem.text)
        else:
            logging.debug("sitemap.xml is not a standard sitemap root: %s", root.tag)
    except ET.ParseError as e:
        logging.debug("sitemap.xml XML parse failed, trying <loc> fallback (%s)", e)

    if not found:
        for candidate in re.findall(r"<loc>\s*(.*?)\s*</loc>", text, flags=re.IGNORECASE | re.DOTALL):
            _add_candidate(candidate)

    if not found:
        for candidate in re.findall(r'https?://[^\s"\'<>]+(?:\.xml|\.xml\.gz)\b[^\s"\'<>]*', text, flags=re.IGNORECASE):
            _add_candidate(candidate)

    return found


def extract_seed_urls_from_json_file(file_path, scope):
    if not file_path:
        return []

    try:
        with open(file_path, "r", encoding="utf-8") as fh:
            payload = json.load(fh)
    except FileNotFoundError:
        logging.warning("Seed JSON file not found: %s", file_path)
        return []
    except json.JSONDecodeError as e:
        logging.warning("Seed JSON file is not valid JSON: %s (%s)", file_path, e)
        return []
    except OSError as e:
        logging.warning("Seed JSON file could not be read: %s (%s)", file_path, e)
        return []

    results = payload.get("results")
    if not isinstance(results, list):
        logging.warning("Seed JSON file has no usable 'results' list: %s", file_path)
        return []

    seeds = []
    seen = set()

    for item in results:
        if not isinstance(item, dict):
            continue

        status = item.get("status")
        if not isinstance(status, int):
            logging.debug("Seed JSON entry skipped due to invalid status: %s", item)
            continue

        if status in JSON_SEED_SKIP_STATUSES or status < 100 or status > 599:
            continue

        url = item.get("url")
        if not isinstance(url, str) or not url.strip():
            continue

        url = url.strip()
        if not in_scope(url, scope):
            logging.debug("Seed JSON out-of-scope seed skipped: %s", url)
            continue

        if url not in seen:
            seen.add(url)
            seeds.append(url)

    if seeds:
        logging.info("Seed JSON seeds found in scope: %s", len(seeds))
        for seed in seeds:
            logging.debug("Seed JSON seed: %s", seed)
    else:
        logging.debug("Seed JSON contained no in-scope crawlable seed URLs")

    return seeds


async def fetch_seed_urls(page, args, label, source_url):
    try:
        logging.debug("Checking %s: %s", label, source_url)
        resp = await page.context.request.get(source_url, timeout=args.timeout)

        if resp is None:
            logging.debug("%s unavailable: %s", label, source_url)
            return []

        if resp.status >= 400:
            logging.debug("%s returned HTTP %s: %s", label, resp.status, source_url)
            return []

        content = await resp.text()
    except Exception as e:
        logging.debug("%s check failed: %s (%s)", label, source_url, e)
        return []

    if label == "robots.txt":
        seeds = extract_robots_seed_urls(content, source_url)
    elif label == "sitemap.xml":
        seeds = extract_sitemap_seed_urls(content, source_url)
    else:
        seeds = extract_seed_urls_from_text(content, source_url)
    scoped_seeds = []
    for seed in seeds:
        if in_scope(seed, args.scope):
            if exceeds_max_depth(seed, args.max_depth):
                logging.debug("%s max-depth seed skipped: %s", label, seed)
                continue
            if is_probably_non_html_asset(seed):
                logging.debug("%s asset-like seed skipped: %s", label, seed)
                continue
            scoped_seeds.append(seed)
        else:
            logging.debug("%s out-of-scope seed skipped: %s", label, seed)

    if scoped_seeds:
        logging.info("%s seeds found in scope: %s", label, len(scoped_seeds))
        for seed in scoped_seeds:
            logging.debug("%s seed: %s", label, seed)
    else:
        logging.debug("%s contained no in-scope crawlable seed URLs", label)

    return scoped_seeds


async def prime_queue_from_seed_files(page, args):
    seeds = []

    seeds.extend(extract_seed_urls_from_json_file(args.seed_json_file, args.scope))

    for label, source_url in (
        ("robots.txt", build_robots_url(args.start_url)),
        ("sitemap.xml", build_sitemap_url(args.start_url)),
    ):
        seeds.extend(await fetch_seed_urls(page, args, label, source_url))

    deduped = []
    seen = set()
    for seed in seeds:
        if seed not in seen:
            seen.add(seed)
            deduped.append(seed)

    return deduped


def wp_expand(url):
    out = set()
    try:
        p = urlparse(url)
    except Exception:
        return out

    if p.path.endswith("/") and not p.path.endswith("/embed/"):
        out.add(url.rstrip("/") + "/embed/")
    return out


def smart_key(url, query_agnostic_paths):
    p = urlparse(url)
    path = p.path or "/"

    for prefix in query_agnostic_paths:
        if path.startswith(prefix):
            return f"{p.scheme}://{p.hostname}{path}"

    params = []
    if p.query:
        for part in p.query.split("&"):
            if part:
                params.append(unquote(part))
    params.sort()

    return f"{p.scheme}://{p.hostname}{path}?{'&'.join(params)}"


def normalize_url_for_form_signature(url):
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}{p.path or '/'}"


def normalize_form_field_signature_value(value):
    if isinstance(value, list):
        return ",".join(str(item) for item in value)
    return "" if value is None else str(value)


def build_active_form_signature(page_url, form):
    page_key = normalize_url_for_form_signature(page_url)
    action_key = normalize_url_for_form_signature(form["action"])
    field_state = ",".join(
        f"{field['name']}={field['mode']}:{normalize_form_field_signature_value(field.get('value'))}"
        for field in form["fields"]
    )
    submitter = form.get("submitter") or {}
    submitter_name = submitter.get("name", "")
    variant_key = form.get("variant_key", "")
    return f"{page_key}|{form['method']}|{action_key}|{field_state}|{submitter_name}|{variant_key}"


def build_active_action_signature(page_url, action):
    page_key = normalize_url_for_form_signature(page_url)
    descriptor = "|".join(
        [
            action.get("tag", ""),
            action.get("type", ""),
            action.get("name", ""),
            action.get("id", ""),
            action.get("href", ""),
            action.get("onclick", ""),
            action.get("text", ""),
        ]
    )
    return f"{page_key}|{descriptor}"


def is_same_page_candidate(candidate_url, page_url):
    try:
        candidate = urlparse(candidate_url or "")
        page = urlparse(page_url or "")
    except Exception:
        return False

    return (
        candidate.scheme == page.scheme and
        candidate.netloc == page.netloc and
        (candidate.path or "/") == (page.path or "/") and
        not candidate.query
    )


def should_skip_active_action_candidate(candidate_url, page_url):
    candidate_url = (candidate_url or "").strip()
    if not candidate_url:
        return True, "empty"

    if candidate_url.endswith("/#") or candidate_url.endswith("#"):
        return True, "fragment-only"

    if is_same_page_candidate(candidate_url, page_url):
        return True, "same-page"

    return False, ""


def is_auth_like_url(url):
    try:
        parsed = urlparse(url or "")
    except Exception:
        return False

    haystack = " ".join(
        part for part in (
            parsed.path or "",
            parsed.query or "",
            parsed.fragment or "",
        ) if part
    ).lower()

    auth_tokens = (
        "login",
        "logout",
        "signin",
        "signout",
        "auth",
        "session",
        "account",
        "profile",
        "saveprofile",
        "editprofile",
    )
    return any(token in haystack for token in auth_tokens)


def classify_state_transition(from_url, to_url, has_cookie=False):
    from_url = (from_url or "").strip()
    to_url = (to_url or "").strip()
    if not from_url or not to_url or from_url == to_url:
        return ""

    try:
        before = urlparse(from_url)
        after = urlparse(to_url)
    except Exception:
        return ""

    markers = []

    before_path = before.path or "/"
    after_path = after.path or "/"
    before_query = before.query or ""
    after_query = after.query or ""

    if before_path != after_path:
        markers.append("path-change")
    if before_query != after_query:
        markers.append("query-change")
    if is_auth_like_url(from_url) != is_auth_like_url(to_url):
        markers.append("auth-surface-change")
    elif is_auth_like_url(to_url):
        markers.append("auth-surface")
    if has_cookie:
        markers.append("cookie-context")

    return ",".join(markers)


def append_form_entry(entries, name, value):
    if isinstance(value, list):
        for item in value:
            entries.append((name, item))
    else:
        entries.append((name, value))


def build_field_fill_value(field, payload_index):
    field = field or {}
    name = (field.get("name") or "").strip().lower()
    field_type = (field.get("type") or "").strip().lower()
    placeholder = (field.get("placeholder") or "").strip().lower()
    pattern = (field.get("pattern") or "").strip()
    inputmode = (field.get("inputmode") or "").strip().lower()
    autocomplete = (field.get("autocomplete") or "").strip().lower()
    label_hint = (field.get("label_hint") or "").strip().lower()

    haystack = " ".join(
        part for part in (name, field_type, placeholder, autocomplete, label_hint)
        if part
    )

    if field_type == "email" or any(token in haystack for token in ("email", "e-mail", "mail")):
        return f"tester{payload_index}@example.test"

    if field_type == "url" or any(token in haystack for token in ("website", "web site", "web-site", "homepage", "url", "uri", "link", "site")):
        return f"https://example.test/profile-{payload_index}"

    if field_type == "tel" or any(token in haystack for token in ("phone", "tel", "mobile", "contact")):
        return "+3612345678"

    if any(token in haystack for token in ("card", "cc-", "credit", "debit", "visa", "mastercard", "amex", "cvc", "cvv")):
        if any(token in haystack for token in ("cvc", "cvv", "security code")):
            return "123"
        return "4242424242424242"

    if field_type == "number" or inputmode == "numeric":
        if any(token in haystack for token in ("zip", "postal", "postcode", "pin")):
            return "1234"
        if any(token in haystack for token in ("year", "expiry", "exp")):
            return "2028"
        return str(100 + payload_index)

    if field_type == "date":
        return "2026-12-31"

    if field_type == "month":
        return "2026-12"

    if field_type == "time":
        return "12:34"

    if field_type == "datetime-local":
        return "2026-12-31T12:34"

    if field_type == "color":
        return "#336699"

    if field_type == "search":
        return f"search-{payload_index}"

    if field_type == "password":
        return f"Testpass{payload_index}!42"

    if any(token in haystack for token in ("user", "login", "account", "handle", "nick")):
        return f"tester_{payload_index}"

    if any(token in haystack for token in ("name", "fullname", "full name", "first", "last")):
        return f"Test User {payload_index}"

    if pattern:
        if re.fullmatch(r"\\d[\d\\\[\]\{\},\+\*\?\^\$\|().-]*", pattern):
            return "123456"
        if "@" in pattern:
            return f"tester{payload_index}@example.test"

    return f"test{payload_index}"


def should_urlencode_generated_form_value(value):
    value = "" if value is None else str(value)
    return any(
        ch.isspace() or ch in "@:/?=+%"
        for ch in value
    )


def should_keep_generated_form_value_raw(field):
    field = field or {}
    name = (field.get("name") or "").strip().lower()
    field_type = (field.get("type") or "").strip().lower()
    placeholder = (field.get("placeholder") or "").strip().lower()
    autocomplete = (field.get("autocomplete") or "").strip().lower()
    label_hint = (field.get("label_hint") or "").strip().lower()

    haystack = " ".join(
        part for part in (name, field_type, placeholder, autocomplete, label_hint)
        if part
    )

    raw_safe_tokens = (
        "email",
        "e-mail",
        "mail",
        "website",
        "web site",
        "web-site",
        "homepage",
        "url",
        "uri",
        "link",
        "site",
        "name",
        "fullname",
        "full name",
        "first",
        "last",
    )

    return field_type in {"email", "url"} or any(token in haystack for token in raw_safe_tokens)


def build_active_form_entries(fields):
    entries = []
    payload_index = 1

    for field in fields:
        if field["mode"] == "preserve":
            append_form_entry(entries, field["name"], field["value"])
        else:
            generated_value = build_field_fill_value(field, payload_index)
            should_encode = (
                should_urlencode_generated_form_value(generated_value)
                and not should_keep_generated_form_value_raw(field)
            )
            if should_encode:
                entries.append((field["name"], quote_plus(generated_value, safe=""), True))
            else:
                entries.append((field["name"], generated_value, False))
            payload_index += 1

    return entries


def clone_form_fields(fields):
    cloned = []
    for field in fields or []:
        cloned_field = dict(field)
        if isinstance(cloned_field.get("value"), list):
            cloned_field["value"] = list(cloned_field["value"])
        if isinstance(cloned_field.get("options"), list):
            cloned_field["options"] = [dict(option) for option in cloned_field["options"]]
        cloned.append(cloned_field)
    return cloned


def supports_select_variants(form):
    method = (form.get("method") or "get").lower()
    enctype = (form.get("enctype") or BODY_TYPE_URLENCODED).lower()

    if method == "get":
        return True

    if method != "post":
        return False

    return enctype.startswith(BODY_TYPE_URLENCODED)


def expand_select_field_variants(form):
    base_form = {
        "dom_index": form.get("dom_index"),
        "action": form["action"],
        "method": form["method"],
        "enctype": form["enctype"],
        "fields": clone_form_fields(form["fields"]),
    }

    variants = [base_form]
    if not supports_select_variants(form):
        return variants

    for field_index, field in enumerate(form.get("fields") or []):
        if (field.get("tag") or "").lower() != "select":
            continue
        if field.get("multiple"):
            continue

        options = []
        seen_option_values = set()
        for option in field.get("options") or []:
            option_value = "" if option.get("value") is None else str(option.get("value"))
            if option_value in seen_option_values:
                continue
            seen_option_values.add(option_value)
            options.append(
                {
                    "value": option_value,
                    "label": (option.get("label") or "").strip(),
                }
            )

        current_value = "" if field.get("value") is None else str(field.get("value"))
        alternate_options = [
            option for option in options
            if option["value"] != current_value
        ][:max(0, DEFAULT_MAX_SELECT_OPTIONS_PER_FIELD - 1)]

        for option in alternate_options:
            variant_fields = clone_form_fields(form["fields"])
            variant_fields[field_index]["value"] = option["value"]
            variant_fields[field_index]["variant_selected"] = True
            variants.append(
                {
                    "dom_index": form.get("dom_index"),
                    "action": form["action"],
                    "method": form["method"],
                    "enctype": form["enctype"],
                    "fields": variant_fields,
                    "variant_key": f"select:{field['name']}={option['value']}",
                    "variant_metadata": {
                        "type": "select-option",
                        "field_name": field["name"],
                        "field_value": option["value"],
                        "field_label": option["label"],
                    },
                }
            )

    return variants


def expand_form_submit_variants(form):
    variants = []
    submitters = form.get("submitters") or []

    for select_variant in expand_select_field_variants(form):
        if not submitters:
            variants.append(select_variant)
            continue

        for submitter in submitters:
            variant = {
                "dom_index": select_variant.get("dom_index"),
                "action": select_variant["action"],
                "method": select_variant["method"],
                "enctype": select_variant["enctype"],
                "fields": clone_form_fields(select_variant["fields"]),
                "submitter": submitter,
                "variant_key": select_variant.get("variant_key", ""),
                "variant_metadata": dict(select_variant.get("variant_metadata") or {}),
            }

            if submitter.get("name"):
                variant["fields"] = variant["fields"] + [{
                    "name": submitter["name"],
                    "mode": "preserve",
                    "value": submitter.get("value", ""),
                }]

            variants.append(variant)

    return variants

def merge_url_query(url, entries):
    parsed = urlparse(url)
    existing = parse_qsl(parsed.query, keep_blank_values=True)
    normalized_entries = normalize_request_entries(entries)
    form_keys = {name for name, _, _ in normalized_entries}

    preserved = [(key, value, False) for key, value in existing if key not in form_keys]
    merged = preserved + normalized_entries
    query = serialize_request_entries(merged)

    return parsed._replace(query=query).geturl()


def format_request_preview(method, action, entries):
    method = (method or "GET").upper()
    normalized_entries = normalize_request_entries(entries)

    if method == "GET":
        return f"{method} {merge_url_query(action, normalized_entries)}"

    return f"{method} {action} BODY {serialize_request_entries(normalized_entries)}"


def normalize_request_entries(entries):
    normalized = []

    for item in entries or []:
        if isinstance(item, (list, tuple)) and len(item) == 3:
            name, value, encoded = item
        elif isinstance(item, (list, tuple)) and len(item) == 2:
            name, value = item
            encoded = False
        else:
            continue

        if name is None:
            continue

        normalized.append((str(name), "" if value is None else str(value), bool(encoded)))

    return normalized


def serialize_request_entries(entries):
    serialized = []

    for name, value, encoded in normalize_request_entries(entries):
        encoded_name = quote_plus(name, safe="")
        if encoded:
            encoded_value = value
        else:
            # Keep the raw payload visible on the wire, only protecting separators
            # that would break the query/body structure itself.
            encoded_value = (
                value
                .replace("&", "%26")
                .replace("#", "%23")
            )
        serialized.append(f"{encoded_name}={encoded_value}")

    return "&".join(serialized)


def request_body_type(method, enctype):
    if (method or "get").upper() == "GET":
        return BODY_TYPE_QUERY

    enctype = (enctype or BODY_TYPE_URLENCODED).lower()
    if enctype.startswith(BODY_TYPE_MULTIPART):
        return BODY_TYPE_MULTIPART
    if enctype.startswith(BODY_TYPE_TEXT):
        return BODY_TYPE_TEXT
    return BODY_TYPE_URLENCODED


def build_request_spec(method, url, enctype, entries, origin, metadata=None):
    body_type = request_body_type(method, enctype)
    param_location = INSERTION_POINT_QUERY if body_type == BODY_TYPE_QUERY else INSERTION_POINT_BODY
    params = [
        RequestParam(name=name, value=value, location=param_location, encoded=encoded)
        for name, value, encoded in normalize_request_entries(entries)
    ]
    return RequestSpec(
        method=(method or "GET").upper(),
        url=url,
        body_type=body_type,
        params=params,
        origin=origin,
        metadata=metadata or {},
    )


def request_spec_key(spec):
    names = ",".join(sorted(param.name for param in spec.params))
    return f"{spec.method} {spec.url} [{spec.body_type}] {names}"


def request_spec_preview(spec):
    entries = request_params_to_entries(spec.params)
    return format_request_preview(spec.method, spec.url, entries)


def extract_insertion_points(spec):
    points = [
        InsertionPoint(
            request_key=request_spec_key(spec),
            name=param.name,
            location=param.location,
            base_value=param.value,
        )
        for param in spec.params
    ]
    return sorted(points, key=lambda item: (item.location, item.name))


def get_check_policy(profile_name):
    return CHECK_POLICIES.get((profile_name or "").lower())


def insertion_point_priority(profile_name, insertion_point):
    profile_name = (profile_name or "").lower()
    policy = get_check_policy(profile_name)
    name = (getattr(insertion_point, "name", "") or "").lower()
    base_value = (getattr(insertion_point, "base_value", "") or "").lower()
    score = 0

    if policy and policy.prefers_body and insertion_point.location == INSERTION_POINT_BODY:
        score += 2

    if policy:
        if any(token in name for token in policy.insertion_point_tokens):
            score += 10
        if any(base_value.startswith(prefix) for prefix in policy.insertion_point_value_prefixes):
            score += 8

    if profile_name == "ssrf":
        if any(token in name for token in ("redirect", "callback", "return", "next")):
            score += 2

    elif profile_name == "open-redirect":
        if any(token in name for token in ("redirect", "return", "next", "dest", "target")):
            score += 3
        if base_value.startswith(("http://", "https://", "//")):
            score += 4

    elif profile_name == "path-traversal":
        if "/" in base_value or "\\" in base_value or "." in base_value:
            score += 4

    elif profile_name == "access-control":
        if any(token in name for token in ("admin", "account", "return", "dest")):
            score += 1

    elif profile_name in {"xss", "reflection", "ssti"}:
        if insertion_point.location == INSERTION_POINT_QUERY:
            score += 1
        if policy and any(token in name for token in policy.insertion_point_tokens):
            score += 3

    elif profile_name == "sqli":
        score += sqli_insertion_point_shape_score(insertion_point)

    elif profile_name == "command-injection":
        score += cmdi_insertion_point_shape_score(insertion_point)

    elif profile_name == "xxe":
        score += xxe_insertion_point_shape_score(insertion_point)

    return score


def prioritize_insertion_points(profile_name, spec, eligible_points=None):
    request_key = request_spec_key(spec)
    points = []

    for insertion_point in extract_insertion_points(spec):
        if eligible_points is not None:
            point_identity = insertion_point_identity(request_key, insertion_point)
            if point_identity not in eligible_points:
                continue
        points.append(insertion_point)

    return sorted(
        points,
        key=lambda item: (
            -insertion_point_priority(profile_name, item),
            item.location,
            item.name,
        ),
    )


def mutate_request_spec(spec, insertion_point, payload, encoded=False):
    mutated_params = []

    for param in spec.params:
        value = payload if (
            param.name == insertion_point.name and
            param.location == insertion_point.location
        ) else param.value
        value_encoded = encoded if (
            param.name == insertion_point.name and
            param.location == insertion_point.location
        ) else param.encoded
        mutated_params.append(
            RequestParam(
                name=param.name,
                value=value,
                location=param.location,
                encoded=value_encoded,
            )
        )

    return RequestSpec(
        method=spec.method,
        url=spec.url,
        body_type=spec.body_type,
        params=mutated_params,
        origin=spec.origin,
        metadata=dict(spec.metadata),
    )


def mutation_key(profile_name, insertion_point, payload):
    return "|".join(
        [
            profile_name,
            insertion_point.request_key,
            insertion_point.location,
            insertion_point.name,
            payload,
        ]
    )


def build_payload_token(length=10):
    alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
    return "".join(secrets.choice(alphabet) for _ in range(length))


def instantiate_payload_template(value, token):
    return (value or "").replace(PAYLOAD_TOKEN_PLACEHOLDER, token)


def iter_phase_payload_variants(phase):
    if len(phase.encoded_flags) == len(phase.payloads):
        return list(zip(phase.payloads, phase.encoded_flags))

    variants = []
    for index, payload_template in enumerate(phase.payloads):
        variants.append((payload_template, index % 2 == 1))
    return variants


def request_params_to_entries(params):
    return [(param.name, param.value, param.encoded) for param in params]


def request_params_to_browser_form_entries(params):
    return [(param.name, param.value) for param in params or []]


def build_query_request_spec(url, origin, metadata=None, telemetry=None):
    metadata = metadata or {}
    source_types = metadata.get("candidate_sources") or []
    increment_telemetry_counter(telemetry, "request_spec.query.seen")
    if not is_promotable_query_url(url, source_types=source_types):
        increment_telemetry_counter(telemetry, "request_spec.query.rejected.non_promotable")
        return None

    parsed = urlparse(url)
    entries = parse_qsl(parsed.query, keep_blank_values=True)
    if not entries:
        increment_telemetry_counter(telemetry, "request_spec.query.rejected.no_entries")
        return None

    base_url = parsed._replace(query="", fragment="").geturl()
    increment_telemetry_counter(telemetry, "request_spec.query.accepted")
    return build_request_spec(
        method="GET",
        url=base_url,
        enctype="",
        entries=entries,
        origin=origin,
        metadata=metadata,
    )


def protected_target_route(url):
    parsed = urlparse(url)
    route = parsed.path or "/"
    if parsed.query:
        route = f"{route}?{parsed.query}"
    return route


def protected_target_path(url):
    parsed = urlparse(url)
    return parsed.path or "/"


def register_protected_target(protected_targets, url, status):
    if status not in {401, 403}:
        return None

    route = protected_target_route(url)
    if route not in protected_targets:
        protected_targets[route] = ProtectedTarget(
            url=url,
            route=route,
            status=status,
        )
    return protected_targets[route]


def select_protected_targets(protected_targets, limit=DEFAULT_MAX_REACHABILITY_TARGETS):
    ordered = sorted(
        protected_targets.values(),
        key=lambda item: (
            item.status,
            len(item.route),
            item.route,
        ),
    )
    return ordered[:max(0, limit)]


def dedupe_payload_variants(variants):
    deduped = []
    seen = set()

    for payload, encoded in variants:
        if not payload:
            continue
        key = (payload, bool(encoded))
        if key in seen:
            continue
        seen.add(key)
        deduped.append((payload, bool(encoded)))

    return deduped


def build_target_payload_variants(target_value):
    variants = []

    payload_candidates = [
        (target_value, False),
        (quote_plus(target_value, safe=""), True),
    ]

    for payload, encoded in payload_candidates:
        variants.append((payload, encoded))

    return dedupe_payload_variants(variants)


def build_file_path_payload_variants(target_value):
    normalized_target = (target_value or "").strip()
    if not normalized_target:
        return []

    trimmed_target = normalized_target.lstrip("/")
    slash_encoded_target = trimmed_target.replace("/", "%2F")
    dot_slash_target = trimmed_target.replace("/", "//")

    variants = [
        (f"../../../../../../../../../../{trimmed_target}", False),
        (f"..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F{slash_encoded_target}", False),
        (f"....//....//....//....//....//{dot_slash_target}", False),
        (f"....%2F%2F....%2F%2F....%2F%2F....%2F%2F....%2F%2F{slash_encoded_target}", False),
    ]
    return dedupe_payload_variants(variants)


def build_reachability_payload_variants(target):
    target_kind = getattr(target, "kind", "")
    target_value = getattr(target, "value", "")

    if target_kind == TARGET_KIND_PROTECTED_ROUTE:
        variants = build_target_payload_variants(target_value)
        route_path = target.metadata.get("path", "")
        if route_path and route_path != target_value:
            variants.extend(build_target_payload_variants(route_path))
        return dedupe_payload_variants(variants)

    if target_kind == TARGET_KIND_IN_SCOPE_URL:
        variants = build_target_payload_variants(target_value)

        try:
            parsed = urlparse(target_value)
        except Exception:
            parsed = None

        if parsed is not None:
            relative = parsed.path or "/"
            if parsed.query:
                relative = f"{relative}?{parsed.query}"
            variants.extend(
                build_target_payload_variants(relative)
            )
            if parsed.path:
                variants.extend(
                    build_target_payload_variants(parsed.path)
                )

        return dedupe_payload_variants(variants)

    if target_kind == TARGET_KIND_FILE_PATH:
        return build_file_path_payload_variants(target_value)

    if target_kind == TARGET_KIND_SSRF_SPECIAL:
        return build_target_payload_variants(target_value)

    if target_kind == TARGET_KIND_OPEN_REDIRECT:
        return build_target_payload_variants(target_value)

    return build_target_payload_variants(target_value)


def build_reachability_targets_from_protected(protected_targets, limit=DEFAULT_MAX_REACHABILITY_TARGETS):
    targets = []

    for protected_target in select_protected_targets(protected_targets, limit=limit):
        targets.append(
            ReachabilityTarget(
                profile_name="access-control",
                kind=TARGET_KIND_PROTECTED_ROUTE,
                value=protected_target.route,
                label=protected_target.route,
                baseline_status=protected_target.status,
                metadata={
                    "url": protected_target.url,
                    "path": protected_target_path(protected_target.url),
                    "route": protected_target.route,
                },
            )
        )

    return targets


def build_path_traversal_targets(limit=1):
    targets = [
        ReachabilityTarget(
            profile_name="path-traversal",
            kind=TARGET_KIND_FILE_PATH,
            value="/etc/passwd",
            label="/etc/passwd",
            baseline_status=0,
            metadata={
                "os_family": "unix",
                "target_path": "/etc/passwd",
            },
        )
    ]
    return targets[:max(0, limit)]


def build_file_read_targets(limit=3):
    targets = [
        ReachabilityTarget(
            profile_name="file-read",
            kind=TARGET_KIND_FILE_PATH,
            value="/etc/passwd",
            label="/etc/passwd",
            baseline_status=0,
            metadata={
                "os_family": "unix",
                "target_path": "/etc/passwd",
                "confidence": "high",
            },
        ),
        ReachabilityTarget(
            profile_name="file-read",
            kind=TARGET_KIND_FILE_PATH,
            value="C:/Windows/win.ini",
            label="C:/Windows/win.ini",
            baseline_status=0,
            metadata={
                "os_family": "windows",
                "target_path": "C:/Windows/win.ini",
                "confidence": "medium",
            },
        ),
        ReachabilityTarget(
            profile_name="file-read",
            kind=TARGET_KIND_FILE_PATH,
            value="C:\\Windows\\win.ini",
            label="C:\\Windows\\win.ini",
            baseline_status=0,
            metadata={
                "os_family": "windows",
                "target_path": "C:\\Windows\\win.ini",
                "confidence": "medium",
            },
        ),
    ]
    return targets[:max(0, limit)]


def build_open_redirect_targets(limit=2):
    targets = [
        ReachabilityTarget(
            profile_name="open-redirect",
            kind=TARGET_KIND_OPEN_REDIRECT,
            value="https://example.com/",
            label="https://example.com/",
            baseline_status=0,
            metadata={
                "confidence": "high",
                "redirect_host": "example.com",
                "variant_strength": "absolute",
            },
        ),
        ReachabilityTarget(
            profile_name="open-redirect",
            kind=TARGET_KIND_OPEN_REDIRECT,
            value="//example.com/",
            label="//example.com/",
            baseline_status=0,
            metadata={
                "confidence": "medium",
                "redirect_host": "example.com",
                "variant_strength": "scheme-relative",
            },
        ),
        ReachabilityTarget(
            profile_name="open-redirect",
            kind=TARGET_KIND_OPEN_REDIRECT,
            value="https://example.org/",
            label="https://example.org/",
            baseline_status=0,
            metadata={
                "confidence": "high",
                "redirect_host": "example.org",
                "variant_strength": "absolute",
            },
        ),
        ReachabilityTarget(
            profile_name="open-redirect",
            kind=TARGET_KIND_OPEN_REDIRECT,
            value="//example.org/",
            label="//example.org/",
            baseline_status=0,
            metadata={
                "confidence": "medium",
                "redirect_host": "example.org",
                "variant_strength": "scheme-relative",
            },
        ),
    ]
    return targets[:max(0, limit)]


def target_priority(profile_name, target):
    profile_name = (profile_name or "").lower()
    policy = get_check_policy(profile_name)
    kind = (getattr(target, "kind", "") or "").lower()
    metadata = getattr(target, "metadata", {}) or {}
    score = 0

    if policy:
        score += policy.target_kind_weights.get(kind, 0)
        for metadata_key, weights in policy.target_metadata_priorities.items():
            score += weights.get(metadata.get(metadata_key, ""), 0)
        label = (getattr(target, "label", "") or "").lower()
        if any(token in label for token in policy.target_label_tokens):
            score += 2

    if profile_name == "access-control" and metadata.get("route"):
        score += 2
    if profile_name == "open-redirect" and metadata.get("redirect_host"):
        score += 2

    return score


def prioritize_targets(profile_name, targets):
    return sorted(
        targets,
        key=lambda item: (
            -target_priority(profile_name, item),
            getattr(item, "label", ""),
            getattr(item, "value", ""),
        ),
    )


def resolve_request_spec_url(spec):
    if spec.body_type != BODY_TYPE_QUERY:
        return ""
    return merge_url_query(spec.url, request_params_to_entries(spec.params))


def normalize_ssrf_visible_text(text):
    decoded = unescape(text or "")
    visible_text = re.sub(
        r"<(?:script|style)[^>]*>.*?</(?:script|style)>",
        " ",
        decoded,
        flags=re.IGNORECASE | re.DOTALL,
    )
    visible_text = re.sub(r"<[^>]+>", " ", visible_text)
    return re.sub(r"\s+", " ", visible_text).strip()


def extract_ssrf_fingerprint_markers(text):
    if not text:
        return []

    decoded = unescape(text)
    visible_text = normalize_ssrf_visible_text(text)
    markers = []
    seen = set()

    def _remember(value):
        value = re.sub(r"\s+", " ", (value or "").strip())
        if len(value) < 6:
            return
        if is_low_signal_ssrf_marker(value):
            return
        lowered = value.lower()
        if lowered in seen:
            return
        seen.add(lowered)
        markers.append(value[:120])

    title_match = re.search(r"<title[^>]*>(.*?)</title>", decoded, flags=re.IGNORECASE | re.DOTALL)
    if title_match:
        _remember(re.sub(r"<[^>]+>", " ", title_match.group(1)))

    h1_match = re.search(r"<h1[^>]*>(.*?)</h1>", decoded, flags=re.IGNORECASE | re.DOTALL)
    if h1_match:
        _remember(re.sub(r"<[^>]+>", " ", h1_match.group(1)))

    for snippet in re.findall(r"[A-Za-z][A-Za-z0-9 _/\-.]{15,120}", visible_text):
        cleaned = snippet.strip(" -:|")
        if cleaned:
            _remember(cleaned)
        if len(markers) >= 3:
            break

    return markers[:3]


def is_low_signal_ssrf_marker(value):
    normalized = re.sub(r"\s+", " ", (value or "").strip()).lower()
    if not normalized:
        return True

    if normalized.startswith(("http://", "https://", "/")):
        return True

    common_css_terms = (
        "box-sizing",
        "font-family",
        "background",
        "border-box",
        "linear-gradient",
        "display:",
        "padding:",
        "margin:",
        "width:",
        "height:",
        "color:",
    )
    if any(term in normalized for term in common_css_terms):
        return True

    alpha_words = re.findall(r"[a-z]{3,}", normalized)
    if len(alpha_words) < 2:
        return True

    return False


def extract_ssrf_embedded_markers(text, limit=5):
    visible_text = normalize_ssrf_visible_text(text)
    markers = []
    seen = set()

    for snippet in re.findall(r"[A-Za-z][A-Za-z0-9 ,.'():/_-]{20,160}", visible_text):
        cleaned = re.sub(r"\s+", " ", snippet).strip(" -:|,.;")
        if len(cleaned) < 20 or is_low_signal_ssrf_marker(cleaned):
            continue

        alpha_words = re.findall(r"[A-Za-z]{3,}", cleaned)
        if len(alpha_words) < 3:
            continue

        lowered = cleaned.lower()
        if lowered in seen:
            continue
        seen.add(lowered)
        markers.append(cleaned[:160])
        if len(markers) >= limit:
            break

    return markers


def infer_ssrf_error_signature(text, target_value=""):
    normalized_text = normalize_ssrf_visible_text(text).lower()
    target_value = (target_value or "").lower()

    error_markers = [
        "failed to fetch",
        "connection refused",
        "max retries exceeded",
        "newconnectionerror",
        "name or service not known",
        "temporary failure in name resolution",
        "nodename nor servname provided",
        "connection timed out",
        "read timed out",
        "connect timeout",
        "connection aborted",
        "connection reset",
        "network is unreachable",
        "no route to host",
        "httpconnectionpool",
        "httpsconnectionpool",
        "urllib3",
        "requests.exceptions",
    ]

    if not any(marker in normalized_text for marker in error_markers):
        return ""

    if target_value and target_value not in normalized_text:
        parsed = urlparse(target_value)
        host = (parsed.hostname or "").lower()
        if host and host not in normalized_text:
            return ""

    if "connection refused" in normalized_text or "failed to establish a new connection" in normalized_text:
        return "connection-refused"
    if "timed out" in normalized_text or "timeout" in normalized_text:
        return "network-timeout"
    if "name or service not known" in normalized_text or "temporary failure in name resolution" in normalized_text:
        return "dns-resolution"
    if "network is unreachable" in normalized_text or "no route to host" in normalized_text:
        return "network-unreachable"
    return "backend-fetch-error"


def build_ssrf_seed_urls(request_specs, seed_urls, scope):
    candidates = []
    seen = set()

    for raw_url in seed_urls or []:
        candidate = (raw_url or "").strip()
        if not candidate or not in_scope(candidate, scope):
            continue
        if candidate in seen:
            continue
        seen.add(candidate)
        candidates.append(candidate)

    for spec in prioritize_request_specs(request_specs):
        for candidate in (
            resolve_request_spec_url(spec),
            spec.url,
            spec.metadata.get("source_url", ""),
            spec.metadata.get("page_url", ""),
        ):
            candidate = (candidate or "").strip()
            if not candidate or not in_scope(candidate, scope):
                continue
            if candidate in seen:
                continue
            seen.add(candidate)
            candidates.append(candidate)

    return candidates


def build_ssrf_special_targets(limit=5):
    targets = [
        ReachabilityTarget(
            profile_name="ssrf",
            kind=TARGET_KIND_SSRF_SPECIAL,
            value="http://127.0.0.1/",
            label="http://127.0.0.1/",
            baseline_status=0,
            metadata={
                "confidence": "low",
                "embedded_markers": "localhost || 127.0.0.1 || loopback",
                "fingerprint_strength": "special",
                "required_marker_matches": 1,
                "special_type": "loopback-http",
            },
        ),
        ReachabilityTarget(
            profile_name="ssrf",
            kind=TARGET_KIND_SSRF_SPECIAL,
            value="http://169.254.169.254/latest/meta-data/",
            label="aws-metadata",
            baseline_status=0,
            metadata={
                "confidence": "medium",
                "embedded_markers": "ami-id || instance-id || security-credentials || meta-data",
                "fingerprint_strength": "special",
                "required_marker_matches": 1,
                "special_type": "metadata",
            },
        ),
        ReachabilityTarget(
            profile_name="ssrf",
            kind=TARGET_KIND_SSRF_SPECIAL,
            value="file:///etc/passwd",
            label="file:///etc/passwd",
            baseline_status=0,
            metadata={
                "confidence": "medium",
                "embedded_markers": "root:x:0:0 || daemon:x:1:1 || /bin/bash || /usr/sbin/nologin",
                "fingerprint_strength": "special",
                "required_marker_matches": 1,
                "special_type": "file-passwd",
            },
        ),
        ReachabilityTarget(
            profile_name="ssrf",
            kind=TARGET_KIND_SSRF_SPECIAL,
            value="dict://127.0.0.1:6379/info",
            label="dict://127.0.0.1:6379/info",
            baseline_status=0,
            metadata={
                "confidence": "low",
                "embedded_markers": "redis_version || redis_mode || db0",
                "fingerprint_strength": "special",
                "required_marker_matches": 1,
                "special_type": "dict-redis",
            },
        ),
        ReachabilityTarget(
            profile_name="ssrf",
            kind=TARGET_KIND_SSRF_SPECIAL,
            value="gopher://127.0.0.1:80/_GET%20/%20HTTP/1.0%0D%0A%0D%0A",
            label="gopher://127.0.0.1:80/",
            baseline_status=0,
            metadata={
                "confidence": "low",
                "embedded_markers": "server: || http/1. || html || <!doctype",
                "fingerprint_strength": "special",
                "required_marker_matches": 1,
                "special_type": "gopher-http",
            },
        ),
    ]
    return targets[:max(0, limit)]


def is_likely_ssrf_insertion_point(insertion_point):
    name = (getattr(insertion_point, "name", "") or "").lower()
    base_value = (getattr(insertion_point, "base_value", "") or "").lower()

    url_like_tokens = (
        "url",
        "uri",
        "link",
        "src",
        "image",
        "avatar",
        "fetch",
        "resource",
        "callback",
        "redirect",
        "webhook",
        "endpoint",
    )
    if any(token in name for token in url_like_tokens):
        return True

    if base_value.startswith(("http://", "https://", "file://", "dict://", "gopher://")):
        return True

    return False


async def build_ssrf_targets_from_request_specs(api_context, request_specs, seed_urls, args, limit=DEFAULT_MAX_REACHABILITY_TARGETS):
    targets = []
    seed_candidates = build_ssrf_seed_urls(request_specs, seed_urls, args.scope)
    browser_context = getattr(args, "browser_context", None)

    for target_url in seed_candidates:

        try:
            if USE_BROWSER_REPLAY_FOR_VULN_CHECKS and browser_context is not None:
                response_result = await fetch_url_result_in_browser(
                    browser_context,
                    target_url,
                    args.timeout,
                )
                response_text = response_result.get("text") or ""
                response_status = response_result.get("status", 0)
            else:
                response_result = await api_context.get(target_url, timeout=args.timeout)
                response_text = await response_result.text()
                response_status = response_result.status
        except Exception as e:
            logging.debug("ssrf target seed fetch failed: %s (%s)", target_url, e)
            continue

        if response_status >= 400:
            continue

        markers = extract_ssrf_fingerprint_markers(response_text)
        if not markers:
            continue

        targets.append(
            ReachabilityTarget(
                profile_name="ssrf",
                kind=TARGET_KIND_IN_SCOPE_URL,
                value=target_url,
                label=target_url,
                baseline_status=response_status,
                metadata={
                    "fingerprint": " || ".join(markers),
                    "embedded_markers": " || ".join(extract_ssrf_embedded_markers(response_text)),
                    "fingerprint_strength": "strong" if len(markers) >= 2 else "weak",
                    "required_marker_matches": 2 if len(markers) >= 2 else 1,
                    "confidence": "high" if len(markers) >= 2 else "medium",
                    "seed_visible_text": normalize_ssrf_visible_text(response_text)[:400],
                },
            )
        )

        if len(targets) >= max(0, limit):
            break

    return targets


def register_request_spec(request_specs, spec, max_specs=None):
    if spec is None:
        return None

    key = request_spec_key(spec)
    if key not in request_specs:
        if max_specs is not None and len(request_specs) >= max_specs:
            return None
        request_specs[key] = spec
        return request_specs[key]

    existing = request_specs[key]
    existing_sources = set(existing.metadata.get("candidate_sources") or [])
    incoming_sources = set(spec.metadata.get("candidate_sources") or [])
    merged_sources = sorted(existing_sources | incoming_sources)
    if merged_sources:
        existing.metadata["candidate_sources"] = merged_sources
        merged_score = candidate_source_score(merged_sources)
        existing.metadata["candidate_source_score"] = str(merged_score)
        existing.metadata["candidate_source_trust"] = (
            "high" if merged_score >= PROMOTABLE_QUERY_SOURCE_SCORE else "low"
        )

    for metadata_key, metadata_value in (spec.metadata or {}).items():
        if metadata_key in {"candidate_sources", "candidate_source_score", "candidate_source_trust"}:
            continue
        if metadata_value and not existing.metadata.get(metadata_key):
            existing.metadata[metadata_key] = metadata_value

    return existing


def request_spec_limit_reached(request_specs, max_specs):
    if max_specs is None:
        return False
    return len(request_specs) >= max_specs


def is_supported_check_spec(spec):
    if spec.body_type == BODY_TYPE_QUERY:
        return True
    if spec.method == "POST" and spec.body_type == BODY_TYPE_URLENCODED:
        return True
    return False


def request_spec_candidate_score(spec):
    metadata = getattr(spec, "metadata", {}) or {}
    score = metadata.get("candidate_source_score", "")
    try:
        return int(score)
    except (TypeError, ValueError):
        return 0


def request_spec_origin_priority(spec):
    origin = (getattr(spec, "origin", "") or "").lower()
    origin_weights = {
        "browser-formdata": 7,
        "form-preview": 6,
        "crawl-url": 4,
    }
    return origin_weights.get(origin, 0)


def request_spec_priority(spec):
    metadata = getattr(spec, "metadata", {}) or {}
    source_trust = (metadata.get("candidate_source_trust") or "").lower()
    body_type = getattr(spec, "body_type", "")
    method = getattr(spec, "method", "")
    param_count = len(getattr(spec, "params", []) or [])

    trust_bonus = 2 if source_trust == "high" else 0
    body_bonus = 1 if body_type != BODY_TYPE_QUERY else 0
    method_bonus = 1 if method == "POST" else 0

    return (
        request_spec_origin_priority(spec),
        request_spec_candidate_score(spec) + trust_bonus,
        body_bonus + method_bonus,
        param_count,
    )


def prioritize_request_specs(request_specs):
    return sorted(
        request_specs.values(),
        key=lambda spec: (
            -request_spec_priority(spec)[0],
            -request_spec_priority(spec)[1],
            -request_spec_priority(spec)[2],
            -request_spec_priority(spec)[3],
            request_spec_key(spec),
        ),
    )


def is_request_spec_trusted_for_profile(spec, profile_name):
    if spec is None:
        return False

    profile_name = (profile_name or "").lower()
    metadata = getattr(spec, "metadata", {}) or {}
    origin = (getattr(spec, "origin", "") or "").lower()
    body_type = getattr(spec, "body_type", "")

    if body_type != BODY_TYPE_QUERY:
        return True

    source_score = request_spec_candidate_score(spec)
    source_trust = (metadata.get("candidate_source_trust") or "").lower()

    if origin in {"form-preview", "browser-formdata"}:
        return True

    profile_thresholds = {
        "cors": PROMOTABLE_QUERY_SOURCE_SCORE,
        "open-redirect": PROMOTABLE_QUERY_SOURCE_SCORE,
        "ssrf": PROMOTABLE_QUERY_SOURCE_SCORE,
    }
    threshold = profile_thresholds.get(profile_name, 0)
    if threshold <= 0:
        return True

    if source_score >= threshold:
        return True
    if source_trust == "high":
        return True

    return False


def filter_request_specs_for_profile(request_specs, profile_name):
    filtered = {}
    for key, spec in (request_specs or {}).items():
        if is_request_spec_trusted_for_profile(spec, profile_name):
            filtered[key] = spec
    return filtered


def resolve_request_spec_target(spec):
    if spec.body_type == BODY_TYPE_QUERY:
        return merge_url_query(spec.url, request_params_to_entries(spec.params))
    return spec.url


def request_host(url):
    try:
        return (urlparse(url or "").hostname or "").lower()
    except Exception:
        return ""


def request_path(url):
    try:
        return (urlparse(url or "").path or "/")
    except Exception:
        return "/"


def register_audit_sweep_target(targets, url, args):
    if targets is None:
        return

    candidate = (url or "").strip()
    if not candidate:
        return
    if not in_scope(candidate, args.scope):
        return
    if is_excluded(candidate, args.exclude_paths):
        return
    if is_probably_non_html_asset(candidate):
        return

    try:
        parsed = urlparse(candidate)
    except Exception:
        return

    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return

    targets.add(candidate)


def deferred_marker_payload(token):
    return f"bober-dm-{token}"


def is_deferred_marker_candidate(insertion_point):
    name = (getattr(insertion_point, "name", "") or "").strip().lower()
    base_value = (getattr(insertion_point, "base_value", "") or "").strip()
    location = (getattr(insertion_point, "location", "") or "").strip().lower()

    if location not in {INSERTION_POINT_QUERY, INSERTION_POINT_BODY}:
        return False

    negative_tokens = (
        "csrf", "token", "nonce", "timestamp", "id", "page", "offset",
        "limit", "sort", "order", "lang", "state", "session", "auth",
        "password", "pass", "pwd",
    )
    if any(token in name for token in negative_tokens):
        return False

    positive_tokens = (
        "name", "username", "display_name", "displayname", "title", "subject",
        "message", "comment", "content", "text", "description", "bio",
        "about", "location", "website", "url", "redirect", "next", "return",
        "link", "homepage", "profile",
    )
    if any(token in name for token in positive_tokens):
        return True

    if re.fullmatch(r"\d+", base_value):
        return False

    if len(base_value) > 0 and len(base_value) <= 160 and re.search(r"[A-Za-z]", base_value):
        return True

    return False


def deferred_marker_insertion_point_priority(insertion_point):
    name = (getattr(insertion_point, "name", "") or "").strip().lower()
    location = (getattr(insertion_point, "location", "") or "").strip().lower()
    score = 0

    strong_tokens = (
        "comment", "message", "content", "text", "bio", "about", "title",
        "description", "name", "username", "display_name", "website", "url",
        "redirect", "next", "return",
    )
    medium_tokens = ("subject", "location", "profile", "link")

    if any(token in name for token in strong_tokens):
        score += 10
    if any(token in name for token in medium_tokens):
        score += 4
    if location == INSERTION_POINT_BODY:
        score += 2
    if location == INSERTION_POINT_QUERY:
        score += 1

    return score


def prioritize_deferred_marker_points(spec):
    request_key = request_spec_key(spec)
    candidates = []
    for insertion_point in extract_insertion_points(spec):
        if not is_deferred_marker_candidate(insertion_point):
            continue
        candidates.append(insertion_point)

    return sorted(
        candidates,
        key=lambda item: (
            -deferred_marker_insertion_point_priority(item),
            insertion_point_identity(request_key, item),
        ),
    )


def replay_capability_key(spec, replay_mode, detector, failure_kind):
    return (
        request_host(resolve_request_spec_target(spec)),
        request_path(resolve_request_spec_target(spec)),
        (getattr(spec, "method", "") or "").upper(),
        (replay_mode or "").lower(),
        (detector or "").lower(),
        (failure_kind or "").lower(),
    )


def remember_replay_failure(spec, replay_mode, detector, failure_kind):
    capability_key = replay_capability_key(spec, replay_mode, detector, failure_kind)
    host = capability_key[0]
    if host:
        REPLAY_FAILURE_CAPABILITIES.add(capability_key)


def has_replay_failure_capability(spec, replay_mode, detector):
    host = request_host(resolve_request_spec_target(spec))
    path = request_path(resolve_request_spec_target(spec))
    method = (getattr(spec, "method", "") or "").upper()
    replay_mode = (replay_mode or "").lower()
    detector = (detector or "").lower()

    for candidate in REPLAY_FAILURE_CAPABILITIES:
        if candidate[:5] == (host, path, method, replay_mode, detector):
            return candidate[5]
    return ""


def normalize_response_headers(headers):
    return {
        str(key).lower(): value
        for key, value in dict(headers or {}).items()
    }


async def fetch_cors_probe_result_in_browser(browser_context, spec, timeout, origin, preflight=False):
    page = await browser_context.new_page()
    page.set_default_navigation_timeout(timeout)
    target_url = resolve_request_spec_target(spec)
    body = None
    trigger_method = spec.method
    trigger_headers = {}
    response_records = []
    started = time.perf_counter()

    if spec.method == "POST" and spec.body_type == BODY_TYPE_URLENCODED:
        body = serialize_request_entries(request_params_to_entries(spec.params))
        trigger_headers["Content-Type"] = BODY_TYPE_URLENCODED

    if preflight:
        trigger_headers["X-Bober-Cors"] = "1"

    def _on_response(resp):
        try:
            if resp.url != target_url:
                return
            expected_method = "OPTIONS" if preflight else spec.method
            if resp.request.method != expected_method:
                return
            response_records.append(resp)
        except Exception:
            return

    async def _route_handler(route):
        request = route.request
        if request.url != target_url:
            await route.continue_()
            return

        headers = dict(request.headers)
        headers["Origin"] = origin
        if request.method == "OPTIONS":
            headers["Access-Control-Request-Method"] = spec.method
            if spec.method == "POST" and spec.body_type == BODY_TYPE_URLENCODED:
                headers["Access-Control-Request-Headers"] = "content-type,x-bober-cors"
            elif preflight:
                headers["Access-Control-Request-Headers"] = "x-bober-cors"

        await route.continue_(headers=headers)

    await page.route("**/*", _route_handler)
    page.on("response", _on_response)

    try:
        await page.goto("data:text/html,<html><body>bober cors probe</body></html>", wait_until="domcontentloaded")
        try:
            await page.evaluate(
                """
                async ({ url, method, headers, body }) => {
                    try {
                        await fetch(url, {
                            method,
                            mode: 'cors',
                            credentials: 'include',
                            headers,
                            body,
                        });
                    } catch (e) {
                        return String(e);
                    }
                    return 'ok';
                }
                """,
                {
                    "url": target_url,
                    "method": trigger_method,
                    "headers": trigger_headers,
                    "body": body,
                },
            )
        except Exception:
            pass

        await asyncio.sleep(0.5)
        response = response_records[-1] if response_records else None
        if response is None:
            duration_ms = int((time.perf_counter() - started) * 1000)
            return {
                "status": 0,
                "text": "",
                "url": target_url,
                "headers": {},
                "duration_ms": duration_ms,
                "probe_method": "OPTIONS" if preflight else trigger_method,
                "target_url": target_url,
            }

        try:
            headers = await response.all_headers()
        except Exception:
            headers = {}
        try:
            text = await response.text()
        except Exception:
            text = ""

        duration_ms = int((time.perf_counter() - started) * 1000)
        return {
            "status": response.status,
            "text": text,
            "url": response.url,
            "headers": normalize_response_headers(headers),
            "duration_ms": duration_ms,
            "probe_method": response.request.method,
            "target_url": target_url,
        }
    finally:
        try:
            page.remove_listener("response", _on_response)
        except Exception:
            pass
        try:
            await page.unroute("**/*", _route_handler)
        except Exception:
            pass
        await page.close()


async def fetch_request_spec_response(api_context, spec, timeout, browser_context=None):
    result = await fetch_request_spec_result(
        api_context,
        spec,
        timeout,
        browser_context=browser_context,
    )
    return result["status"], result["text"]


async def fetch_url_result_in_browser(browser_context, url, timeout):
    page = await browser_context.new_page()
    page.set_default_navigation_timeout(timeout)
    started = time.perf_counter()

    try:
        response = await navigate_page(page, url, timeout)

        status = response.status if response is not None else 0
        final_url = page.url or url
        headers = {}
        text = ""

        if response is not None:
            try:
                headers = await response.all_headers()
            except Exception:
                headers = {}
            try:
                text = await response.text()
            except Exception:
                text = await safe_page_content(page)
        else:
            text = await safe_page_content(page)

        duration_ms = int((time.perf_counter() - started) * 1000)
        return {
            "status": status,
            "text": text,
            "url": final_url,
            "headers": headers,
            "duration_ms": duration_ms,
        }
    finally:
        await page.close()


def browser_replay_context_url(spec):
    metadata = getattr(spec, "metadata", {}) or {}
    for candidate in (
        metadata.get("page_url", ""),
        metadata.get("source_url", ""),
        spec.url,
    ):
        candidate = (candidate or "").strip()
        if candidate.startswith(("http://", "https://")):
            return candidate
    return spec.url


def is_execution_context_destroyed_error(exc):
    message = str(exc or "").lower()
    return "execution context was destroyed" in message


async def submit_form_entries_in_page(page, action, entries, timeout):
    document_responses = []

    def _on_response(resp):
        try:
            if getattr(resp.request, "resource_type", "") == "document":
                document_responses.append(resp)
        except Exception:
            return

    page.on("response", _on_response)
    try:
        try:
            await page.evaluate(
                """
                ({ action, entries }) => {
                    const form = document.createElement('form');
                    form.method = 'post';
                    form.action = action;
                    form.style.display = 'none';

                    for (const [name, value] of entries) {
                        const input = document.createElement('input');
                        input.type = 'hidden';
                        input.name = name;
                        input.value = value;
                        form.appendChild(input);
                    }

                    document.body.appendChild(form);
                    HTMLFormElement.prototype.submit.call(form);
                }
                """,
                {
                    "action": action,
                    "entries": entries,
                },
            )
        except Exception as e:
            if not is_execution_context_destroyed_error(e):
                raise

        try:
            await page.wait_for_load_state("domcontentloaded", timeout=timeout)
        except Exception:
            pass

        await asyncio.sleep(0.2)
        return document_responses[-1] if document_responses else None
    finally:
        try:
            page.remove_listener("response", _on_response)
        except Exception:
            pass


async def fetch_request_spec_result_in_browser(browser_context, spec, timeout):
    page = await browser_context.new_page()
    page.set_default_navigation_timeout(timeout)
    started = time.perf_counter()

    try:
        if spec.body_type == BODY_TYPE_QUERY:
            target_url = merge_url_query(spec.url, request_params_to_entries(spec.params))
            response = await navigate_page(page, target_url, timeout)

            status = response.status if response is not None else 0
            final_url = page.url or target_url
            headers = {}
            text = ""

            if response is not None:
                try:
                    headers = await response.all_headers()
                except Exception:
                    headers = {}
                try:
                    text = await response.text()
                except Exception:
                    text = await safe_page_content(page)
            else:
                text = await safe_page_content(page)

            duration_ms = int((time.perf_counter() - started) * 1000)
            return {
                "status": status,
                "text": text,
                "url": final_url,
                "headers": headers,
                "duration_ms": duration_ms,
            }

        if spec.method == "POST" and spec.body_type == BODY_TYPE_URLENCODED:
            entries = request_params_to_browser_form_entries(spec.params)
            context_url = browser_replay_context_url(spec)
            await navigate_page(page, context_url, timeout)
            response = await submit_form_entries_in_page(page, spec.url, entries, timeout)

            headers = {}
            if response is not None:
                try:
                    headers = await response.all_headers()
                except Exception:
                    headers = {}
            try:
                text = await safe_page_content(page, retries=0, delay=0.05)
            except Exception:
                text = ""

            duration_ms = int((time.perf_counter() - started) * 1000)
            return {
                "status": response.status if response is not None else 0,
                "text": text,
                "url": page.url or spec.url,
                "headers": headers,
                "duration_ms": duration_ms,
            }

        raise ValueError(f"Unsupported browser request spec for checks: {spec.method} {spec.body_type}")
    finally:
        await page.close()


async def fetch_request_spec_result(api_context, spec, timeout, browser_context=None):
    if browser_context is None:
        raise ValueError("browser_context is required for vulnerability replay")
    return await fetch_request_spec_result_in_browser(browser_context, spec, timeout)


def build_payload_match_candidates(payload):
    candidates = []
    seen = set()
    current = payload or ""

    for _ in range(3):
        candidate = current
        if candidate and candidate not in seen:
            seen.add(candidate)
            candidates.append(candidate)

        decoded = unquote(candidate)
        if decoded == candidate:
            break
        current = decoded

    return candidates


def find_reflection_evidence(text, payload):
    if not text or not payload:
        return ""

    for candidate in build_payload_match_candidates(payload):
        if candidate in text:
            return candidate

    decoded_text = unescape(text)
    for candidate in build_payload_match_candidates(payload):
        if candidate in decoded_text:
            return candidate

    return ""


def find_raw_html_evidence(text, payload):
    if not text or not payload:
        return "", ""

    decoded_text = unescape(text)
    for candidate in build_payload_match_candidates(payload):
        if "<" not in candidate and ">" not in candidate:
            continue
        if candidate in text:
            return candidate, "raw"
        if candidate in decoded_text:
            return candidate, "html-escaped"

    return "", ""


def infer_reflection_context(text, payload):
    if not text or not payload:
        return ""

    for candidate in build_payload_match_candidates(payload):
        if not candidate:
            continue

        for haystack in (text, unescape(text)):
            idx = haystack.find(candidate)
            if idx == -1:
                continue

            before = haystack[:idx]
            after = haystack[idx + len(candidate):]
            tail_before = before[-300:]
            head_after = after[:300]

            last_script_open = tail_before.lower().rfind("<script")
            last_script_close = tail_before.lower().rfind("</script")
            if last_script_open != -1 and last_script_open > last_script_close:
                script_end = head_after.lower().find("</script")
                if script_end != -1:
                    return "script-block"

            last_tag_open = tail_before.rfind("<")
            last_tag_close = tail_before.rfind(">")
            if last_tag_open > last_tag_close:
                tag_fragment = tail_before[last_tag_open:] + head_after
                if re.search(r"""\w+\s*=\s*['"][^'"]*$""", tag_fragment):
                    return "attribute-value"
                if re.search(r"""\w+\s*=\s*[^\s>]*$""", tag_fragment):
                    return "attribute-unquoted"
                return "html-tag"

            if "<!--" in tail_before and "-->" not in tail_before.split("<!--")[-1]:
                if "-->" in head_after:
                    return "html-comment"

            return "html-text"

    return ""


def extract_payload_attribute_value(payload, attribute_name):
    if not payload or not attribute_name:
        return ""

    pattern = re.compile(
        rf"""{re.escape(attribute_name)}\s*=\s*["']([^"']+)["']""",
        flags=re.IGNORECASE,
    )

    for candidate in build_payload_match_candidates(payload):
        match = pattern.search(candidate)
        if match:
            return match.group(1)

    return ""


async def find_raw_html_dom_evidence(browser_context, text, payload):
    if not text or not payload:
        return ""

    marker = extract_payload_attribute_value(payload, "data-bober-xss")
    if not marker:
        return ""

    page = await browser_context.new_page()
    try:
        await page.set_content(text, wait_until="domcontentloaded")
        await asyncio.sleep(0)
        return await page.evaluate(
            """
            (expected) => {
                const nodes = Array.from(document.querySelectorAll('[data-bober-xss]'));
                const target = nodes.find(node => node.getAttribute('data-bober-xss') === expected);
                if (!target) {
                    return '';
                }

                const tag = (target.tagName || '').toLowerCase();
                const attrs = target.getAttributeNames().sort();
                const inlineHandlers = attrs.filter(name => name.startsWith('on'));
                const details = [`dom-node tag=${tag}`];

                if (attrs.length) {
                    details.push(`attrs=${attrs.join(',')}`);
                }
                if (inlineHandlers.length) {
                    details.push(`inline-handlers=${inlineHandlers.join(',')}`);
                }

                return details.join(' ');
            }
            """,
            marker,
        ) or ""
    except Exception as e:
        logging.debug("Raw HTML DOM analysis failed (%s)", e)
        return ""
    finally:
        await page.close()


async def find_raw_html_phase_evidence(browser_context, text, payload):
    raw_evidence, reflection_mode = find_raw_html_evidence(text, payload)
    if not raw_evidence:
        return ""

    dom_evidence = await find_raw_html_dom_evidence(browser_context, text, payload)
    context = infer_reflection_context(text, payload)
    if dom_evidence:
        if context:
            return f"{dom_evidence} context={context}"
        return dom_evidence

    evidence_key = "html-reflection"
    if reflection_mode == "html-escaped":
        evidence_key = "escaped-html-reflection"
        raw_evidence = escape(raw_evidence, quote=True)

    if context:
        return f"{evidence_key}={raw_evidence} context={context}"
    return f"{evidence_key}={raw_evidence}"


def find_evaluated_text_evidence(text, payload, expected_outputs):
    if not text or not expected_outputs:
        return ""

    decoded_text = unescape(text)
    raw_payload_present = payload in text or payload in decoded_text

    for expected in expected_outputs:
        if expected in text or expected in decoded_text:
            if not raw_payload_present:
                return expected

    return ""


def classify_ssti_expected_output(payload, expected):
    payload = payload or ""
    expected = expected or ""

    if "1337*13" in payload and expected == "17381":
        return "jinja-like-arithmetic"
    if "11111-123" in payload and expected == "10988":
        return "el-like-arithmetic"
    if "1234" in payload and "321" in payload and expected == "1555":
        return "erb-like-arithmetic"
    return "template-evaluation"


def infer_template_error_signature(text):
    if not text:
        return ""

    lowered = unescape(text).lower()
    signatures = [
        ("jinja-like-error", ["jinja", "template syntax error", "undefinederror"]),
        ("twig-like-error", ["twig", "unexpected token", "syntax error"]),
        ("django-like-error", ["templateSyntaxError".lower(), "django", "could not parse the remainder"]),
        ("erb-like-error", ["actionview::template", "syntax error", "erb"]),
        ("freemarker-like-error", ["freemarker", "templateexception", "parseexception"]),
        ("velocity-like-error", ["velocity", "parse error", "lexical error"]),
        ("generic-template-error", ["template", "syntax error"]),
    ]

    for label, markers in signatures:
        if all(marker in lowered for marker in markers):
            return label

    return ""


def infer_sql_error_signature(text):
    if not text:
        return ""

    lowered = unescape(text).lower()
    signatures = [
        ("postgresql-error", ["postgresql", "syntax error at or near"]),
        ("postgresql-query-error", ["pg_query", "query failed"]),
        ("mysql-syntax-error", ["you have an error in your sql syntax"]),
        ("mysql-warning", ["warning", "mysql"]),
        ("mariadb-syntax-error", ["mariadb", "sql syntax"]),
        ("sql-server-odbc-error", ["odbc sql server driver", "syntax error"]),
        ("sql-server-unclosed-quote", ["unclosed quotation mark", "sql server"]),
        ("sql-server-native-error", ["microsoft ole db provider for sql server"]),
        ("oracle-error", ["ora-", "oracle"]),
        ("sqlite-error", ["sqlite", "syntax error"]),
        ("sqlite-query-error", ["sqlite_exception"]),
        ("jdbc-sql-error", ["sqlsyntaxerrorexception"]),
        ("database-syntax-error", ["database", "syntax error"]),
        ("database-near-error", ["database", "near", "syntax error"]),
        ("query-syntax-error", ["query", "syntax error"]),
        ("statement-syntax-error", ["statement", "syntax error"]),
        ("near-syntax-error", ["near", "syntax error"]),
        ("quoted-string-error", ["quoted string", "terminated"]),
        ("unterminated-string-error", ["unterminated", "string"]),
        ("sqlstate-error", ["sqlstate"]),
        ("generic-sql-error", ["sql", "syntax"]),
    ]

    for label, markers in signatures:
        if all(marker in lowered for marker in markers):
            return label

    return ""


def infer_command_error_signature(text):
    if not text:
        return ""

    lowered = unescape(text).lower()
    signatures = [
        ("unix-shell-syntax-error", ["sh:", "syntax error"]),
        ("bash-syntax-error", ["bash:", "syntax error"]),
        ("shell-unexpected-token", ["unexpected token"]),
        ("shell-unexpected-eof", ["unexpected eof"]),
        ("shell-command-not-found", ["command not found"]),
        ("shell-not-found", ["/bin/sh", "not found"]),
        ("shell-eof-while-looking-for-matching", ["unexpected eof while looking for matching"]),
        ("windows-cmd-not-recognized", ["is not recognized as an internal or external command"]),
        ("windows-cmd-syntax-error", ["cmd.exe", "syntax"]),
        ("powershell-command-not-found", ["powershell", "is not recognized"]),
        ("powershell-not-found", ["the term", "is not recognized"]),
        ("unterminated-quoted-string", ["unterminated", "quoted string"]),
    ]

    for label, markers in signatures:
        if all(marker in lowered for marker in markers):
            return label

    return ""


def normalize_diffable_response_text(text):
    visible = normalize_ssrf_visible_text(text)
    return re.sub(r"\s+", " ", (visible or "").strip())


def build_sqli_diff_evidence(baseline_result, response_result, payload):
    if not baseline_result or not response_result:
        return ""

    baseline_status = baseline_result.get("status", 0)
    response_status = response_result.get("status", 0)
    baseline_url = (baseline_result.get("url") or "").strip()
    response_url = (response_result.get("url") or "").strip()
    baseline_text = baseline_result.get("text") or ""
    response_text = response_result.get("text") or ""

    if infer_sql_error_signature(response_text):
        return ""

    payload_reflected = bool(find_reflection_evidence(response_text, payload))
    status_changed = response_status != baseline_status
    path_changed = protected_target_path(response_url) != protected_target_path(baseline_url)

    baseline_visible = normalize_diffable_response_text(baseline_text)
    response_visible = normalize_diffable_response_text(response_text)
    baseline_len = len(baseline_visible)
    response_len = len(response_visible)
    length_delta = abs(response_len - baseline_len)
    max_len = max(baseline_len, response_len, 1)
    length_ratio = length_delta / max_len

    similarity = 1.0
    if baseline_visible and response_visible:
        similarity = difflib.SequenceMatcher(
            None,
            baseline_visible[:4000],
            response_visible[:4000],
        ).ratio()

    if status_changed and not payload_reflected:
        return " ".join(
            [
                f"baseline_status={baseline_status}",
                f"final_status={response_status}",
                f"baseline_len={baseline_len}",
                f"final_len={response_len}",
                "signature=status-change",
            ]
        )

    if path_changed and not payload_reflected:
        return " ".join(
            [
                f"baseline_status={baseline_status}",
                f"final_status={response_status}",
                f"baseline_path={protected_target_path(baseline_url)}",
                f"final_path={protected_target_path(response_url)}",
                "signature=path-change",
            ]
        )

    if payload_reflected:
        return ""

    if (
        baseline_len >= 40 and
        response_len >= 40 and
        length_delta >= 120 and
        length_ratio >= 0.30 and
        similarity <= 0.72
    ):
        return " ".join(
            [
                f"baseline_status={baseline_status}",
                f"final_status={response_status}",
                f"baseline_len={baseline_len}",
                f"final_len={response_len}",
                f"similarity={similarity:.2f}",
                "signature=response-diff",
            ]
        )

    return ""


def build_sqli_time_evidence(baseline_result, response_result, payload):
    if not baseline_result or not response_result:
        return ""

    baseline_duration = int(baseline_result.get("duration_ms", 0) or 0)
    response_duration = int(response_result.get("duration_ms", 0) or 0)
    duration_delta = response_duration - baseline_duration
    response_text = response_result.get("text") or ""

    if infer_sql_error_signature(response_text):
        return ""

    if find_reflection_evidence(response_text, payload):
        return ""

    if response_duration < DEFAULT_SQLI_TIME_THRESHOLD_MS:
        return ""

    if duration_delta < DEFAULT_SQLI_TIME_THRESHOLD_MS:
        return ""

    return " ".join(
        [
            f"baseline_status={baseline_result.get('status', 0)}",
            f"final_status={response_result.get('status', 0)}",
            f"baseline_duration_ms={baseline_duration}",
            f"final_duration_ms={response_duration}",
            f"delay_delta_ms={duration_delta}",
            "signature=time-delay",
        ]
    )


def build_cmdi_probe_evidence(baseline_result, response_result, payload):
    if not baseline_result or not response_result:
        return ""

    response_text = response_result.get("text") or ""
    signature = infer_command_error_signature(response_text)
    if signature:
        evidence = find_status_500_evidence(
            response_result.get("status", 0),
            baseline_result.get("status", 0),
        )
        if evidence:
            return f"{evidence} signature={signature}"
        return f"signature={signature}"

    if find_reflection_evidence(response_text, payload):
        return ""

    baseline_status = baseline_result.get("status", 0)
    response_status = response_result.get("status", 0)
    baseline_url = (baseline_result.get("url") or "").strip()
    response_url = (response_result.get("url") or "").strip()
    baseline_text = baseline_result.get("text") or ""

    status_changed = response_status != baseline_status
    path_changed = protected_target_path(response_url) != protected_target_path(baseline_url)

    baseline_visible = normalize_diffable_response_text(baseline_text)
    response_visible = normalize_diffable_response_text(response_text)
    baseline_len = len(baseline_visible)
    response_len = len(response_visible)
    length_delta = abs(response_len - baseline_len)
    max_len = max(baseline_len, response_len, 1)
    length_ratio = length_delta / max_len

    similarity = 1.0
    if baseline_visible and response_visible:
        similarity = difflib.SequenceMatcher(
            None,
            baseline_visible[:4000],
            response_visible[:4000],
        ).ratio()

    if status_changed:
        return " ".join(
            [
                f"baseline_status={baseline_status}",
                f"final_status={response_status}",
                f"baseline_len={baseline_len}",
                f"final_len={response_len}",
                "signature=status-change",
            ]
        )

    if path_changed:
        return " ".join(
            [
                f"baseline_status={baseline_status}",
                f"final_status={response_status}",
                f"baseline_path={protected_target_path(baseline_url)}",
                f"final_path={protected_target_path(response_url)}",
                "signature=path-change",
            ]
        )

    if (
        baseline_len >= 40 and
        response_len >= 40 and
        length_delta >= 120 and
        length_ratio >= 0.30 and
        similarity <= 0.72
    ):
        return " ".join(
            [
                f"baseline_status={baseline_status}",
                f"final_status={response_status}",
                f"baseline_len={baseline_len}",
                f"final_len={response_len}",
                f"similarity={similarity:.2f}",
                "signature=response-diff",
            ]
        )

    return ""


def build_cmdi_time_evidence(baseline_result, response_result, payload):
    if not baseline_result or not response_result:
        return ""

    baseline_duration = int(baseline_result.get("duration_ms", 0) or 0)
    response_duration = int(response_result.get("duration_ms", 0) or 0)
    duration_delta = response_duration - baseline_duration
    response_text = response_result.get("text") or ""

    if infer_command_error_signature(response_text):
        return ""

    if find_reflection_evidence(response_text, payload):
        return ""

    if response_duration < DEFAULT_CMDI_TIME_THRESHOLD_MS:
        return ""

    if duration_delta < DEFAULT_CMDI_TIME_THRESHOLD_MS:
        return ""

    return " ".join(
        [
            f"baseline_status={baseline_result.get('status', 0)}",
            f"final_status={response_result.get('status', 0)}",
            f"baseline_duration_ms={baseline_duration}",
            f"final_duration_ms={response_duration}",
            f"delay_delta_ms={duration_delta}",
            "signature=time-delay",
        ]
    )


def find_status_500_evidence(status_code, baseline_status):
    if status_code >= 500 and baseline_status < 500:
        return f"status={status_code}"
    return ""


async def confirm_status_probe_evidence(
    api_context,
    spec,
    timeout,
    baseline_status,
    browser_context=None,
    signature_resolver=None,
    confirmation_requests=DEFAULT_STATUS_PROBE_CONFIRMATION_REQUESTS,
):
    first_status, first_text = await fetch_request_spec_response(
        api_context,
        spec,
        timeout,
        browser_context=browser_context,
    )
    first_evidence = find_status_500_evidence(first_status, baseline_status)
    if not first_evidence:
        return ""

    first_signature = signature_resolver(first_text) if signature_resolver else ""
    if first_signature:
        return f"{first_evidence} signature={first_signature}"

    confirmations = 1
    last_status = first_status
    for _ in range(max(1, confirmation_requests) - 1):
        confirm_status, confirm_text = await fetch_request_spec_response(
            api_context,
            spec,
            timeout,
            browser_context=browser_context,
        )
        last_status = confirm_status
        if confirm_status < 500:
            return ""

        confirm_signature = signature_resolver(confirm_text) if signature_resolver else ""
        if confirm_signature:
            return f"status={confirm_status} signature={confirm_signature}"

        if confirm_status == first_status:
            confirmations += 1

    if confirmations < max(1, confirmation_requests):
        return ""

    return " ".join(
        [
            f"status={first_status}",
            f"confirmations={confirmations}",
            f"last_status={last_status}",
            "signature=repeated-5xx",
        ]
    )


def analyze_passwd_disclosure(text):
    if not text:
        return None

    decoded_text = unescape(text)
    text_only = re.sub(r"<[^>]+>", "\n", decoded_text)
    passwd_lines = []
    usernames = []

    for raw_line in text_only.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if not re.match(r"^[a-z_][a-z0-9_-]*:[^:]*:\d+:\d+:[^:]*:[^:]*:[^:]*$", line, flags=re.IGNORECASE):
            continue
        passwd_lines.append(line)
        usernames.append(line.split(":", 1)[0])

    if len(passwd_lines) < 2:
        return None

    markers = []
    joined = "\n".join(passwd_lines)
    username_set = set(usernames)

    if "root" in username_set:
        markers.append("root-entry")
    if "daemon" in username_set:
        markers.append("daemon-entry")
    if "nobody" in username_set:
        markers.append("nobody-entry")
    if re.search(r"/bin/(?:bash|sh)\b", joined):
        markers.append("shell")
    if re.search(r"/usr/sbin/nologin\b", joined):
        markers.append("nologin")
    if len(passwd_lines) >= 3:
        markers.append("multi-account")

    if "root-entry" not in markers:
        return None

    return {
        "markers": markers,
        "accounts": len(passwd_lines),
        "sample_users": usernames[:3],
    }


def classify_passwd_disclosure(markers, accounts=0):
    marker_set = set(markers or [])
    if not marker_set:
        return ""

    if {"root-entry", "daemon-entry", "shell", "multi-account"} <= marker_set and accounts >= 3:
        return "strong-passwd-disclosure"
    if {"root-entry", "shell"} <= marker_set:
        return "interactive-shell-passwd-disclosure"
    if {"root-entry", "daemon-entry"} <= marker_set or {"root-entry", "nobody-entry"} <= marker_set:
        return "service-account-passwd-disclosure"
    if {"root-entry", "nologin"} <= marker_set:
        return "nologin-passwd-disclosure"
    if "root-entry" in marker_set and accounts >= 2:
        return "passwd-disclosure"
    return ""


def find_passwd_disclosure_evidence(text):
    analysis = analyze_passwd_disclosure(text)
    if not analysis:
        return ""

    markers = ",".join(analysis["markers"])
    sample_users = ",".join(analysis["sample_users"])
    parts = [
        f"markers={markers}",
        f"accounts={analysis['accounts']}",
    ]
    if sample_users:
        parts.append(f"sample-users={sample_users}")

    signature = classify_passwd_disclosure(analysis["markers"], analysis["accounts"])
    if signature:
        parts.append(f"signature={signature}")

    return " ".join(parts)


def find_win_ini_disclosure_evidence(text):
    if not text:
        return ""

    decoded_text = unescape(text)
    normalized = decoded_text.lower()
    markers = []

    if "[fonts]" in normalized:
        markers.append("fonts-section")
    if "[extensions]" in normalized:
        markers.append("extensions-section")
    if "mapi=1" in normalized:
        markers.append("mapi")
    if "for 16-bit app support" in normalized:
        markers.append("16-bit-app-support")
    if "windows" in normalized and "load=" in normalized and "run=" in normalized:
        markers.append("windows-section")

    if len(markers) < 2:
        return ""

    signature = "strong-win-ini-disclosure" if len(markers) >= 3 else "win-ini-disclosure"
    return " ".join(
        [
            f"markers={','.join(markers[:4])}",
            f"signature={signature}",
        ]
    )


def infer_xml_parser_error_signature(text):
    if not text:
        return ""

    lowered = unescape(text).lower()
    signatures = [
        ("doctype-disallowed", ["doctype", "disallow"]),
        ("external-entity-blocked", ["external entity", "forbidden"]),
        ("undefined-entity", ["entity", "not defined"]),
        ("xml-parse-error", ["xml", "parse", "error"]),
        ("sax-parse-error", ["saxparseexception"]),
    ]

    for label, markers in signatures:
        if all(marker in lowered for marker in markers):
            return label

    return ""


async def find_browser_execution_evidence(browser_context, spec, marker, timeout):
    if not marker:
        return ""
    known_failure = has_replay_failure_capability(spec, "browser-submit", "browser-event")
    if known_failure:
        capability_key = replay_capability_key(
            spec,
            "browser-submit",
            "browser-event",
            known_failure,
        )
        if capability_key not in REPLAY_FAILURE_CAPABILITIES_LOGGED:
            REPLAY_FAILURE_CAPABILITIES_LOGGED.add(capability_key)
            logging.debug(
                "Skipping browser proof replay after capability failure (%s): %s",
                known_failure,
                request_spec_key(spec),
            )
        return ""

    page = await browser_context.new_page()
    page.set_default_navigation_timeout(timeout)
    console_hits = []
    dialog_hits = []

    def _remember_hit(bucket, value):
        if not value:
            return
        text = str(value).strip()
        if marker not in text:
            return
        bucket.append(text[:300])

    def _on_console(message):
        try:
            _remember_hit(console_hits, message.text)
        except Exception:
            return

    def _on_dialog(dialog):
        try:
            _remember_hit(dialog_hits, f"{dialog.type}:{dialog.message}")
        finally:
            try:
                asyncio.create_task(dialog.dismiss())
            except Exception:
                return

    page.on("console", _on_console)
    page.on("dialog", _on_dialog)
    try:
        if spec.body_type == BODY_TYPE_QUERY:
            target_url = merge_url_query(spec.url, request_params_to_entries(spec.params))
            await navigate_page(page, target_url, timeout)
        elif spec.method == "POST" and spec.body_type == BODY_TYPE_URLENCODED:
            entries = request_params_to_browser_form_entries(spec.params)
            context_url = browser_replay_context_url(spec)
            await navigate_page(page, context_url, timeout)
            await submit_form_entries_in_page(page, spec.url, entries, timeout)
        else:
            raise ValueError(f"Unsupported browser request spec for checks: {spec.method} {spec.body_type}")

        await asyncio.sleep(ACTIVE_ACTION_WAIT)
        if console_hits:
            return f"console={console_hits[0]}"
        if dialog_hits:
            return f"alert={dialog_hits[0]}"
        return ""
    finally:
        try:
            page.remove_listener("console", _on_console)
        except Exception:
            pass
        try:
            page.remove_listener("dialog", _on_dialog)
        except Exception:
            pass
        await page.close()


async def evaluate_phase(api_context, browser_context, spec, phase, payload, expected_outputs, marker, timeout, baseline_status, baseline_result=None):
    if phase.detector == "reflection":
        _, response_text = await fetch_request_spec_response(
            api_context,
            spec,
            timeout,
            browser_context=browser_context,
        )
        return find_reflection_evidence(response_text, payload)

    if phase.detector == "raw-html":
        _, response_text = await fetch_request_spec_response(
            api_context,
            spec,
            timeout,
            browser_context=browser_context,
        )
        return await find_raw_html_phase_evidence(browser_context, response_text, payload)

    if phase.detector == "evaluated-text":
        _, response_text = await fetch_request_spec_response(
            api_context,
            spec,
            timeout,
            browser_context=browser_context,
        )
        expected = find_evaluated_text_evidence(response_text, payload, expected_outputs)
        if not expected:
            return ""
        signature = classify_ssti_expected_output(payload, expected)
        return f"evaluated={expected} signature={signature}"

    if phase.detector == "status-500":
        return await confirm_status_probe_evidence(
            api_context,
            spec,
            timeout,
            baseline_status,
            browser_context=browser_context,
            signature_resolver=infer_template_error_signature,
        )

    if phase.detector == "sqli-error":
        status_code, response_text = await fetch_request_spec_response(
            api_context,
            spec,
            timeout,
            browser_context=browser_context,
        )
        signature = infer_sql_error_signature(response_text)
        if not signature:
            return ""

        evidence = find_status_500_evidence(status_code, baseline_status)
        if evidence:
            return f"{evidence} signature={signature}"
        return f"signature={signature}"

    if phase.detector == "sqli-diff":
        response_result = await fetch_request_spec_result(
            api_context,
            spec,
            timeout,
            browser_context=browser_context,
        )
        return build_sqli_diff_evidence(baseline_result, response_result, payload)

    if phase.detector == "sqli-time":
        response_result = await fetch_request_spec_result(
            api_context,
            spec,
            timeout,
            browser_context=browser_context,
        )
        return build_sqli_time_evidence(baseline_result, response_result, payload)

    if phase.detector == "cmdi-probe":
        response_result = await fetch_request_spec_result(
            api_context,
            spec,
            timeout,
            browser_context=browser_context,
        )
        return build_cmdi_probe_evidence(baseline_result, response_result, payload)

    if phase.detector == "cmdi-time":
        response_result = await fetch_request_spec_result(
            api_context,
            spec,
            timeout,
            browser_context=browser_context,
        )
        return build_cmdi_time_evidence(baseline_result, response_result, payload)

    if phase.detector == "xxe-parser-error":
        _, response_text = await fetch_request_spec_response(
            api_context,
            spec,
            timeout,
            browser_context=browser_context,
        )
        signature = infer_xml_parser_error_signature(response_text)
        if not signature:
            return ""
        return f"signature={signature}"

    if phase.detector == "xxe-file-disclosure":
        _, response_text = await fetch_request_spec_response(
            api_context,
            spec,
            timeout,
            browser_context=browser_context,
        )
        passwd_evidence = find_passwd_disclosure_evidence(response_text)
        if passwd_evidence:
            return passwd_evidence
        return find_win_ini_disclosure_evidence(response_text)

    if phase.detector == "browser-event":
        return await find_browser_execution_evidence(browser_context, spec, marker, timeout)

    return ""


def instantiate_phase_payload(phase, payload_template):
    token = build_payload_token()
    payload = instantiate_payload_template(payload_template, token)
    marker = instantiate_payload_template(phase.marker, token)
    expected_output_templates = phase.expected_outputs.get(payload_template)
    if expected_output_templates is None:
        expected_output_templates = phase.expected_outputs.get(unquote(payload_template), [])
    expected_outputs = [
        instantiate_payload_template(value, token)
        for value in expected_output_templates
    ]
    return payload, marker, expected_outputs


def is_transient_navigation_error(exc):
    message = str(exc or "").lower()
    return (
        "page is navigating and changing the content" in message or
        "unable to retrieve content because the page is navigating" in message
    )


def is_benign_request_failure(resource_type, failure):
    resource_type = (resource_type or "").lower()
    failure = (failure or "").lower()
    return (
        resource_type in {"image", "media", "font", "stylesheet"} and
        ("err_aborted" in failure or "err_blocked_by_orb" in failure)
    )


def is_non_applicable_browser_proof_error(profile, phase, exc):
    if (profile or "").lower() != "xss":
        return False
    if getattr(phase, "detector", "") != "browser-event":
        return False

    message = str(exc or "").lower()
    return (
        "failed to fetch" in message or
        "invalid url" in message or
        "no schema supplied" in message
    )


def classify_replay_failure_kind(exc):
    message = str(exc or "").lower()
    if "failed to fetch" in message:
        return "browser-fetch-failed"
    if "execution context was destroyed" in message:
        return "navigation-context-destroyed"
    if "timeout" in message:
        return "timeout"
    return ""


def compact_exception_message(exc):
    message = str(exc or "").strip()
    if not message:
        return "unknown error"
    return message.splitlines()[0].strip()


def parse_evidence_fields(evidence):
    fields = {}
    for token in re.split(r"\s+", (evidence or "").strip()):
        if "=" not in token:
            continue
        key, value = token.split("=", 1)
        if not key:
            continue
        fields[key] = value
    return fields


def resolve_payload_result_confidence(profile_name, phase, evidence):
    base_confidence = (getattr(phase, "confidence", "") or "low").lower()
    profile_name = (profile_name or "").lower()
    evidence_fields = parse_evidence_fields(evidence)

    if profile_name == "xss":
        if "escaped-html-reflection" in evidence_fields:
            return "low"
        if "html-reflection" in evidence_fields:
            return "medium"
        if "dom-node" in (evidence or "").lower():
            return base_confidence

    if profile_name == "ssti" and (getattr(phase, "name", "") or "").lower() == "template-probe":
        if (evidence_fields.get("signature") or "").lower() == "repeated-5xx":
            return "low"

    return base_confidence


def resolve_cors_result_confidence(evidence):
    signature = (parse_evidence_fields(evidence).get("signature") or "").lower()
    if signature in {"arbitrary-origin-credentialed", "wildcard-origin-credentialed"}:
        return "high"
    if signature in {"arbitrary-origin-preflight", "wildcard-origin-preflight"}:
        return "medium"
    if signature in {"arbitrary-origin-allowed", "wildcard-origin-allowed"}:
        return "low"
    return "low"


def infer_xss_payload_vector(payload):
    normalized_candidates = [
        candidate.lower()
        for candidate in build_payload_match_candidates(payload)
        if candidate
    ]

    for candidate in normalized_candidates:
        if "</script><script>" in candidate:
            return "script-breakout"
        if candidate.startswith('"><svg') or '"><svg' in candidate:
            return "attribute-breakout"
        if candidate.startswith("<img") or "<img" in candidate:
            return "html-event-handler"
        if "<svg" in candidate and "onload" in candidate:
            return "svg-onload"

    return ""


def build_cors_evidence(response_result, origin, probe_kind):
    headers = normalize_response_headers((response_result or {}).get("headers") or {})
    acao = (headers.get("access-control-allow-origin") or "").strip()
    acac = (headers.get("access-control-allow-credentials") or "").strip().lower()
    acam = (headers.get("access-control-allow-methods") or "").strip()

    if not acao:
        return ""

    signature = ""
    if acao == origin:
        if acac == "true":
            signature = "arbitrary-origin-credentialed"
        elif probe_kind == "preflight":
            signature = "arbitrary-origin-preflight"
        else:
            signature = "arbitrary-origin-allowed"
    elif acao == "*":
        if acac == "true":
            signature = "wildcard-origin-credentialed"
        elif probe_kind == "preflight":
            signature = "wildcard-origin-preflight"
        else:
            signature = "wildcard-origin-allowed"

    if not signature:
        return ""

    evidence_parts = [
        f"probe={probe_kind}",
        f"final_status={response_result.get('status', 0)}",
        f"allow_origin={acao}",
        f"signature={signature}",
    ]

    if acac:
        evidence_parts.append(f"allow_credentials={acac}")
    if acam:
        evidence_parts.append(f"allow_methods={acam.replace(' ', '')}")

    return " ".join(evidence_parts)

def parse_set_cookie_header_values(headers):
    if not headers:
        return []

    raw_values = []
    for key, value in dict(headers).items():
        if str(key).lower() != "set-cookie":
            continue
        if isinstance(value, list):
            raw_values.extend(str(item) for item in value if item)
        elif value:
            raw_values.extend(
                part.strip()
                for part in re.split(r"\r?\n", str(value))
                if part.strip()
            )

    return raw_values


def build_security_headers_evidence(response_result):
    headers = normalize_response_headers((response_result or {}).get("headers") or {})
    final_url = (response_result or {}).get("url") or ""
    missing = []

    required_headers = [
        "content-security-policy",
        "x-content-type-options",
        "referrer-policy",
    ]

    for header_name in required_headers:
        if not headers.get(header_name):
            missing.append(header_name)

    try:
        parsed = urlparse(final_url)
    except Exception:
        parsed = None

    if parsed is not None and parsed.scheme == "https" and not headers.get("strict-transport-security"):
        missing.append("strict-transport-security")

    if not missing:
        return ""

    return " ".join(
        [
            f"final_status={(response_result or {}).get('status', 0)}",
            f"missing={','.join(missing)}",
            "signature=missing-security-headers",
        ]
    )


def build_clickjacking_evidence(response_result):
    headers = normalize_response_headers((response_result or {}).get("headers") or {})
    xfo = (headers.get("x-frame-options") or "").strip()
    csp = (headers.get("content-security-policy") or "").strip()
    csp_lower = csp.lower()

    has_frame_ancestors = "frame-ancestors" in csp_lower
    xfo_valid = xfo.lower() in {"deny", "sameorigin"}
    csp_blocks_framing = (
        "frame-ancestors 'none'" in csp_lower or
        "frame-ancestors 'self'" in csp_lower
    )

    if xfo_valid or csp_blocks_framing:
        return ""

    evidence_parts = [
        f"final_status={(response_result or {}).get('status', 0)}",
    ]
    if xfo:
        evidence_parts.append(f"xfo={xfo}")
    else:
        evidence_parts.append("xfo=missing")

    if has_frame_ancestors:
        evidence_parts.append("frame-ancestors=present")
    else:
        evidence_parts.append("frame-ancestors=missing")

    evidence_parts.append("signature=frameable-response")
    return " ".join(evidence_parts)


def build_cookie_flag_findings(spec, response_result):
    headers = (response_result or {}).get("headers") or {}
    set_cookie_values = parse_set_cookie_header_values(headers)
    findings = []

    for cookie_header in set_cookie_values:
        parts = [part.strip() for part in cookie_header.split(";") if part.strip()]
        if not parts or "=" not in parts[0]:
            continue

        cookie_name = parts[0].split("=", 1)[0].strip()
        attribute_flags = {part.lower() for part in parts[1:]}
        missing = []

        if not any(flag == "secure" for flag in attribute_flags):
            missing.append("secure")
        if not any(flag == "httponly" for flag in attribute_flags):
            missing.append("httponly")
        if not any(flag.startswith("samesite=") for flag in attribute_flags):
            missing.append("samesite")

        if not missing:
            continue

        lowered_cookie_name = cookie_name.lower()
        sensitive = any(token in lowered_cookie_name for token in ("session", "auth", "token", "sid", "jwt"))
        findings.append(
            CheckResult(
                profile_name="cookie-flags",
                request_key=request_spec_key(spec),
                insertion_point=InsertionPoint(
                    request_key=request_spec_key(spec),
                    name=cookie_name,
                    location=INSERTION_POINT_HEADER,
                    base_value="",
                ),
                payload=cookie_name,
                phase_name="set-cookie-analysis",
                confidence="medium" if sensitive else "low",
                evidence=" ".join(
                    [
                        f"cookie={cookie_name}",
                        f"missing={','.join(missing)}",
                        f"sensitive={'yes' if sensitive else 'no'}",
                        "signature=weak-cookie-flags",
                    ]
                ),
                reflected=False,
                request_metadata=dict(getattr(spec, "metadata", {}) or {}),
            )
        )

    return findings


def build_cookie_flag_findings_for_target(target_url, response_result):
    pseudo_spec = RequestSpec(
        method="GET",
        url=target_url,
        body_type=BODY_TYPE_QUERY,
        params=[],
        origin="audit-sweep",
        metadata={"source_url": target_url},
    )
    return build_cookie_flag_findings(pseudo_spec, response_result)


def find_markup_context_for_token(text, token):
    if not text or not token:
        return ""

    for haystack in (text, unescape(text)):
        idx = haystack.find(token)
        if idx == -1:
            continue

        before = haystack[:idx]
        after = haystack[idx + len(token):]
        tail_before = before[-300:]
        head_after = after[:300]

        last_tag_open = tail_before.rfind("<")
        last_tag_close = tail_before.rfind(">")
        if last_tag_open > last_tag_close:
            tag_fragment = tail_before[last_tag_open:] + head_after
            if re.search(r"""\w+\s*=\s*['"][^'"]*$""", tag_fragment):
                return "attribute-value"
            if re.search(r"""\w+\s*=\s*[^\s>]*$""", tag_fragment):
                return "attribute-unquoted"
            return "html-tag"

    return ""


def build_deferred_marker_results_for_response(response_result, marker_seeds, target_url):
    if not marker_seeds:
        return []

    results = []
    text = (response_result or {}).get("text") or ""
    final_url = (response_result or {}).get("url") or target_url
    headers = normalize_response_headers((response_result or {}).get("headers") or {})
    location_header = (
        headers.get("location")
        or headers.get("content-location")
        or headers.get("x-pingback")
        or ""
    ).strip()
    visible_text = normalize_ssrf_visible_text(text)
    seen = set()

    for seed in marker_seeds:
        token = seed.token
        payload = deferred_marker_payload(token)
        hit_type = ""
        evidence_parts = [
            f"seed_request={seed.request_key}",
            f"seed_param={seed.param_name}",
            f"seed_target={seed.target_url}",
            f"token={token}",
        ]

        if token in final_url or payload in final_url:
            hit_type = "url-hit"
            evidence_parts.append(f"final_url={final_url}")
        elif location_header and (token in location_header or payload in location_header):
            hit_type = "header-hit"
            evidence_parts.append(f"location={location_header}")
        else:
            markup_context = find_markup_context_for_token(text, token) or find_markup_context_for_token(text, payload)
            if markup_context:
                hit_type = "markup-hit"
                evidence_parts.append(f"context={markup_context}")
            elif token in text or payload in text or token in unescape(text) or payload in unescape(text) or token in visible_text or payload in visible_text:
                hit_type = "text-hit"

        if not hit_type:
            continue

        evidence_parts.append(f"observed_on={target_url}")
        evidence_parts.append(f"final_status={(response_result or {}).get('status', 0)}")
        evidence_parts.append(f"signature={hit_type}")
        dedupe_key = (seed.request_key, seed.param_name, target_url, hit_type)
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)

        results.append(
            CheckResult(
                profile_name="deferred-marker",
                request_key=f"GET {target_url}",
                insertion_point=InsertionPoint(
                    request_key=seed.request_key,
                    name=seed.param_name,
                    location=seed.param_location,
                    base_value="",
                ),
                payload=payload,
                phase_name=hit_type,
                confidence="medium",
                evidence=" ".join(evidence_parts),
                reflected=False,
                request_metadata={"source_url": target_url},
            )
        )

    return results


def classify_result_diagnosis(result):
    if result is None:
        return ""

    evidence = (result.evidence or "").lower()
    evidence_fields = parse_evidence_fields(result.evidence)
    signature = (evidence_fields.get("signature") or "").lower()
    profile = (result.profile_name or "").lower()
    phase = (result.phase_name or "").lower()

    if profile == "xss":
        if phase == "xss-proof":
            vector = infer_xss_payload_vector(getattr(result, "payload", ""))
            if "alert=" in evidence:
                return f"browser-execution-alert:{vector}" if vector else "browser-execution-alert"
            if "console=" in evidence:
                return f"browser-execution-script:{vector}" if vector else "browser-execution-script"
            return f"browser-execution:{vector}" if vector else "browser-execution"
        if "dom-node tag=" in evidence:
            return "html-to-dom"
        if "escaped-html-reflection=" in evidence:
            return "escaped-html-reflection"
        if "html-reflection=" in evidence:
            return "html-reflection"

    if profile == "reflection":
        return "input-reflection"

    if profile == "ssti":
        if phase == "ssti-proof":
            if signature == "jinja-like-arithmetic":
                return "server-evaluation:jinja-like-arithmetic"
            if signature == "el-like-arithmetic":
                return "server-evaluation:el-like-arithmetic"
            if signature == "erb-like-arithmetic":
                return "server-evaluation:erb-like-arithmetic"
            return "server-evaluation"
        if phase == "template-probe":
            if signature == "jinja-like-error":
                return "template-error:jinja-like-error"
            if signature == "twig-like-error":
                return "template-error:twig-like-error"
            if signature == "django-like-error":
                return "template-error:django-like-error"
            if signature == "erb-like-error":
                return "template-error:erb-like-error"
            if signature == "freemarker-like-error":
                return "template-error:freemarker-like-error"
            if signature == "velocity-like-error":
                return "template-error:velocity-like-error"
            return "template-error"

    if profile == "sqli":
        if phase == "sql-time-probe":
            return "sqli:time-delay"
        if phase == "sql-response-diff":
            return "sqli:response-diff"
        if signature == "postgresql-error":
            return "sqli:error-based:postgresql"
        if signature == "postgresql-query-error":
            return "sqli:error-based:postgresql"
        if signature == "mysql-syntax-error":
            return "sqli:error-based:mysql"
        if signature == "mysql-warning":
            return "sqli:error-based:mysql"
        if signature == "mariadb-syntax-error":
            return "sqli:error-based:mariadb"
        if signature == "sql-server-odbc-error":
            return "sqli:error-based:sql-server"
        if signature == "sql-server-unclosed-quote":
            return "sqli:error-based:sql-server"
        if signature == "sql-server-native-error":
            return "sqli:error-based:sql-server"
        if signature == "oracle-error":
            return "sqli:error-based:oracle"
        if signature == "sqlite-error":
            return "sqli:error-based:sqlite"
        if signature == "sqlite-query-error":
            return "sqli:error-based:sqlite"
        if signature == "jdbc-sql-error":
            return "sqli:error-based:jdbc"
        return "sqli:error-based"

    if profile == "command-injection":
        if phase == "cmd-time-probe":
            return "cmdi:time-delay"
        if signature == "unix-shell-syntax-error":
            return "cmdi:error-based:unix-shell"
        if signature == "bash-syntax-error":
            return "cmdi:error-based:bash"
        if signature == "shell-unexpected-token":
            return "cmdi:error-based:shell-unexpected-token"
        if signature == "shell-unexpected-eof":
            return "cmdi:error-based:shell-unexpected-eof"
        if signature == "shell-command-not-found":
            return "cmdi:error-based:shell-command-not-found"
        if signature == "shell-not-found":
            return "cmdi:error-based:unix-shell"
        if signature == "shell-eof-while-looking-for-matching":
            return "cmdi:error-based:quoted-shell-breakout"
        if signature == "windows-cmd-not-recognized":
            return "cmdi:error-based:windows-cmd"
        if signature == "windows-cmd-syntax-error":
            return "cmdi:error-based:windows-cmd"
        if signature == "powershell-command-not-found":
            return "cmdi:error-based:powershell"
        if signature == "powershell-not-found":
            return "cmdi:error-based:powershell"
        if signature == "unterminated-quoted-string":
            return "cmdi:error-based:quoted-string"
        if signature == "status-change":
            return "cmdi:response-diff:status-change"
        if signature == "path-change":
            return "cmdi:response-diff:path-change"
        if signature == "response-diff":
            return "cmdi:response-diff"
        return "cmdi:probe"

    if profile == "xxe":
        if phase == "xml-entity-file":
            if signature == "strong-passwd-disclosure":
                return "xxe:file-disclosure-passwd"
            if signature == "interactive-shell-passwd-disclosure":
                return "xxe:file-disclosure-passwd"
            if signature == "service-account-passwd-disclosure":
                return "xxe:file-disclosure-passwd"
            if signature == "nologin-passwd-disclosure":
                return "xxe:file-disclosure-passwd"
            if signature == "strong-win-ini-disclosure":
                return "xxe:file-disclosure-win-ini"
            if signature == "win-ini-disclosure":
                return "xxe:file-disclosure-win-ini"
            return "xxe:file-disclosure"
        if phase == "xml-parser-probe":
            if signature == "doctype-disallowed":
                return "xxe:doctype-disallowed"
            if signature == "external-entity-blocked":
                return "xxe:external-entity-blocked"
            if signature == "undefined-entity":
                return "xxe:undefined-entity"
            return "xxe:parser-error"

    if profile == "path-traversal":
        if signature == "strong-passwd-disclosure":
            return "file-disclosure:strong-passwd-disclosure"
        if signature == "interactive-shell-passwd-disclosure":
            return "file-disclosure:interactive-shell-passwd-disclosure"
        if signature == "service-account-passwd-disclosure":
            return "file-disclosure:service-account-passwd-disclosure"
        if signature == "nologin-passwd-disclosure":
            return "file-disclosure:nologin-passwd-disclosure"
        return "file-disclosure"

    if profile == "file-read":
        if signature == "strong-passwd-disclosure":
            return "file-disclosure:strong-passwd-disclosure"
        if signature == "interactive-shell-passwd-disclosure":
            return "file-disclosure:interactive-shell-passwd-disclosure"
        if signature == "service-account-passwd-disclosure":
            return "file-disclosure:service-account-passwd-disclosure"
        if signature == "nologin-passwd-disclosure":
            return "file-disclosure:nologin-passwd-disclosure"
        if signature == "strong-win-ini-disclosure":
            return "file-disclosure:strong-win-ini-disclosure"
        if signature == "win-ini-disclosure":
            return "file-disclosure:win-ini-disclosure"
        return "file-disclosure"

    if profile == "access-control":
        if signature == "protected-target-direct":
            return "protected-target-reached:direct-route"
        if signature == "protected-target-path":
            return "protected-target-reached:path-match"
        return "protected-target-reached"

    if profile == "open-redirect":
        if signature == "external-redirect":
            return "open-redirect:external-target"
        if signature == "location-header-external":
            return "open-redirect:location-header"
        return "open-redirect"

    if profile == "cors":
        if signature == "arbitrary-origin-credentialed":
            return "cors:arbitrary-origin-credentialed"
        if signature == "wildcard-origin-credentialed":
            return "cors:wildcard-origin-credentialed"
        if signature == "arbitrary-origin-preflight":
            return "cors:arbitrary-origin-preflight"
        if signature == "wildcard-origin-preflight":
            return "cors:wildcard-origin-preflight"
        if signature == "arbitrary-origin-allowed":
            return "cors:arbitrary-origin-allowed"
        if signature == "wildcard-origin-allowed":
            return "cors:wildcard-origin-allowed"
        return "cors"

    if profile == "security-headers":
        missing = (evidence_fields.get("missing") or "").lower()
        if "content-security-policy" in missing:
            return "security-headers:missing-csp"
        if "strict-transport-security" in missing:
            return "security-headers:missing-hsts"
        if "x-content-type-options" in missing:
            return "security-headers:missing-x-content-type-options"
        return "security-headers:missing"

    if profile == "clickjacking":
        if signature == "frameable-response":
            return "clickjacking:frameable"
        return "clickjacking"

    if profile == "cookie-flags":
        missing = (evidence_fields.get("missing") or "").lower()
        sensitive = (evidence_fields.get("sensitive") or "").lower() == "yes"
        if "secure" in missing and sensitive:
            return "cookie-flags:sensitive-missing-secure"
        if "httponly" in missing and sensitive:
            return "cookie-flags:sensitive-missing-httponly"
        if "samesite" in missing and sensitive:
            return "cookie-flags:sensitive-missing-samesite"
        if "secure" in missing:
            return "cookie-flags:missing-secure"
        if "httponly" in missing:
            return "cookie-flags:missing-httponly"
        if "samesite" in missing:
            return "cookie-flags:missing-samesite"
        return "cookie-flags"

    if profile == "deferred-marker":
        if signature == "text-hit":
            return "deferred-marker:text-hit"
        if signature == "url-hit":
            return "deferred-marker:url-hit"
        if signature == "header-hit":
            return "deferred-marker:header-hit"
        if signature == "markup-hit":
            return "deferred-marker:markup-hit"
        return "deferred-marker"

    if profile == "ssrf":
        if signature == "backend-fetch-attempt":
            fetch_error = (evidence_fields.get("fetch-error") or "").lower()
            if fetch_error == "connection-refused":
                return "server-side-fetch:connection-attempt"
            if fetch_error == "network-timeout":
                return "server-side-fetch:network-timeout"
            if fetch_error == "dns-resolution":
                return "server-side-fetch:dns-resolution"
            if fetch_error == "network-unreachable":
                return "server-side-fetch:network-unreachable"
            return "server-side-fetch:backend-fetch-error"
        if signature == "embedded-source-response":
            return "server-side-fetch:embedded-source-response"
        if signature == "in-scope-fetch-fingerprint":
            return "server-side-fetch:in-scope-fingerprint"
        if signature == "special-file-fetch":
            return "server-side-fetch:file-fetch"
        return "server-side-fetch"

    return ""


def extract_summary_key_value_pairs(text):
    text = (text or "").strip()
    if not text:
        return []

    matches = list(re.finditer(r"([A-Za-z0-9_-]+)=", text))
    if not matches:
        return []

    pairs = []
    for index, match in enumerate(matches):
        key = match.group(1)
        value_start = match.end()
        value_end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        value = text[value_start:value_end].strip()
        if value:
            pairs.append((key, value))

    return pairs


def summary_core_fields(result):
    profile_name = (getattr(result, "profile_name", "") or "").lower()

    if profile_name in {"security-headers", "clickjacking"}:
        return []

    fields = [("param", result.insertion_point.name)]

    if profile_name in {"deferred-marker", "xss", "reflection", "ssti", "sqli", "command-injection", "xxe", "ssrf"}:
        fields.append(("payload", result.payload))

    return fields


def summary_evidence_fields(result):
    profile_name = (getattr(result, "profile_name", "") or "").lower()
    decision = result_decision_context(result)
    evidence_pairs = extract_summary_key_value_pairs(getattr(result, "evidence", ""))
    evidence_fields = {key: value for key, value in evidence_pairs}
    diagnosis = decision["diagnosis"]

    fields = []
    if diagnosis:
        fields.append(("diagnosis", diagnosis))

    if profile_name == "deferred-marker":
        for key in ("seed_request",):
            value = evidence_fields.get(key)
            if value:
                fields.append((key, value))
        return fields

    if profile_name == "security-headers":
        for key in ("missing", "endpoint_count", "endpoint_list"):
            value = evidence_fields.get(key)
            if value:
                fields.append((key, value))
        return fields

    if profile_name == "clickjacking":
        for key in ("xfo", "frame-ancestors", "endpoint_count", "endpoint_list"):
            value = evidence_fields.get(key)
            if value:
                fields.append((key, value))
        return fields

    if profile_name == "ssrf":
        fetch_target = evidence_fields.get("target_url") or evidence_fields.get("target_label")
        if fetch_target:
            fields.append(("fetch_target", fetch_target))

        signature = evidence_fields.get("signature", "")
        if signature == "embedded-source-response":
            evidence_value = evidence_fields.get("embedded-markers", "")
            if evidence_value:
                fields.append(("evidence", evidence_value))
        elif signature == "in-scope-fetch-fingerprint":
            evidence_value = evidence_fields.get("matched-markers", "")
            if evidence_value:
                fields.append(("evidence", evidence_value))
        elif signature == "backend-fetch-attempt":
            fetch_error = evidence_fields.get("fetch-error", "")
            if fetch_error:
                fields.append(("fetch_error", fetch_error))
        elif signature == "special-file-fetch":
            for key in ("markers", "sample-users"):
                value = evidence_fields.get(key)
                if value:
                    fields.append(("evidence", value))
                    break
        return fields

    if profile_name == "reflection":
        if result.evidence:
            fields.append(("evidence", result.evidence))
        return fields

    if profile_name == "xss":
        for key in ("html-reflection", "escaped-html-reflection"):
            value = evidence_fields.get(key)
            if value:
                fields.append(("evidence", value))
                break
        context = evidence_fields.get("context")
        if context:
            fields.append(("context", context))
        return fields

    if profile_name == "ssti":
        for key in ("evaluated", "status", "confirmations"):
            value = evidence_fields.get(key)
            if value:
                fields.append((key, value))
        return fields

    if profile_name in {"sqli", "command-injection", "xxe", "file-read", "path-traversal", "access-control", "open-redirect", "cors", "cookie-flags", "ssrf"}:
        preferred_order = (
            "final_status",
            "status",
            "missing",
            "cookie",
            "observed_on",
            "baseline",
            "baseline_status",
            "target_label",
            "target_path",
            "target_route",
            "final_route",
            "final_url",
            "location",
            "allow_origin",
            "allow_credentials",
            "allow_methods",
            "markers",
            "accounts",
            "sample-users",
        )
        for key in preferred_order:
            value = evidence_fields.get(key)
            if value:
                fields.append((key, value))
        return fields

    evidence_pairs = extract_summary_key_value_pairs(getattr(result, "evidence", ""))
    if evidence_pairs:
        fields.extend(evidence_pairs)
    elif getattr(result, "evidence", ""):
        fields.append(("evidence", result.evidence))

    return fields


def append_summary_field_lines(lines, fields, use_color=True, indent="  "):
    if not fields:
        return

    width = max(len(key) for key, _ in fields)
    for key, value in fields:
        colored_key = colorize(f"{key:<{width}}", ANSI_CYAN, use_color)
        lines.append(f"{indent}{colored_key} : {value}")


def colorize(text, color, enabled=True):
    if not enabled:
        return text
    return f"{color}{text}{ANSI_RESET}"


def confidence_color(confidence):
    normalized = (confidence or "").lower()
    if normalized == "high":
        return f"{ANSI_BOLD}{ANSI_RED}"
    if normalized == "medium":
        return f"{ANSI_BOLD}{ANSI_CYAN}"
    return f"{ANSI_BOLD}{ANSI_GREEN}"


def result_decision_context(result):
    diagnosis = classify_result_diagnosis(result)
    evidence_fields = parse_evidence_fields(getattr(result, "evidence", ""))
    diagnosis_family = diagnosis.split(":", 1)[0] if diagnosis else ""
    confidence = (getattr(result, "confidence", "") or "").lower()
    signature = (evidence_fields.get("signature") or "").lower()

    return {
        "diagnosis": diagnosis,
        "diagnosis_family": diagnosis_family,
        "confidence": confidence,
        "signature": signature,
        "evidence_fields": evidence_fields,
    }


def confidence_label(confidence, use_color=True):
    normalized = (confidence or "").lower()
    if normalized == "high":
        return colorize("[HIGH]", confidence_color(normalized), use_color)
    if normalized == "medium":
        return colorize("[MEDIUM]", confidence_color(normalized), use_color)
    return colorize("[LOW]", confidence_color(normalized), use_color)


def result_priority(result):
    decision = result_decision_context(result)
    diagnosis_family = decision["diagnosis_family"]
    confidence = decision["confidence"]

    diagnosis_rank = {
        "browser-execution-alert": 5,
        "browser-execution-script": 5,
        "browser-execution-dom": 5,
        "browser-execution": 5,
        "sqli": 5,
        "cmdi": 5,
        "xxe": 5,
        "open-redirect": 5,
        "cors": 4,
        "clickjacking": 3,
        "security-headers": 2,
        "cookie-flags": 3,
        "deferred-marker": 3,
        "protected-target-reached": 5,
        "server-side-fetch": 5,
        "server-evaluation": 5,
        "file-disclosure": 5,
        "html-to-dom": 4,
        "html-reflection": 3,
        "escaped-html-reflection": 2,
        "template-error": 2,
        "input-reflection": 1,
    }
    confidence_rank = {"high": 3, "medium": 2, "low": 1}

    return (
        diagnosis_rank.get(diagnosis_family, 0),
        confidence_rank.get(confidence, 0),
    )


def aggregate_security_header_results(results):
    grouped = {}

    for result in results:
        evidence_fields = parse_evidence_fields(getattr(result, "evidence", ""))
        missing = evidence_fields.get("missing", "")
        if not missing:
            missing = "unknown"

        key = (
            result.profile_name,
            missing,
        )
        grouped.setdefault(key, []).append(result)

    aggregated = []
    for _, members in grouped.items():
        primary = members[0]
        endpoint_labels = []
        for item in members:
            endpoint_labels.append(item.request_key)

        deduped_endpoints = []
        seen = set()
        for endpoint in endpoint_labels:
            if endpoint in seen:
                continue
            seen.add(endpoint)
            deduped_endpoints.append(endpoint)

        evidence_fields = parse_evidence_fields(primary.evidence)
        evidence_parts = []
        if evidence_fields.get("final_status"):
            evidence_parts.append(f"final_status={evidence_fields['final_status']}")
        if evidence_fields.get("missing"):
            evidence_parts.append(f"missing={evidence_fields['missing']}")
        evidence_parts.append(f"endpoint_count={len(deduped_endpoints)}")
        evidence_parts.append("endpoint_list=see-aggregate-detail")
        if evidence_fields.get("signature"):
            evidence_parts.append(f"signature={evidence_fields['signature']}")

        aggregated.append(
            CheckResult(
                profile_name=primary.profile_name,
                request_key=f"{len(deduped_endpoints)} endpoint(s)",
                insertion_point=primary.insertion_point,
                payload=primary.payload,
                phase_name=primary.phase_name,
                confidence=primary.confidence,
                evidence=" ".join(evidence_parts),
                reflected=False,
                request_metadata={
                    "aggregate_member_requests": deduped_endpoints,
                },
            )
        )

    return aggregated


def aggregate_clickjacking_results(results):
    grouped = {}

    for result in results:
        evidence_fields = parse_evidence_fields(getattr(result, "evidence", ""))
        signature = evidence_fields.get("signature", "") or "unknown"
        xfo = evidence_fields.get("xfo", "") or "unknown"
        frame_ancestors = evidence_fields.get("frame-ancestors", "") or "unknown"

        key = (
            result.profile_name,
            signature,
            xfo,
            frame_ancestors,
        )
        grouped.setdefault(key, []).append(result)

    aggregated = []
    for _, members in grouped.items():
        primary = members[0]
        endpoint_labels = []
        for item in members:
            endpoint_labels.append(item.request_key)

        deduped_endpoints = []
        seen = set()
        for endpoint in endpoint_labels:
            if endpoint in seen:
                continue
            seen.add(endpoint)
            deduped_endpoints.append(endpoint)

        evidence_fields = parse_evidence_fields(primary.evidence)
        evidence_parts = []
        if evidence_fields.get("final_status"):
            evidence_parts.append(f"final_status={evidence_fields['final_status']}")
        if evidence_fields.get("xfo"):
            evidence_parts.append(f"xfo={evidence_fields['xfo']}")
        if evidence_fields.get("frame-ancestors"):
            evidence_parts.append(f"frame-ancestors={evidence_fields['frame-ancestors']}")
        evidence_parts.append(f"endpoint_count={len(deduped_endpoints)}")
        evidence_parts.append("endpoint_list=see-aggregate-detail")
        if evidence_fields.get("signature"):
            evidence_parts.append(f"signature={evidence_fields['signature']}")

        aggregated.append(
            CheckResult(
                profile_name=primary.profile_name,
                request_key=f"{len(deduped_endpoints)} endpoint(s)",
                insertion_point=primary.insertion_point,
                payload=primary.payload,
                phase_name=primary.phase_name,
                confidence=primary.confidence,
                evidence=" ".join(evidence_parts),
                reflected=False,
                request_metadata={
                    "aggregate_member_requests": deduped_endpoints,
                },
            )
        )

    return aggregated


def priority_label(result, use_color=True):
    diagnosis_score, confidence_score = result_priority(result)
    score = max(diagnosis_score, confidence_score)
    priority_color = confidence_color(getattr(result, "confidence", ""))

    if score >= 5:
        return colorize("[P1]", priority_color, use_color)
    if score >= 4:
        return colorize("[P2]", priority_color, use_color)
    if score >= 3:
        return colorize("[P3]", priority_color, use_color)
    return colorize("[P4]", priority_color, use_color)


def summarize_check_results(results):
    security_header_results = [
        result for result in results
        if (getattr(result, "profile_name", "") or "").lower() == "security-headers"
    ]
    clickjacking_results = [
        result for result in results
        if (getattr(result, "profile_name", "") or "").lower() == "clickjacking"
    ]
    non_security_header_results = [
        result for result in results
        if (getattr(result, "profile_name", "") or "").lower() not in {"security-headers", "clickjacking"}
    ]

    grouped = {}

    for result in non_security_header_results:
        key = (
            result.profile_name,
            result.request_key,
            result.insertion_point.location,
            result.insertion_point.name,
        )
        existing = grouped.get(key)
        if existing is None:
            grouped[key] = result
            continue

        result_decision = result_decision_context(result)
        existing_decision = result_decision_context(existing)
        confidence_rank = {"low": 1, "medium": 2, "high": 3}
        if confidence_rank.get(result_decision["confidence"], 0) > confidence_rank.get(existing_decision["confidence"], 0):
            grouped[key] = result
            continue

        if result_priority(result) > result_priority(existing):
            grouped[key] = result

    summarized = list(grouped.values())
    if security_header_results:
        summarized.extend(aggregate_security_header_results(security_header_results))
    if clickjacking_results:
        summarized.extend(aggregate_clickjacking_results(clickjacking_results))
    return summarized


def insertion_point_identity(request_key, insertion_point):
    return (
        request_key,
        insertion_point.location,
        insertion_point.name,
    )


def render_check_summary(results, use_color=True):
    summarized = summarize_check_results(results)
    lines = []

    title = colorize("Scan Summary", f"{ANSI_BOLD}{ANSI_WHITE}", use_color)
    lines.append(title)

    if not summarized:
        lines.append(f"{colorize('[OK]', ANSI_GREEN, use_color)} No findings detected.")
        return "\n".join(lines)

    lines.append(
        f"{colorize('[!]', ANSI_YELLOW, use_color)} Findings: {len(summarized)} "
        f"(deduplicated by profile/request/parameter)"
    )

    grouped_by_profile = {}
    for result in sorted(
        summarized,
        key=lambda item: (
            -result_priority(item)[0],
            -result_priority(item)[1],
            item.profile_name,
            item.request_key,
            item.insertion_point.location,
            item.insertion_point.name,
        ),
    ):
        grouped_by_profile.setdefault(result.profile_name, []).append(result)

    for profile_name, profile_results in grouped_by_profile.items():
        display_name = PROFILE_DISPLAY_NAMES.get(profile_name, profile_name.upper())
        lines.append("")
        lines.append(colorize(f"=== {display_name} ===", f"{ANSI_BOLD}{ANSI_YELLOW}", use_color))
        lines.append(f"findings={len(profile_results)}")

        for result in profile_results:
            lines.append("")
            lines.append(
                f"{priority_label(result, use_color)} "
                f"{confidence_label(result.confidence, use_color)} "
                f"{colorize('request', ANSI_CYAN, use_color)} {result.request_key}"
            )
            core_fields = summary_core_fields(result)
            append_summary_field_lines(lines, core_fields, use_color=use_color)

            evidence_fields = summary_evidence_fields(result)
            append_summary_field_lines(lines, evidence_fields, use_color=use_color)

    return "\n".join(lines)


def build_file_only_aggregate_detail_lines(results, request_specs=None, audit_sweep_targets=None):
    detail_lines = []
    aggregate_results = []

    for result in summarize_check_results(results):
        metadata = getattr(result, "request_metadata", {}) or {}
        aggregate_members = metadata.get("aggregate_member_requests") or []
        if not aggregate_members:
            continue
        aggregate_results.append((result, aggregate_members))

    collected_endpoint_lines = []
    collected_endpoint_seen = set()

    for target_url in sorted(audit_sweep_targets or []):
        endpoint_line = f"GET {target_url}"
        if endpoint_line in collected_endpoint_seen:
            continue
        collected_endpoint_seen.add(endpoint_line)
        collected_endpoint_lines.append(endpoint_line)

    for spec in prioritize_request_specs(request_specs or {}):
        endpoint_line = request_spec_key(spec)
        if endpoint_line in collected_endpoint_seen:
            continue
        collected_endpoint_seen.add(endpoint_line)
        collected_endpoint_lines.append(endpoint_line)

    if not aggregate_results and not collected_endpoint_lines:
        return detail_lines

    detail_lines.append("")
    detail_lines.append(f"{ANSI_BOLD}{ANSI_WHITE}=== AGGREGATE DETAIL ==={ANSI_RESET}")

    for result, aggregate_members in aggregate_results:
        evidence_fields = parse_evidence_fields(getattr(result, "evidence", ""))
        signature = evidence_fields.get("signature", "unknown")
        detail_lines.append("")
        detail_lines.append(f"{ANSI_BOLD}{ANSI_YELLOW}[profile] {result.profile_name}{ANSI_RESET}")
        detail_lines.append(f"  signature      : {signature}")
        detail_lines.append(f"  endpoint_count : {len(aggregate_members)}")
        for endpoint in aggregate_members:
            detail_lines.append(f"  endpoint       : {endpoint}")

    if collected_endpoint_lines:
        detail_lines.append("")
        detail_lines.append(f"{ANSI_BOLD}{ANSI_YELLOW}[collected-endpoints]{ANSI_RESET}")
        detail_lines.append(f"  endpoint_count : {len(collected_endpoint_lines)}")
        for endpoint_line in collected_endpoint_lines:
            detail_lines.append(f"  endpoint       : {endpoint_line}")

    return detail_lines


async def safe_page_content(page, retries=2, delay=0.3):
    last_error = None

    for attempt in range(retries + 1):
        try:
            return await page.content()
        except Exception as e:
            last_error = e
            if not is_transient_navigation_error(e) or attempt >= retries:
                raise
            logging.debug(
                "Transient page.content() retry %s/%s on %s (%s)",
                attempt + 1,
                retries,
                getattr(page, "url", "?"),
                e,
            )
            await asyncio.sleep(delay)

    raise last_error


async def run_payload_profile_checks(profile, api_context, browser_context, request_specs, args, eligible_points=None):
    results = []
    checked_specs = 0
    executed_requests = 0
    seen_mutations = set()

    for spec in prioritize_request_specs(request_specs):
        if not is_supported_check_spec(spec):
            logging.debug(
                "Check skip (unsupported request type): %s [%s]",
                request_spec_key(spec),
                spec.body_type,
            )
            continue

        checked_specs += 1
        logging.debug(
            "%s checks on %s with %s insertion point(s)",
            profile.name,
            request_spec_key(spec),
            len(prioritize_insertion_points(profile.name, spec, eligible_points=eligible_points)),
        )

        try:
            baseline_result = await fetch_request_spec_result(
                api_context,
                spec,
                args.timeout,
                browser_context=browser_context,
            )
            baseline_status = baseline_result["status"]
        except Exception as e:
            logging.warning(
                "%s baseline request failed: %s (%s)",
                profile.name,
                request_spec_key(spec),
                e,
            )
            continue

        request_profile_mutations = 0
        for insertion_point in prioritize_insertion_points(
            profile.name,
            spec,
            eligible_points=eligible_points,
        ):
            best_result = None

            for phase in profile.phases:
                phase_success = None

                for payload_template, payload_is_encoded in iter_phase_payload_variants(phase):
                    if request_profile_mutations >= DEFAULT_MAX_MUTATIONS_PER_REQUEST_PROFILE:
                        logging.warning(
                            "%s check stopped for request due to mutation safety fuse: %s",
                            profile.name,
                            request_spec_key(spec),
                        )
                        break

                    current_mutation_key = mutation_key(profile.name, insertion_point, payload_template)
                    if current_mutation_key in seen_mutations:
                        logging.debug("Check skip (duplicate mutation): %s", current_mutation_key)
                        continue
                    seen_mutations.add(current_mutation_key)

                    payload, marker, expected_outputs = instantiate_phase_payload(phase, payload_template)
                    mutated_spec = mutate_request_spec(
                        spec,
                        insertion_point,
                        payload,
                        encoded=payload_is_encoded,
                    )

                    try:
                        evidence = await evaluate_phase(
                            api_context,
                            browser_context,
                            mutated_spec,
                            phase,
                            payload,
                            expected_outputs,
                            marker,
                            args.timeout,
                            baseline_status,
                            baseline_result=baseline_result,
                        )
                    except Exception as e:
                        replay_failure_kind = ""
                        if getattr(phase, "detector", "") == "browser-event":
                            replay_failure_kind = classify_replay_failure_kind(e)
                            if replay_failure_kind:
                                remember_replay_failure(
                                    mutated_spec,
                                    "browser-submit",
                                    phase.detector,
                                    replay_failure_kind,
                                )

                        if is_non_applicable_browser_proof_error(profile.name, phase, e):
                            logging.warning(
                                "%s browser proof could not be completed with current replay method: %s | %s[%s] payload=%s (%s)",
                                profile.name,
                                request_spec_key(spec),
                                insertion_point.name,
                                insertion_point.location,
                                payload,
                                compact_exception_message(e),
                            )
                            break
                        elif replay_failure_kind:
                            logging.warning(
                                "%s replay strategy failed: %s | %s[%s] payload=%s (%s)",
                                profile.name,
                                request_spec_key(spec),
                                insertion_point.name,
                                insertion_point.location,
                                payload,
                                compact_exception_message(e),
                            )
                            break
                        else:
                            logging.warning(
                                "%s check failed: %s | %s=%s (%s)",
                                profile.name,
                                request_spec_key(spec),
                                insertion_point.name,
                                payload,
                                e,
                            )
                        continue

                    request_profile_mutations += 1
                    executed_requests += 1
                    if not evidence:
                        continue

                    phase_success = CheckResult(
                        profile_name=profile.name,
                        request_key=request_spec_key(spec),
                        insertion_point=insertion_point,
                        payload=payload,
                        phase_name=phase.name,
                        confidence=resolve_payload_result_confidence(
                            profile.name,
                            phase,
                            evidence,
                        ),
                        evidence=evidence,
                        reflected=True,
                        request_metadata=dict(spec.metadata),
                    )
                    break

                if request_profile_mutations >= DEFAULT_MAX_MUTATIONS_PER_REQUEST_PROFILE:
                    break

                if phase_success is None:
                    break

                best_result = phase_success

            if best_result is None:
                continue

            results.append(best_result)
            diagnosis = classify_result_diagnosis(best_result)
            priority = priority_label(best_result, use_color=False)
            logging.warning(
                "%s Potential %s (%s/%s): %s | %s[%s] payload=%s%s",
                priority,
                best_result.profile_name,
                best_result.phase_name,
                best_result.confidence,
                best_result.request_key,
                best_result.insertion_point.name,
                best_result.insertion_point.location,
                best_result.payload,
                f" diagnosis={diagnosis}" if diagnosis else "",
            )

    logging.info(
        "%s checks completed: checked_specs=%s executed_requests=%s findings=%s",
        profile.name,
        checked_specs,
        executed_requests,
        len(results),
    )
    return results


async def run_reflection_checks(api_context, browser_context, request_specs, args):
    if not args.check_vulnerabilities:
        return [], set()

    results = await run_payload_profile_checks(
        REFLECTION_PAYLOADS,
        api_context,
        browser_context,
        request_specs,
        args,
    )
    eligible_points = {
        insertion_point_identity(result.request_key, result.insertion_point)
        for result in results
    }
    logging.info("reflection eligible insertion points: %s", len(eligible_points))
    return results, eligible_points


async def run_xss_checks(api_context, browser_context, request_specs, args, eligible_points=None):
    if not args.check_vulnerabilities:
        return []
    if eligible_points is not None and not eligible_points:
        logging.info("xss checks skipped: no reflection-positive insertion points")
        return []
    return await run_payload_profile_checks(
        XSS_PAYLOADS,
        api_context,
        browser_context,
        request_specs,
        args,
        eligible_points=eligible_points,
    )


async def run_ssti_checks(api_context, browser_context, request_specs, args, eligible_points=None):
    if not args.check_vulnerabilities:
        return []
    if eligible_points is not None and not eligible_points:
        logging.info("ssti checks skipped: no reflection-positive insertion points")
        return []
    return await run_payload_profile_checks(
        SSTI_PAYLOADS,
        api_context,
        browser_context,
        request_specs,
        args,
        eligible_points=eligible_points,
    )


async def run_sqli_checks(api_context, browser_context, request_specs, args):
    if not args.check_vulnerabilities:
        return []

    eligible_points = set()
    for spec in request_specs.values():
        for insertion_point in extract_insertion_points(spec):
            if is_likely_sqli_insertion_point(insertion_point):
                eligible_points.add(insertion_point_identity(request_spec_key(spec), insertion_point))

    if not eligible_points:
        logging.info("sqli checks skipped: no likely database-facing insertion points")
        return []

    return await run_payload_profile_checks(
        SQLI_PAYLOADS,
        api_context,
        browser_context,
        request_specs,
        args,
        eligible_points=eligible_points,
    )


async def run_command_injection_checks(api_context, browser_context, request_specs, args):
    if not args.check_vulnerabilities:
        return []

    eligible_points = set()
    for spec in request_specs.values():
        for insertion_point in extract_insertion_points(spec):
            if is_likely_cmdi_insertion_point(insertion_point):
                eligible_points.add(insertion_point_identity(request_spec_key(spec), insertion_point))

    if not eligible_points:
        logging.info("command-injection checks skipped: no likely command-facing insertion points")
        return []

    return await run_payload_profile_checks(
        COMMAND_INJECTION_PAYLOADS,
        api_context,
        browser_context,
        request_specs,
        args,
        eligible_points=eligible_points,
    )


def normalized_markup_candidates(value):
    candidates = []
    seen = set()
    current = (value or "").strip()

    for _ in range(3):
        candidate = unescape(current).strip()
        if candidate and candidate not in seen:
            seen.add(candidate)
            candidates.append(candidate)

        decoded = unquote(current)
        if decoded == current:
            break
        current = decoded

    return candidates


def sqli_insertion_point_shape_score(insertion_point):
    name = (getattr(insertion_point, "name", "") or "").lower()
    base_value = (getattr(insertion_point, "base_value", "") or "").strip()
    lowered_value = base_value.lower()
    score = 0

    strong_name_tokens = (
        "id", "user", "username", "email", "login", "password", "pass",
        "passwd", "pwd", "search", "query",
        "filter", "sort", "order", "category", "page", "lang",
    )
    medium_name_tokens = (
        "account", "profile", "customer", "member", "name", "slug",
        "keyword", "term", "role", "group", "author",
    )

    if any(token in name for token in strong_name_tokens):
        score += 8
    if any(token in name for token in medium_name_tokens):
        score += 3

    if getattr(insertion_point, "location", "") == INSERTION_POINT_QUERY:
        score += 1
    if getattr(insertion_point, "location", "") == INSERTION_POINT_BODY:
        score += 2

    if re.fullmatch(r"\d{1,12}", base_value):
        score += 7
    elif re.fullmatch(r"[a-f0-9]{8,32}", lowered_value):
        score += 4
    elif re.fullmatch(r"[a-z0-9][a-z0-9_.@+-]{1,63}", lowered_value):
        score += 3

    if "@" in base_value and re.fullmatch(r"[^@\s]{1,64}@[^@\s]{1,255}", base_value):
        score += 2

    if 0 < len(base_value) <= 64 and re.search(r"[a-zA-Z0-9]", base_value):
        score += 1

    if len(base_value) > 120:
        score -= 6
    elif len(base_value) > 64:
        score -= 3

    if lowered_value.startswith(("http://", "https://", "file://", "dict://", "gopher://", "//")):
        score -= 8
    if is_xml_like_value(base_value):
        score -= 10
    if any(sep in base_value for sep in ("/", "\\")) and not re.fullmatch(r"[a-zA-Z0-9/_-]{1,64}", base_value):
        score -= 4
    if any(ch in base_value for ch in ("{", "}", "[", "]", "<", ">")):
        score -= 5

    return score


def is_likely_sqli_insertion_point(insertion_point):
    return sqli_insertion_point_shape_score(insertion_point) >= 6


def cmdi_insertion_point_shape_score(insertion_point):
    name = (getattr(insertion_point, "name", "") or "").lower()
    base_value = (getattr(insertion_point, "base_value", "") or "").strip()
    lowered_value = base_value.lower()
    score = 0

    strong_name_tokens = (
        "host", "hostname", "ip", "address", "domain", "dns", "ping",
        "cmd", "exec", "execute", "run", "command", "cli",
    )
    medium_name_tokens = (
        "query", "lookup", "target", "path", "file", "folder", "dir",
        "tool", "process", "program", "service",
    )

    if any(token in name for token in strong_name_tokens):
        score += 9
    if any(token in name for token in medium_name_tokens):
        score += 4

    if getattr(insertion_point, "location", "") == INSERTION_POINT_QUERY:
        score += 1
    if getattr(insertion_point, "location", "") == INSERTION_POINT_BODY:
        score += 2

    if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", base_value):
        score += 6
    elif re.fullmatch(r"[a-z0-9.-]{1,253}", lowered_value) and "." in lowered_value:
        score += 5
    elif re.fullmatch(r"[a-z0-9_-]{1,64}", lowered_value):
        score += 2

    if lowered_value.startswith(("http://", "https://", "ftp://", "file://", "dict://", "gopher://")):
        score -= 6
    if is_xml_like_value(base_value):
        score -= 10
    if any(ch in base_value for ch in ("{", "}", "[", "]", "<", ">")):
        score -= 5
    if len(base_value) > 120:
        score -= 5

    return score


def is_likely_cmdi_insertion_point(insertion_point):
    return cmdi_insertion_point_shape_score(insertion_point) >= 6


def is_xml_like_value(value):
    for candidate in normalized_markup_candidates(value):
        lowered = candidate.lower()

        if lowered.startswith(("<?xml", "<!doctype", "<soap:", "<soapenv:", "<env:envelope")):
            return True

        if "&lt;" in lowered and any(
            marker in lowered for marker in ("&lt;?xml", "&lt;!doctype", "&lt;soap:", "&lt;env:")
        ):
            return True

        if re.search(
            r"<([a-z_][a-z0-9_.:-]{0,40})(?:\s[^>]*)?>.*?</\1\s*>",
            candidate,
            flags=re.IGNORECASE | re.DOTALL,
        ):
            return True

    return False


def xxe_url_shape_score(url):
    parsed = urlparse(url or "")
    path = (parsed.path or "").lower()
    score = 0

    if path.endswith((".xml", ".wsdl", ".xsd", ".svg", ".rss", ".atom")):
        score += 6

    strong_tokens = ("soap", "saml", "xml", "wsdl", "rss", "atom", "feed")
    if any(token in path for token in strong_tokens):
        score += 4

    return score


def xxe_insertion_point_shape_score(insertion_point):
    name = (getattr(insertion_point, "name", "") or "").lower()
    base_value = (getattr(insertion_point, "base_value", "") or "").strip()
    score = 0

    xml_like_tokens = (
        "xml", "soap", "saml", "svg", "rss", "atom", "feed",
        "document", "envelope", "assertion", "metadata",
    )
    generic_tokens = ("request", "payload", "data", "body")

    if any(token in name for token in xml_like_tokens):
        score += 8
    if any(token in name for token in generic_tokens):
        score += 2
    if is_xml_like_value(base_value):
        score += 10
    if base_value.strip().startswith(("<?xml", "<", "%3c", "%3C", "&lt;")):
        score += 3

    return score


def xxe_request_shape_score(spec):
    if spec is None:
        return 0

    score = xxe_url_shape_score(getattr(spec, "url", ""))
    body_type = getattr(spec, "body_type", "")
    params = list(getattr(spec, "params", []) or [])

    if body_type != BODY_TYPE_QUERY:
        score += 3
    if body_type == BODY_TYPE_TEXT:
        score += 4

    param_scores = []
    has_body_xml_value = False
    for param in params:
        insertion_point = InsertionPoint(
            request_key=request_spec_key(spec),
            name=param.name,
            location=param.location,
            base_value=param.value,
        )
        current_score = xxe_insertion_point_shape_score(insertion_point)
        param_scores.append(current_score)
        if insertion_point.location == INSERTION_POINT_BODY and is_xml_like_value(insertion_point.base_value):
            has_body_xml_value = True

    if param_scores:
        score += max(param_scores)

    if has_body_xml_value:
        score += 4

    return score


def is_likely_xxe_insertion_point(insertion_point):
    return xxe_insertion_point_shape_score(insertion_point) >= 8


async def run_xxe_checks(api_context, browser_context, request_specs, args):
    if not args.check_vulnerabilities:
        return []

    eligible_points = set()
    for spec in request_specs.values():
        if xxe_request_shape_score(spec) < 10:
            logging.debug("xxe request skipped: request-shape score too low: %s", request_spec_key(spec))
            continue
        for insertion_point in extract_insertion_points(spec):
            if is_likely_xxe_insertion_point(insertion_point):
                eligible_points.add(insertion_point_identity(request_spec_key(spec), insertion_point))

    if not eligible_points:
        logging.info("xxe checks skipped: no xml-like insertion points")
        return []

    return await run_payload_profile_checks(
        XXE_PAYLOADS,
        api_context,
        browser_context,
        request_specs,
        args,
        eligible_points=eligible_points,
    )


async def run_path_traversal_checks(api_context, browser_context, request_specs, args):
    if not args.check_vulnerabilities:
        return []

    eligible_points = build_policy_eligible_points("path-traversal", request_specs, minimum_priority=8)
    if not eligible_points:
        logging.info("path-traversal checks skipped: no path-like insertion points")
        return []

    targets = build_path_traversal_targets()
    return await run_target_reachability_checks(
        "path-traversal",
        targets,
        api_context,
        browser_context,
        request_specs,
        args,
        evidence_builder=build_path_traversal_evidence,
        phase_name="file-disclosure",
        confidence="high",
        eligible_points=eligible_points,
    )


def build_path_traversal_evidence(target, response_result, baseline_result=None):
    evidence = find_passwd_disclosure_evidence(response_result.get("text") or "")
    if not evidence:
        return ""

    return " ".join(
        [
            f"target_kind={target.kind}",
            f"target_label={target.label}",
            f"target_path={target.metadata.get('target_path', target.value)}",
            evidence,
        ]
    )


async def run_file_read_checks(api_context, browser_context, request_specs, args):
    if not args.check_vulnerabilities:
        return []

    eligible_points = build_policy_eligible_points("file-read", request_specs, minimum_priority=8)
    if not eligible_points:
        logging.info("file-read checks skipped: no file-like insertion points")
        return []

    targets = build_file_read_targets()
    return await run_target_reachability_checks(
        "file-read",
        targets,
        api_context,
        browser_context,
        request_specs,
        args,
        evidence_builder=build_file_read_evidence,
        phase_name="file-read",
        confidence="high",
        include_baseline=True,
        eligible_points=eligible_points,
    )


def build_file_read_evidence(target, response_result, baseline_result=None):
    text = response_result.get("text") or ""
    evidence = find_passwd_disclosure_evidence(text)
    if not evidence:
        evidence = find_win_ini_disclosure_evidence(text)
    if not evidence:
        return ""

    baseline_text = (baseline_result or {}).get("text") or ""
    if evidence == find_passwd_disclosure_evidence(baseline_text):
        return ""
    if evidence == find_win_ini_disclosure_evidence(baseline_text):
        return ""

    return " ".join(
        [
            f"target_kind={target.kind}",
            f"target_label={target.label}",
            f"target_path={target.metadata.get('target_path', target.value)}",
            evidence,
        ]
    )


def build_access_control_evidence(target, response_result, baseline_result=None):
    final_url = response_result["url"]
    final_status = response_result["status"]
    final_route = protected_target_route(final_url)
    final_path = protected_target_path(final_url)
    target_route = target.metadata.get("route", target.value)
    target_path = target.metadata.get("path") or protected_target_path(target.metadata.get("url", ""))

    if final_status >= 400:
        return ""

    signature = ""
    if final_route == target_route:
        signature = "protected-target-direct"
    elif target_path and final_path == target_path:
        signature = "protected-target-path"
    else:
        return ""

    return " ".join(
        [
            f"baseline={target.baseline_status}",
            f"target_kind={target.kind}",
            f"target_label={target.label}",
            f"target_route={target_route}",
            f"final_status={final_status}",
            f"final_route={final_route}",
            f"signature={signature}",
        ]
    )


def is_likely_open_redirect_insertion_point(insertion_point):
    name = (getattr(insertion_point, "name", "") or "").lower()
    base_value = (getattr(insertion_point, "base_value", "") or "").lower()

    redirect_like_tokens = (
        "url",
        "uri",
        "redirect",
        "next",
        "return",
        "continue",
        "dest",
        "destination",
        "target",
        "to",
        "out",
    )
    if any(token in name for token in redirect_like_tokens):
        return True

    if base_value.startswith(("http://", "https://", "//")):
        return True

    return False


def build_policy_eligible_points(profile_name, request_specs, minimum_priority=1):
    eligible_points = set()

    for spec in request_specs.values():
        request_key = request_spec_key(spec)
        for insertion_point in extract_insertion_points(spec):
            if insertion_point_priority(profile_name, insertion_point) < minimum_priority:
                continue
            eligible_points.add(insertion_point_identity(request_key, insertion_point))

    return eligible_points


def resolve_open_redirect_result_confidence(target, evidence, default_confidence):
    base_confidence = (target.metadata.get("confidence") or default_confidence or "low").lower()
    evidence_fields = parse_evidence_fields(evidence)
    signature = (evidence_fields.get("signature") or "").lower()
    variant_strength = (target.metadata.get("variant_strength") or "").lower()

    if signature == "external-redirect":
        if variant_strength == "absolute":
            return "high"
        if variant_strength == "scheme-relative":
            return "medium"

    if signature == "location-header-external":
        if variant_strength == "absolute":
            return "medium"
        if variant_strength == "scheme-relative":
            return "low"

    return base_confidence


def build_open_redirect_evidence(target, response_result, baseline_result=None):
    final_url = (response_result.get("url") or "").strip()
    final_status = response_result.get("status", 0)
    headers = response_result.get("headers") or {}
    location_header = (headers.get("location") or headers.get("Location") or "").strip()
    baseline_url = (baseline_result or {}).get("url", "")
    baseline_headers = (baseline_result or {}).get("headers") or {}
    baseline_location = (baseline_headers.get("location") or baseline_headers.get("Location") or "").strip()

    if not final_url:
        return ""

    try:
        final_parsed = urlparse(final_url)
        baseline_parsed = urlparse(baseline_url) if baseline_url else None
    except Exception:
        return ""

    target_host = (target.metadata.get("redirect_host") or "").lower()
    final_host = (final_parsed.hostname or "").lower()
    baseline_host = (baseline_parsed.hostname or "").lower() if baseline_parsed is not None else ""
    if target_host and final_host == target_host and final_url != baseline_url and final_host != baseline_host:
        return " ".join(
            [
                f"baseline={target.baseline_status}",
                f"target_kind={target.kind}",
                f"target_label={target.label}",
                f"target_url={target.value}",
                f"baseline_status_before_mutation={(baseline_result or {}).get('status', '?')}",
                f"final_status={final_status}",
                f"baseline_url={baseline_url or '-'}",
                f"final_url={final_url}",
                "signature=external-redirect",
            ]
        )

    if location_header:
        try:
            location_parsed = urlparse(location_header)
            location_host = (location_parsed.hostname or "").lower()
        except Exception:
            location_host = ""
        baseline_location_host = ""
        if baseline_location:
            try:
                baseline_location_host = (urlparse(baseline_location).hostname or "").lower()
            except Exception:
                baseline_location_host = ""
        if target_host and location_host == target_host and location_host != baseline_location_host:
            return " ".join(
                [
                    f"baseline={target.baseline_status}",
                    f"target_kind={target.kind}",
                    f"target_label={target.label}",
                    f"target_url={target.value}",
                    f"baseline_status_before_mutation={(baseline_result or {}).get('status', '?')}",
                    f"final_status={final_status}",
                    f"baseline_url={baseline_url or '-'}",
                    f"final_url={final_url}",
                    f"location={location_header}",
                    "signature=location-header-external",
                ]
            )

    return ""


def build_ssrf_evidence(target, response_result, baseline_result=None):
    text = response_result.get("text") or ""
    if response_result["status"] >= 400 or not text:
        return ""

    raw_payload_present = target.value in text or unescape(target.value) in unescape(text)
    if raw_payload_present:
        return ""

    markers = [part.strip() for part in (target.metadata.get("fingerprint") or "").split("||") if part.strip()]
    matched = []
    lowered_text = unescape(text).lower()
    baseline_text = ""
    visible_response_text = normalize_ssrf_visible_text(text).lower()
    baseline_visible_text = ""
    if baseline_result is not None:
        baseline_text = unescape(baseline_result.get("text") or "").lower()
        baseline_visible_text = normalize_ssrf_visible_text(baseline_result.get("text") or "").lower()
    required_marker_matches = max(1, int(target.metadata.get("required_marker_matches", 2)))
    special_type = target.metadata.get("special_type", "")
    error_signature = infer_ssrf_error_signature(text, target.value)
    baseline_error_signature = infer_ssrf_error_signature(
        (baseline_result or {}).get("text") or "",
        target.value,
    )

    if special_type == "file-passwd":
        passwd_evidence = find_passwd_disclosure_evidence(text)
        baseline_passwd_evidence = find_passwd_disclosure_evidence(baseline_result.get("text") or "") if baseline_result else ""
        if passwd_evidence and not baseline_passwd_evidence:
            return " ".join(
                [
                    f"baseline={target.baseline_status}",
                    f"target_kind={target.kind}",
                    f"target_label={target.label}",
                    f"target_url={target.value}",
                    f"fingerprint_strength={target.metadata.get('fingerprint_strength', 'unknown')}",
                    f"baseline_status_before_mutation={(baseline_result or {}).get('status', '?')}",
                    f"final_status={response_result['status']}",
                    passwd_evidence,
                    "signature=special-file-fetch",
                ]
            )

    if error_signature and error_signature != baseline_error_signature:
        return " ".join(
            [
                f"baseline={target.baseline_status}",
                f"target_kind={target.kind}",
                f"target_label={target.label}",
                f"target_url={target.value}",
                f"fingerprint_strength={target.metadata.get('fingerprint_strength', 'unknown')}",
                f"baseline_status_before_mutation={(baseline_result or {}).get('status', '?')}",
                f"final_status={response_result['status']}",
                f"fetch-error={error_signature}",
                "signature=backend-fetch-attempt",
            ]
        )

    for marker in markers:
        lowered_marker = marker.lower()
        if lowered_marker in lowered_text and lowered_marker not in baseline_text:
            matched.append(marker)

    embedded_markers = [
        part.strip()
        for part in (target.metadata.get("embedded_markers") or "").split("||")
        if part.strip()
    ]
    embedded_matches = []
    for marker in embedded_markers:
        lowered_marker = marker.lower()
        if lowered_marker in visible_response_text and lowered_marker not in baseline_visible_text:
            embedded_matches.append(marker)

    if len(matched) >= required_marker_matches:
        return " ".join(
            [
                f"baseline={target.baseline_status}",
                f"target_kind={target.kind}",
                f"target_label={target.label}",
                f"target_url={target.value}",
                f"fingerprint_strength={target.metadata.get('fingerprint_strength', 'unknown')}",
                f"baseline_status_before_mutation={(baseline_result or {}).get('status', '?')}",
                f"final_status={response_result['status']}",
                f"matched-marker-count={len(matched)}",
                f"matched-markers={','.join(matched[:3])}",
                "signature=in-scope-fetch-fingerprint",
            ]
        )

    if not embedded_matches:
        return ""

    return " ".join(
        [
            f"baseline={target.baseline_status}",
            f"target_kind={target.kind}",
            f"target_label={target.label}",
            f"target_url={target.value}",
            f"fingerprint_strength={target.metadata.get('fingerprint_strength', 'unknown')}",
            f"baseline_status_before_mutation={(baseline_result or {}).get('status', '?')}",
            f"final_status={response_result['status']}",
            f"embedded-marker-count={len(embedded_matches)}",
            f"embedded-markers={','.join(embedded_matches[:2])}",
            "signature=embedded-source-response",
        ]
    )


def resolve_ssrf_result_confidence(target, evidence, default_confidence):
    base_confidence = (target.metadata.get("confidence") or default_confidence or "low").lower()
    evidence_fields = parse_evidence_fields(evidence)
    signature = (evidence_fields.get("signature") or "").lower()

    if signature == "backend-fetch-attempt":
        if target.kind == TARGET_KIND_SSRF_SPECIAL:
            special_type = target.metadata.get("special_type", "")
            if special_type in {"metadata", "loopback-http", "dict-redis", "gopher-http"}:
                return "medium"
        return base_confidence

    if target.kind != TARGET_KIND_SSRF_SPECIAL:
        return base_confidence

    if signature == "special-file-fetch":
        return "high"

    strongest_match_count = 0
    for key in ("matched-marker-count", "embedded-marker-count"):
        value = evidence_fields.get(key)
        if value and value.isdigit():
            strongest_match_count = max(strongest_match_count, int(value))

    special_type = target.metadata.get("special_type", "")
    if special_type == "metadata":
        return "high" if strongest_match_count >= 2 else "medium"
    if special_type == "loopback-http":
        return "medium" if strongest_match_count >= 2 else "low"
    if special_type in {"dict-redis", "gopher-http"}:
        return "medium" if strongest_match_count >= 2 else "low"

    return base_confidence


def resolve_target_confidence(profile_name, target, evidence, default_confidence):
    base_confidence = target.metadata.get("confidence", default_confidence)
    if (profile_name or "").lower() == "ssrf":
        return resolve_ssrf_result_confidence(target, evidence, base_confidence)
    if (profile_name or "").lower() == "open-redirect":
        return resolve_open_redirect_result_confidence(target, evidence, base_confidence)
    return base_confidence


async def run_target_reachability_checks(
    profile_name,
    targets,
    api_context,
    browser_context,
    request_specs,
    args,
    evidence_builder,
    phase_name="target-reachability",
    confidence="high",
    include_baseline=False,
    eligible_points=None,
    spec_filter=None,
):
    if not args.check_vulnerabilities or not targets:
        return []

    results = []
    checked_specs = 0
    executed_requests = 0
    ordered_targets = prioritize_targets(profile_name, targets)
    concurrency = clamp_check_concurrency(
        getattr(args, "reachability_check_concurrency", DEFAULT_REACHABILITY_CHECK_CONCURRENCY)
    )
    semaphore = asyncio.Semaphore(concurrency)

    logging.info("%s checks using %s reachability target(s)", profile_name, len(ordered_targets))

    candidate_specs = []
    for spec in prioritize_request_specs(request_specs):
        if not is_supported_check_spec(spec):
            continue
        if spec_filter is not None and not spec_filter(spec):
            logging.debug(
                "%s check skipped due to request spec trust policy: %s",
                profile_name,
                request_spec_key(spec),
            )
            continue
        candidate_specs.append(spec)

    async def _check_single_spec(spec):
        async with semaphore:
            local_results = []
            local_executed_requests = 0
            seen_mutations = set()
            baseline_result = None

            if include_baseline:
                try:
                    baseline_result = await fetch_request_spec_result(
                        api_context,
                        spec,
                        args.timeout,
                        browser_context=browser_context,
                    )
                except Exception as e:
                    return {
                        "checked_specs": 1,
                        "executed_requests": 0,
                        "results": [],
                        "baseline_error": e,
                        "spec": spec,
                    }

            for insertion_point in prioritize_insertion_points(
                profile_name,
                spec,
                eligible_points=eligible_points,
            ):
                result = None

                for target in ordered_targets:
                    for payload, payload_is_encoded in build_reachability_payload_variants(target):
                        current_mutation_key = mutation_key(profile_name, insertion_point, payload)
                        if current_mutation_key in seen_mutations:
                            continue
                        seen_mutations.add(current_mutation_key)

                        mutated_spec = mutate_request_spec(
                            spec,
                            insertion_point,
                            payload,
                            encoded=payload_is_encoded,
                        )
                        try:
                            response_result = await fetch_request_spec_result(
                                api_context,
                                mutated_spec,
                                args.timeout,
                                browser_context=browser_context,
                            )
                        except Exception as e:
                            logging.warning(
                                "%s check failed: %s | %s=%s (%s)",
                                profile_name,
                                request_spec_key(spec),
                                insertion_point.name,
                                payload,
                                e,
                            )
                            continue

                        local_executed_requests += 1
                        evidence = evidence_builder(target, response_result, baseline_result=baseline_result)
                        if not evidence:
                            continue

                        result = CheckResult(
                            profile_name=profile_name,
                            request_key=request_spec_key(spec),
                            insertion_point=insertion_point,
                            payload=payload,
                            phase_name=phase_name,
                            confidence=resolve_target_confidence(
                                profile_name,
                                target,
                                evidence,
                                confidence,
                            ),
                            evidence=evidence,
                            reflected=False,
                            request_metadata=dict(spec.metadata),
                        )
                        break

                    if result is not None:
                        break

                if result is None:
                    continue

                local_results.append(result)

            return {
                "checked_specs": 1,
                "executed_requests": local_executed_requests,
                "results": local_results,
                "baseline_error": None,
                "spec": spec,
            }

    spec_batches = await asyncio.gather(*(_check_single_spec(spec) for spec in candidate_specs))

    for spec_batch in spec_batches:
        checked_specs += spec_batch["checked_specs"]
        executed_requests += spec_batch["executed_requests"]

        if spec_batch["baseline_error"] is not None:
            logging.warning(
                "%s baseline request failed: %s (%s)",
                profile_name,
                request_spec_key(spec_batch["spec"]),
                spec_batch["baseline_error"],
            )
            continue

        for result in spec_batch["results"]:
            results.append(result)
            diagnosis = classify_result_diagnosis(result)
            priority = priority_label(result, use_color=False)
            logging.warning(
                "%s Potential %s (%s/%s): %s | %s[%s] payload=%s%s",
                priority,
                result.profile_name,
                result.phase_name,
                result.confidence,
                result.request_key,
                result.insertion_point.name,
                result.insertion_point.location,
                result.payload,
                f" diagnosis={diagnosis}" if diagnosis else "",
            )

    logging.info(
        "%s checks completed: checked_specs=%s executed_requests=%s findings=%s",
        profile_name,
        checked_specs,
        executed_requests,
        len(results),
    )
    return results


async def run_access_control_checks(api_context, browser_context, protected_targets, request_specs, args):
    if not args.check_vulnerabilities or not protected_targets:
        return []

    targets = build_reachability_targets_from_protected(protected_targets)
    return await run_target_reachability_checks(
        "access-control",
        targets,
        api_context,
        browser_context,
        request_specs,
        args,
        evidence_builder=build_access_control_evidence,
        phase_name="target-reachability",
        confidence="high",
    )

async def run_deferred_marker_seed_checks(api_context, browser_context, request_specs, args):
    if not args.check_vulnerabilities:
        return []

    seeds = []
    executed_requests = 0
    seen_seed_points = set()

    for spec in prioritize_request_specs(request_specs):
        if not is_supported_check_spec(spec):
            continue

        for insertion_point in prioritize_deferred_marker_points(spec):
            point_identity = insertion_point_identity(request_spec_key(spec), insertion_point)
            if point_identity in seen_seed_points:
                continue
            if len(seeds) >= DEFAULT_MAX_DEFERRED_MARKER_SEEDS:
                logging.info("deferred marker seed limit reached: %s", DEFAULT_MAX_DEFERRED_MARKER_SEEDS)
                logging.info(
                    "deferred marker seeding completed: executed_requests=%s seeds=%s",
                    executed_requests,
                    len(seeds),
                )
                return seeds

            seen_seed_points.add(point_identity)
            token = build_payload_token()
            payload = deferred_marker_payload(token)
            mutated_spec = mutate_request_spec(spec, insertion_point, payload, encoded=False)
            try:
                await fetch_request_spec_result(
                    api_context,
                    mutated_spec,
                    args.timeout,
                    browser_context=browser_context,
                )
            except Exception as e:
                logging.warning(
                    "deferred marker seed failed: %s | %s[%s] (%s)",
                    request_spec_key(spec),
                    insertion_point.name,
                    insertion_point.location,
                    e,
                )
                continue

            executed_requests += 1
            seeds.append(
                DeferredMarkerSeed(
                    token=token,
                    request_key=request_spec_key(spec),
                    param_name=insertion_point.name,
                    param_location=insertion_point.location,
                    target_url=resolve_request_spec_target(spec),
                )
            )

    logging.info(
        "deferred marker seeding completed: executed_requests=%s seeds=%s",
        executed_requests,
        len(seeds),
    )
    return seeds


async def run_final_audit_sweep(browser_context, audit_sweep_targets, request_specs, deferred_marker_seeds, args):
    if not args.check_vulnerabilities:
        return []

    targets = set(audit_sweep_targets or set())
    for spec in prioritize_request_specs(request_specs):
        register_audit_sweep_target(targets, resolve_request_spec_target(spec), args)
        register_audit_sweep_target(targets, spec.url, args)
        metadata = getattr(spec, "metadata", {}) or {}
        register_audit_sweep_target(targets, metadata.get("page_url", ""), args)
        register_audit_sweep_target(targets, metadata.get("source_url", ""), args)

    ordered_targets = sorted(targets)
    results = []
    executed_requests = 0
    concurrency = clamp_check_concurrency(
        getattr(args, "audit_sweep_concurrency", DEFAULT_AUDIT_SWEEP_CONCURRENCY)
    )
    semaphore = asyncio.Semaphore(concurrency)

    async def _audit_single_target(target_url):
        async with semaphore:
            try:
                response_result = await fetch_url_result_in_browser(
                    browser_context,
                    target_url,
                    args.timeout,
                )
            except Exception as e:
                return {
                    "target_url": target_url,
                    "error": e,
                    "response_result": None,
                    "result_items": [],
                }

            target_results = []
            security_headers_evidence = build_security_headers_evidence(response_result)
            if security_headers_evidence:
                target_results.append(
                    CheckResult(
                        profile_name="security-headers",
                        request_key=f"GET {target_url}",
                        insertion_point=InsertionPoint(
                            request_key=f"GET {target_url}",
                            name="response-headers",
                            location=INSERTION_POINT_HEADER,
                            base_value="",
                        ),
                        payload="response-headers",
                        phase_name="security-headers",
                        confidence="low",
                        evidence=security_headers_evidence,
                        reflected=False,
                        request_metadata={"source_url": target_url},
                    )
                )

            clickjacking_evidence = build_clickjacking_evidence(response_result)
            if clickjacking_evidence:
                target_results.append(
                    CheckResult(
                        profile_name="clickjacking",
                        request_key=f"GET {target_url}",
                        insertion_point=InsertionPoint(
                            request_key=f"GET {target_url}",
                            name="response-headers",
                            location=INSERTION_POINT_HEADER,
                            base_value="",
                        ),
                        payload="frame-protection",
                        phase_name="frame-policy",
                        confidence="medium",
                        evidence=clickjacking_evidence,
                        reflected=False,
                        request_metadata={"source_url": target_url},
                    )
                )

            target_results.extend(build_cookie_flag_findings_for_target(target_url, response_result))
            target_results.extend(build_deferred_marker_results_for_response(response_result, deferred_marker_seeds, target_url))
            return {
                "target_url": target_url,
                "error": None,
                "response_result": response_result,
                "result_items": target_results,
            }

    audit_batches = await asyncio.gather(*(_audit_single_target(target_url) for target_url in ordered_targets))

    for audit_batch in audit_batches:
        if audit_batch["error"] is not None:
            logging.warning("final audit sweep failed: %s (%s)", audit_batch["target_url"], audit_batch["error"])
            continue

        executed_requests += 1
        results.extend(audit_batch["result_items"])

    logging.info(
        "final audit sweep completed: checked_targets=%s executed_requests=%s findings=%s",
        len(ordered_targets),
        executed_requests,
        len(results),
    )
    return results


async def run_cors_checks(api_context, browser_context, request_specs, args):
    if not args.check_vulnerabilities:
        return []

    results = []
    checked_specs = 0
    executed_requests = 0
    probe_origin = DEFAULT_CORS_TEST_ORIGIN

    for spec in prioritize_request_specs(request_specs):
        if not is_supported_check_spec(spec):
            continue
        if not is_request_spec_trusted_for_profile(spec, "cors"):
            logging.debug(
                "cors check skipped due to request spec trust policy: %s",
                request_spec_key(spec),
            )
            continue

        checked_specs += 1
        request_key = request_spec_key(spec)
        insertion_point = InsertionPoint(
            request_key=request_key,
            name="Origin",
            location=INSERTION_POINT_HEADER,
            base_value="",
        )

        result = None
        for probe_kind in ("actual", "preflight"):
            if probe_kind == "preflight" and spec.method == "GET":
                continue

            try:
                response_result = await fetch_cors_probe_result_in_browser(
                    browser_context,
                    spec,
                    args.timeout,
                    probe_origin,
                    preflight=(probe_kind == "preflight"),
                )
            except Exception as e:
                logging.warning(
                    "cors check failed: %s | %s (%s)",
                    request_key,
                    probe_kind,
                    e,
                )
                continue

            executed_requests += 1
            evidence = build_cors_evidence(response_result, probe_origin, probe_kind)
            if not evidence:
                continue

            result = CheckResult(
                profile_name="cors",
                request_key=request_key,
                insertion_point=insertion_point,
                payload=probe_origin,
                phase_name=probe_kind,
                confidence=resolve_cors_result_confidence(evidence),
                evidence=evidence,
                reflected=False,
                request_metadata=dict(spec.metadata),
            )
            break

        if result is None:
            continue

        results.append(result)
        diagnosis = classify_result_diagnosis(result)
        priority = priority_label(result, use_color=False)
        logging.warning(
            "%s Potential %s (%s/%s): %s | %s[%s] payload=%s%s",
            priority,
            result.profile_name,
            result.phase_name,
            result.confidence,
            result.request_key,
            result.insertion_point.name,
            result.insertion_point.location,
            result.payload,
            f" diagnosis={diagnosis}" if diagnosis else "",
        )

    logging.info(
        "cors checks completed: checked_specs=%s executed_requests=%s findings=%s",
        checked_specs,
        executed_requests,
        len(results),
    )
    return results


async def run_open_redirect_checks(api_context, browser_context, request_specs, args):
    if not args.check_vulnerabilities:
        return []

    eligible_points = set()
    for spec in request_specs.values():
        for insertion_point in extract_insertion_points(spec):
            if is_likely_open_redirect_insertion_point(insertion_point):
                eligible_points.add(insertion_point_identity(request_spec_key(spec), insertion_point))

    if not eligible_points:
        logging.info("open-redirect checks skipped: no redirect-like insertion points")
        return []

    targets = build_open_redirect_targets()
    return await run_target_reachability_checks(
        "open-redirect",
        targets,
        api_context,
        browser_context,
        request_specs,
        args,
        evidence_builder=build_open_redirect_evidence,
        phase_name="target-reachability",
        confidence="high",
        include_baseline=True,
        eligible_points=eligible_points,
        spec_filter=lambda spec: is_request_spec_trusted_for_profile(spec, "open-redirect"),
    )


async def run_ssrf_checks(api_context, browser_context, request_specs, seed_urls, args):
    if not args.check_vulnerabilities:
        return []

    trusted_request_specs = filter_request_specs_for_profile(request_specs, "ssrf")
    if not trusted_request_specs:
        logging.info("ssrf checks skipped: no trusted request specs for SSRF policy")
        return []

    eligible_points = set()
    for spec in trusted_request_specs.values():
        for insertion_point in extract_insertion_points(spec):
            if is_likely_ssrf_insertion_point(insertion_point):
                eligible_points.add(insertion_point_identity(request_spec_key(spec), insertion_point))

    if not eligible_points:
        logging.info("ssrf checks skipped: no URL-like insertion points")
        return []

    targets = await build_ssrf_targets_from_request_specs(api_context, trusted_request_specs, seed_urls, args)
    targets.extend(build_ssrf_special_targets())
    targets = targets[: max(0, DEFAULT_MAX_REACHABILITY_TARGETS + 4)]
    if not targets:
        logging.info("ssrf checks skipped: no usable in-scope target fingerprints")
        return []

    return await run_target_reachability_checks(
        "ssrf",
        targets,
        api_context,
        browser_context,
        trusted_request_specs,
        args,
        evidence_builder=build_ssrf_evidence,
        phase_name="target-fetch",
        confidence="high",
        include_baseline=True,
        eligible_points=eligible_points,
    )


async def run_vulnerability_checks(browser_context, request_specs, protected_targets, seed_urls, audit_sweep_targets, args):
    all_results = []
    args.browser_context = browser_context

    reflection_results, eligible_points = await run_reflection_checks(
        None,
        browser_context,
        request_specs,
        args,
    )
    all_results.extend(reflection_results)
    all_results.extend(
        await run_xss_checks(
            None,
            browser_context,
            request_specs,
            args,
            eligible_points=eligible_points,
        )
    )
    all_results.extend(
        await run_ssti_checks(
            None,
            browser_context,
            request_specs,
            args,
            eligible_points=eligible_points,
        )
    )
    deferred_marker_seeds = await run_deferred_marker_seed_checks(
        None,
        browser_context,
        request_specs,
        args,
    )
    all_results.extend(await run_sqli_checks(None, browser_context, request_specs, args))
    all_results.extend(await run_command_injection_checks(None, browser_context, request_specs, args))
    all_results.extend(await run_xxe_checks(None, browser_context, request_specs, args))
    all_results.extend(await run_path_traversal_checks(None, browser_context, request_specs, args))
    all_results.extend(await run_file_read_checks(None, browser_context, request_specs, args))
    all_results.extend(await run_open_redirect_checks(None, browser_context, request_specs, args))
    all_results.extend(await run_cors_checks(None, browser_context, request_specs, args))
    all_results.extend(await run_ssrf_checks(None, browser_context, request_specs, seed_urls, args))
    all_results.extend(await run_access_control_checks(None, browser_context, protected_targets, request_specs, args))
    all_results.extend(
        await run_final_audit_sweep(
            browser_context,
            audit_sweep_targets,
            request_specs,
            deferred_marker_seeds,
            args,
        )
    )

    logging.info("\n%s", render_check_summary(all_results, use_color=True))
    for detail_line in build_file_only_aggregate_detail_lines(
        all_results,
        request_specs=request_specs,
        audit_sweep_targets=audit_sweep_targets,
    ):
        logging.info(detail_line, extra={"file_only_detail": True})
    return all_results


async def discover_forms(page, page_url):
    return await page.evaluate(
        """
        (baseUrl) => {
            const forms = [];

            for (const [formIndex, form] of Array.from(document.forms).entries()) {
                let action = baseUrl;
                try {
                    action = new URL(form.getAttribute('action') || baseUrl, baseUrl).href;
                } catch (e) {
                    action = baseUrl;
                }

                const method = (form.getAttribute('method') || 'get').toLowerCase();
                const enctype = (
                    form.getAttribute('enctype') || 'application/x-www-form-urlencoded'
                ).toLowerCase();

                const fields = [];
                const submitters = [];

                for (const el of Array.from(form.elements)) {
                    if (!el || !el.name || el.disabled) {
                        continue;
                    }

                    const tag = (el.tagName || '').toLowerCase();
                    const type = ((el.getAttribute('type') || '') + '').toLowerCase();

                    if (type === 'reset' || type === 'file') {
                        continue;
                    }

                    if (
                        type === 'submit' ||
                        (tag === 'button' && (!type || type === 'submit'))
                    ) {
                        submitters.push({
                            name: el.name,
                            value: el.value || el.innerText || '',
                            id: el.getAttribute('id') || '',
                            text: (el.innerText || el.value || '').replace(/\\s+/g, ' ').trim().slice(0, 80),
                        });
                        continue;
                    }

                    if (type === 'button' || type === 'image') {
                        continue;
                    }

                    let mode = 'payload';
                    let value = '';

                    if (type === 'hidden') {
                        mode = 'preserve';
                        value = el.value || '';
                    } else if (tag === 'select') {
                        mode = 'preserve';
                        if (el.multiple) {
                            value = Array.from(el.selectedOptions || []).map(opt => opt.value);
                        } else {
                            value = el.value || (el.options.length ? el.options[0].value : '');
                        }
                    } else if (type === 'checkbox') {
                        if (!el.checked && el.name) {
                            continue;
                        }
                        mode = 'preserve';
                        value = el.value || 'on';
                    } else if (type === 'radio') {
                        if (!el.checked) {
                            continue;
                        }
                        mode = 'preserve';
                        value = el.value || 'on';
                    }

                    fields.push({
                        name: el.name,
                        tag,
                        type,
                        multiple: Boolean(tag === 'select' && el.multiple),
                        mode,
                        value,
                        placeholder: (el.getAttribute('placeholder') || '').trim().slice(0, 120),
                        pattern: (el.getAttribute('pattern') || '').trim().slice(0, 120),
                        inputmode: (el.getAttribute('inputmode') || '').trim().slice(0, 40).toLowerCase(),
                        autocomplete: (el.getAttribute('autocomplete') || '').trim().slice(0, 80).toLowerCase(),
                        label_hint: (() => {
                            const label = (
                                (el.labels && el.labels.length ? Array.from(el.labels).map(node => node.textContent || '').join(' ') : '') ||
                                el.getAttribute('aria-label') ||
                                el.getAttribute('title') ||
                                ''
                            );
                            return label.replace(/\\s+/g, ' ').trim().slice(0, 120);
                        })(),
                        options: tag === 'select'
                            ? Array.from(el.options || []).slice(0, 20).map(opt => ({
                                value: opt.value || '',
                                label: (opt.textContent || '').replace(/\\s+/g, ' ').trim().slice(0, 120),
                                selected: Boolean(opt.selected),
                            }))
                            : [],
                    });
                }

                if (fields.length) {
                    forms.push({ dom_index: formIndex, action, method, enctype, fields, submitters });
                }
            }

            return forms;
        }
        """,
        page_url,
    )


async def discover_active_actions(page, page_url):
    return await page.evaluate(
        """
        () => {
            const actions = [];
            const seen = new Set();
            let seq = 0;

            const nodes = Array.from(
                document.querySelectorAll(
                    'a, button, input[type="button"], input[type="submit"], input[type="image"], [onclick], [role="button"]'
                )
            );

            for (const el of nodes) {
                if (!el || typeof el.getAttribute !== 'function') {
                    continue;
                }

                const tag = (el.tagName || '').toLowerCase();
                const type = ((el.getAttribute('type') || '') + '').toLowerCase();
                const href = (el.getAttribute('href') || '').trim();
                const onclick = (el.getAttribute('onclick') || '').trim();
                const role = (el.getAttribute('role') || '').toLowerCase();
                const name = (el.getAttribute('name') || '').trim();
                const elementId = (el.getAttribute('id') || '').trim();
                const text = (
                    el.innerText ||
                    el.value ||
                    el.getAttribute('aria-label') ||
                    el.getAttribute('title') ||
                    ''
                ).replace(/\\s+/g, ' ').trim().slice(0, 80);

                if (el.disabled) {
                    continue;
                }

                if (!el.getClientRects || el.getClientRects().length === 0) {
                    continue;
                }

                if (el.closest('form') && (
                    tag === 'button' ||
                    (tag === 'input' && ['submit', 'image'].includes(type))
                )) {
                    continue;
                }

                const isJsAction =
                    Boolean(onclick) ||
                    href.startsWith('javascript:') ||
                    href === '#' ||
                    role === 'button' ||
                    tag === 'button' ||
                    (tag === 'input' && ['button', 'submit', 'image'].includes(type));

                if (!isJsAction) {
                    continue;
                }

                const signature = [tag, type, name, elementId, href, onclick, text].join('|');
                if (seen.has(signature)) {
                    continue;
                }
                seen.add(signature);

                const actionId = `bober-action-${seq++}`;
                el.setAttribute('data-bober-action-id', actionId);

                actions.push({
                    action_id: actionId,
                    tag,
                    type,
                    name,
                    id: elementId,
                    href,
                    onclick,
                    text,
                });
            }

            return actions;
        }
        """,
    )


async def submit_active_form(context, page_url, form, args, request_specs=None, max_request_specs=None):
    entries = build_active_form_entries(form["fields"])
    method = (form.get("method") or "get").lower()
    enctype = (form.get("enctype") or "application/x-www-form-urlencoded").lower()
    action = form["action"]
    form_metadata = {"page_url": page_url}
    form_metadata.update(form.get("variant_metadata") or {})
    initial_spec = build_request_spec(
        method=method,
        url=action,
        enctype=enctype,
        entries=entries,
        origin="form-preview",
        metadata=form_metadata,
    )

    logging.info(
        "Active form submit: %s %s (enctype=%s, fields=%s)",
        method.upper(),
        action,
        enctype,
        len(entries),
    )
    logging.debug("Active form preview: %s", request_spec_preview(initial_spec))
    logging.debug("Active form insertion points: %s", len(extract_insertion_points(initial_spec)))
    logging.debug("Replay target (active-form): %s", request_spec_preview(initial_spec))
    if request_specs is not None:
        if request_spec_limit_reached(request_specs, max_request_specs):
            logging.debug("Active form skipped due to request spec limit: %s", action)
            return []
        register_request_spec(request_specs, initial_spec, max_specs=max_request_specs)
    submit_page = await context.new_page()
    submit_page.set_default_navigation_timeout(args.timeout)
    request_urls = set()
    response_urls = set()
    emitted_form_request = False

    def _on_request(req):
        nonlocal emitted_form_request
        try:
            logging.debug(
                "Active form browser request: %s [%s] %s",
                req.method,
                req.resource_type,
                req.url,
            )
        except Exception:
            pass

        try:
            request_method = (req.method or "").upper()
            request_url = req.url
            if request_method == method.upper() and request_url.startswith(action):
                emitted_form_request = True
        except Exception:
            pass

        if req.resource_type in {"document", "fetch", "xhr"}:
            request_urls.add(req.url)

    def _on_request_failed(req):
        failure = ""
        try:
            failure = req.failure or ""
        except Exception:
            pass

        resource_type = getattr(req, "resource_type", "unknown")
        if is_benign_request_failure(resource_type, failure):
            logging.debug(
                "Active form browser request aborted: %s [%s] %s (%s)",
                getattr(req, "method", "?"),
                resource_type,
                getattr(req, "url", "?"),
                failure,
            )
        else:
            logging.warning(
                "Active form browser request failed: %s [%s] %s (%s)",
                getattr(req, "method", "?"),
                resource_type,
                getattr(req, "url", "?"),
                failure,
            )

    def _on_response(resp):
        try:
            response_urls.update(extract_response_header_urls(resp))
        except Exception:
            return

    submit_page.on("request", _on_request)
    submit_page.on("requestfailed", _on_request_failed)
    submit_page.on("response", _on_response)

    try:
        await navigate_page(submit_page, page_url, args.timeout)
        submit_forms = await discover_forms(submit_page, page_url)
        target_form = next(
            (candidate for candidate in submit_forms if candidate.get("dom_index") == form.get("dom_index")),
            None,
        )
        if not target_form:
            logging.warning("Active form target no longer available on %s", page_url)
            return []

        logging.debug("Active form browser submit from: %s", submit_page.url)

        submitter = form.get("submitter") or {}
        submitter_name = submitter.get("name") or ""
        submitter_id = submitter.get("id") or ""
        submitter_text = submitter.get("text") or ""

        async def _submit_form():
            return await submit_page.evaluate(
            """
            ({ formIndex, entries, submitterName, submitterId, submitterText }) => {
                const form = Array.from(document.forms)[formIndex];
                if (!form) {
                    throw new Error('Form not found');
                }

                const grouped = new Map();
                for (const [name, value] of entries) {
                    if (!grouped.has(name)) {
                        grouped.set(name, []);
                    }
                    grouped.get(name).push(value);
                }

                for (const el of Array.from(form.elements)) {
                    if (!el || !el.name || el.disabled) {
                        continue;
                    }

                    const values = grouped.get(el.name);
                    if (!values || !values.length) {
                        continue;
                    }

                    const tag = (el.tagName || '').toLowerCase();
                    const type = ((el.getAttribute('type') || '') + '').toLowerCase();

                    if (type === 'checkbox') {
                        el.checked = values.includes(el.value || 'on');
                    } else if (type === 'radio') {
                        el.checked = values.includes(el.value || 'on');
                    } else if (tag === 'select' && el.multiple) {
                        const wanted = new Set(values.map(String));
                        for (const opt of Array.from(el.options || [])) {
                            opt.selected = wanted.has(opt.value);
                        }
                    } else {
                        el.value = values[values.length - 1];
                    }

                    el.dispatchEvent(new Event('input', { bubbles: true }));
                    el.dispatchEvent(new Event('change', { bubbles: true }));
                }

                let submitter = null;
                if (submitterId) {
                    submitter = form.querySelector(`#${CSS.escape(submitterId)}`);
                }

                if (!submitter && submitterName) {
                    submitter = form.querySelector(`[name="${CSS.escape(submitterName)}"]`);
                }

                if (!submitter && submitterText) {
                    submitter = Array.from(
                        form.querySelectorAll('button, input[type="submit"], input[type="image"]')
                    ).find(el => {
                        const text = (el.innerText || el.value || '').replace(/\\s+/g, ' ').trim();
                        return text === submitterText;
                    }) || null;
                }

                if (!submitter) {
                    submitter = form.querySelector('button[type="submit"], input[type="submit"], input[type="image"]');
                }

                let previewEntries = [];
                try {
                    const formData = submitter && typeof FormData === 'function'
                        ? new FormData(form, submitter)
                        : new FormData(form);
                    previewEntries = Array.from(formData.entries()).map(([name, value]) => [name, String(value)]);
                } catch (e) {
                    previewEntries = [];
                }

                // Avoid named form controls (for example name="action") shadowing
                // HTMLFormElement properties during browser-side replay.
                const replayForm = document.createElement('form');
                const rawMethod = (form.getAttribute('method') || 'get').toLowerCase();
                const rawAction = form.getAttribute('action') || window.location.href;
                const rawEnctype = form.getAttribute('enctype') || '';

                replayForm.method = rawMethod;
                replayForm.action = rawAction;
                if (rawEnctype) {
                    replayForm.enctype = rawEnctype;
                }
                replayForm.style.display = 'none';

                for (const [name, value] of previewEntries) {
                    const hidden = document.createElement('input');
                    hidden.type = 'hidden';
                    hidden.name = name;
                    hidden.value = value;
                    replayForm.appendChild(hidden);
                }

                document.body.appendChild(replayForm);
                HTMLFormElement.prototype.submit.call(replayForm);

                return previewEntries;
            }
            """,
            {
                "formIndex": form["dom_index"],
                "entries": entries,
                "submitterName": submitter_name,
                "submitterId": submitter_id,
                "submitterText": submitter_text,
            },
        )

        browser_entries = await _submit_form()
        if browser_entries:
            browser_metadata = {"page_url": page_url}
            browser_metadata.update(form.get("variant_metadata") or {})
            browser_spec = build_request_spec(
                method=method,
                url=action,
                enctype=enctype,
                entries=browser_entries,
                origin="browser-formdata",
                metadata=browser_metadata,
            )
            logging.debug(
                "Active form browser payload preview: %s",
                request_spec_preview(browser_spec),
            )
            if request_specs is not None:
                register_request_spec(request_specs, browser_spec, max_specs=max_request_specs)
        await asyncio.sleep(ACTIVE_ACTION_WAIT)
    except Exception as e:
        logging.warning("Active form failed: %s %s (%s)", method.upper(), action, e)
        await submit_page.close()
        return []
    finally:
        try:
            submit_page.remove_listener("request", _on_request)
        except Exception:
            pass
        try:
            submit_page.remove_listener("requestfailed", _on_request_failed)
        except Exception:
            pass
        try:
            submit_page.remove_listener("response", _on_response)
        except Exception:
            pass

    response_url = submit_page.url
    logging.debug("Active form browser result: %s", response_url)
    state_transition = classify_state_transition(page_url, response_url, has_cookie=bool(args.cookie))
    if state_transition:
        logging.debug(
            "State transition (active-form): %s -> %s [%s]",
            page_url,
            response_url,
            state_transition,
        )
    if not emitted_form_request:
        logging.warning("Active form browser did not emit matching %s request to %s", method.upper(), action)

    discovered = set()
    discovered.add(response_url)
    discovered.update(request_urls)
    discovered.update(response_urls)

    try:
        body = await safe_page_content(submit_page)
    except Exception:
        body = ""

    if body:
        for u, _ in extract_url_candidates(body, response_url):
            discovered.add(u)

    await submit_page.close()
    return list(discovered)


async def process_active_forms(page, page_url, args, submitted_forms, request_specs=None, max_request_specs=None):
    forms = await discover_forms(page, page_url)
    if not forms:
        return []

    logging.info("Active mode: discovered %s form(s) on %s", len(forms), page_url)

    discovered_urls = []
    context = page.context

    for form in forms:
        for form_variant in expand_form_submit_variants(form):
            if request_specs is not None and request_spec_limit_reached(request_specs, max_request_specs):
                return discovered_urls
            signature = build_active_form_signature(page_url, form_variant)
            if signature in submitted_forms:
                continue
            submitted_forms.add(signature)

            for discovered_url in await submit_active_form(
                context,
                page_url,
                form_variant,
                args,
                request_specs=request_specs,
                max_request_specs=max_request_specs,
            ):
                discovered_urls.append(discovered_url)

    return discovered_urls


async def trigger_active_action(context, page_url, action, args):
    action_page = await context.new_page()
    action_page.set_default_navigation_timeout(args.timeout)
    request_urls = set()
    response_urls = set()

    def _on_request(req):
        if req.resource_type in {"document", "fetch", "xhr"}:
            request_urls.add(req.url)

    def _on_response(resp):
        try:
            response_urls.update(extract_response_header_urls(resp))
        except Exception:
            return

    action_page.on("request", _on_request)
    action_page.on("response", _on_response)

    try:
        await navigate_page(action_page, page_url, args.timeout)
        actions = await discover_active_actions(action_page, page_url)
        target = next((item for item in actions if item.get("action_id") == action.get("action_id")), None)
        if not target:
            logging.debug("Active action target no longer available on %s", page_url)
            return []

        logging.debug(
            "Active action trigger: %s %s",
            target.get("tag", "element"),
            target.get("text") or target.get("href") or target.get("id") or target.get("name") or "<unnamed>",
        )
        logging.debug(
            "Replay target (active-action): page=%s href=%s onclick=%s",
            page_url,
            shorten_debug_value(target.get("href", "")),
            shorten_debug_value(target.get("onclick", "")),
        )

        locator = action_page.locator(f'[data-bober-action-id="{target["action_id"]}"]').first
        await locator.scroll_into_view_if_needed()

        try:
            await locator.click(timeout=args.timeout, force=True)
        except Exception:
            await locator.evaluate("(el) => el.click()")

        await asyncio.sleep(ACTIVE_ACTION_WAIT)

        state_transition = classify_state_transition(page_url, action_page.url, has_cookie=bool(args.cookie))
        if state_transition:
            logging.debug(
                "State transition (active-action): %s -> %s [%s]",
                page_url,
                action_page.url,
                state_transition,
            )

        discovered = set(request_urls)
        discovered.update(response_urls)
        discovered.add(action_page.url)

        try:
            html = await action_page.content()
        except Exception:
            html = ""

        if html:
            for u, _ in extract_url_candidates(html, action_page.url):
                discovered.add(u)

        return list(discovered)
    except Exception as e:
        logging.warning("Active action failed on %s (%s)", page_url, e)
        return []
    finally:
        try:
            action_page.remove_listener("request", _on_request)
        except Exception:
            pass
        try:
            action_page.remove_listener("response", _on_response)
        except Exception:
            pass
        await action_page.close()


async def process_active_actions(page, page_url, args, triggered_actions):
    actions = await discover_active_actions(page, page_url)
    if not actions:
        return []

    logging.info("Active mode: discovered %s JS action(s) on %s", len(actions), page_url)

    discovered_urls = []
    context = page.context

    for action in actions:
        signature = build_active_action_signature(page_url, action)
        if signature in triggered_actions:
            continue
        triggered_actions.add(signature)

        for discovered_url in await trigger_active_action(context, page_url, action, args):
            skip_candidate, skip_reason = should_skip_active_action_candidate(discovered_url, page_url)
            if skip_candidate:
                logging.debug(
                    "Active action candidate skipped (%s): %s",
                    skip_reason,
                    discovered_url,
                )
                continue
            discovered_urls.append(discovered_url)

    return discovered_urls


# ---------------- STATE TOKEN GUARD ----------------

def exceeds_state_token_limit(url, tokens, max_repeat):
    if not tokens:
        return False

    try:
        p = urlparse(url)
    except Exception:
        return False

    path_parts = [x for x in p.path.lower().split("/") if x]

    query_parts = []
    for param in p.query.split("&"):
        if "=" in param:
            _, v = param.split("=", 1)
            decoded = unquote(v).lower()
            for part in re.split(r"[\/;]", decoded):
                if part:
                    query_parts.append(part)

    for token in tokens:
        if path_parts.count(token) + query_parts.count(token) > max_repeat:
            return True

    return False


# ---------------- RECURSIVE TRAP GUARD ----------------

def is_recursive_trap(
    url,
    max_param_len=DEFAULT_MAX_PARAM_LEN,
    max_repeat_segments=DEFAULT_MAX_REPEAT_SEGMENTS,
):
    try:
        parsed = urlparse(url)
    except Exception:
        return False

    if not parsed.query:
        return False

    for param in parsed.query.split("&"):
        if "=" not in param:
            continue

        _, value = param.split("=", 1)
        decoded = unquote(value)

        if len(decoded) > max_param_len:
            return True

        parts = [p for p in decoded.split("/") if p]
        for seg in set(parts):
            if parts.count(seg) >= max_repeat_segments:
                return True

        if parsed.path:
            path_clean = parsed.path.strip("/")
            if path_clean and path_clean in decoded:
                return True

    return False


# ---------------- MAIN CRAWLER ----------------

async def crawl(args):
    visited = set()
    queue = []
    candidate_sources = {}
    discovery_telemetry = {}
    submitted_forms = set()
    triggered_actions = set()
    collected_request_specs = {}
    protected_targets = {}
    ssrf_seed_urls = set()
    audit_sweep_targets = set()

    proxy = None
    if not args.no_proxy:
        proxy = {"server": args.proxy}

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=True, proxy=proxy)

        headers = {"User-Agent": USER_AGENT}
        if args.cookie:
            headers["Cookie"] = args.cookie

        ctx = await browser.new_context(
            ignore_https_errors=True,
            extra_http_headers=headers
        )

        page = await ctx.new_page()
        page.set_default_navigation_timeout(args.timeout)

        ws_seen = False
        capture_navigation_headers = False
        navigation_header_urls = set()

        def _on_ws(ws):
            nonlocal ws_seen
            ws_seen = True
            logging.debug("WebSocket opened: %s", ws.url)

        def _on_response(resp):
            nonlocal navigation_header_urls
            if not capture_navigation_headers:
                return

            try:
                for header_url in extract_response_header_urls(resp):
                    navigation_header_urls.add(header_url)
            except Exception:
                return

        page.on("websocket", _on_ws)
        page.on("response", _on_response)

        seed_urls = await prime_queue_from_seed_files(page, args)
        for seed_url in seed_urls:
            enqueue_candidate_url(
                queue,
                seed_url,
                args,
                source="seed",
                candidate_sources=candidate_sources,
                telemetry=discovery_telemetry,
            )
        enqueue_candidate_url(
            queue,
            args.start_url,
            args,
            source="start-url",
            candidate_sources=candidate_sources,
            telemetry=discovery_telemetry,
        )


        while queue and len(collected_request_specs) < args.max_pages:
            ws_seen = False
            url = queue.pop(0)

            if not in_scope(url, args.scope):
                continue
            if is_excluded(url, args.exclude_paths):
                continue
            if exceeds_max_depth(url, args.max_depth):
                continue
            if is_probably_non_html_asset(url):
                continue
            if is_recursive_trap(url):
                continue
            if exceeds_state_token_limit(url, args.state_tokens, args.state_max_repeat):
                continue

            key = smart_key(url, args.query_agnostic_paths)
            if key in visited:
                logging.debug("Queue suppress (already-visited): %s [key=%s]", url, key)
                continue

            logging.info("Visiting: %s", url)
            candidate_source_types = candidate_source_summary(candidate_sources, url)
            candidate_trust_score = candidate_source_score(candidate_source_types)
            query_spec = build_query_request_spec(
                url,
                origin="crawl-url",
                metadata={
                    "source_url": url,
                    "candidate_sources": candidate_source_types,
                    "candidate_source_trust": "high" if candidate_trust_score >= PROMOTABLE_QUERY_SOURCE_SCORE else "low",
                    "candidate_source_score": str(candidate_trust_score),
                },
                telemetry=discovery_telemetry,
            )
            if query_spec is None and urlparse(url).query:
                logging.debug(
                    "Query URL not promoted to request spec due to validation guard: %s (sources=%s score=%s)",
                    url,
                    ",".join(candidate_source_types) or "unknown",
                    candidate_trust_score,
                )

            try:
                navigation_header_urls = set()
                capture_navigation_headers = True
                response = await navigate_page(page, url, args.timeout)
                capture_navigation_headers = False

                if args.ws_aware:
                    try:
                        # adjunk időt a WS initre
                        await asyncio.sleep(1.0)
                    except Exception:
                        pass

                if args.ws_aware and ws_seen:
                    logging.debug("WS-aware: WS seen, waiting for DOM settle")

                    try:
                        await page.wait_for_function(
                            "() => document.body && document.body.innerText.length > 300",
                            timeout=6000
                        )
                    except Exception:
                        await asyncio.sleep(1.0)

                html = await safe_page_content(page)
                resolved_page_url = (page.url or "").strip()
                if not resolved_page_url and response is not None:
                    resolved_page_url = (response.url or "").strip()
                if not resolved_page_url:
                    resolved_page_url = url
                if resolved_page_url != url:
                    logging.debug("Resolved page URL: %s -> %s", url, resolved_page_url)
                register_audit_sweep_target(audit_sweep_targets, resolved_page_url, args)
                state_transition = classify_state_transition(url, resolved_page_url, has_cookie=bool(args.cookie))
                if state_transition:
                    logging.debug(
                        "State transition (crawl): %s -> %s [%s]",
                        url,
                        resolved_page_url,
                        state_transition,
                    )
                register_request_spec(
                    collected_request_specs,
                    query_spec,
                    max_specs=args.max_pages,
                )
                if request_spec_limit_reached(collected_request_specs, args.max_pages):
                    visited.add(key)
                    break

            except Exception as e:
                capture_navigation_headers = False
                for header_url in navigation_header_urls:
                    enqueue_candidate_url(
                        queue,
                        header_url,
                        args,
                        source="header",
                        candidate_sources=candidate_sources,
                        telemetry=discovery_telemetry,
                    )
                if navigation_header_urls:
                    logging.debug(
                        "Preserved %s header-derived target(s) after navigation failure: %s",
                        len(navigation_header_urls),
                        url,
                    )
                if is_transient_navigation_error(e):
                    logging.debug("Transient navigation/content race: %s (%s)", url, e)
                else:
                    logging.warning("Failed: %s (%s)", url, e)
                visited.add(key)
                continue

            for header_url in navigation_header_urls:
                enqueue_candidate_url(
                    queue,
                    header_url,
                    args,
                    source="header",
                    candidate_sources=candidate_sources,
                    telemetry=discovery_telemetry,
                )

            if response is not None:
                ssrf_seed_urls.add(response.url)
                register_audit_sweep_target(audit_sweep_targets, response.url, args)
                try:
                    register_protected_target(protected_targets, response.url, response.status)
                except Exception:
                    pass
                for header_url in extract_response_header_urls(response):
                    enqueue_candidate_url(
                        queue,
                        header_url,
                        args,
                        source="header",
                        candidate_sources=candidate_sources,
                        telemetry=discovery_telemetry,
                    )
            else:
                ssrf_seed_urls.add(url)

            if args.active_mode:
                for active_url in await process_active_forms(
                    page,
                    resolved_page_url,
                    args,
                    submitted_forms,
                    request_specs=collected_request_specs,
                    max_request_specs=args.max_pages,
                ):
                    enqueue_candidate_url(
                        queue,
                        active_url,
                        args,
                        source="active-form",
                        candidate_sources=candidate_sources,
                        telemetry=discovery_telemetry,
                    )
                if request_spec_limit_reached(collected_request_specs, args.max_pages):
                    visited.add(key)
                    break
                for active_url in await process_active_actions(page, resolved_page_url, args, triggered_actions):
                    enqueue_candidate_url(
                        queue,
                        active_url,
                        args,
                        source="active-action",
                        candidate_sources=candidate_sources,
                        telemetry=discovery_telemetry,
                    )

            for u, source_type in extract_url_candidates(html, resolved_page_url, telemetry=discovery_telemetry):
                enqueue_candidate_url(
                    queue,
                    u,
                    args,
                    source=f"content-{source_type}",
                    candidate_sources=candidate_sources,
                    telemetry=discovery_telemetry,
                )

                if args.wp_expand:
                    for wp_u in wp_expand(u):
                        enqueue_candidate_url(
                            queue,
                            wp_u,
                            args,
                            source="wp-expand",
                            candidate_sources=candidate_sources,
                            telemetry=discovery_telemetry,
                        )

            visited.add(key)
            await asyncio.sleep(args.delay)

        if len(collected_request_specs) >= args.max_pages:
            logging.info(
                "Collected request spec limit reached: %s/%s",
                len(collected_request_specs),
                args.max_pages,
            )
        if collected_request_specs:
            logging.info("Collected request specs: %s", len(collected_request_specs))
        if protected_targets:
            logging.info("Protected target candidates: %s", len(protected_targets))
        for telemetry_line in format_telemetry_summary_lines(discovery_telemetry):
            logging.info("%s", telemetry_line)
        if args.check_vulnerabilities:
            await run_vulnerability_checks(
                ctx,
                collected_request_specs,
                protected_targets,
                ssrf_seed_urls,
                audit_sweep_targets,
                args,
            )

        await browser.close()


# ---------------- CLI ----------------

def print_examples():
    print("""
==========================
BoberCrawler – Examples
==========================

1) Basic in-scope crawl
-----------------------
bober-crawler --start-url "https://example.com/" --scope "https://example.com" --no-proxy


2) Crawl behind non-default Burp proxy
--------------------------------------
bober-crawler --start-url "https://example.com/" --scope "https://example.com" --proxy 127.0.0.1:9090


3) Authenticated area crawl with cookies
----------------------------------------
bober-crawler --start-url "https://example.com/account" --scope "https://example.com" --cookie "sessionid=abc123; csrftoken=xyz" --exclude-paths "/logout,/cdn,/static"


4) JavaScript / WebSocket-heavy app
-----------------------------------
bober-crawler --start-url "https://example.com/app" --scope "https://example.com" --ws-aware --delay 0.25 --max-pages 150


5) WordPress / state-aware crawl
--------------------------------
bober-crawler --start-url "https://wp-site.example" --scope "https://wp-site.example" --wp-expand --state-tokens "embed,feed,rss2" --state-max-repeat 1 --query-agnostic-paths "/search,/shop" --exclude-paths "/wp-admin,/wp-login.php"


6) Full vulnerability workflow
------------------------------
bober-crawler --start-url "https://target.example/" --scope "https://target.example" --check-vulnerabilities --proxy 127.0.0.1:9090


7) Authenticated vulnerability assessment with tuned concurrency
----------------------------------------------------------------
bober-crawler --start-url "https://example.com/app" --scope "https://example.com" --cookie "session=abc123" --check-vulnerabilities --audit-sweep-concurrency 3 --reachability-check-concurrency 5 --delay 0.2


8) Focused crawl with custom seeds and stricter limits
------------------------------------------------------
bober-crawler --start-url "https://example.com/docs" --scope "https://example.com/docs" --seed-json-file ".\\results.json" --max-depth 3 --max-pages 120 --exclude-paths "/logout,/admin" --query-agnostic-paths "/search"

==========================
""".strip())


def normalize_log_mode(raw_value):
    normalized = (raw_value or "").strip().lower()
    if normalized not in LOG_MODE_ALIASES:
        valid = ", ".join(sorted(LOG_MODE_ALIASES))
        raise ValueError(f"Unsupported --debug-level value: {raw_value} (expected one of: {valid})")
    return LOG_MODE_ALIASES[normalized]


def configure_logging(log_file, log_mode):
    root_logger = logging.getLogger()
    root_logger.handlers.clear()
    root_logger.setLevel(logging.DEBUG)

    if log_mode == LOG_MODE_CLEAN:
        formatter = CleanLogFormatter()
        filter_obj = CleanLogFilter()
        handler_level = logging.INFO
    elif log_mode == LOG_MODE_DEBUG:
        formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
        filter_obj = None
        handler_level = logging.DEBUG
    else:
        formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
        filter_obj = None
        handler_level = logging.INFO

    file_handler = logging.FileHandler(log_file, encoding="utf-8")
    stream_handler = logging.StreamHandler(sys.stdout)
    detail_file_handler = logging.FileHandler(log_file, encoding="utf-8")

    for handler in (file_handler, stream_handler):
        handler.setLevel(handler_level)
        handler.setFormatter(formatter)
        handler.addFilter(ExcludeFileOnlyDetailFilter())
        if filter_obj is not None:
            handler.addFilter(filter_obj)
        root_logger.addHandler(handler)

    detail_file_handler.setLevel(logging.INFO)
    detail_file_handler.setFormatter(logging.Formatter("%(message)s"))
    detail_file_handler.addFilter(FileOnlyDetailFilter())
    root_logger.addHandler(detail_file_handler)


def main():
    try:
        ensure_browser()

        ap = argparse.ArgumentParser(
            description="Burp-friendly Playwright crawler",
            formatter_class=argparse.ArgumentDefaultsHelpFormatter,
            add_help=True
        )

        REQUIRED = " (REQUIRED)"

        # --- optional example flag ---
        ap.add_argument("--example", action="store_true",
                        help="Show usage examples and exit")

        # --- add all other arguments WITHOUT required=True ---
        ap.add_argument("--start-url", help="Starting URL" + REQUIRED)
        ap.add_argument("--scope", help="Scope URL (protocol+host+path)" + REQUIRED)
        ap.add_argument(
            "--proxy",
            default=DEFAULT_PROXY_SERVER,
            help="Proxy server as host:port or scheme://host:port",
        )
        ap.add_argument("--no-proxy", action="store_true", help="Disable proxy entirely")
        ap.add_argument("--cookie")
        ap.add_argument("--exclude-paths", default="", help="Comma-separated path prefixes to skip")
        ap.add_argument("--query-agnostic-paths", default="", help="Paths where query string is ignored")
        ap.add_argument("--state-tokens", default="", help="Limits recursion caused by repeating tokens")
        ap.add_argument("--state-max-repeat", type=int, default=2, help="Max allowed repeats of same state")
        ap.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help="Navigation timeout in ms")
        ap.add_argument("--delay", type=float, default=DEFAULT_DELAY, help="Delay between requests (seconds)")
        ap.add_argument(
            "--max-pages",
            type=int,
            default=DEFAULT_MAX_PAGES,
            help="Maximum collected request specs/endpoints to gather before stopping",
        )
        ap.add_argument("--max-depth", type=int, default=DEFAULT_MAX_DEPTH, help="Maximum allowed URL path depth")
        ap.add_argument("--seed-json-file", help="Optional JSON file with seed URLs from results[].url")
        ap.add_argument("--active-mode", action="store_true", help="Submit discovered HTML forms with test payloads")
        ap.add_argument("--check-vulnerabilities", action="store_true", help="Run the full vulnerability checking workflow on collected inputs")
        ap.add_argument(
            "--audit-sweep-concurrency",
            type=int,
            default=DEFAULT_AUDIT_SWEEP_CONCURRENCY,
            help=f"Parallelism for final audit sweep checks (clamped to 1-{MAX_CHECK_CONCURRENCY})",
        )
        ap.add_argument(
            "--reachability-check-concurrency",
            type=int,
            default=DEFAULT_REACHABILITY_CHECK_CONCURRENCY,
            help=f"Parallelism for reachability checks (clamped to 1-{MAX_CHECK_CONCURRENCY})",
        )
        ap.add_argument(
            "--debug-level",
            default=LOG_MODE_NORMAL,
            help="Logging output mode: clean|normal|debug (aliases: 1|2|3, low|medium|high)",
        )
        ap.add_argument("--wp-expand", action="store_true", help="Expand WordPress endpoints")
        ap.add_argument("--ws-aware", action="store_true", help="Wait for WebSocket-gated content before extraction")

        # --- first parse ---
        args = ap.parse_args()

        # --- example handling ---
        if args.example:
            print_examples()
            sys.exit(0)

        # --- now check manually that required args exist ---
        required_args = ["start_url", "scope"]
        missing = [a for a in required_args if getattr(args, a) is None]
        if missing:
            ap.error(f"Missing required arguments: {', '.join(missing)}")

        # --- normalize args ---
        args.scope = parse_scope(args.scope)
        args.exclude_paths = [p.strip() for p in args.exclude_paths.split(",") if p.strip()]
        args.query_agnostic_paths = [p.rstrip("/") for p in args.query_agnostic_paths.split(",") if p.strip()]
        args.state_tokens = [t.strip().lower() for t in args.state_tokens.split(",") if t.strip()]
        if args.max_depth < 0:
            ap.error("--max-depth must be 0 or greater")
        if args.max_pages < 1:
            ap.error("--max-pages must be 1 or greater")
        if not args.no_proxy:
            try:
                args.proxy = normalize_proxy_server(args.proxy)
            except ValueError as e:
                ap.error(f"Unsupported --proxy value: {e}")
        concurrency_adjustments = []
        for attr_name, flag_name in (
            ("audit_sweep_concurrency", "--audit-sweep-concurrency"),
            ("reachability_check_concurrency", "--reachability-check-concurrency"),
        ):
            raw_value = getattr(args, attr_name)
            clamped_value = clamp_check_concurrency(raw_value)
            if clamped_value != raw_value:
                concurrency_adjustments.append((flag_name, raw_value, clamped_value))
            setattr(args, attr_name, clamped_value)
        try:
            args.debug_level = normalize_log_mode(args.debug_level)
        except ValueError as e:
            ap.error(str(e))
        if args.check_vulnerabilities:
            args.active_mode = True

        # --- logging setup ---
        log_file = build_log_filename(args.start_url)
        configure_logging(log_file, args.debug_level)

        logging.info("Log file: %s", log_file)
        if args.debug_level != LOG_MODE_CLEAN:
            logging.info("Start URL: %s | Scope: %s://%s%s",
                        args.start_url, args.scope["scheme"], args.scope["host"], args.scope["path"])
            for flag_name, raw_value, clamped_value in concurrency_adjustments:
                logging.warning(
                    "%s adjusted from %s to safe limit %s",
                    flag_name,
                    raw_value,
                    clamped_value,
                )
            if args.check_vulnerabilities:
                logging.info(
                    "Vulnerability checking enabled: active form discovery forced on, mutation safety fuse per request/profile=%s",
                    DEFAULT_MAX_MUTATIONS_PER_REQUEST_PROFILE,
                )

        asyncio.run(crawl(args))

    except KeyboardInterrupt:
        print("\n[INTERRUPT] Execution interrupted by user. Exiting...\n")
        sys.exit(0)

if __name__ == "__main__":
    main()
