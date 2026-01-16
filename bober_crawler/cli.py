#!/usr/bin/env python3
import asyncio
import argparse
import logging
import re
import sys
import os
from html import unescape
from urllib.parse import urljoin, urlparse, unquote

from playwright.async_api import async_playwright
from playwright.sync_api import sync_playwright

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

LOG_FILE = "bobercrawler.log"
DEFAULT_TIMEOUT = 15000
DEFAULT_DELAY = 0.15
DEFAULT_MAX_PAGES = 1000

# recursive trap defaults
DEFAULT_MAX_PARAM_LEN = 200
DEFAULT_MAX_REPEAT_SEGMENTS = 3

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36"
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
        logging.StreamHandler(sys.stdout),
    ],
)

# ---------------- HELPERS ----------------

def parse_scope(scope_url):
    p = urlparse(scope_url)
    return {
        "scheme": p.scheme,
        "host": p.hostname,
        "path": p.path.rstrip("/") or "/"
    }


def in_scope(url, scope):
    try:
        p = urlparse(url)
    except Exception:
        return False

    if p.scheme != scope["scheme"]:
        return False

    if p.hostname != scope["host"]:
        return False

    path = p.path or "/"
    return path.startswith(scope["path"])


def is_excluded(url, excluded):
    try:
        path = urlparse(url).path or "/"
    except Exception:
        return False
    return any(path.startswith(p) for p in excluded)


def extract_urls(html, base):
    found = set()

    patterns = [
        r'''(?:href|src)\s*=\s*["']([^"' >]+)''',
        r'''url\(\s*["']?([^"')]+)["']?\s*\)''',
        r'''https?://[^\s"'<>]+'''
    ]

    for pat in patterns:
        for m in re.findall(pat, html, flags=re.IGNORECASE):
            raw = unescape(m.strip())
            try:
                found.add(urljoin(base, raw))
            except Exception:
                continue

    return found


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

    # default behavior
    params = []
    if p.query:
        for part in p.query.split("&"):
            if part:
                params.append(unquote(part))
    params.sort()

    return f"{p.scheme}://{p.hostname}{path}?{'&'.join(params)}"


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
        total = path_parts.count(token) + query_parts.count(token)
        if total > max_repeat:
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
    queue = [args.start_url]

    proxy = {"server": f"http://{args.proxy_host}:{args.proxy_port}"}

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

        while queue and len(visited) < args.max_pages:
            url = queue.pop(0)

            if not in_scope(url, args.scope):
                continue

            if is_excluded(url, args.exclude_paths):
                logging.info("Excluded: %s", url)
                continue

            if is_recursive_trap(url):
                logging.info("Recursive trap filtered: %s", url)
                continue

            if exceeds_state_token_limit(
                url,
                args.state_tokens,
                args.state_max_repeat
            ):
                logging.info("State token limit hit: %s", url)
                continue

            key = smart_key(url, args.query_agnostic_paths)
            if key in visited:
                continue

            logging.info("Visiting: %s", url)

            try:
                await page.goto(url, wait_until="load")
                html = await page.content()
            except Exception as e:
                logging.warning("Failed: %s (%s)", url, e)
                visited.add(key)
                continue

            for u in extract_urls(html, url):
                if not in_scope(url, args.scope):
                    continue
                if is_recursive_trap(u):
                    continue
                if exceeds_state_token_limit(
                    u,
                    args.state_tokens,
                    args.state_max_repeat
                ):
                    continue

                queue.append(u)

                for wp_u in wp_expand(u):
                    if not is_recursive_trap(wp_u):
                        queue.append(wp_u)

            visited.add(key)
            await asyncio.sleep(args.delay)

        await browser.close()


# ---------------- CLI ----------------

def main():

    ensure_browser()

    ap = argparse.ArgumentParser(description="Burp-friendly Playwright crawler (smart-only)")

    ap.add_argument("--start-url", required=True)
    ap.add_argument(
        "--scope",
        required=True,
        help="URL with protocol,host,path. (e.g. https://bober.pol or https://bober.pol/bobers)")

    ap.add_argument("--proxy-host", required=True)
    ap.add_argument("--proxy-port", required=True, type=int)

    ap.add_argument("--cookie")
    ap.add_argument("--exclude-paths", default="")

    ap.add_argument(
        "--query-agnostic-paths",
        default="",
        help="Comma separated path prefixes where query string is ignored for deduplication (e.g. /shop,/shop/)"
    )

    ap.add_argument(
        "--state-tokens",
        default="",
        help="Comma separated tokens to limit recursion (e.g. embed,feed,rss2)"
    )

    ap.add_argument(
        "--state-max-repeat",
        type=int,
        default=2,
        help="Max allowed repetition per state token"
    )

    ap.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    ap.add_argument("--delay", type=float, default=DEFAULT_DELAY)
    ap.add_argument("--max-pages", type=int, default=DEFAULT_MAX_PAGES)

    args = ap.parse_args()

    args.scope = parse_scope(args.scope)
    args.exclude_paths = [p.strip() for p in args.exclude_paths.split(",") if p.strip()]
    args.query_agnostic_paths = [p.rstrip("/") for p in args.query_agnostic_paths.split(",") if p.strip()]
    args.state_tokens = [t.strip().lower() for t in args.state_tokens.split(",") if t.strip()]

    asyncio.run(crawl(args))


if __name__ == "__main__":
    main()
