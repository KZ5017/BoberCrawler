#!/usr/bin/env python3
import asyncio
import argparse
import logging
import re
import sys
import os
from html import unescape
from urllib.parse import urljoin, urlparse, unquote
from datetime import datetime

from playwright.async_api import async_playwright
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

    return (p.path or "/").startswith(scope["path"])


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
    queue = [args.start_url]

    proxy = None
    if not args.no_proxy:
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

        ws_seen = False

        def _on_ws(ws):
            nonlocal ws_seen
            ws_seen = True
            logging.info("WebSocket opened: %s", ws.url)

        page.on("websocket", _on_ws)


        while queue and len(visited) < args.max_pages:
            ws_seen = False
            url = queue.pop(0)

            if not in_scope(url, args.scope):
                continue
            if is_excluded(url, args.exclude_paths):
                continue
            if is_recursive_trap(url):
                continue
            if exceeds_state_token_limit(url, args.state_tokens, args.state_max_repeat):
                continue

            key = smart_key(url, args.query_agnostic_paths)
            if key in visited:
                continue

            logging.info("Visiting: %s", url)

            try:
                await page.goto(url, wait_until="load")

                if args.ws_aware:
                    try:
                        # adjunk időt a WS initre
                        await asyncio.sleep(1.0)
                    except Exception:
                        pass

                if args.ws_aware and ws_seen:
                    logging.info("WS-aware: WS seen, waiting for DOM settle")

                    try:
                        await page.wait_for_function(
                            "() => document.body && document.body.innerText.length > 300",
                            timeout=6000
                        )
                    except Exception:
                        await asyncio.sleep(1.0)

                html = await page.content()

            except Exception as e:
                logging.warning("Failed: %s (%s)", url, e)
                visited.add(key)
                continue

            for u in extract_urls(html, url):
                if not in_scope(u, args.scope):
                    continue
                if is_recursive_trap(u):
                    continue
                if exceeds_state_token_limit(u, args.state_tokens, args.state_max_repeat):
                    continue

                queue.append(u)

                if args.wp_expand:
                    for wp_u in wp_expand(u):
                        if not is_recursive_trap(wp_u):
                            queue.append(wp_u)

            visited.add(key)
            await asyncio.sleep(args.delay)

        await browser.close()


# ---------------- CLI ----------------

def print_examples():
    print("""
==========================
BoberCrawler – Examples
==========================

1) Minimal crawl
----------------
bober-crawler \\
  --start-url 'https://example.com/' \\
  --scope 'https://example.com' \\
  --no-proxy


2) WordPress site expansion + State-aware crawl (token-based)
----------------------------------
bober-crawler \\
  --start-url 'https://wp-site.example' \\
  --scope 'https://wp-site.example' \\
  --state-tokens 'embed,feed,rss2' \\
  --state-max-repeat 1 \\
  --wp-expand \\
  --query-agnostic-paths '/search,/shop' \\
  --exclude-paths '/wp-admin,/wp-login.php' \\


3) WebSocket-gated content
--------------------------
bober-crawler \\
  --start-url 'https://example.com/app' \\
  --scope 'https://example.com' \\
  --ws-aware \\
  --proxy-port 9090


4) Custom port + cookies (authenticated area) + aggressive filtering
-------------------------------------
bober-crawler \\
  --start-url 'https://example.com:8443/app' \\
  --scope 'https://example.com:8443' \\
  --cookie 'sessionid=abc123; csrftoken=xyz' \\
  --exclude-paths '/logout,/static,/cdn' \\
  --query-agnostic-paths '/search,/shop' \\
  --delay 0.05 \\
  --max-pages 500 \\
  --proxy-host 192.168.1.111 \\
  --proxy-port 9090

==========================
""".strip())


def main():
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
    ap.add_argument("--proxy-host", default=PROXY_HOST, help="Proxy host (default: 127.0.0.1)")
    ap.add_argument("--proxy-port", type=int, default=PROXY_PORT, help="Proxy port (default: 8080)")
    ap.add_argument("--no-proxy", action="store_true", help="Disable proxy entirely")
    ap.add_argument("--cookie")
    ap.add_argument("--exclude-paths", default="", help="Comma-separated path prefixes to skip")
    ap.add_argument("--query-agnostic-paths", default="", help="Paths where query string is ignored")
    ap.add_argument("--state-tokens", default="", help="Limits recursion caused by repeating tokens")
    ap.add_argument("--state-max-repeat", type=int, default=2, help="Max allowed repeats of same state")
    ap.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help="Navigation timeout in ms")
    ap.add_argument("--delay", type=float, default=DEFAULT_DELAY, help="Delay between requests (seconds)")
    ap.add_argument("--max-pages", type=int, default=DEFAULT_MAX_PAGES, help="Maximum pages to crawl")
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

    # --- logging setup ---
    log_file = build_log_filename(args.start_url)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[logging.FileHandler(log_file, encoding="utf-8"),
                  logging.StreamHandler(sys.stdout)]
    )

    logging.info("Log file: %s", log_file)
    logging.info("Start URL: %s | Scope: %s://%s%s",
                 args.start_url, args.scope["scheme"], args.scope["host"], args.scope["path"])

    asyncio.run(crawl(args))


if __name__ == "__main__":
    main()
