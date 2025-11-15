#!/usr/bin/env python3
"""
Async Playwright Crawler (BoberCrawler.py)

- Async implementation using playwright.async_api
- Seeds initial URLs from a file (urls.txt) to capture passive-scan findings early
- Improved link extraction: srcset, CSS url(...) and @import, basic src/srcset parsing
- CLI requires start-url and scope-host
- Authentication: supply session identifiers via --cookies (Cookie header string)
- Optional forbidden paths via --forbidden-paths to avoid calling sensitive endpoints
- English comments only
"""

import re
import sys
import asyncio
import logging
import argparse
from html import unescape
from pathlib import Path
from urllib.parse import urljoin, urlparse, urldefrag, unquote

from playwright.async_api import async_playwright

# --- Defaults --- (overridden by CLI)
DEFAULT_PROXY = "http://127.0.0.1:8080"
DEFAULT_URLS_FILE = "urls.txt"
DEFAULT_NAVIGATION_TIMEOUT_MS = 15000
DEFAULT_MAX_PAGES = 1000
DEFAULT_DELAY_BETWEEN_REQUESTS = 0.15
SITEMAP_FILE = "sitemap.txt"
LOG_FILE = "BoberCrawler_async_cookieauth.log"

# realistic Chrome user agent string
DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36"
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.FileHandler(LOG_FILE, mode="w", encoding="utf-8"), logging.StreamHandler(sys.stdout)],
)


# --- Utilities ---

def load_seed_urls(path: str) -> list:
    """Load seed URLs from a file, one per line. Clean obvious display artifacts."""
    p = Path(path)
    if not p.exists():
        return []
    lines = []
    for raw in p.read_text(encoding="utf-8").splitlines():
        if not raw:
            continue
        s = raw.strip()
        parts = [part.strip() for part in re.split(r',\s*', s) if part.strip()]
        for part in parts:
            cleaned = re.sub(r'\s+\d+w$', '', part)
            if cleaned:
                lines.append(cleaned)
    return lines


def is_same_scope(url: str, scope_host: str) -> bool:
    """Return True if the URL belongs to the configured scope host."""
    try:
        p = urlparse(url)
        return p.hostname == scope_host
    except Exception:
        return False


def normalize_url(base: str, link: str) -> str | None:
    """
    Resolve relative URLs, remove fragments, and return a normalized absolute URL.
    Be forgiving with common formatting mistakes.
    """
    if not link:
        return None
    link = link.strip()
    if link.lower().startswith(("javascript:", "mailto:", "tel:")):
        return None
    if re.match(r'https?:/[^/]', link):
        link = link.replace('http:/', 'http://', 1).replace('https:/', 'https://', 1)
    try:
        abs_url = urljoin(base, link)
    except Exception:
        return None
    abs_url, _ = urldefrag(abs_url)
    try:
        abs_url = unquote(abs_url)
    except Exception:
        pass
    parsed = urlparse(abs_url)
    if parsed.scheme not in ("http", "https"):
        return None
    normalized = parsed._replace(netloc=parsed.netloc.lower()).geturl()
    return normalized


def extract_links_from_html(html: str, base_url: str) -> set:
    """
    Improved link extraction:
    - href and src attributes
    - srcset lists
    - CSS url(...) and @import occurrences inside inline styles or style tags
    - simple JSON/oEmbed URLs present as attributes or text
    """
    urls = set()

    for match in re.findall(r'(?:href|src)\s*=\s*["\']([^"\'>\s]+)', html, flags=re.IGNORECASE):
        value = unescape(match)
        u = normalize_url(base_url, value)
        if u:
            urls.add(u)

    for match in re.findall(r'srcset\s*=\s*["\']([^"\']+)["\']', html, flags=re.IGNORECASE):
        for part in re.split(r',\s*', match):
            part = unescape(part)
            url_candidate = part.split()[0]
            u = normalize_url(base_url, url_candidate)
            if u:
                urls.add(u)

    for match in re.findall(r'url\(\s*["\']?([^"\')]+)["\']?\s*\)', html, flags=re.IGNORECASE):
        value = unescape(match)
        u = normalize_url(base_url, value)
        if u:
            urls.add(u)

    for match in re.findall(r'@import\s+["\']([^"\']+)["\']', html, flags=re.IGNORECASE):
        value = unescape(match)
        u = normalize_url(base_url, value)
        if u:
            urls.add(u)

    for match in re.findall(r'https?://[^\s"\']+', html):
        if len(match) > 2000 or match.startswith('data:'):
            continue
        value = unescape(match)
        u = normalize_url(base_url, value)
        if u:
            urls.add(u)

    return urls


# --- Forbidden paths handling ---

def parse_forbidden_paths(raw: str | None) -> list:
    """
    Parse a comma-separated forbidden paths string into a normalized list of path prefixes.
    Ensure each entry starts with a single leading slash and has no trailing spaces.
    """
    if not raw:
        return []
    parts = [p.strip() for p in raw.split(',') if p.strip()]
    normalized = []
    for p in parts:
        if not p.startswith('/'):
            p = '/' + p
        # remove duplicate trailing slashes
        p = re.sub(r'/+$', '', p) if p != '/' else '/'
        normalized.append(p)
    # sort longer prefixes first to make checks deterministic (not strictly necessary)
    normalized.sort(key=lambda x: -len(x))
    return normalized


def path_is_forbidden(url: str, forbidden_prefixes: list) -> bool:
    """
    Return True if the URL's path matches or is a subpath of any forbidden prefix.
    Matching logic:
      - exact match: /logout == /logout
      - prefix match: /logout/anything startswith /logout
      - file match: /logout.php equals /logout.php
    """
    if not forbidden_prefixes:
        return False
    try:
        p = urlparse(url)
        path = p.path or '/'
    except Exception:
        return False
    for fp in forbidden_prefixes:
        if fp == '/':
            return True
        if path == fp:
            return True
        # ensure prefix match respects path segment boundaries:
        if path.startswith(fp.rstrip('/') + '/'):
            return True
    return False


# --- Async spider core ---

async def run_spider(
    start_url: str,
    scope_host: str,
    proxy: str,
    seed_file: str,
    user_agent: str,
    navigation_timeout_ms: int,
    max_pages: int,
    delay_between_requests: float,
    cookie_header: str | None,
    forbidden_prefixes: list,
):
    """
    Main async crawling loop using Playwright Chromium with proxy configuration.
    If cookie_header is provided, set it as the Cookie header for all requests.
    The forbidden_prefixes list contains path prefixes that must not be requested.
    """
    visited = set()
    to_visit = []

    # start by validating / adding seed URLs in a safe order, but avoid forbidden paths
    seed_urls = load_seed_urls(seed_file)
    # prioritize start_url, but validate it first
    if path_is_forbidden(start_url, forbidden_prefixes):
        logging.error("Start URL %s path is forbidden by forbidden paths. Aborting.", start_url)
        sys.exit(2)

    # initial queue: start_url first, then seed URLs (skipping forbidden ones)
    to_visit.append(start_url)
    for s in seed_urls:
        if s == start_url:
            continue
        if path_is_forbidden(s, forbidden_prefixes):
            logging.info("Skipping seed URL due to forbidden path: %s", s)
            continue
        to_visit.append(s)

    logging.info("Loaded %d seed URLs from %s (after filtering forbidden paths)", len([u for u in seed_urls if not path_is_forbidden(u, forbidden_prefixes)]), seed_file)

    sitemap = []

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=True, proxy={"server": proxy} if proxy else None)
        # set extra headers on context to include Cookie if provided
        extra_headers = {"User-Agent": user_agent}
        if cookie_header:
            extra_headers["Cookie"] = cookie_header

        context = await browser.new_context(
            user_agent=user_agent,
            ignore_https_errors=True,
            extra_http_headers=extra_headers,
        )

        page = await context.new_page()
        page.set_default_navigation_timeout(navigation_timeout_ms)

        logging.info("Initial queue snapshot (first 40): %s", to_visit[:40])

        while to_visit and len(visited) < max_pages:
            url = to_visit.pop(0)
            if url in visited:
                continue
            if not is_same_scope(url, scope_host):
                logging.debug("Skipping out-of-scope URL: %s", url)
                continue
            if path_is_forbidden(url, forbidden_prefixes):
                logging.info("Skipping forbidden path (not requesting): %s", url)
                # mark as visited so we don't attempt again, but do not add to sitemap
                visited.add(url)
                continue

            logging.info("Visiting (%d/%d): %s", len(visited) + 1, max_pages, url)
            try:
                response = await page.goto(url, wait_until="load")
                if response:
                    logging.info("HTTP %s %s", response.status, url)
                else:
                    logging.info("No HTTP response object for %s", url)

                try:
                    html = await page.content()
                except Exception as e:
                    logging.warning("Failed to get page content for %s: %s", url, e)
                    html = ""

                links = extract_links_from_html(html, url)

                ct = ""
                try:
                    ct = response.headers.get("content-type", "") if response else ""
                except Exception:
                    ct = ""

                if not links and ct:
                    logging.debug("No links extracted from %s (Content-Type: %s)", url, ct)

                # Enqueue same-scope, unseen, non-forbidden links
                for link in links:
                    if link in visited or link in to_visit:
                        continue
                    if not is_same_scope(link, scope_host):
                        continue
                    if path_is_forbidden(link, forbidden_prefixes):
                        logging.debug("Filtered out link due to forbidden path: %s", link)
                        visited.add(link)  # mark so we don't revisit repeatedly
                        continue
                    to_visit.append(link)

                visited.add(url)
                sitemap.append(url)

                await asyncio.sleep(delay_between_requests)
            except Exception as exc:
                logging.warning("Error visiting %s: %s", url, exc)
                visited.add(url)
                sitemap.append(url)

        try:
            await page.close()
            await context.close()
            await browser.close()
        except Exception:
            pass

    with open(SITEMAP_FILE, "w", encoding="utf-8") as f:
        for u in sitemap:
            f.write(u + "\n")
    logging.info("Crawling finished. Visited %d URLs. Sitemap saved to %s", len(visited), SITEMAP_FILE)


# --- CLI entry point ---

def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Playwright async Crawler (seeded).")
    parser.add_argument("--start-url", "-s", required=True, help="Start URL for crawling (required).")
    parser.add_argument("--scope-host", "-H", required=True, help="Hostname to restrict crawling to (required).")
    parser.add_argument("--proxy", "-p", default=DEFAULT_PROXY, help=f"HTTP proxy server (default: {DEFAULT_PROXY}).")
    parser.add_argument("--seed-file", "-u", default=DEFAULT_URLS_FILE, help=f"File with seed URLs (one per line) (default: {DEFAULT_URLS_FILE}).")
    parser.add_argument("--user-agent", "-a", default=DEFAULT_USER_AGENT, help="User agent string to use (default: a modern Chrome UA).")
    parser.add_argument("--timeout-ms", "-t", type=int, default=DEFAULT_NAVIGATION_TIMEOUT_MS, help=f"Navigation timeout in milliseconds (default: {DEFAULT_NAVIGATION_TIMEOUT_MS}).")
    parser.add_argument("--max-pages", "-m", type=int, default=DEFAULT_MAX_PAGES, help=f"Maximum number of pages to visit (default: {DEFAULT_MAX_PAGES}).")
    parser.add_argument("--delay", "-d", type=float, default=DEFAULT_DELAY_BETWEEN_REQUESTS, help=f"Delay between requests in seconds (default: {DEFAULT_DELAY_BETWEEN_REQUESTS}).")
    parser.add_argument("--cookies", "-c", help='Cookie header value to send with requests, e.g. "SESSION=abc; csrftoken=xyz" (optional).')
    parser.add_argument("--forbidden-paths", "-F", help='Comma-separated list of path prefixes to never request, e.g. "/logout,/logout.php" (optional).')
    return parser.parse_args()


def validate_start_in_scope(start_url: str, scope_host: str) -> bool:
    """Return True if start_url hostname matches scope_host."""
    try:
        p = urlparse(start_url)
        return p.hostname == scope_host
    except Exception:
        return False


def main():
    args = parse_args()

    # ensure start URL is in scope
    if not validate_start_in_scope(args.start_url, args.scope_host):
        logging.error("Start URL %s is not within the scope host %s. Aborting.", args.start_url, args.scope_host)
        sys.exit(2)

    forbidden_prefixes = parse_forbidden_paths(args.forbidden_paths)

    # ensure start_url path is not forbidden
    if path_is_forbidden(args.start_url, forbidden_prefixes):
        logging.error("Start URL %s path is forbidden by --forbidden-paths. Aborting.", args.start_url)
        sys.exit(2)

    logging.info("Starting BoberCrawler async (cookie auth)")
    logging.info("Start URL: %s", args.start_url)
    logging.info("Scope host: %s", args.scope_host)
    logging.info("Proxy: %s", args.proxy)
    logging.info("Seed file: %s", args.seed_file)
    logging.info("User agent: %s", args.user_agent)
    logging.info("Timeout (ms): %d", args.timeout_ms)
    logging.info("Max pages: %d", args.max_pages)
    logging.info("Delay (s): %s", args.delay)
    logging.info("Cookies provided: %s", bool(args.cookies))
    logging.info("Forbidden path prefixes: %s", forbidden_prefixes)

    asyncio.run(
        run_spider(
            start_url=args.start_url,
            scope_host=args.scope_host,
            proxy=(args.proxy if args.proxy else None),
            seed_file=args.seed_file,
            user_agent=args.user_agent,
            navigation_timeout_ms=args.timeout_ms,
            max_pages=args.max_pages,
            delay_between_requests=args.delay,
            cookie_header=args.cookies,
            forbidden_prefixes=forbidden_prefixes,
        )
    )


if __name__ == "__main__":
    main()
