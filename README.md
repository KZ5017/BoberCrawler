# BoberCrawler

**BoberCrawler** is a Burp-friendly, Playwright-based crawler for security testing, reconnaissance, and controlled exploration of modern web applications.

The current feature set documented below reflects the latest packaged CLI behavior in [`bober_crawler/cli.py`](./bober_crawler/cli.py).

## Features

- Async Playwright crawl engine with Chromium
- Strict scope enforcement by scheme + host + path prefix
- Smart deduplication for crawl URLs and collected request specs
- Seed discovery from `robots.txt`, `sitemap.xml`, and optional JSON input
- Optional query-agnostic deduplication for filter-heavy endpoints
- Recursive trap and state-token protection for self-reproducing URLs
- Optional WebSocket-aware crawling for JS-gated applications
- Optional active mode that submits discovered HTML forms with safe test values
- Vulnerability workflow built on collected inputs and browser replay
- Burp-friendly proxy support enabled by default
- Timestamped log files and summary output with aggregate detail sections

## Current Coverage

The crawler can currently collect and assess:

- Crawl-discovered GET endpoints
- Query-based request specs
- URL-encoded POST form submissions discovered in the browser
- Protected routes observed through `401` / `403` responses

When vulnerability checks are enabled, the workflow currently includes:

- Reflection
- XSS
- SSTI
- SQL injection
- Command injection
- XXE
- Path traversal
- File read
- Open redirect
- CORS misconfiguration
- SSRF
- Access control reachability
- Security headers audit
- Clickjacking audit
- Cookie flag review
- Stored-input reachability via deferred markers

## Installation

### Install with pipx

```bash
pipx install git+https://github.com/KZ5017/BoberCrawler.git
```

### Install the Playwright browser once

If Chromium is missing, the tool prints the exact command to install it. Typical form:

```bash
python -m playwright install chromium
```

### Verify

```bash
bober-crawler --help
```

## Basic Usage

```bash
bober-crawler --start-url "https://example.com/" --scope "https://example.com"
```

Required arguments:

- `--start-url`
- `--scope`

The `--scope` value defines where the crawler may go. It matches:

- scheme
- hostname
- path prefix

Example:

```bash
--scope "https://example.com/shop"
```

Allowed:

- `https://example.com/shop`
- `https://example.com/shop?page=2`
- `https://example.com/shop/category/item`

Blocked:

- `http://example.com/shop`
- `https://example.com/blog`
- `https://admin.example.com/shop`

## Proxy Handling

By default the crawler assumes a local Burp-style proxy:

```text
http://127.0.0.1:8080
```

Use a custom proxy:

```bash
--proxy 127.0.0.1:9090
```

or:

```bash
--proxy http://127.0.0.1:9090
```

Disable proxying entirely:

```bash
--no-proxy
```

Supported proxy schemes:

- `http`
- `https`
- `socks5`

## Crawl Behavior

### `--max-pages`

`--max-pages` currently limits the number of **collected request specs/endpoints**, not just the number of visited URLs.

That makes it much closer to "how many useful inputs/endpoints did the tool gather before stopping".

### Seed Sources

The crawler can prime discovery from:

- `--start-url`
- `robots.txt`
- `sitemap.xml`
- `--seed-json-file`

The JSON seed file should contain `results[].url` entries.

### Query-Agnostic Paths

Use this when endpoints produce endless query permutations:

```bash
--query-agnostic-paths "/shop,/search"
```

### State Token Guard

Use this to stop recursive URL patterns such as `embed`, `feed`, or similar state tokens:

```bash
--state-tokens "embed,feed,rss2" --state-max-repeat 1
```

### WebSocket-Aware Mode

For apps that reveal useful content only after WS bootstrapping:

```bash
--ws-aware
```

### WordPress Expansion

Optional extra endpoint expansion for WordPress-like surfaces:

```bash
--wp-expand
```

## Active Mode And Vulnerability Checks

### Active Mode

```bash
--active-mode
```

This enables browser-side form discovery and submission using generated test values. The tool currently focuses on URL query inputs and URL-encoded POST forms for replayable testing.

### Full Vulnerability Workflow

```bash
--check-vulnerabilities
```

This automatically enables `--active-mode` and runs the full finding pipeline on collected request specs and final audit targets.

## Output And Logging

Each run creates a timestamped log file like:

```text
example-com_root_2026-04-10_14-35.log
```

Log modes:

- `--debug-level clean`
- `--debug-level normal`
- `--debug-level debug`

Accepted aliases:

- `1`, `low` -> `clean`
- `2`, `medium` -> `normal`
- `3`, `high` -> `debug`

The vulnerability summary includes:

- colored priority and confidence labels
- grouped findings by profile
- aggregate sections for consolidated findings such as security headers and clickjacking
- an `AGGREGATE DETAIL` section in the log file
- a final `[collected-endpoints]` inventory showing the deduplicated endpoint/request-spec list gathered during the run

## Main CLI Options

```text
--example
--start-url
--scope
--proxy
--no-proxy
--cookie
--exclude-paths
--query-agnostic-paths
--state-tokens
--state-max-repeat
--timeout
--delay
--max-pages
--max-depth
--seed-json-file
--active-mode
--check-vulnerabilities
--audit-sweep-concurrency
--reachability-check-concurrency
--debug-level
--wp-expand
--ws-aware
```

Concurrency options are safety-clamped to the current internal maximum.

## Built-In Examples

Show the tool's own example set:

```bash
bober-crawler --example
```

Current examples include:

- basic in-scope crawl
- custom proxy usage
- authenticated crawl with cookies
- JS / WebSocket-heavy application crawl
- WordPress / state-aware crawl
- full vulnerability workflow
- authenticated vulnerability assessment with tuned concurrency
- focused crawl with custom seed JSON and stricter limits

## Example Commands

Basic crawl without proxy:

```bash
bober-crawler --start-url "https://example.com/" --scope "https://example.com" --no-proxy
```

Authenticated crawl:

```bash
bober-crawler --start-url "https://example.com/account" --scope "https://example.com" --cookie "sessionid=abc123; csrftoken=xyz" --exclude-paths "/logout,/cdn,/static"
```

Full vulnerability workflow:

```bash
bober-crawler --start-url "https://target.example/" --scope "https://target.example" --check-vulnerabilities --proxy 127.0.0.1:9090
```

Focused crawl with custom seeds:

```bash
bober-crawler --start-url "https://example.com/docs" --scope "https://example.com/docs" --seed-json-file ".\\results.json" --max-depth 3 --max-pages 120 --exclude-paths "/logout,/admin" --query-agnostic-paths "/search"
```

## Notes

- This is not a brute-force spider
- The crawler prefers deterministic, replayable discovery
- It is designed to stay useful on large, dynamic, filter-heavy applications
- Some vulnerability checks are heuristic and replay-based, so findings still need human validation

## Disclaimer

Use this tool only on systems you own or are explicitly authorized to test.

## License

MIT
