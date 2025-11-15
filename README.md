### Project overview

BoberCrawler — Async Playwright web crawler designed for scoped security-oriented crawling with optional cookie-based authentication and seed URLs. It uses Playwright's async API to drive a headless Chromium instance through an HTTP proxy (e.g., Burp Suite) and writes a sitemap.txt of visited pages. Link extraction includes href/src, srcset, CSS url(...)/@import, and plain http(s) URLs found in page content. The crawler supports forbidden path filtering to avoid calling sensitive endpoints.

---

### Key features

- Async crawler using playwright.async_api for non-blocking navigation
- Seeded startup: loads initial URLs from a seed file to capture passive-scan findings early
- Improved link discovery: href/src, srcset lists, CSS url(...) and @import, and inline HTTP URLs
- Cookie header support: send a Cookie header string to emulate authenticated sessions
- Scope enforcement: restrict crawling to a single hostname via --scope-host
- Forbidden paths: define path prefixes to never request (and avoid sensitive actions like logout)
- Proxy support: route all browser traffic through an HTTP proxy (default http://127.0.0.1:8080)
- Lightweight CLI with configurable timeouts, max pages, delay between requests, and user agent
- Outputs a sitemap.txt (one visited URL per line) and a rotating log file (BoberCrawler_async_cookieauth.log)

---

### Files produced by the script

- sitemap.txt — newline-separated list of visited URLs
- BoberCrawler_async_cookieauth.log — runtime log (INFO+ to console and file)

---

### Requirements and preparations

1. System
    
    - A modern OS with Python 3.10+ recommended (3.9 may work, but typing uses union types).
    - Network access to the target host and to the proxy if you use one.
2. Python environment
    
    - Create an isolated environment (venv or virtualenv) and activate it:
        - `python -m venv .venv`
        - `source .venv/bin/activate` (Linux/macOS) or `.venv\Scripts\activate` (Windows)
3. Install dependencies
    
    - Install Playwright and the async API requirements:
        - `pip install playwright`
    - Install Playwright browsers (required once per machine):
        - `python -m playwright install chromium`
4. Proxy (optional but recommended for security testing)
    
    - Run an HTTP proxy such as Burp Suite or another intercepting proxy and note its address (default in the script is http://127.0.0.1:8080). Configure the script to use it via --proxy to capture or monitor traffic.
5. Seed file (optional)
    
    - Create urls.txt (or another file and pass via --seed-file) containing one URL per line. Seed URLs are enqueued after the configured start URL.
6. Cookie-based auth (optional)
    
    - If you must crawl authenticated pages, supply a Cookie header string via --cookies. Example: `--cookies "SESSION=abcd1234; csrftoken=xyz"`. Ensure the cookie value is valid for the target host and scope.
7. Safety / legal
    
    - Only run against targets you are authorized to test. Avoid including sensitive or destructive paths in the seed file. Use the `--forbidden-paths` option to block actions (e.g.,` /logout,/admin/delete`).

---

### Usage

Basic example (use your own start URL and scope host):

- Example command:
    
    ```
    python BoberCrawler.py --start-url https://example.com/ --scope-host example.com
    ```
    

With proxy and seed file:

- Example command:
    
    ```
    python BoberCrawler.py --start-url https://example.com/ --scope-host example.com --proxy http://127.0.0.1:8080 --seed-file urls.txt
    ```
    

With cookie authentication and forbidden paths:

- Example command:
    
    ```
    python BoberCrawler.py --start-url https://example.com/ --scope-host example.com --cookies "SESSION=abc; csrftoken=def" --forbidden-paths "/logout,/logout.php,/sensitive"
    ```
    

Key CLI options

```
--start-url, -s (required): start URL for the crawl
--scope-host, -H (required): hostname to restrict crawling to (only URLs with this host are enqueued)
--proxy, -p: HTTP proxy server (default: http://127.0.0.1:8080)
--seed-file, -u: file with seed URLs (default: urls.txt)
--user-agent, -a: User-Agent string used by the browser
--timeout-ms, -t: Playwright navigation timeout in milliseconds (default: 15000)
--max-pages, -m: Maximum number of pages to visit (default: 1000)
--delay, -d: Delay between page requests in seconds (default: 0.15)
--cookies, -c: Cookie header string to send with all requests (optional)
--forbidden-paths, -F: Comma-separated path prefixes that must not be requested (optional)
```

---

### Behavioral notes and implementation details

- Scope enforcement is hostname-based; subdomains are considered different hosts and will be treated as out-of-scope.
- The crawler uses a single Playwright page for sequential navigation. It extracts links from the loaded HTML and enqueues same-host links that are not forbidden or already seen.
- Forbidden paths are normalized (leading slash enforced, trailing slashes removed) and matched against the URL path with segment boundary awareness. If a prefix equals "/", everything is considered forbidden.
- Seed URLs are appended after the start URL but skipped if they match forbidden prefixes. This helps capture passive-scan discoveries early.
- Cookie header is applied as an extra HTTP header at the browser context level — it is sent for all requests. Use this carefully and only with valid session values.
- The script marks filtered/forbidden links as visited (so they do not appear in the crawl queue repeatedly) but does not add forbidden-requested URLs to the sitemap.
- Output sitemap contains only pages actually visited (or attempted). Errors visiting pages are logged and the URL is still added to sitemap to preserve the attempted discovery.

---

### Troubleshooting & tips

- If Playwright raises "browser not installed" errors, run: python -m playwright install chromium
- If your proxy requires TLS interception and the target uses HTTPS, ensure Playwright is started with ignore_https_errors=True (already set in the script) and that the proxy's TLS root CA is trusted by your environment if you need to view HTTPS content outside the script.
- If pages appear blank or content not loaded, try increasing --timeout-ms or add a small delay via --delay. Some applications require JS-triggered navigation; the script waits for "load" before extracting content.
- To debug discovery differences vs. other scanners, seed the crawler with the URLs seen by the other tool and run with a low --max-pages to examine behavior quickly.
- Use --forbidden-paths to protect against accidental state-changing requests (logout, delete, purchase endpoints). The script will not issue requests for those prefixes.

---

### Security and ethical considerations

- Do not use cookie values or session tokens that you do not have permission to use. Only crawl accounts and sites for which you have explicit authorization.
- Avoid crawling destructive endpoints. Use --forbidden-paths liberally during security testing to prevent accidental state changes.
- Route traffic through an intercepting proxy (Burp/OWASP ZAP) for visibility during authorized security assessments.

---
