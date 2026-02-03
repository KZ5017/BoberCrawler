# BoberCrawler

**BoberCrawler** is a Burp‑friendly, Playwright‑based web crawler designed for **security testing, reconnaissance, and dynamic web application exploration**.

It focuses on:

- staying strictly inside a defined scope (**protocol + host + path**)
    
- handling modern, JavaScript‑heavy websites
    
- avoiding recursive traps and infinite parameter explosions
    
- producing predictable, deduplicated crawling behavior suitable for pentesting workflows
    

The crawler is intentionally **smart‑only**:  
it does **not brute‑force raw URL permutations**, but instead applies controlled, deterministic logic to keep large sites (e.g. webshops) manageable.

---

## **Features**

✅ Async crawling using Playwright  
✅ Works seamlessly with Burp Suite (proxy support)  
✅ Precise scope control (scheme + host + path)  
✅ Smart URL deduplication  
✅ Optional query‑agnostic paths (ignore query string for selected endpoints)  
✅ Recursive trap detection  
✅ State‑token based recursion limiting (e.g. `embed`, `feed`, `rss`)  
✅ WebSocket‑aware crawling for JS‑gated content  
✅ Designed for large, filter‑heavy webshops  
✅ Installable via **pipx**  
✅ Automatic, timestamped log files per crawl

---

## **Project Structure**

```
BoberCrawler/
├── pyproject.toml
├── requirements.txt
├── bober_crawler/
│   ├── __init__.py
│   └── cli.py
└── README.md
```

---

## **Installation**

### 1️⃣ Install via pipx (recommended)

```bash
pipx install git+https://github.com/KZ5017/BoberCrawler.git
```

This installs the `bober-crawler` command into an **isolated virtual environment**.

---

### 2️⃣ Install Playwright browser (required once)

BoberCrawler uses Playwright and requires Chromium.

If missing, the tool will tell you exactly what to run, for example:

```bash
/home/user/.local/share/pipx/venvs/bober-crawler/bin/python -m playwright install chromium
```

💡 This keeps everything isolated inside the pipx environment  
❌ No system‑wide installation is required

---

### 3️⃣ Verify installation

```bash
bober-crawler --help
```

If the help screen appears without errors, you’re good to go.

---

## **Usage**

### Basic command structure

```bash
bober-crawler --start-url <URL> --scope <URL> [options]
```

### Required parameters

Although not enforced by argparse directly, the following parameters **must be provided**:

- `--start-url`
    
- `--scope`
    

---

## **Scope Handling (Important)**

The `--scope` parameter defines **where the crawler is allowed to go**.

It includes:

- protocol (`https`)
    
- hostname (`example.com`)
    
- path prefix (`/shop`)
    

### Example

```bash
--scope 'https://example.com/shop'
```

Allowed:

- `https://example.com/shop/page/1`
    
- `https://example.com/shop/?a=1`
    
- `https://example.com/shop/category/item`
    

Blocked:

- `https://example.com/blog`
    
- `http://example.com/shop`
    
- `https://other.example.com/shop`
    

---

## **Proxy Handling**

By default, BoberCrawler assumes a **Burp proxy** is running:

```
127.0.0.1:8080
```

You can override or disable this behavior.

### Default (Burp)

_No proxy flags required_

### Custom proxy

```bash
--proxy-host 192.168.1.111 --proxy-port 9090
```

### Disable proxy entirely

```bash
--no-proxy
```

---

## **Query‑Agnostic Paths**

Some endpoints generate endless permutations via query parameters (filters, faceted search).

You can instruct the crawler to **ignore query strings** for specific paths during deduplication.

### Example

```bash
--query-agnostic-paths '/shop,/shop/'
```

This means:

```
/shop/?a=1
/shop/?b=2
/shop/?a=1&b=2
```

➡️ all count as the **same endpoint** for crawling purposes.

Subpaths like `/shop/page/3/` are still fully crawled.

---

## **State Token Guard**

Limits recursion caused by repeating tokens such as:

- `embed`
    
- `feed`
    
- `rss2`
    
- similar self‑reproducing URL patterns
    

### Example

```bash
--state-tokens embed,feed,rss2 --state-max-repeat 1
```

If a token appears more than once in path or query values, the URL is skipped.

---

## **WebSocket‑Aware Crawling**

Some modern applications load content **only after a WebSocket connection is established**.

Enable WS‑aware mode to wait for DOM stabilization before extraction:

```bash
--ws-aware
```

This is especially useful for:

- SPA dashboards
    
- JS‑heavy admin panels
    
- real‑time applications
    

---

## **Examples**

Show built‑in usage examples:

```bash
bober-crawler --example
```

This prints multiple real‑world usage patterns, from minimal crawls to advanced pentest setups.

---

## **Logging**

- A **new log file is generated per run**
    
- Filename format:
    
    ```
    <host>_<path>_<YYYY-MM-DD_HH-MM>.log
    ```
    
- Example:
    
    ```
    example-com_cute_bober_2026-02-02_22-37.log
    ```
    
- Logs are:
    
    - written to file
        
    - streamed to stdout
        

Useful for replaying, auditing, and debugging crawl behavior.

---

## **Notes**

- This tool is **not** a brute‑force spider
    
- Designed for **controlled, intelligent discovery**
    
- Ideal for:
    
    - penetration tests
        
    - bug bounty reconnaissance
        
    - large e‑commerce platforms
        
    - Burp‑assisted analysis
        

---

## **Disclaimer**

Use this tool **only on systems you own or have explicit permission to test**.

---

## **License**

MIT License  
Feel free to modify, extend, and redistribute.
