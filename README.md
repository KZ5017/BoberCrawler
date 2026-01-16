# **BoberCrawler**

**BoberCrawler** is a Burp-friendly, Playwright-based web crawler designed for security testing, reconnaissance, and dynamic web application exploration.

It focuses on:
- staying strictly inside a defined scope (protocol + host + path),
- handling modern, JavaScript-heavy websites,
- avoiding recursive traps and infinite parameter explosions,
- and producing predictable, deduplicated crawling behavior suitable for pentesting workflows.

The crawler is intentionally **smart-only**: it does not brute-force raw URL permutations, but instead applies controlled, deterministic logic to keep large sites (e.g. webshops) manageable.

---

## **Features**

- ✅ Async crawling using **Playwright**
- ✅ Works well with **Burp Suite** (proxy support)
- ✅ Precise scope control (`scheme + host + path`)
- ✅ Smart URL deduplication
- ✅ Optional query-agnostic paths (ignore `?` for selected endpoints)
- ✅ Recursive trap detection
- ✅ State-token based recursion limiting (e.g. `embed`, `feed`, `rss`)
- ✅ Designed for large, filter-heavy webshops
- ✅ Installable via **pipx**

---

## **Project Structure**

```
BoberCrawler/  
├── pyproject.toml  
├── requirements.txt  
├── bober_crawler/  
│ ├── __init__.py  
│ └── cli.py  
└── README.md
```


---

## **Installation**

### 1️⃣ Install via pipx (recommended)

```
pipx install git+https://github.com/KZ5017/BoberCrawler.git
```
This installs the `bober-crawler` command into an isolated virtual environment.

### 2️⃣ Install Playwright browser (required once)

BoberCrawler uses Playwright and requires Chromium.

Run **exactly what the tool tells you** if the browser is missing, for example:

```
/home/user/.local/share/pipx/venvs/bober-crawler/bin/python -m playwright install chromium
```

💡 This keeps everything isolated inside the pipx environment  
❌ No system-wide installation is required

---

### 3️⃣ Verify installation

```
bober-crawler --help
```

If the help screen appears without errors, you’re good to go.

---

## **Usage**

### Basic command structure

```
bober-crawler --start-url <URL> --scope <URL> --proxy-host <HOST> --proxy-port <PORT> [options]
```

---

## **Scope Handling (Important)**

The `--scope` parameter defines **where the crawler is allowed to go**.

It includes:

- protocol (`https`)
    
- hostname (`example.com`)
    
- path prefix (`/shop`)
    

### Example

```
--scope https://example.com/shop
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

## **Query-Agnostic Paths**

Some endpoints generate endless permutations via query parameters (filters, faceted search).

You can tell the crawler to **ignore query strings for specific paths** during deduplication.

### Example

```
--query-agnostic-paths /shop,/shop/
```

This means:

- `/shop/?a=1`
    
- `/shop/?b=2`
    
- `/shop/?a=1&b=2`
    

➡️ all count as **the same endpoint** for crawling purposes.

Subpaths like `/shop/page/3/` are still fully crawled.

---

## **State Token Guard**

Limits recursion caused by repeating tokens like:

- `embed`
    
- `feed`
    
- `rss2`
    
- similar self-reproducing URL patterns
    

### Example

```
--state-tokens embed,feed,rss2 --state-max-repeat 1
```

If a token appears more than once in path or query values, the URL is skipped.

---

## **Common Examples**

### Crawl a webshop section through Burp

```
bober-crawler --start-url https://example.com/shop --scope https://example.com/shop --proxy-host 127.0.0.1 --proxy-port 8080 --query-agnostic-paths /shop --state-tokens embed,feed,rss2 --state-max-repeat 1 --max-pages 10000
```

---

### Crawl with cookies (authenticated area)

```
bober-crawler --start-url https://example.com/account --scope https://example.com --proxy-host 127.0.0.1 --proxy-port 8080 --cookie "sessionid=abc123; csrftoken=xyz"
```

---

## **Logging**

- Logs are written to `bobercrawler.log`
    
- Also streamed to stdout
    
- Useful for replaying or debugging crawl behavior
    

---

## **Notes**

- This tool is **not a brute-force spider**
    
- It is designed for **controlled, intelligent discovery**
    
- Ideal for:
    
    - pentests
        
    - bug bounty recon
        
    - large e-commerce platforms
        
    - Burp-assisted analysis
        

---

## **Disclaimer**

Use this tool **only** on systems you own or have explicit permission to test.

---

## **License**

MIT License
Feel free to modify, extend, and redistribute.
