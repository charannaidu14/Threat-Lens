# ThreatLens — Phishing URL & Website Threat Detector

> **B.Tech Cybersecurity Year 1 Bootcamp Project**  
> Stack: Python 3 · Flask · HTML5 · CSS3 · Vanilla JS · pytest · Gunicorn

[![Tests](https://img.shields.io/badge/tests-303%20passed-brightgreen)](tests/)
[![Coverage](https://img.shields.io/badge/coverage-96%25-brightgreen)](docs/QA_REPORT.md)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue)](requirements.txt)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

---

## What It Does

ThreatLens analyses a URL string against **17 heuristic rules** and returns an
explainable risk score (0–100) labelled Low, Medium, or High.  It is designed
for educational use — it performs **string-only analysis** and never visits,
fetches, or resolves the submitted URL.

An integrated **Chintu AI assistant** (100 % client-side, no external API)
answers questions about cybersecurity topics, how ThreatLens works, and common
attack techniques — all inside a floating chat panel on the dashboard.

---

## Screenshots / Demo

Paste any URL into the scan box and get instant, colour-coded feedback:

```
https://secure-paypal-login.xyz/verify/account/update/confirm
→ Score: 55  |  Risk: Medium  |  4 indicators triggered
```

---

## Quick Start

### Prerequisites

- Python 3.11 or later
- pip

### Install & Run (development)

```bash
# 1. Clone the repository
git clone https://github.com/<your-handle>/threatlens.git
cd threatlens

# 2. Create and activate a virtual environment (recommended)
python -m venv .venv
# Windows
.venv\Scripts\activate
# macOS / Linux
source .venv/bin/activate

# 3. Install runtime dependencies
pip install -r requirements.txt

# 4. Start the development server
python app.py
```

Open `http://localhost:5000` in your browser.

### Run Tests

```bash
# Install dev + test dependencies
pip install -r requirements-dev.txt

# Run all 303 tests
pytest tests/ -v

# Run with coverage report
pytest tests/ --cov=. --cov-report=term-missing
```

---

## Project Structure

```
threatlens/
│
│  ── Application source ──────────────────────────────────────────────────────
├── app.py                   ← Flask factory · routes · security headers
├── analyzer.py              ← Heuristic engine (pure string analysis, no I/O)
├── config.py                ← Rule weights · thresholds · brand/TLD lists
│
│  ── Web layer ───────────────────────────────────────────────────────────────
├── templates/
│   └── index.html           ← SPA shell (Jinja2 for static paths only)
│
├── static/
│   ├── css/
│   │   ├── style.css        ← Base design system (dark navy / cyber)
│   │   └── dashboard.css    ← Dashboard, threat-feed panel & Chintu chat styles
│   └── js/
│       ├── main.js          ← Form handling · fetch · result rendering
│       └── dashboard-ui.js  ← Live dashboard · security toolkit · Chintu AI
│
│  ── Tests ───────────────────────────────────────────────────────────────────
├── tests/
│   ├── __init__.py
│   ├── test_analyzer.py     ← 200 unit tests (one class per rule)
│   └── test_routes.py       ← 103 integration tests (HTTP layer)
│
│  ── Documentation ──────────────────────────────────────────────────────────
├── docs/
│   ├── ARCHITECTURE.md      ← Architecture · API contract · design decisions
│   └── QA_REPORT.md         ← Full QA audit · bugs fixed · coverage analysis
│
│  ── Configuration & deployment ─────────────────────────────────────────────
├── requirements.txt         ← Pinned runtime dependencies
├── requirements-dev.txt     ← Dev/test dependencies (includes requirements.txt)
├── pytest.ini               ← pytest configuration
├── Procfile                 ← Gunicorn entry point (Render / Heroku)
├── render.yaml              ← Render.com deployment descriptor
├── .gitignore               ← Ignores __pycache__, .coverage, .venv, etc.
├── LICENSE                  ← MIT licence
└── README.md                ← This file
```

---

## API Reference

### `GET /`

Returns the single-page application shell.

---

### `GET /api/health`

Liveness probe.

**Response `200`:**
```json
{
  "status":      "ok",
  "service":     "ThreatLens",
  "version":     "2.0.0",
  "description": "Phishing URL & Website Threat Detector",
  "environment": "production"
}
```

---

### `POST /api/analyze`

Analyse a URL for phishing indicators.

**Request** (`Content-Type: application/json`, max 2 KB):
```json
{ "url": "https://example.com/login" }
```

**Success `200`:**
```json
{
  "url_display":        "https://example.com/login",
  "score":              10,
  "risk_level":         "low",
  "risk_label":         "Low Risk",
  "summary":            "No significant phishing indicators were detected...",
  "indicators": [
    {
      "id":          "path_has_login_keyword",
      "name":        "Login / Credential Keywords in Path",
      "triggered":   true,
      "weight":      10,
      "explanation": "The URL contains the keyword 'login'..."
    }
  ],
  "triggered_count":    1,
  "max_possible_score": 260,
  "recommendations":    ["The URL shows no obvious structural red flags.", "..."],
  "disclaimer":         "ThreatLens performs heuristic string analysis only..."
}
```

**Error `400`:**
```json
{ "error": "Only http:// and https:// URLs are supported." }
```

**Rate-limited `429`:**
```json
{ "error": "Too many requests. Please wait before retrying." }
```

---

### `GET /api/threats`

Live threat intelligence feed (falls back to curated static data when the
external feed is unreachable).

**Response `200`:**
```json
{
  "source":  "live",
  "updated": "2025-01-15T14:22:00Z",
  "count":   8,
  "threats": [
    {
      "domain":   "secure-paypa1.com",
      "type":     "Credential Phishing",
      "severity": "critical",
      "target":   "PayPal",
      "reported": "2 min ago",
      "iocs":     ["punycode", "brand-impersonation"]
    }
  ]
}
```

---

## Analysis Rules

17 heuristic rules produce a cumulative score capped at 100.

| Rule ID | Weight | What It Detects |
|---|:-:|---|
| `ip_address_host` | 25 | Raw IPv4 or IPv6 address as host |
| `at_in_authority` | 25 | `@` in URL authority — credential-injection trick |
| `excessive_subdomains` | 20 | More than 3 subdomain labels beyond the registered domain |
| `misleading_brand` | 20 | Known brand name in subdomain/path but not in the registered domain |
| `special_chars_in_domain` | 20 | `%` encoding or consecutive hyphens in hostname |
| `punycode_domain` | 20 | `xn--` label — IDN homograph attack potential |
| `double_slash_redirect` | 20 | `//` after the scheme — open-redirect / parser confusion |
| `suspicious_tld` | 15 | TLD in the known-abuse list (`.xyz`, `.tk`, `.ml`, `.top`, etc.) |
| `numeric_subdomain` | 15 | All-digit subdomain label (e.g. `12345.evil.com`) |
| `url_shortener` | 15 | Host is a known URL-shortening service |
| `port_in_url` | 15 | Non-standard port (anything other than 80, 443, 8080, 8443) |
| `suspicious_encoding` | 15 | High-density percent-encoding or encoded keywords |
| `unicode_in_domain` | 15 | Non-ASCII characters in the hostname |
| `long_url` | 10 | URL length exceeds 75 characters |
| `excessive_path_depth` | 10 | More than 5 path segments |
| `http_scheme` | 10 | Plain HTTP instead of HTTPS |
| `path_has_login_keyword` | 10 | Credential-harvesting keywords in path/query |

### Risk Classification

| Score | Level | Meaning |
|:-:|---|---|
| 0–24 | **Low** | No significant structural indicators detected |
| 25–59 | **Medium** | One or more moderate indicators — exercise caution |
| 60–100 | **High** | Multiple or severe indicators — treat as suspicious |

---

## Security Toolkit

ThreatLens ships seven client-side security tools (all run 100 % in the browser — no data sent to any server):

| Tool | Description |
|---|---|
| Password Strength Analyzer | Entropy score, breach-pattern checks, actionable tips |
| 2FA Compatibility Checker | Tests for TOTP, FIDO2, SMS, hardware-key support |
| Session Security Monitor | Checks HTTPS, cookie flags, referrer policy, CSP |
| Live Threat Intelligence | Curated feed of recent phishing domains and IOCs |
| Hash Generator | SHA-1 / SHA-256 / SHA-512 via Web Crypto API |
| Payload Decoder | Base64 decode/encode, URL decode |
| Email Header Analyser | SPF/DKIM/DMARC pass/fail, hop chain, From/Reply-To mismatch |

---

## Chintu — AI Assistant

**Chintu** is a floating chat assistant built into the dashboard.  
It runs entirely in the browser — no API key, no external calls, no data collected.

- **30+ topic knowledge base**: phishing, XSS, SQLi, SSRF, OWASP Top 10, CVEs, 2FA, password security, email spoofing, DNS attacks, VPNs, cryptography, malware types, incident response, and more  
- **Keyword + fuzzy matching** response engine  
- **Draggable** panel — repositions anywhere on screen  
- **Markdown-lite renderer** — bold, italic, code, lists, tables rendered safely via `createElement` / `textContent` — no `innerHTML`  
- Topic pills for quick questions; clear button; unread badge  

---

## Security Design

| Control | Implementation |
|---|---|
| No SSRF | `analyzer.py` is pure string/parse — zero network calls, zero I/O imports |
| Input validation | Content-Type check → JSON type check → field validation → length bounds → scheme whitelist |
| XSS prevention | CSP `script-src 'self'` only; all DOM output via `textContent`; no `innerHTML` anywhere |
| Credential stripping | Userinfo stripped from `url_display` before any response |
| Rate limiting | `flask-limiter` — 30 req/min per IP on `/api/analyze` |
| Request size cap | `MAX_CONTENT_LENGTH = 2048` bytes |
| Security headers | CSP, X-Frame-Options DENY, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, X-XSS-Protection |
| No fingerprinting | `Server` header removed from every response |
| No data storage | Submitted URLs are never logged or persisted |
| Debug off | `DEBUG=False`; stack traces never surfaced to callers |

---

## Deployment

### Render (recommended)

A `render.yaml` is included. Push to GitHub and connect the repo in the Render
dashboard — it will auto-deploy using Gunicorn.

```yaml
# render.yaml excerpt
startCommand: gunicorn app:app --workers 2 --bind 0.0.0.0:$PORT
```

**Note on rate limiting:** The default `memory://` storage is per-worker.
For accurate cross-worker rate limiting set:
```
RATELIMIT_STORAGE_URI=redis://your-redis-url:6379/0
```

### Heroku / other platforms

```bash
# Procfile is already configured:
web: gunicorn app:app --workers 2 --bind 0.0.0.0:$PORT
```

---

## Sample URLs (for Demo Use)

| URL | Expected Risk |
|---|:-:|
| `https://google.com` | Low |
| `https://subdomain.legit-bank.com/account/summary` | Low–Medium |
| `http://192.168.1.1/login` | High |
| `https://secure-paypal-login.xyz/verify/account/update/confirm` | Medium–High |
| `https://xn--pypal-4ve.com/signin` | High |
| `http://bit.ly/3xAbc12` | Medium |

---

## Test Coverage

```
303 tests  ·  0 failures  ·  0 errors

analyzer.py    226 stmts   4 missed   98%
app.py         103 stmts  10 missed   90%
─────────────────────────────────────────
TOTAL          329 stmts  14 missed   96%
```

See [`docs/QA_REPORT.md`](docs/QA_REPORT.md) for a full audit including bug history and
coverage breakdown.

---

## Disclaimer

ThreatLens performs heuristic string analysis only. It does not visit URLs,
consult threat databases, or guarantee accuracy. A low score does not confirm a
URL is safe — phishing sites can use HTTPS and appear structurally normal. A
high score does not confirm a URL is malicious. Always verify through official
channels and trusted security tools before taking any action.

---

## License

[MIT](LICENSE)
