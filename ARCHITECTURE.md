# ThreatLens — Phishing URL & Website Threat Detector
## Project Architecture Document

> **Author:** B.Tech Cybersecurity Year 1 Bootcamp Project  
> **Stack:** Python 3 · Flask · HTML5 · CSS3 · Vanilla JS · pytest · Gunicorn

---

## 1. Project Overview

ThreatLens is a web application that accepts a URL string, applies a rule-based
heuristic engine to identify phishing indicators, and returns an explainable
risk assessment.  It is designed for educational demonstration and portfolio
use.  It does **not** visit submitted URLs, does **not** store data, and makes
**no claim** of verified malicious or safe classification — only heuristic scoring.

An integrated **Chintu AI assistant** (100 % client-side, no external API)
answers questions about cybersecurity topics and ThreatLens internals from a
30+ topic knowledge base, all rendered safely via `createElement`/`textContent`.

---

## 2. File Structure

```
threatlens/                     ← project root
│
├── app.py                      ← Flask application factory & routes
├── analyzer.py                 ← URL heuristic analysis engine
├── config.py                   ← Configuration constants & thresholds
│
├── templates/
│   └── index.html              ← Single-page application shell
│
├── static/
│   ├── css/
│   │   ├── style.css           ← Full design system (dark navy / cyber)
│   │   └── dashboard.css       ← Dashboard, threat-feed & Chintu chat styles
│   └── js/
│       ├── main.js             ← Vanilla JS: form handling, fetch, UI states
│       └── dashboard-ui.js     ← Dashboard, security toolkit, Chintu AI
│
├── tests/
│   ├── __init__.py
│   ├── test_analyzer.py        ← Unit tests for every analysis rule
│   └── test_routes.py          ← Integration tests for Flask endpoints
│
├── docs/
│   ├── ARCHITECTURE.md         ← This document
│   └── QA_REPORT.md            ← Full QA audit, bugs fixed, coverage analysis
│
├── requirements.txt            ← Runtime dependencies
├── requirements-dev.txt        ← Dev/test dependencies
├── Procfile                    ← Gunicorn entry point for Render/Heroku
├── render.yaml                 ← Render deployment descriptor
├── .gitignore
└── README.md
```

---

## 3. Module Responsibilities

| Module | Responsibility |
|---|---|
| `app.py` | Flask factory, route definitions, input validation, error handlers, security headers |
| `analyzer.py` | Pure-function heuristic engine; no I/O, no network calls |
| `config.py` | Thresholds, rule weights, feature flags — single source of truth |
| `templates/index.html` | Semantic HTML5 shell; Jinja2 used only for static asset paths |
| `static/css/style.css` | Design tokens, layout, components, animations, responsive grid |
| `static/css/dashboard.css` | Dashboard panel, security toolkit, Chintu chat widget styles |
| `static/js/main.js` | Form submit, fetch `/api/analyze`, render results, manage UI states |
| `static/js/dashboard-ui.js` | Live charts, session counters, scan history, security toolkit, Chintu AI |
| `tests/test_analyzer.py` | One test per rule + boundary tests + edge cases |
| `tests/test_routes.py` | HTTP-level tests: valid input, invalid input, rate limits, headers |

---

## 4. API Contract

### `GET /`
Returns the SPA shell.

### `GET /api/health`
```json
{ "status": "ok", "service": "ThreatLens", "version": "2.0.0" }
```

### `POST /api/analyze`
**Request** (`Content-Type: application/json`, max 2 KB):
```json
{ "url": "https://example.com/login" }
```

**Success Response** (`200 OK`):
```json
{
  "url_display": "https://example.com/login",
  "score": 42,
  "risk_level": "medium",
  "risk_label": "Medium Risk",
  "summary": "One or more moderate phishing indicators detected...",
  "indicators": [
    {
      "id": "suspicious_tld",
      "name": "Suspicious TLD",
      "triggered": true,
      "weight": 15,
      "explanation": "The domain uses a TLD commonly associated with phishing campaigns."
    }
  ],
  "recommendations": [
    "Do not enter credentials on this page.",
    "Verify the domain through official channels."
  ],
  "disclaimer": "ThreatLens performs heuristic string analysis only. Always verify through trusted sources."
}
```

**Error Response** (`400 Bad Request`):
```json
{ "error": "Invalid or missing URL field." }
```

**Rate-limit Response** (`429 Too Many Requests`):
```json
{ "error": "Too many requests. Please wait before retrying." }
```

---

## 5. Analysis Rules & Weights

Each rule returns `(triggered: bool, weight: int, explanation: str)`.
Score = sum of triggered weights, clamped to [0, 100].

| Rule ID | Weight | Trigger Condition |
|---|---|---|
| `ip_address_host` | 25 | Host is a raw IP address |
| `at_in_authority` | 25 | `@` in URL authority |
| `excessive_subdomains` | 20 | More than 3 subdomain labels |
| `suspicious_tld` | 15 | TLD in known-phishing list (.xyz, .tk, .ml, .ga, .cf, .gq, .top, .click, .loan, .work, .date, .faith, .racing, .stream, .download) |
| `misleading_brand` | 20 | URL path or subdomain contains a popular brand name but the registered domain does not match |
| `long_url` | 10 | Total URL length > 75 characters |
| `excessive_path_depth` | 10 | Path has more than 5 segments |
| `special_chars_in_domain` | 20 | Domain contains `@`, `%`, or multiple hyphens in sequence |
| `http_scheme` | 10 | Scheme is `http://` (not HTTPS) |
| `punycode_domain` | 20 | Domain contains `xn--` (IDN homograph potential) |
| `numeric_subdomain` | 15 | Subdomain is entirely numeric |
| `url_shortener` | 15 | Host is a known URL-shortening service |
| `path_has_login_keyword` | 10 | Path contains login/signin/verify/secure/update/confirm/account/banking/password |
| `double_slash_redirect` | 20 | URL path contains `//` after scheme (potential redirect abuse) |
| `port_in_url` | 15 | Non-standard port specified in URL |
| `suspicious_encoding` | 15 | High-density percent-encoding or encoded keywords |
| `unicode_in_domain` | 15 | Non-ASCII characters in the hostname |

**Risk Classification (configurable in `config.py`):**
- `0–24` → **Low** — No significant indicators found
- `25–59` → **Medium** — One or more moderate indicators present
- `60–100` → **High** — Multiple or severe indicators detected

---

## 6. Security Controls

| Control | Implementation |
|---|---|
| No URL fetching | `analyzer.py` uses only string/parse operations; zero network calls |
| Input validation | Server-side: type check, length limit (2083 chars), scheme whitelist |
| XSS prevention | `Content-Security-Policy` header; Jinja2 auto-escaping on; JS uses `textContent`/`createElement` — never `innerHTML` for user data |
| Request size limit | Flask `MAX_CONTENT_LENGTH = 2048` bytes |
| Rate limiting | `flask-limiter` — 30 req/min per IP on `/api/analyze` |
| Security headers | `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `CSP` |
| No data storage | No database; no logging of submitted URLs |
| No secret exposure | Generic error messages in production; `DEBUG=False` by default |
| No redirects | No user-controlled redirects anywhere in the app |
| Dependency pinning | All versions pinned in `requirements.txt` |

---

## 7. Chintu AI Architecture

Chintu is implemented entirely in [`static/js/dashboard-ui.js`](../static/js/dashboard-ui.js) and requires no backend changes.

```
User message
    │
    ▼
chintuRespond(msg)
    │  keyword scoring → fuzzy fallback → CHINTU_FALLBACKS
    ▼
{ title, answer }  (plain text with Markdown-lite syntax)
    │
    ▼
renderMarkdownLite(text)
    │  splits lines → createElement for each token
    │  **bold** → <strong>   *italic* → <em>   `code` → <code>
    │  - list → <ul><li>     1. list → <ol><li>
    │  | table | → <table>   ``` fence → <pre><code>
    ▼
DocumentFragment (zero innerHTML, zero eval)
    │
    ▼
chintuAppendMessage() → appends to #chin-messages
```

The floating bubble (`#chintu-bubble`) and panel (`#chintu-panel`) are declared
in `templates/index.html`. The CSS lives in `static/css/dashboard.css`.

---

## 8. Sample URLs (for Demo Use)

| URL | Expected Risk |
|---|---|
| `https://google.com` | Low |
| `http://192.168.1.1/login` | High |
| `https://secure-paypal-login.xyz/verify/account/update` | High |
| `https://xn--pypal-4ve.com` | High |
| `https://subdomain.legit-bank.com/account` | Medium |
| `http://bit.ly/3xAbc12` | Medium |

---

## 9. Implementation Status

1. ✅ **Phase 0** — Plan & directory scaffold
2. ✅ **Phase 1** — `config.py`, `analyzer.py`, `tests/test_analyzer.py` (logic core, fully tested)
3. ✅ **Phase 2** — `app.py` routes, `tests/test_routes.py` (API layer)
4. ✅ **Phase 3** — `templates/index.html`, `static/css/style.css` (visual shell)
5. ✅ **Phase 4** — `static/js/main.js` (interactive frontend)
6. ✅ **Phase 5** — `requirements.txt`, `Procfile`, `render.yaml`, `.gitignore` (deployment)
7. ✅ **Phase 6** — End-to-end validation: 303 tests passing, 96 % coverage
8. ✅ **Phase 7** — Dashboard v7: live charts, security toolkit (7 tools), Chintu AI assistant

---

## 10. Accessibility & Responsiveness

- Semantic HTML5 landmarks (`<main>`, `<section>`, `<header>`, `<footer>`)
- ARIA labels on interactive elements
- Focus-visible outlines for keyboard navigation
- `prefers-reduced-motion` media query disables all animations
- Mobile-first CSS: 320px → 768px → 1280px breakpoints
- Touch targets ≥ 44px

---

## 11. Disclaimer (embedded in UI and API)

> ThreatLens performs heuristic string analysis only. It does not visit URLs,
> consult threat databases, or guarantee accuracy. A low score does not confirm
> a URL is safe; a high score does not confirm it is malicious. Always verify
> through official channels and trusted security tools before taking action.
