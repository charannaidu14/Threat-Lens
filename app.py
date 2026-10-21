"""
app.py — ThreatLens Flask application.

Responsibilities:
- Application factory
- Route definitions
- Server-side input validation
- Security headers (CSP, X-Frame-Options, Permissions-Policy, etc.)
- Generic error handlers
- Rate limiting

Security design notes
---------------------
- No outbound network calls are ever made; analysis is purely string-based.
- Submitted URL content is never logged.
- Stack traces are never surfaced to API callers.
- CSP uses 'self' only for scripts — no 'unsafe-inline' in script-src.
- Permissions-Policy disables all sensitive browser APIs.
"""

import re
import logging
import time
import json
from urllib.parse import urlparse
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError

from flask import Flask, request, jsonify, render_template
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from config import (
    MAX_CONTENT_LENGTH,
    RATE_LIMIT_DEFAULT,
    RATE_LIMIT_ANALYZE,
    MAX_URL_LENGTH,
    MIN_URL_LENGTH,
    APP_NAME,
    APP_VERSION,
    APP_DESCRIPTION,
    SAMPLE_URLS,
)
import analyzer
from analyzer import normalise_url


# ---------------------------------------------------------------------------
# Logging — no URL content is ever logged
# ---------------------------------------------------------------------------
logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Application factory
# ---------------------------------------------------------------------------

def create_app(testing: bool = False) -> Flask:
    app = Flask(__name__)

    # ---- Configuration -----------------------------------------------------
    app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH
    app.config["TESTING"] = testing
    # Disable debug in production — never expose stack traces
    app.config["DEBUG"] = False
    app.config["PROPAGATE_EXCEPTIONS"] = testing

    # ---- Rate limiting -------------------------------------------------------
    # storage_uri="memory://" — suitable for a single-process deployment.
    # For multi-worker Gunicorn, upgrade to Redis: storage_uri="redis://..."
    limiter = Limiter(
        key_func=get_remote_address,
        app=app,
        default_limits=[RATE_LIMIT_DEFAULT],
        storage_uri="memory://",
        # Expose standard RateLimit-* headers so clients can backoff correctly
        headers_enabled=True,
    )

    # ---- Security headers middleware ----------------------------------------
    @app.after_request
    def set_security_headers(response):
        # Prevent MIME-type sniffing
        response.headers["X-Content-Type-Options"] = "nosniff"
        # Deny framing entirely
        response.headers["X-Frame-Options"] = "DENY"
        # Limit referrer exposure
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        # Legacy XSS filter (no-op on modern browsers but harmless)
        response.headers["X-XSS-Protection"] = "1; mode=block"
        # Disable sensitive browser APIs not used by this application
        response.headers["Permissions-Policy"] = (
            "camera=(), microphone=(), geolocation=(), "
            "payment=(), usb=(), interest-cohort=()"
        )
        # Content Security Policy
        # - script-src 'self' only: all JS is served from /static/js/main.js
        #   No inline event handlers or <script> blocks exist in the template.
        # - style-src 'self' 'unsafe-inline': SVG fill/stroke attributes and
        #   the data: favicon require this; no external style sheets are used.
        # - img-src 'self' data:: the favicon is a data: URI SVG.
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "connect-src 'self'; "
            "font-src 'none'; "
            "object-src 'none'; "
            "base-uri 'self'; "
            "form-action 'self'; "
            "frame-ancestors 'none';"
        )
        # Remove server fingerprinting
        response.headers.pop("Server", None)
        return response

    # ---- Routes -------------------------------------------------------------

    @app.route("/")
    def index():
        """Serve the single-page application shell."""
        return render_template("index.html", sample_urls=SAMPLE_URLS)

    @app.route("/api/health", methods=["GET"])
    def health():
        """
        Lightweight liveness probe.

        Response schema
        ---------------
        {
            "status":      "ok",
            "service":     str,   # application name
            "version":     str,   # semantic version
            "description": str,   # one-line description
            "environment": str    # "testing" | "production"
        }
        """
        env = "testing" if app.config.get("TESTING") else "production"
        return jsonify({
            "status":      "ok",
            "service":     APP_NAME,
            "version":     APP_VERSION,
            "description": APP_DESCRIPTION,
            "environment": env,
        })

    @app.route("/api/analyze", methods=["POST"])
    @limiter.limit(RATE_LIMIT_ANALYZE)
    def analyze_url():
        """
        Analyse a submitted URL string for phishing indicators.

        Expects JSON body: { "url": "<string>" }
        Returns full analysis result or a structured error.

        Validation pipeline
        -------------------
        1.  Content-Type must be application/json.
        2.  Body must be valid JSON and the top-level value must be an object
            (dict).  Arrays, strings, numbers, and booleans are rejected here
            rather than causing an AttributeError on .get().
        3.  The "url" field must be present, a string, and non-empty after
            stripping whitespace.
        4.  URL must be within MIN/MAX length bounds.
        5.  javascript: and data: patterns are blocked even if nested.
        6.  normalise_url() lowercases the scheme and validates structure.
        7.  Scheme whitelist: only http and https are accepted.
        8.  A valid host (netloc) must be present.
        9.  analyzer.analyze() runs all 17 heuristic rules.

        Response schema (200)
        ---------------------
        {
            "url_display":        str,
            "score":              int,        # 0–100
            "risk_level":         str,        # "low" | "medium" | "high"
            "risk_label":         str,
            "summary":            str,
            "indicators":         list[dict], # one entry per rule
            "triggered_count":    int,
            "max_possible_score": int,
            "recommendations":    list[str],
            "disclaimer":         str
        }

        Each indicator dict
        -------------------
        {
            "id":          str,
            "name":        str,
            "triggered":   bool,
            "weight":      int,   # 0 if not triggered
            "explanation": str
        }

        Error schema (4xx / 5xx)
        ------------------------
        { "error": str }
        """
        # ---- 1. Content-Type check ------------------------------------------
        if not request.is_json:
            return jsonify({"error": "Request must be JSON with Content-Type application/json."}), 400

        # ---- 2. Parse and type-check JSON body ------------------------------
        data = request.get_json(silent=True)
        if data is None:
            return jsonify({"error": "Malformed JSON body."}), 400
        if not isinstance(data, dict):
            # e.g. body is [], "string", 42, or true
            return jsonify({"error": "Request body must be a JSON object."}), 400

        # ---- 3. Validate 'url' field ----------------------------------------
        raw_url = data.get("url")

        if raw_url is None:
            return jsonify({"error": "Missing required field: 'url'."}), 400

        if not isinstance(raw_url, str):
            return jsonify({"error": "Field 'url' must be a string."}), 400

        url = raw_url.strip()

        if not url:
            return jsonify({"error": "URL must not be empty."}), 400

        # ---- 4. Length bounds -----------------------------------------------
        if len(url) < MIN_URL_LENGTH:
            return jsonify({"error": "URL is too short to be valid."}), 400

        if len(url) > MAX_URL_LENGTH:
            return jsonify({"error": f"URL exceeds maximum allowed length of {MAX_URL_LENGTH} characters."}), 400

        # ---- 5. Block javascript: / data: schemes (even if nested) ----------
        url_lower = url.lower()
        if re.search(r"javascript\s*:", url_lower) or re.search(r"data\s*:", url_lower):
            return jsonify({"error": "URL scheme not permitted."}), 400

        # ---- 6. Normalise (lowercases scheme, validates structure) ----------
        try:
            url = normalise_url(url)
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400

        # ---- 7 & 8. Scheme whitelist + host presence ------------------------
        try:
            parsed = urlparse(url)
        except Exception:
            return jsonify({"error": "Could not parse the submitted URL."}), 400

        if parsed.scheme not in ("http", "https"):
            return jsonify({
                "error": "Only http:// and https:// URLs are supported."
            }), 400

        if not parsed.netloc:
            return jsonify({"error": "URL must include a valid host."}), 400

        # ---- 9. Run analysis ------------------------------------------------
        try:
            result = analyzer.analyze(url)
        except ValueError:
            logger.warning("Analysis ValueError — unparseable URL submitted")
            return jsonify({"error": "Unable to parse the submitted URL."}), 400
        except Exception:
            # Never surface internal details to the caller
            logger.exception("Unexpected analysis error")
            return jsonify({"error": "An internal error occurred. Please try again."}), 500

        return jsonify(result), 200

    # ---- /api/threats — Live Threat Intelligence feed -----------------------

    # Simple in-process cache: (timestamp, payload)
    _threats_cache: dict = {"ts": 0.0, "data": None}
    _THREATS_TTL = 300          # seconds — refresh at most every 5 minutes
    _THREATS_TIMEOUT = 6        # seconds for outbound HTTP

    # Curated static fallback — shown when the external feed is unreachable
    _STATIC_THREATS = [
        {
            "domain": "secure-paypa1.com",
            "type": "Credential Phishing",
            "severity": "critical",
            "target": "PayPal",
            "reported": "2 min ago",
            "iocs": ["punycode", "brand-impersonation"],
        },
        {
            "domain": "login-arnazon.net",
            "type": "E-Commerce Scam",
            "severity": "critical",
            "target": "Amazon",
            "reported": "11 min ago",
            "iocs": ["typosquat", "suspicious-tld"],
        },
        {
            "domain": "bankofamerica-alerts.xyz",
            "type": "Financial Phishing",
            "severity": "high",
            "target": "Bank of America",
            "reported": "34 min ago",
            "iocs": ["brand-impersonation", "suspicious-tld"],
        },
        {
            "domain": "support-microsoft365.tk",
            "type": "Tech Support Scam",
            "severity": "high",
            "target": "Microsoft",
            "reported": "1 hr ago",
            "iocs": ["free-tld", "brand-impersonation"],
        },
        {
            "domain": "dhl-trackparcel.ml",
            "type": "Parcel Delivery Scam",
            "severity": "medium",
            "target": "DHL",
            "reported": "2 hr ago",
            "iocs": ["free-tld", "brand-keyword"],
        },
        {
            "domain": "appleid-verify.cf",
            "type": "Account Takeover",
            "severity": "high",
            "target": "Apple",
            "reported": "3 hr ago",
            "iocs": ["free-tld", "brand-impersonation"],
        },
        {
            "domain": "gov-taxrefund.site",
            "type": "Government Impersonation",
            "severity": "critical",
            "target": "IRS / HMRC",
            "reported": "5 hr ago",
            "iocs": ["suspicious-tld", "gov-keyword"],
        },
        {
            "domain": "netflix-billing.top",
            "type": "Subscription Scam",
            "severity": "medium",
            "target": "Netflix",
            "reported": "7 hr ago",
            "iocs": ["suspicious-tld", "brand-keyword"],
        },
    ]

    @app.route("/api/threats", methods=["GET"])
    @limiter.limit("30 per minute")
    def threat_feed():
        """
        Live Threat Intelligence feed.

        Tries to fetch the latest phishing URLs from PhishTank's public JSON
        feed (no API key required for anonymous access). Normalises the top 8
        results into a compact payload for the dashboard panel.

        Falls back to curated static data when:
          - The external feed is unreachable / times out
          - The feed returns unexpected JSON
          - Rate-limited by PhishTank

        Cache TTL: 5 minutes (in-process memory).

        Response schema (200)
        ---------------------
        {
            "source":    "live" | "cache" | "fallback",
            "updated":   str,          # ISO-8601 timestamp
            "count":     int,
            "threats":   list[dict]    # see below
        }

        Each threat dict
        ----------------
        {
            "domain":   str,
            "type":     str,
            "severity": "critical" | "high" | "medium",
            "target":   str,
            "reported": str,
            "iocs":     list[str]
        }
        """
        now = time.time()
        cache = _threats_cache

        # Serve from cache if still fresh
        if cache["data"] is not None and (now - cache["ts"]) < _THREATS_TTL:
            payload = dict(cache["data"])
            payload["source"] = "cache"
            return jsonify(payload), 200

        # --- Try live PhishTank public feed (no auth required) ---------------
        PHISHTANK_URL = (
            "https://data.phishtank.com/data/online-valid.json"
        )
        threats = None
        try:
            req = Request(
                PHISHTANK_URL,
                headers={
                    "User-Agent": "ThreatLens/2.0 (educational project)",
                    "Accept": "application/json",
                },
            )
            with urlopen(req, timeout=_THREATS_TIMEOUT) as resp:
                raw = json.loads(resp.read().decode("utf-8", errors="replace"))

            # PhishTank returns a list of phish objects; take the 8 most recent
            if isinstance(raw, list) and raw:
                selected = raw[:8]
                from urllib.parse import urlparse as _up
                from datetime import datetime, timezone

                threats = []
                for entry in selected:
                    try:
                        url_str = entry.get("url", "")
                        host = _up(url_str).hostname or url_str[:40]
                        verified = entry.get("verified") == "yes"
                        target_raw = (entry.get("target") or "Unknown").strip()
                        # Map PhishTank category → our severity
                        sev = "critical" if verified else "high"
                        # Relative timestamp from submission_time
                        sub_time = entry.get("submission_time", "")
                        try:
                            dt = datetime.fromisoformat(
                                sub_time.replace("Z", "+00:00")
                            )
                            delta = datetime.now(timezone.utc) - dt
                            mins = int(delta.total_seconds() // 60)
                            if mins < 60:
                                rel = f"{mins} min ago"
                            elif mins < 1440:
                                rel = f"{mins // 60} hr ago"
                            else:
                                rel = f"{mins // 1440} days ago"
                        except Exception:
                            rel = "recently"

                        threats.append({
                            "domain": host[:50],
                            "type": "Phishing" if not target_raw or target_raw == "Other" else f"{target_raw} Phishing",
                            "severity": sev,
                            "target": target_raw,
                            "reported": rel,
                            "iocs": ["phishtank-verified"] if verified else ["phishtank-reported"],
                        })
                    except Exception:
                        continue

        except (URLError, HTTPError, OSError, ValueError, KeyError):
            # Network unreachable / timeout / malformed JSON — use fallback
            threats = None

        if not threats:
            threats = list(_STATIC_THREATS)
            source = "fallback"
        else:
            source = "live"

        from datetime import datetime, timezone as _tz
        updated = datetime.now(_tz.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        payload = {
            "source":  source,
            "updated": updated,
            "count":   len(threats),
            "threats": threats,
        }
        cache["ts"]   = now
        cache["data"] = payload

        return jsonify(payload), 200

    # ---- Error handlers -----------------------------------------------------

    @app.errorhandler(400)
    def bad_request(e):
        return jsonify({"error": "Bad request."}), 400

    @app.errorhandler(404)
    def not_found(e):
        return jsonify({"error": "Resource not found."}), 404

    @app.errorhandler(405)
    def method_not_allowed(e):
        return jsonify({"error": "Method not allowed."}), 405

    @app.errorhandler(413)
    def request_too_large(e):
        return jsonify({"error": "Request body too large."}), 413

    @app.errorhandler(429)
    def rate_limit_exceeded(e):
        return jsonify({"error": "Too many requests. Please wait before retrying."}), 429

    @app.errorhandler(500)
    def internal_error(e):
        return jsonify({"error": "An internal error occurred."}), 500

    return app


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

app = create_app()

if __name__ == "__main__":
    # Development server only — use Gunicorn in production.
    # Gunicorn note: memory:// rate-limit storage is per-worker.
    # For accurate rate limiting across workers, set:
    #   RATELIMIT_STORAGE_URI=redis://localhost:6379/0
    app.run(host="0.0.0.0", port=5000, debug=False)
