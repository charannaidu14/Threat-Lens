"""
config.py — ThreatLens configuration constants.

All thresholds, weights, and feature-flag values live here so that
tuning the analysis engine never requires touching business logic.

Rule weight rationale
---------------------
Weights are assigned on a 5-point scale:
  5  → Very strong signal (almost always deliberate obfuscation)
  4  → Strong signal (unusual in legitimate sites)
  3  → Moderate signal (common in phishing, but also in benign URLs)
  2  → Weak signal (raises suspicion when combined with others)
  1  → Context signal (low alone; meaningful alongside others)

Actual point values are multiples of 5 for readability.
"""

# ---------------------------------------------------------------------------
# Risk score thresholds
# Scores are integers in [0, 100].
# ---------------------------------------------------------------------------
RISK_THRESHOLDS = {
    "low":    (0,  24),   # score 0–24  → Low risk
    "medium": (25, 59),   # score 25–59 → Medium risk
    "high":   (60, 100),  # score 60–100 → High risk
}

RISK_LABELS = {
    "low":    "Low Risk",
    "medium": "Medium Risk",
    "high":   "High Risk",
}

RISK_SUMMARIES = {
    "low": (
        "No significant phishing indicators were detected in the URL structure. "
        "This URL appears relatively benign based on heuristic analysis alone. "
        "Note: a low score does not guarantee the destination is safe — always "
        "verify the site through independent means before submitting credentials."
    ),
    "medium": (
        "One or more moderate phishing indicators were detected. "
        "Exercise caution before interacting with this URL. "
        "Do not enter credentials or personal information without independently "
        "verifying the site's legitimacy."
    ),
    "high": (
        "Multiple or severe phishing indicators were detected. "
        "This URL exhibits structural characteristics strongly associated with "
        "phishing campaigns. Do not enter credentials or personal information. "
        "Treat this URL as suspicious until proven otherwise."
    ),
}

RISK_RECOMMENDATIONS = {
    "low": [
        "The URL shows no obvious structural red flags.",
        "Always verify the domain belongs to the expected organisation before "
        "entering any information.",
        "Remember: HTTPS does not mean a site is trustworthy — phishing sites "
        "can and do use valid TLS certificates.",
        "Keep your browser and security software up to date.",
    ],
    "medium": [
        "Do not enter passwords or personal information without verifying the site.",
        "Check the full URL bar carefully — look for typosquatted or "
        "lookalike domain names.",
        "Look for a valid HTTPS certificate, but note that HTTPS alone does not "
        "make a site safe.",
        "Navigate directly to the official site instead of following this link.",
    ],
    "high": [
        "Do NOT enter any personal information — treat this URL as malicious "
        "until independently verified.",
        "If you received this link by email or message, report it as phishing.",
        "Run the URL through a reputable threat database (e.g. VirusTotal, "
        "Google Safe Browsing).",
        "Notify your organisation's security team if this link appeared in "
        "official communication.",
        "Change your credentials immediately if you have already interacted "
        "with this URL.",
    ],
}

# ---------------------------------------------------------------------------
# Analysis rule weights
#
# Each rule contributes this many points to the total risk score when
# triggered.  Weights are intentionally documented here so they can be
# reviewed and adjusted independently of logic.
#
# Rule ID                       Weight  Rationale
# ─────────────────────────────────────────────────────────────────────────
# ip_address_host                  25   Legitimate services rarely use raw IPs
# at_in_authority                  25   Classic credential-hiding technique
# excessive_subdomains             20   Deep nesting disguises real domain
# misleading_brand                 20   Core impersonation technique
# special_chars_in_domain          20   Encoding tricks / @ bypass
# punycode_domain                  20   Homograph attack vector
# double_slash_redirect            20   Open-redirect / parser confusion
# suspicious_tld                   15   Low-cost TLDs dominate phish domains
# numeric_subdomain                15   Infra pattern: 123456.evil.com
# url_shortener                    15   Hides real destination
# port_in_url                      15   Rogue servers; non-standard ports
# suspicious_encoding              15   Encoded keywords to bypass filters
# unicode_in_domain                15   Homograph without explicit punycode
# long_url                         10   Payload obfuscation / noise
# excessive_path_depth             10   False legitimacy layering
# http_scheme                      10   Unencrypted; lower bar for phish pages
# path_has_login_keyword           10   Credential-harvesting path patterns
# ---------------------------------------------------------------------------
RULE_WEIGHTS = {
    "ip_address_host":          25,
    "at_in_authority":          25,
    "excessive_subdomains":     20,
    "misleading_brand":         20,
    "special_chars_in_domain":  20,
    "punycode_domain":          20,
    "double_slash_redirect":    20,
    "suspicious_tld":           15,
    "numeric_subdomain":        15,
    "url_shortener":            15,
    "port_in_url":              15,
    "suspicious_encoding":      15,
    "unicode_in_domain":        15,
    "long_url":                 10,
    "excessive_path_depth":     10,
    "http_scheme":              10,
    "path_has_login_keyword":   10,
}

# ---------------------------------------------------------------------------
# Rule display names (shown in the UI)
# ---------------------------------------------------------------------------
RULE_NAMES = {
    "ip_address_host":          "IP Address as Host",
    "at_in_authority":          "Credentials / @ in URL Authority",
    "excessive_subdomains":     "Excessive Subdomains",
    "misleading_brand":         "Misleading Brand in URL",
    "special_chars_in_domain":  "Special Characters in Domain",
    "punycode_domain":          "Punycode / IDN Domain",
    "double_slash_redirect":    "Redirect Abuse Pattern",
    "suspicious_tld":           "Suspicious Top-Level Domain",
    "numeric_subdomain":        "Numeric Subdomain",
    "url_shortener":            "URL Shortener Service",
    "port_in_url":              "Non-Standard Port in URL",
    "suspicious_encoding":      "Suspicious Percent-Encoding",
    "unicode_in_domain":        "Non-ASCII / Unicode in Domain",
    "long_url":                 "Unusually Long URL",
    "excessive_path_depth":     "Deeply Nested URL Path",
    "http_scheme":              "Insecure HTTP Scheme",
    "path_has_login_keyword":   "Login / Credential Keywords in Path",
}

# ---------------------------------------------------------------------------
# Suspicious TLDs (commonly abused in phishing campaigns)
# Source: abuse/registration-cost patterns, APWG reports.
# ---------------------------------------------------------------------------
SUSPICIOUS_TLDS = frozenset({
    ".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".top",
    ".click", ".loan", ".work", ".date", ".faith", ".racing",
    ".stream", ".download", ".bit", ".country", ".kim",
    ".science", ".party", ".gdn", ".men", ".review",
    ".accountant", ".win", ".cricket", ".webcam", ".space",
    ".site", ".online", ".tech", ".live",
})

# ---------------------------------------------------------------------------
# Known brand names for misleading-brand detection.
# Check: brand appears in subdomain or path but NOT in the registered domain.
# ---------------------------------------------------------------------------
BRAND_KEYWORDS = [
    "paypal", "google", "amazon", "apple", "microsoft", "facebook",
    "instagram", "netflix", "twitter", "linkedin", "dropbox", "github",
    "ebay", "wellsfargo", "bankofamerica", "chase", "citibank", "hsbc",
    "barclays", "steam", "discord", "whatsapp", "telegram", "zoom",
    "office365", "outlook", "yahoo", "dhl", "fedex", "ups",
    "adobe", "docusign", "coinbase", "binance", "blockchain",
]

# ---------------------------------------------------------------------------
# Known URL shortener hostnames
# ---------------------------------------------------------------------------
URL_SHORTENERS = frozenset({
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "buff.ly",
    "is.gd", "cli.gs", "yfrog.com", "migre.me", "ff.im", "tiny.cc",
    "url4.eu", "tr.im", "twit.ac", "su.pr", "snurl.com", "short.to",
    "budurl.com", "ping.fm", "post.ly", "just.as", "bkite.com",
    "snipr.com", "fic.kr", "loopt.us", "doiop.com", "cutt.us",
    "shorturl.at", "rb.gy", "cutt.ly", "shrtco.de", "soo.gd",
    "v.gd", "qr.ae", "ity.im", "q.gs", "po.st", "bc.vc",
    "twitthis.com", "u.to", "j.mp", "buzurl.com", "urlborg.com",
})

# ---------------------------------------------------------------------------
# Keywords in URL path / query that suggest credential harvesting.
# Matched as whole words where possible; checked on decoded path.
# ---------------------------------------------------------------------------
LOGIN_KEYWORDS = [
    "login", "signin", "sign-in", "sign_in",
    "verify", "verification",
    "secure", "security",
    "update", "upgrade",
    "confirm", "confirmation",
    "account", "accounts",
    "banking", "bank",
    "password", "passwd", "pwd",
    "credential",
    "authenticate", "authentication", "auth",
    "reset", "recover", "recovery",
    "unlock", "reactivate",
    "invoice", "billing", "payment", "checkout",
    "suspended", "limited", "unusual",
]

# ---------------------------------------------------------------------------
# Percent-encoded sequences that, when decoded, form login/suspicious words.
# We also flag high-density encoding: >30 % of the path is percent-encoded.
# ---------------------------------------------------------------------------
ENCODED_SUSPICIOUS_THRESHOLD = 0.30   # fraction of path chars that are %XX

# ---------------------------------------------------------------------------
# URL structural limits
# ---------------------------------------------------------------------------
MAX_URL_LENGTH = 2083       # RFC / IE historic ceiling
MIN_URL_LENGTH = 4          # e.g. "a.bc"
LONG_URL_THRESHOLD = 75     # trigger long_url rule above this length
MAX_PATH_SEGMENTS = 5       # trigger excessive_path_depth above this count
MAX_SUBDOMAIN_LABELS = 3    # trigger excessive_subdomains above this count (labels beyond SLD+TLD)
MAX_PORT_VALUE = 65535      # sanity ceiling for port numbers

# Standard ports that are NOT considered suspicious
STANDARD_PORTS = frozenset({80, 443, 8080, 8443})

# ---------------------------------------------------------------------------
# Flask server limits
# ---------------------------------------------------------------------------
MAX_CONTENT_LENGTH = 2048   # bytes — request body ceiling
RATE_LIMIT_DEFAULT = "60 per minute"
RATE_LIMIT_ANALYZE = "30 per minute"

# ---------------------------------------------------------------------------
# App metadata
# ---------------------------------------------------------------------------
APP_NAME = "ThreatLens"
APP_VERSION = "2.0.0"
APP_DESCRIPTION = "Phishing URL & Website Threat Detector"
DISCLAIMER = (
    "ThreatLens performs heuristic string analysis only. "
    "It does not visit URLs, consult threat databases, or guarantee accuracy. "
    "A low score does not confirm a URL is safe — phishing sites can use HTTPS "
    "and appear structurally normal. A high score does not confirm a URL is "
    "malicious. Always verify through official channels and trusted security "
    "tools before taking any action."
)

# ---------------------------------------------------------------------------
# Sample URLs for demo panel
# ---------------------------------------------------------------------------
SAMPLE_URLS = [
    {
        "url": "https://google.com",
        "label": "Google (expected Low)",
        "risk_hint": "low",
    },
    {
        "url": "https://subdomain.legit-bank.com/account/summary",
        "label": "Bank subdomain (expected Medium)",
        "risk_hint": "medium",
    },
    {
        "url": "http://192.168.1.1/login",
        "label": "Raw IP login page (expected High)",
        "risk_hint": "high",
    },
    {
        "url": "https://secure-paypal-login.xyz/verify/account/update/confirm",
        "label": "Fake PayPal phish (expected High)",
        "risk_hint": "high",
    },
    {
        "url": "https://xn--pypal-4ve.com/signin",
        "label": "Punycode / IDN domain (expected High)",
        "risk_hint": "high",
    },
    {
        "url": "http://bit.ly/3xAbc12",
        "label": "URL shortener (expected Medium)",
        "risk_hint": "medium",
    },
]
