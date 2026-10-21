"""
analyzer.py — ThreatLens heuristic analysis engine.

════════════════════════════════════════════════════════════════════════════
SECURITY CONTRACT
────────────────────────────────────────────────────────────────────────────
This module performs STRING-ONLY analysis of a URL.

It MUST NEVER:
  • Make any outbound network connection.
  • Resolve hostnames via DNS or socket calls.
  • Follow redirects or download page content.
  • Import or call requests, urllib.request, socket, or any I/O library.
  • Execute any content derived from the submitted URL.

Violation of any of the above would turn the analyzer into an
SSRF-capable service — a critical security vulnerability.
════════════════════════════════════════════════════════════════════════════

Public API
──────────
normalise_url(raw: str) -> str
    Normalise whitespace and scheme casing; raise ValueError for
    structurally invalid input before full analysis.

analyze(url: str) -> dict
    Run all heuristic rules on a pre-validated URL string and return
    a fully-formed result dict ready for JSON serialisation.

    Raises ValueError if the URL is structurally unparseable.
    All other exceptions are caught internally and surfaced as
    indicator explanations, never as uncaught errors.
"""

import re
import ipaddress
from urllib.parse import urlparse, unquote

from config import (
    RISK_THRESHOLDS,
    RISK_LABELS,
    RISK_SUMMARIES,
    RISK_RECOMMENDATIONS,
    RULE_WEIGHTS,
    RULE_NAMES,
    SUSPICIOUS_TLDS,
    BRAND_KEYWORDS,
    URL_SHORTENERS,
    LOGIN_KEYWORDS,
    LONG_URL_THRESHOLD,
    MAX_PATH_SEGMENTS,
    MAX_SUBDOMAIN_LABELS,
    STANDARD_PORTS,
    ENCODED_SUSPICIOUS_THRESHOLD,
    DISCLAIMER,
)


# ---------------------------------------------------------------------------
# Pre-compiled patterns (compiled once at import time)
# ---------------------------------------------------------------------------

# Matches a percent-encoded triplet in a URL component
_RE_PCT_ENCODED = re.compile(r"%[0-9A-Fa-f]{2}")

# Matches any non-ASCII character (codepoint > 127)
_RE_NON_ASCII = re.compile(r"[^\x00-\x7F]")

# Matches a valid IPv4 address (used to distinguish from purely numeric labels)
_RE_IPV4 = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)

# Matches multiple consecutive hyphens that are NOT a punycode prefix
_RE_DOUBLE_HYPHEN = re.compile(r"(?<!xn)--")

# ---------------------------------------------------------------------------
# URL Normalisation
# ---------------------------------------------------------------------------

def normalise_url(raw: str) -> str:
    """
    Normalise a raw URL string before analysis.

    Steps
    -----
    1. Strip surrounding whitespace.
    2. Lowercase the scheme component only (preserves path casing for
       case-sensitive matching on real servers).
    3. Reject obviously non-URL strings (no "://" separator).

    Parameters
    ----------
    raw : str
        The raw URL string from the caller.

    Returns
    -------
    str
        Normalised URL string.

    Raises
    ------
    ValueError
        If ``raw`` is not a string, is empty after stripping, or lacks a
        scheme+authority structure entirely.
    """
    if not isinstance(raw, str):
        raise ValueError("URL must be a string.")

    url = raw.strip()

    if not url:
        raise ValueError("URL must not be empty.")

    # Locate the scheme separator
    sep = url.find("://")
    if sep == -1:
        raise ValueError(
            "URL does not contain a scheme separator '://'. "
            "Only absolute URLs with a scheme are supported."
        )

    scheme = url[:sep].lower()
    rest   = url[sep:]          # keeps "://<authority><path>..."

    return scheme + rest


# ---------------------------------------------------------------------------
# Internal result builder
# ---------------------------------------------------------------------------

def _make_indicator(rule_id: str, triggered: bool, explanation: str) -> dict:
    """
    Build a single indicator dict.

    Untriggered indicators record weight=0 so the frontend can display
    them as 'passed' checks without contributing to the score.
    """
    return {
        "id":          rule_id,
        "name":        RULE_NAMES[rule_id],
        "triggered":   triggered,
        "weight":      RULE_WEIGHTS[rule_id] if triggered else 0,
        "explanation": explanation,
    }


# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------

def _extract_port(netloc: str) -> int | None:
    """
    Safely extract an explicit port number from a netloc string.

    Handles:
    - Plain hostname:port        → "example.com:8080"
    - IPv6 with port             → "[::1]:9999"
    - IPv6 without port          → "[::1]"
    - Malformed port strings     → returns None
    - Out-of-range port numbers  → returns None
    """
    try:
        if netloc.startswith("["):
            # IPv6 literal: find closing bracket
            bracket_end = netloc.find("]")
            if bracket_end == -1:
                return None
            after_bracket = netloc[bracket_end + 1:]
            if after_bracket.startswith(":") and len(after_bracket) > 1:
                port_str = after_bracket[1:]
            else:
                return None
        else:
            parts = netloc.rsplit(":", 1)
            if len(parts) != 2:
                return None
            port_str = parts[1]

        if not port_str.isdigit():
            return None
        port = int(port_str)
        return port if 1 <= port <= 65535 else None
    except Exception:
        return None


def _registered_domain(hostname: str) -> str:
    """
    Return the registered domain (SLD + TLD) from a hostname.

    Examples
    --------
    "paypal.evil.com"  →  "evil.com"
    "example.com"      →  "example.com"
    "192.168.1.1"      →  "192.168.1.1"   (unchanged for IPs)
    """
    labels = hostname.lower().rstrip(".").split(".")
    if len(labels) >= 2:
        return ".".join(labels[-2:])
    return hostname.lower()


def _count_pct_encoded(s: str) -> int:
    """Count the number of percent-encoded triplets in a string."""
    return len(_RE_PCT_ENCODED.findall(s))


# ---------------------------------------------------------------------------
# Individual rule functions
# Each returns: (triggered: bool, explanation: str)
# Rule functions MUST NOT raise; use try/except internally.
# ---------------------------------------------------------------------------

def _rule_ip_address_host(hostname: str) -> tuple[bool, str]:
    """
    Trigger if the hostname is a raw IPv4 or IPv6 address.

    Both public and private ranges are flagged — legitimate web services
    virtually never embed raw IP addresses in user-facing links.
    """
    if not hostname:
        return False, "No host present to evaluate."

    # urlparse strips brackets for us; try the normalised hostname
    host = hostname.strip("[]")
    try:
        ipaddress.ip_address(host)
        version = ipaddress.ip_address(host).version
        return True, (
            f"The URL uses a raw IPv{version} address instead of a domain name. "
            "Legitimate services almost never embed bare IP addresses in links "
            "sent to users. This is a common characteristic of phishing pages "
            "hosted on compromised or ephemeral infrastructure."
        )
    except ValueError:
        return False, "The host is a standard domain name, not a raw IP address."


def _rule_at_in_authority(netloc: str) -> tuple[bool, str]:
    """
    Trigger if the URL authority contains an '@' character.

    RFC 3986 defines userinfo@host syntax.  Browsers follow the host
    portion but users see the full authority string, making this a
    classic visual deception technique:
        https://legit-bank.com@evil.com/
    would send the browser to evil.com, not legit-bank.com.
    """
    if "@" in netloc:
        # Extract what the browser would actually connect to
        real_host = netloc.split("@")[-1]
        fake_host = netloc.split("@")[0]
        return True, (
            f"The URL authority contains '@'. The browser connects to "
            f"'{real_host}', not '{fake_host}'. Attackers use this to make "
            "a malicious URL appear to belong to a trusted domain."
        )
    return False, "No '@' credential-injection pattern detected in the URL authority."


def _rule_excessive_subdomains(hostname: str) -> tuple[bool, str]:
    """
    Trigger if the hostname has more subdomain labels than MAX_SUBDOMAIN_LABELS
    beyond the registered domain (SLD + TLD).

    Example: a.b.c.d.example.com has 4 subdomain labels.
    """
    if not hostname:
        return False, "No host present to evaluate."
    labels = hostname.rstrip(".").split(".")
    # Labels beyond the registered domain (last 2 labels)
    subdomain_labels = max(0, len(labels) - 2)
    if subdomain_labels > MAX_SUBDOMAIN_LABELS:
        return True, (
            f"The domain has {subdomain_labels} subdomain label(s) beyond the "
            "registered domain. Phishing sites often stack subdomains to push "
            "the real (malicious) domain out of the visible URL bar and create "
            "a false sense of legitimacy."
        )
    return False, "The domain has a normal number of subdomain labels."


def _rule_suspicious_tld(hostname: str) -> tuple[bool, str]:
    """
    Trigger if the TLD is on the known-suspicious list.

    These TLDs are frequently abused because they are free, offer
    anonymous registration, or have historically poor abuse mitigation.
    """
    if not hostname:
        return False, "No host present to evaluate."
    lower = hostname.lower().rstrip(".")
    for tld in SUSPICIOUS_TLDS:
        if lower.endswith(tld):
            return True, (
                f"The domain uses the TLD '{tld}', which is frequently abused "
                "in phishing and spam campaigns. These TLDs are often chosen "
                "because they are free or have minimal registration requirements, "
                "making them attractive to threat actors."
            )
    return False, "The TLD is not on the high-risk abuse list."


def _rule_misleading_brand(hostname: str, path: str, query: str) -> tuple[bool, str]:
    """
    Trigger if a well-known brand keyword appears in the subdomain, path, or
    query string, but the registered domain (SLD+TLD) does not match the brand.

    This is the core impersonation pattern: paypal.evil.com or
    evil.com/paypal/login — the brand word creates false trust while the
    actual destination domain is attacker-controlled.
    """
    if not hostname:
        return False, "No host present to evaluate."

    hostname_lower = hostname.lower()
    path_lower = path.lower()
    query_lower = query.lower()
    reg_domain = _registered_domain(hostname_lower)

    # The SLD is the first label of the registered domain (e.g. "secure-paypal-login"
    # from "secure-paypal-login.xyz"). We extract it for brand-in-SLD checks.
    sld = reg_domain.split(".")[0] if "." in reg_domain else reg_domain

    for brand in BRAND_KEYWORDS:
        # Brand appears in subdomain labels (above the registered domain)
        brand_in_subdomain = (brand in hostname_lower) and (brand not in reg_domain)

        # Brand embedded in the SLD alongside other characters, e.g. "secure-paypal-login"
        # but not an exact brand SLD like "paypal.com"
        brand_in_sld = (brand in sld) and (sld != brand)

        brand_in_path  = brand in path_lower and brand not in reg_domain
        brand_in_query = brand in query_lower and brand not in reg_domain

        if brand_in_subdomain:
            return True, (
                f"The brand name '{brand}' appears in the subdomain, but the "
                f"registered domain is '{reg_domain}' — not a '{brand}' domain. "
                "This is a classic impersonation technique designed to make the "
                "URL appear to belong to a trusted service."
            )
        if brand_in_sld:
            return True, (
                f"The brand name '{brand}' is embedded within the registered "
                f"domain '{reg_domain}' alongside other words. Legitimate services "
                f"own the brand name as their exact domain — a domain like "
                f"'secure-{brand}-login' is a classic phishing impersonation pattern."
            )
        if brand_in_path or brand_in_query:
            location = "query string" if brand_in_query and not brand_in_path else "path"
            return True, (
                f"The brand name '{brand}' appears in the URL {location}, but the "
                f"registered domain is '{reg_domain}'. Placing a brand name in the "
                "path or query is a common tactic to add false legitimacy to a "
                "phishing URL."
            )
    return False, "No misleading brand keywords were detected in the URL."


def _rule_long_url(url: str) -> tuple[bool, str]:
    """
    Trigger if the full URL length exceeds LONG_URL_THRESHOLD characters.

    Excessively long URLs are used to:
    - Hide the real domain by pushing it past the visible portion of a browser bar.
    - Include encoded payloads or tracking parameters.
    - Confuse automated URL scanners with noise.
    """
    length = len(url)
    if length > LONG_URL_THRESHOLD:
        return True, (
            f"The URL is {length} characters long (threshold: {LONG_URL_THRESHOLD}). "
            "Excessively long URLs are often used to obscure the real destination, "
            "push the domain name out of a browser's visible address bar, or "
            "include obfuscated payloads."
        )
    return False, f"The URL length ({length} chars) is within normal bounds."


def _rule_excessive_path_depth(path: str) -> tuple[bool, str]:
    """
    Trigger if the decoded URL path has more than MAX_PATH_SEGMENTS non-empty segments.

    Deep path nesting creates an appearance of legitimacy
    (e.g. /account/secure/update/verify/confirm) while obscuring the actual
    destination.
    """
    segments = [s for s in path.split("/") if s]
    count = len(segments)
    if count > MAX_PATH_SEGMENTS:
        return True, (
            f"The URL path has {count} segments (threshold: {MAX_PATH_SEGMENTS}). "
            "Deeply nested paths are used to create a false sense of legitimacy "
            "or to bury the real landing page structure."
        )
    return False, f"The URL path depth ({count} segment(s)) is within normal bounds."


def _rule_special_chars_in_domain(hostname: str) -> tuple[bool, str]:
    """
    Trigger if the hostname contains suspicious special characters.

    Checks:
    - '%' in hostname: percent-encoding in a hostname bypasses filters.
    - Consecutive hyphens outside of a valid punycode prefix (xn--):
      may indicate visual domain spoofing.

    Note: '@' in the authority is handled by _rule_at_in_authority to avoid
    duplicate scoring.
    """
    if not hostname:
        return False, "No host present to evaluate."
    if "%" in hostname:
        return True, (
            "The hostname contains a percent-encoded character ('%'). "
            "Percent-encoding inside a hostname is non-standard and is used "
            "to bypass URL-based filters and security scanners."
        )
    # Check for consecutive hyphens not part of a legitimate punycode label
    # xn-- is valid; anything else with -- is suspicious
    for label in hostname.split("."):
        if "--" in label and not label.startswith("xn--"):
            return True, (
                f"The domain label '{label}' contains consecutive hyphens "
                "outside of a valid punycode (xn--) prefix. This pattern can "
                "be used for visual deception in lookalike domain attacks."
            )
    return False, "No deceptive special characters were found in the domain."


def _rule_http_scheme(scheme: str) -> tuple[bool, str]:
    """
    Trigger if the scheme is plain HTTP rather than HTTPS.

    Important caveat: HTTPS does NOT establish that a site is safe or
    legitimate — phishing sites routinely obtain valid TLS certificates.
    However, HTTP absence of encryption is itself a risk indicator,
    particularly for pages that solicit credentials.
    """
    if scheme == "http":
        return True, (
            "The URL uses plain HTTP, meaning traffic between the browser and "
            "server is unencrypted and can be intercepted. While HTTPS does not "
            "guarantee a site is safe, legitimate credential-collecting pages "
            "always use HTTPS."
        )
    # HTTPS detected — explain the caveat explicitly
    return False, (
        "The URL uses HTTPS. Note: HTTPS only encrypts the connection — it does "
        "not guarantee the site is legitimate or trustworthy. Phishing sites "
        "commonly obtain valid TLS certificates."
    )


def _rule_punycode_domain(hostname: str) -> tuple[bool, str]:
    """
    Trigger if the hostname contains a punycode-encoded label (xn--…).

    Punycode (RFC 3492) is the standard encoding for Internationalised
    Domain Names (IDN). Attackers use look-alike Unicode characters in
    domain names to impersonate trusted brands — a homograph attack.
    Example: аpple.com (Cyrillic 'а') encodes to xn--pple-43d.com.
    """
    if not hostname:
        return False, "No host present to evaluate."
    if "xn--" in hostname.lower():
        return True, (
            "The domain contains a punycode-encoded label (xn--…). "
            "This is used in IDN homograph attacks where visually similar "
            "Unicode characters impersonate a trusted domain. "
            "For example, 'аpple.com' (Cyrillic 'а') looks like 'apple.com' "
            "but resolves to a different domain."
        )
    return False, "No punycode / IDN encoding detected in the domain."


def _rule_numeric_subdomain(hostname: str) -> tuple[bool, str]:
    """
    Trigger if any subdomain label is entirely numeric (and not an IP address).

    Example: 12345.evil.com — a common pattern for dynamically generated
    phishing infrastructure where each campaign gets a unique numeric subdomain.
    Pure IP addresses are handled by _rule_ip_address_host.
    """
    if not hostname:
        return False, "No host present to evaluate."
    labels = hostname.rstrip(".").split(".")
    # Only check subdomain labels (everything except the last two: SLD + TLD)
    if len(labels) <= 2:
        return False, "No subdomain labels to evaluate."
    subdomains = labels[:-2]
    for label in subdomains:
        if label.isdigit():
            return True, (
                f"The subdomain '{label}' consists entirely of digits. "
                "Numeric subdomains are unusual for legitimate services and are "
                "a common pattern in dynamically generated phishing infrastructure."
            )
    return False, "No all-numeric subdomain labels detected."


def _rule_url_shortener(hostname: str) -> tuple[bool, str]:
    """
    Trigger if the host is a known URL-shortening service.

    Shortened URLs mask the real destination domain, which prevents users
    and security tools from evaluating the actual target before clicking.
    This is frequently abused in phishing email campaigns.
    """
    if not hostname:
        return False, "No host present to evaluate."
    # Normalise: lowercase, strip leading 'www.'
    host_lower = hostname.lower()
    candidates = {host_lower, host_lower.removeprefix("www.")}
    shorteners_lower = {s.lower() for s in URL_SHORTENERS}
    for candidate in candidates:
        if candidate in shorteners_lower:
            return True, (
                f"'{hostname}' is a known URL shortening service. "
                "Shortened URLs hide the real destination, allowing attackers "
                "to bypass security scanners and prevent users from inspecting "
                "the actual target domain before clicking."
            )
    return False, "The host is not a known URL shortener."


def _rule_path_has_login_keyword(path: str, query: str) -> tuple[bool, str]:
    """
    Trigger if the decoded path or query string contains credential-harvesting keywords.

    Keywords are checked on the percent-decoded string to catch encodings
    like %6C%6F%67%69%6E (= 'login').
    """
    combined = (path + " " + query).lower()
    for keyword in LOGIN_KEYWORDS:
        if keyword in combined:
            return True, (
                f"The URL contains the keyword '{keyword}', which is commonly "
                "found in phishing pages designed to harvest credentials. "
                "Note: many legitimate sites also use these keywords — this "
                "indicator is most meaningful when combined with others."
            )
    return False, "No credential-harvesting keywords detected in the path or query."


def _rule_double_slash_redirect(url: str, scheme: str) -> tuple[bool, str]:
    """
    Trigger if the URL path component contains '//' (after the scheme).

    This pattern exploits open redirect vulnerabilities or parser
    inconsistencies: https://trusted.com//evil.com/page may behave
    differently across browsers and security tools.
    """
    # Skip past scheme://
    after_scheme = url[len(scheme) + 3:]
    if "//" in after_scheme:
        return True, (
            "The URL path contains '//' after the scheme. "
            "This pattern is used to exploit open redirect vulnerabilities or "
            "confuse URL parsers into treating part of the path as a host."
        )
    return False, "No double-slash redirect-abuse pattern detected."


def _rule_port_in_url(netloc: str) -> tuple[bool, str]:
    """
    Trigger if an explicit, non-standard port number is present.

    Standard ports (80, 443, 8080, 8443) are expected and not flagged.
    Unusual ports suggest the server is not a standard web server,
    which is uncommon for legitimate sites serving user-facing content.
    """
    port = _extract_port(netloc)
    if port is not None and port not in STANDARD_PORTS:
        return True, (
            f"The URL specifies port {port}, which is outside the set of "
            "commonly used web ports (80, 443, 8080, 8443). Legitimate sites "
            "serving user-facing content rarely use non-standard ports."
        )
    return False, "No non-standard port detected in the URL."


def _rule_suspicious_encoding(path: str, query: str) -> tuple[bool, str]:
    """
    Trigger if the URL path or query string shows signs of encoding-based
    obfuscation.

    Two sub-checks:
    1. Decoded path/query contains login keywords that were percent-encoded
       in the original — indicates deliberate attempt to bypass keyword filters.
    2. High density of percent-encoded characters: more than
       ENCODED_SUSPICIOUS_THRESHOLD of the path/query characters are %XX
       triplets (not counting the % and hex digits themselves).
    """
    combined_raw = path + query

    # Check 1: keyword visible only after decoding
    decoded_combined = unquote(combined_raw).lower()
    raw_combined_lower = combined_raw.lower()
    for keyword in LOGIN_KEYWORDS:
        if keyword in decoded_combined and keyword not in raw_combined_lower:
            return True, (
                f"The keyword '{keyword}' is hidden inside percent-encoded "
                "characters. This is a deliberate obfuscation technique used to "
                "bypass URL-based phishing filters while preserving the ability "
                "to harvest credentials when the page loads."
            )

    # Check 2: high encoding density
    if len(combined_raw) > 0:
        pct_triplets = _count_pct_encoded(combined_raw)
        # Each triplet is 3 chars (%XX); count them as encoded chars
        encoded_chars = pct_triplets * 3
        density = encoded_chars / len(combined_raw)
        if density >= ENCODED_SUSPICIOUS_THRESHOLD:
            return True, (
                f"{pct_triplets} percent-encoded sequences were found, "
                f"representing {density:.0%} of the path/query string. "
                "A high density of percent-encoding in a URL is unusual for "
                "legitimate sites and is a common obfuscation technique."
            )

    return False, "No suspicious percent-encoding patterns detected."


def _rule_unicode_in_domain(hostname: str) -> tuple[bool, str]:
    """
    Trigger if the hostname contains non-ASCII (Unicode) characters that are
    NOT expressed through punycode encoding.

    Modern URL parsers (including Python's urllib) can accept raw Unicode in
    hostnames.  This rule catches homograph attacks that rely on the browser
    silently accepting a Unicode hostname without encoding it to xn-- form.

    Example: 'gооgle.com' (Cyrillic о, о) may parse as a valid hostname
    without triggering the punycode rule.
    """
    if not hostname:
        return False, "No host present to evaluate."
    if _RE_NON_ASCII.search(hostname):
        # Find the offending characters for the explanation
        bad_chars = set(_RE_NON_ASCII.findall(hostname))
        bad_repr = ", ".join(
            f"U+{ord(c):04X} ('{c}')" for c in sorted(bad_chars)
        )
        return True, (
            f"The domain contains non-ASCII character(s): {bad_repr}. "
            "Non-ASCII characters in domain names are used in homograph attacks "
            "where visually similar Unicode characters impersonate a trusted brand. "
            "This is dangerous because the deception is often invisible to the "
            "naked eye."
        )
    return False, "The domain contains only standard ASCII characters."


# ---------------------------------------------------------------------------
# Score → risk level classifier
# ---------------------------------------------------------------------------

def _classify(score: int) -> str:
    """Return the risk level string for a given numeric score."""
    for level, (low, high) in RISK_THRESHOLDS.items():
        if low <= score <= high:
            return level
    return "high"   # failsafe: anything outside defined bands is high


# ---------------------------------------------------------------------------
# Deduplication guard
# ---------------------------------------------------------------------------

def _deduplicate(indicators: list[dict]) -> list[dict]:
    """
    Ensure each rule_id appears at most once in the indicator list.

    The analysis pipeline is designed to produce exactly one indicator per
    rule, so this is a defensive guard rather than normal operation.
    If a duplicate is somehow produced (e.g. during future refactoring),
    the first occurrence is kept and subsequent ones are discarded so the
    score cannot be inflated by the same finding being counted twice.
    """
    seen: set[str] = set()
    deduped: list[dict] = []
    for ind in indicators:
        if ind["id"] not in seen:
            seen.add(ind["id"])
            deduped.append(ind)
    return deduped


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def analyze(url: str) -> dict:
    """
    Analyse a URL string for phishing indicators.

    This is the single entry point for analysis.  It:
    1. Parses the URL safely with stdlib urlparse.
    2. Runs every rule function.
    3. Deduplicates results.
    4. Sums triggered weights (clamped to [0, 100]).
    5. Classifies the risk level.
    6. Returns a structured result dict.

    Parameters
    ----------
    url : str
        A URL string that has already been validated by the caller
        (scheme is http or https, netloc is non-empty).
        The ``normalise_url`` helper should be called first.

    Returns
    -------
    dict with keys:
        url_display      — sanitised URL string safe for display
        score            — integer 0–100
        risk_level       — "low" | "medium" | "high"
        risk_label       — human-readable label
        summary          — prose summary of the risk assessment
        indicators       — list of indicator dicts (all rules, triggered or not)
        triggered_count  — number of triggered indicators
        max_possible_score — sum of all rule weights (for UI progress bars)
        recommendations  — list of recommended action strings
        disclaimer       — mandatory disclaimer text

    Raises
    ------
    ValueError
        If the URL cannot be parsed at all.  Route handlers catch this.
    """
    # -- Parse ----------------------------------------------------------------
    try:
        parsed = urlparse(url)
    except Exception as exc:
        raise ValueError(f"URL could not be parsed: {exc}") from exc

    scheme   = (parsed.scheme   or "").lower()
    netloc   = (parsed.netloc   or "")
    hostname = (parsed.hostname or "")
    path     = (parsed.path     or "")
    query    = (parsed.query    or "")

    # Decode percent-encoding for content-level checks
    path_decoded  = unquote(path)
    query_decoded = unquote(query)

    # -- Run rules ------------------------------------------------------------
    # Each call returns a completed indicator dict.
    # Rules are evaluated independently; none calls another rule.
    raw_indicators = [
        _make_indicator(
            "ip_address_host",
            *_rule_ip_address_host(hostname)
        ),
        _make_indicator(
            "at_in_authority",
            *_rule_at_in_authority(netloc)
        ),
        _make_indicator(
            "excessive_subdomains",
            *_rule_excessive_subdomains(hostname)
        ),
        _make_indicator(
            "suspicious_tld",
            *_rule_suspicious_tld(hostname)
        ),
        _make_indicator(
            "misleading_brand",
            *_rule_misleading_brand(hostname, path_decoded, query_decoded)
        ),
        _make_indicator(
            "long_url",
            *_rule_long_url(url)
        ),
        _make_indicator(
            "excessive_path_depth",
            *_rule_excessive_path_depth(path_decoded)
        ),
        _make_indicator(
            "special_chars_in_domain",
            *_rule_special_chars_in_domain(hostname)
        ),
        _make_indicator(
            "http_scheme",
            *_rule_http_scheme(scheme)
        ),
        _make_indicator(
            "punycode_domain",
            *_rule_punycode_domain(hostname)
        ),
        _make_indicator(
            "numeric_subdomain",
            *_rule_numeric_subdomain(hostname)
        ),
        _make_indicator(
            "url_shortener",
            *_rule_url_shortener(hostname)
        ),
        _make_indicator(
            "path_has_login_keyword",
            *_rule_path_has_login_keyword(path_decoded, query_decoded)
        ),
        _make_indicator(
            "double_slash_redirect",
            *_rule_double_slash_redirect(url, scheme)
        ),
        _make_indicator(
            "port_in_url",
            *_rule_port_in_url(netloc)
        ),
        _make_indicator(
            "suspicious_encoding",
            *_rule_suspicious_encoding(path, query)
        ),
        _make_indicator(
            "unicode_in_domain",
            *_rule_unicode_in_domain(hostname)
        ),
    ]

    # -- Deduplicate ----------------------------------------------------------
    indicators = _deduplicate(raw_indicators)

    # -- Score ----------------------------------------------------------------
    raw_score = sum(ind["weight"] for ind in indicators)
    score = min(max(raw_score, 0), 100)

    # -- Classify -------------------------------------------------------------
    risk_level = _classify(score)

    # -- Sanitise display URL -------------------------------------------------
    # Strip any userinfo (credentials) from the display string.
    # re.sub replaces everything up to and including the last '@' in netloc.
    safe_netloc = re.sub(r"^[^@]*@", "", netloc)
    display_url = parsed._replace(netloc=safe_netloc).geturl()

    # -- Metadata -------------------------------------------------------------
    triggered_count    = sum(1 for ind in indicators if ind["triggered"])
    max_possible_score = sum(RULE_WEIGHTS.values())

    return {
        "url_display":        display_url,
        "score":              score,
        "risk_level":         risk_level,
        "risk_label":         RISK_LABELS[risk_level],
        "summary":            RISK_SUMMARIES[risk_level],
        "indicators":         indicators,
        "triggered_count":    triggered_count,
        "max_possible_score": max_possible_score,
        "recommendations":    RISK_RECOMMENDATIONS[risk_level],
        "disclaimer":         DISCLAIMER,
    }
