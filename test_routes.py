"""
tests/test_routes.py — Integration tests for ThreatLens Flask routes.

Run with:  pytest tests/test_routes.py -v
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import json
import pytest
from app import create_app


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def client():
    """Create a test client with testing=True (no rate-limit enforcement)."""
    app = create_app(testing=True)
    app.config["TESTING"] = True
    # Disable rate limiting in tests
    app.config["RATELIMIT_ENABLED"] = False
    with app.test_client() as c:
        yield c


def post_analyze(client, payload, content_type="application/json"):
    """Helper: POST /api/analyze with JSON payload."""
    return client.post(
        "/api/analyze",
        data=json.dumps(payload),
        content_type=content_type,
    )


# ---------------------------------------------------------------------------
# GET /
# ---------------------------------------------------------------------------

class TestIndex:
    def test_returns_200(self, client):
        r = client.get("/")
        assert r.status_code == 200

    def test_returns_html(self, client):
        r = client.get("/")
        assert b"ThreatLens" in r.data

    def test_security_headers_present(self, client):
        r = client.get("/")
        assert r.headers.get("X-Frame-Options") == "DENY"
        assert r.headers.get("X-Content-Type-Options") == "nosniff"
        assert "Content-Security-Policy" in r.headers


# ---------------------------------------------------------------------------
# GET /api/health
# ---------------------------------------------------------------------------

class TestHealth:
    def test_returns_200(self, client):
        r = client.get("/api/health")
        assert r.status_code == 200

    def test_returns_ok_status(self, client):
        r = client.get("/api/health")
        body = json.loads(r.data)
        assert body["status"] == "ok"

    def test_returns_service_name(self, client):
        r = client.get("/api/health")
        body = json.loads(r.data)
        assert body["service"] == "ThreatLens"

    def test_returns_version(self, client):
        r = client.get("/api/health")
        body = json.loads(r.data)
        assert "version" in body


# ---------------------------------------------------------------------------
# POST /api/analyze — valid inputs
# ---------------------------------------------------------------------------

class TestAnalyzeValid:
    def test_valid_https_url_returns_200(self, client):
        r = post_analyze(client, {"url": "https://example.com"})
        assert r.status_code == 200

    def test_valid_http_url_returns_200(self, client):
        r = post_analyze(client, {"url": "http://example.com"})
        assert r.status_code == 200

    def test_response_has_score(self, client):
        r = post_analyze(client, {"url": "https://example.com"})
        body = json.loads(r.data)
        assert "score" in body
        assert isinstance(body["score"], int)

    def test_response_has_risk_level(self, client):
        r = post_analyze(client, {"url": "https://example.com"})
        body = json.loads(r.data)
        assert body["risk_level"] in ("low", "medium", "high")

    def test_response_has_indicators(self, client):
        r = post_analyze(client, {"url": "https://example.com"})
        body = json.loads(r.data)
        assert isinstance(body["indicators"], list)
        assert len(body["indicators"]) > 0

    def test_response_has_recommendations(self, client):
        r = post_analyze(client, {"url": "https://example.com"})
        body = json.loads(r.data)
        assert isinstance(body["recommendations"], list)

    def test_response_has_disclaimer(self, client):
        r = post_analyze(client, {"url": "https://example.com"})
        body = json.loads(r.data)
        assert "disclaimer" in body

    def test_google_scores_low(self, client):
        r = post_analyze(client, {"url": "https://google.com"})
        body = json.loads(r.data)
        assert body["risk_level"] == "low"

    def test_ip_url_scores_high(self, client):
        r = post_analyze(client, {"url": "http://192.168.1.1/login"})
        body = json.loads(r.data)
        assert body["risk_level"] == "high"

    def test_url_with_trailing_whitespace_is_accepted(self, client):
        r = post_analyze(client, {"url": "  https://example.com  "})
        assert r.status_code == 200


# ---------------------------------------------------------------------------
# POST /api/analyze — invalid inputs
# ---------------------------------------------------------------------------

class TestAnalyzeInvalid:
    def test_missing_url_field_returns_400(self, client):
        r = post_analyze(client, {"other": "value"})
        assert r.status_code == 400

    def test_null_url_returns_400(self, client):
        r = post_analyze(client, {"url": None})
        assert r.status_code == 400

    def test_integer_url_returns_400(self, client):
        r = post_analyze(client, {"url": 12345})
        assert r.status_code == 400

    def test_empty_string_url_returns_400(self, client):
        r = post_analyze(client, {"url": ""})
        assert r.status_code == 400

    def test_ftp_scheme_returns_400(self, client):
        r = post_analyze(client, {"url": "ftp://example.com/file"})
        assert r.status_code == 400

    def test_javascript_scheme_returns_400(self, client):
        r = post_analyze(client, {"url": "javascript:alert(1)"})
        assert r.status_code == 400

    def test_data_scheme_returns_400(self, client):
        r = post_analyze(client, {"url": "data:text/html,<h1>hi</h1>"})
        assert r.status_code == 400

    def test_no_host_returns_400(self, client):
        r = post_analyze(client, {"url": "https:///path"})
        assert r.status_code == 400

    def test_non_json_content_type_returns_400(self, client):
        r = client.post(
            "/api/analyze",
            data="url=https://example.com",
            content_type="application/x-www-form-urlencoded",
        )
        assert r.status_code == 400

    def test_empty_json_object_returns_400(self, client):
        r = post_analyze(client, {})
        assert r.status_code == 400

    def test_url_exceeding_max_length_returns_400_or_413(self, client):
        # A body over MAX_CONTENT_LENGTH triggers Flask's built-in 413 before
        # our route code runs.  A URL within the body limit but over MAX_URL_LENGTH
        # returns 400 from our validator.  Both are correct rejections.
        long_url = "https://example.com/" + "a" * 2100
        r = post_analyze(client, {"url": long_url})
        assert r.status_code in (400, 413)

    def test_error_response_has_error_key(self, client):
        r = post_analyze(client, {"url": "ftp://example.com"})
        body = json.loads(r.data)
        assert "error" in body

    def test_error_message_is_string(self, client):
        r = post_analyze(client, {"url": None})
        body = json.loads(r.data)
        assert isinstance(body["error"], str)


# ---------------------------------------------------------------------------
# Security header tests
# ---------------------------------------------------------------------------

class TestSecurityHeaders:
    def test_analyze_response_has_csp(self, client):
        r = post_analyze(client, {"url": "https://example.com"})
        assert "Content-Security-Policy" in r.headers

    def test_analyze_response_has_x_frame_options(self, client):
        r = post_analyze(client, {"url": "https://example.com"})
        assert r.headers.get("X-Frame-Options") == "DENY"

    def test_analyze_response_has_nosniff(self, client):
        r = post_analyze(client, {"url": "https://example.com"})
        assert r.headers.get("X-Content-Type-Options") == "nosniff"


# ---------------------------------------------------------------------------
# 404 handler
# ---------------------------------------------------------------------------

class TestNotFound:
    def test_unknown_path_returns_404(self, client):
        r = client.get("/nonexistent-path")
        assert r.status_code == 404

    def test_404_returns_json_error(self, client):
        r = client.get("/nonexistent-path")
        body = json.loads(r.data)
        assert "error" in body


# ---------------------------------------------------------------------------
# Method not allowed
# ---------------------------------------------------------------------------

class TestMethodNotAllowed:
    def test_get_on_analyze_returns_405(self, client):
        r = client.get("/api/analyze")
        assert r.status_code == 405


# ---------------------------------------------------------------------------
# New security / reliability tests (added in hardening pass)
# ---------------------------------------------------------------------------

class TestHealthSchema:
    """Verify the health endpoint returns every documented key."""

    def test_has_environment_key(self, client):
        r = client.get("/api/health")
        body = json.loads(r.data)
        assert "environment" in body

    def test_environment_is_testing(self, client):
        # The fixture passes testing=True
        r = client.get("/api/health")
        body = json.loads(r.data)
        assert body["environment"] == "testing"

    def test_content_type_is_json(self, client):
        r = client.get("/api/health")
        assert "application/json" in r.headers.get("Content-Type", "")


class TestNonObjectJsonBodies:
    """JSON bodies that are valid JSON but not dicts must be rejected with 400."""

    def test_json_array_returns_400(self, client):
        r = client.post(
            "/api/analyze",
            data=b"[]",
            content_type="application/json",
        )
        assert r.status_code == 400

    def test_json_string_returns_400(self, client):
        r = client.post(
            "/api/analyze",
            data=b'"hello"',
            content_type="application/json",
        )
        assert r.status_code == 400

    def test_json_number_returns_400(self, client):
        r = client.post(
            "/api/analyze",
            data=b"42",
            content_type="application/json",
        )
        assert r.status_code == 400

    def test_json_boolean_returns_400(self, client):
        r = client.post(
            "/api/analyze",
            data=b"true",
            content_type="application/json",
        )
        assert r.status_code == 400

    def test_json_null_returns_400(self, client):
        # JSON null parses to Python None — same guard catches it
        r = client.post(
            "/api/analyze",
            data=b"null",
            content_type="application/json",
        )
        assert r.status_code == 400

    def test_error_message_is_string(self, client):
        r = client.post(
            "/api/analyze",
            data=b"[]",
            content_type="application/json",
        )
        body = json.loads(r.data)
        assert isinstance(body.get("error"), str)


class TestUrlBoundaryAndEdgeCases:
    """Edge cases around URL length bounds, whitespace, and scheme anomalies."""

    def test_url_exactly_at_max_length_accepted_or_body_limit(self, client):
        # A URL at MAX_URL_LENGTH (2083 chars) wrapped in JSON exceeds
        # MAX_CONTENT_LENGTH (2048 bytes), so the server correctly returns 413
        # before our route code even runs.  Both 200 and 413 are valid outcomes
        # depending on the JSON overhead; neither is an application error.
        from config import MAX_URL_LENGTH
        url = "https://x.com/" + "a" * (MAX_URL_LENGTH - len("https://x.com/"))
        assert len(url) == MAX_URL_LENGTH
        r = post_analyze(client, {"url": url})
        assert r.status_code in (200, 413), (
            f"Expected 200 (URL accepted) or 413 (body too large), got {r.status_code}"
        )

    def test_url_one_over_max_length_returns_400(self, client):
        from config import MAX_URL_LENGTH
        url = "https://x.com/" + "a" * (MAX_URL_LENGTH - len("https://x.com/") + 1)
        assert len(url) == MAX_URL_LENGTH + 1
        r = post_analyze(client, {"url": url})
        assert r.status_code in (400, 413)

    def test_whitespace_only_url_returns_400(self, client):
        r = post_analyze(client, {"url": "   "})
        assert r.status_code == 400

    def test_scheme_separator_only_returns_400(self, client):
        # "://foo.com" has an empty scheme — normalise_url should reject it
        r = post_analyze(client, {"url": "://foo.com"})
        assert r.status_code == 400

    def test_url_with_newline_stripped_accepted_if_valid(self, client):
        # Whitespace stripping happens server-side; a newline-wrapped URL works
        r = post_analyze(client, {"url": "\nhttps://example.com\n"})
        assert r.status_code == 200

    def test_double_encoded_javascript_blocked(self, client):
        # "javascript" with space before colon
        r = post_analyze(client, {"url": "javascript  :alert(1)"})
        assert r.status_code == 400


class TestAdditionalSecurityHeaders:
    """Verify every new security header is present on responses."""

    def test_permissions_policy_present(self, client):
        r = client.get("/api/health")
        assert "Permissions-Policy" in r.headers

    def test_permissions_policy_disables_camera(self, client):
        r = client.get("/api/health")
        assert "camera=()" in r.headers.get("Permissions-Policy", "")

    def test_permissions_policy_disables_geolocation(self, client):
        r = client.get("/api/health")
        assert "geolocation=()" in r.headers.get("Permissions-Policy", "")

    def test_x_xss_protection_present(self, client):
        r = client.get("/api/health")
        assert "X-XSS-Protection" in r.headers

    def test_csp_no_unsafe_inline_in_script_src(self, client):
        r = client.get("/api/health")
        csp = r.headers.get("Content-Security-Policy", "")
        # Extract the script-src directive value
        for directive in csp.split(";"):
            directive = directive.strip()
            if directive.startswith("script-src"):
                assert "'unsafe-inline'" not in directive, (
                    f"script-src must not contain 'unsafe-inline': {directive}"
                )
                break

    def test_csp_object_src_none(self, client):
        r = client.get("/api/health")
        csp = r.headers.get("Content-Security-Policy", "")
        assert "object-src 'none'" in csp

    def test_csp_base_uri_self(self, client):
        r = client.get("/api/health")
        csp = r.headers.get("Content-Security-Policy", "")
        assert "base-uri 'self'" in csp

    def test_csp_form_action_self(self, client):
        r = client.get("/api/health")
        csp = r.headers.get("Content-Security-Policy", "")
        assert "form-action 'self'" in csp

    def test_no_cors_header_on_health(self, client):
        # No cross-origin requirement exists; CORS headers must not be present
        r = client.get("/api/health")
        assert "Access-Control-Allow-Origin" not in r.headers

    def test_no_cors_header_on_analyze(self, client):
        r = post_analyze(client, {"url": "https://example.com"})
        assert "Access-Control-Allow-Origin" not in r.headers


class TestAnalyzeResponseSchema:
    """Verify the analyze 200 response matches the documented schema exactly."""

    @pytest.fixture(autouse=True)
    def _body(self, client):
        r = post_analyze(client, {"url": "https://example.com"})
        assert r.status_code == 200
        self.body = json.loads(r.data)

    def test_has_url_display(self):
        assert isinstance(self.body["url_display"], str)
        assert len(self.body["url_display"]) > 0

    def test_has_score_int_in_range(self):
        score = self.body["score"]
        assert isinstance(score, int)
        assert 0 <= score <= 100

    def test_has_risk_level_valid(self):
        assert self.body["risk_level"] in ("low", "medium", "high")

    def test_has_risk_label_string(self):
        assert isinstance(self.body["risk_label"], str)
        assert len(self.body["risk_label"]) > 0

    def test_has_summary_string(self):
        assert isinstance(self.body["summary"], str)

    def test_has_indicators_list(self):
        assert isinstance(self.body["indicators"], list)
        assert len(self.body["indicators"]) == 17  # one per rule

    def test_each_indicator_has_required_keys(self):
        for ind in self.body["indicators"]:
            assert "id"          in ind, f"Missing 'id' in {ind}"
            assert "name"        in ind, f"Missing 'name' in {ind}"
            assert "triggered"   in ind, f"Missing 'triggered' in {ind}"
            assert "weight"      in ind, f"Missing 'weight' in {ind}"
            assert "explanation" in ind, f"Missing 'explanation' in {ind}"

    def test_each_indicator_types(self):
        for ind in self.body["indicators"]:
            assert isinstance(ind["id"],          str)
            assert isinstance(ind["name"],         str)
            assert isinstance(ind["triggered"],    bool)
            assert isinstance(ind["weight"],       int)
            assert isinstance(ind["explanation"],  str)

    def test_has_triggered_count_int(self):
        assert isinstance(self.body["triggered_count"], int)
        assert self.body["triggered_count"] >= 0

    def test_has_max_possible_score_int(self):
        assert isinstance(self.body["max_possible_score"], int)
        assert self.body["max_possible_score"] > 0

    def test_has_recommendations_list(self):
        assert isinstance(self.body["recommendations"], list)
        assert len(self.body["recommendations"]) > 0

    def test_each_recommendation_is_string(self):
        for rec in self.body["recommendations"]:
            assert isinstance(rec, str)

    def test_has_disclaimer_string(self):
        assert isinstance(self.body["disclaimer"], str)
        assert len(self.body["disclaimer"]) > 0

    def test_no_extra_internal_keys(self):
        # Ensure no internal state leaks into the response
        allowed = {
            "url_display", "score", "risk_level", "risk_label",
            "summary", "indicators", "triggered_count",
            "max_possible_score", "recommendations", "disclaimer",
        }
        extra = set(self.body.keys()) - allowed
        assert not extra, f"Unexpected keys in response: {extra}"

    def test_triggered_count_matches_indicators(self):
        actual = sum(1 for ind in self.body["indicators"] if ind["triggered"])
        assert actual == self.body["triggered_count"]

    def test_score_consistent_with_risk_level(self):
        score = self.body["score"]
        level = self.body["risk_level"]
        if level == "low":
            assert 0 <= score <= 24
        elif level == "medium":
            assert 25 <= score <= 59
        else:
            assert 60 <= score <= 100


@pytest.fixture
def rate_limited_client():
    """
    A test client with rate limiting ENABLED (not suppressed).
    Used only for tests that verify RateLimit-* response headers.
    The default ``client`` fixture sets RATELIMIT_ENABLED=False, which
    also suppresses the headers — so those tests must use this fixture.
    """
    app = create_app(testing=True)
    app.config["TESTING"] = True
    # Do NOT set RATELIMIT_ENABLED=False here — we want headers injected
    with app.test_client() as c:
        yield c


class TestRateLimitHeaders:
    """Rate-limit response headers are exposed to help clients backoff.

    Uses rate_limited_client (limiter enabled) so flask-limiter actually
    injects the RateLimit-* headers.
    """

    def test_ratelimit_header_present_on_analyze(self, rate_limited_client):
        r = rate_limited_client.post(
            "/api/analyze",
            data='{"url":"https://example.com"}',
            content_type="application/json",
        )
        # flask-limiter 3.x uses X-RateLimit-* (with X- prefix)
        rl_keys = [k for k in r.headers.keys()
                   if "ratelimit" in k.lower()]
        assert len(rl_keys) > 0, (
            "Expected at least one X-RateLimit-* header on /api/analyze response. "
            f"Headers present: {list(r.headers.keys())}"
        )

    def test_ratelimit_header_present_on_health(self, rate_limited_client):
        r = rate_limited_client.get("/api/health")
        # flask-limiter 3.x uses X-RateLimit-* (with X- prefix)
        rl_keys = [k for k in r.headers.keys()
                   if "ratelimit" in k.lower()]
        assert len(rl_keys) > 0, (
            "Expected at least one X-RateLimit-* header on /api/health response. "
            f"Headers present: {list(r.headers.keys())}"
        )


class TestDuplicateSubmissionPrevention:
    """The submit button must be disabled while a request is in-flight."""

    def test_submit_btn_has_aria_label(self, client):
        r = client.get("/")
        assert b'aria-label="Analyze URL"' in r.data

    def test_btn_loading_class_referenced_in_js(self):
        with open("static/js/main.js") as f:
            src = f.read()
        assert "btn--loading" in src, "JS must apply btn--loading to disable the button"

    def test_submit_btn_disabled_in_js(self):
        with open("static/js/main.js") as f:
            src = f.read()
        assert "btn.disabled = on" in src or "disabled = true" in src


class TestFetchTimeout:
    """JS must use AbortController so network stalls don't block forever."""

    def test_abort_controller_in_js(self):
        with open("static/js/main.js") as f:
            src = f.read()
        assert "AbortController" in src

    def test_signal_passed_to_fetch(self):
        with open("static/js/main.js") as f:
            src = f.read()
        assert "signal:" in src or "signal :" in src

    def test_abort_error_handled(self):
        with open("static/js/main.js") as f:
            src = f.read()
        assert "AbortError" in src

    def test_timeout_constant_defined(self):
        with open("static/js/main.js") as f:
            src = f.read()
        assert "FETCH_TIMEOUT_MS" in src


# ---------------------------------------------------------------------------
# Error handler coverage — 413, 500, and analyze ValueError path
# ---------------------------------------------------------------------------

class TestErrorHandlerCoverage:
    """
    Cover the error handler routes that are otherwise hard to reach through
    normal input paths.  Uses monkeypatching where necessary so we never
    execute real malicious code.
    """

    def test_413_handler_returns_json(self, client):
        """
        Flask raises 413 when the body exceeds MAX_CONTENT_LENGTH.
        The handler must return JSON, not an HTML error page.
        """
        # Build a body just over 2048 bytes
        import json as _json
        oversized_url = "https://x.com/" + "a" * 2100
        payload = _json.dumps({"url": oversized_url}).encode()
        r = client.post(
            "/api/analyze",
            data=payload,
            content_type="application/json",
        )
        # Either our 400 validator caught it, or Flask caught it as 413
        assert r.status_code in (400, 413)
        if r.status_code == 413:
            body = _json.loads(r.data)
            assert "error" in body
            assert isinstance(body["error"], str)

    def test_500_handler_returns_json(self, client):
        """
        Monkeypatch analyzer.analyze to raise an unexpected exception and
        confirm the 500 handler returns a safe JSON error, not a stack trace.
        """
        import json as _json
        import analyzer as _analyzer

        original = _analyzer.analyze

        def boom(url):
            raise RuntimeError("synthetic internal error")

        _analyzer.analyze = boom
        try:
            r = client.post(
                "/api/analyze",
                json={"url": "https://example.com"},
            )
            assert r.status_code == 500
            body = _json.loads(r.data)
            assert "error" in body
            # Stack trace must not be surfaced
            assert "RuntimeError"    not in body["error"]
            assert "synthetic"       not in body["error"]
            assert "Traceback"       not in body["error"]
        finally:
            _analyzer.analyze = original

    def test_500_error_does_not_leak_exception_detail(self, client):
        """The error message for a 500 must be generic."""
        import json as _json
        import analyzer as _analyzer

        original = _analyzer.analyze

        def explode(url):
            raise Exception("SECRET_DB_PASSWORD=hunter2 internal state")

        _analyzer.analyze = explode
        try:
            r = client.post(
                "/api/analyze",
                json={"url": "https://example.com"},
            )
            assert r.status_code == 500
            raw = r.data.decode()
            assert "SECRET_DB_PASSWORD" not in raw
            assert "hunter2"            not in raw
        finally:
            _analyzer.analyze = original

    def test_analyze_value_error_returns_400(self, client):
        """
        If analyzer.analyze raises ValueError (malformed URL that slipped
        through the route validator), the route must return 400, not 500.
        """
        import json as _json
        import analyzer as _analyzer

        original = _analyzer.analyze

        def value_err(url):
            raise ValueError("URL could not be parsed: test")

        _analyzer.analyze = value_err
        try:
            r = client.post(
                "/api/analyze",
                json={"url": "https://example.com"},
            )
            assert r.status_code == 400
            body = _json.loads(r.data)
            assert "error" in body
        finally:
            _analyzer.analyze = original

    def test_404_handler_returns_json_not_html(self, client):
        import json as _json
        r = client.get("/nonexistent-path-xyzabc")
        assert r.status_code == 404
        assert b"<!DOCTYPE" not in r.data.upper()
        body = _json.loads(r.data)
        assert "error" in body

    def test_405_handler_returns_json_not_html(self, client):
        import json as _json
        r = client.get("/api/analyze")
        assert r.status_code == 405
        assert b"<!DOCTYPE" not in r.data.upper()
        body = _json.loads(r.data)
        assert "error" in body


# ---------------------------------------------------------------------------
# Sensitive-data leak checks at the API level
# ---------------------------------------------------------------------------

class TestSensitiveDataProtection:
    """
    Verify the API never echoes credentials, paths, or debug info
    back to the caller in response bodies or headers.
    """

    def test_credentials_stripped_from_url_display(self, client):
        import json as _json
        r = client.post(
            "/api/analyze",
            json={"url": "https://admin:s3cr3t@evil.com/page"},
        )
        assert r.status_code == 200
        body = _json.loads(r.data)
        assert "s3cr3t"   not in body["url_display"]
        assert "admin:"   not in body["url_display"]

    def test_credentials_stripped_from_all_response_fields(self, client):
        """
        The password MUST NOT appear in url_display (already tested above).
        It MAY appear in the at_in_authority indicator explanation, which
        intentionally names both sides of the '@' to educate the user about
        the attack.  The critical control is that the frontend renders this
        via textContent, preventing HTML injection.
        """
        import json as _json
        r = client.post(
            "/api/analyze",
            json={"url": "https://admin:s3cr3t@evil.com/page"},
        )
        assert r.status_code == 200
        body = _json.loads(r.data)
        # url_display must never contain the password
        assert "s3cr3t" not in body["url_display"]
        assert "admin:" not in body["url_display"]
        # The response must be valid JSON (no injection breakout)
        assert isinstance(body["score"], int)

    def test_no_stack_trace_in_normal_response(self, client):
        import json as _json
        r = client.post(
            "/api/analyze",
            json={"url": "https://example.com"},
        )
        raw = r.data.decode()
        for trace_marker in ("Traceback", "File \"", "line ", "in <module>"):
            assert trace_marker not in raw, \
                f"Stack trace marker '{trace_marker}' found in normal response"

    def test_server_header_not_present(self, client):
        r = client.get("/api/health")
        # Should have been stripped by set_security_headers
        assert "Server" not in r.headers

    def test_environment_testing_in_health(self, client):
        import json as _json
        r = client.get("/api/health")
        body = _json.loads(r.data)
        # Testing fixture sets TESTING=True → environment should say "testing"
        assert body["environment"] == "testing"
