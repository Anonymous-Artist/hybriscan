"""
tests/test_analyzer.py
──────────────────────
Unit tests for core/analyzer.py.

Covers all five sub-analysers and the top-level Analyser orchestrator.
No real HTTP traffic — all tests use ScanResult fixtures.

Run with:  pytest tests/test_analyzer.py -v
"""

import pytest
from bs4 import BeautifulSoup

from core.analyzer import (
    Analyser,
    AnalysisResult,
    TitleAnalyser,
    FormAnalyser,
    HeaderAnalyser,
    ScriptAnalyser,
    KeywordAnalyser,
    TitleInfo,
    FormInfo,
    FormField,
    HeaderAudit,
    ScriptInfo,
    KeywordInfo,
    SECURITY_HEADERS,
)
from core.scanner import ScanResult


# ─── Fixtures ─────────────────────────────────────────────────────────────────

BASE_CONFIG = {"logging": {"level": "WARNING", "log_to_file": False}}
BASE_URL    = "http://target.local"


def _sr(url: str = BASE_URL, body: str = "", headers: dict | None = None,
        status: int = 200, error: str | None = None) -> ScanResult:
    return ScanResult(
        url=url,
        status_code=None if error else status,
        headers=headers or {},
        body=body,
        elapsed_ms=5.0,
        redirected_url=None,
        error=error,
    )


def _soup(html: str) -> BeautifulSoup:
    return BeautifulSoup(html, "html.parser")


# ─── TitleAnalyser ────────────────────────────────────────────────────────────

class TestTitleAnalyser:
    ta = TitleAnalyser()

    def test_extracts_title_text(self):
        s = _soup("<html><head><title>Welcome</title></head></html>")
        t = self.ta.analyse(s)
        assert t.raw == "Welcome"

    def test_empty_on_no_title(self):
        s = _soup("<html><body>No title</body></html>")
        t = self.ta.analyse(s)
        assert t.raw == ""
        assert t.lower == ""

    def test_admin_keyword_flag(self):
        s = _soup("<title>Administration Panel</title>")
        t = self.ta.analyse(s)
        assert t.has_admin_keyword is True

    def test_login_keyword_flag(self):
        s = _soup("<title>Login to your account</title>")
        t = self.ta.analyse(s)
        assert t.has_login_keyword is True

    def test_error_keyword_flag(self):
        s = _soup("<title>404 Not Found</title>")
        t = self.ta.analyse(s)
        assert t.has_error_keyword is True

    def test_index_of_keyword_flag(self):
        s = _soup("<title>Index of /var/www</title>")
        t = self.ta.analyse(s)
        assert t.has_index_keyword is True

    def test_no_false_positive_on_clean_title(self):
        s = _soup("<title>About Us | Acme Corp</title>")
        t = self.ta.analyse(s)
        assert t.has_admin_keyword is False
        assert t.has_login_keyword is False
        assert t.has_index_keyword is False

    def test_lower_is_lowercase(self):
        s = _soup("<title>ADMIN PANEL</title>")
        t = self.ta.analyse(s)
        assert t.lower == "admin panel"


# ─── FormAnalyser ─────────────────────────────────────────────────────────────

class TestFormAnalyser:
    fa = FormAnalyser()

    def test_detects_password_field(self):
        html = '<form action="/login"><input type="password" name="password"></form>'
        s = _soup(html)
        forms = self.fa.analyse(s, BASE_URL)
        assert len(forms) == 1
        assert forms[0].has_password_field is True

    def test_detects_username_field(self):
        html = '<form><input name="username"><input type="password" name="password"></form>'
        s = _soup(html)
        forms = self.fa.analyse(s, BASE_URL)
        assert forms[0].has_username_field is True

    def test_detects_hidden_fields(self):
        html = '<form><input type="hidden" name="csrf_token" value="abc"></form>'
        s = _soup(html)
        forms = self.fa.analyse(s, BASE_URL)
        assert forms[0].has_hidden_fields is True

    def test_detects_suspicious_action_path(self):
        html = '<form action="/admin/create"><input type="text" name="name"></form>'
        s = _soup(html)
        forms = self.fa.analyse(s, BASE_URL)
        assert forms[0].action_path_suspicious is True

    def test_detects_external_action(self):
        html = '<form action="http://evil.com/collect"><input name="x"></form>'
        s = _soup(html)
        forms = self.fa.analyse(s, BASE_URL)
        assert forms[0].action_is_external is True

    def test_no_external_on_same_origin_action(self):
        html = '<form action="http://target.local/submit"><input name="x"></form>'
        s = _soup(html)
        forms = self.fa.analyse(s, BASE_URL)
        assert forms[0].action_is_external is False

    def test_method_extracted(self):
        html = '<form method="POST" action="/login"><input name="x"></form>'
        s = _soup(html)
        forms = self.fa.analyse(s, BASE_URL)
        assert forms[0].method == "POST"

    def test_multiple_forms_returned(self):
        html = '<form action="/search"><input name="q"></form><form action="/login"><input type="password" name="password"></form>'
        s = _soup(html)
        forms = self.fa.analyse(s, BASE_URL)
        assert len(forms) == 2

    def test_sensitive_field_name_flagged(self):
        html = '<form><input name="api_key" type="text"></form>'
        s = _soup(html)
        forms = self.fa.analyse(s, BASE_URL)
        assert any(f.is_sensitive_name for f in forms[0].fields)

    def test_no_forms_returns_empty_list(self):
        s = _soup("<html><body><p>No forms here.</p></body></html>")
        forms = self.fa.analyse(s, BASE_URL)
        assert forms == []

    def test_form_with_no_action(self):
        html = '<form><input type="password" name="p"></form>'
        s = _soup(html)
        forms = self.fa.analyse(s, BASE_URL)
        assert forms[0].action == ""
        assert forms[0].has_password_field is True


# ─── HeaderAnalyser ───────────────────────────────────────────────────────────

class TestHeaderAnalyser:
    ha = HeaderAnalyser()

    def _all_headers(self) -> dict[str, str]:
        return {
            "content-security-policy": "default-src 'self'",
            "x-frame-options": "DENY",
            "strict-transport-security": "max-age=31536000; includeSubDomains",
            "x-content-type-options": "nosniff",
            "referrer-policy": "strict-origin-when-cross-origin",
            "permissions-policy": "geolocation=()",
            "x-xss-protection": "1; mode=block",
        }

    def test_all_present_when_all_sent(self):
        audit = self.ha.analyse(self._all_headers())
        assert "content-security-policy" in audit.present
        assert "x-frame-options" in audit.present
        assert "strict-transport-security" in audit.present
        assert "x-content-type-options" in audit.present

    def test_missing_headers_listed(self):
        audit = self.ha.analyse({})
        assert "content-security-policy" in audit.missing
        assert "x-frame-options" in audit.missing
        assert "strict-transport-security" in audit.missing
        assert "x-content-type-options" in audit.missing

    def test_no_missing_when_all_present(self):
        audit = self.ha.analyse(self._all_headers())
        assert audit.missing == []

    def test_insecure_csp_unsafe_inline(self):
        headers = {"content-security-policy": "default-src 'self'; script-src 'unsafe-inline'"}
        audit = self.ha.analyse(headers)
        assert "content-security-policy" in audit.insecure_values

    def test_insecure_csp_unsafe_eval(self):
        headers = {"content-security-policy": "script-src 'unsafe-eval'"}
        audit = self.ha.analyse(headers)
        assert "content-security-policy" in audit.insecure_values

    def test_secure_csp_not_flagged(self):
        headers = {"content-security-policy": "default-src 'self'"}
        audit = self.ha.analyse(headers)
        assert "content-security-policy" not in audit.insecure_values

    def test_short_hsts_flagged(self):
        headers = {"strict-transport-security": "max-age=300"}
        audit = self.ha.analyse(headers)
        assert "strict-transport-security" in audit.insecure_values

    def test_long_hsts_not_flagged(self):
        headers = {"strict-transport-security": "max-age=31536000"}
        audit = self.ha.analyse(headers)
        assert "strict-transport-security" not in audit.insecure_values

    def test_present_and_missing_are_disjoint(self):
        headers = {"x-frame-options": "DENY"}
        audit = self.ha.analyse(headers)
        assert "x-frame-options" in audit.present
        assert "x-frame-options" not in audit.missing

    def test_partial_headers(self):
        headers = {"x-frame-options": "SAMEORIGIN", "x-content-type-options": "nosniff"}
        audit = self.ha.analyse(headers)
        assert len(audit.present) == 2
        assert "content-security-policy" in audit.missing


# ─── ScriptAnalyser ───────────────────────────────────────────────────────────

class TestScriptAnalyser:
    sa = ScriptAnalyser()

    def test_counts_inline_scripts(self):
        html = "<html><body><script>var x=1;</script><script>var y=2;</script></body></html>"
        s = _soup(html)
        info = self.sa.analyse(s)
        assert info.total_inline_scripts == 2

    def test_external_script_not_counted(self):
        html = '<html><body><script src="/app.js"></script><script>var x=1;</script></body></html>'
        s = _soup(html)
        info = self.sa.analyse(s)
        assert info.total_inline_scripts == 1   # only the inline one

    def test_document_cookie_flagged(self):
        html = "<script>var c = document.cookie;</script>"
        s = _soup(html)
        info = self.sa.analyse(s)
        assert any("document" in h and "cookie" in h for h in info.suspicious_pattern_hits)

    def test_eval_flagged(self):
        html = "<script>eval(userInput);</script>"
        s = _soup(html)
        info = self.sa.analyse(s)
        assert any("eval" in h for h in info.suspicious_pattern_hits)

    def test_inner_html_flagged(self):
        html = "<script>el.innerHTML = data;</script>"
        s = _soup(html)
        info = self.sa.analyse(s)
        assert any("innerHTML" in h for h in info.suspicious_pattern_hits)

    def test_alert_flagged(self):
        html = "<script>alert('test')</script>"
        s = _soup(html)
        info = self.sa.analyse(s)
        assert any("alert" in h for h in info.suspicious_pattern_hits)

    def test_clean_script_not_flagged(self):
        html = "<script>var count = 0; count++; console.log(count);</script>"
        s = _soup(html)
        info = self.sa.analyse(s)
        assert info.suspicious_pattern_hits == []

    def test_no_scripts_returns_zero(self):
        s = _soup("<html><body><p>No JS</p></body></html>")
        info = self.sa.analyse(s)
        assert info.total_inline_scripts == 0
        assert info.suspicious_pattern_hits == []

    def test_duplicate_patterns_not_repeated(self):
        html = "<script>document.cookie; document.cookie;</script>"
        s = _soup(html)
        info = self.sa.analyse(s)
        cookie_hits = [h for h in info.suspicious_pattern_hits if "document" in h and "cookie" in h]
        assert len(cookie_hits) == 1


# ─── KeywordAnalyser ──────────────────────────────────────────────────────────

class TestKeywordAnalyser:
    ka = KeywordAnalyser()

    def test_finds_sql_keyword(self):
        s = _soup("<html><body>You have an error in your sql syntax</body></html>")
        info = self.ka.analyse(s)
        assert "sql" in info.found

    def test_finds_password_keyword(self):
        s = _soup("<html><body>Enter your password below</body></html>")
        info = self.ka.analyse(s)
        assert "password" in info.found

    def test_finds_index_of(self):
        s = _soup("<html><body>index of /var/www/html</body></html>")
        info = self.ka.analyse(s)
        assert "index of" in info.found

    def test_snippet_context_captured(self):
        s = _soup("<html><body>Unexpected error: sql exception occurred</body></html>")
        info = self.ka.analyse(s)
        assert "sql" in info.snippet_map
        assert "sql" in info.snippet_map["sql"].lower()

    def test_no_keywords_on_clean_page(self):
        s = _soup("<html><body><p>Welcome to our online store. Browse products.</p></body></html>")
        info = self.ka.analyse(s)
        assert info.found == []

    def test_multiple_keywords_found(self):
        s = _soup("<html><body>sql error debug mode active</body></html>")
        info = self.ka.analyse(s)
        assert "sql" in info.found
        assert "error" in info.found
        assert "debug" in info.found


# ─── Analyser (orchestrator) ──────────────────────────────────────────────────

class TestAnalyser:
    def _analyser(self):
        return Analyser(BASE_CONFIG)

    def test_returns_analysis_result(self):
        a = self._analyser()
        r = _sr(body="<html><body>Hello</body></html>")
        ar = a.analyse(r)
        assert isinstance(ar, AnalysisResult)

    def test_url_preserved(self):
        a = self._analyser()
        r = _sr(url="http://target.local/admin/", body="<html></html>")
        ar = a.analyse(r)
        assert ar.url == "http://target.local/admin/"

    def test_status_code_preserved(self):
        a = self._analyser()
        r = _sr(body="<html></html>", status=403)
        ar = a.analyse(r)
        assert ar.status_code == 403

    def test_failed_request_returns_empty_result(self):
        a = self._analyser()
        r = _sr(error="ConnectionRefused")
        ar = a.analyse(r)
        assert ar.title.raw == ""
        assert ar.forms == []
        assert ar.scripts.total_inline_scripts == 0
        assert ar.keywords.found == []

    def test_title_populated(self):
        a = self._analyser()
        r = _sr(body="<html><head><title>Admin Panel</title></head></html>")
        ar = a.analyse(r)
        assert ar.title.raw == "Admin Panel"
        assert ar.title.has_admin_keyword is True

    def test_forms_populated(self):
        a = self._analyser()
        body = '<html><body><form action="/login"><input type="password" name="password"></form></body></html>'
        r = _sr(body=body)
        ar = a.analyse(r)
        assert len(ar.forms) == 1
        assert ar.forms[0].has_password_field is True

    def test_headers_populated(self):
        a = self._analyser()
        r = _sr(
            body="<html></html>",
            headers={"x-frame-options": "DENY", "x-content-type-options": "nosniff"},
        )
        ar = a.analyse(r)
        assert "x-frame-options" in ar.headers.present
        assert "content-security-policy" in ar.headers.missing

    def test_scripts_populated(self):
        a = self._analyser()
        body = "<html><body><script>eval(userInput)</script></body></html>"
        r = _sr(body=body)
        ar = a.analyse(r)
        assert ar.scripts.total_inline_scripts == 1
        assert len(ar.scripts.suspicious_pattern_hits) > 0

    def test_keywords_populated(self):
        a = self._analyser()
        body = "<html><body><p>SQL error on line 42</p></body></html>"
        r = _sr(body=body)
        ar = a.analyse(r)
        assert "sql" in ar.keywords.found or "error" in ar.keywords.found

    def test_word_count_nonzero(self):
        a = self._analyser()
        r = _sr(body="<html><body><p>Hello world this is a test</p></body></html>")
        ar = a.analyse(r)
        assert ar.word_count > 0

    def test_meta_charset_from_meta_tag(self):
        a = self._analyser()
        body = '<html><head><meta charset="UTF-8"></head></html>'
        r = _sr(body=body)
        ar = a.analyse(r)
        assert ar.meta_charset.upper() == "UTF-8"

    def test_meta_charset_from_content_type_header(self):
        a = self._analyser()
        r = _sr(
            body="<html></html>",
            headers={"content-type": "text/html; charset=iso-8859-1"},
        )
        ar = a.analyse(r)
        assert "iso-8859-1" in ar.meta_charset.lower()

    def test_analyse_many_returns_correct_length(self):
        a = self._analyser()
        results = [
            _sr(url=f"http://target.local/page{i}", body=f"<html><body>Page {i}</body></html>")
            for i in range(4)
        ]
        ars = a.analyse_many(results)
        assert len(ars) == 4

    def test_analyse_many_preserves_order(self):
        a = self._analyser()
        urls = [f"http://target.local/p{i}" for i in range(3)]
        results = [_sr(url=u, body="<html></html>") for u in urls]
        ars = a.analyse_many(results)
        assert [ar.url for ar in ars] == urls

    def test_full_login_page_analysis(self):
        """Integration-style test: realistic login page produces expected flags."""
        body = """
        <html>
          <head>
            <title>Login – MyApp</title>
            <meta charset="UTF-8">
          </head>
          <body>
            <h1>Sign In</h1>
            <form method="POST" action="/auth/login">
              <input type="text" name="username" placeholder="Email">
              <input type="password" name="password" placeholder="Password">
              <input type="hidden" name="csrf_token" value="abc123">
              <button type="submit">Login</button>
            </form>
            <script>document.getElementById('username').focus();</script>
          </body>
        </html>
        """
        a = self._analyser()
        r = _sr(url="http://target.local/login", body=body,
                headers={"content-type": "text/html; charset=utf-8"})
        ar = a.analyse(r)

        assert ar.title.has_login_keyword is True
        assert len(ar.forms) == 1
        assert ar.forms[0].has_password_field is True
        assert ar.forms[0].has_username_field is True
        assert ar.forms[0].has_hidden_fields is True
        assert ar.forms[0].method == "POST"
        assert "content-security-policy" in ar.headers.missing
        assert ar.meta_charset.upper() == "UTF-8"
        assert ar.word_count > 0
