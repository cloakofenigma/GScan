"""Unit + integration tests for G-Hunter.

These exercise the pure logic (severity, URL validation, dedup, redaction,
report rendering) and the concurrent repo-scan orchestration with the scanner
mocked, so they run without git, network, or external scanners installed.
"""
import asyncio
import json
import sys
from pathlib import Path

import pytest

# Make the repo root importable, then load via the compatibility shim, which
# re-exports the public names from the `ghunter` package.
_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))
import ghunter_pro as gh  # noqa: E402
import ghunter.export as gh_export  # noqa: E402


def make_finding(**kw):
    return gh.SecretFinding(
        detector_type=kw.get("dt", "x"),
        detector_name=kw.get("dn", "x"),
        verified=kw.get("verified", False),
        raw_result=kw.get("raw", "{}"),
        repo_url=kw.get("repo", "https://github.com/a/b"),
        file_path=kw.get("file", "f.py"),
        commit=kw.get("commit", "c"),
        timestamp="t",
        scan_tool=kw.get("scan_tool", "trufflehog"),
        found_by=kw.get("found_by", ["trufflehog"]),
        secret_hash=kw.get("hash", ""),
    )


@pytest.fixture
def hunter():
    return gh.GHunter(gh.Config(github_token="x"))


# ---------------------------------------------------------------- severity ---
def test_verified_secret_is_critical(hunter):
    assert hunter.derive_severity(make_finding(verified=True)) == "CRITICAL"


@pytest.mark.parametrize("dt,expected", [
    ("aws-access-token", "HIGH"),
    ("github-pat", "HIGH"),
    ("private-key", "HIGH"),
    ("generic-misc", "MEDIUM"),
])
def test_severity_by_detector(hunter, dt, expected):
    assert hunter.derive_severity(make_finding(dt=dt)) == expected


# ----------------------------------------------------- repo URL validation ---
@pytest.mark.parametrize("url", [
    "https://github.com/a/b.git", "http://example.com/x", "https://gitlab.com/o/r.git",
])
def test_valid_repo_urls(hunter, url):
    assert hunter.is_valid_repo_url(url)


@pytest.mark.parametrize("url", [
    "--upload-pack=evil", "-x", "file:///etc/passwd", "ssh://git@h/x",
    "ext::sh -c id", "", None, "javascript:alert(1)",
])
def test_invalid_repo_urls_blocked(hunter, url):
    assert not hunter.is_valid_repo_url(url)


def test_clone_refuses_unsafe_url(hunter, tmp_path):
    ok, path = hunter.clone_repository("--upload-pack=evil", tmp_path)
    assert ok is False and path is None


# ------------------------------------------------------ gitleaks command -----
def test_gitleaks_legacy_detect(hunter):
    hunter._gitleaks_use_git_subcmd = False
    cmd = hunter._build_gitleaks_cmd(Path("/c"), Path("/o.json"))
    assert cmd[:2] == ["gitleaks", "detect"] and "--source" in cmd


def test_gitleaks_new_git_subcommand(hunter):
    hunter._gitleaks_use_git_subcmd = True
    cmd = hunter._build_gitleaks_cmd(Path("/c"), Path("/o.json"))
    assert cmd[:3] == ["gitleaks", "git", "/c"] and "--source" not in cmd


# --------------------------------------------------------- AI redaction ------
def test_ai_context_redacts_secret(hunter):
    raw = json.dumps({"DetectorName": "AWS", "Raw": "AKIAREALSECRET", "Secret": "shh"})
    ctx = hunter._ai_context(make_finding(raw=raw))
    assert "AKIAREALSECRET" not in ctx and "shh" not in ctx and "[REDACTED]" in ctx


def test_ai_context_opt_in_raw():
    h = gh.GHunter(gh.Config(github_token="x", ai_send_raw=True))
    raw = json.dumps({"Raw": "AKIAREALSECRET"})
    assert "AKIAREALSECRET" in h._ai_context(make_finding(raw=raw))


# ----------------------------------------------------------- dedup -----------
def test_dedup_merges_tools(hunter):
    a = make_finding(scan_tool="trufflehog", found_by=["trufflehog"], hash="H", verified=False)
    b = make_finding(scan_tool="gitleaks", found_by=["gitleaks"], hash="H", verified=True)
    out = hunter.deduplicate_findings([a, b])
    assert len(out) == 1
    assert set(out[0].found_by) == {"trufflehog", "gitleaks"}
    assert out[0].verified is True


# ----------------------------------------------------- rate-limit backoff ----
class _Resp:
    def __init__(self, headers):
        self.headers = headers


def test_rate_limit_retry_after(hunter):
    assert hunter._rate_limit_wait(_Resp({"Retry-After": "7"})) == 7


def test_rate_limit_default(hunter):
    assert hunter._rate_limit_wait(_Resp({})) == 60


# ------------------------------------------------------- HTML XSS safety -----
def test_report_escapes_xss(hunter, tmp_path):
    rf = tmp_path / "scan_results.json"
    rf.write_text(json.dumps({
        "detector_type": "<img src=x onerror=alert(1)>",
        "detector_name": "<script>alert('xss')</script>",
        "verified": True, "repo_url": "javascript:alert(document.cookie)",
        "file_path": "\"><svg onload=alert(2)>", "commit": "c", "timestamp": "t",
        "severity": "HIGH", "false_positive": False, "needs_review": False,
        "ai_analysis": {"reason": "<script>steal()</script>"},
        "raw_result": "x", "scan_tool": "trufflehog", "found_by": ["trufflehog"],
    }) + "\n")
    hunter.generate_html_report(str(rf))
    report = (tmp_path / "report.html").read_text()
    for live in ["<script>alert", "<script>steal", "<img src=x onerror",
                 "<svg onload", 'href="javascript:']:
        assert live not in report, f"live injection present: {live}"
    assert 'href="#"' in report  # javascript: url neutralized


# ------------------------------------------------- secret surfaced in report -
def _write_results(tmp_path, *rows):
    rf = tmp_path / "scan_results.json"
    rf.write_text("\n".join(json.dumps(r) for r in rows) + "\n")
    return rf


def _base_row(**kw):
    row = {
        "detector_type": "generic-api-key", "detector_name": "Generic API Key",
        "verified": False, "repo_url": "https://github.com/a/b", "file_path": "cfg",
        "commit": "c", "timestamp": "t", "severity": "MEDIUM",
        "false_positive": False, "needs_review": True, "ai_analysis": None,
        "raw_result": "{}", "scan_tool": "gitleaks", "found_by": ["gitleaks"],
        "suppressed": False, "suppressed_by": "",
    }
    row.update(kw)
    return row


def test_report_shows_gitleaks_secret(hunter, tmp_path):
    raw = json.dumps({"Secret": "16Bincyshalu", "Match": 'password: "16Bincyshalu"',
                      "StartLine": 19, "Link": "https://github.com/a/b/blob/c/cfg#L19"})
    rf = _write_results(tmp_path, _base_row(raw_result=raw))
    hunter.generate_html_report(str(rf))
    html = (tmp_path / "report.html").read_text()
    assert "16Bincyshalu" in html              # secret value surfaced
    assert "Identified Secret" in html
    assert "secret-value masked" in html       # masked by default
    assert "line 19" in html
    assert 'href="https://github.com/a/b/blob/c/cfg#L19"' in html


def test_report_shows_trufflehog_secret(hunter, tmp_path):
    raw = json.dumps({"Raw": "AKIAIOSFODNN7EXAMPLE", "DetectorName": "AWS"})
    rf = _write_results(tmp_path, _base_row(scan_tool="trufflehog",
                                            found_by=["trufflehog"], raw_result=raw))
    hunter.generate_html_report(str(rf))
    assert "AKIAIOSFODNN7EXAMPLE" in (tmp_path / "report.html").read_text()


def test_report_ai_quota_error_is_clean_note(hunter, tmp_path):
    # Legacy-style result: full 429 blob stored as the reason, no error flag.
    blob = ("AI error: 429 You exceeded your current quota ... "
            "generate_content_free_tier_requests quota_metric violations")
    rf = _write_results(tmp_path, _base_row(ai_analysis={"reason": blob, "severity": "UNKNOWN"}))
    hunter.generate_html_report(str(rf))
    html = (tmp_path / "report.html").read_text()
    assert "AI triage skipped" in html
    assert "generate_content_free_tier" not in html  # blob suppressed
    assert "quota_metric" not in html


def test_report_long_secret_truncated(hunter, tmp_path):
    raw = json.dumps({"Secret": "A" * 1000})
    rf = _write_results(tmp_path, _base_row(raw_result=raw))
    hunter.generate_html_report(str(rf))
    assert "(truncated)" in (tmp_path / "report.html").read_text()


# ------------------------------------------ concurrent repo_scan + resume ----
def _setup_hunter(workers=4):
    h = gh.GHunter(gh.Config(github_token="x", max_repo_workers=workers))
    h.check_git = lambda: True
    h.check_trufflehog = lambda: True
    h.check_gitleaks = lambda: (True, "8.20.0")
    return h


def test_repo_scan_concurrent_and_resume(tmp_path):
    repos = [f"https://github.com/org/repo{i}.git" for i in range(6)]
    rf = tmp_path / "repos.txt"
    rf.write_text("\n".join(repos) + "\n")

    h = _setup_hunter()

    def fake(repo_url, clone_dir, scan_tool, tf, gl, np=False):
        if "repo3" in repo_url:
            return None  # clone failure
        f = make_finding(repo=repo_url, verified="repo1" in repo_url)
        f.severity = h.derive_severity(f)
        return [f]

    h._scan_single_repo = fake
    asyncio.run(h.repo_scan(repo_file=str(rf), scan_tool="trufflehog", resume=False))

    lines = [json.loads(x) for x in (tmp_path / "scan_results.json").read_text().splitlines() if x.strip()]
    assert len(lines) == 5
    prog = json.loads((tmp_path / "progress.json").read_text())
    assert len(prog["scanned_repos"]) == 5 and prog["clone_failures"] == 1
    assert all(x["severity"] != "UNKNOWN" for x in lines)

    # Resume: only the failed repo is retried, no duplicate findings written.
    calls = []

    def fake2(repo_url, *a):
        calls.append(repo_url)
        return None if "repo3" in repo_url else [make_finding(repo=repo_url)]

    h._scan_single_repo = fake2
    asyncio.run(h.repo_scan(repo_file=str(rf), scan_tool="trufflehog", resume=True))
    assert calls == ["https://github.com/org/repo3.git"]
    lines2 = [x for x in (tmp_path / "scan_results.json").read_text().splitlines() if x.strip()]
    assert len(lines2) == 5  # no duplicates


# ----------------------------------------------------------- allowlist -------
def _allowlist(tmp_path, text):
    f = tmp_path / ".ghunterignore"
    f.write_text(text)
    return gh.Allowlist.load([f])


def test_allowlist_path_glob(tmp_path):
    al = _allowlist(tmp_path, "path:**/test/**\n*.example\n")
    assert al.match(make_finding(file="src/test/fixtures/a.py"))
    assert al.match(make_finding(file="config.example"))
    assert al.match(make_finding(file="src/main.py")) is None


def test_allowlist_bare_line_is_path_glob(tmp_path):
    al = _allowlist(tmp_path, "# comment\n\n**/node_modules/**\n")
    assert al.match(make_finding(file="a/node_modules/x/key.js"))
    assert al.match(make_finding(file="a/src/key.js")) is None


def test_allowlist_fingerprint(tmp_path):
    al = _allowlist(tmp_path, "fingerprint:deadbeef\nfp:cafef00d\n")
    assert al.match(make_finding(hash="deadbeef")) == "fingerprint:deadbeef"
    assert al.match(make_finding(hash="cafef00d")) == "fingerprint:cafef00d"
    assert al.match(make_finding(hash="other")) is None
    assert al.match(make_finding(hash="")) is None  # never match empty hash


def test_allowlist_regex(tmp_path):
    al = _allowlist(tmp_path, "regex:DUMMY_SECRET|REPLACE_ME\n")
    assert al.match(make_finding(raw='{"Raw":"DUMMY_SECRET"}'))
    assert al.match(make_finding(raw='{"Raw":"real"}')) is None


def test_allowlist_invalid_regex_is_skipped_not_fatal(tmp_path):
    al = _allowlist(tmp_path, "regex:[unclosed\npath:keep.py\n")
    assert len(al) == 1  # bad regex dropped, valid path rule kept
    assert al.match(make_finding(file="keep.py"))


def test_allowlist_missing_file_is_empty(tmp_path):
    al = gh.Allowlist.load([tmp_path / "nope"])
    assert not al and len(al) == 0


def test_scan_single_repo_tags_suppressed_and_skips_ai(hunter, tmp_path, monkeypatch):
    hunter.allowlist = _allowlist(tmp_path, "path:*.example\n")
    monkeypatch.setattr(hunter, "clone_repository", lambda url, d: (True, tmp_path / "r"))
    monkeypatch.setattr(hunter, "_register_clone", lambda p: None)
    monkeypatch.setattr(hunter, "_unregister_clone", lambda p: None)
    monkeypatch.setattr(hunter, "cleanup_clone", lambda p: None)
    monkeypatch.setattr(hunter, "run_trufflehog_local",
                        lambda c, u: [make_finding(file="config.example"),
                                      make_finding(file="real.py")])
    ai_calls = []
    hunter.gemini_model = object()
    monkeypatch.setattr(hunter, "analyze_with_gemini",
                        lambda f: ai_calls.append(f) or {"false_positive": False})

    out = hunter._scan_single_repo("https://github.com/a/b", tmp_path, "trufflehog", True, False)
    suppressed = [f for f in out if f.suppressed]
    assert len(suppressed) == 1 and suppressed[0].file_path == "config.example"
    assert suppressed[0].suppressed_by == "path:*.example"
    # AI ran only for the non-suppressed finding
    assert len(ai_calls) == 1 and ai_calls[0].file_path == "real.py"


def test_report_separates_suppressed(hunter, tmp_path):
    rf = tmp_path / "scan_results.json"
    rows = [
        {"detector_type": "t", "detector_name": "n", "verified": True, "repo_url": "https://x/y",
         "file_path": "real.py", "commit": "c", "timestamp": "t", "severity": "CRITICAL",
         "false_positive": False, "needs_review": False, "ai_analysis": None,
         "raw_result": "x", "scan_tool": "trufflehog", "found_by": ["trufflehog"],
         "suppressed": False, "suppressed_by": ""},
        {"detector_type": "t", "detector_name": "n", "verified": True, "repo_url": "https://x/y",
         "file_path": "test.example", "commit": "c", "timestamp": "t", "severity": "CRITICAL",
         "false_positive": False, "needs_review": False, "ai_analysis": None,
         "raw_result": "x", "scan_tool": "trufflehog", "found_by": ["trufflehog"],
         "suppressed": True, "suppressed_by": "path:*.example"},
    ]
    rf.write_text("\n".join(json.dumps(r) for r in rows) + "\n")
    hunter.generate_html_report(str(rf))
    report = (tmp_path / "report.html").read_text()
    # Suppressed finding excluded from active severity counts (1 critical, not 2)
    assert 'data-suppressed="true"' in report
    assert "Allowlisted" in report


# ------------------------------------------------------- Gemini model cfg ----
def test_default_gemini_model_is_2_5_flash():
    assert gh.Config(github_token="x").gemini_model == "gemini-2.5-flash"


def test_gemini_model_override():
    c = gh.Config(github_token="x", gemini_model="gemini-2.5-pro")
    assert c.gemini_model == "gemini-2.5-pro"


def test_ghunter_uses_configured_gemini_model(monkeypatch):
    """The configured model name must reach the Gemini SDK constructor."""
    import ghunter.core as core
    created = {}

    class _FakeGenAI:
        @staticmethod
        def configure(**kw):
            pass

        @staticmethod
        def GenerativeModel(name):
            created["name"] = name
            return object()

    monkeypatch.setattr(core, "genai", _FakeGenAI)
    monkeypatch.setattr(core, "GENAI_AVAILABLE", True)
    gh.GHunter(gh.Config(github_token="x", gemini_api_key="k",
                         gemini_model="gemini-2.5-flash"))
    assert created["name"] == "gemini-2.5-flash"


# ------------------------------------------------ query splitting on cap -----
class _FakeResp:
    def __init__(self, status, payload):
        self.status, self._payload, self.headers = status, payload, {}

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def json(self):
        return self._payload


class _FakeSession:
    def __init__(self, responder):
        self.responder = responder
        self.queries = []   # params dicts
        self.calls = []     # (url, params) tuples
        self.closed = False

    def get(self, url, params=None):
        self.queries.append(params)
        self.calls.append((url, params))
        return _FakeResp(*self.responder(url, params))

    async def close(self):
        self.closed = True


def _item(name):
    base = f"https://github.com/o/{name}"
    return {"repository": {"html_url": base}, "html_url": base + "/blob/main/f.py"}


def _wire_search(workers=1, rate=100000):
    h = gh.GHunter(gh.Config(github_token="x", rate_limit=rate, max_repo_workers=workers))
    h.semaphore = asyncio.Semaphore(1)
    return h


def test_size_qualifier_ranges():
    h = _wire_search()
    assert h._size_q(None, 999) == "size:<1000"
    assert h._size_q(1000, 4999) == "size:1000..4999"
    assert h._size_q(100000, None) == "size:>=100000"


def test_search_splits_when_capped():
    h = _wire_search()

    def responder(url, params):
        q, page = params["q"], params["page"]
        if "size:" not in q:
            # 10 full pages -> saturates the 1000-result cap
            return 200, {"items": [_item(f"base-{page}-{i}") for i in range(100)]}
        # size-bucketed sub-query: one short page, unique repo per bucket
        tag = q.split("size:")[1].split()[0]
        return 200, {"items": [_item(f"bucket-{tag}")]}

    h.session = _FakeSession(responder)
    repos, urls = asyncio.run(h.search_github("acme", "password"))

    issued = [p["q"] for p in h.session.queries]
    assert any("size:" in q for q in issued)            # splitting kicked in
    assert any("base-" in r for r in repos)             # base results kept
    assert sum("bucket-" in r for r in repos) == len(gh.GHunter._SIZE_BUCKETS)


def test_search_no_split_when_under_cap():
    h = _wire_search()

    def responder(url, params):
        # Single short page -> genuine last page, never capped
        return 200, {"items": [_item("a"), _item("b")]}

    h.session = _FakeSession(responder)
    repos, urls = asyncio.run(h.search_github("acme", "password"))

    assert all("size:" not in p["q"] for p in h.session.queries)
    assert len(repos) == 2


def test_search_respects_split_disabled():
    h = gh.GHunter(gh.Config(github_token="x", rate_limit=100000, split_on_cap=False))
    h.semaphore = asyncio.Semaphore(1)

    def responder(url, params):
        return 200, {"items": [_item(f"r-{params['page']}-{i}") for i in range(100)]}

    h.session = _FakeSession(responder)
    asyncio.run(h.search_github("acme", "password"))
    assert all("size:" not in p["q"] for p in h.session.queries)


# --------------------------------------------- org/user/gist/commit enum -----
def _repo_obj(name):
    return {"clone_url": f"https://github.com/o/{name}.git",
            "html_url": f"https://github.com/o/{name}"}


def test_enumerate_owner_repos_org():
    h = _wire_search()

    def responder(url, params):
        if "/orgs/acme/repos" in url:
            return 200, [_repo_obj("a"), _repo_obj("b")]
        return 404, []   # user endpoint shouldn't be needed

    h.session = _FakeSession(responder)
    repos = asyncio.run(h.enumerate_owner_repos("acme"))
    assert repos == {"https://github.com/o/a.git", "https://github.com/o/b.git"}
    assert all("/users/" not in u for u, _ in h.session.calls)  # org matched first


def test_enumerate_owner_repos_user_fallback():
    h = _wire_search()

    def responder(url, params):
        if "/orgs/" in url:
            return 404, []        # not an org
        return 200, [_repo_obj("u1")]

    h.session = _FakeSession(responder)
    repos = asyncio.run(h.enumerate_owner_repos("alice"))
    assert repos == {"https://github.com/o/u1.git"}
    assert any("/users/alice/repos" in u for u, _ in h.session.calls)


def test_enumerate_user_gists():
    h = _wire_search()

    def responder(url, params):
        return 200, [{"git_pull_url": "https://gist.github.com/abc123.git"},
                     {"git_pull_url": "https://gist.github.com/def456"}]

    h.session = _FakeSession(responder)
    gists = asyncio.run(h.enumerate_user_gists("alice"))
    assert gists == {"https://gist.github.com/abc123.git", "https://gist.github.com/def456.git"}


def test_search_commits():
    h = _wire_search()

    def responder(url, params):
        return 200, {"items": [
            {"repository": {"html_url": "https://github.com/o/r1"},
             "html_url": "https://github.com/o/r1/commit/deadbeef"},
        ]}

    h.session = _FakeSession(responder)
    repos, urls = asyncio.run(h.search_commits("acme", "password"))
    assert repos == {"https://github.com/o/r1.git"}
    assert urls == {"https://github.com/o/r1/commit/deadbeef"}
    assert "/search/commits" in h.session.calls[0][0]


def test_enum_scan_writes_repos_file(tmp_path):
    h = gh.GHunter(gh.Config(github_token="x", rate_limit=100000,
                             output_base_dir=tmp_path))

    def responder(url, params):
        if "/orgs/acme/repos" in url:
            return 200, [_repo_obj("a")]
        if "/gists" in url:
            return 200, [{"git_pull_url": "https://gist.github.com/g1.git"}]
        return 404, []

    # enum_scan opens its own session via create_session; patch it to our fake
    async def fake_create():
        h.session = _FakeSession(responder)
        h.semaphore = asyncio.Semaphore(1)

    h.create_session = fake_create
    asyncio.run(h.enum_scan(owner="acme", include_gists=True))

    lines = (tmp_path / "acme" / "repos.txt").read_text().splitlines()
    assert "https://github.com/o/a.git" in lines
    assert "https://gist.github.com/g1.git" in lines


# ----------------------------------------------------- NoseyParker -----------
def test_parse_noseyparker_git_provenance(hunter):
    report = json.dumps([{
        "rule_name": "AWS API Key", "rule_text_id": "np.aws.1",
        "matches": [{
            "snippet": {"matching": "AKIAEXAMPLE1234567890"},
            "location": {"source_span": {"start": {"line": 7}}},
            "provenance": [{"kind": "git_repo", "first_commit": {
                "blob_path": "config/aws.txt",
                "commit_metadata": {"commit_id": "abc123"}}}],
        }],
    }])
    fs = hunter.parse_noseyparker_results(report, "https://github.com/a/b")
    assert len(fs) == 1
    f = fs[0]
    assert f.detector_name == "AWS API Key" and f.detector_type == "np.aws.1"
    assert f.file_path == "config/aws.txt" and f.commit == "abc123"
    assert f.scan_tool == "noseyparker" and f.found_by == ["noseyparker"] and f.secret_hash
    raw = json.loads(f.raw_result)
    assert raw["Secret"] == "AKIAEXAMPLE1234567890" and raw["StartLine"] == 7


def test_parse_noseyparker_filesystem_provenance(hunter):
    report = json.dumps([{"rule_name": "X", "matches": [
        {"snippet": {"matching": "s3cr3t"}, "provenance": [{"kind": "file", "path": "a/b.txt"}]}]}])
    fs = hunter.parse_noseyparker_results(report, "r")
    assert fs[0].file_path == "a/b.txt"


def test_parse_noseyparker_bad_json(hunter):
    assert hunter.parse_noseyparker_results("not json", "r") == []


# --------------------------------------------------- custom rule packs -------
def test_rule_pack_explicit_override(hunter, tmp_path):
    cfg = tmp_path / "gl.toml"
    cfg.write_text("x")
    hunter.config.gitleaks_config = str(cfg)
    assert hunter._rule_pack("gitleaks") == str(cfg)


def test_rule_pack_from_rules_dir(hunter, tmp_path):
    rd = tmp_path / "rules"
    rd.mkdir()
    (rd / "gitleaks.toml").write_text("x")
    hunter.config.rules_dir = str(rd)
    assert hunter._rule_pack("gitleaks").endswith("gitleaks.toml")
    assert hunter._rule_pack("trufflehog") is None   # not present in dir


def test_gitleaks_cmd_includes_custom_config(hunter, tmp_path):
    cfg = tmp_path / "gl.toml"
    cfg.write_text("x")
    hunter.config.gitleaks_config = str(cfg)
    hunter._gitleaks_use_git_subcmd = True
    cmd = hunter._build_gitleaks_cmd(Path("/c"), Path("/o.json"))
    assert "--config" in cmd and str(cfg) in cmd


# ----------------------------------------------------- cross-run dedup -------
def test_scan_single_repo_marks_previously_seen(hunter, tmp_path, monkeypatch):
    f = make_finding(repo="https://github.com/a/b", file="x.py", hash="HASH")
    monkeypatch.setattr(hunter, "clone_repository", lambda u, d: (True, tmp_path / "r"))
    monkeypatch.setattr(hunter, "_register_clone", lambda p: None)
    monkeypatch.setattr(hunter, "_unregister_clone", lambda p: None)
    monkeypatch.setattr(hunter, "cleanup_clone", lambda p: None)
    monkeypatch.setattr(hunter, "run_trufflehog_local", lambda c, u: [f])
    hunter._seen_keys = {hunter._finding_key(f)}
    out = hunter._scan_single_repo("https://github.com/a/b", tmp_path, "trufflehog", True, False)
    assert out[0].previously_seen is True


def test_repo_scan_cross_run_new_then_seen(tmp_path):
    rf = tmp_path / "repos.txt"
    rf.write_text("https://github.com/o/r1.git\n")

    # Run 1: finding is new; store gets persisted
    h1 = _setup_hunter()

    def fake1(repo_url, *a):
        fnd = make_finding(repo=repo_url, file="a.py", hash="H1")
        fnd.severity = h1.derive_severity(fnd)
        return [fnd]

    h1._scan_single_repo = fake1
    asyncio.run(h1.repo_scan(repo_file=str(rf), scan_tool="trufflehog", resume=False))
    assert h1.progress.new_secrets == 1
    assert (tmp_path / ".ghunter_seen.json").exists()

    # Run 2: same fingerprint now loaded from the store -> not new
    h2 = _setup_hunter()

    def fake2(repo_url, *a):
        fnd = make_finding(repo=repo_url, file="a.py", hash="H1")
        fnd.severity = h2.derive_severity(fnd)
        if h2._finding_key(fnd) in (h2._seen_keys or set()):
            fnd.previously_seen = True
        return [fnd]

    h2._scan_single_repo = fake2
    asyncio.run(h2.repo_scan(repo_file=str(rf), scan_tool="trufflehog", resume=False))
    assert h2.progress.new_secrets == 0


def test_repo_scan_track_seen_disabled(tmp_path):
    rf = tmp_path / "repos.txt"
    rf.write_text("https://github.com/o/r1.git\n")
    h = gh.GHunter(gh.Config(github_token="x", max_repo_workers=2, track_seen=False))
    h.check_git = lambda: True
    h.check_trufflehog = lambda: True
    h.check_gitleaks = lambda: (True, "8.20.0")
    h._scan_single_repo = lambda repo_url, *a: [make_finding(repo=repo_url)]
    asyncio.run(h.repo_scan(repo_file=str(rf), scan_tool="trufflehog", resume=False))
    assert not (tmp_path / ".ghunter_seen.json").exists()


def test_report_noseyparker_and_seen_badges(hunter, tmp_path):
    rf = tmp_path / "scan_results.json"
    rf.write_text(json.dumps({
        "detector_type": "np.aws.1", "detector_name": "AWS", "verified": False,
        "repo_url": "https://x/y", "file_path": "a", "commit": "c", "timestamp": "t",
        "severity": "HIGH", "false_positive": False, "needs_review": False,
        "ai_analysis": None, "raw_result": "{}", "scan_tool": "noseyparker",
        "found_by": ["noseyparker"], "suppressed": False, "suppressed_by": "",
        "previously_seen": True,
    }) + "\n")
    hunter.generate_html_report(str(rf))
    html = (tmp_path / "report.html").read_text()
    assert "NoseyParker" in html
    assert 'data-previously-seen="true"' in html
    assert "Previously Seen" in html


# ------------------------------------------------ severity calibration -------
def test_severity_high_entropy_generic_promoted(hunter):
    raw = json.dumps({"Secret": "G7xQ!92zPq#1mVkLrTn8Bw", "Entropy": 4.9})
    assert hunter.derive_severity(make_finding(dt="generic", raw=raw)) == "HIGH"


def test_severity_low_entropy_generic_demoted(hunter):
    raw = json.dumps({"Secret": "aaaaaaaa", "Entropy": 1.0})
    assert hunter.derive_severity(make_finding(dt="generic", raw=raw)) == "LOW"


def test_severity_low_entropy_high_signal_demoted_to_medium(hunter):
    raw = json.dumps({"Secret": "changeme", "Entropy": 2.0})
    assert hunter.derive_severity(make_finding(dt="aws-key", raw=raw)) == "MEDIUM"


def test_severity_computes_entropy_when_field_absent(hunter):
    # No Entropy field -> entropy computed from the Secret value (high here)
    raw = json.dumps({"Secret": "qWeRtY12345!@#$%^&*()ZxCvBnM"})
    assert hunter.derive_severity(make_finding(dt="generic", raw=raw)) == "HIGH"


def test_severity_unchanged_without_value(hunter):
    # Regression: empty raw -> no entropy signal -> original behavior
    assert hunter.derive_severity(make_finding(dt="generic-misc")) == "MEDIUM"
    assert hunter.derive_severity(make_finding(dt="aws-key")) == "HIGH"


# --------------------------------------------------- SARIF / JSON export ------
def _export_rows(tmp_path, *rows):
    rf = tmp_path / "scan_results.json"
    rf.write_text("\n".join(json.dumps(r) for r in rows) + "\n")
    return rf


def test_to_sarif_structure():
    findings = [{
        "detector_type": "aws-key", "detector_name": "AWS Key", "severity": "CRITICAL",
        "verified": True, "repo_url": "https://github.com/a/b", "file_path": "cfg",
        "raw_result": json.dumps({"StartLine": 12}), "found_by": ["gitleaks"],
    }]
    doc = gh_export.to_sarif(findings)
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "G-Hunter"
    res = run["results"][0]
    assert res["ruleId"] == "aws-key"
    assert res["level"] == "error"                      # CRITICAL -> error
    assert res["locations"][0]["physicalLocation"]["region"]["startLine"] == 12


def test_to_sarif_marks_suppressed():
    findings = [{"detector_type": "t", "severity": "LOW", "file_path": "x",
                 "raw_result": "{}", "suppressed": True, "suppressed_by": "path:*.example"}]
    res = gh_export.to_sarif(findings)["runs"][0]["results"][0]
    assert res["level"] == "note"
    assert res["suppressions"][0]["kind"] == "external"


def test_json_export_envelope():
    findings = [{"severity": "HIGH", "verified": False, "raw_result": "{}"}]
    doc = gh_export.to_json_export(findings)
    assert doc["schema_version"] == "1.0"
    assert doc["summary"]["high"] == 1 and doc["summary"]["total"] == 1
    assert doc["findings"] == findings


def test_count_at_or_above_excludes_suppressed_and_fp():
    findings = [
        {"severity": "CRITICAL"},
        {"severity": "CRITICAL", "suppressed": True},
        {"severity": "HIGH", "false_positive": True},
        {"severity": "MEDIUM"},
    ]
    assert gh_export.count_at_or_above(findings, "HIGH") == 1   # only the clean CRITICAL
    assert gh_export.count_at_or_above(findings, "MEDIUM") == 2


def test_export_results_writes_sarif_and_gates(hunter, tmp_path):
    rf = _export_rows(tmp_path,
                      {"detector_type": "t", "severity": "CRITICAL", "file_path": "x",
                       "raw_result": "{}", "verified": True})
    gating = hunter.export_results(str(rf), fmt="sarif", fail_on="HIGH")
    out = tmp_path / "scan_results.sarif"
    assert out.exists()
    assert json.loads(out.read_text())["version"] == "2.1.0"
    assert gating == 1   # one CRITICAL at/above HIGH -> CI would exit non-zero


# ----------------------------------------------------------- audit log -------
def test_audit_writes_jsonl(hunter, tmp_path, monkeypatch):
    monkeypatch.setenv("GHUNTER_ACTOR", "tester")
    hunter._audit("repo_scan_start", tmp_path, tool="gitleaks", repo_count=3)
    rec = json.loads((tmp_path / "audit.jsonl").read_text().strip())
    assert rec["event"] == "repo_scan_start" and rec["actor"] == "tester"
    assert rec["tool"] == "gitleaks" and rec["repo_count"] == 3
    assert "timestamp" in rec


def test_audit_disabled_writes_nothing(tmp_path):
    h = gh.GHunter(gh.Config(github_token="x", audit_log=False))
    h._audit("repo_scan_start", tmp_path, tool="gitleaks")
    assert not (tmp_path / "audit.jsonl").exists()


# ----------------------------------------------------------- CLI parser ------
def test_cli_parser_subcommands():
    p = gh.build_parser()
    a = p.parse_args(["scan", "-k", "acme.com,acme"])
    assert a.command == "scan" and a.keywords == "acme.com,acme" and a.commits is False
    a = p.parse_args(["scan", "-k", "acme", "--commits"])
    assert a.commits is True
    a = p.parse_args(["enum", "-o", "acme"])
    assert a.command == "enum" and a.owner == "acme" and a.no_gists is False
    a = p.parse_args(["repo", "-f", "repos.txt", "-t", "both"])
    assert a.command == "repo" and a.tool == "both"
    a = p.parse_args(["repo", "-f", "r.txt", "-t", "all", "--rules-dir", "rules/",
                      "--no-track-seen"])
    assert a.tool == "all" and a.rules_dir == "rules/" and a.no_track_seen is True
    a = p.parse_args(["report", "-i", "out.json"])
    assert a.command == "report" and a.input == "out.json"
    a = p.parse_args(["export", "-i", "out.json", "-f", "sarif", "--fail-on", "HIGH"])
    assert a.command == "export" and a.format == "sarif" and a.fail_on == "HIGH"
