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

    def fake(repo_url, clone_dir, scan_tool, tf, gl):
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


# ----------------------------------------------------------- CLI parser ------
def test_cli_parser_subcommands():
    p = gh.build_parser()
    a = p.parse_args(["scan", "-k", "acme.com,acme"])
    assert a.command == "scan" and a.keywords == "acme.com,acme"
    a = p.parse_args(["repo", "-f", "repos.txt", "-t", "both"])
    assert a.command == "repo" and a.tool == "both"
    a = p.parse_args(["report", "-i", "out.json"])
    assert a.command == "report" and a.input == "out.json"
