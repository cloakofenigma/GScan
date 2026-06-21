"""HTML report generation (Jinja2, autoescaped)."""
import json
import os
from datetime import datetime
from pathlib import Path

from colorama import Fore, Style
from jinja2 import Environment, PackageLoader, select_autoescape

from .version import __version__

# Autoescape is on for all templates, so every value rendered with {{ }} is
# HTML-escaped by default — this is the primary defense against stored XSS in
# the report (a repo/file/secret name containing markup cannot break out).
_ENV = Environment(
    loader=PackageLoader("ghunter", "templates"),
    autoescape=select_autoescape(["html", "j2", "html.j2"], default=True),
)


def _http_only(url) -> str:
    """Return the URL if it is an http(s) link, else '#'."""
    if isinstance(url, str) and url.startswith(("https://", "http://")):
        return url
    return "#"


def _truncate(value, limit: int = 240) -> str:
    """Stringify and cap a value so a huge line can't blow up the report."""
    s = "" if value is None else str(value)
    return s if len(s) <= limit else s[:limit] + " …(truncated)"


def _extract_secret(finding: dict) -> dict:
    """Pull the matched secret value + context out of the scanner's raw JSON.

    Handles both Gitleaks (Secret/Match/StartLine/Link) and TruffleHog
    (Raw/RawV2/Redacted + SourceMetadata) output shapes. The raw value is
    captured during scanning but was never surfaced in the report before.
    """
    try:
        data = json.loads(finding.get("raw_result", "") or "")
    except (json.JSONDecodeError, TypeError):
        data = {}
    if not isinstance(data, dict):
        data = {}

    secret = data.get("Secret") or data.get("Raw") or data.get("RawV2") or data.get("Redacted") or ""
    match = data.get("Match") or data.get("Line") or ""
    line_no = data.get("StartLine")
    if line_no is None:
        line_no = (
            (data.get("SourceMetadata") or {}).get("Data", {}).get("Git", {}).get("line")
        )
    link = data.get("Link") or ""

    return {
        "secret": _truncate(secret),
        "match": _truncate(match),
        "line_no": line_no if isinstance(line_no, (int, str)) and str(line_no).strip() not in ("", "None") else None,
        "secret_link_href": _http_only(link),
        "has_link": bool(link),
    }


def _finding_view(idx: int, finding: dict) -> dict:
    """Build a template-safe view model for one finding.

    Only logic that cannot live in the template (scheme validation, tool
    classification) is done here; all escaping is handled by autoescape.
    """
    severity_raw = str(finding.get("severity", "UNKNOWN"))

    found_by = finding.get("found_by", [])
    scan_tool = finding.get("scan_tool", "")
    if len(found_by) > 1:
        tool_class, tool_text, tool_data = "badge-both", "Both", "both"
    elif "trufflehog" in found_by or scan_tool == "trufflehog":
        tool_class, tool_text, tool_data = "badge-trufflehog", "TruffleHog", "trufflehog"
    elif "gitleaks" in found_by or scan_tool == "gitleaks":
        tool_class, tool_text, tool_data = "badge-gitleaks", "Gitleaks", "gitleaks"
    else:
        tool_class, tool_text, tool_data = "badge-tool", "Unknown", "unknown"

    # Only allow http(s) links; anything else (e.g. javascript:) -> '#'
    repo_url_raw = finding.get("repo_url", "")
    if isinstance(repo_url_raw, str) and repo_url_raw.startswith(("https://", "http://")):
        repo_url_href = repo_url_raw
    else:
        repo_url_href = "#"

    suppressed = bool(finding.get("suppressed"))

    # AI assessment vs. error: a 429/quota failure (or legacy "AI error:" blob)
    # is shown as a short muted note, never as an assessment.
    ai = finding.get("ai_analysis") or {}
    ai_reason = ai.get("reason") if ai else None
    ai_error = bool(ai.get("error"))
    if ai_reason and str(ai_reason).startswith("AI error"):  # legacy results
        ai_error = True
        low = ai_reason.lower()
        if "429" in ai_reason or "quota" in low or "rate limit" in low:
            ai_reason = "AI triage skipped: Gemini rate limit / quota exceeded"
        else:
            ai_reason = "AI triage skipped: analysis failed"

    secret = _extract_secret(finding)
    return {
        "idx": idx,
        "suppressed": suppressed,
        "suppressed_attr": str(suppressed).lower(),
        "suppressed_by": finding.get("suppressed_by", ""),
        "secret": secret["secret"],
        "match": secret["match"],
        "line_no": secret["line_no"],
        "secret_link_href": secret["secret_link_href"],
        "has_secret_link": secret["has_link"],
        "ai_error": ai_error,
        "detector_name": finding.get("detector_name", "Unknown Detector"),
        "detector_type": finding.get("detector_type", "Unknown Type"),
        "severity": severity_raw.lower(),
        "severity_text": severity_raw,
        "verified": bool(finding.get("verified")),
        "verified_badge": "badge-verified" if finding.get("verified") else "badge-unverified",
        "verified_text": "Verified" if finding.get("verified") else "Unverified",
        "verified_attr": str(bool(finding.get("verified"))).lower(),
        "false_positive": bool(finding.get("false_positive")),
        "false_positive_attr": str(bool(finding.get("false_positive"))).lower(),
        "needs_review": bool(finding.get("needs_review")),
        "needs_review_attr": str(bool(finding.get("needs_review"))).lower(),
        "repo_url_href": repo_url_href,
        "repo_url_text": str(repo_url_raw) if repo_url_raw else "N/A",
        "file_path": finding.get("file_path", "N/A"),
        "commit": finding.get("commit", "N/A"),
        "timestamp": finding.get("timestamp", "N/A"),
        "tool_class": tool_class,
        "tool_text": tool_text,
        "tool_data": tool_data,
        "ai_reason": ai_reason,
    }


class ReportMixin:
    """Report generation mixed into GHunter."""

    def generate_html_report(self, results_file: str):
        """Generate the professional HTML report from a scan_results.json file."""
        if not os.path.exists(results_file):
            print(f"{Fore.RED}Error: Results file '{results_file}' not found!{Style.RESET_ALL}")
            return

        # Load findings (one JSON object per line)
        findings = []
        with open(results_file, "r") as f:
            for line in f:
                try:
                    findings.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

        if not findings:
            print(f"{Fore.RED}No findings to report!{Style.RESET_ALL}")
            return

        output_dir = Path(results_file).parent
        report_file = output_dir / "report.html"

        # Severity/tool counts reflect *active* findings only — allowlisted
        # (suppressed) findings are reported separately so they don't inflate
        # the dashboard while staying auditable.
        active = [f for f in findings if not f.get("suppressed")]

        def sev(level):
            return sum(1 for f in active if f.get("severity") == level)

        stats = {
            "total": len(findings),
            "suppressed": sum(1 for f in findings if f.get("suppressed")),
            "verified": sum(1 for f in active if f.get("verified")),
            "false_positives": sum(1 for f in active if f.get("false_positive")),
            "needs_review": sum(1 for f in active if f.get("needs_review")),
            "critical": sev("CRITICAL"),
            "high": sev("HIGH"),
            "medium": sev("MEDIUM"),
            "low": sev("LOW"),
            "by_trufflehog": sum(1 for f in active
                                 if "trufflehog" in f.get("found_by", [f.get("scan_tool", "")])),
            "by_gitleaks": sum(1 for f in active
                               if "gitleaks" in f.get("found_by", [f.get("scan_tool", "")])),
            "by_both_tools": sum(1 for f in active if len(f.get("found_by", [])) > 1),
        }

        template = _ENV.get_template("report.html.j2")
        html_content = template.render(
            generated=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            version=__version__,
            stats=stats,
            findings=[_finding_view(i, f) for i, f in enumerate(findings)],
        )

        with open(report_file, "w") as f:
            f.write(html_content)

        print(f"\n{Fore.GREEN}╔══════════════════════════════════════════════════════════════╗")
        print(f"║              HTML Report Generated Successfully!            ║")
        print(f"╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}")
        print(f"Report saved to: {report_file}")
        print(f"\nOpen in browser: file://{report_file.absolute()}\n")

    async def generate_report_menu(self):
        """Generate HTML report menu"""
        print(f"\n{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗")
        print(f"║           Generate HTML Report                              ║")
        print(f"╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}\n")

        results_file = input(f"{Fore.GREEN}Enter path to scan results JSON file:{Style.RESET_ALL} ").strip()

        if not os.path.exists(results_file):
            print(f"{Fore.RED}Error: Results file '{results_file}' not found!{Style.RESET_ALL}")
            return

        self.generate_html_report(results_file)
