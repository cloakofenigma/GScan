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

    ai = finding.get("ai_analysis") or {}
    return {
        "idx": idx,
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
        "ai_reason": ai.get("reason") if ai else None,
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

        def sev(level):
            return sum(1 for f in findings if f.get("severity") == level)

        stats = {
            "total": len(findings),
            "verified": sum(1 for f in findings if f.get("verified")),
            "false_positives": sum(1 for f in findings if f.get("false_positive")),
            "needs_review": sum(1 for f in findings if f.get("needs_review")),
            "critical": sev("CRITICAL"),
            "high": sev("HIGH"),
            "medium": sev("MEDIUM"),
            "low": sev("LOW"),
            "by_trufflehog": sum(1 for f in findings
                                 if "trufflehog" in f.get("found_by", [f.get("scan_tool", "")])),
            "by_gitleaks": sum(1 for f in findings
                               if "gitleaks" in f.get("found_by", [f.get("scan_tool", "")])),
            "by_both_tools": sum(1 for f in findings if len(f.get("found_by", [])) > 1),
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
