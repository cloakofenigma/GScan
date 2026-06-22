"""Export scan results to SARIF or normalized JSON for CI / SIEM pipelines.

SARIF 2.1.0 is consumed by GitHub code-scanning, DefectDojo, and most SIEMs.
The normalized JSON is a stable, summarized envelope around the raw findings.
Both are offline operations (no token needed), and `--fail-on` enables CI gating.
"""
import json
import os
from datetime import datetime, timezone
from pathlib import Path

from colorama import Fore, Style

from .version import __version__

_SEVERITY_ORDER = {"UNKNOWN": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
_SARIF_LEVEL = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning",
                "LOW": "note", "UNKNOWN": "none"}


def _load_findings(results_file: str) -> list:
    """Load findings from a JSONL scan_results file."""
    findings = []
    with open(results_file, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                findings.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return findings


def _start_line(finding: dict):
    """Best-effort line number for a finding (Gitleaks StartLine / TruffleHog)."""
    try:
        data = json.loads(finding.get("raw_result", "") or "")
    except (json.JSONDecodeError, TypeError):
        return None
    if not isinstance(data, dict):
        return None
    line = data.get("StartLine")
    if line is None:
        line = (data.get("SourceMetadata") or {}).get("Data", {}).get("Git", {}).get("line")
    try:
        return int(line) if line is not None else None
    except (ValueError, TypeError):
        return None


def _summarize(findings: list) -> dict:
    def count(level):
        return sum(1 for f in findings
                   if str(f.get("severity", "UNKNOWN")).upper() == level)
    return {
        "total": len(findings),
        "verified": sum(1 for f in findings if f.get("verified")),
        "suppressed": sum(1 for f in findings if f.get("suppressed")),
        "false_positives": sum(1 for f in findings if f.get("false_positive")),
        "critical": count("CRITICAL"),
        "high": count("HIGH"),
        "medium": count("MEDIUM"),
        "low": count("LOW"),
    }


def to_sarif(findings: list) -> dict:
    """Build a SARIF 2.1.0 document from findings."""
    rules: dict = {}
    results = []

    for f in findings:
        rule_id = str(f.get("detector_type") or "unknown")
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": rule_id,
                "shortDescription": {"text": str(f.get("detector_name") or rule_id)},
            }

        sev = str(f.get("severity", "UNKNOWN")).upper()
        line = _start_line(f)
        region = {"region": {"startLine": line}} if line else {}

        result = {
            "ruleId": rule_id,
            "level": _SARIF_LEVEL.get(sev, "warning"),
            "message": {"text": (
                f"{f.get('detector_name', 'Secret')} in "
                f"{f.get('file_path', 'unknown')} ({f.get('repo_url', '')})"
            )},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": str(f.get("file_path") or "unknown")},
                    **region,
                }
            }],
            "properties": {
                "severity": sev,
                "verified": bool(f.get("verified")),
                "repo_url": f.get("repo_url", ""),
                "commit": f.get("commit", ""),
                "scan_tool": f.get("scan_tool", ""),
                "found_by": f.get("found_by", []),
            },
        }
        if f.get("suppressed"):
            result["suppressions"] = [{
                "kind": "external",
                "justification": str(f.get("suppressed_by", "allowlisted")),
            }]
        results.append(result)

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "G-Hunter",
                "version": __version__,
                "informationUri": "https://github.com/",
                "rules": list(rules.values()),
            }},
            "results": results,
        }],
    }


def to_json_export(findings: list) -> dict:
    """Build a normalized, summarized JSON envelope around the findings."""
    return {
        "schema_version": "1.0",
        "generator": {"name": "G-Hunter", "version": __version__},
        "generated": datetime.now(timezone.utc).isoformat(),
        "summary": _summarize(findings),
        "findings": findings,
    }


def count_at_or_above(findings: list, threshold: str) -> int:
    """Count actionable findings (not suppressed/false-positive) at/above severity."""
    floor = _SEVERITY_ORDER.get(str(threshold).upper(), 99)
    return sum(
        1 for f in findings
        if not f.get("suppressed") and not f.get("false_positive")
        and _SEVERITY_ORDER.get(str(f.get("severity", "UNKNOWN")).upper(), 0) >= floor
    )


class ExportMixin:
    """SARIF / JSON export mixed into GHunter."""

    def export_results(self, results_file: str, fmt: str = "sarif",
                       output: str = None, fail_on: str = None) -> int:
        """Export results; returns the count of findings at/above `fail_on`.

        Returns 0 when no gating threshold is set. The caller (CLI) decides the
        process exit code from the returned count.
        """
        if not os.path.exists(results_file):
            print(f"{Fore.RED}Error: Results file '{results_file}' not found!{Style.RESET_ALL}")
            return 0

        findings = _load_findings(results_file)
        if not findings:
            print(f"{Fore.RED}No findings to export!{Style.RESET_ALL}")
            return 0

        if output:
            out_path = Path(output)
        else:
            suffix = ".sarif" if fmt == "sarif" else ".export.json"
            out_path = Path(results_file).with_suffix(suffix)

        doc = to_sarif(findings) if fmt == "sarif" else to_json_export(findings)
        out_path.write_text(json.dumps(doc, indent=2))

        print(f"\n{Fore.GREEN}Exported {len(findings)} findings to {fmt.upper()}:{Style.RESET_ALL} {out_path}")

        if fail_on:
            gating = count_at_or_above(findings, fail_on)
            if gating:
                print(f"{Fore.RED}{gating} finding(s) at/above {fail_on.upper()} "
                      f"(gating threshold).{Style.RESET_ALL}")
            return gating
        return 0
