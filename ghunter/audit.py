"""Structured audit logging.

Writes one JSON object per significant action to `audit.jsonl` (in the scan's
output directory, falling back to the cwd). This records *what* was scanned,
*when*, and *by whom* — needed for any authorized-engagement / compliance use.
Best-effort: an audit-write failure must never break a scan.
"""
import json
import os
from datetime import datetime, timezone
from pathlib import Path


class AuditMixin:
    """Audit-trail logging mixed into GHunter."""

    @staticmethod
    def _audit_actor() -> str:
        """Identify who ran the scan (overridable for CI via GHUNTER_ACTOR)."""
        return (os.getenv("GHUNTER_ACTOR")
                or os.getenv("USER")
                or os.getenv("USERNAME")
                or "unknown")

    def _audit(self, event: str, output_dir=None, **fields) -> None:
        """Append one audit record. Never raises."""
        if not getattr(self.config, "audit_log", True):
            return
        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": event,
            "actor": self._audit_actor(),
            **fields,
        }
        try:
            base = Path(output_dir) if output_dir else Path(".")
            base.mkdir(parents=True, exist_ok=True)
            with open(base / "audit.jsonl", "a") as f:
                f.write(json.dumps(record) + "\n")
        except Exception as e:  # pragma: no cover - logging must not break scans
            self.logger.debug(f"Audit write failed: {e}")
