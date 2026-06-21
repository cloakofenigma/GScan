"""Finding allowlist (`.ghunterignore`) to suppress known false positives.

The allowlist runs before AI triage and before the finding reaches the report,
so suppressed findings never consume a Gemini call and never add noise to the
dashboard. Suppressed findings are *tagged*, not dropped, so nothing becomes
invisible — the report still shows them (and a count) behind a filter.
"""
import fnmatch
import re
from pathlib import Path
from typing import List, Optional, Set, Tuple


class Allowlist:
    """Suppress findings matching user-provided rules.

    Rule file format — one rule per line, ``#`` starts a comment:

        path:<glob>          fnmatch glob against the finding's file path
        fingerprint:<hash>   exact match against the finding's secret_hash
        fp:<hash>            alias for fingerprint:
        regex:<pattern>      regex searched against the raw finding result
        <glob>               a bare line is treated as a path glob (gitignore-style)

    Invalid regex rules are skipped (and logged), never fatal — a typo in the
    allowlist must not abort a scan.
    """

    def __init__(self) -> None:
        self._path_globs: List[str] = []
        self._fingerprints: Set[str] = set()
        self._regexes: List[Tuple[str, "re.Pattern[str]"]] = []

    def __len__(self) -> int:
        return len(self._path_globs) + len(self._fingerprints) + len(self._regexes)

    def __bool__(self) -> bool:
        return len(self) > 0

    @classmethod
    def load(cls, paths, logger=None) -> "Allowlist":
        """Build an allowlist from one or more rule files (missing files are skipped)."""
        al = cls()
        seen: Set[str] = set()
        for path in paths:
            p = Path(path)
            try:
                if not p.is_file() or str(p.resolve()) in seen:
                    continue
                seen.add(str(p.resolve()))
                lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError as e:
                if logger:
                    logger.warning(f"Could not read allowlist {p}: {e}")
                continue
            for raw in lines:
                al._add_rule(raw, source=str(p), logger=logger)
        return al

    def _add_rule(self, raw: str, source: str = "", logger=None) -> None:
        line = raw.strip()
        if not line or line.startswith("#"):
            return
        lower = line.lower()
        if lower.startswith("path:"):
            self._path_globs.append(line[len("path:"):].strip())
        elif lower.startswith("fingerprint:"):
            self._fingerprints.add(line[len("fingerprint:"):].strip())
        elif lower.startswith("fp:"):
            self._fingerprints.add(line[len("fp:"):].strip())
        elif lower.startswith("regex:"):
            pat = line[len("regex:"):].strip()
            try:
                self._regexes.append((pat, re.compile(pat)))
            except re.error as e:
                if logger:
                    logger.warning(f"Skipping invalid allowlist regex in {source}: {pat!r} ({e})")
        else:
            # Bare line, gitignore-style: treat as a path glob.
            self._path_globs.append(line)

    def match(self, finding) -> Optional[str]:
        """Return the rule that suppresses this finding, or None if it passes.

        Accepts either a SecretFinding-like object (attributes) or a plain dict,
        so it works both during scanning and when re-checking persisted findings.
        """
        def get(key: str) -> str:
            if isinstance(finding, dict):
                val = finding.get(key, "")
            else:
                val = getattr(finding, key, "")
            return val or ""

        file_path = get("file_path")
        for glob in self._path_globs:
            if fnmatch.fnmatch(file_path, glob):
                return f"path:{glob}"

        fingerprint = get("secret_hash")
        if fingerprint and fingerprint in self._fingerprints:
            return f"fingerprint:{fingerprint}"

        raw = get("raw_result")
        for pat, rx in self._regexes:
            if rx.search(raw):
                return f"regex:{pat}"

        return None
