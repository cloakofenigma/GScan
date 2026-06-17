#!/usr/bin/env python3
"""G-Hunter - backwards-compatible entry point.

The implementation now lives in the ``ghunter`` package (split into focused
modules). This shim preserves ``python ghunter_pro.py`` and the public names
(``GHunter``, ``Config``, ``SecretFinding`` ...) that existing scripts and the
test suite import.
"""
from ghunter import (  # noqa: F401
    Config,
    ScanProgress,
    SecretFinding,
    GHunter,
    display_banner,
    build_parser,
    main,
)

# Re-export the optional-Gemini sentinels for compatibility.
from ghunter.ai import genai, GENAI_AVAILABLE  # noqa: F401

if __name__ == "__main__":
    main()
