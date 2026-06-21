"""G-Hunter - Professional GitHub Secrets & Sensitive Information Hunter.

The application is split into focused modules; the GHunter class is composed
from feature mixins (see core.py). This package preserves the public names
that ghunter_pro.py historically exposed.
"""
import sys

# Fail fast with clear remediation rather than auto-installing anything.
try:
    import aiohttp  # noqa: F401
    import tqdm  # noqa: F401
    import colorama
    from dotenv import load_dotenv
except ImportError as e:  # pragma: no cover - environment setup error
    missing = getattr(e, "name", None) or str(e)
    sys.stderr.write(
        f"\nMissing required dependency: {missing}\n"
        "Install project dependencies first:\n"
        "    pip install -r requirements.txt\n"
        "(or: pip install -e .)\n\n"
    )
    raise SystemExit(1)

colorama.init(autoreset=True)
load_dotenv()

from .models import Config, ScanProgress, SecretFinding  # noqa: E402
from .allowlist import Allowlist  # noqa: E402
from .ui import display_banner  # noqa: E402
from .core import GHunter  # noqa: E402
from .cli import build_parser, main  # noqa: E402

__all__ = [
    "Config",
    "ScanProgress",
    "SecretFinding",
    "Allowlist",
    "GHunter",
    "display_banner",
    "build_parser",
    "main",
]
