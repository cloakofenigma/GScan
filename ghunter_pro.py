#!/usr/bin/env python3
"""
G-Hunter - Professional GitHub Secrets & Sensitive Information Hunter
An enterprise-grade tool for discovering exposed secrets on GitHub

Features:
- Async GitHub API scanning with rate limiting
- TruffleHog integration for deep secret detection
- Google Gemini AI analysis for false positive reduction
- HTML report generation with modern UI
- Resume capability and progress tracking
- Secure environment-based configuration

Author: Security Research Team
Version: 3.0 Professional Edition
"""

import os
import sys
import json
import time
import asyncio
import aiohttp
import argparse
import logging
import signal
import subprocess
import shutil
import re
import html
import hashlib
from datetime import datetime
from pathlib import Path
from typing import List, Set, Dict, Optional, Tuple
from dataclasses import dataclass, asdict, field
from concurrent.futures import ThreadPoolExecutor

# Third-party imports with auto-install
try:
    from tqdm import tqdm
    import colorama
    from colorama import Fore, Back, Style
    from dotenv import load_dotenv
    import google.generativeai as genai
except ImportError as e:
    print(f"Installing required dependencies...")
    subprocess.check_call([
        sys.executable, "-m", "pip", "install",
        "tqdm", "colorama", "aiohttp", "python-dotenv", "google-generativeai"
    ])
    from tqdm import tqdm
    import colorama
    from colorama import Fore, Back, Style
    from dotenv import load_dotenv
    import google.generativeai as genai

# Initialize colorama
colorama.init(autoreset=True)

# Load environment variables
load_dotenv()

# ==================== CONFIGURATION ====================

@dataclass
class Config:
    """Application configuration"""
    github_token: str
    gemini_api_key: Optional[str] = None
    base_url: str = "https://api.github.com/search/code"
    rate_limit: int = 10  # requests per minute
    max_concurrent: int = 5
    max_pages: int = 10  # GitHub code search caps results at 1000 (10 pages x 100)
    timeout: int = 30
    retry_attempts: int = 3
    # Privacy: when False, secret values are stripped before sending findings to
    # the Gemini AI for triage. Set True to opt in to sending raw data off-host.
    ai_send_raw: bool = False
    valid_extensions: Set[str] = None
    output_base_dir: Path = Path("outputs")
    # Gitleaks integration settings
    gitleaks_path: str = "/usr/local/bin/gitleaks"
    clone_dir: str = "clones"  # Relative to output directory
    scan_timeout: int = 600  # 10 minutes per repo scan

    def __post_init__(self):
        if self.valid_extensions is None:
            self.valid_extensions = {
                ".php", ".rb", ".py", ".env", ".conf", ".java", ".txt", ".go", ".sql", ".yml",
                ".git", ".sh", ".js", ".ts", ".json", ".xml", ".ini", ".cfg", ".log", ".bak",
                ".db", ".sqlite", ".md", ".properties", ".key", ".pem", ".cert", ".csv",
                ".yaml", ".lock", ".htaccess", ".gitignore", ".config", ".secret", ".toml"
            }

@dataclass
class ScanProgress:
    """Track scan progress and statistics"""
    total_queries: int = 0
    completed_queries: int = 0
    repos_found: int = 0
    urls_found: int = 0
    secrets_found: int = 0
    verified_secrets: int = 0
    false_positives: int = 0
    needs_manual_review: int = 0
    errors: int = 0
    start_time: float = 0
    completed_repos: Set[str] = None
    completed_urls: Set[str] = None
    completed_queries_set: Set[str] = None
    # New fields for gitleaks integration
    scan_tool: str = ""  # "trufflehog" | "gitleaks" | "both"
    scanned_repos: Set[str] = None  # Repos fully scanned (for resume)
    clone_failures: int = 0  # Failed clone attempts

    def __post_init__(self):
        if self.completed_repos is None:
            self.completed_repos = set()
        if self.completed_urls is None:
            self.completed_urls = set()
        if self.completed_queries_set is None:
            self.completed_queries_set = set()
        if self.scanned_repos is None:
            self.scanned_repos = set()

@dataclass
class SecretFinding:
    """Represents a secret finding"""
    detector_type: str
    detector_name: str
    verified: bool
    raw_result: str
    repo_url: str
    file_path: str
    commit: str
    timestamp: str
    ai_analysis: Optional[Dict] = None
    false_positive: bool = False
    needs_review: bool = False
    severity: str = "UNKNOWN"
    # New fields for multi-tool support
    scan_tool: str = ""  # Primary tool that found it: "trufflehog" | "gitleaks"
    found_by: List[str] = field(default_factory=list)  # All tools that found it
    secret_hash: str = ""  # For deduplication (hash of secret value)

# ==================== ASCII BANNER ====================

def display_banner():
    """Display G-Hunter ASCII art banner"""
    banner = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════════════════╗
║                                                                          ║
║   ██████╗       ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗    ║
║  ██╔════╝       ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗   ║
║  ██║  ███╗█████╗███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝   ║
║  ██║   ██║╚════╝██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗   ║
║  ╚██████╔╝      ██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║   ║
║   ╚═════╝       ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝   ║
║                                                                          ║
║          {Fore.YELLOW}Professional GitHub Secrets & Sensitive Info Hunter{Fore.CYAN}           ║
║                    {Fore.GREEN}v3.0 Enterprise Edition{Fore.CYAN}                              ║
║                                                                          ║
║  {Fore.WHITE}Hunt for exposed secrets and sensitive information on GitHub{Fore.CYAN}        ║
║  {Fore.RED}⚠️  Use responsibly and only with proper authorization  ⚠️{Fore.CYAN}          ║
║                                                                          ║
╚══════════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""
    print(banner)

# ==================== MAIN APPLICATION CLASS ====================

class GHunter:
    """Main G-Hunter application class"""

    def __init__(self, config: Config):
        self.config = config
        self.progress = ScanProgress()
        self.session: Optional[aiohttp.ClientSession] = None
        self.semaphore: Optional[asyncio.Semaphore] = None
        self.shutdown_event = asyncio.Event()
        self.logger = self.setup_logging()
        self.setup_signal_handlers()
        self.gemini_model = None

        # Initialize Gemini if API key available
        if self.config.gemini_api_key:
            try:
                genai.configure(api_key=self.config.gemini_api_key)
                self.gemini_model = genai.GenerativeModel('gemini-2.0-flash')
                self.logger.info("Google Gemini AI initialized successfully")
            except Exception as e:
                self.logger.warning(f"Failed to initialize Gemini: {e}")

    def setup_logging(self) -> logging.Logger:
        """Setup comprehensive logging"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('ghunter.log'),
                logging.StreamHandler(sys.stdout)
            ]
        )
        return logging.getLogger('G-Hunter')

    def setup_signal_handlers(self):
        """Setup graceful shutdown handlers with clone cleanup"""
        def signal_handler(signum, frame):
            self.logger.info("Received shutdown signal. Cleaning up...")
            self.shutdown_event.set()

            # Cleanup any in-progress clone
            if hasattr(self, '_current_clone_path') and self._current_clone_path:
                try:
                    if self._current_clone_path.exists():
                        self.logger.info(f"Cleaning up interrupted clone: {self._current_clone_path}")
                        shutil.rmtree(self._current_clone_path)
                        self._current_clone_path = None
                except Exception as e:
                    self.logger.error(f"Failed to cleanup clone on interrupt: {e}")

        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

    def display_menu(self):
        """Display main menu"""
        menu = f"""
{Fore.CYAN}╔═══════════════════════════════════════════════════════════════════╗
║                          MAIN MENU                                ║
╠═══════════════════════════════════════════════════════════════════╣
║                                                                   ║
║  {Fore.GREEN}1.{Fore.CYAN} Git Scan - Scan GitHub for Sensitive Information             ║
║     {Fore.WHITE}• Search GitHub using keywords and git dorks{Fore.CYAN}                 ║
║     {Fore.WHITE}• Find exposed secrets, API keys, credentials{Fore.CYAN}                ║
║     {Fore.WHITE}• Save results to organized directories{Fore.CYAN}                      ║
║                                                                   ║
║  {Fore.GREEN}2.{Fore.CYAN} Repo Scan - Deep scan with TruffleHog/Gitleaks             ║
║     {Fore.WHITE}• Choose: TruffleHog, Gitleaks, or Both{Fore.CYAN}                      ║
║     {Fore.WHITE}• Clone-based local scanning for full history{Fore.CYAN}                ║
║     {Fore.WHITE}• AI-powered false positive reduction{Fore.CYAN}                        ║
║                                                                   ║
║  {Fore.GREEN}3.{Fore.CYAN} Generate HTML Report - Create professional reports          ║
║     {Fore.WHITE}• Modern, interactive HTML dashboard{Fore.CYAN}                         ║
║     {Fore.WHITE}• Filterable results with severity levels{Fore.CYAN}                    ║
║     {Fore.WHITE}• Export findings for stakeholders{Fore.CYAN}                           ║
║                                                                   ║
║  {Fore.GREEN}4.{Fore.CYAN} Help - View detailed usage instructions                     ║
║                                                                   ║
║  {Fore.GREEN}5.{Fore.CYAN} Exit - Quit G-Hunter                                        ║
║                                                                   ║
╚═══════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""
        print(menu)

    def display_help(self):
        """Display help information"""
        help_text = f"""
{Fore.YELLOW}╔══════════════════════════════════════════════════════════════════════════╗
║                           G-HUNTER HELP                                  ║
╚══════════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}

{Fore.GREEN}OVERVIEW:{Style.RESET_ALL}
G-Hunter is a professional-grade tool for identifying exposed secrets and
sensitive information on GitHub repositories using advanced dorking techniques,
TruffleHog/Gitleaks scanning, and AI-powered analysis.

{Fore.GREEN}PREREQUISITES:{Style.RESET_ALL}
1. GitHub Personal Access Token (PAT) with 'public_repo' scope
   → Create at: https://github.com/settings/tokens

2. Git (required for repository cloning)
   → Install: sudo apt install git (Linux)
   → Install: brew install git (macOS)

3. TruffleHog v3.x (for secret scanning - optional)
   → Download binary: https://github.com/trufflesecurity/trufflehog/releases
   → Linux install:
     wget https://github.com/trufflesecurity/trufflehog/releases/download/v3.63.7/trufflehog_3.63.7_linux_amd64.tar.gz
     tar -xzf trufflehog_3.63.7_linux_amd64.tar.gz
     sudo mv trufflehog /usr/local/bin/

4. Gitleaks (for secret scanning - optional)
   → Download binary: https://github.com/gitleaks/gitleaks/releases
   → Linux install:
     wget https://github.com/gitleaks/gitleaks/releases/download/v8.18.2/gitleaks_8.18.2_linux_x64.tar.gz
     tar -xzf gitleaks_8.18.2_linux_x64.tar.gz
     sudo mv gitleaks /usr/local/bin/

5. Google Gemini API Key (optional, for AI analysis)
   → Get at: https://makersuite.google.com/app/apikey

{Fore.GREEN}CONFIGURATION:{Style.RESET_ALL}
Set environment variables in .env file:
   GITHUB_TOKEN=ghp_your_token_here
   GEMINI_API_KEY=your_gemini_key_here (optional)

{Fore.GREEN}MENU OPTIONS:{Style.RESET_ALL}

{Fore.CYAN}1. Git Scan{Style.RESET_ALL}
   • Searches GitHub using keywords (company names, domains, usernames)
   • Combines keywords with git dorks for targeted searches
   • Creates organized output in: outputs/<keyword>/
   • Saves repository URLs in .git format for cloning
   • Supports resume functionality for interrupted scans

   {Fore.YELLOW}Example:{Style.RESET_ALL}
   Keywords: acme.com, acme-corp, acme
   Dorks file: gitDorks.txt
   Output: outputs/acme.com/repos.txt

{Fore.CYAN}2. Repo Scan{Style.RESET_ALL}
   • Choose scanning tool: TruffleHog, Gitleaks, or Both
   • Clones repositories locally for full history scanning
   • Automatic deduplication when using both tools
   • AI-powered false positive reduction (with Gemini)
   • Generates JSON results with detailed metadata

   {Fore.YELLOW}Scanning Tools Comparison:{Style.RESET_ALL}
   ┌────────────┬───────────────────────────────────────────┐
   │ TruffleHog │ • Verifies secrets (checks if active)     │
   │            │ • Best for API keys, tokens, passwords    │
   │            │ • Fast with known patterns                │
   ├────────────┼───────────────────────────────────────────┤
   │ Gitleaks   │ • Comprehensive pattern matching          │
   │            │ • Scans entire git history (--log-opts)   │
   │            │ • Good for custom patterns                │
   ├────────────┼───────────────────────────────────────────┤
   │ Both       │ • Maximum coverage                        │
   │            │ • Automatic deduplication                 │
   │            │ • Tracks which tool found each secret     │
   └────────────┴───────────────────────────────────────────┘

   {Fore.YELLOW}Example:{Style.RESET_ALL}
   Input: outputs/acme.com/repos.txt
   Output: outputs/acme.com/scan_results.json

{Fore.CYAN}3. Generate HTML Report{Style.RESET_ALL}
   • Creates professional, interactive HTML dashboard
   • Filter by: severity, verification status, scan tool
   • Color-coded badges showing which tool found each secret
   • False positive and manual review indicators
   • Exportable for stakeholders

   {Fore.YELLOW}Example:{Style.RESET_ALL}
   Input: outputs/acme.com/scan_results.json
   Output: outputs/acme.com/report.html

{Fore.GREEN}BEST PRACTICES:{Style.RESET_ALL}
✓ Always get authorization before scanning
✓ Respect GitHub's rate limits and ToS
✓ Use specific keywords for targeted results
✓ Use "Both" option for maximum secret detection coverage
✓ Review AI-flagged items manually
✓ Revoke and rotate any exposed secrets immediately
✓ Report findings responsibly

{Fore.GREEN}KEYWORD EXAMPLES:{Style.RESET_ALL}
• Company: acme, acme-corp, acmeinc
• Domains: acme.com, api.acme.com
• Emails: @acme.com
• Usernames: acme-admin, acme-dev

{Fore.RED}LEGAL DISCLAIMER:{Style.RESET_ALL}
This tool is for educational and authorized security testing ONLY.
Unauthorized access to computer systems is illegal. Always obtain
proper authorization before conducting security assessments.

{Fore.GREEN}SUPPORT:{Style.RESET_ALL}
For issues, questions, or contributions:
→ GitHub: https://github.com/your-repo/g-hunter
→ Email: security@yourcompany.com
"""
        print(help_text)

    def _detect_trufflehog_version(self) -> Optional[str]:
        """Detect TruffleHog version and determine if it's v2.x (Python) or v3.x (Go)"""
        try:
            # Try v3.x version command (Go binary)
            result = subprocess.run(
                ['trufflehog', '--version'],
                capture_output=True,
                text=True,
                timeout=5
            )

            if result.returncode == 0 and result.stdout.strip():
                version = result.stdout.strip()
                # v3.x outputs: "trufflehog 3.91.2"
                match = re.search(r'(\d+\.\d+\.?\d*)', version)
                if match:
                    return match.group(1)

            # Try v3.x help command to detect subcommands
            result = subprocess.run(
                ['trufflehog', '--help'],
                capture_output=True,
                text=True,
                timeout=5
            )

            if result.returncode == 0:
                # v3.x has subcommands like 'git', v2.x doesn't
                if '<command>' in result.stdout or 'git' in result.stdout.lower():
                    # Likely v3.x but couldn't get exact version
                    return "3.0+"

                # v2.x has 'git_url' as positional argument
                if 'git_url' in result.stdout:
                    self.logger.warning("Detected TruffleHog v2.x (Python) - incompatible!")
                    return "2.x"

            # Try running with no args - v2.x shows different help
            result = subprocess.run(
                ['trufflehog'],
                capture_output=True,
                text=True,
                timeout=5
            )

            # Check for v2.x signature
            if 'git_url' in result.stdout or 'git_url' in result.stderr:
                return "2.x"

            # Check for v3.x signature
            if 'command' in result.stdout.lower():
                return "3.0+"

        except Exception as e:
            self.logger.error(f"Error detecting TruffleHog version: {e}")

        return None

    def check_trufflehog(self) -> bool:
        """Check if TruffleHog is installed using multiple detection methods"""
        trufflehog_path = shutil.which("trufflehog")

        if not trufflehog_path:
            self.logger.debug("TruffleHog not found in PATH")
            return False

        # Method 1: Try --version (most reliable but sometimes fails with exit code 2)
        try:
            result = subprocess.run(
                ['trufflehog', '--version'],
                capture_output=True,
                text=True,
                timeout=5
            )

            self.logger.debug(f"TruffleHog path: {trufflehog_path}")
            self.logger.debug(f"Version check return code: {result.returncode}")
            self.logger.debug(f"Version output: {result.stdout.strip()}")

            if result.returncode == 0:
                return True

        except subprocess.TimeoutExpired:
            self.logger.warning("TruffleHog --version timed out")
        except Exception as e:
            self.logger.warning(f"TruffleHog --version failed: {e}")

        # Method 2: Try --help (more reliable, always returns 0)
        try:
            result = subprocess.run(
                ['trufflehog', '--help'],
                capture_output=True,
                text=True,
                timeout=5
            )

            if result.returncode == 0 and 'trufflehog' in result.stdout.lower():
                self.logger.debug("TruffleHog detected via --help command")
                return True

        except Exception as e:
            self.logger.warning(f"TruffleHog --help failed: {e}")

        # Method 3: Try running without args (fallback)
        try:
            result = subprocess.run(
                ['trufflehog'],
                capture_output=True,
                text=True,
                timeout=5
            )

            if 'trufflehog' in result.stdout.lower() or 'credentials' in result.stdout.lower():
                self.logger.debug("TruffleHog detected via no-args command")
                return True

        except Exception as e:
            self.logger.warning(f"TruffleHog no-args check failed: {e}")

        # Method 4: Check if file exists and is executable (last resort)
        try:
            import os
            if os.path.isfile(trufflehog_path) and os.access(trufflehog_path, os.X_OK):
                self.logger.info(f"TruffleHog binary found and executable at {trufflehog_path}")
                return True
        except Exception as e:
            self.logger.warning(f"TruffleHog file check failed: {e}")

        # All methods failed
        self.logger.error(f"TruffleHog found at {trufflehog_path} but all verification methods failed")
        return False

    def check_git(self) -> bool:
        """Check if git is installed (required for cloning repositories)"""
        git_path = shutil.which("git")
        if not git_path:
            self.logger.debug("Git not found in PATH")
            return False

        try:
            result = subprocess.run(
                ['git', '--version'],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                self.logger.debug(f"Git found: {result.stdout.strip()}")
                return True
        except Exception as e:
            self.logger.warning(f"Git check failed: {e}")

        return False

    def check_gitleaks(self) -> Tuple[bool, Optional[str]]:
        """Check if Gitleaks is installed and return version"""
        gitleaks_path = shutil.which("gitleaks")
        if not gitleaks_path:
            # Also check configured path
            if os.path.isfile(self.config.gitleaks_path) and os.access(self.config.gitleaks_path, os.X_OK):
                gitleaks_path = self.config.gitleaks_path
            else:
                self.logger.debug("Gitleaks not found in PATH or configured path")
                return False, None

        try:
            result = subprocess.run(
                [gitleaks_path, 'version'],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                version = result.stdout.strip()
                self.logger.debug(f"Gitleaks found: {version}")
                return True, version
        except Exception as e:
            self.logger.warning(f"Gitleaks version check failed: {e}")

        # Try alternative version command
        try:
            result = subprocess.run(
                [gitleaks_path, '--version'],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                version = result.stdout.strip()
                return True, version
        except Exception as e:
            self.logger.warning(f"Gitleaks --version check failed: {e}")

        # Check if executable exists
        if os.path.isfile(gitleaks_path) and os.access(gitleaks_path, os.X_OK):
            return True, "unknown"

        return False, None

    def check_dependencies(self):
        """Check all required dependencies"""
        issues = []
        successes = []
        warnings = []

        # Check GitHub token
        if not self.config.github_token:
            issues.append("GitHub token not configured (set GITHUB_TOKEN environment variable)")
        else:
            # Mask token for security
            masked_token = self.config.github_token[:10] + "..." if len(self.config.github_token) > 10 else "***"
            successes.append(f"GitHub token configured ({masked_token})")

        # Check Git (required for cloning)
        git_installed = self.check_git()
        if not git_installed:
            issues.append("Git not installed (required for Repo Scan)")
        else:
            try:
                result = subprocess.run(['git', '--version'],
                                      capture_output=True, text=True, timeout=5)
                version = result.stdout.strip() if result.returncode == 0 else "unknown"
                successes.append(f"Git installed ({version})")
            except:
                successes.append("Git installed")

        # Check TruffleHog for repo scanning
        trufflehog_installed = self.check_trufflehog()
        if not trufflehog_installed:
            warnings.append("TruffleHog not installed (optional - for TruffleHog scanning)")
        else:
            try:
                result = subprocess.run(['trufflehog', '--version'],
                                      capture_output=True, text=True, timeout=5)
                version = result.stdout.strip() if result.returncode == 0 else "unknown"
                successes.append(f"TruffleHog installed ({version})")
            except:
                successes.append("TruffleHog installed")

        # Check Gitleaks for repo scanning
        gitleaks_installed, gitleaks_version = self.check_gitleaks()
        if not gitleaks_installed:
            warnings.append("Gitleaks not installed (optional - for Gitleaks scanning)")
        else:
            successes.append(f"Gitleaks installed ({gitleaks_version or 'unknown'})")

        # Check Gemini API
        if self.config.gemini_api_key:
            successes.append("Google Gemini API configured (AI analysis enabled)")

        # Display results
        if successes:
            print(f"\n{Fore.GREEN}✓ Dependencies Ready:{Style.RESET_ALL}")
            for success in successes:
                print(f"  • {success}")

        if warnings:
            print(f"\n{Fore.YELLOW}⚠️  Optional Dependencies:{Style.RESET_ALL}")
            for warning in warnings:
                print(f"  • {warning}")

        if issues:
            print(f"\n{Fore.RED}✗ Dependency Issues:{Style.RESET_ALL}")
            for issue in issues:
                print(f"  • {issue}")
            print(f"\n{Fore.YELLOW}Run option 4 (Help) for installation instructions{Style.RESET_ALL}\n")

        if not issues:
            print()  # Extra newline for clean spacing

    def load_dorks(self, dorks_file: str) -> List[str]:
        """Load dorks from file"""
        try:
            with open(dorks_file, 'r') as f:
                dorks = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            self.logger.info(f"Loaded {len(dorks)} dorks from {dorks_file}")
            return dorks
        except FileNotFoundError:
            self.logger.error(f"Dorks file '{dorks_file}' not found")
            return []
        except Exception as e:
            self.logger.error(f"Error loading dorks: {e}")
            return []

    def save_progress(self, output_dir: Path):
        """Save progress to checkpoint file"""
        progress_file = output_dir / "progress.json"
        try:
            progress_data = {
                'total_queries': self.progress.total_queries,
                'completed_queries': self.progress.completed_queries,
                'repos_found': self.progress.repos_found,
                'urls_found': self.progress.urls_found,
                'secrets_found': self.progress.secrets_found,
                'verified_secrets': self.progress.verified_secrets,
                'false_positives': self.progress.false_positives,
                'needs_manual_review': self.progress.needs_manual_review,
                'errors': self.progress.errors,
                'start_time': self.progress.start_time,
                'completed_repos': list(self.progress.completed_repos),
                'completed_urls': list(self.progress.completed_urls),
                'completed_queries_set': list(self.progress.completed_queries_set),
                # New fields for gitleaks integration
                'scan_tool': self.progress.scan_tool,
                'scanned_repos': list(self.progress.scanned_repos),
                'clone_failures': self.progress.clone_failures
            }
            with open(progress_file, 'w') as f:
                json.dump(progress_data, f, indent=2)
        except Exception as e:
            self.logger.error(f"Error saving progress: {e}")

    def load_progress(self, output_dir: Path) -> ScanProgress:
        """Load progress from checkpoint file"""
        progress_file = output_dir / "progress.json"
        if progress_file.exists():
            try:
                with open(progress_file, 'r') as f:
                    data = json.load(f)

                progress = ScanProgress()
                progress.total_queries = data.get('total_queries', 0)
                progress.completed_queries = data.get('completed_queries', 0)
                progress.repos_found = data.get('repos_found', 0)
                progress.urls_found = data.get('urls_found', 0)
                progress.secrets_found = data.get('secrets_found', 0)
                progress.verified_secrets = data.get('verified_secrets', 0)
                progress.false_positives = data.get('false_positives', 0)
                progress.needs_manual_review = data.get('needs_manual_review', 0)
                progress.errors = data.get('errors', 0)
                progress.start_time = data.get('start_time', 0)
                progress.completed_repos = set(data.get('completed_repos', []))
                progress.completed_urls = set(data.get('completed_urls', []))
                progress.completed_queries_set = set(data.get('completed_queries_set', []))
                # New fields for gitleaks integration
                progress.scan_tool = data.get('scan_tool', '')
                progress.scanned_repos = set(data.get('scanned_repos', []))
                progress.clone_failures = data.get('clone_failures', 0)

                self.logger.info(f"Loaded progress: {progress.completed_queries}/{progress.total_queries} queries")
                return progress
            except Exception as e:
                self.logger.error(f"Error loading progress: {e}")

        return ScanProgress()

    def get_repo_name_from_url(self, repo_url: str) -> str:
        """Extract repository name from URL"""
        # Handle URLs like https://github.com/username/reponame.git
        name = repo_url.rstrip('/').split('/')[-1]
        if name.endswith('.git'):
            name = name[:-4]
        return name

    def clone_repository(self, repo_url: str, clone_dir: Path) -> Tuple[bool, Optional[Path]]:
        """Clone a repository to the specified directory"""
        repo_name = self.get_repo_name_from_url(repo_url)
        clone_path = clone_dir / repo_name

        # Remove existing clone if present
        if clone_path.exists():
            self.cleanup_clone(clone_path)

        try:
            self.logger.info(f"Cloning {repo_url} to {clone_path}")
            result = subprocess.run(
                ['git', 'clone', '--quiet', repo_url, str(clone_path)],
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout for clone
            )

            if result.returncode == 0:
                self.logger.info(f"Successfully cloned {repo_name}")
                return True, clone_path
            else:
                self.logger.error(f"Clone failed for {repo_url}: {result.stderr}")
                return False, None

        except subprocess.TimeoutExpired:
            self.logger.error(f"Clone timeout for {repo_url}")
            # Cleanup partial clone
            if clone_path.exists():
                self.cleanup_clone(clone_path)
            return False, None
        except Exception as e:
            self.logger.error(f"Clone error for {repo_url}: {e}")
            if clone_path.exists():
                self.cleanup_clone(clone_path)
            return False, None

    def cleanup_clone(self, clone_path: Path):
        """Remove cloned repository directory"""
        try:
            if clone_path.exists():
                shutil.rmtree(clone_path)
                self.logger.debug(f"Cleaned up {clone_path}")
        except Exception as e:
            self.logger.error(f"Failed to cleanup {clone_path}: {e}")

    # Track current clone path for cleanup on interrupt
    _current_clone_path: Optional[Path] = None

    async def create_session(self):
        """Create async HTTP session"""
        headers = {
            "Authorization": f"token {self.config.github_token}",
            "Accept": "application/vnd.github+json",
            "User-Agent": "G-Hunter/3.0"
        }
        timeout = aiohttp.ClientTimeout(total=self.config.timeout)
        self.session = aiohttp.ClientSession(headers=headers, timeout=timeout)
        self.semaphore = asyncio.Semaphore(self.config.max_concurrent)

    async def close_session(self):
        """Close async HTTP session"""
        if self.session and not self.session.closed:
            await self.session.close()
            await asyncio.sleep(0.1)

    def _rate_limit_wait(self, response) -> int:
        """Compute how long to back off on a 403/429 using GitHub headers."""
        # Retry-After (seconds) is used for secondary/abuse rate limits
        retry_after = response.headers.get("Retry-After")
        if retry_after:
            try:
                return max(1, int(retry_after))
            except ValueError:
                pass
        # Fall back to X-RateLimit-Reset (epoch seconds) when the budget is spent
        reset = response.headers.get("X-RateLimit-Reset")
        remaining = response.headers.get("X-RateLimit-Remaining")
        if reset and remaining == "0":
            try:
                wait = int(reset) - int(time.time())
                if wait > 0:
                    return min(wait + 1, 120)
            except ValueError:
                pass
        return 60

    async def search_github(self, keyword: str, dork: str) -> Tuple[Set[str], Set[str]]:
        """Search GitHub with retry logic and pagination.

        The code-search API returns at most 100 results per page and 1000
        results total (10 pages). We page through results until a short page is
        returned, the per-query cap is reached, or an error stops us.
        """
        async with self.semaphore:
            query = f"{keyword} {dork}"
            repos, urls = set(), set()
            per_page = 100

            for page in range(1, self.config.max_pages + 1):
                if self.shutdown_event.is_set():
                    break

                page_items = None  # None = page could not be fetched

                for attempt in range(self.config.retry_attempts):
                    try:
                        params = {"q": query, "per_page": per_page, "page": page}

                        async with self.session.get(self.config.base_url, params=params) as response:
                            if response.status == 200:
                                data = await response.json()
                                page_items = data.get("items", [])
                                break

                            elif response.status in (403, 429):
                                wait = self._rate_limit_wait(response)
                                self.logger.warning(f"Rate limit hit for '{query}', waiting {wait}s...")
                                await asyncio.sleep(wait)
                                continue

                            elif response.status == 422:
                                # Invalid query, or paging past the 1000-result cap
                                self.logger.debug(f"422 for '{query}' page {page} (end of results)")
                                page_items = []
                                break

                            else:
                                self.logger.error(f"HTTP {response.status} for '{query}'")

                    except Exception as e:
                        self.logger.error(f"Attempt {attempt + 1} failed for '{query}': {e}")
                        if attempt < self.config.retry_attempts - 1:
                            await asyncio.sleep(2 ** attempt)
                        else:
                            self.progress.errors += 1

                # Could not fetch this page after all retries -> stop paging
                if page_items is None:
                    break

                for item in page_items:
                    repo_url = item["repository"]["html_url"]
                    file_url = item["html_url"]

                    # Append .git suffix for clone compatibility
                    if not repo_url.endswith(".git"):
                        repo_url = repo_url + ".git"
                    repos.add(repo_url)

                    # Check file extension
                    if any(file_url.lower().endswith(ext) for ext in self.config.valid_extensions):
                        urls.add(file_url)

                # Last page reached (short or empty page)
                if len(page_items) < per_page:
                    break

                # Throttle between pages of the same query
                await asyncio.sleep(60 / self.config.rate_limit)

            # Throttle between queries
            await asyncio.sleep(60 / self.config.rate_limit)
            return repos, urls

    async def git_scan(self):
        """Main Git scan functionality"""
        print(f"\n{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗")
        print(f"║            Git Scan - GitHub Dorking Search                 ║")
        print(f"╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}\n")

        # Get user input
        keywords_input = input(f"{Fore.GREEN}Enter keywords (comma-separated):{Style.RESET_ALL} ").strip()
        if not keywords_input:
            print(f"{Fore.RED}Error: No keywords provided!{Style.RESET_ALL}")
            return

        keywords = [k.strip() for k in keywords_input.split(",") if k.strip()]

        # Get dorks file
        dorks_file = input(f"{Fore.GREEN}Enter path to git dorks file (default: gitDorks.txt):{Style.RESET_ALL} ").strip()
        if not dorks_file:
            dorks_file = "gitDorks.txt"

        if not os.path.exists(dorks_file):
            print(f"{Fore.RED}Error: Dorks file '{dorks_file}' not found!{Style.RESET_ALL}")
            return

        # Load dorks
        dorks = self.load_dorks(dorks_file)
        if not dorks:
            print(f"{Fore.RED}No dorks loaded!{Style.RESET_ALL}")
            return

        # Create output directory
        first_keyword = keywords[0].replace("/", "_").replace("\\", "_")
        output_dir = self.config.output_base_dir / first_keyword
        output_dir.mkdir(parents=True, exist_ok=True)

        # Ask about resume
        resume = False
        progress_file = output_dir / "progress.json"
        if progress_file.exists():
            resume_input = input(f"{Fore.YELLOW}Previous scan found. Resume? (y/n):{Style.RESET_ALL} ").strip().lower()
            resume = resume_input == 'y'

        # Load or create progress
        if resume:
            self.progress = self.load_progress(output_dir)
            print(f"{Fore.GREEN}Resuming scan... ({self.progress.completed_queries}/{self.progress.total_queries} completed){Style.RESET_ALL}")
        else:
            self.progress = ScanProgress()
            self.progress.total_queries = len(keywords) * len(dorks)
            self.progress.start_time = time.time()

        # Output files
        repos_file_path = output_dir / "repos.txt"
        urls_file_path = output_dir / "urls.txt"

        # Open files in append mode
        repos_file_mode = 'a' if resume else 'w'
        urls_file_mode = 'a' if resume else 'w'

        print(f"\n{Fore.YELLOW}Starting scan...{Style.RESET_ALL}")
        print(f"Keywords: {', '.join(keywords)}")
        print(f"Dorks: {len(dorks)} loaded")
        print(f"Output directory: {output_dir}\n")

        await self.create_session()

        try:
            with open(repos_file_path, repos_file_mode) as repos_file, \
                 open(urls_file_path, urls_file_mode) as urls_file:

                with tqdm(total=self.progress.total_queries,
                         initial=self.progress.completed_queries,
                         desc="Scanning",
                         bar_format='{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]') as pbar:

                    for keyword in keywords:
                        for dork in dorks:
                            if self.shutdown_event.is_set():
                                break

                            query = f"{keyword}:::{dork}"

                            # Skip if already completed
                            if query in self.progress.completed_queries_set:
                                continue

                            repos, urls = await self.search_github(keyword, dork)

                            # Write new results
                            for repo in repos:
                                if repo not in self.progress.completed_repos:
                                    repos_file.write(f"{repo}\n")
                                    repos_file.flush()
                                    self.progress.completed_repos.add(repo)
                                    self.progress.repos_found += 1

                            for url in urls:
                                if url not in self.progress.completed_urls:
                                    urls_file.write(f"{url}\n")
                                    urls_file.flush()
                                    self.progress.completed_urls.add(url)
                                    self.progress.urls_found += 1

                            # Mark query as completed
                            self.progress.completed_queries_set.add(query)
                            self.progress.completed_queries += 1

                            # Save progress
                            self.save_progress(output_dir)

                            pbar.update(1)
                            pbar.set_postfix({
                                'Repos': self.progress.repos_found,
                                'URLs': self.progress.urls_found,
                                'Errors': self.progress.errors
                            })

                        if self.shutdown_event.is_set():
                            break

        except Exception as e:
            self.logger.error(f"Error during scan: {e}")
            self.progress.errors += 1

        finally:
            await self.close_session()

        # Display results
        elapsed_time = time.time() - self.progress.start_time
        print(f"\n{Fore.GREEN}╔══════════════════════════════════════════════════════════════╗")
        print(f"║                    Scan Completed!                          ║")
        print(f"╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}")
        print(f"Time elapsed: {elapsed_time:.2f} seconds")
        print(f"Repositories found: {self.progress.repos_found}")
        print(f"File URLs found: {self.progress.urls_found}")
        print(f"Errors: {self.progress.errors}")
        print(f"\nResults saved to: {output_dir}/")
        print(f"  • {repos_file_path}")
        print(f"  • {urls_file_path}\n")

    # Keys in scanner JSON output that may carry the actual secret value
    _SECRET_KEYS = {"Raw", "RawV2", "Redacted", "Secret", "Match", "Line"}

    def _ai_context(self, finding: SecretFinding) -> str:
        """Build the finding context sent to the AI.

        By default the raw secret value is stripped so credentials never leave
        the host. Set ai_send_raw=True in Config to opt in to sending raw data.
        """
        if self.config.ai_send_raw:
            return finding.raw_result[:500]

        try:
            data = json.loads(finding.raw_result)
        except (json.JSONDecodeError, TypeError):
            return "[raw data redacted]"

        def scrub(obj):
            if isinstance(obj, dict):
                return {
                    k: ("[REDACTED]" if k in self._SECRET_KEYS else scrub(v))
                    for k, v in obj.items()
                }
            if isinstance(obj, list):
                return [scrub(v) for v in obj]
            return obj

        return json.dumps(scrub(data))[:500]

    async def analyze_with_gemini(self, finding: SecretFinding) -> Dict:
        """Analyze finding with Google Gemini AI"""
        if not self.gemini_model:
            return {
                "false_positive": False,
                "needs_review": True,
                "severity": "UNKNOWN",
                "reason": "AI analysis not available"
            }

        try:
            ai_context = self._ai_context(finding)
            prompt = f"""Analyze this potential secret finding and determine:
1. Is this a FALSE POSITIVE? (test data, example, placeholder, etc.)
2. Does it need MANUAL REVIEW?
3. What is the SEVERITY? (CRITICAL, HIGH, MEDIUM, LOW)
4. Brief REASON for your assessment

Finding Details:
- Detector: {finding.detector_name}
- Type: {finding.detector_type}
- Verified: {finding.verified}
- Repository: {finding.repo_url}
- File: {finding.file_path}

Metadata (secret value redacted):
{ai_context}

Respond in JSON format:
{{
  "false_positive": true/false,
  "needs_review": true/false,
  "severity": "CRITICAL/HIGH/MEDIUM/LOW",
  "reason": "brief explanation"
}}
"""

            response = self.gemini_model.generate_content(prompt)
            result_text = response.text.strip()

            # Extract JSON from response
            json_match = re.search(r'\{.*\}', result_text, re.DOTALL)
            if json_match:
                analysis = json.loads(json_match.group())
                return analysis

            return {
                "false_positive": False,
                "needs_review": True,
                "severity": "UNKNOWN",
                "reason": "Could not parse AI response"
            }

        except Exception as e:
            self.logger.error(f"Gemini analysis error: {e}")
            return {
                "false_positive": False,
                "needs_review": True,
                "severity": "UNKNOWN",
                "reason": f"AI error: {str(e)}"
            }

    def run_trufflehog_local(self, clone_path: Path, repo_url: str) -> List[SecretFinding]:
        """Run TruffleHog scan on a local clone using file:// protocol"""
        findings = []

        try:
            # Use file:// protocol to scan local clone with full git history
            file_url = f"file://{clone_path.absolute()}"

            self.logger.info(f"Running TruffleHog on {clone_path}")
            result = subprocess.run(
                ['trufflehog', 'git', file_url, '--json', '--no-update'],
                capture_output=True,
                text=True,
                timeout=self.config.scan_timeout
            )

            if result.stdout:
                for line in result.stdout.strip().splitlines():
                    try:
                        secret_data = json.loads(line)

                        # Extract secret value for hashing (for deduplication)
                        raw_secret = secret_data.get('Raw', '')
                        secret_hash = hashlib.sha256(raw_secret.encode()).hexdigest()[:16] if raw_secret else ''

                        finding = SecretFinding(
                            detector_type=secret_data.get('DetectorType', 'Unknown'),
                            detector_name=secret_data.get('DetectorName', 'Unknown'),
                            verified=secret_data.get('Verified', False),
                            raw_result=line,
                            repo_url=repo_url,
                            file_path=secret_data.get('SourceMetadata', {}).get('Data', {}).get('Git', {}).get('file',
                                      secret_data.get('SourceMetadata', {}).get('Data', {}).get('Filesystem', {}).get('file', 'Unknown')),
                            commit=secret_data.get('SourceMetadata', {}).get('Data', {}).get('Git', {}).get('commit', 'Unknown'),
                            timestamp=datetime.now().isoformat(),
                            scan_tool="trufflehog",
                            found_by=["trufflehog"],
                            secret_hash=secret_hash
                        )

                        findings.append(finding)

                    except json.JSONDecodeError:
                        continue

            # Log errors (filter out harmless updater errors)
            if result.stderr:
                stderr_lower = result.stderr.lower()
                if "error" in stderr_lower and "updater" not in stderr_lower:
                    self.logger.warning(f"TruffleHog stderr: {result.stderr[:200]}")

        except subprocess.TimeoutExpired:
            self.logger.warning(f"TruffleHog timeout for {clone_path}")
        except Exception as e:
            self.logger.error(f"TruffleHog error for {clone_path}: {e}")

        return findings

    def run_gitleaks_local(self, clone_path: Path, repo_url: str, output_file: Path) -> List[SecretFinding]:
        """Run Gitleaks scan on a local clone with full git history"""
        findings = []

        try:
            self.logger.info(f"Running Gitleaks on {clone_path}")

            # Run gitleaks with full history scan
            result = subprocess.run(
                ['gitleaks', 'detect',
                 '--source', str(clone_path),
                 '--log-opts', '--all',  # Scan entire git history
                 '--report-format', 'json',
                 '--report-path', str(output_file),
                 '-v'],
                capture_output=True,
                text=True,
                timeout=self.config.scan_timeout
            )

            # Gitleaks returns exit code 1 if leaks found, 0 if no leaks
            # Parse the output file
            if output_file.exists():
                findings = self.parse_gitleaks_results(output_file, repo_url)

            # Log any errors
            if result.returncode not in [0, 1] and result.stderr:
                self.logger.warning(f"Gitleaks stderr: {result.stderr[:200]}")

        except subprocess.TimeoutExpired:
            self.logger.warning(f"Gitleaks timeout for {clone_path}")
        except Exception as e:
            self.logger.error(f"Gitleaks error for {clone_path}: {e}")

        return findings

    def parse_gitleaks_results(self, json_file: Path, repo_url: str) -> List[SecretFinding]:
        """Parse Gitleaks JSON output into SecretFinding objects"""
        findings = []

        try:
            with open(json_file, 'r') as f:
                data = json.load(f)

            if not isinstance(data, list):
                data = [data] if data else []

            for item in data:
                # Extract secret value for hashing (for deduplication)
                raw_secret = item.get('Secret', '')
                secret_hash = hashlib.sha256(raw_secret.encode()).hexdigest()[:16] if raw_secret else ''

                finding = SecretFinding(
                    detector_type=item.get('RuleID', 'Unknown'),
                    detector_name=item.get('Description', item.get('RuleID', 'Unknown')),
                    verified=False,  # Gitleaks doesn't verify secrets
                    raw_result=json.dumps(item),
                    repo_url=repo_url,
                    file_path=item.get('File', 'Unknown'),
                    commit=item.get('Commit', 'Unknown'),
                    timestamp=datetime.now().isoformat(),
                    scan_tool="gitleaks",
                    found_by=["gitleaks"],
                    secret_hash=secret_hash
                )

                findings.append(finding)

        except json.JSONDecodeError as e:
            self.logger.error(f"Failed to parse Gitleaks JSON: {e}")
        except Exception as e:
            self.logger.error(f"Error parsing Gitleaks results: {e}")

        return findings

    def deduplicate_findings(self, findings: List[SecretFinding]) -> List[SecretFinding]:
        """Deduplicate findings from multiple tools based on repo+file+secret_hash"""
        deduplicated = {}

        for finding in findings:
            # Create unique key based on repo, file, and secret hash
            key = f"{finding.repo_url}:{finding.file_path}:{finding.secret_hash}"

            if key in deduplicated:
                # Merge found_by lists
                existing = deduplicated[key]
                for tool in finding.found_by:
                    if tool not in existing.found_by:
                        existing.found_by.append(tool)
                # If one tool verified, keep it verified
                if finding.verified:
                    existing.verified = True
                # Update scan_tool to indicate both if different
                if finding.scan_tool not in existing.scan_tool:
                    existing.scan_tool = "both"
            else:
                deduplicated[key] = finding

        return list(deduplicated.values())

    def display_tool_selection_menu(self) -> Optional[str]:
        """Display tool selection menu and return user choice"""
        menu = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗
║                  SELECT SCANNING TOOL                        ║
╠══════════════════════════════════════════════════════════════╣
║                                                              ║
║  {Fore.GREEN}1.{Fore.CYAN} TruffleHog  - Fast, good at known secret patterns       ║
║     {Fore.WHITE}• Verifies secrets where possible{Fore.CYAN}                       ║
║     {Fore.WHITE}• Best for API keys, tokens, passwords{Fore.CYAN}                  ║
║                                                              ║
║  {Fore.GREEN}2.{Fore.CYAN} Gitleaks    - Comprehensive, full git history scan      ║
║     {Fore.WHITE}• Scans entire commit history{Fore.CYAN}                           ║
║     {Fore.WHITE}• Good pattern-based detection{Fore.CYAN}                          ║
║                                                              ║
║  {Fore.GREEN}3.{Fore.CYAN} Both        - Maximum coverage (sequential scan)        ║
║     {Fore.WHITE}• Run both tools on each repository{Fore.CYAN}                     ║
║     {Fore.WHITE}• Deduplicates findings automatically{Fore.CYAN}                   ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""
        print(menu)

        choice = input(f"{Fore.GREEN}Enter your choice [1-3]:{Style.RESET_ALL} ").strip()

        if choice == "1":
            return "trufflehog"
        elif choice == "2":
            return "gitleaks"
        elif choice == "3":
            return "both"
        else:
            print(f"{Fore.RED}Invalid choice!{Style.RESET_ALL}")
            return None

    def run_trufflehog_scan(self, repo_file: str, output_dir: Path):
        """Run TruffleHog scan on repositories"""
        if not os.path.exists(repo_file):
            print(f"{Fore.RED}Error: Repo file '{repo_file}' not found!{Style.RESET_ALL}")
            return

        with open(repo_file, 'r') as f:
            repos = [line.strip() for line in f if line.strip()]

        if not repos:
            print(f"{Fore.RED}No repositories found in file!{Style.RESET_ALL}")
            return

        # Verify TruffleHog version before starting
        print(f"\n{Fore.CYAN}Verifying TruffleHog installation...{Style.RESET_ALL}")
        trufflehog_version = self._detect_trufflehog_version()

        if not trufflehog_version:
            print(f"{Fore.RED}Unable to determine TruffleHog version!{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}Please ensure TruffleHog v3.x is installed{Style.RESET_ALL}\n")
            return

        if trufflehog_version.startswith('2'):
            print(f"{Fore.RED}TruffleHog v{trufflehog_version} detected (v2.x - OLD Python version)!{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}G-Hunter requires TruffleHog v3.x (Go binary){Style.RESET_ALL}")
            print(f"\n{Fore.CYAN}Please uninstall the old version and install v3.x:{Style.RESET_ALL}")
            print(f"  1. Uninstall old version: {Fore.WHITE}pip uninstall trufflehog{Style.RESET_ALL}")
            print(f"  2. Install v3.x:")
            print(f"     - macOS: {Fore.WHITE}brew install trufflehog{Style.RESET_ALL}")
            print(f"     - Linux: {Fore.WHITE}Download from https://github.com/trufflesecurity/trufflehog/releases{Style.RESET_ALL}")
            print(f"     - Or use: {Fore.WHITE}curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin{Style.RESET_ALL}\n")
            return

        print(f"{Fore.GREEN}✓ TruffleHog v{trufflehog_version} detected (v3.x compatible){Style.RESET_ALL}\n")
        print(f"{Fore.YELLOW}Starting TruffleHog scan of {len(repos)} repositories...{Style.RESET_ALL}\n")

        results_file = output_dir / "scan_results.json"
        findings: List[SecretFinding] = []

        with tqdm(total=len(repos), desc="Scanning repos") as pbar:
            for repo_url in repos:
                if self.shutdown_event.is_set():
                    break

                try:
                    repo_name = repo_url.split('/')[-1] if '/' in repo_url else repo_url
                    pbar.set_description(f"Scanning {repo_name}")

                    # Run TruffleHog v3.x with correct syntax
                    # Command: trufflehog git <url> --only-verified --json
                    result = subprocess.run(
                        ['trufflehog', 'git', repo_url, '--only-verified', '--json', '--no-update'],
                        capture_output=True,
                        text=True,
                        timeout=300
                    )

                    if result.stdout:
                        for line in result.stdout.strip().splitlines():
                            try:
                                secret_data = json.loads(line)

                                # Create finding object
                                finding = SecretFinding(
                                    detector_type=secret_data.get('DetectorType', 'Unknown'),
                                    detector_name=secret_data.get('DetectorName', 'Unknown'),
                                    verified=secret_data.get('Verified', False),
                                    raw_result=line,
                                    repo_url=repo_url,
                                    file_path=secret_data.get('SourceMetadata', {}).get('Data', {}).get('Filesystem', {}).get('file', 'Unknown'),
                                    commit=secret_data.get('SourceMetadata', {}).get('Data', {}).get('Git', {}).get('commit', 'Unknown'),
                                    timestamp=datetime.now().isoformat()
                                )

                                findings.append(finding)
                                self.progress.secrets_found += 1

                                if finding.verified:
                                    self.progress.verified_secrets += 1

                            except json.JSONDecodeError:
                                continue

                    # Check for errors in stderr
                    if result.stderr:
                        stderr_lower = result.stderr.lower()

                        # Check for v2.x syntax errors (unrecognized arguments)
                        if "unrecognized arguments" in stderr_lower or "git_url" in result.stderr:
                            self.logger.error(f"TruffleHog v2.x syntax error detected!")
                            self.logger.error(f"You may have TruffleHog v2.x (Python) installed instead of v3.x (Go)")
                            self.logger.error(f"Run 'pip uninstall trufflehog' and install v3.x")
                            # Don't spam - just log once
                            if not hasattr(self, '_syntax_error_logged'):
                                self._syntax_error_logged = True
                                print(f"\n{Fore.RED}⚠️  TruffleHog syntax error detected!{Style.RESET_ALL}")
                                print(f"{Fore.YELLOW}You likely have TruffleHog v2.x (Python) instead of v3.x (Go){Style.RESET_ALL}")
                                print(f"{Fore.CYAN}To fix:{Style.RESET_ALL}")
                                print(f"  1. pip uninstall trufflehog")
                                print(f"  2. Install v3.x from https://github.com/trufflesecurity/trufflehog/releases\n")

                        # Log other errors (but filter out the updater error which is harmless)
                        elif "error" in stderr_lower and "updater" not in stderr_lower:
                            self.logger.error(f"TruffleHog error for {repo_url}: {result.stderr}")

                except subprocess.TimeoutExpired:
                    self.logger.warning(f"Timeout scanning {repo_url}")
                    self.progress.errors += 1
                except Exception as e:
                    self.logger.error(f"Error scanning {repo_url}: {e}")
                    self.progress.errors += 1

                pbar.update(1)
                pbar.set_postfix({'Secrets': self.progress.secrets_found})

        # AI Analysis if Gemini available
        if self.gemini_model and findings:
            print(f"\n{Fore.YELLOW}Running AI analysis on {len(findings)} findings...{Style.RESET_ALL}\n")

            with tqdm(total=len(findings), desc="AI Analysis") as pbar:
                for finding in findings:
                    if self.shutdown_event.is_set():
                        break

                    # Run async analysis in sync context
                    analysis = asyncio.run(self.analyze_with_gemini(finding))
                    finding.ai_analysis = analysis
                    finding.false_positive = analysis.get('false_positive', False)
                    finding.needs_review = analysis.get('needs_review', False)
                    finding.severity = analysis.get('severity', 'UNKNOWN')

                    if finding.false_positive:
                        self.progress.false_positives += 1
                    if finding.needs_review:
                        self.progress.needs_manual_review += 1

                    pbar.update(1)
                    time.sleep(0.5)  # Rate limit Gemini API

        # Save results
        with open(results_file, 'w') as f:
            for finding in findings:
                f.write(json.dumps({
                    'detector_type': finding.detector_type,
                    'detector_name': finding.detector_name,
                    'verified': finding.verified,
                    'repo_url': finding.repo_url,
                    'file_path': finding.file_path,
                    'commit': finding.commit,
                    'timestamp': finding.timestamp,
                    'severity': finding.severity,
                    'false_positive': finding.false_positive,
                    'needs_review': finding.needs_review,
                    'ai_analysis': finding.ai_analysis,
                    'raw_result': finding.raw_result
                }) + '\n')

        print(f"\n{Fore.GREEN}╔══════════════════════════════════════════════════════════════╗")
        print(f"║              TruffleHog Scan Completed!                     ║")
        print(f"╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}")
        print(f"Total secrets found: {self.progress.secrets_found}")
        print(f"Verified secrets: {self.progress.verified_secrets}")
        print(f"False positives (AI): {self.progress.false_positives}")
        print(f"Needs manual review: {self.progress.needs_manual_review}")
        print(f"Errors: {self.progress.errors}")
        print(f"\nResults saved to: {results_file}\n")

    async def repo_scan(self):
        """Repository scan functionality with tool selection"""
        print(f"\n{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗")
        print(f"║         Repo Scan - Deep Secret Scanning                    ║")
        print(f"╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}\n")

        # Check Git (required for cloning)
        if not self.check_git():
            print(f"{Fore.RED}Git not found!{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}Git is required for cloning repositories.{Style.RESET_ALL}")
            print("Installation: sudo apt install git\n")
            return

        # Check available tools
        trufflehog_available = self.check_trufflehog()
        gitleaks_available, gitleaks_version = self.check_gitleaks()

        if not trufflehog_available and not gitleaks_available:
            print(f"{Fore.RED}No scanning tools found!{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}Please install at least one of:{Style.RESET_ALL}")
            print("  • TruffleHog: https://github.com/trufflesecurity/trufflehog/releases")
            print("  • Gitleaks: https://github.com/gitleaks/gitleaks/releases\n")
            return

        # Display tool selection menu
        scan_tool = self.display_tool_selection_menu()
        if not scan_tool:
            return

        # Validate tool availability based on selection
        if scan_tool == "trufflehog" and not trufflehog_available:
            print(f"{Fore.RED}TruffleHog not installed!{Style.RESET_ALL}")
            return
        if scan_tool == "gitleaks" and not gitleaks_available:
            print(f"{Fore.RED}Gitleaks not installed!{Style.RESET_ALL}")
            return
        if scan_tool == "both":
            if not trufflehog_available:
                print(f"{Fore.YELLOW}Warning: TruffleHog not available, using Gitleaks only{Style.RESET_ALL}")
                scan_tool = "gitleaks"
            elif not gitleaks_available:
                print(f"{Fore.YELLOW}Warning: Gitleaks not available, using TruffleHog only{Style.RESET_ALL}")
                scan_tool = "trufflehog"

        # Get repo file path
        repo_file = input(f"\n{Fore.GREEN}Enter path to repos file:{Style.RESET_ALL} ").strip()

        if not os.path.exists(repo_file):
            print(f"{Fore.RED}Error: Repo file '{repo_file}' not found!{Style.RESET_ALL}")
            return

        # Load repositories
        with open(repo_file, 'r') as f:
            repos = [line.strip() for line in f if line.strip()]

        if not repos:
            print(f"{Fore.RED}No repositories found in file!{Style.RESET_ALL}")
            return

        # Determine output directory
        repo_path = Path(repo_file)
        output_dir = repo_path.parent

        # Create clones directory
        clone_dir = output_dir / self.config.clone_dir
        clone_dir.mkdir(parents=True, exist_ok=True)

        # Output file
        results_file = output_dir / "scan_results.json"

        # Resume support: reuse prior progress + results when a checkpoint exists
        progress_file = output_dir / "progress.json"
        resume = False
        if progress_file.exists():
            resume_input = input(
                f"{Fore.YELLOW}Previous repo scan found. Resume? (y/n):{Style.RESET_ALL} "
            ).strip().lower()
            resume = resume_input == 'y'

        if resume:
            self.progress = self.load_progress(output_dir)
            print(f"{Fore.GREEN}Resuming repo scan... "
                  f"({len(self.progress.scanned_repos)} repos already scanned){Style.RESET_ALL}")
        else:
            self.progress = ScanProgress()
            self.progress.start_time = time.time()
        self.progress.scan_tool = scan_tool

        # Append when resuming so previously-written findings are preserved
        results_mode = 'a' if resume else 'w'

        print(f"\n{Fore.YELLOW}Starting {scan_tool.upper()} scan of {len(repos)} repositories...{Style.RESET_ALL}")
        print(f"Clone directory: {clone_dir}")
        print(f"Output directory: {output_dir}\n")

        def serialize(finding: SecretFinding) -> str:
            return json.dumps({
                'detector_type': finding.detector_type,
                'detector_name': finding.detector_name,
                'verified': finding.verified,
                'repo_url': finding.repo_url,
                'file_path': finding.file_path,
                'commit': finding.commit,
                'timestamp': finding.timestamp,
                'severity': finding.severity,
                'false_positive': finding.false_positive,
                'needs_review': finding.needs_review,
                'ai_analysis': finding.ai_analysis,
                'raw_result': finding.raw_result,
                'scan_tool': finding.scan_tool,
                'found_by': finding.found_by
            })

        # Keep the results file open for the whole scan and flush per-repo so an
        # interrupted run can be resumed without losing completed work.
        with open(results_file, results_mode) as results_out:
            with tqdm(total=len(repos), initial=len(self.progress.scanned_repos),
                      desc="Scanning repos") as pbar:
                for repo_url in repos:
                    if self.shutdown_event.is_set():
                        print(f"\n{Fore.YELLOW}Scan interrupted. Progress saved - resume to continue.{Style.RESET_ALL}")
                        break

                    # Skip if already scanned (resume)
                    if repo_url in self.progress.scanned_repos:
                        pbar.update(1)
                        continue

                    repo_name = self.get_repo_name_from_url(repo_url)
                    pbar.set_description(f"Cloning {repo_name}")

                    # Clone repository
                    success, clone_path = self.clone_repository(repo_url, clone_dir)

                    if not success:
                        self.progress.clone_failures += 1
                        self.progress.errors += 1
                        self.save_progress(output_dir)
                        pbar.update(1)
                        pbar.set_postfix({'Errors': self.progress.errors, 'Secrets': self.progress.secrets_found})
                        continue

                    # Track current clone for cleanup on interrupt
                    self._current_clone_path = clone_path

                    repo_findings = []

                    try:
                        # Run selected tool(s)
                        if scan_tool in ["trufflehog", "both"] and trufflehog_available:
                            pbar.set_description(f"TruffleHog: {repo_name}")
                            tf_findings = self.run_trufflehog_local(clone_path, repo_url)
                            repo_findings.extend(tf_findings)

                        if scan_tool in ["gitleaks", "both"] and gitleaks_available:
                            pbar.set_description(f"Gitleaks: {repo_name}")
                            gl_output = clone_dir / f"{repo_name}_gitleaks.json"
                            gl_findings = self.run_gitleaks_local(clone_path, repo_url, gl_output)
                            repo_findings.extend(gl_findings)
                            # Cleanup gitleaks output file
                            if gl_output.exists():
                                gl_output.unlink()
                    finally:
                        # Always cleanup clone
                        pbar.set_description(f"Cleanup: {repo_name}")
                        self.cleanup_clone(clone_path)
                        self._current_clone_path = None

                    # Deduplicate this repo's findings when both tools ran
                    # (the dedup key includes repo_url, so per-repo == global)
                    if scan_tool == "both" and repo_findings:
                        repo_findings = self.deduplicate_findings(repo_findings)

                    # AI analysis per-repo so resumed runs keep analyzed results
                    if self.gemini_model and repo_findings:
                        for finding in repo_findings:
                            if self.shutdown_event.is_set():
                                break
                            analysis = await self.analyze_with_gemini(finding)
                            finding.ai_analysis = analysis
                            finding.false_positive = analysis.get('false_positive', False)
                            finding.needs_review = analysis.get('needs_review', False)
                            finding.severity = analysis.get('severity', 'UNKNOWN')
                            if finding.false_positive:
                                self.progress.false_positives += 1
                            if finding.needs_review:
                                self.progress.needs_manual_review += 1
                            time.sleep(0.5)  # Rate limit Gemini API

                    # Update counters and persist findings for this repo
                    for finding in repo_findings:
                        self.progress.secrets_found += 1
                        if finding.verified:
                            self.progress.verified_secrets += 1
                        results_out.write(serialize(finding) + '\n')
                    results_out.flush()

                    # Mark repo as scanned and checkpoint
                    self.progress.scanned_repos.add(repo_url)
                    self.save_progress(output_dir)

                    pbar.update(1)
                    pbar.set_postfix({
                        'Secrets': self.progress.secrets_found,
                        'Errors': self.progress.errors
                    })

        # Cleanup clones directory if empty
        try:
            if clone_dir.exists() and not any(clone_dir.iterdir()):
                clone_dir.rmdir()
        except:
            pass

        # Calculate statistics from the full results file (covers resumed runs)
        elapsed_time = time.time() - self.progress.start_time
        persisted = []
        if results_file.exists():
            with open(results_file, 'r') as rf:
                for line in rf:
                    try:
                        persisted.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        found_by_trufflehog = sum(1 for f in persisted if 'trufflehog' in f.get('found_by', []))
        found_by_gitleaks = sum(1 for f in persisted if 'gitleaks' in f.get('found_by', []))
        found_by_both = sum(1 for f in persisted if len(f.get('found_by', [])) > 1)

        # Display results
        print(f"\n{Fore.GREEN}╔══════════════════════════════════════════════════════════════╗")
        print(f"║                    Scan Completed!                          ║")
        print(f"╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}")
        print(f"Time elapsed: {elapsed_time:.2f} seconds")
        print(f"Repositories scanned: {len(self.progress.scanned_repos)}")
        print(f"Clone failures: {self.progress.clone_failures}")
        print(f"\n{Fore.CYAN}Findings Summary:{Style.RESET_ALL}")
        print(f"  Total secrets found: {self.progress.secrets_found}")
        print(f"  Verified secrets: {self.progress.verified_secrets}")
        if scan_tool == "both":
            print(f"  Found by TruffleHog: {found_by_trufflehog}")
            print(f"  Found by Gitleaks: {found_by_gitleaks}")
            print(f"  Found by Both: {found_by_both}")
        if self.gemini_model:
            print(f"  False positives (AI): {self.progress.false_positives}")
            print(f"  Needs manual review: {self.progress.needs_manual_review}")
        print(f"  Errors: {self.progress.errors}")
        print(f"\nResults saved to: {results_file}\n")

    def generate_html_report(self, results_file: str):
        """Generate professional HTML report"""
        if not os.path.exists(results_file):
            print(f"{Fore.RED}Error: Results file '{results_file}' not found!{Style.RESET_ALL}")
            return

        # Load findings
        findings = []
        with open(results_file, 'r') as f:
            for line in f:
                try:
                    findings.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

        if not findings:
            print(f"{Fore.RED}No findings to report!{Style.RESET_ALL}")
            return

        # Generate HTML
        output_dir = Path(results_file).parent
        report_file = output_dir / "report.html"

        # Count statistics
        total = len(findings)
        verified = sum(1 for f in findings if f.get('verified'))
        false_positives = sum(1 for f in findings if f.get('false_positive'))
        needs_review = sum(1 for f in findings if f.get('needs_review'))
        critical = sum(1 for f in findings if f.get('severity') == 'CRITICAL')
        high = sum(1 for f in findings if f.get('severity') == 'HIGH')
        medium = sum(1 for f in findings if f.get('severity') == 'MEDIUM')
        low = sum(1 for f in findings if f.get('severity') == 'LOW')
        # Tool-specific statistics
        by_trufflehog = sum(1 for f in findings if 'trufflehog' in f.get('found_by', [f.get('scan_tool', '')]))
        by_gitleaks = sum(1 for f in findings if 'gitleaks' in f.get('found_by', [f.get('scan_tool', '')]))
        by_both_tools = sum(1 for f in findings if len(f.get('found_by', [])) > 1)

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>G-Hunter Security Report</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            color: #333;
        }}

        .container {{
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            border-radius: 10px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            overflow: hidden;
        }}

        header {{
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }}

        header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
        }}

        header p {{
            font-size: 1.1em;
            opacity: 0.9;
        }}

        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            padding: 30px;
            background: #f8f9fa;
        }}

        .stat-card {{
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            text-align: center;
            transition: transform 0.2s;
        }}

        .stat-card:hover {{
            transform: translateY(-5px);
        }}

        .stat-value {{
            font-size: 2.5em;
            font-weight: bold;
            margin: 10px 0;
        }}

        .stat-label {{
            color: #666;
            font-size: 0.9em;
            text-transform: uppercase;
        }}

        .critical {{ color: #dc3545; }}
        .high {{ color: #fd7e14; }}
        .medium {{ color: #ffc107; }}
        .low {{ color: #28a745; }}

        .controls {{
            padding: 20px 30px;
            background: white;
            border-bottom: 1px solid #ddd;
            display: flex;
            gap: 15px;
            flex-wrap: wrap;
            align-items: center;
        }}

        .search-box {{
            flex: 1;
            min-width: 250px;
        }}

        .search-box input {{
            width: 100%;
            padding: 10px 15px;
            border: 1px solid #ddd;
            border-radius: 5px;
            font-size: 14px;
        }}

        .filter-group {{
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
        }}

        .filter-btn {{
            padding: 8px 16px;
            border: 1px solid #ddd;
            background: white;
            border-radius: 5px;
            cursor: pointer;
            transition: all 0.2s;
            font-size: 14px;
        }}

        .filter-btn:hover {{
            background: #f8f9fa;
        }}

        .filter-btn.active {{
            background: #007bff;
            color: white;
            border-color: #007bff;
        }}

        .findings {{
            padding: 30px;
        }}

        .finding-card {{
            background: white;
            border: 1px solid #ddd;
            border-radius: 8px;
            margin-bottom: 20px;
            overflow: hidden;
            transition: box-shadow 0.2s;
        }}

        .finding-card:hover {{
            box-shadow: 0 4px 12px rgba(0,0,0,0.1);
        }}

        .finding-header {{
            background: #f8f9fa;
            padding: 15px 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            cursor: pointer;
        }}

        .finding-title {{
            font-weight: bold;
            font-size: 1.1em;
        }}

        .finding-badges {{
            display: flex;
            gap: 10px;
        }}

        .badge {{
            padding: 5px 12px;
            border-radius: 15px;
            font-size: 0.85em;
            font-weight: bold;
        }}

        .badge-verified {{
            background: #28a745;
            color: white;
        }}

        .badge-unverified {{
            background: #6c757d;
            color: white;
        }}

        .badge-false-positive {{
            background: #ffc107;
            color: #333;
        }}

        .badge-needs-review {{
            background: #fd7e14;
            color: white;
        }}

        .badge-severity {{
            color: white;
        }}

        .badge-severity.critical {{ background: #dc3545; }}
        .badge-severity.high {{ background: #fd7e14; }}
        .badge-severity.medium {{ background: #ffc107; color: #333; }}
        .badge-severity.low {{ background: #28a745; }}

        .badge-tool {{
            font-size: 0.75em;
            padding: 3px 8px;
        }}
        .badge-trufflehog {{ background: #6f42c1; color: white; }}
        .badge-gitleaks {{ background: #20c997; color: white; }}
        .badge-both {{ background: #17a2b8; color: white; }}

        .finding-body {{
            padding: 20px;
            display: none;
        }}

        .finding-body.expanded {{
            display: block;
        }}

        .finding-detail {{
            margin-bottom: 15px;
        }}

        .finding-detail-label {{
            font-weight: bold;
            color: #666;
            margin-bottom: 5px;
        }}

        .finding-detail-value {{
            background: #f8f9fa;
            padding: 10px;
            border-radius: 5px;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            word-break: break-all;
        }}

        .ai-analysis {{
            background: #e7f3ff;
            border-left: 4px solid #007bff;
            padding: 15px;
            margin-top: 15px;
            border-radius: 5px;
        }}

        .ai-analysis-title {{
            font-weight: bold;
            color: #007bff;
            margin-bottom: 10px;
        }}

        footer {{
            background: #f8f9fa;
            padding: 20px;
            text-align: center;
            color: #666;
            border-top: 1px solid #ddd;
        }}

        .no-results {{
            text-align: center;
            padding: 40px;
            color: #666;
            font-size: 1.2em;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🔍 G-Hunter Security Report</h1>
            <p>GitHub Secrets & Sensitive Information Analysis</p>
            <p style="font-size: 0.9em; margin-top: 10px;">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </header>

        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-label">Total Findings</div>
                <div class="stat-value">{total}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Verified</div>
                <div class="stat-value" style="color: #28a745;">{verified}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label critical">Critical</div>
                <div class="stat-value critical">{critical}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label high">High</div>
                <div class="stat-value high">{high}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label medium">Medium</div>
                <div class="stat-value medium">{medium}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label low">Low</div>
                <div class="stat-value low">{low}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">False Positives</div>
                <div class="stat-value" style="color: #ffc107;">{false_positives}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Needs Review</div>
                <div class="stat-value" style="color: #fd7e14;">{needs_review}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label" style="color: #6f42c1;">TruffleHog</div>
                <div class="stat-value" style="color: #6f42c1;">{by_trufflehog}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label" style="color: #20c997;">Gitleaks</div>
                <div class="stat-value" style="color: #20c997;">{by_gitleaks}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label" style="color: #17a2b8;">Found by Both</div>
                <div class="stat-value" style="color: #17a2b8;">{by_both_tools}</div>
            </div>
        </div>

        <div class="controls">
            <div class="search-box">
                <input type="text" id="searchInput" placeholder="🔍 Search findings..." onkeyup="filterFindings()">
            </div>
            <div class="filter-group">
                <button class="filter-btn active" onclick="filterBySeverity('all')">All</button>
                <button class="filter-btn" onclick="filterBySeverity('CRITICAL')">Critical</button>
                <button class="filter-btn" onclick="filterBySeverity('HIGH')">High</button>
                <button class="filter-btn" onclick="filterBySeverity('MEDIUM')">Medium</button>
                <button class="filter-btn" onclick="filterBySeverity('LOW')">Low</button>
            </div>
            <div class="filter-group">
                <button class="filter-btn" onclick="filterByType('verified')">Verified Only</button>
                <button class="filter-btn" onclick="filterByType('false_positive')">Hide False Positives</button>
                <button class="filter-btn" onclick="filterByType('needs_review')">Needs Review</button>
            </div>
            <div class="filter-group">
                <button class="filter-btn active" onclick="filterByTool('all')" id="tool-all">All Tools</button>
                <button class="filter-btn" onclick="filterByTool('trufflehog')" id="tool-trufflehog" style="border-color: #6f42c1;">TruffleHog</button>
                <button class="filter-btn" onclick="filterByTool('gitleaks')" id="tool-gitleaks" style="border-color: #20c997;">Gitleaks</button>
                <button class="filter-btn" onclick="filterByTool('both')" id="tool-both" style="border-color: #17a2b8;">Both Tools</button>
            </div>
        </div>

        <div class="findings" id="findingsContainer">
"""

        # Add finding cards
        for idx, finding in enumerate(findings):
            # All values below originate from scanned repos / secret contents and
            # are attacker-influenced, so escape every field before embedding it
            # in HTML to prevent stored XSS in the report.
            severity_raw = str(finding.get('severity', 'UNKNOWN'))
            severity = html.escape(severity_raw.lower(), quote=True)
            severity_text = html.escape(severity_raw)
            verified_badge = 'badge-verified' if finding.get('verified') else 'badge-unverified'
            verified_text = 'Verified' if finding.get('verified') else 'Unverified'

            detector_name = html.escape(str(finding.get('detector_name', 'Unknown Detector')))
            detector_type = html.escape(str(finding.get('detector_type', 'Unknown Type')))
            file_path = html.escape(str(finding.get('file_path', 'N/A')))
            commit = html.escape(str(finding.get('commit', 'N/A')))
            timestamp = html.escape(str(finding.get('timestamp', 'N/A')))

            # Only allow http(s) links; everything else (e.g. javascript:) -> '#'
            repo_url_raw = finding.get('repo_url', '')
            if isinstance(repo_url_raw, str) and repo_url_raw.startswith(('https://', 'http://')):
                repo_url_href = html.escape(repo_url_raw, quote=True)
            else:
                repo_url_href = '#'
            repo_url_text = html.escape(str(repo_url_raw) if repo_url_raw else 'N/A')

            # Determine scan tool for badge and filtering
            found_by = finding.get('found_by', [])
            scan_tool = finding.get('scan_tool', '')
            if len(found_by) > 1:
                tool_class = 'badge-both'
                tool_text = 'Both'
                tool_data = 'both'
            elif 'trufflehog' in found_by or scan_tool == 'trufflehog':
                tool_class = 'badge-trufflehog'
                tool_text = 'TruffleHog'
                tool_data = 'trufflehog'
            elif 'gitleaks' in found_by or scan_tool == 'gitleaks':
                tool_class = 'badge-gitleaks'
                tool_text = 'Gitleaks'
                tool_data = 'gitleaks'
            else:
                tool_class = 'badge-tool'
                tool_text = 'Unknown'
                tool_data = 'unknown'

            badges_html = f'<span class="badge badge-tool {tool_class}">{tool_text}</span>'
            badges_html += f'<span class="badge {verified_badge}">{verified_text}</span>'
            badges_html += f'<span class="badge badge-severity {severity}">{severity_text}</span>'

            if finding.get('false_positive'):
                badges_html += '<span class="badge badge-false-positive">False Positive</span>'

            if finding.get('needs_review'):
                badges_html += '<span class="badge badge-needs-review">Needs Review</span>'

            ai_analysis_html = ""
            if finding.get('ai_analysis'):
                ai = finding['ai_analysis']
                ai_analysis_html = f"""
                <div class="ai-analysis">
                    <div class="ai-analysis-title">🤖 AI Analysis</div>
                    <p><strong>Assessment:</strong> {html.escape(str(ai.get('reason', 'N/A')))}</p>
                </div>
                """

            html_content += f"""
            <div class="finding-card" data-severity="{severity}" data-verified="{str(finding.get('verified')).lower()}"
                 data-false-positive="{str(finding.get('false_positive')).lower()}"
                 data-needs-review="{str(finding.get('needs_review')).lower()}"
                 data-tool="{tool_data}">
                <div class="finding-header" onclick="toggleFinding({idx})">
                    <div class="finding-title">
                        {detector_name} - {detector_type}
                    </div>
                    <div class="finding-badges">
                        {badges_html}
                    </div>
                </div>
                <div class="finding-body" id="finding-{idx}">
                    <div class="finding-detail">
                        <div class="finding-detail-label">Repository</div>
                        <div class="finding-detail-value">
                            <a href="{repo_url_href}" target="_blank" rel="noopener noreferrer">{repo_url_text}</a>
                        </div>
                    </div>
                    <div class="finding-detail">
                        <div class="finding-detail-label">File Path</div>
                        <div class="finding-detail-value">{file_path}</div>
                    </div>
                    <div class="finding-detail">
                        <div class="finding-detail-label">Commit</div>
                        <div class="finding-detail-value">{commit}</div>
                    </div>
                    <div class="finding-detail">
                        <div class="finding-detail-label">Timestamp</div>
                        <div class="finding-detail-value">{timestamp}</div>
                    </div>
                    {ai_analysis_html}
                </div>
            </div>
            """

        html_content += """
        </div>

        <footer>
            <p>Generated by <strong>G-Hunter v3.0</strong> - Professional GitHub Secrets Scanner</p>
            <p style="margin-top: 10px; font-size: 0.9em;">⚠️ Handle this report securely - contains sensitive security information</p>
        </footer>
    </div>

    <script>
        let currentSeverityFilter = 'all';
        let currentTypeFilter = null;
        let currentToolFilter = 'all';

        function toggleFinding(id) {
            const body = document.getElementById('finding-' + id);
            body.classList.toggle('expanded');
        }

        function filterBySeverity(severity) {
            currentSeverityFilter = severity;

            // Update button states for severity
            document.querySelectorAll('.filter-group:nth-child(2) .filter-btn').forEach(btn => {
                if (btn.textContent.toLowerCase() === severity.toLowerCase() ||
                    (btn.textContent === 'All' && severity === 'all')) {
                    btn.classList.add('active');
                } else {
                    btn.classList.remove('active');
                }
            });

            applyFilters();
        }

        function filterByType(type) {
            // Toggle type filter
            if (currentTypeFilter === type) {
                currentTypeFilter = null;
            } else {
                currentTypeFilter = type;
            }

            applyFilters();
        }

        function filterByTool(tool) {
            currentToolFilter = tool;

            // Update button states for tool filter
            ['all', 'trufflehog', 'gitleaks', 'both'].forEach(t => {
                const btn = document.getElementById('tool-' + t);
                if (btn) {
                    if (t === tool) {
                        btn.classList.add('active');
                    } else {
                        btn.classList.remove('active');
                    }
                }
            });

            applyFilters();
        }

        function filterFindings() {
            applyFilters();
        }

        function applyFilters() {
            const searchTerm = document.getElementById('searchInput').value.toLowerCase();
            const cards = document.querySelectorAll('.finding-card');
            let visibleCount = 0;

            cards.forEach(card => {
                let show = true;

                // Severity filter
                if (currentSeverityFilter !== 'all') {
                    show = show && card.dataset.severity === currentSeverityFilter.toLowerCase();
                }

                // Type filter
                if (currentTypeFilter === 'verified') {
                    show = show && card.dataset.verified === 'true';
                } else if (currentTypeFilter === 'false_positive') {
                    show = show && card.dataset.falsePositive !== 'true';
                } else if (currentTypeFilter === 'needs_review') {
                    show = show && card.dataset.needsReview === 'true';
                }

                // Tool filter
                if (currentToolFilter !== 'all') {
                    show = show && card.dataset.tool === currentToolFilter;
                }

                // Search filter
                if (searchTerm) {
                    const text = card.textContent.toLowerCase();
                    show = show && text.includes(searchTerm);
                }

                card.style.display = show ? 'block' : 'none';
                if (show) visibleCount++;
            });

            // Show "no results" message if needed
            const container = document.getElementById('findingsContainer');
            let noResults = container.querySelector('.no-results');

            if (visibleCount === 0) {
                if (!noResults) {
                    noResults = document.createElement('div');
                    noResults.className = 'no-results';
                    noResults.textContent = 'No findings match the current filters';
                    container.appendChild(noResults);
                }
            } else if (noResults) {
                noResults.remove();
            }
        }
    </script>
</body>
</html>
"""

        # Write HTML file
        with open(report_file, 'w') as f:
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

    async def main_menu(self):
        """Main menu loop"""
        while True:
            self.display_menu()

            try:
                choice = input(f"{Fore.GREEN}Enter your choice (1-5):{Style.RESET_ALL} ").strip()

                if choice == "1":
                    await self.git_scan()
                elif choice == "2":
                    await self.repo_scan()
                elif choice == "3":
                    await self.generate_report_menu()
                elif choice == "4":
                    self.display_help()
                elif choice == "5":
                    print(f"\n{Fore.YELLOW}Thank you for using G-Hunter! Stay secure! 🔒{Style.RESET_ALL}\n")
                    break
                else:
                    print(f"{Fore.RED}Invalid choice! Please enter 1-5.{Style.RESET_ALL}")

            except KeyboardInterrupt:
                print(f"\n{Fore.YELLOW}Exiting G-Hunter...{Style.RESET_ALL}\n")
                break
            except Exception as e:
                self.logger.error(f"Unexpected error: {e}")
                print(f"{Fore.RED}An error occurred. Check ghunter.log for details.{Style.RESET_ALL}")

    async def run(self):
        """Main entry point"""
        display_banner()
        self.check_dependencies()
        await self.main_menu()

# ==================== MAIN FUNCTION ====================

def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description="G-Hunter - Professional GitHub Secrets & Sensitive Info Hunter",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging")
    parser.add_argument("--no-menu", action="store_true", help="Skip menu and exit (for testing)")
    args = parser.parse_args()

    # Load configuration from environment
    github_token = os.getenv("GITHUB_TOKEN")
    gemini_api_key = os.getenv("GEMINI_API_KEY")

    if not github_token:
        print(f"{Fore.RED}ERROR: GITHUB_TOKEN environment variable not set!{Style.RESET_ALL}")
        print(f"\n{Fore.YELLOW}Please set your GitHub Personal Access Token:{Style.RESET_ALL}")
        print("  export GITHUB_TOKEN='ghp_your_token_here'")
        print("  OR create a .env file with: GITHUB_TOKEN=ghp_your_token_here")
        print(f"\n{Fore.CYAN}Get your token at: https://github.com/settings/tokens{Style.RESET_ALL}\n")
        sys.exit(1)

    # Create config
    config = Config(
        github_token=github_token,
        gemini_api_key=gemini_api_key
    )

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Create and run G-Hunter
    hunter = GHunter(config)

    if args.no_menu:
        print("G-Hunter initialized successfully!")
        sys.exit(0)

    try:
        asyncio.run(hunter.run())
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Scan interrupted by user{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}Fatal error: {e}{Style.RESET_ALL}")
        logging.exception("Fatal error occurred")
        sys.exit(1)

if __name__ == "__main__":
    main()
