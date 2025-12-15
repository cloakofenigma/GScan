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
from datetime import datetime
from pathlib import Path
from typing import List, Set, Dict, Optional, Tuple
from dataclasses import dataclass, asdict
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
    timeout: int = 30
    retry_attempts: int = 3
    valid_extensions: Set[str] = None
    output_base_dir: Path = Path("outputs")

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

    def __post_init__(self):
        if self.completed_repos is None:
            self.completed_repos = set()
        if self.completed_urls is None:
            self.completed_urls = set()
        if self.completed_queries_set is None:
            self.completed_queries_set = set()

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
                self.gemini_model = genai.GenerativeModel('gemini-2.0-flash-exp')
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
        """Setup graceful shutdown handlers"""
        def signal_handler(signum, frame):
            self.logger.info("Received shutdown signal. Saving progress...")
            self.shutdown_event.set()

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
║  {Fore.GREEN}2.{Fore.CYAN} Repo Scan - Deep scan repositories with TruffleHog          ║
║     {Fore.WHITE}• Scan previously identified repositories{Fore.CYAN}                    ║
║     {Fore.WHITE}• Use TruffleHog for verified secret detection{Fore.CYAN}               ║
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
TruffleHog scanning, and AI-powered analysis.

{Fore.GREEN}PREREQUISITES:{Style.RESET_ALL}
1. GitHub Personal Access Token (PAT) with 'public_repo' scope
   → Create at: https://github.com/settings/tokens

2. TruffleHog installed (for deep scanning)
   → Install: brew install trufflehog (macOS)
   → Install: pip install trufflehog (Python)
   → Install: https://github.com/trufflesecurity/trufflehog/releases

3. Google Gemini API Key (optional, for AI analysis)
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
   • Saves repositories and file URLs separately
   • Supports resume functionality for interrupted scans

   {Fore.YELLOW}Example:{Style.RESET_ALL}
   Keywords: acme.com, acme-corp, acme
   Dorks file: gitDorks.txt
   Output: outputs/acme.com/

{Fore.CYAN}2. Repo Scan{Style.RESET_ALL}
   • Performs deep scanning using TruffleHog
   • Detects verified secrets (API keys, passwords, tokens)
   • AI-powered false positive reduction
   • Marks findings needing manual review
   • Generates JSON results with detailed metadata

   {Fore.YELLOW}Example:{Style.RESET_ALL}
   Input: outputs/acme.com/repos.txt
   Output: outputs/acme.com/scan_results.json

{Fore.CYAN}3. Generate HTML Report{Style.RESET_ALL}
   • Creates professional, interactive HTML dashboard
   • Modern CSS/JS with filtering and sorting
   • Color-coded severity levels (CRITICAL, HIGH, MEDIUM, LOW)
   • False positive indicators
   • Manual review markers
   • Exportable for stakeholders

   {Fore.YELLOW}Example:{Style.RESET_ALL}
   Input: outputs/acme.com/scan_results.json
   Output: outputs/acme.com/report.html

{Fore.GREEN}BEST PRACTICES:{Style.RESET_ALL}
✓ Always get authorization before scanning
✓ Respect GitHub's rate limits and ToS
✓ Use specific keywords for targeted results
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

    def check_dependencies(self):
        """Check all required dependencies"""
        issues = []
        successes = []

        # Check GitHub token
        if not self.config.github_token:
            issues.append("GitHub token not configured (set GITHUB_TOKEN environment variable)")
        else:
            # Mask token for security
            masked_token = self.config.github_token[:10] + "..." if len(self.config.github_token) > 10 else "***"
            successes.append(f"GitHub token configured ({masked_token})")

        # Check TruffleHog for repo scanning
        trufflehog_installed = self.check_trufflehog()
        if not trufflehog_installed:
            issues.append("TruffleHog not installed (required for Repo Scan)")
        else:
            try:
                result = subprocess.run(['trufflehog', '--version'],
                                      capture_output=True, text=True, timeout=5)
                version = result.stdout.strip() if result.returncode == 0 else "unknown"
                successes.append(f"TruffleHog installed ({version})")
            except:
                successes.append("TruffleHog installed")

        # Check Gemini API
        if self.config.gemini_api_key:
            successes.append("Google Gemini API configured (AI analysis enabled)")

        # Display results
        if successes:
            print(f"\n{Fore.GREEN}✓ Dependencies Ready:{Style.RESET_ALL}")
            for success in successes:
                print(f"  • {success}")

        if issues:
            print(f"\n{Fore.RED}⚠️  Dependency Issues:{Style.RESET_ALL}")
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
                'completed_queries_set': list(self.progress.completed_queries_set)
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

                self.logger.info(f"Loaded progress: {progress.completed_queries}/{progress.total_queries} queries")
                return progress
            except Exception as e:
                self.logger.error(f"Error loading progress: {e}")

        return ScanProgress()

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

    async def search_github(self, keyword: str, dork: str) -> Tuple[Set[str], Set[str]]:
        """Search GitHub with retry logic"""
        async with self.semaphore:
            query = f"{keyword} {dork}"
            repos, urls = set(), set()

            for attempt in range(self.config.retry_attempts):
                try:
                    params = {"q": query, "per_page": 100}

                    async with self.session.get(self.config.base_url, params=params) as response:
                        if response.status == 200:
                            data = await response.json()
                            items = data.get("items", [])

                            for item in items:
                                repo_url = item["repository"]["html_url"]
                                file_url = item["html_url"]

                                repos.add(repo_url)

                                # Check file extension
                                if any(file_url.lower().endswith(ext) for ext in self.config.valid_extensions):
                                    urls.add(file_url)

                            break

                        elif response.status == 403:
                            self.logger.warning(f"Rate limit hit for '{query}', waiting 60s...")
                            await asyncio.sleep(60)
                            continue

                        elif response.status == 422:
                            self.logger.error(f"Invalid query '{query}', skipping")
                            break

                        else:
                            self.logger.error(f"HTTP {response.status} for '{query}'")

                except Exception as e:
                    self.logger.error(f"Attempt {attempt + 1} failed for '{query}': {e}")
                    if attempt < self.config.retry_attempts - 1:
                        await asyncio.sleep(2 ** attempt)
                    else:
                        self.progress.errors += 1

            # Rate limiting
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

Raw Data:
{finding.raw_result[:500]}

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
        """Repository scan functionality"""
        print(f"\n{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗")
        print(f"║         Repo Scan - TruffleHog Deep Scanning                ║")
        print(f"╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}\n")

        # Check TruffleHog
        if not self.check_trufflehog():
            print(f"{Fore.RED}TruffleHog not found!{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}Please install TruffleHog and run this tool again.{Style.RESET_ALL}")
            print("Installation: https://github.com/trufflesecurity/trufflehog\n")
            return

        # Get repo file path
        repo_file = input(f"{Fore.GREEN}Enter path to repos file:{Style.RESET_ALL} ").strip()

        if not os.path.exists(repo_file):
            print(f"{Fore.RED}Error: Repo file '{repo_file}' not found!{Style.RESET_ALL}")
            return

        # Determine output directory
        repo_path = Path(repo_file)
        output_dir = repo_path.parent

        # Run scan
        self.run_trufflehog_scan(repo_file, output_dir)

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
        </div>

        <div class="findings" id="findingsContainer">
"""

        # Add finding cards
        for idx, finding in enumerate(findings):
            severity = finding.get('severity', 'UNKNOWN').lower()
            verified_badge = 'badge-verified' if finding.get('verified') else 'badge-unverified'
            verified_text = 'Verified' if finding.get('verified') else 'Unverified'

            badges_html = f'<span class="badge {verified_badge}">{verified_text}</span>'
            badges_html += f'<span class="badge badge-severity {severity}">{finding.get("severity", "UNKNOWN")}</span>'

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
                    <p><strong>Assessment:</strong> {ai.get('reason', 'N/A')}</p>
                </div>
                """

            html_content += f"""
            <div class="finding-card" data-severity="{severity}" data-verified="{str(finding.get('verified')).lower()}"
                 data-false-positive="{str(finding.get('false_positive')).lower()}"
                 data-needs-review="{str(finding.get('needs_review')).lower()}">
                <div class="finding-header" onclick="toggleFinding({idx})">
                    <div class="finding-title">
                        {finding.get('detector_name', 'Unknown Detector')} - {finding.get('detector_type', 'Unknown Type')}
                    </div>
                    <div class="finding-badges">
                        {badges_html}
                    </div>
                </div>
                <div class="finding-body" id="finding-{idx}">
                    <div class="finding-detail">
                        <div class="finding-detail-label">Repository</div>
                        <div class="finding-detail-value">
                            <a href="{finding.get('repo_url', '#')}" target="_blank">{finding.get('repo_url', 'N/A')}</a>
                        </div>
                    </div>
                    <div class="finding-detail">
                        <div class="finding-detail-label">File Path</div>
                        <div class="finding-detail-value">{finding.get('file_path', 'N/A')}</div>
                    </div>
                    <div class="finding-detail">
                        <div class="finding-detail-label">Commit</div>
                        <div class="finding-detail-value">{finding.get('commit', 'N/A')}</div>
                    </div>
                    <div class="finding-detail">
                        <div class="finding-detail-label">Timestamp</div>
                        <div class="finding-detail-value">{finding.get('timestamp', 'N/A')}</div>
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

        function toggleFinding(id) {
            const body = document.getElementById('finding-' + id);
            body.classList.toggle('expanded');
        }

        function filterBySeverity(severity) {
            currentSeverityFilter = severity;

            // Update button states
            document.querySelectorAll('.filter-btn').forEach(btn => {
                if (btn.textContent.toLowerCase() === severity.toLowerCase() ||
                    (btn.textContent === 'All' && severity === 'all')) {
                    btn.classList.add('active');
                } else if (!btn.onclick.toString().includes('filterByType')) {
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
