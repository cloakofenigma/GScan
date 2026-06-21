"""Cloning + secret scanners (TruffleHog/Gitleaks), dedup, severity, repo scan."""
import asyncio
import hashlib
import json
import os
import re
import shutil
import subprocess
import time
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Tuple
from tqdm import tqdm
from colorama import Fore, Style
from .models import ScanProgress, SecretFinding
from .allowlist import Allowlist

class ScanMixin:
    """Cloning and scanning mixed into GHunter."""

    # Accept only plain http(s) git URLs. This blocks argument injection
    # (e.g. a repos.txt line starting with '-' or '--upload-pack=...') and
    # non-network schemes (file://, ssh://, ext::) from reaching git/scanners.
    _REPO_URL_RE = re.compile(r'^https?://[A-Za-z0-9._~:/?#\[\]@!$&\'()*+,;=%-]+$')

    def is_valid_repo_url(self, repo_url: str) -> bool:
        """Validate a repository URL before passing it to a subprocess."""
        if not isinstance(repo_url, str) or not repo_url:
            return False
        if repo_url.startswith('-'):  # never let a URL look like a CLI flag
            return False
        return bool(self._REPO_URL_RE.match(repo_url))

    def get_repo_name_from_url(self, repo_url: str) -> str:
        """Extract repository name from URL"""
        # Handle URLs like https://github.com/username/reponame.git
        name = repo_url.rstrip('/').split('/')[-1]
        if name.endswith('.git'):
            name = name[:-4]
        return name

    def clone_repository(self, repo_url: str, clone_dir: Path) -> Tuple[bool, Optional[Path]]:
        """Clone a repository to the specified directory"""
        # Reject anything that isn't a plain http(s) URL before it reaches git
        if not self.is_valid_repo_url(repo_url):
            self.logger.error(f"Refusing to clone invalid/unsafe repo URL: {repo_url!r}")
            return False, None

        repo_name = self.get_repo_name_from_url(repo_url)
        clone_path = clone_dir / repo_name

        # Remove existing clone if present
        if clone_path.exists():
            self.cleanup_clone(clone_path)

        try:
            self.logger.info(f"Cloning {repo_url} to {clone_path}")
            result = subprocess.run(
                # '--' ensures repo_url is treated as a positional, never a flag
                ['git', 'clone', '--quiet', '--', repo_url, str(clone_path)],
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

    def _build_gitleaks_cmd(self, clone_path: Path, output_file: Path) -> List[str]:
        """Build a Gitleaks command compatible with the installed version.

        Gitleaks 8.19.0 renamed `detect` to the `git` subcommand (with the
        source as a positional). `detect`/`--source` are the legacy form. We
        pick based on the detected version and cache the decision.
        """
        if not hasattr(self, '_gitleaks_use_git_subcmd'):
            self._gitleaks_use_git_subcmd = False
            _, version = self.check_gitleaks()
            if version and version != "unknown":
                m = re.search(r'(\d+)\.(\d+)', version)
                if m and (int(m.group(1)), int(m.group(2))) >= (8, 19):
                    self._gitleaks_use_git_subcmd = True

        common = [
            '--log-opts', '--all',          # scan entire git history
            '--report-format', 'json',
            '--report-path', str(output_file),
            '-v',
        ]
        if self._gitleaks_use_git_subcmd:
            return ['gitleaks', 'git', str(clone_path)] + common
        return ['gitleaks', 'detect', '--source', str(clone_path)] + common

    def run_gitleaks_local(self, clone_path: Path, repo_url: str, output_file: Path) -> List[SecretFinding]:
        """Run Gitleaks scan on a local clone with full git history"""
        findings = []

        try:
            self.logger.info(f"Running Gitleaks on {clone_path}")

            # Run gitleaks with full history scan (command form depends on version)
            result = subprocess.run(
                self._build_gitleaks_cmd(clone_path, output_file),
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

    # Detector hints that indicate a high-impact credential class
    _HIGH_SIGNAL = (
        "aws", "gcp", "azure", "rsa", "ssh", "private", "stripe", "github",
        "gitlab", "slack", "token", "secret", "password", "oauth", "jwt",
        "database", "connectionstring", "twilio", "sendgrid", "npm", "pgp",
    )

    def derive_severity(self, finding: SecretFinding) -> str:
        """Deterministic severity, independent of the optional AI step.

        Ensures the report's severity dashboard is meaningful even when Gemini
        is not configured. A verified (live) secret is always CRITICAL.
        """
        if finding.verified:
            return "CRITICAL"
        name = f"{finding.detector_type} {finding.detector_name}".lower()
        if "private" in name and "key" in name:
            return "HIGH"
        if any(k in name for k in self._HIGH_SIGNAL):
            return "HIGH"
        return "MEDIUM"

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

    def _scan_single_repo(self, repo_url: str, clone_dir: Path, scan_tool: str,
                          trufflehog_available: bool,
                          gitleaks_available: bool) -> Optional[List[SecretFinding]]:
        """Clone, scan, dedup, score, and optionally AI-triage one repository.

        Fully synchronous and self-contained so it can run inside a worker
        thread. Returns the list of findings (possibly empty), or None if the
        clone failed.
        """
        if self.shutdown_event.is_set():
            return []

        success, clone_path = self.clone_repository(repo_url, clone_dir)
        if not success:
            return None

        self._register_clone(clone_path)
        repo_findings: List[SecretFinding] = []
        try:
            if scan_tool in ("trufflehog", "both") and trufflehog_available:
                repo_findings.extend(self.run_trufflehog_local(clone_path, repo_url))

            if scan_tool in ("gitleaks", "both") and gitleaks_available:
                gl_output = clone_dir / f"{clone_path.name}_gitleaks.json"
                repo_findings.extend(self.run_gitleaks_local(clone_path, repo_url, gl_output))
                if gl_output.exists():
                    gl_output.unlink()
        finally:
            self.cleanup_clone(clone_path)
            self._unregister_clone(clone_path)

        # Deduplicate when both tools ran (dedup key includes repo_url)
        if scan_tool == "both" and repo_findings:
            repo_findings = self.deduplicate_findings(repo_findings)

        # Deterministic severity baseline, independent of the optional AI step
        for finding in repo_findings:
            finding.severity = self.derive_severity(finding)

        # Allowlist: tag (don't drop) findings matching .ghunterignore rules so
        # they skip AI triage and stay out of the active dashboard, while
        # remaining auditable in the results file.
        allowlist = getattr(self, "allowlist", None)
        if allowlist:
            for finding in repo_findings:
                rule = allowlist.match(finding)
                if rule:
                    finding.suppressed = True
                    finding.suppressed_by = rule

        # Optional AI triage refines severity and flags false positives
        # (suppressed findings are skipped — saves Gemini calls).
        if self.gemini_model and repo_findings:
            for finding in repo_findings:
                if self.shutdown_event.is_set():
                    break
                if finding.suppressed:
                    continue
                analysis = self.analyze_with_gemini(finding)
                finding.ai_analysis = analysis
                finding.false_positive = analysis.get('false_positive', False)
                finding.needs_review = analysis.get('needs_review', False)
                ai_sev = str(analysis.get('severity', '')).upper()
                if ai_sev in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW'):
                    finding.severity = ai_sev
                time.sleep(0.5)  # Rate limit Gemini API

        return repo_findings


    async def repo_scan(self, repo_file: Optional[str] = None,
                        scan_tool: Optional[str] = None,
                        resume: Optional[bool] = None):
        """Repository scan functionality with tool selection.

        With no arguments the tool/repos-file/resume choices are gathered
        interactively; supplying them skips all prompts (non-interactive/CLI).
        """
        interactive = repo_file is None
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

        # Tool selection (menu when interactive, else use provided value)
        if scan_tool is None:
            scan_tool = self.display_tool_selection_menu()
        if scan_tool not in ("trufflehog", "gitleaks", "both"):
            print(f"{Fore.RED}Invalid scan tool: {scan_tool!r}{Style.RESET_ALL}")
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
        if repo_file is None:
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

        # Load allowlist rules (cwd + per-output-dir .ghunterignore). Used by
        # _scan_single_repo to suppress known false positives before AI/report.
        self.allowlist = Allowlist.load(
            [Path(self.config.allowlist_file), output_dir / self.config.allowlist_file],
            logger=self.logger,
        )
        if self.allowlist:
            print(f"{Fore.CYAN}Allowlist: loaded {len(self.allowlist)} "
                  f"rule(s) from {self.config.allowlist_file}{Style.RESET_ALL}")

        # Create clones directory
        clone_dir = output_dir / self.config.clone_dir
        clone_dir.mkdir(parents=True, exist_ok=True)

        # Output file
        results_file = output_dir / "scan_results.json"

        # Resume support: reuse prior progress + results when a checkpoint exists
        progress_file = output_dir / "progress.json"
        if resume is None:
            resume = False
            if progress_file.exists() and interactive:
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
                'found_by': finding.found_by,
                'suppressed': finding.suppressed,
                'suppressed_by': finding.suppressed_by
            })

        # Concurrency: clone+scan each repo in a worker thread (off the event
        # loop), bounded by max_repo_workers. All shared-state mutation (file
        # writes, progress counters, checkpoint) is serialized via write_lock,
        # and results are flushed + checkpointed per-repo so a run can resume.
        sem = asyncio.Semaphore(self.config.max_repo_workers)
        write_lock = asyncio.Lock()

        with open(results_file, results_mode) as results_out:
            with tqdm(total=len(repos), desc="Scanning repos") as pbar:

                async def process(repo_url: str):
                    if self.shutdown_event.is_set():
                        return
                    async with sem:
                        if self.shutdown_event.is_set():
                            return

                        # Skip already-scanned repos (resume)
                        if repo_url in self.progress.scanned_repos:
                            async with write_lock:
                                pbar.update(1)
                            return

                        repo_findings = await asyncio.to_thread(
                            self._scan_single_repo, repo_url, clone_dir, scan_tool,
                            trufflehog_available, gitleaks_available,
                        )

                        async with write_lock:
                            if repo_findings is None:
                                # Clone failed
                                self.progress.clone_failures += 1
                                self.progress.errors += 1
                            else:
                                for finding in repo_findings:
                                    self.progress.secrets_found += 1
                                    if finding.suppressed:
                                        self.progress.suppressed += 1
                                    if finding.verified:
                                        self.progress.verified_secrets += 1
                                    if finding.false_positive:
                                        self.progress.false_positives += 1
                                    if finding.needs_review:
                                        self.progress.needs_manual_review += 1
                                    results_out.write(serialize(finding) + '\n')
                                results_out.flush()
                                self.progress.scanned_repos.add(repo_url)
                            self.save_progress(output_dir)
                            pbar.update(1)
                            pbar.set_postfix({
                                'Secrets': self.progress.secrets_found,
                                'Errors': self.progress.errors,
                            })

                await asyncio.gather(*(process(r) for r in repos))

        if self.shutdown_event.is_set():
            print(f"\n{Fore.YELLOW}Scan interrupted. Progress saved - resume to continue.{Style.RESET_ALL}")

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
        if self.progress.suppressed:
            print(f"  Suppressed (allowlist): {self.progress.suppressed}")
        if scan_tool == "both":
            print(f"  Found by TruffleHog: {found_by_trufflehog}")
            print(f"  Found by Gitleaks: {found_by_gitleaks}")
            print(f"  Found by Both: {found_by_both}")
        if self.gemini_model:
            print(f"  False positives (AI): {self.progress.false_positives}")
            print(f"  Needs manual review: {self.progress.needs_manual_review}")
        print(f"  Errors: {self.progress.errors}")
        print(f"\nResults saved to: {results_file}\n")

