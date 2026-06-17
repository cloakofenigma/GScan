"""External tool / dependency detection."""
import os
import re
import shutil
import subprocess
from typing import Optional, Tuple
from colorama import Fore, Style

class DependencyMixin:
    """Dependency checks mixed into GHunter."""

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

