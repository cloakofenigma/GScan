"""GHunter orchestrator composed from feature mixins."""
import asyncio
import logging
import shutil
import signal
import sys
import threading
import aiohttp
from pathlib import Path
from typing import Optional, Set
from colorama import Fore, Style
from .models import Config, ScanProgress, SecretFinding
from .ai import AIMixin, genai, GENAI_AVAILABLE
from .ui import display_banner, UIMixin
from .dependencies import DependencyMixin
from .progress import ProgressMixin
from .search import SearchMixin
from .scanners import ScanMixin
from .report import ReportMixin


class GHunter(UIMixin, DependencyMixin, ProgressMixin, SearchMixin,
              ScanMixin, AIMixin, ReportMixin):
    """Main G-Hunter application class."""

    def __init__(self, config: Config):
        self.config = config
        self.progress = ScanProgress()
        self.session: Optional[aiohttp.ClientSession] = None
        self.semaphore: Optional[asyncio.Semaphore] = None
        self.shutdown_event = asyncio.Event()
        # Track in-progress clones (multiple under concurrency) for interrupt cleanup
        self._active_clone_paths: Set[Path] = set()
        self._clone_lock = threading.Lock()
        self.logger = self.setup_logging()
        self.setup_signal_handlers()
        self.gemini_model = None

        # Initialize Gemini if API key available and the SDK is installed
        if self.config.gemini_api_key and GENAI_AVAILABLE:
            try:
                genai.configure(api_key=self.config.gemini_api_key)
                self.gemini_model = genai.GenerativeModel('gemini-2.0-flash')
                self.logger.info("Google Gemini AI initialized successfully")
            except Exception as e:
                self.logger.warning(f"Failed to initialize Gemini: {e}")
        elif self.config.gemini_api_key and not GENAI_AVAILABLE:
            self.logger.warning(
                "GEMINI_API_KEY set but google-generativeai is not installed; "
                "skipping AI analysis. Install with: pip install google-generativeai"
            )

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

            # Cleanup all in-progress clones (there may be several concurrently)
            with self._clone_lock:
                paths = list(self._active_clone_paths)
            for path in paths:
                try:
                    if path.exists():
                        self.logger.info(f"Cleaning up interrupted clone: {path}")
                        shutil.rmtree(path)
                except Exception as e:
                    self.logger.error(f"Failed to cleanup clone on interrupt: {e}")

        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

    def _register_clone(self, path: Path):
        with self._clone_lock:
            self._active_clone_paths.add(path)

    def _unregister_clone(self, path: Path):
        with self._clone_lock:
            self._active_clone_paths.discard(path)


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
