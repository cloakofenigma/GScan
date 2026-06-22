"""Dork loading and scan-progress checkpointing."""
import json
from pathlib import Path
from typing import List
from .models import ScanProgress

class ProgressMixin:
    """Progress persistence mixed into GHunter."""

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
                'suppressed': self.progress.suppressed,
                'new_secrets': self.progress.new_secrets,
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
                progress.suppressed = data.get('suppressed', 0)
                progress.new_secrets = data.get('new_secrets', 0)
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
