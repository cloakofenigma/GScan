"""Data models and configuration for G-Hunter."""
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Set, Dict, Optional

@dataclass
class Config:
    """Application configuration"""
    github_token: str
    gemini_api_key: Optional[str] = None
    base_url: str = "https://api.github.com/search/code"
    rate_limit: int = 10  # requests per minute
    max_concurrent: int = 5
    max_repo_workers: int = 3  # concurrent clone+scan workers in repo scan
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
    allowlist_file: str = ".ghunterignore"  # Rule file to suppress known false positives

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
    suppressed: int = 0  # Findings filtered out by the .ghunterignore allowlist
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
    suppressed: bool = False  # Matched a .ghunterignore allowlist rule
    suppressed_by: str = ""  # The allowlist rule that matched (for auditing)

# ==================== ASCII BANNER ====================
