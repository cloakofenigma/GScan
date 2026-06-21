"""Command-line interface (interactive menu + non-interactive subcommands)."""
import argparse
import asyncio
import logging
import os
import sys
from colorama import Fore, Style
from .models import Config
from .core import GHunter

def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser (interactive menu + non-interactive subcommands)."""
    parser = argparse.ArgumentParser(
        prog="ghunter",
        description="G-Hunter - Professional GitHub Secrets & Sensitive Info Hunter",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  ghunter                              # interactive menu\n"
            "  ghunter scan -k acme.com,acme-corp   # GitHub dork search\n"
            "  ghunter repo -f outputs/acme.com/repos.txt -t both\n"
            "  ghunter report -i outputs/acme.com/scan_results.json\n"
        ),
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging")
    parser.add_argument("--no-menu", action="store_true", help="Initialize and exit (for testing)")

    sub = parser.add_subparsers(dest="command")

    scan_p = sub.add_parser("scan", help="GitHub dork search (non-interactive)")
    scan_p.add_argument("-k", "--keywords", required=True, help="Comma-separated keywords")
    scan_p.add_argument("-d", "--dorks", default="gitDorks.txt", help="Path to dorks file")
    scan_p.add_argument("--resume", action="store_true", help="Resume a prior scan")

    repo_p = sub.add_parser("repo", help="Deep secret scan of repositories (non-interactive)")
    repo_p.add_argument("-f", "--repos-file", required=True, help="File of repo URLs (one per line)")
    repo_p.add_argument("-t", "--tool", choices=["trufflehog", "gitleaks", "both"],
                        default="both", help="Scanner to use")
    repo_p.add_argument("--resume", action="store_true", help="Resume a prior scan")
    repo_p.add_argument("--ai-send-raw", action="store_true",
                        help="Send raw secret data to Gemini (off by default)")

    report_p = sub.add_parser("report", help="Generate an HTML report from scan results")
    report_p.add_argument("-i", "--input", required=True, help="Path to scan_results.json")

    return parser



def main():
    """Main function"""
    parser = build_parser()
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # The report command works offline and needs no GitHub token.
    needs_token = args.command in (None, "scan", "repo")
    github_token = os.getenv("GITHUB_TOKEN")
    gemini_api_key = os.getenv("GEMINI_API_KEY")
    gemini_model = os.getenv("GEMINI_MODEL")  # optional override of the default

    if needs_token and not github_token:
        print(f"{Fore.RED}ERROR: GITHUB_TOKEN environment variable not set!{Style.RESET_ALL}")
        print(f"\n{Fore.YELLOW}Please set your GitHub Personal Access Token:{Style.RESET_ALL}")
        print("  export GITHUB_TOKEN='ghp_your_token_here'")
        print("  OR create a .env file with: GITHUB_TOKEN=ghp_your_token_here")
        print(f"\n{Fore.CYAN}Get your token at: https://github.com/settings/tokens{Style.RESET_ALL}\n")
        sys.exit(1)

    config = Config(
        github_token=github_token or "",
        gemini_api_key=gemini_api_key,
        ai_send_raw=getattr(args, "ai_send_raw", False),
        **({"gemini_model": gemini_model} if gemini_model else {}),
    )

    hunter = GHunter(config)

    if args.no_menu:
        print("G-Hunter initialized successfully!")
        sys.exit(0)

    try:
        if args.command == "scan":
            keywords = [k.strip() for k in args.keywords.split(",") if k.strip()]
            asyncio.run(hunter.git_scan(keywords=keywords, dorks_file=args.dorks,
                                        resume=args.resume))
        elif args.command == "repo":
            asyncio.run(hunter.repo_scan(repo_file=args.repos_file, scan_tool=args.tool,
                                         resume=args.resume))
        elif args.command == "report":
            hunter.generate_html_report(args.input)
        else:
            asyncio.run(hunter.run())
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Scan interrupted by user{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}Fatal error: {e}{Style.RESET_ALL}")
        logging.exception("Fatal error occurred")
        sys.exit(1)

