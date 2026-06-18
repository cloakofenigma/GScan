"""ASCII banner, menus, and help text."""
from typing import Optional
from colorama import Fore, Back, Style

from .version import __version__

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
║                    {Fore.GREEN}v{__version__} Enterprise Edition{Fore.CYAN}                            ║
║                                                                          ║
║  {Fore.WHITE}Hunt for exposed secrets and sensitive information on GitHub{Fore.CYAN}        ║
║  {Fore.RED}⚠️  Use responsibly and only with proper authorization  ⚠️{Fore.CYAN}          ║
║                                                                          ║
╚══════════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""
    print(banner)

class UIMixin:
    """Interactive display helpers mixed into GHunter."""

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

