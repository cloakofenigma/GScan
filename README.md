# G-Hunter 🔍

**Professional GitHub Secrets & Sensitive Information Hunter**

G-Hunter is an enterprise-grade security tool for discovering exposed secrets, API keys, credentials, and sensitive information on GitHub repositories using advanced dorking techniques, TruffleHog/Gitleaks scanning, and AI-powered analysis.

## ⚡ Features

- **🎯 GitHub Dorking** - Advanced search using 500+ git dorks, with full result pagination
- **🔐 TruffleHog & Gitleaks** - Clone-first local scanning; TruffleHog verifies live secrets, Gitleaks adds pattern coverage, with automatic dedup when running both
- **🤖 AI Analysis** - Google Gemini for false-positive reduction; secret values are redacted before being sent off-host by default
- **📊 HTML Reports** - Modern, interactive dashboards with filtering (Jinja2 + autoescape)
- **💾 Resume Capability** - Never lose progress on interrupted scans
- **⚡ Concurrent Scanning** - Async GitHub search and bounded-concurrency repo scanning
- **🧮 Deterministic Severity** - Reproducible severity classification independent of AI
- **🤖 Non-Interactive CLI** - Scriptable `scan` / `repo` / `report` subcommands for CI
- **📁 Organized Output** - Clean directory structure per keyword
- **🎨 Beautiful UI** - Colored terminal output with progress bars

## 🚀 Quick Start

### Prerequisites

1. **Python 3.9+**
2. **Git** (required for clone-based repo scanning)
3. **GitHub Personal Access Token** (PAT)
   - Create at: https://github.com/settings/tokens
   - Required scope: `public_repo`
4. **TruffleHog and/or Gitleaks** (for deep scanning — at least one)
   - TruffleHog: `brew install trufflehog` / `pip install trufflehog` / [releases](https://github.com/trufflesecurity/trufflehog/releases)
   - Gitleaks: `brew install gitleaks` / [releases](https://github.com/gitleaks/gitleaks/releases)
5. **Google Gemini API Key** (optional, for AI analysis)
   - Get at: https://makersuite.google.com/app/apikey

### Installation

```bash
# Clone or download G-Hunter
cd GScan

# Install Python dependencies
pip install -r requirements.txt

# Configure environment variables
cp .env.example .env
# Edit .env and add your tokens

# Make executable (Linux/Mac)
chmod +x ghunter_pro.py

# Run G-Hunter
python ghunter_pro.py
```

### Configuration

Create a `.env` file:

```bash
# Required
GITHUB_TOKEN=ghp_your_github_token_here

# Optional (for AI analysis)
GEMINI_API_KEY=your_gemini_api_key_here
```

**⚠️ SECURITY WARNING:** Never commit your `.env` file or expose your tokens!

## 📖 Usage

### Interactive Menu

Run G-Hunter and use the interactive menu:

```bash
python ghunter_pro.py
```

Menu options:
1. **Git Scan** - Search GitHub for sensitive information
2. **Repo Scan** - Deep scan with TruffleHog
3. **Generate HTML Report** - Create professional reports
4. **Help** - Detailed usage instructions
5. **Exit**

### Non-Interactive CLI (automation / CI)

All three actions can run without the menu, so G-Hunter can be scripted or run
in CI:

```bash
# 1. GitHub dork search
python ghunter_pro.py scan -k acme.com,acme-corp [-d gitDorks.txt] [--resume]

# 2. Deep secret scan of discovered repos
python ghunter_pro.py repo -f outputs/acme.com/repos.txt -t both [--resume]
#    -t {trufflehog|gitleaks|both}   --ai-send-raw  (opt in to send raw data to Gemini)

# 3. Generate the HTML report (works offline, no token required)
python ghunter_pro.py report -i outputs/acme.com/scan_results.json
```

If installed as a package (`pip install -e .`), the `ghunter` console command is
equivalent to `python ghunter_pro.py`.

> **Privacy note:** AI triage redacts the raw secret value before sending a
> finding to Gemini. Pass `--ai-send-raw` only if you explicitly accept sending
> raw secret data off-host.

### Option 1: Git Scan

Searches GitHub using keywords and git dorks:

```
Enter keywords: acme.com, acme-corp, acme
Enter path to git dorks file: gitDorks.txt
```

**Output:**
```
outputs/acme.com/
├── repos.txt          # Unique repositories found
├── urls.txt           # Unique file URLs found
└── progress.json      # Resume checkpoint
```

**Features:**
- Async scanning with rate limiting
- Resume capability for interrupted scans
- Real-time progress tracking
- Deduplication of results

### Option 2: Repo Scan

Deep scans repositories with TruffleHog:

```
Enter path to repos file: outputs/acme.com/repos.txt
```

**Output:**
```
outputs/acme.com/
└── scan_results.json  # Detailed findings with AI analysis
```

**Features:**
- Verified secret detection
- AI-powered false positive reduction
- Severity classification (CRITICAL, HIGH, MEDIUM, LOW)
- Manual review markers
- Comprehensive metadata

### Option 3: Generate HTML Report

Creates professional, interactive HTML dashboard:

```
Enter path to scan results JSON file: outputs/acme.com/scan_results.json
```

**Output:**
```
outputs/acme.com/
└── report.html        # Interactive HTML report
```

**Report Features:**
- Real-time search and filtering
- Severity-based color coding
- Expandable finding details
- AI analysis insights
- Export-ready for stakeholders

## 🧹 Reducing False Positives (Allowlist)

G-Hunter reads a `.ghunterignore` file to suppress findings you've already
reviewed (test data, placeholders, sample configs). Suppressed findings **skip
AI triage** (saving Gemini calls) and are **hidden from the report dashboard by
default**, but they are *never deleted* — they stay in `scan_results.json` and
can be revealed with the report's **"Show Suppressed"** toggle, so nothing
becomes invisible.

Rules are loaded from `.ghunterignore` in the current directory **and** in the
scan's output directory (`outputs/<keyword>/.ghunterignore`); both are combined.
Copy [`.ghunterignore.example`](.ghunterignore.example) to get started.

```
# One rule per line; # for comments
path:**/test/**          # fnmatch glob against the file path
*.example                # a bare line is also treated as a path glob
fingerprint:0123456789abcdef   # exact 16-char secret_hash from a finding
regex:DUMMY_SECRET|REPLACE_ME  # regex against the raw finding result
```

Invalid regex rules are logged and skipped — a typo never aborts a scan.

## 🎯 Best Practices

### Keyword Selection

Choose specific, targeted keywords:

✅ **Good:**
- Company names: `acme`, `acme-corp`, `acmeinc`
- Domains: `acme.com`, `api.acme.com`, `*.acme.com`
- Email patterns: `@acme.com`
- Usernames: `acme-admin`, `acme-dev`

❌ **Avoid:**
- Generic terms: `api`, `password`, `key`
- Single letters: `a`, `b`, `c`

### Git Dorks

G-Hunter includes 513 pre-configured dorks targeting:
- API keys and tokens
- AWS credentials
- Database passwords
- Private keys
- Configuration files
- Environment files

You can customize `gitDorks.txt` with your own patterns.

### Workflow

Recommended workflow for best results:

```
1. Git Scan → Find repositories and files
   ↓
2. Review repos.txt and urls.txt
   ↓
3. Repo Scan → Deep scan with TruffleHog
   ↓
4. Review scan_results.json
   ↓
5. Generate HTML Report → Share with team
   ↓
6. Manual verification of flagged items
   ↓
7. Responsible disclosure
```

## 📂 Output Structure

```
outputs/
└── <keyword>/
    ├── repos.txt              # Unique GitHub repositories
    ├── urls.txt               # Unique file URLs with valid extensions
    ├── progress.json          # Scan progress (for resume)
    ├── scan_results.json      # TruffleHog findings with AI analysis
    └── report.html            # Interactive HTML report
```

## 🤖 AI Analysis

When Google Gemini API key is configured, G-Hunter automatically:

- **Reduces false positives** - Identifies test data, examples, placeholders
- **Classifies severity** - CRITICAL, HIGH, MEDIUM, LOW
- **Flags for review** - Items needing manual verification
- **Provides reasoning** - Explains assessment

Example AI analysis:

```json
{
  "false_positive": false,
  "needs_review": false,
  "severity": "CRITICAL",
  "reason": "Valid AWS access key with high entropy, appears in production config"
}
```

## 🔒 Security Considerations

### Before Scanning

- ✅ Obtain proper authorization
- ✅ Review GitHub Terms of Service
- ✅ Respect rate limits
- ✅ Use dedicated security testing account

### After Finding Secrets

1. **Verify** - Confirm the secret is real, not a test/example
2. **Document** - Record all findings systematically
3. **Report** - Follow responsible disclosure process
4. **Remediate** - Revoke and rotate exposed secrets immediately
5. **Prevent** - Implement git hooks, secret scanners in CI/CD

### Token Security

**⚠️ CRITICAL:**
- Never commit tokens to git
- Never share tokens publicly
- Use environment variables only
- Rotate tokens regularly
- Use least-privilege scopes

## 🐛 Troubleshooting

### Common Issues

**"GITHUB_TOKEN environment variable not set"**
```bash
# Solution: Create .env file or export
export GITHUB_TOKEN='ghp_your_token_here'
```

**"TruffleHog not found"**
```bash
# macOS
brew install trufflehog

# Linux/Windows (pip)
pip install trufflehog

# Or download binary
# https://github.com/trufflesecurity/trufflehog/releases
```

**"Rate limit hit"**
- G-Hunter automatically waits for rate limit reset
- Reduce `max_concurrent` in Config
- Use authenticated requests (ensure token is set)

**"Scan interrupted"**
- Use resume functionality
- Progress is auto-saved every query
- Answer 'y' when prompted to resume

## 📊 Performance

### Benchmarks

- **GitHub Scan:** ~6 seconds per query (rate limit compliant)
- **TruffleHog Scan:** 1-5 minutes per repository (varies by size)
- **AI Analysis:** ~0.5 seconds per finding
- **HTML Generation:** < 1 second for 1000 findings

### Optimization Tips

- Use specific keywords (fewer false positives)
- Curate your dorks list (remove irrelevant patterns)
- Run scans during off-peak hours
- Use resume for large scans

## 🤝 Contributing

Contributions welcome! Areas for improvement:

- Additional git dorks
- New file extensions
- Additional AI providers
- Export formats (PDF, CSV, JSON)
- Integration with SIEM tools
- Slack/Teams notifications

## 📜 Legal & Disclaimer

**IMPORTANT:** This tool is for educational and authorized security testing ONLY.

- ⚖️ Unauthorized access to computer systems is illegal
- 📋 Always obtain proper authorization before scanning
- 🔍 Follow responsible disclosure practices
- 🚫 Do not use for malicious purposes

The authors and contributors are not responsible for misuse of this tool.

## 📞 Support

- **Issues:** Report bugs or request features
- **Documentation:** This README and in-app Help menu
- **Updates:** Check for new versions regularly

## 🎓 Credits

Developed by cybersecurity professionals for the security community.

**Technologies:**
- GitHub Code Search API
- TruffleHog (Truffle Security) & Gitleaks
- Google Gemini (Google AI)
- Python asyncio ecosystem + Jinja2

## 📄 License

See LICENSE file for details.

---

**Made with ❤️ for the security community**

*G-Hunter v3.1.0 Professional Edition*
