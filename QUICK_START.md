# G-Hunter v3.1.0 - Quick Start Guide

## 🚨 CRITICAL FIRST STEP - Security

**⚠️ IMMEDIATELY REVOKE OLD GITHUB TOKENS!**

Your old scripts had hardcoded tokens. These must be revoked NOW:

1. Visit: https://github.com/settings/tokens
2. Find your old token (if any exist)
3. Click "Delete" or "Revoke"
4. Create a NEW token with scope: `public_repo`

---

## 🚀 Installation (One-Time Setup)

### Option 1: Automated Setup (Recommended)

```bash
cd /home/zenitsu-agatsuma/Documents/GScan
./setup.sh
```

This script will:
- ✅ Install Python dependencies
- ✅ Check for TruffleHog
- ✅ Create .env configuration file
- ✅ Help you configure API tokens
- ✅ Set up directory structure

### Option 2: Manual Setup

```bash
# Install dependencies
pip3 install -r requirements.txt

# Install TruffleHog
# macOS:
brew install trufflehog

# Linux/Windows:
pip install trufflehog

# Configure environment
cp .env.example .env
nano .env
# Add your tokens:
# GITHUB_TOKEN=ghp_your_new_token_here
# GEMINI_API_KEY=your_gemini_key_here  # Optional
```

---

## 🎯 Running G-Hunter

### Launch the Tool

```bash
python3 ghunter_pro.py
```

### Menu Options

```
1. Git Scan       - Search GitHub for sensitive info
2. Repo Scan      - Deep scan with TruffleHog + AI
3. HTML Report    - Generate professional reports
4. Help           - Detailed usage guide
5. Exit           - Quit G-Hunter
```

---

## 📝 Example Workflow

### Scenario: Scanning for "acme.com" secrets

**Step 1: Git Scan**
```
1. Run: python3 ghunter_pro.py
2. Select: 1 (Git Scan)
3. Enter keywords: acme.com, acme, acme-corp
4. Enter dorks file: gitDorks.txt
5. Wait for scan...
```

**Result:**
- `outputs/acme.com/repos.txt` - 45 repositories found
- `outputs/acme.com/urls.txt` - 123 file URLs found

**Step 2: Repo Scan**
```
1. Select: 2 (Repo Scan)
2. Enter file: outputs/acme.com/repos.txt
3. Wait for TruffleHog + AI analysis...
```

**Result:**
- `outputs/acme.com/scan_results.json` - 12 secrets found
  - 8 verified secrets
  - 3 marked as false positives (AI)
  - 2 need manual review

**Step 3: Generate Report**
```
1. Select: 3 (Generate HTML Report)
2. Enter file: outputs/acme.com/scan_results.json
```

**Result:**
- `outputs/acme.com/report.html` - Professional interactive report
- Open in browser to view/filter results

---

## 🎨 Features at a Glance

### Git Scan (Option 1)
- ⚡ Async concurrent scanning (5 simultaneous)
- 🔄 Auto-resume on interruption
- 📊 Real-time progress with ETA
- 📁 Organized output by keyword
- 🎯 Uses 513 git dorks

### Repo Scan (Option 2)
- 🔐 TruffleHog verified secret detection
- 🤖 Google Gemini AI analysis
- 🏷️ Severity classification (CRITICAL/HIGH/MEDIUM/LOW)
- ⚠️ False positive identification
- 📝 Manual review markers

### HTML Report (Option 3)
- 🎨 Modern, responsive design
- 🔍 Real-time search & filtering
- 📊 Statistics dashboard
- 🎯 Click to expand details
- 📤 Stakeholder-ready

---

## 📂 Output Structure

```
outputs/
└── <keyword>/              # e.g., "acme.com"
    ├── repos.txt           # Unique repositories
    ├── urls.txt            # File URLs (filtered by extension)
    ├── scan_results.json   # TruffleHog + AI findings
    ├── report.html         # Interactive dashboard
    └── progress.json       # Resume checkpoint
```

---

## 🔧 Configuration

### Environment Variables (.env file)

```bash
# Required - GitHub Personal Access Token
GITHUB_TOKEN=ghp_your_token_here

# Optional - For AI analysis
GEMINI_API_KEY=your_gemini_key_here
```

### Get Your Tokens

**GitHub Token:**
- URL: https://github.com/settings/tokens/new
- Scope: `public_repo`
- Description: "G-Hunter scanning"

**Gemini API Key (optional):**
- URL: https://makersuite.google.com/app/apikey
- Enables AI-powered false positive reduction

---

## ⚡ Quick Commands

```bash
# Launch G-Hunter
python3 ghunter_pro.py

# Launch with verbose logging
python3 ghunter_pro.py -v

# Run setup
./setup.sh

# View documentation
cat README.md

# View technical analysis
cat ANALYSIS_AND_IMPROVEMENTS.md
```

---

## 🐛 Troubleshooting

### "GITHUB_TOKEN environment variable not set"
```bash
# Solution: Create .env file
cp .env.example .env
nano .env
# Add: GITHUB_TOKEN=ghp_your_token_here
```

### "TruffleHog not found"
```bash
# macOS
brew install trufflehog

# Linux/Windows
pip install trufflehog

# Or download binary from:
# https://github.com/trufflesecurity/trufflehog/releases
```

### "Rate limit hit"
- G-Hunter automatically waits for reset
- This is normal for large scans
- GitHub API limit: 10 searches/minute (authenticated)

### "Scan interrupted, lost progress"
- Don't worry! Progress is auto-saved
- When you restart, choose "Resume? (y/n): y"
- Continues from exact point

---

## 📊 File Extensions Scanned

G-Hunter looks for these file types:
```
.php .rb .py .env .conf .java .txt .go .sql .yml
.git .sh .js .ts .json .xml .ini .cfg .log .bak
.db .sqlite .md .properties .key .pem .cert .csv
.yaml .lock .htaccess .gitignore .config .secret .toml
```

---

## 🎯 Keyword Best Practices

### ✅ Good Keywords

```
Company names:    acme, acme-corp, acmeinc
Domains:          acme.com, api.acme.com
Email patterns:   @acme.com
Usernames:        acme-admin, acme-dev, acme-ci
```

### ❌ Avoid

```
Generic terms:    api, password, key, token
Single letters:   a, b, c
Common words:     test, demo, example
```

---

## 🔐 Security Best Practices

1. ✅ Always get authorization before scanning
2. ✅ Never commit .env file to git (protected by .gitignore)
3. ✅ Rotate GitHub tokens regularly
4. ✅ Use dedicated security testing account
5. ✅ Document all authorized scans
6. ✅ Follow responsible disclosure
7. ✅ Revoke and rotate any exposed secrets immediately

---

## 📞 Getting Help

### Documentation Files
- `README.md` - Complete user guide
- `ANALYSIS_AND_IMPROVEMENTS.md` - Technical deep-dive
- `QUICK_START.md` - This file (quick reference)

### In-App Help
- Run G-Hunter → Select option 4 (Help)

### Logs
- Check `ghunter.log` for detailed errors
- Run with `-v` flag for verbose output

---

## 🎉 You're Ready!

**Your G-Hunter is:**
- ✅ Installed and configured
- ✅ Secure (no hardcoded tokens)
- ✅ Professional and feature-rich
- ✅ Ready for production use

**Happy hunting! 🎯**

---

*G-Hunter v3.1.0 Professional Edition*
*Security made simple*
