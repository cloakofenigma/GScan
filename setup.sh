#!/bin/bash

# G-Hunter Setup Script
# Automated setup for G-Hunter Professional Edition

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}"
echo "╔══════════════════════════════════════════════════════════════════════════╗"
echo "║                                                                          ║"
echo "║   ██████╗       ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗    ║"
echo "║  ██╔════╝       ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗   ║"
echo "║  ██║  ███╗█████╗███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝   ║"
echo "║  ██║   ██║╚════╝██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗   ║"
echo "║  ╚██████╔╝      ██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║   ║"
echo "║   ╚═════╝       ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝   ║"
echo "║                                                                          ║"
echo "║                      Professional Setup Script                          ║"
echo "║                                                                          ║"
echo "╚══════════════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

echo ""
echo -e "${YELLOW}🚀 Starting G-Hunter setup...${NC}"
echo ""

# Check Python version
echo -e "${BLUE}📌 Checking Python version...${NC}"
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}❌ Python 3 is not installed!${NC}"
    echo "Please install Python 3.8 or later and run this script again."
    exit 1
fi

PYTHON_VERSION=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
echo -e "${GREEN}✓ Python ${PYTHON_VERSION} detected${NC}"

# Check pip
echo -e "${BLUE}📌 Checking pip...${NC}"
if ! command -v pip3 &> /dev/null; then
    echo -e "${RED}❌ pip3 is not installed!${NC}"
    exit 1
fi
echo -e "${GREEN}✓ pip3 detected${NC}"

# Install Python dependencies
echo ""
echo -e "${BLUE}📦 Installing Python dependencies...${NC}"
pip3 install -r requirements.txt

# Check TruffleHog
echo ""
echo -e "${BLUE}🔍 Checking for TruffleHog...${NC}"
if ! command -v trufflehog &> /dev/null; then
    echo -e "${YELLOW}⚠️  TruffleHog not found!${NC}"
    echo ""
    echo "TruffleHog is required for deep repository scanning."
    echo ""
    echo "Installation options:"
    echo "  1. macOS:        brew install trufflehog"
    echo "  2. Python:       pip install trufflehog"
    echo "  3. Binary:       https://github.com/trufflesecurity/trufflehog/releases"
    echo ""
    read -p "Would you like to install via pip? (y/n): " install_trufflehog

    if [[ $install_trufflehog =~ ^[Yy]$ ]]; then
        pip3 install trufflehog
        echo -e "${GREEN}✓ TruffleHog installed${NC}"
    else
        echo -e "${YELLOW}⚠️  Skipping TruffleHog installation (required for Repo Scan feature)${NC}"
    fi
else
    TRUFFLEHOG_VERSION=$(trufflehog --version 2>&1 || echo "unknown")
    echo -e "${GREEN}✓ TruffleHog detected: ${TRUFFLEHOG_VERSION}${NC}"
fi

# Setup .env file
echo ""
echo -e "${BLUE}🔐 Setting up environment configuration...${NC}"

if [ -f .env ]; then
    echo -e "${YELLOW}⚠️  .env file already exists!${NC}"
    read -p "Would you like to recreate it? (y/n): " recreate_env

    if [[ $recreate_env =~ ^[Yy]$ ]]; then
        cp .env.example .env
        echo -e "${GREEN}✓ .env file created from template${NC}"
    else
        echo -e "${YELLOW}⚠️  Keeping existing .env file${NC}"
    fi
else
    cp .env.example .env
    echo -e "${GREEN}✓ .env file created from template${NC}"
fi

# Configure tokens
echo ""
echo -e "${BLUE}🔑 Configuring API tokens...${NC}"
echo ""
echo -e "${YELLOW}════════════════════════════════════════════════════════════════${NC}"
echo -e "${YELLOW}IMPORTANT: Never commit your tokens to git!${NC}"
echo -e "${YELLOW}════════════════════════════════════════════════════════════════${NC}"
echo ""

read -p "Do you want to configure tokens now? (y/n): " configure_tokens

if [[ $configure_tokens =~ ^[Yy]$ ]]; then
    echo ""
    echo -e "${BLUE}1. GitHub Personal Access Token${NC}"
    echo "   Required for GitHub API access"
    echo "   Get yours at: https://github.com/settings/tokens"
    echo "   Required scope: public_repo"
    echo ""
    read -p "   Enter your GitHub token (or press Enter to skip): " github_token

    if [ ! -z "$github_token" ]; then
        # Update .env file
        if [[ "$OSTYPE" == "darwin"* ]]; then
            # macOS
            sed -i '' "s/GITHUB_TOKEN=.*/GITHUB_TOKEN=$github_token/" .env
        else
            # Linux
            sed -i "s/GITHUB_TOKEN=.*/GITHUB_TOKEN=$github_token/" .env
        fi
        echo -e "${GREEN}   ✓ GitHub token configured${NC}"
    else
        echo -e "${YELLOW}   ⚠️  Skipped - You'll need to edit .env manually${NC}"
    fi

    echo ""
    echo -e "${BLUE}2. Google Gemini API Key (Optional)${NC}"
    echo "   Used for AI-powered false positive reduction"
    echo "   Get yours at: https://makersuite.google.com/app/apikey"
    echo ""
    read -p "   Enter your Gemini API key (or press Enter to skip): " gemini_key

    if [ ! -z "$gemini_key" ]; then
        if [[ "$OSTYPE" == "darwin"* ]]; then
            sed -i '' "s/GEMINI_API_KEY=.*/GEMINI_API_KEY=$gemini_key/" .env
        else
            sed -i "s/GEMINI_API_KEY=.*/GEMINI_API_KEY=$gemini_key/" .env
        fi
        echo -e "${GREEN}   ✓ Gemini API key configured${NC}"
    else
        echo -e "${YELLOW}   ⚠️  Skipped - AI analysis will be unavailable${NC}"
    fi
else
    echo -e "${YELLOW}⚠️  You'll need to edit .env file manually with your tokens${NC}"
fi

# Create outputs directory
echo ""
echo -e "${BLUE}📁 Creating output directory...${NC}"
mkdir -p outputs
echo -e "${GREEN}✓ outputs/ directory created${NC}"

# Make scripts executable
echo ""
echo -e "${BLUE}🔧 Setting file permissions...${NC}"
chmod +x ghunter_pro.py
chmod +x setup.sh
echo -e "${GREEN}✓ Scripts are now executable${NC}"

# Final summary
echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║                      ✨ Setup Complete! ✨                                ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${BLUE}📋 Setup Summary:${NC}"
echo -e "   ✓ Python dependencies installed"
if command -v trufflehog &> /dev/null; then
    echo -e "   ✓ TruffleHog installed"
else
    echo -e "   ⚠️  TruffleHog not installed (install manually for Repo Scan)"
fi
echo -e "   ✓ Environment file created (.env)"
echo -e "   ✓ Output directory created (outputs/)"
echo -e "   ✓ Scripts made executable"
echo ""
echo -e "${BLUE}🚀 Next Steps:${NC}"
echo ""
echo -e "   1. ${YELLOW}IMPORTANT:${NC} If you have old hardcoded tokens, revoke them:"
echo -e "      https://github.com/settings/tokens"
echo ""
echo -e "   2. Edit .env file with your API tokens (if not done already):"
echo -e "      nano .env"
echo ""
echo -e "   3. Run G-Hunter:"
echo -e "      ${GREEN}python3 ghunter_pro.py${NC}"
echo ""
echo -e "   4. Read the documentation:"
echo -e "      cat README.md"
echo ""
echo -e "${BLUE}📚 Documentation:${NC}"
echo -e "   • README.md                     - User guide"
echo -e "   • ANALYSIS_AND_IMPROVEMENTS.md  - Technical analysis"
echo -e "   • .env.example                  - Configuration template"
echo ""
echo -e "${YELLOW}⚠️  Security Reminder:${NC}"
echo -e "   • Never commit .env file to git"
echo -e "   • Never share your API tokens"
echo -e "   • Rotate tokens regularly"
echo -e "   • Only use for authorized testing"
echo ""
echo -e "${GREEN}Happy hunting! 🎯${NC}"
echo ""
