#!/bin/bash
#
# APT-X Wordlist Downloader
# =========================
#
# Downloads common wordlists for content discovery and fuzzing.
#

set -e

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Default wordlist directory
WORDLIST_DIR="${APTX_WORDLIST_DIR:-$HOME/.aptx/wordlists}"

log_info() {
    echo -e "${BLUE}[*]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[+]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

# Create directory
mkdir -p "$WORDLIST_DIR"
cd "$WORDLIST_DIR"

log_info "Downloading wordlists to: $WORDLIST_DIR"
echo ""

# SecLists subset
log_info "Downloading SecLists common lists..."

# Discovery wordlists
mkdir -p discovery
cd discovery

# Common web paths
if [ ! -f "common.txt" ]; then
    curl -sL "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt" -o common.txt
    log_success "Downloaded: common.txt"
fi

# Directories
if [ ! -f "directory-list-2.3-medium.txt" ]; then
    curl -sL "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/directory-list-2.3-medium.txt" -o directory-list-2.3-medium.txt
    log_success "Downloaded: directory-list-2.3-medium.txt"
fi

# API paths
if [ ! -f "api-endpoints.txt" ]; then
    curl -sL "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/api/api-endpoints.txt" -o api-endpoints.txt
    log_success "Downloaded: api-endpoints.txt"
fi

# Backup files
if [ ! -f "backup-files.txt" ]; then
    curl -sL "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/Common-DB-Backups.txt" -o backup-files.txt
    log_success "Downloaded: backup-files.txt"
fi

cd ..

# Subdomain wordlists
mkdir -p subdomains
cd subdomains

if [ ! -f "subdomains-top1million-5000.txt" ]; then
    curl -sL "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt" -o subdomains-top1million-5000.txt
    log_success "Downloaded: subdomains-top1million-5000.txt"
fi

cd ..

# Parameter wordlists
mkdir -p parameters
cd parameters

if [ ! -f "burp-parameter-names.txt" ]; then
    curl -sL "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/burp-parameter-names.txt" -o burp-parameter-names.txt
    log_success "Downloaded: burp-parameter-names.txt"
fi

cd ..

# Fuzzing wordlists
mkdir -p fuzzing
cd fuzzing

# SQLi
if [ ! -f "sqli.txt" ]; then
    curl -sL "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/SQLi/Generic-SQLi.txt" -o sqli.txt
    log_success "Downloaded: sqli.txt"
fi

# XSS
if [ ! -f "xss.txt" ]; then
    curl -sL "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/XSS/XSS-Jhaddix.txt" -o xss.txt
    log_success "Downloaded: xss.txt"
fi

# LFI
if [ ! -f "lfi.txt" ]; then
    curl -sL "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/LFI/LFI-Jhaddix.txt" -o lfi.txt
    log_success "Downloaded: lfi.txt"
fi

cd ..

echo ""
log_success "Wordlists downloaded to: $WORDLIST_DIR"
echo ""

# Show summary
echo "Contents:"
find . -type f -name "*.txt" | while read file; do
    lines=$(wc -l < "$file")
    echo "  $file ($lines lines)"
done

echo ""
echo "Set APTX_WORDLIST_DIR to change the wordlist location"
