#!/bin/bash
#
# APT-X Installation Script
# =========================
#
# Installs APT-X and its dependencies on Kali Linux or similar systems.
#
# Usage:
#   ./install.sh [options]
#
# Options:
#   --dev       Install development dependencies
#   --tools     Install external security tools
#   --all       Install everything
#   --help      Show this help message
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Defaults
INSTALL_DEV=false
INSTALL_TOOLS=false
PYTHON_CMD="python3"
PIP_CMD="pip3"

# Functions
print_banner() {
    echo -e "${BLUE}"
    echo "    ___    ____  ______   _  __"
    echo "   /   |  / __ \\/_  __/  | |/ /"
    echo "  / /| | / /_/ / / /     |   / "
    echo " / ___ |/ ____/ / /     /   |  "
    echo "/_/  |_/_/     /_/     /_/|_|  "
    echo -e "${NC}"
    echo "APT-X Installer v1.0.0"
    echo "======================"
    echo ""
}

log_info() {
    echo -e "${BLUE}[*]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[+]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

log_error() {
    echo -e "${RED}[-]${NC} $1"
}

check_python() {
    log_info "Checking Python installation..."

    if ! command -v python3 &> /dev/null; then
        log_error "Python 3 is not installed"
        exit 1
    fi

    PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
    log_success "Python $PYTHON_VERSION found"

    # Check version >= 3.9
    if python3 -c 'import sys; exit(0 if sys.version_info >= (3, 9) else 1)'; then
        log_success "Python version is compatible"
    else
        log_error "Python 3.9+ is required"
        exit 1
    fi
}

check_pip() {
    log_info "Checking pip installation..."

    if ! command -v pip3 &> /dev/null; then
        log_warning "pip3 not found, attempting to install..."
        python3 -m ensurepip --upgrade || {
            log_error "Failed to install pip"
            exit 1
        }
    fi

    log_success "pip is available"
}

install_aptx() {
    log_info "Installing APT-X..."

    cd "$PROJECT_ROOT"

    if [ "$INSTALL_DEV" = true ]; then
        log_info "Installing with development dependencies..."
        pip3 install -e ".[dev]"
    else
        pip3 install -e .
    fi

    log_success "APT-X installed successfully"
}

install_tools() {
    log_info "Installing external security tools..."

    # Check if running as root for apt operations
    if [ "$EUID" -ne 0 ]; then
        log_warning "Some tools require root privileges to install"
        SUDO="sudo"
    else
        SUDO=""
    fi

    # Update package list
    log_info "Updating package list..."
    $SUDO apt-get update -qq

    # Install tools via apt
    APT_TOOLS="nmap nikto sqlmap"
    log_info "Installing apt packages: $APT_TOOLS"
    $SUDO apt-get install -y $APT_TOOLS

    # Install Go-based tools
    if command -v go &> /dev/null; then
        log_info "Installing Go-based tools..."

        # Check GOPATH
        if [ -z "$GOPATH" ]; then
            export GOPATH="$HOME/go"
            export PATH="$PATH:$GOPATH/bin"
        fi

        # Install tools
        GO_TOOLS=(
            "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
            "github.com/projectdiscovery/httpx/cmd/httpx@latest"
            "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
            "github.com/ffuf/ffuf/v2@latest"
        )

        for tool in "${GO_TOOLS[@]}"; do
            tool_name=$(basename "$tool" | cut -d@ -f1)
            log_info "Installing $tool_name..."
            go install "$tool" 2>/dev/null || log_warning "Failed to install $tool_name"
        done

        log_success "Go tools installed to $GOPATH/bin"
    else
        log_warning "Go not found, skipping Go-based tools"
        log_info "Install Go and run this script again to install: subfinder, httpx, nuclei, ffuf"
    fi

    # Install Amass
    if command -v snap &> /dev/null; then
        log_info "Installing Amass via snap..."
        $SUDO snap install amass 2>/dev/null || log_warning "Failed to install Amass via snap"
    fi

    log_success "External tools installation complete"
}

verify_installation() {
    log_info "Verifying installation..."

    # Check APT-X CLI
    if command -v aptx &> /dev/null; then
        log_success "APT-X CLI is available"
        aptx --version
    else
        log_warning "APT-X CLI not found in PATH"
        log_info "You may need to add ~/.local/bin to your PATH"
    fi

    # Check tools
    echo ""
    log_info "Checking external tools..."

    TOOLS="nmap amass subfinder httpx nuclei ffuf nikto sqlmap"
    for tool in $TOOLS; do
        if command -v "$tool" &> /dev/null; then
            echo -e "  ${GREEN}✓${NC} $tool"
        else
            echo -e "  ${YELLOW}✗${NC} $tool (not installed)"
        fi
    done
}

initialize_aptx() {
    log_info "Initializing APT-X..."

    # Create directories
    mkdir -p ~/.aptx

    # Initialize if CLI is available
    if command -v aptx &> /dev/null; then
        aptx init --quiet 2>/dev/null || true
    fi

    log_success "APT-X initialized"
}

show_help() {
    echo "APT-X Installation Script"
    echo ""
    echo "Usage: ./install.sh [options]"
    echo ""
    echo "Options:"
    echo "  --dev       Install development dependencies (pytest, black, etc.)"
    echo "  --tools     Install external security tools (nmap, nuclei, etc.)"
    echo "  --all       Install everything (dev + tools)"
    echo "  --help      Show this help message"
    echo ""
    echo "Examples:"
    echo "  ./install.sh              # Basic installation"
    echo "  ./install.sh --dev        # Install with dev dependencies"
    echo "  ./install.sh --tools      # Install with external tools"
    echo "  ./install.sh --all        # Full installation"
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --dev)
            INSTALL_DEV=true
            shift
            ;;
        --tools)
            INSTALL_TOOLS=true
            shift
            ;;
        --all)
            INSTALL_DEV=true
            INSTALL_TOOLS=true
            shift
            ;;
        --help|-h)
            show_help
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            show_help
            exit 1
            ;;
    esac
done

# Main installation
print_banner

log_info "Starting APT-X installation..."
echo ""

check_python
check_pip
echo ""

install_aptx
echo ""

if [ "$INSTALL_TOOLS" = true ]; then
    install_tools
    echo ""
fi

initialize_aptx
echo ""

verify_installation
echo ""

log_success "Installation complete!"
echo ""
echo "To get started:"
echo "  aptx --help          # Show available commands"
echo "  aptx init            # Initialize configuration"
echo "  aptx scan example.com --safe-mode  # Run a scan"
echo ""
echo "Documentation: https://github.com/aptx-framework/aptx"
