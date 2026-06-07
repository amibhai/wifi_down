#!/usr/bin/env bash
# WiFi Auditor — cross-distro install script
# Supports: Kali, Parrot, Ubuntu 22+, Arch, Fedora
# Usage: sudo ./install.sh

set -euo pipefail

VENV_DIR="${HOME}/.wifi-auditor/venv"
MIN_AIRCRACK_MAJOR=1
MIN_AIRCRACK_MINOR=7
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

###############################################################################
# Helpers
###############################################################################

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

info()    { echo -e "${CYAN}[*]${RESET} $*"; }
success() { echo -e "${GREEN}[+]${RESET} $*"; }
warn()    { echo -e "${YELLOW}[!]${RESET} $*"; }
error_msg() { echo -e "${RED}[-]${RESET} $*"; }
die()     { error_msg "$*"; exit 1; }

require_root() {
    [[ $EUID -eq 0 ]] || die "Run as root: sudo $0"
}

###############################################################################
# OS detection via /etc/os-release
###############################################################################

detect_os() {
    if [[ -f /etc/os-release ]]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        OS_ID="${ID:-unknown}"
        OS_ID_LIKE="${ID_LIKE:-}"
        OS_VERSION="${VERSION_ID:-}"
    else
        die "/etc/os-release not found — cannot detect OS. Install manually."
    fi
}

###############################################################################
# Package install per distro
###############################################################################

COMMON_APT_PKGS=(
    aircrack-ng
    hcxdumptool
    hcxtools
    hashcat
    crunch
    macchanger
    iw
    iproute2
    python3
    python3-pip
    python3-venv
)

ARCH_PKGS=(
    aircrack-ng
    hcxdumptool
    hcxtools
    hashcat
    crunch
    macchanger
    iw
    iproute2
    python
    python-pip
)

FEDORA_PKGS=(
    aircrack-ng
    hashcat
    crunch
    macchanger
    iw
    iproute
    python3
    python3-pip
)

install_debian() {
    info "Detected Debian/Ubuntu/Kali/Parrot — using apt"
    apt-get update -qq
    apt-get install -y "${COMMON_APT_PKGS[@]}"
}

install_arch() {
    info "Detected Arch Linux — using pacman"
    pacman -Sy --noconfirm "${ARCH_PKGS[@]}"
    for pkg in hcxdumptool hcxtools; do
        if ! command -v "$pkg" &>/dev/null; then
            warn "$pkg not in official repos — install from AUR: yay -S $pkg"
        fi
    done
}

install_fedora() {
    info "Detected Fedora/RHEL — using dnf"
    dnf install -y "${FEDORA_PKGS[@]}"
    if ! command -v hcxdumptool &>/dev/null; then
        warn "hcxdumptool not in dnf repos — building from source..."
        _build_hcxdumptool_fedora
    fi
}

_build_hcxdumptool_fedora() {
    dnf install -y git gcc libpcap-devel openssl-devel || true
    TMP=$(mktemp -d)
    git clone --depth=1 https://github.com/ZerBea/hcxdumptool.git "$TMP/hcxdumptool"
    make -C "$TMP/hcxdumptool" install || warn "hcxdumptool build failed — PMKID attacks unavailable"
    rm -rf "$TMP"
}

install_packages() {
    case "$OS_ID" in
        kali|parrot|ubuntu|debian|linuxmint|pop)
            install_debian ;;
        arch|manjaro|endeavouros)
            install_arch ;;
        fedora|rhel|centos|rocky|almalinux)
            install_fedora ;;
        *)
            case "$OS_ID_LIKE" in
                *debian*|*ubuntu*)  install_debian ;;
                *arch*)             install_arch ;;
                *fedora*|*rhel*)    install_fedora ;;
                *)  die "Unsupported OS: $OS_ID. Install aircrack-ng suite manually." ;;
            esac
            ;;
    esac
}

###############################################################################
# Aircrack-ng version check
###############################################################################

check_aircrack_version() {
    if ! command -v aircrack-ng &>/dev/null; then
        warn "aircrack-ng not found after install — check package manager output"
        return
    fi
    local version
    version=$(aircrack-ng --version 2>&1 | grep -oP '\d+\.\d+' | head -1)
    local major minor
    IFS='.' read -r major minor <<< "$version"
    major=${major:-0}; minor=${minor:-0}
    if (( major < MIN_AIRCRACK_MAJOR || (major == MIN_AIRCRACK_MAJOR && minor < MIN_AIRCRACK_MINOR) )); then
        warn "aircrack-ng $version is older than recommended ${MIN_AIRCRACK_MAJOR}.${MIN_AIRCRACK_MINOR}"
        warn "Newer versions include PMKID improvements. Consider upgrading."
    else
        success "aircrack-ng $version meets minimum (>=${MIN_AIRCRACK_MAJOR}.${MIN_AIRCRACK_MINOR})"
    fi
}

###############################################################################
# Python venv setup
###############################################################################

setup_venv() {
    info "Creating Python venv at ${VENV_DIR} ..."
    mkdir -p "$(dirname "$VENV_DIR")"
    python3 -m venv "$VENV_DIR"
    # shellcheck disable=SC1091
    source "${VENV_DIR}/bin/activate"
    pip install --upgrade pip -q
    pip install -r "${SCRIPT_DIR}/requirements.txt" -q
    if [[ -f "${SCRIPT_DIR}/pyproject.toml" ]]; then
        pip install -e "${SCRIPT_DIR}" -q
    fi
    success "Python environment ready: ${VENV_DIR}"
}

###############################################################################
# Convenience launcher
###############################################################################

create_launcher() {
    local bin_path="/usr/local/bin/wifi-auditor"
    cat > "$bin_path" <<LAUNCHER
#!/usr/bin/env bash
source "${VENV_DIR}/bin/activate"
exec python -m wifi_auditor.cli "\$@"
LAUNCHER
    chmod +x "$bin_path"
    success "Launcher installed: $bin_path"
}

###############################################################################
# Directory setup
###############################################################################

setup_dirs() {
    local dirs=(
        "${HOME}/.wifi-auditor/sessions"
        "${SCRIPT_DIR}/captures"
        "${SCRIPT_DIR}/wordlists"
        "${SCRIPT_DIR}/results"
    )
    for d in "${dirs[@]}"; do
        mkdir -p "$d"
    done
    success "Working directories created"
}

###############################################################################
# Main
###############################################################################

main() {
    echo -e "${BOLD}${CYAN}"
    echo "╔══════════════════════════════════════════╗"
    echo "║     WiFi Auditor — Install Script v2     ║"
    echo "╚══════════════════════════════════════════╝"
    echo -e "${RESET}"

    require_root
    detect_os
    info "OS: $OS_ID ${OS_VERSION:-}"

    info "Installing system packages..."
    install_packages

    check_aircrack_version

    info "Setting up Python environment..."
    setup_venv

    setup_dirs
    create_launcher

    echo
    success "Installation complete!"
    echo -e "  Run: ${BOLD}sudo wifi-auditor${RESET}"
    echo -e "  Or:  ${BOLD}sudo python3 wifi_auditor.py${RESET}"
    echo -e "  Pre-flight check: ${BOLD}wifi-auditor --preflight${RESET}"
    echo
    warn "Only use on networks you own or have written authorization to test."
}

main "$@"
