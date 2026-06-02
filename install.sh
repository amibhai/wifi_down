#!/bin/bash
# WiFi Auditor — dependency installer
# Tested on Kali Linux / Parrot OS / Ubuntu 22.04+

set -e
RED='\033[91m'; GREEN='\033[92m'; YELLOW='\033[93m'; RESET='\033[0m'

info()  { echo -e "${GREEN}[+]${RESET} $1"; }
warn()  { echo -e "${YELLOW}[!]${RESET} $1"; }
error() { echo -e "${RED}[-]${RESET} $1"; }

# Must run as root
if [[ $EUID -ne 0 ]]; then
    error "Run this script as root: sudo ./install.sh"
    exit 1
fi

info "Updating package lists..."
apt-get update -qq

info "Installing aircrack-ng suite..."
apt-get install -y aircrack-ng

info "Installing additional wireless tools..."
apt-get install -y \
    iw \
    wireless-tools \
    net-tools \
    crunch \
    macchanger

# Optional but recommended
info "Installing hcxdumptool and hcxtools (PMKID attacks)..."
if apt-get install -y hcxdumptool hcxtools 2>/dev/null; then
    info "hcxdumptool / hcxtools installed."
else
    warn "hcxdumptool not found in repos. Trying to build from source..."
    apt-get install -y git libpcap-dev
    TMP_DIR=$(mktemp -d)
    git clone https://github.com/ZerBea/hcxdumptool.git "$TMP_DIR/hcxdumptool"
    make -C "$TMP_DIR/hcxdumptool"
    install -m 755 "$TMP_DIR/hcxdumptool/hcxdumptool" /usr/local/bin/
    git clone https://github.com/ZerBea/hcxtools.git "$TMP_DIR/hcxtools"
    make -C "$TMP_DIR/hcxtools"
    make -C "$TMP_DIR/hcxtools" install
    rm -rf "$TMP_DIR"
    info "hcxdumptool / hcxtools built and installed."
fi

info "Installing hashcat (GPU cracking, optional)..."
apt-get install -y hashcat || warn "hashcat install failed — GPU cracking unavailable."

info "Installing Python 3 (should already be present)..."
apt-get install -y python3 python3-pip

# rockyou.txt
ROCKYOU='/usr/share/wordlists/rockyou.txt'
if [[ ! -f "$ROCKYOU" ]]; then
    warn "rockyou.txt not found at $ROCKYOU"
    if [[ -f "${ROCKYOU}.gz" ]]; then
        info "Decompressing rockyou.txt.gz..."
        gunzip "${ROCKYOU}.gz"
    else
        warn "Download manually: https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt"
    fi
else
    info "rockyou.txt found at $ROCKYOU"
fi

# Permissions
chmod +x wifi_auditor.py

echo ""
info "═══════════════════════════════════════════════════════"
info " Installation complete!"
info " Run: sudo python3 wifi_auditor.py"
info "═══════════════════════════════════════════════════════"
