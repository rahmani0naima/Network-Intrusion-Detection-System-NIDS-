#!/usr/bin/env bash
# ==========================================================================
# 01_install_suricata.sh
# Installs Suricata IDS on a Debian/Ubuntu lab VM and prepares it for
# custom-rule based intrusion detection.
#
# Usage:
#   sudo bash 01_install_suricata.sh
# ==========================================================================
set -euo pipefail

echo "[*] Updating package index..."
apt-get update -y

echo "[*] Installing Suricata + supporting tools..."
apt-get install -y software-properties-common
add-apt-repository -y ppa:oisf/suricata-stable || true
apt-get update -y
apt-get install -y suricata jq curl net-tools tcpdump

echo "[*] Verifying installation..."
suricata --build-info | head -n 20

echo "[*] Detecting default network interface..."
DEFAULT_IFACE=$(ip route | awk '/default/ {print $5; exit}')
echo "    Detected interface: ${DEFAULT_IFACE:-<none found, set manually>}"

echo "[*] Creating working directories..."
mkdir -p /etc/suricata/rules
mkdir -p /var/log/suricata

echo "[*] Enabling the community-id and eve.json JSON log format is handled in suricata.yaml (see 02_configure_suricata.sh)."
echo "[+] Base install complete."
echo "    Next: run 02_configure_suricata.sh to apply the custom config,"
echo "    then place custom.rules in /etc/suricata/rules/."
