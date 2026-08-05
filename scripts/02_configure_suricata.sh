#!/usr/bin/env bash
# ==========================================================================
# 02_configure_suricata.sh
# Applies the configuration changes this project needs on top of the
# default /etc/suricata/suricata.yaml that ships with the package.
#
# Rather than shipping a full replacement suricata.yaml (which is ~1500
# lines and version-specific), this script patches the handful of keys
# that matter for this task, and backs up the original first.
#
# Usage:
#   sudo bash 02_configure_suricata.sh <interface-name>
#   e.g. sudo bash 02_configure_suricata.sh eth0
# ==========================================================================
set -euo pipefail

IFACE="${1:?Usage: 02_configure_suricata.sh <interface-name>}"
CONF=/etc/suricata/suricata.yaml
BACKUP=/etc/suricata/suricata.yaml.bak.$(date +%s)

echo "[*] Backing up original config to ${BACKUP}"
cp "$CONF" "$BACKUP"

echo "[*] Setting capture interface to ${IFACE}"
sed -i "s/interface: eth0/interface: ${IFACE}/" "$CONF" || true

echo "[*] Enabling eve.json alert/http/dns/tls/flow logging (JSON output is what the"
echo "    dashboard and auto-responder both consume)."
python3 - "$CONF" <<'PYEOF'
import sys, re
path = sys.argv[1]
with open(path) as f:
    content = f.read()

# Ensure eve-log is enabled with the event types this project relies on.
# This is a light-touch patch: it only flips 'enabled: no' to 'yes' under
# the eve-log block and does not attempt a full YAML rewrite.
content = re.sub(
    r"(- eve-log:\n\s+enabled: )no",
    r"\1yes",
    content,
    count=1,
)
with open(path, "w") as f:
    f.write(content)
print("Patched eve-log enabled: yes")
PYEOF

echo "[*] Pointing default-rule-path and adding custom.rules to the ruleset list"
sed -i 's#^default-rule-path:.*#default-rule-path: /etc/suricata/rules#' "$CONF"
if ! grep -q "custom.rules" "$CONF"; then
  sed -i '/rule-files:/a\  - custom.rules' "$CONF"
fi

echo "[+] Config patched. Validate with:"
echo "    sudo suricata -T -c ${CONF} -i ${IFACE}"
