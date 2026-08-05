#!/usr/bin/env python3
"""
auto_response.py

Response mechanism for the NIDS (Task 4, requirement 4).

Tails Suricata's eve.json in real time. When an alert event matches a
severity/classtype policy, it takes an automated action:

  - LOW/MEDIUM severity -> log to incidents.log
  - HIGH severity / repeated offender -> block the source IP via iptables
    and log the incident

This intentionally does NOT auto-block on every single alert (that would
let an attacker trivially DoS you by spoofing source IPs against noisy
low-severity rules). It uses a repeat-offender counter plus a severity
threshold, which is the standard approach for automated IDS response.

Usage:
    sudo python3 auto_response.py --eve /var/log/suricata/eve.json
    sudo python3 auto_response.py --eve /var/log/suricata/eve.json --dry-run

--dry-run prints what it WOULD block without touching iptables — use this
for the demo/video walkthrough so you don't need root or a real firewall.
"""
import argparse
import json
import logging
import subprocess
import time
from collections import defaultdict
from datetime import datetime, timedelta, timezone

# --------------------------------------------------------------------------
# Policy
# --------------------------------------------------------------------------
BLOCK_AFTER_ALERTS = 3          # repeat-offender threshold within WINDOW_SECONDS
WINDOW_SECONDS = 60
HIGH_SEVERITY_IMMEDIATE_BLOCK = 1  # Suricata severity 1 = high -> block on first hit
BLOCK_DURATION_MINUTES = 30     # how long an IP stays blocked before auto-unblock

logging.basicConfig(
    filename="incidents.log",
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
console = logging.StreamHandler()
console.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
logging.getLogger().addHandler(console)
log = logging.getLogger("auto_response")


class ResponseEngine:
    def __init__(self, dry_run: bool = True):
        self.dry_run = dry_run
        self.offense_counts = defaultdict(list)   # src_ip -> [timestamps]
        self.blocked_ips = {}                      # src_ip -> unblock_time

    def handle_alert(self, event: dict):
        alert = event.get("alert", {})
        src_ip = event.get("src_ip")
        if not src_ip or not alert:
            return

        severity = alert.get("severity", 3)
        signature = alert.get("signature", "unknown signature")

        log.info(f"ALERT src={src_ip} severity={severity} sig=\"{signature}\"")

        self._auto_unblock_expired()

        if src_ip in self.blocked_ips:
            return  # already blocked, nothing more to do

        now = datetime.now(timezone.utc)
        self.offense_counts[src_ip].append(now)
        # keep only offenses within the rolling window
        self.offense_counts[src_ip] = [
            t for t in self.offense_counts[src_ip] if now - t < timedelta(seconds=WINDOW_SECONDS)
        ]

        should_block = (
            severity <= HIGH_SEVERITY_IMMEDIATE_BLOCK
            or len(self.offense_counts[src_ip]) >= BLOCK_AFTER_ALERTS
        )

        if should_block:
            self._block_ip(src_ip, reason=signature)

    def _block_ip(self, ip: str, reason: str):
        unblock_at = datetime.now(timezone.utc) + timedelta(minutes=BLOCK_DURATION_MINUTES)
        self.blocked_ips[ip] = unblock_at

        if self.dry_run:
            log.warning(f"[DRY-RUN] Would block {ip} for {BLOCK_DURATION_MINUTES}m (reason: {reason})")
            return

        try:
            subprocess.run(
                ["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"],
                check=True,
            )
            log.warning(f"BLOCKED {ip} for {BLOCK_DURATION_MINUTES}m (reason: {reason})")
        except subprocess.CalledProcessError as e:
            log.error(f"Failed to block {ip}: {e}")
        except FileNotFoundError:
            log.error("iptables not found — run on a Linux host with iptables installed, or use --dry-run")

    def _auto_unblock_expired(self):
        now = datetime.now(timezone.utc)
        expired = [ip for ip, t in self.blocked_ips.items() if now >= t]
        for ip in expired:
            if not self.dry_run:
                try:
                    subprocess.run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], check=True)
                except subprocess.CalledProcessError:
                    pass
            log.info(f"UNBLOCKED {ip} (block duration expired)")
            del self.blocked_ips[ip]


def tail_f(path):
    """Generator that yields new lines appended to a file, like `tail -f`."""
    with open(path, "r") as f:
        f.seek(0, 2)  # jump to end of file
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
            yield line


def main():
    parser = argparse.ArgumentParser(description="Auto-response engine for Suricata eve.json alerts.")
    parser.add_argument("--eve", default="/var/log/suricata/eve.json", help="Path to Suricata eve.json")
    parser.add_argument("--dry-run", action="store_true", help="Log intended actions without touching iptables")
    args = parser.parse_args()

    engine = ResponseEngine(dry_run=args.dry_run)
    log.info(f"Starting auto-response engine (dry_run={args.dry_run}) watching {args.eve}")

    for line in tail_f(args.eve):
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if event.get("event_type") == "alert":
            engine.handle_alert(event)


if __name__ == "__main__":
    main()
