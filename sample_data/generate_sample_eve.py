#!/usr/bin/env python3
"""
Generates a synthetic eve.json file matching the shape of real Suricata
alert output, using the SIDs/signatures from rules/custom.rules. Useful
for demoing or unit-testing the dashboard without a live Suricata sensor.

Usage:
    python3 generate_sample_eve.py > eve.json
"""
import json
import random
from datetime import datetime, timedelta, timezone

SIGNATURES = [
    (9000001, "CUSTOM Possible TCP SYN Port Scan", 2, "attempted-recon"),
    (9000002, "CUSTOM NULL Scan Detected", 2, "attempted-recon"),
    (9000010, "CUSTOM ICMP Flood Detected", 2, "attempted-dos"),
    (9000011, "CUSTOM Possible SYN Flood", 1, "attempted-dos"),
    (9000020, "CUSTOM Possible SSH Brute Force", 1, "attempted-admin"),
    (9000031, "CUSTOM SQL Injection - UNION SELECT", 1, "web-application-attack"),
    (9000032, "CUSTOM Directory Traversal Attempt", 2, "web-application-attack"),
    (9000034, "CUSTOM Suspicious User-Agent (scanner tool)", 2, "web-application-attack"),
    (9000040, "CUSTOM Possible DNS Tunneling - long query", 2, "trojan-activity"),
    (9000050, "CUSTOM Telnet Usage Detected (insecure protocol)", 3, "policy-violation"),
]

SRC_IPS = ["203.0.113.45", "198.51.100.23", "203.0.113.77", "192.0.2.14", "198.51.100.99"]
DST_IP = "192.168.56.10"

events = []
now = datetime.now(timezone.utc)
for i in range(120):
    ts = now - timedelta(seconds=random.randint(0, 3600))
    sid, sig, sev, classtype = random.choice(SIGNATURES)
    src = random.choice(SRC_IPS)
    events.append({
        "timestamp": ts.strftime("%Y-%m-%dT%H:%M:%S.%f%z"),
        "event_type": "alert",
        "src_ip": src,
        "dest_ip": DST_IP,
        "src_port": random.randint(1024, 65535),
        "dest_port": random.choice([22, 23, 53, 80, 443]),
        "proto": random.choice(["TCP", "UDP", "ICMP"]),
        "alert": {
            "signature_id": sid,
            "signature": sig,
            "severity": sev,
            "category": classtype,
        },
    })

events.sort(key=lambda e: e["timestamp"])
for e in events:
    print(json.dumps(e))
