#!/usr/bin/env python3
"""
NIDS Dashboard — Flask app (Task 4, requirement 5: visualize detected
attacks using dashboards/graphs).

Reads a Suricata eve.json file (real or the bundled synthetic sample) and
serves:
  - GET /                -> dashboard UI
  - GET /api/alerts       -> raw alert list (most recent first, capped)
  - GET /api/stats        -> aggregate stats for the charts

Run:
    pip install -r requirements.txt
    python3 app.py --eve ../sample_data/eve.json
    # then open http://127.0.0.1:5000

Point --eve at your real /var/log/suricata/eve.json once Suricata is
running to switch from the demo dataset to live data. The page auto-
refreshes every 5 seconds.
"""
import argparse
import json
from collections import Counter
from pathlib import Path

from flask import Flask, jsonify, render_template

app = Flask(__name__)
EVE_PATH = None  # set in main()
MAX_ALERTS_RETURNED = 500


def load_alerts():
    if not EVE_PATH or not Path(EVE_PATH).exists():
        return []
    alerts = []
    with open(EVE_PATH, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if event.get("event_type") == "alert":
                alerts.append(event)
    alerts.sort(key=lambda e: e.get("timestamp", ""), reverse=True)
    return alerts[:MAX_ALERTS_RETURNED]


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/alerts")
def api_alerts():
    alerts = load_alerts()
    simplified = [
        {
            "timestamp": a.get("timestamp"),
            "src_ip": a.get("src_ip"),
            "dest_ip": a.get("dest_ip"),
            "dest_port": a.get("dest_port"),
            "proto": a.get("proto"),
            "signature": a.get("alert", {}).get("signature"),
            "severity": a.get("alert", {}).get("severity"),
            "category": a.get("alert", {}).get("category"),
        }
        for a in alerts
    ]
    return jsonify(simplified)


@app.route("/api/stats")
def api_stats():
    alerts = load_alerts()

    by_signature = Counter(a.get("alert", {}).get("signature", "unknown") for a in alerts)
    by_src_ip = Counter(a.get("src_ip", "unknown") for a in alerts)
    by_severity = Counter(a.get("alert", {}).get("severity", 0) for a in alerts)
    by_category = Counter(a.get("alert", {}).get("category", "unknown") for a in alerts)

    # bucket alerts by minute for a timeline chart
    timeline = Counter()
    for a in alerts:
        ts = a.get("timestamp", "")
        bucket = ts[:16]  # 'YYYY-MM-DDTHH:MM'
        if bucket:
            timeline[bucket] += 1
    timeline_sorted = sorted(timeline.items())

    return jsonify({
        "total_alerts": len(alerts),
        "top_signatures": by_signature.most_common(10),
        "top_source_ips": by_src_ip.most_common(10),
        "by_severity": dict(by_severity),
        "by_category": by_category.most_common(10),
        "timeline": timeline_sorted,
    })


def main():
    global EVE_PATH
    parser = argparse.ArgumentParser(description="NIDS alert dashboard")
    parser.add_argument("--eve", default="../sample_data/eve.json", help="Path to eve.json")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5000)
    args = parser.parse_args()
    EVE_PATH = args.eve
    app.run(host=args.host, port=args.port, debug=True)


if __name__ == "__main__":
    main()
