#!/usr/bin/env python3
"""
modules/reporter.py — Human-readable HTML / Markdown report generator
──────────────────────────────────────────────────────────────────────
Reads a session *.jsonl* log produced by modules/logger.py and renders
a penetration-test style report.

Usage:
    from modules.reporter import generate_report
    generate_report("results/session_HomeNet_20260101.jsonl")
"""

import json
import os
from datetime import datetime, timezone


_TEMPLATE_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>WiFi Audit Report — {ssid}</title>
  <style>
    body {{ font-family: 'Segoe UI', sans-serif; background: #0d1117; color: #e6edf3; margin: 0; padding: 2rem; }}
    h1   {{ color: #58a6ff; border-bottom: 1px solid #30363d; padding-bottom: .5rem; }}
    h2   {{ color: #79c0ff; margin-top: 2rem; }}
    table{{ border-collapse: collapse; width: 100%; margin-top: 1rem; }}
    th   {{ background: #161b22; color: #8b949e; text-align: left; padding: .5rem .75rem; border: 1px solid #30363d; }}
    td   {{ padding: .5rem .75rem; border: 1px solid #30363d; }}
    tr:nth-child(even) td {{ background: #161b22; }}
    .found {{ color: #3fb950; font-weight: bold; }}
    .fail  {{ color: #f85149; }}
    .meta  {{ color: #8b949e; font-size: .85rem; }}
  </style>
</head>
<body>
  <h1>📶 WiFi Auditor — Penetration Test Report</h1>
  <p class="meta">Generated: {generated} UTC</p>

  <h2>Target</h2>
  <table>
    <tr><th>SSID</th><td>{ssid}</td></tr>
    <tr><th>Session start</th><td>{start}</td></tr>
    <tr><th>Session end</th><td>{end}</td></tr>
    <tr><th>Elapsed</th><td>{elapsed}</td></tr>
    <tr><th>Outcome</th><td class="{outcome_cls}">{outcome}</td></tr>
  </table>

  <h2>Event Timeline</h2>
  <table>
    <tr><th>Timestamp</th><th>Event</th><th>Details</th></tr>
    {rows}
  </table>
</body>
</html>
"""


def _load_events(jsonl_path: str) -> list[dict]:
    events = []
    with open(jsonl_path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                events.append(json.loads(line))
    return events


def generate_report(jsonl_path: str, out_dir: str | None = None) -> str:
    """
    Parse *jsonl_path* and write an HTML report beside it (or into *out_dir*).
    Returns the path to the generated HTML file.
    """
    events = _load_events(jsonl_path)

    ssid      = next((e.get("ssid", "unknown") for e in events if e.get("event") == "session_start"), "unknown")
    start_ts  = next((e.get("ts", "") for e in events if e.get("event") == "session_start"), "")
    end_ev    = next((e for e in events if e.get("event") == "session_end"), {})
    end_ts    = end_ev.get("ts", "")
    elapsed   = f"{end_ev.get('elapsed_s', '?')} s"
    success   = end_ev.get("success", False)

    outcome     = "✅  Key found" if success else "❌  Not cracked"
    outcome_cls = "found" if success else "fail"

    rows = []
    for ev in events:
        ts     = ev.get("ts", "")[:19].replace("T", " ")
        name   = ev.get("event", "")
        detail = "; ".join(f"{k}={v}" for k, v in ev.items() if k not in ("event", "ts"))
        rows.append(f"<tr><td>{ts}</td><td>{name}</td><td>{detail}</td></tr>")

    html = _TEMPLATE_HTML.format(
        ssid=ssid,
        generated=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
        start=start_ts[:19].replace("T", " "),
        end=end_ts[:19].replace("T", " "),
        elapsed=elapsed,
        outcome=outcome,
        outcome_cls=outcome_cls,
        rows="\n    ".join(rows),
    )

    out_dir  = out_dir or os.path.dirname(jsonl_path)
    basename = os.path.splitext(os.path.basename(jsonl_path))[0]
    out_path = os.path.join(out_dir, f"{basename}_report.html")

    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(html)

    print(f"[+] Report written → {out_path}")
    return out_path
