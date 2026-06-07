"""Pentest report generator — reads JSON session files and produces Markdown + findings.json."""
from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

SESSIONS_DIR = Path.home() / ".wifi-auditor" / "sessions"
REPORTS_DIR  = Path("results")


###############################################################################
# Helpers
###############################################################################

def _sha256_file(path: Path) -> str:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return "unavailable"


def _load_session(session_id: str) -> dict:
    """Load a session dict from ~/.wifi-auditor/sessions/<id>.json or legacy jsonl."""
    path = SESSIONS_DIR / f"{session_id}.json"
    if path.exists():
        return json.loads(path.read_text())

    # Fallback: legacy JSON-lines session logs in results/
    for p in Path("results").glob(f"*{session_id}*.jsonl"):
        events: list[dict] = []
        for line in p.read_text().splitlines():
            try:
                events.append(json.loads(line))
            except Exception:
                pass
        return {"events": events, "_source": str(p), "session_id": session_id}

    raise FileNotFoundError(
        f"Session {session_id!r} not found in {SESSIONS_DIR} or results/"
    )


###############################################################################
# Public API
###############################################################################

def generate_report(
    session_id: str,
    out_dir: Path = REPORTS_DIR,
) -> tuple[Path, Path]:
    """
    Generate a Markdown pentest report and findings.json for *session_id*.
    Returns (markdown_path, json_path).
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    data = _load_session(session_id)

    bssid        = data.get("target_bssid", "Unknown")
    ssid         = data.get("target_ssid",  "Unknown")
    stage        = data.get("stage",        "unknown")
    started_at   = data.get("started_at",   "Unknown")
    capture_file = data.get("capture_file")
    wordlist_file= data.get("wordlist_file")

    # Extract result, duration, errors from events list or flat fields
    key_found: Optional[str] = data.get("result")
    errors:    list[str]     = []
    duration_s: Optional[float] = data.get("duration_s")

    for evt in data.get("events", []):
        if evt.get("event") == "key_found":
            key_found = evt.get("key", "")
        if "error" in evt:
            errors.append(str(evt["error"]))
        if evt.get("event") == "session_end":
            duration_s = evt.get("elapsed_s")

    outcome = (
        "KEY FOUND"   if key_found else
        "NOT CRACKED" if stage in ("done", "cracking") else
        "IN PROGRESS"
    )
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    cap_hash     = _sha256_file(Path(capture_file)) if capture_file else "N/A"
    dur_str      = f"{duration_s:.0f}s" if duration_s else "N/A"

    # ── Markdown body ─────────────────────────────────────────────────────────
    md: list[str] = [
        "# WiFi Security Audit Report",
        "",
        f"**Generated:** {generated_at}  ",
        f"**Session ID:** `{session_id}`  ",
        "",
        "---",
        "",
        "## Executive Summary",
        "",
    ]
    if key_found:
        md.append(
            f"A WiFi security assessment was performed against **{ssid}** "
            f"(BSSID: `{bssid}`). "
            f"The WPA2 pre-shared key was **successfully recovered**: `{key_found}`."
        )
    else:
        md.append(
            f"A WiFi security assessment was performed against **{ssid}** "
            f"(BSSID: `{bssid}`). "
            "The pre-shared key was **not** recovered within the scope of this test. "
            "The network may use a strong, non-dictionary password."
        )

    md += [
        "",
        "---",
        "",
        "## Scope Confirmation",
        "",
        "| Field | Value |",
        "|-------|-------|",
        f"| Target SSID | `{ssid}` |",
        f"| Target BSSID | `{bssid}` |",
        f"| Session ID | `{session_id}` |",
        f"| Test Started | {started_at} |",
        f"| Duration | {dur_str} |",
        "",
        "---",
        "",
        "## Methodology",
        "",
        "| Step | Description |",
        "|------|-------------|",
        "| 1 | Pre-flight check — verified tools and interface capability |",
        "| 2 | Network scan — identified target AP from surrounding networks |",
        "| 3 | Handshake / PMKID capture — collected WPA2 authentication material |",
        "| 4 | Wordlist generation — built targeted password candidates |",
        "| 5 | Password cracking — dictionary attack against captured material |",
        "",
        "---",
        "",
        "## Findings",
        "",
        f"**Outcome:** `{outcome}`",
        "",
        "| Parameter | Value |",
        "|-----------|-------|",
        f"| Outcome | `{outcome}` |",
        f"| Key Found | `{key_found or 'N/A'}` |",
        f"| Stage Reached | `{stage}` |",
        f"| Errors Logged | {len(errors)} |",
        "",
    ]

    if errors:
        md += ["### Errors", ""]
        for e in errors:
            md.append(f"- `{e}`")
        md.append("")

    md += [
        "---",
        "",
        "## Evidence",
        "",
        "| Artifact | Details |",
        "|----------|---------|",
        f"| Capture File | `{capture_file or 'N/A'}` |",
        f"| Capture SHA-256 | `{cap_hash}` |",
        f"| Wordlist Used | `{wordlist_file or 'N/A'}` |",
        f"| Session Log | `{SESSIONS_DIR / (session_id + '.json')}` |",
        "",
        "---",
        "",
        "> *Report generated by WiFi Auditor v2.0.0*",
        "",
    ]

    md_path = out_dir / f"report_{session_id}.md"
    md_path.write_text("\n".join(md), encoding="utf-8")
    logger.info("Markdown report: %s", md_path)

    # ── findings.json ─────────────────────────────────────────────────────────
    findings = {
        "session_id":    session_id,
        "target_bssid":  bssid,
        "target_ssid":   ssid,
        "outcome":       outcome,
        "key_found":     key_found,
        "stage_reached": stage,
        "started_at":    started_at,
        "duration_s":    duration_s,
        "capture_file":  capture_file,
        "capture_sha256":cap_hash,
        "wordlist_file": wordlist_file,
        "errors":        errors,
        "generated_at":  generated_at,
    }
    json_path = out_dir / f"findings_{session_id}.json"
    json_path.write_text(json.dumps(findings, indent=2), encoding="utf-8")
    logger.info("Findings JSON: %s", json_path)

    return md_path, json_path
