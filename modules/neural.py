"""
NEURAL PATHFINDER — AI-powered structured attack planning.

Not a chatbot. A decision engine that ingests scan results and returns a
structured Attack Brief with ranked steps, probability estimates, wordlist
hints, risk flags, and an executive summary.

Falls back to the rule-based AttackSequencer if no API key is configured.
Requires explicit user consent before any data is sent to OpenAI.

API key stored in: ~/.wifi-auditor/neural.conf  (never in the repo)
Data sent to OpenAI: SSID, BSSID prefix, security type, channel, vendor.
Data NEVER sent: credentials, handshake material, client MACs.
"""
from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

logger = logging.getLogger(__name__)
console = Console()

NEURAL_CONF = Path.home() / ".wifi-auditor" / "neural.conf"

_CONSENT_GIVEN: bool = False  # per-session consent flag


# ─── Data model ───────────────────────────────────────────────────────────────

@dataclass
class AttackStep:
    name:               str
    rationale:          str
    estimated_time:     str    # e.g. "2-5 min"
    success_probability: str   # LOW / MEDIUM / HIGH


@dataclass
class AttackBrief:
    recommended_path:    list[AttackStep]     = field(default_factory=list)
    wordlist_hints:      list[str]            = field(default_factory=list)
    risk_flags:          list[str]            = field(default_factory=list)
    executive_summary:   str                  = ""
    generated_by:        str                  = ""  # "neural" or "rule_based"

    def to_dict(self) -> dict:
        return {
            "recommended_path": [
                {"name": s.name, "rationale": s.rationale,
                 "estimated_time": s.estimated_time,
                 "success_probability": s.success_probability}
                for s in self.recommended_path
            ],
            "wordlist_hints":    self.wordlist_hints,
            "risk_flags":        self.risk_flags,
            "executive_summary": self.executive_summary,
            "generated_by":      self.generated_by,
        }


# ─── API key management ───────────────────────────────────────────────────────

def _load_api_key() -> Optional[str]:
    if NEURAL_CONF.exists():
        try:
            data = json.loads(NEURAL_CONF.read_text())
            return data.get("openai_api_key") or None
        except Exception:
            pass
    return os.environ.get("OPENAI_API_KEY") or None


def _save_api_key(key: str) -> None:
    NEURAL_CONF.parent.mkdir(parents=True, exist_ok=True)
    NEURAL_CONF.write_text(json.dumps({"openai_api_key": key}, indent=2))
    NEURAL_CONF.chmod(0o600)
    logger.info("Neural Pathfinder: API key stored at %s", NEURAL_CONF)


def _prompt_for_api_key() -> Optional[str]:
    console.print()
    console.print(Panel(
        "[bold #00D4AA]NEURAL PATHFINDER — API Key Setup[/bold #00D4AA]\n\n"
        "An OpenAI API key is required. The key will be stored at:\n"
        f"  [dim]{NEURAL_CONF}[/dim]\n\n"
        "It is never written to the repository or transmitted anywhere except OpenAI.\n"
        "Use a key with spend limits configured at platform.openai.com.",
        border_style="#00D4AA",
    ))
    try:
        key = input("  Enter OpenAI API key (or press Enter to skip): ").strip()
    except (KeyboardInterrupt, EOFError):
        return None
    if key and key.startswith("sk-"):
        _save_api_key(key)
        console.print("  [green]Key saved.[/green]")
        return key
    console.print("  [yellow]No valid key entered — rule-based sequencer will be used.[/yellow]")
    return None


# ─── Consent gate ─────────────────────────────────────────────────────────────

def _get_consent() -> bool:
    global _CONSENT_GIVEN
    if _CONSENT_GIVEN:
        return True

    console.print()
    console.print(Panel(
        "[bold yellow]DATA TRANSMISSION NOTICE[/bold yellow]\n\n"
        "Neural Pathfinder will send the following scan metadata to OpenAI:\n"
        "  • SSID, BSSID vendor prefix, security type, channel\n\n"
        "The following data is [bold]NEVER[/bold] transmitted:\n"
        "  • Captured credentials or handshakes\n"
        "  • Client device MACs\n"
        "  • Any raw packet data\n\n"
        "This is subject to OpenAI's data usage policies.",
        border_style="yellow",
        box=box.ROUNDED,
    ))
    try:
        ans = input("  Confirm data transmission consent? [Y/n]: ").strip().lower()
    except (KeyboardInterrupt, EOFError):
        return False
    if ans in ("", "y", "yes"):
        _CONSENT_GIVEN = True
        return True
    return False


# ─── Scan data sanitization (privacy filter) ─────────────────────────────────

def _sanitize_scan_data(networks: list[dict]) -> list[dict]:
    """Strip client MACs and any captured material — only metadata survives."""
    safe = []
    for net in networks:
        safe.append({
            "ssid":          net.get("ssid", ""),
            "bssid_prefix":  net.get("bssid", "")[:8],  # OUI only, not full MAC
            "security":      net.get("privacy", ""),
            "cipher":        net.get("cipher", ""),
            "channel":       net.get("channel", 0),
            "power_dbm":     net.get("power", -80),
            "vendor":        net.get("vendor", ""),
            "wps_enabled":   net.get("wps_enabled", False),
            "wps_locked":    net.get("wps_locked", False),
            "ssid_tag":      net.get("ssid_tag", ""),
            "security_tier": net.get("security_tier", ""),
        })
    return safe


# ─── OpenAI call ──────────────────────────────────────────────────────────────

_SYSTEM_PROMPT = """
You are a WiFi penetration testing decision engine for an authorized security auditor.
Your ONLY role is to analyze scan data and return a structured JSON attack brief.
You must NEVER return free text, conversation, or markdown prose — only the JSON object below.
If you cannot produce the JSON, return {"error": "reason"}.

Return exactly this JSON schema:
{
  "recommended_path": [
    {
      "name": "step name",
      "rationale": "one sentence explanation",
      "estimated_time": "X-Y min",
      "success_probability": "LOW|MEDIUM|HIGH"
    }
  ],
  "wordlist_hints": ["hint1", "hint2"],
  "risk_flags": ["flag1", "flag2"],
  "executive_summary": "Exactly 2 sentences. No markdown."
}

Focus on:
- Most probable attack vectors given the security configuration and vendor
- Wordlist hints: suggest specific seeds based on SSID, vendor, and SSID tag patterns
- Risk flags: WPS lockout risk, WPA3 transition mode caveats, vendor-known default creds
"""


def _call_openai(api_key: str, scan_data: list[dict], model: str = "gpt-4o-mini") -> dict:
    """Call OpenAI and return parsed JSON response dict."""
    try:
        from openai import OpenAI
    except ImportError:
        raise ImportError("openai package not installed — run: pip install openai")

    client = OpenAI(api_key=api_key)

    user_content = json.dumps({
        "scan_results": scan_data,
        "context": "Authorized penetration test. Provide attack brief.",
    })

    response = client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": _SYSTEM_PROMPT.strip()},
            {"role": "user",   "content": user_content},
        ],
        max_tokens=1000,
        temperature=0.2,
        response_format={"type": "json_object"},
    )

    raw = response.choices[0].message.content or "{}"
    return json.loads(raw)


def _parse_openai_response(data: dict) -> AttackBrief:
    steps = []
    for s in data.get("recommended_path", []):
        steps.append(AttackStep(
            name=s.get("name", ""),
            rationale=s.get("rationale", ""),
            estimated_time=s.get("estimated_time", "unknown"),
            success_probability=s.get("success_probability", "MEDIUM"),
        ))
    return AttackBrief(
        recommended_path=steps,
        wordlist_hints=data.get("wordlist_hints", []),
        risk_flags=data.get("risk_flags", []),
        executive_summary=data.get("executive_summary", ""),
        generated_by="neural",
    )


# ─── Rule-based fallback (leverages existing AttackSequencer) ─────────────────

def _rule_based_brief(networks: list[dict]) -> AttackBrief:
    """Generate a deterministic brief using the rule-based sequencer."""
    from .sequencer import AttackSequencer
    sequencer = AttackSequencer()

    if not networks:
        return AttackBrief(
            executive_summary="No targets available for analysis.",
            generated_by="rule_based",
        )

    # Score the best target
    target = max(networks, key=lambda n: int(n.get("power", -100) or -100))
    plan   = sequencer.score_target(target)

    steps = []
    for step in (plan.steps if hasattr(plan, "steps") else []):
        steps.append(AttackStep(
            name=getattr(step, "attack_type", str(step)),
            rationale=getattr(step, "reason", "Ranked by score"),
            estimated_time="2-10 min",
            success_probability="MEDIUM",
        ))

    ssid   = target.get("ssid", "")
    vendor = target.get("vendor", "")

    hints = []
    if ssid:
        hints.append(ssid.lower())
    if vendor:
        hints.append(vendor.lower().split()[0])

    return AttackBrief(
        recommended_path=steps,
        wordlist_hints=hints,
        risk_flags=_infer_risk_flags(target),
        executive_summary=(
            f"Target {ssid!r} uses {target.get('privacy', 'unknown')} with "
            f"{vendor or 'unknown'} hardware. "
            "Rule-based sequencer identified the optimal attack path."
        ),
        generated_by="rule_based",
    )


def _infer_risk_flags(target: dict) -> list[str]:
    flags = []
    if target.get("wps_locked"):
        flags.append("WPS AP-Lock active — PIN spray will trigger lockout")
    privacy = (target.get("privacy") or "").upper()
    if "WPA3" in privacy and "WPA2" in privacy:
        flags.append("WPA3 Transition Mode — downgrade to WPA2 may be possible")
    if target.get("ssid_tag") == "DEFAULT_SSID":
        flags.append("Default SSID detected — vendor defaults likely still set")
    channel = int(target.get("channel") or 6)
    if channel > 11:
        flags.append("5 GHz channel — adapter must support 5 GHz injection")
    return flags


# ─── Rich display ─────────────────────────────────────────────────────────────

def display_attack_brief(brief: AttackBrief) -> None:
    gen_label = (
        "[#00D4AA]Neural Pathfinder[/#00D4AA]"
        if brief.generated_by == "neural"
        else "[dim]Rule-based sequencer[/dim]"
    )

    console.print()
    console.print(Panel(
        f"[bold #00D4AA]NEURAL PATHFINDER — Attack Brief[/bold #00D4AA]  "
        f"[dim]generated by {gen_label}[/dim]",
        border_style="#00D4AA",
    ))

    if brief.executive_summary:
        console.print(f"\n  [bold white]Summary:[/bold white]")
        console.print(f"  {brief.executive_summary}\n")

    if brief.recommended_path:
        t = Table(
            title="Recommended Attack Path",
            box=box.ROUNDED,
            border_style="dim cyan",
            header_style="bold #00D4AA",
        )
        t.add_column("#",                    width=3,  justify="right")
        t.add_column("Step",                 width=30)
        t.add_column("Est. Time",            width=12)
        t.add_column("P(success)",           width=12)
        t.add_column("Rationale",            width=40)

        prob_colors = {"HIGH": "green", "MEDIUM": "yellow", "LOW": "red"}
        for i, step in enumerate(brief.recommended_path, 1):
            pc = prob_colors.get(step.success_probability.upper(), "dim")
            t.add_row(
                str(i),
                f"[white]{step.name}[/white]",
                f"[dim]{step.estimated_time}[/dim]",
                f"[{pc}]{step.success_probability}[/{pc}]",
                step.rationale,
            )
        console.print(t)

    if brief.wordlist_hints:
        console.print(f"\n  [bold]Wordlist seeds (add to custom strategy):[/bold]")
        for hint in brief.wordlist_hints:
            console.print(f"  + [cyan]{hint}[/cyan]")

    if brief.risk_flags:
        console.print(f"\n  [bold yellow]Risk flags:[/bold yellow]")
        for flag in brief.risk_flags:
            console.print(f"  ⚠  [yellow]{flag}[/yellow]")

    console.print()


# ─── CLI entry point ──────────────────────────────────────────────────────────

def neural_menu(
    networks: list[dict],
    openai_model: str = "gpt-4o-mini",
) -> Optional[AttackBrief]:
    """Interactive Neural Pathfinder launcher."""
    console.print()
    console.print(Panel(
        "[bold #00D4AA]NEURAL PATHFINDER[/bold #00D4AA]\n\n"
        "[dim]Structured AI decision engine for attack planning.\n"
        "Analyzes scan data and returns a ranked attack brief.\n"
        "Falls back to rule-based sequencer if no API key is set.[/dim]",
        border_style="#00D4AA",
    ))
    console.print()

    if not networks:
        console.print("[red]  No scan results available. Run a scan first.[/red]")
        return None

    api_key = _load_api_key()

    if not api_key:
        console.print("  [yellow][!][/yellow] No OpenAI API key configured.")
        api_key = _prompt_for_api_key()

    if api_key:
        if not _get_consent():
            console.print("  [yellow]Consent declined — using rule-based sequencer.[/yellow]")
            brief = _rule_based_brief(networks)
        else:
            console.print(f"\n  [cyan][*][/cyan] Analyzing {len(networks)} target(s) with "
                          f"[white]{openai_model}[/white]...")
            try:
                sanitized = _sanitize_scan_data(networks)
                raw       = _call_openai(api_key, sanitized, openai_model)
                brief     = _parse_openai_response(raw)
            except Exception as exc:
                logger.warning("Neural Pathfinder API call failed: %s", exc)
                console.print(f"  [yellow][!][/yellow] API call failed: {exc}")
                console.print("  [dim]Falling back to rule-based sequencer.[/dim]")
                brief = _rule_based_brief(networks)
                brief.executive_summary = (
                    brief.executive_summary +
                    " Neural analysis unavailable — rule-based sequencer used."
                )
    else:
        console.print("  [dim]Using rule-based sequencer (no API key).[/dim]")
        brief = _rule_based_brief(networks)
        brief.executive_summary = (
            brief.executive_summary +
            " Neural analysis unavailable — rule-based sequencer used."
        )

    display_attack_brief(brief)

    # Audit log
    logger.info(
        "NEURAL_PATHFINDER generated_by=%s steps=%d flags=%d",
        brief.generated_by, len(brief.recommended_path), len(brief.risk_flags),
    )

    return brief
