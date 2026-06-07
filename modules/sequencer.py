"""Smart attack sequencer — scores a target AP and produces an ordered attack plan."""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Optional

from rich import box
from rich.console import Console
from rich.panel import Panel

logger = logging.getLogger(__name__)
console = Console()


@dataclass
class AttackStep:
    attack_type: str
    wordlist_strategy: str
    reason: str
    score: float = 0.0


@dataclass
class AttackPlan:
    target_bssid: str
    target_ssid: str
    steps: list[AttackStep] = field(default_factory=list)
    reasoning: list[str] = field(default_factory=list)


class AttackSequencer:
    """
    Score a discovered AP and produce an ordered list of (attack, wordlist)
    pairs ranked by estimated probability of success.
    """

    def score_target(self, ap_info: dict) -> AttackPlan:
        bssid: str    = ap_info.get("bssid", "")
        ssid: str     = ap_info.get("ssid", ap_info.get("essid", ""))
        privacy: str  = ap_info.get("privacy", "WPA2").upper()
        signal: int   = int(ap_info.get("power", "-70").lstrip() or -70)
        clients: int  = int(ap_info.get("client_count", 0) or 0)
        has_pmkid: bool  = bool(ap_info.get("pmkid_capable", False))
        wps_enabled: bool = bool(ap_info.get("wps_enabled", False))
        wps_locked: bool  = bool(ap_info.get("wps_locked",  False))
        wps_version: str  = ap_info.get("wps_version", "")
        vendor: Optional[str] = ap_info.get("vendor")
        ssid_tag: str = ap_info.get("ssid_tag", "")

        plan = AttackPlan(target_bssid=bssid, target_ssid=ssid)
        steps: list[AttackStep] = []

        # ── WEP: instant win ─────────────────────────────────────────────
        if "WEP" in privacy:
            steps.append(AttackStep(
                attack_type="wep_arp_replay",
                wordlist_strategy="n/a",
                reason="WEP detected — ARP replay recovers key without wordlist",
                score=100.0,
            ))
            plan.reasoning.append("WEP: ARP replay is the fastest attack path (no wordlist needed)")
            plan.steps = steps
            self.display_plan(plan)
            return plan

        # ── OPEN: no auth to crack ────────────────────────────────────────
        if "OPN" in privacy or privacy == "":
            plan.reasoning.append("Network is OPEN — no authentication to crack")
            plan.steps = []
            self.display_plan(plan)
            return plan

        # ── WPS Pixie-Dust: highest priority if WPS is on and unlocked ───
        if wps_enabled and not wps_locked:
            ver_tag = f" v{wps_version}" if wps_version else ""
            steps.append(AttackStep(
                attack_type="wps_pixiedust",
                wordlist_strategy="n/a",
                reason=(
                    f"WPS{ver_tag} enabled, not locked — Pixie-Dust recovers PSK "
                    "in <30 s on vulnerable APs (no wordlist needed)"
                ),
                score=95.0,
            ))
            steps.append(AttackStep(
                attack_type="wps_pin_spray",
                wordlist_strategy="vendor_pins",
                reason=f"WPS{ver_tag} enabled — OUI-matched vendor PINs + {30} common PINs",
                score=92.0,
            ))
            plan.reasoning.append(
                f"WPS{ver_tag} detected and unlocked — Pixie-Dust is the fastest path"
            )
        elif wps_enabled and wps_locked:
            ver_tag = f" v{wps_version}" if wps_version else ""
            plan.reasoning.append(
                f"WPS{ver_tag} detected but AP-Lock is set — PIN attacks will fail; "
                "Pixie-Dust may still work (proceeds offline after nonce capture)"
            )
            steps.append(AttackStep(
                attack_type="wps_pixiedust",
                wordlist_strategy="n/a",
                reason=f"WPS{ver_tag} locked — Pixie-Dust still works if nonces captured",
                score=70.0,
            ))
        else:
            plan.reasoning.append("WPS not detected — skipping WPS attacks")

        # ── PMKID: no client required ─────────────────────────────────────
        if has_pmkid or clients == 0:
            wl = "vendor_defaults" if vendor else "ssid_mutations"
            steps.append(AttackStep(
                attack_type="pmkid",
                wordlist_strategy=wl,
                reason="PMKID: no client reconnect needed" + (
                    f" — vendor '{vendor}' known, defaults loaded first" if vendor else ""
                ),
                score=90.0,
            ))
            plan.reasoning.append("PMKID preferred: works without any associated client")

        # ── Deauth + handshake ────────────────────────────────────────────
        if clients > 0:
            deauth_score = 75.0 + min(clients * 3, 15)
            if signal < -75:
                deauth_score -= 25
                plan.reasoning.append(
                    f"Weak signal ({signal} dBm) — deauth may be unreliable; "
                    "reduce --deauth-limit if sending"
                )
            wl = "vendor_defaults" if vendor else "ssid_mutations"
            steps.append(AttackStep(
                attack_type="deauth_handshake",
                wordlist_strategy=wl,
                reason=f"{clients} client(s) visible, signal {signal} dBm",
                score=deauth_score,
            ))
            plan.reasoning.append(
                f"Deauth handshake: {clients} client(s) at {signal} dBm "
                f"(score {deauth_score:.0f})"
            )
        else:
            plan.reasoning.append("No clients visible — deauth not viable; using PMKID/passive")

        # ── Passive capture: always a fallback ───────────────────────────
        steps.append(AttackStep(
            attack_type="passive_handshake",
            wordlist_strategy="ssid_mutations",
            reason="Passive: wait for natural client reconnection",
            score=20.0,
        ))

        # ── Wordlist strategy enrichment ──────────────────────────────────
        if vendor:
            for step in steps:
                if step.attack_type in ("pmkid", "deauth_handshake"):
                    step.wordlist_strategy = "vendor_defaults"
            plan.reasoning.append(f"Vendor '{vendor}' identified — defaults prioritized")

        ssid_clean = ssid.replace(" ", "")
        if ssid_clean and ssid_clean.isdigit():
            for step in steps:
                step.wordlist_strategy = "phone_numbers"
            plan.reasoning.append("SSID is all-numeric — phone number patterns prioritized")
        elif ssid and ssid[-1].isdigit():
            plan.reasoning.append("SSID ends in digit(s) — year/number mutations added")

        if ssid_tag == "DEFAULT_SSID":
            plan.reasoning.append("Default SSID detected — vendor defaults are high-confidence")

        # ── Sort by score ─────────────────────────────────────────────────
        steps.sort(key=lambda s: s.score, reverse=True)
        plan.steps = steps
        self.display_plan(plan)
        return plan

    def display_plan(self, plan: AttackPlan) -> None:
        if not plan.reasoning and not plan.steps:
            return
        reasoning_lines = "\n".join(f"  • {r}" for r in plan.reasoning) or "  (none)"
        if plan.steps:
            steps_lines = "\n".join(
                f"  [{i+1}] [cyan]{s.attack_type}[/] + [yellow]{s.wordlist_strategy}[/]"
                f"  — {s.reason}"
                for i, s in enumerate(plan.steps)
            )
        else:
            steps_lines = "  (no attack steps — network may be open or already owned)"

        console.print(Panel(
            f"[bold]Target:[/] {plan.target_ssid} ({plan.target_bssid})\n\n"
            f"[bold]Reasoning:[/]\n{reasoning_lines}\n\n"
            f"[bold]Attack Plan (ranked):[/]\n{steps_lines}",
            title="[bold cyan]Smart Attack Sequencer[/]",
            box=box.ROUNDED,
        ))
