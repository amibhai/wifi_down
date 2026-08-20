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
        try:
            signal: int = int(str(ap_info.get("power", -70)).strip() or -70)
        except (ValueError, TypeError):
            signal = -70
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

        # ── Non-PSK networks: no dictionary/handshake path exists ─────────
        # WPA3-SAE, Enterprise (802.1X) and OWE have no pre-shared key to guess,
        # so recommending a handshake/PMKID capture would only waste time.
        tier = ap_info.get("security_tier", "")
        try:
            from modules.scanner import is_dictionary_crackable
            non_crackable = bool(tier) and not is_dictionary_crackable(tier)
        except Exception:
            non_crackable = False
        if non_crackable:
            label = {
                "WPA3_SAE": "WPA3-SAE",
                "WPA2_ENT": "WPA2-Enterprise (802.1X)",
                "WPA3_ENT": "WPA3-Enterprise (802.1X)",
                "OWE":      "Enhanced Open (OWE)",
            }.get(tier, tier)
            plan.reasoning.append(
                f"{label}: no pre-shared key to attack — handshake/PMKID "
                f"dictionary cracking does not apply"
            )
            plan.steps = []
            self.display_plan(plan)
            return plan

        # ── Target-driven crack plan (fuses SSID class + vendor + tier) ──
        try:
            from modules import strategy
            crack_plan = strategy.recommend_strategies(ap_info)
        except Exception:
            crack_plan = []
        crack_primary = crack_plan[0].name if crack_plan else "ssid_mutations"

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
            steps.append(AttackStep(
                attack_type="pmkid",
                wordlist_strategy=crack_primary,
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
            steps.append(AttackStep(
                attack_type="deauth_handshake",
                wordlist_strategy=crack_primary,
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
            wordlist_strategy=crack_primary,
            reason="Passive: wait for natural client reconnection",
            score=20.0,
        ))

        # ── Crack-strategy plan (engine-driven, explainable) ──────────────
        # Every capture step shares the same ranked primary strategy; the full
        # ordered plan is surfaced so the operator sees *why* it was chosen.
        if crack_plan:
            for step in steps:
                if step.attack_type in ("pmkid", "deauth_handshake", "passive_handshake"):
                    step.wordlist_strategy = crack_primary
            plan.reasoning.append(
                "Crack plan (best first): " + strategy.describe_plan(crack_plan)
            )
            plan.reasoning.append(f"→ {crack_plan[0].label}: {crack_plan[0].rationale}")

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
