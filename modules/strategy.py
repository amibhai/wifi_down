#!/usr/bin/env python3
"""
modules/strategy.py — target-driven crack-strategy engine
──────────────────────────────────────────────────────────
Every other module in this tool *gathers* intelligence about a target — the
SSID class, the OUI vendor, the band, the security tier, the name entropy. This
module is where that intelligence finally *pays off*: given one enriched AP
dict it returns a **ranked, explained** sequence of cracking strategies, so the
operator (or full-auto mode) attacks with the highest-probability wordlist
first instead of blindly running rockyou against everything.

That target→strategy fusion is what most tools in this class simply do not do,
and it is pure, deterministic, and fully unit-tested (no RF, no subprocess).

The strategy *names* line up with the generators in ``modules/wordlist.py`` /
``modules/temporal.py`` so a caller can act on them directly.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from modules import scanner

# ── Strategy identifiers (aligned with wordlist.py / temporal.py) ─────────────
S_VENDOR_DEFAULTS = "vendor_defaults"    # router_defaults.yaml known PSKs
S_TEMPORAL_PSK    = "temporal_vendor_psk"  # MAC/date-derived vendor algorithm
S_ISP_PATTERNS    = "isp_patterns"       # ISP-format SSID → provisioning patterns
S_PHONE_NUMBERS   = "phone_numbers"      # numeric SSID → phone/digit lists
S_DIGIT_MASKS     = "digit_masks"        # 8–10 digit brute masks
S_CUPP_PERSONAL   = "cupp_personal"      # personal-name SSID → CUPP profiling
S_COMMON          = "common_passwords"   # breach-frequency common list
S_RULE_BASED      = "rule_based"         # common list + best64 rules
S_MASK_BRUTEFORCE = "mask_bruteforce"    # last resort for high-entropy targets


@dataclass
class CrackStrategy:
    name: str          # machine id (see S_* above)
    label: str         # human-readable
    rationale: str     # *why* this target warrants it
    score: float       # 0–100 priority (higher = try first)


def vendor_has_temporal_algo(vendor: str) -> bool:
    """
    True if a **vendor-specific** (not merely generic) MAC/date PSK algorithm
    exists for *vendor* in the temporal engine.
    """
    v = (vendor or "").lower()
    if not v:
        return False
    try:
        from modules import temporal
        for algo in temporal.ALGORITHMS:
            for token in algo.vendors:
                if token != "generic" and token and token in v:
                    return True
    except Exception:
        return False
    return False


def _resolve_vendor(target: dict) -> str:
    """Vendor name from the target dict, falling back to an OUI lookup."""
    vendor = target.get("vendor") or ""
    if vendor:
        return vendor
    bssid = target.get("bssid", "")
    if bssid:
        try:
            from modules.oui import get_vendor
            return get_vendor(bssid) or ""
        except Exception:
            return ""
    return ""


def recommend_strategies(target: dict) -> list[CrackStrategy]:
    """
    Rank cracking strategies for an enriched AP dict (best first).

    Returns ``[]`` for targets with no dictionary-crackable PSK (Enterprise,
    WPA3-SAE, OWE, OPEN, WEP) — the sequencer already routes those elsewhere.

    Signals fused: ``security_tier`` (crackability), ``ssid_tag``,
    ``ssid_entropy``, and ``vendor`` (direct or via OUI).
    """
    tier = target.get("security_tier", "")
    # Respect the crackable verdict when present; else derive from the tier.
    crackable = target.get("crackable")
    if crackable is None:
        crackable = scanner.is_dictionary_crackable(tier) if tier else True
    if tier and not crackable:
        return []

    ssid_tag = target.get("ssid_tag", "")
    entropy  = float(target.get("ssid_entropy", 0.0) or 0.0)
    vendor   = _resolve_vendor(target)

    out: list[CrackStrategy] = []

    # ── Vendor / default-SSID intelligence — highest hit-rate when it applies ─
    if ssid_tag == scanner.TAG_DEFAULT_SSID or vendor:
        vlabel = vendor or "this model"
        out.append(CrackStrategy(
            S_VENDOR_DEFAULTS, "Vendor default PSKs",
            f"{'Default-format SSID' if ssid_tag == scanner.TAG_DEFAULT_SSID else 'Known vendor ' + vlabel}"
            f" — routers ship documented default passwords; try them first",
            score=94.0 if ssid_tag == scanner.TAG_DEFAULT_SSID else 86.0,
        ))

    if vendor_has_temporal_algo(vendor):
        out.append(CrackStrategy(
            S_TEMPORAL_PSK, f"Temporal vendor PSK ({vendor})",
            f"{vendor} has a documented MAC/date-derived default-PSK algorithm — "
            f"generate the exact candidate keyspace offline",
            score=88.0,
        ))

    # ── SSID-shape driven strategies ─────────────────────────────────────────
    if ssid_tag == scanner.TAG_ISP_FORMAT:
        out.append(CrackStrategy(
            S_ISP_PATTERNS, "ISP provisioning patterns",
            "ISP-format SSID — provider gateways use predictable provisioning PSKs",
            score=82.0,
        ))
    elif ssid_tag == scanner.TAG_NUMERIC:
        out.append(CrackStrategy(
            S_PHONE_NUMBERS, "Phone / numeric lists",
            "Numeric SSID correlates with phone-number / all-digit passwords",
            score=78.0,
        ))
        out.append(CrackStrategy(
            S_DIGIT_MASKS, "8–10 digit masks",
            "Numeric-leaning target — bounded digit brute-force is tractable",
            score=66.0,
        ))
    elif ssid_tag == scanner.TAG_PERSONAL:
        out.append(CrackStrategy(
            S_CUPP_PERSONAL, "Personal profiling (CUPP)",
            "Personal-name SSID — owner-derived words + dates are likely",
            score=74.0,
        ))
    elif ssid_tag == scanner.TAG_RANDOM_HEX:
        out.append(CrackStrategy(
            S_MASK_BRUTEFORCE, "Mask brute-force",
            "Random-hex SSID suggests a factory-random PSK — dictionaries rarely "
            "hit; a targeted mask is the realistic path",
            score=48.0,
        ))

    # ── Entropy nudge: a low-entropy human SSID → dictionary is likely ───────
    common_score = 62.0 if entropy and entropy < 2.5 else 58.0

    # ── Universal fallbacks (always available) ───────────────────────────────
    out.append(CrackStrategy(
        S_COMMON, "Common passwords",
        "Breach-frequency list covers the long tail of weak human passwords",
        score=common_score,
    ))
    out.append(CrackStrategy(
        S_RULE_BASED, "Common + best64 rules",
        "Rule-mutated common list catches simple leet/suffix variations",
        score=50.0,
    ))

    # Dedupe by name (keep the highest-scoring instance) then rank.
    best: dict[str, CrackStrategy] = {}
    for s in out:
        if s.name not in best or s.score > best[s.name].score:
            best[s.name] = s
    return sorted(best.values(), key=lambda s: -s.score)


def primary_strategy(target: dict) -> Optional[str]:
    """The single best strategy name for *target*, or ``None`` if uncrackable."""
    ranked = recommend_strategies(target)
    return ranked[0].name if ranked else None


def describe_plan(strategies: list[CrackStrategy], top: int = 3) -> str:
    """One-line summary of the top strategies, e.g. for logs/UI."""
    if not strategies:
        return "no dictionary-crackable strategy for this target"
    names = " → ".join(s.label for s in strategies[:top])
    return names
