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

import logging
import os
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional

from modules import scanner

logger = logging.getLogger(__name__)

WORDLIST_DIR = "wordlists"
WPA_MIN, WPA_MAX = 8, 63          # a WPA PSK is 8–63 chars; anything else is noise

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


# ══════════════════════════════════════════════════════════════════════════════
# Execution — turn a strategy into an actual wordlist file
# ══════════════════════════════════════════════════════════════════════════════

def _common_data_path() -> Optional[str]:
    """Path to the bundled breach-frequency common-password list, if present."""
    p = Path(__file__).resolve().parent.parent / "data" / "common_passwords.txt"
    return str(p) if p.is_file() else None


def _vendor_default_passwords(vendor: str, bssid: str) -> list[str]:
    """
    Default PSK candidates for *vendor* from ``data/router_defaults.yaml``, with
    ``{last4mac}`` substituted. Uses the vendor we already resolved at scan time
    rather than re-doing an OUI lookup, so it works offline and deterministically.
    """
    vendor = (vendor or "").strip()
    if not vendor:
        return []
    last4 = bssid.replace(":", "").lower()[-4:] if bssid else ""
    try:
        import yaml
        from modules.oui import DEFAULTS_FILE
        with open(DEFAULTS_FILE, encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
    except Exception as exc:  # pragma: no cover - config edge
        logger.debug("router_defaults load failed: %s", exc)
        return []

    vlow = vendor.lower()
    out: list[str] = []
    for pattern, entry in data.get("vendor_defaults", {}).items():
        plow = pattern.lower()
        if plow in vlow or vlow in plow:
            for pwd in entry.get("passwords", []):
                out.append(str(pwd).replace("{last4mac}", last4))
            break
    seen: set[str] = set()
    return [p for p in out if not (p in seen or seen.add(p))]


def materialize_strategy(name: str, target: dict, out_dir: str = WORDLIST_DIR) -> Optional[str]:
    """
    Produce a concrete wordlist file for strategy *name* against *target*, or
    ``None`` when it cannot be auto-materialised (digit/mask brute-force and
    personal CUPP profiling need a mask engine or interactive input — the caller
    simply falls through to the next strategy).
    """
    os.makedirs(out_dir, exist_ok=True)
    bssid  = target.get("bssid", "")
    vendor = _resolve_vendor(target)
    ssid   = target.get("ssid") or target.get("essid") or ""
    stamp  = datetime.now().strftime("%Y%m%d_%H%M%S")
    tag    = (bssid.replace(":", "")[-6:] or "target")

    if name == S_VENDOR_DEFAULTS:
        pwds = _vendor_default_passwords(vendor, bssid)
        if not pwds:
            return None
        out = os.path.join(out_dir, f"vendordef_{tag}_{stamp}.txt")
        with open(out, "w", encoding="utf-8") as fh:
            fh.write("\n".join(pwds) + "\n")
        return out

    if name == S_TEMPORAL_PSK:
        if not bssid:
            return None
        try:
            from modules import temporal
            out_path = Path(out_dir) / f"temporal_{tag}_{stamp}.txt"
            path, count = temporal.generate_temporal_wordlist(
                bssid, vendor or "generic", out_path=out_path
            )
            return str(path) if count > 0 else None
        except Exception as exc:
            logger.debug("temporal materialise failed: %s", exc)
            return None

    if name in (S_COMMON, S_RULE_BASED):
        return _common_data_path()

    if name == S_PHONE_NUMBERS:
        out = os.path.join(out_dir, f"phones_{tag}_{stamp}.txt")
        try:
            from modules.wordlist import gen_phones
            return out if gen_phones(out) > 0 else None
        except Exception as exc:
            logger.debug("phones materialise failed: %s", exc)
            return None

    if name == S_ISP_PATTERNS:
        if not ssid or ssid == "<hidden>":
            return None
        out = os.path.join(out_dir, f"ssidmut_{tag}_{stamp}.txt")
        try:
            from modules.wordlist import gen_ssid
            return out if gen_ssid(ssid, out) > 0 else None
        except Exception as exc:
            logger.debug("ssid-mutation materialise failed: %s", exc)
            return None

    # S_DIGIT_MASKS / S_CUPP_PERSONAL / S_MASK_BRUTEFORCE — not a plain wordlist.
    return None


def build_auto_wordlist(
    target: dict,
    out_dir: str = WORDLIST_DIR,
    max_lines: int = 2_000_000,
) -> Optional[str]:
    """
    Execute the full ranked plan into **one** WPA-valid, de-duplicated wordlist,
    ordered best-strategy-first (few high-probability candidates up front, the
    broad common list last). Returns the combined file path, or ``None`` for a
    non-crackable target.

    This is what closes the loop: the strategy the engine *recommends* is the
    wordlist that actually gets cracked, with zero operator interaction.
    """
    plan = recommend_strategies(target)
    if not plan:
        return None

    names = [s.name for s in plan]
    if S_COMMON not in names:      # always guarantee the fallback
        names.append(S_COMMON)

    seen: set[str] = set()
    combined: list[str] = []
    used: list[str] = []
    for name in names:
        try:
            path = materialize_strategy(name, target, out_dir)
        except Exception:
            path = None
        if not path or not os.path.isfile(path):
            continue
        added = 0
        try:
            with open(path, "r", errors="replace") as fh:
                for line in fh:
                    w = line.strip()
                    if not w or w in seen or not (WPA_MIN <= len(w) <= WPA_MAX):
                        continue
                    seen.add(w)
                    combined.append(w)
                    added += 1
                    if len(combined) >= max_lines:
                        break
        except OSError:
            continue
        if added:
            used.append(name)
        if len(combined) >= max_lines:
            break

    if not combined:
        return None

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    tag = (target.get("bssid", "").replace(":", "")[-6:] or "target")
    out = os.path.join(out_dir, f"auto_{tag}_{stamp}.txt")
    with open(out, "w", encoding="utf-8") as fh:
        fh.write("\n".join(combined) + "\n")
    logger.info("AUTO_WORDLIST target=%s strategies=%s candidates=%d path=%s",
                target.get("bssid", ""), "+".join(used), len(combined), out)
    return out


# ══════════════════════════════════════════════════════════════════════════════
# Mask attacks — the strategies a wordlist cannot express (hashcat -a 3)
# ══════════════════════════════════════════════════════════════════════════════

def _digit_mask(n: int) -> str:
    return "?d" * n


def masks_for_target(target: dict) -> list[str]:
    """
    hashcat brute-force masks (attack mode ``-a 3``) suited to *target*,
    best-first. These express the ``digit_masks`` / ``mask_bruteforce``
    strategies the engine recommends but a wordlist cannot materialise.

    Returns ``[]`` for non-crackable targets. An 8-digit all-numeric PSK is the
    single most common brute-forceable WPA key (10^8 ≈ minutes on a GPU), so it
    is always offered for a crackable target; numeric-SSID targets additionally
    get the 9- and 10-digit spaces (phone numbers).
    """
    tier = target.get("security_tier", "")
    crackable = target.get("crackable")
    if crackable is None:
        crackable = scanner.is_dictionary_crackable(tier) if tier else True
    if tier and not crackable:
        return []

    ssid_tag = target.get("ssid_tag", "")
    masks: list[str]
    if ssid_tag in (scanner.TAG_NUMERIC, scanner.TAG_ISP_FORMAT):
        masks = [_digit_mask(10), _digit_mask(8), _digit_mask(9), _digit_mask(11)]
    else:
        masks = [_digit_mask(8)]     # classic 8-digit numeric default PSK
    seen: set[str] = set()
    return [m for m in masks if not (m in seen or seen.add(m))]


def materialize_masks(target: dict, out_dir: str = WORDLIST_DIR) -> Optional[str]:
    """
    Write the target's masks to a hashcat ``.hcmask`` file (one mask per line)
    for ``hashcat -a 3 -m 22000 <hash> <file.hcmask>``. Returns the path, or
    ``None`` when no mask applies (non-crackable target).
    """
    masks = masks_for_target(target)
    if not masks:
        return None
    os.makedirs(out_dir, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    tag = (target.get("bssid", "").replace(":", "")[-6:] or "target")
    out = os.path.join(out_dir, f"masks_{tag}_{stamp}.hcmask")
    with open(out, "w", encoding="utf-8") as fh:
        fh.write("\n".join(masks) + "\n")
    return out
