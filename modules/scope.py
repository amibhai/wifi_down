"""Scope enforcement — authorize targets before any frame injection."""
from __future__ import annotations

import logging
import sys
from datetime import date, datetime
from pathlib import Path
from typing import Optional

import yaml
from rich import box
from rich.console import Console
from rich.panel import Panel

from .exceptions import ScopeError

logger = logging.getLogger(__name__)
console = Console()

DEFAULT_SCOPE_FILE = Path("scope.yaml")


class ScopeManager:
    """
    Load scope.yaml and provide is_authorized() / require_authorized() guards.

    Call require_authorized() before EVERY operation that sends frames.
    Passive scanning (read-only) does NOT require a scope check.
    """

    def __init__(self, scope_file: Path = DEFAULT_SCOPE_FILE) -> None:
        self._scope_file = scope_file
        self._targets: dict[str, dict] = {}
        if scope_file.exists():
            self._load(scope_file)
        else:
            logger.debug("No scope file at %s — all frame-injection will be blocked", scope_file)

    def _load(self, path: Path) -> None:
        try:
            with open(path) as f:
                data = yaml.safe_load(f) or {}
            for entry in data.get("authorized_targets", []):
                bssid = entry.get("bssid", "").upper()
                if bssid:
                    self._targets[bssid] = entry
            logger.info("Scope file loaded: %d target(s) from %s", len(self._targets), path)
        except Exception as exc:
            logger.error("Failed to load scope file %s: %s", path, exc)

    # ── Public API ────────────────────────────────────────────────────────────

    def is_authorized(self, bssid: str) -> bool:
        bssid = bssid.upper()
        entry = self._targets.get(bssid)
        if not entry:
            return False
        valid_until = entry.get("valid_until")
        if valid_until:
            try:
                expiry = datetime.strptime(str(valid_until), "%Y-%m-%d").date()
                if date.today() > expiry:
                    logger.warning("Scope entry for %s expired on %s", bssid, valid_until)
                    return False
            except ValueError:
                pass
        return True

    def require_authorized(self, bssid: str, operation: str = "this operation") -> None:
        """
        Raise ScopeError if *bssid* is not in the scope file.
        This is a hard block — the caller must not proceed if this raises.
        """
        if not self._targets:
            raise ScopeError(
                f"No scope file loaded. Cannot perform {operation!r}. "
                "Create scope.yaml first:  wifi-auditor --scope-wizard",
                bssid=bssid,
            )
        if not self.is_authorized(bssid):
            raise ScopeError(
                f"BSSID {bssid!r} is NOT listed in scope.yaml. "
                f"Obtain written authorization and add it before {operation!r}.",
                bssid=bssid,
            )
        logger.info("Scope check PASSED: %s → %s", bssid, operation)

    @property
    def authorized_targets(self) -> dict[str, dict]:
        return dict(self._targets)


# ─── Scope wizard ─────────────────────────────────────────────────────────────

def scope_wizard() -> None:
    """Interactive wizard that builds/appends to scope.yaml with a consent checklist."""
    console.print()
    console.print(Panel.fit(
        "[bold yellow]⚠  SCOPE WIZARD — AUTHORIZATION CHECKLIST  ⚠[/]\n\n"
        "You MUST confirm ALL of the following before adding any target:",
        box=box.DOUBLE,
        border_style="red",
    ))
    console.print()

    checklist = [
        "I own this network OR hold WRITTEN permission from the owner",
        "The permission specifies exact dates and scope of testing",
        "I understand unauthorized access violates CFAA / CMA / IT Act 2000",
        "I will not disrupt other users beyond what is strictly necessary",
        "I will store captured credentials securely and delete them when done",
        "I accept full legal responsibility for my actions during this test",
    ]

    for i, item in enumerate(checklist, 1):
        console.print(f"  [bold cyan]{i}.[/] {item}")

    console.print()
    answer = input("Type exactly  YES I CONFIRM  to proceed: ").strip()
    if answer != "YES I CONFIRM":
        console.print("[red]Aborted — scope.yaml was NOT modified.[/]")
        return

    new_targets: list[dict] = []
    while True:
        console.print()
        bssid = input("Target BSSID (XX:XX:XX:XX:XX:XX) or blank to finish: ").strip().upper()
        if not bssid:
            break
        import re
        if not re.match(r"^([0-9A-F]{2}:){5}[0-9A-F]{2}$", bssid):
            console.print("[red]Invalid BSSID format. Example: AA:BB:CC:DD:EE:FF[/]")
            continue
        ssid          = input("  SSID: ").strip()
        authorized_by = input("  Authorized by (full name): ").strip()
        valid_until   = input("  Valid until (YYYY-MM-DD): ").strip()
        notes         = input("  Notes (e.g. 'Written email from owner dated 2026-06-01'): ").strip()

        new_targets.append({
            "bssid":         bssid,
            "ssid":          ssid,
            "authorized_by": authorized_by,
            "valid_until":   valid_until,
            "notes":         notes,
        })
        console.print(f"  [green]✓ Added {bssid} ({ssid})[/]")

    if not new_targets:
        console.print("[yellow]No targets entered — scope.yaml unchanged.[/]")
        return

    existing: dict = {}
    if DEFAULT_SCOPE_FILE.exists():
        try:
            with open(DEFAULT_SCOPE_FILE) as f:
                existing = yaml.safe_load(f) or {}
        except Exception:
            pass

    existing.setdefault("authorized_targets", []).extend(new_targets)

    with open(DEFAULT_SCOPE_FILE, "w") as f:
        yaml.dump(existing, f, default_flow_style=False, sort_keys=False)

    console.print(f"\n[bold green]✓ scope.yaml updated — {len(new_targets)} target(s) added[/]")
    console.print(f"  Path: {DEFAULT_SCOPE_FILE.resolve()}")
