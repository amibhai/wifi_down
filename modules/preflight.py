"""Pre-flight system checker — verify all dependencies and wireless interfaces."""
from __future__ import annotations

import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from typing import Optional

from rich import box
from rich.console import Console
from rich.table import Table

from .exceptions import DependencyError

console = Console()

MIN_PYTHON = (3, 10)
MIN_AIRCRACK_VERSION = (1, 7)

# (tool_name, version_command, version_regex)
REQUIRED_TOOLS: list[tuple[str, str, str]] = [
    ("airmon-ng",   "airmon-ng --version",    r"(\d+\.\d+[\.\d]*)"),
    ("airodump-ng", "airodump-ng --version",  r"(\d+\.\d+[\.\d]*)"),
    ("aireplay-ng", "aireplay-ng --version",  r"(\d+\.\d+[\.\d]*)"),
    ("aircrack-ng", "aircrack-ng --version",  r"Aircrack-ng\s+(\d+\.\d+[\.\d]*)"),
    ("iw",          "iw --version",           r"iw version (\d+\.\d+)"),
    ("ip",          "ip -V",                  r"iproute2[- ](\d+\.\d+)"),
]

OPTIONAL_TOOLS: list[tuple[str, str, str]] = [
    ("hcxdumptool",   "hcxdumptool --version",   r"(\d+\.\d+[\.\d]*)"),
    ("hcxpcapngtool", "hcxpcapngtool --version", r"(\d+\.\d+[\.\d]*)"),
    ("hashcat",       "hashcat --version",        r"v?(\d+\.\d+[\.\d]*)"),
    ("crunch",        "crunch 2>&1 | head -1",   r"(\d+\.\d+)"),
    ("macchanger",    "macchanger --version",     r"(\d+\.\d+)"),
]


@dataclass
class ToolStatus:
    name: str
    path: Optional[str]
    version: Optional[str]
    ok: bool
    required: bool
    note: str = ""


def _get_version(cmd_str: str, pattern: str) -> Optional[str]:
    try:
        result = subprocess.run(
            cmd_str, shell=True, capture_output=True, text=True, timeout=5
        )
        output = result.stdout + result.stderr
        m = re.search(pattern, output, re.IGNORECASE)
        return m.group(1) if m else "found"
    except Exception:
        return None


def _check_tool(name: str, cmd: str, pattern: str, required: bool) -> ToolStatus:
    path = shutil.which(name)
    if not path:
        return ToolStatus(
            name=name, path=None, version=None, ok=False,
            required=required, note="Not found",
        )

    version = _get_version(cmd, pattern)
    ok = version is not None
    note = ""

    if name == "aircrack-ng" and version and version != "found":
        try:
            parts = tuple(int(x) for x in version.split(".")[:2])
            if parts < MIN_AIRCRACK_VERSION:
                ok = False
                note = f"Requires >= {'.'.join(str(x) for x in MIN_AIRCRACK_VERSION)}"
        except ValueError:
            pass

    return ToolStatus(name=name, path=path, version=version, ok=ok, required=required, note=note)


def _get_wireless_interfaces() -> list[str]:
    try:
        result = subprocess.run(["iw", "dev"], capture_output=True, text=True, timeout=5)
        return re.findall(r"Interface\s+(\w+)", result.stdout)
    except Exception:
        return []


def _check_monitor_mode(iface: str) -> bool:
    try:
        result = subprocess.run(
            ["iw", iface, "info"], capture_output=True, text=True, timeout=5
        )
        return "monitor" in result.stdout.lower()
    except Exception:
        return False


def _check_injection(iface: str) -> bool:
    """Non-disruptive injection test via aireplay-ng --test."""
    if not shutil.which("aireplay-ng"):
        return False
    try:
        result = subprocess.run(
            ["aireplay-ng", "--test", iface],
            capture_output=True, text=True, timeout=10,
        )
        output = result.stdout + result.stderr
        return "injection is working" in output.lower()
    except Exception:
        return False


def _check_proc_net_wireless() -> list[str]:
    try:
        with open("/proc/net/wireless") as f:
            lines = f.readlines()[2:]
        return [line.split(":")[0].strip() for line in lines if ":" in line]
    except Exception:
        return []


def run_preflight(exit_on_failure: bool = True) -> bool:
    """
    Run all pre-flight checks and display rich tables.
    Returns True if all *required* checks pass; exits with code 2 if
    exit_on_failure is True and something is broken.
    """
    console.print()
    console.print("[bold cyan]╔══════════════════════════════════════╗[/]")
    console.print("[bold cyan]║      WiFi Auditor — Pre-Flight       ║[/]")
    console.print("[bold cyan]╚══════════════════════════════════════╝[/]")
    console.print()

    all_pass = True

    # ── Python version ────────────────────────────────────────────────────
    py_ok = sys.version_info >= MIN_PYTHON

    # ── Tool checks ───────────────────────────────────────────────────────
    statuses: list[ToolStatus] = []
    for name, cmd, pattern in REQUIRED_TOOLS:
        s = _check_tool(name, cmd, pattern, required=True)
        statuses.append(s)
        if not s.ok:
            all_pass = False

    for name, cmd, pattern in OPTIONAL_TOOLS:
        statuses.append(_check_tool(name, cmd, pattern, required=False))

    # ── Dependency table ──────────────────────────────────────────────────
    dep_table = Table(
        title="System Dependencies",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold blue",
    )
    dep_table.add_column("Tool", style="bold", width=18)
    dep_table.add_column("Found", justify="center", width=7)
    dep_table.add_column("Version", width=12)
    dep_table.add_column("Req'd", justify="center", width=7)
    dep_table.add_column("Status", width=36)

    py_ver = ".".join(str(x) for x in sys.version_info[:3])
    py_req = ".".join(str(x) for x in MIN_PYTHON)
    dep_table.add_row(
        "python",
        "[green]✓[/]" if py_ok else "[red]✗[/]",
        py_ver,
        "[bold]YES[/]",
        f"[green]OK (>={py_req})[/]" if py_ok else f"[red]Requires >={py_req}[/]",
    )

    for s in statuses:
        found_icon = "[green]✓[/]" if s.path else "[red]✗[/]"
        ver_str = s.version or "—"
        req_str = "[bold]YES[/]" if s.required else "[dim]opt[/]"

        if s.ok:
            status_str = f"[green]OK[/]" + (f"  {s.note}" if s.note else "")
        elif s.required:
            status_str = f"[red]FAIL[/]  {s.note or 'Not found'}"
            all_pass = False
        else:
            status_str = f"[yellow]SKIP[/]  {s.note or 'Optional — install for full features'}"

        dep_table.add_row(s.name, found_icon, ver_str, req_str, status_str.strip())

    console.print(dep_table)
    console.print()

    # ── Wireless interfaces ───────────────────────────────────────────────
    ifaces = _get_wireless_interfaces()
    proc_ifaces = _check_proc_net_wireless()

    iface_table = Table(
        title="Wireless Interfaces",
        box=box.ROUNDED,
        header_style="bold blue",
    )
    iface_table.add_column("Interface", width=15)
    iface_table.add_column("Monitor Mode", justify="center", width=14)
    iface_table.add_column("In /proc/net", justify="center", width=14)
    iface_table.add_column("Injection", justify="center", width=12)

    if ifaces:
        for iface in ifaces:
            mon = _check_monitor_mode(iface)
            in_proc = any(iface in x for x in proc_ifaces) or iface in proc_ifaces
            inject = _check_injection(iface) if mon else False
            iface_table.add_row(
                iface,
                "[green]yes[/]" if mon else "[dim]no[/]",
                "[green]yes[/]" if in_proc else "[dim]no[/]",
                "[green]yes[/]" if inject else "[dim]—[/]",
            )
    else:
        iface_table.add_row("[red]none detected[/]", "—", "—", "—")
        all_pass = False

    console.print(iface_table)

    # ── Result ────────────────────────────────────────────────────────────
    console.print()
    if all_pass:
        console.print("[bold green]✓ All pre-flight checks passed. Ready to audit.[/]")
        return True

    console.print("[bold red]✗ Pre-flight FAILED — fix the issues above before continuing.[/]")
    _print_fix_instructions(statuses)

    if exit_on_failure:
        sys.exit(2)
    return False


def _print_fix_instructions(statuses: list[ToolStatus]) -> None:
    missing = [s for s in statuses if not s.ok and s.required]
    if not missing:
        return
    console.print()
    console.print("[bold yellow]Fix Instructions:[/]")
    names = " ".join(s.name for s in missing)
    console.print(f"  [cyan]Kali / Parrot / Ubuntu:[/]  sudo apt install aircrack-ng {names}")
    console.print(f"  [cyan]Arch:[/]                     sudo pacman -S aircrack-ng {names}")
    console.print(f"  [cyan]Fedora:[/]                   sudo dnf install aircrack-ng {names}")
    console.print()
    console.print("  Or run the install script:  [bold]sudo ./install.sh[/]")
