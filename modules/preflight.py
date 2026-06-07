"""Pre-flight system checker — verify all dependencies and wireless interfaces."""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from rich import box
from rich.console import Console
from rich.table import Table

from .exceptions import DependencyError

console = Console()

MIN_PYTHON = (3, 10)
MIN_AIRCRACK_VERSION = (1, 7)

SENTINEL_FILE = Path.home() / ".wifi-auditor" / ".preflight_done"

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
    # WPS tools (added for wps.py module)
    ("reaver",        "reaver --version 2>&1 | head -2", r"(\d+\.\d+[\.\d]*)"),
    ("wash",          "wash --version 2>&1 | head -2",   r"(\d+\.\d+[\.\d]*)"),
    ("bully",         "bully 2>&1 | head -2",            r"(\d+\.\d+[\.\d]*)"),
    # Offline cracking extras
    ("cowpatty",      "cowpatty 2>&1 | head -2",         r"(\d+\.\d+[\.\d]*)"),
]

# Package name per tool per package manager.
# wash ships inside the reaver package on most distros.
TOOL_PACKAGES: dict[str, dict[str, Optional[str]]] = {
    "airmon-ng":     {"apt": "aircrack-ng",  "pacman": "aircrack-ng",  "dnf": "aircrack-ng"},
    "airodump-ng":   {"apt": "aircrack-ng",  "pacman": "aircrack-ng",  "dnf": "aircrack-ng"},
    "aireplay-ng":   {"apt": "aircrack-ng",  "pacman": "aircrack-ng",  "dnf": "aircrack-ng"},
    "aircrack-ng":   {"apt": "aircrack-ng",  "pacman": "aircrack-ng",  "dnf": "aircrack-ng"},
    "iw":            {"apt": "iw",           "pacman": "iw",           "dnf": "iw"},
    "ip":            {"apt": "iproute2",     "pacman": "iproute2",     "dnf": "iproute"},
    "hcxdumptool":   {"apt": "hcxdumptool",  "pacman": "hcxdumptool",  "dnf": None},
    "hcxpcapngtool": {"apt": "hcxtools",     "pacman": "hcxtools",     "dnf": None},
    "hashcat":       {"apt": "hashcat",      "pacman": "hashcat",      "dnf": "hashcat"},
    "crunch":        {"apt": "crunch",       "pacman": "crunch",       "dnf": "crunch"},
    "macchanger":    {"apt": "macchanger",   "pacman": "macchanger",   "dnf": "macchanger"},
    "reaver":        {"apt": "reaver",       "pacman": "reaver",       "dnf": None},
    "wash":          {"apt": "reaver",       "pacman": "reaver",       "dnf": None},
    "bully":         {"apt": "bully",        "pacman": "bully",        "dnf": None},
    "cowpatty":      {"apt": "cowpatty",     "pacman": "cowpatty",     "dnf": None},
}


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


###############################################################################
# Package manager detection + auto-install
###############################################################################

def detect_package_manager() -> str:
    """Return the first available package manager: apt-get, pacman, or dnf."""
    for pm in ("apt-get", "pacman", "dnf", "yum"):
        if shutil.which(pm):
            return pm
    return ""


def _pm_key(pm: str) -> str:
    """Map package manager binary to TOOL_PACKAGES key."""
    if pm in ("apt-get", "apt"):
        return "apt"
    if pm == "pacman":
        return "pacman"
    if pm in ("dnf", "yum"):
        return "dnf"
    return ""


def auto_install_missing(statuses: list[ToolStatus]) -> list[str]:
    """
    Attempt to install every missing tool (required + optional) using the
    system package manager.  Must be run as root.

    Returns a list of package names that were successfully installed.
    """
    if os.geteuid() != 0:
        console.print(
            "[yellow]  Auto-install skipped — not running as root. "
            "Re-run with sudo to install missing packages.[/]"
        )
        return []

    pm = detect_package_manager()
    if not pm:
        console.print("[yellow]  No supported package manager found (apt/pacman/dnf).[/]")
        return []

    pm_key = _pm_key(pm)

    # Collect unique packages needed (multiple tools can map to the same package)
    pkgs_to_install: dict[str, list[str]] = {}   # pkg_name → [tool_names]
    for s in statuses:
        if s.ok:
            continue
        pkg = TOOL_PACKAGES.get(s.name, {}).get(pm_key)
        if pkg:
            pkgs_to_install.setdefault(pkg, []).append(s.name)

    if not pkgs_to_install:
        console.print("[dim]  No installable packages found for missing tools.[/]")
        return []

    installed: list[str] = []

    for pkg, tools in pkgs_to_install.items():
        tool_list = ", ".join(tools)
        console.print(f"  [cyan]Installing[/] [bold]{pkg}[/] (provides: {tool_list}) ...")
        try:
            if pm == "apt-get":
                cmd = ["apt-get", "install", "-y", "--no-install-recommends", pkg]
            elif pm == "pacman":
                cmd = ["pacman", "-S", "--noconfirm", "--needed", pkg]
            elif pm in ("dnf", "yum"):
                cmd = [pm, "install", "-y", pkg]
            else:
                continue

            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=120
            )
            if result.returncode == 0:
                console.print(f"    [green]OK[/] {pkg}")
                installed.append(pkg)
            else:
                stderr = result.stderr.strip()[:120]
                console.print(f"    [yellow]WARN[/] {pkg}: {stderr}")
        except subprocess.TimeoutExpired:
            console.print(f"    [red]TIMEOUT[/] installing {pkg}")
        except Exception as exc:
            console.print(f"    [red]ERROR[/] {pkg}: {exc}")

    return installed


###############################################################################
# Core preflight runner
###############################################################################

def run_preflight(exit_on_failure: bool = True) -> tuple[bool, list[ToolStatus]]:
    """
    Run all pre-flight checks and display rich tables.

    Returns (all_required_pass, statuses).
    Exits with code 2 if exit_on_failure=True and a required check fails.
    """
    console.print()
    console.print("[bold cyan]╔══════════════════════════════════════╗[/]")
    console.print("[bold cyan]║      WiFi Auditor -- Pre-Flight      ║[/]")
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
    dep_table.add_column("Tool",    style="bold", width=18)
    dep_table.add_column("Found",   justify="center", width=7)
    dep_table.add_column("Version", width=12)
    dep_table.add_column("Req'd",   justify="center", width=7)
    dep_table.add_column("Status",  width=38)

    py_ver = ".".join(str(x) for x in sys.version_info[:3])
    py_req = ".".join(str(x) for x in MIN_PYTHON)
    dep_table.add_row(
        "python",
        "[green]OK[/]" if py_ok else "[red]FAIL[/]",
        py_ver,
        "[bold]YES[/]",
        f"[green]OK (>={py_req})[/]" if py_ok else f"[red]Requires >={py_req}[/]",
    )

    for s in statuses:
        found_icon = "[green]OK[/]"  if s.path  else "[red]--[/]"
        ver_str    = s.version or "--"
        req_str    = "[bold]YES[/]" if s.required else "[dim]opt[/]"

        if s.ok:
            status_str = "[green]OK[/]" + (f"  {s.note}" if s.note else "")
        elif s.required:
            status_str = f"[red]FAIL[/]  {s.note or 'Not found'}"
            all_pass = False
        else:
            status_str = f"[yellow]SKIP[/]  {s.note or 'Optional — install for full features'}"

        dep_table.add_row(s.name, found_icon, ver_str, req_str, status_str.strip())

    console.print(dep_table)
    console.print()

    # ── Wireless interfaces ───────────────────────────────────────────────
    ifaces      = _get_wireless_interfaces()
    proc_ifaces = _check_proc_net_wireless()

    iface_table = Table(
        title="Wireless Interfaces",
        box=box.ROUNDED,
        header_style="bold blue",
    )
    iface_table.add_column("Interface",   width=15)
    iface_table.add_column("Monitor Mode", justify="center", width=14)
    iface_table.add_column("In /proc/net", justify="center", width=14)
    iface_table.add_column("Injection",    justify="center", width=12)

    if ifaces:
        for iface in ifaces:
            mon      = _check_monitor_mode(iface)
            in_proc  = any(iface in x for x in proc_ifaces) or iface in proc_ifaces
            inject   = _check_injection(iface) if mon else False
            iface_table.add_row(
                iface,
                "[green]yes[/]" if mon  else "[dim]no[/]",
                "[green]yes[/]" if in_proc else "[dim]no[/]",
                "[green]yes[/]" if inject else "[dim]--[/]",
            )
    else:
        iface_table.add_row("[red]none detected[/]", "--", "--", "--")
        all_pass = False

    console.print(iface_table)

    # ── Summary ───────────────────────────────────────────────────────────
    console.print()
    if all_pass:
        console.print("[bold green]All pre-flight checks passed. Ready to audit.[/]")
    else:
        console.print("[bold red]Pre-flight FAILED -- fix the issues above before continuing.[/]")
        _print_fix_instructions(statuses)
        if exit_on_failure:
            sys.exit(2)

    return all_pass, statuses


###############################################################################
# Auto-fix entry point
###############################################################################

def run_preflight_with_autofix() -> bool:
    """
    Run preflight, auto-install any missing tools, then re-run to confirm.
    Writes the sentinel file on success so the auto-check is not repeated.

    Returns True if all required checks pass after the fix attempt.
    """
    console.print()
    console.print(
        "[bold cyan]First-time setup: running pre-flight check and "
        "auto-installing missing tools...[/]"
    )
    console.print()

    # ── First pass ────────────────────────────────────────────────────────
    all_pass, statuses = run_preflight(exit_on_failure=False)

    # ── Auto-install missing ──────────────────────────────────────────────
    missing = [s for s in statuses if not s.ok]
    if missing:
        missing_names = ", ".join(s.name for s in missing)
        console.print(
            f"\n[yellow]  {len(missing)} tool(s) missing:[/] {missing_names}"
        )
        console.print("[cyan]  Attempting auto-install...[/]\n")

        installed = auto_install_missing(statuses)

        if installed:
            console.print(
                f"\n[green]  Installed {len(installed)} package(s):[/] "
                f"{', '.join(installed)}"
            )
            console.print("\n[cyan]  Re-running pre-flight check...[/]\n")
            all_pass, statuses = run_preflight(exit_on_failure=False)
        else:
            console.print(
                "\n[yellow]  No packages could be auto-installed. "
                "Install missing tools manually and re-run --preflight.[/]"
            )
    else:
        console.print("[green]  All tools already present — nothing to install.[/]")

    # ── Write sentinel so this auto-check is not repeated ─────────────────
    SENTINEL_FILE.parent.mkdir(parents=True, exist_ok=True)
    SENTINEL_FILE.touch()
    console.print(
        f"\n[dim]  Sentinel written: {SENTINEL_FILE}[/]"
        "\n[dim]  Future starts skip this auto-check. "
        "Run [bold]wifi-auditor --preflight[/dim] at any time to re-check.[/]\n"
    )

    return all_pass


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
    console.print("  Or re-run the install script:  [bold]sudo ./install.sh[/]")
