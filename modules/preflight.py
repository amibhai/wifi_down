"""
Pre-flight system checker — verify all dependencies and wireless interfaces.
First-run experience with interactive dependency installer.
Rerunnable via: wifi-auditor --preflight
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from importlib import import_module
from pathlib import Path
from typing import Optional

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.table import Table

from .exceptions import DependencyError

console = Console()

MIN_PYTHON          = (3, 10)
MIN_AIRCRACK_VERSION = (1, 7)

SENTINEL_FILE = Path.home() / ".wifi-auditor" / ".preflight_done"

# ─── Tool definitions ─────────────────────────────────────────────────────────

# (tool_name, version_command, version_regex, category, install_hint)
REQUIRED_TOOLS: list[tuple[str, str, str, str, str]] = [
    ("airmon-ng",   "airmon-ng --version",   r"(\d+\.\d+[\.\d]*)", "wireless", "aircrack-ng"),
    ("airodump-ng", "airodump-ng --version", r"(\d+\.\d+[\.\d]*)", "wireless", "aircrack-ng"),
    ("aireplay-ng", "aireplay-ng --version", r"(\d+\.\d+[\.\d]*)", "wireless", "aircrack-ng"),
    ("aircrack-ng", "aircrack-ng --version", r"Aircrack-ng\s+(\d+\.\d+[\.\d]*)", "wireless", "aircrack-ng"),
    ("iw",          "iw --version",          r"iw version (\d+\.\d+)",            "wireless", "iw"),
    ("ip",          "ip -V",                 r"iproute2[- ](\d+\.\d+)",           "system",   "iproute2"),
]

OPTIONAL_TOOLS: list[tuple[str, str, str, str, str]] = [
    ("hcxdumptool",  "hcxdumptool --version",   r"(\d+\.\d+[\.\d]*)", "capture",  "hcxdumptool"),
    ("hcxpcapngtool","hcxpcapngtool --version",  r"(\d+\.\d+[\.\d]*)", "capture",  "hcxtools"),
    ("hashcat",      "hashcat --version",         r"v?(\d+\.\d+[\.\d]*)", "cracking","hashcat"),
    ("crunch",       "crunch 2>&1 | head -1",    r"(\d+\.\d+)",          "wordlist", "crunch"),
    ("macchanger",   "macchanger --version",      r"(\d+\.\d+)",          "misc",     "macchanger"),
    ("reaver",       "reaver --version 2>&1 | head -2", r"(\d+\.\d+[\.\d]*)", "wps", "reaver"),
    ("wash",         "wash --version 2>&1 | head -2",   r"(\d+\.\d+[\.\d]*)", "wps", "reaver"),
    ("bully",        "bully 2>&1 | head -2",            r"(\d+\.\d+[\.\d]*)", "wps", "bully"),
    ("cowpatty",     "cowpatty 2>&1 | head -2",         r"(\d+\.\d+[\.\d]*)", "cracking","cowpatty"),
    # Gap-closer features
    ("hostapd",      "hostapd -v 2>&1 | head -1", r"hostapd v?(\d+\.\d+[\.\d]*)", "phantom",   "hostapd"),
    ("dnsmasq",      "dnsmasq --version 2>&1 | head -1", r"Dnsmasq version (\d+\.\d+)", "phantom","dnsmasq"),
    ("bettercap",    "bettercap --version 2>&1",  r"v?(\d+\.\d+[\.\d]*)",           "intercept","bettercap"),
    ("curl",         "curl --version 2>&1 | head -1", r"curl (\d+\.\d+[\.\d]*)",    "misc",     "curl"),
    ("nginx",        "nginx -v 2>&1",             r"nginx/(\d+\.\d+[\.\d]*)",        "phantom",  "nginx"),
]

# Python package requirements: (import_name, pip_name, category)
PIP_PACKAGES: list[tuple[str, str, str]] = [
    ("reportlab",  "reportlab",  "report"),
    ("weasyprint", "weasyprint", "report"),
    ("textual",    "textual",    "prism_tui"),
    ("httpx",      "httpx",      "intelligence"),
    ("fastapi",    "fastapi",    "api"),
    ("uvicorn",    "uvicorn",    "api"),
    ("openai",     "openai",     "neural"),
]

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
    "hostapd":       {"apt": "hostapd",      "pacman": "hostapd",      "dnf": "hostapd"},
    "dnsmasq":       {"apt": "dnsmasq",      "pacman": "dnsmasq",      "dnf": "dnsmasq"},
    "bettercap":     {"apt": "bettercap",    "pacman": "bettercap",    "dnf": None},
    "curl":          {"apt": "curl",         "pacman": "curl",         "dnf": "curl"},
    "nginx":         {"apt": "nginx",        "pacman": "nginx",        "dnf": "nginx"},
}

# Features blocked when optional tools are missing
FEATURE_MAP: dict[str, list[str]] = {
    "hostapd":      ["Phantom AP"],
    "dnsmasq":      ["Phantom AP captive portal DNS"],
    "bettercap":    ["Signal Intercept"],
    "nginx":        ["Phantom AP portal (fallback)"],
    "hcxdumptool":  ["PMKID capture"],
    "hcxpcapngtool":["PMKID conversion"],
    "hashcat":      ["GPU-accelerated cracking"],
    "reaver":       ["WPS Pixie-Dust + PIN spray"],
    "cowpatty":     ["Cowpatty offline cracking"],
}


@dataclass
class ToolStatus:
    name: str
    path: Optional[str]
    version: Optional[str]
    ok: bool
    required: bool
    category: str
    install_hint: str
    note: str = ""


@dataclass
class PipStatus:
    import_name: str
    pip_name: str
    category: str
    ok: bool
    version: Optional[str] = None


# ─── Detection helpers ────────────────────────────────────────────────────────

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


def _check_tool(name: str, cmd: str, pattern: str, required: bool,
                category: str, hint: str) -> ToolStatus:
    path = shutil.which(name)
    if not path:
        return ToolStatus(name=name, path=None, version=None, ok=False,
                          required=required, category=category,
                          install_hint=hint, note="Not found")
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
    return ToolStatus(name=name, path=path, version=version, ok=ok,
                      required=required, category=category,
                      install_hint=hint, note=note)


def _check_pip(import_name: str, pip_name: str, category: str) -> PipStatus:
    try:
        mod = import_module(import_name)
        ver = getattr(mod, "__version__", None) or getattr(mod, "VERSION", "found")
        return PipStatus(import_name=import_name, pip_name=pip_name,
                         category=category, ok=True, version=str(ver))
    except ImportError:
        return PipStatus(import_name=import_name, pip_name=pip_name,
                         category=category, ok=False)


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


# ─── Package manager detection ───────────────────────────────────────────────

def detect_package_manager() -> str:
    for pm in ("apt-get", "pacman", "dnf", "yum"):
        if shutil.which(pm):
            return pm
    return ""


def _pm_key(pm: str) -> str:
    if pm in ("apt-get", "apt"):
        return "apt"
    if pm == "pacman":
        return "pacman"
    if pm in ("dnf", "yum"):
        return "dnf"
    return ""


# ─── Interactive install ──────────────────────────────────────────────────────

def _install_system_packages(pkg_names: list[str], pm: str) -> dict[str, bool]:
    """Install system packages and return {pkg_name: success}."""
    results: dict[str, bool] = {}
    pm_key = _pm_key(pm)
    if not pm_key:
        return {}

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        console=console,
        transient=True,
    ) as prog:
        task = prog.add_task("Installing...", total=len(pkg_names))
        for pkg in pkg_names:
            prog.update(task, description=f"Installing [cyan]{pkg}[/cyan]...")
            if pm == "apt-get":
                cmd = ["apt-get", "install", "-y", "--no-install-recommends", pkg]
            elif pm == "pacman":
                cmd = ["pacman", "-S", "--noconfirm", "--needed", pkg]
            else:
                cmd = [pm, "install", "-y", pkg]
            try:
                r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
                results[pkg] = r.returncode == 0
                if not results[pkg]:
                    console.print(f"  [yellow]WARN[/] {pkg}: {(r.stderr or '').strip()[:80]}")
            except Exception as exc:
                results[pkg] = False
                console.print(f"  [red]ERROR[/] {pkg}: {exc}")
            prog.advance(task)
    return results


def _install_pip_packages(pip_names: list[str]) -> dict[str, bool]:
    """Install Python packages via pip and return {pkg_name: success}."""
    results: dict[str, bool] = {}
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        console=console,
        transient=True,
    ) as prog:
        task = prog.add_task("pip install...", total=len(pip_names))
        for pkg in pip_names:
            prog.update(task, description=f"pip install [cyan]{pkg}[/cyan]...")
            try:
                r = subprocess.run(
                    [sys.executable, "-m", "pip", "install", "-q", pkg],
                    capture_output=True, text=True, timeout=120,
                )
                results[pkg] = r.returncode == 0
                if not results[pkg]:
                    console.print(f"  [yellow]WARN[/] pip {pkg}: {(r.stderr or '').strip()[:80]}")
            except Exception as exc:
                results[pkg] = False
                console.print(f"  [red]ERROR[/] pip {pkg}: {exc}")
            prog.advance(task)
    return results


def _prompt_install(group_label: str, tool_names: list[str]) -> bool:
    """Prompt user to install a group of tools. Returns True if user said yes."""
    console.print(
        f"\n  [bold yellow]{group_label}:[/bold yellow] "
        + ", ".join(f"[cyan]{n}[/cyan]" for n in tool_names)
    )
    try:
        ans = input("  Install them now? [Y/n]: ").strip().lower()
    except (KeyboardInterrupt, EOFError):
        return False
    return ans in ("", "y", "yes")


# ─── Display table ────────────────────────────────────────────────────────────

def _build_tool_table(statuses: list[ToolStatus], pip_statuses: list[PipStatus]) -> Table:
    t = Table(
        title="System Dependencies — wifi_down",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold #00D4AA",
        border_style="dim cyan",
    )
    t.add_column("Tool",       style="bold", width=18)
    t.add_column("Status",     justify="center", width=8)
    t.add_column("Version",    width=12)
    t.add_column("Category",   width=12)
    t.add_column("Install cmd", width=28)

    py_ok  = sys.version_info >= MIN_PYTHON
    py_ver = ".".join(str(x) for x in sys.version_info[:3])
    t.add_row(
        "python",
        "[green]✓[/]" if py_ok else "[red]✗[/]",
        py_ver,
        "runtime",
        f"requires >= {'.'.join(str(x) for x in MIN_PYTHON)}",
    )

    for s in statuses:
        if s.ok:
            status_icon = "[green]✓[/]"
            inst_hint   = "[dim]installed[/dim]"
        elif s.required:
            status_icon = "[red]✗[/]"
            inst_hint   = f"[red]apt install {s.install_hint}[/red]"
        else:
            status_icon = "[yellow]–[/]"
            inst_hint   = f"[dim]apt install {s.install_hint}[/dim]"

        t.add_row(
            s.name,
            status_icon,
            s.version or "[dim]–[/]",
            f"[dim]{s.category}[/dim]",
            inst_hint,
        )

    # Pip packages
    t.add_section()
    for p in pip_statuses:
        if p.ok:
            icon  = "[green]✓[/]"
            hint  = "[dim]installed[/dim]"
            ver   = p.version or "found"
        else:
            icon  = "[yellow]–[/]"
            hint  = f"[dim]pip install {p.pip_name}[/dim]"
            ver   = "[dim]–[/]"
        t.add_row(p.import_name, icon, ver, f"[dim]{p.category}[/dim]", hint)

    return t


# ─── Core preflight runner ────────────────────────────────────────────────────

def run_preflight(exit_on_failure: bool = True) -> tuple[bool, list[ToolStatus]]:
    """
    Run all pre-flight checks and display rich tables.
    Returns (all_required_pass, statuses).
    """
    console.print()
    console.print(Panel.fit(
        "[bold #00D4AA]wifi_down — Pre-Flight System Check[/bold #00D4AA]",
        border_style="#00D4AA",
        padding=(0, 4),
    ))
    console.print()

    all_pass = sys.version_info >= MIN_PYTHON

    statuses: list[ToolStatus] = []
    for name, cmd, pattern, cat, hint in REQUIRED_TOOLS:
        s = _check_tool(name, cmd, pattern, required=True, category=cat, hint=hint)
        statuses.append(s)
        if not s.ok:
            all_pass = False

    for name, cmd, pattern, cat, hint in OPTIONAL_TOOLS:
        statuses.append(_check_tool(name, cmd, pattern, required=False, category=cat, hint=hint))

    pip_statuses = [_check_pip(imp, pip, cat) for imp, pip, cat in PIP_PACKAGES]

    console.print(_build_tool_table(statuses, pip_statuses))
    console.print()

    # Wireless interface table
    ifaces = _get_wireless_interfaces()
    iface_table = Table(
        title="Wireless Interfaces",
        box=box.ROUNDED,
        header_style="bold #00D4AA",
        border_style="dim cyan",
    )
    iface_table.add_column("Interface",    width=15)
    iface_table.add_column("Monitor Mode", justify="center", width=14)

    if ifaces:
        for iface in ifaces:
            mon = _check_monitor_mode(iface)
            iface_table.add_row(
                iface,
                "[green]yes[/]" if mon else "[dim]no[/]",
            )
    else:
        iface_table.add_row("[red]none detected[/]", "--")
        all_pass = False

    console.print(iface_table)
    console.print()

    # Feature availability summary
    blocked: list[tuple[str, str]] = []
    for s in statuses:
        if not s.ok and s.name in FEATURE_MAP:
            for feat in FEATURE_MAP[s.name]:
                blocked.append((feat, s.name))

    if blocked:
        console.print("[dim]Features unavailable due to missing optional tools:[/dim]")
        for feat, tool in blocked:
            console.print(f"  [yellow]•[/yellow] [dim]{feat}[/dim]  [dim](requires {tool})[/dim]")
        console.print()

    if all_pass:
        console.print("[bold green]✓ All required checks passed. Ready to audit.[/bold green]")
    else:
        console.print("[bold red]✗ Pre-flight FAILED — fix the issues above before continuing.[/bold red]")
        if exit_on_failure:
            sys.exit(2)

    return all_pass, statuses


# ─── Interactive first-run installer ─────────────────────────────────────────

def run_preflight_with_autofix() -> bool:
    """
    Full interactive first-run experience:
    1. Scan everything.
    2. Show table.
    3. Group missing into REQUIRED / OPTIONAL and prompt install each group.
    4. Re-verify and update table.
    5. Write sentinel on success.
    """
    console.print()
    console.print(Panel.fit(
        "[bold #00D4AA]wifi_down — First-Run Setup[/bold #00D4AA]\n"
        "[dim]Scanning system and installing missing dependencies...[/dim]",
        border_style="#00D4AA",
        padding=(0, 4),
    ))
    console.print()

    # First pass
    all_pass, statuses = run_preflight(exit_on_failure=False)
    pip_statuses = [_check_pip(imp, pip, cat) for imp, pip, cat in PIP_PACKAGES]

    pm = detect_package_manager()
    pm_key = _pm_key(pm)

    # ── Required system tools ─────────────────────────────────────────────
    missing_required = [s for s in statuses if not s.ok and s.required]
    if missing_required:
        pkg_map: dict[str, list[str]] = {}
        for s in missing_required:
            pkg = TOOL_PACKAGES.get(s.name, {}).get(pm_key) if pm_key else None
            if pkg:
                pkg_map.setdefault(pkg, []).append(s.name)

        if pkg_map and _prompt_install(
            "REQUIRED tools missing (tool will not function without these)",
            [s.name for s in missing_required],
        ):
            if os.geteuid() != 0:
                console.print("[yellow]  Not running as root — cannot install system packages.[/]")
            else:
                _install_system_packages(list(pkg_map.keys()), pm)

    # ── Optional system tools ─────────────────────────────────────────────
    missing_optional = [s for s in statuses if not s.ok and not s.required]
    if missing_optional:
        pkg_map_opt: dict[str, list[str]] = {}
        for s in missing_optional:
            pkg = TOOL_PACKAGES.get(s.name, {}).get(pm_key) if pm_key else None
            if pkg:
                pkg_map_opt.setdefault(pkg, []).append(s.name)

        if pkg_map_opt and _prompt_install(
            "OPTIONAL tools missing (features will be limited)",
            [s.name for s in missing_optional],
        ):
            if os.geteuid() != 0:
                console.print("[yellow]  Not running as root — cannot install system packages.[/]")
            else:
                _install_system_packages(list(pkg_map_opt.keys()), pm)
        else:
            _report_skipped_features(missing_optional)

    # ── Pip packages ──────────────────────────────────────────────────────
    missing_pip = [p for p in pip_statuses if not p.ok]
    if missing_pip:
        if _prompt_install(
            "Python packages missing (leapfrog features require these)",
            [p.pip_name for p in missing_pip],
        ):
            _install_pip_packages([p.pip_name for p in missing_pip])

    # ── Re-verify ─────────────────────────────────────────────────────────
    if missing_required or missing_optional or missing_pip:
        console.print("\n[cyan]Re-running verification...[/cyan]\n")
        all_pass, _ = run_preflight(exit_on_failure=False)
    else:
        console.print("[green]  All tools already present — nothing to install.[/green]")

    # ── Write sentinel ─────────────────────────────────────────────────────
    SENTINEL_FILE.parent.mkdir(parents=True, exist_ok=True)
    SENTINEL_FILE.touch()
    console.print(
        f"\n[dim]  Sentinel written: {SENTINEL_FILE}[/dim]"
        "\n[dim]  Future starts skip this check. "
        "Run [bold]wifi-auditor --preflight[/bold] to re-check anytime.[/dim]\n"
    )
    return all_pass


def _report_skipped_features(missing: list[ToolStatus]) -> None:
    names = [s.name for s in missing]
    for name in names:
        if name in FEATURE_MAP:
            for feat in FEATURE_MAP[name]:
                console.print(f"  [dim]→ {feat} unavailable (skipped {name})[/dim]")


def auto_install_missing(statuses: list[ToolStatus]) -> list[str]:
    """Legacy compatibility: install all missing tools non-interactively."""
    if os.geteuid() != 0:
        console.print("[yellow]  Auto-install skipped — not running as root.[/]")
        return []
    pm = detect_package_manager()
    if not pm:
        return []
    pm_key = _pm_key(pm)
    pkg_map: dict[str, list[str]] = {}
    for s in statuses:
        if s.ok:
            continue
        pkg = TOOL_PACKAGES.get(s.name, {}).get(pm_key)
        if pkg:
            pkg_map.setdefault(pkg, []).append(s.name)
    if not pkg_map:
        return []
    results = _install_system_packages(list(pkg_map.keys()), pm)
    return [pkg for pkg, ok in results.items() if ok]
