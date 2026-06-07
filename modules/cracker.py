#!/usr/bin/env python3
"""
Cracking module: aircrack-ng, cowpatty, and hashcat (dict + rule-based).

Backend matrix
──────────────
Capture type  │ aircrack-ng │ cowpatty │ hashcat dict │ hashcat rules
──────────────┼─────────────┼──────────┼──────────────┼──────────────
.cap (WPA HS) │      ✓      │    ✓     │  ✓ (convert) │  ✓ (convert)
:pmkid        │   fallback  │    —     │      ✓       │      ✓
"""

import os
import re
import shutil
import subprocess
import time
from datetime import datetime
from modules.banner import C, info, success, warn, error, found, print_section

RESULTS_DIR = "results"
os.makedirs(RESULTS_DIR, exist_ok=True)

# Hashcat rule search paths (ordered by preference)
_RULE_SEARCH_PATHS = [
    "/usr/share/hashcat/rules",
    "/usr/local/share/hashcat/rules",
    "/opt/hashcat/rules",
    "rules",
]


###############################################################################
# Public entry point
###############################################################################

def cracker_menu(capture_file: str, wordlist_file: str, ssid: str = "") -> None:
    print_section("Handshake Cracker")

    # ── PMKID path ────────────────────────────────────────────────────────────
    if capture_file.endswith(":pmkid"):
        hash_file = capture_file.replace(":pmkid", "")
        _crack_pmkid_menu(hash_file, wordlist_file)
        return

    # ── WPA handshake path ────────────────────────────────────────────────────
    if not os.path.exists(capture_file):
        error(f"Capture file not found: {capture_file}")
        return
    if not os.path.exists(wordlist_file):
        error(f"Wordlist not found: {wordlist_file}")
        return

    info(f"Capture  : {capture_file}")
    info(f"Wordlist : {wordlist_file}")
    if ssid:
        info(f"SSID     : {ssid}")
    wl_size = _count_lines(wordlist_file)
    info(f"Wordlist : {wl_size:,} entries")

    info("Verifying capture file...")
    if not _has_handshake(capture_file):
        warn("aircrack-ng did not detect a complete 4-way handshake.")
        c = input(f"  {C.YELLOW}Continue anyway? [y/N]: {C.RESET}").strip().lower()
        if c != "y":
            return

    has_cowpatty = shutil.which("cowpatty") is not None
    has_hashcat  = shutil.which("hashcat")  is not None

    print(f"""
  {C.WHITE}Cracking Backend:{C.RESET}
  {C.GREEN}[1]{C.RESET} aircrack-ng   {C.DIM}– fast dict attack, GPU optional{C.RESET}
  {C.GREEN}[2]{C.RESET} cowpatty      {C.DIM}– PMK-cache optimised, needs SSID{"" if ssid else f"  {C.RED}(no SSID set){C.RESET}"}{C.RESET}{"" if has_cowpatty else f"  {C.RED}[not installed]{C.RESET}"}
  {C.GREEN}[3]{C.RESET} hashcat dict  {C.DIM}– GPU-accelerated, converts .cap → hc22000{"" if has_hashcat else f"  {C.RED}[not installed]{C.RESET}"}{C.RESET}
  {C.GREEN}[4]{C.RESET} hashcat rules {C.DIM}– dict + rule mutations (best64, d3ad0ne){"" if has_hashcat else f"  {C.RED}[not installed]{C.RESET}"}{C.RESET}
""")

    choice = input(f"  {C.YELLOW}Backend [1]: {C.RESET}").strip() or "1"

    if choice == "1":
        print()
        info("Starting aircrack-ng...")
        info(f"  {C.DIM}Press Ctrl+C to abort.{C.RESET}")
        print()
        _run_aircrack(capture_file, wordlist_file)
    elif choice == "2":
        if not has_cowpatty:
            error("cowpatty not found. Install: sudo apt install cowpatty")
            return
        if not ssid:
            ssid = input(f"  {C.YELLOW}SSID (required for cowpatty): {C.RESET}").strip()
            if not ssid:
                error("SSID is required for cowpatty.")
                return
        _run_cowpatty(capture_file, wordlist_file, ssid)
    elif choice == "3":
        if not has_hashcat:
            error("hashcat not found. Install: sudo apt install hashcat")
            return
        hc_file = _convert_cap_to_hc22000(capture_file)
        if hc_file:
            _run_hashcat(hc_file, wordlist_file, rules=None)
        else:
            warn("Conversion failed — falling back to aircrack-ng.")
            _run_aircrack(capture_file, wordlist_file)
    elif choice == "4":
        if not has_hashcat:
            error("hashcat not found. Install: sudo apt install hashcat")
            return
        rule = _pick_rule_file()
        hc_file = _convert_cap_to_hc22000(capture_file)
        if hc_file:
            _run_hashcat(hc_file, wordlist_file, rules=rule)
        else:
            warn("Conversion failed — falling back to aircrack-ng.")
            _run_aircrack(capture_file, wordlist_file)
    else:
        error(f"Unknown option: {choice!r}")


###############################################################################
# PMKID menu  (hash already in hashcat 22000 format)
###############################################################################

def _crack_pmkid_menu(hash_file: str, wordlist_file: str) -> None:
    if not os.path.exists(hash_file):
        error(f"PMKID hash file not found: {hash_file}")
        return

    has_hashcat = shutil.which("hashcat") is not None
    info(f"PMKID hash : {hash_file}")
    info(f"Wordlist   : {wordlist_file}")

    print(f"""
  {C.WHITE}PMKID Cracking Backend:{C.RESET}
  {C.GREEN}[1]{C.RESET} hashcat dict  {C.DIM}– GPU-accelerated dictionary (mode 22000){"" if has_hashcat else f"  {C.RED}[not installed]{C.RESET}"}{C.RESET}
  {C.GREEN}[2]{C.RESET} hashcat rules {C.DIM}– dict + rule mutations (best64, d3ad0ne){"" if has_hashcat else f"  {C.RED}[not installed]{C.RESET}"}{C.RESET}
  {C.GREEN}[3]{C.RESET} aircrack-ng   {C.DIM}– CPU fallback{C.RESET}
""")

    choice = input(f"  {C.YELLOW}Backend [1]: {C.RESET}").strip() or "1"

    if choice == "1":
        if not has_hashcat:
            error("hashcat not found — falling back to aircrack-ng.")
            _run_aircrack(hash_file, wordlist_file)
            return
        _run_hashcat(hash_file, wordlist_file, rules=None)
    elif choice == "2":
        if not has_hashcat:
            error("hashcat not found.")
            return
        rule = _pick_rule_file()
        _run_hashcat(hash_file, wordlist_file, rules=rule)
    elif choice == "3":
        _run_aircrack(hash_file, wordlist_file)
    else:
        error(f"Unknown option: {choice!r}")


###############################################################################
# Backend: aircrack-ng
###############################################################################

def _run_aircrack(capture_file: str, wordlist_file: str) -> None:
    cmd = ["aircrack-ng", "-w", wordlist_file, capture_file]
    start = time.time()
    output_lines: list[str] = []

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        for line in proc.stdout:
            line = line.rstrip()
            output_lines.append(line)
            _print_aircrack_line(line)
        proc.wait()
    except KeyboardInterrupt:
        proc.terminate()
        proc.wait()
        warn("Cracking aborted by user.")
        return

    elapsed = time.time() - start
    key = _parse_key_aircrack("\n".join(output_lines))
    print()
    if key:
        found(f"KEY FOUND!  →  {key}")
        _save_result(capture_file, wordlist_file, key, elapsed, "aircrack-ng")
    else:
        error(f"Key NOT found in this wordlist. ({elapsed:.0f}s elapsed)")
        info("Try a larger wordlist, hashcat rules, or a targeted mutation approach.")


def _print_aircrack_line(line: str) -> None:
    if "KEY FOUND" in line.upper():
        print(f"  {C.BOLD}{C.GREEN}{line}{C.RESET}")
    elif "FAILED" in line.upper() or "not in dictionary" in line.lower():
        print(f"  {C.RED}{line}{C.RESET}")
    elif re.search(r"\d+\.\d+ k/s", line):
        print(f"  \r{C.DIM}{line}{C.RESET}", end="", flush=True)
    elif line.strip():
        print(f"  {C.DIM}{line}{C.RESET}")


def _parse_key_aircrack(output: str) -> str | None:
    m = re.search(r"KEY FOUND!\s*\[\s*(.+?)\s*\]", output, re.IGNORECASE)
    return m.group(1) if m else None


###############################################################################
# Backend: cowpatty
###############################################################################

def _run_cowpatty(capture_file: str, wordlist_file: str, ssid: str) -> None:
    """
    cowpatty is faster than aircrack-ng for PMK lookups (pre-computed tables).
    It requires the SSID because the PMK = PBKDF2(password, SSID, 4096, 32).
    """
    print()
    info("Starting cowpatty...")
    info(f"  SSID: {ssid!r}")
    info(f"  {C.DIM}Press Ctrl+C to abort.{C.RESET}")
    print()

    cmd = ["cowpatty", "-r", capture_file, "-f", wordlist_file, "-s", ssid]
    start = time.time()
    output_lines: list[str] = []

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        for line in proc.stdout:
            line = line.rstrip()
            output_lines.append(line)
            _print_cowpatty_line(line)
        proc.wait()
    except KeyboardInterrupt:
        proc.terminate()
        proc.wait()
        warn("cowpatty aborted by user.")
        return

    elapsed = time.time() - start
    full   = "\n".join(output_lines)
    key    = _parse_key_cowpatty(full)
    print()
    if key:
        found(f"KEY FOUND!  →  {key}")
        _save_result(capture_file, wordlist_file, key, elapsed, "cowpatty")
    else:
        error(f"Key NOT found ({elapsed:.0f}s).")
        info("cowpatty hint: use genpmk to pre-compute a PMK table for repeated attacks on the same SSID.")


def _print_cowpatty_line(line: str) -> None:
    lu = line.upper()
    if "THE NETWORK KEY IS" in lu or "FOUND KEY" in lu:
        print(f"  {C.BOLD}{C.GREEN}{line}{C.RESET}")
    elif "UNCOMPLETED" in lu or "FAILED" in lu:
        print(f"  {C.RED}{line}{C.RESET}")
    elif re.search(r"\d+\.\d+\s+passphrases", line):
        print(f"  \r{C.DIM}{line}{C.RESET}", end="", flush=True)
    elif line.strip():
        print(f"  {C.DIM}{line}{C.RESET}")


def _parse_key_cowpatty(output: str) -> str | None:
    # "The network key is: thepassword"
    m = re.search(r"(?:network key|found key)\s*(?:is|:)\s*(.+)", output, re.IGNORECASE)
    return m.group(1).strip().strip('"').strip("'") if m else None


###############################################################################
# Backend: hashcat (dict + rules)
###############################################################################

def _run_hashcat(hash_file: str, wordlist_file: str, rules: str | None = None) -> None:
    mode_label = f"rules ({os.path.basename(rules)})" if rules else "dict"
    print()
    info(f"Starting hashcat ({mode_label}, mode 22000)...")
    info(f"  {C.DIM}Press Ctrl+C to abort.{C.RESET}")
    print()

    cmd = [
        "hashcat",
        "-m", "22000",
        hash_file,
        wordlist_file,
        "--potfile-disable",
        "-O",               # optimised kernels
        "--status",
        "--status-timer=10",
    ]
    if rules:
        cmd += ["-r", rules]

    start = time.time()
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        for line in proc.stdout:
            line = line.rstrip()
            if line:
                _print_hashcat_line(line)
        proc.wait()
    except KeyboardInterrupt:
        proc.terminate()
        warn("hashcat aborted.")
        return

    elapsed = time.time() - start
    key = _hashcat_result(hash_file)
    print()
    if key:
        found(f"KEY FOUND!  →  {key}")
        _save_result(hash_file, wordlist_file, key, elapsed, f"hashcat-{mode_label}")
    else:
        error(f"Key NOT found ({elapsed:.0f}s).")
        if not rules:
            info("Try hashcat with rules (option 4) for mutation coverage.")


def _print_hashcat_line(line: str) -> None:
    lu = line.upper()
    if "CRACKED" in lu:
        print(f"  {C.BOLD}{C.GREEN}{line}{C.RESET}")
    elif "STATUS" in lu or "SPEED" in lu or "PROGRESS" in lu:
        print(f"  \r{C.DIM}{line}{C.RESET}", end="", flush=True)
    elif line.strip() and not line.startswith("INFO:"):
        print(f"  {C.DIM}{line}{C.RESET}")


def _hashcat_result(hash_file: str) -> str | None:
    for potfile in (
        os.path.expanduser("~/.local/share/hashcat/hashcat.potfile"),
        "hashcat.potfile",
    ):
        if os.path.exists(potfile):
            with open(potfile) as f:
                for line in f:
                    line = line.strip()
                    if ":" in line:
                        return line.split(":", 1)[-1]
    return None


###############################################################################
# hc22000 conversion  (for WPA .cap → hashcat)
###############################################################################

def _convert_cap_to_hc22000(cap_file: str) -> str | None:
    """
    Convert a .cap file to hashcat 22000 format using hcxpcapngtool.
    Returns the output path or None if conversion fails.
    """
    if not shutil.which("hcxpcapngtool"):
        warn("hcxpcapngtool not found — install hcxtools: sudo apt install hcxtools")
        return None

    out = cap_file.replace(".cap", ".hc22000")
    info(f"Converting {os.path.basename(cap_file)} → hc22000 format...")
    result = subprocess.run(
        ["hcxpcapngtool", "-o", out, cap_file],
        capture_output=True, text=True,
    )
    if os.path.exists(out) and os.path.getsize(out) > 0:
        success(f"Converted: {out}")
        return out
    # hcxpcapngtool succeeded but produced empty file → no EAPOL in cap
    warn(f"hcxpcapngtool output empty — cap may lack a complete EAPOL exchange.")
    warn("Stderr: " + result.stderr.strip()[:200])
    return None


###############################################################################
# Rule file picker
###############################################################################

def _pick_rule_file() -> str | None:
    candidates = ["best64", "d3ad0ne", "dive", "rockyou-30000", "toggles1"]
    available: list[tuple[str, str]] = []

    for name in candidates:
        for base in _RULE_SEARCH_PATHS:
            path = os.path.join(base, f"{name}.rule")
            if os.path.exists(path):
                available.append((name, path))
                break

    if not available:
        warn("No hashcat rule files found in standard paths.")
        custom = input(f"  {C.YELLOW}Enter full path to rule file (blank to skip): {C.RESET}").strip()
        return custom if custom and os.path.exists(custom) else None

    print(f"\n  {C.WHITE}Available rule files:{C.RESET}")
    for i, (name, path) in enumerate(available, 1):
        lines = _count_lines(path)
        print(f"  {C.GREEN}[{i}]{C.RESET} {name:<16} {C.DIM}({lines:,} rules)  {path}{C.RESET}")
    print(f"  {C.GREEN}[0]{C.RESET} Enter custom path")

    try:
        raw = input(f"\n  {C.YELLOW}Rule set [1]: {C.RESET}").strip() or "1"
        idx = int(raw)
    except (ValueError, KeyboardInterrupt):
        idx = 1

    if idx == 0:
        custom = input(f"  {C.YELLOW}Path to .rule file: {C.RESET}").strip()
        return custom if custom and os.path.exists(custom) else None
    if 1 <= idx <= len(available):
        chosen = available[idx - 1]
        info(f"Rule: {chosen[0]}  ({chosen[1]})")
        return chosen[1]
    warn("Invalid selection — using best64 if available.")
    return available[0][1] if available else None


###############################################################################
# Helpers
###############################################################################

def _has_handshake(cap_file: str) -> bool:
    result = subprocess.run(
        ["aircrack-ng", cap_file],
        capture_output=True, text=True, timeout=15,
    )
    output = result.stdout + result.stderr
    return bool(re.search(r"WPA\s*\(\s*[1-9]", output, re.IGNORECASE))


def _count_lines(path: str) -> int:
    try:
        result = subprocess.run(["wc", "-l", path], capture_output=True, text=True)
        return int(result.stdout.split()[0])
    except Exception:
        return 0


def _save_result(
    capture: str, wordlist: str, key: str, elapsed: float, backend: str
) -> None:
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    path  = os.path.join(RESULTS_DIR, f"result_{stamp}.txt")
    with open(path, "w") as f:
        f.write(f"Timestamp : {datetime.now()}\n")
        f.write(f"Backend   : {backend}\n")
        f.write(f"Capture   : {capture}\n")
        f.write(f"Wordlist  : {wordlist}\n")
        f.write(f"Key Found : {key}\n")
        f.write(f"Time      : {elapsed:.1f}s\n")
    success(f"Result saved → {path}")
