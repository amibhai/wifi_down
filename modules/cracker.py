#!/usr/bin/env python3
"""
Cracking module: wraps aircrack-ng (WPA handshake) and hashcat (PMKID).

Parses output for KEY FOUND, shows live progress, writes result to results/.
"""

import os
import re
import time
import subprocess
import threading
from datetime import datetime
from modules.banner import C, info, success, warn, error, found, print_section

RESULTS_DIR = 'results'
os.makedirs(RESULTS_DIR, exist_ok=True)


def cracker_menu(capture_file: str, wordlist_file: str):
    print_section("Handshake Cracker")

    # PMKID hash file (from hcxdumptool)
    if capture_file.endswith(':pmkid'):
        hash_file = capture_file.replace(':pmkid', '')
        _crack_pmkid(hash_file, wordlist_file)
        return

    if not os.path.exists(capture_file):
        error(f"Capture file not found: {capture_file}")
        return
    if not os.path.exists(wordlist_file):
        error(f"Wordlist not found: {wordlist_file}")
        return

    info(f"Capture  : {capture_file}")
    info(f"Wordlist : {wordlist_file}")

    wl_size = _count_lines(wordlist_file)
    info(f"Wordlist size: {wl_size:,} entries")

    # Check the capture file has a valid handshake first
    info("Verifying capture file...")
    if not _has_handshake(capture_file):
        warn("aircrack-ng did not detect a complete 4-way handshake in this file.")
        c = input(f"  {C.YELLOW}Continue anyway? [y/N]: {C.RESET}").strip().lower()
        if c != 'y':
            return

    print()
    info("Starting aircrack-ng...")
    info(f"  {C.DIM}Press Ctrl+C to abort.{C.RESET}")
    print()

    _run_aircrack(capture_file, wordlist_file)


# ─────────────────────────────────────────────────────────────────────────────
# aircrack-ng for WPA 4-way handshake
# ─────────────────────────────────────────────────────────────────────────────

def _run_aircrack(capture_file: str, wordlist_file: str):
    cmd = ['aircrack-ng', '-w', wordlist_file, capture_file]
    start = time.time()
    output_lines = []

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
    full_output = '\n'.join(output_lines)
    key = _parse_key(full_output)

    print()
    if key:
        found(f"KEY FOUND!  →  {key}")
        _save_result(capture_file, wordlist_file, key, elapsed)
    else:
        error(f"Key NOT found in this wordlist. ({elapsed:.0f}s elapsed)")
        info("Try a larger wordlist, different mutations, or a targeted approach.")


def _print_aircrack_line(line: str):
    """Pretty-print relevant aircrack-ng lines."""
    if 'KEY FOUND' in line.upper():
        print(f"  {C.BOLD}{C.GREEN}{line}{C.RESET}")
    elif 'FAILED' in line.upper() or 'not in dictionary' in line.lower():
        print(f"  {C.RED}{line}{C.RESET}")
    elif re.search(r'\d+\.\d+ k/s', line):
        # Progress line — overwrite in place
        print(f"  \r{C.DIM}{line}{C.RESET}", end='', flush=True)
    elif line.strip():
        print(f"  {C.DIM}{line}{C.RESET}")


def _parse_key(output: str) -> str | None:
    """Extract the password from aircrack-ng output."""
    # KEY FOUND! [ thepassword ]
    m = re.search(r'KEY FOUND!\s*\[\s*(.+?)\s*\]', output, re.IGNORECASE)
    if m:
        return m.group(1)
    return None


# ─────────────────────────────────────────────────────────────────────────────
# hashcat for PMKID (22000 format)
# ─────────────────────────────────────────────────────────────────────────────

def _crack_pmkid(hash_file: str, wordlist_file: str):
    import shutil
    if not shutil.which('hashcat'):
        # Try aircrack-ng with PMKID hash file (it supports -K flag)
        warn("hashcat not found. Trying aircrack-ng for PMKID...")
        _run_aircrack(hash_file, wordlist_file)
        return

    info(f"PMKID hash: {hash_file}")
    info(f"Wordlist  : {wordlist_file}")
    info("Running hashcat (mode 22000)...")

    cmd = [
        'hashcat',
        '-m', '22000',
        hash_file,
        wordlist_file,
        '--potfile-disable',
        '-O',
    ]

    start = time.time()
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        for line in proc.stdout:
            l = line.rstrip()
            if l:
                print(f"  {C.DIM}{l}{C.RESET}")
        proc.wait()
    except KeyboardInterrupt:
        proc.terminate()
        warn("Aborted.")
        return

    elapsed = time.time() - start
    # Check potfile for result
    # hashcat writes to hashcat.potfile by default
    key = _hashcat_result(hash_file)
    print()
    if key:
        found(f"KEY FOUND!  →  {key}")
        _save_result(hash_file, wordlist_file, key, elapsed)
    else:
        error(f"Key NOT found. ({elapsed:.0f}s)")


def _hashcat_result(hash_file: str) -> str | None:
    potfile = os.path.expanduser('~/.local/share/hashcat/hashcat.potfile')
    if not os.path.exists(potfile):
        potfile = 'hashcat.potfile'
    if not os.path.exists(potfile):
        return None
    with open(potfile) as f:
        for line in f:
            line = line.strip()
            if ':' in line:
                return line.split(':', 1)[-1]
    return None


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _has_handshake(cap_file: str) -> bool:
    result = subprocess.run(
        ['aircrack-ng', cap_file],
        capture_output=True, text=True, timeout=15
    )
    output = result.stdout + result.stderr
    return bool(re.search(r'WPA\s*\(\s*[1-9]', output, re.IGNORECASE))


def _count_lines(path: str) -> int:
    try:
        result = subprocess.run(['wc', '-l', path], capture_output=True, text=True)
        return int(result.stdout.split()[0])
    except Exception:
        return 0


def _save_result(capture: str, wordlist: str, key: str, elapsed: float):
    stamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    result_file = os.path.join(RESULTS_DIR, f'result_{stamp}.txt')
    with open(result_file, 'w') as f:
        f.write(f"Timestamp : {datetime.now()}\n")
        f.write(f"Capture   : {capture}\n")
        f.write(f"Wordlist  : {wordlist}\n")
        f.write(f"Key Found : {key}\n")
        f.write(f"Time      : {elapsed:.1f}s\n")
    success(f"Result saved to {result_file}")
