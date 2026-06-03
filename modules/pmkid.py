#!/usr/bin/env python3
"""
modules/pmkid.py — PMKID hash extraction helper
────────────────────────────────────────────────
Converts a raw hcxdumptool .pcapng capture to a hashcat-ready
22000/16800 hash file using hcxpcapngtool.

Standalone usage:
    from modules.pmkid import extract_pmkid_hashes
    hash_file = extract_pmkid_hashes("captures/target-01.pcapng")
"""

import os
import subprocess
import shutil
from datetime import datetime


def extract_pmkid_hashes(pcapng_file: str, out_dir: str | None = None) -> str | None:
    """
    Run hcxpcapngtool on *pcapng_file* and return the path to the
    resulting 22000-format hash file, or None on failure.
    """
    if not shutil.which("hcxpcapngtool"):
        print("[-] hcxpcapngtool not found — install hcxtools.")
        return None

    if not os.path.isfile(pcapng_file):
        print(f"[-] Capture file not found: {pcapng_file}")
        return None

    out_dir = out_dir or os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "captures"
    )
    os.makedirs(out_dir, exist_ok=True)

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    hash_file = os.path.join(out_dir, f"pmkid_{ts}.hc22000")

    cmd = ["hcxpcapngtool", "-o", hash_file, pcapng_file]
    print(f"[*] Extracting PMKID hashes → {hash_file}")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        if os.path.isfile(hash_file) and os.path.getsize(hash_file) > 0:
            line_count = sum(1 for _ in open(hash_file))
            print(f"[+] Extracted {line_count} hash(es) → {hash_file}")
            return hash_file
        else:
            print("[-] hcxpcapngtool produced an empty or no output file.")
            print(result.stderr.strip())
            return None
    except subprocess.TimeoutExpired:
        print("[-] hcxpcapngtool timed out.")
        return None
    except Exception as exc:
        print(f"[-] Error: {exc}")
        return None


def crack_pmkid_hashcat(hash_file: str, wordlist: str, rules: str | None = None) -> str | None:
    """
    Run hashcat mode 22000 against *hash_file* with *wordlist*.
    Returns the cracked password string or None.
    """
    if not shutil.which("hashcat"):
        print("[-] hashcat not found.")
        return None

    cmd = [
        "hashcat",
        "-m", "22000",
        hash_file,
        wordlist,
        "--quiet",
        "--status",
        "--status-timer", "10",
    ]
    if rules:
        cmd += ["-r", rules]

    print(f"[*] hashcat mode 22000  |  wordlist: {os.path.basename(wordlist)}")
    try:
        subprocess.run(cmd, timeout=3600)
        # Try to read potfile
        pot = os.path.expanduser("~/.hashcat/hashcat.potfile")
        if os.path.isfile(pot):
            with open(pot) as fh:
                for line in reversed(fh.readlines()):
                    if ":" in line:
                        return line.strip().split(":")[-1]
    except subprocess.TimeoutExpired:
        print("[-] hashcat timed out.")
    except Exception as exc:
        print(f"[-] hashcat error: {exc}")
    return None
