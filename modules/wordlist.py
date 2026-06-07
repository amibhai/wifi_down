#!/usr/bin/env python3
"""
Comprehensive wordlist generation engine.

Strategies:
  1  SSID-Based Mutations
  2  Common Passwords  (top-1000 built-in + rockyou path)
  3  Custom Seeds + Mutations
  4  Personal Info  (CUPP-style)
  5  Date Patterns
  6  Phone Number Patterns
  7  Keyboard Walk Patterns
  8  Crunch Brute-Force
  9  Hybrid / Combine Multiple Lists
"""

import os
import re
import shutil
import subprocess
import itertools
from datetime import date
from modules.banner import C, info, success, warn, error, print_section

WORDLIST_DIR = 'wordlists'
os.makedirs(WORDLIST_DIR, exist_ok=True)

# Minimum and maximum WPA password lengths
WPA_MIN = 8
WPA_MAX = 63

# ─────────────────────────────────────────────────────────────────────────────
# Mutation helpers
# ─────────────────────────────────────────────────────────────────────────────

LEET_MAP = {
    'a': ['4', '@'], 'e': ['3'], 'i': ['1', '!'],
    'o': ['0'], 's': ['5', '$'], 't': ['7'], 'l': ['1'],
    'g': ['9'], 'b': ['8'],
}

COMMON_SUFFIXES = [
    '1', '12', '123', '1234', '12345', '123456',
    '0', '00', '000', '007', '99', '100',
    '!', '@', '#', '*', '.', '_', '?',
    '1!', '1@', '123!', '123@', '@123',
]

YEARS = [str(y) for y in range(1990, date.today().year + 2)]
YEARS_SHORT = [str(y)[2:] for y in range(1990, date.today().year + 2)]


def _leet(word: str) -> set:
    """Generate single-substitution leet variants."""
    variants = {word}
    for i, ch in enumerate(word.lower()):
        if ch in LEET_MAP:
            for sub in LEET_MAP[ch]:
                variants.add(word[:i] + sub + word[i+1:])
    # Full leet version
    full = word.lower()
    for ch, subs in LEET_MAP.items():
        full = full.replace(ch, subs[0])
    variants.add(full)
    variants.add(full.capitalize())
    return variants


def _case_variants(word: str) -> set:
    variants = {word, word.lower(), word.upper(), word.capitalize(), word.title()}
    # Alternating case
    alt = ''.join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(word))
    variants.add(alt)
    return variants


def _affix(word: str) -> set:
    words = set()
    for sfx in COMMON_SUFFIXES:
        words.add(word + sfx)
        words.add(word.capitalize() + sfx)
        words.add(word.lower() + sfx)
    for yr in YEARS:
        words.add(word + yr)
        words.add(word.lower() + yr)
        words.add(word.capitalize() + yr)
    for yr in YEARS_SHORT:
        words.add(word + yr)
        words.add(word.capitalize() + yr)
    return words


def mutate(word: str) -> set:
    """Apply all mutations to a single word and return a set."""
    all_words = set()
    all_words.update(_case_variants(word))
    all_words.update(_leet(word))
    base_set = set(all_words)  # don't mutate leet results with affixes (too noisy)
    for base in base_set:
        all_words.update(_affix(base))
    all_words.add(word[::-1])   # reversed
    return all_words


def _filter_wpa(words: set) -> set:
    return {w for w in words if WPA_MIN <= len(w) <= WPA_MAX}


def _write_wordlist(words: set, path: str) -> int:
    filtered = _filter_wpa(words)
    with open(path, 'w', errors='replace') as f:
        f.write('\n'.join(sorted(filtered)) + '\n')
    return len(filtered)


# ─────────────────────────────────────────────────────────────────────────────
# Strategy 1: SSID-based
# ─────────────────────────────────────────────────────────────────────────────

def gen_ssid(ssid: str, out: str) -> int:
    info(f"Generating SSID-based mutations for '{ssid}'...")
    words = set()
    # Core mutations on full SSID
    words.update(mutate(ssid))

    # Parts split by non-alphanumeric
    parts = re.split(r'[^a-zA-Z0-9]', ssid)
    for part in parts:
        if len(part) >= 3:
            words.update(mutate(part))

    # WiFi-specific combinations
    for tag in ['wifi', 'home', 'net', 'admin', 'pass', 'password', 'wlan', 'router']:
        words.update(mutate(ssid.lower() + tag))
        words.update(mutate(ssid + tag))

    count = _write_wordlist(words, out)
    success(f"SSID wordlist: {count} entries → {out}")
    return count


# ─────────────────────────────────────────────────────────────────────────────
# Strategy 2: Common passwords
# ─────────────────────────────────────────────────────────────────────────────

def gen_common(out: str, rockyou_path: str = '') -> int:
    words = set()

    # Built-in list
    builtin = os.path.join(os.path.dirname(__file__), '..', 'data', 'common_passwords.txt')
    if os.path.exists(builtin):
        with open(builtin) as f:
            words.update(line.strip() for line in f if line.strip())
        info(f"Loaded {len(words)} built-in common passwords.")

    # rockyou.txt
    if rockyou_path and os.path.exists(rockyou_path):
        info(f"Loading rockyou.txt from {rockyou_path}...")
        with open(rockyou_path, 'r', errors='replace') as f:
            for line in f:
                w = line.strip()
                if WPA_MIN <= len(w) <= WPA_MAX:
                    words.add(w)
        info(f"Total after rockyou: {len(words)}")
    elif not rockyou_path:
        default_paths = ['/usr/share/wordlists/rockyou.txt', '/usr/share/wordlists/rockyou.txt.gz']
        for p in default_paths:
            if os.path.exists(p) and not p.endswith('.gz'):
                info(f"Found rockyou.txt at {p}")
                with open(p, 'r', errors='replace') as f:
                    for line in f:
                        w = line.strip()
                        if WPA_MIN <= len(w) <= WPA_MAX:
                            words.add(w)
                break

    filtered = _filter_wpa(words)
    with open(out, 'w', errors='replace') as f:
        f.write('\n'.join(sorted(filtered)) + '\n')

    success(f"Common passwords: {len(filtered)} entries → {out}")
    return len(filtered)


# ─────────────────────────────────────────────────────────────────────────────
# Strategy 3: Custom seeds
# ─────────────────────────────────────────────────────────────────────────────

def gen_seeds(seeds: list[str], out: str) -> int:
    info(f"Mutating {len(seeds)} custom seed(s)...")
    words = set()
    for seed in seeds:
        words.update(mutate(seed.strip()))
        # Combine pairs
        if len(seeds) > 1:
            for other in seeds:
                if other != seed:
                    words.update(mutate(seed + other))
                    words.update(mutate(seed.capitalize() + other.capitalize()))

    count = _write_wordlist(words, out)
    success(f"Seed-based wordlist: {count} entries → {out}")
    return count


# ─────────────────────────────────────────────────────────────────────────────
# Strategy 4: Personal info (CUPP-style)
# ─────────────────────────────────────────────────────────────────────────────

def gen_personal(out: str) -> int:
    print_section("Personal Info Wordlist (CUPP-style)")
    print(f"  {C.DIM}Leave blank to skip any field.{C.RESET}\n")

    fields = {
        'name':          input(f"  {C.YELLOW}Target's name: {C.RESET}").strip(),
        'surname':       input(f"  {C.YELLOW}Surname: {C.RESET}").strip(),
        'nickname':      input(f"  {C.YELLOW}Nickname: {C.RESET}").strip(),
        'birthdate':     input(f"  {C.YELLOW}Birthdate (DDMMYYYY): {C.RESET}").strip(),
        'partner':       input(f"  {C.YELLOW}Partner's name: {C.RESET}").strip(),
        'partner_bday':  input(f"  {C.YELLOW}Partner birthdate (DDMMYYYY): {C.RESET}").strip(),
        'child':         input(f"  {C.YELLOW}Child's name: {C.RESET}").strip(),
        'child_bday':    input(f"  {C.YELLOW}Child birthdate (DDMMYYYY): {C.RESET}").strip(),
        'pet':           input(f"  {C.YELLOW}Pet name: {C.RESET}").strip(),
        'company':       input(f"  {C.YELLOW}Company / school: {C.RESET}").strip(),
        'keywords':      input(f"  {C.YELLOW}Other keywords (comma-separated): {C.RESET}").strip(),
    }

    words = set()
    seeds = [v for v in fields.values() if v]
    keywords_extra = [k.strip() for k in fields['keywords'].split(',') if k.strip()]
    seeds += keywords_extra

    for s in seeds:
        words.update(mutate(s))

    # Date-derived patterns
    bdate = fields.get('birthdate', '')
    if bdate and len(bdate) == 8:
        words.update(_date_forms(bdate))
    pbdate = fields.get('partner_bday', '')
    if pbdate and len(pbdate) == 8:
        words.update(_date_forms(pbdate))

    # Pairwise combinations
    non_empty = [v for k, v in fields.items() if v and k not in ('keywords',)]
    for a, b in itertools.permutations(non_empty, 2):
        words.update(mutate(a + b))
        words.update(mutate(a.lower() + b.lower()))

    count = _write_wordlist(words, out)
    success(f"Personal wordlist: {count} entries → {out}")
    return count


def _date_forms(ddmmyyyy: str) -> set:
    """Generate common date formatting permutations from DDMMYYYY string."""
    if len(ddmmyyyy) != 8:
        return set()
    dd, mm, yyyy = ddmmyyyy[:2], ddmmyyyy[2:4], ddmmyyyy[4:]
    yy = yyyy[2:]
    variants = set()
    for d, m, y, yr in itertools.product([dd], [mm], [yyyy], [yy]):
        for sep in ['', '-', '/', '.', '_']:
            variants.add(d + sep + m + sep + y)
            variants.add(m + sep + d + sep + y)
            variants.add(y + sep + m + sep + d)
            variants.add(d + sep + m + sep + yr)
    return variants


# ─────────────────────────────────────────────────────────────────────────────
# Strategy 5: Date patterns
# ─────────────────────────────────────────────────────────────────────────────

def gen_dates(out: str, start_year: int = 1980, end_year: int = None) -> int:
    if end_year is None:
        end_year = date.today().year + 1
    info(f"Generating date patterns {start_year}–{end_year}...")
    words = set()
    separators = ['', '-', '/', '.', '_']
    for year in range(start_year, end_year + 1):
        for month in range(1, 13):
            for day in range(1, 32):
                dd = f"{day:02d}"
                mm = f"{month:02d}"
                yyyy = str(year)
                yy = yyyy[2:]
                for sep in separators:
                    words.add(dd + sep + mm + sep + yyyy)
                    words.add(dd + sep + mm + sep + yy)
                    words.add(mm + sep + dd + sep + yyyy)
                    words.add(yyyy + sep + mm + sep + dd)
    count = _write_wordlist(words, out)
    success(f"Date patterns: {count} entries → {out}")
    return count


# ─────────────────────────────────────────────────────────────────────────────
# Strategy 6: Phone number patterns
# ─────────────────────────────────────────────────────────────────────────────

def gen_phones(out: str) -> int:
    info("Generating phone number patterns...")
    words = set()
    # India (10-digit, starting with 6-9)
    for prefix in ['6', '7', '8', '9']:
        for _ in range(100):
            import random
            n = prefix + ''.join([str(random.randint(0, 9)) for _ in range(9)])
            words.add(n)
            words.add('+91' + n)
            words.add('0' + n)

    # Generic patterns
    for a in range(100, 1000):
        for b in range(1000, 10000):
            n10 = f"{a:03d}{b:04d}0000"[:10]
            words.add(n10)

    # Common formats with separators
    extras = set()
    for w in list(words)[:500]:
        if len(w) == 10:
            extras.add(w[:3] + '-' + w[3:6] + '-' + w[6:])
            extras.add(w[:3] + ' ' + w[3:6] + ' ' + w[6:])
    words.update(extras)

    count = _write_wordlist(words, out)
    success(f"Phone patterns: {count} entries → {out}")
    return count


# ─────────────────────────────────────────────────────────────────────────────
# Strategy 7: Keyboard walk patterns
# ─────────────────────────────────────────────────────────────────────────────

KEYBOARD_WALKS = [
    'qwerty', 'qwertyuiop', 'asdfgh', 'asdfghjkl', 'zxcvbn', 'zxcvbnm',
    '1q2w3e4r', '1q2w3e4r5t', 'qazwsx', 'qazwsxedc',
    'qweasdzxc', '1qaz2wsx', '!qaz@wsx', '!qaz2wsx',
    'qwert', 'qwerty123', 'qwerty1', 'qwerty12',
    '1234qwer', 'abcdefgh', 'abcd1234',
    'password', 'p@ssw0rd', 'passw0rd', 'p@ssword',
    'letmein', 'iloveyou', 'welcome1', 'monkey123',
    'dragon123', 'master123', 'baseball1', 'football1',
    'abc123', 'abc@123', 'abc@1234',
    '1234abcd', '12345678', '123456789', '1234567890',
]

def gen_keyboard(out: str) -> int:
    info("Generating keyboard walk patterns...")
    words = set()
    for w in KEYBOARD_WALKS:
        words.update(mutate(w))
    count = _write_wordlist(words, out)
    success(f"Keyboard walk wordlist: {count} entries → {out}")
    return count


# ─────────────────────────────────────────────────────────────────────────────
# Strategy 8: Crunch brute-force
# ─────────────────────────────────────────────────────────────────────────────

def gen_crunch(min_len: int, max_len: int, charset: str, out: str) -> int:
    if not shutil.which('crunch'):
        error("crunch not found. Install it: apt install crunch")
        return 0
    if min_len < WPA_MIN:
        min_len = WPA_MIN
    if max_len > WPA_MAX:
        max_len = WPA_MAX

    info(f"Running crunch: charset='{charset}' len={min_len}–{max_len}...")
    warn("This can generate VERY large files. Be patient.")

    cmd = ['crunch', str(min_len), str(max_len), charset, '-o', out]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        if proc.returncode == 0 and os.path.exists(out):
            count = sum(1 for _ in open(out))
            success(f"Crunch wordlist: {count} entries → {out}")
            return count
        else:
            error(f"crunch failed: {proc.stderr}")
            return 0
    except subprocess.TimeoutExpired:
        error("crunch timed out.")
        return 0


# ─────────────────────────────────────────────────────────────────────────────
# Strategy 9: Combine / merge wordlists
# ─────────────────────────────────────────────────────────────────────────────

def gen_vendor_defaults(bssid: str, out: str) -> int:
    """Strategy 11 — vendor default passwords via IEEE OUI lookup."""
    info(f"Looking up vendor defaults for {bssid} ...")
    try:
        from modules.oui import get_vendor, get_vendor_wordlist
        vendor = get_vendor(bssid)
        if vendor:
            info(f"  Vendor: {vendor}")
        passwords = get_vendor_wordlist(bssid)
    except Exception as exc:
        warn(f"OUI lookup failed: {exc}")
        passwords = []

    if not passwords:
        warn(f"No vendor defaults found for {bssid}")
        return 0

    words: set = set()
    for pwd in passwords:
        words.add(pwd)
        words.update(mutate(pwd))

    count = _write_wordlist(words, out)
    success(f"Vendor defaults wordlist: {count} entries → {out}")
    return count


def gen_combine(files: list[str], out: str) -> int:
    info(f"Merging {len(files)} wordlist(s) and deduplicating...")
    seen = set()
    with open(out, 'w', errors='replace') as fout:
        for path in files:
            if not os.path.exists(path):
                warn(f"  File not found: {path}")
                continue
            with open(path, 'r', errors='replace') as fin:
                for line in fin:
                    w = line.strip()
                    if WPA_MIN <= len(w) <= WPA_MAX and w not in seen:
                        seen.add(w)
                        fout.write(w + '\n')
    success(f"Combined wordlist: {len(seen)} unique entries → {out}")
    return len(seen)


# ─────────────────────────────────────────────────────────────────────────────
# Interactive menu
# ─────────────────────────────────────────────────────────────────────────────

def wordlist_menu(ssid: str = None, auto: bool = False) -> str | None:
    print_section("Wordlist Generator")

    if auto:
        # In auto mode: generate SSID + common + keyboard combined
        out_file = os.path.join(WORDLIST_DIR, f'auto_{(ssid or "combined").replace(" ","_")}.txt')
        tmp_files = []

        if ssid:
            f1 = os.path.join(WORDLIST_DIR, '_tmp_ssid.txt')
            gen_ssid(ssid, f1)
            tmp_files.append(f1)

        f2 = os.path.join(WORDLIST_DIR, '_tmp_common.txt')
        gen_common(f2)
        tmp_files.append(f2)

        f3 = os.path.join(WORDLIST_DIR, '_tmp_keyboard.txt')
        gen_keyboard(f3)
        tmp_files.append(f3)

        gen_combine(tmp_files, out_file)
        return out_file

    print(f"""
  {C.WHITE}Wordlist Strategies:{C.RESET}
  {C.GREEN} [1]{C.RESET} SSID-Based Mutations          {C.GREEN} [2]{C.RESET} Common Passwords
  {C.GREEN} [3]{C.RESET} Custom Seeds + Mutations      {C.GREEN} [4]{C.RESET} Personal Info (CUPP-style)
  {C.GREEN} [5]{C.RESET} Date Patterns                 {C.GREEN} [6]{C.RESET} Phone Number Patterns
  {C.GREEN} [7]{C.RESET} Keyboard Walk Patterns        {C.GREEN} [8]{C.RESET} Crunch Brute-Force
  {C.GREEN} [9]{C.RESET} Combine Multiple Wordlists    {C.GREEN}[10]{C.RESET} All Strategies
  {C.CYAN}[11]{C.RESET} Vendor Defaults  (OUI lookup)  {C.CYAN}[12]{C.RESET} Use Existing Wordlist File
  {C.RED} [0]{C.RESET} Back
""")

    choice = input(f"  {C.YELLOW}Strategy: {C.RESET}").strip()

    if choice == '0':
        return None

    stamp = __import__('datetime').datetime.now().strftime('%Y%m%d_%H%M%S')

    if choice == '1':
        name = ssid or input(f"  {C.YELLOW}SSID: {C.RESET}").strip()
        out = os.path.join(WORDLIST_DIR, f'ssid_{stamp}.txt')
        gen_ssid(name, out)
        return out

    elif choice == '2':
        out = os.path.join(WORDLIST_DIR, f'common_{stamp}.txt')
        ry = input(f"  {C.YELLOW}Path to rockyou.txt (Enter to skip): {C.RESET}").strip()
        gen_common(out, ry)
        return out

    elif choice == '3':
        raw = input(f"  {C.YELLOW}Enter seed words (comma-separated): {C.RESET}").strip()
        seeds = [s.strip() for s in raw.split(',') if s.strip()]
        if not seeds:
            error("No seeds provided.")
            return None
        out = os.path.join(WORDLIST_DIR, f'seeds_{stamp}.txt')
        gen_seeds(seeds, out)
        return out

    elif choice == '4':
        out = os.path.join(WORDLIST_DIR, f'personal_{stamp}.txt')
        gen_personal(out)
        return out

    elif choice == '5':
        try:
            sy = int(input(f"  {C.YELLOW}Start year [{1990}]: {C.RESET}").strip() or '1990')
            ey = int(input(f"  {C.YELLOW}End year [{date.today().year}]: {C.RESET}").strip() or str(date.today().year))
        except ValueError:
            sy, ey = 1990, date.today().year
        out = os.path.join(WORDLIST_DIR, f'dates_{stamp}.txt')
        gen_dates(out, sy, ey)
        return out

    elif choice == '6':
        out = os.path.join(WORDLIST_DIR, f'phones_{stamp}.txt')
        gen_phones(out)
        return out

    elif choice == '7':
        out = os.path.join(WORDLIST_DIR, f'keyboard_{stamp}.txt')
        gen_keyboard(out)
        return out

    elif choice == '8':
        charset = input(f"  {C.YELLOW}Charset (e.g. abcdefghijklmnopqrstuvwxyz0123456789): {C.RESET}").strip()
        if not charset:
            error("No charset given.")
            return None
        try:
            mn = int(input(f"  {C.YELLOW}Min length [{WPA_MIN}]: {C.RESET}").strip() or str(WPA_MIN))
            mx = int(input(f"  {C.YELLOW}Max length [8]: {C.RESET}").strip() or '8')
        except ValueError:
            mn, mx = WPA_MIN, WPA_MIN
        out = os.path.join(WORDLIST_DIR, f'crunch_{stamp}.txt')
        gen_crunch(mn, mx, charset, out)
        return out

    elif choice == '9':
        raw = input(f"  {C.YELLOW}Paths to wordlists (comma-separated): {C.RESET}").strip()
        files = [f.strip() for f in raw.split(',') if f.strip()]
        out = os.path.join(WORDLIST_DIR, f'combined_{stamp}.txt')
        gen_combine(files, out)
        return out

    elif choice == '10':
        tmp_files = []
        if ssid:
            f = os.path.join(WORDLIST_DIR, '_all_ssid.txt');  gen_ssid(ssid, f);   tmp_files.append(f)
        f = os.path.join(WORDLIST_DIR, '_all_common.txt');    gen_common(f);        tmp_files.append(f)
        f = os.path.join(WORDLIST_DIR, '_all_keyboard.txt');  gen_keyboard(f);      tmp_files.append(f)
        seeds_raw = input(f"  {C.YELLOW}Custom seeds (comma-sep, Enter to skip): {C.RESET}").strip()
        if seeds_raw:
            seeds = [s.strip() for s in seeds_raw.split(',') if s.strip()]
            f = os.path.join(WORDLIST_DIR, '_all_seeds.txt'); gen_seeds(seeds, f); tmp_files.append(f)
        out = os.path.join(WORDLIST_DIR, f'all_strategies_{stamp}.txt')
        gen_combine(tmp_files, out)
        return out

    elif choice == '11':
        # Strategy 11: Vendor defaults via OUI lookup
        bssid = input(f"  {C.YELLOW}Target BSSID (for vendor lookup): {C.RESET}").strip().upper()
        out = os.path.join(WORDLIST_DIR, f'vendor_{stamp}.txt')
        count = gen_vendor_defaults(bssid, out)
        if count == 0:
            warn("No vendor defaults found for this BSSID. Falling back to common passwords.")
            gen_common(out)
        return out

    elif choice == '12':
        path = input(f"  {C.YELLOW}Path to wordlist file: {C.RESET}").strip()
        if os.path.exists(path):
            success(f"Using existing wordlist: {path}")
            return path
        error(f"File not found: {path}")
        return None

    else:
        error("Invalid choice.")
        return None
