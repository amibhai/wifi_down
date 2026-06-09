#!/usr/bin/env python3
"""
Comprehensive wordlist generation engine — v2.

Strategies:
  1  SSID-Based Mutations
  2  Common Passwords  (built-in top-list + rockyou path)
  3  Custom Seeds + Mutations
  4  Personal Info  (rebuilt — 10 mutation families, probability-sorted output)
  5  Date Patterns
  6  Phone Number Patterns
  7  Keyboard Walk Patterns
  8  Crunch Brute-Force
  9  Combine / Merge Multiple Wordlists
  10 All Strategies
  11 Vendor Defaults  (OUI lookup)
  12 Use Existing Wordlist File
  13 Custom Pattern Builder  (token-based, uses pattern_engine)
  14 Smart Scenario Engine   (profile-based, probability-sorted)
"""

from __future__ import annotations

import itertools
import os
import random
import re
import shutil
import subprocess
from datetime import date
from modules.banner import C, info, success, warn, error, print_section

try:
    from tqdm import tqdm as _tqdm
    _HAS_TQDM = True
except ImportError:
    _HAS_TQDM = False

WORDLIST_DIR = 'wordlists'
os.makedirs(WORDLIST_DIR, exist_ok=True)

WPA_MIN = 8
WPA_MAX = 63

# ── Stores context from the last personal-info session for Strategy 13/14 ─────
_last_personal_fields: dict = {}

# ─────────────────────────────────────────────────────────────────────────────
# Core mutation helpers  (used by strategies 1-3 and internally)
# ─────────────────────────────────────────────────────────────────────────────

LEET_MAP = {
    'a': ['4', '@'], 'e': ['3'], 'i': ['1', '!'],
    'o': ['0'], 's': ['5', '$'], 't': ['7'], 'l': ['1'], 'g': ['9'], 'b': ['8'],
}

COMMON_SUFFIXES = [
    '1', '12', '123', '1234', '12345', '123456',
    '0', '00', '000', '007', '99', '100',
    '!', '@', '#', '*', '.', '_', '?',
    '1!', '1@', '123!', '123@', '@123',
]

YEARS       = [str(y) for y in range(1990, date.today().year + 2)]
YEARS_SHORT = [str(y)[2:] for y in range(1990, date.today().year + 2)]


def _leet(word: str) -> set[str]:
    """Single-substitution leet variants plus a full-leet pass."""
    variants = {word}
    w = word.lower()
    for i, ch in enumerate(w):
        if ch in LEET_MAP:
            for sub in LEET_MAP[ch]:
                variants.add(w[:i] + sub + w[i + 1:])
    full = w
    for ch, subs in LEET_MAP.items():
        full = full.replace(ch, subs[0])
    variants.add(full)
    variants.add(full.capitalize())
    return variants


def _case_variants(word: str) -> set[str]:
    variants = {word, word.lower(), word.upper(), word.capitalize(), word.title()}
    alt = ''.join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(word))
    variants.add(alt)
    return variants


def _affix(word: str) -> set[str]:
    """Traditional suffix/prefix mutations (year concat, common suffixes)."""
    words: set[str] = set()
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


def mutate(word: str) -> set[str]:
    """Apply all mutations to a single word (used by strategies 1-3)."""
    all_words: set[str] = set()
    all_words.update(_case_variants(word))
    all_words.update(_leet(word))
    for base in set(all_words):
        all_words.update(_affix(base))
    all_words.add(word[::-1])
    return all_words


def _filter_wpa(words: set[str]) -> set[str]:
    return {w for w in words if WPA_MIN <= len(w) <= WPA_MAX}


def _write_wordlist(words: set[str], path: str) -> int:
    """Alphabetically sorted, WPA-filtered write (used by strategies 1-3, 5-7)."""
    filtered = _filter_wpa(words)
    with open(path, 'w', errors='replace') as f:
        f.write('\n'.join(sorted(filtered)) + '\n')
    return len(filtered)


def _write_ordered(candidates: list[str], path: str,
                   min_len: int = WPA_MIN, max_len: int = WPA_MAX) -> int:
    """
    Write candidates in the order they appear (highest-priority first),
    deduplicating on the fly.  Used by strategies 4 and 14.
    """
    seen: set[str] = set()
    count = 0
    with open(path, 'w', errors='replace') as f:
        for word in candidates:
            if min_len <= len(word) <= max_len and word not in seen:
                seen.add(word)
                f.write(word + '\n')
                count += 1
    return count


# ── QoL helpers ───────────────────────────────────────────────────────────────

def _print_stats(count: int, path: str) -> None:
    size = os.path.getsize(path) if os.path.exists(path) else 0
    size_str = (f"{size / 1_048_576:.1f} MB" if size > 1_048_576
                else f"{size / 1024:.1f} KB")
    cps = 1_000_000  # assumed hashes/sec for aircrack-ng on WPA2
    secs = count / cps if cps else 0
    if secs < 60:
        crack_est = f"{secs:.0f}s"
    elif secs < 3600:
        crack_est = f"{secs / 60:.1f}m"
    else:
        crack_est = f"{secs / 3600:.1f}h"
    print(f"\n  {C.CYAN}{'─'*50}{C.RESET}")
    print(f"  {C.GREEN}Candidates:{C.RESET} {count:,}")
    print(f"  {C.GREEN}File:      {C.RESET} {path}")
    print(f"  {C.GREEN}Size:      {C.RESET} {size_str}")
    print(f"  {C.DIM}Est. crack time @ 1M h/s: {crack_est}{C.RESET}")


def _preview_top10(path: str) -> None:
    if not os.path.exists(path):
        return
    print(f"\n  {C.DIM}Top 10 (highest-priority) candidates:{C.RESET}")
    with open(path, errors='replace') as f:
        for i, line in enumerate(f):
            if i >= 10:
                break
            print(f"    {i + 1:2d}. {line.rstrip()}")


def _dedup_against_existing(new_path: str, existing_path: str) -> int:
    """Remove from new_path every entry that already appears in existing_path."""
    if not os.path.exists(existing_path):
        return 0
    existing: set[str] = set()
    with open(existing_path, 'r', errors='replace') as f:
        existing.update(l.strip() for l in f if l.strip())
    keep: list[str] = []
    removed = 0
    with open(new_path, 'r', errors='replace') as f:
        for line in f:
            w = line.strip()
            if w in existing:
                removed += 1
            else:
                keep.append(w)
    with open(new_path, 'w', errors='replace') as f:
        f.write('\n'.join(keep) + '\n')
    return removed


def _post_gen_prompts(path: str, count: int) -> str:
    """
    Offer post-generation QoL options: dedup, preview, pipe-to-cracker.
    Returns the (possibly unchanged) final path.
    """
    _print_stats(count, path)
    _preview_top10(path)

    if input(f"\n  {C.YELLOW}Remove duplicates vs an existing wordlist? [y/N]: {C.RESET}").strip().lower() == 'y':
        ep = input(f"  {C.YELLOW}  Path to existing wordlist: {C.RESET}").strip()
        if ep:
            rm = _dedup_against_existing(path, ep)
            info(f"  Removed {rm:,} already-seen entries.")

    if input(f"  {C.YELLOW}Pipe directly to cracker now? [y/N]: {C.RESET}").strip().lower() == 'y':
        try:
            from modules.cracker import cracker_menu
            cracker_menu(capture_file='', wordlist_file=path)
        except Exception as exc:
            warn(f"Cracker error: {exc}")

    return path


# ─────────────────────────────────────────────────────────────────────────────
# Strategy 1: SSID-based
# ─────────────────────────────────────────────────────────────────────────────

def gen_ssid(ssid: str, out: str) -> int:
    info(f"Generating SSID-based mutations for '{ssid}'...")
    words: set[str] = set()
    words.update(mutate(ssid))
    for part in re.split(r'[^a-zA-Z0-9]', ssid):
        if len(part) >= 3:
            words.update(mutate(part))
    for tag in ['wifi', 'home', 'net', 'admin', 'pass', 'password', 'wlan', 'router']:
        words.update(mutate(ssid.lower() + tag))
        words.update(mutate(ssid + tag))
    count = _write_wordlist(words, out)
    success(f"SSID wordlist: {count:,} entries → {out}")
    return count


# ─────────────────────────────────────────────────────────────────────────────
# Strategy 2: Common passwords
# ─────────────────────────────────────────────────────────────────────────────

def gen_common(out: str, rockyou_path: str = '') -> int:
    words: set[str] = set()
    builtin = os.path.join(os.path.dirname(__file__), '..', 'data', 'common_passwords.txt')
    if os.path.exists(builtin):
        with open(builtin) as f:
            words.update(l.strip() for l in f if l.strip())
        info(f"Loaded {len(words):,} built-in common passwords.")
    if rockyou_path and os.path.exists(rockyou_path):
        info(f"Loading rockyou.txt from {rockyou_path}...")
        with open(rockyou_path, 'r', errors='replace') as f:
            for line in f:
                w = line.strip()
                if WPA_MIN <= len(w) <= WPA_MAX:
                    words.add(w)
    elif not rockyou_path:
        for p in ['/usr/share/wordlists/rockyou.txt']:
            if os.path.exists(p):
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
    success(f"Common passwords: {len(filtered):,} entries → {out}")
    return len(filtered)


# ─────────────────────────────────────────────────────────────────────────────
# Strategy 3: Custom seeds
# ─────────────────────────────────────────────────────────────────────────────

def gen_seeds(seeds: list[str], out: str) -> int:
    info(f"Mutating {len(seeds)} custom seed(s)...")
    words: set[str] = set()
    for seed in seeds:
        words.update(mutate(seed.strip()))
        if len(seeds) > 1:
            for other in seeds:
                if other != seed:
                    words.update(mutate(seed + other))
                    words.update(mutate(seed.capitalize() + other.capitalize()))
    count = _write_wordlist(words, out)
    success(f"Seed-based wordlist: {count:,} entries → {out}")
    return count


# ─────────────────────────────────────────────────────────────────────────────
# Strategy 4: Personal Info  (completely rebuilt)
# ─────────────────────────────────────────────────────────────────────────────

# Separator priority for name+year combos (most common real-world patterns first)
_P4_SEPS = [
    ('',  98), ('@', 95), ('.', 90), ('#', 88),
    ('_', 85), ('-', 82), ('!', 78), ('$', 74), ('*', 70),
]
_P4_SPECIALS = ['!', '@', '#', '$', '%', '&', '*', '.', '_', '-', '~', '!@', '!!']
_P4_WALKS    = ['123', '1234', '12345', '!@#', 'qwerty', 'asdf', '1q2w', '007']


def _date_forms(ddmmyyyy: str) -> list[str]:
    """All common date formatting variants from a DDMMYYYY string."""
    if len(ddmmyyyy) != 8:
        return []
    dd, mm, yyyy, yy = ddmmyyyy[:2], ddmmyyyy[2:4], ddmmyyyy[4:], ddmmyyyy[6:]
    variants: list[str] = []
    for sep in ['', '-', '/', '.', '_']:
        variants.append(dd + sep + mm + sep + yyyy)
        variants.append(mm + sep + dd + sep + yyyy)
        variants.append(yyyy + sep + mm + sep + dd)
        variants.append(dd + sep + mm + sep + yy)
        variants.append(mm + sep + dd + sep + yy)
    return variants


def _gen_personal_candidates(
    word_tokens: list[str],
    year_tokens: list[str],
    year_short_tokens: list[str],
    all_num_tokens: list[str],
    date_strs: list[str],
) -> list[str]:
    """
    Generate personal-info candidates in probability order (highest first).

    10 mutation families — output list is already ordered; caller deduplicates
    on write via _write_ordered().
    """
    result: list[str] = []
    seen: set[str] = set()

    def add(w: str) -> None:
        if w not in seen:
            seen.add(w)
            result.append(w)

    all_years = year_tokens + year_short_tokens  # full first, short second

    # ── Family 1: name + separator + year  (THE KEY BUG FIX) ─────────────────
    
    for tok in word_tokens:
        for yr in year_tokens:
            for sep, _ in _P4_SEPS:
                add(tok.lower() + sep + yr)
                add(tok.capitalize() + sep + yr)
                add(tok.upper() + yr)         # PARV2003
                if sep:
                    add(yr + sep + tok.lower())
        for yr_s in year_short_tokens:
            for sep, _ in _P4_SEPS:
                add(tok.lower() + sep + yr_s)
                add(tok.capitalize() + sep + yr_s)

    # ── Family 2: leet + year  (p@rv2003, p@rv@2003, etc.) ───────────────────
    for tok in word_tokens:
        for leet_v in _leet(tok):
            if leet_v == tok.lower():
                continue  # skip non-leet copy
            for yr in all_years:
                add(leet_v + yr)
                add(leet_v + '@' + yr)
                add(leet_v + '#' + yr)

    # ── Family 3: name + year + special  (parv2003!, Parv2003@, etc.) ─────────
    for tok in word_tokens:
        for yr in all_years:
            for sp in _P4_SPECIALS[:7]:   # top 7 most common specials
                add(tok.lower() + yr + sp)
                add(tok.capitalize() + yr + sp)
                add(sp + tok.lower() + yr)

    # ── Family 4: raw case / leet variants (single-token, no suffix) ──────────
    for tok in word_tokens:
        for v in _case_variants(tok):
            add(v)
        for v in _leet(tok):
            add(v)
        add(tok[::-1])

    # ── Family 5: name + non-year numbers (favourite number, phone tail) ──────
    for tok in word_tokens:
        for num in all_num_tokens:
            if num in year_tokens or num in year_short_tokens:
                continue  # already covered by Family 1
            add(tok.lower() + num)
            add(tok.capitalize() + num)
            add(num + tok.lower())

    # ── Family 6: traditional affixes  (COMMON_SUFFIXES + year concat) ────────
    for tok in word_tokens:
        for w in _affix(tok):
            add(w)

    # ── Family 7: 2-word combinations ─────────────────────────────────────────
    name_toks = [t for t in word_tokens if not t.isdigit()][:6]
    for a, b in itertools.permutations(name_toks, 2):
        for sep in ['', '_', '.', '@', '-']:
            add(a.lower() + sep + b.lower())
            add(a.capitalize() + sep + b.lower())
            add(a.capitalize() + sep + b.capitalize())
        for yr in year_tokens[:4]:
            add(a.lower() + b.lower() + yr)
            add(a.capitalize() + b.capitalize() + yr)
            add(a.capitalize() + '@' + b.lower() + yr)

    # ── Family 8: keyboard walk suffixes ──────────────────────────────────────
    for tok in word_tokens[:4]:
        for walk in _P4_WALKS:
            add(tok.lower() + walk)
            add(tok.capitalize() + walk)

    # ── Family 9: date pattern strings ────────────────────────────────────────
    for dt in date_strs:
        add(dt)
        for tok in word_tokens[:3]:
            add(tok.lower() + dt)
            add(tok.capitalize() + '_' + dt)

    # ── Family 10: zero-padding  (parv00, parv000, parv007, etc.) ─────────────
    for tok in word_tokens:
        for pad in ['00', '000', '0000', '01', '02', '007', '11', '99']:
            add(tok.lower() + pad)
            add(tok.capitalize() + pad)

    return result


def _collect_personal_fields() -> dict:
    """Prompt user for personal info fields and return as a dict."""
    print(f"\n  {C.DIM}Leave blank to skip any field.  Date format: DDMMYYYY{C.RESET}\n")

    def ask(prompt: str) -> str:
        return input(f"  {C.YELLOW}{prompt}: {C.RESET}").strip()

    return {
        'firstname':        ask("Target firstname"),
        'lastname':         ask("Lastname"),
        'nickname':         ask("Nickname / alias"),
        'partner_name':     ask("Partner's name"),
        'pet_name':         ask("Pet name"),
        'dob_full':         ask("Birthdate (DDMMYYYY)"),
        'partner_dob':      ask("Partner birthdate (DDMMYYYY)"),
        'company':          ask("Company / school"),
        'city':             ask("City / hometown"),
        'favourite_word':   ask("Favourite word / hobby"),
        'favourite_number': ask("Favourite number"),
        'phone':            ask("Phone tail (last 4-6 digits, or full)"),
        'keywords':         ask("Other keywords (comma-separated)"),
    }


def gen_personal(out: str) -> int:
    global _last_personal_fields
    print_section("Personal Info Wordlist — Strategy 4")

    fields = _collect_personal_fields()
    _last_personal_fields = fields  # make available to strategies 13 & 14

    # ── Extract token pools ──────────────────────────────────────────────────
    word_tokens: list[str] = []
    for key in ('firstname', 'lastname', 'nickname', 'partner_name', 'pet_name',
                'company', 'city', 'favourite_word'):
        val = fields.get(key, '').strip()
        if val:
            word_tokens.append(val)

    # Extra keyword seeds
    kw_raw = fields.get('keywords', '')
    for kw in (k.strip() for k in kw_raw.split(',') if k.strip()):
        word_tokens.append(kw)

    year_tokens:       list[str] = []
    year_short_tokens: list[str] = []
    date_strs:         list[str] = []

    for dob_key in ('dob_full', 'partner_dob'):
        dob = fields.get(dob_key, '').strip()
        if len(dob) == 8 and dob.isdigit():
            yr4, yr2 = dob[4:], dob[6:]
            if yr4 not in year_tokens:
                year_tokens.append(yr4)
            if yr2 not in year_short_tokens:
                year_short_tokens.append(yr2)
            date_strs.extend(_date_forms(dob))

    all_num_tokens: list[str] = list(year_tokens) + list(year_short_tokens)
    fav_num = fields.get('favourite_number', '').strip()
    if fav_num:
        all_num_tokens.append(fav_num)
    phone = fields.get('phone', '').strip()
    if phone:
        word_tokens.append(phone)  # treat phone as a word token for combo generation

    if not word_tokens:
        warn("No usable fields entered.")
        return 0

    info(f"Tokens: {', '.join(word_tokens[:6])}{'…' if len(word_tokens)>6 else ''}")
    info(f"Years : {', '.join(year_tokens + year_short_tokens) or '(none)' }")

    # ── Generate candidates in probability order ──────────────────────────────
    candidates = _gen_personal_candidates(
        word_tokens, year_tokens, year_short_tokens, all_num_tokens, date_strs
    )

    count = _write_ordered(candidates, out)
    success(f"Personal wordlist: {count:,} entries → {out}")

    _post_gen_prompts(out, count)
    return count


# ─────────────────────────────────────────────────────────────────────────────
# Strategy 5: Date patterns
# ─────────────────────────────────────────────────────────────────────────────

def gen_dates(out: str, start_year: int = 1980, end_year: int | None = None) -> int:
    if end_year is None:
        end_year = date.today().year + 1
    info(f"Generating date patterns {start_year}–{end_year}...")
    words: set[str] = set()
    for year in range(start_year, end_year + 1):
        for month in range(1, 13):
            for day_n in range(1, 32):
                dd, mm = f"{day_n:02d}", f"{month:02d}"
                yyyy, yy = str(year), str(year)[2:]
                for sep in ['', '-', '/', '.', '_']:
                    words.add(dd + sep + mm + sep + yyyy)
                    words.add(dd + sep + mm + sep + yy)
                    words.add(mm + sep + dd + sep + yyyy)
                    words.add(yyyy + sep + mm + sep + dd)
    count = _write_wordlist(words, out)
    success(f"Date patterns: {count:,} entries → {out}")
    return count


# ─────────────────────────────────────────────────────────────────────────────
# Strategy 6: Phone number patterns
# ─────────────────────────────────────────────────────────────────────────────

def gen_phones(out: str) -> int:
    info("Generating phone number patterns...")
    words: set[str] = set()
    for prefix in ['6', '7', '8', '9']:
        for _ in range(200):
            n = prefix + ''.join(str(random.randint(0, 9)) for _ in range(9))
            words.add(n)
            words.add('+91' + n)
            words.add('0' + n)
    for a in range(100, 400):
        for b in range(1000, 5000, 100):
            n10 = f"{a:03d}{b:07d}"[:10]
            words.add(n10)
    extras: set[str] = set()
    for w in list(words)[:500]:
        if len(w) == 10:
            extras.add(w[:3] + '-' + w[3:6] + '-' + w[6:])
            extras.add(w[:3] + ' ' + w[3:6] + ' ' + w[6:])
    words.update(extras)
    count = _write_wordlist(words, out)
    success(f"Phone patterns: {count:,} entries → {out}")
    return count


# ─────────────────────────────────────────────────────────────────────────────
# Strategy 7: Keyboard walk patterns
# ─────────────────────────────────────────────────────────────────────────────

KEYBOARD_WALKS = [
    'qwerty', 'qwertyuiop', 'asdfgh', 'asdfghjkl', 'zxcvbn', 'zxcvbnm',
    '1q2w3e4r', '1q2w3e4r5t', 'qazwsx', 'qazwsxedc', 'qweasdzxc',
    '1qaz2wsx', '!qaz@wsx', '!qaz2wsx', 'qwert', 'qwerty123', 'qwerty1',
    '1234qwer', 'abcdefgh', 'abcd1234', 'password', 'p@ssw0rd', 'passw0rd',
    'p@ssword', 'letmein', 'iloveyou', 'welcome1', 'monkey123', 'dragon123',
    'master123', 'abc123', 'abc@123', 'abc@1234', '1234abcd',
    '12345678', '123456789', '1234567890',
]


def gen_keyboard(out: str) -> int:
    info("Generating keyboard walk patterns...")
    words: set[str] = set()
    for w in KEYBOARD_WALKS:
        words.update(mutate(w))
    count = _write_wordlist(words, out)
    success(f"Keyboard walk wordlist: {count:,} entries → {out}")
    return count


# ─────────────────────────────────────────────────────────────────────────────
# Strategy 8: Crunch brute-force
# ─────────────────────────────────────────────────────────────────────────────

def gen_crunch(min_len: int, max_len: int, charset: str, out: str) -> int:
    if not shutil.which('crunch'):
        error("crunch not found — apt install crunch")
        return 0
    min_len = max(min_len, WPA_MIN)
    max_len = min(max_len, WPA_MAX)
    info(f"Running crunch: charset='{charset}' len={min_len}–{max_len} ...")
    warn("This can generate very large files.")
    try:
        proc = subprocess.run(
            ['crunch', str(min_len), str(max_len), charset, '-o', out],
            capture_output=True, text=True, timeout=600,
        )
        if proc.returncode == 0 and os.path.exists(out):
            count = sum(1 for _ in open(out))
            success(f"Crunch wordlist: {count:,} entries → {out}")
            return count
        error(f"crunch failed: {proc.stderr}")
        return 0
    except subprocess.TimeoutExpired:
        error("crunch timed out.")
        return 0


# ─────────────────────────────────────────────────────────────────────────────
# Strategy 9: Combine / merge wordlists
# ─────────────────────────────────────────────────────────────────────────────

def gen_combine(files: list[str], out: str) -> int:
    info(f"Merging {len(files)} wordlist(s) and deduplicating...")
    seen: set[str] = set()
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
    success(f"Combined wordlist: {len(seen):,} unique entries → {out}")
    return len(seen)


# ─────────────────────────────────────────────────────────────────────────────
# Strategy 11: Vendor defaults
# ─────────────────────────────────────────────────────────────────────────────

def gen_vendor_defaults(bssid: str, out: str) -> int:
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
    words: set[str] = set()
    for pwd in passwords:
        words.add(pwd)
        words.update(mutate(pwd))
    count = _write_wordlist(words, out)
    success(f"Vendor defaults wordlist: {count:,} entries → {out}")
    return count


# ─────────────────────────────────────────────────────────────────────────────
# Strategy 13: Custom Pattern Builder
# ─────────────────────────────────────────────────────────────────────────────

def gen_pattern(out_dir: str = WORDLIST_DIR, fields: dict | None = None) -> str | None:
    """
    Strategy 13 — delegate to the pattern_engine interactive menu.
    Auto-populates context from the last personal-info session if available.
    """
    from modules.pattern_engine import build_context, pattern_menu, PatternContext

    ctx: PatternContext
    src = fields or _last_personal_fields
    if src:
        ctx = build_context(src)
        info("Pattern context auto-populated from session personal info.")
    else:
        ctx = PatternContext()

    return pattern_menu(ctx, out_dir)


# ─────────────────────────────────────────────────────────────────────────────
# Strategy 14: Smart Scenario Engine
# ─────────────────────────────────────────────────────────────────────────────

# Each scenario: list of (pattern_string, priority).
# Patterns are generated in descending priority order → output is probability-sorted.
_SCENARIOS: dict[str, dict] = {
    '1': {
        'name': 'Indian Mobile User',
        'desc': 'Most prevalent Indian WiFi password patterns (name+sep+year)',
        'fields': ['firstname', 'lastname', 'dob_full', 'favourite_number'],
        'patterns': [
            ('%w@%Y',   100), ('%w%Y',    98), ('%T%Y',    96),
            ('%w.%Y',    94), ('%w#%Y',   92), ('%w_%Y',   90),
            ('%U%Y',     88), ('%w@%y',   86), ('%T@%Y',   84),
            ('%w%Y!',    82), ('%L%Y',    80), ('%w%y',    78),
            ('%T%y',     76), ('%w%Y@',   74), ('%w!%Y',   72),
            ('%w_%y',    70), ('%w%N',    68), ('%T%N',    66),
            ('%w%Y#',    64), ('%T%Y!',   62),
        ],
    },
    '2': {
        'name': 'Corporate Employee',
        'desc': 'Office/enterprise password patterns (company+name+year)',
        'fields': ['firstname', 'lastname', 'company', 'dob_full', 'favourite_number'],
        'patterns': [
            ('%T@%Y',    95), ('%w%Y',    93), ('%T%Y',    91),
            ('%W%N',     88), ('%T%Y!',   86), ('%T%Y@',   84),
            ('%T%T%Y',   82), ('%w%2%2',  78), ('%T[!@#$]%y', 76),
            ('%T%T',     70), ('%T%T!',   68), ('%w%4',    65),
        ],
    },
    '3': {
        'name': 'Student',
        'desc': 'Student account patterns (name+year, short combos)',
        'fields': ['firstname', 'lastname', 'nickname', 'dob_full'],
        'patterns': [
            ('%w%Y',     95), ('%T%Y',    93), ('%w@%Y',   90),
            ('%w%y',     88), ('%w123',   85), ('%w1234',  82),
            ('%T123',    80), ('%w!',      75), ('%w.%y',   73),
            ('%w%N',     70), ('%r%Y',    60), ('%w%2%2',  58),
        ],
    },
    '4': {
        'name': 'General Consumer',
        'desc': 'Broad consumer patterns from breach database statistics',
        'fields': ['firstname', 'dob_full', 'pet_name', 'favourite_word'],
        'patterns': [
            ('%w%Y',     95), ('%T%Y',    93), ('%w@%Y',   92),
            ('%w%s',     88), ('%T%s%Y',  85), ('%w%n%n%n', 82),
            ('%w%2%2',   78), ('%k',       72), ('%L%Y',    68),
            ('%w%0%0%0', 65), ('%w%Y%s',  62),
        ],
    },
    '5': {
        'name': 'Custom',
        'desc': 'Build your own pattern list (opens Pattern Builder)',
        'fields': ['firstname', 'lastname', 'nickname', 'dob_full',
                   'favourite_number', 'favourite_word'],
        'patterns': [],  # resolved via pattern_menu
    },
}


def _collect_scenario_fields(field_keys: list[str]) -> dict:
    """Prompt only the fields relevant to the chosen scenario."""
    _labels = {
        'firstname':        'Firstname',
        'lastname':         'Lastname',
        'nickname':         'Nickname / alias',
        'partner_name':     "Partner's name",
        'pet_name':         'Pet name',
        'dob_full':         'Birthdate (DDMMYYYY)',
        'company':          'Company / school',
        'city':             'City / hometown',
        'favourite_word':   'Favourite word',
        'favourite_number': 'Favourite number',
    }
    print(f"\n  {C.DIM}Enter info for this scenario (blank to skip):{C.RESET}\n")
    result: dict = {}
    for key in field_keys:
        lbl = _labels.get(key, key)
        result[key] = input(f"  {C.YELLOW}{lbl}: {C.RESET}").strip()
    return result


def gen_scenario(out: str, fields: dict | None = None) -> int:
    global _last_personal_fields
    print_section("Smart Scenario Engine — Strategy 14")

    print(f"""
  Select target profile:
  {C.GREEN}[1]{C.RESET} Indian Mobile User    — name+sep+year (most common Indian WiFi pattern)
  {C.GREEN}[2]{C.RESET} Corporate Employee    — company + name + year combos
  {C.GREEN}[3]{C.RESET} Student               — name+year, short combinations
  {C.GREEN}[4]{C.RESET} General Consumer      — statistically common breach patterns
  {C.GREEN}[5]{C.RESET} Custom                — opens interactive Pattern Builder
  {C.RED}[0]{C.RESET} Back
""")

    choice = input(f"  {C.YELLOW}Scenario: {C.RESET}").strip()
    if choice == '0' or choice not in _SCENARIOS:
        return 0

    scenario = _SCENARIOS[choice]
    print(f"\n  {C.CYAN}{scenario['name']}{C.RESET}: {scenario['desc']}")

    # Custom scenario → delegate to pattern_engine
    if choice == '5':
        src = fields or _last_personal_fields
        from modules.pattern_engine import build_context, pattern_menu, PatternContext
        ctx = build_context(src) if src else PatternContext()
        result = pattern_menu(ctx, WORDLIST_DIR)
        return 1 if result else 0

    # Collect fields (or reuse from caller / previous personal session)
    if fields is None:
        if _last_personal_fields:
            reuse = input(
                f"  {C.YELLOW}Reuse personal info from previous session? [Y/n]: {C.RESET}"
            ).strip().lower()
            fields = _last_personal_fields if reuse != 'n' else _collect_scenario_fields(scenario['fields'])
        else:
            fields = _collect_scenario_fields(scenario['fields'])

    _last_personal_fields = fields

    # Build pattern context
    from modules.pattern_engine import build_context, expand_pattern

    ctx = build_context(fields)
    if not ctx.words:
        warn("No words in context — at least a firstname is needed.")
        return 0

    info(f"Pool : {', '.join(ctx.words[:6])}")
    info(f"Years: {', '.join(ctx.years[:4])}")

    # Generate in priority order (highest-priority patterns first)
    patterns = sorted(scenario['patterns'], key=lambda x: -x[1])
    seen: set[str] = set()
    count = 0

    total_est = len(patterns) * max(1, len(ctx.words)) * max(1, len(ctx.years))

    _bar = None
    if _HAS_TQDM:
        from modules.pattern_engine import estimate_count
        total_est = sum(estimate_count(p_str, ctx) for p_str, _ in patterns)
        _bar = _tqdm(total=total_est, desc='  Generating', unit=' words', leave=False)

    with open(out, 'w', errors='replace') as f:
        for pat_str, _ in patterns:
            for word in expand_pattern(pat_str, ctx):
                if _bar:
                    _bar.update(1)
                if WPA_MIN <= len(word) <= WPA_MAX and word not in seen:
                    seen.add(word)
                    f.write(word + '\n')
                    count += 1

    if _bar:
        _bar.close()

    success(f"Scenario '{scenario['name']}': {count:,} entries → {out}")
    _post_gen_prompts(out, count)
    return count


# ─────────────────────────────────────────────────────────────────────────────
# Interactive menu
# ─────────────────────────────────────────────────────────────────────────────

def wordlist_menu(ssid: str | None = None, auto: bool = False) -> str | None:
    print_section("Wordlist Generator")

    if auto:
        stamp = __import__('datetime').datetime.now().strftime('%Y%m%d_%H%M%S')
        out_file = os.path.join(WORDLIST_DIR, f'auto_{(ssid or "combined").replace(" ", "_")}.txt')
        tmp_files: list[str] = []
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
  {C.GREEN} [3]{C.RESET} Custom Seeds + Mutations      {C.GREEN} [4]{C.RESET} Personal Info  (rebuilt v2)
  {C.GREEN} [5]{C.RESET} Date Patterns                 {C.GREEN} [6]{C.RESET} Phone Number Patterns
  {C.GREEN} [7]{C.RESET} Keyboard Walk Patterns        {C.GREEN} [8]{C.RESET} Crunch Brute-Force
  {C.GREEN} [9]{C.RESET} Combine Multiple Wordlists    {C.GREEN}[10]{C.RESET} All Strategies
  {C.CYAN}[11]{C.RESET} Vendor Defaults  (OUI lookup)  {C.CYAN}[12]{C.RESET} Use Existing Wordlist File
  {C.CYAN}[13]{C.RESET} {C.BOLD}Custom Pattern Builder{C.RESET}        {C.CYAN}[14]{C.RESET} {C.BOLD}Smart Scenario Engine{C.RESET}
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
        raw = input(f"  {C.YELLOW}Seed words (comma-separated): {C.RESET}").strip()
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
            sy = int(input(f"  {C.YELLOW}Start year [1990]: {C.RESET}").strip() or '1990')
            ey = int(input(f"  {C.YELLOW}End year [{date.today().year}]: {C.RESET}").strip()
                     or str(date.today().year))
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
        charset = input(
            f"  {C.YELLOW}Charset (e.g. abcdefghijklmnopqrstuvwxyz0123456789): {C.RESET}"
        ).strip()
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
        raw = input(f"  {C.YELLOW}Wordlist paths (comma-separated): {C.RESET}").strip()
        files = [f.strip() for f in raw.split(',') if f.strip()]
        out = os.path.join(WORDLIST_DIR, f'combined_{stamp}.txt')
        gen_combine(files, out)
        return out

    elif choice == '10':
        tmp_files_all: list[str] = []
        if ssid:
            f = os.path.join(WORDLIST_DIR, '_all_ssid.txt')
            gen_ssid(ssid, f)
            tmp_files_all.append(f)
        f = os.path.join(WORDLIST_DIR, '_all_common.txt')
        gen_common(f)
        tmp_files_all.append(f)
        f = os.path.join(WORDLIST_DIR, '_all_keyboard.txt')
        gen_keyboard(f)
        tmp_files_all.append(f)
        seeds_raw = input(f"  {C.YELLOW}Custom seeds (comma-sep, Enter to skip): {C.RESET}").strip()
        if seeds_raw:
            seeds = [s.strip() for s in seeds_raw.split(',') if s.strip()]
            f = os.path.join(WORDLIST_DIR, '_all_seeds.txt')
            gen_seeds(seeds, f)
            tmp_files_all.append(f)
        out = os.path.join(WORDLIST_DIR, f'all_strategies_{stamp}.txt')
        gen_combine(tmp_files_all, out)
        return out

    elif choice == '11':
        bssid = input(f"  {C.YELLOW}Target BSSID (for vendor lookup): {C.RESET}").strip().upper()
        out = os.path.join(WORDLIST_DIR, f'vendor_{stamp}.txt')
        count = gen_vendor_defaults(bssid, out)
        if count == 0:
            warn("No vendor defaults found. Falling back to common passwords.")
            gen_common(out)
        return out

    elif choice == '12':
        path = input(f"  {C.YELLOW}Path to wordlist file: {C.RESET}").strip()
        if os.path.exists(path):
            success(f"Using existing wordlist: {path}")
            return path
        error(f"File not found: {path}")
        return None

    elif choice == '13':
        return gen_pattern(WORDLIST_DIR)

    elif choice == '14':
        out = os.path.join(WORDLIST_DIR, f'scenario_{stamp}.txt')
        gen_scenario(out)
        return out if os.path.exists(out) else None

    else:
        error("Invalid choice.")
        return None
