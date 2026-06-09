#!/usr/bin/env python3
"""
Custom Pattern Builder Engine — backend for Strategy 13.

Pattern token reference:
  %W   pool words as-is           %w  pool words lowercase
  %U   pool words UPPERCASE        %T  pool words Titlecase
  %L   pool words leet-substituted %r  pool words reversed
  %Y   4-digit years (e.g. 2003)   %y  2-digit years (e.g. 03)
  %D   full date DDMMYYYY           %d  day DD     %m  month MM
  %N   favourite number(s)
  %s   single special char  (!@#$%^&*._-)
  %S   symbol pairs  (!!, @@, !@, !123, 123!, @1)
  %k   keyboard walk fragments
  %0   literal zero "0"
  %n   single digit 0-9
  %2   common 2-digit  (00,01,07,11,12,21,22,69,77,99)
  %4   common 4-digit  (0000,1111,1234,6969,9999 + session years)
  [abc]   pick one char from the bracket set
  {text}  literal string inserted verbatim
"""

from __future__ import annotations

import itertools
import json
import re
from pathlib import Path
from typing import Iterator

# ── Constant pools ────────────────────────────────────────────────────────────

_SPECIAL_POOL   = ['!', '@', '#', '$', '%', '^', '&', '*', '.', '_', '-', '~']
_SYMBOL_PAIRS   = ['!!', '@@', '##', '$$', '!@', '!#', '@!', '!123', '123!', '@1', '1!']
_KEYBOARD_WALKS = ['qwerty', 'asdf', '1234', '12345', '1q2w', 'qazwsx', '!@#$', 'abc123']
_DEFAULT_YEARS  = [str(y) for y in range(1990, 2027)]
_DEFAULT_YEARS_SHORT = [str(y)[2:] for y in range(1990, 2027)]
_COMMON_2DIGIT  = ['00', '01', '07', '11', '12', '21', '22', '33', '44',
                   '55', '66', '69', '77', '88', '99']
_COMMON_4DIGIT  = ['0000', '1111', '1234', '1357', '2580', '3210', '4321',
                   '6666', '6969', '7777', '8888', '9999']

_LEET_MAP_FIRST = {'a': '@', 'e': '3', 'i': '1', 'o': '0', 's': '$', 't': '7', 'l': '1'}

# ── Persistent storage ────────────────────────────────────────────────────────

_PATTERNS_FILE = Path.home() / '.wifi-auditor' / 'custom_patterns.json'


def load_saved_patterns() -> list[str]:
    if _PATTERNS_FILE.exists():
        try:
            return json.loads(_PATTERNS_FILE.read_text()).get('patterns', [])
        except Exception:
            return []
    return []


def save_pattern(pattern: str) -> None:
    existing = load_saved_patterns()
    if pattern not in existing:
        existing.append(pattern)
    _PATTERNS_FILE.parent.mkdir(parents=True, exist_ok=True)
    _PATTERNS_FILE.write_text(json.dumps({'patterns': existing}, indent=2))


def delete_pattern(pattern: str) -> bool:
    existing = load_saved_patterns()
    if pattern in existing:
        existing.remove(pattern)
        _PATTERNS_FILE.write_text(json.dumps({'patterns': existing}, indent=2))
        return True
    return False


# ── Leet helper ───────────────────────────────────────────────────────────────

def _leet_first(word: str) -> str:
    """Apply leet substitution to the first eligible character only."""
    out = list(word.lower())
    for i, ch in enumerate(out):
        if ch in _LEET_MAP_FIRST:
            out[i] = _LEET_MAP_FIRST[ch]
            break
    return ''.join(out)


# ── Pattern context ───────────────────────────────────────────────────────────

class PatternContext:
    """Holds all token pools used during pattern expansion."""

    def __init__(
        self,
        words: list[str] | None = None,
        years: list[str] | None = None,
        years_short: list[str] | None = None,
        date_full: str = '',
        day: str = '',
        month: str = '',
        numbers: list[str] | None = None,
        special_chars: list[str] | None = None,
    ):
        self.words        = words or []
        self.years        = years if years is not None else _DEFAULT_YEARS
        self.years_short  = years_short if years_short is not None else _DEFAULT_YEARS_SHORT
        self.date_full    = date_full
        self.day          = day
        self.month        = month
        self.numbers      = numbers or ['1', '7', '99', '0']
        self.special_chars = special_chars or _SPECIAL_POOL

    def __repr__(self) -> str:
        return (f"PatternContext(words={self.words[:3]!r}, "
                f"years={self.years[:3]!r}, numbers={self.numbers!r})")


def build_context(fields: dict) -> PatternContext:
    """
    Build a PatternContext from a personal-info fields dict.

    Recognised keys: firstname, lastname, nickname, partner_name, pet_name,
                     company, city, favourite_word, favourite_number,
                     dob_full (DDMMYYYY), phone.
    """
    words: list[str] = []
    for key in ('firstname', 'lastname', 'nickname', 'partner_name', 'pet_name',
                'company', 'city', 'favourite_word'):
        val = fields.get(key, '').strip()
        if val:
            words.append(val)

    years: list[str] = []
    years_short: list[str] = []
    date_full = day = month = ''

    dob = fields.get('dob_full', '').strip()
    if len(dob) == 8 and dob.isdigit():
        date_full = dob
        day       = dob[:2]
        month     = dob[2:4]
        years.append(dob[4:])
        years_short.append(dob[6:])

    numbers: list[str] = []
    fav = fields.get('favourite_number', '').strip()
    if fav:
        numbers.append(fav)
    numbers.extend(y for y in years if y not in numbers)
    if not numbers:
        numbers = ['1', '7', '99', '0']

    return PatternContext(
        words=words,
        years=years if years else _DEFAULT_YEARS,
        years_short=years_short if years_short else _DEFAULT_YEARS_SHORT,
        date_full=date_full,
        day=day,
        month=month,
        numbers=numbers,
    )


# ── Tokeniser ─────────────────────────────────────────────────────────────────

def tokenize_pattern(pattern: str) -> list[tuple[str, str]]:
    """
    Parse a pattern string into a list of (type, value) tuples.
    Types: 'token' (%X), 'charset' ([abc]), 'literal' (plain text or {text}).
    """
    tokens: list[tuple[str, str]] = []
    i, n = 0, len(pattern)
    while i < n:
        ch = pattern[i]
        if ch == '%' and i + 1 < n:
            tokens.append(('token', pattern[i + 1]))
            i += 2
        elif ch == '[':
            try:
                j = pattern.index(']', i + 1)
                tokens.append(('charset', pattern[i + 1:j]))
                i = j + 1
            except ValueError:
                tokens.append(('literal', ch))
                i += 1
        elif ch == '{':
            try:
                j = pattern.index('}', i + 1)
                tokens.append(('literal', pattern[i + 1:j]))
                i = j + 1
            except ValueError:
                tokens.append(('literal', ch))
                i += 1
        else:
            j = i
            while j < n and pattern[j] not in ('%', '[', '{'):
                j += 1
            if j > i:
                tokens.append(('literal', pattern[i:j]))
            i = j
    return tokens


# ── Segment expander ──────────────────────────────────────────────────────────

def expand_segment(tok_type: str, tok_val: str, ctx: PatternContext) -> list[str]:
    """Return all possible string values for a single parsed segment."""
    if tok_type == 'literal':
        return [tok_val]
    if tok_type == 'charset':
        return list(tok_val) if tok_val else ['']

    # tok_type == 'token'
    cmd = tok_val
    w = ctx.words

    _dispatch: dict[str, list[str]] = {
        'W': w if w else [''],
        'w': [x.lower() for x in w] if w else [''],
        'U': [x.upper() for x in w] if w else [''],
        'T': [x.capitalize() for x in w] if w else [''],
        'L': [_leet_first(x) for x in w] if w else [''],
        'r': [x[::-1] for x in w] if w else [''],
        'Y': ctx.years or ['2000'],
        'y': ctx.years_short or ['00'],
        'D': [ctx.date_full] if ctx.date_full else ['01012000'],
        'd': [ctx.day] if ctx.day else ['01'],
        'm': [ctx.month] if ctx.month else ['01'],
        'N': ctx.numbers or ['1'],
        's': ctx.special_chars or _SPECIAL_POOL,
        'S': _SYMBOL_PAIRS,
        'k': _KEYBOARD_WALKS,
        '0': ['0'],
        'n': [str(d) for d in range(10)],
        '2': _COMMON_2DIGIT,
    }

    if cmd in _dispatch:
        return _dispatch[cmd]
    if cmd == '4':
        extra = [y for y in ctx.years[:3] if len(y) == 4]
        return list(dict.fromkeys(_COMMON_4DIGIT + extra))

    return [f'%{cmd}']  # unknown token: treat as literal


# ── Core expansion API ────────────────────────────────────────────────────────

def expand_pattern(pattern: str, ctx: PatternContext) -> Iterator[str]:
    """
    Expand a pattern string into all password candidates via cartesian product.
    Yields one string at a time — memory-efficient for large expansions.
    """
    segments = tokenize_pattern(pattern)
    if not segments:
        return
    options = [expand_segment(t, v, ctx) for t, v in segments]
    for combo in itertools.product(*options):
        yield ''.join(combo)


def estimate_count(pattern: str, ctx: PatternContext) -> int:
    """Return the upper-bound candidate count for a pattern (before dedup/length filter)."""
    segments = tokenize_pattern(pattern)
    total = 1
    for tok_type, tok_val in segments:
        total *= max(1, len(expand_segment(tok_type, tok_val, ctx)))
    return total


def preview_pattern(pattern: str, ctx: PatternContext, n: int = 10) -> list[str]:
    """Return the first n candidates produced by the pattern."""
    result: list[str] = []
    for candidate in expand_pattern(pattern, ctx):
        result.append(candidate)
        if len(result) >= n:
            break
    return result


# ── Interactive menu ──────────────────────────────────────────────────────────

TOKEN_HELP = """
  Pattern tokens
  ──────────────────────────────────────────────────────
  %W  pool words (as-is)    %w  lowercase    %U  UPPER
  %T  Titlecase              %L  leet         %r  reversed
  %Y  4-digit year           %y  2-digit year
  %D  date DDMMYYYY          %d  day DD       %m  month MM
  %N  favourite number       %s  special !@#  %S  pair !!
  %k  keyboard walk          %n  digit 0-9    %0  zero
  %2  2-digit                %4  4-digit
  [abc]  one char from set   {text}  literal string
  ──────────────────────────────────────────────────────
  Examples:
    %T@%Y      →  Parv@2003
    %w%s%Y     →  parv!2003  parv@2003  parv#2003 …
    %T[!@#]%y  →  Parv!03   Parv@03   Parv#03
    %w_%Y%s    →  parv_2003!  parv_2003@  …
"""

_MAX_WARN = 500_000


def pattern_menu(
    ctx: PatternContext | None = None,
    out_dir: str = 'wordlists',
) -> str | None:
    """
    Interactive custom pattern builder.
    Returns path to generated wordlist, or None if cancelled.
    """
    from modules.banner import C, info, success, warn, error
    import os
    from datetime import datetime

    WPA_MIN, WPA_MAX = 8, 63

    print(f"\n{C.CYAN}{'─'*60}{C.RESET}")
    print(f"  {C.BOLD}Custom Pattern Builder  (Strategy 13){C.RESET}")
    print(f"{C.CYAN}{'─'*60}{C.RESET}")
    print(TOKEN_HELP)

    if ctx is None:
        ctx = PatternContext()

    if ctx.words:
        print(f"  {C.DIM}Pool words : {', '.join(ctx.words[:8])}{C.RESET}")
    if ctx.years and ctx.years != _DEFAULT_YEARS:
        print(f"  {C.DIM}Years      : {', '.join(ctx.years[:4])}{C.RESET}")
    if ctx.numbers:
        print(f"  {C.DIM}Numbers    : {', '.join(ctx.numbers[:4])}{C.RESET}")

    saved = load_saved_patterns()
    if saved:
        print(f"\n  {C.DIM}Saved patterns ({len(saved)}): "
              + "  ".join(saved[:6])
              + (f"  …" if len(saved) > 6 else "") + f"{C.RESET}")

    raw = input(
        f"\n  {C.YELLOW}Pattern(s) — space/comma-separated "
        f"(or 'list', 'del <pattern>') [Enter=back]: {C.RESET}"
    ).strip()

    if not raw:
        return None

    # ── list command ──
    if raw.lower() == 'list':
        if not saved:
            warn("No saved patterns yet.")
            return None
        print(f"\n  Saved patterns:")
        for i, p in enumerate(saved, 1):
            cnt = estimate_count(p, ctx)
            print(f"    [{i:2d}] {p:30s}  ≈ {cnt:,}")
        sel = input(f"  {C.YELLOW}Use # (or Enter to cancel): {C.RESET}").strip()
        if sel.isdigit() and 1 <= int(sel) <= len(saved):
            raw = saved[int(sel) - 1]
        else:
            return None

    # ── del command ──
    if raw.lower().startswith('del '):
        pat = raw[4:].strip()
        if delete_pattern(pat):
            info(f"Deleted: {pat}")
        else:
            warn(f"Not found in saved patterns: {pat}")
        return None

    raw_patterns = [p.strip() for p in re.split(r'[,\s]+', raw) if p.strip()]
    if not raw_patterns:
        return None

    # ── estimate + preview ──
    total_est = sum(estimate_count(p, ctx) for p in raw_patterns)
    print(f"\n  Estimated candidates: {C.CYAN}{total_est:,}{C.RESET}")
    for p in raw_patterns[:3]:
        prev = preview_pattern(p, ctx, 6)
        print(f"  [{p}] → {C.DIM}{', '.join(prev)}{C.RESET}")

    if total_est > _MAX_WARN:
        warn(f"Large expansion ({total_est:,}). May take a while.")
        if input(f"  {C.YELLOW}Continue? [y/N]: {C.RESET}").strip().lower() != 'y':
            return None

    # ── generate ──
    stamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    out = os.path.join(out_dir, f'pattern_{stamp}.txt')
    os.makedirs(out_dir, exist_ok=True)

    seen: set[str] = set()
    count = 0

    _bar = None
    try:
        from tqdm import tqdm as _tqdm
        _bar = _tqdm(total=total_est, desc='  Expanding', unit=' words', leave=False)
    except ImportError:
        pass

    with open(out, 'w', errors='replace') as f:
        for pat in raw_patterns:
            for word in expand_pattern(pat, ctx):
                if _bar:
                    _bar.update(1)
                if WPA_MIN <= len(word) <= WPA_MAX and word not in seen:
                    seen.add(word)
                    f.write(word + '\n')
                    count += 1

    if _bar:
        _bar.close()

    # ── save prompt ──
    if input(f"  {C.YELLOW}Save pattern(s) for future use? [y/N]: {C.RESET}").strip().lower() == 'y':
        for p in raw_patterns:
            save_pattern(p)
        info(f"Saved → {_PATTERNS_FILE}")

    success(f"Pattern wordlist: {count:,} entries → {out}")
    return out
