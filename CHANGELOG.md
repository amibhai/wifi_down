# Changelog

All notable changes to **WiFi Auditor** are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

---

## [0.4.5] — 2026-06-11

### Changed

- `modules/banner.py` — launch experience overhaul:
  - **`_print_made_by_art()`** — large 6-row block-letter `MADE BY` art
    (`MADE_BY_ART` constant) with pink/light-pink gradient (`color(213)` left
    half → `color(219)` right half); `ॐ अ मी ॐ` centered in Devanagari with
    `"  Ami  "` Unicode fallback; decorative `···· ✦ ····` deco lines above and
    below.
  - **`_print_quotes(num=3)`** — picks 3 random entries from `QUOTES` pool
    (10 quotes, 8 authors); animates each character at 5 ms/char using raw ANSI
    italic 256-colour; separated by dim `─` rules; attribution line in
    `color(51)`.
  - **`_print_disclaimer()`** — red-bordered Rich `Panel` titled `LEGAL NOTICE`
    listing CFAA, UK Computer Misuse Act, India IT Act 2000, and HMAC audit
    trail notice; rendered after quotes.
  - **`_pulsing_enter_prompt()`** — pulses `[ Press ENTER to continue ]` through
    3 colour cycles (`color(51)→87→123→87→51`) at 150 ms each, then waits for
    `input()`; clears screen with `os.system("clear"|"cls")` after Enter so the
    full banner only appears once per session.
  - **`print_compact_header(interface=None)`** — one-line dim-cyan header
    `wifi_down  ◈  HH:MM:SS  ◈  <iface>` using `_S_MID` + `_S_DIAMOND` +
    `_S_STATUS_VAL` styles; `_get_interface()` auto-detects interface when
    `interface=None`.
  - **`print_banner()` flow** — calls `_print_made_by_art()`, `_print_quotes(3)`,
    `_print_disclaimer()`, `_pulsing_enter_prompt()` in sequence after the
    animated wifi_down box; clears screen after Enter.

- `wifi_auditor/cli.py` — compact header + session state wiring:
  - Imports `print_compact_header` from `modules.banner` (alongside existing
    `print_banner`, `print_menu` etc.).
  - **Menu loop** — `print_compact_header(interface=state.get("monitor_interface"))`
    called at the top of every `while True:` iteration so a live timestamp and
    active interface are always visible.
  - **`action_capture()`** — stores `handshake_file=cap` in `_sm.transition()`
    call; `state["capture_file"] = cap` already set.
  - **`action_full_auto()`** — `_sm.transition(Stage.CAPTURING, capture_file=cap,
    handshake_file=cap)` added after successful capture.
  - **`run_headless()`** — `sm.transition(Stage.CAPTURING, capture_file=cap,
    handshake_file=cap)` added after successful capture.

---

## [0.4.4] — 2026-06-11

### Changed

- `modules/handshake.py` — complete rewrite; three-engine parallel architecture:

  **Engines (all started simultaneously at capture start):**

  - **Engine 1 — airodump-ng file watcher** (`_file_watcher_thread`): polls the
    `.cap` file every 0.5 s (was 1 s); verifies with all three methods
    (`_verify_aircrack`, `_verify_cowpatty`, `_verify_tshark`) so partial
    handshakes that aircrack-ng misses are caught.
  - **Engine 2 — scapy AsyncSniffer** (`_scapy_sniffer_thread`): captures EAPOL
    frames in-memory in real-time; zero dependency on disk writes; BPF filter
    `ether proto 0x888e`; detects M1+M2 directly by checking `Dot11.addr2`
    (AP→Client) and `Dot11.addr1` (Client→AP) against the target BSSID;
    writes a `.cap` via `wrpcap()` on success.
  - **Engine 3 — hcxdumptool PMKID** (`_pmkid_engine_thread`): runs passively
    from the very start alongside deauth (not as a fallback); checks every 2 s
    for a valid `.hc22000` via `hcxpcapngtool`; `--disable_deauthentication`
    flag keeps it passive; BSSID filter written to a tempfile.

  **Verification — three methods (`verify_handshake`):**

  - `_verify_aircrack` — `aircrack-ng -b <bssid> <cap>`; regex for
    `\d+ handshake` or `WPA (\d+ handshake`.
  - `_verify_cowpatty` — `cowpatty -r <cap> -s <ssid> -f -`; catches partial
    handshakes.
  - `_verify_tshark` — counts EAPOL frames for the target BSSID; ≥2 frames →
    crackable M1+M2.

  **Deauth improvements:**

  - Channel locked with **both** `iw dev <iface> set channel` and
    `iwconfig <iface> channel` before any deauth burst (`_lock_channel`).
  - Cap file verified to exist (`_wait_for_file`, 6 s timeout) before first
    deauth burst; warns but continues if slow.
  - Handshake watch ticks every **0.3 s** (was 1 s) inside each deauth interval.
  - `--ignore-negative-one` passed to every `aireplay-ng` call to prevent
    channel fighting.
  - **Phase 1** — 10 targeted unicast attempts × 5 packets, top-2 clients.
  - **Phase 2** — 5 broadcast fallback attempts × 10 packets.
  - **Phase 3** — pure PMKID wait up to 90 s (Engine 3 already running).

  **Backward compatibility aliases (existing callers unchanged):**

  - `kill_proc_safe` → `_kill`
  - `start_capture_process` → `_start_airodump`
  - `send_deauth_burst` → `_deauth_burst`

---

## [0.4.3] — 2026-06-10

### Changed

- `modules/handshake.py` — full rewrite of the Strategy 2 deauth pipeline:
  - **`discover_clients(bssid, monitor_interface, scan_duration, channel)`**
    Runs `airodump-ng` for N seconds, parses the Station section of the CSV,
    returns clients sorted strongest-signal-first.  Exact BSSID match on
    `row[5]` — no false positives from nearby APs.  Rich Live countdown.
  - **`display_clients(clients, bssid)`**
    Rich table with colour-coded signal strength (green>-50, yellow>-70, red).
  - **`send_targeted_deauth(bssid, client_mac, monitor_interface, limiter, count=8)`**
    Sends in both directions using the per-client rate-limiter key:
    - Dir 1: `aireplay-ng -0 8 -a <AP> -c <client>` — spoofed as AP
    - Dir 2: `aireplay-ng -0 8 -a <client> -c <AP>` — spoofed as client;
      forces the AP to drop the client from its association table so the
      client must do a full 4-way handshake on reconnect regardless of PMF.
  - **`send_broadcast_deauth_fallback()`** — kept as fallback for the
    no-clients-found case (16 packets, rate-limited).
  - **`_deauth_capture()` — rewired pipeline:**
    1. Start `airodump-ng` passive capture in background (runs throughout)
    2. Spawn PMKID thread in parallel (daemon, up to 60 s)
    3. Per attempt: discover clients → targeted deauth per client →
       check after each → wait for reassociation → repeat
    4. Falls back to broadcast if zero clients found
    5. Attempt budget: `max(3, timeout // 28)` — 120 s → 4 attempts
    6. `dump_proc.wait(timeout=5)` with `kill()` fallback (was bare `.wait()`)
    7. SHA-256 of cap file printed on success as audit evidence
  - **`verify_handshake(cap_file, bssid)`** — new public wrapper around
    `_verify_handshake` for callers outside the module.
  - **`_verify_handshake()`** — passes `-b <bssid>` to `aircrack-ng` for
    accurate per-AP detection; adds PMKID match; removes brittle line scan.
  - **`_pmkid_capture()`** — hardened: `mkstemp` temp file, BSSID lowercase,
    `--disable_deauthentication` flag, proc kill fallback, 100-byte min size,
    `.hc22000` extension, `hcxpcapngtool` wrapped in `try/except + timeout`.
  - Removed `_send_deauth()` helper (superseded by `send_targeted_deauth`).

- `modules/ratelimit.py` — per-client bucket keying:
  - `DeauthRateLimiter._key(bssid, client_mac=None)` — static method
    returning `"BSSID:CLIENT"` for targeted deauth, `"BSSID"` for broadcast.
  - `check_burst()`, `wait_for_burst()`, `get_stats()` accept optional
    `client_mac` param.  All existing broadcast callers hit the `None`
    default — no behaviour change for broadcast paths.

---

## [0.4.2] — 2026-06-10

### Fixed

- **Critical — `enable_monitor_mode` never matched on real airmon-ng output**
  (`modules/utils.py`).  Pattern 1 contained `\[\S+\]\S+` — the `\S+` after
  `[wlan0]` requires a non-space character immediately after the closing
  bracket, but real airmon-ng output is
  `monitor mode vif enabled for [wlan0] on [wlan0mon]` (space after bracket).
  The optional group silently failed, then tried to match `on` at the wrong
  position — so no regex ever matched.
- **No-op guessing fallback** — the duplicate typo
  `interface.replace('wlan', 'wlan')` is a no-op; interface name changes were
  never detected when regex failed.

### Added

- `modules/interface.py` (new module, ~199 lines):
  - **Fixed regex patterns** — 5 correct patterns covering all real-world
    airmon-ng output variants (space-separated `on [iface]`, inline, old-style
    suffix-less, parenthesised, `*mon` shorthand).
  - `kill_interfering_processes()` — `airmon-ng check kill` + `systemctl stop`
    for NetworkManager/wpa_supplicant + `pkill -9` for dhclient/dhcpcd + 1.5 s
    settle sleep; verbose Rich output per step.
  - `verify_monitor_mode(interface)` — reads `iw dev` and confirms `type
    monitor` is present for the specific interface after airmon-ng returns.
  - Full `iw dev` fallback — if regex still finds nothing, scans for any
    monitor-mode interface already present.
  - `get_wireless_interfaces()` / `get_monitor_interfaces()` — dedicated
    helpers for managed and monitor interface lists.
  - Verbose `RuntimeError` — contains exact command, return code, stdout,
    stderr, and post-attempt interface list so failures are immediately
    actionable.
  - Root check at the top of `enable_monitor_mode`.

### Changed

- `modules/utils.py` — old broken `enable_monitor_mode`, `disable_monitor_mode`,
  and `kill_interfering_processes` implementations replaced with re-exports from
  `modules.interface`; minor variable-name fix in `get_wireless_interfaces`
  (`ifaces` → `iface`).
- `wifi_auditor/cli.py`:
  - `action_set_interface()` and `run_headless()` now catch `RuntimeError` and
    display the full diagnostic message; removed the now-redundant pre-call to
    `kill_interfering_processes()` (it runs inside `enable_monitor_mode`);
    removed stale `kill_interfering_processes` import.
  - `_action_check_interface()` — new diagnostic function: prints `iw dev` raw
    output, managed/monitor interface lists, interfering processes, airmon-ng
    availability, and root status.
  - `--check-interface` CLI flag — runs `_action_check_interface()` and exits;
    useful for diagnosing issues without reading source code.

---

## [0.4.1] — 2026-06-10

### Changed
- `modules/banner.py` — full rewrite of the terminal identity module:
  - **UTF-8 shim** — `_make_console()` wraps `sys.stdout.buffer` in a UTF-8
    `TextIOWrapper` so `अमी` renders correctly on any Linux terminal; falls
    back to `"Ami"` on `UnicodeEncodeError` (Windows cp1252 dev machines).
  - **Hardcoded art constant** — `WIFI_DOWN_ART` (6-row list of strings with
    box-drawing characters); never regenerated at runtime.
  - **256-colour palette** — 15 `Style` objects using `color(N)` notation:
    `color(23)` dim-teal outer box, `color(30)` noise accent, `color(51/87/50)`
    left/mid/right art gradient, `color(45)` corner accent, `color(213)` credit
    name, `color(240)` dim metadata text.
  - **`_color_art_row()`** — splits each row into three equal zones and applies
    the L→M→R gradient; corner box-drawing chars (`╗╔╝╚╣╠╦╩╬`) receive the
    `color(45)` accent regardless of zone.
  - **Static helpers** — `_build_separator()` (`─── ◈ ───`), `_build_tagline()`
    (`◤ … ◥`), `_build_status()` (`◈ interface … ◈ scope … ◈ session ◈`).
  - **`_build_static_banner()`** — produces the full 16-line banner as a
    `list[Text]` without any animation, used when `animate=False`.
  - **`_compact_banner()`** — narrow-terminal fallback (<90 cols): plain
    27-char box with `wifi_down` + `made by अमी`; no animation.
  - **`print_banner()` — 5-phase animation engine** (requires ≥90 col terminal,
    uses `rich.live.Live` at 120 fps):
    - **Phase 1** — outer `┌─┐`/`└─┘` box draws left→right/top→bottom at
      0.003 s/char; side bars appear row by row.
    - **Phase 2** — top and bottom noise rows fill left→right with `▒→░`
      flicker (0.001 s flicker, 0.002 s settle per char); art-row `░` side
      borders appear instantly.
    - **Phase 3** — column sweep across all 6 art rows simultaneously at
      0.008 s/column; each column increment reveals the next character in all
      rows with correct gradient and corner colouring.
    - **Phase 4** — credit line (`made by अमी`) snaps in right-aligned inside
      the noise border.
    - **Phase 5** — separator, tagline, and status bar are printed below the
      Live block after it closes so they persist cleanly in the scroll buffer.
  - **Status bar** — now uses `◈` diamonds and reads `iface`, `scope` (auto-
    detected from `scope.yaml`), and a live session timestamp; previous ANSI
    f-string status bar removed.
  - Removed: glow-line animation, `_DIM_CYAN` constant (already fixed in
    0.4.0-patch), `_TEAL` f-string colour, old `_con` module-level console.

---

## [0.4.0] — 2026-06-09

### Added
- `modules/pattern_engine.py` (new, ~424 lines):
  - Self-contained pattern expansion engine used by Strategy 13 and 14.
  - **Token reference**: `%W/%w/%U/%T` (pool words as-is/lower/UPPER/Title), `%L/%r` (leet/reversed),
    `%Y/%y` (4-digit/2-digit years), `%D/%d/%m` (date/day/month), `%N` (favourite number),
    `%s/%S/%k` (special char/symbol pair/keyboard walk), `%n/%2/%4` (digit/2-digit/4-digit number),
    `[abc]` (one char from set), `{text}` (literal string).
  - `PatternContext` — holds word pool, year pool, number pool, date fragments, special chars.
  - `build_context(fields)` — builds a `PatternContext` from a personal-info fields dict (accepts
    all 13 Strategy-4 keys).
  - `tokenize_pattern(pattern)` — parses a pattern string into `(type, value)` tuples.
  - `expand_segment(tok_type, tok_val, ctx)` — resolves one parsed segment to its full value list.
  - `expand_pattern(pattern, ctx)` — Cartesian-product generator; memory-efficient, yields one
    candidate at a time.
  - `estimate_count(pattern, ctx)` — upper-bound candidate count shown before generation commits.
  - `preview_pattern(pattern, ctx, n)` — returns first n candidates for UI preview.
  - `pattern_menu(ctx, out_dir)` — interactive builder: shows token help, lists/saves/deletes
    patterns, estimates count, warns if > 500k, generates WPA-filtered wordlist, optional `tqdm`
    progress bar, save-to-JSON prompt.
  - `load_saved_patterns()` / `save_pattern()` / `delete_pattern()` — JSON persistence at
    `~/.wifi-auditor/custom_patterns.json`; reloaded automatically on next run.

- `modules/wordlist.py` — completely rebuilt (~1,031 lines):
  - **Bug fixed**: `parv@2003` now lands at position 1 in the output file. All 6 previously-missing
    combinations (`parv@2003`, `Parv2003`, `PARV2003`, `parv2003!`, `p@rv2003`, `parv@03`) are
    generated by the new 10-family mutation engine.
  - **Strategy 4 (Personal Info)** — full rebuild:
    - 13 fields collected: `firstname`, `lastname`, `nickname`, `partner_name`, `pet_name`,
      `company`, `city`, `favourite_word`, `favourite_number`, `dob_full`, `partner_dob`, `phone`,
      `keywords`.
    - Token pools extracted separately: `word_tokens`, `year_tokens`, `year_short_tokens`,
      `all_num_tokens`, `date_strs`.
    - `_gen_personal_candidates()` — 10 mutation families emitted in probability order:
      1. name + sep + year (`parv@2003`, `Parv2003`, `PARV2003`)
      2. leet + year (`p@rv2003`, `p@rv@2003`)
      3. name + year + special (`parv2003!`, `Parv2003@`, `!parv2003`)
      4. raw case / leet / reversed (base variants)
      5. name + favourite number / phone tail
      6. traditional affixes (`COMMON_SUFFIXES` + year concat)
      7. 2-word combos (`parvkumar`, `Parv_Kumar`, `ParvKumar2003`)
      8. keyboard walk suffixes
      9. date pattern strings
      10. zero-padding (`parv00`, `parv007`, `Parv99`)
    - `_write_ordered()` — deduplicates on the fly, preserves probability order.
  - **Strategy 13 (Custom Pattern Builder)** — `gen_pattern()` delegates to
    `pattern_engine.pattern_menu()` and auto-populates context from the last Strategy 4 session
    (`_last_personal_fields`).
  - **Strategy 14 (Smart Scenario Engine)** — `gen_scenario()` with 5 profiles sorted by
    real-world breach frequency:
    - `[1]` Indian Mobile User — `%w@%Y` highest priority → produces `parv@2003` before `parv2003`
    - `[2]` Corporate Employee — `%T@%Y` first
    - `[3]` Student — `%w%Y` first
    - `[4]` General Consumer — statistically common breach patterns
    - `[5]` Custom — opens `pattern_menu()` directly
    - Reuses `_last_personal_fields` if a Strategy 4 session was already run (prompts Y/n).
    - Optional `tqdm` progress bar using `estimate_count()` per pattern.
  - **QoL post-gen prompts** (`_post_gen_prompts()`) — runs after every strategy that calls
    `_write_ordered()`:
    - Stats panel: candidate count, file path, size (KB/MB), estimated crack time @ 1 M h/s.
    - Top-10 preview: first 10 lines of the output file.
    - Optional dedup against an existing wordlist (`_dedup_against_existing()`).
    - Optional pipe-to-cracker: launches `cracker_menu()` immediately.

### Fixed
- Strategy 4 separator-year ordering bug: separator priority list `_P4_SEPS` now emits `@`
  (priority 95) before `.` (90) before `#` (88), so `parv@2003` appears before `parv.2003`
  and `parv#2003` in the output.

---

## [0.3.1] — 2026-06-08

### Added
- `modules/preflight.py`:
  - `SENTINEL_FILE` constant (`~/.wifi-auditor/.preflight_done`) — shared with `cli.py` so both agree on the single path.
  - `OPTIONAL_TOOLS` — extended with `reaver`, `wash`, `bully`, `cowpatty` (shown in the pre-flight table alongside hcxdumptool, hashcat, crunch, macchanger).
  - `TOOL_PACKAGES` dict — maps every tool name to its `apt` / `pacman` / `dnf` package name; `wash` correctly maps to `reaver` (ships in the same package on all distros).
  - `detect_package_manager()` — detects `apt-get`, `pacman`, `dnf`, or `yum` from PATH.
  - `auto_install_missing(statuses)` — deduplicates packages (e.g. `airmon-ng` + `airodump-ng` + `aireplay-ng` + `aircrack-ng` all map to one `aircrack-ng` install), runs the appropriate install command, reports success/failure per package.
  - `run_preflight()` signature updated — now returns `(bool, list[ToolStatus])` so callers can act on the results instead of only reading stdout.
  - `run_preflight_with_autofix()` — new main entry point: pass 1 (display table) → `auto_install_missing()` → pass 2 (confirm fixes) → write sentinel.

- `install.sh`:
  - `SENTINEL_FILE` bash variable — mirrors the Python constant.
  - `_PKG_INSTALL` variable — set inside each `install_*` function so `run_first_preflight` knows which install command to use.
  - `_ensure_tool(binary, install_cmd)` — checks PATH, installs if absent, warns on failure.
  - `run_first_preflight()` — called at the end of `main()`, after `create_launcher`:
    1. Calls `_ensure_tool` for `reaver`, `wash` (→ reaver pkg), `bully`, `cowpatty`, `hashcat`, `crunch`, `macchanger`.
    2. Sources the venv and runs `run_preflight_with_autofix()` via inline Python heredoc.
    3. Writes sentinel from bash (`touch`) as belt-and-suspenders backup.

- `wifi_auditor/cli.py`:
  - Imports `run_preflight_with_autofix`, `SENTINEL_FILE` from `modules.preflight`.
  - `_check_first_run()` — checks if `SENTINEL_FILE` exists; if absent, calls `run_preflight_with_autofix()` with a one-time warning; no-op on all subsequent launches.
  - `main()` — calls `_check_first_run()` right after `check_root()`, before `print_banner()`, only in interactive mode (not headless/auto).

### Flow summary

```
sudo ./install.sh  →  run_first_preflight()  →  sentinel written
sudo wifi-auditor  →  _check_first_run()  →  sentinel exists  →  instant start
sudo wifi-auditor  →  _check_first_run()  →  no sentinel  →  auto-preflight (first pip-only install)
sudo wifi-auditor --preflight  →  always fresh check, never writes sentinel
```

---

## [0.3.0] — 2026-06-08

### Added
- `modules/wps.py` — complete WPS attack module (741 lines):
  - `detect_wps_capability()` — passive 6-second `wash` scan on BSSID+channel, returns `{enabled, locked, version}`; called automatically after every target selection; no scope required.
  - `wps_menu()` — interactive menu with 4 modes + scope enforcement + `--fast` bypass support.
  - Mode 1 — **Pixie-Dust**: `reaver -K 1` or `bully --pixie`; offline nonce recovery; cracks vulnerable APs in <30 s.
  - Mode 2 — **Vendor PIN Spray**: OUI-matched vendor defaults (26 OUI entries) queued first, then 30 common PINs.
  - Mode 3 — **Full PIN Brute-Force**: all ~11,000 valid WPS PINs via reaver with configurable delay + lock-wait; reaver saves state to `/etc/reaver/` for resume.
  - Mode 4 — **Wash Scan**: passive WPS beacon discovery, shows locked/unlocked per AP, no scope required.
  - `_valid_wps_pin()` — WPS 8-digit Luhn-variant checksum validator.
  - `VENDOR_PINS` — 26 OUI entries → known default WPS PINs (Belkin, Tenda, TP-Link, D-Link, Netgear, Huawei, ZyXEL, Linksys, Asus, Buffalo, Motorola, Cisco).
  - `COMMON_PINS` — 30 most-cracked WPS PINs across all vendors.
  - Dual backend: auto-detects `reaver` vs `bully`; prompts if both installed.
  - WPS lock detection in real-time — aborts PIN spray and warns when AP-Lock bit is set.
  - Results saved to `results/wps_TIMESTAMP.txt` (mode, BSSID, PIN, PSK).

### Changed
- `modules/cracker.py` — complete rewrite, now 4 backends:
  - `[1] aircrack-ng` — dict attack, unchanged.
  - `[2] cowpatty` — PMK-cache optimised; `cowpatty -r cap -f wordlist -s SSID`; auto-prompts for SSID if not in session state.
  - `[3] hashcat dict` — GPU-accelerated; auto-calls `hcxpcapngtool` to convert `.cap → .hc22000`; graceful aircrack-ng fallback if `hcxtools` missing.
  - `[4] hashcat rules` — dict + rule mutations; searches `/usr/share/hashcat/rules/` (and 3 other paths) for `best64`, `d3ad0ne`, `dive`, `rockyou-30000`, `toggles1`; interactive picker shows rule line counts; custom path fallback.
  - PMKID sub-menu: hashcat-dict / hashcat-rules / aircrack fallback.
  - `cracker_menu(capture, wordlist, ssid="")` — SSID parameter added; passed automatically from session state in all call sites.
- `modules/scanner.py` — WPA3 SAE downgrade detection:
  - `classify_security()` returns `{security_tier, wpa3_downgrade_risk}`.
  - WPA3-only APs shown as green `WPA3-SAE`; transition-mode APs shown as yellow `WPA3/WPA2`.
  - `↓SAE` flag in scan table when AP advertises both WPA3 + WPA2 (transition mode = downgrade attack surface).
  - Column renamed from `ENCRYPTION` to `SECURITY`; footer explains `↓SAE`.
- `modules/sequencer.py` — WPS-aware attack scoring:
  - Reads `wps_enabled`, `wps_locked`, `wps_version` from target dict.
  - WPS unlocked: Pixie-Dust scored 95, PIN Spray scored 92 (above PMKID at 90).
  - WPS locked: Pixie-Dust added at score 70 (PIN attacks deprioritised — lock makes them futile).
  - Reasoning bullets in attack plan explain WPS detection result.
- `modules/handshake.py`:
  - `capture_handshake_menu(..., fast=False)` — new `fast` parameter.
  - `_enforce_scope_and_consent(..., fast=False)` — when `fast=True`, shows red warning panel and returns immediately (skips scope check + BSSID consent prompt).
- `modules/deauth.py`:
  - `deauth_menu(..., fast=False)` — same `fast` parameter pattern as `handshake.py`.
  - When `fast=True`: red "Fast Mode Active" panel replaces scope error + consent flow.
- `modules/banner.py`:
  - Main menu updated: added `[w] WPS Attack (Pixie-Dust / PIN spray / brute-force)` entry under a new `── WPS ──` section header.
- `wifi_auditor/cli.py`:
  - `--fast` argparse flag → sets `_FAST_MODE = True` globally; shows red Rich double-bordered warning panel at startup.
  - `[w]` / `[W]` menu keys mapped to new `action_wps()`.
  - `action_wps()` — calls `wps_menu()` with current interface + target + scope + fast flag.
  - SSID passed automatically to `cracker_menu()` at all call sites: `cracker_menu(cap, wl, ssid=target["ssid"])`.
  - `fast=_FAST_MODE` forwarded to `capture_handshake_menu`, `deauth_menu`, and `wps_menu` at every call site.
  - `action_scan()` — after target selection, calls `detect_wps_capability()` and stores result in target dict; sequencer sees WPS state.
  - `action_full_auto()` — Step 3 is WPS probe. WPS enabled + unlocked → takes WPS path (`wps_menu()`) and returns. WPS locked or absent → falls through to handshake path.

### Fixed
- SSID was not passed to `cracker_menu` in all call sites, causing `cowpatty` to always prompt for SSID interactively.

---

## [Unreleased]

### Added
- `modules/logger.py` — structured JSON-lines session logger; every audit run is recorded with timestamps and events.
- `modules/pmkid.py` — standalone PMKID hash extraction via `hcxpcapngtool` + hashcat mode-22000 cracking helper.
- `modules/reporter.py` — renders a dark-theme HTML penetration-test report from any session log file.
- `requirements.txt` — pinned Python dependencies (`colorama`, `tabulate`, `tqdm`).
- `.gitignore` — comprehensive ignore rules (captures, wordlists, results, venv, IDE artefacts).

---

## [0.2.0] — 2026-06-01

### Added
- `modules/wep.py` — full WEP cracking pipeline: ARP replay, fragmentation, ChopChop, and crack-existing-cap modes.
- IV threshold logic: first attempt at 10 k IVs, re-attempt every 5 k, give up at 150 k.

---

## [0.1.0] — 2026-05-28

### Added
- Initial public release.
- `wifi_auditor.py` — main menu-driven entry point with session state.
- `modules/banner.py` — ASCII banner, colour helpers.
- `modules/utils.py` — root check, dependency check, monitor-mode management.
- `modules/scanner.py` — `airodump-ng` wrapper + CSV parser.
- `modules/handshake.py` — passive / deauth / PMKID capture strategies.
- `modules/wordlist.py` — 10-strategy wordlist generation engine.
- `modules/cracker.py` — `aircrack-ng` / hashcat wrapper.
- `install.sh` — Debian/Ubuntu dependency installer.
- `README.md` — full project documentation.
