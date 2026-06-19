# Changelog

All notable changes to **WiFi Auditor** are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

---

## [0.8.0] — 2026-06-19

### Fixed — 7 surviving bugs in the post-v0.7.0 handshake pipeline

**Surviving Bug 1 — `AsyncSniffer` blocks on `.stop()` — sniffer thread never exits cleanly**
- `modules/handshake.py` (`_scapy_sniffer_thread`): switched from `sniff()` with `stop_filter`
  to `AsyncSniffer`. `AsyncSniffer.stop(join=True)` is called from the main thread after
  `stop_ev` is set — this takes effect immediately without waiting for the next packet.
  Old `sniff(stop_filter=...)` polled the stop condition only when a packet arrived;
  on quiet networks the thread hung indefinitely after capture succeeded.

**Surviving Bug 2 — `aireplay-ng` fights `airodump-ng` for channel ownership**
- `modules/handshake.py` (`_deauth_targeted`, `_deauth_broadcast`): `-D` flag
  (`--disable_deauthentication` channel lock inside aireplay-ng) added to every
  `aireplay-ng -0` invocation. Without `-D`, aireplay-ng tries to lock the channel
  itself, conflicting with the running airodump-ng and producing `channel -1` errors
  that cause deauth frames to be sent on the wrong channel or not at all.
  `-x 1000` (burst rate) also added to ensure all frames fire quickly.

**Surviving Bug 3 — hcxdumptool `--filterlist_ap` format — BSSID must NOT contain colons**
- `modules/handshake.py` (`_run_pmkid_phase`): BSSID filter file is now written as
  `aabbcc112233` (lowercase, no colons). hcxdumptool's `--filterlist_ap` expects the
  colon-free hex format; writing `aa:bb:cc:11:22:33` caused it to match nothing and
  capture all traffic indiscriminately, ignoring the target filter entirely.

**Surviving Bug 4 — `verify_handshake` called on every loop tick — CPU thrash + false negatives**
- `modules/handshake.py` (`capture_handshake`): `VERIFY_INTERVAL = 3.0` constant
  introduced. `verify_handshake()` is now rate-limited: only called if
  `time.time() - last_verify_time >= VERIFY_INTERVAL`. Old code called it on every
  2-second CSV poll, running multiple expensive aircrack-ng / tshark subprocesses
  per deauth round, sometimes consuming I/O bandwidth needed by airodump-ng.

**Surviving Bug 5 — too few deauth frames + too short wait window → AP ignores deauth**
- `modules/handshake.py` (`capture_handshake`): targeted deauth now sends `count=64`
  frames per client (was 8–10) and the wait window after each burst is 12 seconds
  (4 × 3 s sleeps). Modern APs and congested 2.4 GHz environments drop most deauth
  frames; 64 frames with -x 1000 ensures enough survive to force a reassociation.

**Surviving Bug 6 — early exit from reassoc window**
- `modules/handshake.py` (`capture_handshake`): The old inner loop had a `break` after the first "not yet" check, meaning the 5-second window effectively collapsed to 1 second of actual listening. The client reconnects in 1-3 seconds but the handshake exchange itself takes another second or two — we were bailing before it completed.
- `REASSOC_WAIT` increased from 5s to 30s. The full sequence after deauth is: client notices disconnect (~0.5s) → client scans/probes → AP responds → 4-way handshake exchange. On a real network with retries and congestion this easily takes 5-15 seconds, so 5s was far too tight. 30 seconds gives the whole cycle room to breathe. Cycle at 10 packets, 30s window. If the client doesn't reconnect in that window, the next burst fires immediately and the cycle repeats.

**Architectural fix — two separate airodump-ng instances caused a capture gap**
- `modules/handshake.py` (`capture_handshake`): **one** airodump-ng instance now
  writes both `-01.cap` and `-01.csv` simultaneously by omitting `--output-format`.
  Previous architecture used a separate `client_scanner.scan_clients()` call (its own
  airodump-ng process) that had to terminate before the cap-capture process started,
  leaving a window where no frames were captured. The single-instance approach
  eliminates this gap: client discovery reads the live CSV while capture is already
  running via `_parse_clients_from_csv()`.

### Changed

- **`modules/client_scanner.py` deleted** — all functionality merged into
  `modules/handshake.py`:
  - `WifiClient` dataclass (slimmed to `mac`, `power`, `packets` + `signal_label`
    property) lives in `handshake.py`.
  - `_parse_clients_from_csv(csv_path, target_bssid)` replaces the old
    `_parse_airodump_csv`; backward-compat alias `_parse_airodump_csv` preserved.
  - `_find_csv_file(prefix)` added alongside existing `_find_cap_file`.
  - `lock_channel_verified` backward-compat alias for `_lock_channel` preserved.

- **`tests/test_handshake.py`** — 6 new test classes added (total: 14 classes):
  - `TestScapyStopFix` — verifies `stop_event` path through `_scapy_sniffer_thread`.
  - `TestHcxdumptoolFilterFormat` — asserts filter file written without colons;
    `_run_pmkid_phase` integration test.
  - `TestSingleAirodumpInstance` — confirms airodump command omits `--output-format`;
    CSV parsed while airodump is still running.
  - `TestVerifyRateLimit` — verifies `VERIFY_INTERVAL >= 3.0` and `count=64` are
    present in `capture_handshake` source.
  - Import path updated: `from modules.handshake import _parse_clients_from_csv as
    _parse_airodump_csv, WifiClient` (old `modules.client_scanner` import removed).
  - `WifiClient` constructor calls updated to keyword-only `mac=`, `power=`, `packets=`
    (3-field dataclass vs old 6-field); `signal_display` → `signal_label`.

  - **Deauth burst and wait architecture**:
    - Added `_deauth_burst_parallel(iface, bssid, client_macs, count)` — sends exactly N deauth frames to each target client simultaneously using `--deauth N`, then blocks until all aireplay-ng processes exit. This replaces the `--deauth 0` (infinite) pattern.
    - Added `deauth_count: int = 10` parameter to `capture_handshake()`.
    - Phase 2 and Phase 3 (broadcast fallback) now use a burst-and-wait pattern: burst N packets (~0.1s), wait 5 seconds of silence to allow client reassociation, verify the cap file, then repeat until phase time expires.
    - Removed `aireplay_procs` tracking since deauth processes now exit naturally after each burst.
    - Kept `_start_deauth` as a backward-compat export so test imports continue to work.

- **`wifi_auditor/cli.py`**:
  - `action_capture()` now prompts for `Deauth packets per burst [10]:` before starting capture and passes the answer to `capture_handshake()`.

---

## [0.7.0] — 2026-06-19

### Fixed — 11 confirmed bugs in handshake capture pipeline

**Bug 1 — airodump writes `prefix-01.cap` not `prefix.cap` (`_find_cap_file`)**
- `modules/handshake.py`: `_find_cap_file()` now uses `glob(prefix + '-*.cap')` and returns
  `max(..., key=os.path.getmtime)`. Old code used `prefix + '.cap'` which airodump-ng never
  creates — cap file was never found, verification always failed.

**Bug 2 — missing `--write-interval 1` — cap file never flushed**
- `modules/handshake.py` (`_launch_airodump`) and `modules/client_scanner.py` (`scan_clients`):
  `--write-interval 1` added to every airodump-ng invocation so the output file is flushed to
  disk every second instead of at process exit.

**Bug 3 — missing `-a` flag — client list flooded with unassociated stations**
- `modules/client_scanner.py` (`scan_clients`): `-a` flag added to airodump-ng command.
  Without it the Station section includes every device that ever sent a probe request,
  making the client list unusable for targeted deauth.

**Bug 4 — null bytes in CSV crash `csv.reader`**
- `modules/client_scanner.py` (`_parse_airodump_csv`): file is read with `errors='replace'`
  then each line has `line.replace('\0', '')` applied before passing to `csv.reader`.
  Null bytes inside CSV records caused `csv.reader` to raise or silently corrupt rows.

**Bug 5 — first client row silently dropped**
- `modules/client_scanner.py` (`_parse_airodump_csv`): `hit_clients` flag is set to `True`
  *before* the `continue` that skips the `Station MAC` header row.
  Old code set the flag after `continue`, meaning `hit_clients` was never `True` when
  the first data row was evaluated and it was always skipped.

**Bug 6 — BSSID comparison fails on whitespace**
- `modules/client_scanner.py` (`_parse_airodump_csv`): every field in each CSV row is
  `.strip()`-ped before use. airodump-ng surrounds most fields with leading/trailing spaces;
  without stripping, `assoc_bssid != target_bssid.upper()` was always `True`.

**Bug 7 — aireplay-ng "direction 2" wrong — use scapy for Client→AP deauth**
- `modules/handshake.py` (`_send_deauth_burst`): the second deauth direction is now sent
  as a raw scapy frame (`Dot11Deauth` with `addr1=BSSID, addr2=CLIENT, addr3=BSSID`).
  Old code swapped `-a` and `-c` args which produced a mangled frame the kernel rejected.

**Bug 8 — BPF filter unreliable in monitor mode — switch to `lfilter`**
- `modules/handshake.py` (`_scapy_eapol_sniffer`): scapy `sniff()` now uses
  `lfilter=lambda p: p.haslayer(EAPOL)` instead of `filter='ether proto 0x888e'`.
  In monitor mode RadioTap encapsulation shifts byte offsets so the BPF string filter
  matches nothing on most drivers; Python-level `lfilter` is 100% reliable.

**Bug 9 — hcxdumptool + airodump-ng on same interface simultaneously**
- `modules/handshake.py` (`capture_handshake`): airodump-ng is fully terminated and the
  interface is given 1 s to settle before `_run_hcxdumptool_pmkid()` is called.
  Old code spawned hcxdumptool while airodump-ng was still running, causing both tools
  to fight for exclusive interface access and neither to capture anything.

**Bug 10 — tshark counted any 2 EAPOL frames as a valid handshake**
- `modules/handshake.py` (`verify_handshake`, all three methods): verification now checks
  EAPOL Key Information field bits to classify each frame as M1/M2/M3/M4 and requires
  either M1+M2 or M2+M3 to be present before declaring success. Old tshark method
  counted raw EAPOL frame count ≥ 2 which returned true for any EAP exchange including
  incomplete ones that hashcat/aircrack-ng cannot crack.

**Bug 11 — channel lock never verified**
- `modules/handshake.py` (`lock_channel_verified`): after setting the channel via
  `iw dev set channel` + `iwconfig channel`, the function reads back `iw dev info` and
  confirms the reported channel matches the requested one. Retries up to 3 times.
  Old code assumed the set command succeeded and never verified, causing the interface
  to silently capture on the wrong channel.

### Added

- **`modules/client_scanner.py`** — new dedicated, independently testable module:
  - `WifiClient` dataclass — `mac`, `bssid`, `power`, `packets`, `first_seen`,
    `last_seen` fields; `signal_display` property (excellent/good/fair/weak).
  - `scan_clients(bssid, channel, monitor_interface, duration, verbose)` — runs
    airodump-ng with `-a --write-interval 1 --output-format csv` and returns a
    `List[WifiClient]` sorted by signal strength (strongest first), deduplicated by MAC.
  - `_parse_airodump_csv(csv_path, target_bssid)` — parser implementing Bug 3–6 fixes;
    handles null bytes, whitespace, not-associated markers, wrong-BSSID entries, and
    the first-row drop bug.
  - `display_clients(clients, bssid)` — formatted table output.

- **`tests/test_handshake.py`** — 8 regression test classes covering all 11 bugs:
  - `TestCSVParsing` — 8 parameterised cases covering Bugs 3–6
    (null bytes, not-associated, wrong BSSID, first-row drop, whitespace, missing file,
    deduplication, signal sort order).
  - `TestWifiClientSignalDisplay` — 4 cases for `signal_display` property.
  - `TestVerifyHandshake` — 4 cases covering Bug 10 (aircrack 0-handshake rejection,
    1-handshake acceptance, too-small file, missing file).
  - `TestCapFileFinding` — 4 cases covering Bug 1 (numbered glob, none, unprefixed,
    most-recent).
  - `TestLockChannelVerified` — 2 cases covering Bug 11 (confirmed, mismatch).

### Changed

- `wifi_auditor/cli.py` — all `capture_handshake()` call sites unchanged (same
  signature); `modules.client_scanner` imported inside `capture_handshake()` to keep
  the public API stable. No CLI flag changes required.

---

## [0.6.0] — 2026-06-15

### Removed

- **scope.yaml enforcement system removed entirely.**
  Deleted `modules/scope.py`, `tests/test_scope.py`.
  Removed `ScopeManager`, `ScopeError`, consent prompts, per-BSSID authorization gates,
  6-point wizard (`--scope-wizard`), `--scope` / `--fast` / `--verify-log`
  CLI flags, and HMAC-chained audit log (`chain.json`).
  All `scope` and `fast` parameters removed from `deauth`, `handshake`,
  `pmkid`, `wep`, and `wps` module function signatures.
  `ScopeError` removed from `modules/exceptions.py`.

### Added

- Single plain-text legal notice printed once at startup via
  `_print_disclaimer()` in `modules/banner.py`. Replaces all enforcement
  with a one-time disclaimer.

### Changed

- All action functions in `wifi_auditor/cli.py` call module functions
  directly with no scope arguments.
- `modules/banner.py`: removed `_get_scope()` helper and `scope` segment
  from the startup status line.

---

## [0.4.6] — 2026-06-11

### Changed

- `modules/banner.py` — complete rewrite; typewriter-first, pure ANSI, no
  `rich.live.Live` or `rich.panel.Panel`:

  **Removed:**
  - `MADE_BY_ART` constant and old `_print_made_by_art()` (centered block-letter art)
  - `_build_static_banner`, `_build_separator`, `_build_tagline`, `_build_status`,
    `_render_frame` (Live-based banner assembly helpers)
  - `_compact_banner`, `_noise_row_text`, `_art_row_partial` (noise-border animation)
  - All phase-based `rich.live.Live` animation (phases 1–5 outer box sweep)
  - Old `_pulsing_enter_prompt` (replaced by `_print_enter_prompt`)
  - Old `_print_quotes` (3-quote display → now 1 random quote via `_print_quote`)
  - Old `_print_disclaimer` (Rich `Panel` version → plain typewriter lines)
  - `rich.live.Live` and `rich.panel.Panel` imports

  **Added:**
  - `typewrite(text, style, delay, newline)` — reusable char-by-char printer;
    converts `style` with `_ansi()`, writes each char with `sys.stdout.write`,
    flushes after every character.
  - `_ansi(style_str)` — converts space-separated Rich-style tokens
    (`bold`, `dim`, `italic`, `color(N)`) to a single ANSI escape sequence.
  - `_print_art()` — scan-line reveal of `WIFI_DOWN_ART`; 0.04 s delay between
    rows; tri-zone gradient (`color(51/87/50)`) + `color(45)` corner accent via
    `_color_row()`.
  - `_print_made_by()` — right-aligned `── made by  अ म ी  ──` (Devanagari with
    spaces between aksharas); char-by-char at 0.04 s/char; `"A m i"` ASCII
    fallback on `UnicodeEncodeError`.
  - `_print_quote(author, quote)` — single random quote selected by caller;
    separator `─` lines, `❝` / `❞` wrapping, `color(252) italic` typewriter at
    0.022 s/char, `color(87) bold` attribution at 0.035 s/char.
  - `_print_disclaimer()` — plain typewriter lines (no Panel); `color(196) bold`
    header + 4 `color(252)` body lines at 0.015 s/char; bounded by `─` separators.
  - `_print_status(iface, scope, ts)` — segment-by-segment ANSI typewriter at
    0.012 s/char; `color(51)` `◈` diamonds, `color(240) dim` labels,
    `color(87) bold` values.
  - `_print_enter_prompt()` — typewriter at 0.045 s/char → 3 full pulse cycles
    of `color(51)→87→123→87→51` at 150 ms per step (5 colors × 3 cycles = 15
    transitions) → `input("")` wait → `console.clear()` after Enter.

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
