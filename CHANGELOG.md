# Changelog

All notable changes to **WiFi Auditor** are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

---

## [0.5.0] — 2026-06-15

### Fixed

- **Critical — WPS module unreachable via `wifi_auditor.py`** (`wifi_auditor.py`).
  `action_wps()` was only wired in `wifi_auditor/cli.py`; the legacy entry point
  had no `'w'`/`'W'` keys in its `ACTIONS` dict and never imported `modules/wps.py`.
  Added `from modules.wps import wps_menu, detect_wps_capability`, added `action_wps()`,
  and mapped `'w'`/`'W'` to it.

- **Critical — WPS probe never ran after scan** (`wifi_auditor.py`).
  `action_scan()` ended at `state['target'] = target` with no WPS capability check —
  so the Smart Sequencer always scored without WPS context.
  Added a `detect_wps_capability()` call after target selection; result is merged into
  the target dict and a status line is printed (`WPS v2.0 [unlocked]` / `WPS not detected`).
  Non-fatal: wrapped in `try/except` so a missing `wash` binary doesn't abort the scan.

- **Critical — Full Auto skipped WPS path entirely** (`wifi_auditor.py`).
  `action_full_auto()` went straight from scan to `capture_handshake` with no WPS branch.
  Inserted Step 3 (WPS probe) between scan and capture; if WPS is enabled and unlocked,
  the WPS path is taken and the function returns — otherwise falls through to the handshake
  pipeline. Step numbers in log messages updated accordingly (3/5 → 4/5 → 5/5).

- **Potential regression — `enable_monitor_mode` re-export verified** (`modules/utils.py`).
  Confirmed that `utils.py` re-exports `enable_monitor_mode`, `disable_monitor_mode`, and
  `kill_interfering_processes` from `modules.interface` (the fixed implementation added in
  v0.4.2). The old broken regex (`\[\S+\]\S+`) is no longer present in the active code path.

- **`import traceback` inside `except` block** (`wifi_auditor.py`).
  Moved to the module-level import block alongside `os`, `sys`, `signal`.

- **`_cleanup()` silently swallowed `disable_monitor_mode` exceptions** (`wifi_auditor.py`,
  `wifi_auditor/cli.py`). `except Exception: pass` replaced with a `stderr` print that
  includes the interface name and the manual recovery command
  (`sudo airmon-ng stop <iface>`).

### Changed

- **`wifi_auditor.py` consolidated into a thin delegation shim.**
  The 299-line flat script (plain `dict` state, no scope enforcement, ~v0.1.0 features)
  is replaced with an 18-line shim that imports and calls `wifi_auditor.cli.main()`.
  `python3 wifi_auditor.py` continues to work identically. All features — StateManager,
  `--fast`, `--headless`, `--preflight`, `--scope-wizard`, `--check-interface`, SSID
  passthrough, SIGHUP handling — are now available via both entry points.

- **SIGHUP handler added** (`wifi_auditor/cli.py`).
  `signal.signal(signal.SIGHUP, _signal_handler)` added alongside SIGINT and SIGTERM.
  SSH sessions that disconnect now cleanly disable monitor mode before exit.

- **`pyproject.toml` is now the single source of truth for dependencies.**
  `requirements.txt` is retained as the install-time file but `pyproject.toml`'s
  `[project.dependencies]` reads from it via `dynamic = ["dependencies"]` +
  `[tool.setuptools.dynamic]`. Version pins between the two files can no longer drift.

- **`__version__ = "0.5.0"` exported from `wifi_auditor/__init__.py`.**
  All previous launches that called `from wifi_auditor import __version__` would raise
  `ImportError`; they now resolve correctly. The banner hardcodes the string as a
  `__version__` import rather than a literal.

- **`--version` CLI flag added** (`wifi_auditor/cli.py`).
  `parser.add_argument('--version', action='version', version=f'wifi-auditor {__version__}')`.
  The flag works without root (check runs before `check_root()`).

- **`data/router_defaults.yaml` — metadata header added.**
  Prepended `schema_version: 1`, `last_updated: "2026-06-15"`, and `sources:` block.
  Each vendor entry now has a documented `oui_prefixes` + `default_passwords` schema.

### Added

- **`.github/workflows/ci.yml`** — GitHub Actions CI workflow.
  Runs on every push and PR to `main`. Matrix: Python 3.10 / 3.11 / 3.12.
  Steps: `pip install -r requirements.txt -r requirements-dev.txt` → `ruff check .`
  → `mypy modules/ wifi_auditor/ --ignore-missing-imports` → `pytest tests/ -v --tb=short`.

- **`scope.yaml.example`** — template for the authorization file.
  `scope.yaml` itself is now gitignored (was previously committed to the repo, risking
  leakage of real target BSSIDs and authorization data). Users `cp scope.yaml.example scope.yaml`
  and fill in their details, or run `wifi-auditor --scope-wizard`.

- **`.gitkeep` files** in `captures/`, `wordlists/`, `results/`.
  Git does not track empty directories. A fresh clone now includes the expected output
  directories, preventing `FileNotFoundError` on first use. `.gitignore` updated with
  negation rules (`captures/*` / `!captures/.gitkeep`, etc.).

- **`SECURITY.md`** — responsible disclosure policy.
  Covers: scope (vulnerabilities in the tool itself), reporting channel, response timeline
  (48 h acknowledge / 7 d assess / 30 d fix / disclose after fix), and a note clarifying
  that security research on wifi_down itself is welcome.

- **`CONTRIBUTING.md`** — contributor onboarding guide.
  Covers: dev setup (venv → pip install → pytest → ruff), branch naming conventions,
  commit message style, PR checklist, and instructions for adding a new attack module.

- **`tests/test_banner.py`** — banner smoke test suite.
  Three tests: `test_print_banner_does_not_raise()` (patches `input()` and `sys.stdout`);
  `test_print_menu_does_not_raise()` (empty state + full state); `test_color_constants_exist()`
  (asserts `C.RED`, `C.GREEN`, `C.YELLOW`, `C.CYAN`, `C.WHITE`, `C.RESET`, `C.BOLD`, `C.DIM`
  are non-None strings). `modules/banner.py` marked FROZEN at v0.4.6 with a header comment.

- **`tests/test_router_defaults.py`** — schema validation for `data/router_defaults.yaml`.
  Four tests: YAML loads without error; `schema_version` present and is `int`;
  `last_updated` present; every vendor entry has a non-empty `default_passwords` list.

- **`tests/test_version.py`** — `__version__` export sanity check.
  Asserts `wifi_auditor.__version__` is a non-empty string and not the fallback `"0.0.0-dev"`.

---

## [0.4.6] — 2026-06-11

### Changed

- `modules/banner.py` — complete rewrite; typewriter-first, pure ANSI, no `rich.live.Live`
  or `rich.panel.Panel`:

  **Removed:** `MADE_BY_ART` constant, `_print_made_by_art()`, `_build_static_banner`,
  `_build_separator`, `_build_tagline`, `_build_status`, `_render_frame`,
  `_compact_banner`, `_noise_row_text`, `_art_row_partial`, all phase-based
  `rich.live.Live` animation, `_pulsing_enter_prompt`, old `_print_quotes` (3-quote),
  old `_print_disclaimer` (Rich Panel), `rich.live.Live` + `rich.panel.Panel` imports.

  **Added:** `typewrite(text, style, delay, newline)` — reusable char-by-char printer;
  `_ansi(style_str)` — converts space-separated Rich-style tokens to ANSI escape;
  `_print_art()` — scan-line reveal with tri-zone gradient;
  `_print_made_by()` — right-aligned Devanagari credit line with ASCII fallback;
  `_print_quote(author, quote)` — single random quote with `❝`/`❞` wrapping;
  `_print_disclaimer()` — plain typewriter legal notice (no Panel);
  `_print_status(iface, scope, ts)` — segment-by-segment ANSI typewriter;
  `_print_enter_prompt()` — typewriter + 3 pulse cycles + `input("")` wait.

---

## [0.4.5] — 2026-06-11

### Changed

- `modules/banner.py` — launch experience overhaul:
  - `_print_made_by_art()` — large 6-row block-letter `MADE BY` art with pink/light-pink
    gradient; `ॐ अ मी ॐ` in Devanagari with ASCII fallback.
  - `_print_quotes(num=3)` — 3 random entries from a 10-quote pool, 5 ms/char ANSI italic.
  - `_print_disclaimer()` — red-bordered Rich `Panel` listing CFAA, UK CMA, India IT Act 2000,
    and HMAC audit trail notice.
  - `_pulsing_enter_prompt()` — pulses `[ Press ENTER to continue ]` through 3 colour cycles.
  - `print_compact_header(interface=None)` — one-line dim-cyan header for menu loop.
  - `print_banner()` calls `_print_made_by_art()` → `_print_quotes(3)` → `_print_disclaimer()`
    → `_pulsing_enter_prompt()`.
- `wifi_auditor/cli.py` — compact header wired into menu loop; `action_capture()` and
  `action_full_auto()` / `run_headless()` store `handshake_file` in `_sm.transition()`.

---

## [0.4.4] — 2026-06-11

### Changed

- `modules/handshake.py` — complete rewrite; three-engine parallel architecture:
  - **Engine 1** — airodump-ng file watcher: polls `.cap` every 0.5 s; verifies with
    aircrack-ng, cowpatty, and tshark.
  - **Engine 2** — scapy AsyncSniffer: captures EAPOL frames in-memory; BPF
    `ether proto 0x888e`; zero disk dependency.
  - **Engine 3** — hcxdumptool PMKID: runs passively from start; checks for valid
    `.hc22000` every 2 s; `--disable_deauthentication` keeps it passive.
  - Verification: `_verify_aircrack`, `_verify_cowpatty`, `_verify_tshark` (≥2 EAPOL frames).
  - Deauth: channel locked with both `iw dev` and `iwconfig`; Phase 1 — 10 targeted
    unicast × 5 pkts (top-2 clients, both directions); Phase 2 — 5 broadcast × 10 pkts;
    Phase 3 — PMKID wait 90 s. Handshake watch ticks every 0.3 s.
  - Backward-compatibility aliases retained for existing callers.

---

## [0.4.3] — 2026-06-10

### Changed

- `modules/handshake.py` — full rewrite of Strategy 2 deauth pipeline:
  - `discover_clients()` — parses airodump-ng CSV Station section, sorted by signal.
  - `send_targeted_deauth()` — both directions (AP→Client and Client→AP) with per-client
    rate-limiter key.
  - `send_broadcast_deauth_fallback()` — kept for no-clients-found case.
  - Attempt budget: `max(3, timeout // 28)`.
- `modules/ratelimit.py` — per-client bucket keying via
  `_key(bssid, client_mac=None)` static method.

---

## [0.4.2] — 2026-06-10

### Fixed

- **Critical — `enable_monitor_mode` never matched on real airmon-ng output**
  (`modules/utils.py`). Pattern `\[\S+\]\S+` required a non-space char immediately
  after `]`, but real output has a space: `monitor mode vif enabled for [wlan0] on [wlan0mon]`.
  The no-op guess fallback `interface.replace('wlan', 'wlan')` also never changed the name.

### Added

- `modules/interface.py` (~199 lines): 5 correct regex patterns for all real-world
  airmon-ng output variants; `kill_interfering_processes()` with systemctl + pkill;
  `verify_monitor_mode(interface)`; `get_wireless_interfaces()` / `get_monitor_interfaces()`;
  verbose `RuntimeError` on failure (command, return code, stdout, stderr, interface list).

### Changed

- `modules/utils.py` — old broken implementations replaced with re-exports from
  `modules.interface`.
- `wifi_auditor/cli.py` — `action_set_interface()` and `run_headless()` catch
  `RuntimeError` and display full diagnostic; `--check-interface` CLI flag added.

---

## [0.4.1] — 2026-06-10

### Changed

- `modules/banner.py` — full rewrite:
  - UTF-8 shim via `_make_console()`; `अमी` renders correctly on any Linux terminal.
  - `WIFI_DOWN_ART` hardcoded (6-row, never regenerated at runtime).
  - 256-colour palette (15 `Style` objects).
  - `_color_art_row()` — L/M/R tri-zone gradient + corner accent.
  - `print_banner()` — 5-phase `rich.live.Live` animation at 120 fps.
  - Status bar with `◈` diamonds, live timestamp, scope detection.

---

## [0.4.0] — 2026-06-09

### Added

- `modules/pattern_engine.py` (~424 lines) — self-contained pattern expansion engine:
  - Token reference: `%W/%w/%U/%T`, `%L/%r`, `%Y/%y`, `%D/%d/%m`, `%N`, `%s/%S/%k`,
    `%n/%2/%4`, `[abc]`, `{text}`.
  - `PatternContext`, `build_context()`, `tokenize_pattern()`, `expand_segment()`,
    `expand_pattern()` (Cartesian-product generator), `estimate_count()`, `preview_pattern()`.
  - `pattern_menu()` — interactive builder with token help, save/load/delete, count estimate,
    500k warning, optional `tqdm` progress bar.
  - `load_saved_patterns()` / `save_pattern()` / `delete_pattern()` — JSON persistence at
    `~/.wifi-auditor/custom_patterns.json`.

- `modules/wordlist.py` — complete rebuild (~1,031 lines):
  - Strategy 4 (Personal Info) — 13 fields, 10 mutation families in probability order.
  - Strategy 13 (Custom Pattern Builder) — delegates to `pattern_engine.pattern_menu()`.
  - Strategy 14 (Smart Scenario Engine) — 5 profiles sorted by real-world breach frequency.
  - `_post_gen_prompts()` — stats panel, top-10 preview, optional dedup, optional
    pipe-to-cracker.

### Fixed

- Strategy 4 separator-year ordering bug: `@` (95) now emits before `.` (90) before `#` (88).

---

## [0.3.1] — 2026-06-08

### Added

- `modules/preflight.py` — `OPTIONAL_TOOLS` extended with `reaver`, `wash`, `bully`,
  `cowpatty`; `TOOL_PACKAGES` dict mapping every tool to its distro package name
  (`wash` → `reaver`); `detect_package_manager()`; `auto_install_missing()` with
  deduplication; `run_preflight_with_autofix()` two-pass entry point.
- `install.sh` — `_ensure_tool`, `run_first_preflight()`, sentinel write from bash.
- `wifi_auditor/cli.py` — `_check_first_run()` sentinel guard; `main()` calls it after
  `check_root()`, only in interactive mode.

---

## [0.3.0] — 2026-06-08

### Added

- `modules/wps.py` (~741 lines) — full WPS attack module:
  - `detect_wps_capability()` — passive 6-second wash scan; returns `{enabled, locked, version}`.
  - Mode 1 — Pixie-Dust (`reaver -K 1` or `bully --pixie`).
  - Mode 2 — Vendor PIN Spray (26 OUI entries → vendor defaults + 30 common PINs).
  - Mode 3 — Full PIN Brute-Force (~11,000 PINs, resumable reaver state).
  - Mode 4 — Wash Scan (passive discovery only).
  - `_valid_wps_pin()` — Luhn-variant 8-digit checksum validator.
  - Dual backend: auto-detects `reaver` vs `bully`.
  - WPS lock detection in real-time.
  - Results saved to `results/wps_TIMESTAMP.txt`.

### Changed

- `modules/cracker.py` — 4 backends: aircrack-ng / cowpatty / hashcat dict / hashcat rules.
- `modules/scanner.py` — WPA3 SAE downgrade detection; `↓SAE` flag in scan table.
- `modules/sequencer.py` — WPS-aware scoring (Pixie-Dust 95, PIN Spray 92, locked 70).
- `modules/handshake.py` + `modules/deauth.py` — `fast=False` parameter added.
- `wifi_auditor/cli.py` — `--fast` flag; `[w]`/`[W]` keys; `action_wps()`; SSID passed
  to `cracker_menu()` at all call sites; WPS probe in `action_scan()` and `action_full_auto()`.

### Fixed

- SSID not passed to `cracker_menu()` at all call sites — `cowpatty` always prompted
  interactively.

---

## [0.2.0] — 2026-06-01

### Added

- `modules/wep.py` — full WEP cracking pipeline: ARP replay, fragmentation, ChopChop,
  crack-existing-cap modes. IV threshold logic: first attempt at 10k IVs, re-attempt every 5k,
  give up at 150k.

---

## [0.1.0] — 2026-05-28

### Added

- Initial public release.
- `wifi_auditor.py` — menu-driven entry point with session state.
- `modules/banner.py`, `utils.py`, `scanner.py`, `handshake.py`, `wordlist.py`,
  `cracker.py` — core pipeline.
- `install.sh` — Debian/Ubuntu dependency installer.
- `README.md` — full project documentation.
