# Changelog

All notable changes to **WiFi Auditor** are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

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
