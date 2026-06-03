# Changelog

All notable changes to **WiFi Auditor** are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

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
