# WiFi Auditor



Automated WiFi security auditing framework. Menu-driven, end-to-end pipeline:
**scan → WPS probe → WPS attack / handshake capture → wordlist → crack → report.**

> **LEGAL NOTICE** — Use **only** on networks you own or have explicit **written permission** to test.
> Unauthorized access is a criminal offence (CFAA, UK Computer Misuse Act, India IT Act 2000).
> The authors accept **no liability** for misuse.

---

## Features

| Stage                  | What it does                                                                                    |
| ---------------------- | ----------------------------------------------------------------------------------------------- |
| **Scanner**            | Monitor-mode scan via `airodump-ng` — SSID entropy + vendor tags + WPA3 downgrade detection     |
| **WPS Attacks**        | Pixie-Dust / Vendor PIN spray (OUI-matched, 26 vendors) / Full brute-force / Wash scan          |
| **Handshake Capture**  | Passive / deauth / PMKID — three parallel engines, scope-gated, consent-prompted                |
| **Wordlist Generator** | 14 strategies — vendor defaults, CUPP-style personal profiling, custom pattern builder          |
| **Cracker**            | `aircrack-ng` + `cowpatty` + `hashcat` dict + `hashcat` rule-based (best64, d3ad0ne, dive…)     |
| **WEP Cracker**        | ARP replay / fragmentation / ChopChop pipelines                                                 |
| **Deauth Attack**      | Rate-limited (token bucket), consent-required, scope-enforced                                   |
| **Smart Sequencer**    | WPS-aware ranking: WPS unlocked → 95, PMKID → 90, deauth → 75                                   |
| **Full Auto Mode**     | Scan → WPS probe → WPS path OR handshake path → wordlist → crack (unattended)                   |
| **Pentest Reports**    | Markdown + JSON + HTML, SHA-256 evidence hashes, HMAC-chained audit log                         |

---

## Quick Start

```bash
git clone https://github.com/amibhai/wifi_down.git
cd wifi_down
sudo ./install.sh             # detects OS, installs deps, creates venv
sudo wifi-auditor --preflight # verify everything is ready
sudo wifi-auditor --version   # confirm version
sudo wifi-auditor             # launch interactive menu
```

---

## Installation

### Automated (recommended)

```bash
sudo ./install.sh
```

The script auto-detects your OS and uses the correct package manager:

| OS                                   | Package manager                       |
| ------------------------------------ | ------------------------------------- |
| Kali / Parrot / Ubuntu 22+ / Debian  | `apt`                                 |
| Arch / Manjaro                       | `pacman` (+ AUR warning for hcxtools) |
| Fedora / RHEL / Rocky                | `dnf` (hcxdumptool built from source) |

After install, a Python venv is created at `~/.wifi-auditor/venv` and a launcher
at `/usr/local/bin/wifi-auditor`.

`install.sh` also runs `run_first_preflight()` which:
1. Calls `_ensure_tool` for every optional binary (`reaver`, `wash`, `bully`, `cowpatty`, `hashcat`, `crunch`, `macchanger`) — installing any that are missing.
2. Sources the venv and runs `run_preflight_with_autofix()` (two-pass: show table → auto-install → re-show table).
3. Writes the sentinel `~/.wifi-auditor/.preflight_done` (both bash and Python — belt-and-suspenders).

### Manual

```bash
sudo apt-get install aircrack-ng hcxdumptool hcxtools hashcat crunch \
     macchanger iw reaver bully wash cowpatty
pip install -r requirements.txt
```

> If you skip `install.sh`, the sentinel will be absent. The **first** `sudo wifi-auditor`
> launch auto-runs `run_preflight_with_autofix()`. All subsequent starts are instant.

---

## Auto-Setup & First-Run Flow

WiFi Auditor uses a sentinel file (`~/.wifi-auditor/.preflight_done`) to ensure the full
dependency check runs **exactly once** — either at the end of `install.sh` or on the very
first manual launch — and never again slows startup.

```
sudo ./install.sh
  ├─ apt/pacman/dnf: install core packages
  ├─ setup Python venv + pip install
  ├─ create /usr/local/bin/wifi-auditor
  └─ run_first_preflight()
       ├─ _ensure_tool reaver / wash / bully / cowpatty / ...
       │    └─ if missing → install automatically
       ├─ source venv → run_preflight_with_autofix()
       │    ├─ Pass 1: display full dependency table
       │    ├─ auto_install_missing() → installs anything still absent
       │    ├─ Pass 2: re-display table confirming everything fixed
       │    └─ write ~/.wifi-auditor/.preflight_done
       └─ sentinel also written by bash (belt-and-suspenders)

Next launch:  sudo wifi-auditor
  ├─ check_root()
  ├─ _check_first_run()  →  sentinel exists  →  returns immediately (no-op)
  ├─ check_dependencies()
  └─ print_banner() → menu

Manual install (no install.sh):
  First sudo wifi-auditor
  ├─ _check_first_run()  →  no sentinel
  ├─ run_preflight_with_autofix()  (same two-pass flow)
  └─ sentinel written → all future starts instant

Manual re-check at any time:
  sudo wifi-auditor --preflight   ← always works, never writes sentinel
```

### Sentinel details

| Path                        | `~/.wifi-auditor/.preflight_done`                                                       |
| --------------------------- | --------------------------------------------------------------------------------------- |
| Created by                  | `install.sh` (bash `touch`) AND `run_preflight_with_autofix()` (Python `Path.touch()`) |
| Effect when present         | `_check_first_run()` in `cli.py` returns immediately                                    |
| Delete to re-trigger        | `rm ~/.wifi-auditor/.preflight_done` then `sudo wifi-auditor`                           |
| Does `--preflight` write it?| **No** — `--preflight` is always a fresh check                                          |

---

## Docker

```bash
# Build (Kali base)
docker build -t wifi-auditor .

# Interactive menu
sudo ./docker-run.sh

# Headless mode
sudo ./docker-run.sh --headless --scope scope.yaml \
     --target AA:BB:CC:DD:EE:FF --auto
```

### USB Passthrough for External Adapter

1. Plug in your wireless adapter **before** starting the container.
2. The container gets `/dev/bus/usb` via `docker-compose.yml` (`devices:` section).
3. Inside the container, run `iw dev` to confirm the adapter is visible.
4. Verify injection: `aireplay-ng --test wlan0mon`

```yaml
# docker-compose.yml (relevant section)
devices:
  - /dev/bus/usb:/dev/bus/usb
```

If the adapter doesn't appear: check `lsusb` on the host; ensure the kernel driver
(e.g. `rtl8812au-dkms`) is loaded on the **host** — Docker passes the device, not the driver.

---

## Pre-flight Checker

```bash
sudo wifi-auditor --preflight
```

Always performs a fresh check. Never writes the sentinel.

### What is checked

| Tool                                              | Required | Purpose                                     |
| ------------------------------------------------- | -------- | ------------------------------------------- |
| python ≥ 3.10                                     | YES      | Runtime                                     |
| airmon-ng, airodump-ng, aireplay-ng, aircrack-ng  | YES      | Core capture + crack                        |
| iw, ip                                            | YES      | Interface management                        |
| hcxdumptool, hcxpcapngtool                        | opt      | PMKID capture + `.cap` → `.hc22000`         |
| hashcat                                           | opt      | GPU cracking                                |
| crunch                                            | opt      | Brute-force wordlist generation             |
| macchanger                                        | opt      | MAC randomisation                           |
| reaver                                            | opt      | WPS Pixie-Dust + PIN brute-force            |
| wash                                              | opt      | WPS AP discovery (ships with reaver)        |
| bully                                             | opt      | WPS alternate backend                       |
| cowpatty                                          | opt      | PMK-cache optimised cracking                |

### Example output

```
╔══════════════════════════════════════╗
║      WiFi Auditor -- Pre-Flight      ║
╚══════════════════════════════════════╝

┌──────────────────┬───────┬─────────────┬───────┬──────────────────────┐
│ Tool             │ Found │ Version     │ Req'd │ Status               │
├──────────────────┼───────┼─────────────┼───────┼──────────────────────┤
│ python           │  OK   │ 3.11.2      │  YES  │ OK (>=3.10)          │
│ airmon-ng        │  OK   │ 1.7         │  YES  │ OK                   │
│ hcxdumptool      │  OK   │ 6.2.7       │  opt  │ OK                   │
│ reaver           │  OK   │ 1.6.6       │  opt  │ OK                   │
│ wash             │  OK   │ 1.6.6       │  opt  │ OK                   │
│ cowpatty         │  OK   │ 4.8         │  opt  │ OK                   │
└──────────────────┴───────┴─────────────┴───────┴──────────────────────┘

✓ All pre-flight checks passed. Ready to audit.
```

---

## scope.yaml

> `scope.yaml` is **gitignored**. Copy the template to get started:

```bash
cp scope.yaml.example scope.yaml
wifi-auditor --scope-wizard   # interactive builder with 6-point checklist
```

`scope.yaml.example` format:

```yaml
authorized_targets:
  - bssid: "AA:BB:CC:DD:EE:FF"
    ssid: "YourNetworkName"
    authorized_by: "Full Name (relationship: owner / written-permission)"
    valid_until: "YYYY-MM-DD"
    notes: "Source of authorization: e.g. written email dated YYYY-MM-DD"
```

### Scope enforcement rules

| Operation                        | Scope required  |
| -------------------------------- | --------------- |
| Network scan (passive)           | No              |
| WPS wash scan                    | No              |
| Passive handshake capture        | Warning only    |
| Deauth attack                    | **Hard block**  |
| PMKID capture                    | **Hard block**  |
| WEP injection attacks            | **Hard block**  |
| WPS Pixie-Dust / PIN attack      | **Hard block**  |

---

## WPS Attack Module

Full WPS attack suite in `modules/wps.py` (741 lines).

### Attack modes

| Mode                          | Description                                                 | Backend                           |
| ----------------------------- | ----------------------------------------------------------- | --------------------------------- |
| **[1] Pixie-Dust**            | Offline nonce recovery — cracks vulnerable APs in <30 s     | `reaver -K 1` or `bully --pixie`  |
| **[2] Vendor PIN Spray**      | OUI-matched vendor defaults first, then 30 common PINs      | `reaver` / `bully -p PIN`         |
| **[3] Full PIN Brute-Force**  | All ~11,000 valid WPS PINs, configurable delay + lock-wait  | `reaver` (resumable state)        |
| **[4] Wash Scan**             | Passive WPS beacon discovery — shows locked/unlocked        | `wash`                            |

### OUI vendor PIN database (26 entries)

| Vendor         | OUI prefix examples                              |
| -------------- | ------------------------------------------------ |
| Belkin         | `00265A`, `94103E`, `001882`                     |
| Tenda          | `C83A35`, `F8D111`                               |
| TP-Link        | `1C3950`, `50C7BF`, `D8EB97`, `EC172F`, `6045CB` |
| D-Link         | `001CF0`, `144D67`, `1CAFF7`                     |
| Netgear        | `001422`, `20E52A`, `C0FF28`                     |
| Huawei         | `B0487A`, `48AD08`                               |
| ZyXEL          | `74DADA`                                         |
| Linksys/Cisco  | `001217`, `002275`, `001D7E`                     |
| Asus           | `A8B1D4`, `04D4C4`                               |
| Buffalo        | `706F81`                                         |
| Motorola       | `0018E7`                                         |

### Automatic WPS probe

After every target selection, a **6-second passive wash scan** runs automatically:

```
Probing WPS capability (6 s wash scan)...
✓ WPS v2.0 detected on AA:BB:CC:DD:EE:FF  [unlocked]
```

The result annotates the target dict (`wps_enabled`, `wps_locked`, `wps_version`)
and feeds into the Smart Sequencer.

### Full Auto WPS routing

```
Scan → Select target → Auto WPS probe (6 s wash)
                              ↓
                  WPS enabled & unlocked?
                  YES    → Pixie-Dust → PIN spray fallback
                  LOCKED → PMKID path (WPS PIN attacks deprioritised)
                  NO     → Handshake → Wordlist → Crack
```

---

## Cracking Engine

Four backends for WPA handshakes and PMKID hashes:

```
[1] aircrack-ng   — fast dict attack
[2] cowpatty      — PMK-cache optimised (auto-passes SSID from session)
[3] hashcat dict  — GPU-accelerated, auto-converts .cap → .hc22000
[4] hashcat rules — dict + rule mutations (best64, d3ad0ne, dive…)
```

### hashcat rule-based cracking

Rule files are auto-discovered and shown with line counts:

```
[1] best64        (77 rules)
[2] d3ad0ne       (34,096 rules)
[3] dive          (99,089 rules)
[4] rockyou-30000 (30,000 rules)
[5] toggles1      (9,000 rules)
[0] Enter custom path
```

### `.cap` → `.hc22000` conversion

Backends 3 and 4 call `hcxpcapngtool` automatically. Falls back to aircrack-ng
gracefully if `hcxtools` is not installed.

---

## WPA3 SAE Downgrade Detection

| SECURITY column                 | Meaning                                        |
| ------------------------------- | ---------------------------------------------- |
| `WPA3-SAE` (green)              | WPA3-only — SAE handshake, no downgrade        |
| `WPA3/WPA2` + `↓SAE` (yellow)   | Transition mode — WPA2 clients still accepted  |
| `WPA2` (white)                  | Standard WPA2-PSK                              |
| `WEP` (red)                     | Critically weak — instant crack                |

---

## Smart Attack Sequencer

WPS-aware scoring before touching any target:

```
WEP detected                   → score 100  (instant win)
WPS unlocked (Pixie-Dust)      → score  95
WPS unlocked (PIN spray)       → score  92
PMKID capable / 0 clients      → score  90
Deauth viable                  → score  75 + min(clients×3, 15)
WPS locked (Pixie-Dust only)   → score  70  (PIN futile)
Weak signal (<−75 dBm)         → deauth score −25
Passive fallback               → score  20  (always appended)
```

---

## Handshake Capture — Three Parallel Engines

`modules/handshake.py` runs three engines simultaneously from capture start:

| Engine | Method | Details |
| ------ | ------ | ------- |
| 1 | airodump-ng file watcher | polls `.cap` every 0.5 s; verifies with aircrack-ng, cowpatty, tshark |
| 2 | scapy AsyncSniffer | captures EAPOL frames in-memory; BPF `ether proto 0x888e`; zero disk dependency |
| 3 | hcxdumptool PMKID | runs passively alongside deauth from the start; checks for `.hc22000` every 2 s |

Deauth pipeline: Phase 1 — targeted unicast (top-2 clients, both directions) → Phase 2 — broadcast fallback → Phase 3 — PMKID wait (90 s).

---

## CLI Reference

```
wifi-auditor --version              Print version and exit
wifi-auditor --preflight            Pre-flight dependency check
wifi-auditor --scope-wizard         Interactive scope.yaml builder
wifi-auditor --scope FILE           Load specific scope file (default: ./scope.yaml)
wifi-auditor --headless             Non-interactive automated mode
wifi-auditor --target BSSID         Target for headless mode
wifi-auditor --auto                 Alias for --headless
wifi-auditor --interface IFACE      Force specific wireless interface
wifi-auditor --check-interface      Diagnose interface / monitor-mode issues and exit
wifi-auditor --deauth-limit N       Max deauth bursts/min (default 5, max 20)
wifi-auditor --report SESSION_ID    Generate Markdown + JSON pentest report
wifi-auditor --verify-log           Verify HMAC-chained audit log integrity
wifi-auditor --refresh-oui          Re-download IEEE OUI database
wifi-auditor --debug                Enable DEBUG logging to console
wifi-auditor --fast                 Lab/CTF mode: skip scope+consent (red warning shown)
```

### Interactive menu keys

```
[1]  Set interface + enable monitor mode
[2]  Scan networks  (+ auto WPS probe after selection)
[3]  Capture handshake / PMKID
[4]  Generate wordlist
[5]  Crack  (aircrack / cowpatty / hashcat dict / hashcat rules)
[6]  Full Auto  (scan → WPS probe → WPS or handshake → wordlist → crack)
[7]  WEP attack pipeline
[8]  Show session state
[9]  Deauth attack
[w]  WPS attack  (Pixie-Dust / PIN spray / brute-force / Wash scan)
[0]  Exit
```

### `--fast` lab mode

```bash
sudo wifi-auditor --fast
```

Disables scope.yaml enforcement and consent prompts. Intended for **isolated lab /
CTF environments only**. A bold red warning panel is displayed at startup and before
every injection. All actions are still logged with `scope_bypassed=True`.

> **Warning:** `--fast` does **not** make the tool anonymous or legal. Use exclusively
> on networks you own.

### Headless / scheduled audit example

```bash
sudo wifi-auditor \
  --headless \
  --scope scope.yaml \
  --target AA:BB:CC:DD:EE:FF \
  --interface wlan0 \
  --deauth-limit 3 \
  --auto
```

---

## Audit Log Verification

Every log line is HMAC-SHA256 chained — tampering or deletion is detectable:

```bash
wifi-auditor --verify-log
# ✓ Audit log integrity verified (342 entries, chain intact)
# — or —
# ✗ Audit log TAMPERED or MISSING lines!
```

The chain key is derived from `machine-id + tool version`. Signature chain stored
at `~/.wifi-auditor/chain.json`.

---

## Pentest Report Generator

```bash
wifi-auditor --report 20260604_143022
```

Output:
- `results/report_20260604_143022.md` — executive summary, scope, methodology, findings, evidence
- `results/findings_20260604_143022.json` — machine-readable for tool chaining
- `results/wps_TIMESTAMP.txt` — WPS results (timestamp, mode, BSSID, PIN, PSK)

SHA-256 of the capture file is included as evidence integrity.

---

## Wordlist Strategies

| #   | Strategy                     | Notes                                                  |
| --- | ---------------------------- | ------------------------------------------------------ |
| 1   | SSID Mutations               | leet, caps, year/number/symbol affixes                 |
| 2   | Common Passwords             | Built-in top-200 + optional rockyou.txt                |
| 3   | Custom Seeds                 | Provide seed words → mutate                            |
| 4   | Personal Info (CUPP-style)   | 13 fields: name, DOB, pet, company…                    |
| 5   | Date Patterns                | All DDMMYYYY / YYYYMMDD combinations                   |
| 6   | Phone Numbers                | 10-digit + country-code variants                       |
| 7   | Keyboard Walks               | qwerty, 1q2w3e4r, etc.                                 |
| 8   | Crunch Brute-Force           | Full charset via `crunch`                              |
| 9   | Combine Multiple Lists       | Merge + deduplicate                                    |
| 10  | All Strategies               | Run everything combined                                |
| 11  | Vendor Defaults              | OUI lookup → router model defaults (30-day cache)      |
| 12  | Use Existing File            | Load a wordlist from disk                              |
| 13  | Custom Pattern Builder       | Token-based pattern engine (`%w@%Y`, `%T%n`, etc.)     |
| 14  | Smart Scenario Engine        | 5 profiles by breach frequency (Indian Mobile, Corp…)  |

---

## Interface Diagnostics

If monitor mode fails, run:

```bash
sudo wifi-auditor --check-interface
```

Prints: `iw dev` raw output, managed/monitor interface lists, interfering processes,
airmon-ng availability, and root status — without starting the full tool.

---

## Deauth Rate Limiter

Controlled via `--deauth-limit N` (default 5, max 20 bursts/min):

- Token bucket refills at N tokens / 60 seconds per BSSID
- Global hard cap: 100 frames/second across all targets
- Live stats:

```
Rate limiter: 4.2/5 tokens  (max 5 bursts/min  fps=12/100)
```

---

## Known-working Adapters

| Adapter                        | Chipset    | Monitor | Injection |
| ------------------------------ | ---------- | ------- | --------- |
| Alfa AWUS036ACH                | RTL8812AU  | ✓       | ✓         |
| Alfa AWUS036NHA                | AR9271     | ✓       | ✓         |
| TP-Link TL-WN722N **v1 only**  | AR9271     | ✓       | ✓         |
| Panda PAU09                    | RT5572     | ✓       | ✓         |

---

## How WPA2 Cracking Works

```
Client ──── EAPOL M1 ────▶ AP
Client ◀─── EAPOL M2 ──── AP
Client ──── EAPOL M3 ────▶ AP
Client ◀─── EAPOL M4 ──── AP
       └── capture ──▶ .cap file

For each candidate:
  PMK = PBKDF2-HMAC-SHA1(password, SSID, 4096, 32)
  PTK = PRF-512(PMK, "Pairwise key expansion", ANonce, SNonce, MACs)
  MIC = HMAC-MD5/SHA1/SHA256(KCK, EAPOL frame)
  if MIC == captured_MIC → PASSWORD FOUND
```

## How WPS Pixie-Dust Works

```
Attacker ──── WPS M1 ────▶ AP  (sends empty AuthKey)
Attacker ◀─── WPS M2 ──── AP  (AP reveals E-S1, E-S2 nonces in clear)
                               ↓
              reaver -K 1 / bully --pixie
              offline: brute PSK1/PSK2 from E-S1, E-S2, PKe, PKr, AuthKey
              if AP uses weak/static nonces → PIN recovered in <30 s
              PSK extracted from PIN via follow-up M4/M6 exchange
```

Affected vendors: many Broadcom- and Ralink-based routers 2010–2018 (D-Link, Tenda,
TP-Link, Belkin, Netgear, Asus).

---

## Directory Structure

```
wifi_down/
├── .github/
│   └── workflows/
│       └── ci.yml                  CI: ruff + mypy + pytest on push/PR
├── wifi_auditor/                   Python package (console_scripts entry point)
│   ├── __init__.py                 exports __version__ = "0.5.0"
│   └── cli.py                      Full CLI: 15 flags + [w] WPS key + StateManager
├── modules/
│   ├── banner.py                   Pure ANSI typewriter (frozen at v0.4.6)
│   ├── cracker.py                  4-backend cracker
│   ├── deauth.py                   Deauth + rate limiter + scope + --fast support
│   ├── exceptions.py               Typed exception hierarchy
│   ├── fingerprint.py              Passive 802.11 device fingerprinter (scapy)
│   ├── handshake.py                3-engine parallel capture
│   ├── interface.py                Fixed monitor-mode regex (5 patterns)
│   ├── logger.py                   JSON-lines session logger
│   ├── oui.py                      IEEE OUI database + vendor defaults (30-day cache)
│   ├── pattern_engine.py           Token-based pattern expansion engine
│   ├── pmkid.py                    PMKID extraction + hashcat
│   ├── preflight.py                Pre-flight checker + auto_install_missing()
│   ├── ratelimit.py                Token-bucket deauth rate limiter
│   ├── reporter.py                 Markdown + JSON + HTML pentest report generator
│   ├── runner.py                   SubprocessRunner with retries + typed errors
│   ├── scanner.py                  airodump-ng wrapper + WPA3 downgrade detection
│   ├── scope.py                    Scope enforcement + 6-point wizard
│   ├── sequencer.py                WPS-aware smart attack sequencer
│   ├── state.py                    StateManager + session persistence + signal handling
│   ├── utils.py                    Root check + re-exports from interface.py
│   ├── wep.py                      WEP attack pipeline
│   ├── wordlist.py                 14-strategy wordlist engine (1,031 lines)
│   └── wps.py                      WPS: Pixie-Dust / Vendor PIN / Full brute / Wash
├── data/
│   ├── common_passwords.txt
│   └── router_defaults.yaml        Vendor → default passwords (schema v1, 30-day cache)
├── tests/
│   ├── test_banner.py              Banner smoke tests (frozen at v0.4.6)
│   ├── test_hmac.py                HMAC chain tamper detection
│   ├── test_oui.py                 OUI lookup (mock HTTP)
│   ├── test_preflight.py           Preflight logic (mock subprocess)
│   ├── test_router_defaults.py     router_defaults.yaml schema validation
│   ├── test_runner.py              SubprocessRunner timeout + retry
│   ├── test_scope.py               Scope enforcement
│   └── test_version.py             __version__ export sanity
├── captures/                       Handshake .cap files  [gitignored, .gitkeep tracks dir]
├── wordlists/                      Generated wordlists    [gitignored, .gitkeep tracks dir]
├── results/                        Reports + WPS results  [gitignored, .gitkeep tracks dir]
├── .gitignore
├── CHANGELOG.md
├── CONTRIBUTING.md
├── Dockerfile
├── LICENSE
├── README.md
├── SECURITY.md
├── docker-compose.yml
├── docker-run.sh
├── install.sh
├── pyproject.toml                  Single source of truth for deps
├── requirements.txt                Python runtime deps
├── requirements-dev.txt            Dev deps: pytest, ruff, mypy
├── scope.yaml.example              Template — copy to scope.yaml (gitignored)
└── wifi_auditor.py                 Legacy shim → delegates to wifi_auditor/cli.py
```

---

## Troubleshooting

**"No wireless interfaces found"** — Run `iw dev` and `ip link`. Adapter may need a driver (`dkms`). Use `--check-interface` for a full diagnostic printout.

**Monitor mode fails** — `sudo airmon-ng check kill && sudo airmon-ng start wlan0`. Then run `--check-interface` to confirm.

**Scope error on startup** — Create `scope.yaml` with `wifi-auditor --scope-wizard`.

**"BSSID mismatch" on consent prompt** — Type the full BSSID character-by-character as shown (no paste).

**OUI database unavailable** — `wifi-auditor --refresh-oui` to force re-download.

**WPS not found after scan** — AP may have WPS disabled in firmware. Use mode [4] Wash Scan on a specific channel for a longer look.

**reaver "WPS transaction failed"** — AP is rate-limiting WPS attempts. Use `--delay` (mode 3 prompts you), or wait for lockout to expire (5–60 min).

**hashcat rule file not found** — Install `hashcat-rules` package or run from a directory containing a `rules/` folder.

**cowpatty "Collected all necessary data"** — SSID mismatch. Ensure session SSID matches the one used during capture.

**Monitor mode interface left stranded after crash** — `sudo airmon-ng stop wlan0mon`. From v0.5.0, cleanup errors are printed to stderr instead of silently swallowed.

---

## Development

```bash
git clone https://github.com/amibhai/wifi_down.git
cd wifi_down
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
pip install -r requirements-dev.txt

pytest tests/ -v          # run test suite
ruff check .              # lint
mypy modules/ wifi_auditor/ --ignore-missing-imports   # type check
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for branch naming, commit conventions, and the PR checklist.

---

## Security

To report a vulnerability in the tool itself, see [SECURITY.md](SECURITY.md).

---

## License

MIT — for authorized security testing only. See [LICENSE](LICENSE) for full terms.
