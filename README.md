# WiFi Auditor

Automated WiFi security auditing framework. Menu-driven, end-to-end pipeline:
**scan → WPS probe → WPS attack / handshake capture → wordlist → crack → report.**

> **LEGAL NOTICE** — Use **only** on networks you own or have explicit **written permission** to test.  
> Unauthorized access is a criminal offence (CFAA, UK Computer Misuse Act, India IT Act 2000, etc.).  
> The authors accept **no liability** for misuse.

---

## Features

| Stage | What it does |
|---|---|
| **Scanner** | Monitor mode scan via `airodump-ng` with SSID entropy + vendor tags + WPA3 downgrade detection |
| **WPS Attacks** | Pixie-Dust (offline nonce) / Vendor PIN spray (OUI-matched) / Full brute-force / Wash scan |
| **Handshake Capture** | Passive / deauth / PMKID — scope-gated and consent-prompted |
| **Wordlist Generator** | 12 strategies including OUI vendor defaults and CUPP-style personal profiling |
| **Cracker** | `aircrack-ng` + `cowpatty` + `hashcat` dict + `hashcat` rule-based (best64, d3ad0ne, dive…) |
| **WEP Cracker** | ARP replay / fragmentation / ChopChop pipelines |
| **Deauth Attack** | Rate-limited, consent-required, scope-enforced |
| **Smart Sequencer** | WPS-aware ranking: WPS unlocked → score 95, PMKID → 90, deauth → 75 |
| **Full Auto Mode** | Scan → WPS probe → WPS path OR handshake path → wordlist → crack |
| **Pentest Reports** | Markdown + JSON + HTML, SHA-256 evidence, HMAC-chained audit log |

---

## Quick Start

```bash
git clone https://github.com/amibhai/wifi_down.git
cd wifi_down
sudo ./install.sh          # detects OS, installs deps, creates venv
sudo wifi-auditor --preflight   # verify everything is ready
sudo wifi-auditor          # launch interactive menu
```

---

## Installation

### Automated (recommended)

```bash
sudo ./install.sh
```

The script auto-detects your OS and uses the correct package manager:

| OS | Package manager |
|---|---|
| Kali / Parrot / Ubuntu 22+ / Debian | `apt` |
| Arch / Manjaro | `pacman` (+ AUR warning for hcxtools) |
| Fedora / RHEL / Rocky | `dnf` (hcxdumptool built from source) |

After install, a Python venv is created at `~/.wifi-auditor/venv` and a launcher at `/usr/local/bin/wifi-auditor`.

At the end of `install.sh`, the new `run_first_preflight()` function:
1. Calls `_ensure_tool` for every optional/WPS binary (`reaver`, `wash`, `bully`, `cowpatty`, `hashcat`, `crunch`, `macchanger`) — installing any that are missing via the already-selected package manager.
2. Sources the Python venv and runs `run_preflight_with_autofix()` (two-pass: show table → auto-install stragglers → re-show table).
3. Writes the sentinel `~/.wifi-auditor/.preflight_done` (both from Python and from bash — belt-and-suspenders).

### Manual

```bash
sudo apt-get install aircrack-ng hcxdumptool hcxtools hashcat crunch macchanger iw \
     reaver bully wash cowpatty
pip install -r requirements.txt
```

> [!NOTE]
> If you skip `install.sh`, the sentinel will be absent. The **first** `sudo wifi-auditor` launch
> will automatically detect this and run `run_preflight_with_autofix()` for you. All subsequent
> starts are instant — the sentinel check is a single `Path.exists()` call.

---

## Auto-Setup & First-Run Flow

WiFi Auditor uses a sentinel file (`~/.wifi-auditor/.preflight_done`) to ensure the full
dependency check runs **exactly once** — either at the end of `install.sh` or on the very first
manual launch — and never again slows startup after that.

```
sudo ./install.sh
  ├─ apt/pacman/dnf: install core packages
  ├─ setup Python venv + pip install
  ├─ create /usr/local/bin/wifi-auditor
  └─ run_first_preflight()
       ├─ _ensure_tool reaver / wash / bully / cowpatty / ...
       │    └─ if missing → apt-get install -y <pkg>  (auto)
       ├─ source venv → run_preflight_with_autofix()
       │    ├─ Pass 1 : display full dependency table
       │    ├─ auto_install_missing() → installs anything still absent
       │    ├─ Pass 2 : re-display table confirming everything fixed
       │    └─ write ~/.wifi-auditor/.preflight_done
       └─ sentinel also written by bash (belt-and-suspenders)

Next launch:  sudo wifi-auditor
  ├─ check_root()
  ├─ _check_first_run()  →  sentinel exists  →  returns immediately (no-op)
  ├─ check_dependencies()
  └─ print_banner() → menu

Manual install path (no install.sh):
  First  sudo wifi-auditor
  ├─ _check_first_run()  →  no sentinel
  ├─ run_preflight_with_autofix()  (same two-pass flow)
  └─ sentinel written → all future starts are instant

Manual re-check at any time:
  sudo wifi-auditor --preflight   ← always works, never writes sentinel
```

### Sentinel details

| Path | `~/.wifi-auditor/.preflight_done` |
|---|---|
| Created by | `install.sh` (bash `touch`) AND `run_preflight_with_autofix()` (Python `Path.touch()`) |
| Effect when present | `_check_first_run()` in `cli.py` returns immediately |
| Delete to re-trigger | `rm ~/.wifi-auditor/.preflight_done` then `sudo wifi-auditor` |
| Does `--preflight` write it? | **No** — `--preflight` is always a fresh check |

---

## Docker

### Build and run

```bash
# Build the image (Kali base)
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

If the adapter doesn't appear: check `lsusb` on the host; ensure the kernel driver (e.g. `rtl8812au-dkms`) is loaded on the **host** (Docker passes the device, not the driver).

---

## Pre-flight Checker

Run a manual dependency check at any time:

```bash
sudo wifi-auditor --preflight
```

This **always** performs a fresh check and **never** writes the sentinel, so it is safe to use for
diagnostics without affecting the auto-setup flow.

### What is checked

| Tool | Required | Purpose |
|---|---|---|
| python ≥ 3.10 | YES | Runtime |
| airmon-ng, airodump-ng, aireplay-ng, aircrack-ng | YES | Core capture + crack |
| iw, ip | YES | Interface management |
| hcxdumptool, hcxpcapngtool | opt | PMKID capture + .cap→hc22000 conversion |
| hashcat | opt | GPU cracking |
| crunch | opt | Brute-force wordlist generation |
| macchanger | opt | MAC randomisation |
| **reaver** | opt | WPS Pixie-Dust + PIN brute-force |
| **wash** | opt | WPS AP discovery (ships with reaver package) |
| **bully** | opt | WPS alternate backend |
| **cowpatty** | opt | PMK-cache optimised cracking |

### auto_install_missing()

When called from `run_preflight_with_autofix()`, this function:
1. Detects the package manager (`apt-get`, `pacman`, or `dnf`).
2. Deduplicates packages — `airmon-ng`, `airodump-ng`, `aireplay-ng`, and `aircrack-ng` all map to the `aircrack-ng` package; `wash` maps to `reaver` since they ship together.
3. Runs the install command for each unique package.
4. Reports success/failure per package.

```
Package mapping examples (TOOL_PACKAGES):
  airmon-ng, airodump-ng, aireplay-ng, aircrack-ng → aircrack-ng
  wash                                              → reaver  (same package)
  hcxpcapngtool                                     → hcxtools
  ip                                                → iproute2 (apt) / iproute (dnf)
```

### Example output

```
╔══════════════════════════════════════╗
║      WiFi Auditor -- Pre-Flight      ║
╚══════════════════════════════════════╝

┌──────────────────┬───────┬─────────────┬───────┬──────────────────────────────────────┐
│ Tool             │ Found │ Version     │ Req'd │ Status                               │
├──────────────────┼───────┼─────────────┼───────┼──────────────────────────────────────┤
│ python           │  OK   │ 3.11.2      │  YES  │ OK (>=3.10)                          │
│ airmon-ng        │  OK   │ 1.7         │  YES  │ OK                                   │
│ airodump-ng      │  OK   │ 1.7         │  YES  │ OK                                   │
│ aireplay-ng      │  OK   │ 1.7         │  YES  │ OK                                   │
│ aircrack-ng      │  OK   │ 1.7         │  YES  │ OK (>=1.7)                           │
│ iw               │  OK   │ 5.19        │  YES  │ OK                                   │
│ ip               │  OK   │ 5.18        │  YES  │ OK                                   │
│ hcxdumptool      │  OK   │ 6.2.7       │  opt  │ OK                                   │
│ hcxpcapngtool    │  OK   │ 6.2.7       │  opt  │ OK                                   │
│ hashcat          │  OK   │ 6.2.6       │  opt  │ OK                                   │
│ crunch           │  OK   │ 3.6         │  opt  │ OK                                   │
│ macchanger       │  OK   │ 1.7.0       │  opt  │ OK                                   │
│ reaver           │  OK   │ 1.6.6       │  opt  │ OK                                   │
│ wash             │  OK   │ 1.6.6       │  opt  │ OK                                   │
│ bully            │  OK   │ 1.4         │  opt  │ OK                                   │
│ cowpatty         │  OK   │ 4.8         │  opt  │ OK                                   │
└──────────────────┴───────┴─────────────┴───────┴──────────────────────────────────────┘

┌──────────────┬──────────────┬──────────────┬─────┐
│ Interface    │ Monitor Mode │ In /proc/net │ Inj │
├──────────────┼──────────────┼──────────────┼─────┤
│ wlan0mon     │     yes      │     yes      │ yes │
└──────────────┴──────────────┴──────────────┴─────┘

✓ All pre-flight checks passed. Ready to audit.
```

---

## scope.yaml Format

Create `scope.yaml` before running any attack (required for frame injection):

```yaml
authorized_targets:
  - bssid: "AA:BB:CC:DD:EE:FF"
    ssid: "HomeNetwork"
    authorized_by: "John Doe (owner)"
    valid_until: "2026-12-31"
    notes: "Written email from owner dated 2026-06-01"
```

Use the interactive wizard to build it:

```bash
wifi-auditor --scope-wizard
```

The wizard displays a 6-point authorization checklist and requires explicit confirmation before adding any target.

### Scope enforcement rules

| Operation | Scope required |
|---|---|
| Network scan (passive) | No |
| WPS wash scan | No |
| Passive handshake capture | Warning only |
| Deauth attack | **Hard block** |
| PMKID capture | **Hard block** |
| WEP injection attacks | **Hard block** |
| **WPS Pixie-Dust / PIN attack** | **Hard block** |

---

## WPS Attack Module

WiFi Auditor includes a full WPS attack suite in `modules/wps.py`.

### Attack Modes

| Mode | Description | Backend |
|---|---|---|
| **[1] Pixie-Dust** | Offline nonce recovery — cracks vulnerable APs in <30 s | reaver `-K 1` or bully `--pixie` |
| **[2] Vendor PIN Spray** | OUI-matched vendor defaults first, then 30 common PINs | reaver / bully `-p PIN` |
| **[3] Full PIN Brute-Force** | All ~11,000 valid WPS PINs with configurable delay + lock-wait | reaver (resumable state) |
| **[4] Wash Scan** | Passive WPS beacon discovery — shows locked/unlocked status | wash |

### OUI Vendor PIN Database (26 entries)

The Vendor PIN Spray mode looks up the first 6 hex characters of the target BSSID against a built-in table of known default WPS PINs:

| Vendor | OUI examples |
|---|---|
| Belkin | `00265A`, `94103E`, `001882` |
| Tenda | `C83A35`, `F8D111` |
| TP-Link | `1C3950`, `50C7BF`, `D8EB97`, `EC172F`, `6045CB` |
| D-Link | `001CF0`, `144D67`, `1CAFF7` |
| Netgear | `001422`, `20E52A`, `C0FF28` |
| Huawei | `B0487A`, `48AD08` |
| ZyXEL | `74DADA` |
| Linksys/Cisco | `001217`, `002275`, `001D7E` |
| Asus | `A8B1D4`, `04D4C4` |
| Buffalo | `706F81` |
| Motorola | `0018E7` |

If no vendor match is found, falls back to 30 common PINs (from public research).

### Automatic WPS Probe

After every target is selected (scan or full-auto), the tool runs a **6-second passive wash scan** on the target's channel:

```
Probing WPS capability (6 s wash scan)...
✓ WPS v2.0 detected on AA:BB:CC:DD:EE:FF  [unlocked]
```

The result annotates the target dict (`wps_enabled`, `wps_locked`, `wps_version`) and is fed into the Smart Sequencer.

### Full Auto WPS Routing

```
Scan → Select target → Auto WPS probe (6s wash)
                             ↓
                 WPS enabled & unlocked?
                 YES  → Pixie-Dust first (mode 1) → PIN spray fallback
                 LOCKED → PMKID path (WPS PIN attacks blocked)
                 NO   → Handshake → Wordlist → Crack
```

### Example

```bash
# Launch WPS menu from interactive session
[w] WPS Attack

# Or jump straight to WPS in headless mode
sudo wifi-auditor --fast --interface wlan0mon
# Then select [w] from the menu
```

---

## Cracking Engine

`cracker_menu()` now offers **4 backends** for WPA handshakes and PMKID hashes:

```
  Cracking Backend:
  [1] aircrack-ng   – fast dict attack, GPU optional
  [2] cowpatty      – PMK-cache optimised (needs SSID)
  [3] hashcat dict  – GPU-accelerated, auto-converts .cap → hc22000
  [4] hashcat rules – dict + rule mutations (best64, d3ad0ne, dive…)
```

### hashcat Rule-Based Cracking

Rule files are auto-discovered from standard paths (`/usr/share/hashcat/rules/`, etc.) and displayed with line counts:

```
  Available rule files:
  [1] best64           (77 rules)    /usr/share/hashcat/rules/best64.rule
  [2] d3ad0ne          (34,096 rules) /usr/share/hashcat/rules/d3ad0ne.rule
  [3] dive             (99,089 rules) /usr/share/hashcat/rules/dive.rule
  [4] rockyou-30000    (30,000 rules)
  [5] toggles1         (9,000 rules)
  [0] Enter custom path
```

A 10,000-word list + `best64` generates ~640,000 candidates — covering character substitutions, appended digits, and capitalisation patterns used by most humans for Wi-Fi passwords.

### cowpatty

```bash
cowpatty -r capture.cap -f wordlist.txt -s "MySSID"
```

cowpatty pre-computes the PMK (PBKDF2-HMAC-SHA1) once per password, making it faster than aircrack-ng for repeated cracking against the same SSID. WiFi Auditor auto-passes the SSID from the session state.

### .cap → hc22000 Conversion

Backends 3 and 4 automatically call `hcxpcapngtool` to convert `.cap` → `.hc22000` before running hashcat. Falls back to aircrack-ng gracefully if `hcxtools` is not installed.

---

## WPA3 SAE Downgrade Detection

`scanner.py` now classifies each AP's security tier and flags **transition-mode** APs that advertise both WPA3 and WPA2 — a downgrade attack surface:

| SECURITY column | Meaning |
|---|---|
| `WPA3-SAE` (green) | WPA3-only — SAE handshake, no downgrade |
| `WPA3/WPA2` + `↓SAE` (yellow) | Transition mode — WPA2 clients still accepted |
| `WPA2` (white) | Standard WPA2-PSK |
| `WEP` (red) | Critically weak — instant crack |

The `↓SAE` flag in the scan table helps you identify APs where a downgrade attack may be feasible before selecting a target.

---

## Smart Attack Sequencer

The sequencer scores each discovered AP and generates a **ranked attack plan** before touching the target. Scores are now WPS-aware:

```
Scoring factors:
  • WEP detected                   → score 100  (instant win)
  • WPS unlocked (Pixie-Dust)      → score 95   ← new
  • WPS unlocked (PIN spray)       → score 92   ← new
  • PMKID capable / 0 clients      → score 90
  • WPS locked (Pixie-Dust only)   → score 70   ← new (PIN futile)
  • Deauth viable                  → score 75 + min(clients×3, 15)
  • Weak signal (<-75 dBm)         → deauth score −25
  • Vendor known                   → wordlist_strategy = vendor_defaults
  • All-numeric SSID               → wordlist_strategy = phone_numbers
  • Default SSID tag               → vendor_defaults high-confidence flag
  • Passive fallback               → score 20  (always appended)
```

---

## CLI Reference

```
wifi-auditor --preflight              Pre-flight dependency check
wifi-auditor --scope-wizard           Interactive scope.yaml builder
wifi-auditor --scope FILE             Load specific scope file (default: ./scope.yaml)
wifi-auditor --headless               Non-interactive automated mode
wifi-auditor --target BSSID           Target for headless mode
wifi-auditor --auto                   Alias for --headless
wifi-auditor --interface IFACE        Force specific wireless interface
wifi-auditor --deauth-limit N         Max deauth bursts/min (default 5, max 20)
wifi-auditor --report SESSION_ID      Generate Markdown + JSON pentest report
wifi-auditor --verify-log             Verify HMAC-chained audit log integrity
wifi-auditor --refresh-oui            Re-download IEEE OUI database
wifi-auditor --debug                  Enable DEBUG logging to console
wifi-auditor --fast                   Lab/CTF mode: skip scope+consent (red warning shown)
```

### Interactive Menu Keys

```
[1]  Set interface + enable monitor mode
[2]  Scan networks (+ auto WPS probe)
[3]  Capture handshake / PMKID
[4]  Generate wordlist
[5]  Crack (aircrack / cowpatty / hashcat dict / hashcat rules)
[6]  Full Auto (scan → WPS or handshake → wordlist → crack)
[7]  WEP attack pipeline
[8]  Show session state
[9]  Deauth attack
[w]  WPS attack (Pixie-Dust / PIN spray / brute-force / wash scan)
[0]  Exit
```

### --fast Lab Mode

```bash
sudo wifi-auditor --fast
```

Disables scope.yaml enforcement and consent prompts. Intended for **isolated lab environments / CTF** only. A bold red warning panel is displayed at startup and before every injection. All actions are still logged with `scope_bypassed=True`.

> [!WARNING]
> `--fast` does **not** make the tool anonymous or legal. It only removes the interactive consent
> gates. Use exclusively on networks you own.

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

Every log line is HMAC-SHA256 chained so tampering or deletion is detectable:

```bash
wifi-auditor --verify-log
# ✓ Audit log integrity verified (342 entries, chain intact)
# — or —
# ✗ Audit log TAMPERED or MISSING lines!
```

The chain key is derived from `machine-id + tool version`. The signature chain is stored in `~/.wifi-auditor/chain.json`.

---

## Pentest Report Generator

Generate a structured Markdown report + `findings.json` from any completed session:

```bash
wifi-auditor --report 20260604_143022
```

Output files:
- `results/report_20260604_143022.md` — executive summary, scope, methodology, findings, evidence
- `results/findings_20260604_143022.json` — machine-readable for tool chaining

WPS results are saved separately to `results/wps_TIMESTAMP.txt` (timestamp, mode, BSSID, PIN, PSK).

The report includes SHA-256 of the capture file as evidence integrity.

---

## Wordlist Strategies

| # | Strategy | Notes |
|---|---|---|
| 1 | SSID Mutations | leet, caps, year/number/symbol affixes |
| 2 | Common Passwords | Built-in top-200 + optional rockyou.txt |
| 3 | Custom Seeds | Provide seed words → mutate |
| 4 | Personal Info (CUPP-style) | Name, DOB, pet, company |
| 5 | Date Patterns | All DDMMYYYY / YYYYMMDD combinations |
| 6 | Phone Numbers | 10-digit + country-code variants |
| 7 | Keyboard Walks | qwerty, 1q2w3e4r, etc. |
| 8 | Crunch Brute-Force | Full charset via `crunch` |
| 9 | Combine Multiple Lists | Merge + deduplicate |
| 10 | All Strategies | Run everything combined |
| **11** | **Vendor Defaults** | **OUI lookup → router model defaults (30-day cache)** |
| 12 | Use Existing File | Load a wordlist from disk |

Strategy 11 downloads the IEEE OUI database (cached 30 days at `~/.wifi-auditor/oui.db`) and returns default passwords for the detected router vendor (TP-Link, Netgear, D-Link, Huawei, etc.).

---

## Directory Structure

```
wifi-auditor/
├── wifi_auditor/               Python package (console_scripts entry point)
│   ├── __init__.py
│   └── cli.py                  Full CLI (15 flags + [w] WPS menu key)
├── modules/
│   ├── banner.py               Colors, display helpers, WPS menu entry
│   ├── cracker.py              4-backend cracker: aircrack/cowpatty/hashcat-dict/hashcat-rules
│   ├── deauth.py               Deauth attack (scope + consent + rate limit + --fast support)
│   ├── exceptions.py           Typed exception hierarchy
│   ├── fingerprint.py          Passive 802.11 device fingerprinter (scapy)
│   ├── handshake.py            Passive / deauth / PMKID capture (+ --fast support)
│   ├── logger.py               JSON-lines session logger
│   ├── oui.py                  IEEE OUI database + vendor defaults
│   ├── pmkid.py                PMKID extraction + hashcat
│   ├── preflight.py            Pre-flight system checker
│   ├── ratelimit.py            Token-bucket deauth rate limiter
│   ├── report.py               Markdown + JSON pentest report generator
│   ├── reporter.py             HTML report (legacy)
│   ├── runner.py               SubprocessRunner with retries + typed errors
│   ├── scanner.py              airodump-ng + SSID entropy + WPA3 downgrade detection
│   ├── scope.py                Scope enforcement + wizard
│   ├── sequencer.py            Smart attack sequencer (WPS-aware scoring)
│   ├── state.py                Session state + persistence + signal handling
│   ├── utils.py                Root check, logging, HMAC audit log
│   ├── wep.py                  WEP attack pipeline
│   ├── wordlist.py             12-strategy wordlist engine
│   └── wps.py                  WPS: Pixie-Dust / Vendor PIN spray / Full brute / Wash scan
├── data/
│   ├── common_passwords.txt
│   └── router_defaults.yaml    Vendor → default password mapping
├── tests/
│   ├── test_hmac.py            HMAC chain tamper detection
│   ├── test_oui.py             OUI lookup (mock HTTP)
│   ├── test_preflight.py       Preflight logic (mock subprocess)
│   ├── test_runner.py          SubprocessRunner timeout + retry
│   └── test_scope.py           Scope enforcement
├── captures/                   Handshake .cap files
├── wordlists/                  Generated wordlists
├── results/                    Cracked keys + WPS results + reports
├── scope.yaml                  Authorization list (edit before attacking)
├── pyproject.toml              PEP 517 package + console_scripts
├── requirements.txt            Python deps
├── requirements-dev.txt        Dev deps (pytest, ruff, mypy)
├── install.sh                  Multi-distro installer
├── Dockerfile                  Kali-based container
├── docker-compose.yml          Privileged + USB passthrough
└── docker-run.sh               Docker convenience wrapper
```

---

## How WPA2 Cracking Works

```
Client ──── EAPOL M1 ────▶ AP
Client ◀─── EAPOL M2 ──── AP
Client ──── EAPOL M3 ────▶ AP
Client ◀─── EAPOL M4 ──── AP
        └── capture ──▶ .cap file

For each password candidate:
  PMK = PBKDF2-HMAC-SHA1(password, SSID, 4096, 32)
  PTK = PRF-512(PMK, "Pairwise key expansion", ANonce, SNonce, MACs)
  MIC = HMAC-MD5/SHA1/SHA256(KCK, EAPOL frame)
  if MIC == captured_MIC → PASSWORD FOUND
```

---

## How WPS Pixie-Dust Works

```
Attacker ──── WPS M1 ────▶ AP  (sends empty AuthKey)
Attacker ◀─── WPS M2 ──── AP  (AP reveals E-S1, E-S2 nonces in clear)
                               ↓
              reaver -K 1 / bully --pixie
              offline: brute PSK1/PSK2 from E-S1,E-S2,PKe,PKr,AuthKey
              if AP uses weak/static nonces → PIN recovered in <30 s
              PSK extracted from PIN via follow-up M4/M6 exchange
```

Affected vendors: many Broadcom- and Ralink-based routers shipped 2010–2018 (D-Link, Tenda, TP-Link, Belkin, Netgear, Asus).

---

## Deauth Rate Limiter

Controlled via `--deauth-limit N` (default 5, max 20 bursts/min):

- Token bucket refills at N tokens/60 seconds per BSSID
- Global hard cap: 100 frames/second across all targets
- Live stats shown during attack:
  ```
  Rate limiter: 4.2/5 tokens  (max 5 bursts/min  fps=12/100)
  ```

---

## Adapters Known to Work

| Adapter | Chipset | Monitor | Injection |
|---|---|---|---|
| Alfa AWUS036ACH | RTL8812AU | ✓ | ✓ |
| Alfa AWUS036NHA | AR9271 | ✓ | ✓ |
| TP-Link TL-WN722N **v1 only** | AR9271 | ✓ | ✓ |
| Panda PAU09 | RT5572 | ✓ | ✓ |

---

## Troubleshooting

**"No wireless interfaces found"** — Check `iw dev` and `ip link`. Your adapter may need a driver (`dkms`).

**Monitor mode fails** — `sudo airmon-ng check kill && sudo airmon-ng start wlan0`.

**Scope error on startup** — Create `scope.yaml` with `wifi-auditor --scope-wizard`.

**"BSSID mismatch" on consent prompt** — Type the full BSSID character-by-character as shown (no paste).

**OUI database unavailable** — Run `wifi-auditor --refresh-oui` to force a re-download.

**WPS not found after scan** — The AP may have WPS disabled in firmware. Use mode [4] Wash Scan on a specific channel for a longer look.

**reaver "WPS transaction failed"** — AP may be rate-limiting WPS attempts. Use `--delay` (mode 3 prompts you) or wait for lockout to expire (5–60 min).

**hashcat rule file not found** — Install `hashcat-rules` package or run `wifi-auditor` from a directory containing a `rules/` folder.

**cowpatty "Collected all necessary data"** — SSID mismatch. Ensure the SSID in session state matches the one used during capture.

---

## Development

```bash
pip install -r requirements-dev.txt
pytest tests/ -v
ruff check .
mypy modules/ wifi_auditor/
```

---

## License

MIT — for authorized security testing only. See `LICENSE` for full terms.
