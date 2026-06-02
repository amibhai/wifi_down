# WiFi Auditor

Automated WPA2/WPA3 security auditing framework. Menu-driven, end-to-end pipeline: scan → capture → wordlist → crack.

> **LEGAL NOTICE** — Use **only** on networks you own or have explicit written permission to test. Unauthorized access is a criminal offence in most jurisdictions (CFAA, UK Computer Misuse Act, IT Act 2000, etc.). The authors accept no liability for misuse.

---

## Features

| Stage | What it does |
|---|---|
| **Scanner** | Puts adapter into monitor mode, runs `airodump-ng`, displays live table of nearby APs with SSID / BSSID / Channel / Encryption / Signal |
| **Handshake Capture** | Three strategies: (1) passive wait, (2) deauth attack (`aireplay-ng -0`) to force client reconnect, (3) PMKID capture via `hcxdumptool` (no client needed) |
| **Wordlist Generator** | 10 strategies — see below |
| **Cracker** | Runs `aircrack-ng` against the `.cap` file; also supports `hashcat` mode 22000 for PMKID hashes |
| **Full Auto Mode** | One keystroke to run the complete pipeline |

### Wordlist Generator Strategies

| # | Strategy | Notes |
|---|---|---|
| 1 | SSID Mutations | leet, caps, year/number/symbol affixes, reversed, wifi suffixes |
| 2 | Common Passwords | Built-in top-200 list + optional `rockyou.txt` |
| 3 | Custom Seeds + Mutations | Provide your own seed words |
| 4 | Personal Info (CUPP-style) | Name, DOB, partner, pet, company, keywords |
| 5 | Date Patterns | Every date combination (DDMMYYYY, YYYYMMDD, separators) |
| 6 | Phone Number Patterns | 10-digit numbers + country-code variants |
| 7 | Keyboard Walk Patterns | qwerty, 1q2w3e4r, asdfgh, etc. + mutations |
| 8 | Crunch Brute-Force | Full charset brute force via `crunch` |
| 9 | Combine Multiple Lists | Merge & deduplicate existing wordlists |
| 10 | All Strategies | Run everything and combine |

---

## Requirements

- **OS**: Kali Linux, Parrot OS, or any Debian-based distro with aircrack-ng
- **Hardware**: WiFi adapter that supports **monitor mode** and **packet injection** (e.g. Alfa AWUS036ACH, AWUS036NHA, TP-Link TL-WN722N v1)
- **Python**: 3.10+
- **Root**: Required (sudo)

### Required tools
```
airmon-ng   airodump-ng   aireplay-ng   aircrack-ng   iwconfig
```

### Optional tools
```
hcxdumptool   hcxtools   hashcat   crunch
```

---

## Installation

```bash
git clone https://github.com/your-username/wifi-auditor.git
cd wifi-auditor
sudo ./install.sh
```

Or install manually:
```bash
sudo apt-get install aircrack-ng crunch hcxdumptool hcxtools hashcat
```

---

## Usage

```bash
sudo python3 wifi_auditor.py
```

### Quick walkthrough

```
[1] Set Interface      →  Select wlan0, enable monitor mode (wlan0mon)
[2] Scan Networks      →  Pick scan duration, select target AP
[3] Capture Handshake  →  Choose: passive / deauth / PMKID
[4] Generate Wordlist  →  Choose strategy (SSID mutations recommended first)
[5] Crack              →  aircrack-ng matches passwords against MIC
[6] Full Auto          →  Does all of the above in sequence
```

### Full Auto Mode example

```
[>] 6
  [*] Step 1/5: Setting up interface...
  [+] Monitor mode: wlan0mon
  [*] Step 2/5: Scanning for networks...
      # SSID                BSSID               CH   ENCRYPTION   PWR
      1 HomeNetwork         AA:BB:CC:DD:EE:FF    6    WPA2         -65
  Select target [1-1]: 1
  [*] Step 3/5: Capturing handshake (deauth mode)...
  [+] WPA handshake captured! → captures/HomeNetwork_20260101_120000-01.cap
  [*] Step 4/5: Generating wordlist...
  [*] Step 5/5: Cracking...
  [★] KEY FOUND!  →  HomeNetwork2023!
```

---

## Directory Structure

```
wifi-auditor/
├── wifi_auditor.py       Main entry point
├── modules/
│   ├── banner.py         Colors, ASCII banner, display helpers
│   ├── utils.py          Root check, dependency check, interface management
│   ├── scanner.py        airodump-ng wrapper + CSV parser
│   ├── handshake.py      Passive / deauth / PMKID capture
│   ├── wordlist.py       10-strategy wordlist generation engine
│   └── cracker.py        aircrack-ng / hashcat wrapper
├── data/
│   └── common_passwords.txt   Built-in password list
├── captures/             Handshake .cap files saved here
├── wordlists/            Generated wordlists saved here
├── results/              Cracked keys saved here
└── install.sh            Dependency installer
```

---

## How WPA2 Cracking Works

```
Client ──── EAPOL M1 ────▶ AP
Client ◀─── EAPOL M2 ──── AP
Client ──── EAPOL M3 ────▶ AP
Client ◀─── EAPOL M4 ──── AP
        └── capture ──▶ .cap file

For each password in wordlist:
  PMK  = PBKDF2-HMAC-SHA1(password, SSID, 4096, 32)
  PTK  = PRF-512(PMK, "Pairwise key expansion", ANonce, SNonce, MACs)
  MIC  = HMAC-MD5/SHA1/SHA256(KCK, EAPOL frame)
  if MIC == captured_MIC → PASSWORD FOUND
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

**"No wireless interfaces found"** — Check `iwconfig` / `ip link`. Your adapter may need a driver.

**Monitor mode fails** — Try `sudo airmon-ng check kill` then `sudo airmon-ng start wlan0`.

**No handshake captured** — The client must reconnect. Use deauth mode or wait for a natural roam event. Increase timeout.

**aircrack-ng finds no handshake** — Capture may be incomplete. Try re-capturing. Verify: `aircrack-ng captures/yourfile-01.cap`.

---

## License

MIT — for authorized security testing only.
