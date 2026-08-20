"""
Unit tests for modules/pmkid.py — hashcat-22000 hash intelligence.

Pure logic only (parsing/summarising/`--show` output). No hashcat, no RF.
Real 22000 lines are used so the parser is validated against the actual format
hcxpcapngtool emits.
"""
from __future__ import annotations

from modules import pmkid
from modules.pmkid import (
    mac_from_hex, essid_from_hex, parse_hc22000_line,
    summarize_hash_lines, summarize_hash_file, describe_summary,
    parse_hashcat_show, TYPE_PMKID, TYPE_EAPOL,
)

# "HomeNet" == 486f6d654e6574 ; AP aa:bb:cc:dd:ee:ff ; STA 11:22:33:44:55:66
ESSID_HEX = "486f6d654e6574"          # HomeNet
AP  = "aabbccddeeff"
STA = "112233445566"
PMKID_LINE = f"WPA*01*deadbeefcafebabedeadbeefcafebabe*{AP}*{STA}*{ESSID_HEX}***"
EAPOL_LINE = (f"WPA*02*0011223344556677889900aabbccddee*{AP}*{STA}*{ESSID_HEX}*"
              f"cafe...*0103...*00")


class TestMacFromHex:
    def test_valid(self):
        assert mac_from_hex("aabbccddeeff") == "AA:BB:CC:DD:EE:FF"

    def test_uppercase_input(self):
        assert mac_from_hex("AABBCCDDEEFF") == "AA:BB:CC:DD:EE:FF"

    def test_bad_length(self):
        assert mac_from_hex("aabbcc") == ""

    def test_non_hex(self):
        assert mac_from_hex("zzbbccddeeff") == ""

    def test_empty(self):
        assert mac_from_hex("") == ""


class TestEssidFromHex:
    def test_decodes_text(self):
        assert essid_from_hex(ESSID_HEX) == "HomeNet"

    def test_odd_length(self):
        assert essid_from_hex("abc") == ""

    def test_empty(self):
        assert essid_from_hex("") == ""

    def test_utf8(self):
        # "café" → 636166c3a9
        assert essid_from_hex("636166c3a9") == "café"


class TestParseHc22000Line:
    def test_pmkid(self):
        rec = parse_hc22000_line(PMKID_LINE)
        assert rec["type"] == TYPE_PMKID
        assert rec["type_name"] == "PMKID"
        assert rec["bssid"] == "AA:BB:CC:DD:EE:FF"
        assert rec["station"] == "11:22:33:44:55:66"
        assert rec["essid"] == "HomeNet"

    def test_eapol(self):
        rec = parse_hc22000_line(EAPOL_LINE)
        assert rec["type"] == TYPE_EAPOL
        assert rec["type_name"] == "EAPOL"
        assert rec["bssid"] == "AA:BB:CC:DD:EE:FF"

    def test_not_wpa(self):
        assert parse_hc22000_line("1234:abcd") is None

    def test_too_few_fields(self):
        assert parse_hc22000_line("WPA*01*hash") is None

    def test_empty(self):
        assert parse_hc22000_line("") is None
        assert parse_hc22000_line(None) is None

    def test_bad_bssid_rejected(self):
        assert parse_hc22000_line(f"WPA*01*hash*ZZZ*{STA}*{ESSID_HEX}***") is None


class TestSummarize:
    def test_mixed(self):
        s = summarize_hash_lines([PMKID_LINE, EAPOL_LINE, "garbage", ""])
        assert s["total"] == 2
        assert s["pmkid"] == 1
        assert s["eapol"] == 1
        assert s["crackable"] is True
        assert "AA:BB:CC:DD:EE:FF" in s["networks"]
        net = s["networks"]["AA:BB:CC:DD:EE:FF"]
        assert net["ssid"] == "HomeNet"
        assert net["pmkid"] == 1 and net["eapol"] == 1

    def test_empty(self):
        s = summarize_hash_lines([])
        assert s["total"] == 0 and s["crackable"] is False and s["networks"] == {}

    def test_multiple_networks(self):
        other = f"WPA*01*ffff...*001122334455*{STA}*{ESSID_HEX}***"
        s = summarize_hash_lines([PMKID_LINE, other])
        assert len(s["networks"]) == 2
        assert s["pmkid"] == 2

    def test_file(self, tmp_path):
        f = tmp_path / "h.hc22000"
        f.write_text(PMKID_LINE + "\n" + EAPOL_LINE + "\n", encoding="utf-8")
        s = summarize_hash_file(str(f))
        assert s["total"] == 2

    def test_file_missing(self):
        assert summarize_hash_file("/no/such/file.hc22000")["total"] == 0


class TestDescribeSummary:
    def test_mixed(self):
        s = summarize_hash_lines([PMKID_LINE, EAPOL_LINE])
        assert describe_summary(s) == "1 PMKID + 1 EAPOL across 1 network(s)"

    def test_pmkid_only(self):
        assert describe_summary(summarize_hash_lines([PMKID_LINE])) == \
            "1 PMKID across 1 network(s)"

    def test_none(self):
        assert describe_summary(summarize_hash_lines([])) == \
            "no crackable PMKID/EAPOL hashes"


class TestParseHashcatShow:
    def test_maps_bssid_to_password(self):
        out = parse_hashcat_show(f"{PMKID_LINE}:hunter2\n")
        assert out == {"AA:BB:CC:DD:EE:FF": "hunter2"}

    def test_password_with_colon(self):
        # The 22000 hash has no ':' so split-on-first-colon keeps a colon pw intact.
        out = parse_hashcat_show(f"{PMKID_LINE}:pa:ss:word\n")
        assert out["AA:BB:CC:DD:EE:FF"] == "pa:ss:word"

    def test_ignores_noise(self):
        assert parse_hashcat_show("Session..........: hashcat\n\n") == {}

    def test_empty(self):
        assert parse_hashcat_show("") == {}
