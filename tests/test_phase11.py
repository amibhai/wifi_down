"""
Tests for Phase 11 loose-ends: hashcat mask generation, the WPA3-SAE downgrade
personality, and raw-.cap handshake assembly. Pure logic only.
"""
from __future__ import annotations

from modules import phantom, pmkid, strategy
from modules import wpacrypto as wc

# ── #2 Mask attacks ──────────────────────────────────────────────────────────

class TestMasks:
    def test_generic_crackable_gets_8digit(self):
        m = strategy.masks_for_target({"security_tier": "WPA2", "ssid_tag": "CUSTOM"})
        assert m == ["?d?d?d?d?d?d?d?d"]

    def test_numeric_gets_phone_lengths(self):
        m = strategy.masks_for_target({"security_tier": "WPA2", "ssid_tag": "NUMERIC"})
        assert "?d" * 10 in m and "?d" * 8 in m and "?d" * 9 in m
        assert len(m) == len(set(m))               # deduped

    def test_non_crackable_empty(self):
        assert strategy.masks_for_target({"security_tier": "WPA2_ENT"}) == []
        assert strategy.masks_for_target({"security_tier": "WPA3_SAE"}) == []

    def test_materialize_writes_hcmask(self, tmp_path):
        p = strategy.materialize_masks(
            {"security_tier": "WPA2", "ssid_tag": "NUMERIC", "bssid": "AA:BB:CC:DD:EE:FF"},
            out_dir=str(tmp_path))
        assert p and p.endswith(".hcmask")
        lines = open(p, encoding="utf-8").read().splitlines()
        assert all(set(ln) <= set("?d") for ln in lines)

    def test_materialize_none_for_enterprise(self, tmp_path):
        assert strategy.materialize_masks(
            {"security_tier": "WPA2_ENT"}, out_dir=str(tmp_path)) is None


# ── #3 WPA3-SAE active downgrade ─────────────────────────────────────────────

class TestDowngrade:
    def test_recommended_for_transition(self):
        assert phantom.downgrade_recommended({"security_tier": "WPA3_TRANS"}) is True
        assert phantom.downgrade_recommended({"wpa3_downgrade_risk": True}) is True

    def test_not_recommended_otherwise(self):
        assert phantom.downgrade_recommended({"security_tier": "WPA2"}) is False
        assert phantom.downgrade_recommended({"security_tier": "WPA3_SAE"}) is False
        assert phantom.downgrade_recommended(None) is False

    def test_hostapd_conf_is_wpa2_only(self):
        p = phantom._write_hostapd_conf(
            "wlan0", "TargetNet", 6, phantom.PERSONALITY_DOWNGRADE)
        try:
            conf = p.read_text()
            assert "wpa=2" in conf
            assert "WPA-PSK" in conf
            assert "CCMP" in conf
            assert "SAE" not in conf              # the whole point of a downgrade
        finally:
            p.unlink(missing_ok=True)


# ── #4 Raw .cap handshake assembly (pure crypto path) ────────────────────────

SSID, AP, STA, PW = "CapNet", "aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66", "raccoon12"
ANONCE = bytes([0x11] * 32)
SNONCE = bytes([0x22] * 32)


def _m1_frame():
    f = bytearray(121)
    f[0], f[1], f[4] = 0x02, 0x03, 0x02
    f[5:7] = (0x0088).to_bytes(2, "big")     # ACK-ish, version 2
    f[17:49] = ANONCE
    return bytes(f)


def _m2_frame():
    f = bytearray(121)
    f[0], f[1], f[4] = 0x02, 0x03, 0x02
    f[5:7] = (0x010a).to_bytes(2, "big")     # MIC + pairwise, version 2
    f[17:49] = SNONCE
    frame = bytes(f)
    # Insert the real MIC computed from PW so the assembled record verifies.
    p = wc.ptk(wc.pmk(PW, SSID), AP, STA, ANONCE, SNONCE)
    mic = wc.compute_mic(wc.kck(p), wc.zero_mic(frame), 2)
    return frame[:81] + mic + frame[97:]


class TestCapAssembly:
    def test_assemble_record_fields(self):
        rec = pmkid._assemble_eapol_record(SSID, AP, STA, _m1_frame(), _m2_frame())
        assert rec["bssid"] == "AA:BB:CC:DD:EE:FF"
        assert rec["anonce"] == ANONCE.hex()
        assert rec["snonce"] == SNONCE.hex()
        assert rec["key_version"] == 2

    def test_assembled_record_verifies_correct_password(self):
        rec = pmkid._assemble_eapol_record(SSID, AP, STA, _m1_frame(), _m2_frame())
        assert pmkid._record_matches(rec, PW, {}) is True

    def test_assembled_record_rejects_wrong_password(self):
        rec = pmkid._assemble_eapol_record(SSID, AP, STA, _m1_frame(), _m2_frame())
        assert pmkid._record_matches(rec, "wrongkey1", {}) is False

    def test_short_frames_return_none(self):
        assert pmkid._assemble_eapol_record(SSID, AP, STA, b"\x00" * 10, _m2_frame()) is None

    def test_norm_mac(self):
        assert pmkid._norm_mac("aa:bb:cc:dd:ee:ff") == "AA:BB:CC:DD:EE:FF"
        assert pmkid._norm_mac("aabbccddeeff") == "AA:BB:CC:DD:EE:FF"


class TestCapExtractionGraceful:
    def test_missing_scapy_or_file_returns_empty(self):
        # No scapy installed OR file absent → [] (never raises).
        assert pmkid.extract_handshakes_from_cap("/no/such/file.cap") == []

    def test_crack_cap_pure_no_records_returns_none(self, tmp_path):
        wl = tmp_path / "wl.txt"
        wl.write_text("whatever1\n", encoding="utf-8")
        assert pmkid.crack_cap_pure("/no/such/file.cap", str(wl)) is None
