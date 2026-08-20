"""
Unit tests for modules/wpacrypto.py — offline WPA verification crypto.

Correctness is anchored two ways:
  1. PMK against the **published IEEE 802.11i / RFC PBKDF2 test vectors** (the
     hard part — the KDF — is proven against known answers).
  2. Full round-trips (PMK→PTK→KCK→MIC and PMK→PMKID): a key computed by this
     module must verify with the right passphrase and be rejected with a wrong
     one. This exercises every line of the derivation end to end.
"""
from __future__ import annotations

from modules import wpacrypto as wc


# The two canonical IEEE 802.11i passphrase→PMK vectors.
PMK_VECTORS = [
    ("password", "IEEE",
     "f42c6fc52df0ebef9ebb4b90b38a5f902e83fe1b135a70e23aed762e9710a12e"),
    ("ThisIsAPassword", "ThisIsASSID",
     "0dc0d6eb90555ed6419756b9a15ec3e3209b63df707dd508d14581f8982721af"),
]

AP  = "aa:bb:cc:dd:ee:ff"
STA = "11:22:33:44:55:66"
ANONCE = "00" * 32
SNONCE = "11" * 32
SSID = "TestNet"
PW   = "password123"
WRONG = "wrongpass9"


class TestPMK:
    def test_ieee_vectors(self):
        for pw, ssid, expect in PMK_VECTORS:
            assert wc.pmk(pw, ssid).hex() == expect

    def test_length(self):
        assert len(wc.pmk("whatever", "SSID")) == 32

    def test_deterministic(self):
        assert wc.pmk(PW, SSID) == wc.pmk(PW, SSID)


class TestByteHelper:
    def test_hex_with_colons(self):
        assert wc._b("aa:bb:cc") == b"\xaa\xbb\xcc"

    def test_bytes_passthrough(self):
        assert wc._b(b"\x01\x02") == b"\x01\x02"


class TestPTK:
    def test_length_64(self):
        p = wc.ptk(wc.pmk(PW, SSID), AP, STA, ANONCE, SNONCE)
        assert len(p) == 64

    def test_kck_is_first_16(self):
        p = wc.ptk(wc.pmk(PW, SSID), AP, STA, ANONCE, SNONCE)
        assert wc.kck(p) == p[:16]

    def test_symmetry_ap_sta_order(self):
        # min/max ordering means swapping AP/STA yields the SAME PTK.
        a = wc.ptk(wc.pmk(PW, SSID), AP, STA, ANONCE, SNONCE)
        b = wc.ptk(wc.pmk(PW, SSID), STA, AP, SNONCE, ANONCE)
        assert a == b


class TestPMKIDRoundTrip:
    def test_correct_passphrase_verifies(self):
        pmkid = wc.compute_pmkid(wc.pmk(PW, SSID), AP, STA)
        assert wc.verify_pmkid(PW, SSID, AP, STA, pmkid) is True

    def test_wrong_passphrase_rejected(self):
        pmkid = wc.compute_pmkid(wc.pmk(PW, SSID), AP, STA)
        assert wc.verify_pmkid(WRONG, SSID, AP, STA, pmkid) is False

    def test_wrong_ssid_rejected(self):
        pmkid = wc.compute_pmkid(wc.pmk(PW, SSID), AP, STA)
        assert wc.verify_pmkid(PW, "OtherNet", AP, STA, pmkid) is False

    def test_pmkid_length(self):
        assert len(wc.compute_pmkid(wc.pmk(PW, SSID), AP, STA)) == 16

    def test_accepts_hex_pmkid(self):
        pmkid = wc.compute_pmkid(wc.pmk(PW, SSID), AP, STA)
        assert wc.verify_pmkid(PW, SSID, AP, STA, pmkid.hex()) is True


class TestEAPOLRoundTrip:
    def _frame(self):
        # A plausible EAPOL-Key frame long enough to hold the MIC field.
        return bytes(range(120))

    def _mic_for(self, pw, key_version=2):
        frame = wc.zero_mic(self._frame())
        p = wc.ptk(wc.pmk(pw, SSID), AP, STA, ANONCE, SNONCE)
        return frame, wc.compute_mic(wc.kck(p), frame, key_version)

    def test_correct_passphrase_verifies(self):
        frame, mic = self._mic_for(PW)
        assert wc.verify_eapol(PW, SSID, AP, STA, ANONCE, SNONCE, frame, mic) is True

    def test_wrong_passphrase_rejected(self):
        frame, mic = self._mic_for(PW)
        assert wc.verify_eapol(WRONG, SSID, AP, STA, ANONCE, SNONCE, frame, mic) is False

    def test_wpa1_md5_variant(self):
        frame, mic = self._mic_for(PW, key_version=1)
        assert len(mic) == 16
        assert wc.verify_eapol(PW, SSID, AP, STA, ANONCE, SNONCE, frame, mic,
                               key_version=1) is True

    def test_zero_mic_clears_field(self):
        frame = bytes([0xFF] * 120)
        z = wc.zero_mic(frame)
        assert z[wc.MIC_OFFSET:wc.MIC_OFFSET + wc.MIC_LEN] == b"\x00" * wc.MIC_LEN
        assert z[:wc.MIC_OFFSET] == frame[:wc.MIC_OFFSET]  # rest untouched


class TestPureCracker:
    def test_crack_pmkid_finds_password(self):
        pmkid = wc.compute_pmkid(wc.pmk(PW, SSID), AP, STA)
        wl = ["short", "nope1234", PW, "later9999"]
        assert wc.crack_pmkid(SSID, AP, STA, pmkid, wl) == PW

    def test_crack_pmkid_miss(self):
        pmkid = wc.compute_pmkid(wc.pmk(PW, SSID), AP, STA)
        assert wc.crack_pmkid(SSID, AP, STA, pmkid, ["aaaaaaaa", "bbbbbbbb"]) is None

    def test_crack_pmkid_skips_invalid_length(self):
        # 'short' (<8) must be skipped, not crash — and the real one still found.
        pmkid = wc.compute_pmkid(wc.pmk(PW, SSID), AP, STA)
        assert wc.crack_pmkid(SSID, AP, STA, pmkid, ["short", "x", PW]) == PW

    def test_crack_eapol_finds_password(self):
        frame = wc.zero_mic(bytes(range(120)))
        p = wc.ptk(wc.pmk(PW, SSID), AP, STA, ANONCE, SNONCE)
        mic = wc.compute_mic(wc.kck(p), frame, 2)
        wl = ["nope1234", PW]
        assert wc.crack_eapol(SSID, AP, STA, ANONCE, SNONCE, frame, mic, wl) == PW
