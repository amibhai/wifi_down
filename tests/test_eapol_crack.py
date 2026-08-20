"""
Tests for pure-Python 4-way handshake (EAPOL / type 02) support in the 22000
pipeline — Phase 10.

A valid EAPOL 22000 line is *constructed* from a known passphrase (SNonce placed
at the standard offset, MIC computed over the zeroed frame) and must then be
parsed, cracked, and verified back to that passphrase. This exercises the whole
EAPOL path end to end with no RF and no external tools.
"""
from __future__ import annotations

from modules import wpacrypto as wc
from modules import pmkid


SSID = "HandshakeNet"
AP   = "aabbccddeeff"
STA  = "112233445566"
PW   = "sunshine88"
ANONCE = bytes([0x11] * 32)
SNONCE = bytes([0x22] * 32)


def _build_eapol_frame() -> bytes:
    """A minimal but structurally-correct EAPOL-Key frame (M2), MIC field zeroed."""
    frame = bytearray(121)
    frame[0] = 0x02                       # 802.1X version
    frame[1] = 0x03                       # type = EAPOL-Key
    frame[2:4] = (len(frame) - 4).to_bytes(2, "big")
    frame[4] = 0x02                       # descriptor type (RSN)
    frame[5:7] = (0x008a).to_bytes(2, "big")   # key info: low 3 bits = version 2
    frame[17:49] = SNONCE                 # Key Nonce (SNonce) at offset 17
    # frame[81:97] MIC field stays zero
    return bytes(frame)


def _build_line(pw: str = PW, ssid: str = SSID) -> str:
    frame = _build_eapol_frame()
    p = wc.ptk(wc.pmk(pw, ssid), AP, STA, ANONCE, SNONCE)
    mic = wc.compute_mic(wc.kck(p), wc.zero_mic(frame), 2)
    return (f"WPA*02*{mic.hex()}*{AP}*{STA}*{ssid.encode().hex()}*"
            f"{ANONCE.hex()}*{frame.hex()}*00")


def _write(tmp_path, line):
    f = tmp_path / "hs.hc22000"
    f.write_text(line + "\n", encoding="utf-8")
    return str(f)


def _wordlist(tmp_path, words):
    f = tmp_path / "wl.txt"
    f.write_text("\n".join(words) + "\n", encoding="utf-8")
    return str(f)


class TestEapolFieldExtraction:
    def test_snonce_offset(self):
        frame = _build_eapol_frame()
        assert wc.snonce_from_eapol(frame) == SNONCE

    def test_key_version(self):
        frame = _build_eapol_frame()
        assert wc.key_version_from_eapol(frame) == 2

    def test_key_version_short_frame_defaults_2(self):
        assert wc.key_version_from_eapol(b"\x00\x00") == 2


class TestParseEapolLine:
    def test_parses_fields(self):
        rec = pmkid.parse_hc22000_eapol(_build_line())
        assert rec["type"] == "02"
        assert rec["bssid"] == "AA:BB:CC:DD:EE:FF"
        assert rec["essid"] == SSID
        assert rec["anonce"] == ANONCE.hex()
        assert rec["snonce"] == SNONCE.hex()
        assert rec["key_version"] == 2

    def test_rejects_pmkid_line(self):
        assert pmkid.parse_hc22000_eapol("WPA*01*deadbeef*aabbccddeeff*112233445566*4869**") is None

    def test_rejects_garbage(self):
        assert pmkid.parse_hc22000_eapol("nonsense") is None


class TestPureEapolCrack:
    def test_recovers_handshake_password(self, tmp_path):
        hf = _write(tmp_path, _build_line())
        wl = _wordlist(tmp_path, ["nope1234", "wrongone", PW, "later999"])
        assert pmkid.crack_hc22000_pure(hf, wl) == ("AA:BB:CC:DD:EE:FF", PW)

    def test_alias_crack_pmkid_pure_handles_eapol(self, tmp_path):
        hf = _write(tmp_path, _build_line())
        wl = _wordlist(tmp_path, ["aaaaaaaa", PW])
        assert pmkid.crack_pmkid_pure(hf, wl) == ("AA:BB:CC:DD:EE:FF", PW)

    def test_miss_returns_none(self, tmp_path):
        hf = _write(tmp_path, _build_line())
        wl = _wordlist(tmp_path, ["aaaaaaaa", "bbbbbbbb"])
        assert pmkid.crack_hc22000_pure(hf, wl) is None


class TestVerifierHandlesEapol:
    def test_correct_password(self, tmp_path):
        v = pmkid.make_verifier(_write(tmp_path, _build_line()))
        assert v is not None
        assert v(PW) is True

    def test_wrong_password(self, tmp_path):
        v = pmkid.make_verifier(_write(tmp_path, _build_line()))
        assert v("notitmate") is False

    def test_pmkid_alias_also_verifies_eapol(self, tmp_path):
        v = pmkid.make_pmkid_verifier(_write(tmp_path, _build_line()))
        assert v(PW) is True


class TestMixedRecords:
    def test_load_both_pmkid_and_eapol(self, tmp_path):
        pmkid_line = (f"WPA*01*"
                      f"{wc.compute_pmkid(wc.pmk('otherpw12', SSID), AP, STA).hex()}"
                      f"*{AP}*{STA}*{SSID.encode().hex()}***")
        f = tmp_path / "mixed.hc22000"
        f.write_text(_build_line() + "\n" + pmkid_line + "\n", encoding="utf-8")
        records = pmkid.load_hc22000_records(str(f))
        types = sorted(r["type"] for r in records)
        assert types == ["01", "02"]
