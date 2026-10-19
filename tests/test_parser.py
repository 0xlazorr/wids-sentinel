"""
Tests for 802.11 FrameParser.
"""

from wids.core.parser import FrameParser
from wids.core.models import FrameSubtype
from tests.conftest import make_beacon, make_deauth


def test_parse_beacon():
    pkt = make_beacon(ssid="TestNetwork", bssid="00:11:22:33:44:55", channel=11, crypto="WPA2", seq=123)
    parsed = FrameParser.parse(pkt)

    assert parsed is not None
    assert parsed.subtype == FrameSubtype.BEACON
    assert parsed.subtype_name == "Beacon"
    assert parsed.addr2 == "00:11:22:33:44:55"
    assert parsed.addr3 == "00:11:22:33:44:55"
    assert parsed.ssid == "TestNetwork"
    assert parsed.channel == 11
    assert parsed.crypto_type == "WPA2"
    assert parsed.sequence_num == 123


def test_parse_wpa3_beacon():
    pkt = make_beacon(ssid="NextGenWiFi", bssid="00:aa:bb:cc:dd:ee", channel=36, crypto="WPA3")
    parsed = FrameParser.parse(pkt)

    assert parsed is not None
    assert parsed.crypto_type == "WPA3"
    assert parsed.ssid == "NextGenWiFi"


def test_parse_deauth():
    pkt = make_deauth(
        bssid="00:11:22:33:44:55",
        src="00:11:22:33:44:55",
        dst="11:22:33:44:55:66",
        reason=7,
    )
    parsed = FrameParser.parse(pkt)

    assert parsed is not None
    assert parsed.subtype == FrameSubtype.DEAUTH
    assert parsed.subtype_name == "Deauthentication"
    assert parsed.addr1 == "11:22:33:44:55:66"
    assert parsed.addr2 == "00:11:22:33:44:55"
    assert parsed.addr3 == "00:11:22:33:44:55"


def test_parse_non_80211():
    from scapy.layers.inet import IP, ICMP
    pkt = IP(dst="1.1.1.1") / ICMP()
    parsed = FrameParser.parse(pkt)
    assert parsed is None


def test_sanitize_ssid_null_bytes():
    assert FrameParser._sanitize_ssid("WiFi\x00\x00") == "WiFi"
    assert FrameParser._sanitize_ssid("\x00\x00\x00") == "<Hidden SSID>"
    assert FrameParser._sanitize_ssid(None) is None


def test_normalize_mac():
    assert FrameParser._normalize_mac("00:11:22:33:44:55") == "00:11:22:33:44:55"
    assert FrameParser._normalize_mac("AA:BB:CC:DD:EE:FF") == "aa:bb:cc:dd:ee:ff"
    assert FrameParser._normalize_mac(b"\xaa\xbb\xcc\xdd\xee\xff") == "aa:bb:cc:dd:ee:ff"
    assert FrameParser._normalize_mac(b"00:11:22:33:44:55") == "00:11:22:33:44:55"
    assert FrameParser._normalize_mac(None) is None


def test_parse_5ghz_ht_channel():
    from scapy.layers.dot11 import RadioTap, Dot11, Dot11Beacon, Dot11Elt
    # 5GHz beacon with HT Operation element (ID 61), channel 36
    pkt = (
        RadioTap()
        / Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2="00:11:22:33:44:55", addr3="00:11:22:33:44:55")
        / Dot11Beacon()
        / Dot11Elt(ID=0, info=b"5G_Network")
        / Dot11Elt(ID=61, info=bytes([36]) + b"\x00" * 21)
    )
    parsed = FrameParser.parse(pkt)
    assert parsed is not None
    assert parsed.channel == 36


def test_parse_radiotap_frequency_channel():
    from scapy.layers.dot11 import RadioTap, Dot11, Dot11Beacon, Dot11Elt
    # Beacon without DS set, but with RadioTap ChannelFrequency 5180 (Channel 36)
    rt = RadioTap(ChannelFrequency=5180)
    pkt = (
        rt
        / Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2="00:11:22:33:44:55", addr3="00:11:22:33:44:55")
        / Dot11Beacon()
        / Dot11Elt(ID=0, info=b"5G_Freq_Net")
    )
    parsed = FrameParser.parse(pkt)
    assert parsed is not None
    assert parsed.channel == 36
