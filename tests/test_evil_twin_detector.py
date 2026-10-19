"""
Tests for EvilTwinDetector.
"""

from wids.detectors.evil_twin import EvilTwinDetector
from wids.core.parser import FrameParser
from wids.core.models import Severity
from tests.conftest import make_beacon


def test_authorized_beacon_no_alert(base_config):
    detector = EvilTwinDetector(base_config)
    # Authorized AP in base_config: Corp_Secure_WiFi @ 00:11:22:33:44:55 on Ch 6 WPA2
    raw = make_beacon("Corp_Secure_WiFi", "00:11:22:33:44:55", channel=6, crypto="WPA2")
    parsed = FrameParser.parse(raw)
    alerts = detector.process(parsed)

    assert len(alerts) == 0


def test_evil_twin_unauthorized_bssid(base_config):
    detector = EvilTwinDetector(base_config)
    # Attacker broadcasts authorized SSID from rogue BSSID 00:66:77:88:99:00
    raw = make_beacon("Corp_Secure_WiFi", "00:66:77:88:99:00", channel=6, crypto="WPA2")
    parsed = FrameParser.parse(raw)
    alerts = detector.process(parsed)

    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.rule_name == "WIDS-RULE-002:EVIL_TWIN_ROGUE_AP"
    assert alert.severity == Severity.CRITICAL
    assert alert.bssid == "00:66:77:88:99:00"
    assert alert.details["rogue_bssid"] == "00:66:77:88:99:00"
    assert alert.details["authorized_bssid"] == "00:11:22:33:44:55"


def test_encryption_downgrade_alert(base_config):
    detector = EvilTwinDetector(base_config)
    # Authorized BSSID broadcasting OPEN network instead of WPA2
    raw = make_beacon("Corp_Secure_WiFi", "00:11:22:33:44:55", channel=6, crypto="OPEN")
    parsed = FrameParser.parse(raw)
    alerts = detector.process(parsed)

    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.rule_name == "WIDS-RULE-003:CRYPTO_DOWNGRADE"
    assert alert.severity == Severity.CRITICAL
    assert alert.details["expected_crypto"] == "WPA2"
    assert alert.details["observed_crypto"] == "OPEN"


def test_channel_mismatch_alert(base_config):
    detector = EvilTwinDetector(base_config)
    # Expected channel is 6, seen on channel 1
    raw = make_beacon("Corp_Secure_WiFi", "00:11:22:33:44:55", channel=1, crypto="WPA2")
    parsed = FrameParser.parse(raw)
    alerts = detector.process(parsed)

    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.rule_name == "WIDS-RULE-004:CHANNEL_MISMATCH"
    assert alert.severity == Severity.MEDIUM
    assert alert.details["expected_channel"] == 6
    assert alert.details["observed_channel"] == 1


def test_hidden_ssid_no_evil_twin_alert(base_config):
    detector = EvilTwinDetector(base_config)
    # Beacons with empty/hidden SSID from two different BSSIDs
    raw1 = make_beacon("", "00:aa:bb:cc:dd:01")
    raw2 = make_beacon("", "00:aa:bb:cc:dd:02")

    alerts1 = detector.process(FrameParser.parse(raw1))
    alerts2 = detector.process(FrameParser.parse(raw2))

    assert len(alerts1) == 0
    assert len(alerts2) == 0


def test_multiple_authorized_aps_same_ssid_no_false_positive(base_config):
    # Add a second authorized AP sharing the same SSID "Corp_Secure_WiFi"
    base_config.add_authorized_ap(
        ssid="Corp_Secure_WiFi",
        bssid="00:11:22:33:44:66",
        channel=1,
        crypto="WPA2",
    )
    detector = EvilTwinDetector(base_config)

    # Beacon from the second authorized AP
    raw = make_beacon("Corp_Secure_WiFi", "00:11:22:33:44:66", channel=1, crypto="WPA2")
    alerts = detector.process(FrameParser.parse(raw))

    # Must NOT trigger an Evil Twin alert on another authorized AP
    assert len(alerts) == 0
