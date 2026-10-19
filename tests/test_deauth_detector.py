"""
Tests for DeauthFloodDetector.
"""

from wids.detectors.deauth_flood import DeauthFloodDetector
from wids.core.parser import FrameParser
from wids.core.models import Severity
from tests.conftest import make_deauth


def test_deauth_below_threshold(base_config):
    detector = DeauthFloodDetector(base_config)
    # Threshold is 5. Send 3 frames.
    alerts = []
    for _ in range(3):
        raw = make_deauth("00:11:22:33:44:55", "00:11:22:33:44:55", "aa:bb:cc:dd:ee:ff")
        parsed = FrameParser.parse(raw)
        alerts.extend(detector.process(parsed))

    assert len(alerts) == 0


def test_deauth_burst_triggers_alert(base_config):
    detector = DeauthFloodDetector(base_config)
    alerts = []
    # Send 6 frames (threshold is 5) within the same window
    for _ in range(6):
        raw = make_deauth("00:11:22:33:44:55", "00:11:22:33:44:55", "aa:bb:cc:dd:ee:ff")
        parsed = FrameParser.parse(raw)
        alerts.extend(detector.process(parsed))

    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.rule_name == "WIDS-RULE-001:DEAUTH_FLOOD"
    assert alert.severity in (Severity.CRITICAL, Severity.HIGH)
    assert alert.bssid == "00:11:22:33:44:55"
    assert alert.target_mac == "aa:bb:cc:dd:ee:ff"
    assert alert.ssid == "Corp_Secure_WiFi"


def test_broadcast_deauth_severity_critical(base_config):
    detector = DeauthFloodDetector(base_config)
    alerts = []
    for _ in range(6):
        raw = make_deauth("00:99:88:77:66:55", "00:99:88:77:66:55", "ff:ff:ff:ff:ff:ff")
        parsed = FrameParser.parse(raw)
        alerts.extend(detector.process(parsed))

    assert len(alerts) == 1
    assert alerts[0].severity == Severity.CRITICAL
    assert alerts[0].details["is_broadcast"] is True
