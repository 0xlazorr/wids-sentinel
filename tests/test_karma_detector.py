"""
Tests for KarmaDetector.
"""

from wids.detectors.karma import KarmaDetector
from wids.core.parser import FrameParser
from wids.core.models import Severity
from tests.conftest import make_probe_resp


def test_single_probe_resp_no_alert(base_config):
    detector = KarmaDetector(base_config)
    raw = make_probe_resp("MyHomeWiFi", "aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66")
    parsed = FrameParser.parse(raw)
    alerts = detector.process(parsed)
    assert len(alerts) == 0


def test_karma_multiple_ssids_triggers_alert(base_config):
    detector = KarmaDetector(base_config)
    rogue_bssid = "de:ad:be:ef:00:01"
    ssids = ["Starbucks_Free", "Airport_Guest", "Hotel_Lobby_5G"]

    alerts = []
    for s in ssids:
        raw = make_probe_resp(s, rogue_bssid, "11:22:33:44:55:66")
        parsed = FrameParser.parse(raw)
        alerts.extend(detector.process(parsed))

    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.rule_name == "WIDS-RULE-005:KARMA_MANA_ATTACK"
    assert alert.severity == Severity.CRITICAL
    assert alert.bssid == rogue_bssid
    assert alert.details["total_ssids_claimed"] >= 3

    # Additional probe response within cooldown period should NOT alert
    raw_extra = make_probe_resp("Hotel_Pool_WiFi", rogue_bssid, "11:22:33:44:55:66")
    extra_alerts = detector.process(FrameParser.parse(raw_extra))
    assert len(extra_alerts) == 0
