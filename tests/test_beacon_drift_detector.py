"""
Tests for BeaconDriftDetector.
"""

from wids.detectors.beacon_drift import BeaconDriftDetector
from wids.core.parser import FrameParser
from wids.core.models import Severity
from tests.conftest import make_beacon


def test_normal_beacon_sequence(base_config):
    detector = BeaconDriftDetector(base_config)
    alerts = []
    # Normal sequence progression (e.g. 100, 101, 102)
    for i in range(3):
        raw = make_beacon("NormalNet", "00:11:22:33:44:55", seq=100 + i, timestamp=1000.0 + i * 0.1)
        parsed = FrameParser.parse(raw)
        alerts.extend(detector.process(parsed))

    assert len(alerts) == 0


def test_beacon_sequence_jump_anomaly(base_config):
    detector = BeaconDriftDetector(base_config)
    # First beacon at seq 100
    raw1 = make_beacon("NormalNet", "00:11:22:33:44:55", seq=100, timestamp=1000.0)
    detector.process(FrameParser.parse(raw1))

    # Second beacon arrives 0.1s later with seq 900 (jump > 200)
    raw2 = make_beacon("NormalNet", "00:11:22:33:44:55", seq=900, timestamp=1000.1)
    alerts = detector.process(FrameParser.parse(raw2))

    assert len(alerts) == 1
    assert alerts[0].rule_name == "WIDS-RULE-007:BEACON_SEQ_ANOMALY"
    assert alerts[0].severity == Severity.MEDIUM
    assert alerts[0].details["delta"] == 800


def test_multicast_bit_on_bssid_alert(base_config):
    detector = BeaconDriftDetector(base_config)
    # BSSID with multicast bit set (e.g., 01:xx:xx:xx:xx:xx)
    raw = make_beacon("SpoofedNet", "01:22:33:44:55:66", seq=10, timestamp=1000.0)
    alerts = detector.process(FrameParser.parse(raw))

    assert len(alerts) == 1
    assert alerts[0].rule_name == "WIDS-RULE-006:MALFORMED_BSSID"
    assert alerts[0].severity == Severity.HIGH
