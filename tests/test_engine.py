"""
End-to-end tests for SentinelEngine and alert handling.
"""

import os
import tempfile
from scapy.utils import wrpcap

from wids.engine import SentinelEngine
from wids.alerts.handler import AlertHandler
from wids.core.parser import FrameParser
from tests.conftest import make_beacon, make_deauth


def test_engine_processes_frames_and_logs(base_config):
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        alert_file = tmp.name

    try:
        handler = AlertHandler(output_file=alert_file)
        engine = SentinelEngine(config=base_config, alert_handler=handler)

        # 1 legitimate beacon
        p1 = FrameParser.parse(make_beacon("Corp_Secure_WiFi", "00:11:22:33:44:55", channel=6, crypto="WPA2"))
        engine.process_frame(p1)

        # 1 rogue beacon
        p2 = FrameParser.parse(make_beacon("Corp_Secure_WiFi", "aa:bb:cc:dd:ee:ff", channel=6, crypto="WPA2"))
        alerts = engine.process_frame(p2)

        assert len(alerts) == 1
        assert engine.frames_inspected == 2
        assert len(engine.discovered_aps) == 2

        # Check alert was logged to JSON file
        assert os.path.exists(alert_file)
        with open(alert_file, "r") as f:
            lines = f.readlines()
            assert len(lines) == 1
            assert "EVIL_TWIN" in lines[0]
    finally:
        if os.path.exists(alert_file):
            os.remove(alert_file)


def test_engine_offline_pcap_execution(base_config):
    # Generate temporary PCAP file
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as pcap_tmp:
        pcap_path = pcap_tmp.name

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as json_tmp:
        json_path = json_tmp.name

    try:
        packets = []
        # Legitimate beacon
        packets.append(make_beacon("Corp_Secure_WiFi", "00:11:22:33:44:55", channel=6, crypto="WPA2"))
        # 6 deauth packets to trigger deauth flood
        for _ in range(6):
            packets.append(make_deauth("00:11:22:33:44:55", "00:11:22:33:44:55", "11:22:33:44:55:66"))

        wrpcap(pcap_path, packets)

        handler = AlertHandler(output_file=json_path)
        engine = SentinelEngine(config=base_config, alert_handler=handler)

        engine.start_offline(pcap_path)

        assert engine.frames_inspected == 7
        summary = handler.get_summary()
        assert summary["TOTAL"] >= 1
    finally:
        if os.path.exists(pcap_path):
            os.remove(pcap_path)
        if os.path.exists(json_path):
            os.remove(json_path)
