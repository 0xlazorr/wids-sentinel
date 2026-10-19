"""
Tests for CLI and Configuration.
"""

import os
import tempfile
from unittest.mock import patch

from wids.cli import build_parser, main
from wids.config import SentinelConfig
from tests.conftest import make_beacon
from scapy.utils import wrpcap


def test_cli_parser_defaults():
    parser = build_parser()
    args = parser.parse_args(["-r", "test.pcap"])
    assert args.read_pcap == "test.pcap"
    assert args.output == "alerts.json"


def test_config_from_json():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as tmp:
        tmp.write('{"authorized_aps": [{"ssid": "Test", "bssid": "AA:BB:CC:DD:EE:FF", "channel": 1}], "deauth_threshold_burst": 12}')
        cfg_path = tmp.name

    try:
        cfg = SentinelConfig.from_json(cfg_path)
        assert "aa:bb:cc:dd:ee:ff" in cfg.authorized_aps
        assert cfg.authorized_aps["aa:bb:cc:dd:ee:ff"].ssid == "Test"
        assert cfg.deauth_threshold_burst == 12
    finally:
        if os.path.exists(cfg_path):
            os.remove(cfg_path)


def test_cli_execution_with_pcap():
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as pcap_tmp:
        pcap_path = pcap_tmp.name

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as json_tmp:
        json_path = json_tmp.name

    try:
        wrpcap(pcap_path, [make_beacon("TestNet", "00:11:22:33:44:55")])

        test_args = ["wids-sentinel", "-r", pcap_path, "-o", json_path, "--auth-ssid", "TestNet", "--auth-bssid", "00:11:22:33:44:55"]
        with patch("sys.argv", test_args):
            exit_code = main()
            assert exit_code == 0
    finally:
        if os.path.exists(pcap_path):
            os.remove(pcap_path)
        if os.path.exists(json_path):
            os.remove(json_path)


def test_cli_mismatched_auth_flags():
    test_args = ["wids-sentinel", "-r", "test.pcap", "--auth-ssid", "TestNet"]
    with patch("sys.argv", test_args):
        exit_code = main()
        assert exit_code == 1
