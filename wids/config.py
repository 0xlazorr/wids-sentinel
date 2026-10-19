"""
Configuration management for wids-sentinel.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional
import json
import os


@dataclass
class AuthorizedAP:
    ssid: str
    bssid: str
    channel: Optional[int] = None
    expected_crypto: Optional[str] = None


@dataclass
class SentinelConfig:
    """Master configuration options for the IDS engine."""
    # Authorized network profiles: BSSID (lowercase) -> AuthorizedAP
    authorized_aps: Dict[str, AuthorizedAP] = field(default_factory=dict)

    # Thresholds
    deauth_threshold_burst: int = 8         # frames per time window
    deauth_window_seconds: float = 2.0      # sliding window size
    disassoc_threshold_burst: int = 8
    disassoc_window_seconds: float = 2.0

    # Detection feature toggles
    enable_deauth_detection: bool = True
    enable_disassoc_detection: bool = True
    enable_evil_twin_detection: bool = True
    enable_karma_detection: bool = True
    enable_beacon_drift_detection: bool = True

    # Output options
    alert_log_file: Optional[str] = "alerts.json"
    verbose: bool = False

    @classmethod
    def from_json(cls, file_path: str) -> "SentinelConfig":
        """Load configuration from a JSON file."""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Config file not found: {file_path}")

        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        auth_aps: Dict[str, AuthorizedAP] = {}
        for item in data.get("authorized_aps", []):
            bssid = item["bssid"].lower()
            auth_aps[bssid] = AuthorizedAP(
                ssid=item.get("ssid", ""),
                bssid=bssid,
                channel=item.get("channel"),
                expected_crypto=item.get("expected_crypto"),
            )

        return cls(
            authorized_aps=auth_aps,
            deauth_threshold_burst=data.get("deauth_threshold_burst", 8),
            deauth_window_seconds=data.get("deauth_window_seconds", 2.0),
            disassoc_threshold_burst=data.get("disassoc_threshold_burst", 8),
            disassoc_window_seconds=data.get("disassoc_window_seconds", 2.0),
            enable_deauth_detection=data.get("enable_deauth_detection", True),
            enable_disassoc_detection=data.get("enable_disassoc_detection", True),
            enable_evil_twin_detection=data.get("enable_evil_twin_detection", True),
            enable_karma_detection=data.get("enable_karma_detection", True),
            enable_beacon_drift_detection=data.get("enable_beacon_drift_detection", True),
            alert_log_file=data.get("alert_log_file", "alerts.json"),
            verbose=data.get("verbose", False),
        )

    def add_authorized_ap(self, ssid: str, bssid: str, channel: Optional[int] = None, crypto: Optional[str] = None):
        """Register an authorized AP in-memory."""
        normalized_bssid = bssid.lower()
        self.authorized_aps[normalized_bssid] = AuthorizedAP(
            ssid=ssid,
            bssid=normalized_bssid,
            channel=channel,
            expected_crypto=crypto,
        )
