"""
Rogue AP and Evil Twin Detection Module.
Identifies unauthorized APs broadcasting legitimate SSIDs or spoofing legitimate APs.
"""

from typing import Dict, List, Set
from collections import defaultdict
import time

from wids.detectors.base import BaseDetector
from wids.core.models import ParsedFrame, FrameSubtype, Alert, Severity, AccessPoint


class EvilTwinDetector(BaseDetector):
    """
    Detects Rogue Access Points, Evil Twin clones, and encryption downgrades.
    """

    def __init__(self, config):
        super().__init__(config)
        self.enabled = config.enable_evil_twin_detection

        # In-memory AP tracking: BSSID -> AccessPoint
        self.observed_aps: Dict[str, AccessPoint] = {}

        # SSID -> Set of BSSIDs
        self.ssid_to_bssids: Dict[str, Set[str]] = defaultdict(set)

        # Alert cooldown to prevent alert spamming for continuous beacons
        self._alert_timestamps: Dict[str, float] = {}
        self.cooldown_period = 60.0  # seconds between repeated alerts for the same rogue entity

    @property
    def name(self) -> str:
        return "EvilTwinRogueAPDetector"

    def reset(self) -> None:
        self.observed_aps.clear()
        self.ssid_to_bssids.clear()
        self._alert_timestamps.clear()

    def _should_alert(self, key: str, timestamp: float) -> bool:
        """Check if an alert should fire based on cooldown."""
        last_time = self._alert_timestamps.get(key, 0.0)
        if timestamp - last_time >= self.cooldown_period:
            self._alert_timestamps[key] = timestamp
            return True
        return False

    def process(self, frame: ParsedFrame) -> List[Alert]:
        alerts: List[Alert] = []

        if not self.enabled:
            return alerts

        # Only inspect Beacon and Probe Response frames
        if frame.subtype not in (FrameSubtype.BEACON, FrameSubtype.PROBE_RESP):
            return alerts

        bssid = frame.addr3 or frame.addr2
        ssid = frame.ssid

        if not bssid or not ssid:
            return alerts

        bssid_lower = bssid.lower()
        self.ssid_to_bssids[ssid].add(bssid_lower)

        # Check against authorized AP profiles
        authorized_ap = self.config.authorized_aps.get(bssid_lower)
        is_known_authorized = authorized_ap is not None

        # Prevent unbounded growth of observed APs
        if len(self.observed_aps) > 5000 and bssid_lower not in self.observed_aps:
            # Prune APs older than 1 hour
            now = frame.timestamp
            stale_keys = [k for k, v in self.observed_aps.items() if now - v.last_seen > 3600]
            for sk in stale_keys:
                del self.observed_aps[sk]

        # Record / Update observed AP
        if bssid_lower not in self.observed_aps:
            ap = AccessPoint(
                bssid=bssid_lower,
                ssid=ssid,
                channel=frame.channel,
                crypto_type=frame.crypto_type,
                first_seen=frame.timestamp,
                last_seen=frame.timestamp,
                is_authorized=is_known_authorized,
            )
            self.observed_aps[bssid_lower] = ap
        else:
            ap = self.observed_aps[bssid_lower]
            ap.last_seen = frame.timestamp
            ap.beacon_count += 1
            if frame.channel is not None:
                ap.channel = frame.channel

        # --- Rule 1: Rogue AP broadcasting an Authorized SSID (Classic Evil Twin) ---
        for auth_bssid, auth_profile in self.config.authorized_aps.items():
            if auth_profile.ssid.lower() == ssid.lower() and bssid_lower != auth_bssid:
                alert_key = f"evil_twin_{bssid_lower}_{ssid}"
                if self._should_alert(alert_key, frame.timestamp):
                    desc = (
                        f"CRITICAL: Rogue AP / Evil Twin detected! Unauthorized BSSID [{bssid_lower}] "
                        f"is broadcasting authorized SSID '{ssid}'. Legitimate BSSID is [{auth_bssid}]."
                    )
                    mitigation = (
                        "Initiate wireless containment or locate and disable the rogue AP device. "
                        "Warn users not to connect to open or untrusted networks matching this SSID."
                    )
                    alerts.append(
                        Alert(
                            rule_name="WIDS-RULE-002:EVIL_TWIN_ROGUE_AP",
                            severity=Severity.CRITICAL,
                            description=desc,
                            source_mac=bssid_lower,
                            bssid=bssid_lower,
                            ssid=ssid,
                            mitigation=mitigation,
                            details={
                                "rogue_bssid": bssid_lower,
                                "authorized_bssid": auth_bssid,
                                "ssid": ssid,
                                "rogue_crypto": frame.crypto_type,
                                "channel": frame.channel,
                            },
                            timestamp=frame.timestamp,
                        )
                    )

        # --- Rule 2: Encryption Downgrade Attack ---
        # If an authorized AP or known secure SSID is broadcasting without encryption (OPEN / WEP)
        for auth_bssid, auth_profile in self.config.authorized_aps.items():
            if auth_profile.ssid.lower() == ssid.lower() and auth_profile.expected_crypto:
                expected = auth_profile.expected_crypto.upper()
                current = frame.crypto_type.upper()
                if expected in ("WPA2", "WPA3") and current in ("OPEN", "WEP"):
                    alert_key = f"downgrade_{bssid_lower}_{ssid}"
                    if self._should_alert(alert_key, frame.timestamp):
                        desc = (
                            f"CRITICAL: Wireless Encryption Downgrade detected on SSID '{ssid}'! "
                            f"Expected security suite [{expected}], but BSSID [{bssid_lower}] is broadcasting [{current}]."
                        )
                        mitigation = (
                            "Verify AP security configuration. Ensure captive portals or fake APs are not attempting "
                            "to harvest unencrypted credentials or MITM user traffic."
                        )
                        alerts.append(
                            Alert(
                                rule_name="WIDS-RULE-003:CRYPTO_DOWNGRADE",
                                severity=Severity.CRITICAL,
                                description=desc,
                                source_mac=bssid_lower,
                                bssid=bssid_lower,
                                ssid=ssid,
                                mitigation=mitigation,
                                details={
                                    "bssid": bssid_lower,
                                    "ssid": ssid,
                                    "expected_crypto": expected,
                                    "observed_crypto": current,
                                },
                                timestamp=frame.timestamp,
                            )
                        )

        # --- Rule 3: Channel Anomaly on Authorized AP ---
        if is_known_authorized and authorized_ap.channel is not None and frame.channel is not None:
            if authorized_ap.channel != frame.channel:
                alert_key = f"channel_drift_{bssid_lower}_{frame.channel}"
                if self._should_alert(alert_key, frame.timestamp):
                    desc = (
                        f"WARNING: Channel anomaly on authorized AP [{bssid_lower}]. "
                        f"Expected channel {authorized_ap.channel}, but beacon detected on channel {frame.channel}."
                    )
                    mitigation = (
                        "Investigate potential rogue device spoofing the authorized BSSID on an adjacent channel."
                    )
                    alerts.append(
                        Alert(
                            rule_name="WIDS-RULE-004:CHANNEL_MISMATCH",
                            severity=Severity.MEDIUM,
                            description=desc,
                            source_mac=bssid_lower,
                            bssid=bssid_lower,
                            ssid=ssid,
                            mitigation=mitigation,
                            details={
                                "bssid": bssid_lower,
                                "expected_channel": authorized_ap.channel,
                                "observed_channel": frame.channel,
                            },
                            timestamp=frame.timestamp,
                        )
                    )

        return alerts
