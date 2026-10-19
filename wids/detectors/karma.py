"""Karma / MANA rogue AP detector."""

from typing import Dict, List, Set
from collections import defaultdict
import time

from wids.detectors.base import BaseDetector
from wids.core.models import ParsedFrame, FrameSubtype, Alert, Severity


class KarmaDetector(BaseDetector):
    def __init__(self, config):
        super().__init__(config)
        self.enabled = config.enable_karma_detection
        self.ssid_threshold = 3  # Alert if single BSSID claims >= 3 distinct SSIDs in probe responses

        # BSSID -> Set of SSIDs claimed in Probe Responses
        self._bssid_ssids: Dict[str, Set[str]] = defaultdict(set)
        self._alert_timestamps: Dict[str, float] = {}
        self.cooldown_period = 60.0  # seconds between repeated alerts

    @property
    def name(self) -> str:
        return "KarmaManaDetector"

    def reset(self) -> None:
        self._bssid_ssids.clear()
        self._alert_timestamps.clear()

    def process(self, frame: ParsedFrame) -> List[Alert]:
        alerts: List[Alert] = []

        if not self.enabled:
            return alerts

        # Only inspect Probe Response frames
        if frame.subtype != FrameSubtype.PROBE_RESP:
            return alerts

        bssid = frame.addr3 or frame.addr2
        ssid = frame.ssid

        if not bssid or not ssid or ssid.strip() == "":
            return alerts

        bssid_lower = bssid.lower()

        # Prevent unbounded memory usage
        if len(self._bssid_ssids) > 1000 and bssid_lower not in self._bssid_ssids:
            # Drop oldest 200 entries
            keys_to_drop = list(self._bssid_ssids.keys())[:200]
            for k in keys_to_drop:
                del self._bssid_ssids[k]

        self._bssid_ssids[bssid_lower].add(ssid)

        distinct_ssids = self._bssid_ssids[bssid_lower]

        if len(distinct_ssids) >= self.ssid_threshold:
            last_alert = self._alert_timestamps.get(bssid_lower, 0.0)
            if frame.timestamp - last_alert >= self.cooldown_period:
                self._alert_timestamps[bssid_lower] = frame.timestamp

                ssid_sample = list(distinct_ssids)[:5]
                desc = (
                    f"Karma/MANA rogue AP: {bssid_lower} answered probe requests for "
                    f"{len(distinct_ssids)} SSIDs: {', '.join(ssid_sample)}"
                )
                mitigation = (
                    "Disable auto-connect to open Wi-Fi on client devices. Locate and isolate rogue radio."
                )

                alerts.append(
                    Alert(
                        rule_name="WIDS-RULE-005:KARMA_MANA_ATTACK",
                        severity=Severity.CRITICAL,
                        description=desc,
                        source_mac=bssid_lower,
                        bssid=bssid_lower,
                        ssid="[MULTIPLE]",
                        mitigation=mitigation,
                        details={
                            "bssid": bssid_lower,
                            "claimed_ssids": list(distinct_ssids),
                            "total_ssids_claimed": len(distinct_ssids),
                        },
                        timestamp=frame.timestamp,
                    )
                )

        return alerts
