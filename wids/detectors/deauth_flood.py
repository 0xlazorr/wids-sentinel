"""
Deauthentication and Disassociation Flood Detection Module.
Detects burst attacks targeting client disconnections.
"""

from collections import defaultdict, deque
from typing import Dict, List, Tuple
import time

from wids.detectors.base import BaseDetector
from wids.core.models import ParsedFrame, FrameSubtype, Alert, Severity


class DeauthFloodDetector(BaseDetector):
    """
    Detects 802.11 Deauthentication and Disassociation flood attacks.
    Uses sliding-window rate tracking per (transmitter, receiver) and per BSSID.
    """

    def __init__(self, config):
        super().__init__(config)
        self.enabled = config.enable_deauth_detection or config.enable_disassoc_detection
        self.window_seconds = config.deauth_window_seconds
        self.threshold = config.deauth_threshold_burst

        # Sliding window history: key -> deque of timestamps
        # Key: (bssid, source_mac, target_mac, frame_type)
        self._history: Dict[Tuple[str, str, str, str], deque] = defaultdict(deque)

        # Alert cooldown to avoid alert storming
        self._last_alert_time: Dict[Tuple[str, str, str, str], float] = {}
        self.cooldown_period = 5.0  # seconds between repeated alerts for the same stream

    @property
    def name(self) -> str:
        return "DeauthDisassocFloodDetector"

    def reset(self) -> None:
        self._history.clear()
        self._last_alert_time.clear()

    def process(self, frame: ParsedFrame) -> List[Alert]:
        alerts: List[Alert] = []

        if not self.enabled:
            return alerts

        is_deauth = frame.subtype == FrameSubtype.DEAUTH
        is_disassoc = frame.subtype == FrameSubtype.DISASSOC

        if not (is_deauth or is_disassoc):
            return alerts

        frame_type_str = "Deauthentication" if is_deauth else "Disassociation"
        src = frame.addr2 or "unknown"
        dst = frame.addr1 or "unknown"
        bssid = frame.addr3 or "unknown"
        current_time = frame.timestamp

        key = (bssid, src, dst, frame_type_str)
        window = self._history[key]

        # Prune expired timestamps from the sliding window
        window.append(current_time)
        while window and (current_time - window[0] > self.window_seconds):
            window.popleft()

        count = len(window)

        if count >= self.threshold:
            last_alert = self._last_alert_time.get(key, 0.0)
            if current_time - last_alert >= self.cooldown_period:
                self._last_alert_time[key] = current_time

                is_broadcast = (dst.lower() == "ff:ff:ff:ff:ff:ff")
                is_auth_ap = bssid.lower() in self.config.authorized_aps

                if is_broadcast or is_auth_ap:
                    severity = Severity.CRITICAL
                else:
                    severity = Severity.HIGH

                target_desc = "broadcast (all clients)" if is_broadcast else f"client [{dst}]"
                desc = (
                    f"Possible 802.11 {frame_type_str} flood attack detected! "
                    f"Transmitter [{src}] injected {count} {frame_type_str} frames in "
                    f"{self.window_seconds:.1f}s targeting {target_desc} on BSSID [{bssid}]."
                )

                mitigation = (
                    "Enable 802.11w Protected Management Frames (PMF / Management Frame Protection) "
                    "on the AP and clients to enforce cryptographic signatures on deauth/disassoc frames."
                )

                alert = Alert(
                    rule_name="WIDS-RULE-001:DEAUTH_FLOOD",
                    severity=severity,
                    description=desc,
                    source_mac=src,
                    target_mac=dst,
                    bssid=bssid,
                    ssid=frame.ssid,
                    mitigation=mitigation,
                    details={
                        "frame_type": frame_type_str,
                        "frame_count": count,
                        "window_seconds": self.window_seconds,
                        "is_broadcast": is_broadcast,
                        "is_authorized_bssid": is_auth_ap,
                    },
                    timestamp=current_time,
                )
                alerts.append(alert)

        return alerts
