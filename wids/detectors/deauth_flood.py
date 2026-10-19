"""Deauthentication and disassociation flood detector."""

from collections import defaultdict, deque
from typing import Dict, List, Tuple
import time

from wids.detectors.base import BaseDetector
from wids.core.models import ParsedFrame, FrameSubtype, Alert, Severity


class DeauthFloodDetector(BaseDetector):
    def __init__(self, config):
        super().__init__(config)
        self.enabled = config.enable_deauth_detection or config.enable_disassoc_detection
        self.window_seconds = config.deauth_window_seconds
        self.threshold = config.deauth_threshold_burst

        self._history: Dict[Tuple[str, str, str, str], deque] = defaultdict(deque)
        self._last_alert_time: Dict[Tuple[str, str, str, str], float] = {}
        self.cooldown_period = 5.0

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

        frame_type_str = "Deauth" if is_deauth else "Disassoc"
        src = frame.addr2 or "unknown"
        dst = frame.addr1 or "unknown"
        bssid = frame.addr3 or "unknown"
        current_time = frame.timestamp

        key = (bssid, src, dst, frame_type_str)

        # Prune stale tracking keys periodically
        if len(self._history) > 1000:
            stale_keys = [
                k for k, win in self._history.items()
                if not win or (current_time - win[-1] > self.window_seconds)
            ]
            for sk in stale_keys:
                del self._history[sk]

            stale_alerts = [
                k for k, t in self._last_alert_time.items()
                if (current_time - t > self.cooldown_period * 2)
            ]
            for sa in stale_alerts:
                del self._last_alert_time[sa]

        window = self._history[key]
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

                severity = Severity.CRITICAL if (is_broadcast or is_auth_ap) else Severity.HIGH
                target_desc = "broadcast" if is_broadcast else dst
                desc = (
                    f"{frame_type_str} flood: {count} frames in {self.window_seconds:.1f}s "
                    f"from {src} targeting {target_desc} (BSSID: {bssid})"
                )
                mitigation = (
                    "Enforce 802.11w (PMF) on AP and clients to reject unauthenticated management frames."
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
