"""
Beacon Drift and Sequence Number Anomaly Detector.
Detects spoofed 802.11 beacons and injected frame anomalies.
"""

from typing import Dict, List, Optional
import time

from wids.detectors.base import BaseDetector
from wids.core.models import ParsedFrame, FrameSubtype, Alert, Severity


class BeaconDriftDetector(BaseDetector):
    """
    Detects irregular jumps in sequence numbers and invalid BSSID flags in beacons.
    """

    def __init__(self, config):
        super().__init__(config)
        self.enabled = config.enable_beacon_drift_detection

        # BSSID -> last sequence number
        self._last_seq: Dict[str, int] = {}
        # BSSID -> last seen timestamp
        self._last_time: Dict[str, float] = {}
        # Cooldown per BSSID
        self._cooldown: Dict[str, float] = {}

    @property
    def name(self) -> str:
        return "BeaconDriftDetector"

    def reset(self) -> None:
        self._last_seq.clear()
        self._last_time.clear()
        self._cooldown.clear()

    def process(self, frame: ParsedFrame) -> List[Alert]:
        alerts: List[Alert] = []

        if not self.enabled or frame.subtype != FrameSubtype.BEACON:
            return alerts

        bssid = frame.addr3 or frame.addr2
        if not bssid or frame.sequence_num is None:
            return alerts

        bssid_lower = bssid.lower()
        curr_seq = frame.sequence_num
        curr_time = frame.timestamp

        # Check for invalid Multicast bit in BSSID (bit 0 of octet 0 must be 0 for unicast BSSID)
        try:
            first_byte = int(bssid_lower.split(":")[0], 16)
            if first_byte & 0x01:
                if curr_time - self._cooldown.get(f"multicast_{bssid_lower}", 0.0) > 10.0:
                    self._cooldown[f"multicast_{bssid_lower}"] = curr_time
                    alerts.append(
                        Alert(
                            rule_name="WIDS-RULE-006:MALFORMED_BSSID",
                            severity=Severity.HIGH,
                            description=(
                                f"Malformed BSSID detected: [{bssid_lower}] has the multicast/broadcast bit set, "
                                f"indicating an illegally crafted or spoofed 802.11 beacon."
                            ),
                            source_mac=bssid_lower,
                            bssid=bssid_lower,
                            ssid=frame.ssid,
                            mitigation="Inspect local wireless spectrum for custom packet generation or rogue transmitters.",
                            details={"bssid": bssid_lower, "first_byte_hex": hex(first_byte)},
                            timestamp=curr_time,
                        )
                    )
        except Exception:
            pass

        # Check sequence number progression
        if bssid_lower in self._last_seq:
            prev_seq = self._last_seq[bssid_lower]
            prev_time = self._last_time.get(bssid_lower, curr_time)

            time_diff = curr_time - prev_time

            # Sequence numbers are 12-bit (0 - 4095)
            # Calculate forward distance with wrap-around
            if curr_seq >= prev_seq:
                forward_diff = curr_seq - prev_seq
                is_backward_reorder = False
            else:
                forward_diff = (curr_seq + 4096) - prev_seq
                # If the previous sequence was only slightly ahead (<= 20), this is normal out-of-order jitter/retransmission
                is_backward_reorder = (prev_seq - curr_seq) <= 20

            # If frames arrive closely (< 0.5s) and sequence jumps significantly forward (> 200 and < 3800)
            if time_diff < 0.5 and (200 < forward_diff < 3800) and not is_backward_reorder:
                if curr_time - self._cooldown.get(f"seq_{bssid_lower}", 0.0) > 10.0:
                    self._cooldown[f"seq_{bssid_lower}"] = curr_time
                    alerts.append(
                        Alert(
                            rule_name="WIDS-RULE-007:BEACON_SEQ_ANOMALY",
                            severity=Severity.MEDIUM,
                            description=(
                                f"Abrupt sequence number jump on BSSID [{bssid_lower}]. "
                                f"Jumped from {prev_seq} to {curr_seq} in {time_diff:.2f}s (delta: {forward_diff}). "
                                f"May indicate beacon injection or multiple transmitters."
                            ),
                            source_mac=bssid_lower,
                            bssid=bssid_lower,
                            ssid=frame.ssid,
                            mitigation="Verify if multiple APs are broadcasting identical BSSIDs or if injection is occurring.",
                            details={
                                "bssid": bssid_lower,
                                "previous_seq": prev_seq,
                                "current_seq": curr_seq,
                                "delta": forward_diff,
                            },
                            timestamp=curr_time,
                        )
                    )

        self._last_seq[bssid_lower] = curr_seq
        self._last_time[bssid_lower] = curr_time

        return alerts
