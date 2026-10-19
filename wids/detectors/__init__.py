"""
Detection rules and modules for wids-sentinel.
"""

from wids.detectors.base import BaseDetector
from wids.detectors.deauth_flood import DeauthFloodDetector
from wids.detectors.evil_twin import EvilTwinDetector
from wids.detectors.karma import KarmaDetector
from wids.detectors.beacon_drift import BeaconDriftDetector

__all__ = [
    "BaseDetector",
    "DeauthFloodDetector",
    "EvilTwinDetector",
    "KarmaDetector",
    "BeaconDriftDetector",
]
