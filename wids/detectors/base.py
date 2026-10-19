"""
Abstract Base Detector definition for wids-sentinel.
"""

from abc import ABC, abstractmethod
from typing import List

from wids.core.models import ParsedFrame, Alert
from wids.config import SentinelConfig


class BaseDetector(ABC):
    """Abstract interface that all intrusion detection rules must implement."""

    def __init__(self, config: SentinelConfig):
        self.config = config
        self.enabled = True

    @property
    @abstractmethod
    def name(self) -> str:
        """Rule name or identifier."""
        pass

    @abstractmethod
    def process(self, frame: ParsedFrame) -> List[Alert]:
        """Inspect a parsed 802.11 frame and return any generated alerts."""
        pass

    def reset(self) -> None:
        """Reset internal detector state."""
        pass
