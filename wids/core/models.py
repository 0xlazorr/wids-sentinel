"""
Core data models for wids-sentinel.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Any, Optional, List
import time
import uuid


class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class FrameSubtype(int, Enum):
    ASSOC_REQ = 0
    ASSOC_RESP = 1
    REASSOC_REQ = 2
    REASSOC_RESP = 3
    PROBE_REQ = 4
    PROBE_RESP = 5
    BEACON = 8
    DISASSOC = 10
    AUTH = 11
    DEAUTH = 12
    ACTION = 13
    OTHER = 99


@dataclass
class ParsedFrame:
    timestamp: float
    subtype: FrameSubtype
    subtype_name: str
    addr1: Optional[str] = None  # Destination / RA
    addr2: Optional[str] = None  # Source / TA
    addr3: Optional[str] = None  # BSSID
    ssid: Optional[str] = None
    channel: Optional[int] = None
    crypto_type: str = "OPEN"
    signal_dbm: Optional[int] = None
    sequence_num: Optional[int] = None
    raw_packet: Any = field(default=None, repr=False)


@dataclass
class Alert:
    rule_name: str
    severity: Severity
    description: str
    source_mac: Optional[str] = None
    target_mac: Optional[str] = None
    bssid: Optional[str] = None
    ssid: Optional[str] = None
    mitigation: str = ""
    details: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)
    alert_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])

    def to_dict(self) -> Dict[str, Any]:
        return {
            "alert_id": self.alert_id,
            "timestamp": self.timestamp,
            "rule_name": self.rule_name,
            "severity": self.severity.value,
            "description": self.description,
            "source_mac": self.source_mac,
            "target_mac": self.target_mac,
            "bssid": self.bssid,
            "ssid": self.ssid,
            "mitigation": self.mitigation,
            "details": self.details,
        }


@dataclass
class AccessPoint:
    bssid: str
    ssid: str
    channel: Optional[int] = None
    crypto_type: str = "OPEN"
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    beacon_count: int = 1
    signal_history: List[int] = field(default_factory=list)
    last_seq_num: Optional[int] = None
    is_authorized: bool = False
