"""
Shared test fixtures and 802.11 packet crafting helpers.
"""

import pytest
import time
from scapy.layers.dot11 import (
    RadioTap,
    Dot11,
    Dot11Beacon,
    Dot11ProbeResp,
    Dot11Deauth,
    Dot11Elt,
)

from wids.config import SentinelConfig


@pytest.fixture
def base_config():
    """Provides a baseline SentinelConfig with pre-configured authorized APs."""
    config = SentinelConfig(
        deauth_threshold_burst=5,
        deauth_window_seconds=2.0,
        disassoc_threshold_burst=5,
        disassoc_window_seconds=2.0,
    )
    config.add_authorized_ap(
        ssid="Corp_Secure_WiFi",
        bssid="00:11:22:33:44:55",
        channel=6,
        crypto="WPA2",
    )
    return config


def make_beacon(
    ssid: str,
    bssid: str,
    channel: int = 6,
    crypto: str = "WPA2",
    seq: int = 100,
    timestamp: float = None,
):
    """Craft an 802.11 Beacon packet."""
    ts = timestamp or time.time()
    rt = RadioTap()
    dot11 = Dot11(
        type=0,
        subtype=8,
        addr1="ff:ff:ff:ff:ff:ff",
        addr2=bssid,
        addr3=bssid,
        SC=(seq << 4),
    )
    beacon = Dot11Beacon(cap="ESS+privacy" if crypto != "OPEN" else "ESS")
    essid = Dot11Elt(ID="SSID", info=ssid.encode())
    dsset = Dot11Elt(ID="DSset", info=bytes([channel]))

    pkt = rt / dot11 / beacon / essid / dsset

    if crypto == "WPA2":
        # Add minimal RSN Information Element (ID 48)
        rsn = Dot11Elt(ID=48, info=b"\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x02\x00\x00")
        pkt = pkt / rsn
    elif crypto == "WPA3":
        # RSN with AKM suite 8 (SAE)
        rsn = Dot11Elt(ID=48, info=b"\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x08\x00\x00")
        pkt = pkt / rsn

    pkt.time = ts
    return pkt


def make_deauth(
    bssid: str,
    src: str,
    dst: str,
    reason: int = 7,
    timestamp: float = None,
):
    """Craft an 802.11 Deauthentication frame."""
    ts = timestamp or time.time()
    rt = RadioTap()
    dot11 = Dot11(
        type=0,
        subtype=12,
        addr1=dst,
        addr2=src,
        addr3=bssid,
    )
    deauth = Dot11Deauth(reason=reason)
    pkt = rt / dot11 / deauth
    pkt.time = ts
    return pkt


def make_probe_resp(
    ssid: str,
    bssid: str,
    client_dst: str,
    channel: int = 6,
    timestamp: float = None,
):
    """Craft an 802.11 Probe Response frame."""
    ts = timestamp or time.time()
    rt = RadioTap()
    dot11 = Dot11(
        type=0,
        subtype=5,
        addr1=client_dst,
        addr2=bssid,
        addr3=bssid,
    )
    resp = Dot11ProbeResp(cap="ESS")
    essid = Dot11Elt(ID="SSID", info=ssid.encode())
    dsset = Dot11Elt(ID="DSset", info=bytes([channel]))
    pkt = rt / dot11 / resp / essid / dsset
    pkt.time = ts
    return pkt
