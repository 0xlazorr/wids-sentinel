"""
Parser for 802.11 Wi-Fi management frames.
"""

from typing import Optional, Tuple
import time

from scapy.layers.dot11 import (
    Dot11,
    Dot11Beacon,
    Dot11ProbeReq,
    Dot11ProbeResp,
    Dot11Deauth,
    Dot11Disas,
    Dot11Elt,
    RadioTap,
)

from wids.core.models import ParsedFrame, FrameSubtype


class FrameParser:
    """Parses raw Scapy 802.11 packets into standardized ParsedFrame objects."""

    SUBTYPE_MAP = {
        0: (FrameSubtype.ASSOC_REQ, "Association Request"),
        1: (FrameSubtype.ASSOC_RESP, "Association Response"),
        2: (FrameSubtype.REASSOC_REQ, "Reassociation Request"),
        3: (FrameSubtype.REASSOC_RESP, "Reassociation Response"),
        4: (FrameSubtype.PROBE_REQ, "Probe Request"),
        5: (FrameSubtype.PROBE_RESP, "Probe Response"),
        8: (FrameSubtype.BEACON, "Beacon"),
        10: (FrameSubtype.DISASSOC, "Disassociation"),
        11: (FrameSubtype.AUTH, "Authentication"),
        12: (FrameSubtype.DEAUTH, "Deauthentication"),
        13: (FrameSubtype.ACTION, "Action"),
    }

    @classmethod
    def parse(cls, packet) -> Optional[ParsedFrame]:
        """Convert a Scapy packet into ParsedFrame if it has a Dot11 layer."""
        if not packet.haslayer(Dot11):
            return None

        dot11 = packet[Dot11]
        raw_type = dot11.type
        raw_subtype = dot11.subtype

        # We focus on management frames (type 0)
        if raw_type != 0:
            return None

        subtype_enum, subtype_name = cls.SUBTYPE_MAP.get(
            raw_subtype, (FrameSubtype.OTHER, f"Management-{raw_subtype}")
        )

        # Extract addresses
        addr1 = dot11.addr1.lower() if dot11.addr1 else None
        addr2 = dot11.addr2.lower() if dot11.addr2 else None
        addr3 = dot11.addr3.lower() if dot11.addr3 else None

        # Extract sequence control
        seq_num = None
        if hasattr(dot11, "SC") and dot11.SC is not None:
            seq_num = dot11.SC >> 4

        # Extract Signal strength from RadioTap if present
        signal_dbm = None
        if packet.haslayer(RadioTap):
            try:
                rt = packet[RadioTap]
                if hasattr(rt, "dBm_AntSignal") and rt.dBm_AntSignal is not None:
                    sig = int(rt.dBm_AntSignal)
                    # Convert unsigned 8-bit signal to signed dBm
                    signal_dbm = sig - 256 if sig > 127 else sig
            except Exception:
                signal_dbm = None

        # Extract SSID, Channel, and Encryption
        ssid = None
        channel = None
        crypto = "OPEN"

        if packet.haslayer(Dot11Beacon) or packet.haslayer(Dot11ProbeResp):
            ssid, channel, crypto = cls._extract_ap_metadata(packet, dot11)
        elif packet.haslayer(Dot11ProbeReq):
            ssid = cls._extract_ssid_from_elts(packet)

        pkt_time = float(getattr(packet, "time", time.time()))

        return ParsedFrame(
            timestamp=pkt_time,
            subtype=subtype_enum,
            subtype_name=subtype_name,
            addr1=addr1,
            addr2=addr2,
            addr3=addr3,
            ssid=ssid,
            channel=channel,
            crypto_type=crypto,
            signal_dbm=signal_dbm,
            sequence_num=seq_num,
            raw_packet=packet,
        )

    @classmethod
    def _sanitize_ssid(cls, raw: str) -> Optional[str]:
        """Strip null bytes and non-printable characters from SSID."""
        if raw is None:
            return None
        cleaned = "".join(c for c in raw if c.isprintable()).replace("\x00", "").strip()
        if not cleaned:
            return "<Hidden SSID>"
        return cleaned

    @classmethod
    def _extract_ssid_from_elts(cls, packet) -> Optional[str]:
        """Extract SSID from Information Elements (ID 0)."""
        elt = packet.getlayer(Dot11Elt)
        depth = 0
        while elt and depth < 64:
            depth += 1
            if elt.ID == 0:  # SSID parameter set
                try:
                    raw_info = elt.info
                    if isinstance(raw_info, bytes):
                        raw_str = raw_info.decode("utf-8", errors="replace")
                    else:
                        raw_str = str(raw_info)
                    return cls._sanitize_ssid(raw_str)
                except Exception:
                    return None
            elt = elt.payload.getlayer(Dot11Elt)
        return None

    @classmethod
    def _extract_ap_metadata(cls, packet, dot11) -> Tuple[Optional[str], Optional[int], str]:
        """Extract SSID, Channel, and Cipher Suite from Beacon or Probe Response."""
        ssid = None
        channel = None
        has_privacy = False
        has_wpa = False
        has_rsn = False
        is_wpa3 = False

        if hasattr(dot11, "cap"):
            # Check privacy flag (WEP / WPA / WPA2)
            has_privacy = bool(dot11.cap & 0x0010 or "privacy" in str(dot11.cap).lower())

        elt = packet.getlayer(Dot11Elt)
        depth = 0
        while elt and depth < 64:
            depth += 1
            if elt.ID == 0:  # SSID
                try:
                    raw_info = elt.info
                    if isinstance(raw_info, bytes):
                        raw_str = raw_info.decode("utf-8", errors="replace")
                    else:
                        raw_str = str(raw_info)
                    ssid = cls._sanitize_ssid(raw_str)
                except Exception:
                    ssid = None

            elif elt.ID == 3:  # DS Parameter Set (Channel)
                try:
                    if elt.info:
                        raw_ch = int(elt.info[0]) if isinstance(elt.info, (bytes, bytearray)) else int(elt.info)
                        if 1 <= raw_ch <= 196:
                            channel = raw_ch
                except Exception:
                    pass

            elif elt.ID == 48:  # RSN (WPA2 / WPA3)
                has_rsn = True
                # Check for SAE (WPA3 Authentication Key Management)
                try:
                    raw_bytes = bytes(elt)
                    if b"\x00\x0f\xac\x08" in raw_bytes:  # AKM Suite 8: SAE (WPA3-Personal)
                        is_wpa3 = True
                except Exception:
                    pass

            elif elt.ID == 221:  # Vendor Specific (WPA1)
                try:
                    raw_info = bytes(elt.info) if hasattr(elt, "info") else b""
                    if raw_info.startswith(b"\x00\x50\xf2\x01"):  # Microsoft OUI WPA1
                        has_wpa = True
                except Exception:
                    pass

            elt = elt.payload.getlayer(Dot11Elt)

        # Classify encryption type
        if is_wpa3:
            crypto = "WPA3"
        elif has_rsn:
            crypto = "WPA2"
        elif has_wpa:
            crypto = "WPA"
        elif has_privacy:
            crypto = "WEP"
        else:
            crypto = "OPEN"

        return ssid, channel, crypto
