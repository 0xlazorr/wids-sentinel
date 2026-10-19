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

    @staticmethod
    def _normalize_mac(addr) -> Optional[str]:
        if not addr:
            return None
        if isinstance(addr, (bytes, bytearray)):
            if len(addr) == 6:
                return ":".join(f"{b:02x}" for b in addr)
            try:
                addr = addr.decode("utf-8", errors="ignore")
            except Exception:
                return None
        clean = str(addr).strip().lower()
        return clean if clean else None

    @classmethod
    def parse(cls, packet) -> Optional[ParsedFrame]:
        if not packet.haslayer(Dot11):
            return None

        dot11 = packet[Dot11]
        raw_type = dot11.type
        raw_subtype = dot11.subtype

        # Management frames only (type 0)
        if raw_type != 0:
            return None

        subtype_enum, subtype_name = cls.SUBTYPE_MAP.get(
            raw_subtype, (FrameSubtype.OTHER, f"Management-{raw_subtype}")
        )

        addr1 = cls._normalize_mac(dot11.addr1)
        addr2 = cls._normalize_mac(dot11.addr2)
        addr3 = cls._normalize_mac(dot11.addr3)

        # Sequence control (high 12 bits)
        seq_num = None
        if hasattr(dot11, "SC") and dot11.SC is not None:
            try:
                seq_num = int(dot11.SC) >> 4
            except (TypeError, ValueError):
                seq_num = None

        # RadioTap dBm antenna signal
        signal_dbm = None
        if packet.haslayer(RadioTap):
            try:
                rt = packet[RadioTap]
                if hasattr(rt, "dBm_AntSignal") and rt.dBm_AntSignal is not None:
                    sig = int(rt.dBm_AntSignal)
                    signal_dbm = sig - 256 if sig > 127 else sig
            except Exception:
                signal_dbm = None

        ssid = None
        channel = None
        crypto = "OPEN"

        if packet.haslayer(Dot11Beacon) or packet.haslayer(Dot11ProbeResp):
            ssid, channel, crypto = cls._extract_ap_metadata(packet, dot11)
        elif packet.haslayer(Dot11ProbeReq):
            ssid = cls._extract_ssid_from_elts(packet)

        raw_t = getattr(packet, "time", None)
        if raw_t is not None:
            try:
                pkt_time = float(raw_t)
            except (ValueError, TypeError):
                pkt_time = time.time()
        else:
            pkt_time = time.time()

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

            elif elt.ID == 3:  # DS Parameter Set (Channel for 2.4 GHz)
                try:
                    if elt.info:
                        raw_ch = int(elt.info[0]) if isinstance(elt.info, (bytes, bytearray)) else int(elt.info)
                        if 1 <= raw_ch <= 196:
                            channel = raw_ch
                except Exception:
                    pass

            elif elt.ID == 61:  # HT Operation (Primary Channel for 5 GHz / 802.11n/ac)
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

        # Fallback channel derivation from RadioTap frequency if not found in 802.11 elements
        if channel is None and packet.haslayer(RadioTap):
            try:
                rt = packet[RadioTap]
                freq = (
                    getattr(rt, "ChannelFrequency", None)
                    or getattr(rt, "ChannelPlusFrequency", None)
                    or (rt.fields.get("ChannelFrequency") if hasattr(rt, "fields") else None)
                    or (rt.fields.get("ChannelPlusFrequency") if hasattr(rt, "fields") else None)
                )
                if freq is not None:
                    freq_int = int(freq)
                    if 2412 <= freq_int <= 2472:
                        channel = (freq_int - 2407) // 5
                    elif freq_int == 2484:
                        channel = 14
                    elif 5180 <= freq_int <= 5885:
                        channel = (freq_int - 5000) // 5
                    elif 5955 <= freq_int <= 7115:
                        channel = (freq_int - 5950) // 5
            except Exception:
                pass

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
