"""
Packet capture and PCAP ingestion engine for wids-sentinel.
"""

from typing import Callable, Optional
import os
import time

from scapy.all import sniff, PcapReader
from scapy.layers.dot11 import Dot11

from wids.core.parser import FrameParser
from wids.core.models import ParsedFrame


class PacketSource:
    """Manages packet ingestion from either a live Wi-Fi interface or a PCAP capture file."""

    def __init__(
        self,
        interface: Optional[str] = None,
        pcap_file: Optional[str] = None,
        bpf_filter: Optional[str] = None,
        packet_callback: Optional[Callable[[ParsedFrame], None]] = None,
    ):
        self.interface = interface
        self.pcap_file = pcap_file
        self.bpf_filter = bpf_filter or "type mgt"
        self.callback = packet_callback
        self.running = False
        self.packets_processed = 0

    def start(self, count: int = 0) -> None:
        """Start capturing packets."""
        self.running = True
        self.packets_processed = 0

        if self.pcap_file:
            self._read_pcap(count)
        elif self.interface:
            self._sniff_live(count)
        else:
            raise ValueError("Either an interface or a pcap_file must be specified.")

    def stop(self) -> None:
        """Stop packet processing."""
        self.running = False

    def _handle_packet(self, raw_pkt) -> None:
        """Process an individual raw Scapy packet safely."""
        if not self.running:
            return

        try:
            self.packets_processed += 1
            parsed = FrameParser.parse(raw_pkt)
            if parsed and self.callback:
                self.callback(parsed)
        except Exception:
            # Safely drop malformed/fuzzed frames without crashing capture loop
            pass

    def _read_pcap(self, max_count: int = 0) -> None:
        """Read and replay packets from an offline PCAP/PCAPNG file."""
        if not os.path.exists(self.pcap_file):
            raise FileNotFoundError(f"PCAP file not found: {self.pcap_file}")

        with PcapReader(self.pcap_file) as reader:
            for pkt in reader:
                if not self.running:
                    break
                self._handle_packet(pkt)
                if max_count and self.packets_processed >= max_count:
                    break

    def _sniff_live(self, count: int = 0) -> None:
        """Sniff packets from a live network interface."""
        try:
            sniff(
                iface=self.interface,
                filter=self.bpf_filter,
                prn=self._handle_packet,
                count=count,
                store=False,
                stop_filter=lambda _: not self.running,
            )
        except PermissionError:
            raise PermissionError(
                f"Permission denied on interface '{self.interface}'. "
                "Raw packet capture requires root/sudo privileges (or CAP_NET_RAW / CAP_NET_ADMIN capabilities)."
            )
        except Exception as e:
            raise RuntimeError(f"Error during packet capture on interface '{self.interface}': {e}")
