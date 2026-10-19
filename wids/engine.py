from typing import Dict, List, Optional
import time

from rich.console import Console
from rich.table import Table

from wids.config import SentinelConfig
from wids.core.models import ParsedFrame, Alert, AccessPoint, FrameSubtype
from wids.core.sniffer import PacketSource
from wids.alerts.handler import AlertHandler
from wids.detectors.base import BaseDetector
from wids.detectors.deauth_flood import DeauthFloodDetector
from wids.detectors.evil_twin import EvilTwinDetector
from wids.detectors.karma import KarmaDetector
from wids.detectors.beacon_drift import BeaconDriftDetector


class SentinelEngine:
    def __init__(self, config: SentinelConfig, alert_handler: Optional[AlertHandler] = None):
        self.config = config
        self.alert_handler = alert_handler or AlertHandler(output_file=config.alert_log_file)
        self.console = Console()

        # Initialize detector pipeline
        self.detectors: List[BaseDetector] = [
            DeauthFloodDetector(config),
            EvilTwinDetector(config),
            KarmaDetector(config),
            BeaconDriftDetector(config),
        ]

        # Inventory of observed wireless entities
        self.discovered_aps: Dict[str, AccessPoint] = {}
        self.discovered_clients: set = set()

        # Engine statistics
        self.frames_inspected = 0
        self.start_time: float = 0.0
        self.current_source: Optional[PacketSource] = None

    def start_offline(self, pcap_path: str, max_count: int = 0) -> None:
        """Run engine against an offline PCAP file."""
        self.start_time = time.time()
        self.current_source = PacketSource(pcap_file=pcap_path, packet_callback=self.process_frame)
        self.current_source.start(count=max_count)

    def start_live(self, interface: str, max_count: int = 0) -> None:
        """Run engine against a live monitor-mode wireless interface."""
        self.start_time = time.time()
        self.current_source = PacketSource(interface=interface, packet_callback=self.process_frame)
        self.current_source.start(count=max_count)

    def stop(self) -> None:
        """Stop packet capture cleanly."""
        if self.current_source:
            self.current_source.stop()

    def process_frame(self, frame: ParsedFrame) -> List[Alert]:
        """Core frame processing logic invoked for each captured packet."""
        self.frames_inspected += 1
        alerts_generated: List[Alert] = []

        # Track discovery
        self._track_entities(frame)

        # Run frame through each detector
        for detector in self.detectors:
            try:
                new_alerts = detector.process(frame)
                for alert in new_alerts:
                    self.alert_handler.handle(alert)
                    alerts_generated.append(alert)
            except Exception as e:
                if self.config.verbose:
                    self.console.print(f"[red]Error in detector {detector.name}: {e}[/red]")

        return alerts_generated

    def _track_entities(self, frame: ParsedFrame) -> None:
        """Catalog APs and clients from the frame with memory bounding."""
        try:
            # Catalog AP
            if frame.subtype in (FrameSubtype.BEACON, FrameSubtype.PROBE_RESP):
                bssid = frame.addr3 or frame.addr2
                if bssid and frame.ssid:
                    bssid_lower = bssid.lower()
                    if bssid_lower not in self.discovered_aps:
                        if len(self.discovered_aps) < 5000:
                            is_auth = bssid_lower in self.config.authorized_aps
                            self.discovered_aps[bssid_lower] = AccessPoint(
                                bssid=bssid_lower,
                                ssid=frame.ssid,
                                channel=frame.channel,
                                crypto_type=frame.crypto_type,
                                first_seen=frame.timestamp,
                                last_seen=frame.timestamp,
                                is_authorized=is_auth,
                            )
                    else:
                        ap = self.discovered_aps[bssid_lower]
                        ap.last_seen = frame.timestamp
                        ap.beacon_count += 1
                        if frame.channel:
                            ap.channel = frame.channel

            # Catalog Client addresses (transmitter or receiver that is not an AP or broadcast)
            if len(self.discovered_clients) < 10000:
                for addr in (frame.addr1, frame.addr2):
                    if addr and addr.lower() != "ff:ff:ff:ff:ff:ff":
                        addr_l = addr.lower()
                        if addr_l not in self.discovered_aps:
                            self.discovered_clients.add(addr_l)
        except Exception:
            pass

    def print_summary(self) -> None:
        """Print an execution summary report."""
        elapsed = time.time() - self.start_time if self.start_time else 0.0

        table = Table(title="WIDS-Sentinel Operational Summary", show_header=True, header_style="bold cyan")
        table.add_column("Metric", style="dim")
        table.add_column("Value", justify="right")

        table.add_row("Execution Time", f"{elapsed:.2f} seconds")
        table.add_row("802.11 Frames Inspected", str(self.frames_inspected))
        table.add_row("Discovered Access Points", str(len(self.discovered_aps)))
        table.add_row("Discovered Client Devices", str(len(self.discovered_clients)))

        summary = self.alert_handler.get_summary()
        table.add_row("Critical Alerts", f"[bold red]{summary.get('CRITICAL', 0)}[/bold red]")
        table.add_row("High Alerts", f"[red]{summary.get('HIGH', 0)}[/red]")
        table.add_row("Medium Alerts", f"[yellow]{summary.get('MEDIUM', 0)}[/yellow]")
        table.add_row("Low / Info Alerts", str(summary.get("LOW", 0) + summary.get("INFO", 0)))
        table.add_row("Total Security Alerts", f"[bold]{summary.get('TOTAL', 0)}[/bold]")

        self.console.print(table)
