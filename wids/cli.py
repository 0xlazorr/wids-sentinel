"""
Command-Line Interface for wids-sentinel.
"""

import argparse
import sys
import os

from rich.console import Console
from rich.panel import Panel

from wids import __version__
from wids.config import SentinelConfig
from wids.engine import SentinelEngine
from wids.alerts.handler import AlertHandler


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="wids-sentinel",
        description="Real-Time 802.11 Wireless Intrusion Detection System (WIDS)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Inspect an offline PCAP capture file:
  wids-sentinel -r sample_attack.pcap -c config.json

  # Monitor a live wireless interface in monitor mode:
  wids-sentinel -i wlan0mon -c config.json -o live_alerts.json

  # Quick-add an authorized AP directly from CLI:
  wids-sentinel -r capture.pcap --auth-ap "CorpWiFi" "00:11:22:33:44:55" --channel 6 --crypto WPA2
        """,
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-i", "--interface", help="Live wireless monitor-mode interface (e.g. wlan0mon)")
    group.add_argument("-r", "--read-pcap", help="Path to PCAP/PCAPNG capture file to analyze")

    parser.add_argument("-c", "--config", help="Path to JSON configuration file with authorized AP profiles")
    parser.add_argument("-o", "--output", default="alerts.json", help="Path to write JSON alert logs (default: alerts.json)")
    parser.add_argument("--count", type=int, default=0, help="Maximum number of packets to process (0 = infinite)")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose debug output")
    parser.add_argument("--version", action="version", version=f"wids-sentinel v{__version__}")

    # Direct authorization flags
    parser.add_argument("--auth-ssid", help="Authorized SSID to register")
    parser.add_argument("--auth-bssid", help="Authorized BSSID matching the SSID")
    parser.add_argument("--auth-channel", type=int, help="Expected channel for the authorized AP")
    parser.add_argument("--auth-crypto", default="WPA2", help="Expected encryption for authorized AP (default: WPA2)")

    return parser


def main() -> int:
    console = Console()
    parser = build_parser()
    args = parser.parse_args()

    # Load or initialize config
    if args.config:
        try:
            config = SentinelConfig.from_json(args.config)
        except Exception as e:
            console.print(f"[bold red]Failed to load config file {args.config}: {e}[/bold red]")
            return 1
    else:
        config = SentinelConfig()

    config.alert_log_file = args.output
    config.verbose = args.verbose

    # Handle inline authorized AP registration
    if args.auth_ssid and args.auth_bssid:
        config.add_authorized_ap(
            ssid=args.auth_ssid,
            bssid=args.auth_bssid,
            channel=args.auth_channel,
            crypto=args.auth_crypto,
        )

    # Banner
    banner = (
        f"[bold cyan]WIDS-Sentinel[/bold cyan] [green]v{__version__}[/green] — "
        f"[dim]802.11 Wireless Intrusion Detection System[/dim]\n"
        f"Active Authorized APs: [bold yellow]{len(config.authorized_aps)}[/bold yellow] | "
        f"Alert Log: [bold white]{config.alert_log_file}[/bold white]"
    )
    console.print(Panel(banner, border_style="cyan"))

    alert_handler = AlertHandler(output_file=config.alert_log_file, console=console)
    engine = SentinelEngine(config=config, alert_handler=alert_handler)

    try:
        if args.read_pcap:
            console.print(f"[bold green]Starting analysis on PCAP:[/bold green] {args.read_pcap}")
            engine.start_offline(args.read_pcap, max_count=args.count)
        elif args.interface:
            console.print(f"[bold green]Listening on interface:[/bold green] {args.interface} [dim](monitor mode required)[/dim]")
            engine.start_live(args.interface, max_count=args.count)
    except KeyboardInterrupt:
        console.print("\n[yellow]Stopping capture (interrupted by user)...[/yellow]")
    except Exception as e:
        console.print(f"[bold red]Execution error: {e}[/bold red]")
        return 1
    finally:
        console.print("\n")
        engine.print_summary()

    return 0


if __name__ == "__main__":
    sys.exit(main())
