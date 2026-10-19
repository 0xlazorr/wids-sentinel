"""CLI for wids-sentinel."""

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
examples:
  wids-sentinel -r capture.pcap -c config.json
  wids-sentinel -i wlan0mon -c config.json -o alerts.json
  wids-sentinel -r capture.pcap --auth-ssid "Office" --auth-bssid "00:11:22:33:44:55"
        """,
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-i", "--interface", help="Monitor mode interface (e.g. wlan0mon)")
    group.add_argument("-r", "--read-pcap", help="PCAP capture file to inspect")

    parser.add_argument("-c", "--config", help="JSON config file with authorized AP profiles")
    parser.add_argument("-o", "--output", default="alerts.json", help="JSON alert output file (default: alerts.json)")
    parser.add_argument("--count", type=int, default=0, help="Max packet count (0 = continuous)")
    parser.add_argument("--verbose", action="store_true", help="Verbose debug output")
    parser.add_argument("--version", action="version", version=f"wids-sentinel {__version__}")

    parser.add_argument("--auth-ssid", help="Authorized network SSID")
    parser.add_argument("--auth-bssid", help="Authorized BSSID matching the SSID")
    parser.add_argument("--auth-channel", type=int, help="Authorized channel")
    parser.add_argument("--auth-crypto", default="WPA2", help="Authorized crypto suite (default: WPA2)")

    return parser


def main() -> int:
    console = Console()
    parser = build_parser()
    args = parser.parse_args()

    if args.config:
        try:
            config = SentinelConfig.from_json(args.config)
        except Exception as e:
            console.print(f"[bold red]Config error: {e}[/bold red]")
            return 1
    else:
        config = SentinelConfig()

    config.alert_log_file = args.output
    config.verbose = args.verbose

    if (args.auth_ssid and not args.auth_bssid) or (args.auth_bssid and not args.auth_ssid):
        console.print("[bold red]Both --auth-ssid and --auth-bssid are required to register an AP.[/bold red]")
        return 1

    if args.auth_ssid and args.auth_bssid:
        config.add_authorized_ap(
            ssid=args.auth_ssid,
            bssid=args.auth_bssid,
            channel=args.auth_channel,
            crypto=args.auth_crypto,
        )

    if args.interface and hasattr(os, "geteuid") and os.geteuid() != 0:
        console.print("[yellow]Note: Live capture on raw interfaces usually requires root (sudo).[/yellow]")

    banner = (
        f"[bold cyan]wids-sentinel[/bold cyan] [green]v{__version__}[/green]\n"
        f"Authorized APs: [bold yellow]{len(config.authorized_aps)}[/bold yellow] | "
        f"Alert Log: [bold white]{config.alert_log_file}[/bold white]"
    )
    console.print(Panel(banner, border_style="cyan"))

    alert_handler = AlertHandler(output_file=config.alert_log_file, console=console)
    engine = SentinelEngine(config=config, alert_handler=alert_handler)

    try:
        if args.read_pcap:
            console.print(f"[bold green]Inspecting PCAP:[/bold green] {args.read_pcap}")
            engine.start_offline(args.read_pcap, max_count=args.count)
        elif args.interface:
            console.print(f"[bold green]Sniffing on:[/bold green] {args.interface}")
            engine.start_live(args.interface, max_count=args.count)
    except KeyboardInterrupt:
        console.print("\n[yellow]Stopping capture...[/yellow]")
        engine.stop()
    except Exception as e:
        console.print(f"[bold red]Error: {e}[/bold red]")
        return 1
    finally:
        if engine.frames_inspected > 0 or engine.start_time > 0:
            console.print("\n")
            engine.print_summary()

    return 0


if __name__ == "__main__":
    sys.exit(main())
