"""
Alert formatting utilities using Rich and JSON.
"""

from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.table import Table

from wids.core.models import Alert, Severity


class AlertFormatter:
    """Renders Alert objects into styled Rich panels or structured text."""

    SEVERITY_COLORS = {
        Severity.INFO: "blue",
        Severity.LOW: "cyan",
        Severity.MEDIUM: "yellow",
        Severity.HIGH: "bright_red",
        Severity.CRITICAL: "bold white on red",
    }

    @classmethod
    def to_panel(cls, alert: Alert) -> Panel:
        color = cls.SEVERITY_COLORS.get(alert.severity, "white")
        title = f"[{color}][ALERT] {alert.severity.value}: {alert.rule_name}[/{color}]"

        text = Text()
        text.append(f"Description: ", style="bold")
        text.append(f"{alert.description}\n")

        if alert.bssid:
            text.append(f"BSSID: ", style="bold cyan")
            text.append(f"{alert.bssid}  ")
        if alert.ssid:
            text.append(f"SSID: ", style="bold magenta")
            text.append(f"'{alert.ssid}'  ")
        if alert.source_mac:
            text.append(f"Transmitter: ", style="bold yellow")
            text.append(f"{alert.source_mac}  ")
        if alert.target_mac:
            text.append(f"Target: ", style="bold")
            text.append(f"{alert.target_mac}\n")
        else:
            text.append("\n")

        if alert.mitigation:
            text.append(f"Mitigation: ", style="bold green")
            text.append(f"{alert.mitigation}\n")

        return Panel(text, title=title, border_style=color.split()[-1])
