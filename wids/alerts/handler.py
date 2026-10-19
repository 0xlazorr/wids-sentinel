"""
Alert Dispatcher and Persistence Handler.
Handles logging to console, appending to alerts.json, and alert analytics.
"""

from typing import List, Optional
import json
import os
import sys

from rich.console import Console

from wids.core.models import Alert, Severity
from wids.alerts.formatters import AlertFormatter


class AlertHandler:
    """Dispatches alerts to active sinks (Console, JSON file)."""

    def __init__(self, output_file: Optional[str] = "alerts.json", console: Optional[Console] = None):
        self.output_file = output_file
        self.console = console or Console()
        self.alerts: List[Alert] = []

    def handle(self, alert: Alert) -> None:
        """Handle a single security alert."""
        self.alerts.append(alert)

        # Print formatted panel to terminal
        panel = AlertFormatter.to_panel(alert)
        self.console.print(panel)

        # Append to JSON alert file if configured
        if self.output_file:
            self._write_json_alert(alert)

    def _write_json_alert(self, alert: Alert) -> None:
        """Append an alert record to the JSON file."""
        try:
            dir_name = os.path.dirname(self.output_file)
            if dir_name:
                os.makedirs(os.path.abspath(dir_name), exist_ok=True)
            with open(self.output_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(alert.to_dict()) + "\n")
        except Exception as e:
            self.console.print(f"[red]Failed to write alert to file {self.output_file}: {e}[/red]")

    def get_summary(self) -> dict:
        """Return counts of alerts grouped by severity."""
        summary = {s.value: 0 for s in Severity}
        for a in self.alerts:
            summary[a.severity.value] += 1
        summary["TOTAL"] = len(self.alerts)
        return summary
