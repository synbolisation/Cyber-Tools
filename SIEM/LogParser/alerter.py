from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .detectors import Alert

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    _HAS_RICH = True
    _console = Console()
except ImportError:  # pragma: no cover
    _HAS_RICH = False
    _console = None


SEVERITY_STYLES = {
    "LOW": "cyan",
    "MEDIUM": "yellow",
    "HIGH": "red",
    "CRITICAL": "bold white on red",
}


def print_alert(alert: "Alert") -> None:
    if not _HAS_RICH:
        print(f"[{alert.severity}] {alert.rule_id} :: {alert.description}")
        for ev in alert.triggering_events[:3]:
            print(f"   - {ev.raw}")
        return

    style = SEVERITY_STYLES.get(alert.severity, "white")
    title = Text(f"{alert.severity}  {alert.rule_name}", style=style)

    body = Text()
    body.append(f"Rule:   {alert.rule_id}\n", style="dim")
    body.append(f"When:   {alert.timestamp}\n", style="dim")
    if alert.group_key:
        body.append(f"Group:  {alert.group_key}\n", style="dim")
    body.append(f"\n{alert.description}\n\n", style="default")
    body.append("Triggering events:\n", style="bold")
    for ev in alert.triggering_events[:5]:
        body.append(f"  • {ev.raw}\n", style="dim")
    if len(alert.triggering_events) > 5:
        body.append(f"  … and {len(alert.triggering_events) - 5} more\n", style="dim italic")

    _console.print(Panel(body, title=title, border_style=style))


def print_summary(*, total_lines: int, parsed: int, skipped: int, alerts: int) -> None:
    if not _HAS_RICH:
        print(f"\nLines: {total_lines}  Parsed: {parsed}  Skipped: {skipped}  Alerts: {alerts}")
        return

    table = Table(title="Ingestion summary", show_header=False, border_style="dim")
    table.add_column(style="dim")
    table.add_column(style="bold")
    table.add_row("Total lines", str(total_lines))
    table.add_row("Parsed",      str(parsed))
    table.add_row("Skipped",     str(skipped))
    table.add_row("Alerts",      str(alerts))
    _console.print(table)
