"""Output formatting utilities for Autosploit."""

from typing import List, Dict, Any, Optional
from datetime import datetime

import can
from rich.console import Console
from rich.table import Table
from rich.progress import (
    Progress,
    SpinnerColumn,
    BarColumn,
    TextColumn,
    TimeRemainingColumn,
    TimeElapsedColumn,
    TaskProgressColumn,
)
from rich.spinner import Spinner
from rich.live import Live
from rich.text import Text

console = Console()


def format_can_frame(msg: can.Message, include_timestamp: bool = False) -> str:
    """Format CAN message as human-readable string."""

    arb_id_str = format_can_id(msg.arbitration_id, msg.is_extended_id)
    data_str = format_can_data(msg.data) if msg.data else ""

    parts = []

    if include_timestamp and msg.timestamp:
        parts.append(f"{msg.timestamp:.6f}")

    parts.append(arb_id_str)
    parts.append(f"[{len(msg.data)}]")

    if data_str:
        parts.append(data_str)

    if msg.is_remote_frame:
        parts.append("(RTR)")
    if msg.is_error_frame:
        parts.append("(ERR)")

    return " ".join(parts)


def format_can_id(arb_id: int, extended: bool = False) -> str:
    """Format CAN arbitration ID as hex string."""

    if extended:
        return f"0x{arb_id:08X}"
    else:
        return f"0x{arb_id:03X}"


def format_can_data(data: bytes, separator: str = " ") -> str:
    """Format CAN data bytes as hex string."""

    return separator.join(f"{byte:02X}" for byte in data)


def parse_can_data(data_str: str) -> bytes:
    """Parse hex string into bytes."""

    cleaned = data_str.replace("0x", "").replace(",", " ").replace(":", " ")
    hex_bytes = cleaned.split()

    return bytes(int(h, 16) for h in hex_bytes if h)


def create_module_table(modules: List[Dict[str, Any]]) -> Table:
    """Create formatted table of modules."""

    table = Table(
        title="[bold cyan]Available Modules[/bold cyan]",
        show_header=True,
        header_style="bold magenta",
        border_style="cyan",
        title_style="bold",
    )

    table.add_column("Name", style="cyan", justify="left", no_wrap=False)
    table.add_column("Category", style="magenta", justify="center")
    table.add_column("Risk", style="yellow", justify="center", no_wrap=True)
    table.add_column("Description", style="white", justify="left")

    for module in modules:
        name = module.get("name", "Unknown")
        category = module.get("category", "N/A")
        risk = module.get("risk_level", "medium")
        description = module.get("description", "")

        risk_colors = {
            "low": "green",
            "medium": "yellow",
            "high": "red",
            "critical": "bold red",
        }
        risk_color = risk_colors.get(risk.lower(), "yellow")
        risk_display = f"[{risk_color}]{risk.upper()}[/{risk_color}]"

        table.add_row(name, category, risk_display, description)

    return table


def create_options_table(options: Dict[str, Any]) -> Table:
    """Create formatted table of module options."""

    table = Table(
        title="[bold cyan]Module Options[/bold cyan]",
        show_header=True,
        header_style="bold magenta",
        border_style="cyan",
    )

    table.add_column("Option", style="cyan", justify="left", no_wrap=True)
    table.add_column("Current Value", style="green", justify="left")
    table.add_column("Required", style="yellow", justify="center", no_wrap=True)
    table.add_column("Description", style="white", justify="left")

    for option_name, option_data in options.items():
        value = option_data.get("value", "")
        required = option_data.get("required", False)
        description = option_data.get("description", "")

        if value is None or value == "":
            value_display = "[dim italic]<not set>[/dim italic]"
        else:
            if isinstance(value, int) and value > 255:
                value_display = f"{value} (0x{value:X})"
            else:
                value_display = str(value)

        required_display = "[red]YES[/red]" if required else "[dim]no[/dim]"

        table.add_row(option_name, value_display, required_display, description)

    return table


def create_progress_bar(
    total: int,
    description: str = "Processing",
    show_time: bool = True,
    show_speed: bool = False
) -> Progress:
    """Create rich progress bar."""

    columns = [
        SpinnerColumn(),
        TextColumn("[bold blue]{task.description}[/bold blue]"),
        BarColumn(complete_style="green", finished_style="bold green"),
        TaskProgressColumn(),
    ]

    if show_time:
        columns.append(TimeRemainingColumn())
        columns.append(TimeElapsedColumn())

    return Progress(*columns, console=console)


def create_spinner(description: str = "Working", style: str = "dots") -> Live:
    """Create animated spinner for indeterminate progress."""

    spinner = Spinner(style, text=f"[cyan]{description}...[/cyan]")
    return Live(spinner, console=console, transient=True)


def format_status(
    message: str,
    status: str = "info",
    include_timestamp: bool = False
) -> Text:
    """Format status message with icon and color."""

    status_styles = {
        "success": ("[green][+][/green]", "green"),
        "error": ("[red][-][/red]", "red"),
        "info": ("[blue][*][/blue]", "blue"),
        "warning": ("[yellow][!][/yellow]", "yellow"),
        "debug": ("[dim][?][/dim]", "dim"),
    }

    icon, color = status_styles.get(status, ("[white][*][/white]", "white"))

    text = Text()

    if include_timestamp:
        now = datetime.now().strftime("%H:%M:%S")
        text.append(f"[{now}] ", style="dim")

    text.append_text(Text.from_markup(icon))
    text.append(" ")
    text.append(message, style=color)

    return text


def print_success(message: str, **kwargs):
    """Print success message."""
    console.print(format_status(message, "success"), **kwargs)


def print_error(message: str, **kwargs):
    """Print error message."""
    console.print(format_status(message, "error"), **kwargs)


def print_info(message: str, **kwargs):
    """Print info message."""
    console.print(format_status(message, "info"), **kwargs)


def print_warning(message: str, **kwargs):
    """Print warning message."""
    console.print(format_status(message, "warning"), **kwargs)