#!/usr/bin/env python3
"""
Shared terminal output helpers for the perimetr toolkit.

Every script imports this instead of rolling its own print()/colorama
formatting, so a sweep, a port scan, and a nuclei report all look like they
came from the same tool instead of three different eras of shell scripting.
Built on rich, which already degrades box-drawing/color gracefully on
terminals that can't render it (no per-script encoding workarounds needed).
"""

from rich.console import Console
from rich.table import Table
from rich.text import Text
from rich.panel import Panel
from rich import box

console = Console()


def banner(title, subtitle=None):
    body = Text(title, style="bold cyan", justify="center")
    if subtitle:
        body = Text.assemble(body, "\n", Text(subtitle, style="dim italic", justify="center"))
    console.print(Panel(body, box=box.HEAVY, border_style="cyan", padding=(1, 4)))


def section(title):
    """A horizontal rule with a title - marks the start of a new stage/step."""
    console.rule(f"[bold cyan]{title}[/bold cyan]")


def info(msg):
    console.print(f"[cyan][*][/cyan] {msg}")


def success(msg):
    console.print(f"[bold green][+][/bold green] {msg}")


def warn(msg):
    console.print(f"[yellow][!][/yellow] {msg}")


def error(msg):
    console.print(f"[bold red][!][/bold red] {msg}")


def table(title, columns, rows):
    """columns: list of header strings. rows: list of tuples/lists."""
    t = Table(title=title, box=box.SIMPLE_HEAVY, header_style="bold white", title_justify="left")
    for col in columns:
        t.add_column(col)
    for row in rows:
        t.add_row(*[str(v) for v in row])
    console.print(t)


def summary(title, stats):
    """stats: list of (label, value) pairs, printed as a simple key/value block."""
    console.print(f"\n[bold cyan]{'='*70}[/bold cyan]")
    console.print(f"[bold cyan]{title}[/bold cyan]")
    console.print(f"[bold cyan]{'='*70}[/bold cyan]")
    for label, value in stats:
        console.print(f"  [white]{label}:[/white] {value}")
    console.print(f"[bold cyan]{'='*70}[/bold cyan]\n")
