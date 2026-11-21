
import os
import sys

from rich import box
from rich.align import Align
from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

from .banners import BANNERS, choose_banner

# Dev/CI helper: MEGALIT_SNAPSHOT=out.svg records the whole run and saves on exit.
SNAPSHOT = os.environ.get("MEGALIT_SNAPSHOT", "")

# Shared console for the whole tool (highlight off keeps URLs clean).
console = Console(highlight=False, soft_wrap=False, record=bool(SNAPSHOT))

# Secondary console for stderr — used in --json mode so stdout stays pure JSON.
err_console = Console(file=sys.stderr, highlight=False, soft_wrap=False)

# When True (set by the CLI for --json), ok/warn/err/info go to stderr.
JSON_MODE = False

BANNER_COUNT = len(BANNERS)

# vertical gradient kept for other widgets
LINE_GRADIENT = ("bright_magenta", "magenta", "magenta",
                 "bright_blue", "blue", "bright_cyan")

ROLE_STYLES = {
    "WAF": "bold red",
    "CDN": "bold cyan",
    "LB": "bold magenta",
    "CLOUD": "bold yellow",
    "PROXY": "bold blue",
    "TECH": "bold green",
    "WAF/CDN": "bold bright_red",
    "WAF/LB": "bold bright_red",
    "CDN/LB": "bold cyan",
}

CONF_STYLES = {
    "HIGH": "bold bright_green",
    "MEDIUM": "bold bright_yellow",
    "LOW": "dim white",
}

CONF_FILLED = {"HIGH": 8, "MEDIUM": 5, "LOW": 2}

# Table header used across all report tables (deep indigo + white text).
THEAD = "bold bright_white on rgb(52,40,110)"

def save_snapshot() -> None:
    """Persist the recorded run (only when MEGALIT_SNAPSHOT is set)."""
    if SNAPSHOT and console.record:
        try:
            if SNAPSHOT.lower().endswith(".html"):
                console.save_html(SNAPSHOT)
            elif SNAPSHOT.lower().endswith(".svg"):
                console.save_svg(SNAPSHOT, title="Megalit")
            else:
                console.save_text(SNAPSHOT)
        except Exception:
            pass


def center(renderable):
    """Center-align any renderable on the terminal width."""
    return Align.center(renderable)


def style_role(role: str) -> str:
    return ROLE_STYLES.get(role, "bold white")


# ───────────────────────────── low-level banner kit ──────────────────────

def print_banner(version: str = "", dest=None) -> None:
    """Random FIRE EYE collection banner (renamed MEGALIT), centered.

    Same behavior as fireeye_v3: pick a random banner each run and print it
    with Align.center.  `version` is accepted for API compatibility; the art
    itself already carries the v3 tag in its sidebar.
    `dest` overrides the output console (stderr in --json mode)."""
    banner = choose_banner()
    (dest or console).print(center(Text.from_markup(banner)))
    (dest or console).print()


def set_terminal_title() -> None:
    """(@)==[MEGALIT]==(@) in the terminal title bar (fireeye-style).
    Skipped when stdout is not a TTY (piped output stays clean)."""
    try:
        if not sys.stdout.isatty():
            return
        sys.stdout.write("\x1b[1;35m\x1b]2;(@)==[MEGALIT]==(@)\x07")
        sys.stdout.flush()
    except Exception:
        pass


# ───────────────────────── typewriter NOTE (fireeye style) ──────────────────

def print_profile(pairs, dest=None) -> None:
    """Centered scan-profile chips line:  target: x · requests: n · ...
    `dest` overrides the output console (stderr in --json mode)."""
    t = Text(justify="center")
    for i, (k, v) in enumerate(pairs):
        if i:
            t.append("   │   ", style="bright_black")
        t.append(f"{k} ", style="dim bright_white")
        t.append(str(v), style="bold bright_green")
    (dest or console).print(center(t))
    (dest or console).print()


# ───────────────────────────── section headers ───────────────────────────

def section(title: str, icon: str = "◆", style: str = "bright_cyan") -> None:
    """Fancy centered section divider:  ────── ⛨ DETECTION RESULTS ──────"""
    t = Text()
    t.append(f"{icon} ", style=f"bold {style}")
    t.append(title.upper(), style="bold bright_white")
    console.print()
    console.print(Rule(t, style=style, align="center", characters="─"))


def note(msg: str) -> None:
    console.print(center(Text(msg, style="dim italic")))


# ───────────────────────────── panels & glyphs ───────────────────────────

def kv_panel(title, rows, border="bright_blue", box_style=box.ROUNDED,
             key_style="bold bright_cyan", key_width=17):
    """Centered panel of perfectly aligned key→value rows (grid-based).
    Values may be rich Text (safe) or str (rich markup)."""
    grid = Table.grid(padding=(0, 2), pad_edge=False)
    grid.add_column(justify="left", min_width=key_width, no_wrap=True)
    grid.add_column(justify="left")
    for k, v in rows:
        key = Text()
        key.append("▸ ", style="bright_black")
        key.append(str(k), style=key_style)
        if isinstance(v, Text):
            val = v
        else:
            try:
                val = Text.from_markup(str(v))
            except Exception:
                val = Text(str(v))
        grid.add_row(key, val)
    console.print(center(
        Panel(grid, title=f"[bold]{title}[/]", border_style=border,
              box=box_style, padding=(1, 2))))


def stat_strip(pairs) -> None:
    """Centered dashboard strip: big value over a dim label, one column per stat.
    pairs = [(value, label, color), ...]"""
    grid = Table.grid(pad_edge=False, padding=(0, 3))
    for _ in pairs:
        grid.add_column(justify="center")
    row = []
    for value, label, color in pairs:
        t = Text(justify="center")
        t.append(str(value), style=f"bold {color}")
        t.append("\n", style="")
        t.append(str(label), style="dim bright_white")
        row.append(t)
    grid.add_row(*row)
    console.print(center(grid))


def ok(msg: str) -> None:
    (err_console if JSON_MODE else console).print(
        center(Text.from_markup(f"[bold bright_green]✔[/] {msg}")))


def warn(msg: str) -> None:
    (err_console if JSON_MODE else console).print(
        center(Text.from_markup(f"[bold bright_yellow]⚠[/] {msg}")))


def err(msg: str) -> None:
    (err_console if JSON_MODE else console).print(
        center(Text.from_markup(f"[bold bright_red]✘[/] {msg}")))


def info(msg: str) -> None:
    (err_console if JSON_MODE else console).print(
        center(Text.from_markup(f"[bold bright_cyan]➤[/] {msg}")))


# ───────────────────────────── little widgets ────────────────────────────

def conf_bar(conf: str) -> str:
    """Certainty meter:  ▰▰▰▰▰▰▰▰  HIGH"""
    filled = CONF_FILLED.get(conf, 1)
    color = {"HIGH": "bright_green", "MEDIUM": "bright_yellow", "LOW": "grey62"}.get(conf, "grey62")
    bar = "▰" * filled + "▱" * (8 - filled)
    return f"[{color}]{bar}[/]  [bold {color}]{conf}[/]"


def progress_bar_text(pct: int, total_blocks: int = 20) -> str:
    """Fireeye-style numeric confidence bar:  [████████░░░░░░] 45%
    green ≥ 70 · yellow ≥ 40 · red below (rich markup string)."""
    pct = max(0, min(100, int(pct)))
    filled = int((pct / 100.0) * total_blocks)
    empty = total_blocks - filled
    color = "bold green" if pct >= 70 else ("bold yellow" if pct >= 40 else "bold red")
    return f"[{color}]" + "█" * filled + "[/]" + "░" * empty + f" [bold white]{pct}%[/]"


def score_bar(score: float, mx: float, width: int = 8) -> str:
    """Mini relative score meter:  ▕████░░░░▏"""
    filled = 1 if mx <= 0 else max(1, min(width, round(score / mx * width)))
    return f"[bright_cyan]{'█' * filled}[/][bright_black]{'░' * (width - filled)}[/]"

