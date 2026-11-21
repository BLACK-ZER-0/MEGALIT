
import datetime
import logging
import logging.handlers
import os

from rich.text import Text

from .ui import console, err_console

# ── custom levels ────────────────────────────────────────────────────────────
TRACE = 5
VERBOSE = 7
logging.addLevelName(TRACE, "TRACE")
logging.addLevelName(VERBOSE, "VERBOSE")

# ── styles ───────────────────────────────────────────────────────────────────
# colorful level-cell palette: each level word gets its own color
_LEVEL_STYLE = {
    "TRACE": "bright_blue",
    "VERBOSE": "bright_cyan",
    "DEBUG": "bold bright_green",
    "INFO": "bold bright_magenta",
    "WARNING": "bold bright_yellow",
    "ERROR": "bold bright_red",
    "CRITICAL": "bold white on red",
}
_TIME_STYLE = "bright_black"
_BRACKET = "bright_black"
_ARROW = "bold bright_magenta"

# message color per level
_MSG_STYLE = {
    "TRACE": "grey62",
    "VERBOSE": "grey74",
    "DEBUG": "grey74",
    "INFO": "bright_white",
    "WARNING": "bright_yellow",
    "ERROR": "bright_red",
    "CRITICAL": "bold bright_red",
}

# method tag → color ([HTTP], [DETECT], [PROBE], …)
TAG_COLORS = {
    "HTTP": "bright_cyan",
    "DETECT": "bright_magenta",
    "PROBE": "bright_red",
    "DNS": "bright_blue",
    "SIG": "bright_green",
    "HEUR": "bright_green",
    "REPORT": "bright_yellow",
    "LOAD": "bright_yellow",
    "CLI": "bright_white",
    "CORE": "grey62",
    "MAIN": "bright_white",
}
DEFAULT_TAG_COLOR = "bright_magenta"

# subsystem tag → emoji (the [emoji] cell)
TAG_EMOJI = {
    "HTTP": "🌐",
    "DETECT": "🕵️ ",
    "PROBE": "🚀",
    "DNS": "🛰️",
    "SIG": "🧩",
    "HEUR": "🧠",
    "REPORT": "📄",
    "LOAD": "📦",
    "CLI": "⌨️",
    "CORE": "⚙️ ",
    "MAIN": "⛰️",
}
DEFAULT_TAG_EMOJI = "🧭"

# level → emoji override (trouble must be visible at a glance)
_LEVEL_EMOJI = {
    "WARNING": "⚠️",
    "ERROR": "🛑",
    "CRITICAL": "💥",
    "DEBUG": "🔍",
    "TRACE": "🐜",
}

# module filename → pretty method tag
TAG_MAP = {
    "httpclient": "HTTP",
    "detector": "DETECT",
    "prober": "PROBE",
    "dnsinfo": "DNS",
    "signatures": "SIG",
    "heuristics": "HEUR",
    "reporter": "REPORT",
    "userloaders": "LOAD",
    "cli": "CLI",
    "logman": "CORE",
    "__main__": "MAIN",
}


# short level names so the 6-char cell stays aligned: [ info ]
_SHORT_LEVEL = {
    "TRACE": "trace", "VERBOSE": "vbose", "DEBUG": "debug", "INFO": "info",
    "WARNING": "warn", "ERROR": "error", "CRITICAL": "crit",
}


def tag_for(record: logging.LogRecord) -> str:
   
    t = getattr(record, "tag", None)
    if t:
        return str(t).upper()
    return TAG_MAP.get(record.module, record.module.upper()[:8])


def emoji_for(record: logging.LogRecord) -> str:
    
    lvl = record.levelname
    if lvl in _LEVEL_EMOJI:
        return _LEVEL_EMOJI[lvl]
    return TAG_EMOJI.get(tag_for(record), DEFAULT_TAG_EMOJI)


def _level_cell(levelname: str) -> str:
    return _SHORT_LEVEL.get(levelname, levelname.lower())[:6].center(6)


def _render_line(record: logging.LogRecord, ts: str, msg: str) -> Text:
    """Build the rich-colored  [time] [emoji] [ level ] [TAG] => msg  line."""
    lvl = record.levelname
    tag = tag_for(record)
    line = Text(" ")  # ← the user-spec extra leading space
    line.append(f" [{ts}]", style=_TIME_STYLE)
    line.append(" [", style=_TIME_STYLE)
    line.append(emoji_for(record), style="")
    line.append("]", style=_TIME_STYLE)
    line.append(" [", style=_BRACKET)
    line.append(_level_cell(lvl), style=_LEVEL_STYLE.get(lvl, "bright_white"))
    line.append("]", style=_BRACKET)
    line.append(" [", style=_BRACKET)
    line.append(tag, style=TAG_COLORS.get(tag, DEFAULT_TAG_COLOR))
    line.append("]", style=_BRACKET)
    line.append(" => ", style=_ARROW)
    line.append(msg, style=_MSG_STYLE.get(lvl, "bright_white"))
    if record.exc_info:
        import traceback
        tb = "".join(traceback.format_exception(*record.exc_info))
        line.append("\n" + tb, style="red")
    return line


class ConsoleLogHandler(logging.Handler):
   

    def __init__(self, console_obj):
        super().__init__()
        self.console = console_obj

    def emit(self, record: logging.LogRecord) -> None:
        try:
            msg = record.getMessage()
        except Exception:
            msg = str(record.msg)
        try:
            ts = datetime.datetime.fromtimestamp(record.created).strftime("%H:%M:%S")
        except Exception:
            ts = "--:--:--"
        line = _render_line(record, ts, msg)
        # Console lines stay single-line (ellipsized) — full text lives in the file.
        try:
            line.truncate(max(40, self.console.width - 1), overflow="ellipsis")
        except Exception:
            pass
        self.console.print(line, markup=False, highlight=False, soft_wrap=False)


class FileLogFormatter(logging.Formatter):
    

    def format(self, record: logging.LogRecord) -> str:
        ts = datetime.datetime.fromtimestamp(record.created).strftime("%Y-%m-%d %H:%M:%S")
        try:
            msg = record.getMessage()
        except Exception:
            msg = str(record.msg)
        line = (f" [{ts}] [{emoji_for(record)}] [{_level_cell(record.levelname)}] "
                f"[{tag_for(record)}] => {msg}")
        if record.exc_info:
            line += "\n" + self.formatException(record.exc_info)
        return line


class MegalitLogger(logging.LoggerAdapter):
    """Logger with a fixed subsystem tag + trace()/verbose() helpers."""

    def process(self, msg, kwargs):
        extra = dict(kwargs.get("extra") or {})
        extra.setdefault("tag", (self.extra or {}).get("tag"))
        kwargs["extra"] = extra
        return msg, kwargs

    def trace(self, msg, *args, **kwargs):
        self.log(TRACE, msg, *args, **kwargs)

    def verbose(self, msg, *args, **kwargs):
        self.log(VERBOSE, msg, *args, **kwargs)

    def warn(self, msg, *args, **kwargs):
        self.warning(msg, *args, **kwargs)


_configured = False
_log_path = ""


def setup_logging(verbose: bool = False, debug: bool = False, log_dir: str = "logs",
                  json_mode: bool = False) -> str:
    
    global _configured, _log_path
    logger = logging.getLogger("megalit")
    logger.setLevel(TRACE)
    logger.handlers.clear()
    logger.propagate = False

    os.makedirs(log_dir, exist_ok=True)
    ts = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    _log_path = os.path.join(log_dir, f"megalit_{ts}.log")

    fh = logging.handlers.RotatingFileHandler(
        _log_path, maxBytes=1_000_000, backupCount=5, encoding="utf-8")
    fh.setFormatter(FileLogFormatter())
    fh.setLevel(TRACE)
    logger.addHandler(fh)

    ch = ConsoleLogHandler(err_console if json_mode else console)
    if debug:
        ch.setLevel(TRACE)       # 5  — everything, incl. raw header dumps
    elif verbose:
        ch.setLevel(VERBOSE)     # 7  — + request/hop/probe flow narration
    else:
        ch.setLevel(logging.INFO)  # 20 — clean: milestones, findings, warnings
    logger.addHandler(ch)

    _configured = True
    get_logger("CORE").debug("logging ready → %s (file=TRACE, console=%s)",
                             _log_path, logging.getLevelName(ch.level))
    return _log_path


def get_logger(tag: str = "") -> MegalitLogger:
    """Get the megalit logger with a subsystem tag, e.g. get_logger("HTTP")."""
    return MegalitLogger(logging.getLogger("megalit"),
                         {"tag": tag} if tag else {})


def log_path() -> str:
    return _log_path


def log_session_header(version: str, summary: str) -> None:
    """One-line session banner in the log file (keeps the stream tidy)."""
    log = get_logger("CORE")
    log.info("session ▶ Megalit v%s │ %s", version, summary)


def log_session_footer(version: str, summary: str) -> None:
    get_logger("CORE").info("session ■ end v%s │ %s", version, summary)
