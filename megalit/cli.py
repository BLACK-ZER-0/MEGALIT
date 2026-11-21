
import argparse
import asyncio
import datetime
import json
import os
import re
import subprocess
import sys

from pathlib import Path
from rich import box
from rich.panel import Panel
from rich.text import Text

from . import __version__, reporter, ui
from .detector import run as run_detection
from .httpclient import HTTPClient
from .logman import get_logger, log_session_footer, log_session_header, setup_logging
from .signatures import SIGNATURES
from .ui import (BANNER_COUNT, center, console, err, ok, print_banner,
                 print_profile, save_snapshot, set_terminal_title, warn)
from .userloaders import load_user_list, load_vendor_names

try:  # pretty colored --help when rich is new enough
    from rich.argparse import RichHelpFormatter as _HelpFormatter
except Exception:  # pragma: no cover
    _HelpFormatter = argparse.RawDescriptionHelpFormatter


class _BannerParser(argparse.ArgumentParser):
    """--help first prints a random banner, exactly like fireeye_v3 did."""

    def print_help(self, file=None):
        if not ui.JSON_MODE:
            print("\n")
            print_banner(__version__)
        super().print_help(file)

EXAMPLES = """examples:
  ./megalit.sh https://example.com
  ./megalit.sh https://example.com --show-headers          # plain-HTTP site
  ./megalit.sh https://example.com --findall --verbose
  ./megalit.sh https://example.com --json                          # pure JSON on stdout
  ./megalit.sh https://example.com --json result.json              # JSON saved + live report
  ./megalit.sh https://example.com --json --request 3
  ./megalit.sh https://example.com --headers "X-Custom:1;Accept:application/json"
  ./megalit.sh https://example.com --header-search "server|cache" --debug
  ./megalit.sh https://example.com --user-list my_waf.json --user-vendors-list vendors.txt
  ./megalit.sh https://example.com --proxy proxies.txt             # http/socks4/socks5 mixed
"""


class _VersionAction(argparse.Action):
    """-v/--version with rich colors."""

    def __call__(self, parser, namespace, values, option_string=None):
        try:
            from .ui import console as _c
            _c.print(Text.assemble(
                ("⚡ Megalit ", "bold bright_magenta"),
                (f"v{__version__}", "bold bright_cyan"),
                (" — advanced async WAF / CDN / LB fingerprinting framework",
                 "dim bright_white")))
        except Exception:  # pragma: no cover
            print(f"Megalit v{__version__}")
        raise SystemExit(0)


def build_parser() -> argparse.ArgumentParser:
    if len(sys.argv) == 1:
      console.print(f"[bold white] [[bold color(73)]+[bold white]] [bold color(78)]Use: python3 {Path(sys.argv[0]).name} --help")
      sys.exit(0)

    p = _BannerParser(
        prog="megalit",
        description="Megalit — advanced async WAF / CDN / LB detection framework "
                    "(aiohttp + rich). Multi-technique: headers, cookies, body, "
                    "DNS, TLS, active probes.",
        epilog=EXAMPLES,
        formatter_class=_HelpFormatter, usage=argparse.SUPPRESS
    )
    p.add_argument("target", nargs="?", default=None,
                   help="Target domain or URL (e.g. example.com)")
    p.add_argument("--verbose", action="store_true",
                   help="Verbose output (default: False)")
    p.add_argument("--request", type=int, default=2, metavar="REQUEST",
                   help="Number of requests to send (default: 2)")
    p.add_argument("--debug", action="store_true",
                   help="Debug mode (extra logs)")
    p.add_argument("-a", "--findall", action="store_true",
                   help="Find all WAFs which match the signatures, do not stop "
                        "testing on the first one")
    p.add_argument("--json", nargs="?", const=True, default=False, metavar="FILE",
                   help="JSON output. Bare --json → pure JSON on stdout; "
                        "--json FILE → save JSON to FILE and show the colorful "
                        "report on screen (default: False)")
    p.add_argument("--show-headers", action="store_true",
                   help="Show HTTP response headers using curl -I (default: False)")
    p.add_argument("--header-search", metavar="HEADER_SEARCH",
                   help="Regex to search inside headers/cookies/body for quick evidence")
    p.add_argument("--headers", metavar="HEADERS",
                   help="Custom request headers, format: 'Key:Val;Key2:Val2'")
    p.add_argument("--no-rotate-ua", action="store_true",
                   help="Disable UA rotation and use a single fallback UA")
    p.add_argument("--report", metavar="REPORT",
                   help="Path to save markdown report (default: auto filename)")
    p.add_argument("--user-list", metavar="USER_LIST",
                   help="Path to user-supplied WAF/CDN/Token list (JSON or simple format)")
    p.add_argument("--user-vendors-list", metavar="USER_VENDORS_LIST",
                   help="Path to user-supplied vendor list (JSON or text), "
                        "merged into strong vendors")
    p.add_argument("--proxy", metavar="PROXY_FILE",
                   help="Path to proxy list (ip:port, http://, https://, "
                        "socks4://, socks5://), one per line")
    p.add_argument("--selftest", action="store_true",
                   help="Run offline signature-DB integrity + matcher tests, then exit")
    p.add_argument("-v", "--version", action=_VersionAction, nargs=0,
                   help="Show tool version and exit")
    return p


def _parse_custom_headers(spec: str) -> dict:
    custom = {}
    for part in spec.split(";"):
        part = part.strip()
        if not part:
            continue
        if ":" not in part:
            raise ValueError(f"invalid header '{part}' — expected 'Key:Val'")
        k, v = part.split(":", 1)
        k, v = k.strip(), v.strip()
        if not k:
            raise ValueError(f"invalid header '{part}' — empty key")
        custom[k] = v
    return custom


def _load_proxies(path: str) -> list:
    proxies = []
    with open(path, "r", encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if re.match(r"^\d{1,3}(\.\d{1,3}){3}:\d+$", line):
                line = "http://" + line
            if not re.match(r"^(https?|socks4|socks5)://", line):
                warn(f"proxy line {lineno} skipped (bad scheme): {line[:40]}")
                continue
            proxies.append(line)
    return proxies


def _auto_report_path(target: str) -> str:
    host = re.sub(r"[^A-Za-z0-9._-]", "_", target.split("://", 1)[-1].split("/")[0])
    ts = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    return f"megalit-report-{host}-{ts}.md"


def _curl_headers(target: str) -> str:
    """Real `curl -I -L` dump (fireeye behavior) — falls back to '' when curl
    is missing / fails; the reporter then keeps the aiohttp raw headers."""
    url = target if "://" in target else "http://" + target
    try:
        proc = subprocess.run(
            ["curl", "-I", "-L", "-s", "--max-time", "12", url],
            capture_output=True, text=True, timeout=14)
        return (proc.stdout or "").strip() or (proc.stderr or "").strip()
    except Exception:
        return ""


async def _async_main(args, custom_headers: dict, proxies: list,
                      user_sigs: list, strong_vendors: set, log_file: str) -> int:
    client = HTTPClient(proxies=proxies, rotate_ua=not args.no_rotate_ua)
    await client.start()
    try:
        result = await run_detection(args, client, user_sigs, strong_vendors)
    finally:
        await client.close()

    if result.get("fatal"):
        console.print(center(Panel(
            Text(f"Target unreachable: {result['error']}\n"
                 f"Check the domain / network / proxy settings.", style="bright_red"),
            title=Text(" ✘ MEGALIT FAILED ", style="bold bright_white on red"),
            title_align="center", border_style="red", box=box.DOUBLE,
            padding=(1, 4))))
        console.print(center(Text(f"log → {log_file}", style="dim")))
        return 2

    result["log_file"] = log_file

    if args.show_headers:
        real_curl = await asyncio.to_thread(_curl_headers, args.target)
        if real_curl:
            result["curl_headers_raw"] = real_curl

    # --json comes in two shapes: True (bare → pure stdout JSON) or a FILE path
    # (save JSON to FILE and show the colorful report on screen).
    json_path = args.json if isinstance(args.json, str) and args.json.strip() else ""
    pure_json = bool(args.json) and not json_path

    if args.show_headers:  # keep the curl -I dump available in JSON mode too
        result["response_headers_raw"] = result.get("show_headers_raw", "")

    if pure_json:
        reporter.print_json(result)
    else:
        if json_path:
            try:
                with open(json_path, "w", encoding="utf-8") as fh:
                    json.dump(reporter.to_json_dict(result), fh,
                              indent=2, ensure_ascii=False)
                ok(f"json → [bold bright_cyan]{json_path}[/]")
            except OSError as e:
                err(f"--json: cannot write '{json_path}': {e}")
                return 2
        reporter.render(result, args)

    # markdown report: auto filename in visible modes, explicit path in JSON mode
    report_path = ""
    if not pure_json or args.report:
        report_path = args.report or _auto_report_path(args.target)
        try:
            reporter.save_markdown(result, report_path)
        except OSError as e:
            err(f"--report: cannot write '{report_path}': {e}")
            return 2

    if not pure_json:
        st = result["stats"]
        done = Text(justify="center")
        done.append("✔  ", style="bold bright_green")
        done.append("SCAN COMPLETE", style="bold bright_white on bright_green")
        done.append("  ✔\n\n", style="bold bright_green")
        chips = [("requests", str(st["requests"]), "bright_cyan"),
                 ("time", f"{st['elapsed']}s", "bright_magenta"),
                 ("findings", str(len(result["findings"])), "bright_yellow"),
                 ("uas", str(st["uas_used"]), "bright_green"),
                 ("proxies", str(st["proxies_used"]), "bright_blue")]
        for i, (k, v, c) in enumerate(chips):
            if i:
                done.append("  │  ", style="bright_black")
            done.append(f"{k} ", style="dim bright_white")
            done.append(v, style=f"bold {c}")
        if report_path:
            done.append("\n\n📄 report → ", style="dim")
            done.append(report_path, style="bold bright_yellow")
        if json_path:
            done.append("\n🧾 json    → ", style="dim")
            done.append(json_path, style="bold bright_cyan")
        done.append("\n📜 log    → ", style="dim")
        done.append(log_file, style="bold bright_cyan")
        console.print(center(Panel(done, border_style="bright_green",
                                   box=box.DOUBLE, padding=(1, 4))))
    return 0


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if getattr(args, "selftest", False):
        from .selftest import run as _run_selftest
        return _run_selftest()
    if not args.target:
        parser.error("the following arguments are required: target")
    # args.json is True (bare) or a FILE path (str) or False — always boolean-ish
    ui.JSON_MODE = bool(args.json)  # route UI ops lines to stderr in JSON modes

    # ① terminal title + logo first — logs must never appear above it.
    #    In JSON modes the banner/profile go to STDERR so stdout stays pure JSON.
    set_terminal_title()
    if ui.JSON_MODE:
        from .ui import err_console
        print_banner(__version__, dest=err_console)
    else:
        print_banner(__version__)

    if args.request < 0:
        err("--request must be >= 0")
        return 2

    try:
        custom_headers = _parse_custom_headers(args.headers) if args.headers else {}
    except ValueError as e:
        err(str(e))
        return 2

    try:
        if args.header_search:
            re.compile(args.header_search, re.I)
    except re.error as e:
        err(f"invalid --header-search regex: {e}")
        return 2

    # ② logging up next — every later line follows the unified format
    log_file = setup_logging(verbose=args.verbose, debug=args.debug,
                             json_mode=ui.JSON_MODE)
    log = get_logger("CLI")

    proxies = []
    if args.proxy:
        if not os.path.isfile(args.proxy):
            err(f"proxy file not found: {args.proxy}")
            return 2
        proxies = _load_proxies(args.proxy)
        ok(f"[bold]{len(proxies)}[/] proxy loaded")

    user_sigs = []
    if args.user_list:
        try:
            user_sigs = load_user_list(args.user_list)
        except Exception as e:
            err(f"--user-list: {e}")
            return 2
        ok(f"[bold]{len(user_sigs)}[/] user signature(s) merged")

    strong_vendors = set()
    if args.user_vendors_list:
        try:
            names = load_vendor_names(args.user_vendors_list)
        except Exception as e:
            err(f"--user-vendors-list: {e}")
            return 2
        strong_vendors = set(names)
        ok(f"[bold]{len(names)}[/] user vendor(s) merged into strong list")

    n_pat = sum(len(s.matches) for s in SIGNATURES)
    n_pat += sum(len(s.matches) for s in user_sigs)
    n_vend = len(SIGNATURES) + len(user_sigs)
    profile_pairs = [
        ("target", args.target),
        ("req", args.request),
        ("vendors", f"{n_vend}+"),
        ("patterns", str(n_pat)),
        ("findall", "ON" if args.findall else "off"),
        ("ua-rot", "off" if args.no_rotate_ua else "ON"),
        ("proxy", len(proxies)),
        ("debug", "ON" if args.debug else "off"),
    ]
    if ui.JSON_MODE:  # stderr — stdout stays pure JSON (same as the banner)
        from .ui import err_console
        print_profile(profile_pairs, dest=err_console)
    else:
        print_profile(profile_pairs)

    log_session_header(__version__,
                       f"target={args.target} | request={args.request} | findall={args.findall} "
                       f"| json={args.json} | rotate_ua={not args.no_rotate_ua} "
                       f"| proxies={len(proxies)} | user_sigs={len(user_sigs)}")

    try:
        rc = asyncio.run(_async_main(args, custom_headers, proxies,
                                     user_sigs, strong_vendors, log_file))
        log_session_footer(__version__, f"exit_code={rc}")
        return rc
    except KeyboardInterrupt:
        warn("\nInterrupted by user (Ctrl+C)")
        log.warning("interrupted by user (Ctrl+C)")
        return 130
    except Exception as e:  # last-resort guard
        log.exception("Unhandled error")
        err(f"unexpected error: {e}  (see log: {log_file})")
        return 1
    finally:
        save_snapshot()


if __name__ == "__main__":
    sys.exit(main())
