
import datetime
import json
from dataclasses import asdict
from typing import Dict

from rich import box
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

from . import __version__
from .signatures import SIGNATURES
from .ui import (CONF_STYLES, THEAD, center, conf_bar, console, kv_panel,
                 note, progress_bar_text, score_bar, section, stat_strip,
                 style_role)

ROLE_COLORS_MD = {"WAF": "🔴", "CDN": "🔵", "LB": "🟣", "CLOUD": "🟡",
                  "PROXY": "🟠", "TECH": "🟢", "WAF/CDN": "🔴", "WAF/LB": "🟣",
                  "LB/CDN": "🔵"}

LAYER_ICONS = [("WAF", "🛡", "bright_red"), ("CDN", "🌀", "bright_cyan"),
               ("LB", "🔀", "bright_magenta"), ("CLOUD", "🌥", "bright_yellow"),
               ("PROXY", "🕵", "bright_blue"), ("TECH", "⚙", "bright_green")]

FIELD_COLORS = {"header": "bright_cyan", "header_name": "bright_cyan",
                "header_value": "bright_cyan", "cookie": "bright_magenta",
                "cookie_name": "bright_magenta", "cookie_value": "bright_magenta",
                "body": "bright_green", "status": "bright_yellow",
                "cname": "bright_blue", "ptr": "bright_blue", "ns": "bright_blue",
                "cert": "bright_blue", "ip_range": "bright_yellow"}


def _conf(conf: str) -> str:
    mark = {"HIGH": "●●●", "MEDIUM": "●●○", "LOW": "●○○"}.get(conf, "○○○")
    return f"[{CONF_STYLES[conf]}]{mark} {conf}[/]"


def _mk_table(title: str, border: str, heavy: bool = False) -> Table:
    return Table(box=box.HEAVY_HEAD if heavy else box.ROUNDED,
                 title=Text(title, style=f"bold {border}"),
                 title_justify="center", header_style=THEAD,
                 row_styles=["", "dim"], pad_edge=False, expand=False,
                 show_lines=True,  # every row visually separated (user spec)
                 border_style=border)


def render(result: Dict, args) -> None:
    """Full colorful centered terminal report."""
    st = result["stats"]
    v = result["verdict"]

    # ── scan overview dashboard ───────────────────────────────────────────
    stat_strip([
        (st["requests"], "requests", "bright_cyan"),
        (f"{st['elapsed']}s", "elapsed", "bright_magenta"),
        (len(result["findings"]), "findings", "bright_yellow"),
        (v["waf"] or "—", "waf", "bright_red" if v["waf"] else "grey62"),
        (len(v["cdn"]) or "—", "cdn", "bright_cyan"),
        (len(v["lb"]) or "—", "lb", "bright_magenta"),
    ])

    # ── target summary ──
    dns = result["dns"]
    cert = dns.get("cert") or {}
    fin = result["final_url"]
    rows = [
        ("Target", escape(str(result["target"]))),
        ("Primary URL", f"[bright_green]{escape(result['primary_url'])}[/]"),
        ("Final URL", f"[bright_green]{escape(fin)}[/]"),
        ("Scheme", _scheme_text(result)),
        ("Scheme Note", Text(escape(result["scheme"]["note"]), style="dim italic")),
        ("IPv4", escape(", ".join(dns.get("ips") or []) or "—")),
    ]
    if dns.get("cname"):
        rows.append(("CNAME", f"[dim]{escape(dns['cname'])}[/]"))
    if dns.get("ns"):
        rows.append(("NS", escape(", ".join(dns["ns"][:4]))))
    if dns.get("ptrs"):
        rows.append(("PTR", escape(", ".join(dns["ptrs"][:3]))))
    if cert.get("issuer"):
        rows.append(("TLS Issuer", f"[bright_magenta]{escape(cert['issuer'])}[/]"))
        if cert.get("valid_to"):
            rows.append(("TLS Expires", escape(str(cert["valid_to"]))))
    if cert.get("version"):
        tls_bits = [escape(cert["version"])]
        if cert.get("cipher"):
            tls_bits.append(escape(cert["cipher"]))
        if cert.get("alpn"):
            tls_bits.append(f"ALPN={escape(cert['alpn'])}")
        rows.append(("TLS", " · ".join(tls_bits)))
        if cert.get("h2"):
            rows.append(("HTTP/2", "[bold bright_green]✔ negotiated (h2 via ALPN)[/]"))
    for k, v2 in result.get("server_tech", {}).items():
        rows.append((k, escape(v2[:70])))
    section("Target Summary", icon="🎯", style="bright_blue")
    kv_panel("◈ target intelligence", rows, border="bright_blue")

    # ── findings ──
    section("Detection Results — WAF / CDN / LB", icon="🛡", style="bright_magenta")
    findings = result["findings"]
    if findings:
        _stack_panel(findings)
        console.print()
        _layers_panel(result)
        console.print()
        _findings_tables(findings)
        # fireeye-style separation: user-list matches get their own table
        custom = [f for f in findings if f.get("user")]
        if custom:
            console.print()
            _custom_table(custom)
    else:
        console.print(center(Text("✔ No WAF / CDN / LB signature matched.",
                                  style="bold bright_green")))

    # ── redirect chain ──
    chain = result["chain"]
    if len(chain) > 1 or any(c["status"] and 300 <= c["status"] < 400 for c in chain):
        section("Redirect Chain", icon="🌐", style="bright_cyan")
        tree = Tree(f"[bold]🌐 {escape(result['primary_url'])}[/]")
        for c in chain:
            if c["error"]:
                label = f"[red]✘ {escape(c['error'])}[/]"
            elif 300 <= (c["status"] or 0) < 400:
                loc = c["location"] or c["final_url"]
                label = (f"[bright_yellow]HTTP {c['status']} ↷[/] "
                         f"[bright_cyan]{escape(loc)}[/]")
            else:
                label = (f"[bright_green]HTTP {c['status']} ✔[/] "
                         f"[bright_cyan]{escape(c['final_url'])}[/]")
            tree.add(label)
        console.print(center(tree))

    # ── active probes ──
    probes = result["probes"]
    skipped = result.get("skipped_probes")
    if skipped:
        note(f"⚡ Active probes {skipped}")
    if probes:
        section("Active Probe Results", icon="⚔", style="bright_red")
        t = _mk_table("⚔ attack-vector probes", "bright_red")
        t.add_column("Probe", style="bold white")
        t.add_column("Kind", justify="center", style="dim")
        t.add_column("Status", justify="center")
        t.add_column("Result", justify="center")
        t.add_column("Attributed WAF", overflow="fold")
        t.add_column("Note", overflow="fold", style="dim")
        for p in probes:
            status = f"[bright_green]{p.status}[/]" if p.status else "[red]ERR[/]"
            if p.blocked:
                res = "[bold bright_red]⛔ BLOCKED[/]"
            elif p.error:
                res = "[dim]– error[/]"
            else:
                res = "[bold bright_green]✔ PASSED[/]"
            attr = ", ".join(f"[bold red]{escape(m)}[/]" for m in p.matched) or "[dim]—[/]"
            t.add_row(escape(p.name), escape(getattr(p, "kind", "path")), status, res,
                      attr, escape(p.note))
        console.print(center(t))

    # ── security headers ──
    sec = result["sec_headers"]
    section("Security Headers Audit", icon="🔒", style="bright_yellow")
    n_present, n_total = len(sec["present"]), len(sec["present"]) + len(sec["missing"])
    grade, gcolor = _sec_grade(n_present, n_total)
    t = _mk_table(f"🔒 security headers — coverage {n_present}/{n_total}",
                  "bright_yellow")
    t.add_column("Header", style="bold white")
    t.add_column("Status", justify="center")
    t.add_column("Value", overflow="fold", style="dim")
    for label, val in sec["present"].items():
        t.add_row(escape(label), "[bold bright_green]✔ set[/]", escape(val))
    for label in sec["missing"]:
        t.add_row(escape(label), "[bright_red]✗ missing[/]", "—")
    console.print(center(t))
    meter = "▓" * n_present + "░" * (n_total - n_present)
    console.print(center(Text.from_markup(
        f"[dim]coverage[/] [{gcolor}]{meter}[/] [bold {gcolor}]{n_present}/{n_total}"
        f"  →  grade {grade}[/]")))

    # ── anti-bot / cache / rate-limit heuristics ────────────────────────
    _heuristics_panels(result)

    # ── header search ──
    hs = result.get("header_search") or []
    if hs:
        section(f"Header Search — “{getattr(args, 'header_search', '')}”",
                icon="🔎", style="bright_cyan")
        t = _mk_table(f"🔎 regex evidence — {len(hs)} hit(s)", "bright_cyan")
        t.add_column("Field", justify="center", style="bold bright_cyan")
        t.add_column("Match", overflow="fold", style="bold bright_yellow")
        t.add_column("Context", overflow="fold", style="dim")
        t.add_column("Where", overflow="fold", style="dim italic")
        for h in hs:
            t.add_row(escape(h["field"]), escape(h["match"]),
                      escape(h["context"]), escape(h["where"]))
        console.print(center(t))

    # ── curl -I style headers ──
    if getattr(args, "show_headers", False):
        raw = result.get("curl_headers_raw") or result.get("show_headers_raw") or ""
        section("Response Headers (curl -I style)", icon="📡", style="bright_blue")
        console.print(center(_raw_headers_panel(raw)))

    # ── verdict ──
    _verdict_panel(result)

    # ── DDoS impact chance (fireeye port) ──
    _ddos_panel(result)

    # ── signature database footer ──
    _db_footer()


def _ddos_panel(result: Dict) -> None:
    """💥 DDoS Impact Chance ➤ NN % (level) — centered panel, fireeye style."""
    d = result.get("ddos_impact") or {}
    if not d:
        return
    chance, level = d.get("chance", 0), d.get("level", "Low")
    color = "red" if level == "High" else ("yellow" if level == "Medium" else "green")
    body = Text(justify="center")
    body.append("💥 DDoS Impact Chance ", style="bold color(78)")
    body.append("➤ ", style="bright_black")
    body.append(f"{chance} % ({level})", style=f"bold {color}")
    hint = {"High": "weak shielding — volumetric attacks likely reach the origin",
            "Medium": "partial shielding — some attack traffic still gets through",
            "Low": "strong shielding — origin well protected against volumetric attacks"
            }.get(level, "")
    if hint:
        body.append("\n")
        body.append(hint, style="dim italic")
    console.print(center(Panel(
        body, title=Text(" 💥 DDoS IMPACT ", style="bold bright_white"),
        border_style="bold cyan", box=box.ROUNDED, padding=(0, 3))))


def _custom_table(custom) -> None:
    """Separate section for --user-list matches (fireeye '[Custom]' parity)."""
    t = _mk_table(f"★ {len(custom)} custom signature(s) matched (--user-list)",
                  "bright_yellow")
    t.add_column("Vendor", style="bold bright_yellow")
    t.add_column("Role", justify="center")
    t.add_column("Confidence", justify="center")
    t.add_column("Evidence", overflow="fold", style="dim")
    for f in custom:
        ev = ", ".join(f"{e.field}:{e.sample[:30]}" for e in f["evidence"][:3])
        t.add_row(escape(f["vendor"]), " ".join(f["roles"]),
                  progress_bar_text(f.get("pct", 25), 16), escape(ev))
    console.print(center(t))


def _db_footer() -> None:
    """Centered dim footer: signature DB size + engine info."""
    n_vendors = len({s.vendor for s in SIGNATURES})
    n_sigs = len(SIGNATURES)
    n_patterns = sum(len(s.matches) for s in SIGNATURES)
    from collections import Counter
    by_role = Counter()
    for v in {s.vendor for s in SIGNATURES}:
        roles = {s.role.split("/")[0] for s in SIGNATURES if s.vendor == v}
        for r in roles:
            by_role[r] += 1
    breakdown = "  ·  ".join(f"{role} {by_role[role]}" for role in
                             ("WAF", "CDN", "LB", "PROXY", "CLOUD", "TECH"))
    console.print()
    console.print(center(Text.from_markup(
        f"[dim]⛰ Megalit v{__version__} · signature DB: "
        f"[bold bright_cyan]{n_vendors}[/] vendors / [bold bright_cyan]{n_sigs}[/] "
        f"signature sets / [bold bright_cyan]{n_patterns}[/] patterns"
        f"  ({breakdown}) · aiohttp async engine[/]")))


# per-category findings tables (user spec): WAF / CDN / LB / PROXY / CLOUD / TECH
ROLE_META = {
    "WAF": ("🛡", "bright_red", "WAF / firewall"),
    "CDN": ("🌀", "bright_cyan", "CDN"),
    "LB": ("🔀", "bright_magenta", "Load Balancer"),
    "PROXY": ("🕵", "bright_blue", "Proxy"),
    "CLOUD": ("🌥", "bright_yellow", "Cloud platform"),
    "TECH": ("⚙", "bright_green", "Server tech"),
}


def _findings_tables(findings) -> None:
    """One separated table per protection category — WAF, CDN, LB, … each alone.
    A vendor with combined roles (e.g. WAF/CDN) appears in every matching table."""
    max_score = max((f["score"] for f in findings), default=1) or 1
    printed = False
    for role, (icon, color, label) in ROLE_META.items():
        group = [f for f in findings if _has_role(f, role)]
        if not group:
            continue
        printed = True
        t = _mk_table(f"{icon} {label} — {len(group)} vendor(s)", color, heavy=True)
        t.add_column("#", justify="right")
        t.add_column("Vendor", style="bold white")
        t.add_column("Role", justify="center")
        t.add_column("Confidence", justify="center")
        t.add_column("Score", justify="right")
        t.add_column("Evidence (top hits)", overflow="fold")
        t.add_column("Src", justify="center")
        for i, f in enumerate(group, 1):
            rank_style = {1: "bold bright_yellow", 2: "bold bright_white"}.get(i, "dim")
            role_cells = " ".join(
                f"[{style_role(r)}]{escape(r)}[/]" for r in f["roles"])
            ev = ", ".join(
                f"[dim]{escape(e.field)}:[/]{escape(e.sample[:34])}"
                for e in f["evidence"][:3])
            more = (f" [dim]+{len(f['evidence']) - 3} more[/]"
                    if len(f["evidence"]) > 3 else "")
            # two-line certainty cell: level meter over the fireeye % bar
            cert = Text.from_markup(
                conf_bar(f["confidence"]) + "\n" + progress_bar_text(f.get("pct", 25), 10))
            t.add_row(f"[{rank_style}]{i}[/]",
                      (f"[bright_yellow]★[/] " if f.get("user") else "")
                      + (f"[dim]◦[/] " if not f.get("has_curated", True) else "")
                      + escape(f["vendor"]),
                      role_cells, cert,
                      f"[bold bright_cyan]{f['score']}[/] {score_bar(f['score'], max_score)}",
                      ev + more,
                      "[bright_yellow]U[/]" if f.get("user") else "[dim]db[/]")
        console.print(center(t))
        console.print()  # blank line between category tables
    if printed:
        legend = "  ".join(f"[{style_role(r)}]● {escape(r)}[/]" for r in
                           ["WAF", "WAF/CDN", "CDN", "LB", "CLOUD", "PROXY", "TECH"])
        console.print(center(Text.from_markup(
            f"[dim]Legend:[/dim] {legend}  [dim]│[/dim]  "
            f"[dim]★ U = user list · ◦ = loose-token hint only (not a confirmed verdict)[/dim]")))


def _has_role(f, role: str) -> bool:
    """WAF/CDN-style combined roles count for every token inside them."""
    return any(role == r or role in r.split("/") for r in f["roles"])


def _stack_panel(findings) -> None:
    """🧱 protection stack — one row per layer with the strongest vendor."""
    max_score = max((f["score"] for f in findings), default=1) or 1
    grid = Table.grid(padding=(0, 2), pad_edge=False)
    grid.add_column(justify="left", no_wrap=True)   # layer chip
    grid.add_column(justify="left", no_wrap=True)   # vendor
    grid.add_column(justify="left", no_wrap=True)   # meter
    grid.add_column(justify="right", no_wrap=True)  # score
    shown_any = False
    for role, icon, color in LAYER_ICONS:
        best = next((f for f in findings if _has_role(f, role)), None)
        chip = Text()
        chip.append(f"{icon} ", style=color)
        chip.append(f"{role:<5}", style=f"bold {color}")
        if best:
            shown_any = True
            grid.add_row(chip,
                         Text.from_markup(f"[bold white]{escape(best['vendor'])}[/]"),
                         Text.from_markup(score_bar(best["score"], max_score)),
                         Text.from_markup(f"[bold bright_cyan]{best['score']}[/]"))
        else:
            grid.add_row(chip, Text.from_markup("[dim]—[/]"), Text(""), Text(""))
    if shown_any:
        console.print(center(Panel(
            grid, title="[bold]🧱 protection stack[/]", border_style="bright_magenta",
            box=box.ROUNDED, padding=(0, 2))))


def _layers_panel(result: Dict) -> None:
    """◈ layer map — distinct serving layers seen across all responses.
    Highlights round-robin / multi-layer targets (origin WAF + edge proxy),
    which a single-connection scanner never notices."""
    layers = result.get("layers") or []
    if not layers:
        return
    multi = len(layers) > 1
    t = _mk_table(
        f"◈ layer map — {len(layers)} distinct serving layer(s)"
        + ("  [bright_yellow](multi-layer target — evidence fused across all)[/]"
           if multi else ""), "bright_cyan")
    t.add_column("Server", style="bold white", overflow="fold")
    t.add_column("Resp", justify="right")
    t.add_column("Statuses", style="dim", overflow="fold")
    for layer in layers[:4]:
        sts = ", ".join(f"HTTP {s}×{n}" for s, n in sorted(layer["statuses"].items()))
        t.add_row(escape(layer["server"]), str(layer["n"]), escape(sts))
    console.print(center(Panel(t, border_style="bright_cyan",
                               box=box.ROUNDED, padding=(0, 2))))


def _heuristics_panels(result: Dict) -> None:
    """Anti-bot intel, cache chain and rate-limit signals — centered panels."""
    anti_bot = result.get("anti_bot") or []
    cache_chain = result.get("cache_chain") or []
    rate_limit = result.get("rate_limit") or {}
    if not (anti_bot or cache_chain or rate_limit.get("present")):
        return
    section("Heuristic Intelligence", icon="🧠", style="bright_green")
    if anti_bot:
        t = _mk_table("🤖 anti-bot & challenge layer", "bright_green")
        t.add_column("Mechanism", style="bold white")
        t.add_column("Evidence", overflow="fold", style="dim")
        t.add_column("Seen at", overflow="fold", style="dim italic")
        for a in anti_bot:
            t.add_row(f"[bold bright_green]{escape(a['label'])}[/]",
                      escape(a["evidence"]), escape(a["where"]))
        console.print(center(t))
    if cache_chain:
        chips = Text(justify="center")
        for i, c in enumerate(cache_chain):
            if i:
                chips.append("  ⭢  ", style="bright_black")
            chips.append(f"{c['layer']}", style="bold bright_cyan")
            if c.get("value") and c["layer"] not in ("Cache (Age header)",):
                chips.append(f" [{escape(c['value'][:26])}]", style="dim")
        console.print(center(Text.from_markup("[dim]cache chain ⭢[/]")))
        console.print(center(chips))
    if rate_limit.get("present"):
        rows = [(h, escape(v)) for h, v in list(rate_limit["headers"].items())[:6]]
        kv_panel("⏱ rate-limit signals", rows, border="bright_yellow",
                 key_style="bold bright_yellow")


def _sec_grade(n: int, total: int):
    """Security-headers coverage grade → (grade, color)."""
    if total <= 0:
        return "—", "dim"
    if n == total:
        return "A+", "bold bright_green"
    if n >= total - 1:
        return "A", "bright_green"
    if n >= 5:
        return "B", "bright_yellow"
    if n >= 3:
        return "C", "bright_yellow"
    if n >= 1:
        return "D", "bright_red"
    return "F", "bold bright_red"


def _verdict_panel(result: Dict) -> None:
    """Big centered verdict panel."""
    v = result["verdict"]
    lines = Text(justify="center")
    border = "bright_green"
    if v["waf"]:
        border = "bright_red"
        lines.append("  WAF DETECTED  ", style="bold bright_white on red")
        lines.append("\n\n")
        lines.append(v["waf"], style="bold bright_red")
        if v.get("waf_score"):
            lines.append(f"   ·   score {v['waf_score']}", style="bold bright_white")
        if v.get("waf_conf"):
            lines.append(Text.from_markup(f"\n{conf_bar(v['waf_conf'])}"))
        lines.append("\n\n")
    else:
        border = "bright_green"
        lines.append("  NO WAF DETECTED  ", style="bold black on bright_green")
        lines.append("\n\n")
        lines.append("origin server may be directly exposed\n", style="dim italic")
        if not (v["cdn"] or v["lb"]):
            lines.append("\n")
    if v["cdn"]:
        lines.append("🌀 CDN ", style="bold bright_cyan")
        lines.append("▸ ", style="bright_black")
        lines.append(", ".join(v["cdn"]) + "\n", style="bold white")
    if v["lb"]:
        lines.append("🔀 LB  ", style="bold bright_magenta")
        lines.append("▸ ", style="bright_black")
        lines.append(", ".join(v["lb"]) + "\n", style="bold white")
    if not v["cdn"] and not v["lb"]:
        lines.append(Text.from_markup("[dim]no CDN / LB identified[/dim]\n"))
    lines.append("\n")
    lines.append(v["summary"], style="italic dim")
    # traffic flow + exposure score
    flow = result.get("flow") or ""
    exposure = result.get("exposure") or {}
    extra = Text(justify="center")
    if flow:
        extra.append("\n\n")
        extra.append("🧭 ", style="bold bright_magenta")
        extra.append(flow, style="bold bright_white")
    if exposure.get("grade"):
        advice = exposure.get("advice") or []
        extra.append("\n\n")
        extra.append("🛡 protection score ", style="dim bright_white")
        extra.append(f"{exposure['score']}/100", style="bold bright_cyan")
        extra.append("   grade ", style="dim bright_white")
        extra.append(str(exposure["grade"]), style="bold bright_yellow")
        if advice:
            extra.append("\n")
            for i, a in enumerate(advice[:4]):
                if i:
                    extra.append("\n")
                extra.append("  ⚠ ", style="bright_yellow")
                extra.append(a, style="dim italic")
    if extra.plain:
        lines.append(extra)
    title = Text(" ◈ VERDICT ", style="bold bright_white")
    panel = Panel(center(lines), title=title, title_align="center",
                  border_style=border, box=box.DOUBLE, padding=(1, 4))
    console.print()
    console.print(center(panel))


def _raw_headers_panel(raw: str):
    """curl -I style panel with colored header names/values."""
    body = Text()
    lines = (raw or "(no headers)").replace("\r\n", "\n").split("\n")
    for i, ln in enumerate(lines):
        if i:
            body.append("\n")
        if i == 0:
            body.append(ln, style="bold bright_green")
        elif ":" in ln:
            k, _, v = ln.partition(":")
            body.append(k + ":", style="bold bright_cyan")
            body.append(v, style="white")
        else:
            body.append(ln, style="white")
    return Panel(body, box=box.SQUARE, border_style="blue", padding=(0, 1),
                 title=Text(" raw headers ", style="dim"), title_align="right")


def _scheme_text(result: Dict) -> str:
    s = result["scheme"]
    https = "[bright_green]HTTPS ✔[/]" if s["https_ok"] else "[bright_red]HTTPS ✗[/]"
    http = "[bright_green]HTTP ✔[/]" if s["http_ok"] else "[bright_red]HTTP ✗[/]"
    arrow = "   [bright_yellow]⇄ HTTP→HTTPS redirect[/]" if s["http_redirects_to_https"] else ""
    return Text.from_markup(f"{https}   {http}{arrow}")


def to_json_dict(result: Dict) -> Dict:
    """JSON-safe report dict."""
    out = dict(result)
    out.pop("show_headers_raw", None)
    out["findings"] = [
        {**f, "evidence": [asdict(e) for e in f["evidence"]],
         "roles": list(f["roles"])}
        for f in result["findings"]
    ]
    out["probes"] = [asdict(p) for p in result.get("probes", [])]
    out["generated"] = datetime.datetime.now().isoformat(timespec="seconds")
    out["tool"] = "Megalit"
    out["version"] = __version__
    return out


def save_markdown(result: Dict, path: str) -> str:
    """Write a markdown report. Returns the path."""
    dns = result["dns"]
    cert = dns.get("cert") or {}
    st = result["stats"]
    v = result["verdict"]
    L = []
    L.append(f"# Megalit Report — {result['target']}")
    L.append("")
    L.append(f"> Generated by **Megalit v{__version__}** on "
             f"{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    L.append("")
    L.append("## Target")
    L.append("")
    L.append("| Field | Value |")
    L.append("|---|---|")
    L.append(f"| Target | `{result['target']}` |")
    L.append(f"| Primary URL | `{result['primary_url']}` |")
    L.append(f"| Final URL | `{result['final_url']}` |")
    L.append(f"| Scheme | {result['scheme']['note']} |")
    L.append(f"| IPv4 | {', '.join(dns.get('ips') or []) or '—'} |")
    if dns.get("cname"):
        L.append(f"| CNAME | `{dns['cname']}` |")
    if dns.get("ns"):
        L.append(f"| NS | {', '.join(dns['ns'])} |")
    if dns.get("ptrs"):
        L.append(f"| PTR | {', '.join(dns['ptrs'])} |")
    if cert.get("issuer"):
        L.append(f"| TLS Issuer | {cert['issuer']} |")
    if cert.get("valid_to"):
        L.append(f"| TLS Expires | {cert['valid_to']} |")
    if cert.get("version"):
        tls_parts = [cert["version"]]
        if cert.get("cipher"):
            tls_parts.append(cert["cipher"])
        if cert.get("alpn"):
            tls_parts.append(f"ALPN={cert['alpn']}")
        L.append(f"| TLS | {' · '.join(tls_parts)} |")
    if cert.get("h2"):
        L.append("| HTTP/2 | negotiated (h2) |")
    for k, val in result.get("server_tech", {}).items():
        L.append(f"| {k} | {val} |")
    L.append("")
    L.append("## Detection Results")
    L.append("")
    if result["findings"]:
        L.append("| # | Vendor | Role | Confidence | Score | Evidence |")
        L.append("|---|---|---|---|---|---|")
        for i, f in enumerate(result["findings"], 1):
            ev = "; ".join(f"{e.field}: `{e.sample}`" for e in f["evidence"][:5])
            star = "★ " if f.get("user") else ""
            L.append(f"| {i} | {star}{f['vendor']} | {', '.join(f['roles'])} "
                     f"| {f['confidence']} | {f['score']} | {ev} |")
    else:
        L.append("_No WAF / CDN / LB signature matched._")
    L.append("")
    L.append("## Verdict")
    L.append("")
    L.append(f"- **WAF:** {v['waf'] or '—'}"
             + (f" ({v['waf_conf']})" if v["waf"] else ""))
    L.append(f"- **CDN:** {', '.join(v['cdn']) or '—'}")
    L.append(f"- **Load Balancer:** {', '.join(v['lb']) or '—'}")
    L.append("")
    L.append(f"{v['summary']}")
    L.append("")
    d = result.get("ddos_impact") or {}
    if d:
        L.append(f"**DDoS impact chance:** {d.get('chance', 0)}% "
                 f"(level: {d.get('level', 'Low')})")
        L.append("")
    if result.get("flow"):
        L.append(f"**Traffic flow:** `{result['flow']}`")
        L.append("")
    exp = result.get("exposure") or {}
    if exp.get("grade"):
        L.append(f"**Protection score:** {exp['score']}/100 (grade {exp['grade']})")
        L.append("")
        for a in exp.get("advice") or []:
            L.append(f"- ⚠ {a}")
        L.append("")
    ab = result.get("anti_bot") or []
    if ab:
        L.append("## Anti-Bot / Challenge Layer")
        L.append("")
        L.append("| Mechanism | Evidence | Seen at |")
        L.append("|---|---|---|")
        for a in ab:
            L.append(f"| {a['label']} | `{a['evidence']}` | {a['where']} |")
        L.append("")
    cc = result.get("cache_chain") or []
    if cc:
        L.append("## Cache Chain")
        L.append("")
        L.append(" → ".join(f"{c['layer']} ({c['header']})" for c in cc))
        L.append("")
    rl = result.get("rate_limit") or {}
    if rl.get("present"):
        L.append("## Rate-Limit Signals")
        L.append("")
        for h, val in rl["headers"].items():
            L.append(f"- `{h}: {val}`")
        L.append("")
    if result["chain"]:
        L.append("## Redirect Chain")
        L.append("")
        L.append("```")
        for c in result["chain"]:
            if c["error"]:
                L.append(f"{c['url']}  ✘ {c['error']}")
            else:
                L.append(f"{c['url']}  → HTTP {c['status']} "
                         + (f"→ {c['location']}" if c["location"] else ""))
        L.append("```")
        L.append("")
    if result["probes"]:
        L.append("## Active Probes")
        L.append("")
        L.append("| Probe | Kind | Status | Result | Attributed | Note |")
        L.append("|---|---|---|---|---|---|")
        for p in result["probes"]:
            res = "⛔ BLOCKED" if p.blocked else ("– error" if p.error else "✔ PASSED")
            L.append(f"| {p.name} | {p.kind} | {p.status or 'ERR'} | {res} "
                     f"| {', '.join(p.matched) or '—'} | {p.note} |")
        L.append("")
    if result.get("layers"):
        L.append("## Layer Map")
        L.append("")
        L.append("| Server | Responses | Statuses |")
        L.append("|---|---|---|")
        for layer in result["layers"]:
            sts = ", ".join(f"HTTP {s} ×{n}" for s, n in sorted(layer["statuses"].items()))
            L.append(f"| {layer['server']} | {layer['n']} | {sts} |")
        L.append("")
    sec = result["sec_headers"]
    L.append("## Security Headers")
    L.append("")
    L.append("| Header | Status |")
    L.append("|---|---|")
    for label, val in sec["present"].items():
        L.append(f"| {label} | ✔ set |")
    for label in sec["missing"]:
        L.append(f"| {label} | ✗ missing |")
    L.append("")
    if result.get("header_search"):
        L.append(f"## Header Search — `{result.get('header_search_pattern', '')}`")
        L.append("")
        L.append("| Field | Match | Context | Where |")
        L.append("|---|---|---|---|")
        for h in result["header_search"]:
            L.append(f"| {h['field']} | `{h['match']}` | `{h['context']}` | {h['where']} |")
        L.append("")
    L.append("## Stats")
    L.append("")
    L.append(f"- Requests: {st['requests']}")
    L.append(f"- Elapsed: {st['elapsed']}s")
    L.append(f"- UAs used: {st['uas_used']}")
    L.append(f"- Proxies used: {st['proxies_used']}")
    L.append("")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(L))
    return path


def print_json(result: Dict) -> None:
    console.print_json(json.dumps(to_json_dict(result)))
