
import asyncio
import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Dict, List, Tuple

from .httpclient import FetchResult
from .logman import get_logger
from .signatures import Evidence, match_contexts, ctx_from_response

BLOCK_STATUSES = {403, 406, 418, 429, 501}
GENERIC_BLOCK = re.compile(
    r"forbidden|access\s+denied|request\s+blocked|blocked|request\s+unsuccessful"
    r"|not\s+acceptable|captcha|challenge|security\s+check|waf|firewall",
    re.I,
)

BOT_UA = "python-requests/2.32.0"
EVIL_UA = "sqlmap/1.8"


@dataclass
class Probe:
    """One active probe definition."""
    name: str
    kind: str          # path | method | ua | burst
    target: str        # path (path/ua) | method name (method) | repeat count (burst)
    ua: str = ""       # only for kind == "ua"
    note_hint: str = ""


PROBES: List[Probe] = [
    Probe("XSS reflection",    "path",  "/?megalit=<svg/onload=alert(1)>"),
    Probe("HTML injection",    "path",  "/?megalit=<script>alert('megalit')</script>"),
    Probe("SQLi tautology",    "path",  "/?id=1%27%20OR%20%271%27%3D%271"),
    Probe("SQLi UNION",        "path",  "/?id=1%20UNION%20SELECT%20NULL,NULL,NULL--"),
    Probe("LFI /etc/passwd",   "path",  "/?file=../../../../etc/passwd"),
    Probe("Path traversal",    "path",  "/.%2e/.%2e/.%2e/etc/passwd"),
    Probe("Raw dot-segment LFI", "rawpath", "/../../etc/passwd"),
    Probe("SQLi SLEEP time-based", "path", "/?id=1%20AND%20SLEEP%285%29%20AND%20%22a%22%3D%22a%22"),
    Probe("Null byte LFI",     "path",  "/?file=../../../../etc/passwd%00"),
    Probe("Double encoding",   "path",  "/?id=1%2527%20OR%20%271%2527%3D%25271"),
    Probe("Log4Shell JNDI",    "path",  "/?q=${jndi:ldap://megalit.probe}"),
    Probe("Command injection", "path",  "/?cmd=;cat%20/etc/passwd"),
    Probe("XXE doctype",       "path",  "/?payload=%3C%3Fxml%20version%3D%221.0%22%3F%3E%3C!DOCTYPE%20r%20%5B%3C!ENTITY%20x%20SYSTEM%20%22file%3A%2F%2F%2Fetc%2Fpasswd%22%3E%5D%3E%3Cr%3E%26x%3B%3C%2Fr%3E"),
    Probe("SSTI injection",    "path",  "/?tpl={{7*7}}$<%= 7*7 %>"),
    Probe("PHP-CGI injection", "path",  "/?-d+allow_url_include%3D1+-d+auto_prepend_file%3Dphp://input"),
    Probe("Sensitive path",    "path",  "/wp-login.php"),
    Probe("WP admin probe",    "path",  "/wp-admin/"),
    Probe("Env file probe",    "path",  "/.env"),
    Probe("Git config probe",  "path",  "/.git/config"),
    Probe("AWS creds probe",   "path",  "/.aws/credentials"),
    Probe("DS_Store probe",    "path",  "/.DS_Store"),
    Probe("phpinfo probe",     "path",  "/phpinfo.php"),
    Probe("xmlrpc probe",      "path",  "/xmlrpc.php"),
    Probe("server-status",     "path",  "/server-status"),
    Probe("Flask console",     "path",  "/console/"),
    Probe("OPTIONS method",    "method", "OPTIONS"),
    Probe("TRACE method",      "method", "TRACE"),
    Probe("Bot UA block test", "ua",    "/", ua=BOT_UA),
    Probe("Evil UA block test", "ua",   "/?megalit=1%27", ua=EVIL_UA),
    Probe("Rate-limit burst",  "burst", "4"),
]


@dataclass
class ProbeResult:
    name: str
    url: str
    status: int
    blocked: bool
    note: str
    matched: List[str] = field(default_factory=list)
    elapsed: float = 0.0
    error: str = ""
    kind: str = "path"


def classify(r: FetchResult, baseline_status: int) -> Tuple[bool, str]:
    """
    Decide whether a probe response looks like an active block.
    Plain 4xx/404 without block evidence is NOT a block — only dedicated
    block statuses or block-keyword bodies count.
    """
    if r.error:
        return False, f"request error: {r.error}"
    if r.status in BLOCK_STATUSES:
        return True, f"HTTP {r.status} on attack vector"
    if GENERIC_BLOCK.search(r.body or ""):
        return True, "block keywords in response body"
    note = f"HTTP {r.status}"
    if baseline_status == 200 and r.status >= 400:
        note += " (vs baseline 200)"
    return False, note + " — no block signature"


def _run_match(r: FetchResult, extra_sigs) -> List[str]:
    evs = match_contexts([ctx_from_response(r)], extra_sigs)
    return sorted({e.vendor for e in evs if "WAF" in e.role})


async def run_probes(client, base_url: str, baseline_status: int,
                     findall: bool, extra_sigs=None) -> Tuple[List[ProbeResult], List[Evidence]]:
    """
    Fire the probe list sequentially (rate-limit friendly).
    Without --findall we stop as soon as active blocking is confirmed AND attributed.
    Returns (probe results, evidence collected from probe responses).
    """
    log = get_logger("PROBE")
    results: List[ProbeResult] = []
    evidences: List[Evidence] = []
    for p in PROBES:
        url = urllib.parse.urljoin(base_url, p.target) if p.kind in ("path", "ua") \
            else base_url
        s, px = client.pick()
        if p.kind == "method":
            r = await client.fetch(url, method=p.target, session=s, proxy=px)
        elif p.kind == "rawpath":
            # keep literal ../ segments — yarl(encoded=True) skips normalization
            from yarl import URL
            r = await client.fetch(URL(base_url.rstrip("/") + p.target, encoded=True),
                                   session=s, proxy=px)
        elif p.kind == "ua":
            r = await client.fetch(url, session=s, proxy=px, ua=p.ua)
        elif p.kind == "burst":
            results.append(await _burst_probe(client, base_url, p, log))
            continue
        else:
            r = await client.fetch(url, session=s, proxy=px)
        blocked, note = classify(r, baseline_status)
        matched: List[str] = []
        if not r.error:
            evs = match_contexts([ctx_from_response(r)], extra_sigs)
            evidences.extend(evs)
            matched = sorted({e.vendor for e in evs if "WAF" in e.role})
        results.append(ProbeResult(p.name, url, r.status, blocked, note, matched,
                                   r.elapsed, r.error, kind=p.kind))
        log.verbose("Probe %-20s → HTTP %s blocked=%s matched=%s",
                 p.name, r.status or "-", blocked, matched or "-")
        if blocked and matched and not findall:
            log.info("Active blocking confirmed by %s — stopping probes "
                     "(use -a/--findall to force all probes)", ", ".join(matched))
            break
    return results, evidences


async def _burst_probe(client, base_url: str, p: Probe, log) -> ProbeResult:
    """N rapid requests — reveal 429 / retry-after rate limiting."""
    try:
        n = max(2, min(6, int(p.target)))
    except ValueError:
        n = 4
    statuses, retry_after = [], ""
    url = base_url
    t0 = asyncio.get_event_loop().time()
    for i in range(n):
        s, px = client.pick()
        r = await client.fetch(url, session=s, proxy=px)
        statuses.append(r.status or 0)
        ra = r.get_header("retry-after")
        if ra:
            retry_after = ra
        await asyncio.sleep(0.05)
    elapsed = asyncio.get_event_loop().time() - t0
    n429 = sum(1 for st in statuses if st == 429)
    n5xx = sum(1 for st in statuses if 500 <= st < 600)
    blocked = n429 > 0
    if n429:
        note = (f"HTTP 429 on {n429}/{n} rapid requests"
                + (f" (retry-after: {retry_after}s)" if retry_after else ""))
    elif n5xx:
        note = f"{n5xx}/{n} requests → 5xx under burst (possible protection)"
    else:
        note = f"{n} rapid requests → no rate limit ({'/'.join(str(s) or '-' for s in statuses)})"
    log.verbose("Burst %dx → %s", n, note)
    return ProbeResult(p.name, url, statuses[-1] or 0, blocked, note,
                       elapsed=round(elapsed, 2), kind="burst")
