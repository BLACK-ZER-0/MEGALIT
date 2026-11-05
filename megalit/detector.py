
import asyncio
import re
import time
import urllib.parse
from typing import Dict, List, Optional

from . import dnsinfo, heuristics
from .httpclient import FetchResult, HTTPClient
from .logman import get_logger
from .prober import run_probes
from .signatures import (aggregate, match_contexts, match_dns, ctx_from_response)
from .ui import console

MAX_HOPS = 8
SEC_HEADERS = [
    ("strict-transport-security", "HSTS"),
    ("content-security-policy", "CSP"),
    ("x-frame-options", "X-Frame-Options"),
    ("x-content-type-options", "X-Content-Type-Options"),
    ("referrer-policy", "Referrer-Policy"),
    ("permissions-policy", "Permissions-Policy"),
    ("x-xss-protection", "X-XSS-Protection"),
    ("cross-origin-opener-policy", "COOP"),
]
SCHEME_OF = {"https": "http", "http": "https"}


def _plan_schemes(target: str) -> Dict:
    """Decide candidate URLs respecting explicit scheme; bare → https then http."""
    t = target.strip().rstrip("/")
    m = re.match(r"^(https?)://(.+)$", t, re.I)
    if m:
        sch = m.group(1).lower()
        rest = m.group(2)
        return {
            "candidates": [f"{sch}://{rest}"],
            "other": f"{SCHEME_OF[sch]}://{rest}",
            "explicit": sch,
            "rest": rest,
        }
    return {
        "candidates": [f"https://{t}", f"http://{t}"],
        "other": "",
        "explicit": None,
        "rest": t,
    }


async def run(args, client: HTTPClient, extra_sigs: List, strong_vendors: set) -> Dict:
    log = get_logger("DETECT")
    t_start = time.perf_counter()
    stats = {"requests": 0}
    responses: List[FetchResult] = []

    # quiet = pure stdout-JSON mode only (bare --json); --json FILE keeps phases
    quiet = getattr(args, "json", False) is True

    def phase(text: str):
        """Phase milestone — a plain one-line INFO log (no spinner animation)."""
        if not quiet:
            log.info(text.rstrip("…").rstrip())
        return _null_ctx()

    plan = _plan_schemes(args.target)
    log.verbose("plan ▸ candidates=%s │ alt=%s │ explicit=%s",
             plan["candidates"], plan["other"] or "-", plan["explicit"] or "auto")

    # ── 1. primary scheme resolution ──────────────────────────────────────
    with phase("Resolving target & probing schemes…"):
        primary_resp: Optional[FetchResult] = None
        primary_url = ""
        for cand in plan["candidates"]:
            s, px = client.pick()
            r = await client.fetch(cand, session=s, proxy=px)
            stats["requests"] += 1
            responses.append(r)
            if not r.error:
                primary_resp, primary_url = r, cand
                break
            log.info("Candidate %s failed (%s) — trying next", cand, r.error)
        if primary_resp is None:
            detail = responses[0].error if responses else "no response"
            log.error("Target unreachable: %s", detail)
            return {"fatal": True, "target": args.target, "error": detail}

        primary_scheme = urllib.parse.urlsplit(primary_url).scheme
        rest = plan["rest"]
        other_url = plan["other"] or f"{SCHEME_OF[primary_scheme]}://{rest}"

        # alt-scheme check (http↔https insight; crucial for http-only sites)
        s, px = client.pick()
        alt_resp = await client.fetch(other_url, session=s, proxy=px)
        stats["requests"] += 1
        responses.append(alt_resp)
        log.verbose("alt-scheme ▸ %s → %s", other_url, alt_resp.status or alt_resp.error)

    # ── 2. redirect chain ─────────────────────────────────────────────────
    with phase("Following redirect chain…"):
        chain = [primary_resp]
        cur = primary_resp
        for _ in range(MAX_HOPS):
            if cur.error or not (300 <= cur.status < 400):
                break
            loc = cur.get_header("location")
            if not loc:
                break
            nxt = urllib.parse.urljoin(cur.final_url or cur.url, loc)
            s, px = client.pick()
            r = await client.fetch(nxt, session=s, proxy=px)
            stats["requests"] += 1
            r.hop_from = cur.final_url or cur.url
            responses.append(r)
            chain.append(r)
            cur = r
            log.verbose("Hop → %s (HTTP %s)", nxt, r.status)
        final_resp = chain[-1]
        final_url = final_resp.final_url or final_resp.url
        hops = len(chain) - 1
        log.info("final URL ▸ %s (HTTP %s, %d hop(s))",
                 final_url, final_resp.status or final_resp.error or "?", hops)

    # ── 3. baseline repeats ───────────────────────────────────────────────
    n_extra = max(0, int(getattr(args, "request", 2)))
    if n_extra:
        with phase(f"Baseline fingerprinting ({n_extra} request(s))…"):
            for _ in range(n_extra):
                s, px = client.pick()
                r = await client.fetch(final_url, session=s, proxy=px)
                stats["requests"] += 1
                responses.append(r)

    hostname = urllib.parse.urlsplit(final_url).hostname or \
        urllib.parse.urlsplit(primary_url).hostname or ""

    # ── 4. DNS + TLS ──────────────────────────────────────────────────────
    with phase("Gathering DNS & TLS intelligence…"):
        dns = await dnsinfo.gather_dns(hostname)
        log.verbose("DNS: ips=%s cname=%s ns=%s ranges=%d cert=%s",
                 dns["ips"], dns["cname"], dns["ns"], len(dns["ranges"]),
                 bool(dns["cert"]))

    # ── 5. passive fingerprinting ─────────────────────────────────────────
    with phase("Passive fingerprinting (headers / cookies / body / DNS / TLS)…"):
        ctxs = [ctx_from_response(r) for r in responses if not r.error]
        log.verbose("Matching %d signature set(s) against %d response context(s)",
                 1, len(ctxs))
        evidences = match_contexts(ctxs, extra_sigs)
        evidences.extend(match_dns(dns, extra_sigs))
        log.info("Passive evidence: %d hit(s)", len(evidences))

    preliminary = aggregate(evidences, strong_vendors,
                            user_vendors={s.vendor for s in extra_sigs})
    waf_best = next((f for f in preliminary
                     if "WAF" in " ".join(f["roles"]) and f["confidence"] != "LOW"
                     and f.get("has_curated")), None)

    # ── 5b. heuristics — anti-bot, cache chain, rate-limit (no extra requests)
    with phase("Heuristic analysis (anti-bot / cache chain / rate-limit)…"):
        anti_bot = heuristics.detect_anti_bot(responses)
        cache_chain = heuristics.detect_cache_chain(responses)
        rate_limit = heuristics.detect_rate_limit(responses)
        log.verbose("Heuristics: anti-bot=%d cache-layers=%d rate-limit=%s",
                 len(anti_bot), len(cache_chain), rate_limit["present"])

    # ── 6. active probes ──────────────────────────────────────────────────
    probes, skipped = [], ""
    if waf_best and not getattr(args, "findall", False):
        skipped = (f"skipped — HIGH-confidence WAF '{waf_best['vendor']}' found passively "
                   f"(use -a/--findall to force all probes)")
        log.info("Active probes %s", skipped)
    else:
        with phase("Active probing (attack vectors)…"):
            baseline_status = final_resp.status if not final_resp.error else 0
            probes, pev = await run_probes(
                client, final_url, baseline_status,
                getattr(args, "findall", False), extra_sigs)
            stats["requests"] += len(probes)
            evidences.extend(pev)

    # ── 7. aggregate + verdict ────────────────────────────────────────────
    findings = aggregate(evidences, strong_vendors,
                         user_vendors={s.vendor for s in extra_sigs})
    # wafw00f-grade verdicts: only vendors with curated/definitive evidence
    # qualify — loose fireeye-token hints stay in the findings table but can
    # never be named as THE waf/cdn/lb of a target
    waf_f = next((f for f in findings
                  if "WAF" in " ".join(f["roles"]) and f["confidence"] != "LOW"
                  and f.get("has_curated")), None)
    cdn_list = [f["vendor"] for f in findings if "CDN" in " ".join(f["roles"])
                and f["confidence"] != "LOW" and f.get("has_curated")]
    lb_list = [f["vendor"] for f in findings if "LB" in " ".join(f["roles"])
               and f["confidence"] != "LOW" and f.get("has_curated")]

    if waf_f:
        summary = (f"Traffic to {args.target} appears shielded by {waf_f['vendor']} "
                   f"with {waf_f['confidence']} confidence (score {waf_f['score']}).")
    elif any(f["confidence"] == "LOW" for f in findings):
        summary = ("Only weak hints found — no protection layer confirmed. "
                   "Re-run with -a --verbose for deeper probing.")
    else:
        summary = (f"No protection layer confidently identified — "
                   f"{args.target} may be exposed directly to the origin.")

    # ── scheme insight (the HTTP fix report) ──────────────────────────────
    https_ok = any(not r.error and urllib.parse.urlsplit(r.final_url or r.url).scheme == "https"
                   for r in responses)
    http_ok = any(not r.error and urllib.parse.urlsplit(r.final_url or r.url).scheme == "http"
                  for r in responses)
    redirects_to_https = any(
        not r.error and r.get_header("location", ).lower().startswith("https://")
        for r in responses
        if urllib.parse.urlsplit(r.final_url or r.url).scheme == "http")
    if plan["explicit"] == "http" and not https_ok:
        scheme_note = "Explicit HTTP target — HTTPS not reachable"
    elif http_ok and redirects_to_https:
        scheme_note = "HTTP redirects to HTTPS"
    elif http_ok and https_ok:
        scheme_note = "Both HTTP and HTTPS reachable (detection ran on both)"
    elif http_ok:
        scheme_note = "HTTP-only host — detected over plain HTTP ✔"
    else:
        scheme_note = "HTTPS-only host"

    # ── security headers audit ────────────────────────────────────────────
    present, missing = {}, []
    for h, label in SEC_HEADERS:
        val = final_resp.get_header(h)
        if val:
            present[label] = val[:80]
        else:
            missing.append(label)

    server_tech = {
        "Server": final_resp.get_header("server"),
        "X-Powered-By": final_resp.get_header("x-powered-by"),
        "Via": final_resp.get_header("via"),
        "X-Generator": final_resp.get_header("x-generator"),
    }
    server_tech = {k: v for k, v in server_tech.items() if v}

    # ── exposure score + traffic flow ──────────────────────────────────────────────
    exposure = heuristics.exposure_score(
        {"present": present, "missing": missing}, dns.get("cert") or {},
        waf_f["vendor"] if waf_f else "", cdn_list, lb_list,
        anti_bot, rate_limit)
    flow = heuristics.traffic_flow(findings, server_tech)
    ddos = heuristics.ddos_impact(
        findings, final_resp.headers,
        extra_vendors=sorted(strong_vendors) if strong_vendors else None)

    stats["elapsed"] = round(time.perf_counter() - t_start, 2)
    stats["uas_used"] = len({r.ua for r in responses if r.ua})
    stats["proxies_used"] = len({r.proxy for r in responses if r.proxy})
    stats["failed"] = sum(1 for r in responses if r.error)

    header_search_hits = []
    if getattr(args, "header_search", None):
        header_search_hits = _header_search(args.header_search, responses)
    header_search_pattern = getattr(args, "header_search", "") or ""

    # ── layer map — cluster responses by Server header ────────────────────────────
    # Multi-layer / round-robin targets (origin + edge) reveal every distinct
    # layer here; wafw00f has no equivalent.
    _buckets: Dict[str, Dict] = {}
    for _r in responses:
        if _r.error:
            continue
        _srv = _r.get_header("server") or "(no server header)"
        _b = _buckets.setdefault(_srv, {"server": _srv, "n": 0, "statuses": {}})
        _b["n"] += 1
        _st = str(_r.status or "?")
        _b["statuses"][_st] = _b["statuses"].get(_st, 0) + 1
    layers = sorted(_buckets.values(), key=lambda x: -x["n"])

    log.info("Done: %d finding(s), %d probe(s), %d request(s) in %.2fs",
             len(findings), len(probes), stats["requests"], stats["elapsed"])

    return {
        "target": args.target,
        "primary_url": primary_url,
        "final_url": final_url,
        "hostname": hostname,
        "scheme": {
            "https_ok": https_ok, "http_ok": http_ok,
            "http_redirects_to_https": bool(redirects_to_https),
            "note": scheme_note,
        },
        "chain": [
            {"url": r.url, "final_url": r.final_url, "status": r.status,
             "location": r.get_header("location"), "error": r.error}
            for r in chain
        ],
        "dns": dns,
        "findings": findings,
        "probes": probes,
        "skipped_probes": skipped,
        "sec_headers": {"present": present, "missing": missing},
        "server_tech": server_tech,
        "anti_bot": anti_bot,
        "cache_chain": cache_chain,
        "rate_limit": rate_limit,
        "layers": layers,
        "exposure": exposure,
        "flow": flow,
        "ddos_impact": ddos,
        "header_search": header_search_hits,
        "header_search_pattern": header_search_pattern,
        "show_headers_raw": final_resp.raw_headers,
        "stats": stats,
        "verdict": {"waf": waf_f["vendor"] if waf_f else None,
                    "waf_conf": waf_f["confidence"] if waf_f else None,
                    "waf_score": waf_f["score"] if waf_f else 0,
                    "cdn": cdn_list, "lb": lb_list, "summary": summary},
    }


def _header_search(pattern: str, responses: List[FetchResult]) -> List[Dict]:
    """Regex search over raw headers, cookies and bodies of every response."""
    log = get_logger("DETECT")
    try:
        rx = re.compile(pattern, re.I)
    except re.error as e:
        raise ValueError(f"invalid --header-search regex: {e}")
    hits: List[Dict] = []
    for r in responses:
        if r.error:
            continue
        for h, v in r.header_pairs:
            for m in rx.finditer(f"{h}: {v}"):
                hits.append({"field": "header", "where": r.final_url or r.url,
                             "match": m.group(0)[:80],
                             "context": _snip(f"{h}: {v}", m.start(), m.end())})
        for cn, cv in r.cookies.items():
            for m in rx.finditer(f"{cn}={cv}"):
                hits.append({"field": "cookie", "where": r.final_url or r.url,
                             "match": m.group(0)[:80],
                             "context": _snip(f"{cn}={cv}", m.start(), m.end())})
        for m in rx.finditer(r.body or ""):
            hits.append({"field": "body", "where": r.final_url or r.url,
                         "match": m.group(0)[:80],
                         "context": _snip(r.body, m.start(), m.end())})
    log.info("Header search '%s' → %d hit(s)", pattern, len(hits))
    return hits[:60]


def _snip(text: str, start: int, end: int, pad: int = 34) -> str:
    a = max(0, start - pad)
    b = min(len(text), end + pad)
    out = text[a:b].replace("\n", " ").replace("\r", " ")
    return ("…" if a > 0 else "") + out + ("…" if b < len(text) else "")


class _null_ctx:
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False
