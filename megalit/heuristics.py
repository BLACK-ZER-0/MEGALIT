"""
Megalit heuristics engine — behavioural & structural analysis that goes beyond
static signature matching.  ZERO extra requests: everything is computed from
responses already collected by the detector.
"""
import re
from typing import Dict, List

from .logman import get_logger

# ── anti-bot / challenge markers (label, regex over body/headers) ────────────
ANTIBOT_MARKERS = [
    ("Cloudflare Challenge", r"challenge-platform|__cf_chl|cdn-cgi/challenge-platform|just a moment"),
    ("Cloudflare Turnstile", r"challenges\.cloudflare\.com/turnstile|cf-turnstile"),
    ("DataDome Captcha", r"captcha-delivery\.com|datadome.{0,40}captcha"),
    ("PerimeterX / HUMAN", r"px-captcha|px-cloud\.net"),
    ("AWS WAF Captcha", r"awswaf.{0,30}captcha|captcha\.awswaf"),
    ("hCaptcha", r"hcaptcha\.com|hcaptcha-challenge"),
    ("Google reCAPTCHA", r"recaptcha/api|grecaptcha|google\.com/recaptcha"),
    ("GeeTest", r"geetest"),
    ("Kasada", r"kpsdk"),
    ("Queue-it Waiting Room", r"queue-it\.net|queue-it\.io"),
]

# ── cache-layer header map (header_name → layer label) ───────────────────────
CACHE_HEADERS = {
    "cf-cache-status": "Cloudflare cache",
    "cf-ray": "Cloudflare edge",
    "x-amz-cf-pop": "CloudFront edge",
    "x-amz-cf-id": "CloudFront",
    "x-served-by": "Fastly (x-served-by)",
    "x-fastly-request-id": "Fastly",
    "fastly-io-info": "Fastly IO",
    "x-varnish": "Varnish",
    "x-drupal-cache": "Drupal cache",
    "x-hw": "StackPath/Highwinds",
    "x-proxy-cache": "nginx proxy_cache",
    "x-akamai-transformed": "Akamai cache",
    "x-cache": "X-Cache layer",
    "x-cache-lookup": "X-Cache-Lookup layer",
    "x-cdn": "X-CDN cache",
    "age": "Cache (Age header)",
}

RATE_LIMIT_HEADERS = [
    "x-ratelimit-limit", "x-ratelimit-remaining", "x-ratelimit-reset",
    "x-rate-limit-limit", "x-rate-limit-remaining", "x-rate-limit-reset",
    "ratelimit-limit", "ratelimit-remaining", "ratelimit-reset",
    "x-quota-limit", "x-quota-remaining", "x-contentful-ratelimit-*",
]


def detect_anti_bot(responses) -> List[Dict]:
    """Find captcha widgets / JS challenge platforms across all collected bodies."""
    log = get_logger("HEUR")
    found: List[Dict] = []
    seen = set()
    for r in responses:
        if r.error:
            continue
        body = (r.body or "")
        if not body:
            continue
        blob = body
        for h, v in r.header_pairs:
            blob += f"\n{h}: {v}"
        for label, pat in ANTIBOT_MARKERS:
            if label in seen:
                continue
            m = re.search(pat, blob, re.I)
            if m:
                seen.add(label)
                found.append({
                    "label": label,
                    "evidence": m.group(0)[:64],
                    "where": r.final_url or r.url,
                })
                log.verbose("anti-bot marker: %s (%s)", label, m.group(0)[:40])
    return found


def detect_cache_chain(responses) -> List[Dict]:
    """Reconstruct the caching layer chain from cache-related headers."""
    log = get_logger("HEUR")
    chain: List[Dict] = []
    seen = set()
    for r in responses:
        if r.error:
            continue
        for h, v in r.header_pairs:
            hl = h.lower()
            layer = CACHE_HEADERS.get(hl)
            if not layer or layer in seen:
                continue
            seen.add(layer)
            chain.append({"layer": layer, "header": h, "value": v[:60]})
            log.verbose("cache layer: %s (%s: %s)", layer, h, v[:40])
    return chain


def detect_rate_limit(responses) -> Dict:
    """Collect rate-limit / quota / retry-after protection signals."""
    log = get_logger("HEUR")
    hits: Dict[str, str] = {}
    for r in responses:
        if r.error:
            continue
        for h, v in r.header_pairs:
            hl = h.lower()
            matched = any(
                hl == p or (p.endswith("*") and hl.startswith(p[:-1]))
                for p in RATE_LIMIT_HEADERS)
            if matched or hl == "retry-after":
                hits.setdefault(h, v[:60])
    result = {
        "present": bool(hits),
        "headers": hits,
        "note": ("rate-limit headers exposed — anti-bruteforce layer likely in front"
                 if hits else ""),
    }
    if hits:
        log.verbose("rate-limit signals: %s", ", ".join(hits))
    return result


def exposure_score(sec_headers: Dict, tls: Dict, waf: str, cdn: list,
                   lb: list, anti_bot: list, rate_limit: Dict) -> Dict:
    """
    Protection Score 0-100:
      WAF 40 · anti-bot/captcha 10 · CDN 15 · LB 5 ·
      security-headers coverage 0-20 · HSTS 5 · modern TLS 5
    Grade: A+ ≥90 · A ≥75 · B ≥60 · C ≥45 · D ≥30 · F <30
    """
    score = 0
    advice = []
    if waf:
        score += 40
    else:
        advice.append("no WAF identified — attacks reach the origin directly")
    if anti_bot:
        score += 10
    else:
        advice.append("no captcha / challenge layer detected (bot-friendly)")
    if cdn:
        score += 15
    else:
        advice.append("no CDN — no edge shielding or DDoS absorption")
    if lb:
        score += 5
    n = len(sec_headers.get("present", {}))
    total = n + len(sec_headers.get("missing", []))
    if total:
        score += round(n / total * 20)
        if n < total:
            advice.append(f"security headers incomplete ({n}/{total} set)")
    else:
        advice.append("no security-header information collected")
    if tls.get("hsts") or "HSTS" in sec_headers.get("present", {}):
        score += 5
    else:
        advice.append("no HSTS — downgrade attacks possible")
    if (tls.get("version") or "").startswith(("TLSv1.3", "TLSv1.2")):
        score += 5
    if rate_limit.get("present"):
        score += 5
    score = min(100, score)
    grade, gcolor = ("A+", "bold bright_green") if score >= 90 else \
                    ("A", "bright_green") if score >= 75 else \
                    ("B", "bright_yellow") if score >= 60 else \
                    ("C", "bright_yellow") if score >= 45 else \
                    ("D", "bright_red") if score >= 30 else ("F", "bold bright_red")
    return {"score": score, "grade": grade, "advice": advice}


def traffic_flow(findings: List[Dict], server_tech: Dict) -> str:
    """Build the Client → WAF/CDN → LB → Origin traffic-flow line."""
    def _has(f, role):
        return any(role == r or role in r.split("/") for r in f["roles"])

    def _best(role):
        for f in findings:
            if _has(f, role) and f["confidence"] != "LOW":
                return f["vendor"]
        return None

    hops = []
    waf = _best("WAF")
    if waf:
        hops.append(f"{waf} (WAF)")
    cdn = _best("CDN")
    if cdn and cdn != waf:
        hops.append(f"{cdn} (CDN)")
    lb = _best("LB")
    if lb:
        hops.append(f"{lb} (LB)")
    origin = server_tech.get("Server", "")
    if origin:
        origin = re.sub(r"[/ ].*$", "", origin.strip())
        hops.append(f"{origin} (origin)")
    elif hops:
        hops.append("origin")
    if not hops:
        return ""
    return "Client → " + " → ".join(hops)


# ─────────────────────── DDoS impact chance (fireeye port) ───────────────────
#
# Ported from fireeye_v3's compute_ddos_impact(): the more protection layers sit
# in front of the origin (WAF > CDN > DDoS scrubbing > LB > hosting), the lower
# the chance a plain volumetric attack reaches and hurts the origin.  Strong,
# well-known DDoS-absorbing vendors reduce the chance further; security headers
# shave off a few extra points.

STRONG_DDOS_VENDORS = frozenset("""
cloudflare akamai fastly stackpath imperva aws azure google cloud oracle ibm
alibaba tencent baidu huawei ovh hetzner digitalocean linode scaleway upcloud
vultr ionos vercel netlify rackspace kinsta wpengine siteground pantheon
namecheap contabo modsecurity naxsi janusec safe3 safedog safeline webarx
indusface wallarm perimeterx armor zscaler ddos-guard voxility deflect radware
barracuda fortinet fortigate fortiguard fortiweb sophos checkpoint mcafee
symantec bitdefender eset secureworks arbor networks corero trustwave alert
logic armorlogic appwall profense rsfirewall wordfence defiant virusdie sucuri
comodo cwatch aesecure shieldon siteguard variti secupress reblaze greywizard
hyperguard art of defense cloudbric penta security securence arvancloud cdn77
keycdn cachefly limelight edgecast chinacache cdnns maxcdn netdna qiniu qcloud
yxcdn yxlink xuanwudun yundun yunsuo yunjiasu newdefend xlabs pksec wts-waf
shield safeentry phion ergon baffin bay big-ip citrix netscaler kona ghost
appsec shield sitedefender webknight webtotem webseal a10 threatx fireeye
bitninja bekchy blockdos cloudfloor cloudprotect cloudns cachewall websense
incapsula distil dosarrest guardpost link11 nsfocus nexusguard myra nemesida
kemp loadmaster varnish envoy haproxy litespeed caddy traefik palo alto
sonicwall watchguard f5 silverline ddos guards qiniu kona
""".split())

_DDOS_ROLE_DEDUCTION = {
    "DDOS": 25, "WAF": 8, "CDN": 18, "LB": 6, "CLOUD": 4, "PROXY": 5, "TECH": 2,
}


def ddos_impact(findings: List[Dict], headers: Dict, extra_vendors=None) -> Dict:
    """Estimate the chance (0-100%) a DDoS attack reaches the origin.

    fireeye_v3 logic adapted to Megalit findings: base 75, minus points per
    detected layer (WAF/CDN/LB/cloud), minus extra for strong DDoS vendors and
    present security headers.  Level: High > 65 · Medium > 30 · Low."""
    deduction = 0
    strong = STRONG_DDOS_VENDORS
    if extra_vendors:
        merged = {str(v).strip().lower() for v in extra_vendors if str(v).strip()}
        strong = strong | merged

    for f in findings or []:
        roles = f.get("roles") or ["WAF"]
        for role in roles:
            # combined roles like "WAF/CDN" contribute for each component
            for part in str(role).split("/"):
                deduction += _DDOS_ROLE_DEDUCTION.get(part.upper(), 8)
        name = str(f.get("vendor", "")).lower()
        if any(s in name for s in strong):
            deduction += 8

    present = (headers or {}).keys() if hasattr(headers, "keys") else []
    sec_headers = ("strict-transport-security", "content-security-policy",
                   "x-frame-options", "x-xss-protection", "x-content-type-options")
    deduction += sum(3 for sh in sec_headers
                     if any(str(k).lower() == sh for k in present))

    chance = max(0, min(100, int(75 - deduction)))
    level = "High" if chance > 65 else ("Medium" if chance > 30 else "Low")
    return {"chance": chance, "level": level}
