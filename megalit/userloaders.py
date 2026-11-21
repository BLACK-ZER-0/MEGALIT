
import json
import os
import re

from .logman import get_logger
from .signatures import Match, Signature

VALID_FIELDS = {
    "header", "header_name", "header_value",
    "cookie", "cookie_name", "cookie_value",
    "body", "status", "cname", "ptr", "ns", "cert",
}
DEFAULT_WEIGHT = 30
_ROLE_ORDER = {"WAF": 0, "CDN": 1, "LB": 2}


def _safe(pattern: str) -> bool:
    """True when the pattern compiles as a case-insensitive regex."""
    try:
        re.compile(pattern, re.I)
        return True
    except re.error:
        return False


def _normalize_role(raw: str) -> str:
    """'CDN/WAF' → 'WAF/CDN', 'waf' → 'WAF', unknown → 'WAF'."""
    parts = [p.strip().upper() for p in str(raw or "WAF").split("/") if p.strip()]
    parts = [p for p in parts if p in ("WAF", "CDN", "LB", "CLOUD", "PROXY", "TECH")]
    if not parts:
        return "WAF"
    return "/".join(sorted(set(parts), key=lambda p: _ROLE_ORDER.get(p, 9)))


def _fireeye_entry_to_sig(e: dict):
    """Convert a fireeye-style entry {name, type, headers, cookies, body, server}
    into a Megalit Signature. Returns None when the entry has no usable name."""
    vendor = (e.get("name") or "").strip()
    if not vendor:
        return None
    role = _normalize_role(e.get("type") or "WAF")
    ms = []
    for h in e.get("headers") or []:
        h = str(h).strip()
        if h and _safe(h):
            ms.append(Match("header", h, 35))
    for c in e.get("cookies") or []:
        c = str(c).strip()
        if c and _safe(c):
            ms.append(Match("cookie", c, 40))
    for b in e.get("body") or []:
        b = str(b).strip()
        if b and _safe(b):
            ms.append(Match("body", b, 45))
    for s in e.get("server") or []:
        s = str(s).strip()
        if s and _safe(s):
            # fireeye matched server tokens against the Server header value AND
            # every header name — replicate with header_value + header_name
            ms.append(Match("header_value", s, 25))
            ms.append(Match("header_name", s, 25))
    return Signature(vendor, role, ms) if ms else None


def load_user_list(path: str):
    """Load user signatures → List[Signature]. Raises ValueError with a friendly msg."""
    log = get_logger()
    if not os.path.isfile(path):
        raise ValueError(f"user list not found: {path}")
    with open(path, "r", encoding="utf-8") as fh:
        raw = fh.read().strip()

    sigs: list = []
    if raw.startswith(("{", "[")):
        data = json.loads(raw)
        if isinstance(data, dict) and "vendors" in data:
            entries = data["vendors"]          # format 1
        elif isinstance(data, list):
            entries = data                     # format 2 / fireeye format 4
        else:
            entries = list(data.items())       # fireeye format 5 (WAF_DB-style dict)
        for e in entries:
            if isinstance(e, tuple):           # WAF_DB-style dict item
                name, body = e
                if not isinstance(body, dict):
                    continue
                e = dict(body)
                e.setdefault("name", name)
            if not isinstance(e, dict):
                continue
            if "vendor" in e:                  # Megalit-native entry
                vendor = (e.get("vendor") or "").strip()
                if not vendor:
                    continue
                role = _normalize_role(e.get("category") or e.get("role") or "WAF")
                matches = e.get("matches")
                if matches is None:
                    matches = [{"field": e.get("field", "header"),
                                "pattern": e.get("pattern", ""),
                                "weight": e.get("weight", DEFAULT_WEIGHT)}]
                ms = []
                for m in matches:
                    fld = (m.get("field") or "header").strip().lower()
                    pat = (m.get("pattern") or "").strip()
                    if fld not in VALID_FIELDS or not pat:
                        raise ValueError(f"invalid match {m!r} for vendor '{vendor}' "
                                         f"(field must be one of {sorted(VALID_FIELDS)})")
                    ms.append(Match(fld, pat, int(m.get("weight", DEFAULT_WEIGHT))))
                if ms:
                    sigs.append(Signature(vendor, role, ms))
            else:                              # fireeye-style entry
                sig = _fireeye_entry_to_sig(e)
                if sig:
                    sigs.append(sig)
    else:
        for lineno, line in enumerate(raw.splitlines(), 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = [p.strip() for p in line.replace(",", "|").split("|")]
            if len(parts) >= 4:                # Megalit-native text format
                vendor, role, fld, pat = parts[0], _normalize_role(parts[1]), \
                    parts[2].lower(), parts[3]
                weight = int(parts[4]) if len(parts) > 4 and parts[4] else DEFAULT_WEIGHT
                if fld not in VALID_FIELDS:
                    raise ValueError(f"user list line {lineno}: invalid field '{fld}' "
                                     f"(valid: {sorted(VALID_FIELDS)})")
                sigs.append(Signature(vendor, role, [Match(fld, pat, weight)]))
            elif len(parts) == 3:              # fireeye text format: Name|Manu|tokens
                tokens = [t.strip() for t in parts[2].split(",") if t.strip()]
                sig = _fireeye_entry_to_sig({
                    "name": parts[0], "type": "WAF",
                    "headers": tokens, "server": tokens})
                if sig:
                    sigs.append(sig)
            else:
                raise ValueError(f"user list line {lineno}: expected "
                                 f"Vendor|category|field|pattern|weight or "
                                 f"Name|Manufacturer|token1,token2 — got: {line}")

    log.info("Loaded %d user signature(s) from %s", len(sigs), path)
    return sigs


def load_vendor_names(path: str):
    """Load user vendor names → List[str]. Raises ValueError with a friendly msg."""
    log = get_logger()
    if not os.path.isfile(path):
        raise ValueError(f"vendor list not found: {path}")
    with open(path, "r", encoding="utf-8") as fh:
        raw = fh.read().strip()
    names: list = []
    if raw.startswith(("[", "{")):
        data = json.loads(raw)
        if isinstance(data, dict):
            data = data.get("vendors", [])
        names = [str(x).strip() for x in data if str(x).strip()]
    else:
        for line in raw.splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                names.append(line)
    log.info("Loaded %d user vendor name(s) from %s", len(names), path)
    return names
