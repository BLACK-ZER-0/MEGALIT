
import re
from types import SimpleNamespace

from .signatures import SIGNATURES, DEFINITIVE, IP_RANGES  # noqa


def _fake(status, headers, body=""):
    return SimpleNamespace(header_pairs=headers, cookies={}, body=body,
                           status=status, final_url="t", url="t")


def _ev(resp, vendor):
    from .signatures import ctx_from_response, match_contexts
    return [e for e in match_contexts([ctx_from_response(resp)])
            if e.vendor == vendor]


def run() -> int:
    checks: list = []

    def check(name, fn):
        try:
            detail = fn()
            checks.append((True, name, detail or ""))
        except AssertionError as e:
            checks.append((False, name, str(e)))
        except Exception as e:  # noqa: BLE001
            checks.append((False, name, f"{type(e).__name__}: {e}"))

    def all_regexes_compile():
        n = 0
        for sig in SIGNATURES:
            for m in sig.matches:
                if m.field not in ("status", "behavior"):
                    re.compile(m.pattern, re.I)
                    n += 1
        return f"{n} patterns OK"

    def definitive_integrity():
        assert len(DEFINITIVE) >= 15, f"only {len(DEFINITIVE)} definitive tokens"
        return f"{len(DEFINITIVE)} definitive tokens"

    def ip_ranges_integrity():
        import ipaddress
        for _cidr, _vendor, _w in IP_RANGES:
            ipaddress.ip_network(_cidr, strict=False)
        return f"{len(IP_RANGES)} ranges OK"

    def vendor_coverage():
        vendors = {s.vendor for s in SIGNATURES}
        assert len(vendors) >= 400, f"vendor count dropped to {len(vendors)}"
        return f"{len(vendors)} vendors"

    def no_hex_unsafe_tokens():
        from .megalit_tokens import TOKENS
        bad = []
        for v, t in TOKENS.items():
            for fld in ("headers", "cookies", "body", "server"):
                for tok in t.get(fld) or []:
                    s = str(tok)
                    if re.fullmatch(r"[0-9a-fA-F]{2,4}", s.replace("-", "")):
                        bad.append(f"{v}/{fld}:{s!r}")
        assert not bad, f"hex-unsafe loose tokens: {bad[:5]}"
        return "loose token audit clean"

    def behavior_litespeed():
        ev = _ev(_fake(403, [("Server", "LiteSpeed"),
                             ("X-Turbo-Charged-By", "LiteSpeed")]), "LiteSpeed")
        assert any(e.field == "behavior" for e in ev), "LiteSpeed behavior miss"
        ev2 = _ev(_fake(403, [("Server", "nginx")]), "LiteSpeed")
        assert not any(e.field == "behavior" for e in ev2), "false LiteSpeed behavior"
        return "co-occurrence ±"

    def behavior_modsecurity():
        ev = _ev(_fake(403, [("Reason", "ModSecurity Action")]), "ModSecurity")
        assert any(e.field == "behavior" and e.weight == 65 for e in ev), "modsec behavior miss"
        ev2 = _ev(_fake(200, [("Server", "NOYB")]), "ModSecurity")
        assert any(e.weight == 55 for e in ev2), "NOYB miss"
        return "Reason+403 / NOYB"

    def behavior_shieldon_pair():
        ev = _ev(_fake(403, [], "Access denied — The IP address you are "
                                 "using has been blocked."), "Shieldon Firewall (Shieldon.io)")
        assert any(e.field == "behavior" for e in ev), "shieldon pair miss"
        ev2 = _ev(_fake(403, [], "Access denied, sorry."), "Shieldon Firewall (Shieldon.io)")
        assert not ev2, "shieldon generic Access denied FP"
        return "paired strings ±"

    def corroboration_bonus():
        from .signatures import Evidence, aggregate
        evs = [Evidence("V", "WAF", "header_value", "p1", "s", 40),
               Evidence("V", "WAF", "body", "p2", "s2", 40)]
        one = aggregate(evs[:1])
        two = aggregate(evs)
        assert one[0]["score"] == 40 and two[0]["score"] == 88, \
            f"bonus math wrong: {one[0]['score']} vs {two[0]['score']}"
        return "40 → 88 with 2 fields"

    check("signature regexes compile", all_regexes_compile)
    check("definitive token set", definitive_integrity)
    check("IP ranges parse", ip_ranges_integrity)
    check("vendor coverage ≥400", vendor_coverage)
    check("loose-token hex audit", no_hex_unsafe_tokens)
    check("behavior: LiteSpeed 403 co-occurrence", behavior_litespeed)
    check("behavior: ModSecurity Reason/NOYB", behavior_modsecurity)
    check("behavior: Shieldon paired strings", behavior_shieldon_pair)
    check("aggregate corroboration bonus", corroboration_bonus)

    ok = all(c[0] for c in checks)
    print(f"Megalit self-test — {sum(c[0] for c in checks)}/{len(checks)} passed")
    for good, name, detail in checks:
        mark = "✓" if good else "✗"
        print(f"  {mark} {name}" + (f"  [{detail}]" if detail else ""))
    return 0 if ok else 1
