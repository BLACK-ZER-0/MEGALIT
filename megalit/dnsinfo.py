
import asyncio
import ipaddress
import re
import socket
import ssl

from .logman import get_logger
from .signatures import IP_RANGES


async def gather_dns(hostname: str) -> dict:
    log = get_logger("DNS")
    result = {
        "host": hostname,
        "cname": "",
        "aliases": [],
        "ips": [],
        "ptrs": [],
        "ns": [],
        "ranges": [],
        "cert": {},
    }
    if not hostname:
        return result
    loop = asyncio.get_running_loop()

    # A records / canonical name
    try:
        cname, aliases, ips = await asyncio.wait_for(
            loop.run_in_executor(None, socket.gethostbyname_ex, hostname), 10)
        result["cname"] = (cname or "").rstrip(".")
        result["aliases"] = [a.rstrip(".") for a in aliases if a.rstrip(".") != result["cname"]]
        result["ips"] = list(ips)[:8]
        log.debug("DNS %s → cname=%s ips=%s aliases=%s",
                  hostname, result["cname"], result["ips"], result["aliases"])
    except Exception as e:
        log.debug("DNS resolve failed for %s: %s", hostname, e)

    # NS records, PTR lookups and TLS cert run in parallel
    async def _ns_task():
        try:
            import dns.resolver

            def _ns():
                r = dns.resolver.Resolver()
                r.lifetime = 5.0
                ans = r.resolve(hostname, "NS", raise_on_no_answer=False)
                return [str(x).rstrip(".") for x in ans]

            return await asyncio.wait_for(loop.run_in_executor(None, _ns), 8) or []
        except Exception as e:
            log.debug("NS lookup unavailable (%s) — install dnspython for NS fingerprints", e)
            return []

    async def _ptr_task():
        out = []
        for ip in result["ips"][:3]:
            try:
                host, _, _ = await asyncio.wait_for(
                    loop.run_in_executor(None, socket.gethostbyaddr, ip), 4)
                if host:
                    out.append(host.rstrip("."))
                    log.debug("PTR %s → %s", ip, host)
            except Exception:
                pass
        return out

    async def _cert_task():
        return await _get_cert(hostname)

    ns_res, ptr_res, cert_res = await asyncio.gather(
        _ns_task(), _ptr_task(), _cert_task())
    result["ns"] = ns_res
    result["ptrs"] = ptr_res
    result["cert"] = cert_res

    # IP range matching
    for cidr, vendor, weight in IP_RANGES:
        try:
            net = ipaddress.ip_network(cidr)
        except ValueError:  # pragma: no cover
            continue
        for ip in result["ips"]:
            try:
                if ipaddress.ip_address(ip) in net:
                    result["ranges"].append({"cidr": cidr, "vendor": vendor,
                                             "ip": ip, "weight": weight})
                    log.debug("IP %s ∈ %s (%s)", ip, cidr, vendor)
                    break
            except ValueError:
                continue
    return result


async def _get_cert(host: str, port: int = 443, timeout: float = 8) -> dict:
    log = get_logger()
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            ctx.set_alpn_protocols(["h2", "http/1.1"])  # probe HTTP/2 support
        except Exception:
            pass
        writer = None
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ctx), timeout)
            ssl_obj = writer.get_extra_info("ssl_object")
            der = ssl_obj.getpeercert(True) if ssl_obj else None
            info = _parse_der(der) if der else {}
            if ssl_obj:
                try:
                    info["version"] = ssl_obj.version() or ""
                except Exception:
                    pass
                try:
                    cip = ssl_obj.cipher() or ()
                    info["cipher"] = str(cip[0]) if cip else ""
                except Exception:
                    pass
                try:
                    proto = ssl_obj.selected_alpn_protocol() or ""
                    info["alpn"] = proto
                    info["h2"] = proto == "h2"
                except Exception:
                    pass
            log.debug("TLS cert for %s: issuer=%s tls=%s h2=%s",
                      host, info.get("issuer", "-"), info.get("version", "-"),
                      info.get("h2", False))
            return info
        finally:
            if writer is not None:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
    except Exception as e:
        log.debug("TLS cert unavailable for %s: %s", host, e)
        return {}


def _parse_der(der: bytes) -> dict:
    info = {"subject": "", "issuer": "", "valid_to": "", "san": ""}
    try:
        from cryptography import x509
        cert = x509.load_der_x509_certificate(der)
        info["subject"] = cert.subject.rfc4514_string()
        info["issuer"] = cert.issuer.rfc4514_string()
        try:
            info["valid_to"] = cert.not_valid_after_utc.strftime("%Y-%m-%d")
        except Exception:  # pragma: no cover
            info["valid_to"] = str(getattr(cert, "not_valid_after", ""))
        try:
            from cryptography.x509 import SubjectAlternativeName
            ext = cert.extensions.get_extension_for_class(SubjectAlternativeName).value
            info["san"] = ", ".join(ext.get_values_for_type(x509.DNSName)[:8])
        except Exception:
            pass
    except ImportError:
        # naive DER string extraction (no cryptography installed)
        text = der.decode("latin-1", errors="ignore")
        cns = re.findall(r"CN=([\w .\-'*]{1,80})", text)
        if cns:
            info["subject"] = f"CN={cns[0]}"
            info["issuer"] = f"CN={cns[-1]}" if len(cns) > 1 else info["subject"]
    except Exception:  # pragma: no cover
        pass
    return info
