
import asyncio
import random
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

import aiohttp

try:
    from aiohttp_socks import ProxyConnector
    HAS_SOCKS = True
except ImportError:  # pragma: no cover
    HAS_SOCKS = False

from .logman import TRACE, get_logger
from .useragents import FALLBACK_UA, USER_AGENTS

DEFAULT_TIMEOUT = 15
MAX_BODY = 200_000
DEFAULT_HEADERS = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
}


@dataclass
class FetchResult:
    url: str
    method: str = "GET"
    final_url: str = ""
    status: int = 0
    ok: bool = False
    error: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    header_pairs: List[Tuple[str, str]] = field(default_factory=list)
    raw_headers: str = ""
    cookies: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    elapsed: float = 0.0
    proxy: str = ""
    ua: str = ""
    hop_from: str = ""

    def get_header(self, name: str) -> str:
        return self.headers.get(name.lower(), "")


class HTTPClient:
    """Async client manager: one direct session + cached socks sessions."""

    def __init__(self, proxies: Optional[List[str]] = None, rotate_ua: bool = True,
                 timeout: float = DEFAULT_TIMEOUT):
        self.proxies = proxies or []
        self.rotate_ua = rotate_ua
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.timeout_seconds = timeout
        self.session: Optional[aiohttp.ClientSession] = None
        self._socks_sessions: Dict[str, aiohttp.ClientSession] = {}
        self._px_i = 0
        self._warned_socks = False

    async def start(self) -> None:
        # force_close=True → a fresh connection (and fresh DNS resolution) for
        # EVERY request, like wafw00f. Multi-layer / round-robin targets
        # (e.g. cpc.edu.bd alternating LiteSpeed ↔ openresty edge) then reveal
        # ALL of their layers instead of pinning one pool connection.
        conn = aiohttp.TCPConnector(ssl=False, force_close=True,
                                    enable_cleanup_closed=True)
        self.session = aiohttp.ClientSession(connector=conn, timeout=self.timeout)
        get_logger("HTTP").debug("HTTP engine started (proxies=%d, rotate_ua=%s, socks_lib=%s)",
                                 len(self.proxies), self.rotate_ua, HAS_SOCKS)

    async def close(self) -> None:
        for s in [self.session] + list(self._socks_sessions.values()):
            if s and not s.closed:
                try:
                    await s.close()
                except Exception:
                    pass
        get_logger("HTTP").debug("HTTP engine closed")

    def pick(self) -> Tuple[aiohttp.ClientSession, Optional[str]]:
        """Round-robin proxy rotation → (session, proxy_url_or_None)."""
        if not self.proxies:
            return self.session, None
        self._px_i = (self._px_i + 1) % len(self.proxies)
        px = self.proxies[self._px_i]
        if px.startswith(("socks4://", "socks5://")):
            if HAS_SOCKS:
                if px not in self._socks_sessions:
                    conn = ProxyConnector.from_url(px, ssl=False)
                    self._socks_sessions[px] = aiohttp.ClientSession(
                        connector=conn, timeout=self.timeout)
                return self._socks_sessions[px], px
            if not self._warned_socks:
                self._warned_socks = True
                get_logger("HTTP").warning(
                    "aiohttp-socks not installed — socks proxies ignored (pip install aiohttp-socks)")
            return self.session, None
        # http/https proxies travel via per-request `proxy=` on the direct session
        return self.session, px

    def next_ua(self) -> str:
        return FALLBACK_UA if not self.rotate_ua else random.choice(USER_AGENTS)

    async def fetch(self, url: str, method: str = "GET", headers: Optional[Dict] = None,
                    data=None, ua: Optional[str] = None,
                    session: Optional[aiohttp.ClientSession] = None,
                    proxy: Optional[str] = None) -> FetchResult:
        """Single HTTP request (no auto-redirect). Never raises — errors go into result."""
        res = FetchResult(url=str(url), method=method)
        res.ua = ua or self.next_ua()
        res.proxy = proxy or ""
        sess = session or self.session
        hdrs = dict(DEFAULT_HEADERS)
        hdrs["User-Agent"] = res.ua
        if headers:
            hdrs.update(headers)
        req: Dict = {"headers": hdrs}
        if proxy and proxy.startswith(("http://", "https://")):
            req["proxy"] = proxy
        log = get_logger("HTTP")
        log.debug("→ %s %s (px=%s, ua=%.36s…)", method, url,
                  res.proxy or "-", res.ua)
        t0 = time.perf_counter()
        try:
            async with sess.request(method, url, data=data, allow_redirects=False, **req) as resp:
                res.status = resp.status
                res.final_url = str(resp.url)
                res.ok = 200 <= resp.status < 400
                try:
                    raw_body = await resp.content.read(MAX_BODY)
                except Exception as e:
                    log.debug("body read failed for %s: %s", url, e)
                    raw_body = b""
                # curl -I style raw headers
                try:
                    ver = f"HTTP/{resp.version.major}.{resp.version.minor}"
                except Exception:
                    ver = "HTTP/1.1"
                lines = [f"{ver} {resp.status} {resp.reason or ''}".rstrip()]
                for k, v in resp.raw_headers:
                    kn = k.decode("latin-1")
                    vn = v.decode("latin-1")
                    res.header_pairs.append((kn, vn))
                    res.headers[kn.lower()] = vn
                    lines.append(f"{kn}: {vn}")
                res.raw_headers = "\r\n".join(lines)
                for k, morsel in resp.cookies.items():
                    res.cookies[k] = morsel.value
                try:
                    charset = resp.get_encoding() or "utf-8"
                except Exception:
                    charset = "utf-8"
                try:
                    res.body = raw_body.decode(charset, errors="replace")
                except LookupError:
                    res.body = raw_body.decode("utf-8", errors="replace")
        except Exception as e:
            res.error = f"{type(e).__name__}: {e}"[:200]
            log.debug("✗ %s %s → %s", method, url, res.error)
        res.elapsed = time.perf_counter() - t0
        if not res.error:
            log.debug("✓ %s %s → %s · %.2fs · %dB",
                      method, url, res.status, res.elapsed, len(res.body))
            if res.header_pairs:
                dump = " │ ".join(f"{h}={v}" for h, v in res.header_pairs[:14])
                suffix = " …" if len(res.header_pairs) > 14 else ""
                log.trace("headers %s → %.400s%s", url, dump, suffix)
        return res
