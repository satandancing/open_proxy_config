"""HTTP client with SSRF guard, size limits, timeouts, and rate limiting."""

from __future__ import annotations

import ipaddress
import socket
import time
import urllib.error
import urllib.request
from collections import defaultdict
from dataclasses import dataclass
from typing import Mapping
from urllib.parse import urljoin, urlparse


_BLOCKED_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("240.0.0.0/4"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]


def _ip_blocked(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    for net in _BLOCKED_NETWORKS:
        if ip in net:
            return True
    return ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved


def is_safe_url(url: str, *, allow_private: bool = False) -> bool:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return False
    host = parsed.hostname
    if not host:
        return False
    if host.lower() in ("localhost", "localhost.localdomain"):
        return False
    try:
        ip = ipaddress.ip_address(host)
        if not allow_private and _ip_blocked(ip):
            return False
        return True
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, parsed.port or 443, type=socket.SOCK_STREAM)
    except socket.gaierror:
        return False
    for info in infos:
        addr = info[4][0]
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            continue
        if not allow_private and _ip_blocked(ip):
            return False
    return True


class RateLimiter:
    def __init__(self, per_minute: int) -> None:
        self._per_minute = max(1, per_minute)
        self._hits: dict[str, list[float]] = defaultdict(list)

    def wait(self, host: str) -> None:
        now = time.monotonic()
        window = 60.0
        hits = self._hits[host]
        self._hits[host] = [t for t in hits if now - t < window]
        if len(self._hits[host]) >= self._per_minute:
            sleep_for = window - (now - self._hits[host][0]) + 0.05
            if sleep_for > 0:
                time.sleep(sleep_for)
        self._hits[host].append(time.monotonic())


@dataclass
class HttpSettings:
    timeout_seconds: float = 30.0
    max_body_bytes: int = 10 * 1024 * 1024
    rate_limit_per_host_per_minute: int = 30


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class SafeHttpClient:
    def __init__(self, settings: HttpSettings | None = None) -> None:
        self.settings = settings or HttpSettings()
        self._limiter = RateLimiter(self.settings.rate_limit_per_host_per_minute)
        self._opener = urllib.request.build_opener(_NoRedirect())

    def get(
        self,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        follow_redirects: bool = True,
        max_redirects: int = 5,
    ) -> bytes:
        current = url
        redirects = 0
        while True:
            if not is_safe_url(current):
                raise ValueError(f"SSRF blocked or invalid URL: {current}")
            parsed = urlparse(current)
            host = parsed.hostname or ""
            self._limiter.wait(host)
            req = urllib.request.Request(
                current,
                headers=dict(headers or {}),
                method="GET",
            )
            try:
                with self._opener.open(
                    req, timeout=self.settings.timeout_seconds
                ) as resp:
                    if resp.status in (301, 302, 303, 307, 308):
                        if not follow_redirects:
                            raise urllib.error.HTTPError(
                                current, resp.status, "redirect disabled", resp.headers, None
                            )
                        loc = resp.headers.get("Location")
                        if not loc:
                            raise ValueError("redirect without Location")
                        redirects += 1
                        if redirects > max_redirects:
                            raise ValueError("too many redirects")
                        current = urljoin(current, loc)
                        continue
                    data = resp.read(self.settings.max_body_bytes + 1)
            except urllib.error.HTTPError as e:
                if (
                    follow_redirects
                    and e.code in (301, 302, 303, 307, 308)
                    and e.headers.get("Location")
                ):
                    redirects += 1
                    if redirects > max_redirects:
                        raise ValueError("too many redirects") from e
                    current = urljoin(current, e.headers["Location"])
                    continue
                raise
            if len(data) > self.settings.max_body_bytes:
                raise ValueError(f"response too large from {current}")
            return data
