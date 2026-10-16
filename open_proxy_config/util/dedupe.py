from __future__ import annotations

from typing import Any

from open_proxy_config.parsers.subscription import proxy_fingerprint


def dedupe_proxies(proxies: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[str] = set()
    out: list[dict[str, Any]] = []
    for p in proxies:
        fp = proxy_fingerprint(p)
        if fp in seen:
            continue
        seen.add(fp)
        out.append(p)
    return out
