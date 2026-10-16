from __future__ import annotations

from collections import Counter
from typing import Any


def count_by_type(proxies: list[dict[str, Any]]) -> dict[str, int]:
    c: Counter[str] = Counter()
    for p in proxies:
        c[str(p.get("type", "unknown"))] += 1
    return dict(sorted(c.items()))
