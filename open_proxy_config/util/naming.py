"""Unique proxy names with country flags."""

from __future__ import annotations

import re
from typing import Any

_COUNTRY_FLAGS = {
    "JP": "🇯🇵",
    "US": "🇺🇸",
    "KR": "🇰🇷",
    "TW": "🇹🇼",
    "HK": "🇭🇰",
    "SG": "🇸🇬",
    "DE": "🇩🇪",
    "GB": "🇬🇧",
    "FR": "🇫🇷",
    "NL": "🇳🇱",
    "CA": "🇨🇦",
    "AU": "🇦🇺",
    "VN": "🇻🇳",
    "TH": "🇹🇭",
    "RU": "🇷🇺",
    "CN": "🇨🇳",
}


def sanitize_name(name: str) -> str:
    name = re.sub(r"[\r\n\t]", " ", name)
    name = re.sub(r"\s+", " ", name).strip()
    return name[:80] if name else "node"


def country_from_text(text: str) -> str | None:
    m = re.search(r"\b([A-Z]{2})\b", text)
    if m:
        return m.group(1)
    for code, flag in _COUNTRY_FLAGS.items():
        if flag in text:
            return code
    return None


def make_unique_names(
    proxies: list[dict[str, Any]],
    *,
    prefix: str,
    default_country: str | None = None,
) -> list[dict[str, Any]]:
    seen: set[str] = set()
    out: list[dict[str, Any]] = []
    for i, p in enumerate(proxies):
        country = p.get("country") or country_from_text(str(p.get("name", ""))) or default_country
        flag = _COUNTRY_FLAGS.get(country or "", "")
        base = sanitize_name(str(p.get("name", f"{prefix}-{i+1}")))
        candidate = f"{flag}{prefix}-{base}" if flag else f"{prefix}-{base}"
        n = 1
        name = candidate
        while name in seen:
            n += 1
            name = f"{candidate}-{n}"
        seen.add(name)
        cp = dict(p)
        cp["name"] = name
        if country:
            cp["country"] = country
        out.append(cp)
    return out
