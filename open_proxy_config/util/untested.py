"""Mark proxies that skipped L3 validation."""

from __future__ import annotations

from typing import Any

UNTESTED_SUFFIX = " [未测速]"
VPNGATE_UNTESTED_GROUP = "VPNGate-未测速"


def apply_untested_name_suffix(
    proxies: list[dict[str, Any]],
    untested_original_names: set[str],
    *,
    suffix: str = UNTESTED_SUFFIX,
) -> dict[str, str]:
    """Rename openvpn nodes that skipped L3. Returns old_name -> new_name mapping."""
    renamed: dict[str, str] = {}
    used = {p["name"] for p in proxies}
    for p in proxies:
        if p.get("type") != "openvpn" or p["name"] not in untested_original_names:
            continue
        old = p["name"]
        base = old.removesuffix(suffix) if old.endswith(suffix) else old
        candidate = base + suffix
        n = 1
        while candidate in used and candidate != old:
            n += 1
            candidate = f"{base}{suffix}-{n}"
        if candidate != old:
            used.discard(old)
            used.add(candidate)
            p["name"] = candidate
            renamed[old] = candidate
    return renamed


def remap_name_lists(name_lists: dict[str, list[str]], renamed: dict[str, str]) -> None:
    for key, names in name_lists.items():
        name_lists[key] = [renamed.get(n, n) for n in names]
