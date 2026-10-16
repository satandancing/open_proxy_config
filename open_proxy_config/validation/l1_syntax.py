"""L1: structural validation of Mihomo proxy dicts."""

from __future__ import annotations

from typing import Any

_REQUIRED: dict[str, list[str]] = {
    "ss": ["server", "port", "cipher", "password"],
    "vmess": ["server", "port", "uuid"],
    "vless": ["server", "port", "uuid"],
    "trojan": ["server", "port", "password"],
    "hysteria2": ["server", "port", "password"],
    "wireguard": ["server", "port", "private-key"],
    "openvpn": ["server", "port", "proto", "ca"],
}


def _valid_port(port: Any) -> bool:
    try:
        p = int(port)
        return 1 <= p <= 65535
    except (TypeError, ValueError):
        return False


def validate_proxy(proxy: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if not proxy.get("name"):
        errors.append("missing name")
    typ = proxy.get("type")
    if not typ:
        errors.append("missing type")
        return errors
    for field in _REQUIRED.get(str(typ), []):
        if not proxy.get(field):
            errors.append(f"missing {field}")
    if proxy.get("port") is not None and not _valid_port(proxy.get("port")):
        errors.append("invalid port")
    if proxy.get("server") in (None, ""):
        errors.append("missing server")
    return errors


def filter_valid_proxies(proxies: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[str]]:
    good: list[dict[str, Any]] = []
    messages: list[str] = []
    for p in proxies:
        errs = validate_proxy(p)
        if errs:
            messages.append(f"{p.get('name', '?')}: {', '.join(errs)}")
            continue
        good.append(p)
    return good, messages
