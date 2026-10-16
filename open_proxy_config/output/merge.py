"""Build full mihomo.yaml and provider.yaml."""

from __future__ import annotations

from collections import defaultdict
from typing import Any

import yaml

from open_proxy_config.util.naming import _COUNTRY_FLAGS


def _group_by_country(proxies: list[dict[str, Any]]) -> dict[str, list[str]]:
    groups: dict[str, list[str]] = defaultdict(list)
    for p in proxies:
        code = (p.get("country") or "XX").upper()
        groups[code].append(p["name"])
    return dict(groups)


def build_provider_yaml(proxies: list[dict[str, Any]]) -> str:
    doc = {"proxies": proxies}
    return yaml.dump(doc, allow_unicode=True, sort_keys=False)


def build_mihomo_config(
    proxies: list[dict[str, Any]],
    *,
    by_source: dict[str, list[str]],
    rules: list[str],
) -> str:
    names = [p["name"] for p in proxies]
    country_groups = _group_by_country(proxies)
    proxy_groups: list[dict[str, Any]] = [
        {
            "name": "GLOBAL",
            "type": "select",
            "proxies": ["AUTO", "DIRECT"] + names[:50],
        },
        {
            "name": "AUTO",
            "type": "url-test",
            "proxies": names,
            "url": "https://www.gstatic.com/generate_204",
            "interval": 300,
            "tolerance": 50,
        },
    ]
    for src, src_names in by_source.items():
        if not src_names:
            continue
        proxy_groups.append(
            {
                "name": f"SRC-{src}",
                "type": "select",
                "proxies": src_names,
            }
        )
    for code, cnames in sorted(country_groups.items()):
        if not cnames or code == "XX":
            continue
        flag = _COUNTRY_FLAGS.get(code, "")
        proxy_groups.append(
            {
                "name": f"{flag} {code}".strip(),
                "type": "select",
                "proxies": cnames,
            }
        )
    doc = {
        "mixed-port": 7890,
        "allow-lan": False,
        "mode": "rule",
        "log-level": "info",
        "dns": {
            "enable": True,
            "listen": "0.0.0.0:1053",
            "enhanced-mode": "fake-ip",
            "nameserver": ["https://1.1.1.1/dns-query", "223.5.5.5"],
        },
        "proxies": proxies,
        "proxy-groups": proxy_groups,
        "rules": rules
        + [
            "GEOIP,CN,DIRECT",
            "MATCH,GLOBAL",
        ],
    }
    return yaml.dump(doc, allow_unicode=True, sort_keys=False)
