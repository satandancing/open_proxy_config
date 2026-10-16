"""VPN Gate CSV API -> Mihomo openvpn proxies."""

from __future__ import annotations

import base64
import csv
import io
import re
from typing import Any

from open_proxy_config.safety.http_client import SafeHttpClient
from open_proxy_config.sources.base import Source, SourceResult
from open_proxy_config.util.naming import make_unique_names


def _extract_block(content: str, key: str) -> str | None:
    pattern = rf"<{key}>\s*(.*?)\s*</{key}>"
    m = re.search(pattern, content, re.DOTALL | re.IGNORECASE)
    return m.group(1).strip() if m else None


def parse_openvpn_config(ovpn: str) -> dict[str, Any] | None:
    remote_m = re.search(r"^remote\s+(\S+)\s+(\d+)", ovpn, re.MULTILINE)
    if not remote_m:
        return None
    server, port_s = remote_m.group(1), remote_m.group(2)
    proto_m = re.search(r"^proto\s+(tcp|udp)", ovpn, re.MULTILINE | re.IGNORECASE)
    proto = (proto_m.group(1).lower() if proto_m else "udp")
    ca = _extract_block(ovpn, "ca")
    if not ca:
        return None
    cert = _extract_block(ovpn, "cert")
    key = _extract_block(ovpn, "key")
    tls_auth = _extract_block(ovpn, "tls-auth")
    tls_crypt = _extract_block(ovpn, "tls-crypt")
    node: dict[str, Any] = {
        "type": "openvpn",
        "server": server,
        "port": int(port_s),
        "proto": proto,
        "udp": proto == "udp",
        "ca": ca if ca.endswith("\n") else ca + "\n",
        "username": "vpn",
        "password": "vpn",
    }
    if cert and key:
        node["cert"] = cert if cert.endswith("\n") else cert + "\n"
        node["key"] = key if key.endswith("\n") else key + "\n"
    if tls_crypt:
        node["tls-crypt"] = tls_crypt if tls_crypt.endswith("\n") else tls_crypt + "\n"
    elif tls_auth:
        node["tls-auth"] = tls_auth if tls_auth.endswith("\n") else tls_auth + "\n"
        kd = re.search(r"^key-direction\s+(\d+)", ovpn, re.MULTILINE)
        if kd:
            node["key-direction"] = kd.group(1)
    return node


class VPNGateSource(Source):
    source_id = "vpngate"

    def __init__(
        self,
        client: SafeHttpClient,
        api_url: str,
        max_nodes: int = 50,
        emit_ovpn_dir: bool = True,
    ) -> None:
        self.client = client
        self.api_url = api_url
        self.max_nodes = max_nodes
        self.emit_ovpn_dir = emit_ovpn_dir

    def fetch(self) -> SourceResult:
        result = SourceResult(source_id=self.source_id)
        try:
            raw = self.client.get(self.api_url)
        except Exception as e:
            result.errors.append(f"fetch failed: {e}")
            return result
        text = raw.decode("utf-8", errors="replace")
        # CSV: skip first line (*vpn_servers)
        lines = text.splitlines()
        if lines and lines[0].startswith("*"):
            lines = lines[1:]
        reader = csv.reader(io.StringIO("\n".join(lines)))
        ovpn_files: dict[str, str] = {}
        proxies: list[dict[str, Any]] = []
        for row in reader:
            if len(row) < 15:
                continue
            country = row[1] if len(row) > 1 else ""
            hostname = row[0]
            openvpn_b64 = ""
            if len(row) > 15 and row[15]:
                openvpn_b64 = row[15]
            elif len(row) > 14 and row[14]:
                openvpn_b64 = row[14]
            if not openvpn_b64:
                continue
            try:
                ovpn = base64.b64decode(openvpn_b64).decode("utf-8", errors="replace")
            except Exception:
                continue
            parsed = parse_openvpn_config(ovpn)
            if not parsed:
                continue
            parsed["name"] = f"{country}-{hostname}"
            parsed["country"] = country[:2].upper() if country else None
            proxies.append(parsed)
            if self.emit_ovpn_dir:
                safe_host = re.sub(r"[^\w.-]+", "_", hostname)[:40]
                ovpn_files[f"{safe_host}.ovpn"] = ovpn
            if len(proxies) >= self.max_nodes:
                break
        result.proxies = make_unique_names(proxies, prefix="VG")
        if ovpn_files:
            result.extras["ovpn_files"] = ovpn_files
        return result
