"""Cloudflare WARP (personal) WireGuard proxy for Mihomo.

Registration follows wgcf v2 (API v0a5641, RFC3339Nano TOS timestamp, wireguard tunnel fields).
Reference: https://github.com/ViRb3/wgcf (MIT) — logic reimplemented, not copied.
"""

from __future__ import annotations

import base64
import json
import os
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from open_proxy_config.sources.base import Source, SourceResult

CF_API_VERSION = "v0a5641"
CF_API_BASE = f"https://api.cloudflareclient.com/{CF_API_VERSION}"


def _cf_headers(access_token: str | None = None) -> dict[str, str]:
    headers = {
        "Content-Type": "application/json; charset=UTF-8",
        "User-Agent": "1.1.1.1/6.38.9-5641 (Android 16.0.0)",
        "CF-Client-Version": "a-6.38.9-5641",
        "Connection": "Keep-Alive",
    }
    if access_token:
        headers["Authorization"] = f"Bearer {access_token}"
    return headers


def _b64_pubkey(priv: X25519PrivateKey) -> str:
    pub = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.b64encode(pub).decode()


def _b64_privkey(priv: X25519PrivateKey) -> str:
    raw = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return base64.b64encode(raw).decode()


def _decode_b64(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.b64decode(s + pad)


def _priv_from_b64(private_key_b64: str) -> X25519PrivateKey:
    return X25519PrivateKey.from_private_bytes(_decode_b64(private_key_b64))


def _tos_timestamp() -> str:
    t = datetime.now(timezone.utc)
    return t.strftime("%Y-%m-%dT%H:%M:%S.") + f"{t.microsecond // 1000:03d}Z"


def generate_warp_credentials() -> dict[str, str]:
    priv = X25519PrivateKey.generate()
    return {
        "private_key": _b64_privkey(priv),
        "public_key": _b64_pubkey(priv),
    }


def register_warp_device(private_key_b64: str, device_model: str = "PC") -> dict[str, Any]:
    priv = _priv_from_b64(private_key_b64)
    public_key = _b64_pubkey(priv)
    payload = {
        "key": public_key,
        "install_id": "",
        "fcm_token": "",
        "tos": _tos_timestamp(),
        "model": device_model,
        "serial_number": "",
        "locale": "en_US",
        "os_version": "16.0.0",
        "key_type": "curve25519",
        "tunnel_type": "wireguard",
    }
    req = urllib.request.Request(
        f"{CF_API_BASE}/reg",
        data=json.dumps(payload).encode(),
        headers=_cf_headers(),
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")
        raise RuntimeError(f"WARP reg HTTP {e.code}: {body}") from e


def fetch_source_device(device_id: str, access_token: str) -> dict[str, Any]:
    req = urllib.request.Request(
        f"{CF_API_BASE}/reg/{device_id}",
        headers=_cf_headers(access_token),
        method="GET",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")
        raise RuntimeError(f"WARP device HTTP {e.code}: {body}") from e


def _parse_endpoint(endpoint: dict[str, Any]) -> tuple[str, int]:
    host_field = endpoint.get("host") or ""
    if host_field:
        if ":" in host_field:
            host, port_s = host_field.rsplit(":", 1)
            return host, int(port_s)
        return host_field, 2408
    v4 = endpoint.get("v4") or ""
    if v4 and ":" in v4:
        host, port_s = v4.split(":", 1)
        port = int(port_s) if port_s.isdigit() and int(port_s) > 0 else 2408
        return host, port
    ports = endpoint.get("ports") or [2408]
    return "162.159.123.1", int(ports[0])


def _reserved_from_client_id(client_id: str) -> list[int]:
    raw = _decode_b64(client_id)
    if len(raw) < 3:
        raw = raw + b"\x00" * (3 - len(raw))
    return list(raw[:3])


def mihomo_proxy_from_warp_config(
    private_key_b64: str,
    warp_config: dict[str, Any],
    *,
    name: str = "🇺🇸WARP-CF",
) -> dict[str, Any]:
    iface = warp_config.get("interface") or {}
    addresses = iface.get("addresses") or {}
    client_ip = addresses.get("v4") or "172.16.0.2"
    client_ipv6 = addresses.get("v6")
    peers = warp_config.get("peers") or []
    if not peers:
        raise ValueError("WARP config missing peers")
    peer = peers[0]
    server_host, server_port = _parse_endpoint(peer.get("endpoint") or {})
    proxy: dict[str, Any] = {
        "name": name,
        "type": "wireguard",
        "server": server_host,
        "port": server_port,
        "ip": client_ip,
        "private-key": private_key_b64,
        "public-key": peer.get("public_key"),
        "udp": True,
        "mtu": 1280,
    }
    if client_ipv6:
        proxy["ipv6"] = client_ipv6
    client_id = warp_config.get("client_id")
    if client_id:
        proxy["reserved"] = _reserved_from_client_id(client_id)
    return proxy


def build_wireguard_proxy_from_registration(reg: dict[str, Any], private_key_b64: str) -> dict[str, Any]:
    cfg = reg.get("config")
    if not cfg:
        device_id = reg["id"]
        token = reg["token"]
        reg = fetch_source_device(device_id, token)
        cfg = reg.get("config")
    if not cfg:
        raise ValueError("no WireGuard config in WARP registration response")
    return mihomo_proxy_from_warp_config(private_key_b64, cfg)


def load_or_create_warp_account(
    *,
    output_dir: str,
    register_if_missing: bool,
) -> dict[str, str] | None:
    env_pk = os.environ.get("WARP_PRIVATE_KEY")
    env_id = os.environ.get("WARP_DEVICE_ID")
    env_token = os.environ.get("WARP_ACCESS_TOKEN")
    if env_pk and env_id and env_token:
        return {
            "private_key": env_pk,
            "device_id": env_id,
            "access_token": env_token,
        }
    state_path = os.path.join(output_dir, ".warp-account.json")
    if os.path.isfile(state_path):
        with open(state_path, encoding="utf-8") as f:
            data = json.load(f)
        if data.get("private_key") and data.get("device_id") and data.get("access_token"):
            return data
    if not register_if_missing:
        return None
    creds = generate_warp_credentials()
    reg = register_warp_device(creds["private_key"])
    account = {
        "private_key": creds["private_key"],
        "device_id": reg["id"],
        "access_token": reg["token"],
        "license": (reg.get("account") or {}).get("license"),
        "registration_log": {
            "api_version": CF_API_VERSION,
            "has_config": bool(reg.get("config")),
        },
    }
    os.makedirs(output_dir, exist_ok=True)
    with open(state_path, "w", encoding="utf-8") as f:
        json.dump(account, f, indent=2)
    return account


class WarpSource(Source):
    source_id = "warp"

    def __init__(
        self,
        output_dir: str,
        register_if_missing: bool = True,
        endpoint_host: str = "162.159.123.1",
        endpoint_port: int = 2408,
        client_ipv4: str = "172.16.0.2",
    ) -> None:
        self.output_dir = output_dir
        self.register_if_missing = register_if_missing
        # legacy config keys kept for compatibility; endpoint derived from API when possible
        self.endpoint_host = endpoint_host
        self.endpoint_port = endpoint_port
        self.client_ipv4 = client_ipv4

    def fetch(self) -> SourceResult:
        result = SourceResult(source_id=self.source_id)
        try:
            account = load_or_create_warp_account(
                output_dir=self.output_dir,
                register_if_missing=self.register_if_missing,
            )
        except (urllib.error.URLError, OSError, json.JSONDecodeError, KeyError, RuntimeError) as e:
            result.errors.append(f"warp account: {e}")
            return result
        if not account:
            result.errors.append(
                "WARP credentials missing; set WARP_* env vars or enable register_if_missing"
            )
            return result
        try:
            device = fetch_source_device(account["device_id"], account["access_token"])
            cfg = device.get("config")
            if not cfg:
                raise ValueError("device response missing config")
            proxy = mihomo_proxy_from_warp_config(account["private_key"], cfg)
        except Exception as e:
            result.errors.append(f"warp config: {e}")
            return result
        result.proxies = [proxy]
        result.extras["account_present"] = True
        return result
