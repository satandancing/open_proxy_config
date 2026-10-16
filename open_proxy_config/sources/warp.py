"""Cloudflare WARP (personal) WireGuard proxy for Mihomo."""

from __future__ import annotations

import base64
import json
import os
import uuid
import urllib.error
import urllib.request
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from open_proxy_config.sources.base import Source, SourceResult

CF_REG_URL = "https://api.cloudflareclient.com/v0a2158/reg"
CF_API_VERSION = "v0a2158"


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


def generate_warp_credentials() -> dict[str, str]:
    priv = X25519PrivateKey.generate()
    return {
        "private_key": _b64_privkey(priv),
        "public_key": _b64_pubkey(priv),
    }


def register_warp_device(private_key_b64: str) -> dict[str, Any]:
    """Register or refresh WARP device via Cloudflare public API."""
    priv = X25519PrivateKey.from_private_bytes(
        base64.b64decode(private_key_b64 + "==")
    )
    public_key = _b64_pubkey(priv)
    payload = {
        "key": public_key,
        "install_id": str(uuid.uuid4()),
        "fcm_token": "",
        "tos": "2022-11-02",
        "model": "PC",
        "serial_number": "",
        "locale": "en_US",
    }
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        CF_REG_URL,
        data=data,
        headers={
            "Content-Type": "application/json",
            "User-Agent": "Mozilla/5.0",
            "CF-Client-Version": "a-7.0-2576",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        body = json.loads(resp.read().decode())
    return body


def load_or_create_warp_account(
    *,
    output_dir: str,
    register_if_missing: bool,
) -> dict[str, str] | None:
    """Load secrets from env or local state file under output_dir (never repo root)."""
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
        "license": reg.get("account", {}).get("license"),
    }
    os.makedirs(output_dir, exist_ok=True)
    with open(state_path, "w", encoding="utf-8") as f:
        json.dump(account, f, indent=2)
    return account


def build_wireguard_proxy(
    account: dict[str, str],
    *,
    endpoint_host: str,
    endpoint_port: int,
    client_ipv4: str,
) -> dict[str, Any]:
    # Cloudflare WARP server public key (well-known for consumer WARP)
    server_public_key = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="
    return {
        "name": "WARP-CF",
        "type": "wireguard",
        "server": endpoint_host,
        "port": endpoint_port,
        "ip": client_ipv4,
        "private-key": account["private_key"],
        "public-key": server_public_key,
        "udp": True,
        "mtu": 1280,
        "reserved": [0, 0, 0],
    }


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
        except (urllib.error.URLError, OSError, json.JSONDecodeError, KeyError) as e:
            result.errors.append(f"warp account: {e}")
            return result
        if not account:
            result.errors.append(
                "WARP credentials missing; set WARP_* env vars or enable register_if_missing"
            )
            return result
        proxy = build_wireguard_proxy(
            account,
            endpoint_host=self.endpoint_host,
            endpoint_port=self.endpoint_port,
            client_ipv4=self.client_ipv4,
        )
        proxy["name"] = "🇺🇸WARP-CF"
        result.proxies = [proxy]
        result.extras["account_present"] = True
        return result
