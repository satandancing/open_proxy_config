"""Parse base64 lists, Clash YAML fragments, and proxy URIs."""

from __future__ import annotations

import base64
import json
import re
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse

import yaml

_URI_SCHEMES = ("ss://", "ssr://", "vmess://", "vless://", "trojan://", "hysteria2://")


def try_decode_base64_text(raw: bytes) -> str | None:
    text = raw.decode("utf-8", errors="ignore").strip()
    if not text:
        return None
    # Already plain text with URIs or yaml
    if any(s in text for s in _URI_SCHEMES) or text.startswith("proxies:"):
        return text
    pad = "=" * (-len(text) % 4)
    try:
        decoded = base64.b64decode(text + pad, validate=False)
        return decoded.decode("utf-8", errors="ignore")
    except Exception:
        return text


def split_lines(blob: str) -> list[str]:
    return [ln.strip() for ln in blob.replace("\r", "\n").split("\n") if ln.strip()]


def parse_clash_yaml(blob: str) -> list[dict[str, Any]]:
    try:
        doc = yaml.safe_load(blob)
    except yaml.YAMLError:
        return []
    if not isinstance(doc, dict):
        return []
    proxies = doc.get("proxies")
    if not isinstance(proxies, list):
        return []
    return [p for p in proxies if isinstance(p, dict) and p.get("name") and p.get("type")]


def _b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def parse_ss_uri(uri: str) -> dict[str, Any] | None:
    if not uri.startswith("ss://"):
        return None
    rest = uri[5:]
    name = "ss-node"
    if "#" in rest:
        rest, frag = rest.split("#", 1)
        name = unquote(frag) or name
    if "@" in rest:
        userinfo, hostport = rest.rsplit("@", 1)
        if ":" in userinfo:
            method, password = userinfo.split(":", 1)
            method = unquote(method)
            password = unquote(password)
        else:
            decoded = base64.b64decode(userinfo + "==").decode(errors="ignore")
            if ":" not in decoded:
                return None
            method, password = decoded.split(":", 1)
    else:
        try:
            decoded = base64.b64decode(rest + "==").decode(errors="ignore")
        except Exception:
            return None
        if "@" not in decoded:
            return None
        userinfo, hostport = decoded.rsplit("@", 1)
        method, password = userinfo.split(":", 1)
    host, port_s = hostport.split(":", 1)
    port = int(re.sub(r"\D.*", "", port_s))
    return {
        "name": name,
        "type": "ss",
        "server": host,
        "port": port,
        "cipher": method,
        "password": password,
    }


def parse_vmess_uri(uri: str) -> dict[str, Any] | None:
    if not uri.startswith("vmess://"):
        return None
    payload = uri[8:]
    try:
        data = json.loads(base64.b64decode(payload + "==").decode(errors="ignore"))
    except Exception:
        return None
    if not isinstance(data, dict):
        return None
    return {
        "name": data.get("ps") or data.get("remark") or "vmess",
        "type": "vmess",
        "server": data.get("add"),
        "port": int(data.get("port", 0)),
        "uuid": data.get("id"),
        "alterId": int(data.get("aid", 0)),
        "cipher": data.get("scy") or "auto",
        "tls": str(data.get("tls", "")).lower() in ("tls", "true", "1"),
        "network": data.get("net") or "tcp",
    }


def parse_vless_uri(uri: str) -> dict[str, Any] | None:
    if not uri.startswith("vless://"):
        return None
    parsed = urlparse(uri)
    uuid = parsed.username
    host = parsed.hostname
    port = parsed.port or 443
    qs = parse_qs(parsed.query)
    name = unquote(parsed.fragment) if parsed.fragment else "vless"
    node: dict[str, Any] = {
        "name": name,
        "type": "vless",
        "server": host,
        "port": port,
        "uuid": uuid,
        "tls": (qs.get("security", ["none"])[0] == "tls"),
        "network": qs.get("type", ["tcp"])[0],
    }
    if qs.get("flow"):
        node["flow"] = qs["flow"][0]
    return node


def parse_trojan_uri(uri: str) -> dict[str, Any] | None:
    if not uri.startswith("trojan://"):
        return None
    parsed = urlparse(uri)
    password = unquote(parsed.username or "")
    name = unquote(parsed.fragment) if parsed.fragment else "trojan"
    return {
        "name": name,
        "type": "trojan",
        "server": parsed.hostname,
        "port": parsed.port or 443,
        "password": password,
        "sni": parse_qs(parsed.query).get("sni", [parsed.hostname])[0],
    }


def parse_hysteria2_uri(uri: str) -> dict[str, Any] | None:
    if not uri.startswith("hysteria2://") and not uri.startswith("hy2://"):
        return None
    prefix = "hysteria2://" if uri.startswith("hysteria2://") else "hy2://"
    parsed = urlparse(uri)
    password = unquote(parsed.username or "")
    name = unquote(parsed.fragment) if parsed.fragment else "hysteria2"
    return {
        "name": name,
        "type": "hysteria2",
        "server": parsed.hostname,
        "port": parsed.port or 443,
        "password": password,
    }


def parse_uri_line(line: str) -> dict[str, Any] | None:
    for prefix, parser in (
        ("ss://", parse_ss_uri),
        ("vmess://", parse_vmess_uri),
        ("vless://", parse_vless_uri),
        ("trojan://", parse_trojan_uri),
        ("hysteria2://", parse_hysteria2_uri),
        ("hy2://", parse_hysteria2_uri),
    ):
        if line.startswith(prefix):
            return parser(line)
    return None


def parse_subscription_blob(raw: bytes) -> list[dict[str, Any]]:
    text = try_decode_base64_text(raw)
    if not text:
        return []
    proxies: list[dict[str, Any]] = []
    if "proxies:" in text or text.lstrip().startswith("{"):
        proxies.extend(parse_clash_yaml(text))
    for line in split_lines(text):
        if line.startswith("#"):
            continue
        if line.startswith("proxies:"):
            continue
        node = parse_uri_line(line)
        if node:
            proxies.append(node)
    return proxies


def proxy_fingerprint(proxy: dict[str, Any]) -> str:
    typ = proxy.get("type", "")
    parts = [
        typ,
        str(proxy.get("server", "")),
        str(proxy.get("port", "")),
        str(proxy.get("uuid", "")),
        str(proxy.get("password", "")),
        str(proxy.get("cipher", "")),
    ]
    return "|".join(parts).lower()
