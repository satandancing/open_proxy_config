import base64
from pathlib import Path

import yaml

from open_proxy_config.parsers.subscription import (
    parse_clash_yaml,
    parse_subscription_blob,
    parse_ss_uri,
    proxy_fingerprint,
)
from open_proxy_config.sources.vpngate import parse_openvpn_config as vg_parse


FIXTURES = Path(__file__).parent / "fixtures"


def test_parse_clash_yaml() -> None:
    text = (FIXTURES / "sample_clash.yaml").read_text(encoding="utf-8")
    nodes = parse_clash_yaml(text)
    assert len(nodes) == 1
    assert nodes[0]["type"] == "ss"


def test_parse_ss_uri() -> None:
    line = (FIXTURES / "sample_uris.txt").read_text().splitlines()[0]
    node = parse_ss_uri(line)
    assert node and node["server"] == "1.2.3.4"


def test_parse_subscription_base64() -> None:
    raw = base64.b64encode(b"ss://YWVzLTI1Ni1nY206cGFzcy@5.6.7.8:443#x").decode()
    nodes = parse_subscription_blob(raw.encode())
    assert nodes and nodes[0]["server"] == "5.6.7.8"


def test_proxy_fingerprint_dedupe() -> None:
    a = {"type": "ss", "server": "a", "port": 1, "password": "p", "cipher": "c"}
    b = dict(a)
    assert proxy_fingerprint(a) == proxy_fingerprint(b)


def test_parse_openvpn() -> None:
    ovpn = (FIXTURES / "sample_ovpn.txt").read_text()
    node = vg_parse(ovpn)
    assert node
    assert node["type"] == "openvpn"
    assert node["server"] == "vpn.example.com"
    assert "BEGIN CERTIFICATE" in node["ca"]
