from open_proxy_config.output.merge import build_mihomo_config, build_provider_yaml
from open_proxy_config.util.dedupe import dedupe_proxies
from open_proxy_config.util.naming import make_unique_names
from open_proxy_config.validation.l1_syntax import filter_valid_proxies


def test_dedupe() -> None:
    nodes = [
        {"type": "ss", "server": "a", "port": 1, "cipher": "x", "password": "p", "name": "n1"},
        {"type": "ss", "server": "a", "port": 1, "cipher": "x", "password": "p", "name": "n2"},
    ]
    assert len(dedupe_proxies(nodes)) == 1


def test_unique_names() -> None:
    nodes = [{"name": "a", "type": "ss"}, {"name": "a", "type": "ss"}]
    out = make_unique_names(nodes, prefix="T")
    assert out[0]["name"] != out[1]["name"]


def test_l1_filter() -> None:
    good, _ = filter_valid_proxies(
        [{"name": "x", "type": "ss", "server": "h", "port": 443, "cipher": "a", "password": "b"}]
    )
    assert len(good) == 1
    bad, errs = filter_valid_proxies([{"name": "x", "type": "ss"}])
    assert not bad and errs


def test_build_outputs() -> None:
    proxies = [
        {
            "name": "n1",
            "type": "ss",
            "server": "h",
            "port": 1,
            "cipher": "a",
            "password": "b",
            "country": "JP",
        }
    ]
    provider = build_provider_yaml(proxies)
    assert "proxies:" in provider
    full = build_mihomo_config(proxies, by_source={"aggregator": ["n1"]}, rules=[])
    assert "proxy-groups:" in full
