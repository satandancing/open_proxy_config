from open_proxy_config.output.merge import build_mihomo_config
from open_proxy_config.util.untested import (
    UNTESTED_SUFFIX,
    VPNGATE_UNTESTED_GROUP,
    apply_untested_name_suffix,
)


def test_suffix_and_group() -> None:
    proxies = [
        {"name": "VG-JP", "type": "openvpn", "country": "JP"},
        {"name": "PUB-ss", "type": "ss", "country": "US"},
    ]
    apply_untested_name_suffix(proxies, {"VG-JP"})
    assert proxies[0]["name"].endswith(UNTESTED_SUFFIX)
    yaml_text = build_mihomo_config(
        proxies,
        by_source={"vpngate": [proxies[0]["name"]], "aggregator": [proxies[1]["name"]]},
        rules=[],
        openvpn_untested_names=[proxies[0]["name"]],
    )
    assert VPNGATE_UNTESTED_GROUP in yaml_text
    assert UNTESTED_SUFFIX in yaml_text
    assert "AUTO" in yaml_text
    # untested openvpn excluded from url-test list (only ss in AUTO proxies line after AUTO:)
    assert "PUB-ss" in yaml_text
