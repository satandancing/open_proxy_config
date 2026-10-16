import pytest

from open_proxy_config.sources.warp import (
    generate_warp_credentials,
    mihomo_proxy_from_warp_config,
    register_warp_device,
)


def test_generate_credentials_length() -> None:
    creds = generate_warp_credentials()
    assert len(creds["private_key"]) > 20
    assert len(creds["public_key"]) > 20


def test_mihomo_proxy_from_config() -> None:
    cfg = {
        "client_id": "+S0e",
        "interface": {"addresses": {"v4": "172.16.0.2", "v6": "2606::1"}},
        "peers": [
            {
                "public_key": "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
                "endpoint": {"host": "engage.cloudflareclient.com:2408"},
            }
        ],
    }
    p = mihomo_proxy_from_warp_config("privkey", cfg)
    assert p["type"] == "wireguard"
    assert p["server"] == "engage.cloudflareclient.com"
    import base64

    assert p["reserved"] == list(base64.b64decode("+S0e" + "=="))[:3]


@pytest.mark.integration
def test_register_warp_live() -> None:
    creds = generate_warp_credentials()
    reg = register_warp_device(creds["private_key"])
    assert reg.get("id") and reg.get("token")
    assert reg.get("config", {}).get("peers")
