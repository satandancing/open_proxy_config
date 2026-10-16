from open_proxy_config.sources.warp import build_wireguard_proxy, generate_warp_credentials


def test_generate_credentials_length() -> None:
    creds = generate_warp_credentials()
    assert len(creds["private_key"]) > 20
    assert len(creds["public_key"]) > 20


def test_build_wireguard_proxy() -> None:
    account = {"private_key": "abc", "device_id": "d", "access_token": "t"}
    p = build_wireguard_proxy(
        account, endpoint_host="1.1.1.1", endpoint_port=2408, client_ipv4="172.16.0.2"
    )
    assert p["type"] == "wireguard"
    assert p["private-key"] == "abc"
