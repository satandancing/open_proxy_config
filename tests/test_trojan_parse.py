from open_proxy_config.parsers.subscription import parse_trojan_uri


def test_trojan_invalid_does_not_raise() -> None:
    assert parse_trojan_uri("trojan://#bad@1.2.3.4:443#x") is None
