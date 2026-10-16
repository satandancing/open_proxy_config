import pytest

from open_proxy_config.safety.http_client import is_safe_url


@pytest.mark.parametrize(
    "url,ok",
    [
        ("https://example.com/path", True),
        ("http://127.0.0.1/", False),
        ("http://localhost/", False),
        ("http://192.168.1.1/", False),
        ("http://10.0.0.1/", False),
        ("file:///etc/passwd", False),
        ("ftp://example.com/", False),
    ],
)
def test_is_safe_url(url: str, ok: bool) -> None:
    assert is_safe_url(url) is ok
