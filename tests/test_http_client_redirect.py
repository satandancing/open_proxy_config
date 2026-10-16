from unittest.mock import MagicMock, patch

import pytest

from open_proxy_config.safety.http_client import SafeHttpClient


def test_blocks_redirect_to_private() -> None:
    client = SafeHttpClient()
    first = MagicMock()
    first.status = 302
    first.headers = {"Location": "http://127.0.0.1/secret"}
    first.__enter__ = lambda s: first
    first.__exit__ = MagicMock(return_value=False)
    with patch.object(client._opener, "open", return_value=first):
        with pytest.raises(ValueError, match="SSRF"):
            client.get("https://example.com/")
