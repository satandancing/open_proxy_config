from open_proxy_config.sources.vpngate import VPNGateSource
from open_proxy_config.safety.http_client import SafeHttpClient


SAMPLE_CSV = """*vpn_servers
HostName,IP,Score,Ping,Speed,CountryLong,CountryShort,Sess,Uptime,Users,Traffic,LogType,Operator,Message,OpenVPN_TCP_Config,OpenVPN_UDP_Config
vpn123,1.2.3.4,100,10,100,Japan,JP,1,1,1,1,2weeks,op,msg,,
"""


def test_vpngate_parse_empty_config_skipped(monkeypatch) -> None:
    class FakeClient:
        def get(self, url):
            return SAMPLE_CSV.encode()

    src = VPNGateSource(FakeClient(), "https://example.com/api", max_nodes=5)
    res = src.fetch()
    assert res.proxies == []
