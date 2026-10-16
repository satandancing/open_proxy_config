from __future__ import annotations

from open_proxy_config.parsers.subscription import parse_subscription_blob
from open_proxy_config.safety.http_client import SafeHttpClient
from open_proxy_config.sources.base import Source, SourceResult
from open_proxy_config.util.dedupe import dedupe_proxies
from open_proxy_config.util.naming import make_unique_names


class AggregatorSource(Source):
    source_id = "aggregator"

    def __init__(
        self,
        client: SafeHttpClient,
        urls: list[str],
        max_nodes_per_url: int = 200,
    ) -> None:
        self.client = client
        self.urls = urls
        self.max_nodes_per_url = max_nodes_per_url

    def fetch(self) -> SourceResult:
        result = SourceResult(source_id=self.source_id)
        all_nodes: list[dict] = []
        for url in self.urls:
            try:
                raw = self.client.get(url)
            except Exception as e:
                result.errors.append(f"{url}: {e}")
                continue
            nodes = parse_subscription_blob(raw)[: self.max_nodes_per_url]
            all_nodes.extend(nodes)
        all_nodes = dedupe_proxies(all_nodes)
        result.proxies = make_unique_names(all_nodes, prefix="PUB")
        return result
