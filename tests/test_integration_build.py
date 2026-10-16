import json
import os
from pathlib import Path

import pytest
import yaml

from open_proxy_config.builder import run_build
from open_proxy_config.validation.mihomo_runner import ensure_mihomo, mihomo_config_test


@pytest.mark.integration
def test_live_build_and_mihomo_test(tmp_path: Path) -> None:
    cfg = {
        "output_dir": str(tmp_path / "dist"),
        "previous_state_file": str(tmp_path / "dist" / ".state.json"),
        "http": {"timeout_seconds": 45, "max_body_bytes": 5_000_000, "rate_limit_per_host_per_minute": 60},
        "validation": {
            "enabled": True,
            "mihomo_version": "v1.19.32",
            "concurrency": 3,
            "test_timeout_seconds": 15,
            "skip_openvpn_l3": True,
        },
        "sources": {
            "vpngate": {"enabled": True, "max_nodes": 5, "emit_ovpn_dir": False},
            "warp": {"enabled": True, "register_if_missing": True},
            "aggregator": {"enabled": False, "urls": []},
        },
        "merge": {"rules": []},
    }
    report = run_build(cfg)
    out = tmp_path / "dist" / "mihomo.yaml"
    assert out.is_file(), report.errors
    data = yaml.safe_load(out.read_text(encoding="utf-8"))
    assert data.get("proxies")
    bin_path = ensure_mihomo("v1.19.32", tmp_path / "cache")
    ok, log = mihomo_config_test(bin_path, out)
    assert ok, log
    # Persist metrics for CI logs
    metrics = {
        "sources": report.sources,
        "l3": report.l3_stats,
        "proxy_count": len(data["proxies"]),
    }
    (tmp_path / "integration-metrics.json").write_text(json.dumps(metrics, indent=2))
    print("INTEGRATION_METRICS", json.dumps(metrics))
