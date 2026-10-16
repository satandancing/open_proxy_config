import json
import shutil
from pathlib import Path

import pytest
import yaml

from open_proxy_config.builder import run_build
from open_proxy_config.config_loader import load_config
from open_proxy_config.sources.aggregator import AggregatorSource
from open_proxy_config.safety.http_client import SafeHttpClient
from open_proxy_config.sources.vpngate import VPNGateSource
from open_proxy_config.sources.warp import WarpSource, register_warp_device, generate_warp_credentials
from open_proxy_config.util.metrics import count_by_type
from open_proxy_config.validation.l1_syntax import filter_valid_proxies
from open_proxy_config.validation.mihomo_runner import (
    ensure_mihomo,
    l3_test_proxies,
    mihomo_config_test,
)


def _example_aggregator_urls() -> list[str]:
    cfg = load_config(Path(__file__).resolve().parents[1] / "config.example.yaml")
    return list(cfg["sources"]["aggregator"]["urls"])


def _integration_cfg(tmp_path: Path, **validation_overrides) -> dict:
    val = {
        "enabled": True,
        "mihomo_version": "v1.19.32",
        "concurrency": 4,
        "test_timeout_seconds": 20,
        "skip_openvpn_l3": True,
        "openvpn_l3_max": 0,
    }
    val.update(validation_overrides)
    return {
        "output_dir": str(tmp_path / "dist"),
        "previous_state_file": str(tmp_path / "dist" / ".state.json"),
        "http": {
            "timeout_seconds": 45,
            "max_body_bytes": 8_000_000,
            "rate_limit_per_host_per_minute": 60,
        },
        "validation": val,
        "sources": {
            "vpngate": {"enabled": True, "max_nodes": 8, "emit_ovpn_dir": False},
            "warp": {"enabled": True, "register_if_missing": True},
            "aggregator": {
                "enabled": True,
                "urls": _example_aggregator_urls(),
                "max_nodes_per_url": 25,
            },
        },
        "merge": {"rules": []},
    }


@pytest.mark.integration
def test_full_pipeline_with_aggregator_l3(tmp_path: Path) -> None:
    report = run_build(_integration_cfg(tmp_path))
    out = tmp_path / "dist" / "mihomo.yaml"
    assert out.is_file(), report.errors
    data = yaml.safe_load(out.read_text(encoding="utf-8"))
    assert data.get("proxies")
    bin_path = ensure_mihomo("v1.19.32", tmp_path / "cache")
    ok, log = mihomo_config_test(bin_path, out)
    assert ok, log
    metrics = {
        "sources": report.sources,
        "l3": report.l3_stats,
        "proxy_count": len(data["proxies"]),
        "errors": report.errors,
    }
    print("INTEGRATION_METRICS", json.dumps(metrics, ensure_ascii=False))
    (tmp_path / "integration-metrics.json").write_text(
        json.dumps(metrics, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    assert report.sources["aggregator"]["fetched"] > 0
    assert report.sources["aggregator"].get("passed_l3", 0) >= 0


@pytest.mark.integration
def test_warp_registration_and_l3(tmp_path: Path) -> None:
    creds = generate_warp_credentials()
    reg = register_warp_device(creds["private_key"])
    src = WarpSource(output_dir=str(tmp_path / "warp"), register_if_missing=True)
    # inject fresh account via env-less state file
    state = {
        "private_key": creds["private_key"],
        "device_id": reg["id"],
        "access_token": reg["token"],
    }
    warp_dir = tmp_path / "warp"
    warp_dir.mkdir(parents=True, exist_ok=True)
    (warp_dir / ".warp-account.json").write_text(json.dumps(state), encoding="utf-8")
    res = src.fetch()
    assert res.proxies, res.errors
    passed, stats = l3_test_proxies(
        res.proxies,
        mihomo_version="v1.19.32",
        cache_dir=str(tmp_path / "cache"),
        test_url="https://www.gstatic.com/generate_204",
        concurrency=1,
        timeout_seconds=25,
        skip_openvpn=True,
    )
    print(
        "WARP_L3",
        json.dumps(
            {
                "registration_id": reg["id"],
                "proxy": {k: res.proxies[0].get(k) for k in ("server", "port", "ip", "reserved")},
                "l3_stats": stats,
                "passed": len(passed),
            }
        ),
    )
    assert len(passed) == 1, stats


@pytest.mark.integration
def test_vpngate_openvpn_l3_sample(tmp_path: Path) -> None:
    client = SafeHttpClient()
    vg = VPNGateSource(client, "https://www.vpngate.net/api/iphone/", max_nodes=6)
    res = vg.fetch()
    assert res.proxies
    good, _ = filter_valid_proxies(res.proxies)
    sample = [p for p in good if p.get("type") == "openvpn"][:3]
    assert len(sample) >= 1
    passed, stats = l3_test_proxies(
        sample,
        mihomo_version="v1.19.32",
        cache_dir=str(tmp_path / "cache"),
        test_url="https://www.gstatic.com/generate_204",
        concurrency=1,
        timeout_seconds=60,
        skip_openvpn=False,
        openvpn_l3_max=3,
    )
    print(
        "OPENVPN_L3",
        json.dumps(
            {
                "attempted": stats.get("openvpn_l3_attempted"),
                "passed": len(passed),
                "failed_by_type": stats.get("failed_by_type"),
                "passed_by_type": stats.get("passed_by_type"),
                "names_passed": [p["name"] for p in passed],
            }
        ),
    )


@pytest.mark.integration
def test_aggregator_parse_counts(tmp_path: Path) -> None:
    client = SafeHttpClient()
    src = AggregatorSource(client, _example_aggregator_urls(), max_nodes_per_url=40)
    res = src.fetch()
    good, _ = filter_valid_proxies(res.proxies)
    print(
        "AGGREGATOR_PARSE",
        json.dumps(
            {
                "fetched": len(res.proxies),
                "l1_passed": len(good),
                "by_type": count_by_type(good),
                "errors": res.errors,
            }
        ),
    )
    assert len(res.proxies) > 0
    assert len(good) > 0


@pytest.mark.integration
def test_workflow_build_dist_and_keep_previous(tmp_path: Path) -> None:
    cfg_path = tmp_path / "config.yaml"
    shutil.copy(
        Path(__file__).resolve().parents[1] / "config.example.yaml",
        cfg_path,
    )
    cfg = load_config(cfg_path)
    cfg["output_dir"] = str(tmp_path / "dist")
    cfg["previous_state_file"] = str(tmp_path / "dist" / ".state.json")
    cfg["validation"]["concurrency"] = 3
    cfg["sources"]["vpngate"]["max_nodes"] = 5
    cfg["sources"]["aggregator"]["max_nodes_per_url"] = 15
    report = run_build(cfg)
    dist = tmp_path / "dist"
    assert (dist / "mihomo.yaml").is_file()
    assert (dist / "provider.yaml").is_file()
    assert report.output_written
    # simulate failed build: disable all sources
    cfg_fail = dict(cfg)
    cfg_fail["sources"] = {
        "vpngate": {"enabled": False},
        "warp": {"enabled": False},
        "aggregator": {"enabled": False, "urls": []},
    }
    cfg_fail["validation"] = {"enabled": False}
    report2 = run_build(cfg_fail)
    assert report2.kept_previous
    assert (dist / "mihomo.yaml").is_file()
    publish = tmp_path / "publish"
    publish.mkdir()
    shutil.copy(dist / "mihomo.yaml", publish / "mihomo.yaml")
    shutil.copy(dist / "provider.yaml", publish / "provider.yaml")
    print(
        "WORKFLOW_SIM",
        json.dumps(
            {
                "first_build_proxies": len(yaml.safe_load((dist / "mihomo.yaml").read_text())["proxies"]),
                "kept_previous": report2.kept_previous,
                "publish_files": sorted(p.name for p in publish.iterdir()),
            }
        ),
    )
