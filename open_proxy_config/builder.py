"""Main build orchestration."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from open_proxy_config.output.merge import build_mihomo_config, build_provider_yaml
from open_proxy_config.safety.http_client import HttpSettings, SafeHttpClient
from open_proxy_config.sources.aggregator import AggregatorSource
from open_proxy_config.sources.vpngate import VPNGateSource
from open_proxy_config.sources.warp import WarpSource
from open_proxy_config.util.dedupe import dedupe_proxies
from open_proxy_config.util.metrics import count_by_type
from open_proxy_config.util.untested import apply_untested_name_suffix, remap_name_lists
from open_proxy_config.validation.l1_syntax import filter_valid_proxies
from open_proxy_config.validation.mihomo_runner import (
    ensure_mihomo,
    l3_test_proxies,
    mihomo_config_test,
)


@dataclass
class BuildReport:
    sources: dict[str, dict[str, Any]] = field(default_factory=dict)
    l1_dropped: int = 0
    l3_stats: dict[str, Any] = field(default_factory=dict)
    output_written: bool = False
    kept_previous: bool = False
    errors: list[str] = field(default_factory=list)


def _load_previous_proxies(state_file: Path) -> list[dict[str, Any]] | None:
    if not state_file.is_file():
        return None
    try:
        data = json.loads(state_file.read_text(encoding="utf-8"))
        proxies = data.get("proxies")
        if isinstance(proxies, list) and proxies:
            return proxies
    except (json.JSONDecodeError, OSError):
        return None
    return None


def _save_state(state_file: Path, proxies: list[dict[str, Any]], report: BuildReport) -> None:
    state_file.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "proxies": proxies,
        "report": {
            "sources": report.sources,
            "l3_stats": report.l3_stats,
        },
    }
    state_file.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def run_build(config: dict[str, Any]) -> BuildReport:
    report = BuildReport()
    out_dir = Path(config.get("output_dir", "./dist"))
    state_file = Path(config.get("previous_state_file", out_dir / ".state.json"))
    http_cfg = config.get("http", {})
    client = SafeHttpClient(
        HttpSettings(
            timeout_seconds=float(http_cfg.get("timeout_seconds", 30)),
            max_body_bytes=int(http_cfg.get("max_body_bytes", 10 * 1024 * 1024)),
            rate_limit_per_host_per_minute=int(
                http_cfg.get("rate_limit_per_host_per_minute", 30)
            ),
        )
    )
    sources_cfg = config.get("sources", {})
    all_by_source: dict[str, list[dict[str, Any]]] = {}
    by_source_names: dict[str, list[str]] = {}

    if sources_cfg.get("vpngate", {}).get("enabled", True):
        vg = sources_cfg.get("vpngate", {})
        src = VPNGateSource(
            client,
            api_url=vg.get("api_url", "https://www.vpngate.net/api/iphone/"),
            max_nodes=int(vg.get("max_nodes", 50)),
            emit_ovpn_dir=bool(vg.get("emit_ovpn_dir", True)),
        )
        res = src.fetch()
        report.sources["vpngate"] = {
            "fetched": len(res.proxies),
            "count": len(res.proxies),
            "parsed_by_type": count_by_type(res.proxies),
            "errors": res.errors,
        }
        if res.extras.get("ovpn_files"):
            ovpn_dir = out_dir / "ovpn"
            ovpn_dir.mkdir(parents=True, exist_ok=True)
            for name, content in res.extras["ovpn_files"].items():
                (ovpn_dir / name).write_text(content, encoding="utf-8")
        all_by_source["vpngate"] = res.proxies

    if sources_cfg.get("warp", {}).get("enabled", True):
        w = sources_cfg.get("warp", {})
        src = WarpSource(
            output_dir=str(out_dir),
            register_if_missing=bool(w.get("register_if_missing", True)),
            endpoint_host=w.get("endpoint_host", "162.159.123.1"),
            endpoint_port=int(w.get("endpoint_port", 2408)),
            client_ipv4=w.get("client_ipv4", "172.16.0.2"),
        )
        res = src.fetch()
        report.sources["warp"] = {
            "fetched": len(res.proxies),
            "count": len(res.proxies),
            "parsed_by_type": count_by_type(res.proxies),
            "errors": res.errors,
        }
        all_by_source["warp"] = res.proxies

    if sources_cfg.get("aggregator", {}).get("enabled", True):
        a = sources_cfg.get("aggregator", {})
        src = AggregatorSource(
            client,
            urls=list(a.get("urls", [])),
            max_nodes_per_url=int(a.get("max_nodes_per_url", 200)),
        )
        res = src.fetch()
        report.sources["aggregator"] = {
            "fetched": len(res.proxies),
            "count": len(res.proxies),
            "parsed_by_type": count_by_type(res.proxies),
            "errors": res.errors,
        }
        all_by_source["aggregator"] = res.proxies

    merged: list[dict[str, Any]] = []
    for src_id, proxies in all_by_source.items():
        good, _ = filter_valid_proxies(proxies)
        report.l1_dropped += len(proxies) - len(good)
        report.sources[src_id]["l1_passed"] = len(good)
        report.sources[src_id]["l1_passed_by_type"] = count_by_type(good)
        merged.extend(good)
        by_source_names[src_id] = [p["name"] for p in good]

    merged = dedupe_proxies(merged)

    val_cfg = config.get("validation", {})
    if val_cfg.get("enabled", True) and merged:
        cache = out_dir / ".mihomo-cache"
        merged, l3_stats = l3_test_proxies(
            merged,
            mihomo_version=str(val_cfg.get("mihomo_version", "v1.19.32")),
            cache_dir=str(cache),
            test_url=str(val_cfg.get("test_url", "https://www.gstatic.com/generate_204")),
            concurrency=int(val_cfg.get("concurrency", 8)),
            timeout_seconds=int(val_cfg.get("test_timeout_seconds", 25)),
            skip_openvpn=bool(val_cfg.get("skip_openvpn_l3", True)),
            openvpn_l3_max=int(val_cfg.get("openvpn_l3_max", 0)),
        )
        report.l3_stats = l3_stats
        untested_raw = set(l3_stats.get("untested_l3_names") or [])
        if untested_raw:
            renamed = apply_untested_name_suffix(merged, untested_raw)
            remap_name_lists(by_source_names, renamed)
            openvpn_untested_final = [
                p["name"] for p in merged if p.get("type") == "openvpn" and p["name"].endswith(" [未测速]")
            ]
            report.l3_stats["openvpn_untested_marked"] = len(openvpn_untested_final)
        else:
            openvpn_untested_final = []
        names_set = {p["name"] for p in merged}
        for src_id in list(by_source_names.keys()):
            by_source_names[src_id] = [n for n in by_source_names[src_id] if n in names_set]
            l3_tested = [
                p
                for p in merged
                if p["name"] in set(by_source_names[src_id])
                and p["name"] not in set(openvpn_untested_final)
            ]
            report.sources[src_id]["passed_l3"] = len(l3_tested)
            report.sources[src_id]["l3_untested"] = len(
                [n for n in by_source_names[src_id] if n in openvpn_untested_final]
            )
            report.sources[src_id]["l3_passed_by_type"] = count_by_type(l3_tested)
    else:
        openvpn_untested_final = []

    previous = _load_previous_proxies(state_file)
    if not merged:
        if previous:
            merged = previous
            report.kept_previous = True
            report.errors.append("no nodes passed; kept previous snapshot")
        else:
            report.errors.append("no nodes available and no previous snapshot")
            return report

    merge_rules = list(config.get("merge", {}).get("rules", []))
    mihomo_yaml = build_mihomo_config(
        merged,
        by_source=by_source_names,
        rules=merge_rules,
        openvpn_untested_names=openvpn_untested_final if val_cfg.get("enabled", True) else [],
    )
    provider_yaml = build_provider_yaml(merged)

    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "mihomo.yaml").write_text(mihomo_yaml, encoding="utf-8")
    (out_dir / "provider.yaml").write_text(provider_yaml, encoding="utf-8")
    _save_state(state_file, merged, report)
    report.output_written = True

    # Final syntax check on full config
    if val_cfg.get("enabled", True):
        try:
            bin_path = ensure_mihomo(
                str(val_cfg.get("mihomo_version", "v1.19.32")), out_dir / ".mihomo-cache"
            )
            import tempfile

            with tempfile.TemporaryDirectory() as td:
                cfg = Path(td) / "mihomo.yaml"
                cfg.write_text(mihomo_yaml, encoding="utf-8")
                ok, log = mihomo_config_test(bin_path, cfg)
                report.l3_stats["full_config_test"] = ok
                if not ok:
                    report.errors.append(f"full config test failed: {log[:500]}")
        except Exception as e:
            report.errors.append(f"mihomo test: {e}")

    return report
