"""Download pinned Mihomo and run L3 HTTPS forwarding tests."""

from __future__ import annotations

import json
import os
import platform
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

import yaml

MIHOMO_RELEASE_BASE = (
    "https://github.com/MetaCubeX/mihomo/releases/download/{version}/"
)


def mihomo_asset_name(version: str) -> str:
    arch = platform.machine().lower()
    if arch in ("x86_64", "amd64"):
        arch_tag = "amd64"
    elif arch in ("aarch64", "arm64"):
        arch_tag = "arm64"
    else:
        arch_tag = "amd64"
    system = platform.system().lower()
    if system == "linux":
        return f"mihomo-linux-{arch_tag}-{version}.gz"
    if system == "darwin":
        return f"mihomo-darwin-{arch_tag}-{version}.gz"
    return f"mihomo-linux-{arch_tag}-{version}.gz"


def ensure_mihomo(version: str, cache_dir: str | Path) -> Path:
    cache = Path(cache_dir)
    cache.mkdir(parents=True, exist_ok=True)
    binary = cache / f"mihomo-{version}"
    if binary.is_file() and os.access(binary, os.X_OK):
        return binary
    asset = mihomo_asset_name(version)
    url = MIHOMO_RELEASE_BASE.format(version=version) + asset
    gz_path = cache / asset
    if not gz_path.is_file():
        urllib.request.urlretrieve(url, gz_path)
    import gzip

    with gzip.open(gz_path, "rb") as f_in:
        data = f_in.read()
    binary.write_bytes(data)
    binary.chmod(0o755)
    return binary


def write_minimal_config(
    path: Path,
    proxies: list[dict[str, Any]],
    test_url: str,
    *,
    controller_port: int = 19090,
    mixed_port: int = 17890,
) -> None:
    names = [p["name"] for p in proxies]
    doc = {
        "mixed-port": mixed_port,
        "allow-lan": False,
        "mode": "rule",
        "log-level": "error",
        "external-controller": f"127.0.0.1:{controller_port}",
        "proxies": proxies,
        "proxy-groups": [
            {
                "name": "AUTO",
                "type": "url-test",
                "proxies": names,
                "url": test_url,
                "interval": 300,
                "tolerance": 50,
            }
        ],
        "rules": ["MATCH,AUTO"],
    }
    path.write_text(yaml.dump(doc, allow_unicode=True, sort_keys=False), encoding="utf-8")


def mihomo_config_test(binary: Path, config_path: Path) -> tuple[bool, str]:
    proc = subprocess.run(
        [str(binary), "-t", "-f", str(config_path)],
        capture_output=True,
        text=True,
        timeout=120,
    )
    ok = proc.returncode == 0
    out = (proc.stdout or "") + (proc.stderr or "")
    return ok, out


def _wait_port(host: str, port: int, timeout: float = 15.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=1):
                return True
        except OSError:
            time.sleep(0.2)
    return False


def _proxy_delay_ms(
    controller_port: int, proxy_name: str, test_url: str, timeout_ms: int
) -> int | None:
    enc_name = urllib.parse.quote(proxy_name, safe="")
    url = (
        f"http://127.0.0.1:{controller_port}/proxies/{enc_name}/delay"
        f"?url={urllib.parse.quote(test_url, safe='')}&timeout={timeout_ms}"
    )
    try:
        with urllib.request.urlopen(url, timeout=timeout_ms / 1000 + 5) as resp:
            data = json.loads(resp.read().decode())
        delay = data.get("delay")
        if isinstance(delay, int) and delay > 0:
            return delay
    except (urllib.error.URLError, json.JSONDecodeError, TimeoutError, OSError):
        return None
    return None


def l3_test_proxies(
    proxies: list[dict[str, Any]],
    *,
    mihomo_version: str,
    cache_dir: str,
    test_url: str,
    concurrency: int,
    timeout_seconds: int,
    skip_openvpn: bool = True,
    openvpn_l3_max: int = 0,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    stats: dict[str, Any] = {
        "tested": 0,
        "passed": 0,
        "failed": 0,
        "skipped_openvpn": 0,
        "openvpn_l3_attempted": 0,
        "l3_method": "mihomo_delay_api",
        "passed_by_type": {},
        "failed_by_type": {},
        "untested_l3_names": [],
    }
    binary = ensure_mihomo(mihomo_version, cache_dir)
    passed: list[dict[str, Any]] = []
    to_test: list[dict[str, Any]] = []
    openvpn_l3_count = 0

    def _bump(bucket: dict[str, int], typ: str) -> None:
        bucket[typ] = bucket.get(typ, 0) + 1

    for p in proxies:
        typ = str(p.get("type", "unknown"))
        if p.get("type") == "openvpn":
            if skip_openvpn:
                stats["skipped_openvpn"] += 1
                stats["untested_l3_names"].append(p["name"])
                passed.append(p)
                continue
            if openvpn_l3_max > 0 and openvpn_l3_count >= openvpn_l3_max:
                stats["skipped_openvpn"] += 1
                stats["untested_l3_names"].append(p["name"])
                passed.append(p)
                continue
            openvpn_l3_count += 1
            stats["openvpn_l3_attempted"] += 1
        to_test.append(p)

    batch_size = max(1, min(concurrency, 16))
    timeout_ms = int(timeout_seconds * 1000)
    controller_base = 29190
    mixed_base = 27890

    for i in range(0, len(to_test), batch_size):
        batch = to_test[i : i + batch_size]
        controller_port = controller_base + (i % 100)
        mixed_port = mixed_base + (i % 100)
        with tempfile.TemporaryDirectory() as td:
            cfg = Path(td) / "config.yaml"
            write_minimal_config(
                cfg, batch, test_url, controller_port=controller_port, mixed_port=mixed_port
            )
            ok, _ = mihomo_config_test(binary, cfg)
            if not ok:
                stats["failed"] += len(batch)
                stats["tested"] += len(batch)
                continue
            proc = subprocess.Popen(
                [str(binary), "-f", str(cfg), "-d", td],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            try:
                if not _wait_port("127.0.0.1", controller_port, timeout=20):
                    stats["failed"] += len(batch)
                    stats["tested"] += len(batch)
                    continue
                for p in batch:
                    stats["tested"] += 1
                    typ = str(p.get("type", "unknown"))
                    delay = _proxy_delay_ms(
                        controller_port, p["name"], test_url, timeout_ms
                    )
                    if delay is not None:
                        passed.append(p)
                        stats["passed"] += 1
                        _bump(stats["passed_by_type"], typ)
                    else:
                        stats["failed"] += 1
                        _bump(stats["failed_by_type"], typ)
            finally:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
    return passed, stats
