import json
from pathlib import Path

from open_proxy_config.builder import run_build


def test_keep_previous_when_empty(tmp_path: Path) -> None:
    state = tmp_path / "dist" / ".state.json"
    state.parent.mkdir(parents=True)
    state.write_text(
        json.dumps(
            {
                "proxies": [
                    {
                        "name": "keep",
                        "type": "ss",
                        "server": "h",
                        "port": 1,
                        "cipher": "a",
                        "password": "b",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    cfg = {
        "output_dir": str(tmp_path / "dist"),
        "previous_state_file": str(state),
        "validation": {"enabled": False},
        "sources": {
            "vpngate": {"enabled": False},
            "warp": {"enabled": False},
            "aggregator": {"enabled": False, "urls": []},
        },
    }
    report = run_build(cfg)
    assert report.kept_previous
    assert (tmp_path / "dist" / "mihomo.yaml").is_file()
