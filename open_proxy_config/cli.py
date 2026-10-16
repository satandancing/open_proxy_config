from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from open_proxy_config.builder import run_build
from open_proxy_config.config_loader import load_config


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="open-proxy-config")
    sub = parser.add_subparsers(dest="command", required=True)
    build_p = sub.add_parser("build", help="Fetch sources, validate, write mihomo.yaml")
    build_p.add_argument(
        "-c",
        "--config",
        default="config.yaml",
        help="Path to config.yaml (default: config.yaml)",
    )
    build_p.add_argument(
        "--report-json",
        default="",
        help="Write build report JSON to this path",
    )
    args = parser.parse_args(argv)
    if args.command == "build":
        cfg_path = Path(args.config)
        if not cfg_path.is_file():
            print(f"config not found: {cfg_path}", file=sys.stderr)
            return 2
        config = load_config(cfg_path)
        report = run_build(config)
        if args.report_json:
            Path(args.report_json).write_text(
                json.dumps(report.__dict__, indent=2, default=str), encoding="utf-8"
            )
        print(json.dumps(report.__dict__, indent=2, default=str))
        return 0 if report.output_written else 1
    return 1
