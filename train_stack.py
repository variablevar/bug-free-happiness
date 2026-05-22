#!/usr/bin/env python3
"""Train both one-class GNN models in sequence (malware + benign)."""

import argparse
import subprocess
import sys


def run_cmd(cmd: list[str]) -> int:
    print("[TrainStack] Running:", " ".join(cmd))
    return subprocess.call(cmd)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Train malware + benign one-class GNN stack"
    )
    parser.add_argument("manifest", help="Path to dataset_manifest.csv")
    parser.add_argument("--base-dir", default=None, dest="base_dir")
    parser.add_argument(
        "--exclude-uncertain",
        action="store_true",
        dest="exclude_uncertain",
    )
    args, passthrough = parser.parse_known_args()

    py = sys.executable
    common = [args.manifest]
    if args.base_dir:
        common += ["--base-dir", args.base_dir]
    if args.exclude_uncertain:
        common += ["--exclude-uncertain"]

    rc = run_cmd([py, "train_malware_model.py", *common, *passthrough])
    if rc != 0:
        return rc

    rc = run_cmd([py, "train_benign_model.py", *common, *passthrough])
    if rc != 0:
        return rc

    print("[TrainStack] Done.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
