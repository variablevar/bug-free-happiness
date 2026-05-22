#!/usr/bin/env python3
"""
CLI wrapper: Vol3 upload session → GNN model scan (stdout JSON).

Delegates to in-process model_scan.run_upload_session_model_scan (same code as server.py).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Repo root on sys.path for `import model_scan`
_SCRIPT_DIR = Path(__file__).resolve().parent.parent
if str(_SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPT_DIR))

from model_scan import run_upload_session_model_scan  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description="Vol3 upload session → GNN model scan (stdout JSON)")
    ap.add_argument("--dump-root", required=True, help="Absolute path to upload_sessions/<dump_id>")
    ap.add_argument("--mode", choices=("two_model", "binary"), default="two_model")
    ap.add_argument("--binary-model", default="", dest="binary_model")
    ap.add_argument("--benign-model", default="", dest="benign_model")
    ap.add_argument("--malware-model", default="", dest="malware_model")
    ap.add_argument("--mc-samples", type=int, default=2, dest="mc_samples")
    args = ap.parse_args()

    dump_root = Path(args.dump_root).resolve()
    body: dict = {"mode": args.mode, "mc_samples": int(args.mc_samples)}
    if args.binary_model.strip():
        body["binary_model"] = args.binary_model.strip()
    if args.benign_model.strip():
        body["benign_model"] = args.benign_model.strip()
    if args.malware_model.strip():
        body["malware_model"] = args.malware_model.strip()

    result = run_upload_session_model_scan(dump_root, body)
    print(json.dumps(result, ensure_ascii=False))
    return 0 if result.get("success") else 1


if __name__ == "__main__":
    raise SystemExit(main())
