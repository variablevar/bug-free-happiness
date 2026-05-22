"""
In-process GNN model scan for a single Vol3 upload_sessions folder.

Used by server.py (no subprocess). CLI scripts/vol3_model_scan.py delegates here.
"""

from __future__ import annotations

import csv
import os
import tempfile
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import analyze_binary_model
import analyze_two_model


def repo_root() -> Path:
    env = os.environ.get("DATASETS_REPO", "").strip()
    if env:
        return Path(env).resolve()
    return Path(__file__).resolve().parent


def default_model_paths(r: Path) -> tuple[Path, Path, Path]:
    out = r / "outputs"
    b = os.environ.get("MODEL_BINARY", "").strip()
    g = os.environ.get("MODEL_BENIGN", "").strip()
    m = os.environ.get("MODEL_MALWARE", "").strip()
    return (
        Path(b) if b else out / "binary_model.pt",
        Path(g) if g else out / "benign_model.pt",
        Path(m) if m else out / "malware_model.pt",
    )


def _graph_counts(pkl: Path) -> tuple[int, int]:
    try:
        import pickle  # noqa: PLC0415

        with open(pkl, "rb") as f:
            G = pickle.load(f)
        return int(G.number_of_nodes()), int(G.number_of_edges())
    except Exception:
        return 0, 0


def _write_manifest(path: Path, *, folder: str, nodes: int, edges: int) -> None:
    row = {
        "sample_id": "01",
        "folder": folder,
        "label": 0,
        "family": "upload_session",
        "benign_subtype": "",
        "label_source": "vol3_model_scan",
        "label_version": "v1",
        "reviewer_id": "",
        "reviewed_at": "",
        "feedback_state": "unreviewed",
        "curated_label": "",
        "train_eligible": "True",
        "uncertain": "False",
        "uncertain_reason": "",
        "nodes": nodes,
        "edges": edges,
        "max_score": 0,
        "attack_steps": 0,
        "injections": 0,
        "c2_conns": 0,
        "verdict": "LOW — model scan",
        "graph_attr": "",
        "label_signals_top": "",
        "label_signals_json": "{}",
    }
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(row.keys()))
        w.writeheader()
        w.writerow(row)


def run_upload_session_model_scan(session_dir: Path, body: dict[str, Any]) -> dict[str, Any]:
    """
    Run two_model or binary analysis on one upload session directory.

    body keys: mode, binary_model, benign_model, malware_model, mc_samples,
      fusion_w_binary, fusion_w_dual, fusion_w_heuristic, fusion_triage_low,
      fusion_triage_high, fusion_gate_dual_high_high, logit_clip
    """
    dump_root = session_dir.resolve()
    if not dump_root.is_dir():
        return {"success": False, "error": f"session not a directory: {dump_root}"}
    pkl = dump_root / "graph.pkl"
    if not pkl.is_file():
        return {
            "success": False,
            "error": "graph.pkl not found; run graph pipeline on this session first",
            "dump_root": str(dump_root),
        }

    folder = dump_root.name
    base_dir = dump_root.parent
    r = repo_root()
    pb, pg, pm = default_model_paths(r)
    mode = str(body.get("mode", "two_model") or "two_model").strip().lower()
    if mode not in ("two_model", "binary"):
        return {"success": False, "error": 'mode must be "two_model" or "binary"'}

    if body.get("binary_model"):
        pb = Path(str(body["binary_model"]).strip()).expanduser().resolve()
    if body.get("benign_model"):
        pg = Path(str(body["benign_model"]).strip()).expanduser().resolve()
    if body.get("malware_model"):
        pm = Path(str(body["malware_model"]).strip()).expanduser().resolve()

    for name, pth in (("binary", pb), ("benign", pg), ("malware", pm)):
        if mode == "binary" and name != "binary":
            continue
        if not pth.is_file():
            return {"success": False, "error": f"missing {name} model: {pth}"}

    nodes, edges = _graph_counts(pkl)
    fd, manifest_path = tempfile.mkstemp(prefix="vol3_scan_manifest_", suffix=".csv")
    os.close(fd)
    manifest_path = Path(manifest_path)
    out_json = tempfile.NamedTemporaryFile(prefix="vol3_scan_out_", suffix=".json", delete=False)
    out_json.close()
    out_path = Path(out_json.name)
    mc = max(1, int(body.get("mc_samples", 2) or 2))

    try:
        _write_manifest(manifest_path, folder=folder, nodes=nodes, edges=edges)
        if mode == "two_model":
            args = SimpleNamespace(
                manifest=str(manifest_path),
                base_dir=str(base_dir),
                malware_model=str(pm),
                benign_model=str(pg),
                binary_model=str(pb),
                output_json=str(out_path),
                mc_samples=mc,
                malware_ensemble_models=None,
                benign_ensemble_models=None,
                binary_ensemble_models=None,
                fusion_w_binary=float(body.get("fusion_w_binary", 0.35)),
                fusion_w_dual=float(body.get("fusion_w_dual", 0.40)),
                fusion_w_heuristic=float(body.get("fusion_w_heuristic", 0.25)),
                fusion_triage_low=float(body.get("fusion_triage_low", 0.40)),
                fusion_triage_high=float(body.get("fusion_triage_high", 0.65)),
                fusion_gate_dual_high_high=bool(body.get("fusion_gate_dual_high_high", True)),
                logit_clip=float(body.get("logit_clip", 0.0) or 0.0),
            )
            try:
                analysis = analyze_two_model.run(args)
            except SystemExit as exc:
                return {"success": False, "error": f"analyze_two_model aborted: {exc!r}"}
            except Exception as exc:
                return {"success": False, "error": f"analyze_two_model failed: {exc}"}
        else:
            args = SimpleNamespace(
                manifest=str(manifest_path),
                base_dir=str(base_dir),
                model=str(pb),
                output_json=str(out_path),
                mc_samples=mc,
                ensemble_models=None,
                max_ambiguity_width=float(body.get("max_ambiguity_width", 0.12)),
                min_ambiguity_width=float(body.get("min_ambiguity_width", 0.06)),
                logit_clip=float(body.get("logit_clip", 0.0) or 0.0),
            )
            try:
                analysis = analyze_binary_model.run(args)
            except SystemExit as exc:
                return {"success": False, "error": f"analyze_binary_model aborted: {exc!r}"}
            except Exception as exc:
                return {"success": False, "error": f"analyze_binary_model failed: {exc}"}

        return {
            "success": True,
            "dump_id": folder,
            "mode": mode,
            "manifest_folder": folder,
            "base_dir": str(base_dir),
            "analysis": analysis,
        }
    finally:
        try:
            manifest_path.unlink(missing_ok=True)
        except OSError:
            pass
        try:
            out_path.unlink(missing_ok=True)
        except OSError:
            pass
