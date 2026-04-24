"""
IOC-style metrics for a single sample directory (e.g. upload_sessions/<dump_id>).
Reuses the same heuristics as scripts/ioc corpus tools, without WithVirus/NoVirus pairing.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, List, Optional

import pandas as pd

from ioc_analysis.csv_loader import load_windows_plugin_csv

SUSP_PATH_PATTERNS = [
    r".*\\temp\\.*\.exe",
    r".*\\appdata\\.*\.exe",
    r".*\\windows\\temp\\",
    r"readme\.txt",
    r"\.crypt",
    r"\.locked",
    r"!!!_DECRYPT_!!!",
    r"wanacry",
    r"\.scr$",
    r"\.pif$",
    r"decrypt\.html",
]
TEMP_EXE_PATTERN = re.compile(
    r"(temp|appdata|windows\\temp).*(\.exe|\.scr|\.pif|\.dll)$", re.IGNORECASE
)


def _pid_set(csv_path: Path) -> set:
    if not csv_path.exists():
        return set()
    try:
        return set(pd.read_csv(csv_path)["PID"].astype(str))
    except Exception:
        return set()


def detect_hidden_processes(img_dir: Path) -> Dict[str, Any]:
    pslist_pids = _pid_set(img_dir / "windows_pslist.csv")
    psscan_pids = _pid_set(img_dir / "windows_psscan.csv")
    hidden_pids = psscan_pids - pslist_pids
    suspicious_names: List[str] = []
    csv = img_dir / "windows_psscan.csv"
    if hidden_pids and csv.exists():
        try:
            df = pd.read_csv(csv)
            hidden = df[df["PID"].astype(str).isin(hidden_pids)]
            suspicious_names = hidden["ImageFileName"].dropna().unique().tolist()
        except Exception:
            pass
    return {
        "hidden_count": len(hidden_pids),
        "total_psscan": len(psscan_pids),
        "total_pslist": len(pslist_pids),
        "hidden_names": ", ".join(str(x) for x in suspicious_names[:5]),
    }


def load_netscan_metrics(img_dir: Path) -> Dict[str, Any]:
    csv_file = img_dir / "windows_netscan.csv"
    if not csv_file.exists():
        return {"connections": 0, "susp_ports": 0, "c2_hits": 0}
    try:
        df = pd.read_csv(csv_file)
    except Exception:
        return {"connections": 0, "susp_ports": 0, "c2_hits": 0}
    suspicious = df[
        (df["LocalPort"] > 10000)
        | (df["ForeignAddr"].str.contains(r"\.ru|\.top|\.xyz|tor|onion", na=False))
    ]
    return {
        "connections": len(df),
        "susp_ports": len(df[df["LocalPort"].isin([80, 443, 4444, 8080, 9001])]),
        "c2_hits": len(suspicious),
    }


def load_filescan_suspicious_metrics(img_dir: Path) -> Dict[str, Any]:
    csv_file = img_dir / "windows_filescan.csv"
    if not csv_file.exists():
        return {"suspicious_count": 0, "deleted_count": 0, "susp_names": ""}
    try:
        df = pd.read_csv(csv_file)
    except Exception:
        return {"suspicious_count": 0, "deleted_count": 0, "susp_names": ""}
    suspicious = 0
    deleted = 0
    names: List[str] = []
    for _, row in df.iterrows():
        fname = str(row.get("Name", "")).lower()
        details = str(row.get("Details", row.get("Type", ""))).lower()
        if any(re.search(p, fname) for p in SUSP_PATH_PATTERNS) or TEMP_EXE_PATTERN.search(fname):
            suspicious += 1
            names.append(fname[:50])
        if "file_deleted" in details or "deleted" in details:
            deleted += 1
    return {
        "suspicious_count": suspicious,
        "deleted_count": deleted,
        "susp_names": ", ".join(sorted(set(names))[:6]),
    }


def malfind_row_count(img_dir: Path) -> int:
    p = img_dir / "windows_malfind.csv"
    if not p.exists():
        return 0
    try:
        return len(pd.read_csv(p))
    except Exception:
        return 0


def master_ioc_row_for_dir(img_dir: Path) -> Dict[str, Any]:
    """Single-folder analogue of analysis_corpus.py paired IOC counts."""
    pslist = load_windows_plugin_csv(img_dir, "pslist")
    psscan = load_windows_plugin_csv(img_dir, "psscan")
    malfind = load_windows_plugin_csv(img_dir, "malfind")
    filescan = load_windows_plugin_csv(img_dir, "filescan")
    susp = pd.DataFrame()
    if not filescan.empty and "Name" in filescan.columns:
        susp = filescan[filescan["Name"].str.contains(r"\.(exe|dll|pif)$", na=False)]
    hidden = detect_hidden_processes(img_dir)
    return {
        "dump_id": img_dir.name,
        "process_count": len(pslist),
        "malfind_rows": len(malfind),
        "suspicious_files": len(susp),
        "hidden_procs": int(hidden["hidden_count"]),
        "hidden_names_preview": hidden.get("hidden_names", ""),
    }


def iter_upload_session_dirs(sessions_root: Path, dump_id: Optional[str] = None) -> List[Path]:
    if not sessions_root.is_dir():
        return []
    if dump_id:
        d = dump_id.strip()
        if not d or ".." in d or "/" in d or "\\" in d:
            return []
        base = sessions_root.resolve()
        resolved = (sessions_root / d).resolve()
        try:
            resolved.relative_to(base)
        except ValueError:
            return []
        return [resolved] if resolved.is_dir() else []
    out: List[Path] = []
    for child in sorted(sessions_root.iterdir()):
        if child.is_dir() and any(child.glob("windows_*.csv")):
            out.append(child)
    return out
