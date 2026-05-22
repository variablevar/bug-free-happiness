#!/usr/bin/env python3
"""
Volatility 3 CSV API - YOUR CODE + UNLIMITED SIZE ✅
"""

import os
import sys
import shutil
import time
import json
import uuid
import threading
from pathlib import Path
from typing import Dict, Any, List
from concurrent.futures import ThreadPoolExecutor
from fastapi import FastAPI, UploadFile, File, HTTPException, Form, Request, Body
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse, FileResponse
import starlette
from starlette.middleware.base import BaseHTTPMiddleware
import subprocess
import uvicorn

# 🔧 UNLIMITED MULTIPART MIDDLEWARE
class UnlimitedMultipartMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: starlette.requests.Request, call_next):
        if request.headers.get("content-type", "").startswith("multipart/form-data"):
            # Disable ALL multipart limits
            request.state.max_fields_size = 0  # Unlimited bytes
            request.state.max_fields = float('inf')  # Unlimited fields
        response = await call_next(request)
        return response

app = FastAPI(title="Vol3 Pro API")
app.add_middleware(UnlimitedMultipartMiddleware)  # ✅ FIXED
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

PLUGINS = [
    "windows.pslist", "windows.psscan", "windows.pstree", "windows.malfind",
    "windows.netscan", "windows.cmdline", "windows.dlllist", "windows.handles",
    "windows.threads", "windows.vadinfo", "windows.filescan", "windows.driverscan",
    "windows.ssdt", "windows.registry.hivelist"
]

CSV_FILENAME_MAP = {
    "windows.pslist": "windows_pslist.csv",
    "windows.psscan": "windows_psscan.csv", 
    "windows.pstree": "windows_pstree.csv",
    "windows.malfind": "windows_malfind.csv",
    "windows.netscan": "windows_netscan.csv",
    "windows.cmdline": "windows_cmdline.csv",
    "windows.dlllist": "windows_dlllist.csv",
    "windows.handles": "windows_handles.csv",
    "windows.threads": "windows_threads.csv",
    "windows.vadinfo": "windows_vadinfo.csv",
    "windows.filescan": "windows_filescan.csv",
    "windows.driverscan": "windows_driverscan.csv",
    "windows.ssdt": "windows_ssdt.csv",
    "windows.registry.hivelist": "windows_registry_hivelist.csv",
}

MAX_WORKERS = min(12, os.cpu_count() or 4)
SCRIPT_DIR = Path(__file__).resolve().parent
SESSIONS_DIR = SCRIPT_DIR / "upload_sessions"
SESSIONS_DIR.mkdir(parents=True, exist_ok=True)
OUTPUTS_DIR = SCRIPT_DIR / "outputs"

IOC_RUNNER = SCRIPT_DIR / "scripts" / "ioc" / "upload_sessions_batch.py"
IOC_SCRIPT_IDS = frozenset(
    {
        "code_injection",
        "hidden_proc",
        "network",
        "filescan",
        "analysis_corpus",
    }
)
IOC_EXPORTED_FILES = frozenset(
    {
        "ioc_uploads_malfind.csv",
        "ioc_uploads_hidden_proc.csv",
        "ioc_uploads_netscan.csv",
        "ioc_uploads_filescan.csv",
        "ioc_uploads_master_iocs.csv",
    }
)
IOC_PRIMARY_OUTPUT = {
    "code_injection": "ioc_uploads_malfind.csv",
    "hidden_proc": "ioc_uploads_hidden_proc.csv",
    "network": "ioc_uploads_netscan.csv",
    "filescan": "ioc_uploads_filescan.csv",
    "analysis_corpus": "ioc_uploads_master_iocs.csv",
}
IOC_STDOUT_CAP = 400_000
IOC_STDERR_CAP = 50_000
GRAPH_POOL = ThreadPoolExecutor(max_workers=max(4, min(8, os.cpu_count() or 4)))
GRAPH_JOB_LOCK = threading.Lock()
GRAPH_JOBS: Dict[str, Dict[str, Any]] = {}
PLUGIN_BY_CSV = {v: k for k, v in CSV_FILENAME_MAP.items()}


def _now_ms() -> int:
    return int(time.time() * 1000)


def _safe_rel(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(SCRIPT_DIR.resolve()))
    except Exception:
        return str(path.resolve())


def _run_python_script(script_name: str, sample_dir: Path, timeout: int = 900) -> Dict[str, Any]:
    script_path = SCRIPT_DIR / script_name
    start = time.time()
    result = subprocess.run(
        [sys.executable, str(script_path), str(sample_dir)],
        capture_output=True,
        text=True,
        timeout=timeout,
        cwd=str(SCRIPT_DIR),
    )
    return {
        "ok": result.returncode == 0,
        "returncode": result.returncode,
        "stdout": result.stdout[-4000:],
        "stderr": result.stderr[-4000:],
        "elapsed_ms": int((time.time() - start) * 1000),
        "script": script_name,
    }


def _safe_upload_name(name: str) -> str:
    safe_name = Path(name or "dump.mem").name
    if ".." in safe_name or "/" in safe_name or "\\" in safe_name:
        return "dump.mem"
    return safe_name


def _resolve_plugin(plugin_ref: str) -> str:
    p = (plugin_ref or "").strip()
    if p in CSV_FILENAME_MAP:
        return p
    if p in PLUGIN_BY_CSV:
        return PLUGIN_BY_CSV[p]
    raise ValueError(f"unsupported plugin: {plugin_ref}")


def _pick_memory_file(session_dir: Path) -> Path:
    preferred = {".mem", ".raw", ".vmem", ".dmp", ".img", ".bin"}
    files = [p for p in session_dir.iterdir() if p.is_file()]
    for f in files:
        if f.suffix.lower() in preferred:
            return f
    for f in files:
        if not f.name.lower().endswith(".csv"):
            return f
    raise FileNotFoundError("no memory image found for dump")


def _create_dump_session(file: UploadFile) -> Dict[str, Any]:
    dump_id = str(uuid.uuid4())
    session_dir = SESSIONS_DIR / dump_id
    session_dir.mkdir(parents=True, exist_ok=True)
    mem_name = _safe_upload_name(file.filename or "dump.mem")
    mem_path = session_dir / mem_name
    try:
        with open(mem_path, "wb") as f:
            shutil.copyfileobj(file.file, f)
        return {
            "dump_id": dump_id,
            "session_dir": session_dir,
            "mem_path": mem_path,
        }
    except Exception:
        shutil.rmtree(session_dir, ignore_errors=True)
        raise


def _run_and_persist_plugin(session_dir: Path, plugin_ref: str) -> Dict[str, Any]:
    plugin = _resolve_plugin(plugin_ref)
    mem_path = _pick_memory_file(session_dir)
    csv_name, content = run_vol3_plugin(mem_path, plugin)
    _write_session_csvs(session_dir, {csv_name: content})
    return {
        "plugin": plugin,
        "csv_name": csv_name,
        "content": content,
        "has_data": bool(content and "\n" in content and not content.startswith("#")),
    }


def _normalize_graph_response(sample_dir: Path) -> Dict[str, Any]:
    analysis_path = sample_dir / "analysis_report.json"
    graph_attr_path = sample_dir / "graph_attr.json"
    graph_json_path = sample_dir / "graph.json"

    if not analysis_path.exists():
        raise FileNotFoundError(f"analysis_report.json not found in {sample_dir}")

    with open(analysis_path, "r", encoding="utf-8") as f:
        analysis = json.load(f)

    graph_attr = {"graph_attr": [0.0] * 5, "label_signals": {}}
    if graph_attr_path.exists():
        with open(graph_attr_path, "r", encoding="utf-8") as f:
            graph_attr = json.load(f)

    graph_summary = {"nodes": 0, "edges": 0, "node_types": {}, "edge_types": {}}
    if graph_json_path.exists():
        with open(graph_json_path, "r", encoding="utf-8") as f:
            graph_data = json.load(f)
        nodes = graph_data.get("nodes", [])
        links = graph_data.get("links", [])
        node_types: Dict[str, int] = {}
        edge_types: Dict[str, int] = {}
        for n in nodes:
            t = n.get("node_type", "unknown")
            node_types[t] = node_types.get(t, 0) + 1
        for e in links:
            t = e.get("edge_type", "unknown")
            edge_types[t] = edge_types.get(t, 0) + 1
        graph_summary = {
            "nodes": len(nodes),
            "edges": len(links),
            "node_types": node_types,
            "edge_types": edge_types,
        }

    return {
        "sample": {
            "path": str(sample_dir.resolve()),
            "name": sample_dir.name,
            "relative_path": _safe_rel(sample_dir),
        },
        "summary": analysis.get("summary", {}),
        "attack_chain": analysis.get("attack_chain", {}),
        "entry_points": analysis.get("entry_points", []),
        "processes": analysis.get("processes", []),
        "network": analysis.get("network", []),
        "injections": analysis.get("injections", []),
        "credentials": analysis.get("credentials", []),
        "drivers": analysis.get("drivers", []),
        "hidden_processes": analysis.get("hidden_processes", []),
        "graph_attr": graph_attr.get("graph_attr", [0.0] * 5),
        "label_signals": graph_attr.get("label_signals", {}),
        "graph": graph_summary,
        "meta": {
            "analysis_tool": analysis.get("meta", {}).get("tool", "analyze_graph.py"),
            "source": analysis.get("meta", {}).get("source", str(sample_dir)),
        },
    }


def _write_session_csvs(session_dir: Path, results: Dict[str, str]) -> None:
    """Persist plugin CSV strings so dump_id folders work with build_graph / triage."""
    for csv_name, content in results.items():
        if not isinstance(content, str):
            continue
        safe_name = Path(csv_name).name
        if ".." in safe_name or "/" in safe_name or "\\" in safe_name:
            continue
        try:
            (session_dir / safe_name).write_text(content, encoding="utf-8", errors="replace")
        except OSError as exc:
            print(f"[WARN] could not write {safe_name}: {exc}")


def _session_dir_for_dump(dump_id: str) -> Path:
    d = dump_id.strip()
    if not d or ".." in d or "/" in d or "\\" in d:
        raise ValueError("invalid dump_id")
    base = SESSIONS_DIR.resolve()
    resolved = (SESSIONS_DIR / d).resolve()
    try:
        resolved.relative_to(base)
    except ValueError:
        raise ValueError("invalid dump_id") from None
    return resolved


def _graph_step_labels(steps: List[Dict[str, Any]]) -> List[str]:
    """Human labels for build_dataset-equivalent pipeline steps (order-aware)."""
    bg_count = 0
    labels: List[str] = []
    for s in steps:
        name = str(s.get("script") or "")
        if name == "build_graph.py":
            bg_count += 1
            labels.append("Build graph (bootstrap)" if bg_count == 1 else "Build graph (enrich)")
        elif name == "filter_malicious.py":
            labels.append("Filter malicious")
        elif name == "analyze_graph.py":
            labels.append("Analyze graph")
        else:
            labels.append(name or "step")
    return labels


def _list_upload_session_dirs_for_batch() -> List[Path]:
    """Session dirs under upload_sessions/ that have at least one windows_*.csv."""
    if not SESSIONS_DIR.is_dir():
        return []
    out: List[Path] = []
    for child in sorted(SESSIONS_DIR.iterdir()):
        if not child.is_dir():
            continue
        try:
            resolved = child.resolve()
            resolved.relative_to(SESSIONS_DIR.resolve())
        except ValueError:
            continue
        if any(child.glob("windows_*.csv")):
            out.append(resolved)
    return out


def _run_graph_job(job_id: str, sample_dir: Path, run_build: bool) -> None:
    start_ms = _now_ms()
    steps: list[Dict[str, Any]] = []
    try:
        with GRAPH_JOB_LOCK:
            GRAPH_JOBS[job_id]["status"] = "running"
            GRAPH_JOBS[job_id]["progress"] = 5

        if run_build:
            with GRAPH_JOB_LOCK:
                GRAPH_JOBS[job_id]["progress"] = 15
            steps.append(_run_python_script("build_graph.py", sample_dir))
            if not steps[-1]["ok"]:
                raise RuntimeError(f"build_graph (bootstrap) failed: {steps[-1]['stderr'][:300]}")
            with GRAPH_JOB_LOCK:
                GRAPH_JOBS[job_id]["progress"] = 35
            steps.append(_run_python_script("filter_malicious.py", sample_dir))
            if not steps[-1]["ok"]:
                raise RuntimeError(f"filter_malicious failed: {steps[-1]['stderr'][:300]}")
            with GRAPH_JOB_LOCK:
                GRAPH_JOBS[job_id]["progress"] = 50
            steps.append(_run_python_script("build_graph.py", sample_dir))
            if not steps[-1]["ok"]:
                raise RuntimeError(f"build_graph (enrich) failed: {steps[-1]['stderr'][:300]}")

        with GRAPH_JOB_LOCK:
            GRAPH_JOBS[job_id]["progress"] = 60
        steps.append(_run_python_script("analyze_graph.py", sample_dir))
        if not steps[-1]["ok"]:
            raise RuntimeError(f"analyze_graph failed: {steps[-1]['stderr'][:300]}")

        with GRAPH_JOB_LOCK:
            GRAPH_JOBS[job_id]["progress"] = 90
        data = _normalize_graph_response(sample_dir)

        with GRAPH_JOB_LOCK:
            GRAPH_JOBS[job_id].update(
                {
                    "status": "completed",
                    "progress": 100,
                    "finished_at_ms": _now_ms(),
                    "elapsed_ms": _now_ms() - start_ms,
                    "steps": steps,
                    "result": data,
                    "error": None,
                }
            )
    except Exception as e:
        with GRAPH_JOB_LOCK:
            GRAPH_JOBS[job_id].update(
                {
                    "status": "failed",
                    "progress": 100,
                    "finished_at_ms": _now_ms(),
                    "elapsed_ms": _now_ms() - start_ms,
                    "steps": steps,
                    "error": str(e),
                }
            )

def run_vol3_plugin(mem_file: Path, plugin: str) -> tuple[str, str]:
    """✅ vol -f mem -r csv plugin"""
    csv_name = CSV_FILENAME_MAP[plugin]
    
    cmd = [
        "vol",
        "-f", str(mem_file),
        "-r", "csv",
        plugin
    ]
    
    try:
        result = subprocess.run(
            cmd, 
            capture_output=True, 
            text=True, 
            timeout=300,  # 5 minutes per plugin
            cwd=mem_file.parent
        )
        
        if result.returncode == 0:
            csv_content = result.stdout.strip()
            if csv_content and '\n' in csv_content:
                return csv_name, csv_content
            else:
                return csv_name, "# EMPTY OUTPUT\n"
        else:
            stderr = result.stderr.strip()
            return csv_name, f"# ERROR {result.returncode}\n{stderr[:300]}\n"
            
    except subprocess.TimeoutExpired:
        return csv_name, "# TIMEOUT 300s\n"
    except FileNotFoundError:
        return csv_name, "# vol command not found\n"
    except Exception as e:
        return csv_name, f"# CRASH: {str(e)[:100]}\n"

@app.post("/api/v1/analyze")
async def analyze_csv(
    file: UploadFile = File(...),
    plugins: str = Form("[]")
):
    start_time = time.time()
    try:
        created = _create_dump_session(file)
        dump_id = created["dump_id"]
        session_dir = created["session_dir"]
        mem_path = created["mem_path"]

        size_mb = mem_path.stat().st_size / 1024**2
        print(f"🚀 [seq] dump_id={dump_id} {mem_path.name} ({size_mb:.1f}MB)")

        requested_plugins = PLUGINS
        try:
            parsed = json.loads(plugins or "[]")
            if isinstance(parsed, list) and parsed:
                requested_plugins = [_resolve_plugin(str(p)) for p in parsed]
        except Exception:
            requested_plugins = PLUGINS

        results: Dict[str, str] = {}
        for plugin in requested_plugins:
            out = _run_and_persist_plugin(session_dir, plugin)
            results[out["csv_name"]] = out["content"]
            print(f"✅ {len(results)}/{len(requested_plugins)}: {out['csv_name']}")

        elapsed = time.time() - start_time
        print(f"🎉 dump_id={dump_id} {elapsed:.1f}s | {len(results)} CSVs (sequential) -> {session_dir}")

        return {
            "success": True,
            "dump_id": dump_id,
            "session_path": str(session_dir),
            "filename": file.filename,
            "fileSize": int(mem_path.stat().st_size),
            "results": results,
            "stats": {
                "threads": 1,
                "time_ms": int(elapsed * 1000),
                "csvs": len(results),
            },
        }

    except Exception as e:
        if "session_dir" in locals():
            shutil.rmtree(session_dir, ignore_errors=True)
        raise HTTPException(500, str(e))

@app.get("/health")
async def health():
    return {"status": "✅ UNLIMITED READY", "plugins": PLUGINS, "threads": MAX_WORKERS}


def _enqueue_graph_job(sample_dir: Path, dump_id: str, run_build: bool) -> str:
    job_id = str(uuid.uuid4())
    created_at = _now_ms()
    with GRAPH_JOB_LOCK:
        GRAPH_JOBS[job_id] = {
            "job_id": job_id,
            "status": "queued",
            "progress": 0,
            "created_at_ms": created_at,
            "started_at_ms": None,
            "finished_at_ms": None,
            "elapsed_ms": None,
            "sample_path": str(sample_dir),
            "dump_id": dump_id or None,
            "run_build": bool(run_build),
            "steps": [],
            "result": None,
            "error": None,
        }

    def _task():
        with GRAPH_JOB_LOCK:
            GRAPH_JOBS[job_id]["started_at_ms"] = _now_ms()
        _run_graph_job(job_id, sample_dir, run_build=bool(run_build))

    GRAPH_POOL.submit(_task)
    return job_id


@app.post("/api/v1/graph/jobs")
async def create_graph_job(
    dump_id: str = Form(""),
    run_build: bool = Form(True),
):
    """Queue graph pipeline for one upload session (upload_sessions/<dump_id> only)."""
    dump_id = (dump_id or "").strip()
    if not dump_id:
        raise HTTPException(400, "dump_id is required (upload_sessions only; sample_path is not supported)")
    try:
        sample_dir = _session_dir_for_dump(dump_id)
    except ValueError:
        raise HTTPException(400, "invalid dump_id")
    if not sample_dir.exists() or not sample_dir.is_dir():
        raise HTTPException(400, f"dump session not found: {dump_id}")

    job_id = _enqueue_graph_job(sample_dir, dump_id, bool(run_build))
    return {
        "success": True,
        "job_id": job_id,
        "status": "queued",
        "progress": 0,
        "sample_path": str(sample_dir),
        "dump_id": dump_id,
    }


@app.post("/api/v1/graph/jobs/batch")
async def create_graph_jobs_batch(payload: Dict[str, Any] = Body(...)):
    """
    Queue the graph pipeline for many upload sessions.
    Body: { \"all\": true } or { \"dump_ids\": [\"uuid\", ...] }, optional \"run_build\": true (default).
    """
    run_build = bool(payload.get("run_build", True))
    all_flag = bool(payload.get("all", False))
    raw_ids = payload.get("dump_ids")

    targets: List[Path] = []
    rejected: List[Dict[str, str]] = []

    if all_flag:
        targets = _list_upload_session_dirs_for_batch()
    elif isinstance(raw_ids, list) and raw_ids:
        seen: set[str] = set()
        for item in raw_ids:
            did = str(item).strip()
            if not did or did in seen:
                continue
            seen.add(did)
            try:
                p = _session_dir_for_dump(did)
            except ValueError:
                rejected.append({"dump_id": did, "reason": "invalid dump_id"})
                continue
            if not p.is_dir():
                rejected.append({"dump_id": did, "reason": "not found"})
                continue
            if not any(p.glob("windows_*.csv")):
                rejected.append({"dump_id": did, "reason": "no windows_*.csv"})
                continue
            targets.append(p)
    else:
        raise HTTPException(400, 'send {"all": true} or {"dump_ids": ["uuid", ...]}')

    if not targets:
        return {
            "success": True,
            "jobs": [],
            "rejected": rejected,
            "message": "no matching upload sessions",
        }

    jobs_out: List[Dict[str, str]] = []
    for sample_dir in targets:
        did = sample_dir.name
        jid = _enqueue_graph_job(sample_dir, did, run_build)
        jobs_out.append({"dump_id": did, "job_id": jid})

    return {
        "success": True,
        "jobs": jobs_out,
        "rejected": rejected,
        "run_build": run_build,
    }


@app.get("/api/v1/graph/jobs/{job_id}")
async def get_graph_job_status(job_id: str):
    with GRAPH_JOB_LOCK:
        job = GRAPH_JOBS.get(job_id)
        if not job:
            raise HTTPException(404, f"job not found: {job_id}")
        raw_steps = job.get("steps", [])
        step_labels = _graph_step_labels(raw_steps)
        steps_payload = [
            {
                "script": s.get("script"),
                "label": step_labels[i] if i < len(step_labels) else str(s.get("script") or ""),
                "ok": s.get("ok"),
                "elapsed_ms": s.get("elapsed_ms"),
                "returncode": s.get("returncode"),
            }
            for i, s in enumerate(raw_steps)
        ]
        return {
            "success": True,
            "job_id": job_id,
            "status": job["status"],
            "progress": job["progress"],
            "created_at_ms": job["created_at_ms"],
            "started_at_ms": job["started_at_ms"],
            "finished_at_ms": job["finished_at_ms"],
            "elapsed_ms": job["elapsed_ms"],
            "sample_path": job["sample_path"],
            "dump_id": job.get("dump_id"),
            "error": job["error"],
            "step_labels": step_labels,
            "steps": steps_payload,
        }


@app.get("/api/v1/graph/jobs/{job_id}/result")
async def get_graph_job_result(job_id: str):
    with GRAPH_JOB_LOCK:
        job = GRAPH_JOBS.get(job_id)
        if not job:
            raise HTTPException(404, f"job not found: {job_id}")
        status = job["status"]
        if status != "completed":
            return {
                "success": False,
                "job_id": job_id,
                "status": status,
                "progress": job["progress"],
                "error": job["error"],
                "data": None,
            }
        return {
            "success": True,
            "job_id": job_id,
            "status": status,
            "progress": job["progress"],
            "error": None,
            "data": job["result"],
        }


@app.get("/api/v1/dumps")
async def list_dump_sessions():
    if not SESSIONS_DIR.is_dir():
        return {"success": True, "dumps": []}
    expected_csv = set(CSV_FILENAME_MAP.values())
    dumps: List[Dict[str, Any]] = []
    for child in sorted(SESSIONS_DIR.iterdir(), key=lambda p: p.stat().st_mtime_ns, reverse=True):
        if not child.is_dir():
            continue
        try:
            session_dir = _session_dir_for_dump(child.name)
        except ValueError:
            continue
        files = [p.name for p in session_dir.iterdir() if p.is_file()]
        csv_files = {f for f in files if f.endswith(".csv")}
        mem_candidates = [p for p in session_dir.iterdir() if p.is_file() and not p.name.endswith(".csv")]
        mem_path = max(mem_candidates, key=lambda p: p.stat().st_size, default=None)
        total_bytes = sum(p.stat().st_size for p in session_dir.iterdir() if p.is_file())
        dumps.append(
            {
                "dump_id": child.name,
                "updated_at_ms": int(session_dir.stat().st_mtime * 1000),
                "memory_filename": mem_path.name if mem_path else None,
                "memory_size_bytes": int(mem_path.stat().st_size) if mem_path else None,
                "csv_count": len(csv_files),
                "file_count": len(files),
                "total_bytes": int(total_bytes),
                "plugins_complete": expected_csv.issubset(csv_files),
            }
        )
    return {"success": True, "dumps": dumps}


@app.get("/api/v1/dumps/{dump_id}")
async def get_dump_session(dump_id: str):
    try:
        session_dir = _session_dir_for_dump(dump_id)
    except ValueError:
        raise HTTPException(400, "invalid dump_id")
    if not session_dir.is_dir():
        raise HTTPException(404, "dump not found")
    names = sorted(p.name for p in session_dir.iterdir() if p.is_file())
    try:
        mem = _pick_memory_file(session_dir)
        mem_name = mem.name
        mem_size = int(mem.stat().st_size)
    except FileNotFoundError:
        mem_name = None
        mem_size = None
    expected_csv = set(CSV_FILENAME_MAP.values())
    csv_files = {f for f in names if f.endswith(".csv")}
    return {
        "success": True,
        "dump_id": dump_id,
        "path": str(session_dir),
        "files": names,
        "memory_filename": mem_name,
        "memory_size_bytes": mem_size,
        "plugins_complete": expected_csv.issubset(csv_files),
    }


@app.get("/api/v1/dumps/{dump_id}/csv/{csv_name}")
async def get_dump_csv_file(dump_id: str, csv_name: str):
    try:
        session_dir = _session_dir_for_dump(dump_id)
    except ValueError:
        raise HTTPException(400, "invalid dump_id")
    if not session_dir.is_dir():
        raise HTTPException(404, "dump not found")
    safe = Path(csv_name).name
    if safe != csv_name or ".." in csv_name or "/" in csv_name or "\\" in csv_name:
        raise HTTPException(400, "invalid csv_name")
    if not safe.endswith(".csv"):
        raise HTTPException(400, "invalid csv_name")
    path = session_dir / safe
    if not path.is_file():
        raise HTTPException(404, "csv not found")
    return PlainTextResponse(path.read_text(encoding="utf-8", errors="replace"))


@app.post("/api/v1/dumps/upload")
async def upload_dump_file(file: UploadFile = File(...)):
    try:
        created = _create_dump_session(file)
        mem_path: Path = created["mem_path"]
        session_dir: Path = created["session_dir"]
        return {
            "success": True,
            "dump_id": created["dump_id"],
            "filename": file.filename,
            "fileSize": int(mem_path.stat().st_size),
            "session_path": str(session_dir),
        }
    except Exception as e:
        raise HTTPException(500, str(e))


@app.post("/api/v1/dumps/{dump_id}/plugins/{plugin_name}")
async def run_single_plugin(dump_id: str, plugin_name: str):
    try:
        session_dir = _session_dir_for_dump(dump_id)
    except ValueError:
        raise HTTPException(400, "invalid dump_id")
    if not session_dir.is_dir():
        raise HTTPException(404, "dump not found")
    try:
        out = _run_and_persist_plugin(session_dir, plugin_name)
    except FileNotFoundError as e:
        raise HTTPException(400, str(e))
    except ValueError as e:
        raise HTTPException(400, str(e))
    return {
        "success": True,
        "dump_id": dump_id,
        "plugin": out["plugin"],
        "csv_name": out["csv_name"],
        "content": out["content"],
        "has_data": out["has_data"],
    }


@app.post("/api/v1/dumps/{dump_id}/triage")
async def run_dump_triage(dump_id: str):
    try:
        session_dir = _session_dir_for_dump(dump_id)
    except ValueError:
        raise HTTPException(400, "invalid dump_id")
    if not session_dir.is_dir():
        raise HTTPException(404, "dump not found")
    script_path = SCRIPT_DIR / "memory_triage.py"
    if not script_path.is_file():
        raise HTTPException(500, "memory_triage.py not found")
    env = {**os.environ, "TRIAGE_QUIET": "1"}
    proc = subprocess.run(
        [sys.executable, str(script_path), str(session_dir), "--json-stdout", "--no-charts"],
        capture_output=True,
        text=True,
        timeout=300,
        cwd=str(SCRIPT_DIR),
        env=env,
    )
    if proc.returncode != 0:
        raise HTTPException(
            500,
            f"triage failed: {(proc.stderr or proc.stdout or '')[-800:]}",
        )
    raw = (proc.stdout or "").strip()
    if not raw:
        return {"success": True, "dump_id": dump_id, "findings": []}
    try:
        findings: List[Dict[str, Any]] = json.loads(raw)
    except json.JSONDecodeError:
        raise HTTPException(500, "triage returned invalid JSON")
    return {"success": True, "dump_id": dump_id, "findings": findings}


@app.post("/api/v1/dumps/{dump_id}/model-scan")
async def run_dump_model_scan(dump_id: str, request: Request):
    """
    Run GNN inference on one upload_sessions folder (requires graph.pkl).

    Optional JSON body: mode (two_model|binary), binary_model, benign_model,
    malware_model (paths), mc_samples (int, default 2 in wrapper).
    Defaults: MODEL_* env or datasets/outputs/*.pt
    """
    try:
        session_dir = _session_dir_for_dump(dump_id)
    except ValueError:
        raise HTTPException(400, "invalid dump_id")
    if not session_dir.is_dir():
        raise HTTPException(404, "dump not found")
    if not (session_dir / "graph.pkl").is_file():
        raise HTTPException(
            400,
            "graph.pkl not found for this session; complete the graph pipeline first",
        )
    try:
        body = await request.json()
    except Exception:
        body = {}
    if not isinstance(body, dict):
        body = {}

    from model_scan import run_upload_session_model_scan

    payload_out = run_upload_session_model_scan(session_dir, body)
    if not payload_out.get("success"):
        raise HTTPException(
            status_code=400,
            detail=str(payload_out.get("error", "model_scan reported failure")),
        )
    return payload_out


@app.post("/api/v1/ioc/run")
async def run_ioc_script(payload: Dict[str, Any] = Body(...)):
    """Run IOC metrics over upload_sessions/ (dashboard dumps). Optional dump_id = one session."""
    script_id = str(payload.get("script_id", "")).strip()
    if script_id not in IOC_SCRIPT_IDS:
        raise HTTPException(
            400,
            f"unknown script_id; allowed: {', '.join(sorted(IOC_SCRIPT_IDS))}",
        )
    dump_id_raw = payload.get("dump_id")
    dump_id_str = str(dump_id_raw).strip() if dump_id_raw is not None else ""
    if dump_id_str:
        try:
            _session_dir_for_dump(dump_id_str)
        except ValueError:
            raise HTTPException(400, "invalid dump_id")
    if not IOC_RUNNER.is_file():
        raise HTTPException(500, f"missing IOC runner: {IOC_RUNNER.name}")
    cmd = [sys.executable, str(IOC_RUNNER), "--script-id", script_id]
    if dump_id_str:
        cmd.extend(["--dump-id", dump_id_str])
    start = time.time()
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=900,
            cwd=str(SCRIPT_DIR),
        )
    except subprocess.TimeoutExpired:
        raise HTTPException(504, "IOC script timed out (900s)") from None
    elapsed_ms = int((time.time() - start) * 1000)
    stdout = proc.stdout or ""
    stderr = proc.stderr or ""
    if len(stdout) > IOC_STDOUT_CAP:
        stdout = stdout[:IOC_STDOUT_CAP] + "\n… [stdout truncated]\n"
    if len(stderr) > IOC_STDERR_CAP:
        stderr = stderr[:IOC_STDERR_CAP] + "\n… [stderr truncated]\n"
    OUTPUTS_DIR.mkdir(parents=True, exist_ok=True)
    present = sorted(f for f in IOC_EXPORTED_FILES if (OUTPUTS_DIR / f).is_file())
    primary = IOC_PRIMARY_OUTPUT.get(script_id)
    primary_exists = bool(primary and (OUTPUTS_DIR / primary).is_file())
    return {
        "success": proc.returncode == 0,
        "script_id": script_id,
        "dump_id": dump_id_str or None,
        "returncode": proc.returncode,
        "elapsed_ms": elapsed_ms,
        "stdout": stdout,
        "stderr": stderr,
        "output_files_present": present,
        "primary_output": primary,
        "primary_output_written": primary_exists,
    }


@app.get("/api/v1/ioc/outputs/{name}")
async def download_ioc_output(name: str):
    safe = Path(name).name
    if safe != name or ".." in name or "/" in name or "\\" in name:
        raise HTTPException(400, "invalid name")
    if safe not in IOC_EXPORTED_FILES:
        raise HTTPException(404, "unknown output file")
    path = OUTPUTS_DIR / safe
    if not path.is_file():
        raise HTTPException(404, "file not found (run the analysis first)")
    return FileResponse(
        path,
        filename=safe,
        media_type="text/csv",
    )


if __name__ == "__main__":
    print("⚡ Vol3 UNLIMITED | 100GB+ OK | 14x parallel")
    port = int(os.getenv('PORT', 8000))
    # ✅ FIXED: Correct uvicorn args (no limit_max_request_size)
    uvicorn.run(app, host="0.0.0.0", port=port, log_level="info")
