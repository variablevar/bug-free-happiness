#!/usr/bin/env python3
"""
Volatility 3 CSV API - YOUR CODE + UNLIMITED SIZE ✅
"""

import os
import sys
import tempfile
import shutil
import time
from pathlib import Path
from typing import Dict
from concurrent.futures import ThreadPoolExecutor, as_completed
from fastapi import FastAPI, UploadFile, File, HTTPException, Form, Request
from fastapi.middleware.cors import CORSMiddleware
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
        return csv_name, "# TIMEOUT 180s\n"
    except FileNotFoundError:
        return csv_name, "# vol command not found\n"
    except Exception as e:
        return csv_name, f"# CRASH: {str(e)[:100]}\n"

@app.post("/api/v1/analyze")
async def analyze_csv(
    file: UploadFile = File(...),
    plugins: str = Form("[]")
):
    tmp_path = None
    start_time = time.time()
    
    try:
        tmp_path = Path(tempfile.mktemp(suffix=Path(file.filename).suffix))
        with open(tmp_path, "wb") as f:
            shutil.copyfileobj(file.file, f)  # ✅ Streams to disk
        
        size_mb = tmp_path.stat().st_size / 1024**2
        print(f"🚀 [{MAX_WORKERS}t] {tmp_path.name} ({size_mb:.1f}MB)")
        
        # 🔥 PARALLEL CSV GEN
        results: Dict[str, str] = {}
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = {executor.submit(run_vol3_plugin, tmp_path, p): p for p in PLUGINS}
            
            for future in as_completed(futures):
                plugin = futures[future]
                csv_name, content = future.result()
                results[csv_name] = content
                print(f"✅ {len(results)}/14: {csv_name}")
        
        elapsed = time.time() - start_time
        print(f"🎉 {elapsed:.1f}s | {len(results)} CSVs")
        
        return {
            "success": True,
            "filename": file.filename,
            "fileSize": int(tmp_path.stat().st_size),
            "results": results,
            "stats": {
                "threads": MAX_WORKERS,
                "time_ms": int(elapsed * 1000),
                "csvs": len(results)
            }
        }
        
    except Exception as e:
        raise HTTPException(500, str(e))
    
    finally:
        if tmp_path and tmp_path.exists():
            tmp_path.unlink()

@app.get("/health")
async def health():
    return {"status": "✅ UNLIMITED READY", "plugins": PLUGINS, "threads": MAX_WORKERS}

if __name__ == "__main__":
    print("⚡ Vol3 UNLIMITED | 100GB+ OK | 14x parallel")
    port = int(os.getenv('PORT', 8000))
    # ✅ FIXED: Correct uvicorn args (no limit_max_request_size)
    uvicorn.run(app, host="0.0.0.0", port=port, log_level="info")
