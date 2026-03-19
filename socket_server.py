#!/usr/bin/env python3

from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import socketio
import uvicorn
import tempfile
import shutil
import os
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
import subprocess
import time
import asyncio
from typing import Dict, Optional
from dataclasses import dataclass

# ================= SOCKET.IO =================
sio = socketio.AsyncServer(
    async_mode='asgi',
    cors_allowed_origins='*',
    logger=True
)

fastapi_app = FastAPI(title="Vol3 Pro API v1.0")
fastapi_app.add_middleware(CORSMiddleware, allow_origins=["*"])

app = socketio.ASGIApp(sio, other_asgi_app=fastapi_app)

# ✅ GLOBAL MAIN LOOP (FIX)
MAIN_LOOP = None

@fastapi_app.on_event("startup")
async def startup_event():
    global MAIN_LOOP
    MAIN_LOOP = asyncio.get_running_loop()

# ================= CONFIG =================
PLUGINS = [
    "windows.pslist", "windows.psscan", "windows.pstree", "windows.malfind",
    "windows.netscan", "windows.cmdline", "windows.dlllist", "windows.handles"
]

CSV_MAP = {p: f"windows_{p.split('.')[-1]}.csv" for p in PLUGINS}

# ================= DATA =================
@dataclass
class AnalysisSession:
    uid: str
    mem_path: Path
    filename: str
    start_time: float
    results: Dict[str, str] = None
    client_sid: Optional[str] = None

sessions: Dict[str, AnalysisSession] = {}

# ================= THREAD-SAFE EMIT =================
def emit_safe(event, data, room):
    if MAIN_LOOP is not None:
        MAIN_LOOP.call_soon_threadsafe(
            asyncio.create_task,
            sio.emit(event, data, room=room)
        )

# ================= API =================
@fastapi_app.post("/api/v1/upload")
async def upload_file(file: UploadFile = File(...)):
    uid = f"{file.filename}_{int(time.time())}"

    tmp_path = Path(tempfile.mktemp(
        dir="/tmp",
        prefix=f"vol3_{uid}_",
        suffix=Path(file.filename).suffix
    ))

    with open(tmp_path, "wb") as f:
        shutil.copyfileobj(file.file, f)

    sessions[uid] = AnalysisSession(
        uid=uid,
        mem_path=tmp_path,
        filename=file.filename,
        start_time=time.time()
    )

    return {"success": True, "uid": uid}

# ================= SOCKET EVENTS =================
@sio.event
async def connect(sid, environ, auth):
    print(f"🔌 {sid} connected")
    await sio.emit('status', {'connected': True}, room=sid)

@sio.event
async def disconnect(sid):
    print(f"🔌 {sid} disconnected")

@sio.on('analyze:start')
async def analyze_start(sid, data):
    uid = data.get('uid')

    if uid not in sessions:
        await sio.emit('analyze:error', {'error': 'Invalid UID'}, room=sid)
        return

    session = sessions[uid]
    session.client_sid = sid

    await sio.emit('analyze:start', {'uid': uid}, room=sid)

    session.results = {}

    with ThreadPoolExecutor(max_workers=12) as executor:
        futures = [
            executor.submit(run_plugin, session.mem_path, p, sid)
            for p in PLUGINS
        ]

        completed = 0
        for f in as_completed(futures):
            name, content = f.result()
            session.results[name] = content
            completed += 1

            await sio.emit('progress:update', {
                'completed': completed,
                'total': len(PLUGINS)
            }, room=sid)

    await sio.emit('analyze:complete', {
        'uid': uid,
        'results': session.results
    }, room=sid)

# ================= PLUGIN =================
def run_plugin(mem_path: Path, plugin: str, sid: str):
    csv_name = CSV_MAP[plugin]

    emit_safe('plugin:start', {'plugin': csv_name}, sid)

    cmd = ["vol", "-f", str(mem_path), "-r", "csv", plugin]
    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode == 0:
        content = result.stdout
        emit_safe('plugin:done', {'plugin': csv_name}, sid)
    else:
        content = result.stderr
        emit_safe('plugin:error', {'plugin': csv_name}, sid)

    return csv_name, content

# ================= HEALTH =================
@fastapi_app.get("/health")
async def health():
    return {"status": "ok", "sessions": len(sessions)}

# ================= RUN =================
if __name__ == "__main__":
    print("🚀 Vol3 Server (Thread-Safe + Fixed)")
    uvicorn.run(app, host="0.0.0.0", port=8000)