#!/usr/bin/env python3
"""
FAST Volatility 3 CSV Extractor (Threaded) - Fixed
"""

import os
import subprocess
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

MEM_DIR = Path("dumps")
OUT_DIR = Path("extracted_csvs")
PLUGINS = [
    "windows.info", "windows.pslist", "windows.pstree", "windows.psscan",
    "windows.cmdline", "windows.dlllist", "windows.netscan",
    "windows.registry.hivelist", "windows.services", "windows.malfind",
    "windows.ssdt", "windows.handles", "windows.filescan", "windows.threads",
    "windows.version", "windows.driverscan", "windows.vadinfo"
]

# Plugins known to be slow — give them more time
SLOW_PLUGINS = {"windows.handles", "windows.vadinfo", "windows.filescan", "windows.threads"}
DEFAULT_TIMEOUT = 60   # seconds
SLOW_TIMEOUT    = 120   # seconds

MAX_WORKERS = os.cpu_count() * 2


def find_mem_files():
    mem_files = []
    for ext in ["*.mem", "*.raw", "*.dmp", "*.bin", "*.mddramimage", "*.img", "*.vmem"]:
        mem_files.extend(MEM_DIR.glob(ext))
        mem_files.extend(MEM_DIR.rglob(ext))
    return sorted(set(mem_files))


def extract_single_plugin(mem_file: Path, plugin: str) -> tuple:
    img_name = mem_file.stem
    img_dir  = OUT_DIR / img_name
    img_dir.mkdir(parents=True, exist_ok=True)

    csv_file = img_dir / f"{plugin.replace('.', '_')}.csv"

    if csv_file.exists() and csv_file.stat().st_size > 0:
        print(f"  [skip] {plugin} (already exists)")
        return (img_name, plugin, True)

    # KEY FIX 1: -q silences progress noise from polluting CSV output
    # KEY FIX 2: write file via stdout=open() — no shell redirect conflict
    cmd = ["vol", "-q", "-f", str(mem_file), "-r", "csv", plugin]

    timeout = SLOW_TIMEOUT if plugin in SLOW_PLUGINS else DEFAULT_TIMEOUT

    try:
        with open(csv_file, "w", encoding="utf-8") as f_out:
            result = subprocess.run(
                cmd,
                stdout=f_out,          # KEY FIX 2: direct file write, no shell redirect
                stderr=subprocess.PIPE, # capture errors separately
                text=True,
                timeout=timeout         # KEY FIX 3: prevent hung threads
            )

        # Remove empty files so re-runs don't skip them
        if csv_file.stat().st_size == 0:
            csv_file.unlink()
            print(f"  [empty] {plugin} | stderr: {result.stderr.strip()[:120]}")
            return (img_name, plugin, False)

        return (img_name, plugin, True)

    except subprocess.TimeoutExpired:
        if csv_file.exists():
            csv_file.unlink()
        print(f"  [timeout] {plugin} after {timeout}s")
        return (img_name, plugin, False)

    except Exception as e:
        print(f"  [error] {plugin}: {e}")
        return (img_name, plugin, False)


def extract_csvs(mem_file: Path):
    print(f"\n[=== {mem_file.stem} ===]")
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = [
            executor.submit(extract_single_plugin, mem_file, plugin)
            for plugin in PLUGINS
        ]
        success = 0
        for future in as_completed(futures):
            img_name, plugin, ok = future.result()
            status = "[+]" if ok else "[!]"
            print(f"  {status} {plugin}")
            if ok:
                success += 1
    return success


def main():
    OUT_DIR.mkdir(exist_ok=True)
    mem_files = find_mem_files()
    if not mem_files:
        print("[!] No memory files found in dumps/")
        return

    print(f"🚀 FAST Extraction: {len(PLUGINS)} plugins × {len(mem_files)} files")
    print(f"🧵 Threads: {MAX_WORKERS} | Output: {OUT_DIR}")

    total_success = 0
    for mem_file in mem_files:
        success = extract_csvs(mem_file)
        total_success += success
        print(f"  → {success}/{len(PLUGINS)} CSVs extracted")

    print(f"\n✅ Done! {total_success} CSVs written to {OUT_DIR}")


if __name__ == "__main__":
    main()