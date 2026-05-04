"""
FAST Volatility 3 CSV Extractor (Threaded)
Scans memory_dumps/*.mem → ALL plugins → ALL CSVs (parallel execution)
"""

import os
import subprocess
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
import sys

# === CONFIG ===
MEM_DIR = Path("benign_dumps")
OUT_DIR = Path("extracted_csvs")
# Vol 3 plugin names (windows.services / windows.version are not valid — use svcscan / verinfo).
PLUGINS = [
    "windows.info", "windows.pslist", "windows.pstree", "windows.psscan",
    "windows.cmdline", "windows.dlllist", "windows.netscan",
    "windows.registry.hivelist", "windows.svcscan", "windows.malfind",
    "windows.ssdt", "windows.handles", "windows.filescan", "windows.threads",
    "windows.verinfo", "windows.driverscan", "windows.vadinfo",
]
# Stable CSV basenames for plugins whose default stem would differ from legacy names.
PLUGIN_CSV_NAME = {
    "windows.svcscan": "windows_services.csv",
    "windows.verinfo": "windows_version.csv",
}

MAX_WORKERS = os.cpu_count() * 2  # Aggressive threading

def find_mem_files():
    """Find all .mem/.raw recursively."""
    mem_files = []
    for ext in ["*.mem", "*.raw", "*.dmp", "*.bin", "*.vmem"]:
        mem_files.extend(MEM_DIR.glob(ext))
        mem_files.extend(MEM_DIR.rglob(ext))
    return sorted(set(mem_files))

def extract_single_plugin(mem_file: Path, plugin: str) -> tuple:
    """Run ONE plugin → CSV (thread target)."""
    img_name = mem_file.stem
    img_dir = OUT_DIR / img_name
    img_dir.mkdir(parents=True, exist_ok=True)
    
    csv_file = img_dir / PLUGIN_CSV_NAME.get(
        plugin, f"{plugin.replace('.', '_')}.csv"
    )
    cmd = f'vol -f "{mem_file}" -r csv {plugin} > "{csv_file}"'
    print(cmd)
    if os.path.isfile(csv_file):
        return (img_name, plugin, True)

    
    # try:
    #     subprocess.run(cmd, shell=True, check=True, 
    #                   capture_output=True, text=True)
    #     return (img_name, plugin, True)
    # except  Exception as error:
    #     return (img_name, plugin, False)
    return (img_name, plugin, False)


def extract_csvs(mem_file: Path):
    """Threaded extraction for ALL plugins on one mem file."""
    
    # Submit ALL plugins in parallel
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = [
            executor.submit(extract_single_plugin, mem_file, plugin)
            for plugin in PLUGINS
        ]
        
        success = 0
        for future in as_completed(futures):
            img_name, plugin, ok = future.result()
            if ok:
                success += 1
            else:
                pass
        
        return success

def main():
    OUT_DIR.mkdir(exist_ok=True)
    
    mem_files = find_mem_files()
    if not mem_files:
        return
    
    print(f"🚀 FAST Extraction: {len(PLUGINS)} plugins x {len(mem_files)} files")
    print(f"🧵 Threads: {MAX_WORKERS} | Output: {OUT_DIR}")
    
    total_success = 0
    for mem_file in mem_files:
        success = extract_csvs(mem_file)
        total_success += success

if __name__ == "__main__":
    main()