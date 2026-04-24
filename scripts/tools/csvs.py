#!/usr/bin/env python3
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[2]
extracted_data_dir = BASE_DIR / "extracted_data"
extracted_csvs_dir = BASE_DIR / "extracted_csvs"
os.makedirs(extracted_csvs_dir, exist_ok=True)

for root, _, files in os.walk(extracted_data_dir):
    for file in files:
        if file.endswith(".csv"):
            source_path = os.path.join(root, file)
            rel_path = os.path.relpath(root, extracted_data_dir)
            dest_dir = os.path.join(extracted_csvs_dir, rel_path)
            os.makedirs(dest_dir, exist_ok=True)
            dest_path = os.path.join(dest_dir, file)
            with open(source_path, "r", encoding="utf-8", errors="ignore") as src:
                with open(dest_path, "w", encoding="utf-8") as dst:
                    dst.write(src.read())
            print(f"Copied: {file}")

