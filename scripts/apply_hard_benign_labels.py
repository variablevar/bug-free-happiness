#!/usr/bin/env python3
"""
Patch dataset_manifest.csv with curated benign_subtype / train_eligible from a labels CSV.

Expected columns: folder, benign_subtype, train_eligible (optional: label)
Example subtypes: clean_benign, hard_benign_admin_tooling
"""

from __future__ import annotations

import argparse
import csv
from pathlib import Path


def main() -> None:
    p = argparse.ArgumentParser(description="Apply hard-benign governance labels to manifest")
    p.add_argument("manifest", help="dataset_manifest.csv to update in place")
    p.add_argument("labels_csv", help="CSV with folder, benign_subtype, train_eligible")
    p.add_argument("--dry-run", action="store_true")
    args = p.parse_args()

    labels_path = Path(args.labels_csv)
    if not labels_path.is_file():
        example = labels_path.parent / "hard_benign_labels.example.csv"
        hint = (
            f"\n  Create {labels_path} with columns: folder, benign_subtype, train_eligible, label\n"
            f"  See template: {example}\n"
            f"  Each folder must exist under the manifest base-dir (e.g. extracted_csvs/<folder>/).\n"
            f"  Do not relabel *-NoVirus MalVol controls as clean_benign — add new benign captures instead."
        )
        raise SystemExit(f"[ERROR] labels CSV not found: {labels_path}{hint}")

    labels: dict[str, dict] = {}
    with labels_path.open(newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            folder = str(row.get("folder", "")).strip()
            if folder:
                labels[folder] = row

    manifest_path = Path(args.manifest)
    rows = list(csv.DictReader(manifest_path.open(newline="", encoding="utf-8")))
    if not rows:
        raise SystemExit("[ERROR] empty manifest")
    fieldnames = list(rows[0].keys())
    for col in ("benign_subtype", "train_eligible", "label_quality_flag", "label_quality_reason"):
        if col not in fieldnames:
            fieldnames.append(col)

    updated = 0
    for row in rows:
        folder = str(row.get("folder", "")).strip()
        if folder not in labels:
            continue
        src = labels[folder]
        row["benign_subtype"] = str(src.get("benign_subtype", row.get("benign_subtype", "")))
        te = str(src.get("train_eligible", "true")).strip().lower()
        row["train_eligible"] = "True" if te in {"1", "true", "yes"} else "False"
        row["label_quality_flag"] = "False"
        row["label_quality_reason"] = ""
        if "label" in src and str(src["label"]).strip() != "":
            row["label"] = str(src["label"]).strip()
        updated += 1

    print(f"[apply_hard_benign_labels] matched {updated}/{len(rows)} rows")
    if args.dry_run:
        return
    with manifest_path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)
    print(f"[apply_hard_benign_labels] wrote {manifest_path}")


if __name__ == "__main__":
    main()
