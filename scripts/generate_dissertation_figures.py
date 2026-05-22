#!/usr/bin/env python3
"""Generate dissertation figures from dataset_manifest.csv and analysis reports."""

from __future__ import annotations

import json
from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "extracted_data" / "dataset_manifest.csv"
OUT_DIR = ROOT / "latex_dissertation" / "figures"
EXTRACTED = ROOT / "extracted_data"

plt.rcParams.update(
    {
        "font.size": 10,
        "axes.titlesize": 11,
        "axes.labelsize": 10,
        "figure.dpi": 150,
        "savefig.dpi": 300,
        "savefig.bbox": "tight",
    }
)


def load_manifest() -> pd.DataFrame:
    df = pd.read_csv(MANIFEST)
    df["label_name"] = df["label"].map({0: "Benign (NoVirus)", 1: "Malware (WithVirus)"})
    df["uncertain"] = df["uncertain"].astype(str).str.lower().eq("true")
    return df


def fig_dataset_overview(df: pd.DataFrame) -> None:
    fig, axes = plt.subplots(1, 2, figsize=(8, 3.5))

    labels = ["Benign", "Malware"]
    counts = [int((df["label"] == 0).sum()), int((df["label"] == 1).sum())]
    colors = ["#4C78A8", "#E45756"]
    axes[0].bar(labels, counts, color=colors, edgecolor="black", linewidth=0.5)
    axes[0].set_ylabel("Number of samples")
    axes[0].set_title("(a) Dataset label balance (n=30)")
    for i, v in enumerate(counts):
        axes[0].text(i, v + 0.3, str(v), ha="center", fontsize=9)

    benign = df[df["label"] == 0]
    uncertain_n = int(benign["uncertain"].sum())
    certain_n = len(benign) - uncertain_n
    axes[1].bar(
        ["Uncertain benign", "Other benign"],
        [uncertain_n, certain_n],
        color=["#F58518", "#72B7B2"],
        edgecolor="black",
        linewidth=0.5,
    )
    axes[1].set_ylabel("Number of samples")
    axes[1].set_title("(b) Benign rows flagged uncertain")
    for i, v in enumerate([uncertain_n, certain_n]):
        axes[1].text(i, v + 0.2, str(v), ha="center", fontsize=9)

    fig.tight_layout()
    fig.savefig(OUT_DIR / "fig_dataset_overview.pdf")
    plt.close(fig)


def fig_graph_scale(df: pd.DataFrame) -> None:
    fig, axes = plt.subplots(1, 2, figsize=(8, 3.5))
    groups = [df[df["label"] == 0], df[df["label"] == 1]]
    titles = ["Benign", "Malware"]

    for ax, g, title in zip(axes, groups, titles):
        bp = ax.boxplot(
            [g["nodes"], g["edges"]],
            tick_labels=["Nodes", "Edges"],
            patch_artist=True,
        )
        for patch, c in zip(bp["boxes"], ["#4C78A8", "#E45756"]):
            patch.set_facecolor(c)
            patch.set_alpha(0.7)
        ax.set_title(title)
        ax.set_ylabel("Count (log scale)")
        ax.set_yscale("log")

    fig.suptitle("Graph size distribution by label", y=1.02, fontsize=11)
    fig.tight_layout()
    fig.savefig(OUT_DIR / "fig_graph_scale.pdf")
    plt.close(fig)


def fig_forensic_signals(df: pd.DataFrame) -> None:
    metrics = ["injections", "c2_conns", "max_score"]
    benign = df[df["label"] == 0][metrics].mean()
    malware = df[df["label"] == 1][metrics].mean()

    x = range(len(metrics))
    width = 0.35
    fig, ax = plt.subplots(figsize=(7, 3.5))
    ax.bar([i - width / 2 for i in x], benign, width, label="Benign (mean)", color="#4C78A8")
    ax.bar([i + width / 2 for i in x], malware, width, label="Malware (mean)", color="#E45756")
    ax.set_xticks(list(x))
    ax.set_xticklabels(["Injections", "C2 connections", "Max process score"])
    ax.set_ylabel("Mean value")
    ax.set_title("Mean forensic signal strength by label")
    ax.legend()
    fig.tight_layout()
    fig.savefig(OUT_DIR / "fig_forensic_signals.pdf")
    plt.close(fig)


def fig_family_coverage(df: pd.DataFrame) -> None:
    fam = df.groupby("family").size().sort_values(ascending=True)
    fig, ax = plt.subplots(figsize=(6, 5))
    fam.plot(kind="barh", ax=ax, color="#54A24B", edgecolor="black", linewidth=0.4)
    ax.set_xlabel("Number of samples (WithVirus + NoVirus pairs)")
    ax.set_ylabel("Malware family")
    ax.set_title("Dataset coverage by malware family")
    fig.tight_layout()
    fig.savefig(OUT_DIR / "fig_family_coverage.pdf")
    plt.close(fig)


def fig_verdict_distribution(df: pd.DataFrame) -> None:
    verdicts = df["verdict"].str.extract(r"^(\w+)")[0].fillna("OTHER")
    counts = verdicts.value_counts()
    fig, ax = plt.subplots(figsize=(6, 3.5))
    counts.plot(kind="bar", ax=ax, color="#B279A2", edgecolor="black", linewidth=0.4)
    ax.set_xlabel("Rule-based verdict category")
    ax.set_ylabel("Sample count")
    ax.set_title("Distribution of triage verdict categories")
    ax.tick_params(axis="x", rotation=0)
    fig.tight_layout()
    fig.savefig(OUT_DIR / "fig_verdict_distribution.pdf")
    plt.close(fig)


def fig_wannacry_node_types() -> None:
    report_path = EXTRACTED / "WannaCry-WithVirus" / "analysis_report.json"
    if not report_path.exists():
        return
    with open(report_path, encoding="utf-8") as f:
        data = json.load(f)
    node_types = data.get("summary", {}).get("node_types", {})
    if not node_types:
        return

    labels = list(node_types.keys())
    values = list(node_types.values())
    fig, ax = plt.subplots(figsize=(5.5, 4))
    ax.pie(
        values,
        labels=labels,
        autopct=lambda p: f"{p:.1f}%" if p > 3 else "",
        startangle=140,
    )
    ax.set_title("WannaCry-WithVirus: node-type composition")
    fig.tight_layout()
    fig.savefig(OUT_DIR / "fig_wannacry_node_types.pdf")
    plt.close(fig)


def write_stats_json(df: pd.DataFrame) -> None:
  stats = {
      "n_samples": int(len(df)),
      "n_malware": int((df["label"] == 1).sum()),
      "n_benign": int((df["label"] == 0).sum()),
      "n_uncertain_benign": int(df[df["label"] == 0]["uncertain"].sum()),
      "nodes_min": int(df["nodes"].min()),
      "nodes_max": int(df["nodes"].max()),
      "nodes_median": float(df["nodes"].median()),
      "edges_min": int(df["edges"].min()),
      "edges_max": int(df["edges"].max()),
      "edges_median": float(df["edges"].median()),
  }
  out = OUT_DIR / "dataset_stats.json"
  with open(out, "w", encoding="utf-8") as f:
      json.dump(stats, f, indent=2)


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    df = load_manifest()
    write_stats_json(df)
    fig_dataset_overview(df)
    fig_graph_scale(df)
    fig_forensic_signals(df)
    fig_family_coverage(df)
    fig_verdict_distribution(df)
    fig_wannacry_node_types()
    print(f"Wrote figures to {OUT_DIR}")


if __name__ == "__main__":
    main()
