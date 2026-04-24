from pathlib import Path

import pandas as pd


def iter_sample_dirs(data_dir: Path):
    """Yield sample directories in deterministic order."""
    if not data_dir.exists():
        return []
    return [entry for entry in sorted(data_dir.iterdir()) if entry.is_dir()]


def sample_name_from_dir(sample_dir: Path) -> str:
    """Return family name without WithVirus/NoVirus suffix."""
    return sample_dir.name.replace("-WithVirus", "").replace("-NoVirus", "")


def configuration_from_dir(sample_dir: Path) -> str:
    return "WithVirus" if "WithVirus" in sample_dir.name else "NoVirus"


def split_config(df: pd.DataFrame):
    with_virus_df = df[df["Configuration"] == "WithVirus"]
    no_virus_df = df[df["Configuration"] == "NoVirus"]
    return with_virus_df, no_virus_df


def paired_by_family(df: pd.DataFrame, value_columns: list[str]):
    """
    Return per-family paired rows for WithVirus and NoVirus.
    Output columns:
      Ransomware Family,
      <col>_with, <col>_no for each value column.
    """
    subset = df[["Ransomware Family", "Configuration", *value_columns]].copy()
    with_df = (
        subset[subset["Configuration"] == "WithVirus"]
        .drop(columns=["Configuration"])
        .rename(columns={col: f"{col}_with" for col in value_columns})
    )
    no_df = (
        subset[subset["Configuration"] == "NoVirus"]
        .drop(columns=["Configuration"])
        .rename(columns={col: f"{col}_no" for col in value_columns})
    )
    return with_df.merge(no_df, on="Ransomware Family", how="inner")


def ensure_outputs_dir(path: str = "outputs") -> Path:
    out_dir = Path(path)
    out_dir.mkdir(parents=True, exist_ok=True)
    return out_dir

