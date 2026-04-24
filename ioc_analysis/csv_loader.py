from pathlib import Path

import pandas as pd


def load_windows_plugin_csv(sample_dir: Path, plugin: str) -> pd.DataFrame:
    """Load windows_<plugin>.csv for a sample directory."""
    csv_file = sample_dir / f"windows_{plugin.replace('.', '_')}.csv"
    return pd.read_csv(csv_file) if csv_file.exists() else pd.DataFrame()

