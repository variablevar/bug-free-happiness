#!/usr/bin/env python3
"""Export dissertation figure data for LaTeX/pgfplots (legacy entry point)."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXPORT = ROOT / "scripts" / "export_dissertation_figure_data.py"


def main() -> None:
    subprocess.run([sys.executable, str(EXPORT)], check=True)
    print(
        "Figure data exported. Rebuild PDF with: cd latex_dissertation && latexmk -pdf main.tex"
    )


if __name__ == "__main__":
    main()
