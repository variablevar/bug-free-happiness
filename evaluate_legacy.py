#!/usr/bin/env python3
"""
Legacy placeholder.

The previous binary evaluation script was retired in favor of `evaluate.py`,
which merges two-model + binary analysis and reports manifest subset metrics
(`ambiguous_novirus_control`, `train_eligible`, `manifest_uncertain`, etc.).
"""

if __name__ == "__main__":
    raise SystemExit(
        "Legacy binary evaluator retired. Use `python evaluate.py <manifest>`."
    )

