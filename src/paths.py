"""Filesystem layout of the package.

All scripts resolve their input and output locations through this module so
that the package can be moved or the data and output roots redirected without
editing any script.

Environment overrides:
  SUITABILITY_DATA     directory holding the raw datasets (default: <root>/data)
  SUITABILITY_OUTPUTS  directory holding pipeline outputs (default: <root>/outputs)
"""
from __future__ import annotations

import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"

DATA = Path(os.environ.get("SUITABILITY_DATA", ROOT / "data"))
OUTPUTS = Path(os.environ.get("SUITABILITY_OUTPUTS", ROOT / "outputs"))

VERDICTS = OUTPUTS / "verdicts"
FIGURES = OUTPUTS / "figures"
PROBE_OUTPUTS = OUTPUTS / "probes"
REPORTS = OUTPUTS / "reports"


def dataset_dir(slug: str) -> Path:
    """Output directory of one dataset (Stage 1 CSV plus stage sub-directories)."""
    return OUTPUTS / slug


def normalized_csv(slug: str) -> Path:
    return dataset_dir(slug) / "normalized_full.csv"


def stage2_dir(slug: str) -> Path:
    return dataset_dir(slug) / "stage2"


def stage3_dir(slug: str) -> Path:
    return dataset_dir(slug) / "stage3_d4"
