"""The datasets under assessment and their dataset-level scores.

The scores live in a corpus file, not in this module, so that nothing in the
code refers to a dataset by name. The file ships empty and fills up as datasets
are profiled: the notebook and save_dataset() write entries into it. Point the
environment variable SUITABILITY_CORPUS at another file to keep several
collections apart.

    corpus/datasets.json                default, overridden by SUITABILITY_CORPUS

Corpus file format
------------------
```
{
  "name": "...",
  "description": "...",
  "calibration_pool": ["<name>", ...],          datasets the thresholds were derived on
  "stage2_overrides": {"<name>": "<dirname>"},  non-default Stage 2 directory
  "drain_lines_overrides": {"<name>": "<dirname>"},
  "file_level_label_artefact": ["<name>", ...], labels are per file, so D3 is inflated
  "d6_tactic_resolution": ["<name>", ...],      D6 derived from tactics, not comparable
  "indeterminate_notes": {"<name>": {"D3": "why it cannot be measured"}},
  "datasets": {
    "<display name>": {
      "slug": "<output directory name>",
      "scores": {"D1":, "D1_robust":, "D2":, "D3":, "D4":, "D4_part":, "D5":},
      "d3_information": {"U":, "purity":},      omit when there are no per-line labels
      "global_neardup":, "d3_revised_legacy":, "d3_cross_file_jaccard":,
      "d4_attack":, "d6":, "d7":               all optional
    }
  }
}
```

A score may be null where a dimension cannot be measured: D3 without per-line
labels, D4 with a single host. A dataset with no `d3_information` entry is
treated as D3-unavailable and receives INDETERMINATE on every task that needs
D3. That is deliberate: nothing falls back silently to another metric.

What the tables mean
--------------------
D1        raw normalised entropy H / log2(K), median over files
D1_robust canonical D1: median over files of
          0.25 * (H/log2K + (1 - Gini_v2) + (1 - top-10%-coverage) + (1 - NearDup_global))
D2        median over files of transition entropy / log2(K)
D3        legacy class separation ratio; the decision rule gates on
          max(U, purity) from d3_information instead
D4        D4_conn, share of host pairs sharing a non-private IPv4 address
D4_part   share of host pairs sharing a participation identifier
D5        1 - median over files of boilerplate proportion
D6, D7    descriptive only; they never enter a verdict

Names exposed by this module
----------------------------
DATASETS, CORPUS_SCORES, D3_INFO, D3_REVISED, D3_CROSS_FILE_JACCARD,
D3_FILE_LEVEL_ARTEFACT, D4_ATTACK, D6_INFO, D6_TACTIC_RESOLUTION, D7_INFO,
GLOBAL_NEARDUP, INDETERMINATE_NOTES, CALIBRATION_POOL, STAGE2_OVERRIDES,
DRAIN_LINES_OVERRIDES, plus d3_gating, d4_gating, slug_of, display_name_of and
save_dataset, which writes one dataset back to the corpus file.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

CORPUS_FILE = Path(os.environ.get(
    "SUITABILITY_CORPUS", ROOT / "corpus" / "datasets.json"))

SCORE_KEYS = ("D1", "D1_robust", "D2", "D3", "D4", "D4_part", "D5")


def _load(path: Path) -> dict:
    if not path.exists():
        raise SystemExit(
            f"corpus file not found: {path}\n"
            f"Set SUITABILITY_CORPUS to a corpus file, or create one; the format is "
            f"documented at the top of {Path(__file__).name}.")
    with path.open(encoding="utf-8") as fh:
        return json.load(fh)


_corpus = _load(CORPUS_FILE)
_entries: dict[str, dict] = _corpus.get("datasets", {})

CORPUS_NAME: str = _corpus.get("name", CORPUS_FILE.stem)

# display name -> output directory slug
DATASETS: dict[str, str] = {
    name: entry.get("slug", name) for name, entry in _entries.items()
}

# display name -> {D1, D1_robust, D2, D3, D4, D4_part, D5}
CORPUS_SCORES: dict[str, dict[str, float | None]] = {
    name: {key: entry.get("scores", {}).get(key) for key in SCORE_KEYS}
    for name, entry in _entries.items()
}


def _column(field: str) -> dict:
    return {name: entry[field] for name, entry in _entries.items() if field in entry}


# U = I(template; label) / H(label); purity = smoothed attack-purity coverage.
# The decision rule gates on max(U, purity).
D3_INFO: dict[str, dict[str, float]] = _column("d3_information")

# Dataset-wide near-duplicate ratio that enters D1_robust.
GLOBAL_NEARDUP: dict[str, float] = _column("global_neardup")

# Legacy per-file D3 and the cross-file template Jaccard, both reported for
# comparison only; neither enters a verdict.
D3_REVISED: dict[str, float] = _column("d3_revised_legacy")
D3_CROSS_FILE_JACCARD: dict[str, float] = _column("d3_cross_file_jaccard")

# Entity recall restricted to co-attacked host pairs (supplementary).
D4_ATTACK: dict[str, float] = _column("d4_attack")

# Descriptive dimensions.
D6_INFO: dict[str, float] = _column("d6")
D7_INFO: dict[str, float | None] = _column("d7")

# Datasets whose labels are per file, so max(U, purity) reflects file identity
# rather than per-line separability.
D3_FILE_LEVEL_ARTEFACT: frozenset[str] = frozenset(
    _corpus.get("file_level_label_artefact", ()))

# Datasets whose D6 is derived from tactics rather than techniques, and is
# therefore not comparable with the other D6 values.
D6_TACTIC_RESOLUTION: frozenset[str] = frozenset(
    _corpus.get("d6_tactic_resolution", ()))

# Why a dimension is unavailable, per dataset.
INDETERMINATE_NOTES: dict[str, dict[str, str]] = _corpus.get("indeterminate_notes", {})

# Datasets the thresholds were derived on, pooled.
CALIBRATION_POOL: tuple[str, ...] = tuple(_corpus.get("calibration_pool", ()))
AIT_TRIO = CALIBRATION_POOL   # former name, kept until the last caller is updated

# Stage output directories that differ from the defaults.
STAGE2_OVERRIDES: dict[str, str] = _corpus.get("stage2_overrides", {})
DRAIN_LINES_OVERRIDES: dict[str, str] = _corpus.get("drain_lines_overrides", {})


def d3_gating(dataset: str) -> float | None:
    """Effective D3 used by the decision rule: max(U, purity), or None."""
    info = D3_INFO.get(dataset)
    if info is None:
        return None
    return max(info["U"], info["purity"])


def d4_gating(scores: dict) -> float | None:
    """Effective D4 used by the decision rule: max(D4_conn, D4_part).

    A dataset supports cross-host reconstruction if hosts are linkable through
    either channel, so the gate is the maximum. None entries are skipped; if
    both channels are unavailable the result is None.
    """
    vals = [v for v in (scores.get("D4"), scores.get("D4_part")) if v is not None]
    return max(vals) if vals else None


def slug_of(dataset: str) -> str:
    """Output-directory slug of a dataset given its display name or slug."""
    if dataset in DATASETS:
        return DATASETS[dataset]
    if dataset in DATASETS.values():
        return dataset
    raise KeyError(f"unknown dataset: {dataset}")


def display_name_of(slug: str) -> str:
    """Display name of a dataset given its slug (or display name)."""
    for name, value in DATASETS.items():
        if value == slug or name == slug:
            return name
    raise KeyError(f"unknown dataset slug: {slug}")


def save_dataset(name: str, slug: str, scores: dict,
                 d3_information: dict | None = None,
                 extras: dict | None = None,
                 corpus_file: Path | None = None) -> Path:
    """Add or replace one dataset in the corpus file, and in the loaded tables.

    `scores` holds D1, D1_robust, D2, D3, D4, D4_part and D5; a missing or None
    entry marks a dimension that could not be measured. `d3_information` is the
    {U, purity} pair, omitted when the dataset has no per-line labels. `extras`
    can carry the optional per-dataset keys, for example global_neardup, d6, d7.

    Returns the path written.
    """
    target = Path(corpus_file) if corpus_file else CORPUS_FILE
    document = _load(target) if target.exists() else {"datasets": {}}
    entries = document.setdefault("datasets", {})

    entry = dict(entries.get(name, {}))
    entry["slug"] = slug
    entry["scores"] = {key: scores.get(key) for key in SCORE_KEYS}
    if d3_information:
        entry["d3_information"] = {"U": d3_information["U"],
                                   "purity": d3_information["purity"]}
    else:
        entry.pop("d3_information", None)
    for key, value in (extras or {}).items():
        if value is not None:
            entry[key] = value
    entries[name] = entry

    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("w", encoding="utf-8") as fh:
        json.dump(document, fh, indent=2)
        fh.write("\n")

    # Keep the tables loaded in this session in step with the file.
    DATASETS[name] = slug
    CORPUS_SCORES[name] = entry["scores"]
    if d3_information:
        D3_INFO[name] = entry["d3_information"]
    else:
        D3_INFO.pop(name, None)
    return target
