"""Stage 2: mine templates from the normalized CSV and measure each source file.

One Drain3 miner is fitted per source file. Every line receives a template id,
and the id sequence is the shared input for four dimensions:

  D1  structural diversity: template count, entropy, Gini, parameter coverage,
      near-duplicates, and the per-file composites
  D2  temporal dependence: transition entropy, self-transition rate
  D3  label quality: class ratios, class-exclusive templates
  D5  semantic richness: type-token ratio, boilerplate proportion

The dataset-wide near-duplicate ratio is computed here too, because it needs
the mined templates of every file at once and it completes D1.

Reads   outputs/<slug>/normalized_full.csv
Writes  drain_templates.csv, drain_lines.csv, d1_metrics.csv,
        drain_summary.json and d1_global_neardup.json in the output directory

Usage:
  python src/templates.py --normalized-csv outputs/<slug>/normalized_full.csv \
      --output-dir outputs/<slug>/stage2
  python src/templates.py --output-dir outputs/<slug>/stage2 --neardup-only
"""
from __future__ import annotations

import argparse
import csv
import json
import math
import re
import time
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime
from itertools import groupby
from pathlib import Path
from typing import Any, Iterable

from drain3 import TemplateMiner
from drain3.template_miner_config import TemplateMinerConfig


@dataclass
class DrainConfig:
    depth: int = 4
    sim_th: float = 0.5
    max_children: int = 100
    max_clusters: int | None = 500     # 0 or None disables the cap
    parametrize_numeric_tokens: bool = True


DRAIN_TEMPLATES_COLUMNS = [
    "source_file",
    "template_id",
    "template_str",
    "count",
    "attack_count",
    "normal_count",
    "exclusive_class",
]

DRAIN_LINES_COLUMNS = [
    "source_file",
    "line_no",
    "template_id",
    "parameters",
]

# The file is named d1_metrics.csv but holds the per-file metrics of D1, D2,
# D3 and D5.
D1_METRICS_COLUMNS = [
    # identification
    "source_file",
    "host",
    # D1: structural diversity
    "template_count",
    "shannon_entropy",
    "gini_coeff",
    "top10_coverage",
    "param_token_ratio",
    "mean_params_per_line",
    "near_duplicate_ratio",
    "d1_robust",
    "d1_robust_v2",
    "active_cluster_count",
    # D2: temporal dependence
    "transition_entropy",
    "self_transition_ratio",
    "unique_transition_count",
    "interarrival_mean_s",
    "interarrival_cv",
    # D3: label quality
    "total_lines",
    "attack_lines",
    "normal_lines",
    "attack_line_ratio",
    "exclusive_attack_templates",
    "exclusive_normal_templates",
    "exclusive_attack_template_ratio",
    "exclusive_normal_template_ratio",
    "class_separation_ratio",
    "attack_exclusive_line_coverage",   # fraction of attack lines covered by attack-exclusive templates
    "attack_temporal_concentration",
    # D5: semantic richness
    "type_token_ratio",
    "boilerplate_proportion",
    "mean_template_tokens",
]


# ---------------------------------------------------------------------------
# Helper: metric calculations
# ---------------------------------------------------------------------------

def _entropy(counts: list[int]) -> float:
    total = sum(counts)
    if total == 0:
        return 0.0
    return -sum((c / total) * math.log2(c / total) for c in counts if c > 0)


def _gini(counts: list[int]) -> float:
    """Gini coefficient over template frequency counts.
    Returns 0 (perfectly equal) to 1 (all lines in one template).
    """
    n = len(counts)
    if n == 0:
        return 0.0
    total = sum(counts)
    if total == 0:
        return 0.0
    sorted_counts = sorted(counts)
    weighted_sum = sum((i + 1) * c for i, c in enumerate(sorted_counts))
    return (2 * weighted_sum - (n + 1) * total) / (n * total)


def _transition_entropy(bigram_counts: Counter) -> float:
    """H(T_{n+1} | T_n): conditional entropy of next template given current template."""
    total = sum(bigram_counts.values())
    if total == 0:
        return 0.0
    # H(T_n, T_{n+1})
    joint_h = -sum((c / total) * math.log2(c / total) for c in bigram_counts.values() if c > 0)
    # H(T_n) from marginal of source template
    source_counts: Counter = Counter()
    for (ti, _), c in bigram_counts.items():
        source_counts[ti] += c
    marginal_h = -sum((c / total) * math.log2(c / total) for c in source_counts.values() if c > 0)
    # H(T_{n+1} | T_n) = H(T_n, T_{n+1}) - H(T_n)
    return max(0.0, joint_h - marginal_h)


def _interarrival_stats(timestamps: list[float]) -> tuple[float, float]:
    """Return (mean_s, cv) of inter-arrival times.

    cv = std / mean; returns (nan, nan) if fewer than 2 valid timestamps.
    Negative gaps (out-of-order lines) are discarded before computing stats.
    """
    if len(timestamps) < 2:
        return float("nan"), float("nan")
    diffs = [timestamps[i + 1] - timestamps[i] for i in range(len(timestamps) - 1)]
    diffs = [d for d in diffs if d >= 0]
    if not diffs:
        return float("nan"), float("nan")
    mean_d = sum(diffs) / len(diffs)
    if mean_d == 0.0:
        return 0.0, float("nan")
    variance = sum((d - mean_d) ** 2 for d in diffs) / len(diffs)
    cv = math.sqrt(variance) / mean_d
    return mean_d, cv


def _near_duplicate_ratio(template_stats: dict[int, dict], max_sample: int = 1000) -> float:
    """Fraction of templates with Jaccard similarity >= 0.8 to at least one other template.

    Token sets exclude the <*> wildcard so that shared constant tokens drive
    the score, not wildcard density.

    Complexity is O(n^2) with n = min(len(template_stats), max_sample). Files
    with very high template counts (for example telemetry files after Drain
    LRU evictions) can accumulate hundreds of thousands of cluster ids, so the
    template list is stride-sampled to max_sample entries; the result is then a
    sample-based estimate.
    """
    templates = [ts["template_str"] for ts in template_stats.values()]
    n = len(templates)
    if n < 2:
        return 0.0
    if n > max_sample:
        # Stride sampling: deterministic and spread across the vocabulary.
        step = n // max_sample
        templates = templates[::step][:max_sample]
        n = len(templates)
    token_sets = [frozenset(t.split()) - {"<*>"} for t in templates]
    is_near_dup = [False] * n
    for i in range(n):
        for j in range(i + 1, n):
            if is_near_dup[i] and is_near_dup[j]:
                continue
            a, b = token_sets[i], token_sets[j]
            union_size = len(a | b)
            if union_size == 0:
                continue
            if len(a & b) / union_size >= 0.8:
                is_near_dup[i] = True
                is_near_dup[j] = True
    return sum(is_near_dup) / n


def _parse_iso_ts(ts_str: str) -> float | None:
    """Convert an ISO 8601 timestamp string to a Unix timestamp (seconds since epoch).

    Handles the Z suffix for Python versions before 3.11 by replacing it with +00:00.
    Returns None for empty or unparseable strings.
    """
    if not ts_str:
        return None
    try:
        cleaned = ts_str.replace("Z", "+00:00")
        dt = datetime.fromisoformat(cleaned)
        return dt.timestamp()
    except (ValueError, TypeError, OverflowError):
        return None


# ---------------------------------------------------------------------------
# Infrastructure telemetry file detection
# ---------------------------------------------------------------------------

# Logstash/Metricbeat system metrics: date-prefixed system.<type>.log files.
# Every line is a distinct metric sample, so Drain produces one template per
# line without useful merging and runs out of memory on large files. The
# system.auth and system.syslog variants carry real log events and are kept.
_METRICS_FILE_RE = re.compile(
    r"[/\\]logstash[/\\][^/\\]+[/\\]\d{4}-\d{2}-\d{2}-system\."
    r"(?!auth\.|syslog\.)[^/\\]+\.log$"
)

# Suricata IDS stats.log: per-second monitoring counters in the format
# "metric_name | Total | value", without security event content or labels.
# In the AIT-LDS scenarios these files hold the large majority of all lines
# and would dominate the dataset-level D1 and D5 aggregates, so they are
# excluded for the same reason as the Logstash system metrics.
# Path pattern: gather/<host>/logs/suricata/stats.log.
_SURICATA_STATS_RE = re.compile(
    r"[/\\]suricata[/\\]stats\.log$"
)


def _is_metrics_file(source_file: str) -> bool:
    return (
        bool(_METRICS_FILE_RE.search(source_file))
        or bool(_SURICATA_STATS_RE.search(source_file))
    )


def _make_miner(config: DrainConfig) -> TemplateMiner:
    cfg = TemplateMinerConfig()
    cfg.drain_depth = config.depth
    cfg.drain_sim_th = config.sim_th
    cfg.drain_max_children = config.max_children
    # 0 and None both mean no cap; Drain3 itself accepts only None for that.
    cfg.drain_max_clusters = config.max_clusters or None
    cfg.parametrize_numeric_tokens = config.parametrize_numeric_tokens
    return TemplateMiner(config=cfg)


# ---------------------------------------------------------------------------
# Per-source-file processing
# ---------------------------------------------------------------------------

def _process_source(
    source_file: str,
    rows: Iterable[dict[str, str]],
    config: DrainConfig,
    t_writer: csv.DictWriter,
    l_writer: csv.DictWriter | None,
    d_writer: csv.DictWriter,
) -> dict[str, Any]:
    """Fit Drain on one source file's rows, write outputs, return per-file stats."""
    host = "unknown"
    miner = _make_miner(config)

    # template_id -> {count, attack_count, normal_count, template_str}
    template_stats: dict[int, dict[str, Any]] = {}
    n_lines = 0

    # D2 state, collected during the streaming pass
    bigram_counts: Counter = Counter()
    prev_tid: int | None = None
    n_transitions = 0
    n_self_transitions = 0
    timestamps: list[float] = []
    attack_timestamps: list[float] = []

    for row in rows:
        if n_lines == 0:
            host = row.get("host", "unknown")
        n_lines += 1

        msg = row.get("raw_message", "")
        is_attack = row.get("is_attack", "False") in ("True", "true", "1")
        try:
            line_no = int(row.get("line_no", 0))
        except ValueError:
            line_no = 0

        result = miner.add_log_message(msg)
        tid: int = result["cluster_id"]
        template_str: str = result["template_mined"]

        if tid not in template_stats:
            template_stats[tid] = {
                "count": 0,
                "attack_count": 0,
                "normal_count": 0,
                "template_str": template_str,
            }
        ts_stat = template_stats[tid]
        ts_stat["count"] += 1
        ts_stat["template_str"] = template_str  # update as Drain refines the template
        if is_attack:
            ts_stat["attack_count"] += 1
        else:
            ts_stat["normal_count"] += 1

        if l_writer is not None:
            try:
                params = miner.get_parameter_list(template_str, msg) or []
            except Exception:
                params = []
            l_writer.writerow({
                "source_file": source_file,
                "line_no": line_no,
                "template_id": tid,
                "parameters": json.dumps(params, ensure_ascii=True),
            })

        # D2: timestamp collection
        ts_val = _parse_iso_ts(row.get("timestamp_parsed", ""))
        if ts_val is not None:
            timestamps.append(ts_val)
            if is_attack:
                attack_timestamps.append(ts_val)

        # D2: bigram tracking
        if prev_tid is not None:
            bigram_counts[(prev_tid, tid)] += 1
            n_transitions += 1
            if prev_tid == tid:
                n_self_transitions += 1
        prev_tid = tid

    # Determine exclusive class per template
    for ts_stat in template_stats.values():
        if ts_stat["attack_count"] > 0 and ts_stat["normal_count"] == 0:
            ts_stat["exclusive_class"] = "attack"
        elif ts_stat["attack_count"] == 0 and ts_stat["normal_count"] > 0:
            ts_stat["exclusive_class"] = "normal"
        else:
            ts_stat["exclusive_class"] = "mixed"

    # Write templates
    for tid, ts_stat in template_stats.items():
        t_writer.writerow({
            "source_file": source_file,
            "template_id": tid,
            "template_str": ts_stat["template_str"],
            "count": ts_stat["count"],
            "attack_count": ts_stat["attack_count"],
            "normal_count": ts_stat["normal_count"],
            "exclusive_class": ts_stat["exclusive_class"],
        })

    # ------------------------------------------------------------------
    # D1: structural diversity
    # ------------------------------------------------------------------
    counts = [ts_stat["count"] for ts_stat in template_stats.values()]
    n_attacks = sum(ts_stat["attack_count"] for ts_stat in template_stats.values())
    n_normal = sum(ts_stat["normal_count"] for ts_stat in template_stats.values())
    n_templates = len(counts)
    entropy = _entropy(counts)
    gini = _gini(counts)
    top10_sum = sum(sorted(counts, reverse=True)[:10])
    top10_coverage = top10_sum / n_lines if n_lines > 0 else 0.0
    excl_attack = sum(1 for ts_stat in template_stats.values() if ts_stat["exclusive_class"] == "attack")
    excl_normal = sum(1 for ts_stat in template_stats.values() if ts_stat["exclusive_class"] == "normal")

    # Parameter token coverage: share of <*> tokens over all template tokens.
    all_template_tokens = sum(len(ts_stat["template_str"].split()) for ts_stat in template_stats.values())
    all_param_tokens = sum(ts_stat["template_str"].count("<*>") for ts_stat in template_stats.values())
    param_token_ratio = all_param_tokens / all_template_tokens if all_template_tokens > 0 else 0.0
    mean_params_per_line = (
        sum(ts_stat["count"] * ts_stat["template_str"].count("<*>") for ts_stat in template_stats.values()) / n_lines
        if n_lines > 0 else 0.0
    )
    near_dup_ratio = _near_duplicate_ratio(template_stats)

    # d1_robust: equal-weighted composite of four diversity signals, each in
    # [0, 1], higher meaning more diverse:
    #   d1_norm      = H / log2(K)   normalised per-file entropy
    #   1 - gini                     inverted Gini (high Gini = concentrated)
    #   1 - top10                    inverted coverage of the ten most frequent templates
    #   1 - near_dup                 inverted within-file near-duplicate ratio
    d1_norm = entropy / math.log2(n_templates) if n_templates > 1 else 0.0
    d1_robust = 0.25 * (d1_norm + (1.0 - gini) + (1.0 - top10_coverage) + (1.0 - near_dup_ratio))
    # d1_robust_v2: scale-corrected variant of the same composite.
    #   H / log2(K)      normalised entropy
    #   1 - Gini_v2      Gini with 1.0 imputed for K = 1 (a single template is
    #                    maximally concentrated)
    #   1 - top_10%_cov  coverage of the top ceil(0.10 * K) templates instead of a
    #                    fixed top ten, so the term does not depend on K
    #   1 - NearDup      near-duplicate ratio
    # The per-file value written here uses the within-file near_dup_ratio as the
    # NearDup term. The dataset-level score replaces it with the global
    # dataset-wide near-duplicate ratio (fraction of all
    # distinct templates with a near-twin anywhere in the dataset, Jaccard >= 0.8),
    # which coincides with near_dup_ratio for single-file datasets.
    _top_pct_k = max(1, math.ceil(n_templates * 0.10))
    _top_pct_sum = sum(sorted(counts, reverse=True)[:_top_pct_k])
    _top_pct_coverage = _top_pct_sum / n_lines if n_lines > 0 else 0.0
    _gini_v2 = gini if n_templates > 1 else 1.0
    _d1rv2_3comp = d1_norm + (1.0 - _gini_v2) + (1.0 - _top_pct_coverage)
    d1_robust_v2 = 0.25 * (_d1rv2_3comp + (1.0 - near_dup_ratio))
    # active_cluster_count: clusters currently held in the Drain tree. When
    # max_clusters is set, evicted clusters are excluded, unlike template_count,
    # which counts every cluster id ever assigned.
    active_cluster_count = len(miner.drain.id_to_cluster)

    # ------------------------------------------------------------------
    # D2: temporal dependence
    # ------------------------------------------------------------------
    trans_entropy = _transition_entropy(bigram_counts)
    self_trans_ratio = n_self_transitions / n_transitions if n_transitions > 0 else float("nan")
    unique_trans_count = len(bigram_counts)
    ia_mean, ia_cv = _interarrival_stats(timestamps)

    # ------------------------------------------------------------------
    # D3: label quality
    # ------------------------------------------------------------------
    attack_line_ratio = n_attacks / n_lines if n_lines > 0 else 0.0
    excl_attack_ratio = excl_attack / n_templates if n_templates > 0 else 0.0
    excl_normal_ratio = excl_normal / n_templates if n_templates > 0 else 0.0
    class_sep_ratio = (excl_attack + excl_normal) / n_templates if n_templates > 0 else 0.0
    # attack_exclusive_line_coverage: fraction of attack lines covered by
    # attack-exclusive templates. Unlike class_sep_ratio, which counts
    # templates, it is not inflated by large vocabularies of rare templates.
    excl_attack_line_count = sum(
        ts["count"] for ts in template_stats.values() if ts["exclusive_class"] == "attack"
    )
    attack_exclusive_line_coverage = excl_attack_line_count / n_attacks if n_attacks > 0 else 0.0

    # attack_temporal_concentration: fraction of the total log time span covered
    # by the attack event window; a small value means temporally localised attacks.
    if attack_timestamps and timestamps:
        total_span = max(timestamps) - min(timestamps)
        attack_span = max(attack_timestamps) - min(attack_timestamps)
        atc = attack_span / total_span if total_span > 0 else 0.0
    else:
        atc = 0.0

    # ------------------------------------------------------------------
    # D5: semantic richness
    # ------------------------------------------------------------------
    type_token_ratio = n_templates / n_lines if n_lines > 0 else 0.0
    boilerplate_prop = max(counts) / n_lines if n_lines > 0 and counts else 0.0
    mean_template_tokens_val = (
        sum(len(ts_stat["template_str"].split()) for ts_stat in template_stats.values()) / n_templates
        if n_templates > 0 else 0.0
    )

    def _r(x: float) -> float | str:
        """Round finite floats; pass through nan as empty string for CSV."""
        if math.isnan(x):
            return ""
        return round(x, 6)

    d_writer.writerow({
        "source_file": source_file,
        "host": host,
        # D1
        "template_count": n_templates,
        "shannon_entropy": _r(entropy),
        "gini_coeff": _r(gini),
        "top10_coverage": _r(top10_coverage),
        "param_token_ratio": _r(param_token_ratio),
        "mean_params_per_line": _r(mean_params_per_line),
        "near_duplicate_ratio": _r(near_dup_ratio),
        "d1_robust": _r(d1_robust),
        "d1_robust_v2": _r(d1_robust_v2),
        "active_cluster_count": active_cluster_count,
        # D2
        "transition_entropy": _r(trans_entropy),
        "self_transition_ratio": _r(self_trans_ratio),
        "unique_transition_count": unique_trans_count,
        "interarrival_mean_s": _r(ia_mean),
        "interarrival_cv": _r(ia_cv),
        # D3
        "total_lines": n_lines,
        "attack_lines": n_attacks,
        "normal_lines": n_normal,
        "attack_line_ratio": _r(attack_line_ratio),
        "exclusive_attack_templates": excl_attack,
        "exclusive_normal_templates": excl_normal,
        "exclusive_attack_template_ratio": _r(excl_attack_ratio),
        "exclusive_normal_template_ratio": _r(excl_normal_ratio),
        "class_separation_ratio": _r(class_sep_ratio),
        "attack_exclusive_line_coverage": _r(attack_exclusive_line_coverage),
        "attack_temporal_concentration": _r(atc),
        # D5
        "type_token_ratio": _r(type_token_ratio),
        "boilerplate_proportion": _r(boilerplate_prop),
        "mean_template_tokens": _r(mean_template_tokens_val),
    })

    return {
        "source_file": source_file,
        "n_lines": n_lines,
        "n_templates": n_templates,
        "near_dup_ratio": near_dup_ratio,
        "d1_robust_v2": d1_robust_v2,
    }


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def mine_templates(
    normalized_csv: Path,
    output_dir: Path,
    config: DrainConfig | None = None,
    write_line_assignments: bool = True,
    sample_fraction: float = 1.0,
    skip_metrics_files: bool = True,
) -> dict[str, Any]:
    """Run Drain on all source files in a normalized CSV and write the Stage 2 outputs.

    Args:
        normalized_csv: Path to the normalized CSV produced by Stage 1.
        output_dir: Directory to write outputs into.
        config: Drain configuration. Defaults to DrainConfig().
        write_line_assignments: Whether to write drain_lines.csv (large file).
        sample_fraction: Fraction of source files to process (0.0-1.0). Files
            are selected by stride over the file ordering so the sample is
            spread evenly. 1.0 processes all files.
        skip_metrics_files: Skip the telemetry files matched by _is_metrics_file
            (Logstash/Metricbeat system metrics and Suricata stats.log).

    Returns:
        Summary dict mirroring drain_summary.json.
    """
    if config is None:
        config = DrainConfig()

    output_dir.mkdir(parents=True, exist_ok=True)
    templates_csv = output_dir / "drain_templates.csv"
    lines_csv = output_dir / "drain_lines.csv"
    d1_csv = output_dir / "d1_metrics.csv"
    summary_json = output_dir / "drain_summary.json"

    sample_fraction = max(0.0, min(1.0, sample_fraction))
    stride = max(1, round(1.0 / sample_fraction)) if sample_fraction < 1.0 else 1

    total_files = 0
    total_templates = 0
    total_lines = 0
    file_index = 0
    skipped_metrics: list[str] = []

    # The dataset-wide near-duplicate ratio is computed afterwards from
    # drain_templates.csv by compute_global_neardup below.

    lines_ctx: Any
    if write_line_assignments:
        lines_ctx = lines_csv.open("w", newline="", encoding="utf-8")
    else:

        class _NullFile:
            def write(self, *a: Any) -> int:
                return 0

            def __enter__(self) -> "_NullFile":
                return self

            def __exit__(self, *a: Any) -> None:
                pass

        lines_ctx = _NullFile()

    with (
        templates_csv.open("w", newline="", encoding="utf-8") as tf,
        lines_ctx as lf_raw,
        d1_csv.open("w", newline="", encoding="utf-8") as df,
        normalized_csv.open("r", newline="", encoding="utf-8") as nf,
    ):
        t_writer = csv.DictWriter(tf, fieldnames=DRAIN_TEMPLATES_COLUMNS)
        t_writer.writeheader()

        l_writer: csv.DictWriter | None = None
        if write_line_assignments:
            l_writer = csv.DictWriter(lf_raw, fieldnames=DRAIN_LINES_COLUMNS)
            l_writer.writeheader()

        d_writer = csv.DictWriter(df, fieldnames=D1_METRICS_COLUMNS)
        d_writer.writeheader()

        reader = csv.DictReader(nf)

        for source_file, group_iter in groupby(reader, key=lambda r: r["source_file"]):
            if file_index % stride != 0:
                for _ in group_iter:
                    pass
                file_index += 1
                continue
            file_index += 1
            if skip_metrics_files and _is_metrics_file(source_file):
                skipped_metrics.append(source_file)
                for _ in group_iter:
                    pass
                continue
            stats = _process_source(source_file, group_iter, config, t_writer, l_writer, d_writer)
            total_files += 1
            total_templates += stats["n_templates"]
            total_lines += stats["n_lines"]
            if total_files % 50 == 0:
                print(f"  processed {total_files} source files, {total_lines:,} lines so far...")

    summary: dict[str, Any] = {
        "total_source_files": total_files,
        "total_templates": total_templates,
        "total_lines_processed": total_lines,
        "drain_config": {
            "depth": config.depth,
            "sim_th": config.sim_th,
            "max_children": config.max_children,
            "max_clusters": config.max_clusters,
            "parametrize_numeric_tokens": config.parametrize_numeric_tokens,
        },
        "write_line_assignments": write_line_assignments,
        "sample_fraction": sample_fraction,
        "skip_metrics_files": skip_metrics_files,
        "skipped_metrics_files_count": len(skipped_metrics),
        "skipped_metrics_files": skipped_metrics,
        "outputs": {
            "drain_templates_csv": str(templates_csv),
            "drain_lines_csv": str(lines_csv) if write_line_assignments else None,
            "d1_metrics_csv": str(d1_csv),
            "drain_summary_json": str(summary_json),
        },
    }
    summary_json.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return summary

csv.field_size_limit(10_000_000)

SIM_THRESHOLD = 0.8
MAX_SAMPLE = 5_000


# ---------------------------------------------------------------------------
# Core computation
# ---------------------------------------------------------------------------

def compute_global_neardup(templates_csv: Path) -> dict:
    t0 = time.time()

    # Global template registry: template_str -> set of source files
    template_files: dict[str, set[str]] = defaultdict(set)
    with open(templates_csv, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            tstr = row.get("template_str", "").strip()
            sf   = row.get("source_file", "")
            if tstr:
                template_files[tstr].add(sf)

    n_files = len({sf for files in template_files.values() for sf in files})
    total = len(template_files)
    templates_list = list(template_files.items())   # [(tstr, {files}), ...]

    # Exact cross-file duplicates: same template_str in more than one file (informational)
    exact_cross = sum(1 for _, files in templates_list if len(files) > 1)
    exact_ratio = exact_cross / total if total > 0 else 0.0

    # Stride sampling for large vocabularies
    sampled = total > MAX_SAMPLE
    if sampled:
        step = total // MAX_SAMPLE
        templates_list = templates_list[::step][:MAX_SAMPLE]
    sample_size = len(templates_list)

    # Token sets without the <*> wildcard
    token_sets = [
        (tstr, files, frozenset(tstr.split()) - {"<*>"})
        for tstr, files in templates_list
    ]

    # Inverted index: token -> template indices
    inv_index: dict[str, list[int]] = defaultdict(list)
    for idx, (_, _, toks) in enumerate(token_sets):
        for tok in toks:
            inv_index[tok].append(idx)

    is_near_dup = [False] * sample_size

    for i, (tstr_i, files_i, toks_i) in enumerate(token_sets):
        if is_near_dup[i]:
            continue
        if not toks_i:
            continue
        # Candidates: any other template sharing at least one token, regardless of file
        candidates: set[int] = set()
        for tok in toks_i:
            for j in inv_index[tok]:
                if j != i:
                    candidates.add(j)
        for j in candidates:
            toks_j = token_sets[j][2]
            union_size = len(toks_i | toks_j)
            if union_size and len(toks_i & toks_j) / union_size >= SIM_THRESHOLD:
                is_near_dup[i] = True
                is_near_dup[j] = True
                break

    near_dup_count = sum(is_near_dup)
    # Lower bound: exact cross-file duplicates in the sample are near-duplicates by definition
    sample_exact = sum(1 for _, files, _ in token_sets if len(files) > 1)
    near_dup_count = max(near_dup_count, sample_exact)

    ratio = near_dup_count / sample_size if sample_size > 0 else 0.0

    elapsed = round(time.time() - t0, 1)

    return {
        "n_files": n_files,
        "total_distinct_templates": total,
        "global_neardup_count": near_dup_count,
        "global_neardup_ratio": round(ratio, 6),
        "exact_cross_file_dups": exact_cross,
        "exact_cross_file_ratio": round(exact_ratio, 6),
        "sampled": sampled,
        "sample_size": sample_size,
        "sim_threshold": SIM_THRESHOLD,
        "elapsed_s": elapsed,
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Stage 2: template mining, per-file metrics and the near-duplicate ratio",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    p.add_argument("--normalized-csv", help="Stage 1 output; not needed with --neardup-only")
    p.add_argument("--output-dir", required=True, help="where the Stage 2 files are written")
    p.add_argument("--drain-depth", type=int, default=4, help="Drain parse tree depth")
    p.add_argument("--drain-sim-th", type=float, default=0.5,
                   help="similarity threshold for merging a line into a cluster")
    p.add_argument("--drain-max-children", type=int, default=100,
                   help="maximum children per internal node")
    p.add_argument("--drain-max-clusters", type=int, default=500,
                   help="maximum clusters per source file; 0 disables the cap")
    p.add_argument("--no-parametrize-numeric", action="store_true", default=False,
                   help="do not replace numeric tokens before matching")
    p.add_argument("--no-line-assignments", action="store_true", default=False,
                   help="do not write drain_lines.csv, the per-line template assignments")
    p.add_argument("--no-skip-metrics-files", action="store_true", default=False,
                   help="include per-second telemetry files that are skipped by default")
    p.add_argument("--sample-fraction", type=float, default=1.0,
                   help="fraction of source files to process")
    p.add_argument("--neardup-only", action="store_true",
                   help="recompute only the near-duplicate ratio from drain_templates.csv")
    return p


def main() -> None:
    args = _build_parser().parse_args()
    output_dir = Path(args.output_dir)

    if not args.neardup_only:
        if not args.normalized_csv:
            raise SystemExit("--normalized-csv is required unless --neardup-only is given")
        normalized_csv = Path(args.normalized_csv)
        if not normalized_csv.exists():
            raise SystemExit(f"normalized CSV not found: {normalized_csv}")

        config = DrainConfig(
            depth=args.drain_depth,
            sim_th=args.drain_sim_th,
            max_children=args.drain_max_children,
            max_clusters=args.drain_max_clusters,
            parametrize_numeric_tokens=not args.no_parametrize_numeric,
        )
        print("Stage 2: template mining")
        print(f"  input:      {normalized_csv}")
        print(f"  output_dir: {output_dir}")
        started = time.perf_counter()
        summary = mine_templates(
            normalized_csv=normalized_csv,
            output_dir=output_dir,
            config=config,
            write_line_assignments=not args.no_line_assignments,
            skip_metrics_files=not args.no_skip_metrics_files,
            sample_fraction=args.sample_fraction,
        )
        print(f"  done in {time.perf_counter() - started:.1f}s")
        print(f"  source files: {summary['total_source_files']}")
        print(f"  templates:    {summary['total_templates']}")
        print(f"  lines:        {summary['total_lines_processed']}")

    templates_csv = output_dir / "drain_templates.csv"
    if not templates_csv.exists():
        raise SystemExit(f"template table not found: {templates_csv}")
    print("\nGlobal near-duplicate ratio")
    started = time.perf_counter()
    result = compute_global_neardup(templates_csv)
    out_path = output_dir / "d1_global_neardup.json"
    out_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(f"  distinct templates: {result['total_distinct_templates']}")
    print(f"  near-duplicate ratio: {result['global_neardup_ratio']:.4f}")
    print(f"  done in {time.perf_counter() - started:.1f}s")
    print(f"\nWritten to {output_dir}")


if __name__ == "__main__":
    main()
