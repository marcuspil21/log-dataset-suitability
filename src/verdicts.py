"""The decision rule, and the verdict table it produces.

Each task has a set of necessary dimensions. A dataset is SUITABLE for a task
when every necessary dimension reaches its threshold, UNSUITABLE when one falls
below it, and INDETERMINATE when one could not be measured. A dimension that
cannot be measured is a withheld judgment, not a failure, so INDETERMINATE
outranks UNSUITABLE. Supporting dimensions are reported alongside a verdict and
never change it.

Before applying the rule, the stored scores are mapped to the gating values:
D1 from the near-duplicate corrected composite, D3 from max(U, purity), and D4
from the better of the two linkability channels.

D5 to D7 are descriptive and gate nothing.

Reads the corpus through src/registry.py, so no raw data is needed.

Usage:
  python src/verdicts.py
  python src/verdicts.py --tau-d1 0.35 --output-dir outputs/verdicts
"""
from __future__ import annotations

import argparse
import csv
import datetime
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from paths import VERDICTS
from registry import (
    CORPUS_SCORES,
    D3_FILE_LEVEL_ARTEFACT,
    D3_INFO,
    D3_REVISED,
    D6_INFO,
    D6_TACTIC_RESOLUTION,
    D7_INFO,
    INDETERMINATE_NOTES,
    d3_gating,
    d4_gating,
)


APPLICATION_CLASSES: dict[str, dict[str, Any]] = {
    "anomaly_detection": {
        "display_name": "Anomaly Detection",
        "necessary": ["D1", "D3"],
        "supporting": ["D2"],
    },
    "incident_reconstruction": {
        "display_name": "Incident Reconstruction",
        "necessary": ["D2", "D4"],
        "supporting": ["D1", "D3"],
    },
    "root_cause_analysis": {
        "display_name": "Root Cause Analysis",
        "necessary": ["D3", "D4"],
        "supporting": ["D2"],
    },
    "cti_attribution": {
        "display_name": "CTI / ATT&CK Attribution",
        "necessary": ["D3"],
        "supporting": ["D1", "D4"],
    },
}

THRESHOLDS: dict[str, float] = {
    "D1": 0.40,
    "D2": 0.15,
    "D3": 0.25,  # for the information-theoretic D3 = max(U, purity); stable over [0.15, 0.30]
    "D4": 0.40,
    "D5": 0.40,
}

# Human-readable calibration status of each threshold (reported in the verdict table).
THRESHOLD_CALIBRATION_STATUS: dict[str, str] = {
    "D1": "calibrated by boilerplate-concentration perturbation on the calibration subset (rho = -1.0); scale-invariant under uniform duplication",
    "D2": "calibrated by permutation null analysis (tau* = 0.15); structural threshold held fixed",
    "D3": "calibrated for the information-theoretic D3 = max(U, purity) (tau* = 0.25) by null-floor, corpus-gap and classifier-anchor triangulation",
    "D4": "placement indicative; response tested by entity-scrub perturbation (rho <= -0.98 on three datasets); external footing from the entity-recall probe",
    "D5": "non-gating descriptive metric; threshold retained for reporting only; sensitivity-validated by boilerplate-injection perturbation on the calibration subset (rho = -1.0); no external probe",
}


def assess_suitability(
    scores: dict[str, float | None],
    application: str,
    d3_cross_file_jaccard: float | None = None,
    d3_structural_flag: bool = False,
) -> dict[str, Any]:
    """Return a verdict dict for a dataset's D-scores against an application class.

    Parameters
    ----------
    scores:
        Dict mapping dimension names ("D1".."D5") to float scores or None.
        None means the dimension could not be computed for this dataset.
    application:
        Key from APPLICATION_CLASSES (e.g. "anomaly_detection").
    d3_cross_file_jaccard:
        Cross-file Jaccard similarity between the attack-pool and normal-pool
        template sets. Used as the effective D3 only when
        d3_structural_flag is True; ignored otherwise.
    d3_structural_flag:
        True when the within-file D3 score is a structural artefact of file-level
        labelling (every source file is entirely attack or entirely normal, so
        the class separation ratio is 1.000 regardless of template
        separability). When True and d3_cross_file_jaccard is given, the Jaccard
        substitutes for D3; when True and d3_cross_file_jaccard is None, D3 is
        treated as unavailable (INDETERMINATE). With the defaults the scores are
        used as given.

    Returns
    -------
    dict with keys:
        application, display_name, verdict, dimension_results,
        supporting_pass, supporting_total, necessary_dims, supporting_dims
    """
    # Resolve the effective D3 score.
    if d3_structural_flag:
        effective_scores = dict(scores)
        if d3_cross_file_jaccard is not None:
            effective_scores["D3"] = d3_cross_file_jaccard
        else:
            effective_scores["D3"] = None
    else:
        effective_scores = scores
    if application not in APPLICATION_CLASSES:
        raise ValueError(
            f"Unknown application '{application}'. "
            f"Valid keys: {list(APPLICATION_CLASSES)}"
        )

    app = APPLICATION_CLASSES[application]
    tau = THRESHOLDS

    dimension_results: dict[str, dict[str, Any]] = {}
    verdict = "SUITABLE"

    # Necessary dimensions decide the verdict.
    for dim in app["necessary"]:
        val = effective_scores.get(dim)
        threshold = tau[dim]
        if val is None:
            dimension_results[dim] = {
                "role": "necessary",
                "score": None,
                "threshold": threshold,
                "result": "INDETERMINATE",
            }
            verdict = "INDETERMINATE"
        elif val >= threshold:
            dimension_results[dim] = {
                "role": "necessary",
                "score": round(float(val), 4),
                "threshold": threshold,
                "result": "PASS",
            }
        else:
            dimension_results[dim] = {
                "role": "necessary",
                "score": round(float(val), 4),
                "threshold": threshold,
                "result": "FAIL",
            }
            # UNSUITABLE only overrides SUITABLE, never INDETERMINATE.
            if verdict == "SUITABLE":
                verdict = "UNSUITABLE"

    # Supporting dimensions are informational and do not affect the verdict.
    for dim in app["supporting"]:
        val = effective_scores.get(dim)
        threshold = tau[dim]
        if val is None:
            dimension_results[dim] = {
                "role": "supporting",
                "score": None,
                "threshold": threshold,
                "result": "INDETERMINATE",
            }
        elif val >= threshold:
            dimension_results[dim] = {
                "role": "supporting",
                "score": round(float(val), 4),
                "threshold": threshold,
                "result": "PASS",
            }
        else:
            dimension_results[dim] = {
                "role": "supporting",
                "score": round(float(val), 4),
                "threshold": threshold,
                "result": "FAIL",
            }

    supporting_pass = sum(
        1 for d in app["supporting"]
        if dimension_results.get(d, {}).get("result") == "PASS"
    )

    return {
        "application": application,
        "display_name": app["display_name"],
        "verdict": verdict,
        "dimension_results": dimension_results,
        "supporting_pass": supporting_pass,
        "supporting_total": len(app["supporting"]),
        "necessary_dims": app["necessary"],
        "supporting_dims": app["supporting"],
    }


def assess_all_applications(
    scores: dict[str, float | None],
    d3_cross_file_jaccard: float | None = None,
    d3_structural_flag: bool = False,
) -> dict[str, dict[str, Any]]:
    """Run assess_suitability for all application classes."""
    return {
        app: assess_suitability(scores, app, d3_cross_file_jaccard, d3_structural_flag)
        for app in APPLICATION_CLASSES
    }

VERDICT_SYMBOL = {
    "SUITABLE": "SUITABLE",
    "UNSUITABLE": "UNSUITABLE",
    "INDETERMINATE": "INDET.",
}

# Application classes whose necessary set includes D4 (used to select the
# datasets for the supplementary D5/D6/D7 table).
_D4_GATED_TASKS = {"incident_reconstruction", "root_cause_analysis"}


def build_verdict_rows(tau_overrides: dict[str, float] | None = None) -> list[dict]:
    """Return one verdict dict per (dataset, application).

    tau_overrides temporarily replaces entries of THRESHOLDS for the duration
    of the call, so a caller can explore other thresholds without editing them.
    """
    original = dict(THRESHOLDS)
    if tau_overrides:
        THRESHOLDS.update(tau_overrides)
    try:
        rows = []
        for dataset, scores in CORPUS_SCORES.items():
            # D1_robust is the canonical D1 where available.
            effective_scores = {**scores, "D1": scores.get("D1_robust") if scores.get("D1_robust") is not None else scores.get("D1")}
            # D4 gate: max(D4_conn, D4_part).
            effective_scores["D4"] = d4_gating(scores)
            # D3 gate: information-theoretic max(U, purity) for every labelled
            # dataset; datasets absent from D3_INFO keep their registry D3 entry
            # (None for the unlabelled ones).
            if dataset in D3_INFO:
                effective_scores = {**effective_scores, "D3": d3_gating(dataset)}
            for app_key in APPLICATION_CLASSES:
                result = assess_suitability(effective_scores, app_key)
                app = APPLICATION_CLASSES[app_key]

                dim_scores = {
                    dim: result["dimension_results"].get(dim, {}).get("score")
                    for dim in ["D1", "D2", "D3", "D4", "D5"]
                }
                row = {
                    "dataset":        dataset,
                    "application":    result["display_name"],
                    "verdict":        result["verdict"],
                    "necessary_dims": ",".join(app["necessary"]),
                    "supporting_dims": ",".join(app["supporting"]),
                    "supporting_pass": f"{result['supporting_pass']}/{result['supporting_total']}",
                }
                for dim in ["D1", "D2", "D3", "D4", "D5"]:
                    row[f"{dim}_score"] = dim_scores[dim]
                    row[f"{dim}_thresh"] = THRESHOLDS[dim]
                rows.append(row)
        return rows
    finally:
        THRESHOLDS.clear()
        THRESHOLDS.update(original)


def write_csv(rows: list[dict], path: Path) -> None:
    fieldnames = [
        "dataset", "application", "verdict",
        "necessary_dims", "supporting_dims", "supporting_pass",
        "D1_score", "D1_thresh",
        "D2_score", "D2_thresh",
        "D3_score", "D3_thresh",
        "D4_score", "D4_thresh",
        "D5_score", "D5_thresh",
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)
    print(f"  Wrote: {path}")


def write_markdown(rows: list[dict], path: Path) -> None:
    """Write a compact pivot table: datasets as rows, applications as columns."""
    apps = [APPLICATION_CLASSES[k]["display_name"] for k in APPLICATION_CLASSES]
    datasets = list(CORPUS_SCORES)

    verdict_map: dict[tuple[str, str], str] = {
        (r["dataset"], r["application"]): r["verdict"]
        for r in rows
    }

    # Score cells per dataset. The D1 column shows D1_robust where available and
    # the D3 column the effective D3 the rule gates on: max(U, purity), marked
    # with * (or with a dagger for file-level-label artefacts); D3_REVISED is
    # the fallback for a labelled dataset absent from D3_INFO.
    score_map: dict[str, dict[str, str]] = {
        ds: {
            dim: (f"{v:.3f}" if v is not None else "–")
            for dim, v in scores.items()
        }
        for ds, scores in CORPUS_SCORES.items()
    }
    for ds, scores in CORPUS_SCORES.items():
        d1r = scores.get("D1_robust")
        score_map[ds]["D1"] = f"{d1r:.3f}" if d1r is not None else score_map[ds].get("D1", "–")
        d3eff = d3_gating(ds)
        if d3eff is None:
            d3eff = D3_REVISED.get(ds)
        if d3eff is not None:
            mark = "†" if ds in D3_FILE_LEVEL_ARTEFACT else "*"
            score_map[ds]["D3"] = f"{d3eff:.3f}{mark}"

    lines = [
        "# Corpus Suitability Assessment",
        "",
        f"**Generated:** {datetime.date.today().isoformat()}  ",
        "**Decision rule:** `src/verdicts.py`  ",
        "**Verdicts:** SUITABLE = all necessary dims ≥ τ; UNSUITABLE = any necessary dim < τ; "
        "INDET. = any necessary dim unavailable  ",
        "",
        "## Threshold values",
        "",
        "| Dimension | τ | Calibration status |",
        "|---|---|---|",
    ]
    for dim, tau in THRESHOLDS.items():
        lines.append(f"| {dim} | {tau} | {THRESHOLD_CALIBRATION_STATUS[dim]} |")

    lines += [
        "",
        "## Verdict table",
        "",
    ]

    header = "| Dataset | D1_robust | D2 | D3_eff | D4_conn | D4_part | D4_max | D5 | " + " | ".join(apps) + " |"
    sep = "|---|---|---|---|---|---|---|---|" + "|".join(["---"] * len(apps)) + "|"
    lines.append(header)
    lines.append(sep)

    for ds in datasets:
        sc = score_map[ds]
        verdicts = [
            VERDICT_SYMBOL.get(verdict_map.get((ds, a), "–"), "–")
            for a in apps
        ]
        d4_part = sc.get("D4_part", "–")
        d4m = d4_gating(CORPUS_SCORES[ds])
        d4_max = f"{d4m:.3f}" if d4m is not None else "–"
        lines.append(
            f"| {ds} | {sc['D1']} | {sc['D2']} | {sc['D3']} | {sc['D4']} | {d4_part} | **{d4_max}** | {sc['D5']} | "
            + " | ".join(verdicts) + " |"
        )

    n_datasets = len(datasets)
    n_pairs = n_datasets * len(apps)
    lines += [
        "",
        "\\* D3_eff = information-theoretic D3 = max(U, purity), the value the decision "
        f"rule gates on for every labelled dataset (τ_D3 = {THRESHOLDS['D3']}).",
        "",
        "**D5 is non-gating.** The D5 column is reported for context only; semantic richness "
        "does not enter any verdict. CTI gates on D3 alone, so D5 is a descriptive "
        "dimension alongside D6 and D7. "
        f"The verdict space is {n_datasets} dataset(s) x {len(apps)} tasks = {n_pairs} pairs.",
    ]
    if D3_FILE_LEVEL_ARTEFACT:
        marked = ", ".join(sorted(D3_FILE_LEVEL_ARTEFACT))
        lines += [
            "",
            f"**† File-level-label artefact ({marked}).** These datasets carry per-file "
            "labels, so max(U, purity) reflects file identity rather than per-line attack "
            "separability. The value is kept for consistency with the other labelled "
            "datasets; verdicts that rest on it are artefacts of the labelling "
            "granularity, not evidence of separability.",
        ]
    if INDETERMINATE_NOTES:
        lines += ["", "## Notes on INDETERMINATE verdicts", ""]
        for ds, dim_notes in INDETERMINATE_NOTES.items():
            for dim, note in dim_notes.items():
                lines.append(f"- **{ds} / {dim}:** {note}")

    # Supplementary D5/D6/D7 context for labelled datasets that are SUITABLE on
    # a D4-gated task.
    d4_task_names = {APPLICATION_CLASSES[k]["display_name"] for k in _D4_GATED_TASKS}
    suit_d4: dict[str, list[str]] = {}
    for r in rows:
        if r["application"] in d4_task_names and r["verdict"] == "SUITABLE":
            suit_d4.setdefault(r["dataset"], []).append(r["application"])
    supp = [(ds, tasks, D6_INFO.get(ds), D7_INFO.get(ds))
            for ds, tasks in suit_d4.items()
            if CORPUS_SCORES.get(ds, {}).get("D3") is not None]  # has attack labels
    if supp:
        lines += [
            "",
            "## Supplementary descriptive dimensions (D5/D6/D7) -- non-gating",
            "",
            "Descriptive metrics that do not affect any verdict. "
            "D5 = semantic richness (reported for every dataset; full column in the verdict "
            "table above). D6 = ATT&CK technique diversity, supplied in the corpus file; a "
            "value marked † was derived from tactic labels rather than technique codes and "
            "is not comparable with the others. D7 = normal-workflow diversity, also "
            "supplied in the corpus file. The rows below add D5/D6/D7 context for datasets "
            "**SUITABLE on a D4-gated task (Incident Reconstruction / Root Cause Analysis) "
            "with attack labels**.",
            "",
            "| Dataset | D4-suitable for | D5 (semantic) | D6 (ATT&CK div.) | D7 (workflow div.) |",
            "|---|---|---|---|---|",
        ]
        for ds, tasks, d6, d7 in supp:
            t = ", ".join("IR" if "Incident" in x else "RCA" for x in sorted(tasks))
            d5v = CORPUS_SCORES.get(ds, {}).get("D5")
            d5s = f"{d5v:.3f}" if d5v is not None else "N/A"
            d6s = f"{d6:.3f}" if d6 is not None else "N/A"
            if d6 is not None and ds in D6_TACTIC_RESOLUTION:
                d6s += "†"
            d7s = f"{d7:.3f}" if d7 is not None else "N/A"
            lines.append(f"| {ds} | {t} | {d5s} | {d6s} | {d7s} |")

    lines += [
        "",
        "## Application class definitions",
        "",
        "| Application | Necessary (Na) | Supporting (Sa) |",
        "|---|---|---|",
    ]
    for app_key, app_def in APPLICATION_CLASSES.items():
        na = ", ".join(app_def["necessary"])
        sa = ", ".join(app_def["supporting"])
        lines.append(f"| {app_def['display_name']} | {na} | {sa} |")

    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    print(f"  Wrote: {path}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Write the verdict table for every dataset in the corpus",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    for dim in ("d1", "d2", "d3", "d4"):
        parser.add_argument(f"--tau-{dim}", type=float, default=None,
                            help=f"override the {dim.upper()} threshold "
                                 f"(default {THRESHOLDS[dim.upper()]})")
    parser.add_argument("--output-dir", type=Path, default=VERDICTS,
                        help="directory for suitability_verdicts.csv and .md")
    args = parser.parse_args()

    if not CORPUS_SCORES:
        print("No datasets recorded yet, so there is nothing to give a verdict on.")
        print("Profile one first: open notebooks/pipeline.ipynb, or run")
        print("  python src/run_pipeline.py --config configs/example.yml")
        print("and save the score vector it prints into the corpus file that "
              "src/registry.py loads.")
        return

    overrides = {dim.upper(): getattr(args, f"tau_{dim}")
                 for dim in ("d1", "d2", "d3", "d4")
                 if getattr(args, f"tau_{dim}") is not None}

    print("Thresholds:", THRESHOLDS)
    if overrides:
        print("Overrides: ", overrides)

    rows = build_verdict_rows(overrides or None)
    write_csv(rows, args.output_dir / "suitability_verdicts.csv")
    write_markdown(rows, args.output_dir / "suitability_verdicts.md")

    print("\nVerdicts:")
    datasets = list(CORPUS_SCORES)
    apps = list(APPLICATION_CLASSES)
    header = f"  {'Dataset':<16} " + "  ".join(f"{k[:9]:<9}" for k in apps)
    print(header)
    print("  " + "-" * (len(header) - 2))
    lookup = {(r["dataset"], r["application"]): r["verdict"] for r in rows}
    tally = {"SUITABLE": 0, "UNSUITABLE": 0, "INDETERMINATE": 0}
    for dataset in datasets:
        cells = []
        for key in apps:
            verdict = lookup.get((dataset, APPLICATION_CLASSES[key]["display_name"]), "?")
            tally[verdict] = tally.get(verdict, 0) + 1
            cells.append(f"{VERDICT_SYMBOL.get(verdict, '?'):<9}")
        print(f"  {dataset:<16} " + "  ".join(cells))

    total = sum(tally.values())
    print()
    for verdict in ("SUITABLE", "UNSUITABLE", "INDETERMINATE"):
        print(f"  {verdict:<15}{tally.get(verdict, 0):>4}  of {total} (dataset, task) pairs")


if __name__ == "__main__":
    main()
