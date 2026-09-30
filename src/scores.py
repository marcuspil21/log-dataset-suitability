"""Turn the stage outputs of a dataset into one score vector.

Two steps, both reading what Stages 2 and 3 wrote.

Label separability (D3) is measured on the global joint distribution of
(template, label) over the whole dataset rather than per file, which makes it
invariant to how the logs happen to be split into files. Two components are
reported: Theil's uncertainty coefficient U, estimated with Hausser-Strimmer
shrinkage, and a Jeffreys-smoothed attack-purity coverage. The decision rule
gates on their maximum. This step needs per-line labels and the per-line
template assignments; without either it is skipped.

The score vector then aggregates the per-file metrics to the dataset: medians
throughout, the near-duplicate correction applied to D1, and the two D4
channels read from the Stage 3 summary. The entry it prints is ready to paste
into the corpus file that src/registry.py loads.

Reads   outputs/<slug>/<stage2>/{d1_metrics.csv, drain_lines.csv,
        d1_global_neardup.json} and outputs/<slug>/stage3_d4/d4_summary.json
Writes  outputs/verdicts/d3_information.json

Usage:
  python src/scores.py --dataset <slug>
  python src/scores.py --dataset <slug> --json outputs/<slug>/scores.json
"""
from __future__ import annotations

import argparse
import csv
import json
import math
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import paths
from paths import VERDICTS
from registry import (
    D3_INFO,
    D3_REVISED,
    DATASETS,
    DRAIN_LINES_OVERRIDES,
    STAGE2_OVERRIDES,
    display_name_of,
    slug_of,
)


csv.field_size_limit(10 ** 8)

LOG2 = math.log(2.0)
ALPHA = BETA = 0.5   # Jeffreys prior for the purity smoothing

# Labelled datasets: the ones for which an information-theoretic D3 is defined.
TARGETS = list(D3_INFO)

# A (file index, line number) pair is packed into one integer; the multiplier
# exceeds the line count of every file, so keys cannot collide.
LINE_KEY_BASE = 10 ** 10

D3_INFORMATION_JSON = VERDICTS / "d3_information.json"


def resolve_paths(ds, stage2_subdir=None):
    """Return (drain_lines.csv, normalized_full.csv) for a dataset.

    A registered dataset is resolved through its slug and honours the Stage 2
    directory override recorded for it, unless `stage2_subdir` names the
    directory explicitly. A dataset that is not registered yet is resolved as a
    directory name under outputs/, so a new dataset can be measured before it
    is added to the corpus.
    """
    try:
        slug = slug_of(ds)
    except KeyError:
        slug = ds
    subdir = stage2_subdir or DRAIN_LINES_OVERRIDES.get(ds, "stage2")
    return (paths.dataset_dir(slug) / subdir / "drain_lines.csv",
            paths.normalized_csv(slug))


def template_label_counts(ds, stage2_subdir=None):
    """Pooled [attack_lines, normal_lines] per global template_id over all files,
    or None if an input file is missing."""
    lines_csv, normalized_csv = resolve_paths(ds, stage2_subdir)
    for path in (lines_csv, normalized_csv):
        if not path.exists():
            print(f"{ds}: missing {path}", flush=True)
            return None

    # Which (source file, line) pairs are attack lines, from the Stage 1 CSV.
    file_ids: dict[str, int] = {}
    attack_keys: set[int] = set()
    with normalized_csv.open(encoding="utf-8") as fh:
        reader = csv.reader(fh)
        header = next(reader)
        i_source = header.index("source_file")
        i_line = header.index("line_no")
        i_attack = header.index("is_attack")
        for row in reader:
            try:
                line_no = int(row[i_line])
            except (ValueError, IndexError):
                continue
            file_id = file_ids.setdefault(row[i_source], len(file_ids))
            if row[i_attack].strip().lower() in ("true", "1", "yes"):
                attack_keys.add(file_id * LINE_KEY_BASE + line_no)

    # Pool those labels by template id, using the per-line assignments.
    counts: dict[int, list[int]] = {}
    with lines_csv.open(encoding="utf-8") as fh:
        reader = csv.reader(fh)
        next(reader)
        for row in reader:
            if len(row) < 3:
                continue
            file_id = file_ids.get(row[0])
            if file_id is None:
                continue
            try:
                line_no = int(row[1])
                template_id = int(row[2])
            except ValueError:
                continue
            pair = counts.get(template_id)
            if pair is None:
                pair = counts[template_id] = [0, 0]
            is_attack = (file_id * LINE_KEY_BASE + line_no) in attack_keys
            pair[0 if is_attack else 1] += 1
    return counts


def _ent_bits(ps):
    return -sum(p * math.log(p) / LOG2 for p in ps if p > 0)


def metrics(counts):
    """U estimates and smoothed purity from pooled template-label counts."""
    A = sum(c[0] for c in counts.values())
    Nn = sum(c[1] for c in counts.values())
    N = A + Nn
    if N == 0 or A == 0:
        return {"n_attack": A, "n_total": N, "note": "no attack lines"}
    # plug-in entropies (bits)
    HL = _ent_bits([A / N, Nn / N])
    HLgivenT = 0.0
    for a, n in counts.values():
        tot = a + n
        HLgivenT += (tot / N) * _ent_bits([a / tot, n / tot])
    I_plug = HL - HLgivenT
    U_plug = I_plug / HL if HL > 0 else 0.0
    # Miller-Madow: correct H(L), H(T), H(L,T) by (m-1)/(2N) nats
    def mm(H_bits, m):
        return H_bits + (m - 1) / (2 * N) / LOG2
    m_L = (A > 0) + (Nn > 0)
    m_T = len(counts)
    m_LT = sum((a > 0) + (n > 0) for a, n in counts.values())
    HT = _ent_bits([(a + n) / N for a, n in counts.values()])
    HLT = _ent_bits([x / N for a, n in counts.values() for x in (a, n) if x > 0])
    HL_mm, HT_mm, HLT_mm = mm(HL, m_L), mm(HT, m_T), mm(HLT, m_LT)
    I_mm = HL_mm + HT_mm - HLT_mm
    U_mm = max(0.0, min(1.0, I_mm / HL_mm)) if HL_mm > 0 else 0.0
    # Hausser-Strimmer shrinkage on the joint cells
    cells = [x for a, n in counts.values() for x in (a, n) if x > 0]
    m = len(cells); t_unif = 1.0 / m
    sum_pml2 = sum((c / N) ** 2 for c in cells)
    denom = (N - 1) * sum((t_unif - c / N) ** 2 for c in cells)
    lam = 1.0 if denom == 0 else max(0.0, min(1.0, (1 - sum_pml2) / denom))
    # shrunk joint cell probabilities, marginals re-derived from them
    HLT_sh = 0.0; pL_a = 0.0
    pT = []
    for a, n in counts.values():
        pa = (lam * t_unif + (1 - lam) * a / N) if a > 0 else 0.0
        pn = (lam * t_unif + (1 - lam) * n / N) if n > 0 else 0.0
        pL_a += pa
        if pa > 0: HLT_sh -= pa * math.log(pa) / LOG2
        if pn > 0: HLT_sh -= pn * math.log(pn) / LOG2
        if (pa + pn) > 0: pT.append(pa + pn)
    HL_sh = _ent_bits([pL_a, 1 - pL_a])
    HT_sh = _ent_bits(pT)
    I_sh = HL_sh + HT_sh - HLT_sh
    U_sh = max(0.0, min(1.0, I_sh / HL_sh)) if HL_sh > 0 else 0.0
    # smoothed attack-purity coverage
    soft_cov = sum(a * (a + ALPHA) / (a + n + ALPHA + BETA) for a, n in counts.values()) / A
    return {
        "U_shrinkage": round(U_sh, 4),
        "U_millermadow": round(U_mm, 4),
        "U_plugin": round(U_plug, 4),
        "purity_coverage": round(soft_cov, 4),
        "shrink_lambda": round(lam, 4),
        "H_label_bits": round(HL, 4),
        "n_attack": A, "n_normal": Nn, "n_total": N,
        "n_templates": m_T,
    }


def merge_records(existing: list[dict], new: list[dict]) -> list[dict]:
    """Replace records of the same dataset in place, append the others."""
    by_name = {r["dataset"]: r for r in new}
    merged = [by_name.pop(r["dataset"], r) for r in existing]
    merged.extend(by_name.values())
    return merged


def _med(lst: list[float]) -> float:
    s = sorted(lst)
    n = len(s)
    if n == 0:
        return float("nan")
    return (s[n // 2 - 1] + s[n // 2]) / 2 if n % 2 == 0 else s[n // 2]


def _round(v: float | None, nd: int = 4) -> float | None:
    return round(v, nd) if v is not None else None


def load_d3_information(name: str | None) -> tuple[float | None, float | None]:
    """U and purity of one dataset, read back from d3_information.json."""
    if name is None or not D3_INFORMATION_JSON.exists():
        return None, None
    with D3_INFORMATION_JSON.open(encoding="utf-8") as fh:
        entries = json.load(fh)
    for entry in entries:
        if entry.get("dataset") == name:
            return entry.get("U_shrinkage"), entry.get("purity_coverage")
    return None, None


def resolve_dataset(token: str) -> tuple[str | None, str]:
    """Return (display name or None if unregistered, slug) for a CLI token."""
    if token in DATASETS:
        return token, DATASETS[token]
    if token in DATASETS.values():
        return display_name_of(token), token
    if (paths.OUTPUTS / token).is_dir():
        return None, token
    raise SystemExit(f"unknown dataset '{token}': not in the registry and "
                     f"{paths.OUTPUTS / token} does not exist")




def _stage2_file(stage2: Path, slug: str, filename: str) -> Path | None:
    """File under the chosen Stage 2 directory, else under the default stage2/."""
    p = stage2 / filename
    if p.exists():
        return p
    fallback = paths.stage2_dir(slug) / filename
    return fallback if fallback.exists() else None


def extract_scores(name: str | None, slug: str, stage2_subdir: str) -> dict:
    """Score vector of one dataset, or {} if d1_metrics.csv is absent."""
    stage2 = paths.dataset_dir(slug) / stage2_subdir
    metrics_csv = stage2 / "d1_metrics.csv"
    neardup_json = _stage2_file(stage2, slug, "d1_global_neardup.json")
    d3_json = _stage2_file(stage2, slug, "d3_cross_file.json")
    d4_json = paths.stage3_dir(slug) / "d4_summary.json"

    if not metrics_csv.exists():
        print(f"  {slug}: missing {metrics_csv}, skipping")
        return {}

    rows = list(csv.DictReader(metrics_csv.open(encoding="utf-8")))
    valid = [r for r in rows if r.get("total_lines") and int(r["total_lines"]) > 0]

    # D1 = median(H / log2 K) over files with more than one template
    d1_vals = []
    for r in valid:
        K = float(r["template_count"]) if r.get("template_count") else 1.0
        if K > 1 and r.get("shannon_entropy"):
            d1_vals.append(float(r["shannon_entropy"]) / math.log2(K))
    D1 = _med(d1_vals) if d1_vals else None

    # D2 = median(TE / log2(K)) over files with more than one template.
    # Single-template files have log2(K) = 0 and no transition structure to
    # normalise, so they are left out of the median rather than given a
    # substitute denominator. D2_all_files applies log2(max(K, 2)) to every
    # file instead and is reported for comparison only.
    d2_vals = []
    d2_vals_all = []
    for r in valid:
        K = float(r["template_count"]) if r.get("template_count") else 1.0
        TE = float(r["transition_entropy"]) if r.get("transition_entropy") and r["transition_entropy"] else 0.0
        d2_vals_all.append(TE / math.log2(max(K, 2)))
        if K > 1:
            d2_vals.append(TE / math.log2(K))
    D2 = _med(d2_vals) if d2_vals else None
    D2_all_files = _med(d2_vals_all)

    # D5 = 1 - median(boilerplate_proportion)
    d5_vals = [float(r["boilerplate_proportion"]) for r in valid
               if r.get("boilerplate_proportion") and r["boilerplate_proportion"]]
    D5 = 1.0 - _med(d5_vals) if d5_vals else None

    # D1_robust: per-file median of d1_robust_v2, then the per-file near-duplicate
    # term is replaced by the dataset-wide ratio.
    d1r_vals = [float(r["d1_robust_v2"]) for r in valid
                if r.get("d1_robust_v2") and r["d1_robust_v2"]]
    per_file_d1_robust_v2 = _med(d1r_vals) if d1r_vals else None
    nd_vals = [float(r["near_duplicate_ratio"]) for r in valid
               if r.get("near_duplicate_ratio") and r["near_duplicate_ratio"]]
    per_file_nd = _med(nd_vals) if nd_vals else None

    global_nd: float | None = None
    D1_robust: float | None = None
    if neardup_json is not None:
        with open(neardup_json, encoding="utf-8") as f:
            nd_data = json.load(f)
        global_nd = nd_data.get("global_neardup_ratio")
        if global_nd is not None and per_file_d1_robust_v2 is not None and per_file_nd is not None:
            D1_robust = per_file_d1_robust_v2 + 0.25 * (per_file_nd - global_nd)

    # D3 (class separation ratio) and D3_revised (attack-exclusive line
    # coverage), both averaged over files with attack lines.
    attack_rows = [r for r in valid if r.get("attack_lines") and int(r["attack_lines"]) > 0]
    d3_rev_vals = [float(r["attack_exclusive_line_coverage"]) for r in attack_rows
                   if r.get("attack_exclusive_line_coverage") and r["attack_exclusive_line_coverage"]]
    D3_revised = sum(d3_rev_vals) / len(d3_rev_vals) if d3_rev_vals else None
    d3_raw_vals = [float(r["class_separation_ratio"]) for r in attack_rows
                   if r.get("class_separation_ratio") and r["class_separation_ratio"]]
    D3_raw = sum(d3_raw_vals) / len(d3_raw_vals) if d3_raw_vals else None

    # Cross-file template Jaccard (reference only).
    D3_jaccard: float | None = None
    if d3_json is not None:
        with open(d3_json, encoding="utf-8") as f:
            d3_data = json.load(f)
        raw_j = d3_data.get("jaccard", "")
        if raw_j not in ("", None):
            D3_jaccard = float(str(raw_j).replace(",", "."))

    # D4 channels from Stage 3.
    D4_conn: float | None = None
    D4_part: float | None = None
    if d4_json.exists():
        with open(d4_json, encoding="utf-8") as f:
            d4_data = json.load(f)
        # With fewer than two hosts there are no host pairs, so D4 is undefined
        # rather than zero. The summary reports 0.0 in its ratio fields in that
        # case, which would otherwise read as "measured, no sharing".
        if d4_data.get("cross_host_pair_count", 0) < 1:
            D4_conn = D4_part = None
        elif d4_data.get("entity_types") and sum(
                t.get("total_distinct", 0)
                for t in d4_data["entity_types"].values()) == 0:
            # No entity of any recognised family occurs anywhere in the dataset,
            # so linkability was never observable: undefined, not measured zero.
            D4_conn = D4_part = None
        else:
            # "D4_conn" present and null means undefined; only a summary written
            # before the two channels were separated lacks the key entirely.
            D4_conn = (d4_data["D4_conn"] if "D4_conn" in d4_data
                       else d4_data.get("ip_sharing_ratio"))
            D4_part = d4_data.get("D4_part")
    else:
        print(f"  {slug}: missing {d4_json}, D4 not available")

    # An unregistered dataset is recorded under its slug by the step above.
    U, purity = load_d3_information(name if name is not None else slug)

    return {
        "dataset": name if name is not None else slug,
        "slug": slug,
        "stage2_subdir": stage2_subdir,
        "D1": _round(D1),
        "D1_robust_v2_prelim": _round(per_file_d1_robust_v2),
        "per_file_nd": _round(per_file_nd),
        "global_nd": _round(global_nd),
        "D1_robust": _round(D1_robust),
        "D2": _round(D2),
        "D2_all_files": _round(D2_all_files),
        "D3": _round(D3_raw),
        "D3_revised": _round(D3_revised),
        "D3_jaccard": _round(D3_jaccard),
        "D3_U": U,
        "D3_purity": purity,
        "D4_conn": _round(D4_conn),
        "D4_part": _round(D4_part),
        "D5": _round(D5),
        "n_files": len(valid),
        "n_attack_files": len(attack_rows),
    }


def _fmt(v) -> str:
    return "None" if v is None else str(v)


def measure_separability(targets, output, stage2_subdir=None):
    """Measure label separability for each dataset that allows it.

    `stage2_subdir` names the Stage 2 directory holding drain_lines.csv; by
    default the recorded override for the dataset, else stage2/."""
    records = []
    for dataset in targets:
        counts = template_label_counts(dataset, stage2_subdir)
        if counts is None:
            continue
        measured = metrics(counts)
        records.append({"dataset": dataset, "D3_revised_old": D3_REVISED.get(dataset),
                        **measured})
        if "U_shrinkage" in measured:
            print(f"  {dataset:<16} U={measured['U_shrinkage']:.4f}  "
                  f"purity={measured['purity_coverage']:.4f}  "
                  f"templates={measured['n_templates']}")
        else:
            print(f"  {dataset:<16} {measured.get('note')}")
    if not records:
        return []
    if output.exists():
        with output.open(encoding="utf-8") as fh:
            records = merge_records(json.load(fh), records)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8") as fh:
        json.dump(records, fh, indent=1)
    print(f"  written to {output}")
    return records


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Dataset-level scores from the stage outputs",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("--dataset", nargs="+", metavar="NAME", default=None,
                        help="datasets to score, by name, slug, or directory under "
                             "outputs/; default: every dataset in the corpus")
    parser.add_argument("--stage2-subdir", default=None, metavar="NAME",
                        help="Stage 2 directory to read; default: the recorded "
                             "override, else 'stage2'")
    parser.add_argument("--json", type=Path, default=None, metavar="PATH",
                        help="also write the score entries to this file")
    parser.add_argument("--skip-d3", action="store_true",
                        help="do not recompute label separability")
    args = parser.parse_args()

    tokens = args.dataset if args.dataset else list(DATASETS)

    if not args.skip_d3:
        print("Label separability (D3)")
        if not measure_separability(tokens, VERDICTS / "d3_information.json",
                                    args.stage2_subdir):
            print("  not computable here; needs per-line labels and drain_lines.csv")
        print()

    results = []
    for token in tokens:
        name, slug = resolve_dataset(token)
        subdir = args.stage2_subdir
        if subdir is None:
            subdir = STAGE2_OVERRIDES.get(name, "stage2") if name is not None else "stage2"
        scores = extract_scores(name, slug, subdir)
        if not scores:
            continue
        results.append(scores)
        note = (f"(global near-duplicate {scores['global_nd']:.4f})"
                if scores["global_nd"] is not None
                else "(d1_global_neardup.json missing, no correction applied)")
        print(f"{scores['dataset']}  [{slug}/{subdir}]")
        print(f"  D1         = {_fmt(scores['D1'])}")
        print(f"  D1_robust  = {_fmt(scores['D1_robust'])}  {note}")
        print(f"  D2         = {_fmt(scores['D2'])}")
        print(f"  D3         = {_fmt(scores['D3'])}  (legacy per-file value)")
        if scores["D3_U"] is not None:
            print(f"  D3 U/purity= {scores['D3_U']} / {scores['D3_purity']}")
        else:
            print("  D3 U/purity= not computed")
        print(f"  D4_conn    = {_fmt(scores['D4_conn'])}")
        print(f"  D4_part    = {_fmt(scores['D4_part'])}")
        print(f"  D5         = {_fmt(scores['D5'])}")
        print(f"  files: {scores['n_files']} total, "
              f"{scores['n_attack_files']} with attack lines")
        print()

    if not results:
        raise SystemExit("no dataset had stage output to score")

    print("=" * 62)
    print("Corpus entries: paste into the file that src/registry.py loads")
    print("=" * 62)
    for entry in results:
        d1r = (entry["D1_robust"] if entry["D1_robust"] is not None
               else entry["D1_robust_v2_prelim"])
        print(f'  "{entry["dataset"]}": {{')
        print(f'    "slug": "{entry["slug"]}",')
        line = (f'    "scores": {{"D1": {_fmt(entry["D1"])}, '
                f'"D1_robust": {_fmt(d1r)}, "D2": {_fmt(entry["D2"])}, '
                f'"D3": {_fmt(entry["D3"])}, "D4": {_fmt(entry["D4_conn"])}, '
                f'"D4_part": {_fmt(entry["D4_part"])}, "D5": {_fmt(entry["D5"])}}}')
        if entry["D3_U"] is not None:
            print(line + ",")
            print(f'    "d3_information": {{"U": {entry["D3_U"]}, '
                  f'"purity": {entry["D3_purity"]}}}')
        else:
            print(line)
        print("  },")

    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(results, indent=2), encoding="utf-8")
        print(f"\nwritten: {args.json}")


if __name__ == "__main__":
    main()
