"""Run the whole pipeline for one dataset.

Stage 1  normalize raw logs into the 13-column CSV     normalize.py
Stage 2  mine templates, per-file metrics, near-dup     templates.py
Stage 3  cross-component structure, D4                  entities.py
         label separability and the score vector        scores.py

Stage 1 runs only when a config is given; without one the pipeline starts from
an existing outputs/<slug>/normalized_full.csv.

Label separability needs per-line labels and the per-line template
assignments; without them the score vector is still produced, with D3 absent.

Usage:
  python src/run_pipeline.py --config configs/mylogs.yml
  python src/run_pipeline.py --dataset mylogs
  python src/run_pipeline.py --dataset mylogs --drain-sim-th 0.4 --drain-max-clusters 1000
"""
from __future__ import annotations

import argparse
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import paths

SRC = Path(__file__).resolve().parent
PYTHON = sys.executable


def run_step(name: str, command: list, optional: bool = False) -> bool:
    """Run one stage. Returns True on success."""
    printable = [str(part) for part in command]
    print(f"\n{'=' * 70}\n{name}\n{'=' * 70}")
    print("  " + " ".join(printable[1:]))
    started = time.perf_counter()
    result = subprocess.run(printable, cwd=paths.ROOT)
    elapsed = time.perf_counter() - started
    if result.returncode == 0:
        print(f"  done in {elapsed:.1f}s")
        return True
    if optional:
        print(f"  not applicable to this dataset, skipped (exit {result.returncode})")
        return False
    print(f"  FAILED (exit {result.returncode}) after {elapsed:.1f}s")
    return False


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run every stage of the pipeline for one dataset",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("--config", type=Path, default=None,
                        help="Stage 1 config; without it Stage 1 is skipped")
    parser.add_argument("--dataset", default=None,
                        help="dataset slug; read from the config when not given")
    parser.add_argument("--stage2-subdir", default="stage2",
                        help="name of the Stage 2 output directory")
    parser.add_argument("--drain-depth", type=int, default=4)
    parser.add_argument("--drain-sim-th", type=float, default=0.5)
    parser.add_argument("--drain-max-children", type=int, default=100)
    parser.add_argument("--drain-max-clusters", type=int, default=500,
                        help="0 disables the cluster cap")
    parser.add_argument("--skip-line-assignments", action="store_true",
                        help="do not write drain_lines.csv; label separability then "
                             "cannot be computed")
    parser.add_argument("--keep-telemetry-files", action="store_true",
                        help="mine the per-second telemetry files that Stage 2 skips "
                             "by default (Logstash system.*.log, Suricata stats.log)")
    args = parser.parse_args()

    slug = args.dataset
    if slug is None and args.config is not None:
        from normalize import load_config
        slug = load_config(args.config).get("dataset")
    if not slug:
        raise SystemExit("give --dataset, or a --config that sets 'dataset'")

    normalized = paths.normalized_csv(slug)
    stage2 = paths.dataset_dir(slug) / args.stage2_subdir
    stage3 = paths.stage3_dir(slug)

    print(f"Dataset:    {slug}")
    print(f"Outputs to: {paths.dataset_dir(slug)}")

    if args.config is not None:
        if not run_step("Stage 1: normalization",
                        [PYTHON, SRC / "normalize.py", "--config", args.config]):
            raise SystemExit(1)
    elif not normalized.exists():
        print(f"\nStage 1 output not found: {normalized}")
        print("Pass --config to run Stage 1, or normalize the dataset first.")
        raise SystemExit(1)

    missing: list[str] = []

    stage2_cmd = [PYTHON, SRC / "templates.py",
                  "--normalized-csv", normalized, "--output-dir", stage2,
                  "--drain-depth", args.drain_depth,
                  "--drain-sim-th", args.drain_sim_th,
                  "--drain-max-children", args.drain_max_children,
                  "--drain-max-clusters", args.drain_max_clusters]
    if args.skip_line_assignments:
        stage2_cmd.append("--no-line-assignments")
    if args.keep_telemetry_files:
        stage2_cmd.append("--no-skip-metrics-files")
    if not run_step("Stage 2: templates, per-file metrics, near-duplicate ratio",
                    stage2_cmd):
        print("\nStage 2 failed; the later stages depend on it.")
        raise SystemExit(1)

    if not run_step("Stage 3: cross-component structure (D4)",
                    [PYTHON, SRC / "entities.py",
                     "--normalized-csv", normalized, "--output-dir", stage3]):
        missing.append("D4 (tasks that need it will be INDETERMINATE)")

    if not run_step("Label separability and the dataset score vector",
                    [PYTHON, SRC / "scores.py",
                     "--dataset", slug, "--stage2-subdir", args.stage2_subdir]):
        missing.append("dataset-level scores")

    print(f"\n{'=' * 70}")
    if missing:
        print("Finished with missing results:")
        for item in missing:
            print(f"  - {item}")
    else:
        print("Finished. All stages produced their output.")
    print(f"{'=' * 70}")
    print("\nNext: add the printed score vector to the corpus file that "
          "src/registry.py loads,\nthen run\n  python src/verdicts.py\n"
          "or open notebooks/pipeline.ipynb.")


if __name__ == "__main__":
    main()
