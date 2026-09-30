# outputs/

This directory starts empty. Every file below is produced by running the
pipeline; nothing here is shipped with the package.

Running the stages for a dataset creates:

```
outputs/<slug>/normalized_full.csv          Stage 1
outputs/<slug>/stage2/                      Stage 2 and 2.5
    drain_templates.csv, drain_lines.csv, d1_metrics.csv, drain_summary.json,
    d1_global_neardup.json
outputs/<slug>/stage3_d4/                   Stage 3
    d4_per_host.csv, d4_cross_host.csv, d4_summary.json
```

Corpus-level results are written to:

```
outputs/verdicts/d3_information.json        label separability, one entry per dataset
outputs/verdicts/suitability_verdicts.csv   the verdict table
outputs/verdicts/suitability_verdicts.md
outputs/figures/verdicts_<slug>.png         the verdict figure, from the notebook
```

`normalized_full.csv` and `drain_lines.csv` can be very large and are listed in
`.gitignore`. Set `SUITABILITY_OUTPUTS` to write somewhere else. See the README
for the commands and `docs/METHOD.md` section 10 for what each file holds.
