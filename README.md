# Log Dataset Suitability

A framework for deciding whether a log dataset can support a security-analytics
task. It measures seven structural dimensions of a dataset and derives, for each
of four analytic tasks, whether the dataset is capable of supporting it, without
training a detector. It accompanies the master's thesis *Assessing Dataset
Suitability for Log-Based Security Analytics* (TU Wien).

| Dimension | Property | Role |
|---|---|---|
| D1 | structural diversity of the template vocabulary | core |
| D2 | temporal dependence of the event sequence | core |
| D3 | separability of attack and normal events by template | core |
| D4 | cross-component linkability through shared identifiers | core |
| D5 | semantic richness (share of lines outside the dominant template) | descriptive |
| D6 | ATT&CK technique diversity of the labelled attacks | descriptive |
| D7 | diversity of normal workflows | descriptive |

A conjunctive decision rule over the four core dimensions D1 to D4 yields
SUITABLE, UNSUITABLE or
INDETERMINATE for anomaly detection, incident reconstruction, root cause
analysis and CTI attribution. A dimension that cannot be measured yields
INDETERMINATE rather than a failure: judgment is withheld, not given against the
dataset.

Only Stage 1, which normalizes raw logs into a fixed schema, depends on the log
format, and it is configured rather than coded. Everything after it is the same
code for every dataset.

## Contents

```
README.md
LICENSE
requirements.txt
docs/METHOD.md                every metric, the aggregation and the decision rule
review-materials/             the per-source appraisals of the literature review (LaTeX)
configs/                      example Stage 1 configurations
corpus/datasets.json          the score vectors of the datasets you profile
notebooks/pipeline.ipynb      runs every stage and produces the verdict figure
src/
  normalize.py              Stage 1: raw logs to the 13-column CSV, config-driven
  templates.py              Stage 2: template mining, per-file metrics, near-duplicates
  entities.py               Stage 3: cross-component entity analysis
  scores.py                 label separability and the dataset-level score vector
  verdicts.py               the decision rule and the verdict table
  run_pipeline.py           every stage for one dataset, in order
  schema.py                 the normalized schema and the line-level parsing helpers
  registry.py               loads the corpus file
  paths.py                  data and output roots
outputs/                      empty; everything in it is produced by a run
```

## Installation

Python 3.11 or newer.

```
python -m venv .venv
.venv\Scripts\activate          # Windows
source .venv/bin/activate       # Linux, macOS
pip install -r requirements.txt
```

## Quickest path

```
jupyter notebook notebooks/pipeline.ipynb
```

The notebook runs every stage and ends with the verdict figure. With no data
present it writes a small synthetic dataset first, so it runs end to end out of
the box. Point section 1 at your own logs to profile those instead.

## Running it on your own dataset

Describe the log format in a YAML or JSON config:

```yaml
dataset:   mylogs
input_dir: data/mylogs
pattern:   "**/*.log"

host:
  from: path_part        # path_part | filename | line_regex | fixed
  index: 0

timestamp:
  from: auto             # auto | regex | none

labels:
  from: line_numbers     # none | line_numbers | id_regex | time_windows | file_glob
  path: data/mylogs/labels.json
```

Then run every stage:

```
python src/run_pipeline.py --config configs/example.yml
```

That normalizes the logs, mines templates, computes the per-file metrics and the
global near-duplicate ratio, runs the cross-component analysis, measures label
separability and prints the dataset's score vector. Add that vector to
`corpus/datasets.json` and the verdicts include it:

```
python src/verdicts.py
```

`configs/example.yml` and `configs/example_labelled.yml` are starting points, and
every config key is documented at the top of `src/normalize.py`.

Three things decide what can be measured:

- **Row order is the event sequence.** D2 reads the order of rows within a file,
  not the timestamps. Do not sort the CSV.
- **Per-line labels drive D3.** Labels that mark whole files (`labels.from:
  file_glob`) make D3 measure file identity instead. The code does not detect
  this: leave `d3_information` out of the corpus entry, and the D3 verdicts
  become INDETERMINATE rather than inflated. Labels from `time_windows` need
  parsed timestamps; with `timestamp.from: none` every line is normal.
- **Host values are the D4 graph.** A single host means no host pairs, so D4 is
  undefined. It is also undefined when no recognised identifier occurs anywhere
  in the dataset: linkability was never observable, which is different from a
  measured zero.

Four behaviours are easy to miss and change the numbers:

- **Only log-like file names are read.** After `pattern` has matched, a file is
  read only if it is named `*.log`, `*.log.*`, `eve.json`, `syslog`,
  `auth.log`, `audit.log`, `openvpn.log` or `dnsmasq.log` and looks like text
  (compressed and binary files are skipped). A `.txt`, `.json` or `.jsonl`
  file is ignored; rename it or extend `is_log_text_candidate` in
  `src/schema.py`.
- **Stage 2 skips two telemetry file kinds by default:** Logstash
  `system.<type>.log` metric dumps and Suricata `stats.log`. They are counters,
  not events, and would swamp D1 and D5. `--keep-telemetry-files` mines them
  anyway; the skipped paths are listed in `drain_summary.json`.
- **D4 recognises five identifier kinds only:** IPv4 addresses outside the
  private ranges, UUIDs, Windows SIDs, Hadoop/YARN ids and HDFS block ids. A
  dataset that links hosts through usernames, session ids or IPv6 scores zero
  on both channels, and a dataset whose hosts talk only over a private LAN
  scores zero on the address channel. Extend `_ENTITY_TYPES` in
  `src/entities.py` for other identifiers.
- **The `D3` key in a corpus entry is a legacy per-file value.** The decision
  rule gates on `d3_information` (`max(U, purity)`), which `scores.py` prints
  alongside. Without that block a dataset is INDETERMINATE on every task that
  needs D3.

## The corpus file

`corpus/datasets.json` holds one score vector per dataset and `src/registry.py`
loads it. It ships empty and fills up as datasets are profiled: the notebook
writes an entry when `SAVE_TO_CORPUS` is set, and `registry.save_dataset` does the
same from a script. Once more than one dataset is recorded, the verdict figure
becomes comparative. Point `SUITABILITY_CORPUS` at another file to keep several
collections apart. Nothing in the code refers to a dataset by name.

Two further environment variables move the roots: `SUITABILITY_DATA` for raw
datasets and `SUITABILITY_OUTPUTS` for pipeline output.

## Notes

- Drain3 runs with depth 4, similarity threshold 0.5, at most 100 children per
  node and a cap of 500 clusters per source file. Template counts are not
  comparable across different settings, so keep them fixed when comparing
  datasets; `--drain-sim-th` and `--drain-max-clusters` change them.
- Aggregation from files to datasets uses medians throughout.
- Stage 1 and Stage 2 dominate the runtime. The normalized CSV can reach tens of
  gigabytes and the per-line template assignments over a gigabyte;
  `--skip-line-assignments` avoids the largest file, at the cost of D3.
- The thresholds (0.40, 0.15, 0.25, 0.40) were calibrated in the study, and
  `docs/METHOD.md` records where each came from. Changing one invalidates that
  calibration.
- D6 and D7 are not computed here. Both depend on information specific to a
  dataset's ground truth or layout; they are supplied in the corpus file when
  available and never enter a verdict.
- Dependency versions are pinned in `requirements.txt`; the study ran on Python
  3.11 on Windows.

## License and citation

MIT, see `LICENSE`. When using the pipeline or its results, cite the thesis.
