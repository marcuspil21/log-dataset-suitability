# Method: how the suitability scores are computed

This document describes the framework: every stage, how each metric is computed,
how verdicts are derived, and how the framework was validated. It is written for
any log dataset, not for one particular collection.

Only Stage 1 is specific to a log format. Everything after it is the same code for
every dataset, driven by one normalized CSV. The README is the practical guide to
running the framework on a dataset; this document explains what the numbers mean.

Section 11 collects the results the framework produced on the twenty datasets
profiled in the study. They are not shipped with the package, which starts with an
empty corpus; they are reported here as worked examples, to show what the scores
and verdicts look like on real datasets.

## 1. Purpose

The framework answers one question per (dataset, task) pair:

> Is this log dataset structurally capable of supporting this security-analytics task?

It does so without training a detector. It measures seven dimensions of a dataset
(D1 to D7), four of which (D1 to D4) are core dimensions in a conjunctive decision rule
over four application classes (anomaly detection, incident reconstruction, root
cause analysis, CTI/ATT&CK attribution). The output is a verdict, SUITABLE,
UNSUITABLE or INDETERMINATE, for each dataset and task.

Three properties define the design:

1. Only Stage 1 is dataset-specific. Every dataset is reduced to one common
   13-column schema, and every later stage is identical code for every dataset.
2. Every dimension except D4 is derived from mined log templates. D4 works on the
   raw message text.
3. Only D1 to D4 can decide a verdict. D5, D6 and D7 are reported and attached as
   descriptive context, but never change a verdict.

## 2. Package map

| Path | Contents |
|---|---|
| `src/normalize.py` | Stage 1: raw logs to the 13-column CSV, driven by a config file |
| `src/schema.py` | The normalized schema and the shared line-level parsing helpers |
| `src/templates.py` | Stage 2: template mining, the per-file metrics and the near-duplicate ratio |
| `src/entities.py` | Stage 3: cross-component entity analysis |
| `src/scores.py` | Label separability and the dataset-level score vector |
| `src/verdicts.py` | The decision rule and the verdict table |
| `src/registry.py` | Loads the corpus file: the datasets and their scores |
| `src/paths.py` | Data and output roots, overridable by environment variable |
| `src/run_pipeline.py` | Every stage for one dataset, in order |
| `configs/` | Example Stage 1 configurations |
| `corpus/` | The corpus file: one score vector per dataset, empty until you profile one |
| `notebooks/pipeline.ipynb` | Runs every stage and produces the verdict figure |
| `outputs/<slug>/` | Per-dataset stage output; empty until the pipeline runs |

## 3. End-to-end data flow

```
RAW DATASET (any format: syslog, Apache, audit, CSV, JSONL, event XML, ...)
      v
[STAGE 1]  normalization                      src/normalize.py
      |      schema and shared helpers        src/schema.py
      |      timestamp parsing -> label join -> file selection
      v
   normalized_full.csv   (13 columns, one row per log line)
      |
      +-----------------------------------------------+
      v                                               v
[STAGE 2]  Drain3 template mining                [STAGE 3]  D4 cross-component
      |    one miner per source file                  |   entity extraction from RAW TEXT
      |    per-file D1, D2, D3 (legacy), D5           |   (bypasses templates entirely)
      +-> drain_templates.csv                         +-> d4_per_host.csv
      +-> drain_lines.csv                             +-> d4_cross_host.csv
      +-> d1_metrics.csv                              +-> d4_summary.json (D4_conn, D4_part)
      +-> drain_summary.json
      |
      +-[STAGE 2.5] global near-duplicate ratio ----> d1_global_neardup.json
      v
[STAGE 3b] dataset-level aggregation
      |    D1_robust = median over files, global near-duplicate corrected
      |    D2        = median over files
      |    D3_eff    = max(U, purity) on the global (template, label) table
      |    D4_max    = max(D4_conn, D4_part)
      |    D5        = 1 - median(boilerplate proportion)
      v
   dataset score vector (D1r, D2, D3eff, D4max, D5)
      |
      +----------------------------> [STAGE 4] descriptive extensions
      |                                   D6  ATT&CK attack diversity
      v                                   D7  normal-workflow diversity
[STAGE 5] decision rule (D1 to D4 only)        |  (annotate the verdict,
      |    conjunctive necessary condition     |   never enter the rule)
      v                                        |
   VERDICT per (dataset, task) <---------------+
      v
[STAGE 6] the verdict table, and the figure in notebooks/pipeline.ipynb

```

Stage 1 and everything after it, for one dataset:

```bash
python src/run_pipeline.py --config configs/<slug>.yml
```

or, with Stage 1 already run, `python src/run_pipeline.py --dataset <slug>`.

## 4. Stage 1: normalization

Code: `src/normalize.py`, with the schema and the shared
line-level helpers in `src/schema.py`.
Output: `outputs/<slug>/normalized_full.csv`.

This is the only dataset-specific stage. Its job is to turn any log format into one
row per log line in a fixed schema. It is driven by a YAML or JSON config with
three format-specific parts, each a small set of keys documented at the top of
`src/normalize.py`: `host` (how a line is attributed to a component), `timestamp`
(how its time is read) and `labels` (how its ground truth is joined). Nothing is
coded per dataset. A format none of the built-in options covers is the one case
that needs code, in the resolver functions of `src/normalize.py`.

### 4.1 Output schema (13 columns)

| Column | Type | Description |
|---|---|---|
| `dataset` | str | Short dataset identifier |
| `host` | str | Logical host or node; filename prefix if the format has no host field |
| `source_file` | str | Path of the source file relative to the dataset root |
| `line_no` | int | 1-based line number within the source file |
| `raw_message` | str | Full original log line, unmodified except for the trailing newline |
| `timestamp_raw` | str | Timestamp exactly as it appears in the line, or `""` |
| `timestamp_parsed` | str | ISO 8601 UTC, or `""` |
| `timestamp_parse_success` | bool | Whether parsing succeeded |
| `within_simulation_window` | bool | Reserved; the config-driven Stage 1 writes `True` |
| `is_attack` | bool | Ground-truth attack flag; unlabelled lines default to `False` |
| `label_status` | str | Whether ground truth existed for this file |
| `labels` | str | JSON list of label strings; `["attack"]` or `[]` from the config-driven Stage 1 |
| `rules` | str | JSON object of rule or signature names; `{}` from the config-driven Stage 1 |

Downstream stages read only five of these: `host`, `source_file`, `raw_message`,
`timestamp_parsed`, `is_attack`. The rest are provenance and diagnostics.

### 4.2 Timestamp parsing

The shared helper tries a list of formats in priority order, taking the first that
both matches and yields a plausible time:

1. Linux audit epoch: `msg=audit(<epoch>:<seq>)`
2. ISO 8601 prefix at line start
3. JSON `"@timestamp"` field
4. JSON generic `"timestamp"` field
5. Apache combined log: `[DD/Mon/YYYY:HH:MM:SS +HHMM]`
6. Apache error log: `[Day Mon DD HH:MM:SS.us YYYY]`
7. syslog `Mon DD HH:MM:SS`, which needs the year supplied from outside the line,
   because the line does not carry it

Where none of these matches, `timestamp: {from: regex, pattern: ..., strptime: ...}`
in the Stage 1 config names the dataset's own format.

If nothing matches, the row is still emitted with `timestamp_parse_success=False`.
Nothing is dropped for being unparseable. Stage 2 and Stage 3 do not need
timestamps: row order carries the event sequence, and D4 reads the message text.

### 4.3 Label join

Ground truth is loaded once and applied per line by the `labels` section of the
config. The natural key depends on the dataset, and the config offers one mode per
key: original line number (`line_numbers`), an identifier in the line such as a
block or session id (`id_regex`), an attack time window (`time_windows`) or the
file itself (`file_glob`). Any line with no matching label record is marked normal
(`is_attack=False`). This is the conservative direction: unlabelled means "not
known to be attack", never "attack".

Labels that mark whole files (`file_glob`) make D3 measure file identity rather
than per-line separability. The code does not detect this; the corpus entry of
such a dataset should carry no `d3_information` block, so that D3 is
INDETERMINATE rather than inflated.

### 4.4 File selection

A file under `input_dir` is read when it matches `pattern` and no `exclude` glob,
has a log-like name (`*.log`, `*.log.*`, `eve.json`, `syslog`, `auth.log`,
`audit.log`, `openvpn.log`, `dnsmasq.log`; `is_log_text_candidate` in
`src/schema.py`) and looks like text: a known binary suffix or a NUL byte in the
first 4 KB rules it out (`is_probably_text_file`), so compressed rotations,
packet captures, journals and images are skipped without being parsed.

The Stage 1 summary reports the timestamp parse rate and the attack line count.
A low parse rate means the `timestamp` section does not match the format; zero
attack lines with labels configured means the label key does not join. Both
should be resolved before the later stages are trusted.

### 4.5 Exclusions and sampling

Two things can happen at Stage 1 that must be stated whenever line counts are
quoted, because both change the metrics.

- Exclusions. Subtrees that are not event logs (packet capture dumps, binary
  journals, per-second monitoring counters) are excluded at Stage 1 or skipped at
  Stage 2 by the telemetry-file detector. A monitoring counter file can dominate a
  dataset by line count while carrying no security event content, which distorts D1
  and D5.
- Sampling. Where a dataset is too large to process in full, an adapter may sample.
  The sampling method matters for D2: per-event Bernoulli sampling preserves event
  order but deletes most events, so two adjacent rows in the sample were far apart
  in the source, which inflates D2. Block sampling (runs of consecutive events)
  does not. The study quantifies this on the reference corpus.

## 5. Stage 2: template mining and per-file metrics

Code: `src/templates.py`.
Output: `outputs/<slug>/stage2/{drain_templates.csv, drain_lines.csv, d1_metrics.csv, drain_summary.json}`.

```bash
python src/templates.py \
  --normalized-csv outputs/<slug>/normalized_full.csv \
  --output-dir     outputs/<slug>/stage2 \
  --drain-max-clusters 500
```

### 5.1 Drain3 template mining

One independent Drain3 miner per source file (`_process_source`). Drain3 is an
online parser: it buckets messages by token count, walks a fixed-depth prefix tree,
and merges a line into an existing cluster when their token similarity clears
`sim_th`. Variable tokens become `<*>`.

```
"connection from 10.0.0.5 closed"   \
"connection from 10.0.0.9 closed"    +-->  template "connection from <*> closed"   template_id = 7
"connection from 10.0.0.23 closed"  /
```

Configuration (`DrainConfig`): `depth=4`, `sim_th=0.5`, `max_children=100`,
`max_clusters=500`, `parametrize_numeric_tokens=True`. Lowering `sim_th` to about
0.4 helps logs with long variable-heavy messages; raising or removing the cluster
cap suits a single very large file with unbounded variety. Every departure from the
defaults belongs in the record of the run, because template counts are not
comparable across settings.

Every line receives a `template_id`. The template-id set and the id sequence in row
order are the shared input for D1, D2, D3 and D5. Two file classes are skipped as
infrastructure telemetry rather than log events: Logstash/Metricbeat date-prefixed
`system.<type>.log`, and Suricata `stats.log` (`--no-skip-metrics-files` disables
this).

Because miners are per file, `template_count` is a per-file vocabulary.
`active_cluster_count` reports the live cluster count in the tree, which differs
from `template_count` when LRU eviction is active under `max_clusters`.

### 5.2 Per-file metric columns (`d1_metrics.csv`)

| Group | Column | Meaning |
|---|---|---|
| id | `source_file`, `host` | identification |
| D1 | `template_count` (K) | distinct templates in the file |
| D1 | `shannon_entropy` (H) | entropy over template frequencies, bits |
| D1 | `gini_coeff` | Gini over template frequencies; 0 = uniform, 1 = one template holds everything |
| D1 | `top10_coverage` | share of lines in the 10 most frequent templates (fixed-10 form, comparison only) |
| D1 | `param_token_ratio` | share of template tokens that are `<*>` |
| D1 | `mean_params_per_line` | average number of variable slots per line |
| D1 | `near_duplicate_ratio` | share of templates with Jaccard >= 0.8 to another template in the same file (token sets, `<*>` excluded) |
| D1 | `d1_robust`, `d1_robust_v2` | per-file composites (Section 5.3) |
| D1 | `active_cluster_count` | live Drain clusters after eviction |
| D2 | `transition_entropy` (T) | H(T_{n+1} given T_n), bits |
| D2 | `self_transition_ratio` | share of bigrams where the template repeats |
| D2 | `unique_transition_count` | number of distinct bigrams |
| D2 | `interarrival_mean_s`, `interarrival_cv` | timing statistics over parsed timestamps |
| D3 | `total_lines`, `attack_lines`, `normal_lines`, `attack_line_ratio` | label mass |
| D3 | `exclusive_attack_templates`, `exclusive_normal_templates` and their ratios | template exclusivity counts |
| D3 | `class_separation_ratio` | legacy CSR (Section 7.3) |
| D3 | `attack_exclusive_line_coverage` | legacy D3_revised (Section 7.3) |
| D3 | `attack_temporal_concentration` | attack time span / total time span |
| D5 | `type_token_ratio` | K / N |
| D5 | `boilerplate_proportion` | max template count / N |
| D5 | `mean_template_tokens` | mean template length in tokens |

### 5.3 Per-file composites

```
d1_norm       = H / log2(K)                     (0 when K <= 1)
d1_robust     = 0.25 * (d1_norm + (1 - Gini) + (1 - top10_coverage) + (1 - near_dup))
d1_robust_v2  = 0.25 * (d1_norm + (1 - Gini_v2) + (1 - top_10%_coverage) + (1 - near_dup))
```

`d1_robust_v2` is the scale-corrected form: `Gini_v2` imputes 1.0 for K = 1 files
(a single-template file is maximally concentrated, not perfectly equal), and
`top_10%_coverage` uses the top ceil(0.10 * K) templates instead of a fixed 10,
which makes it invariant to vocabulary size. The fixed top-10 column saturates at
1.0 for the many small-K files and is retained only for comparison.

The near-duplicate sub-component is replaced at dataset level (Section 7.1).

The canonical D1 reported in the thesis is therefore not the `d1_robust` column
of `d1_metrics.csv`. It is the `d1_robust_v2` form, aggregated by median across
source files and combined with the dataset-wide near-duplicate ratio from
`d1_global_neardup.json`. Reading `d1_robust` straight out of the per-file CSV
gives a different, higher number, because that column carries the fixed top-10
coverage and the per-file near-duplicate rate.

### 5.4 Stage 2.5: the global near-duplicate ratio

`src/templates.py` also reads
`stage2/drain_templates.csv` and writes `stage2/d1_global_neardup.json`, the
dataset-wide near-duplicate ratio that enters D1_robust (Section 7.1).

A template counts as a near-duplicate when another template anywhere in the
dataset, in the same file or a different one, reaches a token-set Jaccard of 0.8
against it. Per-file near-duplication only captures parser fragmentation; the
global figure captures the vocabulary redundancy that matters for structural
diversity. For a single-file dataset the two coincide by definition.

## 6. Stage 3: D4 cross-component structure

Code: `src/entities.py`.
Output: `outputs/<slug>/stage3_d4/{d4_per_host.csv, d4_cross_host.csv, d4_summary.json}`.

```bash
python src/entities.py \
  --normalized-csv outputs/<slug>/normalized_full.csv \
  --output-dir     outputs/<slug>/stage3_d4
```

D4 reads `raw_message` directly and bypasses Stage 2 entirely. It is the only
dimension not derived from templates, because templating destroys exactly the
variable tokens (addresses, ids) that D4 needs.

### 6.1 Entity extraction

Five entity types are extracted per line by regex and accumulated into a per-host
set of distinct values:

| Type | Pattern | Typical source |
|---|---|---|
| `ipv4` | dotted-decimal | any multi-host dataset |
| `uuid` | RFC 4122 8-4-4-4-12, case-normalised | request, trace and process identifiers |
| `windows_sid` | `S-1-N-...` | domain-joined Windows event logs |
| `hadoop_id` | `application_/appattempt_/attempt_/container_` + 13-digit epoch | Hadoop YARN |
| `hdfs_block` | `blk_[-]NNNN[_NNNN]`, `BP-NNNN-IP-EPOCH` | HDFS |

Exclusions are the substance of the metric. Shared infrastructure creates false
links, so the extractor drops:

- `0.0.0.0`, `127.0.0.1`, `255.255.255.255`;
- all RFC 1918 private ranges (10/8, 172.16/12, 192.168/16) and loopback: a LAN
  gateway, DNS or NTP address appears on every host and would push the score toward
  1.0 with no attack signal;
- all-zero and all-F UUIDs;
- well-known Windows SIDs (LocalSystem, LocalService, NetworkService, Everyone,
  Authenticated Users, This Organization, all `S-1-16-*` integrity levels).

The RFC 1918 filter is not cosmetic. On the reference corpus, applying it moved one
enterprise dataset's D4_conn from 0.398 to 0.186 and another's from 0.191 to 0.110,
and revealed that a cluster dataset's seven "shared" IPs were internal YARN
addresses, taking its D4_conn to 0.000.

### 6.2 Two channels, kept separate

For every unordered host pair, the pipeline records shared entity counts per type,
then aggregates:

```
total_pairs = |hosts| * (|hosts| - 1) / 2

D4_conn  = pairs sharing >= 1 non-private IPv4          / total_pairs
D4_part  = pairs sharing >= 1 participation identifier  / total_pairs
           (uuid, windows_sid, hadoop_id, hdfs_block)
```

`D4_conn` measures network-layer connection (do these hosts talk to the same
endpoint?). `D4_part` measures activity-layer participation (are they involved in
the same traceable unit of work: block, job, process chain, correlated Windows
event?). They are deliberately not averaged: a dataset supports cross-host
reconstruction if it is linkable by either channel, so the rule uses the maximum
(Section 7.4).

The pairwise loop grows with the square of the host count, so for a very large
host graph (tens of thousands of hosts) it becomes infeasible. The same ratios
can then be obtained by inverting the entity-to-hosts incidence, at a cost
proportional to the sum over entities of |hosts(e)|^2, with the extraction and
exclusion code of `src/entities.py` unchanged. The package ships the pairwise
form only.

## 7. Stage 3b: dataset-level aggregation

Per-file metrics become one score vector per dataset
(`src/scores.py --dataset <slug>`). Aggregation uses the median,
not the mean, throughout: a single tiny file with 10 lines and 10 unique templates
would score 1.0 and drag a mean upward.

### 7.1 D1: structural diversity

Question: does this dataset carry a rich, evenly used vocabulary of event types, or
do a few templates dominate?

```
D1_robust = median over files of
            0.25 * [ H/log2(K) + (1 - Gini_v2) + (1 - top_10%_coverage) + (1 - NearDup_global) ]
```

The fourth sub-component is the one that differs from the per-file composite.
`NearDup_global` (from `src/templates.py`, written to
`d1_global_neardup.json`) is the fraction of all distinct templates in the whole
dataset that have a near-twin anywhere, in the same file or a different one, at
token-set Jaccard >= 0.8. Per-file near-duplication only captures parser
fragmentation; global near-duplication captures the vocabulary redundancy that
matters for structural diversity. For single-file datasets the two are identical
by definition.

The correction is substantial where vocabularies repeat across files. On the
reference corpus it moved four datasets by 0.01 to 0.09 and flipped one anomaly
detection verdict (Section 11.1).

Threshold: tau_D1 = 0.40.

### 7.2 D2: temporal dependence

Question: does the current event tell you what comes next, or is the sequence
effectively unstructured?

Per file, over the template-id sequence in physical row order (timestamps are
metadata; row order is the sequence):

```
bigram_counts[(T_i, T_i+1)] += 1
H_joint     = -sum p(a,b) log2 p(a,b)
H_marginal  = -sum p(a)   log2 p(a)
T           = H_joint - H_marginal        = H(T_{n+1} | T_n)
D2_file     = T / log2(K)
D2          = median over files
```

Note the direction: T = 0 means perfectly ordered (the next template is
determined), T = log2(K) means random. Low D2 therefore means highly repetitive,
not "no temporal structure to exploit". This is why the correlation between D2 and
Markov advantage is negative and expected to be.

Null model. If ordering carried no information, transitions would be draws from
the marginal, giving analytically `D2_null = H(T)/log2(K) = D1`. A dataset below
its null has more sequence structure than chance.

Threshold: tau_D2 = 0.15, placed at a natural gap in the initial corpus and kept
fixed thereafter. It is the framework's most fragile threshold: in the study's
sensitivity analysis it moves more verdicts than the other three combined.

### 7.3 D3: label separability

Question: do attack events produce structurally distinct templates, or do attack
and normal traffic share a vocabulary?

Code: `src/scores.py --dataset <slug>`, output
`outputs/verdicts/d3_information.json`; recorded values in `registry.D3_INFO`.

D3 is computed on the global joint distribution P(template, label) over the whole
dataset, not per file. This is the defining property: it makes the metric
invariant to how logs happen to be split into files, which was the defect of both
predecessors.

Component 1: Theil's uncertainty coefficient

```
U(L|T) = I(T;L) / H(L)          I(T;L) = H(L) - H(L|T)
```

U = 1 means the template determines the label; U = 0 means templates carry no
label information. Normalising by H(L) makes datasets with very different attack
rates comparable: H(L) is tiny when attacks are 0.01% of lines, and U rescales to
[0, 1] regardless.

Plug-in mutual information is biased high on sparse tables with about 10^5
templates, so the primary estimator is Hausser-Strimmer shrinkage (joint cell
probabilities shrunk toward uniform with a data-driven lambda), checked against
Miller-Madow. All three estimates plus lambda are written to `d3_information.json`.

Component 2: smoothed attack purity

```
purity = ( sum_t  a_t * (a_t + alpha) / (a_t + n_t + alpha + beta) ) / A       alpha = beta = 0.5 (Jeffreys)
```

The attack-line-weighted mean of each template's smoothed attack purity, where a_t
and n_t are the attack and normal line counts of template t and A is the total
number of attack lines. It answers the attack-side question U can miss when
attacks are a vanishing fraction: do attack lines sit in mostly-attack templates?
Jeffreys smoothing stops a single-line template from claiming purity 1.0.

```
D3_eff = max(U, purity)
```

Threshold: tau_D3 = 0.25, calibrated by triangulation: above the permutation-null
and estimator-bias floor (maximum null U = 0.149), at the only natural gap in the
reference corpus (0.13 to 0.33), and at the point where an out-of-sample
template-to-label classifier becomes effective. Verdicts are invariant over tau in
[0.15, 0.30].

Retired predecessors, still present as labelled reference columns in reports:

1. CSR (class separation ratio): per file, `(excl_attack + excl_normal) / K`,
   averaged over attack-bearing files. Retired because it counts template
   exclusivity, not line coverage: a 1-line exclusive template counts as much as a
   1M-line one, and under file-level labels it is tautologically 1.0.
2. D3_revised: frequency-weighted recall, the fraction of attack lines covered by
   attack-exclusive templates (`attack_exclusive_line_coverage`). It fixed CSR's
   weighting defect but stayed per file, and collapsed toward 0 when recomputed
   globally.

`registry.D3_REVISED` is never used for verdicts. A dataset present in
`CORPUS_SCORES` but absent from `D3_INFO` is treated as D3-unavailable and goes
INDETERMINATE rather than silently deciding on a retired metric.

### 7.4 D4: cross-component correlation

```
D4_max = max(D4_conn, D4_part)
```

Disjunctive, not a weighted mean. The justification is a dataset whose logs contain
no IP addresses at all, so `D4_conn = 0.000`, while block ids link 99.9% of host
pairs, so `D4_part = 0.999`. A mean would have suppressed the correct linkage
mechanism. If both channels are unavailable, D4 is `None` and the dimension is
INDETERMINATE. That happens in two cases: a single-host dataset has no host
pairs, and a dataset in which no entity of any recognised family occurs at all
never made linkability observable, which is distinct from a measured zero
(entities present, but no pair shares one).

Threshold: tau_D4 = 0.40. This is the one indicative threshold: no calibration
curve places it. Its footing is an entity-recall probe and an entity-scrub perturbation, both reported in the study.
Verdicts are invariant over tau in [0.30, 0.55].

Supplementary variant, D4_attack: entity recall restricted to co-attacked host
pairs only, which removes the dilution caused by hundreds of uninvolved hosts.
The full-graph value is kept and D4_attack is reported as supporting evidence: it
can explain an IR or RCA failure as corpus-wide dilution rather than a deficiency,
without overclaiming on a handful of attacked pairs. Recorded values live in
`registry.D4_ATTACK`.

### 7.5 D5: semantic richness (descriptive)

```
boilerplate_proportion = max(c_i) / N               per file
D5 = 1 - median(boilerplate_proportion)             per dataset
```

The share of lines belonging to the single most common template, inverted. High
D5 means no one event type swamps the log.

tau_D5 = 0.40 is retained for reporting only. D5 is descriptive like D6 and D7.
With D5 descriptive, the Log Interpretation task had no necessary dimension and was
retired, which sets the verdict space at four tasks per dataset. D5 is
sensitivity-validated in the study by a boilerplate-injection perturbation.

## 8. Stage 4: descriptive extensions D6 and D7

These attach to the verdict and never enter the rule. Neither has a calibrated
threshold, and neither is computed by the package: both depend on information that
is specific to a dataset's ground truth or directory layout, so each is supplied in
the corpus file when it is available. They are defined here because the corpus
records them and the study reports them.

### 8.1 D6: ATT&CK attack diversity

D6 is not computed by the package. Extracting techniques from ground truth is tied
to the exact label format of a dataset, and no general extractor exists, so D6 is a
descriptive value a user supplies in the registry when the dataset carries ATT&CK
labels. Its definition is:

```
T_b = |distinct tactics| / 14                   tactic breadth (ATT&CK v14 has 14 tactics)
T_d = |distinct techniques| / N_ref             technique density
      N_ref = sum over observed tactics of that tactic's ATT&CK v14 technique count
T_e = H(technique frequencies) / log2(|techniques|)     balance
D6  = OWA([T_b, T_d, T_e], w = [0.5, 0.3, 0.2])
    = 0.5 * max + 0.3 * median + 0.2 * min
```

N_ref varies by dataset: it is the technique capacity of the tactics a dataset
exhibits, not a constant. The ordered weighted average rewards a dataset that is
strong on any axis while still requiring the others to be non-trivial.

The label regime a value comes from has to travel with it, because regimes are not
interchangeable: technique codes read from a machine-readable attack description,
technique codes derived from attack-step names, and tactic-only labels mapped 1:1
to canonical techniques all produce numbers on different scales. A tactic-resolution
value is a lower bound on T_d and a proxy for T_e, and is not comparable with the
others. `registry.D6_TACTIC_RESOLUTION` carries that flag so it is printed wherever
the value is.

### 8.2 D7: normal-workflow diversity

D7 is supplied in the corpus file; the study computed it from the Stage 2
output.

Computed only over pure-normal files (`attack_line_ratio == 0.0`). Categories are
derived from the log source filename: the first dot-separated component of the
basename, prefixed with the parent directory when that directory is informative
(`apache2/access.log` gives `apache2/access`; `auth.log.2` gives `auth`).

```
W_b = n / N_ref                              breadth   (n = distinct categories)
W_d = log2(c_mean + 1) / log2(D_ref + 1)     depth     (c_mean = mean distinct templates per category)
W_e = H(lines per category) / log2(n)        evenness  (Pielou's J)
D7  = (W_b + W_d + W_e) / 3                  simple mean, equal weights
```

Unlike D6 this uses a plain mean, not an OWA: evenness measures whether the benign
background is realistically balanced, and that signal must not be compensated by
breadth or depth. A mean encodes "all three are equally necessary" instead of an
unverified compensability assumption.

Calibration constants, fixed after a first corpus pass and written into the output
JSON: N_ref = 167, D_ref = 5211.98. A dataset with no pure-normal file reports no
D7.

## 9. Stage 5: the decision rule

Code: `src/verdicts.py`; applied over the registry by
`src/verdicts.py`.

### 9.1 Application classes

| Task | Necessary | Supporting (reported, never decisive) |
|---|---|---|
| Anomaly Detection (AD) | D1, D3 | D2 |
| Incident Reconstruction (IR) | D2, D4 | D1, D3 |
| Root Cause Analysis (RCA) | D3, D4 | D2 |
| CTI / ATT&CK Attribution (CTI) | D3 | D1, D4 |

### 9.2 Thresholds

| Dim | tau | Basis |
|---|---:|---|
| D1 | 0.40 | calibrated: boilerplate-concentration perturbation, rho = -1.0; scale-invariant under uniform duplication |
| D2 | 0.15 | empirical: permutation-null gap on the initial corpus, kept fixed |
| D3 | 0.25 | calibrated: null-floor, corpus-gap and classifier-anchor triangulation |
| D4 | 0.40 | indicative placement; response perturbation-tested (entity-scrub sweep, rho <= -0.98); external footing is the entity-recall probe |
| D5 | 0.40 | descriptive; retained for reporting only |

### 9.3 Verdict logic

```
for each necessary dimension:
    value is None      -> INDETERMINATE
    value >= tau       -> PASS
    value <  tau       -> FAIL

SUITABLE       all necessary dimensions PASS
UNSUITABLE     at least one necessary dimension FAILs
INDETERMINATE  at least one necessary dimension is unavailable
```

INDETERMINATE outranks UNSUITABLE. In `assess_suitability`, UNSUITABLE only
overrides SUITABLE, never INDETERMINATE. A dimension that cannot be measured is a
withheld judgment, not a failure: a dataset is not penalised for something the
framework could not observe.

Supporting dimensions are evaluated and reported (`supporting_pass: n/m`) but do
not enter the verdict.

### 9.4 What the engine substitutes before applying the rule

`build_verdict_rows()` maps recorded scores to the values the rule compares:

- `D1` <- `D1_robust` (the near-duplicate corrected value, never raw entropy)
- `D3` <- `max(U, purity)` from `D3_INFO` (`registry.d3_gating`); if the dataset is
  absent from `D3_INFO`, D3 is unavailable and the dimension is INDETERMINATE
- `D4` <- `max(D4_conn, D4_part)` (`registry.d4_gating`), skipping `None` values;
  both `None` means unavailable
- `D2`, `D5` <- as recorded

The thresholds can be overridden for one run with `--tau-d1`, `--tau-d2`,
`--tau-d3` and `--tau-d4` instead of editing `src/verdicts.py`.

## 10. Artefact reference

| File | Stage | Contents |
|---|---|---|
| `outputs/<slug>/normalized_full.csv` | 1 | one row per log line, 13 columns |
| `outputs/<slug>/stage2/drain_templates.csv` | 2 | per (source_file, template_id): template string, count, attack/normal counts, exclusive class |
| `outputs/<slug>/stage2/drain_lines.csv` | 2 | per-line template assignment and extracted parameters (large; `--no-line-assignments` skips it) |
| `outputs/<slug>/stage2/d1_metrics.csv` | 2 | all per-file D1/D2/D3/D5 metrics (the name is historical) |
| `outputs/<slug>/stage2/drain_summary.json` | 2 | file, template and line counts; Drain configuration |
| `outputs/<slug>/stage2/d1_global_neardup.json` | 2.5 | global near-duplicate ratio |
| `outputs/<slug>/stage3_d4/d4_per_host.csv` | 3 | per host: entity counts by type, timestamp range |
| `outputs/<slug>/stage3_d4/d4_cross_host.csv` | 3 | per host pair: shared entity counts by type, time overlap |
| `outputs/<slug>/stage3_d4/d4_summary.json` | 3 | D4_conn, D4_part, pair totals |
| `outputs/verdicts/d3_information.json` | 3b | U (three estimators), purity, lambda, H(label), K |
| `outputs/verdicts/suitability_verdicts.{csv,md}` | 5 | the verdict table |
| `outputs/figures/verdicts_<slug>.png` | 6 | the verdict figure, written by the notebook |

D6 and D7 have no artefact here: both are supplied in the corpus file (Section 8).

## 11. Results reported in the study

Everything in this section is a result, not part of the method: the output of the
framework on the twenty datasets profiled in the study, spanning enterprise syslog
collections, cloud and cluster logs, supercomputer logs, network flows and
provenance streams. They are reported here as worked examples. The package itself
starts with an empty corpus and fills it with the datasets you profile.

Stage 2 settings that differ from the defaults, because template counts are not
comparable across settings: `sim_th` 0.40 for Santos and ATLASv2; `max_clusters`
1000 for HDFS_2, CADETS and THEIA, 5000 in the capped Thunderbird run and no cap in
the canonical Thunderbird run.

### 11.1 Master score table

D1 is `D1_robust`; D3 is `D3_eff = max(U, purity)`; D4 is
`D4_max = max(D4_conn, D4_part)`. `--` = not computable.

| Dataset | D1r | D2 | D3_U | D3_pur | D3eff | D4_conn | D4_part | D4max | D5 | D6 | D7 |
|---|---|---|---|---|---|---|---|---|---|---|---|
| AIT-LDS-RM | 0.644 | 0.144 | 0.535 | 0.257 | 0.535 | 0.186 | 0.013 | 0.186 | 0.515 | 0.642 | 0.585 |
| Santos | 0.576 | 0.224 | 0.445 | 0.254 | 0.445 | 0.110 | 0.005 | 0.110 | 0.556 | 0.640 | 0.545 |
| Wilson | 0.563 | 0.213 | 0.833 | 0.872 | 0.872 | 0.152 | 0.003 | 0.152 | 0.527 | 0.675 | 0.569 |
| cam-lds-s1 | 0.671 | 0.144 | 0.611 | 0.665 | 0.665 | 1.000 | 0.366 | 1.000 | 0.774 | 0.660 | 0.355 |
| cam-lds-s2 | 0.675 | 0.143 | 0.330 | 0.271 | 0.330 | 1.000 | 0.143 | 1.000 | 0.805 | 0.675 | 0.326 |
| cam-lds-s3 | 0.703 | 0.137 | 0.581 | 0.550 | 0.581 | 1.000 | 0.172 | 1.000 | 0.794 | 0.700 | 0.342 |
| cam-lds-s4 | 0.721 | 0.141 | 0.437 | 0.264 | 0.437 | 1.000 | 0.000 | 1.000 | 0.816 | 0.609 | 0.332 |
| cam-lds-s5 | 0.735 | 0.155 | 0.380 | 0.262 | 0.380 | 1.000 | 0.000 | 1.000 | 0.815 | 0.569 | 0.323 |
| cam-lds-s6 | 0.707 | 0.146 | 0.369 | 0.374 | 0.374 | 1.000 | 0.167 | 1.000 | 0.775 | 0.629 | 0.356 |
| cam-lds-s7 | 0.749 | 0.146 | 0.674 | 0.614 | 0.674 | 1.000 | 0.167 | 1.000 | 0.811 | 0.761 | 0.336 |
| BGL | 0.327 | 0.047 | 0.882 | 0.859 | 0.882 | -- | -- | -- | 0.638 | -- | -- |
| Thunderbird | 0.272 | 0.109 | 0.9997 | 0.9999 | 1.000 | 0.993 | -- | 0.993 | 0.951 | -- | -- |
| HDFS_1 | 0.459 | 0.179 | 0.075 | 0.106 | 0.106 | 0.000 | 0.999 | 0.999 | 0.846 | -- | -- |
| HDFS_2 | 0.407 (a) | 0.130 | -- | -- | -- | 0.000 | 1.000 | 1.000 | 0.820 | -- | -- |
| Hadoop | 0.590 | 0.056 | 0.067 | 0.872 | 0.872 (c) | 0.000 | 0.020 | 0.020 | 0.887 | -- | 0.737 |
| OpenStack | 0.388 | 0.213 | 0.255 | 0.238 | 0.255 (c) | 0.000 | 0.333 | 0.333 | 0.629 | -- | 0.556 |
| ATLASv2 | 0.260 | 0.419 (b) | 0.133 | 0.001 | 0.133 | 1.000 | 1.000 | 1.000 | 0.660 | -- | 0.538 |
| UWF-ZeekData22 | 0.281 | 0.004 | 0.987 | 0.990 | 0.990 | 0.046 | 0.000 | 0.046 | 0.323 | 0.088 (d) | -- |
| CADETS | 0.433 (b) | 0.484 (b) | -- | -- | -- | 0.500 | 0.000 | 0.500 | 0.708 (b) | -- | 0.485 |
| THEIA | 0.464 (b) | 0.446 (b) | -- | -- | -- | -- | -- | -- | 0.475 (b) | -- | 0.309 |

(a) mined with `max_clusters` 1000 (see the settings above); the default-cap
Drain3 run gives 0.381. (b) derived from a sub-sample and known biased (see the
sampling note at the end of Section 11.3). (c) file-level-label artefact
(Section 11.3). (d) tactic resolution, not comparable to other D6 values
(Section 8.1).

Coverage: D1/D2/D5 all 20; D3 17/20 (HDFS_2, CADETS, THEIA unlabelled); D4 19/20
(THEIA single-host); D6 11/20; D7 15/20.

Supplementary: D4_attack (co-attacked pairs only): AIT-LDS-RM 1.000, ATLASv2 1.000,
Wilson 1.000, Santos 0.833, Hadoop 0.040. If D4_attack replaced D4_conn as the
threshold, five verdicts would flip to SUITABLE. Cross-file Jaccard (reference): Hadoop
0.0597, OpenStack 0.0127, both far below tau_D3.

Global near-duplicate correction (Section 7.1): ATLASv2 0.348 to 0.260 (global
NearDup 70.3%), Thunderbird 0.283 to 0.272 (39.7%), UWF-ZeekData22 to 0.281
(56.25%, which flipped its AD verdict), Hadoop 0.663 to 0.590 (29.5%).

D2 against its null: all twenty datasets sit below their null, so every one has
more sequence structure than chance; the ratio D2/D2_null runs from 0.065 (Hadoop,
nearly deterministic) to 0.602 (ATLASv2). Re-deriving tau_D2 from the full corpus
rather than the initial one would move it to about 0.32, because the seven CAM-LDS
groups and HDFS_1 populate the gap it was placed in, and that would flip
cam-lds-s5 from IR-SUITABLE to UNSUITABLE.

D6 label regimes on the reference corpus:

| Regime | Datasets | Source | Frequency unit |
|---|---|---|---|
| machine | CAM-LDS S1 to S7 | technique codes read directly from the machine-readable attack description | one step entry |
| derived (step) | AIT-LDS-RM, Santos, Wilson | attack-step names mapped to technique codes; 60 of 66 steps mapped, 6 attacker-side control-flow steps skipped | one step execution, directly comparable to CAM-LDS |
| derived (tactic) | UWF-ZeekData22 | the dataset's tactic column, each tactic mapped 1:1 to a canonical technique | one network flow, not comparable; the technique count is a mapping artefact, T_d is a lower bound, T_e is a tactic-level proxy |

D7 reference constants N_ref = 167 and D_ref = 5211.98 both come from Hadoop, the
corpus reference. Datasets with no pure-normal file report no D7: BGL, HDFS_1,
Thunderbird, UWF-ZeekData22.

### 11.2 Verdicts, all 80 pairs

| Dataset | AD | IR | RCA | CTI |
|---|---|---|---|---|
| AIT-LDS-RM | SUITABLE | UNSUITABLE | UNSUITABLE | SUITABLE |
| Santos | SUITABLE | UNSUITABLE | UNSUITABLE | SUITABLE |
| Wilson | SUITABLE | UNSUITABLE | UNSUITABLE | SUITABLE |
| cam-lds-s1 | SUITABLE | UNSUITABLE | SUITABLE | SUITABLE |
| cam-lds-s2 | SUITABLE | UNSUITABLE | SUITABLE | SUITABLE |
| cam-lds-s3 | SUITABLE | UNSUITABLE | SUITABLE | SUITABLE |
| cam-lds-s4 | SUITABLE | UNSUITABLE | SUITABLE | SUITABLE |
| cam-lds-s5 | SUITABLE | SUITABLE | SUITABLE | SUITABLE |
| cam-lds-s6 | SUITABLE | UNSUITABLE | SUITABLE | SUITABLE |
| cam-lds-s7 | SUITABLE | UNSUITABLE | SUITABLE | SUITABLE |
| BGL | UNSUITABLE | INDETERMINATE | INDETERMINATE | SUITABLE |
| Thunderbird | UNSUITABLE | UNSUITABLE | SUITABLE | SUITABLE |
| HDFS_1 | UNSUITABLE | SUITABLE | UNSUITABLE | UNSUITABLE |
| HDFS_2 | INDET | UNSUITABLE | INDET | INDET |
| Hadoop | SUITABLE | UNSUITABLE | UNSUITABLE | SUITABLE |
| OpenStack | UNSUITABLE | UNSUITABLE | UNSUITABLE | SUITABLE |
| ATLASv2 | UNSUITABLE | SUITABLE | UNSUITABLE | UNSUITABLE |
| UWF-ZeekData22 | UNSUITABLE | UNSUITABLE | UNSUITABLE | SUITABLE |
| CADETS | INDET | SUITABLE | INDET | INDET |
| THEIA | INDET | INDET | INDET | INDET |

Tally

| Task | SUITABLE | UNSUITABLE | INDETERMINATE |
|---|---|---|---|
| Anomaly Detection | 11 | 6 | 3 |
| Incident Reconstruction | 4 | 14 | 2 |
| Root Cause Analysis | 8 | 8 | 4 |
| CTI / ATT&CK Attribution | 15 | 2 | 3 |
| Total (80) | 38 | 30 | 12 |

### 11.3 Reading the verdicts

- Incident Reconstruction is the binding constraint (4/20). Almost everything
  clears D4 (all seven CAM-LDS groups sit at exactly 1.000), so it is D2 >= 0.15
  that decides. Only cam-lds-s5 (0.155), ATLASv2 (0.419), HDFS_1 (0.179) and CADETS
  (0.484) pass, and two of those rest on a biased D2 (sub-sampled, see below). Five of seven
  CAM-LDS groups fail IR on D2 in [0.137, 0.146], within 0.013 of the threshold.
  This is the framework's most threshold-fragile result.
- CTI is the loosest (15/20) because D3 is its only necessary dimension.
- CAM-LDS is the only family suitable for RCA (7 of the 8 RCA passes), driven by
  D4 = 1.000 throughout.
- The AIT trio fails IR and RCA purely on D4 (0.110 to 0.186): cross-host
  identifier sharing is weak because traffic concentrates on gateway hosts. The
  D4_attack variant shows their attacked hosts are fully linkable (1.000, 0.833,
  1.000).
- The three most heavily reused public AD benchmarks, HDFS, BGL and Thunderbird,
  are all UNSUITABLE for anomaly detection. HDFS_1 fails on D3 = 0.106 (anomalous
  blocks reuse normal templates), BGL on D1_robust = 0.327, Thunderbird on both
  (D1 = 0.272).
- The 10 INDETERMINATE cells are structural. Nine trace to D3 unavailability
  (HDFS_2 has only block or session labels; CADETS and THEIA are unlabelled
  provenance streams), one to D4 unavailability (THEIA's 1% sample is single-host).
  HDFS_2 scores well on everything it can measure; per-line labels would likely
  resolve it to definite verdicts.

Four SUITABLE verdicts carry documented caveats and are not claims of genuine task
suitability:

| Dataset | Verdict | Caveat |
|---|---|---|
| BGL | CTI SUITABLE | Template-identifiable labels. The alert category is removed at Stage 1, but fault messages rarely occur during normal operation, so D3 = 0.882 measures template distinctiveness rather than task difficulty. The labels are hardware faults, not ATT&CK activity. |
| Thunderbird | RCA + CTI SUITABLE | Label leakage, same mechanism (U = 0.9997, purity = 0.9999). Also computed from a 7.65M-line prefix rather than the full stream, though 0.9999 is so far above the threshold that the verdict is robust to that. |
| Hadoop | AD + CTI SUITABLE | File-level-label artefact. Labels are per file, so `max(U, purity)` is inflated by container identity, not per-line separability: U = 0.067 (low) but purity = 0.872 (high). The honest reading is the cross-file Jaccard, 0.060. |
| OpenStack | CTI SUITABLE | File-level-label artefact. U = 0.255, purity = 0.238; honest cross-file Jaccard is 0.013. |

These four are marked in the engine's markdown output and are adopted
deliberately: every labelled dataset is decided on the same metric for pipeline
consistency, with the artefact disclosed, rather than special-casing two datasets
onto a different metric.

Stage 1 exclusions and sampling behind these numbers: the Santos and Wilson
adapters excluded the `suricata/` and `journal/` subtrees; for AIT-LDS-RM the
Suricata `stats.log` was read at Stage 1 and skipped at Stage 2 by the
telemetry-file detector, and that one file is 17M of 23M processed lines of
per-second monitoring counters, so AIT-LDS-RM analyses 3.66M of 25.4M raw lines by
design. Four datasets were sampled: CADETS 1% (11.93M of about 1.19B events),
THEIA 1% (1.06M of 106.0M), ATLASv2 10% (3.46M of about 34.6M), and Thunderbird,
where aggregates use the full 211M lines but per-line template assignments exist
only for a 7.65M-line prefix.

## 12. Known limitations

### 12.1 Metric-level

1. CTI depends on D3 alone, which makes it a label-quality check rather than an
   attribution-readiness check. A dataset can pass CTI on a high D3 while carrying
   almost no ATT&CK content: on the reference corpus UWF-ZeekData22 passes on
   D3 = 0.990 while carrying two tactics and zero techniques, because
   reconnaissance and discovery flows map to distinct connection-state templates.
   D6 is the dimension that would catch this, but making it co-necessary would
   push 9 of the 20 reference datasets to INDETERMINATE, and D6 has no calibrated
   threshold. Open design question.
2. D6 has no threshold and mixed provenance across label regimes, so values are not
   always comparable between datasets: on the reference corpus 7 machine values, 3
   derived at step resolution and 1 at tactic resolution and explicitly not
   comparable, over a range of 0.088 to 0.761. It is also not computed by the
   package (Section 8.1).
3. D4 saturates at 1.000 for ten of the twenty reference datasets, all seven
   CAM-LDS groups among them, so it discriminates poorly at the top.
4. D2 is the last file-split-dependent metric. D1 and D5 aggregate by median over
   files, D3 is global, D4 is per host, but D2 is computed per file when it
   arguably should be per entity (per host, time-ordered). This is the one open
   metric-correctness item.
5. D5, D6 and D7 are descriptive, so they are validated to a lower standard:
   D5 is perturbation-backed but has no external probe; D6 and D7 have neither.

### 12.2 Label-quality artefacts

A verdict is only as good as the labels behind it, and three failure modes recur.
Label leakage: the label is recoverable from the message text itself, so D3
approaches 1.0 without any real separability. File-level labelling: labels mark
whole files, so purity is inflated by file identity rather than per-line
separability. Identifier-channel linkage: D4 is high because one identifier type
links nearly every host pair, which is a property of that identifier rather than
of host correlation.

On the reference corpus, four SUITABLE verdicts are artefacts of the first two
kinds, all documented in Section 11.3: template-identifiable labels for BGL and Thunderbird,
file-level-label inflation for Hadoop and OpenStack. HDFS_1's IR-SUITABLE is the
third kind: D4 = 0.999 comes from block-id sharing (`D4_part`).

## 13. Glossary

| Term | Meaning |
|---|---|
| Template | Drain3 cluster representative; a log line with variable tokens replaced by `<*>` |
| K | Number of distinct templates in a file |
| NearDup | Fraction of templates with a near-twin at token-set Jaccard >= 0.8; global NearDup searches the whole dataset, per-file only within one file |
| D1_robust | Canonical D1: median over files of the four-component composite, global-NearDup corrected |
| D3_eff | Canonical D3: `max(U, purity)` on the global (template, label) table |
| U | Theil's uncertainty coefficient, I(template; label) / H(label) |
| purity | Jeffreys-smoothed attack-purity coverage |
| D4_conn / D4_part | Connection channel (shared non-private IPv4) / participation channel (shared uuid, SID, YARN id, HDFS block) |
| D4_max | The D4 the rule uses: `max(D4_conn, D4_part)` |
| Necessary dimension | Gates the verdict for a task; all must clear tau for SUITABLE |
| Supporting dimension | Reported alongside a verdict, never changes it |
| INDETERMINATE | A necessary dimension could not be measured; judgment withheld, not failed |
| OWA | Ordered weighted average; weights assigned to sorted values (D6 uses 0.5/0.3/0.2) |
| Reference corpus | The recorded score vectors of the twenty datasets of the study, loaded by `src/registry.py` |
| slug | Output-directory name of a dataset under `outputs/` (`registry.DATASETS` maps display names to slugs) |
