"""Stage 1: turn raw log files into the normalized CSV, driven by a config file.

This is the only dataset-specific step. Everything after it is the same code
for every dataset. Rather than writing an adapter per dataset, describe the
format in a small YAML or JSON config and run this file.

    python src/normalize.py --config configs/mylogs.yml

Config keys
-----------
```yaml
dataset:    mylogs                 # slug; names the output directory
input_dir:  data/mylogs            # root holding the raw files
output:     outputs/mylogs/normalized_full.csv   # optional, this is the default
pattern:    "**/*.log"             # glob for log files, relative to input_dir
exclude:    ["**/metrics/**"]      # optional globs to skip

host:                              # which component produced a line
  from:  path_part                 # path_part | filename | line_regex | fixed
  index: 0                         #   path_part: directory level below input_dir
  pattern: "host=(\\S+)"           #   line_regex: first group is the host
  value: "single-host"             #   fixed: this literal

timestamp:                         # optional; defaults to {from: auto}
  from: auto                       # auto | regex | none
  pattern: "^(\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2})"   # regex: first group
  strptime: "%Y-%m-%d %H:%M:%S"    # regex: how to read that group
  syslog_year: 2024                # auto: needed only for syslog-style lines

labels:                            # optional; defaults to {from: none}
  from: none        # none | line_numbers | id_regex | time_windows | file_glob
  path: data/mylogs/labels.json    # line_numbers: {"<source_file>": [12, 13]}

  # id_regex: a line is attack when an id it contains is listed as anomalous
  pattern: "blk_-?\\d+"            #   how to find ids in the line
  ids_csv: data/mylogs/anomalies.csv
  id_column: BlockId
  label_column: Label              #   optional
  attack_values: ["Anomaly"]       #   rows counted as attack

  # time_windows: a line is attack when its timestamp falls in a window
  windows: [["2024-03-01T10:00:00", "2024-03-01T11:30:00"]]

  # file_glob: every line of a matching file is attack
  attack_glob: "**/abnormal*.log"
```

Only `dataset`, `input_dir` and `host` are required. Any key can be overridden
on the command line, and `--set a.b=value` sets one nested key.

Output: the 13-column CSV that Stage 2 and Stage 3 read, plus a short summary
of what was parsed and labelled.

Three properties matter for the metrics downstream:
  Row order is the event sequence, so lines are written in file order.
  Per-line labels drive D3; a label that marks whole files makes D3 measure
  file identity instead, and it should then be treated as unavailable.
  Distinct host values are the nodes of the D4 graph; one host leaves D4
  undefined.
"""
from __future__ import annotations

import argparse
import csv
import fnmatch
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import paths
from schema import (CSV_COLUMNS, is_log_text_candidate, is_probably_text_file,
                    parse_timestamp)

csv.field_size_limit(10 ** 8)


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
def load_config(path: Path) -> dict:
    """Read a YAML or JSON config file."""
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() in (".yml", ".yaml"):
        try:
            import yaml
        except ImportError:
            raise SystemExit("PyYAML is needed for a YAML config; use JSON instead.")
        config = yaml.safe_load(text)
    else:
        config = json.loads(text)
    if not isinstance(config, dict):
        raise SystemExit(f"{path}: the config must be a mapping of keys to values")
    return config


def apply_overrides(config: dict, assignments: list[str]) -> dict:
    """Apply `--set key.subkey=value` assignments to a config."""
    for item in assignments:
        if "=" not in item:
            raise SystemExit(f"--set expects key=value, got: {item}")
        key, value = item.split("=", 1)
        target = config
        parts = key.split(".")
        for part in parts[:-1]:
            target = target.setdefault(part, {})
        try:
            target[parts[-1]] = json.loads(value)
        except json.JSONDecodeError:
            target[parts[-1]] = value
    return config


# ---------------------------------------------------------------------------
# Host
# ---------------------------------------------------------------------------
def make_host_resolver(spec: dict):
    """Return a function (relative path, line) -> host name."""
    mode = spec.get("from", "path_part")

    if mode == "fixed":
        value = spec.get("value", "host")
        return lambda rel, line: value

    if mode == "filename":
        return lambda rel, line: Path(rel).stem

    if mode == "path_part":
        index = int(spec.get("index", 0))

        def from_path(rel, line):
            parts = Path(rel).parts
            if len(parts) > index + 1:
                return parts[index]
            return Path(rel).stem

        return from_path

    if mode == "line_regex":
        pattern = spec.get("pattern")
        if not pattern:
            raise SystemExit("host.from=line_regex needs a 'pattern'")
        compiled = re.compile(pattern)
        fallback = spec.get("fallback", "unknown")

        def from_line(rel, line):
            match = compiled.search(line)
            return match.group(1) if match else fallback

        return from_line

    raise SystemExit(f"unknown host.from: {mode}")


# ---------------------------------------------------------------------------
# Timestamp
# ---------------------------------------------------------------------------
def make_timestamp_parser(spec: dict):
    """Return a function (line) -> (raw text, ISO 8601, success, datetime)."""
    mode = spec.get("from", "auto")

    if mode == "none":
        return lambda line: ("", "", False, None)

    if mode == "auto":
        year = spec.get("syslog_year")
        return lambda line: parse_timestamp(line, syslog_year=year)

    if mode == "regex":
        pattern = spec.get("pattern")
        fmt = spec.get("strptime")
        if not pattern or not fmt:
            raise SystemExit("timestamp.from=regex needs 'pattern' and 'strptime'")
        compiled = re.compile(pattern)

        def from_regex(line):
            match = compiled.search(line)
            if not match:
                return "", "", False, None
            raw = match.group(1) if match.groups() else match.group(0)
            try:
                parsed = datetime.strptime(raw, fmt)
            except ValueError:
                return raw, "", False, None
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return raw, parsed.isoformat(), True, parsed

        return from_regex

    raise SystemExit(f"unknown timestamp.from: {mode}")


# ---------------------------------------------------------------------------
# Labels
# ---------------------------------------------------------------------------
class Labeller:
    """Decides whether a line is attack activity, and whether a file is labelled."""

    def __init__(self, spec: dict, root: Path):
        self.mode = spec.get("from", "none")
        self.spec = spec
        self.root = root
        self.line_numbers: dict[str, set[int]] = {}
        self.attack_ids: set[str] = set()
        self.id_re: re.Pattern | None = None
        self.windows: list[tuple[datetime, datetime]] = []
        self.attack_glob: str | None = None

        if self.mode == "none":
            return
        if self.mode == "line_numbers":
            data = json.loads(Path(spec["path"]).read_text(encoding="utf-8"))
            data = data.get("attack_line_numbers", data)
            self.line_numbers = {k: set(v) for k, v in data.items()}
        elif self.mode == "id_regex":
            self.id_re = re.compile(spec["pattern"])
            self._load_ids(Path(spec["ids_csv"]), spec)
        elif self.mode == "time_windows":
            for start, end in spec["windows"]:
                self.windows.append((_as_utc(start), _as_utc(end)))
        elif self.mode == "file_glob":
            self.attack_glob = spec["attack_glob"]
        else:
            raise SystemExit(f"unknown labels.from: {self.mode}")

    def _load_ids(self, path: Path, spec: dict) -> None:
        id_column = spec.get("id_column")
        label_column = spec.get("label_column")
        attack_values = {str(v).lower() for v in spec.get("attack_values", ["anomaly"])}
        with path.open(newline="", encoding="utf-8") as fh:
            reader = csv.DictReader(fh)
            if id_column is None:
                id_column = reader.fieldnames[0]
            for row in reader:
                if label_column and str(row.get(label_column, "")).lower() not in attack_values:
                    continue
                value = (row.get(id_column) or "").strip()
                if value:
                    self.attack_ids.add(value)

    def file_is_labelled(self, source_file: str) -> bool:
        if self.mode == "none":
            return False
        if self.mode == "line_numbers":
            return source_file in self.line_numbers
        if self.mode == "file_glob":
            return True
        return True

    def is_attack(self, source_file: str, line_no: int, line: str, when) -> bool:
        if self.mode == "none":
            return False
        if self.mode == "line_numbers":
            return line_no in self.line_numbers.get(source_file, ())
        if self.mode == "id_regex":
            return any(found in self.attack_ids for found in self.id_re.findall(line))
        if self.mode == "time_windows":
            if when is None:
                return False
            return any(start <= when <= end for start, end in self.windows)
        if self.mode == "file_glob":
            return fnmatch.fnmatch(source_file, self.attack_glob)
        return False


def _as_utc(value: str) -> datetime:
    parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


# ---------------------------------------------------------------------------
# Normalization
# ---------------------------------------------------------------------------
def iter_files(root: Path, pattern: str, excludes: list[str]):
    """Log files under the root, in a stable order.

    A file is read when it matches the pattern, no exclude glob, has a log-like
    name (is_log_text_candidate) and looks like text rather than a compressed
    or binary file (is_probably_text_file). Everything else is skipped without
    being opened.
    """
    for path in sorted(root.glob(pattern)):
        if not path.is_file():
            continue
        rel = path.relative_to(root).as_posix()
        if any(fnmatch.fnmatch(rel, item) for item in excludes):
            continue
        if not is_log_text_candidate(path) or not is_probably_text_file(path):
            continue
        yield path, rel


def normalize(config: dict) -> dict:
    """Run Stage 1. Returns a summary of what was written."""
    dataset = config["dataset"]
    root = Path(config["input_dir"])
    if not root.is_dir():
        raise SystemExit(f"input_dir not found: {root}")

    output = Path(config.get("output") or paths.normalized_csv(dataset))
    pattern = config.get("pattern", "**/*.log")
    excludes = list(config.get("exclude", []))

    host_of = make_host_resolver(config.get("host", {"from": "path_part"}))
    timestamp_of = make_timestamp_parser(config.get("timestamp", {"from": "auto"}))
    labeller = Labeller(config.get("labels", {"from": "none"}), root)

    output.parent.mkdir(parents=True, exist_ok=True)
    n_files = n_lines = n_attack = n_parsed = 0
    hosts: set[str] = set()

    with output.open("w", newline="", encoding="utf-8") as out_fh:
        writer = csv.writer(out_fh)
        writer.writerow(CSV_COLUMNS)

        for path, rel in iter_files(root, pattern, excludes):
            labelled = labeller.file_is_labelled(rel)
            n_files += 1
            with path.open(encoding="utf-8", errors="replace") as in_fh:
                for line_no, raw in enumerate(in_fh, start=1):
                    message = raw.rstrip("\r\n")
                    if not message:
                        continue
                    ts_raw, ts_iso, ok, when = timestamp_of(message)
                    attack = labeller.is_attack(rel, line_no, message, when)
                    host = host_of(rel, message)
                    hosts.add(host)
                    n_lines += 1
                    n_attack += attack
                    n_parsed += ok
                    writer.writerow([
                        dataset, host, rel, line_no, message,
                        ts_raw, ts_iso, ok, True, attack,
                        "labeled" if labelled else "unlabeled",
                        json.dumps(["attack"]) if attack else "[]",
                        "{}",
                    ])

    return {
        "dataset": dataset,
        "output": str(output),
        "files": n_files,
        "lines": n_lines,
        "hosts": len(hosts),
        "attack_lines": n_attack,
        "attack_ratio": n_attack / max(n_lines, 1),
        "timestamp_parse_rate": n_parsed / max(n_lines, 1),
    }


def report(summary: dict) -> None:
    print(f"dataset:        {summary['dataset']}")
    print(f"files:          {summary['files']}")
    print(f"lines:          {summary['lines']:,}")
    print(f"hosts:          {summary['hosts']}")
    print(f"attack lines:   {summary['attack_lines']:,} "
          f"({summary['attack_ratio'] * 100:.2f}%)")
    print(f"timestamps:     {summary['timestamp_parse_rate'] * 100:.1f}% parsed")
    print(f"written:        {summary['output']}")
    if summary["files"] == 0:
        print("\nNo files were read. Either nothing under 'input_dir' matched "
              "'pattern', or the matches have no log-like name: only *.log, "
              "*.log.*, eve.json, syslog, auth.log, audit.log, openvpn.log and "
              "dnsmasq.log are read (is_log_text_candidate in schema.py).")
    if summary["hosts"] < 2:
        print("\nOne host only, so D4 is undefined and the tasks that need it "
              "will be INDETERMINATE. Check the host setting.")
    if summary["attack_lines"] == 0:
        print("\nNo attack lines, so D3 cannot be computed and the tasks that "
              "need it will be INDETERMINATE. Check the labels setting.")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Stage 1: normalize raw logs into the 13-column CSV",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("--config", type=Path, help="YAML or JSON config file")
    parser.add_argument("--dataset", help="dataset slug")
    parser.add_argument("--input-dir", help="root holding the raw log files")
    parser.add_argument("--output", help="normalized CSV to write")
    parser.add_argument("--pattern", help="glob for log files under the input directory")
    parser.add_argument("--set", dest="assignments", action="append", default=[],
                        metavar="KEY=VALUE",
                        help="override one config key, for example labels.from=none")
    args = parser.parse_args()

    config = load_config(args.config) if args.config else {}
    for key in ("dataset", "input_dir", "output", "pattern"):
        value = getattr(args, key if key != "input_dir" else "input_dir")
        if value:
            config[key] = value
    config = apply_overrides(config, args.assignments)

    for required in ("dataset", "input_dir"):
        if not config.get(required):
            raise SystemExit(f"'{required}' is required, in the config or on the command line")

    report(normalize(config))


if __name__ == "__main__":
    main()
