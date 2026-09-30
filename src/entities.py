"""Stage 3: link hosts through the identifiers that appear in their messages.

Reads the raw message text directly and bypasses the mined templates, because
templating removes exactly the variable tokens this stage needs. Five entity
types are extracted per line and accumulated into a set per host: IPv4
addresses, UUIDs, Windows security identifiers, Hadoop and YARN identifiers and
HDFS block identifiers.

Shared infrastructure creates links that carry no analytic meaning, so loopback
and broadcast addresses, the private RFC 1918 ranges, the all-zero and all-ones
UUIDs and the well-known Windows identifiers are excluded.

Two channels are reported separately and never combined:
  D4_conn  share of host pairs sharing a non-private IPv4 address
  D4_part  share of host pairs sharing a participation identifier

Reads   outputs/<slug>/normalized_full.csv
Writes  d4_per_host.csv, d4_cross_host.csv and d4_summary.json

Host pairs are enumerated explicitly, so the cost grows with the square of the
host count.

Usage:
  python src/entities.py --normalized-csv outputs/<slug>/normalized_full.csv \
      --output-dir outputs/<slug>/stage3_d4
"""
from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import math
import re
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


csv.field_size_limit(10_000_000)

# ---------------------------------------------------------------------------
# Entity-type regular expressions
# ---------------------------------------------------------------------------

# IPv4: permissive octet match; private/loopback/broadcast excluded below
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_EXCLUDED_IPS: frozenset[str] = frozenset({
    "0.0.0.0",
    "127.0.0.1",
    "255.255.255.255",
})
# RFC 1918 private ranges are excluded: shared infrastructure addresses
# (gateway, DNS, NTP) appear on every host of a LAN and would push
# ip_sharing_ratio towards 1.0 without indicating any cross-host activity.
_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),   # loopback range
]


def _is_excluded_ip(ip: str) -> bool:
    if ip in _EXCLUDED_IPS:
        return True
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in _PRIVATE_NETWORKS)
    except ValueError:
        return False

# UUID: RFC 4122 format (8-4-4-4-12 hex digits), case-insensitive
_UUID_RE = re.compile(
    r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
    re.IGNORECASE,
)
_EXCLUDED_UUIDS: frozenset[str] = frozenset({
    "00000000-0000-0000-0000-000000000000",
    "ffffffff-ffff-ffff-ffff-ffffffffffff",
})

# Windows SID: S-1-N-M[-...], at least 3 components after S
_SID_RE = re.compile(r"\bS-\d+-\d+(?:-\d+){1,}\b")
# Well-known SIDs that appear on every Windows host and carry no cross-host signal
_EXCLUDED_SIDS: frozenset[str] = frozenset({
    "s-1-5-18",   # LocalSystem
    "s-1-5-19",   # LocalService
    "s-1-5-20",   # NetworkService
    "s-1-1-0",    # Everyone
    "s-1-5-11",   # Authenticated Users
    "s-1-5-15",   # This Organization
    "s-1-16-0",   # Untrusted Mandatory Level
    "s-1-16-4096",    # Low Mandatory Level
    "s-1-16-8192",    # Medium Mandatory Level
    "s-1-16-12288",   # High Mandatory Level
    "s-1-16-16384",   # System Mandatory Level
})

# Hadoop / YARN: application_, appattempt_, attempt_, container_ followed by
# a 13-digit epoch timestamp and underscore-delimited alphanumeric suffixes.
# Suffixes can be numeric (0011, 000006) or single-letter task-type codes (m, r).
# Example full IDs:
#   application_1445062781478_0011
#   attempt_1445062781478_0011_m_000006_0
#   container_1445062781478_0013_01_000005
_HADOOP_ID_RE = re.compile(
    r"\b(?:application|appattempt|attempt|container)_\d{13}_\d{4}(?:_[a-z0-9]+)*\b",
    re.IGNORECASE,
)

# HDFS block IDs: blk_<signed-int>[_<generation-stamp>]
# Block-pool IDs: BP-<id>-<ip>-<epoch>
_HDFS_BLOCK_RE = re.compile(
    r"\b(?:blk_-?\d+(?:_\d+)?|BP-\d+-(?:\d{1,3}\.){3}\d{1,3}-\d+)\b"
)

# ---------------------------------------------------------------------------
# Entity-type registry
# name -> (compiled_regex, excluded_set, normalise_fn)
# normalise_fn: applied to each matched string before storing (e.g. .lower())
# ---------------------------------------------------------------------------
_ENTITY_TYPES: list[tuple[str, re.Pattern, frozenset, Any]] = [
    ("ipv4",        _IP_RE,        _EXCLUDED_IPS,    str),
    ("uuid",        _UUID_RE,      _EXCLUDED_UUIDS,  str.lower),
    ("windows_sid", _SID_RE,       _EXCLUDED_SIDS,   str.lower),
    ("hadoop_id",   _HADOOP_ID_RE, frozenset(),      str.lower),
    ("hdfs_block",  _HDFS_BLOCK_RE, frozenset(),     str),
]
_TYPE_NAMES = [t[0] for t in _ENTITY_TYPES]

# ---------------------------------------------------------------------------
# CSV column definitions
# ---------------------------------------------------------------------------
D4_PER_HOST_COLUMNS = [
    "host",
    "line_count",
    # entity counts per type
    "ip_count",
    "uuid_count",
    "windows_sid_count",
    "hadoop_id_count",
    "hdfs_block_count",
    # timestamp range
    "ts_start",
    "ts_end",
    "ts_span_s",
]

D4_CROSS_HOST_COLUMNS = [
    "host_a",
    "host_b",
    # shared counts per type
    "shared_ip_count",
    "shared_uuid_count",
    "shared_sid_count",
    "shared_hadoop_id_count",
    "shared_hdfs_block_count",
    # union: shared count across all types
    "shared_any_count",
    "time_overlap_s",
]

# map entity type name -> per_host column name
_TYPE_TO_HOST_COL = {
    "ipv4":        "ip_count",
    "uuid":        "uuid_count",
    "windows_sid": "windows_sid_count",
    "hadoop_id":   "hadoop_id_count",
    "hdfs_block":  "hdfs_block_count",
}

# map entity type name -> cross_host column name
_TYPE_TO_CROSS_COL = {
    "ipv4":        "shared_ip_count",
    "uuid":        "shared_uuid_count",
    "windows_sid": "shared_sid_count",
    "hadoop_id":   "shared_hadoop_id_count",
    "hdfs_block":  "shared_hdfs_block_count",
}


def _parse_iso_ts(ts_str: str) -> float | None:
    if not ts_str:
        return None
    try:
        dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        return dt.timestamp()
    except (ValueError, TypeError, OverflowError):
        return None


def _extract_entities(raw_message: str) -> dict[str, set[str]]:
    """Extract all entity types from a single raw log message."""
    result: dict[str, set[str]] = {}
    for type_name, regex, excluded, normalise in _ENTITY_TYPES:
        found = {normalise(m) for m in regex.findall(raw_message)}
        if type_name == "ipv4":
            result[type_name] = {ip for ip in found if not _is_excluded_ip(ip)}
        else:
            result[type_name] = found - excluded
    return result


def _time_overlap(start_a: float, end_a: float, start_b: float, end_b: float) -> float:
    overlap_start = max(start_a, start_b)
    overlap_end = min(end_a, end_b)
    return max(0.0, overlap_end - overlap_start)


def measure_entities(
    normalized_csv: Path,
    output_dir: Path,
) -> dict[str, Any]:
    """Compute the D4 cross-host metrics from a normalized CSV.

    Args:
        normalized_csv: Path to the Stage 1 normalized CSV.
        output_dir: Directory to write d4_per_host.csv, d4_cross_host.csv,
            and d4_summary.json.

    Returns:
        Summary dict written to d4_summary.json.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    per_host_csv = output_dir / "d4_per_host.csv"
    cross_host_csv = output_dir / "d4_cross_host.csv"
    summary_json = output_dir / "d4_summary.json"

    # Per-host accumulators
    # host_entity_sets[host][type_name] = set of extracted entity strings
    host_entity_sets: dict[str, dict[str, set[str]]] = defaultdict(
        lambda: {t: set() for t in _TYPE_NAMES}
    )
    host_ts_min: dict[str, float] = {}
    host_ts_max: dict[str, float] = {}
    host_line_count: dict[str, int] = defaultdict(int)

    print("  Streaming normalized CSV for D4 metrics...")
    with normalized_csv.open("r", newline="", encoding="utf-8") as nf:
        reader = csv.DictReader(nf)
        for i, row in enumerate(reader):
            host = row.get("host", "unknown")
            host_line_count[host] += 1

            raw_msg = row.get("raw_message", "")
            entities = _extract_entities(raw_msg)
            for type_name, entity_set in entities.items():
                host_entity_sets[host][type_name].update(entity_set)

            ts_val = _parse_iso_ts(row.get("timestamp_parsed", ""))
            if ts_val is not None:
                if host not in host_ts_min or ts_val < host_ts_min[host]:
                    host_ts_min[host] = ts_val
                if host not in host_ts_max or ts_val > host_ts_max[host]:
                    host_ts_max[host] = ts_val

            if (i + 1) % 1_000_000 == 0:
                print(f"    {i + 1:,} rows processed...")

    hosts = sorted(host_line_count.keys())
    print(f"  Found {len(hosts)} distinct hosts.")

    # Write per-host CSV
    with per_host_csv.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=D4_PER_HOST_COLUMNS)
        writer.writeheader()
        for host in hosts:
            ts_start = host_ts_min.get(host)
            ts_end = host_ts_max.get(host)
            if ts_start is not None and ts_end is not None:
                span = ts_end - ts_start
                ts_start_iso = datetime.fromtimestamp(ts_start, tz=timezone.utc).isoformat()
                ts_end_iso = datetime.fromtimestamp(ts_end, tz=timezone.utc).isoformat()
            else:
                span = float("nan")
                ts_start_iso = ""
                ts_end_iso = ""
            row_dict: dict[str, Any] = {
                "host": host,
                "line_count": host_line_count[host],
                "ts_start": ts_start_iso,
                "ts_end": ts_end_iso,
                "ts_span_s": "" if math.isnan(span) else round(span, 3),
            }
            for type_name, host_col in _TYPE_TO_HOST_COL.items():
                row_dict[host_col] = len(host_entity_sets[host][type_name])
            writer.writerow(row_dict)

    # Compute cross-host pairs
    cross_host_rows: list[dict[str, Any]] = []
    # per-type pair counts
    n_pairs_sharing: dict[str, int] = {t: 0 for t in _TYPE_NAMES}
    n_pairs_sharing_any = 0
    n_pairs_sharing_participation = 0  # >= 1 non-IP entity shared (D4_part numerator)
    n_pairs_time_overlap = 0

    _PARTICIPATION_TYPES = [t for t in _TYPE_NAMES if t != "ipv4"]

    for i, host_a in enumerate(hosts):
        for host_b in hosts[i + 1:]:
            cross_row: dict[str, Any] = {"host_a": host_a, "host_b": host_b}
            shared_any = 0

            for type_name, cross_col in _TYPE_TO_CROSS_COL.items():
                shared = host_entity_sets[host_a][type_name] & host_entity_sets[host_b][type_name]
                shared_count = len(shared)
                cross_row[cross_col] = shared_count
                if shared_count > 0:
                    n_pairs_sharing[type_name] += 1
                    shared_any += shared_count

            cross_row["shared_any_count"] = shared_any
            if shared_any > 0:
                n_pairs_sharing_any += 1

            # participation: any non-IP entity shared
            part_shared = any(
                len(host_entity_sets[host_a][t] & host_entity_sets[host_b][t]) > 0
                for t in _PARTICIPATION_TYPES
            )
            if part_shared:
                n_pairs_sharing_participation += 1

            ta_start = host_ts_min.get(host_a)
            ta_end = host_ts_max.get(host_a)
            tb_start = host_ts_min.get(host_b)
            tb_end = host_ts_max.get(host_b)
            if all(v is not None for v in [ta_start, ta_end, tb_start, tb_end]):
                overlap = _time_overlap(ta_start, ta_end, tb_start, tb_end)  # type: ignore[arg-type]
            else:
                overlap = float("nan")
            cross_row["time_overlap_s"] = (
                "" if (isinstance(overlap, float) and math.isnan(overlap))
                else round(overlap, 3)
            )
            if not (isinstance(overlap, float) and math.isnan(overlap)) and overlap > 0:
                n_pairs_time_overlap += 1

            cross_host_rows.append(cross_row)

    with cross_host_csv.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=D4_CROSS_HOST_COLUMNS)
        writer.writeheader()
        writer.writerows(cross_host_rows)

    # Dataset-level summary
    total_pairs = len(cross_host_rows)

    # Per-type global entity counts and host coverage
    type_summaries: dict[str, dict[str, Any]] = {}
    for type_name in _TYPE_NAMES:
        all_entities: set[str] = set()
        hosts_with_type = 0
        for host in hosts:
            es = host_entity_sets[host][type_name]
            if es:
                hosts_with_type += 1
            all_entities.update(es)
        sharing = n_pairs_sharing[type_name]
        type_summaries[type_name] = {
            "total_distinct": len(all_entities),
            "hosts_with_entities": hosts_with_type,
            "host_coverage": round(hosts_with_type / len(hosts), 6) if hosts else 0.0,
            "pairs_sharing": sharing,
            "sharing_ratio": round(sharing / total_pairs, 6) if total_pairs > 0 else 0.0,
        }

    D4_conn = type_summaries["ipv4"]["sharing_ratio"]
    D4_part = round(n_pairs_sharing_participation / total_pairs, 6) if total_pairs > 0 else 0.0

    summary: dict[str, Any] = {
        "host_count": len(hosts),
        "cross_host_pair_count": total_pairs,
        "pairs_with_time_overlap": n_pairs_time_overlap,
        "time_overlap_ratio": round(n_pairs_time_overlap / total_pairs, 6) if total_pairs > 0 else 0.0,
        # the two D4 channels, reported separately
        "D4_conn": D4_conn,
        "D4_part": D4_part,
        "pairs_sharing_participation": n_pairs_sharing_participation,
        # IP-channel detail (ip_sharing_ratio equals D4_conn)
        "total_distinct_ips": type_summaries["ipv4"]["total_distinct"],
        "hosts_with_ips": type_summaries["ipv4"]["hosts_with_entities"],
        "ip_coverage": type_summaries["ipv4"]["host_coverage"],
        "pairs_sharing_ip": type_summaries["ipv4"]["pairs_sharing"],
        "ip_sharing_ratio": type_summaries["ipv4"]["sharing_ratio"],
        # union over all entity types
        "pairs_sharing_any_entity": n_pairs_sharing_any,
        "entity_sharing_ratio": round(n_pairs_sharing_any / total_pairs, 6) if total_pairs > 0 else 0.0,
        # per-type breakdown
        "entity_types": type_summaries,
        "outputs": {
            "d4_per_host_csv": str(per_host_csv),
            "d4_cross_host_csv": str(cross_host_csv),
            "d4_summary_json": str(summary_json),
        },
    }
    summary_json.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return summary


def main() -> None:
    p = argparse.ArgumentParser(
        description="Stage 3: cross-component structure through shared identifiers",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    p.add_argument("--normalized-csv", required=True, help="Stage 1 output")
    p.add_argument("--output-dir", required=True, help="where the Stage 3 files are written")
    args = p.parse_args()

    normalized_csv = Path(args.normalized_csv)
    if not normalized_csv.exists():
        raise SystemExit(f"normalized CSV not found: {normalized_csv}")
    output_dir = Path(args.output_dir)

    print("Stage 3: cross-component structure")
    print(f"  input:      {normalized_csv}")
    print(f"  output_dir: {output_dir}")
    started = time.perf_counter()
    summary = measure_entities(normalized_csv=normalized_csv, output_dir=output_dir)
    print(f"  done in {time.perf_counter() - started:.1f}s")
    print(f"  hosts:                   {summary['host_count']}")
    print(f"  host pairs:              {summary['cross_host_pair_count']}")
    print(f"  pairs with time overlap: {summary['pairs_with_time_overlap']} "
          f"({summary['time_overlap_ratio']:.1%})")
    print()
    for type_name, stats in summary["entity_types"].items():
        print(f"    {type_name:<14} distinct={stats['total_distinct']:>8,}  "
              f"hosts={stats['hosts_with_entities']}/{summary['host_count']}  "
              f"pairs_sharing={stats['pairs_sharing']:>6}  "
              f"ratio={stats['sharing_ratio']:.4f}")
    print()
    conn, part = summary["D4_conn"], summary["D4_part"]
    print(f"  D4_conn (address sharing):       {conn if conn is None else f'{conn:.4f}'}")
    print(f"  D4_part (participation sharing): {part if part is None else f'{part:.4f}'}")


if __name__ == "__main__":
    main()
