"""Normalized schema and the shared line-level parsing helpers for Stage 1.

This module defines the 13-column normalized schema that Stage 1 writes
(``CSV_COLUMNS``) together with the format-agnostic helpers it uses:
timestamp recognition for the common log formats (``parse_timestamp``) and the
file filters applied when walking a raw dataset tree (``is_log_text_candidate``,
``is_probably_text_file``). Nothing here is tied to a particular dataset
layout; the Stage 1 config in src/normalize.py supplies file discovery, host
derivation and ground truth, and uses these helpers for the parts that are the
same for every corpus.

Usage:
  from schema import CSV_COLUMNS, parse_timestamp
"""
from __future__ import annotations

import re
from datetime import UTC, datetime
from pathlib import Path


AUDIT_TS_RE = re.compile(r"msg=audit\((?P<epoch>\d{10}(?:\.\d+)?):\d+\)")
ISO_TS_RE = re.compile(
    r"^(?P<raw>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)"
)
JSON_TS_RE = re.compile(r'"@timestamp"\s*:\s*"(?P<raw>[^"]+)"')
JSON_GENERIC_TS_RE = re.compile(r'"timestamp"\s*:\s*"(?P<raw>[^"]+)"')
SYSLOG_TS_RE = re.compile(
    r"^(?P<mon>Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+"
    r"(?P<day>\d{1,2})\s+(?P<hms>\d{2}:\d{2}:\d{2})\b"
)
APACHE_TS_RE = re.compile(
    r"\[(?P<day>\d{2})/(?P<mon>[A-Za-z]{3})/(?P<year>\d{4}):"
    r"(?P<hms>\d{2}:\d{2}:\d{2})\s+(?P<offset>[+-]\d{4})\]"
)
# Apache error log: [Thu Jan 20 13:11:29.233000 2022]
APACHE_ERROR_TS_RE = re.compile(
    r"\[(?:\w{3})\s+(?P<mon>[A-Za-z]{3})\s+(?P<day>\d{1,2})\s+"
    r"(?P<hms>\d{2}:\d{2}:\d{2})(?:\.\d+)?\s+(?P<year>\d{4})\]"
)
MONTHS = {
    "Jan": 1,
    "Feb": 2,
    "Mar": 3,
    "Apr": 4,
    "May": 5,
    "Jun": 6,
    "Jul": 7,
    "Aug": 8,
    "Sep": 9,
    "Oct": 10,
    "Nov": 11,
    "Dec": 12,
}

# The normalized schema. Stage 2 and later read these columns by name, so the
# order and the spelling are fixed.
CSV_COLUMNS = [
    "dataset",
    "host",
    "source_file",
    "line_no",
    "raw_message",
    "timestamp_raw",
    "timestamp_parsed",
    "timestamp_parse_success",
    "within_simulation_window",
    "is_attack",
    "label_status",
    "labels",
    "rules",
]

# Extensions that never hold log text, so a raw tree walk can skip them
# without opening the file.
BLOCKED_BINARY_EXTENSIONS = {
    ".xlsx",
    ".xls",
    ".doc",
    ".docx",
    ".pdf",
    ".zip",
    ".gz",
    ".7z",
    ".tar",
    ".journal",
    ".pcap",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".db",
    ".sqlite",
}


# ---------------------------------------------------------------------------
# Timestamps
# ---------------------------------------------------------------------------
def parse_iso_datetime(raw_value: str) -> datetime:
    """Parse an ISO 8601 value into an aware UTC datetime.

    A trailing ``Z`` is accepted, and a value without a zone is read as UTC.
    """
    value = raw_value.strip()
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


def _timestamp_is_plausible(
    ts: datetime, window: tuple[datetime, datetime] | None
) -> bool:
    """Whether a parsed timestamp falls within a year of the collection window.

    The tolerance of one calendar year on each side catches lines whose
    timestamp was mined out of an unrelated numeric field. Without a window
    every timestamp is plausible.
    """
    if window is None:
        return True
    start, end = window
    lower = datetime(start.year - 1, 1, 1, tzinfo=UTC)
    upper = datetime(end.year + 1, 12, 31, 23, 59, 59, tzinfo=UTC)
    return lower <= ts <= upper


def _parse_syslog_timestamp(
    raw_message: str, year: int | None
) -> tuple[str, str, bool, datetime | None]:
    """Parse a syslog ``Mon DD HH:MM:SS`` prefix using an externally supplied year.

    The syslog prefix carries no year, so the caller has to supply one; with
    no year the format is not attempted.
    """
    if year is None:
        return "", "", False, None
    match = SYSLOG_TS_RE.search(raw_message)
    if not match:
        return "", "", False, None
    month_text = match.group("mon")
    month = MONTHS.get(month_text)
    if month is None:
        return "", "", False, None
    day = int(match.group("day"))
    hms = match.group("hms")
    inferred = f"{year:04d}-{month:02d}-{day:02d}T{hms}+00:00"
    try:
        dt = parse_iso_datetime(inferred)
    except ValueError:
        return "", "", False, None
    return match.group(0), dt.isoformat(), True, dt


def _parse_apache_timestamp(raw_message: str) -> tuple[str, str, bool, datetime | None]:
    """Parse the Apache combined-log bracket ``[DD/Mon/YYYY:HH:MM:SS +ZZZZ]``."""
    match = APACHE_TS_RE.search(raw_message)
    if not match:
        return "", "", False, None
    day = int(match.group("day"))
    month_text = match.group("mon")
    month = MONTHS.get(month_text)
    if month is None:
        return "", "", False, None
    year = int(match.group("year"))
    hms = match.group("hms")
    offset = match.group("offset")
    tz = f"{offset[:3]}:{offset[3:]}"
    raw = f"{year:04d}-{month:02d}-{day:02d}T{hms}{tz}"
    try:
        dt = parse_iso_datetime(raw)
    except ValueError:
        return "", "", False, None
    return raw, dt.isoformat(), True, dt


def _parse_apache_error_timestamp(
    raw_message: str,
) -> tuple[str, str, bool, datetime | None]:
    """Parse the Apache error-log bracket ``[Day Mon DD HH:MM:SS(.ffffff) YYYY]``."""
    match = APACHE_ERROR_TS_RE.search(raw_message)
    if not match:
        return "", "", False, None
    month_text = match.group("mon")
    month = MONTHS.get(month_text)
    if month is None:
        return "", "", False, None
    day = int(match.group("day"))
    year = int(match.group("year"))
    hms = match.group("hms")
    raw = f"{year:04d}-{month:02d}-{day:02d}T{hms}+00:00"
    try:
        dt = parse_iso_datetime(raw)
    except ValueError:
        return "", "", False, None
    return match.group(0), dt.isoformat(), True, dt


def parse_timestamp(
    raw_message: str,
    window: tuple[datetime, datetime] | None = None,
    syslog_year: int | None = None,
) -> tuple[str, str, bool, datetime | None]:
    """Recognise the timestamp of one raw log line.

    The formats are tried in a fixed priority order, most specific first:
    audit epoch, ISO 8601 at the start of the line, JSON ``@timestamp``, JSON
    ``timestamp``, Apache combined, Apache error, syslog. Syslog is last and
    is attempted only when ``syslog_year`` is given, because the syslog prefix
    carries no year.

    ``window`` is an optional (start, end) collection window; a parsed value
    more than a calendar year outside it is reported as unparsed, with the raw
    text kept so the caller can see what was rejected.

    Returns (raw timestamp text, ISO 8601 UTC, parse success, datetime).
    """
    audit_match = AUDIT_TS_RE.search(raw_message)
    if audit_match:
        timestamp_raw = audit_match.group("epoch")
        try:
            ts = datetime.fromtimestamp(float(timestamp_raw), tz=UTC)
            if not _timestamp_is_plausible(ts, window):
                return timestamp_raw, "", False, None
            return timestamp_raw, ts.isoformat(), True, ts
        except ValueError:
            return timestamp_raw, "", False, None

    iso_match = ISO_TS_RE.search(raw_message)
    if iso_match:
        timestamp_raw = iso_match.group("raw")
        try:
            ts = parse_iso_datetime(timestamp_raw)
            if not _timestamp_is_plausible(ts, window):
                return timestamp_raw, "", False, None
            return timestamp_raw, ts.isoformat(), True, ts
        except ValueError:
            return timestamp_raw, "", False, None

    json_match = JSON_TS_RE.search(raw_message)
    if json_match:
        timestamp_raw = json_match.group("raw")
        try:
            ts = parse_iso_datetime(timestamp_raw)
            if not _timestamp_is_plausible(ts, window):
                return timestamp_raw, "", False, None
            return timestamp_raw, ts.isoformat(), True, ts
        except ValueError:
            return timestamp_raw, "", False, None

    generic_json_match = JSON_GENERIC_TS_RE.search(raw_message)
    if generic_json_match:
        timestamp_raw = generic_json_match.group("raw")
        try:
            ts = parse_iso_datetime(timestamp_raw)
            if not _timestamp_is_plausible(ts, window):
                return timestamp_raw, "", False, None
            return timestamp_raw, ts.isoformat(), True, ts
        except ValueError:
            return timestamp_raw, "", False, None

    apache_raw, apache_parsed, apache_ok, apache_dt = _parse_apache_timestamp(raw_message)
    if apache_ok and apache_dt is not None:
        if not _timestamp_is_plausible(apache_dt, window):
            return apache_raw, "", False, None
        return apache_raw, apache_parsed, apache_ok, apache_dt

    (
        apache_err_raw,
        apache_err_parsed,
        apache_err_ok,
        apache_err_dt,
    ) = _parse_apache_error_timestamp(raw_message)
    if apache_err_ok and apache_err_dt is not None:
        if not _timestamp_is_plausible(apache_err_dt, window):
            return apache_err_raw, "", False, None
        return apache_err_raw, apache_err_parsed, apache_err_ok, apache_err_dt

    syslog_raw, syslog_parsed, syslog_ok, syslog_dt = _parse_syslog_timestamp(
        raw_message, syslog_year
    )
    if syslog_ok and syslog_dt is not None:
        if not _timestamp_is_plausible(syslog_dt, window):
            return syslog_raw, "", False, None
        return syslog_raw, syslog_parsed, syslog_ok, syslog_dt

    return "", "", False, None


# ---------------------------------------------------------------------------
# Raw file selection
# ---------------------------------------------------------------------------
def is_probably_text_file(path: Path, sample_bytes: int = 4096) -> bool:
    """Whether a file looks like text: known binary suffix or a NUL byte rules it out."""
    if path.suffix.lower() in BLOCKED_BINARY_EXTENSIONS:
        return False
    try:
        with path.open("rb") as f:
            chunk = f.read(sample_bytes)
    except OSError:
        return False
    if not chunk:
        return True
    if b"\x00" in chunk:
        return False
    return True


def is_log_text_candidate(path: Path) -> bool:
    """Whether a file name is one of the common event-log names.

    Rotated files (``*.log.1``) count; files with no log-like name are left
    out so that metric dumps and configuration files do not enter the corpus.
    """
    name = path.name.lower()
    if name.endswith(".log"):
        return True
    if name == "eve.json":
        return True
    if ".log." in name:
        return True
    if name in {"syslog", "auth.log", "audit.log", "openvpn.log", "dnsmasq.log"}:
        return True
    return False
