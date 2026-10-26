#!/usr/bin/env python3
"""Aggregate sanitized OpenSSH auth logs without echoing input values."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import hmac
import ipaddress
import json
import os
from pathlib import Path
import re
import sys
from collections import Counter, defaultdict

MAX_INPUT_BYTES = 5 * 1024 * 1024
BUCKET_SECONDS = 5 * 60
MIN_SOURCE_EVENTS = 5

ISO_PREFIX = re.compile(
    r"^(?P<stamp>\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d"
    r"(?:\.\d+)?(?:Z|[+-]\d\d:?\d\d))\s+(?P<message>.*)$"
)
SYSLOG_PREFIX = re.compile(
    r"^(?P<stamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d\d:\d\d:\d\d)\s+(?P<message>.*)$"
)
DAEMON_PID = re.compile(r"\bsshd\[(\d+)\]:\s*(.*)$", re.IGNORECASE)
AUTH_SOURCE = re.compile(
    r"\b(?:Accepted|Failed)\s+\S+\s+for\s+(?:invalid user\s+)?\S+\s+from\s+(\S+)\s+port\s+\d+",
    re.IGNORECASE,
)
GENERIC_SOURCE = re.compile(
    r"\b(?:from|source)\s+(\[?[0-9A-Fa-f:.%]+\]?)(?=\s|[:,)]|$)",
    re.IGNORECASE,
)
EVENT_PATTERNS = {
    "accepted": re.compile(r"\bAccepted\s+publickey\b", re.IGNORECASE),
    "failed_auth": re.compile(
        r"\b(?:Failed\s+(?:publickey|password|keyboard-interactive|none)|"
        r"authentication failure|maximum authentication attempts exceeded)\b",
        re.IGNORECASE,
    ),
    "preauth_drops": re.compile(r"\[(?:preauth|pre-auth)\]", re.IGNORECASE),
    "maxstartups_events": re.compile(r"\bMaxStartups\b", re.IGNORECASE),
    "persource_penalty_events": re.compile(r"\bPerSourcePenalties\b", re.IGNORECASE),
    "disconnects": re.compile(
        r"\b(?:Disconnected from|Connection closed by|Received disconnect)\b",
        re.IGNORECASE,
    ),
    "timeout_events": re.compile(
        r"\b(?:timed? out|timeout|Timeout, client not responding|keepalive timeout)\b",
        re.IGNORECASE,
    ),
    "fail2ban_events": re.compile(
        r"\bfail2ban\b.*\b(?:ban|unban|banned|unbanned)\b|"
        r"\b(?:ban|unban)\b.*\bfail2ban\b",
        re.IGNORECASE,
    ),
}
SESSION_OPEN = re.compile(r"\bsession opened for user\b", re.IGNORECASE)
SESSION_CLOSE = re.compile(r"\bsession closed for user\b", re.IGNORECASE)


def parse_timezone(value: str | None) -> dt.timezone | None:
    if value is None:
        return None
    if value.upper() in {"UTC", "Z"}:
        return dt.timezone.utc
    match = re.fullmatch(r"([+-])(\d\d):?(\d\d)", value)
    if not match:
        raise ValueError
    hours, minutes = int(match.group(2)), int(match.group(3))
    if hours > 23 or minutes > 59:
        raise ValueError
    offset = dt.timedelta(hours=hours, minutes=minutes)
    if match.group(1) == "-":
        offset = -offset
    return dt.timezone(offset)


def line_timestamp(
    line: str, year: int | None, syslog_timezone: dt.timezone | None
) -> tuple[dt.datetime | None, str | None, str]:
    iso = ISO_PREFIX.match(line)
    if iso:
        stamp = iso.group("stamp")
        if re.search(r"[+-]\d{4}$", stamp):
            stamp = stamp[:-5] + stamp[-5:-2] + ":" + stamp[-2:]
        if stamp.endswith("Z"):
            stamp = stamp[:-1] + "+00:00"
        try:
            parsed = dt.datetime.fromisoformat(stamp)
        except ValueError:
            return None, None, line
        return parsed.astimezone(dt.timezone.utc), parsed.strftime("%z"), iso.group("message")

    syslog = SYSLOG_PREFIX.match(line)
    if syslog:
        if year is None or syslog_timezone is None:
            return None, None, syslog.group("message")
        try:
            parsed = dt.datetime.strptime(
                f"{year} {syslog.group('stamp')}", "%Y %b %d %H:%M:%S"
            ).replace(tzinfo=syslog_timezone)
        except ValueError:
            return None, None, syslog.group("message")
        return parsed.astimezone(dt.timezone.utc), parsed.strftime("%z"), syslog.group("message")
    return None, None, line


def source_address(message: str) -> str | None:
    match = AUTH_SOURCE.search(message) or GENERIC_SOURCE.search(message)
    if not match:
        return None
    candidate = match.group(1).strip("[]")
    if "%" in candidate:
        candidate = candidate.split("%", 1)[0]
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return None


def read_input(path: str | None, use_stdin: bool) -> bytes:
    try:
        if use_stdin:
            stream = sys.stdin.buffer
            data = stream.read(MAX_INPUT_BYTES + 1)
        else:
            assert path is not None
            with Path(path).open("rb") as stream:
                data = stream.read(MAX_INPUT_BYTES + 1)
    except (OSError, ValueError):
        raise RuntimeError("input could not be read") from None
    if len(data) > MAX_INPUT_BYTES:
        raise RuntimeError("input exceeds the 5 MiB limit")
    try:
        data.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise RuntimeError("input is not valid UTF-8") from None
    return data


def build_report(
    raw: bytes,
    year: int | None,
    syslog_timezone: dt.timezone | None,
    include_sources: bool,
) -> dict[str, object]:
    text = raw.decode("utf-8", errors="strict")
    totals: Counter[str] = Counter()
    buckets: dict[int, Counter[str]] = defaultdict(Counter)
    source_totals: dict[str, Counter[str]] = defaultdict(Counter)
    session_open_by_pid: Counter[str] = Counter()
    session_close_by_pid: Counter[str] = Counter()
    timestamps: list[dt.datetime] = []
    zones: set[str] = set()
    untimestamped = 0
    unknown = 0

    for raw_line in text.splitlines():
        if not raw_line:
            continue
        stamp, zone, rest = line_timestamp(raw_line, year, syslog_timezone)
        daemon = DAEMON_PID.search(rest)
        message = daemon.group(2) if daemon else rest
        if stamp is None:
            untimestamped += 1
        else:
            timestamps.append(stamp)
            assert zone is not None
            zones.add(zone)

        found = [name for name, pattern in EVENT_PATTERNS.items() if pattern.search(message)]
        if SESSION_OPEN.search(message):
            found.append("session_open_events")
            if daemon:
                session_open_by_pid[daemon.group(1)] += 1
        if SESSION_CLOSE.search(message):
            found.append("session_close_events")
            if daemon:
                session_close_by_pid[daemon.group(1)] += 1

        if not found or stamp is None:
            unknown += 1
        if stamp is None:
            continue
        for category in found:
            totals[category] += 1
            bucket = int(stamp.timestamp()) // BUCKET_SECONDS * BUCKET_SECONDS
            buckets[bucket][category] += 1
            address = source_address(message)
            if address is not None:
                source_totals[address][category] += 1

    mixed_timezone = len(zones) > 1
    if mixed_timezone:
        # A mixed-offset sample has no reliable common wall-clock interpretation.
        # Keep line totals for transparency but withhold timeline/bucket claims.
        buckets.clear()
        timestamps.clear()
    opens = sum(session_open_by_pid.values())
    matched_closes = sum(
        min(count, session_close_by_pid.get(pid, 0))
        for pid, count in session_open_by_pid.items()
    )
    observed_sessions = max(0, opens - matched_closes) if not mixed_timezone else 0

    report: dict[str, object] = {
        "schema_version": 1,
        "input_limit_bytes": MAX_INPUT_BYTES,
        "attribution": "none; counts describe only the supplied log sample",
        "observed_window_utc": {
            "start": min(timestamps).isoformat().replace("+00:00", "Z") if timestamps else None,
            "end": max(timestamps).isoformat().replace("+00:00", "Z") if timestamps else None,
        },
        "counts": {
            "accepted_publickey": totals["accepted"],
            "failed_authentication": totals["failed_auth"],
            "preauth_drops": totals["preauth_drops"],
            "maxstartups_events": totals["maxstartups_events"],
            "persource_penalty_events": totals["persource_penalty_events"],
            "disconnects": totals["disconnects"],
            "timeout_events": totals["timeout_events"],
            "fail2ban_events": totals["fail2ban_events"],
            "session_open_events": totals["session_open_events"],
            "session_close_events": totals["session_close_events"],
            "successful_ongoing_sessions_observed": observed_sessions,
            "unknown_lines": unknown,
        },
        "buckets_5m_utc": [
            {
                "start": dt.datetime.fromtimestamp(epoch, dt.timezone.utc)
                .isoformat()
                .replace("+00:00", "Z"),
                "counts": dict(sorted(counts.items())),
            }
            for epoch, counts in sorted(buckets.items())
        ],
        "warnings": [],
        "interpretation": [
            "Counts are matching log-line counts; duplicate lines are not deduplicated.",
            "Accepted publickey is authentication evidence, not proof that a session remained open.",
            "Ongoing sessions count unmatched explicit session-open/close records by sshd PID only; incomplete log windows can overcount.",
            "MaxStartups and PerSourcePenalties are counted only when their names appear in a log line.",
            "fail2ban events are counted only when a line names fail2ban and a ban or unban action.",
            "No rate limiting is confirmed by event counts alone; firewall/provider limits require their own logs.",
            "OpenSSH ControlMaster applies to OpenSSH clients; embedded russh session reuse is separate.",
        ],
    }
    warnings: list[str] = report["warnings"]  # type: ignore[assignment]
    if untimestamped:
        warnings.append(f"{untimestamped} line(s) lacked a usable timestamp; excluded from event counts.")
    if unknown:
        warnings.append(f"{unknown} line(s) were unclassified or lacked a usable timestamp.")
    if mixed_timezone:
        warnings.append("Mixed timestamp offsets found; the observed window and time buckets are withheld.")
    if year is None or syslog_timezone is None:
        if any(SYSLOG_PREFIX.match(line) for line in text.splitlines()):
            warnings.append("Syslog timestamps require both --year and --timezone; affected lines are unknown.")

    if include_sources:
        salt = os.urandom(32)
        grouped = []
        for address, counts in source_totals.items():
            event_count = sum(counts.values())
            if event_count < MIN_SOURCE_EVENTS:
                continue
            token = hmac.new(salt, address.encode("ascii"), hashlib.sha256).hexdigest()[:12]
            grouped.append({"source": f"src-{token}", "event_count": event_count})
        report["source_pseudonyms"] = sorted(grouped, key=lambda item: item["source"])
        if len(source_totals) and not grouped:
            warnings.append("Source pseudonyms omitted because no source reached the 5-event threshold.")
    return report


def make_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Aggregate timestamped OpenSSH auth log lines into a redacted report.",
        epilog="Choose exactly one input source: --input PATH or --stdin.",
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--input", metavar="PATH", help="read an existing local log file (max 5 MiB)")
    source.add_argument("--stdin", action="store_true", help="read log bytes from standard input")
    parser.add_argument("--format", choices=("json", "text"), default="text")
    parser.add_argument("--year", type=int, help="year for traditional syslog timestamps")
    parser.add_argument("--timezone", help="fixed offset for syslog, such as UTC or +03:00")
    parser.add_argument(
        "--include-source-pseudonyms",
        action="store_true",
        help="include random per-run source pseudonyms only for sources with at least 5 events",
    )
    return parser


def render_text(report: dict[str, object]) -> str:
    counts = report["counts"]
    assert isinstance(counts, dict)
    window = report["observed_window_utc"]
    assert isinstance(window, dict)
    lines = [
        "SSH authentication and reconnect log report",
        f"Observed UTC window: {window['start'] or 'unavailable'} to {window['end'] or 'unavailable'}",
    ]
    lines.extend(f"{name}: {value}" for name, value in counts.items())
    for warning in report["warnings"]:  # type: ignore[union-attr]
        lines.append(f"Warning: {warning}")
    lines.append("No rate limiting is confirmed by event counts alone.")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = make_parser()
    args = parser.parse_args(argv)
    if (args.year is None) != (args.timezone is None):
        print("error: --year and --timezone must be provided together", file=sys.stderr)
        return 2
    try:
        if args.year is not None and not 1 <= args.year <= 9999:
            raise ValueError
        timezone = parse_timezone(args.timezone)
    except ValueError:
        print("error: invalid year or timezone option", file=sys.stderr)
        return 2
    try:
        raw = read_input(args.input, args.stdin)
        report = build_report(raw, args.year, timezone, args.include_source_pseudonyms)
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except Exception:
        # Never include parser, filesystem, or input-derived exception values.
        print("error: report generation failed", file=sys.stderr)
        return 2
    if args.format == "json":
        print(json.dumps(report, sort_keys=True, ensure_ascii=True))
    else:
        print(render_text(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
