#!/usr/bin/env python3
"""Measure DNS encoded-label candidates and same-process burst maxima in Wazuh JSONL archives."""

from __future__ import annotations

import argparse
import collections
import datetime as dt
import json
import re
from pathlib import Path
from typing import Any, Iterable

ENCODED_LABEL = re.compile(
    r"(?i)(?:^|\.)(?:[0-9a-f]{24,63}|[a-z2-7]{40,63})(?:\.|$)"
)


def parse_system_time(value: str) -> dt.datetime:
    value = value.rstrip("Z")
    whole, _, fraction = value.partition(".")
    normalized = f"{whole}.{(fraction + '000000')[:6]}"
    return dt.datetime.fromisoformat(normalized)


def analyze(records: Iterable[dict[str, Any]], window_seconds: int = 15) -> dict[str, Any]:
    queries: list[str] = []
    candidates: list[str] = []
    by_process: dict[str, list[dt.datetime]] = collections.defaultdict(list)

    for record in records:
        win = record.get("data", {}).get("win", {})
        system = win.get("system", {})
        eventdata = win.get("eventdata", {})
        if system.get("channel") != "Microsoft-Windows-DNS-Client/Operational":
            continue
        if str(system.get("eventID")) != "3006":
            continue

        query = str(eventdata.get("queryName", ""))
        queries.append(query)
        if not ENCODED_LABEL.search(query):
            continue

        candidates.append(query)
        process_id = str(system.get("processID", ""))
        by_process[process_id].append(parse_system_time(str(system["systemTime"])))

    process_bursts = []
    for process_id, timestamps in by_process.items():
        ordered = sorted(timestamps)
        maximum = 0
        right = 0
        for left, start in enumerate(ordered):
            if right < left:
                right = left
            while right < len(ordered) and (ordered[right] - start).total_seconds() <= window_seconds:
                right += 1
            maximum = max(maximum, right - left)
        process_bursts.append(
            {"process_id": process_id, "candidate_events": len(ordered), "max_in_window": maximum}
        )

    process_bursts.sort(key=lambda item: (item["max_in_window"], item["candidate_events"]), reverse=True)
    return {
        "dns_event_count": len(queries),
        "unique_query_count": len(set(queries)),
        "candidate_event_count": len(candidates),
        "unique_candidate_count": len(set(candidates)),
        "window_seconds": window_seconds,
        "process_bursts": process_bursts,
    }


def read_jsonl(path: Path) -> Iterable[dict[str, Any]]:
    with path.open(encoding="utf-8", errors="replace") as stream:
        for line_number, line in enumerate(stream, 1):
            try:
                yield json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid JSON at {path}:{line_number}: {exc}") from exc


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("archive", type=Path, help="Wazuh archives.json or dated ossec-archive JSONL file")
    parser.add_argument("--window", type=int, default=15, help="sliding-window size in seconds")
    args = parser.parse_args()
    print(json.dumps(analyze(read_jsonl(args.archive), args.window), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
