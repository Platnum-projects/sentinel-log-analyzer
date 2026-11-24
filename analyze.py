#!/usr/bin/env python3
"""Analyze synthetic authentication events and emit explainable alerts."""
from __future__ import annotations
import argparse
import json
import sys
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

REQUIRED = {"timestamp", "event_type", "username", "source_ip"}
FAILURE_THRESHOLD = 5
SPRAY_WINDOW = timedelta(minutes=10)
FOLLOWUP_FAILURES = 3
FOLLOWUP_WINDOW = timedelta(minutes=30)
VALID_TYPES = {"login_success", "login_failure"}


def parse_timestamp(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamp must include a timezone")
    return parsed.astimezone(timezone.utc)


def load_events(path: Path) -> tuple[list[dict], int]:
    events = []
    errors = 0
    with path.open(encoding="utf-8") as stream:
        for line_number, line in enumerate(stream, start=1):
            if not line.strip():
                continue
            try:
                event = json.loads(line)
                missing = REQUIRED - event.keys()
                if missing:
                    raise ValueError(f"missing fields: {', '.join(sorted(missing))}")
                if event["event_type"] not in VALID_TYPES:
                    raise ValueError("unsupported event_type")
                event["_time"] = parse_timestamp(event["timestamp"])
                event["_id"] = f"line-{line_number}"
                events.append(event)
            except (json.JSONDecodeError, TypeError, ValueError) as exc:
                print(f"line {line_number}: {exc}", file=sys.stderr)
                errors += 1
    events.sort(key=lambda item: item["_time"])
    return events, errors


def detect(events: list[dict]) -> list[dict]:
    failures: dict[tuple[str, str], list[dict]] = defaultdict(list)
    successes: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for event in events:
        key = (event["username"], event["source_ip"])
        (successes if event["event_type"] == "login_success" else failures)[key].append(event)

    alerts = []
    for (username, source_ip), failed in failures.items():
        for end_index, end_event in enumerate(failed):
            window_start = end_event["_time"] - SPRAY_WINDOW
            recent = [e for e in failed[:end_index + 1] if e["_time"] >= window_start]
            if len(recent) == FAILURE_THRESHOLD:
                alerts.append(make_alert(
                    "AUTH-001", "high", "Repeated failed logins",
                    username, source_ip, recent,
                ))
                break

        for success in successes.get((username, source_ip), []):
            prior = [e for e in failed if timedelta(0) <= success["_time"] - e["_time"] <= FOLLOWUP_WINDOW]
            if len(prior) >= FOLLOWUP_FAILURES:
                evidence = prior + [success]
                alerts.append(make_alert(
                    "AUTH-002", "critical", "Successful login after repeated failures",
                    username, source_ip, evidence,
                ))
                break

    return sorted(alerts, key=lambda alert: (alert["first_seen"], alert["rule_id"]))


def make_alert(rule_id: str, severity: str, title: str, username: str,
               source_ip: str, evidence: list[dict]) -> dict:
    return {
        "rule_id": rule_id,
        "severity": severity,
        "title": title,
        "username": username,
        "source_ip": source_ip,
        "first_seen": min(e["_time"] for e in evidence).isoformat().replace("+00:00", "Z"),
        "last_seen": max(e["_time"] for e in evidence).isoformat().replace("+00:00", "Z"),
        "evidence_count": len(evidence),
        "evidence": [e["_id"] for e in evidence],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="newline-delimited JSON event file")
    parser.add_argument("--output", type=Path, help="write alerts to a JSON file")
    args = parser.parse_args()
    events, errors = load_events(args.input)
    alerts = detect(events)
    rendered = json.dumps(alerts, indent=2)
    if args.output:
        args.output.write_text(rendered + "\n", encoding="utf-8")
        print(f"Wrote {len(alerts)} alert(s) to {args.output}")
    else:
        print(rendered)
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
