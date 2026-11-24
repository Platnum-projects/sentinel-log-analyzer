# Sentinel Log Analyzer

A small, dependency-free Python SIEM exercise that normalizes authentication events, applies transparent detection rules, and writes an analyst-friendly incident report. The included events are entirely synthetic.

## What it demonstrates

- Parsing and validating newline-delimited JSON security events
- Detecting password-spray patterns and successful logins after repeated failures
- Grouping related events into explainable alerts with evidence and severity
- Producing JSON output that can be handed to a ticketing or SIEM workflow
- Keeping detection logic separate from event ingestion

## Quick start

Requires Python 3.10 or newer.

```bash
python analyze.py auth_events.jsonl --output alerts.json
```

To view alerts in the terminal, omit `--output`. Malformed lines are reported to standard error and skipped; the process returns a non-zero status if any input line could not be parsed.

## Included detections

| Rule | Trigger | Severity |
|---|---|---|
| `AUTH-001` | At least five failed logins for one account from one source within ten minutes | High |
| `AUTH-002` | A successful login from the same source within thirty minutes after at least three failures | Critical |

Thresholds and time windows are defined near the top of `analyze.py` so they can be reviewed and tuned. This is a learning project, not a production monitoring system.

## Input format

Each line is a JSON object with `timestamp` (ISO 8601 UTC), `event_type` (`login_success` or `login_failure`), `username`, `source_ip`, and optional `host`. The sample data uses the reserved documentation IP ranges.

## Example output

```json
{
  "rule_id": "AUTH-002",
  "severity": "critical",
  "title": "Successful login after repeated failures",
  "username": "admin",
  "source_ip": "203.0.113.44",
  "first_seen": "2025-03-10T09:01:00Z",
  "last_seen": "2025-03-10T09:06:00Z",
  "evidence_count": 4,
  "evidence": ["... event IDs ..."]
}
```

## Analyst workflow

1. Validate the source and time range of the input logs.
2. Review the alert evidence and confirm whether the activity is expected.
3. Enrich with identity, endpoint, and network context in an authorized environment.
4. Record the conclusion and any response actions in the incident ticket.

## Limitations and safe use

This offline demo uses fixed thresholds and synthetic data. It does not access a network, collect credentials, or block users. Real deployments need environment-specific baselines, clock-skew handling, data-retention controls, and documented response procedures.
