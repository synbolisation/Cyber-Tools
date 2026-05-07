# log_ingestor

A modular, CLI-driven log parser and rule-based detector built as the ingestion stage of a SIEM pipeline.

Started life as `ex4.py` — a script that read a file and grepped for "Failed".
Now: pluggable parsers, a normalized event model, declarative YAML detection rules,
a stateful detection engine with sliding-window thresholds, and JSONL output for
downstream tooling.

## What's new vs. the original

| Original (`ex4.py`)                 | Now                                                      |
| ----------------------------------- | -------------------------------------------------------- |
| Hardcoded `test.log`                | CLI accepts any path or stdin (`-`)                      |
| Substring search for `"Failed"`     | Declarative YAML rules with thresholds & grouping        |
| No structured output                | Normalized `Event` dataclass; JSONL events & alerts      |
| Plain text format only              | Syslog-style + JSON-lines + auto-detect                  |
| No tests                            | 13 pytest cases covering parsers and engine              |
| One file                            | Modular package (`parsers/`, `detectors/`, `cli.py` …)   |

## Install

```bash
pip install -r requirements.txt
```

## Usage

```bash
# Parse a log file into normalized JSONL events
python -m log_ingestor parse samples/auth.log -o events.jsonl

# Parse stdin
cat /var/log/auth.log | python -m log_ingestor parse -

# Run detection rules and print alerts
python -m log_ingestor analyze samples/auth.log

# Same, quietly, persisting alerts to JSONL for an external SIEM
python -m log_ingestor analyze samples/auth.log -q --alerts-output alerts.jsonl

# List loaded rules
python -m log_ingestor rules

# Use a custom rules file
python -m log_ingestor analyze server.log -r my_rules.yaml
```

## Writing detection rules

Rules live in YAML. Example:

```yaml
- id: brute_force_login
  name: "Brute-force login"
  severity: HIGH
  description: "5+ failed logins from the same IP within 5 minutes."
  match:
    event_type: failed_login
  threshold:
    count: 5
    window_seconds: 300
    group_by: source_ip

- id: critical_event
  name: "Critical-severity log event"
  severity: HIGH
  match:
    severity: CRITICAL
```

`match` supports:
- exact field match: `username: root`
- list-of-allowed-values: `severity: [ERROR, CRITICAL]`
- substring search: `message_contains: ["unauthorized", "denied"]`

`threshold` (optional) makes the rule fire only when `count` matching events
occur within `window_seconds`, grouped by one or more fields (`source_ip`,
`username`, or both). Once a group fires, it's debounced until the window
empties below the threshold.

## Architecture

```
log_ingestor/
├── event.py              # Normalized Event dataclass — the shared contract
├── parsers/
│   ├── base.py           # BaseParser interface (parse_line, parse_stream)
│   ├── syslog.py         # Regex-based syslog-style parser
│   ├── json_parser.py    # JSON-lines parser with field aliasing
│   └── auto.py           # Sniffs format from first line
├── detectors/
│   ├── rules.py          # YAML rule loader (Rule, RuleSet, Threshold)
│   └── engine.py         # Stateful detector with sliding windows
├── alerter.py            # Pretty terminal output via `rich`
├── storage.py            # JSONL writer
└── cli.py                # argparse entry point
```

Adding a new parser: subclass `BaseParser`, implement `parse_line`, register in
`parsers/__init__.py::ALL_PARSERS`.

## Tests

```bash
python -m pytest tests/ -q
```

## Roadmap ideas

- `tail` subcommand for live monitoring with `watchdog`
- SQLite event store for retrospective queries
- Severity-based exit codes for cron/CI integration
- Sigma-rule import
- IP enrichment via GeoIP / threat intel feeds
