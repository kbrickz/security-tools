# Security Log Parser – Design Document

## Purpose

Security Log Parser is a Python 3 CLI tool that ingests syslog-formatted files, normalizes each line, and exports structured data in text, JSON, or CSV. It focuses on defensive operations: validating inputs, surfacing parsing failures, and running a threshold-based anomaly detector that highlights failed logins, noisy hosts, or suspicious processes.

## Goals

1. **Reliable parsing** of standard BSD syslog lines with clear feedback when lines fail.
2. **Streaming performance** that can handle large log files without exhausting memory.
3. **Actionable detection** via configurable thresholds that map directly to common SOC triage questions.
4. **Professional UX** with argparse-based commands, logging, and optional failed-line reports.
5. **Extensibility** so new log formats or exporters can reuse the same architecture.

## Architecture Overview

The project uses a function-based architecture with lightweight data classes:

- `LogLine`: metadata for each raw line (line number, decoded text, whether latin‑1 fallback occurred).
- `ParsedEntry`: normalized syslog fields (timestamp, hostname, process, pid, message).
- Core workflow: stream file -> parse syslog -> detect anomalies (optional) -> export.

This separation keeps parsing logic reusable while presenting a clean CLI orchestrator (`main`).

### Core Functions

| Function                                 | Purpose                                                                               | Key Notes                                                                                         |
| ---------------------------------------- | ------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------- |
| `read_file(path)`                        | Streams byte lines, decodes UTF‑8 with latin‑1 fallback, yields `LogLine`.            | Uses `open(..., 'rb')` to handle arbitrary encodings; records fallback usage for observability.   |
| `parse_syslog(line)`                     | Regex-based syslog parser returning `ParsedEntry` or `None`.                          | Regex: `(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+(\w+)\[(\d+)\]:\s*(.*)`; easy to extend for variants. |
| `detect_anomalies(entries, thresholds)`  | Counts failed logins, host activity, process activity; returns structured summary.    | Thresholds are configurable via CLI (`--thresholds key=value`).                                   |
| `export_text/json/csv(entries, output)`  | Output modules for human-readable text, JSON, or CSV.                                 | JSON/CSV rely on dataclass `to_dict()`; CSV uses `csv.DictWriter`.                                |
| `export_anomalies(anomalies, formatter)` | Default ASCII report plus optional custom formatter hook (e.g., JSON).                | Keeps CLI accessible while supporting automation.                                                 |
| `validate_thresholds(args.thresholds)`   | Parses and validates custom threshold flags; exits on invalid input.                  | Prevents typos from silently changing alerting behavior.                                          |
| `validate_output_path(path)`             | Ensures output directories are writable before export.                                | Avoids partial runs failing midway.                                                               |
| `main()`                                 | Orchestrates CLI parsing, file reading, anomaly detection, exporting, error handling. | Uses `argparse` to drive behavior; logs warnings/errors via `logging`.                            |

## Handling Different Log Formats

### Syslog (current support)

- Regex parser extracts timestamp, hostname, process, PID, and message.
- Dataclasses allow future fields (e.g., severity) without changing the exporter interfaces.
- Unparsable lines are captured with reasons and can be exported via `--failed-output`.

### Future Formats (design-ready)

- **Apache/nginx**: Would add dedicated `parse_apache`/`parse_nginx` functions returning `ParsedEntry` derivatives. The streaming reader, anomaly detector, and exporters remain unchanged.
- **JSON logs**: Could accept `--format-input json` to load pre-structured logs; dataclasses would support different constructors.

Every new parser should follow the same contract: convert raw lines into `ParsedEntry` instances so the rest of the pipeline (exporters, anomaly detection) continues to work.

## User-Facing Commands

`log_parser.py` exposes these primary options:

- `logfile` (positional): Path to the log file to parse.
- `--format {text,json,csv}`: Choose output format (default `text`).
- `--output FILE`: Write structured output to a file instead of stdout.
- `--detect`: Enable anomaly detection, printing an ASCII report (or custom formatter output).
- `--thresholds key=value ...`: Override anomaly thresholds (e.g., `--thresholds failed_logins=3 host_activity=30`).
- `--failed-output FILE`: Write a JSON array of unparsable lines and reasons for deeper investigation.

Example workflows:

```bash
# Basic text output
python3 log_parser.py sample.log

# JSON export plus anomaly detection
python3 log_parser.py --format json --output parsed.json --detect sample.log

# Dump unparsable lines to a report for triage
python3 log_parser.py --failed-output failed_lines.json malformed.log
```

## Technologies & Libraries

- **Python 3.11**: Standard library only; no third-party dependencies required.
- **`argparse`**: Handles CLI parsing, built-in help text, and validation for `--format` choices.
- **`re`**: Regex module for syslog parsing; chosen over manual splitting for clarity.
- **`csv` / `json`**: Standard exporters; `csv.DictWriter` ensures RFC 4180 compliance, `json.dump`/`json.dumps` provide structured output.
- **`logging`**: Provides consistent warnings/errors without polluting stdout (important for piping JSON/CSV).
- **`dataclasses`**: `LogLine` and `ParsedEntry` keep data models explicit and easy to extend.

## Design Decisions

| Decision                                    | Impact                                                                                               |
| ------------------------------------------- | ---------------------------------------------------------------------------------------------------- |
| Streaming file reader with latin‑1 fallback | Prevents memory blowups and keeps partial results available even when logs contain mixed encodings.  |
| Dataclass-based parsed entries              | Encourages type safety, easier testing, and clearer exporter implementations.                        |
| ASCII-only anomaly report + formatter hook  | Works in headless terminals while letting teams inject JSON output without rewriting the core logic. |
| Threshold-based anomaly detection           | Provides actionable insights with minimal complexity and no external dependencies.                   |
| `--failed-output` reporting                 | Improves observability by capturing problematic lines for forensic review.                           |
| Logging over print for status               | Keeps stdout clean for structured output while recording warnings/errors in a standard format.       |

## Summary

Security Log Parser prioritizes transparency and extendability. By streaming files, normalizing entries via dataclasses, and exposing intuitive CLI options, the tool gives analysts immediate visibility into their logs without extra dependencies. Future parsers or exporters can plug into the same architecture, ensuring the project remains maintainable as new formats or detection rules are added.***
