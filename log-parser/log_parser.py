#!/usr/bin/env python3
"""
Security Log Parser
A tool to parse and analyze security logs from various formats.

Copyright (c) 2025 Kristen Brickner
Licensed under the MIT License. See LICENSE file for details.
"""

import re       # Regular expressions
import sys      # System-specific parameters and functions
import json     # JavaScript Object Notation encoder and decoder
import csv      # CSV encoder and decoder
import argparse # Argument Parser
import os       # Filesystem / path utilities
import logging  # Structured logging for warnings/errors
from dataclasses import dataclass  # Structured data containers
from typing import Any, Callable, Dict, Iterator, List, Optional, Sequence


logger = logging.getLogger(__name__)


@dataclass
class LogLine:
    """
    Represents a single line read from a log file.

    Attributes:
        number (int): Line number within the file (1-indexed)
        text (str): The decoded line content
        decoding_issue (bool): True if latin-1 fallback was used to decode
    """
    number: int
    text: str
    decoding_issue: bool = False


@dataclass
class ParsedEntry:
    """
    Represents a parsed syslog entry.

    Attributes mirror the syslog components exposed to downstream tooling.
    """
    timestamp: str
    hostname: str
    process: str
    pid: str
    message: str

    def to_dict(self) -> Dict[str, str]:
        """Convert to dict for serialization-friendly consumers."""
        return {
            'timestamp': self.timestamp,
            'hostname': self.hostname,
            'process': self.process,
            'pid': self.pid,
            'message': self.message,
        }


def read_file(filename: str) -> Iterator[LogLine]:
    """
    Stream a log file and yield its lines.

    Handles encoding issues by trying UTF-8 first, then falling back to latin-1
    
    Args:
        filename (str): Path to the log file
        
    Yields:
        LogLine: Metadata for each parsed line, including number, text,
                 and whether latin-1 fallback was required.
        
    Raises:
        FileNotFoundError: If the specified file doesn't exist
        PermissionError: If we don't have permission to read the file
        OSError: For other filesystem-related errors
    """
    fallback_used = False

    def decode_line(raw_line: bytes) -> tuple[str, bool]:
        nonlocal fallback_used
        try:
            return raw_line.decode('utf-8').strip(), False
        except UnicodeDecodeError:
            if not fallback_used:
                logger.warning("File contains non-UTF-8 characters, falling back to latin-1 encoding")
                fallback_used = True
            return raw_line.decode('latin-1').strip(), True

    with open(filename, 'rb') as file:
        for idx, raw_line in enumerate(file, start=1):
            text, used_fallback = decode_line(raw_line)
            yield LogLine(number=idx, text=text, decoding_issue=used_fallback)

def parse_syslog(line: str) -> Optional[ParsedEntry]:
    """
    Parse a single syslog-format line into structured components.
    
    Syslog format: <timestamp> <hostname> <process>[<pid>]: <message>
    Example: Oct 29 14:23:01 webserver sshd[12345]: Failed password for admin
    
    Args:
        line (str): A single log line in syslog format
        
    Returns:
        dict: Parsed components, or None if line doesn't match format
        {
            'timestamp': 'Oct 29 14:23:01',
            'hostname': 'webserver',
            'process': 'sshd',
            'pid': '12345',
            'message': 'Failed password for admin from...'
        }
    """
    # Regular expression pattern for syslog format
    # Breaking down the pattern:
    # (\w+\s+\d+\s+\d+:\d+:\d+) - timestamp like "Oct 29 14:23:01"
    # \s+ - one or more whitespace characters
    # (\S+) - hostname (non-whitespace characters)
    # \s+
    # (\w+) - process name (word characters)
    # \[(\d+)\] - PID in square brackets
    # :\s* - colon and optional whitespace
    # (.*) - message (everything else)
    
    pattern = r'(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+(\w+)\[(\d+)\]:\s*(.*)'
    
    match = re.match(pattern, line)
    
    if match:
        # If pattern matched, extract the groups
        return ParsedEntry(
            timestamp=match.group(1),
            hostname=match.group(2),
            process=match.group(3),
            pid=match.group(4),
            message=match.group(5)
        )
    # Line doesn't match syslog format
    return None

def export_text(entries: Sequence[ParsedEntry]) -> None:
    """
    Export parsed log entries in human-readable text format.

    This is the original console output format, now extracted
    as a function for consistency with JSON export.

    Args:
        entries (list): List of dictionaries, each representing a parsed log entry
    
    Returns:
        None (prints to stdout)
    """
    print(f"Total entries parsed: {len(entries)}\n")

    for idx, entry in enumerate(entries, start=1):
        print(f"Entry {idx}:")
        print(f"  Timestamp: {entry.timestamp}")
        print(f"  Hostname: {entry.hostname}")
        print(f"  Process: {entry.process} (PID: {entry.pid})")
        print(f"  Message: {entry.message}")
        print()
    
    print("-" * 60)
    print(f"Summary: {len(entries)} entries successfully parsed")

def export_json(entries: Sequence[ParsedEntry], output_file: Optional[str] = None) -> None:
    """
    Export parsed log entries to JSON format.

    JSON export is useful for:
    - Ingesting logs into other tools (SIEM, databases)
    - Programmatic analysis (jq, Python scripts)
    - Data pipelines and automation

    Args:
        entries (list): List of dictionaries, each representing a parsed log entry
        output_file (str): Output filename. or None to print stdout
    
    Returns:
        None (writes to file or stdout)
    
    Raises:
        IOError: If file cannot be written
    """
    serializable = [entry.to_dict() for entry in entries]

    if output_file:
        with open(output_file, 'w') as f:
            json.dump(serializable, f, indent=2, ensure_ascii=False)
        logger.info("Successfully exported %d entries to %s", len(entries), output_file)
    else:
        # Print to stdout
        print(json.dumps(serializable, indent=2, ensure_ascii=False))

def export_csv(entries: Sequence[ParsedEntry], output_file: Optional[str] = None) -> None:
    """
    Export parsed log entries to CSV format.

    CSV export is useful for:
    - Spreadsheet analysis (Excel, Google Sheets)
    - Database imports (SQLite, MySQL)
    - Quick command-line filtering (grep, awk, cut)
    - Reporting and visualization

    Args:
        entries (list): List of dictionaries, each representing a parsed log entry
        output_file (str): Output filename, or None to print stdout
    
    Returns:
        None (writes to file or stdout)
    
    Raises:
        IOError: If file cannot be written
    """
    # Define CSV column order
    fieldnames = ['timestamp', 'hostname', 'process', 'pid', 'message']

    if output_file:
        # Write to file
        with open(output_file, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(entry.to_dict() for entry in entries)
        logger.info("Successfully exported %d entries to %s", len(entries), output_file)
    else:
        # Write to stdout
        writer = csv.DictWriter(sys.stdout, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(entry.to_dict() for entry in entries)

def detect_anomalies(
    entries: Sequence[ParsedEntry],
    thresholds: Optional[Dict[str, int]] = None
) -> Dict[str, Any]:
    """
    Detect security anomalies in parsed entries using threshold-based rules.

    This function implements simple counting-based anomaly detection:
    - Counts occurrences of suspicious patterns
    - Compares counts against thresholds
    - Flags entries that exceed thresholds as anomalies

    Anomaly types detected:
    1. Failed Login Attempts - Indicates potential brute force attacks
    2. High Activity Hosts - Single host generating excessive logs
    3. Process Anomalies - Unusual or excessive process activity

    Args:
        entries (list): List of parsed log entry dictionaries
        thresholds (dict, optional): Custom threshold values. Defaults to:
            {
                'failed_logins': 5,     # Alert if >5 failed logins
                'host_activity': 20,    # Alert if host has >20 log entries
                'process_activity': 15  # Alert if process has >15 log entries
            }
    
    Returns :
        dict: Dictionary containing detected anomalies and summary:
        {
            'failed_logins': {
                'count': int,
                'threshold': int,
                'is_anomaly': bool,
                'entries': [...]  # Log entries matching this pattern
            },
            'high_activity_hosts': {
                'hostname': count,  # For each host exceeding threshold
                ...
            },
            'process_anomalies': {
                'process_name: count,  # For each process exceeding threshold
                ...
            },
            'summary': {
                'total_anomalies': int,
                'anomaly_types_found': [...]
            }
        }
    
    Algorithm:
        1. Initialize counters for each anomaly type
        2. Iterate through all log entries
        3. For each entry:
            - Check message for failed login keywords
            - Count entries per hostname
            - Count entries per process
        4. Compare all counts against thresholds
        5. Flag and record anomalies where count > threshold
        6. Return structured results
    
    Example:
        >>> entries = parse_log_file('auth.log')
        >>> anomalies = detect_anomalies(entries)
        >>> if anomalies['failed_logins']['is_anomaly']:
        ...     print(f"ALERT: {anomalies['failed_logins']['count']} failed logins detected!")
    """

    # Set default thresholds if none provided
    if thresholds is None:
        thresholds = {
            'failed_logins': 5,     # Alert if more than 5 failed login attempts
            'host_activity': 20,    # Alert if single host has more than 20 log entries
            'process_activity': 15  # Alert if single process has more than 15 log entries
        }
    # Initialize result structure
    anomalies = {
        'failed_logins': {
            'count': 0,
            'threshold': thresholds['failed_logins'],
            'is_anomaly': False,
            'entries': []
        },
        'high_activity_hosts': {},
        'process_anomalies': {},
        'summary': {
            'total_anomalies': 0,
            'anomaly_types_found': []
        }
    }

    # Initialize counters
    host_counts = {}      # hostname -> count
    process_counts = {}   # process -> count

    # DETECTION PHASE: Count occurrences
    for entry in entries:
        # Detection Rule 1: Failed Login Attempts
        # Look for keywords indicating failed authentication
        message_lower = entry.message.lower()
        if 'failed password' in message_lower or 'authentication failure' in message_lower:
            anomalies['failed_logins']['count'] += 1
            anomalies['failed_logins']['entries'].append(entry.to_dict())
        
        # Detection Rule 2: Host Activity
        # Count log entries per hostname
        hostname = entry.hostname
        host_counts[hostname] = host_counts.get(hostname, 0) + 1

        # Detection Rule 3: Process Activity
        # Count log entries per process
        process = entry.process
        process_counts[process] = process_counts.get(process, 0) + 1
    
    # EVALUATION PHASE: Compare counts to thresholds

    # Evaluate failed logins
    if anomalies['failed_logins']['count'] > thresholds['failed_logins']:
        anomalies['failed_logins']['is_anomaly'] = True
        anomalies['summary']['total_anomalies'] += 1
        anomalies['summary']['anomaly_types_found'].append('failed_logins')
    
    # Evaluate host activity
    for hostname, count in host_counts.items():
        if count > thresholds['host_activity']:
            anomalies['high_activity_hosts'][hostname] = {
                'count': count,
                'threshold': thresholds['host_activity'],
                'is_anomaly': True
            }
            # Only count this once in summary (not per host)
            if 'high_activity_hosts' not in anomalies['summary']['anomaly_types_found']:
                anomalies['summary']['total_anomalies'] += 1
                anomalies['summary']['anomaly_types_found'].append('high_activity_hosts')
    
    # Evaluate process activity
    for process, count in process_counts.items():
        if count > thresholds['process_activity']:
            anomalies['process_anomalies'][process] = {
                'count': count,
                'threshold': thresholds['process_activity'],
                'is_anomaly': True
            }
            # Only count this once in summary
            if 'process_anomalies' not in anomalies['summary']['anomaly_types_found']:
                anomalies['summary']['total_anomalies'] += 1
                anomalies['summary']['anomaly_types_found'].append('process_anomalies')
    
    return anomalies

def export_anomalies(
    anomalies: Dict[str, Any],
    formatter: Optional[Callable[[Dict[str, Any]], Optional[str]]] = None
) -> None:
    """
    Display detected anomalies in human-readable format.

    Args:
        anomalies (dict): Output from detect_anomalies()
        formatter (callable, optional): Custom formatter callable that
            accepts the anomalies dict and returns a string to print or
            writes output directly. Enables downstream integrations such
            as JSON serialization.
    
    Returns:
        None (prints to stdout)
    """
    if formatter:
        formatted_output = formatter(anomalies)
        if formatted_output:
            print(formatted_output)
        return

    print("=" * 60)
    print("ANOMALY DETECTION REPORT")
    print("=" * 60)
    print()

    # Summary
    total = anomalies['summary']['total_anomalies']
    if total == 0:
        print("[OK] No anomalies detected. All activity appears normal.")
        print()
        return
    
    print(f"[WARNING] {total} anomaly type(s) detected")
    print()

    # Failed Logins
    if anomalies['failed_logins']['is_anomaly']:
        count = anomalies['failed_logins']['count']
        threshold = anomalies['failed_logins']['threshold']
        print("[ALERT] FAILED LOGIN ATTEMPTS")
        print(f"   Count: {count} (threshold: {threshold})")
        print("   Risk: Possible brute force attack")
        print("   Action: Investigate source IPs, consider blocking")
        print()

        # Show first 3 examples
        print("   Sample entries:")
        for idx, entry in enumerate(anomalies['failed_logins']['entries'][:3], 1):
            preview = entry['message'][:60]
            print(f"     {idx}. [{entry['timestamp']}] {entry['hostname']}: {preview}...")
        if len(anomalies['failed_logins']['entries']) > 3:
            print(f"     ... and {len(anomalies['failed_logins']['entries']) - 3} more")
        print()
    
    # High Activity Hosts
    if anomalies['high_activity_hosts']:
        print("[ALERT] HIGH ACTIVITY HOSTS")
        print(f"   {len(anomalies['high_activity_hosts'])} host(s) exceeding activity threshold")
        print("   Risk: Compromised system or automated attack")
        print("   Action: Investigate these hosts for unusual behavior")
        print()
        for hostname, data in list(anomalies['high_activity_hosts'].items())[:5]:
            print(f"     - {hostname}: {data['count']} entries (threshold: {data['threshold']})")
        if len(anomalies['high_activity_hosts']) > 5:
            print(f"     ... and {len(anomalies['high_activity_hosts']) - 5} more")
        print()
    
    #  Process Anomalies
    if anomalies['process_anomalies']:
        print("[ALERT] PROCESS ANOMALIES")
        print(f"   {len(anomalies['process_anomalies'])} process(es) with unusual activity")
        print("   Risk: Malware, misconfigured service, or system issue")
        print("   Action: Verify processes are legitimate and expected")
        print()
        for process, data in list(anomalies['process_anomalies'].items())[:5]:
            print(f"     - {process}: {data['count']} entries (threshold: {data['threshold']})")
        if len(anomalies['process_anomalies']) > 5:
            print(f"     ... and {len(anomalies['process_anomalies']) - 5} more")
        print()
    
    print("=" * 60)
    print("END OF ANOMALY REPORT")
    print("=" * 60)

def validate_thresholds(threshold_strings: Optional[List[str]]) -> Optional[Dict[str, int]]:
    """
    Validate and parse threshold arguments from command line.

    Args:
        threshold_strings (list): List of strings like "failed_logins=10"
    
    Returns:
        dict: Validated threshold dictionary
    
    Raises: ValueError If threshold format is invalid
    """
    if not threshold_strings:
        return None
    
    valid_keys = ['failed_logins', 'host_activity', 'process_activity']
    thresholds = {}

    for threshold_str in threshold_strings:
        # Check format: must contain '='
        if '=' not in threshold_str:
            logger.error("Invalid threshold format '%s'", threshold_str)
            logger.error("Expected format: key=value (e.g., failed_logins=10)")
            sys.exit(1)
        
        # Split and validate
        parts = threshold_str.split('=')
        if len(parts) != 2:
            logger.error("Invalid threshold format '%s'", threshold_str)
            logger.error("Expected format: key=value (e.g., failed_logins=10)")
            sys.exit(1)
        
        key, value_str = parts

        # Validate key
        if key not in valid_keys:
            logger.error("Unknown threshold key '%s'", key)
            logger.error("Valid keys: %s", ', '.join(valid_keys))
            sys.exit(1)
        
        # Validate value is a positive integer
        try:
            value = int(value_str)
        except ValueError:
            logger.error("Threshold value '%s' is not a valid integer", value_str)
            sys.exit(1)
        
        if value <= 0:
            logger.error("Threshold value must be positive, got %d", value)
            sys.exit(1)
        
        thresholds[key] = value
    
    return thresholds

def validate_output_path(output_path: Optional[str]) -> None:
    """
    Validate that output path is writable.

    Args:
        output_path (str): Path to output file
    
    Returns:
        None
    
    Raises:
        SystemExit: If path is not writable
    """
    if not output_path:
        return # stdout is always valid
    
    # Check is directory exists
    directory = os.path.dirname(output_path)

    if directory and not os.path.exists(directory):
        logger.error("Output directory '%s' does not exist", directory)
        sys.exit(1)
    
    # Check if we can write to the location
    if directory:
        if not os.access(directory, os.W_OK):
            logger.error("No write permission for directory '%s'", directory)
            sys.exit(1)
    
    else:
        # No directory specified, writing to current directory
        if not os.access('.', os.W_OK):
            logger.error("No write permission in current directory")
            sys.exit(1)

def main() -> None:
    """
    Main function to orchestrate log parsing.

    Usage:
        python log_parser.py <logfile>
        python log_parser.py --format json <logfile>
        python log_parser.py --format csv <logfile>
        python log_parser.py --format json --output results.json <logfile>
        python log_parser.py --detect <logfile
        python log_parser.py --detect --thresholds failed_logins=10 <logfile>
    """
    # Set up command-line argument parser
    parser = argparse.ArgumentParser(
        description='Parse security logs and detect anomalies',
        epilog='Example: python log_parser.py --detect --format json --output sample.log')

    # Required positional argument: the log file
    parser.add_argument('logfile',
                        help='Path to log file to parse')
    
    # Optional: output format
    parser.add_argument('--format',
                        choices=['text', 'json', 'csv'],
                        default='text',
                        help='Output format (default: text)')

    # Optional: output file
    parser.add_argument('--output',
                        help='Output filename (default: stdout)')
    
    parser.add_argument('--failed-output',
                        help='Write unparsable line details to JSON (default: disabled)')
    
    # Optional: enable anomaly detection
    parser.add_argument('--detect',
                        action='store_true',
                        help='Enable anomaly detection')
    
    # Optional: custom thresholds
    parser.add_argument('--thresholds',
                        nargs='*',
                        help='Custom thresholds (e.g., failed_logins=10 host_activity=30)')
    
    # Parse the arguments
    args = parser.parse_args()

    # Validate output path if provided
    validate_output_path(args.output)
    validate_output_path(args.failed_output)

    # Parse all lines into a list of dictionaries
    entries: List[ParsedEntry] = []
    failed_lines = 0
    total_lines = 0
    parse_failures: List[Dict[str, Any]] = []

    try:
        for record in read_file(args.logfile):
            total_lines += 1
            if not record.text:  # Skip empty lines
                continue
            parsed = parse_syslog(record.text)
            if parsed:
                entries.append(parsed)
            else:
                failed_lines += 1
                reasons = ['regex_mismatch']
                if record.decoding_issue:
                    reasons.append('decoding_fallback')
                parse_failures.append({
                    'line_number': record.number,
                    'content': record.text,
                    'reasons': reasons
                })
    except FileNotFoundError:
        logger.error("File '%s' not found.", args.logfile)
        sys.exit(1)
    except PermissionError:
        logger.error("Permission denied reading '%s'.", args.logfile)
        sys.exit(1)
    except OSError as err:
        logger.error("Could not read file '%s': %s", args.logfile, err)
        sys.exit(1)

    # Warn if file is very large
    if total_lines > 100000:
        file_size_mb = os.path.getsize(args.logfile) / (1024 * 1024)
        logger.warning(
            "Large file detected (%d lines, %.1fMB). Processing may take longer and use more memory.",
            total_lines,
            file_size_mb,
        )

    # Check if we got any valid entries
    if not entries:
        logger.error("No valid log entries found in %s", args.logfile)
        logger.error("Parsed %d lines, %d failed to match syslog format", total_lines, failed_lines)
        logger.error("Expected format: <timestamp> <hostname> <process>[<pid>]: <message>")
        logger.error("Example: Nov 12 10:23:01 server sshd[1234]: Connection closed")
        sys.exit(1)
    
    # Optionally warn if many lines failed
    if failed_lines > 0:
        total_processed = len(entries) + failed_lines
        success_rate = len(entries) / total_processed * 100 if total_processed else 0
        if success_rate < 50:
            logger.warning("Only %.1f%% of lines parsed successfully", success_rate)
        if parse_failures:
            preview = parse_failures[0]
            snippet = preview['content'][:60]
            logger.info(
                "Example unparsable line %d: %s (reasons: %s)",
                preview['line_number'],
                snippet,
                ', '.join(preview['reasons']),
            )
    
    # If anomaly detection requested
    if args.detect:
        # Parse custom thresholds if provided
        custom_thresholds = validate_thresholds(args.thresholds)
    
        # Detect anomalies
        anomalies = detect_anomalies(entries, custom_thresholds)

        # Display anomaly report
        export_anomalies(anomalies)

        # If also exporting data, do that too
        if args.format != 'text' or args.output:
            print("\n" + "=" * 60)
            print("PARSED LOG DATA")
            print("=" * 60 + "\n")

    # Optionally export failed line details
    if args.failed_output:
        try:
            with open(args.failed_output, 'w') as failed_file:
                json.dump(parse_failures, failed_file, indent=2, ensure_ascii=False)
            logger.info("Wrote %d unparsable line(s) to %s", len(parse_failures), args.failed_output)
        except OSError as err:
            logger.error("Failed to write unparsable line report: %s", err)
            sys.exit(1)
    elif parse_failures:
        logger.info(
            "Failed to parse %d line(s). Use --failed-output to capture full details.",
            len(parse_failures),
        )

    # Output based on format
    try:
        if args.format == 'json':
            export_json(entries, args.output)
        elif args.format == 'csv':
            export_csv(entries, args.output)
        else:
            export_text(entries)
    except (OSError, TypeError, ValueError) as err:
        logger.error("Failed to export data: %s", err)
        sys.exit(1)

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    try:
        main()
    except KeyboardInterrupt:
        logger.error("Interrupted by user. Exiting cleanly..")
        sys.exit(130)  # Standard exit code for Ctrl+C
