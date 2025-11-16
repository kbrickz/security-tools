#!/usr/bin/env python3
"""
Security Log Parser
A tool to parse and analyze security logs from various formats.

Author: Kristen Brickner
Date: November, 12 2025
Purpose: First security tool
"""

import re       # Regular expressions 
import sys      # System-specific parameters and functions
import json     # JavaScript Object Notation encoder and decoder
import csv      # CSV encoder and decoder
import argparse # Argument Parser


def read_file(filename):
    """
    Read a log file and return its contents as a list of lines.
    
    Args:
        filename (str): Path to the log file
        
    Returns:
        list: List of strings, each representing one line from the file
        
    Raises:
        FileNotFoundError: If the specified file doesn't exist
        PermissionError: If we don't have permission to read the file
    """
    try:
        with open(filename, 'r') as file:
            # readlines() returns a list where each element is a line
            # strip() removes trailing newlines and whitespace
            lines = [line.strip() for line in file.readlines()]
        return lines
    
    except FileNotFoundError:
        print(f"Error: File '{filename}' not found.")
        sys.exit(1)
    
    except PermissionError:
        print(f"Error: Permission denied reading '{filename}'.")
        sys.exit(1)


def parse_syslog(line):
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
        return {
            'timestamp': match.group(1),
            'hostname': match.group(2),
            'process': match.group(3),
            'pid': match.group(4),
            'message': match.group(5)
        }
    else:
        # Line doesn't match syslog format
        return None


def export_text(entries):
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
        print(f"  Timestamp: {entry['timestamp']}")
        print(f"  Hostname: {entry['hostname']}")
        print(f"  Process: {entry['process']} (PID: {entry['pid']})")
        print(f"  Message: {entry['message']}")
        print()
    
    print("-" * 60)
    print(f"Summary: {len(entries)} entries successfully parsed")

def export_json(entries, output_file=None):
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
    try:
        if output_file:
            # Write to file
            with open(output_file, 'w') as f:
                json.dump(entries, f, indent=2, ensure_ascii=False)
            print(f"Successfully exported {len(entries)} entries to {output_file}")
        else:
            # Print to stdout
            print(json.dumps(entries, indent=2, ensure_ascii=False))
    
    except IOError as e:
        print(f"Error writing JSON: {e}", file=sys.stderr)
        sys.exit(1)
    except TypeError as e:
        print(f"Error serializing to JSON: {e}", file=sys.stderr)
        sys.exit(1)

def export_csv(entries, output_file=None):
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

    try:
        if output_file:
            # Write to file
            with open(output_file, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(entries)
            print(f"Successfully exported {len(entries)} entries to {output_file}")
        else:
            # Write to stdout
            writer = csv.DictWriter(sys.stdout, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(entries)

    except IOError as e:
        print(f"Error writing CSV: {e}", file=sys.stderr)
        sys.exit(1)

def detect_anomalies(entries, thresholds=None):
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
        message_lower = entry['message'].lower()
        if 'failed password' in message_lower or 'authentication failure' in message_lower:
            anomalies['failed_logins']['count'] += 1
            anomalies['failed_logins']['entries'].append(entry)
        
        # Detection Rule 2: Host Activity
        # Count log entries per hostname
        hostname = entry['hostname']
        host_counts[hostname] = host_counts.get(hostname, 0) + 1

        # Detection Rule 3: Process Activity
        # Count log entries per process
        process = entry['process']
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

def export_anomalies(anomalies):
    """
    Display detected anomalies in human-readable format.

    Args:
        anomalies (dict): Output from detect_anomalies()
    
    Returns:
        None (prints to stdout)
    """
    print("=" * 60)
    print("ANOMALY DETECTION REPORT")
    print("=" * 60)
    print()

    # Summary
    total = anomalies['summary']['total_anomalies']
    if total == 0:
        print("✓ No anomalies detected. All activity appears normal.")
        print()
        return
    
    print(f"⚠️ {total} anomaly type(s) detected")
    print()

    # Failed Logins
    if anomalies['failed_logins']['is_anomaly']:
        count = anomalies['failed_logins']['count']
        threshold = anomalies['failed_logins']['threshold']
        print(f"🚨 FAILED LOGIN ATTEMPTS")
        print(f"   Count: {count} (threshold: {threshold})")
        print(f"   Risk: Possible brute force attack")
        print(f"   Action Investigate source IPs, consider blocking")
        print()

        # Show first 3 examples
        print("   Sample entries:")
        for idx, entry in enumerate(anomalies['failed_logins']['entries'][:3], 1):
            print(f"     {idx}. [{entry['timestamp']}] {entry['hostname']}: {entry['message'][:60]}...")
        if len(anomalies['failed_logins']['entries']) > 3:
            print(f"     ... and {len(anomalies['failed_logins']['entries']) - 3} more")
        print()
    
    # High Activity Hosts
    if anomalies['high_activity_hosts']:
        print(f"🚨 HIGH ACTIVITY HOSTS")
        print(f"   {len(anomalies['high_activity_hosts'])} host(s) exceeding activity threshold")
        print(f"   Risk: Compromised system or automated attack")
        print(f"   Action: Investigate these hosts for unusual behavior")
        print()
        for hostname, data in list(anomalies['high_activity_hosts'].items())[:5]:
            print(f"     • {hostname}: {data['count']} entries (threshold: {data['threshold']})")
        if len(anomalies['high_activity_hosts']) > 5:
            print(f"     ... and {len(anomalies['high_activity_hosts']) - 5} more")
        print()
    
    #  Process Anomalies
    if anomalies['process_anomalies']:
        print(f"🚨 PROCESS ANOMALIES")
        print(f"   {len(anomalies['process_anomalies'])} process(es) with unusual activity")
        print(f"   Risk: Malware, misconfigured service, or system issue")
        print(f"   Action: Verify processes are legitimate and expected")
        print()
        for process, data in list(anomalies['process_anomalies'].items())[:5]:
            print(f"     • {process}: {data['count']} entries (threshold: {data['threshold']})")
        if len(anomalies['process_anomalies']) > 5:
            print(f"     ... and {len(anomalies['process_anomalies']) - 5} more")
        print()
    
    print("=" * 60)
    print("END OF ANOMALY REPORT")
    print("=" * 60)

def main():
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

    # Read the log file
    lines = read_file(args.logfile)

    # Parse all lines into a list of dictionaries
    entries = []
    for line in lines:
        if not line: # Skip empty lines
            continue
        parsed = parse_syslog(line)
        if parsed:
            entries.append(parsed)
    
    # If anomaly detection requested
    if args.detect:
        # Parse custom thresholds if provided
        custom_thresholds = None
        if args.thresholds:
            custom_thresholds = {}
            for threshold_str in args.thresholds:
                key, value = threshold_str.split('=')
                custom_thresholds[key] = int(value)
    
        # Detect anomalies
        anomalies = detect_anomalies(entries, custom_thresholds)

        # Display anomaly report
        export_anomalies(anomalies)

        # If also exporting data, do that too
        if args.format != 'text' or args.output:
            print("\n" + "=" * 60)
            print("PARSED LOG DATA")
            print("=" * 60 + "\n")

    # Output based on format
    if args.format == 'json':
        export_json(entries, args.output)
    elif args.format == 'csv':
        export_csv(entries, args.output)
    else:
        export_text(entries)

if __name__ == "__main__":
    # This ensures main() only runs when script is executed directly,
    # not when imported as a module
    main()