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

def main():
    """
    Main function to orchestrate log parsing.

    Usage:
        python log_parser.py <logfile>
        python log_parser.py --format json <logfile>
        python log_parser.py --format csv <logfile>
        python log_parser.py --format json --output results.json <logfile>
    """
    # Set up command-line argument parser
    parser = argparse.ArgumentParser(
        description='Parse security logs and export in various formats',
        epilog='Example: python log_parser.py --format json --output results.json sample.log')

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