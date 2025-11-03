#!/usr/bin/env python3
"""
Security Log Parser
A tool to parse and analyze security logs from various formats.

Author: Kristen Brickner
Date: October 2025
Purpose: Week 1 Day 4 - First security tool for curriculum
"""

import re  # Regular expressions for pattern matching
import sys  # System-specific parameters and functions


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


def main():
    """
    Main function to orchestrate log parsing.
    
    Usage: python log_parser.py <logfile>
    """
    # Check if user provided a filename
    if len(sys.argv) < 2:
        print("Usage: python log_parser.py <logfile>")
        print("Example: python log_parser.py sample.log")
        sys.exit(1)
    
    # Get filename from command line argument
    filename = sys.argv[1]
    
    print(f"Parsing log file: {filename}")
    print("-" * 60)
    
    # Read the log file
    lines = read_file(filename)
    
    print(f"Total lines read: {len(lines)}\n")
    
    # Parse each line
    parsed_count = 0
    failed_count = 0
    
    for line_num, line in enumerate(lines, start=1):
        # Skip empty lines
        if not line:
            continue
        
        # Parse the line
        parsed = parse_syslog(line)
        
        if parsed:
            parsed_count += 1
            # Print parsed result
            print(f"Line {line_num}:")
            print(f"  Timestamp: {parsed['timestamp']}")
            print(f"  Hostname:  {parsed['hostname']}")
            print(f"  Process:   {parsed['process']} (PID: {parsed['pid']})")
            print(f"  Message:   {parsed['message']}")
            print()
        else:
            failed_count += 1
            print(f"Line {line_num}: Failed to parse")
            print(f"  Raw: {line}")
            print()
    
    # Print summary
    print("-" * 60)
    print(f"Summary:")
    print(f"  Successfully parsed: {parsed_count}")
    print(f"  Failed to parse:     {failed_count}")
    print(f"  Total lines:         {len(lines)}")


if __name__ == "__main__":
    # This ensures main() only runs when script is executed directly,
    # not when imported as a module
    main()