# Security Log Parser

A Python tool to parse and analyze security logs from various formats. Currently supports syslog format with plans to expand to Apache and nginx logs.

**Version:** 1.3
**Status:** In Progress

## Features

- [x] Parse syslog format
- [x] Structured output (timestamp, hostname, process, PID, message)
- [x] Export to JSON (v1.1)
- [x] Export to CSV (v1.2)
- [x] Anomaly detection with configurable thresholds (NEW in v1.3)
- [x] Export to human-readable text
- [x] Command-line interface with format selection
- [x] Error handling (missing files, permissions, malformed lines)
- [x] Multiple file testing
- [ ] Parse Apache logs (planned v1.4)
- [ ] Parse nginx logs (planned v1.4)
- [ ] Advanced anomaly detection (rate-based, IP tracking) (planned v2.0)

## Installation

### Requirements

- **Python 3.6 or higher** (check with `python3 --version`)
- No external dependencies (uses Python standard library only)

### Setup

1. **Clone or download this repository:**
   ```bash
   git clone https://github.com/kbrickz/security-tools.git
   cd security-tools/log-parser
   ```

2. **Verify Python 3 is installed:**
   ```bash
   python3 --version
   ```
   Should show Python 3.6 or higher.

3. **Make the script executable (optional):**
   ```bash
   chmod +x log_parser.py
   ```

4. **Test the installation:**
   ```bash
   python3 log_parser.py sample.log
   ```
   
   If you see parsed output, installation is successful!

## Usage

### Basic Usage

```bash
python3 log_parser.py <logfile>
```

### Examples

**Parse a single log file:**
```bash
python3 log_parser.py /var/log/syslog
```

**Parse the included sample:**
```bash
python3 log_parser.py sample.log
```

**Run all tests:**
```bash
chmod +x run_tests.sh
./run_tests.sh
```

### Export to JSON

**Print JSON to stdout:**
```bash
python3 log_parser.py --format json sample.log
```

**Save JSON to file:**
```bash
python3 log_parser.py --format json --output results.json sample.log
```

**Example JSON output:**
```json
[
  {
    "timestamp": "Nov 10 10:23:45",
    "hostname": "server1",
    "process": "sshd",
    "pid": "1234",
    "message": "Failed password for admin from 192.168.1.100"
  },
  {
    "timestamp": "Nov 10 10:23:46",
    "hostname": "server1",
    "process": "sshd",
    "pid": "1234",
    "message": "Connection closed"
  }
]
```

**Use JSON output with other tools:**
```bash
# Filter for failed logins
python3 log_parser.py --format json auth.log | jq '.[] | select(.message | contains("Failed"))'

# Count processes
python3 log_parser.py --format json sample.log | jq 'group_by(.process) | map({process: .[0].process, count: length})'

# Export for analysis in Python
python3 log_parser.py --format json --output data.json server.log
python3 -c "import json; data = json.load(open('data.json')); print(len(data))"
```

### Export to CSV

CSV export is ideal for spreadsheet analysis, database imports, and quick command-line filtering.

**Print CSV to stdout:**
````bash
python3 log_parser.py --format csv sample.log
````

**Save CSV to file:**
````bash
python3 log_parser.py --format csv --output results.csv sample.log
````

**Example CSV output:**
````csv
timestamp,hostname,process,pid,message
Oct 29 14:23:01,webserver,sshd,12345,"Failed password for admin from 192.168.1.100"
Oct 29 14:23:04,webserver,sshd,12346,"Accepted password for admin from 192.168.1.100"
````

**Use CSV with other tools:**
````bash
# Import into spreadsheet (Excel, Google Sheets, LibreOffice)
python3 log_parser.py --format csv --output analysis.csv sample.log
# Then open analysis.csv in your spreadsheet software

# Quick filtering with grep
python3 log_parser.py --format csv sample.log | grep "Failed password"

# Filter by column with csvkit (if installed)
python3 log_parser.py --format csv sample.log | csvgrep -c process -m sshd

# Count occurrences by process
python3 log_parser.py --format csv sample.log | csvcut -c process | sort | uniq -c

# Load into SQLite database
python3 log_parser.py --format csv --output logs.csv sample.log
sqlite3 analysis.db ".import logs.csv logs"
````

### Anomaly Detection

Detect security threats using threshold-based pattern matching.

**Enable anomaly detection:**
````bash
python3 log_parser.py --detect sample.log
````

**Customize thresholds:**
````bash
# More sensitive detection (lower thresholds)
python3 log_parser.py --detect --thresholds failed_logins=3 sample.log

# Multiple custom thresholds
python3 log_parser.py --detect --thresholds failed_logins=10 host_activity=30 sample.log
````

**What it detects:**
- **Failed login attempts** (default threshold: 5) - Brute force attacks
- **High activity hosts** (default threshold: 20) - Compromised systems
- **Process anomalies** (default threshold: 15) - Malware or misconfigurations

**Example output:**
````
==============================================================
ANOMALY DETECTION REPORT
==============================================================

⚠️  1 anomaly type(s) detected

🚨 FAILED LOGIN ATTEMPTS
   Count: 8 (threshold: 5)
   Risk: Possible brute force attack
   Action: Investigate source IPs, consider blocking
   
   Sample entries:
     1. [Nov 12 14:23:01] webserver: Failed password for admin...
     2. [Nov 12 14:23:03] webserver: Failed password for admin...
     3. [Nov 12 14:23:05] webserver: Failed password for admin...
     ... and 5 more

==============================================================
````

**Combine with export formats:**
````bash
# Detect anomalies AND export to JSON
python3 log_parser.py --detect --format json --output results.json sample.log
````

### Command Line Options
````
Usage: python3 log_parser.py [-h] [--format {text,json,csv}] [--output OUTPUT] 
                              [--detect] [--thresholds [THRESHOLDS ...]] logfile

positional arguments:
  logfile                 Path to the log file to parse (required)

optional arguments:
  -h, --help              Show this help message and exit
  --format {text,json,csv} Output format: 'text' for console, 'json' for structured data, 'csv' for spreadsheets (default: text)
  --output OUTPUT         Output filename. If not specified, prints to stdout
  --detect                Enable anomaly detection
  --thresholds [THRESHOLDS ...]
                          Custom thresholds (e.g., failed_logins=10 host_activity=30)
````

**Examples:**
```bash
# Default: text output to console
python3 log_parser.py sample.log

# JSON output to console
python3 log_parser.py --format json sample.log

# JSON output to file
python3 log_parser.py --format json --output results.json sample.log

# Text output to file (for saving reports)
python3 log_parser.py sample.log > report.txt

# CSV output to console
python3 log_parser.py --format csv sample.log

# CSV output to file
python3 log_parser.py --format csv --output results.csv sample.log
```

## Output Format

The parser outputs structured information for each log line, followed by a summary.

### Example Output

**Input (sample.log):**
```
Oct 29 14:23:01 webserver sshd[12345]: Failed password for admin from 192.168.1.100 port 52341 ssh2
Oct 29 14:23:04 webserver sshd[12346]: Accepted password for admin from 192.168.1.100 port 52341 ssh2
```

**Output:**
```
Parsing log file: sample.log
------------------------------------------------------------
Total lines read: 2

Line 1:
  Timestamp: Oct 29 14:23:01
  Hostname:  webserver
  Process:   sshd (PID: 12345)
  Message:   Failed password for admin from 192.168.1.100 port 52341 ssh2

Line 2:
  Timestamp: Oct 29 14:23:04
  Hostname:  webserver
  Process:   sshd (PID: 12346)
  Message:   Accepted password for admin from 192.168.1.100 port 52341 ssh2

------------------------------------------------------------
Summary:
  Successfully parsed: 2
  Failed to parse:     0
  Total lines:         2
```

### Error Handling

The tool handles common errors gracefully:

**File not found:**
```bash
$ python3 log_parser.py nonexistent.log
Error: File 'nonexistent.log' not found.
```

**Permission denied:**
```bash
$ python3 log_parser.py /root/secure.log
Error: Permission denied reading '/root/secure.log'.
```

**No filename provided:**
```bash
$ python3 log_parser.py
Usage: python log_parser.py <logfile>
Example: python log_parser.py sample.log
```

**Malformed lines:**

The parser skips lines that don't match syslog format and reports them:
```
Line 3: Failed to parse
  Raw: This is not a valid syslog line
```

## Supported Log Format

### Syslog Format

Standard BSD syslog format:

```
<timestamp> <hostname> <process>[<pid>]: <message>
```

**Components:**
- **Timestamp**: `Month Day HH:MM:SS` (e.g., `Oct 29 14:23:01`)
- **Hostname**: Server/system name (e.g., `webserver`)
- **Process**: Program/service name (e.g., `sshd`)
- **PID**: Process ID in brackets (e.g., `[12345]`)
- **Message**: The actual log message (e.g., `Failed password for admin...`)

**Example:**
```
Oct 29 14:23:01 webserver sshd[12345]: Failed password for admin from 192.168.1.100
```

## Testing

### Test Files Included

The repository includes several test files to verify functionality:

1. **sample.log** - 8 perfect syslog entries (normal operation)
2. **empty.log** - Empty file (edge case)
3. **malformed.log** - Mix of valid and invalid lines (error handling)
4. **large.log** - 49 entries (performance test)

### Running Tests

**Test all files automatically:**
```bash
./run_tests.sh
```

**Test individual files:**
```bash
python3 log_parser.py sample.log
python3 log_parser.py malformed.log
python3 log_parser.py large.log
python3 log_parser.py empty.log
```

### Expected Results

- **sample.log**: 8/8 lines parsed successfully
- **malformed.log**: ~6/10 lines parsed (4 failures expected)
- **large.log**: 50/50 lines parsed successfully
- **empty.log**: 1 lines, no crashes

## Security Use Cases

This log parser is useful for:

- **Incident Response**: Quickly parse logs during security incidents
- **Threat Hunting**: Search for suspicious patterns in system logs
- **Forensics**: Analyze system activity after compromise
- **Bug Bounty**: Verify if attacks left traces in logs
- **Learning**: Understand log formats and parsing techniques

### Example Security Analysis

**Detecting brute force attacks:**

Input logs showing failed login attempts:
```
Oct 29 14:23:01 webserver sshd[12345]: Failed password for admin from 192.168.1.100
Oct 29 14:23:02 webserver sshd[12345]: Failed password for admin from 192.168.1.100
Oct 29 14:23:03 webserver sshd[12345]: Failed password for admin from 192.168.1.100
Oct 29 14:23:04 webserver sshd[12346]: Accepted password for admin from 192.168.1.100
```

Parser output reveals:
- Pattern: 3 failed attempts → 1 success
- Timespan: 3 seconds (automated attack)
- Target: admin account
- Source: 192.168.1.100
- Conclusion: Likely brute force, investigate IP

## Design

See [DESIGN.md](DESIGN.md) for:
- Architecture decisions
- Regular expression patterns
- Future enhancements
- Lessons learned

## Limitations

**Current version (v1.2):**
- Only supports syslog format
- Reads entire file into memory (not ideal for multi-GB files)
- No automatic pattern detection

See [Roadmap](#roadmap) for planned improvements.

## Roadmap

**v1.1**: JSON export (COMPLETE)  
**v1.2**: CSV export (COMPLETE)  
**v1.3**: Threshold-based anomaly detection (COMPLETE)  
**v1.4**: Apache and nginx log support  
**v2.0**: Advanced anomaly detection (rate-based, IP tracking, ML)  
**v2.5**: Real-time monitoring, streaming parser

## Troubleshooting

### Common Issues

**"python3: command not found"**
- Install Python 3: https://www.python.org/downloads/
- Or try `python` instead of `python3`

**"Permission denied"**
- Ensure you have read access to the log file
- Use `sudo` if needed: `sudo python3 log_parser.py /var/log/syslog`

**"No such file or directory"**
- Check the file path is correct
- Use absolute paths if relative paths don't work

**"File is empty, 0 lines"**
- Verify the log file actually contains data
- Check file permissions

## Contributing

This is a learning project built as part of a security research curriculum. Suggestions and improvements welcome!

To contribute:
1. Fork the repository
2. Create a feature branch
3. Submit a pull request

## License

MIT License - see [LICENSE](LICENSE) file for details.

You are free to use, modify, and distribute this tool for any purpose, including commercial applications.

## Author

**Kristen Brickner**
- **GitHub**: [@kbrickz](https://github.com/kbrickz)
- **Twitter**: [@kaybrickz](https://x.com/kaybrickz)
- **Blog**: [kbrickz.github.io](https://kbrickz.github.io)

## Acknowledgments

Built as part of a security researcher curriculum focusing on:
- Python automation for security
- Web application security
- Cloud security (AWS/Azure)
- AI/LLM red teaming

This is the first tool in a collection of 6-8 security tools to be built over the next 12 months.

## Version History

**v1.0** (November 2025)
- Initial release
- Syslog format parsing
- Error handling
- Multiple test files
- Documentation

**v1.1** (November 2025)
- Added JSON export functionality
- Command-line argument parsing with argparse
- Support for `--format` and `--output` flags
- Validated JSON output with special character handling
- Updated documentation with usage examples
- Test files for edge cases (empty, single entry, special chars)

**v1.2** (November 2025)
- Added CSV export functionality
- RFC 4180 compliant CSV format (industry standard)
- Automatic escaping of special characters (commas, quotes, newlines)
- Supports both file output and stdout for piping
- Integration examples with spreadsheets and command-line tools
- Updated documentation with CSV usage patterns
- Tested with edge cases (empty files, special characters, large files)

**v1.3** (November 2025)
- Added threshold-based anomaly detection
- Detects failed login attempts, high activity hosts, and process anomalies
- Configurable thresholds via command line
- Three-phase detection algorithm (counting, evaluation, reporting)
- Comprehensive anomaly reporting with security context
- Combined anomaly detection with existing export formats
- Updated documentation with detection methodology
- Test files for brute force and anomaly scenarios

---

**⭐ Star this repo if you find it useful!**

*Part of the security-tools collection • Building in public • Security research journey*