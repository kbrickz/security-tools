# Security Log Parser

A Python CLI that ingests syslog-formatted files, normalizes them into structured fields, and exports the data for downstream security tooling.

## Features

- Syslog parsing with timestamp/host/process/pid/message normalization
- Streaming file reader with UTF-8/latin-1 fallback for noisy logs
- Human-readable text output plus JSON and CSV exporters
- Threshold-based anomaly detection for failed logins, noisy hosts, and suspicious processes
- CLI argument validation, custom thresholds, and optional failed-line reporting
- Comprehensive unittest suite with fixture coverage

## Installation

### Requirements

- **Python 3.11 or higher** (check with `python3 --version`)
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
```text
==============================================================
ANOMALY DETECTION REPORT
==============================================================

[WARNING] 1 anomaly type(s) detected

[ALERT] FAILED LOGIN ATTEMPTS
   Count: 8 (threshold: 5)
   Risk: Possible brute force attack
   Action: Investigate source IPs, consider blocking
```

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

`log_parser.py` emits structured entries followed by a summary. Example text output for `sample.log`:

```text
Total entries parsed: 2

Entry 1:
  Timestamp: Oct 29 14:23:01
  Hostname: webserver
  Process: sshd (PID: 12345)
  Message: Failed password for admin from 192.168.1.100 port 52341 ssh2

Entry 2:
  Timestamp: Oct 29 14:23:04
  Hostname: webserver
  Process: sshd (PID: 12346)
  Message: Accepted password for admin from 192.168.1.100 port 52341 ssh2

------------------------------------------------------------
Summary: 2 entries successfully parsed
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

### How to Run Tests

Use Python's unittest discovery to execute the full suite:

```bash
python3 -m unittest -v
```

This command runs parser unit tests, export tests, anomaly detection checks, and CLI integration coverage.

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

- Focused on traditional syslog format (no Apache/nginx parsing yet)
- Anomaly detection is rule/threshold-based rather than statistical
- Output is batch-oriented; real-time streaming integrations would require additional work

See [HISTORY.md](HISTORY.md) for release notes and [DESIGN.md](DESIGN.md) for future considerations.

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

## History

Release notes live in [HISTORY.md](HISTORY.md). Each entry captures the features and fixes included in that version.

---

**⭐ Star this repo if you find it useful!**

*Part of the security-tools collection • Building in public • Security research journey*
