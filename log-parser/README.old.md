# Security Log Parser

A Python tool to parse and analyze security logs from various formats. Currently supports syslog format with plans to expand to Apache and nginx logs.

**Version:** 1.0  
**Status:** Production-ready ✅

## Features

- [x] Parse syslog format
- [x] Structured output (timestamp, hostname, process, PID, message)
- [x] Error handling (missing files, permissions, malformed lines)
- [x] Multiple file testing
- [ ] Parse Apache logs (planned v1.1)
- [ ] Parse nginx logs (planned v1.1)
- [ ] Detect patterns (failed logins, unusual activity) (planned v1.2)
- [ ] Export to JSON/CSV (planned v1.2)

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

### Command Line Options

Currently, the tool accepts a single argument: the path to a log file.

```
Usage: python3 log_parser.py <logfile>

Arguments:
  logfile    Path to the log file to parse (required)
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
4. **large.log** - 50 entries (performance test)

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
- **empty.log**: 0 lines, no crashes

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

**Current version (v1.0):**
- Only supports syslog format
- Reads entire file into memory (not ideal for multi-GB files)
- Console output only (no JSON/CSV export)
- No automatic pattern detection

See [Roadmap](#roadmap) for planned improvements.

## Roadmap

**v1.1**: Apache and nginx log support  
**v1.2**: JSON and CSV export  
**v1.3**: Pattern detection (failed logins, brute force)  
**v2.0**: Real-time monitoring, streaming parser

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
- **X**: [@kaybrickz](https://x.com/kaybrickz)
- **Blog**: [kbrickz.github.io](https://kbrickz.github.io)

## Acknowledgments

Built as part of a 12-month security researcher curriculum focusing on:
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
- Production-ready documentation

---

**⭐ Star this repo if you find it useful!**

*Part of the security-tools collection • Building in public • Security research journey*