# Security Log Parser

## Description

A Python tool to parse and analyze security logs from various formats. Currently supports syslog format with plans to expand to Apache and nginx logs.

## Features

- [x] Parse syslog format
- [ ] Parse Apache logs
- [ ] Parse nginx logs
- [ ] Detect patterns (failed logins, unusual activity)
- [ ] Export to JSON/CSV

## Installation

### Requirements
- Python 3.6 or higher
- No external dependencies (uses Python standard library)

### Setup

1. Clone this repository or download the files
2. Ensure Python 3 is installed: `python3 --version`
3. Make the script executable (optional): `chmod +x log_parser.py`

## Usage

### Basic Usage

```bash
python3 log_parser.py <logfile>
```

### Example

```bash
python3 log_parser.py sample.log
```

### Output

The parser outputs structured information for each log line:

```
Parsing log file: sample.log
------------------------------------------------------------
Total lines read: 8

Line 1:
  Timestamp: Oct 29 14:23:01
  Hostname:  webserver
  Process:   sshd (PID: 12345)
  Message:   Failed password for admin from 192.168.1.100 port 52341 ssh2

[Additional lines...]

------------------------------------------------------------
Summary:
  Successfully parsed: 8
  Failed to parse:     0
  Total lines:         8
```

### Sample Log File

A sample log file (`sample.log`) is included for testing. It contains various syslog entries including:
- Failed SSH login attempts
- Successful SSH logins
- System events
- Sudo commands

## Supported Log Format

### Syslog Format

Standard BSD syslog format:
```
<timestamp> <hostname> <process>[<pid>]: <message>
```

Example:
```
Oct 29 14:23:01 webserver sshd[12345]: Failed password for admin from 192.168.1.100
```

**Components parsed:**
- **Timestamp**: When the event occurred
- **Hostname**: Which system generated the log
- **Process**: Which program/service
- **PID**: Process ID
- **Message**: The actual log message

## Design

See [DESIGN.md](DESIGN.md) for detailed design decisions and architecture explanation.

## Security Use Cases

This log parser is useful for:

- **Incident Response**: Quickly parse logs during security incidents
- **Threat Hunting**: Search for suspicious patterns
- **Forensics**: Analyze system activity after compromise
- **Learning**: Understand log formats and parsing techniques

## Limitations

**Current version (v1.0):**
- Only supports syslog format
- Reads entire file into memory (not suitable for very large files)
- Console output only (no JSON/CSV export yet)
- No pattern detection (planned for future versions)

## Roadmap

**v1.1**: Apache and nginx log support
**v1.2**: JSON and CSV export
**v1.3**: Pattern detection (failed logins, brute force attempts)
**v2.0**: Real-time monitoring, database export

## Testing

Test with the included sample log:
```bash
python3 log_parser.py sample.log
```

Test error handling:
```bash
# Nonexistent file
python3 log_parser.py nonexistent.log

# No filename provided
python3 log_parser.py
```

## Contributing

This is a learning project built as part of a security research curriculum. Suggestions and improvements welcome!

## License

MIT License - see [LICENSE](LICENSE) file for details

## Author

**Kristen Brickner**
- GitHub: [@kbrickz](https://github.com/kbrickz)
- X: [@kaybrickz](https://x.com/kaybrickz)
- Blog: [kbrickz.github.io](https://kbrickz.github.io)

## Acknowledgments

Built as part of a 12-month security researcher curriculum focusing on Python automation, web security, cloud security, and AI red teaming.

---

*First tool in the security-tools collection. More coming soon!*