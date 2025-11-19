# History

## v1.3 (November 2025)
- Added threshold-based anomaly detection that tracks failed logins, high-activity hosts, and process anomalies
- Made thresholds configurable via CLI flags and enhanced reporting
- Extended documentation and fixtures for anomaly scenarios

## v1.2 (November 2025)
- Added CSV export with RFC 4180 compliance and proper escaping
- Supported both stdout and file destinations for structured data
- Documented CSV workflows for spreadsheets, databases, and command-line tooling

## v1.1 (November 2025)
- Implemented JSON export and argparse-based CLI flags
- Validated output against edge-case fixtures (empty files, special characters)
- Updated README with structured usage examples

## v1.0 (November 2025)
- Initial release with syslog parsing, error handling, and sample fixtures
- Provided sample logs and documentation for manual testing
