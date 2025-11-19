# Security Log Parser 

A Python 3 CLI tool that ingests syslog-formatted files, normalizes each line into structured timestamp/host/process/message fields, and then exports the data as text, JSON, or CSV for downstream tooling. 

The script emphasizes defensive operations: it validates inputs, surfaces parsing failures, and can optionally run a threshold-based anomaly detector that highlights failed logins, noisy hosts, or suspicious processes. 

The repo includes realistic sample logs, fixtures for edge cases, and a unittest suite that exercises the parser, file handling, threshold validation, and anomaly logic, so a user can clone the project, run `python3 log_parser.py sample.log`, and immediately explore or extend the code without extra dependencies.

## File Tree

```
.
├── .editorconfig
├── .gitignore
├── .github/
│   ├── ISSUE_TEMPLATE/
│   │   ├── bug_report.md
│   │   └── feature_request.md
│   └── workflows/
│       └── ci.yml
├── AGENTS.md
├── CONTRIBUTING.md
├── DESIGN.md
├── HISTORY.md
├── LICENSE
├── README.md
├── __pycache__/
│   ├── log_parser.cpython-311.pyc
│   └── test_log_parser.cpython-311.pyc
├── brute_force.log
├── empty.log
├── large.log
├── log_parser.py
├── malformed.log
├── pyproject.toml
├── requirements-dev.txt
├── run_tests.sh
├── sample.log
├── test.csv
├── test_log_parser.py
├── test_single.log
└── test_special_chars.log
```

## Comment & Note Style

- **Docstrings first:** Every public function/class should have a triple-quoted docstring that explains purpose, inputs, outputs, and errors, matching the tone already used in `log_parser.py` and `test_log_parser.py`.
- **Concise inline comments:** Use one-line `#` comments only when code is non-obvious (e.g., explaining regex groups or threshold rules); avoid repeating what the code already states.
- **Structured explanations:** When documenting complex blocks (like anomaly algorithms), prefer short bullet-style descriptions or numbered steps inside docstrings rather than scattered inline notes.
- **Testing mirrors production:** Unit tests should include short docstrings per test method that describe intent (“Test parsing a valid syslog line”), and setup comments should highlight fixtures or rationale.
- **Tone & format consistency:** Stick to the existing neutral, instructional voice; keep spacing consistent (blank line before comment blocks, single space after `#`), and ensure comments stay aligned with actual behavior whenever code changes.
