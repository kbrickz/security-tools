# Contributing Guidelines

Thanks for your interest in improving this Security Log Parser! Contributions of any size are welcome. To keep things easy for reviewers, please follow these steps:

1. **Fork and branch**
   - Fork this repository and create a feature branch (`git checkout -b feature/my-change`).

2. **Set up the environment**
   - Use Python 3.11+
   - Install dev dependencies if needed: `pip install -r requirements-dev.txt`

3. **Run tests and linting**
   - `python3 -m unittest -v`
   - `ruff check log_parser.py test_log_parser.py`

4. **Coding style**
   - Follow the existing docstring/comment style.
   - Keep output ASCII-only unless documenting Unicode data.
   - Include type hints for new functions whenever possible.

5. **Pull Requests**
   - Describe the motivation and key changes.
   - Reference any relevant issues.
   - Ensure CI checks pass before requesting review.

If you have questions, open an issue or start a discussion. Happy hacking!
