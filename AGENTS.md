# Repository Guidelines

## Project Structure & Module Organization

- `runcloud-triage.py` is the standalone scanner: detection rules, filesystem/log inspection, report generation, system snapshots, and CLI handling.
- `tests/test_triage.py` contains offline detection tests and temporary Linux filesystem fixtures.
- `README.md` documents installation, execution, report interpretation, and limitations. `docs/php2shell-triage-laracraft.md` provides background reference material.
- `runcloud-triage.py.sha256` verifies the distributed script. There are no separate application assets or dependency manifests.

## Build, Test, and Development Commands

Use Python 3.6 or newer; only the standard library is required. No build or package installation step is needed.

- `python3 -m unittest discover -s tests -v` runs the test suite.
- `python3 -m py_compile runcloud-triage.py` checks syntax.
- `python3 -I runcloud-triage.py --help` displays CLI options without scanning.
- `sudo /usr/bin/python3 -I runcloud-triage.py` runs a real scan on an Ubuntu/RunCloud host and writes a private report under `/root`; use a disposable Linux environment for development scans.
- After changing the scanner, run `sha256sum runcloud-triage.py > runcloud-triage.py.sha256`, then `sha256sum --check runcloud-triage.py.sha256`. The README includes a PowerShell equivalent.

On Windows, use `python` if `python3` is unavailable.

## Coding Style & Naming Conventions

Follow existing Python style: four-space indentation, `snake_case` functions and variables, `PascalCase` classes, and `UPPER_SNAKE_CASE` constants. Preserve Python 3.6-compatible syntax and APIs; avoid third-party dependencies. Use LF endings for Python, Markdown, and checksum files as specified by `.gitattributes`. No formatter or linter is configured.

## Testing Guidelines

Use `unittest.TestCase` with descriptive `test_*` methods in `tests/test_*.py`. Add regression fixtures for changed detection, traversal, logging, or reporting behavior. Keep PHP samples inert and never execute them.

Run filesystem tests on Linux; Windows skips them. The isolated chroot CLI test additionally requires root. Exercise exit codes, permissions, limits, and read failures when relevant. No numerical coverage threshold is configured. Newer-interpreter checks do not replace validation on the oldest supported runtime.

## Commit & Pull Request Guidelines

The available history uses a descriptive imperative subject: `Add tests for runcloud-triage.py and SHA256 checksum file`. Follow that style and keep commits focused.

PRs should explain behavior changes, link relevant issues, and report commands run, platform/Python version, and skipped checks. Update documentation and the checksum alongside scanner changes.

## Security & Configuration

Preserve the scanner's read-only contract: write only to a new private report directory, never execute application code, and do not follow symlinks. Keep reports, credentials, and real server logs out of Git. Describe detections as review indicators, not proof of compromise or cleanliness.
