# Contributing

- Stdlib only. No runtime dependencies, ever.
- Python 3.11+. CI runs 3.11-3.15 on Ubuntu and Windows.
- Tests use `unittest`: `python -m unittest discover -s tests`
- Keep the exit codes (0/1/2/3) and seal format stable. A change to either needs a CHANGELOG entry.
- One logical change per PR. By contributing, you agree your work is licensed under Apache-2.0.
