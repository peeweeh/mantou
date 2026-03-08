# Mantou

Local-first security posture scanner for [OpenClaw](https://openclaw.ai).

## Install (pipx — recommended)

```bash
brew install pipx && pipx ensurepath
pipx install git+https://github.com/peeweeh/mantou.git
```

## Usage

```bash
mantou scan --text          # human-readable report
mantou scan --json          # JSON output (default)
mantou rules list           # list all rules
mantou rules show CFG-001   # inspect a rule
```

## Dev Setup

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest tests/ -v
```

## Linting

```bash
black . && isort . && ruff check .
```
