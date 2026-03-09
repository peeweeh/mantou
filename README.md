# Mantou

Local-first security posture scanner for OpenClaw agents.

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Ruleset](https://img.shields.io/badge/rules-58-red)](mantou/rules/)

Your OpenClaw setup can run shell commands, read files, talk to channels, and expose a gateway. Mantou checks that setup fast, locally, and with zero telemetry.

## Why It Exists

Classic security tools do not understand agent configs well. Mantou does.

It scans for things like:
- Open gateway without strong auth
- Over-broad filesystem access
- Open channel policies
- Dangerous tool settings
- Weak file permissions
- Prompt-file secret leaks
- Runtime and patch hygiene signals

Every finding includes a plain fix, so you can go from "that looks bad" to "fixed" quickly.

## Quick Start

```bash
# pipx (recommended)
brew install pipx && pipx ensurepath
pipx install git+https://github.com/peeweeh/mantou.git

# or pip
pip install git+https://github.com/peeweeh/mantou.git
```

Run a scan:

```bash
mantou scan --text
```

Want only actionable signal (less advisory noise):

```bash
mantou scan --text --min-severity medium
```

## Core Commands

```bash
mantou scan --text
mantou scan --json
mantou scan --min-severity high
mantou scan --exit-on critical
mantou scan --config /path/to/openclaw.json
mantou scan --skip-tools

mantou rules list
mantou rules show CFG-001
```

## Example Output

```text
Mantou 0.1.0 - OpenClaw Security Posture Scan
Findings: 7 total (5 critical, 1 high, 1 medium)

[CRITICAL] CFG-018  Small models require sandboxing and web tools disabled
[CRITICAL] CHN-005  Discord group/guild policy is open
[CRITICAL] CHN-007  Open groupPolicy with runtime/filesystem tools exposed
[CRITICAL] TOOL-001 Shell denylist absent or empty
[CRITICAL] TOOL-005 Filesystem deny list missing sensitive paths
[HIGH]     TOOL-002 No confirm-before-exec list defined
[MEDIUM]   TOOL-006 safeBins includes interpreter/runtime binaries without explicit profiles
```

## Rules

Current ruleset: **58 rules**.

Main families:
- `CFG-` gateway and config hardening
- `CHN-` channel access boundaries
- `TOOL-` execution and filesystem limits
- `PERM-` sensitive file and directory permissions
- `PROMPT-` secret patterns in prompt docs
- `OS-` runtime and version checks
- `FS-` local installation shape checks
- `ADV-` manual-verification advisories
- `ISO-` container isolation checks

## Architecture

```text
CLI -> Scanner -> Rule Engine -> Finders -> Findings
                     |
                 JSON rules
```

- Rules live in `mantou/rules/*.json`
- Engine evaluates declarative conditions
- Finders probe config, filesystem, text, and commands
- Findings conform to a Pydantic schema

## Add Custom Rules

Drop your own JSON rule file and point Mantou at it:

```bash
mantou scan --rules ./my-rules
```

Minimal example:

```json
[
  {
    "id": "MY-001",
    "enabled": true,
    "description": "My custom check",
    "target": { "type": "json", "file": "openclaw.json", "path": "$.mykey" },
    "probe": { "type": "value" },
    "condition": { "operator": "equals", "value": "dangerous" },
    "finding": {
      "severity": "high",
      "category": "config",
      "title": "My custom finding",
      "detail": "mykey is dangerous",
      "remediation": "Change mykey to a safer value."
    }
  }
]
```

## Dev Setup

```bash
git clone https://github.com/peeweeh/mantou.git
cd mantou
python3.11 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

pytest tests/ -q
black .
isort .
ruff check .
```

## Contributing

Rule ideas and PRs are welcome. Best contributions are:
- Deterministic
- Low-noise
- Easy to remediate
- Backed by test fixtures

## License

MIT
