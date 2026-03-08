# 🥟 Mantou

**Local-first security posture scanner for [OpenClaw](https://openclaw.ai) AI agents.**

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Ruleset](https://img.shields.io/badge/rules-43-critical-red)](mantou/rules/)

> Your OpenClaw agent has filesystem access, channel integrations, shell execution, and a gateway exposed to the internet. **Did you audit it?**

Mantou scans your local OpenClaw installation in seconds — no cloud, no SaaS, no telemetry. It reads your config, checks file permissions, inspects workspace prompt files for credential leaks, and tells you exactly what's wrong and how to fix it.

```
$ mantou scan --text

Mantou 0.1.0 — OpenClaw Security Posture Scan
Scanned: 2026-03-08  |  Duration: 8ms  |  Platform: darwin

Findings: 6 total  (3 critical, 2 high, 1 medium)

  [CRITICAL] CFG-001 · network
  Gateway exposed without strong auth
  gateway.bind=0.0.0.0 with no auth token. Anyone on your network has full agent access.
  → Set gateway.bind=127.0.0.1 or configure gateway.auth.token (min 32 chars).

  [CRITICAL] TOOL-003 · config
  Filesystem read scope unrestricted
  tools.filesystem.allowRead contains "/" — agent can read your entire disk.
  → Restrict to ["~/.openclaw", "~/workspace"] or a specific project directory.

  [CRITICAL] CHN-005 · config
  Discord group/guild policy is open
  channels.discord.groupPolicy=open means any server can trigger your agent.
  → Set groupPolicy=allowlist and specify guild IDs.

  [HIGH]     PERM-002 · permissions
  openclaw.json is world-readable
  Your config file (contains auth tokens) is readable by all OS users.
  → chmod 600 ~/.openclaw/openclaw.json

  [HIGH]     CFG-004 · skills
  Unverified skills can be installed
  skills.install.allow_unverified=true. Unverified npm packages can be loaded.
  → Set allow_unverified=false.

  [MEDIUM]   CFG-010 · data_retention
  Debug logging enabled
  logging.level=debug may write message content and credentials to disk.
  → Set logging.level=info in production.
```

---

## Why Mantou?

AI agents are a new attack surface that most security tools don't understand yet.

| Risk | What can go wrong | Mantou rule |
|------|-------------------|-------------|
| Open gateway | Agent accessible to anyone on your network/internet | CFG-001, CFG-003 |
| Unrestricted filesystem | Agent can read `~/.ssh`, `~/.aws`, your entire home dir | TOOL-003, TOOL-005 |
| Open channel policies | Anyone on Discord/Telegram/WhatsApp can send commands | CHN-001–005 |
| Credential leak in prompts | AWS keys, tokens in SOUL.md or AGENTS.md | PROMPT-001 |
| Running as root | Full system compromise on any tool execution | OS-001 |
| World-readable config | Auth tokens readable by any local user or process | PERM-002, PERM-005 |
| Unverified skills | Supply-chain attack via malicious npm packages | CFG-004 |
| Weak auth token | Brute-forceable gateway token | CFG-013 |

---

## Install

```bash
# pipx (recommended — isolated, no dependency conflicts)
brew install pipx && pipx ensurepath
pipx install git+https://github.com/peeweeh/mantou.git

# or pip
pip install git+https://github.com/peeweeh/mantou.git
```

---

## Usage

```bash
mantou scan                  # JSON output (pipe-friendly)
mantou scan --text           # human-readable report
mantou scan --min-severity high   # only high + critical
mantou scan --exit-on critical    # exit 1 if any criticals (CI/CD use)
mantou scan --config /path/to/openclaw.json   # explicit config path

mantou rules list            # list all 43 rules
mantou rules show CFG-001    # inspect a single rule
```

### Real-World Output (Sanitized)

```text
$ mantou scan --text --include-info

Mantou 0.1.0 — OpenClaw Security Posture Scan
Scanned: 2026-03-08T14:35:48.420967+00:00  |  Duration: 384ms  |  Platform: darwin
OpenClaw status: detected_config_only

Findings: 21 total  (3 critical, 1 high, 0 medium, 0 low, 17 info)

  [CRITICAL] CHN-005 · config
  Discord group/guild policy is open
  channels.discord.groupPolicy=open means any Discord server can add and use your agent.
  Resource: file:///Users/<user>/.openclaw/openclaw.json
  Evidence: open
  Fix: Set channels.discord.groupPolicy=allowlist and restrict to specific guild IDs.

  [CRITICAL] TOOL-001 · config
  Shell denylist absent or empty
  tools.shell.denylist is missing or empty. The agent can execute any shell command without restriction.
  Resource: file:///Users/<user>/.openclaw/openclaw.json
  Evidence: True
  Fix: Add a denylist with at minimum: ["rm -rf", "curl | sh", "wget | sh", "chmod 777", "dd if="]

  [CRITICAL] TOOL-005 · config
  Filesystem deny list missing sensitive paths
  tools.filesystem.deny is absent or does not include all of: ~/.ssh, ~/.aws, ~/.openclaw/secrets.
  Resource: file:///Users/<user>/.openclaw/openclaw.json
  Evidence: True
  Fix: Add to tools.filesystem.deny: ["~/.ssh", "~/.aws", "~/.openclaw/secrets", "~/.gnupg"].

  [HIGH] TOOL-002 · config
  No confirm-before-exec list defined
  tools.confirmBeforeExecuting is missing or empty. Destructive commands will execute without user confirmation.
  Resource: file:///Users/<user>/.openclaw/openclaw.json
  Evidence: True
  Fix: Define tools.confirmBeforeExecuting with all destructive commands (rm, mv, chmod, curl with -o, etc.).

  [INFO] ADV-001 · network
  Gateway port exposure unknown (manual check required)
  Mantou cannot run `ss` to verify port exposure. Run: ss -tulpn | grep openclaw — confirm the gateway is not bound to 0.0.0.0 unexpectedly.
  Resource: file:///Users/<user>/.openclaw/openclaw.json
  Evidence: loopback
  Fix: Run `ss -tulpn | grep openclaw` and verify the gateway is only accessible from intended interfaces.

  [INFO] ADV-002 · network
  Firewall status not verified (manual check required)
  Mantou cannot run privileged commands. Run: sudo ufw status (Linux) to confirm the gateway port is filtered from external access.
  Resource: file:///Users/<user>/.openclaw/openclaw.json
  Evidence: loopback
  Fix: Run `sudo ufw status` and confirm UWF is enabled with the gateway port blocked from untrusted sources.
```

### CI/CD

```yaml
# GitHub Actions example
- name: Scan OpenClaw config
  run: |
    pipx install git+https://github.com/peeweeh/mantou.git
    mantou scan --exit-on high --json > mantou-report.json
```

---

## Rules (43 total)

| Prefix | Domain | Count |
|--------|--------|-------|
| `CFG-` | Gateway config, auth, TLS, logging, model settings | 10 |
| `CHN-` | Channel access policies (Discord, Telegram, WhatsApp) | 5 |
| `TOOL-` | Filesystem scope, shell denylist, exec confirmation | 5 |
| `PERM-` | File/directory permissions on sensitive paths | 6 |
| `AGT-` | Agent tool boundaries, model assignments | 2 |
| `PROMPT-` | Credential patterns in workspace prompt files | 1 |
| `OS-` | Running as root, container detection, version | 3 |
| `FS-` | OpenClaw directory structure sanity checks | 2 |
| `ADV-` | Advisory checks requiring manual verification | 16 |

```bash
mantou rules list   # full table with severity + category
```

---

## Output Formats

**Text** (`--text`) — human-readable, terminal-friendly.

**JSON** (`--json` or default) — machine-readable, pipe to `jq`, ingest into SIEM:

```json
{
  "scan_id": "bb340d8b-...",
  "timestamp": "2026-03-08T13:15:57Z",
  "phase": 1,
  "platform": { "os": "darwin", "arch": "arm64", "container": false },
  "findings": [
    {
      "id": "CFG-001",
      "phase": 1,
      "severity": "critical",
      "category": "network",
      "resource": "file://~/.openclaw/openclaw.json",
      "title": "Gateway exposed without strong auth",
      "detail": "...",
      "remediation": "..."
    }
  ],
  "summary": { "total": 6, "critical": 3, "high": 2, "medium": 1, "low": 0, "info": 0 }
}
```

---

## Architecture

Mantou is layered and fully local. Nothing leaves your machine.

```
CLI → Scanner → Rule Engine → Finders → Findings
                    ↓
              JSON rule files
              (mantou/rules/)
```

- **Rules** — declarative JSON in `mantou/rules/`. Easy to read, easy to extend.
- **Engine** — loads rules, runs probes (JSONPath, filesystem stat, regex), evaluates conditions.
- **Finders** — config (jsonpath-ng), filesystem (permissions/stat), command (stdout), text (regex).
- **Schema** — Pydantic v2. All findings go through a canonical `Finding` model.

---

## Extend with Custom Rules

Drop a JSON file in your rules directory:

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
      "detail": "mykey is set to dangerous",
      "remediation": "Change mykey to something safe."
    }
  }
]
```

```bash
mantou scan --rules ./my-rules/
```

---

## Dev Setup

```bash
git clone https://github.com/peeweeh/mantou.git && cd mantou
python3.11 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest tests/ -v
black . && isort . && ruff check .
```

60 tests. Zero external calls. Fully offline.

---

## Roadmap

- **Phase 1 (current)** — Static analysis: config, permissions, prompt files, OS context
- **Phase 2** — Tool-based: invoke `openclaw doctor` + `openclaw security audit`, normalize findings, cross-reference with Phase 1
- **Phase 3** — LLM-assisted: semantic analysis of SOUL.md/AGENTS.md for prompt injection risks and over-permissioned agent directives

---

## Contributing

Rules live in `mantou/rules/*.json` — adding a new check is usually just a few lines of JSON. See the [rule authoring guide](mantou/rules/) and existing rules for patterns.

Bug reports, rule ideas, and PRs welcome.

---

## License

MIT
