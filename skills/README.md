# CloudLedger skills

Skills that pair with the CloudLedger server. They direct an MCP client
(Claude Desktop, Claude Code, or any client connected to the server) to turn the
server's raw security findings into a scored, written security assessment.

## Skills

- **security-assessment** — a full, scored security assessment of a scanned
  account: gathers the server's findings and exposure evidence, applies a
  deterministic scoring model, and produces a tiered report (executive summary
  through to technical remediation), closed out by an adversarial challenge
  round that argues the client's side of every significant finding — false
  positive, compensating control, intentional design — and records each
  challenge's disposition, so the assessment is never one-sided. The server
  returns evidence with advisory severities; this skill supplies the scoring
  methodology, the challenge round, and the report.
- **account-inventory** — a complete inventory of the services a scanned account
  uses and to what extent, with accurate counts. Directs the client to the
  summary and resource tools (not the findings tools, which undercount).
- **cost-analysis** — cost breakdown by service and account, spend trends, and a
  forward forecast, from the up-to-12-months of billing data the scanner
  collects.
- **security-groups-review** — a complete audit of every security group and what
  each one actually exposes, tying rules to reachability and implications.
- **attack-path-analysis** — plausible attack paths to compromise the account,
  built as chains from entry to impact and mapped to MITRE ATT&CK.
- **tool-guide** — a router that maps a question to the right tool or task skill,
  so questions are answered from the correct data (e.g. inventory from the
  summary tools, not the findings tools).

### Requirements

The CloudLedger server must be connected to your client, with at least one
scan in its database. The skill depends on these server tools:
`get_security_assessment_data`, `analyze_service_exposure`,
`get_security_check_catalogue` (and `get_prowler_findings` when a Prowler scan
is present).

### Install

Export each skill as a ZIP archive ready for your client's skill installer
(claude.ai, Claude Desktop, and other clients that accept skill uploads):

```bash
cloudledger skills export            # one ZIP per skill, written to the current directory
cloudledger skills export --output ~/Desktop/cloudledger-skills
```

For filesystem-based clients, copy or symlink the skill folder instead. For
Claude Code:

```bash
ln -s "$(pwd)/skills/security-assessment" ~/.claude/skills/security-assessment
```

Then invoke it with `/security-assessment` (optionally naming a scan).
