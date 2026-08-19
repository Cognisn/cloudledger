---
name: security-assessment
description: Produce a scored security assessment report of a scanned AWS account using the CloudLedger server. Use when the user wants to assess, score, grade, or report on the security posture of an AWS account that has been scanned, or asks for a security assessment, security report, or exposure review of scan data. Requires the CloudLedger MCP server (tools get_security_assessment_data, analyze_service_exposure, get_security_check_catalogue). Trigger: /security-assessment.
---

# Security assessment

Turn the CloudLedger server's raw findings into a scored, written security
assessment of a scanned AWS account.

The server returns deterministic evidence with **advisory** severities and a
coverage report; it does not compute a score. This skill supplies the scoring
methodology (`references/scoring-rubric.md`), the report
(`references/report-template.md`), and an adversarial challenge round
(`references/challenge-guide.md`) that argues the client's side of every
significant finding before delivery, so the assessment is never one-sided. The
score is computed here, by the rubric — not by the server.

## Workflow

Follow these steps in order.

### 1. Confirm the server is available

The tools `get_security_assessment_data`, `analyze_service_exposure` and
`get_security_check_catalogue` must be reachable. If they are not, stop and tell
the user the CloudLedger server is not connected — do not produce a partial
report.

### 2. Resolve the scan

Use the latest scan unless the user names a `scan_id`. Call `list_scans` and
`get_scan_summary` if helpful, and state explicitly which account and scan date
you are assessing before continuing.

### 3. Learn the catalogue

Call `get_security_check_catalogue`. Its `count` and check list are the
authoritative set of applicable checks for the coverage calculation. If a check
appears in results that is not in `references/check-interpretation.md`, handle
it gracefully using its server-supplied `recommendation` rather than dropping
it.

### 4. Gather findings

Call `get_security_assessment_data` with no category filter. Keep `categories`,
`not_evaluated`, and `prowler`.

### 5. Gather exposure

Call `analyze_service_exposure` with no service filter. Keep the four service
results and their evidence chains.

### 6. Gather Prowler detail (only if present)

If `prowler.available` is true, call `get_prowler_findings` with
`summary_mode: true` for the corroboration section. If false, skip it entirely.

### 7. Score

Apply `references/scoring-rubric.md` exactly. Compute category sub-scores, the
overall score, grade, and coverage. If Prowler is present, compute both native
and blended scores. Show the working.

### 8. Build the report

Follow `references/report-template.md` section by section. Draw business-impact
framing from `references/check-interpretation.md` and fixes from
`references/remediation-playbooks.md`. Report affected-resource counts even
though the score counts the check, not the resources.

### 9. Challenge the assessment

Apply `references/challenge-guide.md` before delivering. Take the client's
side: contest every critical and high finding (and the summary's top risks)
through the guide's lenses — false positive, compensating control, intentional
design, staleness, materiality — citing scan evidence only. Adjudicate each
challenge as upheld, moderated, or needs client input, and fill the report's
"Challenge and response" section, including the open questions for the client.
Dispositions never change the rubric score.

### 10. Deliver

Present the report as Markdown. If the client supports artifacts and the user
prefers, offer to render it as a page.

## Determinism

The same scan must always yield the same score. Do not improvise weights or
deductions — the rubric is fixed. If you deviate, say why. The challenge round
annotates findings; it never moves the score — a moderated disposition tempers
the narrative, not the number.

## Keeping in step with the server

`references/check-interpretation.md` and `references/remediation-playbooks.md`
enumerate the server's checks at time of writing. `get_security_check_catalogue`
is the runtime source of truth; if the server's check set has grown, assess the
new checks from their catalogue metadata and note that the playbooks should be
updated.
