# Report template

Produce one Markdown document with these sections in order. Fill each from the
actual findings; the prompts describe content, not fixed wording. Draw framing
from check-interpretation.md and fixes from remediation-playbooks.md.

## 1. Header

```
# Security Assessment — <account_name> (<account_number>)
Scan: <scan_id> · <scan date>
Overall: <grade> (<score>/100) — coverage <n>% (<confidence> confidence)
<if Prowler present: Native <grade>/<score> · Blended (with Prowler) <grade>/<score>>
```

## 2. Executive summary

- Two or three sentences on overall posture in plain language.
- The top 3–5 risks, each framed by business impact (what an attacker gains,
  what a breach costs in trust/compliance terms) — drawn from the highest
  severity `findings` checks and the exposure evidence.
- The single most important next action.
- If the challenge round (section 8) moderated any top risk or left it awaiting
  client input, say so here in one sentence — the summary must not read as more
  certain than the challenged findings support.

## 3. Category scorecard

A table: Category | Sub-score | Grade | One-line status. One row per assessed
category; mark unassessed categories "Not assessed".

## 4. Per-category breakdown

For each assessed category: list its `findings` checks, why they matter
(check-interpretation), and the affected-resource count per check.

## 5. Service exposure

The over-exposed EC2 instances, Lambda functions, databases and the public
entry-point inventory from `analyze_service_exposure`, each with its evidence
chain (e.g. instance → public IP → security group → rule → port).

## 6. Coverage and confidence

Two distinct lists — do not conflate them:
- **Scanned, none found** (`not_applicable`): resources the scanner checked for
  and the account does not have (e.g. "no RDS instances", "no load balancers").
  These are NOT gaps and NOT "usage unknown" — state them plainly as absent.
- **Genuine gaps** (`not_evaluated`): checks whose data was never collected
  (an old scan predating the collector, or a denied permission). List each with
  its `not_evaluated_reason` and what to collect (a fresh scan, or the missing
  permission) to close it.

Only the second list reduces coverage/confidence.

## 7. Prowler corroboration

Only when Prowler ran. Summarise `failed_by_severity`, note where Prowler aligns
with or extends the native findings, and reference `get_prowler_findings` for
detail.

## 8. Challenge and response

The adversarial round from challenge-guide.md, presented so the client sees
their side was argued before the report reached them.

- A table: Finding | Client-side challenge | Disposition | Basis. One row per
  challenged finding; the challenge column carries the strongest good-faith
  objection (with its scan evidence), the disposition is Upheld / Moderated /
  Needs client input, and the basis cites the adjudicating evidence.
- Findings with no credible challenge are listed on one line as such — that is
  assurance, not filler.
- **Open questions for the client**: every "needs client input" disposition,
  each stating the specific fact required and how the answer would change the
  assessment.
- If any disposition is Moderated, close with the adjusted-risk view from
  challenge-guide.md — one clearly-labelled narrative sentence; the rubric
  score and grades above remain exactly as computed.

## 9. Detailed findings appendix

Every finding, grouped by category then severity: `resource_id`, region, the
evidence, and the remediation reference. Mark challenged findings with their
section 8 disposition.

## 10. Prioritised remediation roadmap

All findings ordered by severity then effort, each with its concrete fix from
the playbooks, grouped into Immediate, Short term, and Hardening.
