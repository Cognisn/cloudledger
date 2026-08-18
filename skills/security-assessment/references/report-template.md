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

## 8. Detailed findings appendix

Every finding, grouped by category then severity: `resource_id`, region, the
evidence, and the remediation reference.

## 9. Prioritised remediation roadmap

All findings ordered by severity then effort, each with its concrete fix from
the playbooks, grouped into Immediate, Short term, and Hardening.
