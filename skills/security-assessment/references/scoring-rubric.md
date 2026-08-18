# Scoring rubric

Apply this exactly. The same scan MUST always produce the same score. Server
severities are advisory facts; this rubric turns them into a score. Show your
working in the report.

## 1. Category weights (sum to 100)

| Category | Weight |
|---|---|
| identity_access | 25 |
| network_exposure | 20 |
| data_protection | 20 |
| service_exposure | 20 |
| logging_monitoring | 15 |

## 2. Per-category score

Each category starts at 100. For every check in that category whose `status`
is `findings`, subtract by its `default_severity`:

| Severity | Deduction |
|---|---|
| critical | 40 |
| high | 25 |
| medium | 12 |
| low | 5 |
| informational | 0 |

Rules:
- The check is the unit, not the individual finding. A check with 40 affected
  resources deducts the same as one with 1 — but state the resource count in
  the report narrative.
- `clean` checks deduct nothing. `not_applicable` checks (the collector ran and
  the account has none of the resource — "scanned, none found") deduct nothing
  and count as covered. `not_evaluated` checks (the data was never collected)
  deduct nothing and reduce coverage (see section 5).
- Informational checks never deduct; they are inventory.
- Floor each category at 0.

category_score = max(0, 100 − sum of deductions for that category's `findings` checks)

## 3. Overall score

overall = weighted average of assessed category scores, using the weights above.

- A category with zero evaluated checks (every check `not_evaluated`) is
  "Not assessed": exclude it and renormalise the remaining weights so they sum
  to 100. Never treat it as 100.
- Round the overall to the nearest whole number for the headline; keep one
  decimal in the working.

## 4. Grades

| Score | Grade |
|---|---|
| 90–100 | A |
| 80–89 | B |
| 70–79 | C |
| 60–69 | D |
| below 60 | F |

Apply the same bands to category sub-scores.

## 5. Coverage and confidence

- applicable_checks = total checks from `get_security_check_catalogue`.
- evaluated_checks = checks with status `findings`, `clean`, or
  `not_applicable`. A `not_applicable` check WAS evaluated — the scanner ran the
  collector and the account simply has none of that resource, so it counts as
  covered, not a gap.
- coverage = evaluated_checks ÷ applicable_checks, as a percentage.
- Only `not_evaluated` checks (data never collected — an old scan or a denied
  permission) reduce coverage.
- Confidence: High ≥ 90%, Medium 70–89%, Low < 70%.
- Coverage NEVER changes the score. It qualifies it. Always print it on the
  score line, e.g. `B (82/100) — coverage 76% (Medium confidence); 7 checks not evaluated`.
- Do NOT report a `not_applicable` check as a gap or as "usage unknown". State
  it as "scanned; none found" — e.g. "no RDS instances in this account". The
  server's `not_applicable_reason` gives the exact wording.

## 6. Prowler blending

Only when `prowler.available` is true. Always report BOTH the native score
(sections 2–3, Prowler excluded) and the blended score, so scores stay
comparable across scans.

Blended: for each category, add a Prowler deduction from Prowler `FAIL`
findings of severity critical or high that map to that category, capped at 10
points per category. Map Prowler findings to categories by service family:

| Prowler service family (prefix) | Category |
|---|---|
| iam, organizations, accessanalyzer | identity_access |
| ec2 (security groups), vpc | network_exposure |
| s3, rds, ebs, efs, kms, dynamodb, backup | data_protection |
| cloudtrail, guardduty, securityhub, config, cloudwatch | logging_monitoring |
| elb, elbv2, apigateway, apigatewayv2, cloudfront, lambda | service_exposure |

Prowler findings that do not map go into a general note in the Prowler section,
not a deduction. Recompute the overall with the blended category scores. Label
each number clearly as "native" or "blended (with Prowler)".

## 7. Worked example

Assessed data (abbreviated):
- identity_access: `identity.root_mfa_disabled` findings (critical, −40);
  `identity.stale_access_keys` findings (medium, −12). Others clean.
  → 100 − 40 − 12 = 48 (grade F).
- network_exposure: all clean → 100 (A).
- data_protection: `data.s3_public_buckets` findings (critical, −40) → 60 (D).
- service_exposure: `exposure.ec2_public_instances` findings (high, −25) → 75 (C).
- logging_monitoring: every check `not_evaluated` → Not assessed, excluded.

Renormalise weights across the four assessed categories
(25 + 20 + 20 + 20 = 85):
- identity 25/85 = 0.294; network 0.235; data 0.235; service 0.235.

overall = 48(0.294) + 100(0.235) + 60(0.235) + 75(0.235)
        = 14.1 + 23.5 + 14.1 + 17.6 = 69.3 → 69 (grade D).

coverage: say 22 of 29 checks evaluated = 76% (Medium confidence).

Score line: `D (69/100) — coverage 76% (Medium confidence); logging_monitoring not assessed (7 checks not evaluated)`.
