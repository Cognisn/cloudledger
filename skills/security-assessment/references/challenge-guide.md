# Challenge guide

The assessment must not be one-sided. Before delivery, adopt the perspective
of the client whose environment was assessed — the people who built it, know
why it looks the way it does, and will push back on findings they believe are
wrong, mitigated, or deliberate. Argue their side in good faith, then
adjudicate each challenge on the evidence.

## What to challenge

- Every `findings` check with `default_severity` critical or high.
- Every over-exposed resource and public entry point reported by
  `analyze_service_exposure`.
- Any medium finding that made the executive summary's top risks.
- Low and informational findings only where the evidence looks contradictory.

## The lenses

Raise, for each finding in scope, the strongest available challenge through
these lenses. Use as many as genuinely apply; skip lenses with nothing behind
them.

1. **False positive** — does the evidence chain actually demonstrate the
   claim? A security group open to the world matters differently if nothing is
   attached to it; an "exposed" instance without a public IP or route is not
   reachable.
2. **Compensating control** — does other data in the same scan mitigate the
   finding? Account-level public-access blocks over a "public" bucket policy,
   an instance profile constraining leaked-credential blast radius, MFA on the
   affected principals, flow logging over an unlogged VPC.
3. **Intentional design** — is the flagged state plausibly deliberate and
   sanctioned? Bastion hosts, NAT and edge appliances, public static-site
   buckets, deliberately public APIs. Look for signals in the scan data:
   names, tags, instance roles, the surrounding architecture.
4. **Staleness** — is the scan old enough that the finding may no longer
   describe the environment? Compare the scan timestamp (UTC) with the
   assessment date and say so where the gap is material.
5. **Materiality** — is the stated business impact right for this account's
   apparent purpose? A sandbox or workload-isolated account (naming,
   organisation position, resource mix) does not carry production impact
   framing.

## Evidence standard

Every challenge must cite scan data: resource identifiers, fields, tags,
evidence chains, or the scan timestamp. Never invent client facts, business
context, or undocumented controls. If the strongest challenge depends on
something only the client can know, do not guess — the disposition is
**needs client input** and the challenge becomes an open question stating
exactly what answer would change the assessment.

## Dispositions

Adjudicate every challenge to one of three outcomes:

- **Upheld** — the challenge fails; the finding stands. Record the rebuttal so
  the client sees their objection was considered and why it does not hold.
- **Moderated** — the challenge partially succeeds on scan evidence. The
  finding stays in the report and the score, but its narrative severity and
  business-impact framing are tempered, with the reason stated.
- **Needs client input** — unresolvable from scan data. List it under open
  questions with the specific fact required and the effect each answer would
  have.

## Honesty rules

- Challenge in good faith with the strongest argument available; never
  manufacture a weak challenge to appear balanced.
- If no credible challenge exists, write "no credible challenge" — that is
  itself assurance, not a gap in the round.
- The client-advocate voice must never water down a genuine critical. An
  upheld critical stays a critical, stated plainly.

## The score never moves

Dispositions annotate; they do not recompute. The rubric score, grades, and
coverage are untouched by this round — that is the determinism contract. Where
moderated dispositions exist, present an **adjusted-risk view** alongside the
unchanged score: one sentence noting how many score-driving findings were
moderated and the net effect on practical risk, clearly labelled as narrative
judgement, not a score.
