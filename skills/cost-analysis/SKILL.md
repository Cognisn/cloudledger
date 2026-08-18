---
name: cost-analysis
description: Analyse AWS spend for scanned accounts — cost breakdown by service and account, trends over time, and a forward forecast — using the CloudLedger server. Use when the user asks what an account costs, which services or accounts drive spend, how costs are trending, or wants a cost breakdown, cost report, or spend forecast from scan data. Requires the CloudLedger MCP server. Trigger: /cost-analysis.
---

# Cost analysis

Turn the scanner's collected billing data into a cost breakdown and a forward
forecast. The scanner collects up to 12 months of Cost Explorer history per
account, which is what makes both possible.

## Tools

- `get_total_cost` — total spend across accounts, with per-account totals and
  AWS Organizations context.
- `get_cost_by_service` — spend broken down by AWS service.
- `get_cost_trends` — month-by-month history (the basis for the forecast).
- `get_cost_comparison` — compare spend between two periods or scans.
- `get_organizations_cost_breakdown` — **use this in Organizations/Control Tower
  environments** when asked which account costs the most: it separates the
  master/payer account's direct costs from member-account usage, avoiding the
  common trap where the payer account appears to dominate.

## Workflow

### 1. Scope

Confirm which account(s) and time range the user means. Use `list_scans` /
`get_scan_summary` to identify the account. State the account and the period the
data covers before presenting numbers.

### 2. Breakdown

- Headline: `get_total_cost` for the overall figure and per-account split.
- By service: `get_cost_by_service` — report the top services by spend and what
  share each represents.
- Multi-account / Organizations: prefer `get_organizations_cost_breakdown` for
  "which account costs the most", and explain the master-vs-member distinction
  it returns.
- Change over time: `get_cost_comparison` when the user wants period-over-period.

Always state the currency (the tools return it) and the exact months covered.

### 3. Trend and forecast

- Call `get_cost_trends` for the monthly series (`trends`, `month_count`).
- Describe the trend: rising, falling, flat, seasonal, or spiky.
- **Forecast** from the history — the server does not forecast, so you compute
  it and show your method:
  - Use a simple, stated method: a 3-month trailing average for a stable series,
    or a linear projection of the last several months for a clear trend.
  - Project the next 1–3 months and give a range, not false precision.
  - State every assumption (method, months used, that it extrapolates past
    usage and ignores planned changes, Reserved Instance/Savings Plan expiry,
    and one-off charges).
  - Call out anything that undermines the forecast: too few months of data
    (say so and widen the range), a large one-off spike, or an obvious step
    change. If there are fewer than three months of history, do not forecast —
    report the trend only and say why.

### 4. Report

Present: the total and period; a by-service (and, if relevant, by-account)
breakdown with shares; the trend; and the forecast with its method, range, and
assumptions. Flag the biggest cost drivers and, if asked, point to
`find_unused_resources` and `find_vpc_endpoint_opportunities` for savings leads.

## What not to do

- Do not present a forecast as a certainty; always give a range and the method.
- Do not forecast from fewer than three months of data.
- Do not mix currencies or periods without labelling them.
- In Organizations environments, do not report the payer account's consolidated
  total as if it were its own usage — use `get_organizations_cost_breakdown`.
