# Cost Data Collection Fix

## Critical Bug Discovered: 2025-10-26

### The Problem

Cost data collection was returning **incorrect, inflated costs** due to AWS Cost Explorer returning consolidated billing data instead of per-account costs.

### Symptoms

When comparing scanner database costs to AWS Console Cost Explorer:

| Account | AWS Console (Correct) | Scanner DB (Incorrect) | Difference |
|---------|----------------------|------------------------|------------|
| FrontierSoftwareOrg | $87,911.19 | $820,404.80 | +$732,493 ❌ |
| Victor Miloshis | $462,062.66 | $428,533.99 | -$33,529 ❌ |
| **TOTAL** | **$873,708.55** | **$1,535,409.90** | **+$661,701** ❌ |

### Root Cause

The `collect_cost_data()` function in `src/cloudledger/scanner/aws_collector.py` was calling AWS Cost Explorer API **without filtering by account**:

```python
# OLD CODE (WRONG):
response = ce_client.get_cost_and_usage(
    TimePeriod={...},
    Granularity='MONTHLY',
    Metrics=['UnblendedCost'],
    GroupBy=[{'Type': 'DIMENSION', 'Key': 'SERVICE'}]
)
# No Filter parameter! ❌
```

**What Happened:**
1. When scanning the **master/payer account** (FrontierSoftwareOrg) with its credentials, Cost Explorer returned **ALL Organisation accounts' costs** (consolidated billing view)
2. The scanner stored this consolidated total ($820K) as FrontierSoftwareOrg's costs
3. When scanning **member accounts**, some costs were also returned, causing duplicates
4. Both FrontierSoftwareOrg and Victor Miloshis showed identical $232K WorkSpaces costs (clear duplicate)
5. Total costs in database ($1.5M) were **76% higher** than actual costs ($873K)

### The Fix (Commit aed3803)

Added `Filter` parameter to explicitly request costs for only the scanned account:

```python
# NEW CODE (CORRECT):
response = ce_client.get_cost_and_usage(
    TimePeriod={...},
    Granularity='MONTHLY',
    Metrics=['UnblendedCost'],
    Filter={
        'Dimensions': {
            'Key': 'LINKED_ACCOUNT',
            'Values': [account_number]  # ✅ Filter by this account only
        }
    },
    GroupBy=[{'Type': 'DIMENSION', 'Key': 'SERVICE'}]
)
```

This ensures:
- Each scan collects costs **only for that specific account**
- No consolidated billing data is included
- No duplicate costs across accounts
- Accurate per-account cost attribution

### Required Action: RESCAN ALL ACCOUNTS

**You MUST rescan all AWS accounts** for accurate cost data.

#### Steps:

1. **Back up current database** (optional, for comparison):
   ```bash
   cp scanner.db scanner.db.old
   ```

2. **Delete old cost data** (optional - or just rescan and queries will use latest scan):
   ```bash
   python -c "import sqlite3; conn = sqlite3.connect('scanner.db'); conn.execute('DELETE FROM cost_data'); conn.commit()"
   ```

3. **Rescan all accounts**:
   ```bash
   uv run cloudledger scan
   # Enter credentials for ALL accounts in your Organisation
   ```

4. **Verify the fix**:
   After rescanning, check costs match AWS Console:
   ```python
   python debug_costs.py
   ```

### Expected Results After Rescanning

| Account | Expected Cost (from AWS Console) |
|---------|----------------------------------|
| Victor Miloshis | ~$462,000 |
| AU Hosting Services | ~$141,000 |
| UK-Production | ~$114,000 |
| FrontierSoftwareOrg | ~$87,900 |
| AU Network Control | ~$26,000 |
| UK-Network-Control | ~$22,000 |
| Others | <$100 each |
| **TOTAL** | **~$873,700** |

### Impact on MCP Queries

The cost-related MCP queries were returning incorrect data:

- ✅ **get_total_cost** - Now returns accurate per-account costs
- ✅ **get_cost_by_service** - Now shows correct service costs per account
- ✅ **get_organizations_cost_breakdown** - Now correctly identifies highest-cost member account
- ✅ **get_cost_trends** - Historical trends now accurate

### Validation

To verify the fix is working after rescanning:

1. **Check FrontierSoftwareOrg costs**:
   - Should be ~$87,911 (not $820K)
   - Top service should match AWS Console breakdown

2. **Check Victor Miloshis costs**:
   - Should be ~$462,062 (not $428K)
   - No duplicate WorkSpaces costs with FrontierSoftwareOrg

3. **Check Organisation total**:
   - Should be ~$873,708 (not $1.5M)

4. **No duplicate services**:
   - No two accounts should show identical costs for the same service (especially WorkSpaces)

### Technical Details

**AWS Cost Explorer Behaviour:**

When querying Cost Explorer API:
- **Without Filter**: Returns consolidated billing data (all accounts) when called from master/payer account
- **With Filter (LINKED_ACCOUNT)**: Returns only the specified account's costs

**Why This Matters for AWS Organisations:**

In AWS Organisations with consolidated billing:
- The master/payer account **receives the invoice** for all accounts
- But each account's **usage is tracked separately**
- Cost Explorer can show either:
  - **Consolidated view**: All accounts' costs (requires LINKED_ACCOUNT grouping)
  - **Single account view**: One account's costs (requires LINKED_ACCOUNT filtering)

Our scanner scans accounts individually, so we need the **single account view** with filtering.

### Lessons Learnt

1. **Always filter Cost Explorer queries by account** when scanning individual accounts in an Organisation
2. **Validate cost data against AWS Console** to catch discrepancies early
3. **Check for duplicate costs across accounts** (identical service costs in multiple accounts is a red flag)
4. **AWS Cost Explorer defaults to consolidated view** when accessed from master/payer account

### Related Documentation

- AWS Cost Explorer API: https://docs.aws.amazon.com/aws-cost-management/latest/APIReference/API_GetCostAndUsage.html
- Filtering by Linked Account: https://docs.aws.amazon.com/aws-cost-management/latest/APIReference/API_DimensionValues.html
- AWS Organisations Consolidated Billing: https://docs.aws.amazon.com/awsaccountbilling/latest/aboutv2/consolidated-billing.html

### Support

If you encounter issues after rescanning:
- Check `cloudledger.log` for errors during cost collection
- Run `python debug_costs.py` to analyse the database
- Compare against AWS Console Cost Explorer (filter by account)
- Report issues at: https://github.com/Cognisn/cloudledger/issues
