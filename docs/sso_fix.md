# AWS SSO/Identity Centre Fix

## Issue Discovered: 2025-10-27

### The Problem

AWS SSO/Identity Centre permission sets and assignments were **not being collected** during scans, resulting in empty SSO tables in the database.

**User Impact:** When asking Claude.ai questions like "give me a breakdown of the permission sets for FrontierSoftwareOrg", it reported no SSO data found, despite the account having 10 permission sets configured in Identity Centre.

### Root Causes

Two bugs prevented SSO data collection:

#### Bug 1: Hardcoded Region (Primary Issue)

```python
# OLD CODE (WRONG):
sso_client = self.session.client('sso-admin', region_name='us-east-1')
instances_response = sso_client.list_instances()
```

**The Problem:**
- AWS Identity Centre has a "home region" where it's configured
- The instance only appears in API calls to that specific region
- Scanner was hardcoded to look in `us-east-1`
- User's Identity Centre is actually in `ap-southeast-2` (Sydney)
- Result: Found 0 instances, collected 0 permission sets

**Evidence:**
```
Testing SSO in us-east-1... Found 0 instance(s)
Testing SSO in ap-southeast-2... Found 1 instance(s)!
  Permission Sets:
    - AWSReadOnlyAccess
    - Audit-enhanced
    - DevSystemTeam
    - AWSServiceCatalogAdminFullAccess
    - BillingReadOnly
    - UKAWSConsultants
    - AWSAdministratorAccess
    - UKAWSsupport
    - AWSPowerUserAccess
    - AWSServiceCatalogEndUserAccess
```

#### Bug 2: Incorrect Field Names

```python
# OLD CODE (WRONG):
assignment = SSOAssignment(
    scan_id=self.scan_id,
    instance_arn=instance_arn,
    permission_set_arn=ps_arn,
    account_id=account_id,  # ❌ Field doesn't exist in model
    principal_type=assignment_data['PrincipalType'],
    principal_id=assignment_data['PrincipalId'],
    raw_data=assignment_data
)
```

**The Problem:**
- SSOAssignment model expects `target_type` and `target_id` fields
- Collector was passing `account_id` (which doesn't exist)
- Would have caused Pydantic validation errors even if region was correct

### The Fixes (Commit 0a25247)

#### Fix 1: Auto-detect SSO Region

```python
# NEW CODE (CORRECT):
priority_regions = ['ap-southeast-2', 'us-east-1', 'us-west-2', 'eu-west-1']

logger.info("Auto-detecting AWS Identity Centre region...")

for region in priority_regions:
    try:
        test_client = self.session.client('sso-admin', region_name=region)
        response = test_client.list_instances()
        found_instances = response.get('Instances', [])

        if found_instances:
            sso_region = region
            sso_client = test_client
            instances = found_instances
            logger.info(f"Found Identity Centre instance in region: {region}")
            break
    except ClientError as e:
        logger.debug(f"No Identity Centre instance in {region}")
        continue

if not sso_region:
    logger.warning("No AWS Identity Centre instance found in common regions")
    return permission_sets, assignments
```

**Benefits:**
- ✅ Works for any region where Identity Centre is configured
- ✅ Tries most common regions first for performance
- ✅ Logs detected region for troubleshooting
- ✅ Gracefully handles accounts without Identity Centre

#### Fix 2: Correct Field Names

```python
# NEW CODE (CORRECT):
assignment = SSOAssignment(
    scan_id=self.scan_id,
    instance_arn=instance_arn,
    permission_set_arn=ps_arn,
    target_type='AWS_ACCOUNT',  # ✅ Correct field name
    target_id=account_id,       # ✅ Correct field name
    principal_type=assignment_data['PrincipalType'],
    principal_id=assignment_data['PrincipalId'],
    raw_data=assignment_data
)
```

**Benefits:**
- ✅ Matches SSOAssignment model schema
- ✅ No validation errors
- ✅ Data properly stored in database

### Required Action: Rescan Management Account

**You MUST rescan the FrontierSoftwareOrg account** to collect SSO data.

#### Why Only This Account?

AWS SSO/Identity Centre is a **centralised service** that exists only in the AWS Organisations management account. Member accounts don't have their own SSO instances - they inherit access through the management account's Identity Centre.

#### Steps to Rescan:

1. **Rescan FrontierSoftwareOrg only:**
   ```bash
   cd C:\PycharmProjects\cloudledger
   uv run cloudledger scan

   # When prompted:
   Account name: FrontierSoftwareOrg
   Account number: 663104528399
   # Enter fresh ASIA credentials from AWS Access Portal
   ```

2. **Verify SSO data collected:**
   ```bash
   python check_tables.py
   ```

   Should show:
   ```
   sso_permission_sets     10 rows (or more)
   sso_assignments         XX rows (varies by configuration)
   ```

3. **Test with Claude.ai:**
   Ask: "Can you give me a breakdown of the permission sets for FrontierSoftwareOrg?"

   Should now show all 10 permission sets with details.

### Expected Results After Rescan

**Permission Sets (minimum expected):**
- AWSReadOnlyAccess
- Audit-enhanced
- DevSystemTeam
- AWSServiceCatalogAdminFullAccess
- BillingReadOnly
- UKAWSConsultants
- AWSAdministratorAccess
- UKAWSsupport
- AWSPowerUserAccess
- AWSServiceCatalogEndUserAccess

**Assignments:**
Will show which users/groups have which permission sets in which accounts.

### Impact on MCP Queries

After rescanning, these MCP queries will now work properly:

✅ **get_sso_permissions** - Shows all permission sets and their configurations
✅ **Query about permission sets** - "What permission sets exist?"
✅ **Query about assignments** - "Which users have admin access?"
✅ **Query about accounts** - "Which permission sets are assigned to account X?"

### Why This Wasn't Caught Earlier

1. **Silent Failure**: The collect_sso() method catches exceptions and logs warnings, but continues. Without log files visible, the failure was invisible.

2. **No Data Validation**: The scanner didn't verify that SSO data was collected. It silently stored 0 permission sets without warning.

3. **Regional Assumption**: The original implementation assumed all Identity Centre instances would be in us-east-1 (common for global AWS services, but not for Identity Centre).

4. **Limited Testing**: Initial testing was done in us-east-1 region, which worked for those test accounts but failed for Australian organisations using ap-southeast-2.

### Diagnostic Tools Created

Several diagnostic scripts were created to help troubleshoot this issue:

1. **test_sso_access.py** - Tests basic SSO API access
2. **find_sso_region.py** - Auto-detects Identity Centre home region
3. **debug_sso.py** - Analyses SSO data in database
4. **check_tables.py** - Lists all tables and row counts

These tools remain available for future troubleshooting.

### Prevention

To prevent similar issues in future:

1. ✅ **Region Auto-detection**: Now standard for SSO collection
2. ✅ **Better Logging**: Region detection is logged
3. ✅ **Diagnostic Tools**: Available for troubleshooting
4. ⚠ **TODO**: Add data collection validation to verify expected resources were collected
5. ⚠ **TODO**: Add summary showing what was/wasn't collected at end of scan

### Related Issues

This fix complements the earlier cost data fix (commit aed3803). Both issues involved:
- AWS API behaviour that varies by region or account type
- Silent failures during data collection
- Required rescanning to fix

### Technical Details

**AWS Identity Centre Architecture:**
- Global service with a single "home region" per organisation
- Instance ARN format: `arn:aws:sso:::instance/ssoins-XXXXXXXXXXXX`
- API calls must be made to the home region
- Common home regions: ap-southeast-2 (AU), us-east-1 (US), eu-west-1 (EU)

**SSO Data Model:**
- **sso_permission_sets**: Defines roles with policies
- **sso_assignments**: Maps permission sets to principals (users/groups) in specific accounts
- **Instance ARN**: Identifies the Identity Centre instance
- **Identity Store ID**: Links to the identity source (users/groups)

### References

- AWS Identity Centre API: https://docs.aws.amazon.com/singlesignon/latest/APIReference/welcome.html
- SSO Admin API: https://docs.aws.amazon.com/singlesignon/latest/APIReference/API_Operations_AWS_SSO_Admin.html
- Identity Centre Regions: https://docs.aws.amazon.com/singlesignon/latest/userguide/regions.html

### Support

If SSO data still doesn't appear after rescanning:

1. **Run diagnostic:**
   ```bash
   python find_sso_region.py
   ```

2. **Check Identity Centre is enabled:**
   - Log into AWS Console → IAM Identity Centre
   - Verify it's enabled and showing permission sets

3. **Verify credentials have permissions:**
   Required: `sso:ListInstances`, `sso:ListPermissionSets`, `sso:DescribePermissionSet`, `sso:ListAccountAssignments`

4. **Check scan logs:**
   Look for "Auto-detecting AWS Identity Centre region..." and "Found Identity Centre instance in region: X"

5. **Report issue** with diagnostic output
