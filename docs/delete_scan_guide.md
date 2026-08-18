# Delete Scan Guide

## Overview

The `delete-scan` command allows you to remove specific scans and all their associated data from the database. This is particularly useful when:

- Removing failed or incomplete scans
- Deleting old scans before rescanning to fix issues (cost data, SSO data)
- Cleaning up test scans
- Freeing up database space

## Usage

### Interactive Mode (Recommended)

Lists all scans and prompts you to select which one to delete:

```bash
uv run cloudledger delete-scan --database scanner.db
```

**Output:**
```
Available Scans:

╭─────────────────────────────── Scans in Database ───────────────────────────╮
│  # │ Scan ID   │ Account Name        │ Account Number │ Timestamp         │
├────┼───────────┼────────────────────┼───────────────┼──────────────────┤
│  1 │ 2b5d1833…│ FrontierSoftwareOrg│ 663104528399  │ 2025-10-26…      │
│  2 │ 9bca90cd…│ Victor Miloshis    │ 105348353706  │ 2025-10-26…      │
│  3 │ a4983a89…│ AU Hosting         │ 032469871915  │ 2025-10-26…      │
╰────┴───────────┴────────────────────┴───────────────┴──────────────────╯

Enter the number of the scan to delete, or 'q' to quit:
Selection: 2

WARNING: This will permanently delete the following scan:

Scan ID         9bca90cd-1669-4ef4-bfbe-75fad17ba081
Account Name    Victor Miloshis
Account Number  105348353706
Scan Timestamp  2025-10-26 12:34:56
Status          completed

This will delete:
  • Scan metadata
  • All resources collected during this scan
  • Prowler security findings
  • Cost data
  • All other associated data

This operation cannot be undone!

Type 'DELETE' to confirm: DELETE

Deleting scan 9bca90cd-1669-4ef4-bfbe-75fad17ba081...

✓ Scan deleted successfully!

╭─────────────────── Deletion Summary ────────────────────╮
│ Table                    │       Records Deleted │
├──────────────────────────┼──────────────────────┤
│ cost_data                │                   328 │
│ ec2_instances            │                    12 │
│ prowler_findings         │                   523 │
│ scan_metadata            │                     1 │
│ security_groups          │                    45 │
│ vpcs                     │                     8 │
│ … (and other tables)     │                   … │
╰──────────────────────────┴──────────────────────╯

Total records deleted: 1234
```

### Direct Mode (With Scan ID)

Delete a specific scan by providing its scan ID:

```bash
uv run cloudledger delete-scan --database scanner.db --scan-id 9bca90cd-1669-4ef4-bfbe-75fad17ba081
```

This mode still requires confirmation but skips the interactive scan selection.

## Command Options

| Option | Required | Description |
|--------|----------|-------------|
| `--database` | Yes | Path to the SQLite database file |
| `--scan-id` | No | Specific scan ID to delete. If not provided, enters interactive mode |

## Safety Features

### 1. Confirmation Requirement

You must type `DELETE` (all uppercase) to confirm the deletion. Any other input cancels the operation.

```bash
Type 'DELETE' to confirm: delete
Deletion cancelled.
```

### 2. Scan Validation

The command verifies the scan exists before attempting deletion:

```bash
✗ Scan ID 'invalid-scan-id' not found in database.
```

### 3. Clear Warning

Before deletion, you'll see:
- All scan details (account, timestamp, status)
- What data will be deleted
- "This operation cannot be undone!" warning

### 4. Transaction Safety

The deletion uses database transactions to ensure data consistency. Either all related data is deleted, or none is (if an error occurs).

## What Gets Deleted

When you delete a scan, **ALL** associated data is removed:

| Category | Tables |
|----------|--------|
| **Scan Info** | scan_metadata |
| **Security** | prowler_findings |
| **Cost** | cost_data |
| **Compute** | ec2_instances, lambda_functions, ecs_clusters, eks_clusters |
| **Network** | vpcs, subnets, security_groups, route_tables, network_interfaces |
| **Storage** | s3_buckets, ebs_volumes, ebs_snapshots, rds_instances |
| **IAM** | iam_users, iam_roles, iam_policies |
| **DNS** | route53_hosted_zones, route53_record_sets |
| **SSO** | sso_permission_sets, sso_assignments |
| **Organisations** | organizations, organizational_units, organization_accounts |
| **Containers** | ecr_repositories, ecr_images, ecs_services, ecs_task_definitions |
| **Monitoring** | cloudtrail_trails, cloudwatch_log_groups, config_recorders, config_rules |
| **Other** | 30+ additional resource tables |

**Total: 58+ tables** containing all scan-related data.

## Common Use Cases

### Use Case 1: Delete Old Scans Before Rescanning

When you need to rescan accounts to fix issues (like the cost data or SSO bugs):

```bash
# Step 1: List scans to see which are old
uv run cloudledger delete-scan --database scanner.db

# Step 2: Select the old scan to delete (enter number)
Selection: 1

# Step 3: Confirm deletion
Type 'DELETE' to confirm: DELETE

# Step 4: Rescan the account with fresh credentials
uv run cloudledger scan --database scanner.db
```

### Use Case 2: Remove Failed Scans

Delete scans that failed or were interrupted:

```bash
uv run cloudledger delete-scan --database scanner.db

# Look for scans with status "failed" in the list
# Select and delete them
```

### Use Case 3: Clean Up Test Scans

If you were testing the scanner and want to remove test data:

```bash
# Delete multiple test scans one by one
uv run cloudledger delete-scan --database scanner.db
# Repeat for each test scan
```

### Use Case 4: Delete Specific Scan by ID

If you know the exact scan ID to delete (e.g., from MCP query or log):

```bash
uv run cloudledger delete-scan \
  --database scanner.db \
  --scan-id 2b5d1833-7ece-4e72-b7f1-fd53fd1ce8c4
```

## Important Notes

### ⚠️ Cannot Be Undone

Once deleted, scan data **cannot be recovered**. Make sure you've selected the correct scan before confirming.

### ⚠️ MCP Queries Affected

After deleting a scan:
- MCP queries that reference "latest scan" may return different results
- Historical comparisons with deleted scans will fail
- Account summaries may show different data

### ⚠️ Cost/SSO Fix Workflow

For the cost data fix and SSO fix, the recommended workflow is:

1. **Delete old incorrect scans** using this command
2. **Rescan accounts** with fixed code to get correct data
3. **Verify** the new data is correct

Alternative workflow (keeps historical data):
1. **Keep old scans** in database
2. **Rescan accounts** with fixed code
3. **MCP queries** will automatically use the latest scan

### ℹ️ Database Size

Deleting scans will reduce database file size, but SQLite doesn't automatically reclaim the space. To actually shrink the database file:

```bash
# After deleting scans, vacuum the database
sqlite3 scanner.db "VACUUM;"
```

## Troubleshooting

### Error: "no such table: sqlite_sequence"

This is a harmless internal SQLite error and can be ignored. The deletion still completed successfully.

### Error: "database is locked"

Another process (like the MCP server) is using the database. Close all connections and try again:

1. Quit Claude Desktop (if MCP server is running)
2. Close any database browser tools
3. Try the delete command again

### Scan appears in list but deletion fails

Check that:
1. You have write permissions to the database file
2. The database file is not read-only
3. No other processes are using the database

## Technical Details

### Database Operation

The `delete_scan()` method:
1. Validates scan exists
2. Enables foreign key constraints
3. Deletes records from 58+ tables (in order)
4. Deletes scan metadata last
5. Commits transaction
6. Returns deletion counts

### Performance

Deletion speed depends on:
- Number of records in the scan (larger scans take longer)
- Database file size
- Disk speed

Typical deletion times:
- Small scan (100-1000 records): 1-2 seconds
- Medium scan (1000-10000 records): 2-5 seconds
- Large scan (10000+ records): 5-10 seconds

## See Also

- **docs/cost_data_fix.md** - Why you might need to delete old cost data
- **docs/sso_fix.md** - Why you might need to delete old SSO data
- **docs/scanner_usage.md** - How to run scans
- **docs/mcp_setup.md** - How MCP queries use scan data
