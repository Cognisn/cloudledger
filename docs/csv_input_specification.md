# CSV Input Specification

This document describes the CSV file format for batch scanning multiple AWS accounts.

## Overview

The CSV input feature allows you to scan multiple AWS accounts without manual credential entry for each account. This is particularly useful for:

- Scanning many accounts (10+)
- Automated/scheduled scanning
- Consistent Prowler scan levels across accounts
- Reproducible scan configurations

## CSV File Format

### Required Columns

The CSV file must include the following columns (order doesn't matter):

| Column Name | Type | Description | Example |
|------------|------|-------------|---------|
| `account_name` | String | Friendly name for the account | "Production Account" |
| `account_number` | String | 12-digit AWS account ID | "123456789012" |
| `access_key_id` | String | AWS access key ID (starts with ASIA for temporary creds) | "ASIAIOSFODNN7EXAMPLE" |
| `secret_access_key` | String | AWS secret access key | "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" |
| `session_token` | String | AWS session token (required for temporary credentials) | "IQoJb3JpZ2luX2VjEH..." |

### Optional Columns

| Column Name | Type | Description | Valid Values |
|------------|------|-------------|--------------|
| `prowler_level` | String | Prowler scan level | "1", "2", "3", "skip", or empty |

## Prowler Scan Levels

- **1**: Basic security checks (fastest)
- **2**: Standard compliance checks (CIS Benchmarks)
- **3**: Comprehensive security assessment (slowest)
- **skip** or empty: No Prowler scan

## Example CSV File

```csv
account_name,account_number,access_key_id,secret_access_key,session_token,prowler_level
Production Account,123456789012,ASIAIOSFODNN7EXAMPLE,wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY,IQoJb3JpZ2luX2VjEHoaCXVzLXdlc3QtMiJHMEUCIQD...,2
Development Account,987654321098,ASIAJKLMNOPQRSTUVWX,anotherSecretKeyExample1234567890abcdefghij,IQoJb3JpZ2luX2VjEHoaCXVzLXdlc3QtMiJHMEUCIQA...,1
Test Account,567890123456,ASIAQWERTYUIOPASDFG,testSecretKeyExample9876543210zyxwvutsrq,IQoJb3JpZ2luX2VjEHoaCXVzLXdlc3QtMiJHMEUCIQB...,skip
```

## Creating a CSV File

### Method 1: Generate Template

Use the CLI to generate an example CSV file:

```bash
uv run cloudledger create-example-csv --output my_accounts.csv
```

This creates a template file with sample data that you can modify.

### Method 2: Manual Creation

Create a CSV file using any text editor or spreadsheet application:

1. **Using a text editor**:
   ```csv
   account_name,account_number,access_key_id,secret_access_key,session_token,prowler_level
   My Account,123456789012,ASIA...,secret...,token...,2
   ```

2. **Using Excel/Google Sheets**:
   - Create columns with the required headers
   - Fill in account information
   - Export as CSV

### Method 3: From AWS Access Portal

If you're using AWS IAM Identity Centre (formerly AWS SSO):

1. Log into AWS Access Portal
2. For each account, copy the temporary credentials
3. Paste into your CSV file

**Tip**: Create a template with account names and numbers pre-filled, leaving credential columns empty. Fill in credentials just before scanning.

## Validation Rules

### Account Name
- **Cannot be empty**
- Accepts any string value
- Used for display and logging only

### Account Number
- **Must be exactly 12 digits**
- No hyphens or spaces
- Example: `123456789012`

### Access Key ID
- **Cannot be empty**
- Typically starts with `AKIA` (long-term) or `ASIA` (temporary)
- Example: `ASIAIOSFODNN7EXAMPLE`

### Secret Access Key
- **Cannot be empty**
- 40-character alphanumeric string
- Example: `wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY`

### Session Token
- **Required for temporary credentials**
- Long base64-encoded string
- Cannot be empty when using ASIA credentials
- Example: `IQoJb3JpZ2luX2VjEHoaC...` (usually 500+ characters)

### Prowler Level
- **Optional**
- Must be one of: `1`, `2`, `3`, `skip`, or empty
- Case-insensitive
- Invalid values will cause scan to fail for that account

## Security Best Practices

### File Permissions

Restrict access to the CSV file as it contains sensitive credentials:

```bash
# Linux/macOS
chmod 600 accounts.csv

# Windows (PowerShell)
icacls accounts.csv /inheritance:r /grant:r "${env:USERNAME}:F"
```

### Secure Storage

- **Never commit CSV files to version control**
- Store in encrypted filesystem or secure vault
- Delete after use if credentials are short-lived
- Use temporary credentials (ASIA) whenever possible

### Credential Lifecycle

1. Generate temporary credentials from AWS Access Portal
2. Create CSV file
3. Run scan immediately (credentials expire in 1-12 hours)
4. Delete CSV file after scan completes

## Using CSV for Scanning

### Basic Usage

```bash
uv run cloudledger scan \
    --database /path/to/scanner.db \
    --csv accounts.csv
```

### With Specific Regions

```bash
uv run cloudledger scan \
    --database /path/to/scanner.db \
    --csv accounts.csv \
    --regions us-east-1,us-west-2
```

### With Debug Logging

```bash
uv run cloudledger scan \
    --database /path/to/scanner.db \
    --csv accounts.csv \
    --log-level DEBUG
```

## Error Handling

### CSV Parsing Errors

If the CSV file has errors, the scanner will display:
- Row number where error occurred
- Type of error (missing column, invalid format, etc.)
- Specific validation failure

Example error:
```
Error on row 3: account_number must be exactly 12 digits, got: 12345
```

### Credential Errors

If credentials are invalid:
- Error is logged for that specific account
- Scanner continues with remaining accounts
- Summary report shows which accounts failed

### Partial Success

The scanner processes accounts sequentially. If one account fails:
- The error is logged
- Processing continues with the next account
- Final summary shows successes and failures

## CSV File Limits

- **Maximum file size**: No hard limit, but keep reasonable (<10MB)
- **Maximum accounts**: No hard limit, but consider:
  - Scan duration (each account takes 10-30 minutes)
  - Database size growth
  - System resources

## Troubleshooting

### "CSV file not found"
- Check file path is correct
- Use absolute paths for clarity
- Verify file extension is `.csv`

### "Missing required columns"
- Ensure all required columns are present
- Check column name spelling (case-sensitive)
- Remove any extra spaces in column names

### "Invalid data on row X"
- Check that row for empty required fields
- Verify account number is 12 digits
- Ensure prowler_level is valid value

### "Credentials do not match account number"
- Verify you copied credentials for the correct account
- Check session token hasn't expired
- Ensure account number is correct

## Example Workflows

### Workflow 1: Monthly Security Scan

```bash
# 1. Generate template
uv run cloudledger create-example-csv --output monthly_scan.csv

# 2. Fill in account details (keep credentials empty)
# 3. On scan day, add temporary credentials
# 4. Run scan
uv run cloudledger scan --database scans.db --csv monthly_scan.csv

# 5. Delete CSV file
rm monthly_scan.csv
```

### Workflow 2: Continuous Compliance

```bash
# Use automation tool to:
# 1. Fetch temporary credentials from credential provider
# 2. Generate CSV programmatically
# 3. Run scanner
# 4. Clean up CSV file
# 5. Process scan results
```

## Integration with Other Tools

### AWS SSO Credential Helper

Create a script to automatically populate CSV from AWS SSO:

```python
# Example helper script
import boto3
import csv

accounts = [
    {'name': 'Production', 'id': '123456789012'},
    {'name': 'Development', 'id': '987654321098'},
]

# Get credentials for each account via SSO
# Write to CSV file
```

### Secrets Manager

Store account numbers and names in AWS Secrets Manager:
- Fetch list of accounts
- Combine with temporary credentials
- Generate CSV for scanning

## Next Steps

- Review [Scanner Usage Guide](scanner_usage.md)
- Learn about [MCP Server Setup](mcp_setup.md)
- Understand [Database Schema](database_schema.md)
