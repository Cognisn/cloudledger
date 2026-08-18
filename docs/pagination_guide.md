# Query Pagination Guide

## Overview

To handle large datasets and prevent Claude.ai from exceeding the 1MB response limit, the MCP server now supports **pagination** and **summary mode** for queries that return large amounts of data.

## Features

### 1. Pagination

Break large result sets into manageable pages.

**Parameters:**
- `limit` (integer): Maximum number of results to return (default: 100, max: 1000)
- `offset` (integer): Number of results to skip (default: 0)

**Example Queries:**

```
Get first 50 EC2 instances:
- limit: 50
- offset: 0

Get next 50 EC2 instances:
- limit: 50
- offset: 50

Get Prowler findings 100-200:
- limit: 100
- offset: 100
```

### 2. Summary Mode

Get aggregated counts instead of full details when you only need statistics.

**Parameter:**
- `summary_mode` (boolean): Return only counts and aggregates (default: false)

**Example Queries:**

```
Get EC2 instance counts by region (not full details):
- summary_mode: true

Get Prowler finding counts by severity:
- summary_mode: true
```

## Supported Queries

Currently, pagination and summary mode are implemented for:

1. **find_public_ec2_instances** - EC2 instance data
2. **get_prowler_findings** - Security findings (can be thousands)

More queries will be updated as needed.

## Response Format

### Paginated Response

When pagination is used, responses include metadata:

```json
{
  "instances": [...],  
  "count": 100,
  "pagination": {
    "total_count": 523,
    "limit": 100,
    "offset": 0,
    "returned_count": 100,
    "has_more": true,
    "next_offset": 100
  },
  "warnings": [
    "Large dataset (523 total records). Showing 100 records starting at offset 0..."
  ]
}
```

### Summary Mode Response

```json
{
  "summary": {
    "total_instances": 523,
    "by_region": {
      "us-east-1": 234,
      "us-west-2": 156,
      "eu-west-1": 133
    }
  },
  "mode": "summary"
}
```

## Usage Examples in Claude Desktop

### Example 1: Basic Pagination

User: "Show me EC2 instances, but only 20 at a time"

Claude calls: `find_public_ec2_instances` with `{"limit": 20, "offset": 0}`

User: "Show me the next page"

Claude calls: `find_public_ec2_instances` with `{"limit": 20, "offset": 20}`

### Example 2: Summary Mode

User: "How many EC2 instances do I have in each region?"

Claude calls: `find_public_ec2_instances` with `{"summary_mode": true}`

Returns: Counts by region (not full instance details)

### Example 3: Filtered + Paginated

User: "Show me first 50 critical Prowler findings"

Claude calls: `get_prowler_findings` with:
```json
{
  "severity": "CRITICAL",
  "limit": 50,
  "offset": 0
}
```

### Example 4: Summary of Findings

User: "Give me a breakdown of Prowler findings by severity"

Claude calls: `get_prowler_findings` with `{"summary_mode": true}`

Returns: Counts grouped by severity and status

## Best Practices

1. **Start with summary mode** when you only need counts or statistics
2. **Use pagination** when browsing through large datasets
3. **Default limit** of 100 is usually sufficient for most queries
4. **Check pagination.has_more** to determine if more results exist
5. **Use filters** (like severity, region) to reduce result sets before paginating

## When to Use Each Feature

| Scenario | Recommended Approach |
|----------|---------------------|
| "How many instances do I have?" | summary_mode: true |
| "Show me all instances" (thousands) | Use pagination with limit/offset |
| "Show me critical findings" | Filter by severity first |
| "Browse through findings" | Use pagination |
| "Compare counts across regions" | summary_mode: true |

## Technical Details

- **Default limit**: 100 records
- **Maximum limit**: 1000 records per query
- **Default offset**: 0
- **Automatic warnings**: Displayed when total_count > 100

## Future Enhancements

Additional queries will be updated to support pagination as needed. Priority will be given to queries that commonly return large datasets (S3 buckets, security groups, IAM resources, Route53 records).
