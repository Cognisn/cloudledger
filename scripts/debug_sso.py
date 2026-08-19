#!/usr/bin/env python3
"""Debug script to check SSO data in scanner.db"""

import sqlite3
import json

db_path = "scanner.db"
conn = sqlite3.connect(db_path)
conn.row_factory = sqlite3.Row
cursor = conn.cursor()

print("=" * 80)
print("SSO/IDENTITY CENTRE DATA ANALYSIS")
print("=" * 80)

# Check sso_instances table
cursor.execute("SELECT COUNT(*) as count FROM sso_instances")
instance_count = cursor.fetchone()[0]
print(f"\n1. SSO Instances: {instance_count}")

if instance_count > 0:
    cursor.execute("""
        SELECT si.instance_arn, si.identity_store_id, sm.account_name, sm.account_number, si.scan_id
        FROM sso_instances si
        JOIN scan_metadata sm ON si.scan_id = sm.scan_id
    """)

    print("\nSSO Instance Details:")
    for row in cursor.fetchall():
        print(f"  Account: {row['account_name']} ({row['account_number']})")
        print(f"  Instance ARN: {row['instance_arn']}")
        print(f"  Identity Store ID: {row['identity_store_id']}")
        print(f"  Scan ID: {row['scan_id']}")
        print()

# Check sso_permission_sets table
cursor.execute("SELECT COUNT(*) as count FROM sso_permission_sets")
ps_count = cursor.fetchone()[0]
print(f"\n2. SSO Permission Sets: {ps_count}")

if ps_count > 0:
    cursor.execute("""
        SELECT ps.permission_set_name, ps.permission_set_arn, ps.description,
               sm.account_name, sm.account_number
        FROM sso_permission_sets ps
        JOIN scan_metadata sm ON ps.scan_id = sm.scan_id
        ORDER BY sm.account_name, ps.permission_set_name
    """)

    print("\nPermission Sets by Account:")
    current_account = None
    for row in cursor.fetchall():
        if current_account != row["account_name"]:
            current_account = row["account_name"]
            print(f"\n  {current_account} ({row['account_number']}):")
        print(f"    - {row['permission_set_name']}")
        if row["description"]:
            print(f"      Description: {row['description']}")

# Check sso_assignments table
cursor.execute("SELECT COUNT(*) as count FROM sso_assignments")
assignment_count = cursor.fetchone()[0]
print(f"\n3. SSO Assignments: {assignment_count}")

if assignment_count > 0:
    cursor.execute("""
        SELECT sa.permission_set_arn, sa.target_id, sa.principal_type,
               sa.principal_id, sm.account_name
        FROM sso_assignments sa
        JOIN scan_metadata sm ON sa.scan_id = sm.scan_id
        LIMIT 10
    """)

    print("\nSample Assignments (first 10):")
    for row in cursor.fetchall():
        print(f"  Account: {row['account_name']}")
        print(f"  Permission Set: {row['permission_set_arn']}")
        print(f"  Principal: {row['principal_type']} - {row['principal_id']}")
        print()

# Check which accounts were scanned
cursor.execute("""
    SELECT account_name, account_number, scan_id,
           strftime('%Y-%m-%d %H:%M:%S', created_at) as scan_time
    FROM scan_metadata
    ORDER BY created_at DESC
""")

print("\n4. All Scanned Accounts:")
print("-" * 80)
for row in cursor.fetchall():
    print(f"  {row['account_name']:<40} {row['account_number']:<15} {row['scan_time']}")

# Check if FrontierSoftwareOrg has Organizations data
cursor.execute("""
    SELECT org.organization_id, org.master_account_id, sm.account_name, sm.account_number
    FROM organizations org
    JOIN scan_metadata sm ON org.scan_id = sm.scan_id
""")

print("\n5. AWS Organizations Data:")
print("-" * 80)
org_rows = cursor.fetchall()
if org_rows:
    for row in org_rows:
        print(f"  Account: {row['account_name']} ({row['account_number']})")
        print(f"  Organization ID: {row['organization_id']}")
        print(f"  Master Account: {row['master_account_id']}")
        print()
else:
    print("  No Organizations data found!")

# Get FrontierSoftwareOrg scan_id
cursor.execute("""
    SELECT scan_id, account_number
    FROM scan_metadata
    WHERE account_name = 'FrontierSoftwareOrg'
    ORDER BY created_at DESC
    LIMIT 1
""")

frontier_row = cursor.fetchone()
if frontier_row:
    frontier_scan_id = frontier_row["scan_id"]
    frontier_account = frontier_row["account_number"]

    print(f"\n6. FrontierSoftwareOrg Data (scan_id: {frontier_scan_id}):")
    print("-" * 80)

    # Check SSO data for this scan
    cursor.execute(
        "SELECT COUNT(*) FROM sso_instances WHERE scan_id = ?", (frontier_scan_id,)
    )
    print(f"  SSO Instances: {cursor.fetchone()[0]}")

    cursor.execute(
        "SELECT COUNT(*) FROM sso_permission_sets WHERE scan_id = ?",
        (frontier_scan_id,),
    )
    print(f"  SSO Permission Sets: {cursor.fetchone()[0]}")

    cursor.execute(
        "SELECT COUNT(*) FROM sso_assignments WHERE scan_id = ?", (frontier_scan_id,)
    )
    print(f"  SSO Assignments: {cursor.fetchone()[0]}")

    cursor.execute(
        "SELECT COUNT(*) FROM organizations WHERE scan_id = ?", (frontier_scan_id,)
    )
    print(f"  Organizations: {cursor.fetchone()[0]}")

    cursor.execute(
        "SELECT COUNT(*) FROM organization_accounts WHERE scan_id = ?",
        (frontier_scan_id,),
    )
    print(f"  Organization Accounts: {cursor.fetchone()[0]}")

else:
    print("\n6. FrontierSoftwareOrg not found in scan_metadata!")

conn.close()

print("\n" + "=" * 80)
print("DIAGNOSIS:")
print("=" * 80)

if ps_count == 0:
    print("\n⚠ NO SSO PERMISSION SETS FOUND IN DATABASE")
    print("\nPossible causes:")
    print("1. SSO data collection failed during scan (check cloudledger.log)")
    print("2. SSO APIs not accessible with provided credentials")
    print("3. SSO collection code has bugs")
    print("4. Scanner scanning wrong region (SSO is region-specific)")
    print("\nAction: Check cloudledger.log for SSO-related errors")
else:
    print(f"\n✓ Found {ps_count} SSO permission sets")
    if frontier_row:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT COUNT(*) FROM sso_permission_sets WHERE scan_id = ?",
            (frontier_scan_id,),
        )
        frontier_ps_count = cursor.fetchone()[0]
        if frontier_ps_count == 0:
            print(f"\n⚠ But FrontierSoftwareOrg scan has 0 permission sets!")
            print("  Permission sets may be in a different account's scan")
