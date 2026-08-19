#!/usr/bin/env python3
"""Debug script to analyse cost data in scanner.db"""

import sqlite3
from datetime import datetime

db_path = "scanner.db"
conn = sqlite3.connect(db_path)
conn.row_factory = sqlite3.Row
cursor = conn.cursor()

print("=" * 80)
print("COST DATA ANALYSIS")
print("=" * 80)

# Get cost totals by account
cursor.execute("""
    SELECT sm.account_name, cd.account_number,
           SUM(cd.amount) as total_cost,
           MIN(cd.time_period_start) as earliest,
           MAX(cd.time_period_end) as latest,
           COUNT(*) as record_count,
           COUNT(DISTINCT cd.service_name) as service_count,
           cd.currency
    FROM cost_data cd
    JOIN scan_metadata sm ON cd.scan_id = sm.scan_id
    GROUP BY cd.account_number, sm.account_name, cd.currency
    ORDER BY total_cost DESC
""")

print("\n1. COST TOTALS BY ACCOUNT:")
print("-" * 80)
print(f"{'Account Name':<40} {'Account #':<15} {'Total Cost':>15} {'Records':>8}")
print("-" * 80)

total_all = 0.0
for row in cursor.fetchall():
    print(
        f"{row['account_name']:<40} {row['account_number']:<15} ${row['total_cost']:>14,.2f} {row['record_count']:>8}"
    )
    total_all += row["total_cost"]
    earliest = row["earliest"]
    latest = row["latest"]

print("-" * 80)
print(f"{'TOTAL':<40} {'':<15} ${total_all:>14,.2f}")
print(f"\nDate range: {earliest} to {latest}")

# Check for multiple scans per account
cursor.execute("""
    SELECT sm.account_name, sm.account_number, sm.scan_id,
           COUNT(cd.id) as cost_records,
           SUM(cd.amount) as total_cost
    FROM scan_metadata sm
    LEFT JOIN cost_data cd ON sm.scan_id = cd.scan_id
    GROUP BY sm.account_number, sm.scan_id
    ORDER BY sm.account_name
""")

print("\n\n2. SCANS BY ACCOUNT (detecting duplicates):")
print("-" * 80)
print(f"{'Account Name':<30} {'Scan ID':<40} {'Cost Records':>15} {'Total':>15}")
print("-" * 80)

account_scan_counts = {}
for row in cursor.fetchall():
    acct_name = row["account_name"]
    if acct_name not in account_scan_counts:
        account_scan_counts[acct_name] = 0
    account_scan_counts[acct_name] += 1

    print(
        f"{row['account_name']:<30} {row['scan_id']:<40} {row['cost_records']:>15} ${row['total_cost'] or 0:>14,.2f}"
    )

print("\n\n3. ACCOUNTS WITH MULTIPLE SCANS:")
print("-" * 80)
for acct, count in account_scan_counts.items():
    if count > 1:
        print(f"  WARNING: {acct}: {count} scans (cost data may be duplicated!)")

# Check for specific accounts
print("\n\n4. DETAILED BREAKDOWN FOR KEY ACCOUNTS:")
print("-" * 80)

for account_name in ["FrontierSoftwareOrg", "Victor Miloshis"]:
    cursor.execute(
        """
        SELECT cd.service_name, SUM(cd.amount) as service_cost
        FROM cost_data cd
        JOIN scan_metadata sm ON cd.scan_id = sm.scan_id
        WHERE sm.account_name = ?
        GROUP BY cd.service_name
        ORDER BY service_cost DESC
        LIMIT 10
    """,
        (account_name,),
    )

    print(f"\n{account_name} - Top 10 Services:")
    print(f"  {'Service':<50} {'Cost':>15}")
    print(f"  {'-'*50} {'-'*15}")
    for row in cursor.fetchall():
        print(f"  {row['service_name']:<50} ${row['service_cost']:>14,.2f}")

conn.close()
