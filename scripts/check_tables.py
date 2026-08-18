#!/usr/bin/env python3
"""Check what tables exist in scanner.db"""

import sqlite3

db_path = "scanner.db"
conn = sqlite3.connect(db_path)
cursor = conn.cursor()

# Get all tables
cursor.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
tables = cursor.fetchall()

print("Tables in scanner.db:")
print("=" * 80)
for table in tables:
    table_name = table[0]
    cursor.execute(f"SELECT COUNT(*) FROM {table_name}")
    count = cursor.fetchone()[0]
    print(f"  {table_name:<40} {count:>10} rows")

print("\n" + "=" * 80)
print("Looking for SSO/Identity Centre tables:")
sso_tables = [t[0] for t in tables if 'sso' in t[0].lower()]
if sso_tables:
    print(f"  Found: {', '.join(sso_tables)}")
else:
    print("  ⚠ NO SSO TABLES FOUND!")

conn.close()
