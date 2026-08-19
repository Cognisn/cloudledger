#!/usr/bin/env python3
"""
Test SSO/Identity Centre access to diagnose why no data is being collected.

This script will help identify if the issue is:
1. No SSO instances found (Identity Centre not enabled)
2. Permission denied (credentials lack SSO permissions)
3. Wrong region
4. API errors
"""

import boto3
from botocore.exceptions import ClientError
import getpass
import json

print("=" * 80)
print("AWS SSO/IDENTITY CENTRE DIAGNOSTIC TEST")
print("=" * 80)

# You'll need to provide credentials for the FrontierSoftwareOrg account
print("\nThis test requires temporary credentials for FrontierSoftwareOrg account.")
print("Please enter the credentials you use when scanning this account:")
print("(Secret key and session token will be hidden)")
print()

access_key = input("AWS Access Key ID: ").strip()
secret_key = getpass.getpass("AWS Secret Access Key: ").strip()
session_token = getpass.getpass("AWS Session Token: ").strip()

# Create session with provided credentials
session = boto3.Session(
    aws_access_key_id=access_key,
    aws_secret_access_key=secret_key,
    aws_session_token=session_token,
)

print("\n" + "=" * 80)
print("TEST 1: Verify Credentials")
print("=" * 80)

try:
    sts_client = session.client("sts")
    identity = sts_client.get_caller_identity()
    print(f"✓ Credentials valid")
    print(f"  Account: {identity['Account']}")
    print(f"  User/Role ARN: {identity['Arn']}")
except Exception as e:
    print(f"✗ Credentials INVALID: {e}")
    exit(1)

print("\n" + "=" * 80)
print("TEST 2: List SSO Instances (us-east-1)")
print("=" * 80)

try:
    sso_client = session.client("sso-admin", region_name="us-east-1")

    print("Calling sso-admin:ListInstances...")
    instances_response = sso_client.list_instances()

    instances = instances_response.get("Instances", [])
    print(f"✓ API call successful")
    print(f"  Found {len(instances)} SSO instance(s)")

    if len(instances) == 0:
        print("\n⚠ NO SSO INSTANCES FOUND!")
        print("\nPossible reasons:")
        print("  1. AWS SSO/Identity Centre is not enabled for this account")
        print("  2. This is not the management account in the Organisation")
        print("  3. SSO is enabled in a different region (unlikely)")
        print("\nTo check:")
        print("  1. Log into AWS Console for FrontierSoftwareOrg")
        print("  2. Navigate to IAM Identity Centre")
        print("  3. Verify if Identity Centre is enabled")

    else:
        print("\n✓ SSO/Identity Centre IS enabled!")
        for idx, instance in enumerate(instances, 1):
            print(f"\n  Instance {idx}:")
            print(f"    Instance ARN: {instance['InstanceArn']}")
            print(f"    Identity Store ID: {instance['IdentityStoreId']}")

            # Try to list permission sets for this instance
            print(f"\n    Testing permission set access...")
            try:
                ps_paginator = sso_client.get_paginator("list_permission_sets")
                ps_count = 0
                for page in ps_paginator.paginate(InstanceArn=instance["InstanceArn"]):
                    ps_count += len(page.get("PermissionSets", []))

                print(f"    ✓ Found {ps_count} permission set(s)")

                if ps_count > 0:
                    # List first few permission set names
                    ps_response = sso_client.list_permission_sets(
                        InstanceArn=instance["InstanceArn"], MaxResults=5
                    )

                    print(f"\n    Permission Set Names (first 5):")
                    for ps_arn in ps_response.get("PermissionSets", []):
                        try:
                            ps_details = sso_client.describe_permission_set(
                                InstanceArn=instance["InstanceArn"],
                                PermissionSetArn=ps_arn,
                            )
                            ps_name = ps_details["PermissionSet"].get("Name", "Unnamed")
                            print(f"      - {ps_name}")
                        except ClientError as e:
                            print(
                                f"      - {ps_arn} (unable to get details: {e.response['Error']['Code']})"
                            )

            except ClientError as e:
                error_code = e.response["Error"]["Code"]
                error_msg = e.response["Error"]["Message"]
                print(f"    ✗ Failed to list permission sets: {error_code}")
                print(f"      Message: {error_msg}")

                if error_code == "AccessDeniedException":
                    print(f"\n    ⚠ PERMISSION DENIED!")
                    print(
                        f"      Your credentials do not have permission to list SSO permission sets."
                    )
                    print(f"      Required IAM permissions:")
                    print(f"        - sso:ListInstances")
                    print(f"        - sso:ListPermissionSets")
                    print(f"        - sso:DescribePermissionSet")

except ClientError as e:
    error_code = e.response["Error"]["Code"]
    error_msg = e.response["Error"]["Message"]
    print(f"✗ Failed to access SSO API: {error_code}")
    print(f"  Message: {error_msg}")

    if error_code == "AccessDeniedException":
        print(f"\n⚠ PERMISSION DENIED!")
        print(
            f"  Your credentials do not have permission to access SSO/Identity Centre."
        )
        print(f"  Required IAM permissions:")
        print(f"    - sso:ListInstances")
        print(f"    - sso:ListPermissionSets")
        print(f"    - sso:DescribePermissionSet")
        print(f"    - sso:ListAccountAssignments")
        print(f"    - sso:ListAccountsForProvisionedPermissionSet")

except Exception as e:
    print(f"✗ Unexpected error: {e}")
    import traceback

    traceback.print_exc()

print("\n" + "=" * 80)
print("DIAGNOSIS COMPLETE")
print("=" * 80)
