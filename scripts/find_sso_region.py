#!/usr/bin/env python3
"""
Find which region AWS Identity Centre is configured in.
"""

import boto3
from botocore.exceptions import ClientError
import getpass

print("=" * 80)
print("FIND AWS IDENTITY CENTRE HOME REGION")
print("=" * 80)

print("\nEnter credentials for FrontierSoftwareOrg account:")
print("(Secret key and session token will be hidden)")
access_key = input("AWS Access Key ID: ").strip()
secret_key = getpass.getpass("AWS Secret Access Key: ").strip()
session_token = getpass.getpass("AWS Session Token: ").strip()

session = boto3.Session(
    aws_access_key_id=access_key,
    aws_secret_access_key=secret_key,
    aws_session_token=session_token,
)

# Get list of all AWS regions
print("\nGetting available regions...")
ec2 = session.client("ec2", region_name="us-east-1")
regions_response = ec2.describe_regions()
all_regions = [r["RegionName"] for r in regions_response["Regions"]]

print(f"Testing {len(all_regions)} regions for Identity Centre instance...\n")

# Common regions to test first
priority_regions = ["ap-southeast-2", "us-east-1", "us-west-2", "eu-west-1"]

# Test priority regions first
test_order = priority_regions + [r for r in all_regions if r not in priority_regions]

found_instances = []

for region in test_order:
    try:
        sso_client = session.client("sso-admin", region_name=region)
        response = sso_client.list_instances()

        instances = response.get("Instances", [])
        if instances:
            print(f"✓ {region:<20} - FOUND {len(instances)} instance(s)!")
            for instance in instances:
                found_instances.append(
                    {
                        "region": region,
                        "instance_arn": instance["InstanceArn"],
                        "identity_store_id": instance["IdentityStoreId"],
                    }
                )
        else:
            print(f"  {region:<20} - no instances")

    except ClientError as e:
        if e.response["Error"]["Code"] == "AccessDeniedException":
            print(f"✗ {region:<20} - Access Denied")
        else:
            print(f"✗ {region:<20} - {e.response['Error']['Code']}")
    except Exception as e:
        print(f"✗ {region:<20} - Error: {e}")

if found_instances:
    print("\n" + "=" * 80)
    print("IDENTITY CENTRE INSTANCE(S) FOUND!")
    print("=" * 80)

    for idx, inst in enumerate(found_instances, 1):
        print(f"\nInstance {idx}:")
        print(f"  Home Region: {inst['region']}")
        print(f"  Instance ARN: {inst['instance_arn']}")
        print(f"  Identity Store ID: {inst['identity_store_id']}")

        # Test permission sets in this region
        try:
            sso_client = session.client("sso-admin", region_name=inst["region"])
            ps_response = sso_client.list_permission_sets(
                InstanceArn=inst["instance_arn"], MaxResults=10
            )
            ps_count = len(ps_response.get("PermissionSets", []))

            print(f"\n  Testing permission set access in {inst['region']}...")
            print(f"  ✓ Found {ps_count} permission set(s) (showing first 10)")

            # Get permission set names
            for ps_arn in ps_response.get("PermissionSets", []):
                try:
                    ps_details = sso_client.describe_permission_set(
                        InstanceArn=inst["instance_arn"], PermissionSetArn=ps_arn
                    )
                    ps_name = ps_details["PermissionSet"].get("Name", "Unnamed")
                    print(f"    - {ps_name}")
                except Exception as e:
                    print(f"    - (unable to get details: {e})")

        except Exception as e:
            print(f"  ✗ Error listing permission sets: {e}")

    print("\n" + "=" * 80)
    print("REQUIRED FIX:")
    print("=" * 80)
    print(f"\nThe scanner is hardcoded to check us-east-1, but your Identity Centre")
    print(f"is configured in: {found_instances[0]['region']}")
    print(f"\nYou need to update the code to use the correct region.")

else:
    print("\n" + "=" * 80)
    print("NO IDENTITY CENTRE INSTANCES FOUND IN ANY REGION")
    print("=" * 80)
    print("\nThis is unexpected given you're logged in via SSO.")
    print("Please verify Identity Centre is enabled in the AWS Console.")
