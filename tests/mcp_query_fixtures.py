"""
Shared seed data and call matrix for the MCP query-output equivalence harness.

Seeds a deterministic, fully self-describing dataset across two fixture scans
via real `models.py` constructors and `DatabaseOperations`, then exposes
`CALL_MATRIX`: every MCP tool from `mcp/tools.get_tools()` invoked with both
curated (sensible) arguments and empty arguments. Nothing here is derived
from the current clock -- all timestamps are fixed literals so the captured
baseline is reproducible. Uses Australian English in all documentation and
comments.
"""

from datetime import datetime

from cloudledger.database.models import (
    ScanMetadata,
    EC2Instance,
    VPC,
    Subnet,
    SecurityGroup,
    S3Bucket,
    IAMUser,
    IAMRole,
    ProwlerFinding,
    LoadBalancer,
    NATGateway,
    InternetGateway,
    RouteTable,
    NetworkInterface,
    LambdaFunction,
    CostData,
    Route53HostedZone,
    Route53RecordSet,
    Organization,
    OrganizationAccount,
    EBSSnapshot,
)
from cloudledger.database.operations import DatabaseOperations
from cloudledger.database.schema import DatabaseSchema
from cloudledger.mcp.tools import get_tools

# Fixture scan identifiers. SCAN_ID carries the bulk of the seeded resources;
# SCAN_ID_2 carries a small, distinct set so scan-comparison tools have a
# delta to report.
SCAN_ID = "scan-fixture-001"
SCAN_ID_2 = "scan-fixture-002"

# Fixed timestamps -- nothing here is derived from the current clock.
TIMESTAMP_1 = "2026-08-01T00:00:00+00:00"
TIMESTAMP_2 = "2026-08-02T00:00:00+00:00"

FIXTURE_ACCOUNT_NUMBER = "123456789012"
FIXTURE_ACCOUNT_NAME = "Fixture Account"


def _dt(iso: str) -> datetime:
    """Parse a fixed ISO timestamp literal into a datetime."""
    return datetime.fromisoformat(iso)


def seed_database(db_path: str) -> None:
    """
    Initialise a database at `db_path` and populate it with deterministic
    fixture data spanning two scans, covering every resource type the
    curated call matrix exercises.
    """
    DatabaseSchema(db_path).initialise_database()
    db_ops = DatabaseOperations(db_path)

    # -- scan_metadata --------------------------------------------------
    db_ops.insert_scan_metadata(
        ScanMetadata(
            scan_id=SCAN_ID,
            account_name=FIXTURE_ACCOUNT_NAME,
            account_number=FIXTURE_ACCOUNT_NUMBER,
            scan_timestamp=_dt(TIMESTAMP_1),
            prowler_level="2",
            regions_scanned=["ap-southeast-2"],
            scan_status="completed",
            scan_duration_seconds=120.5,
        )
    )
    db_ops.insert_scan_metadata(
        ScanMetadata(
            scan_id=SCAN_ID_2,
            account_name=FIXTURE_ACCOUNT_NAME,
            account_number=FIXTURE_ACCOUNT_NUMBER,
            scan_timestamp=_dt(TIMESTAMP_2),
            prowler_level="2",
            regions_scanned=["ap-southeast-2"],
            scan_status="completed",
            scan_duration_seconds=95.0,
        )
    )

    # -- ec2_instances ----------------------------------------------------
    db_ops.insert_ec2_instances(
        [
            EC2Instance(
                scan_id=SCAN_ID,
                instance_id="i-fixture-001",
                region="ap-southeast-2",
                instance_type="t3.micro",
                state="running",
                public_ip="203.0.113.10",
                private_ip="10.0.1.10",
                vpc_id="vpc-fix-1",
                subnet_id="subnet-fix-1",
                availability_zone="ap-southeast-2a",
                launch_time=_dt(TIMESTAMP_1),
                security_groups=["sg-fix-1"],
                tags={"Name": "fixture-ec2-1"},
                monitoring_state="disabled",
            ),
            EC2Instance(
                scan_id=SCAN_ID,
                instance_id="i-fixture-002",
                region="ap-southeast-2",
                instance_type="t3.small",
                state="running",
                public_ip=None,
                private_ip="10.1.1.10",
                vpc_id="vpc-fix-2",
                subnet_id="subnet-fix-2",
                availability_zone="ap-southeast-2b",
                launch_time=_dt(TIMESTAMP_1),
                security_groups=["sg-fix-2"],
                tags={"Name": "fixture-ec2-2"},
                monitoring_state="disabled",
            ),
        ]
    )
    db_ops.insert_ec2_instances(
        [
            EC2Instance(
                scan_id=SCAN_ID_2,
                instance_id="i-fixture-101",
                region="ap-southeast-2",
                instance_type="t3.micro",
                state="running",
                public_ip="203.0.113.20",
                private_ip="10.2.1.10",
                vpc_id="vpc-fix-3",
                availability_zone="ap-southeast-2a",
                launch_time=_dt(TIMESTAMP_2),
                security_groups=[],
                tags={"Name": "fixture-ec2-101"},
            ),
        ]
    )

    # -- vpcs ---------------------------------------------------------------
    db_ops.insert_vpcs(
        [
            VPC(
                scan_id=SCAN_ID,
                vpc_id="vpc-fix-1",
                region="ap-southeast-2",
                cidr_block="10.0.0.0/16",
                state="available",
                is_default=False,
                instance_tenancy="default",
                tags={"Name": "fixture-vpc-1"},
            ),
            VPC(
                scan_id=SCAN_ID,
                vpc_id="vpc-fix-2",
                region="ap-southeast-2",
                cidr_block="10.1.0.0/16",
                state="available",
                is_default=False,
                instance_tenancy="default",
                tags={"Name": "fixture-vpc-2"},
            ),
        ]
    )
    db_ops.insert_vpcs(
        [
            VPC(
                scan_id=SCAN_ID_2,
                vpc_id="vpc-fix-3",
                region="ap-southeast-2",
                cidr_block="10.2.0.0/16",
                state="available",
                is_default=False,
                instance_tenancy="default",
                tags={"Name": "fixture-vpc-3"},
            ),
        ]
    )

    # -- subnets --------------------------------------------------------
    db_ops.insert_subnets(
        [
            Subnet(
                scan_id=SCAN_ID,
                subnet_id="subnet-fix-1",
                vpc_id="vpc-fix-1",
                region="ap-southeast-2",
                cidr_block="10.0.1.0/24",
                availability_zone="ap-southeast-2a",
                available_ip_count=250,
                map_public_ip=True,
                state="available",
            ),
            Subnet(
                scan_id=SCAN_ID,
                subnet_id="subnet-fix-2",
                vpc_id="vpc-fix-2",
                region="ap-southeast-2",
                cidr_block="10.1.1.0/24",
                availability_zone="ap-southeast-2b",
                available_ip_count=250,
                map_public_ip=False,
                state="available",
            ),
        ]
    )

    # -- security_groups --------------------------------------------------
    db_ops.insert_security_groups(
        [
            SecurityGroup(
                scan_id=SCAN_ID,
                group_id="sg-fix-1",
                group_name="fixture-sg-open",
                vpc_id="vpc-fix-1",
                region="ap-southeast-2",
                description="Fixture security group with open SSH ingress",
                ingress_rules=[
                    {
                        "IpProtocol": "tcp",
                        "FromPort": 22,
                        "ToPort": 22,
                        "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                    }
                ],
                egress_rules=[
                    {
                        "IpProtocol": "-1",
                        "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                    }
                ],
            ),
            SecurityGroup(
                scan_id=SCAN_ID,
                group_id="sg-fix-2",
                group_name="fixture-sg-closed",
                vpc_id="vpc-fix-2",
                region="ap-southeast-2",
                description="Fixture security group restricted to the VPC CIDR",
                ingress_rules=[
                    {
                        "IpProtocol": "tcp",
                        "FromPort": 443,
                        "ToPort": 443,
                        "IpRanges": [{"CidrIp": "10.0.0.0/16"}],
                    }
                ],
                egress_rules=[],
            ),
        ]
    )

    # -- s3_buckets -------------------------------------------------------
    db_ops.insert_s3_buckets(
        [
            S3Bucket(
                scan_id=SCAN_ID,
                bucket_name="fixture-bucket-public",
                creation_date=_dt(TIMESTAMP_1),
                region="ap-southeast-2",
                versioning_status="Enabled",
                public_access_block={
                    "BlockPublicAcls": False,
                    "IgnorePublicAcls": False,
                    "BlockPublicPolicy": False,
                    "RestrictPublicBuckets": False,
                },
                encryption_config=None,
                lifecycle_rules=[
                    {
                        "ID": "fixture-rule",
                        "Status": "Enabled",
                        "Expiration": {"Days": 90},
                    }
                ],
                logging_enabled=False,
                size_bytes=1024,
                object_count=5,
                tags={},
            ),
            S3Bucket(
                scan_id=SCAN_ID,
                bucket_name="fixture-bucket-private",
                creation_date=_dt(TIMESTAMP_1),
                region="ap-southeast-2",
                versioning_status="Enabled",
                public_access_block={
                    "BlockPublicAcls": True,
                    "IgnorePublicAcls": True,
                    "BlockPublicPolicy": True,
                    "RestrictPublicBuckets": True,
                },
                encryption_config={
                    "Rules": [
                        {
                            "ApplyServerSideEncryptionByDefault": {
                                "SSEAlgorithm": "AES256"
                            }
                        }
                    ]
                },
                lifecycle_rules=[],
                logging_enabled=True,
                size_bytes=2048,
                object_count=10,
                tags={
                    "Environment": "fixture",
                    "Owner": "fixture-team",
                    "CostCentre": "fixture-cc",
                    "Project": "fixture-proj",
                },
            ),
        ]
    )

    # -- ebs_snapshots ------------------------------------------------------
    # Two deterministic rows so age-based queries (find_unused_resources'
    # "old snapshots" category, the assessment engine's unencrypted-snapshot
    # check) have a genuine old/recent split to evaluate: one dated well
    # before the default 90-day cutoff, one dated well within it.
    db_ops.insert_ebs_snapshots(
        [
            EBSSnapshot(
                scan_id=SCAN_ID,
                snapshot_id="snap-fixture-old",
                region="ap-southeast-2",
                volume_id="vol-fixture-old",
                volume_size=8,
                encrypted=True,
                state="completed",
                start_time=_dt("2026-01-01T00:00:00+00:00"),
                progress="100%",
                owner_id=FIXTURE_ACCOUNT_NUMBER,
                description="Fixture old snapshot",
                tags={},
            ),
            EBSSnapshot(
                scan_id=SCAN_ID,
                snapshot_id="snap-fixture-recent",
                region="ap-southeast-2",
                volume_id="vol-fixture-recent",
                volume_size=8,
                encrypted=True,
                state="completed",
                start_time=_dt(TIMESTAMP_1),
                progress="100%",
                owner_id=FIXTURE_ACCOUNT_NUMBER,
                description="Fixture recent snapshot",
                tags={},
            ),
        ]
    )

    # -- iam_users ----------------------------------------------------------
    db_ops.insert_iam_users(
        [
            IAMUser(
                scan_id=SCAN_ID,
                user_name="fixture-user-no-mfa",
                user_id="AIDAFIXTURE001",
                arn="arn:aws:iam::123456789012:user/fixture-user-no-mfa",
                create_date=_dt(TIMESTAMP_1),
                mfa_enabled=False,
                access_keys=[
                    {
                        "AccessKeyId": "AKIAFIXTURE001",
                        "Status": "Active",
                        "CreateDate": TIMESTAMP_1,
                    }
                ],
                attached_policies=["AdministratorAccess"],
                groups=[],
            ),
            IAMUser(
                scan_id=SCAN_ID,
                user_name="fixture-user-mfa",
                user_id="AIDAFIXTURE002",
                arn="arn:aws:iam::123456789012:user/fixture-user-mfa",
                create_date=_dt(TIMESTAMP_1),
                mfa_enabled=True,
                access_keys=[],
                attached_policies=["ReadOnlyAccess"],
                groups=["fixture-group"],
            ),
        ]
    )

    # -- iam_roles ------------------------------------------------------
    db_ops.insert_iam_roles(
        [
            IAMRole(
                scan_id=SCAN_ID,
                role_name="fixture-role",
                role_id="AROAFIXTURE001",
                arn="arn:aws:iam::123456789012:role/fixture-role",
                create_date=_dt(TIMESTAMP_1),
                assume_role_policy={"Version": "2012-10-17", "Statement": []},
                attached_policies=["ReadOnlyAccess"],
                max_session_duration=3600,
            ),
        ]
    )

    # -- prowler_findings -------------------------------------------------
    db_ops.insert_prowler_findings(
        [
            ProwlerFinding(
                scan_id=SCAN_ID,
                check_id="fixture_check_high",
                check_title="Fixture high severity check",
                severity="high",
                status="FAIL",
                region="ap-southeast-2",
                resource_id="i-fixture-001",
                resource_arn="arn:aws:ec2:ap-southeast-2:123456789012:instance/i-fixture-001",
                service_name="ec2",
                check_type="fixture_type",
                compliance_frameworks=["CIS_2.0"],
            ),
            ProwlerFinding(
                scan_id=SCAN_ID,
                check_id="fixture_check_medium",
                check_title="Fixture medium severity check",
                severity="medium",
                status="FAIL",
                region="ap-southeast-2",
                resource_id="fixture-bucket-public",
                resource_arn="arn:aws:s3:::fixture-bucket-public",
                service_name="s3",
                check_type="fixture_type",
                compliance_frameworks=["CIS_2.0", "PCI-DSS"],
            ),
            ProwlerFinding(
                scan_id=SCAN_ID,
                check_id="fixture_check_low",
                check_title="Fixture low severity check",
                severity="low",
                status="PASS",
                region="ap-southeast-2",
                resource_id="fixture-user-mfa",
                resource_arn="arn:aws:iam::123456789012:user/fixture-user-mfa",
                service_name="iam",
                check_type="fixture_type",
                compliance_frameworks=[],
            ),
        ]
    )

    # -- load_balancers -------------------------------------------------
    db_ops.insert_load_balancers(
        [
            LoadBalancer(
                scan_id=SCAN_ID,
                load_balancer_name="fixture-alb",
                load_balancer_arn=(
                    "arn:aws:elasticloadbalancing:ap-southeast-2:123456789012:"
                    "loadbalancer/app/fixture-alb/0123456789abcdef"
                ),
                load_balancer_type="application",
                region="ap-southeast-2",
                vpc_id="vpc-fix-1",
                scheme="internet-facing",
                state="active",
                dns_name="fixture-alb-123.ap-southeast-2.elb.amazonaws.com",
                availability_zones=["ap-southeast-2a", "ap-southeast-2b"],
                security_groups=["sg-fix-1"],
                subnets=["subnet-fix-1"],
                created_time=_dt(TIMESTAMP_1),
                listeners=[{"Port": 443, "Protocol": "HTTPS"}],
                target_groups=[],
            ),
        ]
    )

    # -- nat_gateways -----------------------------------------------------
    db_ops.insert_nat_gateways(
        [
            NATGateway(
                scan_id=SCAN_ID,
                nat_gateway_id="nat-fixture-001",
                region="ap-southeast-2",
                vpc_id="vpc-fix-1",
                subnet_id="subnet-fix-1",
                state="available",
                connectivity_type="public",
                public_ip="203.0.113.99",
                private_ip="10.0.1.99",
                created_time=_dt(TIMESTAMP_1),
            ),
        ]
    )

    # -- internet_gateways --------------------------------------------------
    db_ops.insert_internet_gateways(
        [
            InternetGateway(
                scan_id=SCAN_ID,
                internet_gateway_id="igw-fixture-001",
                region="ap-southeast-2",
                vpc_attachments=[{"VpcId": "vpc-fix-1", "State": "available"}],
            ),
        ]
    )

    # -- route_tables -----------------------------------------------------
    db_ops.insert_route_tables(
        [
            RouteTable(
                scan_id=SCAN_ID,
                route_table_id="rtb-fixture-001",
                region="ap-southeast-2",
                vpc_id="vpc-fix-1",
                is_main=True,
                routes=[
                    {
                        "DestinationCidrBlock": "0.0.0.0/0",
                        "GatewayId": "igw-fixture-001",
                    }
                ],
                subnet_associations=["subnet-fix-1"],
                gateway_associations=[],
            ),
        ]
    )

    # -- network_interfaces -------------------------------------------------
    db_ops.insert_network_interfaces(
        [
            NetworkInterface(
                scan_id=SCAN_ID,
                network_interface_id="eni-fixture-001",
                region="ap-southeast-2",
                interface_type="interface",
                status="in-use",
                vpc_id="vpc-fix-1",
                subnet_id="subnet-fix-1",
                availability_zone="ap-southeast-2a",
                private_ip_address="10.0.1.20",
                public_ip="203.0.113.30",
                security_groups=["sg-fix-1"],
            ),
        ]
    )

    # -- lambda_functions -----------------------------------------------
    db_ops.insert_lambda_functions(
        [
            LambdaFunction(
                scan_id=SCAN_ID,
                function_name="fixture-lambda-1",
                function_arn="arn:aws:lambda:ap-southeast-2:123456789012:function:fixture-lambda-1",
                region="ap-southeast-2",
                runtime="python3.12",
                handler="app.handler",
                code_size=1024,
                memory_size=128,
                timeout=30,
                last_modified=_dt(TIMESTAMP_1),
                role_arn="arn:aws:iam::123456789012:role/fixture-role",
                vpc_config={
                    "VpcId": "vpc-fix-1",
                    "SubnetIds": ["subnet-fix-1"],
                    "SecurityGroupIds": ["sg-fix-1"],
                },
                state="Active",
            ),
            LambdaFunction(
                scan_id=SCAN_ID,
                function_name="fixture-lambda-2",
                function_arn="arn:aws:lambda:ap-southeast-2:123456789012:function:fixture-lambda-2",
                region="ap-southeast-2",
                runtime="python3.12",
                handler="app.handler",
                code_size=2048,
                memory_size=256,
                timeout=15,
                last_modified=_dt(TIMESTAMP_1),
                role_arn="arn:aws:iam::123456789012:role/fixture-role",
                vpc_config=None,
                state="Active",
            ),
        ]
    )

    # -- cost_data ------------------------------------------------------
    db_ops.insert_cost_data(
        [
            CostData(
                scan_id=SCAN_ID,
                account_number=FIXTURE_ACCOUNT_NUMBER,
                time_period_start=_dt("2026-07-01T00:00:00+00:00"),
                time_period_end=_dt("2026-07-31T23:59:59+00:00"),
                service_name="Amazon Elastic Compute Cloud - Compute",
                amount=150.25,
                currency="USD",
                unit="USD",
            ),
            CostData(
                scan_id=SCAN_ID,
                account_number=FIXTURE_ACCOUNT_NUMBER,
                time_period_start=_dt("2026-08-01T00:00:00+00:00"),
                time_period_end=_dt("2026-08-31T23:59:59+00:00"),
                service_name="Amazon Simple Storage Service",
                amount=45.10,
                currency="USD",
                unit="USD",
            ),
        ]
    )

    # -- route53_hosted_zones / route53_record_sets ------------------------
    db_ops.insert_route53_hosted_zones(
        [
            Route53HostedZone(
                scan_id=SCAN_ID,
                hosted_zone_id="Z-FIXTURE001",
                name="fixture.example.com.",
                is_private=False,
                resource_record_set_count=2,
                vpc_associations=[],
            ),
        ]
    )
    db_ops.insert_route53_record_sets(
        [
            Route53RecordSet(
                scan_id=SCAN_ID,
                hosted_zone_id="Z-FIXTURE001",
                name="www.fixture.example.com.",
                record_type="A",
                ttl=300,
                resource_records=["203.0.113.10"],
            ),
            Route53RecordSet(
                scan_id=SCAN_ID,
                hosted_zone_id="Z-FIXTURE001",
                name="fixture.example.com.",
                record_type="NS",
                ttl=172800,
                resource_records=["ns-1.awsdns.com."],
            ),
        ]
    )

    # -- organizations / organization_accounts -----------------------------
    db_ops.insert_organizations(
        [
            Organization(
                scan_id=SCAN_ID,
                organization_id="o-fixture001",
                organization_arn="arn:aws:organizations::123456789012:organization/o-fixture001",
                master_account_id=FIXTURE_ACCOUNT_NUMBER,
                master_account_email="fixture-master@example.com",
                feature_set="ALL",
                available_policy_types=[
                    {"Type": "SERVICE_CONTROL_POLICY", "Status": "ENABLED"}
                ],
            ),
        ]
    )
    db_ops.insert_organization_accounts(
        [
            OrganizationAccount(
                scan_id=SCAN_ID,
                account_id=FIXTURE_ACCOUNT_NUMBER,
                account_arn=(
                    f"arn:aws:organizations::123456789012:account/o-fixture001/"
                    f"{FIXTURE_ACCOUNT_NUMBER}"
                ),
                account_name="Fixture Master Account",
                email="fixture-master@example.com",
                status="ACTIVE",
                joined_method="INVITED",
            ),
            OrganizationAccount(
                scan_id=SCAN_ID,
                account_id="210987654321",
                account_arn=(
                    "arn:aws:organizations::123456789012:account/o-fixture001/210987654321"
                ),
                account_name="Fixture Member Account",
                email="fixture-member@example.com",
                status="ACTIVE",
                joined_method="CREATED",
            ),
        ]
    )


# Curated calls: sensible arguments (taken from get_tools() in mcp/tools.py)
# for every tool the seed data can plausibly satisfy, in the order they
# appear here.
_CURATED_CALLS: list[tuple[str, dict]] = [
    ("list_scans", {}),
    ("get_scan_summary", {"scan_id": SCAN_ID}),
    ("find_public_s3_buckets", {"scan_id": SCAN_ID}),
    ("find_public_ec2_instances", {"scan_id": SCAN_ID}),
    ("find_security_group_rules", {"scan_id": SCAN_ID, "allow_all_ingress": True}),
    ("search_by_ip", {"ip_address": "203.0.113.10"}),
    ("get_vpc_architecture", {"vpc_id": "vpc-fix-1", "scan_id": SCAN_ID}),
    ("get_iam_users", {"scan_id": SCAN_ID, "no_mfa_only": True}),
    ("get_prowler_findings", {"scan_id": SCAN_ID, "severity": "HIGH"}),
    ("compare_scans", {"scan_id_1": SCAN_ID, "scan_id_2": SCAN_ID_2}),
    ("get_load_balancers", {"scan_id": SCAN_ID}),
    ("get_nat_gateways", {"scan_id": SCAN_ID}),
    ("get_route_tables", {"scan_id": SCAN_ID}),
    ("get_internet_gateways", {"scan_id": SCAN_ID}),
    ("get_auto_scaling_groups", {"scan_id": SCAN_ID}),
    ("get_network_interfaces_with_public_ips", {"scan_id": SCAN_ID}),
    ("get_ec2_summary_by_account", {}),
    ("get_ec2_changes", {"account_number": FIXTURE_ACCOUNT_NUMBER}),
    ("get_vpc_topology_detailed", {"vpc_id": "vpc-fix-1", "scan_id": SCAN_ID}),
    ("get_workspaces_summary", {"scan_id": SCAN_ID}),
    ("get_s3_lifecycle_policies", {"scan_id": SCAN_ID}),
    ("get_lambda_summary", {"scan_id": SCAN_ID}),
    ("get_route53_zones", {"scan_id": SCAN_ID}),
    ("get_route53_records", {"hosted_zone_id": "Z-FIXTURE001"}),
    ("get_route53_changes", {"account_number": FIXTURE_ACCOUNT_NUMBER}),
    ("get_vpc_flow_log_coverage", {"scan_id": SCAN_ID}),
    ("get_total_cost", {"account_number": FIXTURE_ACCOUNT_NUMBER}),
    ("get_cost_by_service", {"account_number": FIXTURE_ACCOUNT_NUMBER}),
    ("get_cost_trends", {"account_number": FIXTURE_ACCOUNT_NUMBER}),
    ("get_cost_comparison", {}),
    ("analyze_vpc_cidrs", {"scan_id": SCAN_ID}),
    ("find_unused_resources", {"scan_id": SCAN_ID}),
    ("analyze_encryption_coverage", {"scan_id": SCAN_ID}),
    ("find_publicly_accessible_databases", {"scan_id": SCAN_ID}),
    ("analyze_iam_permissions", {"scan_id": SCAN_ID}),
    ("analyze_backup_coverage", {"scan_id": SCAN_ID}),
    ("find_security_group_violations", {"scan_id": SCAN_ID}),
    ("analyze_tag_compliance", {"scan_id": SCAN_ID}),
    ("analyze_container_vulnerabilities", {"scan_id": SCAN_ID}),
    ("find_vpc_endpoint_opportunities", {"scan_id": SCAN_ID}),
    ("get_organizations_structure", {"scan_id": SCAN_ID}),
    ("get_sso_permissions", {"scan_id": SCAN_ID}),
    ("analyze_cloudtrail_coverage", {"scan_id": SCAN_ID}),
    ("analyze_logging_coverage", {"scan_id": SCAN_ID}),
    ("get_bedrock_resources", {"scan_id": SCAN_ID}),
    ("analyze_network_connectivity", {"scan_id": SCAN_ID}),
    ("get_directory_services", {"scan_id": SCAN_ID}),
    ("analyze_managed_services", {"scan_id": SCAN_ID}),
    ("get_organizations_cost_breakdown", {"scan_id": SCAN_ID}),
    ("get_security_assessment_data", {"scan_id": SCAN_ID}),
    ("analyze_service_exposure", {"scan_id": SCAN_ID}),
    ("get_security_check_catalogue", {}),
]

# CALL_MATRIX: curated entries first (in the order declared above), then
# every tool from get_tools() invoked with empty arguments, alphabetically
# by tool name -- including tools already covered by a curated entry, since
# the empty-args error/behaviour shape is itself part of what the harness
# gates.
CALL_MATRIX: list[tuple[str, dict]] = list(_CURATED_CALLS) + [
    (tool["name"], {}) for tool in sorted(get_tools(), key=lambda t: t["name"])
]

# Keys whose values are derived from the current clock at query time or at
# row-insertion time, rather than from seeded data, so they cannot be
# captured deterministically and must be normalised out of any baseline
# comparison.
#
# - "age_days": computed by the assessment engine as (now - timestamp).days.
# - "created_at": every table carries a `created_at TEXT
#   server_default=CURRENT_TIMESTAMP` column stamped at insert time; any
#   `SELECT *` (which most legacy query handlers use) surfaces it as the
#   wall-clock moment the fixture row was seeded, which differs between the
#   baseline capture run and every later equivalence-test run.
VOLATILE_KEYS = {"age_days", "created_at"}


def _normalise(value, volatile_keys=None):
    """
    Recursively replace any dict key in `volatile_keys` (default VOLATILE_KEYS),
    at any depth, with a placeholder.

    Shared by the equivalence test and the baseline-capture script so both
    normalise volatile fields identically.
    """
    if volatile_keys is None:
        volatile_keys = VOLATILE_KEYS
    if isinstance(value, dict):
        return {
            key: (
                "<volatile>" if key in volatile_keys else _normalise(val, volatile_keys)
            )
            for key, val in value.items()
        }
    if isinstance(value, list):
        return [_normalise(item, volatile_keys) for item in value]
    return value
