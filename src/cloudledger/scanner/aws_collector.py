"""
AWS resource collection framework.

This module orchestrates the collection of AWS resource data across regions.
Uses Australian English in all documentation and comments.
"""

import boto3
import json
from typing import List, Dict, Any, Optional
from datetime import datetime, UTC
from botocore.exceptions import ClientError

from ..database.models import (
    EC2Instance,
    VPC,
    Subnet,
    SecurityGroup,
    S3Bucket,
    IAMUser,
    IAMRole,
    Route53HostedZone,
    Route53RecordSet,
    LoadBalancer,
    NATGateway,
    InternetGateway,
    RouteTable,
    AutoScalingGroup,
    NetworkInterface,
    WorkSpace,
    LambdaFunction,
    VPCFlowLog,
    CostData,
    EBSVolume,
    EBSSnapshot,
    RDSInstance,
    IAMPolicy,
    KMSKey,
    ElasticIP,
    ECSCluster,
    ECSService,
    ECSTaskDefinition,
    EKSCluster,
    EKSNodeGroup,
    ECRRepository,
    ECRImage,
    APIGatewayRestAPI,
    APIGatewayHttpAPI,
    APIGatewayStage,
    CloudFrontDistribution,
    # Phase 3: Governance, Logging & Advanced Services
    Organization,
    OrganizationalUnit,
    OrganizationAccount,
    SSOPermissionSet,
    SSOAssignment,
    CloudTrail,
    CloudWatchLogGroup,
    ConfigRecorder,
    ConfigRule,
    BedrockModel,
    BedrockGuardrail,
    BedrockKnowledgeBase,
    BedrockAgent,
    DirectoryService,
    TransitGateway,
    VPNConnection,
    DirectConnectConnection,
    ElastiCacheCluster,
    OpenSearchDomain,
    MSKCluster,
    DynamoDBTable,
    AccountSecurityPosture,
    IAMCredentialReportEntry,
    RegionSecurityServices,
    LambdaExposure,
    S3PublicAccess,
)
from ..utils.aws_helpers import get_all_regions, parse_tags
from ..utils.logging_config import get_logger

logger = get_logger(__name__)


class AWSCollector:
    """Collects AWS resource data across multiple regions."""

    # Global services that don't require regional scanning
    GLOBAL_SERVICES = ["iam", "s3", "route53", "organizations"]

    # Services that are region-specific
    REGIONAL_SERVICES = ["ec2", "vpc"]

    def __init__(
        self, session: boto3.Session, scan_id: str, regions: Optional[List[str]] = None
    ):
        """
        Initialise AWS collector.

        Args:
            session: Boto3 session with valid credentials
            scan_id: Unique identifier for this scan
            regions: List of regions to scan (None = all regions)
        """
        self.session = session
        self.scan_id = scan_id

        # Determine regions to scan
        if regions:
            self.regions = regions
            logger.info(f"Scanning specified regions: {', '.join(regions)}")
        else:
            self.regions = get_all_regions()
            logger.info(f"Scanning all {len(self.regions)} regions")

    def collect_all_resources(self) -> Dict[str, Any]:
        """
        Collect all AWS resources (both global and regional).

        Returns:
            Dictionary containing all collected resources
        """
        logger.info(f"Starting resource collection for scan {self.scan_id}")

        resources = {
            "ec2_instances": [],
            "vpcs": [],
            "subnets": [],
            "security_groups": [],
            "load_balancers": [],
            "nat_gateways": [],
            "internet_gateways": [],
            "route_tables": [],
            "auto_scaling_groups": [],
            "network_interfaces": [],
            "workspaces": [],
            "lambda_functions": [],
            "vpc_flow_logs": [],
            "s3_buckets": [],
            "iam_users": [],
            "iam_roles": [],
            "iam_policies": [],
            "route53_hosted_zones": [],
            "route53_record_sets": [],
            "cost_data": [],
            "ebs_volumes": [],
            "ebs_snapshots": [],
            "rds_instances": [],
            "kms_keys": [],
            "elastic_ips": [],
            # Phase 2: Containers & Application Services
            "ecs_clusters": [],
            "ecs_services": [],
            "ecs_task_definitions": [],
            "eks_clusters": [],
            "eks_node_groups": [],
            "ecr_repositories": [],
            "ecr_images": [],
            "api_gateway_rest_apis": [],
            "api_gateway_http_apis": [],
            "api_gateway_stages": [],
            "cloudfront_distributions": [],
            # Phase 3: Governance, Logging & Advanced Services
            "organizations": [],
            "organizational_units": [],
            "organization_accounts": [],
            "sso_permission_sets": [],
            "sso_assignments": [],
            "cloudtrail_trails": [],
            "cloudwatch_log_groups": [],
            "config_recorders": [],
            "config_rules": [],
            "bedrock_models": [],
            "bedrock_guardrails": [],
            "bedrock_knowledge_bases": [],
            "bedrock_agents": [],
            "directory_services": [],
            "transit_gateways": [],
            "vpn_connections": [],
            "direct_connect_connections": [],
            "elasticache_clusters": [],
            "opensearch_domains": [],
            "msk_clusters": [],
            "dynamodb_tables": [],
            # Security assessment data
            "account_security_posture": [],
            "iam_credential_report": [],
            "region_security_services": [],
            "lambda_exposure": [],
            "s3_public_access": [],
        }

        # Collect global resources (IAM, S3, Route53, Cost Data, CloudFront, Organizations, SSO)
        logger.info("Collecting global resources...")
        try:
            resources["iam_users"] = self.collect_iam_users()
            resources["iam_roles"] = self.collect_iam_roles()
            resources["iam_policies"] = self.collect_iam_policies()
            resources["s3_buckets"] = self.collect_s3_buckets()
            resources["route53_hosted_zones"], resources["route53_record_sets"] = (
                self.collect_route53()
            )
            resources["cost_data"] = self.collect_cost_data()
            resources["cloudfront_distributions"] = (
                self.collect_cloudfront_distributions()
            )
            # Phase 3 global resources
            (
                resources["organizations"],
                resources["organizational_units"],
                resources["organization_accounts"],
            ) = self.collect_organizations()
            resources["sso_permission_sets"], resources["sso_assignments"] = (
                self.collect_sso()
            )
            # Account security posture and credential report
            posture, credential_entries = self.collect_account_security_posture()
            if posture:
                resources["account_security_posture"].append(posture)
            resources["iam_credential_report"].extend(credential_entries)
            # Per-bucket S3 public access facts
            resources["s3_public_access"].extend(self.collect_s3_public_access())
        except Exception as e:
            logger.error(f"Error collecting global resources: {e}", exc_info=True)

        # Collect regional resources
        for region in self.regions:
            logger.info(f"Collecting resources from region: {region}")

            try:
                # EC2 instances
                instances = self.collect_ec2_instances(region)
                resources["ec2_instances"].extend(instances)

                # VPCs
                vpcs = self.collect_vpcs(region)
                resources["vpcs"].extend(vpcs)

                # Subnets
                subnets = self.collect_subnets(region)
                resources["subnets"].extend(subnets)

                # Security Groups
                security_groups = self.collect_security_groups(region)
                resources["security_groups"].extend(security_groups)

                # Load Balancers
                load_balancers = self.collect_load_balancers(region)
                resources["load_balancers"].extend(load_balancers)

                # NAT Gateways
                nat_gateways = self.collect_nat_gateways(region)
                resources["nat_gateways"].extend(nat_gateways)

                # Internet Gateways
                internet_gateways = self.collect_internet_gateways(region)
                resources["internet_gateways"].extend(internet_gateways)

                # Route Tables
                route_tables = self.collect_route_tables(region)
                resources["route_tables"].extend(route_tables)

                # Auto Scaling Groups
                auto_scaling_groups = self.collect_auto_scaling_groups(region)
                resources["auto_scaling_groups"].extend(auto_scaling_groups)

                # Network Interfaces
                network_interfaces = self.collect_network_interfaces(region)
                resources["network_interfaces"].extend(network_interfaces)

                # WorkSpaces
                workspaces = self.collect_workspaces(region)
                resources["workspaces"].extend(workspaces)

                # Lambda Functions
                lambda_functions = self.collect_lambda_functions(region)
                resources["lambda_functions"].extend(lambda_functions)

                # VPC Flow Logs
                vpc_flow_logs = self.collect_vpc_flow_logs(region)
                resources["vpc_flow_logs"].extend(vpc_flow_logs)

                # EBS Volumes
                ebs_volumes = self.collect_ebs_volumes(region)
                resources["ebs_volumes"].extend(ebs_volumes)

                # EBS Snapshots
                ebs_snapshots = self.collect_ebs_snapshots(region)
                resources["ebs_snapshots"].extend(ebs_snapshots)

                # RDS Instances
                rds_instances = self.collect_rds_instances(region)
                resources["rds_instances"].extend(rds_instances)

                # KMS Keys
                kms_keys = self.collect_kms_keys(region)
                resources["kms_keys"].extend(kms_keys)

                # Elastic IPs
                elastic_ips = self.collect_elastic_ips(region)
                resources["elastic_ips"].extend(elastic_ips)

                # Region security services
                region_services = self.collect_region_security_services(region)
                if region_services:
                    resources["region_security_services"].append(region_services)

                # Lambda exposure (function URLs and resource policies)
                resources["lambda_exposure"].extend(
                    self.collect_lambda_exposure(region)
                )

                # Phase 2: ECS Resources
                ecs_clusters = self.collect_ecs_clusters(region)
                resources["ecs_clusters"].extend(ecs_clusters)

                ecs_services = self.collect_ecs_services(region)
                resources["ecs_services"].extend(ecs_services)

                ecs_task_definitions = self.collect_ecs_task_definitions(region)
                resources["ecs_task_definitions"].extend(ecs_task_definitions)

                # EKS Resources
                eks_clusters = self.collect_eks_clusters(region)
                resources["eks_clusters"].extend(eks_clusters)

                eks_node_groups = self.collect_eks_node_groups(region)
                resources["eks_node_groups"].extend(eks_node_groups)

                # ECR Resources
                ecr_repositories = self.collect_ecr_repositories(region)
                resources["ecr_repositories"].extend(ecr_repositories)

                ecr_images = self.collect_ecr_images(region)
                resources["ecr_images"].extend(ecr_images)

                # API Gateway Resources
                api_gateway_rest_apis = self.collect_api_gateway_rest_apis(region)
                resources["api_gateway_rest_apis"].extend(api_gateway_rest_apis)

                api_gateway_http_apis = self.collect_api_gateway_http_apis(region)
                resources["api_gateway_http_apis"].extend(api_gateway_http_apis)

                api_gateway_stages = self.collect_api_gateway_stages(region)
                resources["api_gateway_stages"].extend(api_gateway_stages)

                # Phase 3: Logging & Monitoring
                cloudtrail_trails = self.collect_cloudtrail_trails(region)
                resources["cloudtrail_trails"].extend(cloudtrail_trails)

                cloudwatch_log_groups = self.collect_cloudwatch_log_groups(region)
                resources["cloudwatch_log_groups"].extend(cloudwatch_log_groups)

                config_recorders = self.collect_config_recorders(region)
                resources["config_recorders"].extend(config_recorders)

                config_rules = self.collect_config_rules(region)
                resources["config_rules"].extend(config_rules)

                # Phase 3: Bedrock
                bedrock_models = self.collect_bedrock_models(region)
                resources["bedrock_models"].extend(bedrock_models)

                bedrock_guardrails = self.collect_bedrock_guardrails(region)
                resources["bedrock_guardrails"].extend(bedrock_guardrails)

                bedrock_knowledge_bases = self.collect_bedrock_knowledge_bases(region)
                resources["bedrock_knowledge_bases"].extend(bedrock_knowledge_bases)

                bedrock_agents = self.collect_bedrock_agents(region)
                resources["bedrock_agents"].extend(bedrock_agents)

                # Phase 3: Directory & Networking
                directory_services = self.collect_directory_services(region)
                resources["directory_services"].extend(directory_services)

                transit_gateways = self.collect_transit_gateways(region)
                resources["transit_gateways"].extend(transit_gateways)

                vpn_connections = self.collect_vpn_connections(region)
                resources["vpn_connections"].extend(vpn_connections)

                direct_connect_connections = self.collect_direct_connect_connections(
                    region
                )
                resources["direct_connect_connections"].extend(
                    direct_connect_connections
                )

                # Phase 3: Managed Services
                elasticache_clusters = self.collect_elasticache_clusters(region)
                resources["elasticache_clusters"].extend(elasticache_clusters)

                opensearch_domains = self.collect_opensearch_domains(region)
                resources["opensearch_domains"].extend(opensearch_domains)

                msk_clusters = self.collect_msk_clusters(region)
                resources["msk_clusters"].extend(msk_clusters)

                dynamodb_tables = self.collect_dynamodb_tables(region)
                resources["dynamodb_tables"].extend(dynamodb_tables)

            except Exception as e:
                logger.error(
                    f"Error collecting resources from region {region}: {e}",
                    exc_info=True,
                )

        # Log summary
        for resource_type, items in resources.items():
            logger.info(f"Collected {len(items)} {resource_type}")

        return resources

    def collect_ec2_instances(self, region: str) -> List[EC2Instance]:
        """
        Collect EC2 instances from a specific region.

        Args:
            region: AWS region

        Returns:
            List of EC2 instance models
        """
        instances = []
        ec2_client = self.session.client("ec2", region_name=region)

        try:
            paginator = ec2_client.get_paginator("describe_instances")
            for page in paginator.paginate():
                for reservation in page["Reservations"]:
                    for instance_data in reservation["Instances"]:
                        try:
                            instance = EC2Instance(
                                scan_id=self.scan_id,
                                instance_id=instance_data["InstanceId"],
                                region=region,
                                instance_type=instance_data["InstanceType"],
                                state=instance_data["State"]["Name"],
                                public_ip=instance_data.get("PublicIpAddress"),
                                private_ip=instance_data.get("PrivateIpAddress"),
                                vpc_id=instance_data.get("VpcId"),
                                subnet_id=instance_data.get("SubnetId"),
                                availability_zone=instance_data["Placement"][
                                    "AvailabilityZone"
                                ],
                                launch_time=instance_data[
                                    "LaunchTime"
                                ],  # boto3 returns datetime objects
                                platform=instance_data.get("Platform"),
                                security_groups=[
                                    sg["GroupId"]
                                    for sg in instance_data.get("SecurityGroups", [])
                                ],
                                tags=parse_tags(instance_data.get("Tags", [])),
                                iam_instance_profile=instance_data.get(
                                    "IamInstanceProfile", {}
                                ).get("Arn"),
                                monitoring_state=instance_data.get(
                                    "Monitoring", {}
                                ).get("State"),
                                raw_data=instance_data,
                            )
                            instances.append(instance)
                        except Exception as e:
                            logger.error(
                                f"Error parsing EC2 instance {instance_data.get('InstanceId')}: {e}"
                            )

            logger.debug(f"Collected {len(instances)} EC2 instances from {region}")
        except ClientError as e:
            logger.error(f"Failed to collect EC2 instances from {region}: {e}")

        return instances

    def collect_vpcs(self, region: str) -> List[VPC]:
        """
        Collect VPCs from a specific region.

        Args:
            region: AWS region

        Returns:
            List of VPC models
        """
        vpcs = []
        ec2_client = self.session.client("ec2", region_name=region)

        try:
            paginator = ec2_client.get_paginator("describe_vpcs")
            for page in paginator.paginate():
                for vpc_data in page["Vpcs"]:
                    try:
                        vpc = VPC(
                            scan_id=self.scan_id,
                            vpc_id=vpc_data["VpcId"],
                            region=region,
                            cidr_block=vpc_data["CidrBlock"],
                            state=vpc_data["State"],
                            is_default=vpc_data.get("IsDefault", False),
                            dhcp_options_id=vpc_data.get("DhcpOptionsId"),
                            instance_tenancy=vpc_data.get("InstanceTenancy", "default"),
                            tags=parse_tags(vpc_data.get("Tags", [])),
                            raw_data=vpc_data,
                        )
                        vpcs.append(vpc)
                    except Exception as e:
                        logger.error(f"Error parsing VPC {vpc_data.get('VpcId')}: {e}")

            logger.debug(f"Collected {len(vpcs)} VPCs from {region}")
        except ClientError as e:
            logger.error(f"Failed to collect VPCs from {region}: {e}")

        return vpcs

    def collect_subnets(self, region: str) -> List[Subnet]:
        """
        Collect subnets from a specific region.

        Args:
            region: AWS region

        Returns:
            List of subnet models
        """
        subnets = []
        ec2_client = self.session.client("ec2", region_name=region)

        try:
            paginator = ec2_client.get_paginator("describe_subnets")
            for page in paginator.paginate():
                for subnet_data in page["Subnets"]:
                    try:
                        subnet = Subnet(
                            scan_id=self.scan_id,
                            subnet_id=subnet_data["SubnetId"],
                            vpc_id=subnet_data["VpcId"],
                            region=region,
                            cidr_block=subnet_data["CidrBlock"],
                            availability_zone=subnet_data["AvailabilityZone"],
                            available_ip_count=subnet_data["AvailableIpAddressCount"],
                            map_public_ip=subnet_data.get("MapPublicIpOnLaunch", False),
                            state=subnet_data["State"],
                            tags=parse_tags(subnet_data.get("Tags", [])),
                            raw_data=subnet_data,
                        )
                        subnets.append(subnet)
                    except Exception as e:
                        logger.error(
                            f"Error parsing subnet {subnet_data.get('SubnetId')}: {e}"
                        )

            logger.debug(f"Collected {len(subnets)} subnets from {region}")
        except ClientError as e:
            logger.error(f"Failed to collect subnets from {region}: {e}")

        return subnets

    def collect_security_groups(self, region: str) -> List[SecurityGroup]:
        """
        Collect security groups from a specific region.

        Args:
            region: AWS region

        Returns:
            List of security group models
        """
        security_groups = []
        ec2_client = self.session.client("ec2", region_name=region)

        try:
            paginator = ec2_client.get_paginator("describe_security_groups")
            for page in paginator.paginate():
                for sg_data in page["SecurityGroups"]:
                    try:
                        sg = SecurityGroup(
                            scan_id=self.scan_id,
                            group_id=sg_data["GroupId"],
                            group_name=sg_data["GroupName"],
                            vpc_id=sg_data.get("VpcId"),
                            region=region,
                            description=sg_data["Description"],
                            ingress_rules=sg_data.get("IpPermissions", []),
                            egress_rules=sg_data.get("IpPermissionsEgress", []),
                            tags=parse_tags(sg_data.get("Tags", [])),
                            raw_data=sg_data,
                        )
                        security_groups.append(sg)
                    except Exception as e:
                        logger.error(
                            f"Error parsing security group {sg_data.get('GroupId')}: {e}"
                        )

            logger.debug(
                f"Collected {len(security_groups)} security groups from {region}"
            )
        except ClientError as e:
            logger.error(f"Failed to collect security groups from {region}: {e}")

        return security_groups

    def collect_s3_buckets(self) -> List[S3Bucket]:
        """
        Collect S3 buckets (global service).

        Returns:
            List of S3 bucket models
        """
        buckets = []
        s3_client = self.session.client("s3")

        try:
            response = s3_client.list_buckets()
            for bucket_data in response["Buckets"]:
                bucket_name = bucket_data["Name"]

                try:
                    # Get bucket location
                    location_response = s3_client.get_bucket_location(
                        Bucket=bucket_name
                    )
                    region = location_response.get("LocationConstraint") or "us-east-1"

                    # Get bucket versioning
                    try:
                        versioning = s3_client.get_bucket_versioning(Bucket=bucket_name)
                        versioning_status = versioning.get("Status")
                    except ClientError:
                        versioning_status = None

                    # Get public access block
                    try:
                        pab = s3_client.get_public_access_block(Bucket=bucket_name)
                        public_access_block = pab.get("PublicAccessBlockConfiguration")
                    except ClientError:
                        public_access_block = None

                    # Get bucket tags
                    try:
                        tag_response = s3_client.get_bucket_tagging(Bucket=bucket_name)
                        tags = parse_tags(tag_response.get("TagSet", []))
                    except ClientError:
                        tags = {}

                    bucket = S3Bucket(
                        scan_id=self.scan_id,
                        bucket_name=bucket_name,
                        creation_date=bucket_data[
                            "CreationDate"
                        ],  # boto3 returns datetime objects
                        region=region,
                        versioning_status=versioning_status,
                        public_access_block=public_access_block,
                        encryption_config=None,  # Can be expanded
                        lifecycle_rules=[],  # Can be expanded
                        logging_enabled=False,  # Can be expanded
                        size_bytes=None,  # Requires CloudWatch metrics
                        object_count=None,  # Requires CloudWatch metrics
                        tags=tags,
                        raw_data=bucket_data,
                    )
                    buckets.append(bucket)

                except Exception as e:
                    logger.error(f"Error processing S3 bucket {bucket_name}: {e}")

            logger.debug(f"Collected {len(buckets)} S3 buckets")
        except ClientError as e:
            logger.error(f"Failed to collect S3 buckets: {e}")

        return buckets

    def collect_iam_users(self) -> List[IAMUser]:
        """
        Collect IAM users (global service).

        Returns:
            List of IAM user models
        """
        users = []
        iam_client = self.session.client("iam")

        try:
            paginator = iam_client.get_paginator("list_users")
            for page in paginator.paginate():
                for user_data in page["Users"]:
                    try:
                        user_name = user_data["UserName"]

                        # Get MFA devices
                        mfa_response = iam_client.list_mfa_devices(UserName=user_name)
                        mfa_enabled = len(mfa_response.get("MFADevices", [])) > 0

                        # Get access keys
                        keys_response = iam_client.list_access_keys(UserName=user_name)
                        access_keys = keys_response.get("AccessKeyMetadata", [])

                        # Get attached policies
                        policies_response = iam_client.list_attached_user_policies(
                            UserName=user_name
                        )
                        attached_policies = [
                            p["PolicyArn"]
                            for p in policies_response.get("AttachedPolicies", [])
                        ]

                        # Get groups
                        groups_response = iam_client.list_groups_for_user(
                            UserName=user_name
                        )
                        groups = [
                            g["GroupName"] for g in groups_response.get("Groups", [])
                        ]

                        # Get tags
                        try:
                            tags_response = iam_client.list_user_tags(
                                UserName=user_name
                            )
                            tags = parse_tags(tags_response.get("Tags", []))
                        except ClientError:
                            tags = {}

                        user = IAMUser(
                            scan_id=self.scan_id,
                            user_name=user_name,
                            user_id=user_data["UserId"],
                            arn=user_data["Arn"],
                            create_date=user_data[
                                "CreateDate"
                            ],  # boto3 returns datetime objects
                            password_last_used=user_data.get(
                                "PasswordLastUsed"
                            ),  # boto3 returns datetime objects
                            mfa_enabled=mfa_enabled,
                            access_keys=access_keys,
                            attached_policies=attached_policies,
                            groups=groups,
                            tags=tags,
                            raw_data=user_data,
                        )
                        users.append(user)

                    except Exception as e:
                        logger.error(
                            f"Error processing IAM user {user_data.get('UserName')}: {e}"
                        )

            logger.debug(f"Collected {len(users)} IAM users")
        except ClientError as e:
            logger.error(f"Failed to collect IAM users: {e}")

        return users

    def collect_iam_roles(self) -> List[IAMRole]:
        """
        Collect IAM roles (global service).

        Returns:
            List of IAM role models
        """
        roles = []
        iam_client = self.session.client("iam")

        try:
            paginator = iam_client.get_paginator("list_roles")
            for page in paginator.paginate():
                for role_data in page["Roles"]:
                    try:
                        role_name = role_data["RoleName"]

                        # Get attached policies
                        policies_response = iam_client.list_attached_role_policies(
                            RoleName=role_name
                        )
                        attached_policies = [
                            p["PolicyArn"]
                            for p in policies_response.get("AttachedPolicies", [])
                        ]

                        # Get tags
                        try:
                            tags_response = iam_client.list_role_tags(
                                RoleName=role_name
                            )
                            tags = parse_tags(tags_response.get("Tags", []))
                        except ClientError:
                            tags = {}

                        role = IAMRole(
                            scan_id=self.scan_id,
                            role_name=role_name,
                            role_id=role_data["RoleId"],
                            arn=role_data["Arn"],
                            create_date=role_data[
                                "CreateDate"
                            ],  # boto3 returns datetime objects
                            assume_role_policy=role_data["AssumeRolePolicyDocument"],
                            attached_policies=attached_policies,
                            max_session_duration=role_data.get(
                                "MaxSessionDuration", 3600
                            ),
                            tags=tags,
                            raw_data=role_data,
                        )
                        roles.append(role)

                    except Exception as e:
                        logger.error(
                            f"Error processing IAM role {role_data.get('RoleName')}: {e}"
                        )

            logger.debug(f"Collected {len(roles)} IAM roles")
        except ClientError as e:
            logger.error(f"Failed to collect IAM roles: {e}")

        return roles

    def collect_route53(self) -> tuple[List[Route53HostedZone], List[Route53RecordSet]]:
        """
        Collect Route53 hosted zones and record sets (global service).

        Returns:
            Tuple of (hosted zones list, record sets list)
        """
        hosted_zones = []
        record_sets = []
        route53_client = self.session.client("route53")

        try:
            paginator = route53_client.get_paginator("list_hosted_zones")
            for page in paginator.paginate():
                for zone_data in page["HostedZones"]:
                    try:
                        zone_id = zone_data["Id"].split("/")[-1]

                        # Get hosted zone tags
                        try:
                            tags_response = route53_client.list_tags_for_resource(
                                ResourceType="hostedzone", ResourceId=zone_id
                            )
                            tags = parse_tags(tags_response.get("Tags", []))
                        except ClientError:
                            tags = {}

                        zone = Route53HostedZone(
                            scan_id=self.scan_id,
                            hosted_zone_id=zone_id,
                            name=zone_data["Name"],
                            is_private=zone_data.get("Config", {}).get(
                                "PrivateZone", False
                            ),
                            resource_record_set_count=zone_data[
                                "ResourceRecordSetCount"
                            ],
                            vpc_associations=[],  # Can be expanded
                            tags=tags,
                            raw_data=zone_data,
                        )
                        hosted_zones.append(zone)

                        # Get record sets for this zone
                        record_paginator = route53_client.get_paginator(
                            "list_resource_record_sets"
                        )
                        for record_page in record_paginator.paginate(
                            HostedZoneId=zone_data["Id"]
                        ):
                            for record_data in record_page["ResourceRecordSets"]:
                                try:
                                    record = Route53RecordSet(
                                        scan_id=self.scan_id,
                                        hosted_zone_id=zone_id,
                                        name=record_data["Name"],
                                        record_type=record_data["Type"],
                                        ttl=record_data.get("TTL"),
                                        resource_records=[
                                            r["Value"]
                                            for r in record_data.get(
                                                "ResourceRecords", []
                                            )
                                        ],
                                        alias_target=record_data.get("AliasTarget"),
                                        raw_data=record_data,
                                    )
                                    record_sets.append(record)
                                except Exception as e:
                                    logger.error(
                                        f"Error processing Route53 record: {e}"
                                    )

                    except Exception as e:
                        logger.error(
                            f"Error processing Route53 hosted zone {zone_data.get('Id')}: {e}"
                        )

            logger.debug(
                f"Collected {len(hosted_zones)} Route53 hosted zones and {len(record_sets)} record sets"
            )
        except ClientError as e:
            logger.error(f"Failed to collect Route53 resources: {e}")

        return hosted_zones, record_sets

    def collect_load_balancers(self, region: str) -> List[LoadBalancer]:
        """
        Collect Load Balancers (ELBv2: ALB/NLB/GWLB and Classic ELB) from a specific region.

        Args:
            region: AWS region

        Returns:
            List of LoadBalancer models
        """
        load_balancers = []

        try:
            # Collect ELBv2 load balancers (ALB, NLB, GWLB)
            elbv2_client = self.session.client("elbv2", region_name=region)
            paginator = elbv2_client.get_paginator("describe_load_balancers")

            for page in paginator.paginate():
                for lb_data in page["LoadBalancers"]:
                    try:
                        # Get tags
                        tags_response = elbv2_client.describe_tags(
                            ResourceArns=[lb_data["LoadBalancerArn"]]
                        )
                        tags = {}
                        if tags_response["TagDescriptions"]:
                            tags = parse_tags(
                                tags_response["TagDescriptions"][0].get("Tags", [])
                            )

                        # Get listeners
                        listeners_response = elbv2_client.describe_listeners(
                            LoadBalancerArn=lb_data["LoadBalancerArn"]
                        )
                        listeners = listeners_response.get("Listeners", [])

                        # Get target groups
                        target_groups_response = elbv2_client.describe_target_groups(
                            LoadBalancerArn=lb_data["LoadBalancerArn"]
                        )
                        target_groups = target_groups_response.get("TargetGroups", [])

                        lb = LoadBalancer(
                            scan_id=self.scan_id,
                            load_balancer_name=lb_data["LoadBalancerName"],
                            load_balancer_arn=lb_data["LoadBalancerArn"],
                            load_balancer_type=lb_data["Type"],
                            region=region,
                            vpc_id=lb_data.get("VpcId"),
                            scheme=lb_data["Scheme"],
                            state=lb_data["State"]["Code"],
                            dns_name=lb_data["DNSName"],
                            availability_zones=[
                                az["ZoneName"]
                                for az in lb_data.get("AvailabilityZones", [])
                            ],
                            security_groups=lb_data.get("SecurityGroups", []),
                            subnets=[
                                az["SubnetId"]
                                for az in lb_data.get("AvailabilityZones", [])
                            ],
                            created_time=lb_data.get("CreatedTime"),
                            listeners=listeners,
                            target_groups=target_groups,
                            tags=tags,
                            raw_data=lb_data,
                        )
                        load_balancers.append(lb)

                    except Exception as e:
                        logger.error(
                            f"Error processing load balancer {lb_data.get('LoadBalancerName')}: {e}"
                        )

            # Collect Classic Load Balancers
            elb_client = self.session.client("elb", region_name=region)
            classic_paginator = elb_client.get_paginator("describe_load_balancers")

            for page in classic_paginator.paginate():
                for lb_data in page["LoadBalancerDescriptions"]:
                    try:
                        # Get tags
                        tags_response = elb_client.describe_tags(
                            LoadBalancerNames=[lb_data["LoadBalancerName"]]
                        )
                        tags = {}
                        if tags_response["TagDescriptions"]:
                            tags = parse_tags(
                                tags_response["TagDescriptions"][0].get("Tags", [])
                            )

                        # Build ARN for classic LB (they don't provide ARN directly)
                        account_id = self.session.client("sts").get_caller_identity()[
                            "Account"
                        ]
                        lb_arn = f"arn:aws:elasticloadbalancing:{region}:{account_id}:loadbalancer/{lb_data['LoadBalancerName']}"

                        lb = LoadBalancer(
                            scan_id=self.scan_id,
                            load_balancer_name=lb_data["LoadBalancerName"],
                            load_balancer_arn=lb_arn,
                            load_balancer_type="classic",
                            region=region,
                            vpc_id=lb_data.get("VPCId"),
                            scheme=lb_data["Scheme"],
                            state="active",  # Classic LBs don't have state
                            dns_name=lb_data["DNSName"],
                            availability_zones=lb_data.get("AvailabilityZones", []),
                            security_groups=lb_data.get("SecurityGroups", []),
                            subnets=lb_data.get("Subnets", []),
                            created_time=lb_data.get("CreatedTime"),
                            listeners=lb_data.get("ListenerDescriptions", []),
                            target_groups=[],  # Classic LBs don't have target groups
                            tags=tags,
                            raw_data=lb_data,
                        )
                        load_balancers.append(lb)

                    except Exception as e:
                        logger.error(
                            f"Error processing classic load balancer {lb_data.get('LoadBalancerName')}: {e}"
                        )

            logger.debug(
                f"Collected {len(load_balancers)} load balancers from {region}"
            )

        except ClientError as e:
            logger.error(f"Failed to collect load balancers from {region}: {e}")

        return load_balancers

    def collect_nat_gateways(self, region: str) -> List[NATGateway]:
        """
        Collect NAT Gateways from a specific region.

        Args:
            region: AWS region

        Returns:
            List of NATGateway models
        """
        nat_gateways = []

        try:
            ec2_client = self.session.client("ec2", region_name=region)
            paginator = ec2_client.get_paginator("describe_nat_gateways")

            for page in paginator.paginate():
                for nat_data in page["NatGateways"]:
                    try:
                        # Extract NAT gateway addresses
                        nat_addresses = nat_data.get("NatGatewayAddresses", [])
                        public_ip = (
                            nat_addresses[0].get("PublicIp") if nat_addresses else None
                        )
                        private_ip = (
                            nat_addresses[0].get("PrivateIp") if nat_addresses else None
                        )

                        nat_gateway = NATGateway(
                            scan_id=self.scan_id,
                            nat_gateway_id=nat_data["NatGatewayId"],
                            region=region,
                            vpc_id=nat_data["VpcId"],
                            subnet_id=nat_data["SubnetId"],
                            state=nat_data["State"],
                            connectivity_type=nat_data.get(
                                "ConnectivityType", "public"
                            ),
                            public_ip=public_ip,
                            private_ip=private_ip,
                            created_time=nat_data.get("CreateTime"),
                            nat_gateway_addresses=nat_addresses,
                            tags=parse_tags(nat_data.get("Tags", [])),
                            raw_data=nat_data,
                        )
                        nat_gateways.append(nat_gateway)

                    except Exception as e:
                        logger.error(
                            f"Error processing NAT gateway {nat_data.get('NatGatewayId')}: {e}"
                        )

            logger.debug(f"Collected {len(nat_gateways)} NAT gateways from {region}")

        except ClientError as e:
            logger.error(f"Failed to collect NAT gateways from {region}: {e}")

        return nat_gateways

    def collect_internet_gateways(self, region: str) -> List[InternetGateway]:
        """
        Collect Internet Gateways from a specific region.

        Args:
            region: AWS region

        Returns:
            List of InternetGateway models
        """
        internet_gateways = []

        try:
            ec2_client = self.session.client("ec2", region_name=region)
            paginator = ec2_client.get_paginator("describe_internet_gateways")

            for page in paginator.paginate():
                for igw_data in page["InternetGateways"]:
                    try:
                        # Extract VPC attachments
                        vpc_attachments = [
                            {"VpcId": att["VpcId"], "State": att["State"]}
                            for att in igw_data.get("Attachments", [])
                        ]

                        igw = InternetGateway(
                            scan_id=self.scan_id,
                            internet_gateway_id=igw_data["InternetGatewayId"],
                            region=region,
                            vpc_attachments=vpc_attachments,
                            tags=parse_tags(igw_data.get("Tags", [])),
                            raw_data=igw_data,
                        )
                        internet_gateways.append(igw)

                    except Exception as e:
                        logger.error(
                            f"Error processing internet gateway {igw_data.get('InternetGatewayId')}: {e}"
                        )

            logger.debug(
                f"Collected {len(internet_gateways)} internet gateways from {region}"
            )

        except ClientError as e:
            logger.error(f"Failed to collect internet gateways from {region}: {e}")

        return internet_gateways

    def collect_route_tables(self, region: str) -> List[RouteTable]:
        """
        Collect Route Tables from a specific region.

        Args:
            region: AWS region

        Returns:
            List of RouteTable models
        """
        route_tables = []

        try:
            ec2_client = self.session.client("ec2", region_name=region)
            paginator = ec2_client.get_paginator("describe_route_tables")

            for page in paginator.paginate():
                for rt_data in page["RouteTables"]:
                    try:
                        # Check if this is the main route table
                        is_main = any(
                            assoc.get("Main", False)
                            for assoc in rt_data.get("Associations", [])
                        )

                        # Extract subnet associations
                        subnet_associations = [
                            assoc["SubnetId"]
                            for assoc in rt_data.get("Associations", [])
                            if "SubnetId" in assoc
                        ]

                        # Extract gateway associations
                        gateway_associations = [
                            assoc.get("GatewayId", "")
                            for assoc in rt_data.get("Associations", [])
                            if "GatewayId" in assoc
                        ]

                        route_table = RouteTable(
                            scan_id=self.scan_id,
                            route_table_id=rt_data["RouteTableId"],
                            region=region,
                            vpc_id=rt_data["VpcId"],
                            is_main=is_main,
                            routes=rt_data.get("Routes", []),
                            subnet_associations=subnet_associations,
                            gateway_associations=gateway_associations,
                            tags=parse_tags(rt_data.get("Tags", [])),
                            raw_data=rt_data,
                        )
                        route_tables.append(route_table)

                    except Exception as e:
                        logger.error(
                            f"Error processing route table {rt_data.get('RouteTableId')}: {e}"
                        )

            logger.debug(f"Collected {len(route_tables)} route tables from {region}")

        except ClientError as e:
            logger.error(f"Failed to collect route tables from {region}: {e}")

        return route_tables

    def collect_auto_scaling_groups(self, region: str) -> List[AutoScalingGroup]:
        """
        Collect Auto Scaling Groups from a specific region.

        Args:
            region: AWS region

        Returns:
            List of AutoScalingGroup models
        """
        auto_scaling_groups = []

        try:
            asg_client = self.session.client("autoscaling", region_name=region)
            paginator = asg_client.get_paginator("describe_auto_scaling_groups")

            for page in paginator.paginate():
                for asg_data in page["AutoScalingGroups"]:
                    try:
                        # Parse tags
                        tags = {}
                        for tag in asg_data.get("Tags", []):
                            if tag.get("Key"):
                                tags[tag["Key"]] = tag.get("Value", "")

                        asg = AutoScalingGroup(
                            scan_id=self.scan_id,
                            auto_scaling_group_name=asg_data["AutoScalingGroupName"],
                            auto_scaling_group_arn=asg_data["AutoScalingGroupARN"],
                            region=region,
                            launch_configuration_name=asg_data.get(
                                "LaunchConfigurationName"
                            ),
                            launch_template=asg_data.get("LaunchTemplate")
                            or asg_data.get("MixedInstancesPolicy", {}).get(
                                "LaunchTemplate"
                            ),
                            min_size=asg_data["MinSize"],
                            max_size=asg_data["MaxSize"],
                            desired_capacity=asg_data["DesiredCapacity"],
                            default_cooldown=asg_data.get("DefaultCooldown", 300),
                            availability_zones=asg_data.get("AvailabilityZones", []),
                            load_balancer_names=asg_data.get("LoadBalancerNames", []),
                            target_group_arns=asg_data.get("TargetGroupARNs", []),
                            health_check_type=asg_data.get("HealthCheckType", "EC2"),
                            health_check_grace_period=asg_data.get(
                                "HealthCheckGracePeriod", 0
                            ),
                            vpc_zone_identifier=asg_data.get("VPCZoneIdentifier"),
                            instances=asg_data.get("Instances", []),
                            created_time=asg_data["CreatedTime"],
                            tags=tags,
                            raw_data=asg_data,
                        )
                        auto_scaling_groups.append(asg)

                    except Exception as e:
                        logger.error(
                            f"Error processing Auto Scaling group {asg_data.get('AutoScalingGroupName')}: {e}"
                        )

            logger.debug(
                f"Collected {len(auto_scaling_groups)} Auto Scaling groups from {region}"
            )

        except ClientError as e:
            logger.error(f"Failed to collect Auto Scaling groups from {region}: {e}")

        return auto_scaling_groups

    def collect_network_interfaces(self, region: str) -> List[NetworkInterface]:
        """
        Collect Network Interfaces (ENIs) from a specific region.

        Args:
            region: AWS region

        Returns:
            List of NetworkInterface models
        """
        network_interfaces = []

        try:
            ec2_client = self.session.client("ec2", region_name=region)
            paginator = ec2_client.get_paginator("describe_network_interfaces")

            for page in paginator.paginate():
                for eni_data in page["NetworkInterfaces"]:
                    try:
                        # Extract security groups
                        security_groups = [
                            sg["GroupId"] for sg in eni_data.get("Groups", [])
                        ]

                        # Extract public IP if present
                        public_ip = None
                        if "Association" in eni_data:
                            public_ip = eni_data["Association"].get("PublicIp")

                        eni = NetworkInterface(
                            scan_id=self.scan_id,
                            network_interface_id=eni_data["NetworkInterfaceId"],
                            region=region,
                            interface_type=eni_data.get("InterfaceType", "interface"),
                            status=eni_data["Status"],
                            vpc_id=eni_data["VpcId"],
                            subnet_id=eni_data["SubnetId"],
                            availability_zone=eni_data["AvailabilityZone"],
                            description=eni_data.get("Description"),
                            private_ip_address=eni_data.get("PrivateIpAddress"),
                            private_ip_addresses=eni_data.get("PrivateIpAddresses", []),
                            public_ip=public_ip,
                            mac_address=eni_data.get("MacAddress"),
                            source_dest_check=eni_data.get("SourceDestCheck", True),
                            security_groups=security_groups,
                            attachment=eni_data.get("Attachment"),
                            tags=parse_tags(eni_data.get("TagSet", [])),
                            raw_data=eni_data,
                        )
                        network_interfaces.append(eni)

                    except Exception as e:
                        logger.error(
                            f"Error processing network interface {eni_data.get('NetworkInterfaceId')}: {e}"
                        )

            logger.debug(
                f"Collected {len(network_interfaces)} network interfaces from {region}"
            )

        except ClientError as e:
            logger.error(f"Failed to collect network interfaces from {region}: {e}")

        return network_interfaces

    def collect_workspaces(self, region: str) -> List[WorkSpace]:
        """
        Collect WorkSpaces from a specific region.

        Args:
            region: AWS region

        Returns:
            List of WorkSpace models
        """
        workspaces = []

        try:
            workspaces_client = self.session.client("workspaces", region_name=region)
            paginator = workspaces_client.get_paginator("describe_workspaces")

            for page in paginator.paginate():
                for ws_data in page["Workspaces"]:
                    try:
                        # Get workspace properties
                        workspace_properties = ws_data.get("WorkspaceProperties", {})

                        # Determine VPC from subnet
                        vpc_id = None
                        if ws_data.get("SubnetId"):
                            try:
                                ec2_client = self.session.client(
                                    "ec2", region_name=region
                                )
                                subnet_response = ec2_client.describe_subnets(
                                    SubnetIds=[ws_data["SubnetId"]]
                                )
                                if subnet_response["Subnets"]:
                                    vpc_id = subnet_response["Subnets"][0]["VpcId"]
                            except ClientError:
                                pass

                        # Get tags
                        try:
                            tags_response = workspaces_client.describe_tags(
                                ResourceId=ws_data["WorkspaceId"]
                            )
                            tags = {}
                            for tag in tags_response.get("TagList", []):
                                tags[tag["Key"]] = tag["Value"]
                        except ClientError:
                            tags = {}

                        workspace = WorkSpace(
                            scan_id=self.scan_id,
                            workspace_id=ws_data["WorkspaceId"],
                            region=region,
                            directory_id=ws_data["DirectoryId"],
                            user_name=ws_data["UserName"],
                            bundle_id=ws_data["BundleId"],
                            subnet_id=ws_data["SubnetId"],
                            vpc_id=vpc_id,
                            ip_address=ws_data.get("IpAddress"),
                            state=ws_data["State"],
                            compute_type=ws_data.get(
                                "ComputeTypeName",
                                workspace_properties.get("ComputeTypeName", "UNKNOWN"),
                            ),
                            volume_encryption_enabled=ws_data.get("VolumeEncryptionKey")
                            is not None,
                            user_volume_size_gb=workspace_properties.get(
                                "UserVolumeSizeGib", 10
                            ),
                            root_volume_size_gb=workspace_properties.get(
                                "RootVolumeSizeGib", 80
                            ),
                            running_mode=workspace_properties.get(
                                "RunningMode", "ALWAYS_ON"
                            ),
                            tags=tags,
                            raw_data=ws_data,
                        )
                        workspaces.append(workspace)

                    except Exception as e:
                        logger.error(
                            f"Error processing WorkSpace {ws_data.get('WorkspaceId')}: {e}"
                        )

            logger.debug(f"Collected {len(workspaces)} WorkSpaces from {region}")

        except ClientError as e:
            # WorkSpaces service may not be available in all regions
            if e.response["Error"]["Code"] != "InvalidParameterValuesException":
                logger.error(f"Failed to collect WorkSpaces from {region}: {e}")
        except Exception as e:
            # Handle network errors and other exceptions
            logger.warning(f"Unable to collect WorkSpaces from {region}: {e}")

        return workspaces

    def collect_lambda_functions(self, region: str) -> List[LambdaFunction]:
        """
        Collect Lambda functions from a specific region.

        Args:
            region: AWS region

        Returns:
            List of LambdaFunction models
        """
        lambda_functions = []

        try:
            lambda_client = self.session.client("lambda", region_name=region)
            paginator = lambda_client.get_paginator("list_functions")

            for page in paginator.paginate():
                for func_data in page["Functions"]:
                    try:
                        function_name = func_data["FunctionName"]

                        # Get function tags
                        try:
                            tags_response = lambda_client.list_tags(
                                Resource=func_data["FunctionArn"]
                            )
                            tags = tags_response.get("Tags", {})
                        except ClientError:
                            tags = {}

                        # Get event source mappings (triggers)
                        triggers = []
                        try:
                            esm_paginator = lambda_client.get_paginator(
                                "list_event_source_mappings"
                            )
                            for esm_page in esm_paginator.paginate(
                                FunctionName=function_name
                            ):
                                triggers.extend(esm_page.get("EventSourceMappings", []))
                        except ClientError:
                            pass

                        # Parse environment variables
                        env_vars = {}
                        if "Environment" in func_data:
                            env_vars = func_data["Environment"].get("Variables", {})

                        # Parse VPC config
                        vpc_config = None
                        if "VpcConfig" in func_data and func_data["VpcConfig"].get(
                            "VpcId"
                        ):
                            vpc_config = {
                                "VpcId": func_data["VpcConfig"].get("VpcId"),
                                "SubnetIds": func_data["VpcConfig"].get(
                                    "SubnetIds", []
                                ),
                                "SecurityGroupIds": func_data["VpcConfig"].get(
                                    "SecurityGroupIds", []
                                ),
                            }

                        # Parse layers
                        layers = [
                            layer.get("Arn", "")
                            for layer in func_data.get("Layers", [])
                        ]

                        lambda_function = LambdaFunction(
                            scan_id=self.scan_id,
                            function_name=function_name,
                            function_arn=func_data["FunctionArn"],
                            region=region,
                            runtime=func_data.get("Runtime", "unknown"),
                            handler=func_data["Handler"],
                            code_size=func_data["CodeSize"],
                            memory_size=func_data["MemorySize"],
                            timeout=func_data["Timeout"],
                            last_modified=datetime.fromisoformat(
                                func_data["LastModified"].replace("Z", "+00:00")
                            ),
                            role_arn=func_data["Role"],
                            vpc_config=vpc_config,
                            environment_variables=env_vars,
                            layers=layers,
                            state=func_data.get("State", "Active"),
                            architectures=func_data.get("Architectures", ["x86_64"]),
                            triggers=triggers,
                            tags=tags,
                            raw_data=func_data,
                        )
                        lambda_functions.append(lambda_function)

                    except Exception as e:
                        logger.error(
                            f"Error processing Lambda function {func_data.get('FunctionName')}: {e}"
                        )

            logger.debug(
                f"Collected {len(lambda_functions)} Lambda functions from {region}"
            )

        except ClientError as e:
            logger.error(f"Failed to collect Lambda functions from {region}: {e}")

        return lambda_functions

    def collect_vpc_flow_logs(self, region: str) -> List[VPCFlowLog]:
        """
        Collect VPC Flow Logs from a specific region.

        Args:
            region: AWS region

        Returns:
            List of VPCFlowLog models
        """
        vpc_flow_logs = []

        try:
            ec2_client = self.session.client("ec2", region_name=region)
            paginator = ec2_client.get_paginator("describe_flow_logs")

            for page in paginator.paginate():
                for flow_log_data in page["FlowLogs"]:
                    try:
                        flow_log = VPCFlowLog(
                            scan_id=self.scan_id,
                            flow_log_id=flow_log_data["FlowLogId"],
                            region=region,
                            resource_id=flow_log_data["ResourceId"],
                            resource_type=flow_log_data.get("ResourceType", "VPC"),
                            traffic_type=flow_log_data["TrafficType"],
                            log_destination_type=flow_log_data.get(
                                "LogDestinationType", "cloud-watch-logs"
                            ),
                            log_destination=flow_log_data.get("LogDestination", ""),
                            log_format=flow_log_data.get("LogFormat"),
                            flow_log_status=flow_log_data["FlowLogStatus"],
                            created_time=flow_log_data.get("CreationTime"),
                            tags=parse_tags(flow_log_data.get("Tags", [])),
                            raw_data=flow_log_data,
                        )
                        vpc_flow_logs.append(flow_log)

                    except Exception as e:
                        logger.error(
                            f"Error processing VPC Flow Log {flow_log_data.get('FlowLogId')}: {e}"
                        )

            logger.debug(f"Collected {len(vpc_flow_logs)} VPC Flow Logs from {region}")

        except ClientError as e:
            logger.error(f"Failed to collect VPC Flow Logs from {region}: {e}")

        return vpc_flow_logs

    def collect_cost_data(self) -> List[CostData]:
        """
        Collect cost and billing data for the past 12 months (global service).

        Returns:
            List of CostData models
        """
        cost_records = []

        try:
            # Cost Explorer is only available in us-east-1
            ce_client = self.session.client("ce", region_name="us-east-1")

            # Get account number
            sts_client = self.session.client("sts")
            account_number = sts_client.get_caller_identity()["Account"]

            # Calculate time period (last 12 months)
            from dateutil.relativedelta import relativedelta

            end_date = datetime.now().date()
            start_date = end_date - relativedelta(months=12)

            logger.info(
                f"Collecting cost data from {start_date} to {end_date} for account {account_number}"
            )

            # Get cost data grouped by service and month
            # IMPORTANT: Filter by LINKED_ACCOUNT to get only this account's costs,
            # not consolidated costs from all Organisation accounts
            response = ce_client.get_cost_and_usage(
                TimePeriod={
                    "Start": start_date.strftime("%Y-%m-%d"),
                    "End": end_date.strftime("%Y-%m-%d"),
                },
                Granularity="MONTHLY",
                Metrics=["UnblendedCost"],
                Filter={
                    "Dimensions": {"Key": "LINKED_ACCOUNT", "Values": [account_number]}
                },
                GroupBy=[{"Type": "DIMENSION", "Key": "SERVICE"}],
            )

            # Process results
            for time_period in response.get("ResultsByTime", []):
                period_start = datetime.strptime(
                    time_period["TimePeriod"]["Start"], "%Y-%m-%d"
                )
                period_end = datetime.strptime(
                    time_period["TimePeriod"]["End"], "%Y-%m-%d"
                )

                for group in time_period.get("Groups", []):
                    service_name = group["Keys"][0] if group["Keys"] else "Unknown"

                    # Get cost amount
                    metrics = group.get("Metrics", {})
                    unblended_cost = metrics.get("UnblendedCost", {})
                    amount = float(unblended_cost.get("Amount", 0.0))
                    currency = unblended_cost.get("Unit", "USD")

                    # Only record non-zero costs
                    if amount > 0:
                        cost_record = CostData(
                            scan_id=self.scan_id,
                            account_number=account_number,
                            time_period_start=period_start,
                            time_period_end=period_end,
                            service_name=service_name,
                            amount=amount,
                            currency=currency,
                            unit="UnblendedCost",
                            raw_data=group,
                        )
                        cost_records.append(cost_record)

            logger.debug(f"Collected {len(cost_records)} cost records")

        except ClientError as e:
            # Cost Explorer might not be enabled for the account
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code == "AccessDeniedException":
                logger.warning(
                    "Cost Explorer access denied - may not be enabled for this account"
                )
            else:
                logger.error(f"Failed to collect cost data: {e}")
        except Exception as e:
            logger.error(f"Unexpected error collecting cost data: {e}", exc_info=True)

        return cost_records

    def collect_ebs_volumes(self, region: str) -> List[EBSVolume]:
        """
        Collect EBS volumes from a specific region.

        Args:
            region: AWS region

        Returns:
            List of EBS volume resources
        """
        volumes = []
        try:
            ec2_client = self.session.client("ec2", region_name=region)
            paginator = ec2_client.get_paginator("describe_volumes")

            for page in paginator.paginate():
                for vol_data in page["Volumes"]:
                    # Parse attachment information
                    attached_instance_id = None
                    device_name = None
                    attachment_state = None

                    if vol_data.get("Attachments"):
                        attachment = vol_data["Attachments"][0]  # Primary attachment
                        attached_instance_id = attachment.get("InstanceId")
                        device_name = attachment.get("Device")
                        attachment_state = attachment.get("State")

                    volume = EBSVolume(
                        scan_id=self.scan_id,
                        volume_id=vol_data["VolumeId"],
                        region=region,
                        size=vol_data["Size"],
                        volume_type=vol_data["VolumeType"],
                        iops=vol_data.get("Iops"),
                        throughput=vol_data.get("Throughput"),
                        encrypted=vol_data.get("Encrypted", False),
                        kms_key_id=vol_data.get("KmsKeyId"),
                        state=vol_data["State"],
                        create_time=vol_data["CreateTime"],
                        availability_zone=vol_data["AvailabilityZone"],
                        snapshot_id=vol_data.get("SnapshotId"),
                        attached_instance_id=attached_instance_id,
                        device_name=device_name,
                        attachment_state=attachment_state,
                        multi_attach_enabled=vol_data.get("MultiAttachEnabled", False),
                        tags=parse_tags(vol_data.get("Tags", [])),
                        raw_data=vol_data,
                    )
                    volumes.append(volume)

            logger.debug(f"Collected {len(volumes)} EBS volumes from {region}")

        except ClientError as e:
            logger.error(f"Failed to collect EBS volumes from {region}: {e}")
        except Exception as e:
            logger.error(
                f"Unexpected error collecting EBS volumes from {region}: {e}",
                exc_info=True,
            )

        return volumes

    def collect_ebs_snapshots(self, region: str) -> List[EBSSnapshot]:
        """
        Collect EBS snapshots owned by the account from a specific region.

        Args:
            region: AWS region

        Returns:
            List of EBS snapshot resources
        """
        snapshots = []
        try:
            ec2_client = self.session.client("ec2", region_name=region)

            # Get account ID for filtering
            sts_client = self.session.client("sts")
            account_id = sts_client.get_caller_identity()["Account"]

            # Only collect snapshots owned by this account
            paginator = ec2_client.get_paginator("describe_snapshots")

            for page in paginator.paginate(OwnerIds=[account_id]):
                for snap_data in page["Snapshots"]:
                    snapshot = EBSSnapshot(
                        scan_id=self.scan_id,
                        snapshot_id=snap_data["SnapshotId"],
                        region=region,
                        volume_id=snap_data.get("VolumeId"),
                        volume_size=snap_data["VolumeSize"],
                        encrypted=snap_data.get("Encrypted", False),
                        kms_key_id=snap_data.get("KmsKeyId"),
                        state=snap_data["State"],
                        start_time=snap_data["StartTime"],
                        progress=snap_data["Progress"],
                        owner_id=snap_data["OwnerId"],
                        description=snap_data.get("Description"),
                        tags=parse_tags(snap_data.get("Tags", [])),
                        raw_data=snap_data,
                    )
                    snapshots.append(snapshot)

            logger.debug(f"Collected {len(snapshots)} EBS snapshots from {region}")

        except ClientError as e:
            logger.error(f"Failed to collect EBS snapshots from {region}: {e}")
        except Exception as e:
            logger.error(
                f"Unexpected error collecting EBS snapshots from {region}: {e}",
                exc_info=True,
            )

        return snapshots

    def collect_rds_instances(self, region: str) -> List[RDSInstance]:
        """
        Collect RDS database instances from a specific region.

        Args:
            region: AWS region

        Returns:
            List of RDS instance resources
        """
        rds_instances = []
        try:
            rds_client = self.session.client("rds", region_name=region)
            paginator = rds_client.get_paginator("describe_db_instances")

            for page in paginator.paginate():
                for db_data in page["DBInstances"]:
                    # Parse VPC security groups
                    vpc_security_groups = [
                        sg["VpcSecurityGroupId"]
                        for sg in db_data.get("VpcSecurityGroups", [])
                    ]

                    # Parse endpoint
                    endpoint_address = None
                    endpoint_port = None
                    if db_data.get("Endpoint"):
                        endpoint_address = db_data["Endpoint"].get("Address")
                        endpoint_port = db_data["Endpoint"].get("Port")

                    # Parse subnet group for VPC ID
                    vpc_id = None
                    subnet_group = None
                    if db_data.get("DBSubnetGroup"):
                        subnet_group = db_data["DBSubnetGroup"]["DBSubnetGroupName"]
                        vpc_id = db_data["DBSubnetGroup"].get("VpcId")

                    rds_instance = RDSInstance(
                        scan_id=self.scan_id,
                        db_instance_identifier=db_data["DBInstanceIdentifier"],
                        region=region,
                        db_instance_arn=db_data["DBInstanceArn"],
                        engine=db_data["Engine"],
                        engine_version=db_data["EngineVersion"],
                        db_instance_class=db_data["DBInstanceClass"],
                        allocated_storage=db_data.get("AllocatedStorage", 0),
                        storage_type=db_data.get("StorageType", "standard"),
                        iops=db_data.get("Iops"),
                        multi_az=db_data.get("MultiAZ", False),
                        availability_zone=db_data.get("AvailabilityZone"),
                        secondary_availability_zone=db_data.get(
                            "SecondaryAvailabilityZone"
                        ),
                        publicly_accessible=db_data.get("PubliclyAccessible", False),
                        encrypted=db_data.get("StorageEncrypted", False),
                        kms_key_id=db_data.get("KmsKeyId"),
                        vpc_id=vpc_id,
                        subnet_group=subnet_group,
                        vpc_security_groups=vpc_security_groups,
                        backup_retention_period=db_data.get("BackupRetentionPeriod", 0),
                        preferred_backup_window=db_data.get("PreferredBackupWindow"),
                        latest_restorable_time=db_data.get("LatestRestorableTime"),
                        endpoint_address=endpoint_address,
                        endpoint_port=endpoint_port,
                        db_instance_status=db_data["DBInstanceStatus"],
                        monitoring_interval=db_data.get("MonitoringInterval", 0),
                        performance_insights_enabled=db_data.get(
                            "PerformanceInsightsEnabled", False
                        ),
                        auto_minor_version_upgrade=db_data.get(
                            "AutoMinorVersionUpgrade", True
                        ),
                        deletion_protection=db_data.get("DeletionProtection", False),
                        tags={
                            tag["Key"]: tag["Value"]
                            for tag in db_data.get("TagList", [])
                        },
                        raw_data=db_data,
                    )
                    rds_instances.append(rds_instance)

            logger.debug(f"Collected {len(rds_instances)} RDS instances from {region}")

        except ClientError as e:
            logger.error(f"Failed to collect RDS instances from {region}: {e}")
        except Exception as e:
            logger.error(
                f"Unexpected error collecting RDS instances from {region}: {e}",
                exc_info=True,
            )

        return rds_instances

    def collect_iam_policies(self) -> List[IAMPolicy]:
        """
        Collect IAM policies (customer managed only, global service).

        Returns:
            List of IAM policy resources
        """
        policies = []
        try:
            iam_client = self.session.client("iam")

            # Only collect customer-managed policies (not AWS-managed)
            paginator = iam_client.get_paginator("list_policies")

            for page in paginator.paginate(Scope="Local"):  # Local = customer-managed
                for policy_data in page["Policies"]:
                    policy_arn = policy_data["Arn"]

                    # Get the default policy version document
                    policy_document = {}
                    try:
                        version_response = iam_client.get_policy_version(
                            PolicyArn=policy_arn,
                            VersionId=policy_data["DefaultVersionId"],
                        )
                        policy_document = version_response["PolicyVersion"]["Document"]
                    except ClientError as e:
                        logger.warning(
                            f"Failed to get policy document for {policy_arn}: {e}"
                        )

                    # Get entities attached to this policy
                    attached_users = []
                    attached_roles = []
                    attached_groups = []

                    try:
                        entities = iam_client.list_entities_for_policy(
                            PolicyArn=policy_arn
                        )
                        attached_users = [
                            u["UserName"] for u in entities.get("PolicyUsers", [])
                        ]
                        attached_roles = [
                            r["RoleName"] for r in entities.get("PolicyRoles", [])
                        ]
                        attached_groups = [
                            g["GroupName"] for g in entities.get("PolicyGroups", [])
                        ]
                    except ClientError as e:
                        logger.warning(
                            f"Failed to get entities for policy {policy_arn}: {e}"
                        )

                    # Get tags
                    tags = {}
                    try:
                        tag_response = iam_client.list_policy_tags(PolicyArn=policy_arn)
                        tags = {
                            tag["Key"]: tag["Value"]
                            for tag in tag_response.get("Tags", [])
                        }
                    except ClientError:
                        pass  # Tags might not be available

                    policy = IAMPolicy(
                        scan_id=self.scan_id,
                        policy_arn=policy_arn,
                        policy_name=policy_data["PolicyName"],
                        policy_id=policy_data["PolicyId"],
                        path=policy_data["Path"],
                        default_version_id=policy_data["DefaultVersionId"],
                        attachment_count=policy_data["AttachmentCount"],
                        permissions_boundary_usage_count=policy_data.get(
                            "PermissionsBoundaryUsageCount", 0
                        ),
                        is_attachable=policy_data["IsAttachable"],
                        description=policy_data.get("Description"),
                        create_date=policy_data["CreateDate"],
                        update_date=policy_data["UpdateDate"],
                        policy_document=policy_document,
                        attached_users=attached_users,
                        attached_roles=attached_roles,
                        attached_groups=attached_groups,
                        tags=tags,
                        raw_data=policy_data,
                    )
                    policies.append(policy)

            logger.debug(f"Collected {len(policies)} IAM customer-managed policies")

        except ClientError as e:
            logger.error(f"Failed to collect IAM policies: {e}")
        except Exception as e:
            logger.error(
                f"Unexpected error collecting IAM policies: {e}", exc_info=True
            )

        return policies

    def collect_kms_keys(self, region: str) -> List[KMSKey]:
        """
        Collect KMS encryption keys from a specific region.

        Args:
            region: AWS region

        Returns:
            List of KMS key resources
        """
        kms_keys = []
        try:
            kms_client = self.session.client("kms", region_name=region)

            # Get account ID
            sts_client = self.session.client("sts")
            account_id = sts_client.get_caller_identity()["Account"]

            # List all keys
            paginator = kms_client.get_paginator("list_keys")

            for page in paginator.paginate():
                for key_entry in page["Keys"]:
                    key_id = key_entry["KeyId"]

                    try:
                        # Get key metadata
                        key_metadata = kms_client.describe_key(KeyId=key_id)[
                            "KeyMetadata"
                        ]

                        # Skip AWS-managed keys if desired (optional - collecting all for now)
                        # if key_metadata['KeyManager'] == 'AWS':
                        #     continue

                        # Get key rotation status (only for symmetric keys)
                        rotation_enabled = False
                        if key_metadata["KeySpec"] == "SYMMETRIC_DEFAULT":
                            try:
                                rotation_response = kms_client.get_key_rotation_status(
                                    KeyId=key_id
                                )
                                rotation_enabled = rotation_response.get(
                                    "KeyRotationEnabled", False
                                )
                            except ClientError:
                                pass  # Key might not support rotation

                        # Get key policy
                        key_policy = {}
                        try:
                            policy_response = kms_client.get_key_policy(
                                KeyId=key_id, PolicyName="default"
                            )
                            import json

                            key_policy = json.loads(policy_response["Policy"])
                        except ClientError:
                            pass

                        # Get aliases
                        aliases = []
                        try:
                            alias_response = kms_client.list_aliases(KeyId=key_id)
                            aliases = [
                                alias["AliasName"]
                                for alias in alias_response.get("Aliases", [])
                            ]
                        except ClientError:
                            pass

                        # Get tags
                        tags = {}
                        try:
                            tag_response = kms_client.list_resource_tags(KeyId=key_id)
                            tags = {
                                tag["TagKey"]: tag["TagValue"]
                                for tag in tag_response.get("Tags", [])
                            }
                        except ClientError:
                            pass

                        kms_key = KMSKey(
                            scan_id=self.scan_id,
                            key_id=key_metadata["KeyId"],
                            key_arn=key_metadata["Arn"],
                            region=region,
                            aws_account_id=key_metadata["AWSAccountId"],
                            key_state=key_metadata["KeyState"],
                            creation_date=key_metadata["CreationDate"],
                            key_manager=key_metadata["KeyManager"],
                            key_usage=key_metadata.get("KeyUsage", "ENCRYPT_DECRYPT"),
                            key_spec=key_metadata.get("KeySpec", "SYMMETRIC_DEFAULT"),
                            description=key_metadata.get("Description"),
                            enabled=key_metadata.get("Enabled", True),
                            deletion_date=key_metadata.get("DeletionDate"),
                            rotation_enabled=rotation_enabled,
                            key_policy=key_policy,
                            aliases=aliases,
                            tags=tags,
                            raw_data=key_metadata,
                        )
                        kms_keys.append(kms_key)

                    except ClientError as e:
                        logger.warning(
                            f"Failed to get details for KMS key {key_id} in {region}: {e}"
                        )
                        continue

            logger.debug(f"Collected {len(kms_keys)} KMS keys from {region}")

        except ClientError as e:
            logger.error(f"Failed to collect KMS keys from {region}: {e}")
        except Exception as e:
            logger.error(
                f"Unexpected error collecting KMS keys from {region}: {e}",
                exc_info=True,
            )

        return kms_keys

    def collect_elastic_ips(self, region: str) -> List[ElasticIP]:
        """
        Collect Elastic IP addresses from a specific region.

        Args:
            region: AWS region

        Returns:
            List of Elastic IP resources
        """
        elastic_ips = []
        try:
            ec2_client = self.session.client("ec2", region_name=region)

            response = ec2_client.describe_addresses()

            for eip_data in response.get("Addresses", []):
                elastic_ip = ElasticIP(
                    scan_id=self.scan_id,
                    allocation_id=eip_data.get(
                        "AllocationId", eip_data.get("PublicIp")
                    ),  # EC2-Classic uses PublicIp
                    region=region,
                    public_ip=eip_data["PublicIp"],
                    domain=eip_data.get("Domain", "standard"),
                    instance_id=eip_data.get("InstanceId"),
                    network_interface_id=eip_data.get("NetworkInterfaceId"),
                    network_interface_owner_id=eip_data.get("NetworkInterfaceOwnerId"),
                    private_ip_address=eip_data.get("PrivateIpAddress"),
                    association_id=eip_data.get("AssociationId"),
                    is_associated=eip_data.get("AssociationId") is not None,
                    tags=parse_tags(eip_data.get("Tags", [])),
                    raw_data=eip_data,
                )
                elastic_ips.append(elastic_ip)

            logger.debug(f"Collected {len(elastic_ips)} Elastic IPs from {region}")

        except ClientError as e:
            logger.error(f"Failed to collect Elastic IPs from {region}: {e}")
        except Exception as e:
            logger.error(
                f"Unexpected error collecting Elastic IPs from {region}: {e}",
                exc_info=True,
            )

        return elastic_ips

    # Phase 2: Containers & Application Services Collectors

    def collect_ecs_clusters(self, region: str) -> List[ECSCluster]:
        """
        Collect ECS clusters from a specific region.

        Args:
            region: AWS region

        Returns:
            List of ECS cluster resources
        """
        ecs_clusters = []
        try:
            ecs_client = self.session.client("ecs", region_name=region)

            # List all clusters
            cluster_arns = []
            paginator = ecs_client.get_paginator("list_clusters")
            for page in paginator.paginate():
                cluster_arns.extend(page.get("clusterArns", []))

            if not cluster_arns:
                return ecs_clusters

            # Describe clusters (max 100 at a time)
            for i in range(0, len(cluster_arns), 100):
                batch = cluster_arns[i : i + 100]
                response = ecs_client.describe_clusters(
                    clusters=batch, include=["STATISTICS", "SETTINGS", "TAGS"]
                )

                for cluster_data in response.get("clusters", []):
                    ecs_cluster = ECSCluster(
                        scan_id=self.scan_id,
                        cluster_arn=cluster_data["clusterArn"],
                        cluster_name=cluster_data["clusterName"],
                        region=region,
                        status=cluster_data.get("status", "UNKNOWN"),
                        registered_container_instances_count=cluster_data.get(
                            "registeredContainerInstancesCount", 0
                        ),
                        running_tasks_count=cluster_data.get("runningTasksCount", 0),
                        pending_tasks_count=cluster_data.get("pendingTasksCount", 0),
                        active_services_count=cluster_data.get(
                            "activeServicesCount", 0
                        ),
                        capacity_providers=cluster_data.get("capacityProviders", []),
                        default_capacity_provider_strategy=cluster_data.get(
                            "defaultCapacityProviderStrategy", []
                        ),
                        settings=cluster_data.get("settings", []),
                        statistics=cluster_data.get("statistics", []),
                        tags={
                            tag["key"]: tag["value"]
                            for tag in cluster_data.get("tags", [])
                        },
                        raw_data=cluster_data,
                    )
                    ecs_clusters.append(ecs_cluster)

            logger.debug(f"Collected {len(ecs_clusters)} ECS clusters from {region}")

        except ClientError as e:
            logger.error(f"Failed to collect ECS clusters from {region}: {e}")
        except Exception as e:
            logger.error(
                f"Unexpected error collecting ECS clusters from {region}: {e}",
                exc_info=True,
            )

        return ecs_clusters

    def collect_ecs_services(self, region: str) -> List[ECSService]:
        """
        Collect ECS services from a specific region.

        Args:
            region: AWS region

        Returns:
            List of ECS service resources
        """
        ecs_services = []
        try:
            ecs_client = self.session.client("ecs", region_name=region)

            # List all clusters first
            cluster_arns = []
            paginator = ecs_client.get_paginator("list_clusters")
            for page in paginator.paginate():
                cluster_arns.extend(page.get("clusterArns", []))

            # For each cluster, list and describe services
            for cluster_arn in cluster_arns:
                service_arns = []
                paginator = ecs_client.get_paginator("list_services")
                for page in paginator.paginate(cluster=cluster_arn):
                    service_arns.extend(page.get("serviceArns", []))

                if not service_arns:
                    continue

                # Describe services (max 10 at a time)
                for i in range(0, len(service_arns), 10):
                    batch = service_arns[i : i + 10]
                    response = ecs_client.describe_services(
                        cluster=cluster_arn, services=batch, include=["TAGS"]
                    )

                    for service_data in response.get("services", []):
                        ecs_service = ECSService(
                            scan_id=self.scan_id,
                            service_arn=service_data["serviceArn"],
                            service_name=service_data["serviceName"],
                            cluster_arn=service_data["clusterArn"],
                            region=region,
                            status=service_data.get("status", "UNKNOWN"),
                            task_definition=service_data.get("taskDefinition", ""),
                            desired_count=service_data.get("desiredCount", 0),
                            running_count=service_data.get("runningCount", 0),
                            pending_count=service_data.get("pendingCount", 0),
                            launch_type=service_data.get("launchType"),
                            platform_version=service_data.get("platformVersion"),
                            platform_family=service_data.get("platformFamily"),
                            capacity_provider_strategy=service_data.get(
                                "capacityProviderStrategy", []
                            ),
                            network_configuration=service_data.get(
                                "networkConfiguration", {}
                            ),
                            load_balancers=service_data.get("loadBalancers", []),
                            service_registries=service_data.get(
                                "serviceRegistries", []
                            ),
                            deployment_configuration=service_data.get(
                                "deploymentConfiguration", {}
                            ),
                            deployments=service_data.get("deployments", []),
                            health_check_grace_period_seconds=service_data.get(
                                "healthCheckGracePeriodSeconds"
                            ),
                            scheduling_strategy=service_data.get(
                                "schedulingStrategy", "REPLICA"
                            ),
                            created_at=service_data.get("createdAt"),
                            tags={
                                tag["key"]: tag["value"]
                                for tag in service_data.get("tags", [])
                            },
                            raw_data=service_data,
                        )
                        ecs_services.append(ecs_service)

            logger.debug(f"Collected {len(ecs_services)} ECS services from {region}")

        except ClientError as e:
            logger.error(f"Failed to collect ECS services from {region}: {e}")
        except Exception as e:
            logger.error(
                f"Unexpected error collecting ECS services from {region}: {e}",
                exc_info=True,
            )

        return ecs_services

    def collect_ecs_task_definitions(self, region: str) -> List[ECSTaskDefinition]:
        """
        Collect ECS task definitions from a specific region.

        Args:
            region: AWS region

        Returns:
            List of ECS task definition resources
        """
        ecs_task_definitions = []
        try:
            ecs_client = self.session.client("ecs", region_name=region)

            # List task definition families
            families = []
            paginator = ecs_client.get_paginator("list_task_definition_families")
            for page in paginator.paginate(status="ACTIVE"):
                families.extend(page.get("families", []))

            # For each family, get the latest active task definition
            for family in families:
                try:
                    response = ecs_client.list_task_definitions(
                        familyPrefix=family, status="ACTIVE", sort="DESC", maxResults=1
                    )

                    if response.get("taskDefinitionArns"):
                        task_def_arn = response["taskDefinitionArns"][0]

                        # Describe task definition
                        describe_response = ecs_client.describe_task_definition(
                            taskDefinition=task_def_arn, include=["TAGS"]
                        )

                        task_def_data = describe_response["taskDefinition"]

                        ecs_task_def = ECSTaskDefinition(
                            scan_id=self.scan_id,
                            task_definition_arn=task_def_data["taskDefinitionArn"],
                            family=task_def_data["family"],
                            revision=task_def_data["revision"],
                            region=region,
                            status=task_def_data.get("status", "ACTIVE"),
                            requires_compatibilities=task_def_data.get(
                                "requiresCompatibilities", []
                            ),
                            network_mode=task_def_data.get("networkMode", "bridge"),
                            cpu=task_def_data.get("cpu"),
                            memory=task_def_data.get("memory"),
                            task_role_arn=task_def_data.get("taskRoleArn"),
                            execution_role_arn=task_def_data.get("executionRoleArn"),
                            container_definitions=task_def_data.get(
                                "containerDefinitions", []
                            ),
                            volumes=task_def_data.get("volumes", []),
                            placement_constraints=task_def_data.get(
                                "placementConstraints", []
                            ),
                            requires_attributes=task_def_data.get(
                                "requiresAttributes", []
                            ),
                            pid_mode=task_def_data.get("pidMode"),
                            ipc_mode=task_def_data.get("ipcMode"),
                            proxy_configuration=task_def_data.get("proxyConfiguration"),
                            ephemeral_storage=task_def_data.get("ephemeralStorage"),
                            runtime_platform=task_def_data.get("runtimePlatform"),
                            registered_at=task_def_data.get("registeredAt"),
                            deregistered_at=task_def_data.get("deregisteredAt"),
                            registered_by=task_def_data.get("registeredBy"),
                            tags={
                                tag["key"]: tag["value"]
                                for tag in describe_response.get("tags", [])
                            },
                            raw_data=task_def_data,
                        )
                        ecs_task_definitions.append(ecs_task_def)

                except ClientError as e:
                    logger.warning(
                        f"Failed to describe task definition family {family}: {e}"
                    )
                    continue

            logger.debug(
                f"Collected {len(ecs_task_definitions)} ECS task definitions from {region}"
            )

        except ClientError as e:
            logger.error(f"Failed to collect ECS task definitions from {region}: {e}")
        except Exception as e:
            logger.error(
                f"Unexpected error collecting ECS task definitions from {region}: {e}",
                exc_info=True,
            )

        return ecs_task_definitions

    def collect_eks_clusters(self, region: str) -> List[EKSCluster]:
        """
        Collect EKS clusters from a specific region.

        Args:
            region: AWS region

        Returns:
            List of EKS cluster resources
        """
        eks_clusters = []
        try:
            eks_client = self.session.client("eks", region_name=region)

            # List clusters
            cluster_names = []
            paginator = eks_client.get_paginator("list_clusters")
            for page in paginator.paginate():
                cluster_names.extend(page.get("clusters", []))

            # Describe each cluster
            for cluster_name in cluster_names:
                try:
                    response = eks_client.describe_cluster(name=cluster_name)
                    cluster_data = response["cluster"]

                    # Extract VPC config
                    vpc_config = cluster_data.get("resourcesVpcConfig", {})

                    eks_cluster = EKSCluster(
                        scan_id=self.scan_id,
                        cluster_name=cluster_data["name"],
                        cluster_arn=cluster_data["arn"],
                        region=region,
                        version=cluster_data.get("version", "unknown"),
                        endpoint=cluster_data.get("endpoint"),
                        role_arn=cluster_data.get("roleArn", ""),
                        status=cluster_data.get("status", "UNKNOWN"),
                        vpc_id=vpc_config.get("vpcId", ""),
                        subnet_ids=vpc_config.get("subnetIds", []),
                        security_group_ids=vpc_config.get("securityGroupIds", []),
                        cluster_security_group_id=vpc_config.get(
                            "clusterSecurityGroupId"
                        ),
                        endpoint_public_access=vpc_config.get(
                            "endpointPublicAccess", True
                        ),
                        endpoint_private_access=vpc_config.get(
                            "endpointPrivateAccess", False
                        ),
                        public_access_cidrs=vpc_config.get("publicAccessCidrs", []),
                        resources_vpc_config=vpc_config,
                        logging=cluster_data.get("logging", {}),
                        identity=cluster_data.get("identity"),
                        encryption_config=cluster_data.get("encryptionConfig", []),
                        platform_version=cluster_data.get("platformVersion"),
                        created_at=cluster_data.get("createdAt"),
                        tags=cluster_data.get("tags", {}),
                        raw_data=cluster_data,
                    )
                    eks_clusters.append(eks_cluster)

                except ClientError as e:
                    logger.warning(
                        f"Failed to describe EKS cluster {cluster_name} in {region}: {e}"
                    )
                    continue

            logger.debug(f"Collected {len(eks_clusters)} EKS clusters from {region}")

        except ClientError as e:
            logger.error(f"Failed to collect EKS clusters from {region}: {e}")
        except Exception as e:
            logger.error(
                f"Unexpected error collecting EKS clusters from {region}: {e}",
                exc_info=True,
            )

        return eks_clusters

    def collect_eks_node_groups(self, region: str) -> List[EKSNodeGroup]:
        """
        Collect EKS node groups from a specific region.

        Args:
            region: AWS region

        Returns:
            List of EKS node group resources
        """
        eks_node_groups = []
        try:
            eks_client = self.session.client("eks", region_name=region)

            # First, list all clusters
            cluster_names = []
            paginator = eks_client.get_paginator("list_clusters")
            for page in paginator.paginate():
                cluster_names.extend(page.get("clusters", []))

            # For each cluster, list node groups
            for cluster_name in cluster_names:
                try:
                    nodegroup_names = []
                    paginator = eks_client.get_paginator("list_nodegroups")
                    for page in paginator.paginate(clusterName=cluster_name):
                        nodegroup_names.extend(page.get("nodegroups", []))

                    # Describe each node group
                    for nodegroup_name in nodegroup_names:
                        try:
                            response = eks_client.describe_nodegroup(
                                clusterName=cluster_name, nodegroupName=nodegroup_name
                            )
                            ng_data = response["nodegroup"]

                            eks_node_group = EKSNodeGroup(
                                scan_id=self.scan_id,
                                cluster_name=cluster_name,
                                nodegroup_name=ng_data["nodegroupName"],
                                nodegroup_arn=ng_data["nodegroupArn"],
                                region=region,
                                status=ng_data.get("status", "UNKNOWN"),
                                scaling_config=ng_data.get("scalingConfig", {}),
                                instance_types=ng_data.get("instanceTypes", []),
                                ami_type=ng_data.get("amiType"),
                                release_version=ng_data.get("releaseVersion"),
                                subnets=ng_data.get("subnets", []),
                                remote_access=ng_data.get("remoteAccess"),
                                node_role=ng_data.get("nodeRole", ""),
                                labels=ng_data.get("labels", {}),
                                taints=ng_data.get("taints", []),
                                disk_size=ng_data.get("diskSize"),
                                capacity_type=ng_data.get("capacityType", "ON_DEMAND"),
                                launch_template=ng_data.get("launchTemplate"),
                                update_config=ng_data.get("updateConfig"),
                                health=ng_data.get("health"),
                                created_at=ng_data.get("createdAt"),
                                modified_at=ng_data.get("modifiedAt"),
                                tags=ng_data.get("tags", {}),
                                raw_data=ng_data,
                            )
                            eks_node_groups.append(eks_node_group)

                        except ClientError as e:
                            logger.warning(
                                f"Failed to describe node group {nodegroup_name} in cluster {cluster_name}: {e}"
                            )
                            continue

                except ClientError as e:
                    logger.warning(
                        f"Failed to list node groups for cluster {cluster_name}: {e}"
                    )
                    continue

            logger.debug(
                f"Collected {len(eks_node_groups)} EKS node groups from {region}"
            )

        except ClientError as e:
            logger.error(f"Failed to collect EKS node groups from {region}: {e}")
        except Exception as e:
            logger.error(
                f"Unexpected error collecting EKS node groups from {region}: {e}",
                exc_info=True,
            )

        return eks_node_groups

    def collect_ecr_repositories(self, region: str) -> List[ECRRepository]:
        """
        Collect ECR repositories from a specific region.

        Args:
            region: AWS region

        Returns:
            List of ECR repository resources
        """
        ecr_repositories = []
        try:
            ecr_client = self.session.client("ecr", region_name=region)

            # List repositories
            paginator = ecr_client.get_paginator("describe_repositories")
            for page in paginator.paginate():
                for repo_data in page.get("repositories", []):
                    ecr_repo = ECRRepository(
                        scan_id=self.scan_id,
                        repository_arn=repo_data["repositoryArn"],
                        repository_name=repo_data["repositoryName"],
                        repository_uri=repo_data["repositoryUri"],
                        region=region,
                        registry_id=repo_data["registryId"],
                        image_scanning_configuration=repo_data.get(
                            "imageScanningConfiguration", {}
                        ),
                        image_tag_mutability=repo_data.get(
                            "imageTagMutability", "MUTABLE"
                        ),
                        encryption_configuration=repo_data.get(
                            "encryptionConfiguration", {}
                        ),
                        created_at=repo_data.get("createdAt"),
                        tags={
                            tag["Key"]: tag["Value"]
                            for tag in ecr_client.list_tags_for_resource(
                                resourceArn=repo_data["repositoryArn"]
                            ).get("tags", [])
                        },
                        raw_data=repo_data,
                    )
                    ecr_repositories.append(ecr_repo)

            logger.debug(
                f"Collected {len(ecr_repositories)} ECR repositories from {region}"
            )

        except ClientError as e:
            logger.error(f"Failed to collect ECR repositories from {region}: {e}")
        except Exception as e:
            logger.error(
                f"Unexpected error collecting ECR repositories from {region}: {e}",
                exc_info=True,
            )

        return ecr_repositories

    def collect_ecr_images(self, region: str) -> List[ECRImage]:
        """
        Collect ECR images from a specific region.

        Args:
            region: AWS region

        Returns:
            List of ECR image resources
        """
        ecr_images = []
        try:
            ecr_client = self.session.client("ecr", region_name=region)

            # First, list all repositories
            repositories = []
            paginator = ecr_client.get_paginator("describe_repositories")
            for page in paginator.paginate():
                repositories.extend(page.get("repositories", []))

            # For each repository, list images
            for repo in repositories:
                repository_name = repo["repositoryName"]
                registry_id = repo["registryId"]

                try:
                    paginator = ecr_client.get_paginator("describe_images")
                    for page in paginator.paginate(repositoryName=repository_name):
                        for image_data in page.get("imageDetails", []):
                            ecr_image = ECRImage(
                                scan_id=self.scan_id,
                                repository_name=repository_name,
                                region=region,
                                registry_id=registry_id,
                                image_digest=image_data["imageDigest"],
                                image_tags=image_data.get("imageTags", []),
                                image_size_in_bytes=image_data.get(
                                    "imageSizeInBytes", 0
                                ),
                                image_pushed_at=image_data.get("imagePushedAt"),
                                image_scan_status=image_data.get(
                                    "imageScanStatus", {}
                                ).get("status"),
                                image_scan_findings_summary=image_data.get(
                                    "imageScanFindingsSummary"
                                ),
                                last_recorded_pull_time=image_data.get(
                                    "lastRecordedPullTime"
                                ),
                                artifact_media_type=image_data.get("artifactMediaType"),
                                raw_data=image_data,
                            )
                            ecr_images.append(ecr_image)

                except ClientError as e:
                    logger.warning(
                        f"Failed to list images for repository {repository_name}: {e}"
                    )
                    continue

            logger.debug(f"Collected {len(ecr_images)} ECR images from {region}")

        except ClientError as e:
            logger.error(f"Failed to collect ECR images from {region}: {e}")
        except Exception as e:
            logger.error(
                f"Unexpected error collecting ECR images from {region}: {e}",
                exc_info=True,
            )

        return ecr_images

    def collect_api_gateway_rest_apis(self, region: str) -> List[APIGatewayRestAPI]:
        """
        Collect API Gateway REST APIs from a specific region.

        Args:
            region: AWS region

        Returns:
            List of API Gateway REST API resources
        """
        api_gateway_rest_apis = []
        try:
            apigw_client = self.session.client("apigateway", region_name=region)

            # List REST APIs
            paginator = apigw_client.get_paginator("get_rest_apis")
            for page in paginator.paginate():
                for api_data in page.get("items", []):
                    api_gateway_rest_api = APIGatewayRestAPI(
                        scan_id=self.scan_id,
                        api_id=api_data["id"],
                        name=api_data["name"],
                        region=region,
                        description=api_data.get("description"),
                        endpoint_configuration=api_data.get(
                            "endpointConfiguration", {}
                        ),
                        version=api_data.get("version"),
                        created_date=api_data.get("createdDate"),
                        api_key_source=api_data.get("apiKeySource"),
                        policy=api_data.get("policy"),
                        minimum_compression_size=api_data.get("minimumCompressionSize"),
                        binary_media_types=api_data.get("binaryMediaTypes", []),
                        disable_execute_api_endpoint=api_data.get(
                            "disableExecuteApiEndpoint", False
                        ),
                        tags=api_data.get("tags", {}),
                        raw_data=api_data,
                    )
                    api_gateway_rest_apis.append(api_gateway_rest_api)

            logger.debug(
                f"Collected {len(api_gateway_rest_apis)} API Gateway REST APIs from {region}"
            )

        except ClientError as e:
            logger.error(f"Failed to collect API Gateway REST APIs from {region}: {e}")
        except Exception as e:
            logger.error(
                f"Unexpected error collecting API Gateway REST APIs from {region}: {e}",
                exc_info=True,
            )

        return api_gateway_rest_apis

    def collect_api_gateway_http_apis(self, region: str) -> List[APIGatewayHttpAPI]:
        """
        Collect API Gateway HTTP APIs (v2) from a specific region.

        Args:
            region: AWS region

        Returns:
            List of API Gateway HTTP API resources
        """
        api_gateway_http_apis = []
        try:
            apigwv2_client = self.session.client("apigatewayv2", region_name=region)

            # List HTTP APIs
            paginator = apigwv2_client.get_paginator("get_apis")
            for page in paginator.paginate():
                for api_data in page.get("Items", []):
                    api_gateway_http_api = APIGatewayHttpAPI(
                        scan_id=self.scan_id,
                        api_id=api_data["ApiId"],
                        name=api_data["Name"],
                        region=region,
                        protocol_type=api_data["ProtocolType"],
                        description=api_data.get("Description"),
                        api_endpoint=api_data.get("ApiEndpoint"),
                        cors_configuration=api_data.get("CorsConfiguration"),
                        version=api_data.get("Version"),
                        route_selection_expression=api_data.get(
                            "RouteSelectionExpression"
                        ),
                        disable_execute_api_endpoint=api_data.get(
                            "DisableExecuteApiEndpoint", False
                        ),
                        disable_schema_validation=api_data.get(
                            "DisableSchemaValidation", False
                        ),
                        import_info=api_data.get("ImportInfo", []),
                        created_date=api_data.get("CreatedDate"),
                        tags=api_data.get("Tags", {}),
                        raw_data=api_data,
                    )
                    api_gateway_http_apis.append(api_gateway_http_api)

            logger.debug(
                f"Collected {len(api_gateway_http_apis)} API Gateway HTTP APIs from {region}"
            )

        except ClientError as e:
            logger.error(f"Failed to collect API Gateway HTTP APIs from {region}: {e}")
        except Exception as e:
            logger.error(
                f"Unexpected error collecting API Gateway HTTP APIs from {region}: {e}",
                exc_info=True,
            )

        return api_gateway_http_apis

    def collect_api_gateway_stages(self, region: str) -> List[APIGatewayStage]:
        """
        Collect API Gateway stages from a specific region.

        Args:
            region: AWS region

        Returns:
            List of API Gateway stage resources
        """
        api_gateway_stages = []
        try:
            # Collect REST API stages
            apigw_client = self.session.client("apigateway", region_name=region)

            rest_apis = []
            paginator = apigw_client.get_paginator("get_rest_apis")
            for page in paginator.paginate():
                rest_apis.extend(page.get("items", []))

            for api in rest_apis:
                api_id = api["id"]
                try:
                    response = apigw_client.get_stages(restApiId=api_id)
                    for stage_data in response.get("item", []):
                        api_gateway_stage = APIGatewayStage(
                            scan_id=self.scan_id,
                            api_id=api_id,
                            stage_name=stage_data["stageName"],
                            region=region,
                            api_type="REST",
                            deployment_id=stage_data.get("deploymentId"),
                            description=stage_data.get("description"),
                            created_date=stage_data.get("createdDate"),
                            last_updated_date=stage_data.get("lastUpdatedDate"),
                            access_log_settings=stage_data.get("accessLogSettings"),
                            client_certificate_id=stage_data.get("clientCertificateId"),
                            throttle_settings=stage_data.get("throttleSettings"),
                            method_settings=stage_data.get("methodSettings", {}),
                            variables=stage_data.get("variables", {}),
                            tracing_enabled=stage_data.get("tracingEnabled", False),
                            web_acl_arn=stage_data.get("webAclArn"),
                            tags=stage_data.get("tags", {}),
                            raw_data=stage_data,
                        )
                        api_gateway_stages.append(api_gateway_stage)
                except ClientError as e:
                    logger.warning(f"Failed to get stages for REST API {api_id}: {e}")
                    continue

            # Collect HTTP API stages
            apigwv2_client = self.session.client("apigatewayv2", region_name=region)

            http_apis = []
            paginator = apigwv2_client.get_paginator("get_apis")
            for page in paginator.paginate():
                http_apis.extend(page.get("Items", []))

            for api in http_apis:
                api_id = api["ApiId"]
                try:
                    paginator = apigwv2_client.get_paginator("get_stages")
                    for page in paginator.paginate(ApiId=api_id):
                        for stage_data in page.get("Items", []):
                            api_gateway_stage = APIGatewayStage(
                                scan_id=self.scan_id,
                                api_id=api_id,
                                stage_name=stage_data["StageName"],
                                region=region,
                                api_type="HTTP",
                                deployment_id=stage_data.get("DeploymentId"),
                                description=stage_data.get("Description"),
                                created_date=stage_data.get("CreatedDate"),
                                last_updated_date=stage_data.get("LastUpdatedDate"),
                                access_log_settings=stage_data.get("AccessLogSettings"),
                                throttle_settings=stage_data.get(
                                    "DefaultRouteSettings", {}
                                ).get("ThrottleSettings"),
                                auto_deploy=stage_data.get("AutoDeploy", False),
                                route_settings=stage_data.get("RouteSettings", {}),
                                default_route_settings=stage_data.get(
                                    "DefaultRouteSettings"
                                ),
                                tags=stage_data.get("Tags", {}),
                                raw_data=stage_data,
                            )
                            api_gateway_stages.append(api_gateway_stage)
                except ClientError as e:
                    logger.warning(f"Failed to get stages for HTTP API {api_id}: {e}")
                    continue

            logger.debug(
                f"Collected {len(api_gateway_stages)} API Gateway stages from {region}"
            )

        except ClientError as e:
            logger.error(f"Failed to collect API Gateway stages from {region}: {e}")
        except Exception as e:
            logger.error(
                f"Unexpected error collecting API Gateway stages from {region}: {e}",
                exc_info=True,
            )

        return api_gateway_stages

    def collect_cloudfront_distributions(self) -> List[CloudFrontDistribution]:
        """
        Collect CloudFront distributions (global service).

        Returns:
            List of CloudFront distribution resources
        """
        cloudfront_distributions = []
        try:
            cf_client = self.session.client("cloudfront")

            # List distributions
            paginator = cf_client.get_paginator("list_distributions")
            for page in paginator.paginate():
                distribution_list = page.get("DistributionList", {})

                for dist_summary in distribution_list.get("Items", []):
                    try:
                        # Get full distribution details including tags
                        response = cf_client.get_distribution(Id=dist_summary["Id"])
                        dist_data = response["Distribution"]
                        dist_config = dist_data["DistributionConfig"]

                        # Get tags
                        tags_response = cf_client.list_tags_for_resource(
                            Resource=dist_data["ARN"]
                        )
                        tags = {
                            tag["Key"]: tag["Value"]
                            for tag in tags_response.get("Tags", {}).get("Items", [])
                        }

                        cloudfront_dist = CloudFrontDistribution(
                            scan_id=self.scan_id,
                            distribution_id=dist_data["Id"],
                            distribution_arn=dist_data["ARN"],
                            domain_name=dist_data["DomainName"],
                            status=dist_data["Status"],
                            enabled=dist_config["Enabled"],
                            aliases=list(
                                dist_config.get("Aliases", {}).get("Items", [])
                            ),
                            origins=list(
                                dist_config.get("Origins", {}).get("Items", [])
                            ),
                            origin_groups=list(
                                dist_config.get("OriginGroups", {}).get("Items", [])
                            ),
                            default_root_object=dist_config.get("DefaultRootObject"),
                            default_cache_behavior=dist_config.get(
                                "DefaultCacheBehavior", {}
                            ),
                            cache_behaviors=list(
                                dist_config.get("CacheBehaviors", {}).get("Items", [])
                            ),
                            viewer_certificate=dist_config.get("ViewerCertificate", {}),
                            geo_restriction=dist_config.get("Restrictions", {}).get(
                                "GeoRestriction"
                            ),
                            web_acl_id=dist_config.get("WebACLId"),
                            http_version=dist_config.get("HttpVersion", "http2"),
                            is_ipv6_enabled=dist_config.get("IsIPV6Enabled", True),
                            logging=dist_config.get("Logging"),
                            price_class=dist_config.get("PriceClass", "PriceClass_All"),
                            custom_error_responses=list(
                                dist_config.get("CustomErrorResponses", {}).get(
                                    "Items", []
                                )
                            ),
                            comment=dist_config.get("Comment"),
                            last_modified_time=dist_data.get("LastModifiedTime"),
                            tags=tags,
                            raw_data=dist_data,
                        )
                        cloudfront_distributions.append(cloudfront_dist)

                    except ClientError as e:
                        logger.warning(
                            f"Failed to get distribution details for {dist_summary['Id']}: {e}"
                        )
                        continue

            logger.debug(
                f"Collected {len(cloudfront_distributions)} CloudFront distributions"
            )

        except ClientError as e:
            logger.error(f"Failed to collect CloudFront distributions: {e}")
        except Exception as e:
            logger.error(
                f"Unexpected error collecting CloudFront distributions: {e}",
                exc_info=True,
            )

        return cloudfront_distributions

    # Phase 3: Governance, Logging & Advanced Services Collectors

    def collect_organizations(
        self,
    ) -> tuple[List[Organization], List[OrganizationalUnit], List[OrganizationAccount]]:
        """
        Collect AWS Organizations data (global service).

        Returns:
            Tuple of (organizations, organizational_units, organization_accounts)
        """
        organizations = []
        organizational_units = []
        organization_accounts = []

        try:
            org_client = self.session.client("organizations", region_name="us-east-1")

            # Get organization details
            try:
                org_response = org_client.describe_organization()
                org_data = org_response["Organization"]

                organization = Organization(
                    scan_id=self.scan_id,
                    organization_id=org_data["Id"],
                    organization_arn=org_data["Arn"],
                    master_account_id=org_data["MasterAccountId"],
                    master_account_email=org_data["MasterAccountEmail"],
                    feature_set=org_data.get("FeatureSet", "ALL"),
                    available_policy_types=org_data.get("AvailablePolicyTypes", []),
                    raw_data=org_data,
                )
                organizations.append(organization)

                # Get all organizational units
                root_response = org_client.list_roots()
                for root in root_response.get("Roots", []):
                    root_id = root["Id"]

                    # Recursively get all OUs
                    self._collect_ous_recursive(
                        org_client, root_id, organizational_units
                    )

                # Get all accounts
                paginator = org_client.get_paginator("list_accounts")
                for page in paginator.paginate():
                    for account_data in page.get("Accounts", []):
                        org_account = OrganizationAccount(
                            scan_id=self.scan_id,
                            account_id=account_data["Id"],
                            account_arn=account_data["Arn"],
                            email=account_data["Email"],
                            account_name=account_data.get("Name", ""),
                            status=account_data.get("Status", "UNKNOWN"),
                            joined_method=account_data.get("JoinedMethod", "UNKNOWN"),
                            joined_timestamp=account_data.get("JoinedTimestamp"),
                            raw_data=account_data,
                        )
                        organization_accounts.append(org_account)

            except org_client.exceptions.AWSOrganizationsNotInUseException:
                logger.info("AWS Organizations not enabled for this account")
            except ClientError as e:
                if e.response["Error"]["Code"] == "AccessDeniedException":
                    logger.warning("No permission to access AWS Organizations")
                else:
                    raise

            logger.debug(
                f"Collected {len(organizations)} organizations, {len(organizational_units)} OUs, {len(organization_accounts)} accounts"
            )

        except ClientError as e:
            logger.error(f"Failed to collect Organizations data: {e}")
        except Exception as e:
            logger.error(
                f"Unexpected error collecting Organizations data: {e}", exc_info=True
            )

        return organizations, organizational_units, organization_accounts

    def _collect_ous_recursive(
        self, org_client, parent_id: str, ou_list: List[OrganizationalUnit]
    ) -> None:
        """
        Recursively collect organizational units.

        Args:
            org_client: Organizations client
            parent_id: Parent OU ID
            ou_list: List to append OUs to
        """
        try:
            paginator = org_client.get_paginator("list_organizational_units_for_parent")
            for page in paginator.paginate(ParentId=parent_id):
                for ou_data in page.get("OrganizationalUnits", []):
                    ou = OrganizationalUnit(
                        scan_id=self.scan_id,
                        ou_id=ou_data["Id"],
                        ou_arn=ou_data["Arn"],
                        ou_name=ou_data.get("Name"),
                        parent_id=parent_id,
                        raw_data=ou_data,
                    )
                    ou_list.append(ou)

                    # Recurse into child OUs
                    self._collect_ous_recursive(org_client, ou_data["Id"], ou_list)

        except ClientError as e:
            logger.warning(f"Failed to collect OUs for parent {parent_id}: {e}")

    def collect_sso(self) -> tuple[List[SSOPermissionSet], List[SSOAssignment]]:
        """
        Collect AWS SSO/Identity Center data (global service).

        Note: Identity Centre has a "home region" where it's configured.
        This method auto-detects the region by trying common regions first.

        Returns:
            Tuple of (permission_sets, assignments)
        """
        permission_sets = []
        assignments = []

        try:
            # Identity Centre instance only exists in its home region
            # Try common regions first (most organisations use these)
            priority_regions = ["ap-southeast-2", "us-east-1", "us-west-2", "eu-west-1"]

            sso_region = None
            sso_client = None
            instances = []

            logger.info("Auto-detecting AWS Identity Centre region...")

            # Try priority regions first
            for region in priority_regions:
                try:
                    test_client = self.session.client("sso-admin", region_name=region)
                    response = test_client.list_instances()
                    found_instances = response.get("Instances", [])

                    if found_instances:
                        sso_region = region
                        sso_client = test_client
                        instances = found_instances
                        logger.info(
                            f"Found Identity Centre instance in region: {region}"
                        )
                        break
                except ClientError as e:
                    # Region doesn't have instances or access denied
                    logger.debug(
                        f"No Identity Centre instance in {region}: {e.response['Error']['Code']}"
                    )
                    continue

            if not sso_region:
                logger.warning(
                    "No AWS Identity Centre instance found in common regions. Identity Centre may not be enabled or may be in an uncommon region."
                )
                return permission_sets, assignments

            # Create identity store client in the same region
            identity_store_client = self.session.client(
                "identitystore", region_name=sso_region
            )

            for instance in instances:
                instance_arn = instance["InstanceArn"]
                identity_store_id = instance["IdentityStoreId"]

                # List permission sets
                paginator = sso_client.get_paginator("list_permission_sets")
                for page in paginator.paginate(InstanceArn=instance_arn):
                    for ps_arn in page.get("PermissionSets", []):
                        try:
                            # Get permission set details
                            ps_response = sso_client.describe_permission_set(
                                InstanceArn=instance_arn, PermissionSetArn=ps_arn
                            )
                            ps_data = ps_response["PermissionSet"]

                            # Get managed policies
                            # Note: AWS returns dicts with Name and Arn, but we only store ARNs
                            managed_policies = []
                            mp_paginator = sso_client.get_paginator(
                                "list_managed_policies_in_permission_set"
                            )
                            for mp_page in mp_paginator.paginate(
                                InstanceArn=instance_arn, PermissionSetArn=ps_arn
                            ):
                                # Extract just the ARN from each policy dict
                                managed_policies.extend(
                                    [
                                        p["Arn"]
                                        for p in mp_page.get(
                                            "AttachedManagedPolicies", []
                                        )
                                    ]
                                )

                            # Get inline policy
                            inline_policy = None
                            try:
                                inline_response = (
                                    sso_client.get_inline_policy_for_permission_set(
                                        InstanceArn=instance_arn,
                                        PermissionSetArn=ps_arn,
                                    )
                                )
                                inline_policy = inline_response.get("InlinePolicy")
                            except ClientError:
                                pass

                            permission_set = SSOPermissionSet(
                                scan_id=self.scan_id,
                                permission_set_arn=ps_data["PermissionSetArn"],
                                permission_set_name=ps_data.get("Name"),
                                description=ps_data.get("Description"),
                                instance_arn=instance_arn,
                                session_duration=ps_data.get("SessionDuration"),
                                relay_state=ps_data.get("RelayState"),
                                managed_policies=managed_policies,
                                inline_policy=inline_policy,
                                raw_data=ps_data,
                            )
                            permission_sets.append(permission_set)

                            # Get assignments for this permission set
                            account_paginator = sso_client.get_paginator(
                                "list_accounts_for_provisioned_permission_set"
                            )
                            for account_page in account_paginator.paginate(
                                InstanceArn=instance_arn, PermissionSetArn=ps_arn
                            ):
                                for account_id in account_page.get("AccountIds", []):
                                    # Get assignments for this account
                                    assignment_paginator = sso_client.get_paginator(
                                        "list_account_assignments"
                                    )
                                    for (
                                        assignment_page
                                    ) in assignment_paginator.paginate(
                                        InstanceArn=instance_arn,
                                        AccountId=account_id,
                                        PermissionSetArn=ps_arn,
                                    ):
                                        for assignment_data in assignment_page.get(
                                            "AccountAssignments", []
                                        ):
                                            assignment = SSOAssignment(
                                                scan_id=self.scan_id,
                                                instance_arn=instance_arn,
                                                permission_set_arn=ps_arn,
                                                target_type="AWS_ACCOUNT",  # Fixed: was account_id, should be target_type
                                                target_id=account_id,  # Fixed: was account_id, should be target_id
                                                principal_type=assignment_data[
                                                    "PrincipalType"
                                                ],
                                                principal_id=assignment_data[
                                                    "PrincipalId"
                                                ],
                                                raw_data=assignment_data,
                                            )
                                            assignments.append(assignment)

                        except ClientError as e:
                            logger.warning(
                                f"Failed to get permission set details for {ps_arn}: {e}"
                            )
                            continue

            logger.debug(
                f"Collected {len(permission_sets)} SSO permission sets, {len(assignments)} assignments"
            )

        except ClientError as e:
            if e.response["Error"]["Code"] == "AccessDeniedException":
                logger.warning("No permission to access SSO/Identity Center")
            else:
                logger.error(f"Failed to collect SSO data: {e}")
        except Exception as e:
            logger.error(f"Unexpected error collecting SSO data: {e}", exc_info=True)

        return permission_sets, assignments

    def collect_cloudtrail_trails(self, region: str) -> List[CloudTrail]:
        """
        Collect CloudTrail trails from a specific region.

        Args:
            region: AWS region

        Returns:
            List of CloudTrail trail resources
        """
        cloudtrail_trails = []
        try:
            cloudtrail_client = self.session.client("cloudtrail", region_name=region)

            # List trails
            trails_response = cloudtrail_client.list_trails()

            for trail_info in trails_response.get("Trails", []):
                trail_arn = trail_info["TrailARN"]

                try:
                    # Get trail details
                    trail_response = cloudtrail_client.describe_trails(
                        trailNameList=[trail_info["Name"]]
                    )

                    if not trail_response.get("trailList"):
                        continue

                    trail_data = trail_response["trailList"][0]

                    # Get trail status
                    status_response = cloudtrail_client.get_trail_status(Name=trail_arn)

                    # Get event selectors
                    event_selectors = []
                    try:
                        selectors_response = cloudtrail_client.get_event_selectors(
                            TrailName=trail_arn
                        )
                        event_selectors = selectors_response.get("EventSelectors", [])
                    except ClientError:
                        pass

                    # Get tags
                    tags = {}
                    try:
                        tags_response = cloudtrail_client.list_tags(
                            ResourceIdList=[trail_arn]
                        )
                        for resource_tag in tags_response.get("ResourceTagList", []):
                            if resource_tag["ResourceId"] == trail_arn:
                                tags = {
                                    tag["Key"]: tag["Value"]
                                    for tag in resource_tag.get("TagsList", [])
                                }
                    except ClientError:
                        pass

                    cloudtrail = CloudTrail(
                        scan_id=self.scan_id,
                        trail_arn=trail_arn,
                        trail_name=trail_data.get("Name"),
                        region=region,
                        s3_bucket_name=trail_data.get("S3BucketName"),
                        s3_key_prefix=trail_data.get("S3KeyPrefix"),
                        sns_topic_arn=trail_data.get("SnsTopicARN"),
                        is_multi_region=trail_data.get("IsMultiRegionTrail", False),
                        is_organization_trail=trail_data.get(
                            "IsOrganizationTrail", False
                        ),
                        is_logging=status_response.get("IsLogging", False),
                        log_file_validation_enabled=trail_data.get(
                            "LogFileValidationEnabled", False
                        ),
                        kms_key_id=trail_data.get("KmsKeyId"),
                        cloudwatch_logs_log_group_arn=trail_data.get(
                            "CloudWatchLogsLogGroupArn"
                        ),
                        cloudwatch_logs_role_arn=trail_data.get(
                            "CloudWatchLogsRoleArn"
                        ),
                        event_selectors=event_selectors,
                        home_region=trail_data.get("HomeRegion"),
                        tags=tags,
                        raw_data=trail_data,
                    )
                    cloudtrail_trails.append(cloudtrail)

                except ClientError as e:
                    logger.warning(
                        f"Failed to get trail details for {trail_info['Name']}: {e}"
                    )
                    continue

            logger.debug(
                f"Collected {len(cloudtrail_trails)} CloudTrail trails from {region}"
            )

        except ClientError as e:
            logger.error(f"Failed to collect CloudTrail trails from {region}: {e}")
        except Exception as e:
            logger.error(
                f"Unexpected error collecting CloudTrail trails from {region}: {e}",
                exc_info=True,
            )

        return cloudtrail_trails

    def collect_cloudwatch_log_groups(self, region: str) -> List[CloudWatchLogGroup]:
        """
        Collect CloudWatch Log Groups from a specific region.

        Args:
            region: AWS region

        Returns:
            List of CloudWatch Log Group resources
        """
        log_groups = []
        try:
            logs_client = self.session.client("logs", region_name=region)

            # List log groups
            paginator = logs_client.get_paginator("describe_log_groups")
            for page in paginator.paginate():
                for lg_data in page.get("logGroups", []):
                    # Get tags
                    tags = {}
                    try:
                        tags_response = logs_client.list_tags_for_resource(
                            resourceArn=lg_data["arn"]
                        )
                        tags = tags_response.get("tags", {})
                    except ClientError:
                        pass

                    log_group = CloudWatchLogGroup(
                        scan_id=self.scan_id,
                        log_group_name=lg_data["logGroupName"],
                        log_group_arn=lg_data["arn"],
                        region=region,
                        creation_time=datetime.fromtimestamp(
                            lg_data["creationTime"] / 1000
                        )
                        if "creationTime" in lg_data
                        else None,
                        retention_in_days=lg_data.get("retentionInDays"),
                        metric_filter_count=lg_data.get("metricFilterCount", 0),
                        stored_bytes=lg_data.get("storedBytes", 0),
                        kms_key_id=lg_data.get("kmsKeyId"),
                        data_protection_status=lg_data.get("dataProtectionStatus"),
                        tags=tags,
                        raw_data=lg_data,
                    )
                    log_groups.append(log_group)

            logger.debug(
                f"Collected {len(log_groups)} CloudWatch Log Groups from {region}"
            )

        except ClientError as e:
            logger.error(f"Failed to collect CloudWatch Log Groups from {region}: {e}")
        except Exception as e:
            logger.error(
                f"Unexpected error collecting CloudWatch Log Groups from {region}: {e}",
                exc_info=True,
            )

        return log_groups

    def collect_config_recorders(self, region: str) -> List[ConfigRecorder]:
        """
        Collect AWS Config recorders from a specific region.

        Args:
            region: AWS region

        Returns:
            List of Config Recorder resources
        """
        config_recorders = []
        try:
            config_client = self.session.client("config", region_name=region)

            # Describe configuration recorders
            recorders_response = config_client.describe_configuration_recorders()

            for recorder_data in recorders_response.get("ConfigurationRecorders", []):
                # Get recorder status
                status_data = None
                try:
                    status_response = (
                        config_client.describe_configuration_recorder_status(
                            ConfigurationRecorderNames=[recorder_data["name"]]
                        )
                    )
                    if status_response.get("ConfigurationRecordersStatus"):
                        status_data = status_response["ConfigurationRecordersStatus"][0]
                except ClientError:
                    pass

                config_recorder = ConfigRecorder(
                    scan_id=self.scan_id,
                    recorder_name=recorder_data["name"],
                    recorder_arn=recorder_data.get("recordingGroup", {}).get(
                        "allSupported"
                    ),  # Note: Config doesn't provide ARN
                    region=region,
                    role_arn=recorder_data.get("roleARN"),
                    is_recording=status_data.get("recording", False)
                    if status_data
                    else False,
                    last_status=status_data.get("lastStatus") if status_data else None,
                    recording_group=recorder_data.get("recordingGroup", {}),
                    recording_mode=recorder_data.get("recordingMode", {}),
                    raw_data=recorder_data,
                )
                config_recorders.append(config_recorder)

            logger.debug(
                f"Collected {len(config_recorders)} Config recorders from {region}"
            )

        except ClientError as e:
            logger.error(f"Failed to collect Config recorders from {region}: {e}")
        except Exception as e:
            logger.error(
                f"Unexpected error collecting Config recorders from {region}: {e}",
                exc_info=True,
            )

        return config_recorders

    def collect_config_rules(self, region: str) -> List[ConfigRule]:
        """
        Collect AWS Config rules from a specific region.

        Args:
            region: AWS region

        Returns:
            List of Config Rule resources
        """
        config_rules = []
        try:
            config_client = self.session.client("config", region_name=region)

            # Describe config rules
            paginator = config_client.get_paginator("describe_config_rules")
            for page in paginator.paginate():
                for rule_data in page.get("ConfigRules", []):
                    # Get compliance status
                    compliance_status = None
                    try:
                        compliance_response = (
                            config_client.describe_compliance_by_config_rule(
                                ConfigRuleNames=[rule_data["ConfigRuleName"]]
                            )
                        )
                        if compliance_response.get("ComplianceByConfigRules"):
                            compliance_status = (
                                compliance_response["ComplianceByConfigRules"][0]
                                .get("Compliance", {})
                                .get("ComplianceType")
                            )
                    except ClientError:
                        pass

                    config_rule = ConfigRule(
                        scan_id=self.scan_id,
                        rule_name=rule_data["ConfigRuleName"],
                        rule_arn=rule_data["ConfigRuleArn"],
                        rule_id=rule_data["ConfigRuleId"],
                        region=region,
                        description=rule_data.get("Description"),
                        scope=rule_data.get("Scope"),
                        source=rule_data.get("Source", {}),
                        maximum_execution_frequency=rule_data.get(
                            "MaximumExecutionFrequency"
                        ),
                        config_rule_state=rule_data.get("ConfigRuleState", "ACTIVE"),
                        compliance_type=compliance_status,
                        raw_data=rule_data,
                    )
                    config_rules.append(config_rule)

            logger.debug(f"Collected {len(config_rules)} Config rules from {region}")

        except ClientError as e:
            logger.error(f"Failed to collect Config rules from {region}: {e}")
        except Exception as e:
            logger.error(
                f"Unexpected error collecting Config rules from {region}: {e}",
                exc_info=True,
            )

        return config_rules

    def collect_bedrock_models(self, region: str) -> List[BedrockModel]:
        """
        Collect Amazon Bedrock foundation models from a specific region.

        Args:
            region: AWS region

        Returns:
            List of Bedrock Model resources
        """
        bedrock_models = []
        try:
            bedrock_client = self.session.client("bedrock", region_name=region)

            # List foundation models (this API does not support pagination)
            response = bedrock_client.list_foundation_models()

            for model_data in response.get("modelSummaries", []):
                bedrock_model = BedrockModel(
                    scan_id=self.scan_id,
                    model_arn=model_data["modelArn"],
                    model_id=model_data["modelId"],
                    model_name=model_data.get("modelName"),
                    region=region,
                    provider_name=model_data.get("providerName"),
                    input_modalities=model_data.get("inputModalities", []),
                    output_modalities=model_data.get("outputModalities", []),
                    response_streaming_supported=model_data.get(
                        "responseStreamingSupported", False
                    ),
                    customizations_supported=model_data.get(
                        "customizationsSupported", []
                    ),
                    inference_types_supported=model_data.get(
                        "inferenceTypesSupported", []
                    ),
                    model_lifecycle_status=model_data.get("modelLifecycle", {}).get(
                        "status"
                    ),
                    raw_data=model_data,
                )
                bedrock_models.append(bedrock_model)

            logger.debug(
                f"Collected {len(bedrock_models)} Bedrock models from {region}"
            )

        except ClientError as e:
            if e.response["Error"]["Code"] == "AccessDeniedException":
                logger.warning(f"No permission to access Bedrock in {region}")
            else:
                logger.error(f"Failed to collect Bedrock models from {region}: {e}")
        except Exception as e:
            logger.error(
                f"Unexpected error collecting Bedrock models from {region}: {e}",
                exc_info=True,
            )

        return bedrock_models

    def collect_bedrock_guardrails(self, region: str) -> List[BedrockGuardrail]:
        """
        Collect Amazon Bedrock guardrails from a specific region.

        Args:
            region: AWS region

        Returns:
            List of Bedrock Guardrail resources
        """
        bedrock_guardrails = []
        try:
            bedrock_client = self.session.client("bedrock", region_name=region)

            # List guardrails
            paginator = bedrock_client.get_paginator("list_guardrails")
            for page in paginator.paginate():
                for guardrail_summary in page.get("guardrails", []):
                    try:
                        # Get guardrail details
                        guardrail_response = bedrock_client.get_guardrail(
                            guardrailIdentifier=guardrail_summary["id"]
                        )

                        gr_data = guardrail_response.get("guardrail", {})

                        bedrock_guardrail = BedrockGuardrail(
                            scan_id=self.scan_id,
                            guardrail_id=guardrail_summary["id"],
                            guardrail_arn=guardrail_summary["arn"],
                            guardrail_name=guardrail_summary.get("name"),
                            region=region,
                            description=guardrail_summary.get("description"),
                            status=guardrail_summary.get("status", "UNKNOWN"),
                            version=guardrail_summary.get("version"),
                            blocked_input_messaging=gr_data.get(
                                "blockedInputMessaging"
                            ),
                            blocked_outputs_messaging=gr_data.get(
                                "blockedOutputsMessaging"
                            ),
                            content_policy=gr_data.get("contentPolicy"),
                            word_policy=gr_data.get("wordPolicy"),
                            topic_policy=gr_data.get("topicPolicy"),
                            sensitive_information_policy=gr_data.get(
                                "sensitiveInformationPolicy"
                            ),
                            created_at=guardrail_summary.get("createdAt"),
                            updated_at=guardrail_summary.get("updatedAt"),
                            raw_data=guardrail_summary,
                        )
                        bedrock_guardrails.append(bedrock_guardrail)

                    except ClientError as e:
                        logger.warning(
                            f"Failed to get guardrail details for {guardrail_summary['id']}: {e}"
                        )
                        continue

            logger.debug(
                f"Collected {len(bedrock_guardrails)} Bedrock guardrails from {region}"
            )

        except ClientError as e:
            if e.response["Error"]["Code"] == "AccessDeniedException":
                logger.warning(f"No permission to access Bedrock in {region}")
            else:
                logger.error(f"Failed to collect Bedrock guardrails from {region}: {e}")
        except Exception as e:
            logger.error(
                f"Unexpected error collecting Bedrock guardrails from {region}: {e}",
                exc_info=True,
            )

        return bedrock_guardrails

    def collect_bedrock_knowledge_bases(
        self, region: str
    ) -> List[BedrockKnowledgeBase]:
        """
        Collect Amazon Bedrock knowledge bases from a specific region.

        Args:
            region: AWS region

        Returns:
            List of Bedrock Knowledge Base resources
        """
        bedrock_knowledge_bases = []
        try:
            bedrock_agent_client = self.session.client(
                "bedrock-agent", region_name=region
            )

            # List knowledge bases
            paginator = bedrock_agent_client.get_paginator("list_knowledge_bases")
            for page in paginator.paginate():
                for kb_summary in page.get("knowledgeBaseSummaries", []):
                    try:
                        # Get knowledge base details
                        kb_response = bedrock_agent_client.get_knowledge_base(
                            knowledgeBaseId=kb_summary["knowledgeBaseId"]
                        )

                        kb_data = kb_response["knowledgeBase"]

                        bedrock_kb = BedrockKnowledgeBase(
                            scan_id=self.scan_id,
                            knowledge_base_id=kb_data["knowledgeBaseId"],
                            knowledge_base_arn=kb_data["knowledgeBaseArn"],
                            knowledge_base_name=kb_data.get("name"),
                            region=region,
                            description=kb_data.get("description"),
                            role_arn=kb_data.get("roleArn"),
                            status=kb_data.get("status", "UNKNOWN"),
                            storage_configuration=kb_data.get("storageConfiguration"),
                            knowledge_base_configuration=kb_data.get(
                                "knowledgeBaseConfiguration"
                            ),
                            created_at=kb_data.get("createdAt"),
                            updated_at=kb_data.get("updatedAt"),
                            raw_data=kb_data,
                        )
                        bedrock_knowledge_bases.append(bedrock_kb)

                    except ClientError as e:
                        logger.warning(
                            f"Failed to get knowledge base details for {kb_summary['knowledgeBaseId']}: {e}"
                        )
                        continue

            logger.debug(
                f"Collected {len(bedrock_knowledge_bases)} Bedrock knowledge bases from {region}"
            )

        except ClientError as e:
            if e.response["Error"]["Code"] == "AccessDeniedException":
                logger.warning(f"No permission to access Bedrock in {region}")
            else:
                logger.error(
                    f"Failed to collect Bedrock knowledge bases from {region}: {e}"
                )
        except Exception as e:
            logger.error(
                f"Unexpected error collecting Bedrock knowledge bases from {region}: {e}",
                exc_info=True,
            )

        return bedrock_knowledge_bases

    def collect_bedrock_agents(self, region: str) -> List[BedrockAgent]:
        """
        Collect Amazon Bedrock agents from a specific region.

        Args:
            region: AWS region

        Returns:
            List of Bedrock Agent resources
        """
        bedrock_agents = []
        try:
            bedrock_agent_client = self.session.client(
                "bedrock-agent", region_name=region
            )

            # List agents
            paginator = bedrock_agent_client.get_paginator("list_agents")
            for page in paginator.paginate():
                for agent_summary in page.get("agentSummaries", []):
                    try:
                        # Get agent details
                        agent_response = bedrock_agent_client.get_agent(
                            agentId=agent_summary["agentId"]
                        )

                        agent_data = agent_response["agent"]

                        bedrock_agent = BedrockAgent(
                            scan_id=self.scan_id,
                            agent_id=agent_data["agentId"],
                            agent_arn=agent_data["agentArn"],
                            agent_name=agent_data.get("agentName"),
                            region=region,
                            description=agent_data.get("description"),
                            agent_status=agent_data.get("agentStatus", "UNKNOWN"),
                            agent_version=agent_data.get("agentVersion"),
                            foundation_model=agent_data.get("foundationModel"),
                            instruction=agent_data.get("instruction"),
                            agent_resource_role_arn=agent_data.get(
                                "agentResourceRoleArn"
                            ),
                            idle_session_ttl_in_seconds=agent_data.get(
                                "idleSessionTTLInSeconds"
                            ),
                            prompt_override_configuration=agent_data.get(
                                "promptOverrideConfiguration"
                            ),
                            guardrail_configuration=agent_data.get(
                                "guardrailConfiguration"
                            ),
                            created_at=agent_data.get("createdAt"),
                            updated_at=agent_data.get("updatedAt"),
                            prepared_at=agent_data.get("preparedAt"),
                            raw_data=agent_data,
                        )
                        bedrock_agents.append(bedrock_agent)

                    except ClientError as e:
                        logger.warning(
                            f"Failed to get agent details for {agent_summary['agentId']}: {e}"
                        )
                        continue

            logger.debug(
                f"Collected {len(bedrock_agents)} Bedrock agents from {region}"
            )

        except ClientError as e:
            if e.response["Error"]["Code"] == "AccessDeniedException":
                logger.warning(f"No permission to access Bedrock in {region}")
            else:
                logger.error(f"Failed to collect Bedrock agents from {region}: {e}")
        except Exception as e:
            logger.error(
                f"Unexpected error collecting Bedrock agents from {region}: {e}",
                exc_info=True,
            )

        return bedrock_agents

    def collect_directory_services(self, region: str) -> List[DirectoryService]:
        """
        Collect AWS Directory Service directories from a specific region.

        Args:
            region: AWS region

        Returns:
            List of Directory Service resources
        """
        directory_services = []
        try:
            ds_client = self.session.client("ds", region_name=region)

            # Describe directories
            directories_response = ds_client.describe_directories()

            for dir_data in directories_response.get("DirectoryDescriptions", []):
                # Get snapshots
                snapshots = []
                try:
                    snapshots_response = ds_client.describe_snapshots(
                        DirectoryId=dir_data["DirectoryId"]
                    )
                    snapshots = snapshots_response.get("Snapshots", [])
                except ClientError:
                    pass

                # Get tags
                tags = {}
                try:
                    tags_response = ds_client.list_tags_for_resource(
                        ResourceId=dir_data["DirectoryId"]
                    )
                    tags = {
                        tag["Key"]: tag["Value"]
                        for tag in tags_response.get("Tags", [])
                    }
                except ClientError:
                    pass

                directory_service = DirectoryService(
                    scan_id=self.scan_id,
                    directory_id=dir_data["DirectoryId"],
                    directory_name=dir_data.get("Name"),
                    region=region,
                    directory_type=dir_data.get("Type", "Unknown"),
                    size=dir_data.get("Size"),
                    edition=dir_data.get("Edition"),
                    alias=dir_data.get("Alias"),
                    access_url=dir_data.get("AccessUrl"),
                    description=dir_data.get("Description"),
                    dns_ip_addresses=dir_data.get("DnsIpAddrs", []),
                    stage=dir_data.get("Stage", "Unknown"),
                    launch_time=dir_data.get("LaunchTime"),
                    stage_last_updated_date_time=dir_data.get(
                        "StageLastUpdatedDateTime"
                    ),
                    vpc_settings=dir_data.get("VpcSettings"),
                    connect_settings=dir_data.get("ConnectSettings"),
                    radius_settings=dir_data.get("RadiusSettings"),
                    sso_enabled=dir_data.get("SsoEnabled", False),
                    desired_number_of_domain_controllers=dir_data.get(
                        "DesiredNumberOfDomainControllers"
                    ),
                    snapshots=snapshots,
                    tags=tags,
                    raw_data=dir_data,
                )
                directory_services.append(directory_service)

            logger.debug(
                f"Collected {len(directory_services)} Directory Services from {region}"
            )

        except ClientError as e:
            logger.error(f"Failed to collect Directory Services from {region}: {e}")
        except Exception as e:
            logger.error(
                f"Unexpected error collecting Directory Services from {region}: {e}",
                exc_info=True,
            )

        return directory_services

    def collect_transit_gateways(self, region: str) -> List[TransitGateway]:
        """
        Collect Transit Gateways from a specific region.

        Args:
            region: AWS region

        Returns:
            List of Transit Gateway resources
        """
        transit_gateways = []
        try:
            ec2_client = self.session.client("ec2", region_name=region)

            # Describe transit gateways
            paginator = ec2_client.get_paginator("describe_transit_gateways")
            for page in paginator.paginate():
                for tgw_data in page.get("TransitGateways", []):
                    transit_gateway = TransitGateway(
                        scan_id=self.scan_id,
                        transit_gateway_id=tgw_data["TransitGatewayId"],
                        transit_gateway_arn=tgw_data["TransitGatewayArn"],
                        region=region,
                        state=tgw_data.get("State", "unknown"),
                        owner_id=tgw_data.get("OwnerId"),
                        description=tgw_data.get("Description"),
                        creation_time=tgw_data.get("CreationTime"),
                        options=tgw_data.get("Options", {}),
                        tags=parse_tags(tgw_data.get("Tags", [])),
                        raw_data=tgw_data,
                    )
                    transit_gateways.append(transit_gateway)

            logger.debug(
                f"Collected {len(transit_gateways)} Transit Gateways from {region}"
            )

        except ClientError as e:
            logger.error(f"Failed to collect Transit Gateways from {region}: {e}")
        except Exception as e:
            logger.error(
                f"Unexpected error collecting Transit Gateways from {region}: {e}",
                exc_info=True,
            )

        return transit_gateways

    def collect_vpn_connections(self, region: str) -> List[VPNConnection]:
        """
        Collect VPN connections from a specific region.

        Args:
            region: AWS region

        Returns:
            List of VPN Connection resources
        """
        vpn_connections = []
        try:
            ec2_client = self.session.client("ec2", region_name=region)

            # Describe VPN connections
            response = ec2_client.describe_vpn_connections()

            for vpn_data in response.get("VpnConnections", []):
                vpn_connection = VPNConnection(
                    scan_id=self.scan_id,
                    vpn_connection_id=vpn_data["VpnConnectionId"],
                    region=region,
                    state=vpn_data.get("State", "unknown"),
                    vpn_connection_type=vpn_data.get("Type", "ipsec.1"),
                    customer_gateway_id=vpn_data.get("CustomerGatewayId", ""),
                    vpn_gateway_id=vpn_data.get("VpnGatewayId"),
                    transit_gateway_id=vpn_data.get("TransitGatewayId"),
                    customer_gateway_configuration=vpn_data.get(
                        "CustomerGatewayConfiguration"
                    ),
                    static_routes_only=vpn_data.get("Options", {}).get(
                        "StaticRoutesOnly", False
                    ),
                    vgw_telemetry=vpn_data.get("VgwTelemetry", []),
                    routes=vpn_data.get("Routes", []),
                    category=vpn_data.get("Category"),
                    tags=parse_tags(vpn_data.get("Tags", [])),
                    raw_data=vpn_data,
                )
                vpn_connections.append(vpn_connection)

            logger.debug(
                f"Collected {len(vpn_connections)} VPN connections from {region}"
            )

        except ClientError as e:
            logger.error(f"Failed to collect VPN connections from {region}: {e}")
        except Exception as e:
            logger.error(
                f"Unexpected error collecting VPN connections from {region}: {e}",
                exc_info=True,
            )

        return vpn_connections

    def collect_direct_connect_connections(
        self, region: str
    ) -> List[DirectConnectConnection]:
        """
        Collect AWS Direct Connect connections from a specific region.

        Args:
            region: AWS region

        Returns:
            List of Direct Connect Connection resources
        """
        direct_connect_connections = []
        try:
            dx_client = self.session.client("directconnect", region_name=region)

            # Describe connections
            connections_response = dx_client.describe_connections()

            for conn_data in connections_response.get("connections", []):
                # Get tags
                tags = {}
                try:
                    tags_response = dx_client.describe_tags(
                        resourceArns=[conn_data["connectionId"]]
                    )
                    for resource_tag in tags_response.get("resourceTags", []):
                        if resource_tag["resourceArn"] == conn_data["connectionId"]:
                            tags = {
                                tag["key"]: tag["value"]
                                for tag in resource_tag.get("tags", [])
                            }
                except ClientError:
                    pass

                direct_connect_connection = DirectConnectConnection(
                    scan_id=self.scan_id,
                    connection_id=conn_data["connectionId"],
                    connection_name=conn_data.get("connectionName"),
                    region=region,
                    connection_state=conn_data.get("connectionState", "unknown"),
                    location=conn_data.get("location"),
                    bandwidth=conn_data.get("bandwidth"),
                    vlan=conn_data.get("vlan"),
                    partner_name=conn_data.get("partnerName"),
                    lag_id=conn_data.get("lagId"),
                    aws_device=conn_data.get("awsDevice"),
                    aws_device_v2=conn_data.get("awsDeviceV2"),
                    aws_logical_device_id=conn_data.get("awsLogicalDeviceId"),
                    jumbo_frame_capable=conn_data.get("jumboFrameCapable", False),
                    has_logical_redundancy=conn_data.get("hasLogicalRedundancy"),
                    provider_name=conn_data.get("providerName"),
                    encryption_mode=conn_data.get("encryptionMode"),
                    mac_sec_capable=conn_data.get("macSecCapable", False),
                    port_encryption_status=conn_data.get("portEncryptionStatus"),
                    tags=tags,
                    raw_data=conn_data,
                )
                direct_connect_connections.append(direct_connect_connection)

            logger.debug(
                f"Collected {len(direct_connect_connections)} Direct Connect connections from {region}"
            )

        except ClientError as e:
            logger.error(
                f"Failed to collect Direct Connect connections from {region}: {e}"
            )
        except Exception as e:
            logger.error(
                f"Unexpected error collecting Direct Connect connections from {region}: {e}",
                exc_info=True,
            )

        return direct_connect_connections

    def collect_elasticache_clusters(self, region: str) -> List[ElastiCacheCluster]:
        """
        Collect ElastiCache clusters from a specific region.

        Args:
            region: AWS region

        Returns:
            List of ElastiCache Cluster resources
        """
        elasticache_clusters = []
        try:
            elasticache_client = self.session.client("elasticache", region_name=region)

            # Describe cache clusters
            paginator = elasticache_client.get_paginator("describe_cache_clusters")
            for page in paginator.paginate(ShowCacheNodeInfo=True):
                for cluster_data in page.get("CacheClusters", []):
                    # Get tags
                    tags = {}
                    try:
                        tags_response = elasticache_client.list_tags_for_resource(
                            ResourceName=cluster_data["ARN"]
                        )
                        tags = {
                            tag["Key"]: tag["Value"]
                            for tag in tags_response.get("TagList", [])
                        }
                    except ClientError:
                        pass

                    elasticache_cluster = ElastiCacheCluster(
                        scan_id=self.scan_id,
                        cache_cluster_id=cluster_data["CacheClusterId"],
                        cache_cluster_arn=cluster_data.get("ARN"),
                        region=region,
                        cache_cluster_status=cluster_data.get(
                            "CacheClusterStatus", "unknown"
                        ),
                        engine=cluster_data.get("Engine"),
                        engine_version=cluster_data.get("EngineVersion"),
                        cache_node_type=cluster_data.get("CacheNodeType"),
                        num_cache_nodes=cluster_data.get("NumCacheNodes", 0),
                        preferred_availability_zone=cluster_data.get(
                            "PreferredAvailabilityZone"
                        ),
                        cache_cluster_create_time=cluster_data.get(
                            "CacheClusterCreateTime"
                        ),
                        preferred_maintenance_window=cluster_data.get(
                            "PreferredMaintenanceWindow"
                        ),
                        cache_subnet_group_name=cluster_data.get(
                            "CacheSubnetGroupName"
                        ),
                        cache_security_groups=cluster_data.get(
                            "CacheSecurityGroups", []
                        ),
                        security_groups=[
                            sg["SecurityGroupId"]
                            for sg in cluster_data.get("SecurityGroups", [])
                        ],
                        replication_group_id=cluster_data.get("ReplicationGroupId"),
                        snapshot_retention_limit=cluster_data.get(
                            "SnapshotRetentionLimit"
                        ),
                        snapshot_window=cluster_data.get("SnapshotWindow"),
                        auth_token_enabled=cluster_data.get("AuthTokenEnabled", False),
                        transit_encryption_enabled=cluster_data.get(
                            "TransitEncryptionEnabled", False
                        ),
                        at_rest_encryption_enabled=cluster_data.get(
                            "AtRestEncryptionEnabled", False
                        ),
                        cache_parameter_group=cluster_data.get(
                            "CacheParameterGroup", {}
                        ).get("CacheParameterGroupName"),
                        cache_nodes=cluster_data.get("CacheNodes", []),
                        auto_minor_version_upgrade=cluster_data.get(
                            "AutoMinorVersionUpgrade", False
                        ),
                        notification_configuration=cluster_data.get(
                            "NotificationConfiguration"
                        ),
                        tags=tags,
                        raw_data=cluster_data,
                    )
                    elasticache_clusters.append(elasticache_cluster)

            logger.debug(
                f"Collected {len(elasticache_clusters)} ElastiCache clusters from {region}"
            )

        except ClientError as e:
            logger.error(f"Failed to collect ElastiCache clusters from {region}: {e}")
        except Exception as e:
            logger.error(
                f"Unexpected error collecting ElastiCache clusters from {region}: {e}",
                exc_info=True,
            )

        return elasticache_clusters

    def collect_opensearch_domains(self, region: str) -> List[OpenSearchDomain]:
        """
        Collect OpenSearch Service domains from a specific region.

        Args:
            region: AWS region

        Returns:
            List of OpenSearch Domain resources
        """
        opensearch_domains = []
        try:
            opensearch_client = self.session.client("opensearch", region_name=region)

            # List domain names
            domain_names_response = opensearch_client.list_domain_names()

            for domain_info in domain_names_response.get("DomainNames", []):
                domain_name = domain_info["DomainName"]

                try:
                    # Describe domain
                    domain_response = opensearch_client.describe_domain(
                        DomainName=domain_name
                    )
                    domain_data = domain_response["DomainStatus"]

                    # Get tags
                    tags = {}
                    try:
                        tags_response = opensearch_client.list_tags(
                            ARN=domain_data["ARN"]
                        )
                        tags = {
                            tag["Key"]: tag["Value"]
                            for tag in tags_response.get("TagList", [])
                        }
                    except ClientError:
                        pass

                    opensearch_domain = OpenSearchDomain(
                        scan_id=self.scan_id,
                        domain_id=domain_data["DomainId"],
                        domain_name=domain_data["DomainName"],
                        domain_arn=domain_data["ARN"],
                        region=region,
                        engine_version=domain_data.get("EngineVersion"),
                        cluster_config=domain_data.get("ClusterConfig", {}),
                        ebs_options=domain_data.get("EBSOptions", {}),
                        access_policies=domain_data.get("AccessPolicies"),
                        snapshot_options=domain_data.get("SnapshotOptions", {}),
                        vpc_options=domain_data.get("VPCOptions", {}),
                        cognito_options=domain_data.get("CognitoOptions", {}),
                        encryption_at_rest_options=domain_data.get(
                            "EncryptionAtRestOptions", {}
                        ),
                        node_to_node_encryption_options=domain_data.get(
                            "NodeToNodeEncryptionOptions", {}
                        ),
                        advanced_options=domain_data.get("AdvancedOptions", {}),
                        log_publishing_options=domain_data.get(
                            "LogPublishingOptions", {}
                        ),
                        service_software_options=domain_data.get(
                            "ServiceSoftwareOptions", {}
                        ),
                        domain_endpoint_options=domain_data.get(
                            "DomainEndpointOptions", {}
                        ),
                        advanced_security_options=domain_data.get(
                            "AdvancedSecurityOptions", {}
                        ),
                        auto_tune_options=domain_data.get("AutoTuneOptions", {}),
                        created=domain_data.get("Created", False),
                        deleted=domain_data.get("Deleted", False),
                        endpoint=domain_data.get("Endpoint"),
                        endpoints=domain_data.get("Endpoints", {}),
                        processing=domain_data.get("Processing", False),
                        upgrade_processing=domain_data.get("UpgradeProcessing", False),
                        tags=tags,
                        raw_data=domain_data,
                    )
                    opensearch_domains.append(opensearch_domain)

                except ClientError as e:
                    logger.warning(
                        f"Failed to describe OpenSearch domain {domain_name}: {e}"
                    )
                    continue

            logger.debug(
                f"Collected {len(opensearch_domains)} OpenSearch domains from {region}"
            )

        except ClientError as e:
            logger.error(f"Failed to collect OpenSearch domains from {region}: {e}")
        except Exception as e:
            logger.error(
                f"Unexpected error collecting OpenSearch domains from {region}: {e}",
                exc_info=True,
            )

        return opensearch_domains

    def collect_msk_clusters(self, region: str) -> List[MSKCluster]:
        """
        Collect Amazon MSK (Managed Streaming for Kafka) clusters from a specific region.

        Args:
            region: AWS region

        Returns:
            List of MSK Cluster resources
        """
        msk_clusters = []
        try:
            kafka_client = self.session.client("kafka", region_name=region)

            # List clusters
            paginator = kafka_client.get_paginator("list_clusters_v2")
            for page in paginator.paginate():
                for cluster_info in page.get("ClusterInfoList", []):
                    cluster_arn = cluster_info["ClusterArn"]

                    try:
                        # Get cluster details (v2 API for both provisioned and serverless)
                        if cluster_info["ClusterType"] == "PROVISIONED":
                            cluster_response = kafka_client.describe_cluster_v2(
                                ClusterArn=cluster_arn
                            )
                            cluster_data = cluster_response["ClusterInfo"]

                            # Get tags
                            tags = {}
                            try:
                                tags_response = kafka_client.list_tags_for_resource(
                                    ResourceArn=cluster_arn
                                )
                                tags = tags_response.get("Tags", {})
                            except ClientError:
                                pass

                            provisioned_data = cluster_data.get("Provisioned", {})

                            msk_cluster = MSKCluster(
                                scan_id=self.scan_id,
                                cluster_arn=cluster_arn,
                                cluster_name=cluster_data.get("ClusterName"),
                                region=region,
                                cluster_type=cluster_data.get(
                                    "ClusterType", "PROVISIONED"
                                ),
                                state=cluster_data.get("State", "UNKNOWN"),
                                creation_time=cluster_data.get("CreationTime"),
                                current_version=provisioned_data.get(
                                    "CurrentBrokerSoftwareInfo", {}
                                ).get("KafkaVersion"),
                                broker_node_group_info=provisioned_data.get(
                                    "BrokerNodeGroupInfo"
                                ),
                                encryption_info=provisioned_data.get("EncryptionInfo"),
                                client_authentication=provisioned_data.get(
                                    "ClientAuthentication"
                                ),
                                logging_info=provisioned_data.get("LoggingInfo"),
                                number_of_broker_nodes=provisioned_data.get(
                                    "NumberOfBrokerNodes"
                                ),
                                zookeeper_connect_string=provisioned_data.get(
                                    "ZookeeperConnectString"
                                ),
                                storage_mode=provisioned_data.get("StorageMode"),
                                enhanced_monitoring=provisioned_data.get(
                                    "EnhancedMonitoring"
                                ),
                                open_monitoring=provisioned_data.get("OpenMonitoring"),
                                tags=tags,
                                raw_data=cluster_data,
                            )
                            msk_clusters.append(msk_cluster)

                        elif cluster_info["ClusterType"] == "SERVERLESS":
                            # Serverless clusters have different structure
                            logger.debug(
                                f"Skipping serverless MSK cluster {cluster_arn} (not yet supported)"
                            )

                    except ClientError as e:
                        logger.warning(
                            f"Failed to describe MSK cluster {cluster_arn}: {e}"
                        )
                        continue

            logger.debug(f"Collected {len(msk_clusters)} MSK clusters from {region}")

        except ClientError as e:
            logger.error(f"Failed to collect MSK clusters from {region}: {e}")
        except Exception as e:
            logger.error(
                f"Unexpected error collecting MSK clusters from {region}: {e}",
                exc_info=True,
            )

        return msk_clusters

    def collect_dynamodb_tables(self, region: str) -> List[DynamoDBTable]:
        """
        Collect DynamoDB tables from a specific region.

        Args:
            region: AWS region

        Returns:
            List of DynamoDB Table resources
        """
        dynamodb_tables = []
        try:
            dynamodb_client = self.session.client("dynamodb", region_name=region)

            # List tables
            paginator = dynamodb_client.get_paginator("list_tables")
            for page in paginator.paginate():
                for table_name in page.get("TableNames", []):
                    try:
                        # Describe table
                        table_response = dynamodb_client.describe_table(
                            TableName=table_name
                        )
                        table_data = table_response["Table"]

                        # Get tags
                        tags = {}
                        try:
                            tags_response = dynamodb_client.list_tags_of_resource(
                                ResourceArn=table_data["TableArn"]
                            )
                            tags = {
                                tag["Key"]: tag["Value"]
                                for tag in tags_response.get("Tags", [])
                            }
                        except ClientError:
                            pass

                        # Get continuous backups status
                        continuous_backups_enabled = False
                        point_in_time_recovery_enabled = False
                        try:
                            backups_response = (
                                dynamodb_client.describe_continuous_backups(
                                    TableName=table_name
                                )
                            )
                            continuous_backups_enabled = (
                                backups_response.get(
                                    "ContinuousBackupsDescription", {}
                                ).get("ContinuousBackupsStatus")
                                == "ENABLED"
                            )
                            point_in_time_recovery_enabled = (
                                backups_response.get("ContinuousBackupsDescription", {})
                                .get("PointInTimeRecoveryDescription", {})
                                .get("PointInTimeRecoveryStatus")
                                == "ENABLED"
                            )
                        except ClientError:
                            pass

                        dynamodb_table = DynamoDBTable(
                            scan_id=self.scan_id,
                            table_name=table_data["TableName"],
                            table_arn=table_data["TableArn"],
                            table_id=table_data.get("TableId"),
                            region=region,
                            table_status=table_data.get("TableStatus", "UNKNOWN"),
                            creation_date_time=table_data.get("CreationDateTime"),
                            key_schema=table_data.get("KeySchema", []),
                            attribute_definitions=table_data.get(
                                "AttributeDefinitions", []
                            ),
                            billing_mode=table_data.get("BillingModeSummary", {}).get(
                                "BillingMode", "PROVISIONED"
                            ),
                            provisioned_throughput=table_data.get(
                                "ProvisionedThroughput", {}
                            ),
                            table_size_bytes=table_data.get("TableSizeBytes", 0),
                            item_count=table_data.get("ItemCount", 0),
                            global_secondary_indexes=table_data.get(
                                "GlobalSecondaryIndexes", []
                            ),
                            local_secondary_indexes=table_data.get(
                                "LocalSecondaryIndexes", []
                            ),
                            stream_specification=table_data.get("StreamSpecification"),
                            latest_stream_arn=table_data.get("LatestStreamArn"),
                            sse_description=table_data.get("SSEDescription"),
                            replica=table_data.get("Replicas", []),
                            restore_summary=table_data.get("RestoreSummary"),
                            archival_summary=table_data.get("ArchivalSummary"),
                            table_class_summary=table_data.get("TableClassSummary"),
                            deletion_protection_enabled=table_data.get(
                                "DeletionProtectionEnabled", False
                            ),
                            continuous_backups_enabled=continuous_backups_enabled,
                            point_in_time_recovery_enabled=point_in_time_recovery_enabled,
                            tags=tags,
                            raw_data=table_data,
                        )
                        dynamodb_tables.append(dynamodb_table)

                    except ClientError as e:
                        logger.warning(
                            f"Failed to describe DynamoDB table {table_name}: {e}"
                        )
                        continue

            logger.debug(
                f"Collected {len(dynamodb_tables)} DynamoDB tables from {region}"
            )

        except ClientError as e:
            logger.error(f"Failed to collect DynamoDB tables from {region}: {e}")
        except Exception as e:
            logger.error(
                f"Unexpected error collecting DynamoDB tables from {region}: {e}",
                exc_info=True,
            )

        return dynamodb_tables

    def collect_account_security_posture(
        self,
    ) -> tuple[Optional[AccountSecurityPosture], List[IAMCredentialReportEntry]]:
        """
        Collect account-level security posture: IAM account summary,
        password policy, credential report, and the account-level S3
        Public Access Block. Each part degrades independently on error.
        """
        import csv as csv_module
        import io
        import time

        iam_client = self.session.client("iam")
        posture = AccountSecurityPosture(scan_id=self.scan_id)
        entries: List[IAMCredentialReportEntry] = []

        try:
            posture.account_summary = iam_client.get_account_summary()["SummaryMap"]
        except ClientError as e:
            logger.error(f"Failed to collect IAM account summary: {e}")

        try:
            policy = iam_client.get_account_password_policy()["PasswordPolicy"]
            posture.password_policy = policy
            posture.password_policy_exists = True
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchEntity":
                posture.password_policy_exists = False
                logger.info("No account password policy configured")
            else:
                logger.error(f"Failed to collect password policy: {e}")

        try:
            for _ in range(10):
                state = iam_client.generate_credential_report().get("State")
                if state == "COMPLETE":
                    break
                time.sleep(2)
            report = iam_client.get_credential_report()
            posture.credential_report_generated = datetime.now(UTC)

            def _flag(value: str) -> bool:
                return value.strip().lower() == "true"

            def _optional(value: str) -> Optional[str]:
                stripped = value.strip()
                if stripped in ("N/A", "not_supported", "no_information", ""):
                    return None
                return stripped

            reader = csv_module.DictReader(
                io.StringIO(report["Content"].decode("utf-8"))
            )
            for row in reader:
                password_raw = row.get("password_enabled", "").strip()
                entries.append(
                    IAMCredentialReportEntry(
                        scan_id=self.scan_id,
                        user_name=row["user"],
                        arn=_optional(row.get("arn", "")),
                        user_creation_time=_optional(row.get("user_creation_time", "")),
                        password_enabled=(
                            None
                            if password_raw in ("not_supported", "")
                            else _flag(password_raw)
                        ),
                        password_last_used=_optional(row.get("password_last_used", "")),
                        mfa_active=_flag(row.get("mfa_active", "false")),
                        access_key_1_active=_flag(
                            row.get("access_key_1_active", "false")
                        ),
                        access_key_1_last_rotated=_optional(
                            row.get("access_key_1_last_rotated", "")
                        ),
                        access_key_1_last_used=_optional(
                            row.get("access_key_1_last_used_date", "")
                        ),
                        access_key_2_active=_flag(
                            row.get("access_key_2_active", "false")
                        ),
                        access_key_2_last_rotated=_optional(
                            row.get("access_key_2_last_rotated", "")
                        ),
                        access_key_2_last_used=_optional(
                            row.get("access_key_2_last_used_date", "")
                        ),
                        raw_data=dict(row),
                    )
                )
        except ClientError as e:
            logger.error(f"Failed to collect IAM credential report: {e}")

        try:
            sts_client = self.session.client("sts")
            account_id = sts_client.get_caller_identity()["Account"]
            s3control_client = self.session.client("s3control")
            pab = s3control_client.get_public_access_block(AccountId=account_id)
            posture.account_public_access_block = pab["PublicAccessBlockConfiguration"]
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
                logger.info("No account-level S3 Public Access Block configured")
            else:
                logger.error(f"Failed to collect account Public Access Block: {e}")

        logger.debug(
            f"Collected account security posture and {len(entries)} credential report rows"
        )
        return posture, entries

    def collect_region_security_services(
        self, region: str
    ) -> Optional[RegionSecurityServices]:
        """
        Collect the enablement state of GuardDuty, Security Hub, EBS
        default encryption and IAM Access Analyzer for one region.
        None values mean the state could not be determined (access denied).
        """
        record = RegionSecurityServices(scan_id=self.scan_id, region=region)

        try:
            guardduty = self.session.client("guardduty", region_name=region)
            detector_ids = guardduty.list_detectors().get("DetectorIds", [])
            if detector_ids:
                detector = guardduty.get_detector(DetectorId=detector_ids[0])
                record.guardduty_enabled = detector.get("Status") == "ENABLED"
                record.guardduty_detector = {
                    "DetectorId": detector_ids[0],
                    "Status": detector.get("Status"),
                    "FindingPublishingFrequency": detector.get(
                        "FindingPublishingFrequency"
                    ),
                }
            else:
                record.guardduty_enabled = False
        except ClientError as e:
            logger.error(f"Failed to collect GuardDuty status in {region}: {e}")

        try:
            securityhub = self.session.client("securityhub", region_name=region)
            securityhub.describe_hub()
            record.security_hub_enabled = True
        except ClientError as e:
            if e.response["Error"]["Code"] in (
                "InvalidAccessException",
                "ResourceNotFoundException",
            ):
                record.security_hub_enabled = False
            else:
                logger.error(f"Failed to collect Security Hub status in {region}: {e}")

        try:
            ec2_client = self.session.client("ec2", region_name=region)
            response = ec2_client.get_ebs_encryption_by_default()
            record.ebs_encryption_by_default = response["EbsEncryptionByDefault"]
        except ClientError as e:
            logger.error(f"Failed to collect EBS default encryption in {region}: {e}")

        try:
            analyzer_client = self.session.client("accessanalyzer", region_name=region)
            analyzers = analyzer_client.list_analyzers().get("analyzers", [])
            record.access_analyzers = [
                {
                    "name": a.get("name"),
                    "type": a.get("type"),
                    "status": a.get("status"),
                }
                for a in analyzers
            ]
        except ClientError as e:
            logger.error(f"Failed to collect Access Analyzer status in {region}: {e}")

        return record

    def collect_lambda_exposure(self, region: str) -> List[LambdaExposure]:
        """
        Collect function URL configurations and resource policies for every
        Lambda function in a region, to support public exposure analysis.
        """
        records = []
        lambda_client = self.session.client("lambda", region_name=region)

        try:
            paginator = lambda_client.get_paginator("list_functions")
            for page in paginator.paginate():
                for function in page["Functions"]:
                    name = function["FunctionName"]
                    record = LambdaExposure(
                        scan_id=self.scan_id,
                        region=region,
                        function_name=name,
                        function_arn=function["FunctionArn"],
                    )

                    try:
                        url_configs = lambda_client.list_function_url_configs(
                            FunctionName=name
                        ).get("FunctionUrlConfigs", [])
                        if url_configs:
                            record.url_config = url_configs[0]
                            record.url_auth_type = url_configs[0].get("AuthType")
                    except ClientError as e:
                        logger.error(f"Failed to collect URL config for {name}: {e}")

                    try:
                        policy = lambda_client.get_policy(FunctionName=name)
                        record.resource_policy = json.loads(policy["Policy"])
                    except ClientError as e:
                        if e.response["Error"]["Code"] != "ResourceNotFoundException":
                            logger.error(f"Failed to collect policy for {name}: {e}")

                    records.append(record)

            logger.debug(
                f"Collected Lambda exposure for {len(records)} functions in {region}"
            )
        except ClientError as e:
            logger.error(f"Failed to collect Lambda exposure from {region}: {e}")

        return records

    def collect_s3_public_access(self) -> List[S3PublicAccess]:
        """
        Collect the Public Access Block and policy status for every bucket.
        Missing configuration is recorded explicitly, never omitted.
        """
        records = []
        s3_client = self.session.client("s3")

        try:
            buckets = s3_client.list_buckets().get("Buckets", [])
        except ClientError as e:
            logger.error(f"Failed to list buckets for public access collection: {e}")
            return records

        for bucket in buckets:
            name = bucket["Name"]
            record = S3PublicAccess(scan_id=self.scan_id, bucket_name=name)

            try:
                pab = s3_client.get_public_access_block(Bucket=name)
                record.public_access_block = pab["PublicAccessBlockConfiguration"]
            except ClientError as e:
                if (
                    e.response["Error"]["Code"]
                    != "NoSuchPublicAccessBlockConfiguration"
                ):
                    logger.error(
                        f"Failed to collect Public Access Block for {name}: {e}"
                    )

            try:
                status = s3_client.get_bucket_policy_status(Bucket=name)
                record.policy_is_public = status["PolicyStatus"]["IsPublic"]
            except ClientError as e:
                if e.response["Error"]["Code"] != "NoSuchBucketPolicy":
                    logger.error(f"Failed to collect policy status for {name}: {e}")

            records.append(record)

        logger.debug(f"Collected S3 public access for {len(records)} buckets")
        return records
