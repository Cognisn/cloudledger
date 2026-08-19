"""
Database operations for CloudLedger.

This module provides functions for inserting and querying scan data.
Uses Australian English in all documentation and comments.
"""

import json
from datetime import datetime
from typing import List, Dict, Any, Optional
import logging

import sqlalchemy as sa

from ..utils.timeutils import to_utc_iso
from .engine import make_engine
from .tables import (
    t_scan_metadata,
    t_ec2_instances,
    t_vpcs,
    t_subnets,
    t_security_groups,
    t_s3_buckets,
    t_iam_users,
    t_iam_roles,
    t_prowler_findings,
    t_load_balancers,
    t_nat_gateways,
    t_internet_gateways,
    t_route_tables,
    t_auto_scaling_groups,
    t_network_interfaces,
    t_workspaces,
    t_lambda_functions,
    t_vpc_flow_logs,
    t_cost_data,
    t_route53_hosted_zones,
    t_route53_record_sets,
    t_ebs_volumes,
    t_ebs_snapshots,
    t_rds_instances,
    t_iam_policies,
    t_kms_keys,
    t_elastic_ips,
    t_ecs_clusters,
    t_ecs_services,
    t_ecs_task_definitions,
    t_eks_clusters,
    t_eks_node_groups,
    t_ecr_repositories,
    t_ecr_images,
    t_api_gateway_rest_apis,
    t_api_gateway_http_apis,
    t_api_gateway_stages,
    t_cloudfront_distributions,
    t_organizations,
    t_organizational_units,
    t_organization_accounts,
    t_sso_permission_sets,
    t_sso_assignments,
    t_cloudtrail_trails,
    t_cloudwatch_log_groups,
    t_config_recorders,
    t_config_rules,
    t_bedrock_models,
    t_bedrock_guardrails,
    t_bedrock_knowledge_bases,
    t_bedrock_agents,
    t_directory_services,
    t_transit_gateways,
    t_vpn_connections,
    t_direct_connect_connections,
    t_elasticache_clusters,
    t_opensearch_domains,
    t_msk_clusters,
    t_dynamodb_tables,
    t_account_security_posture,
    t_iam_credential_report,
    t_region_security_services,
    t_lambda_exposure,
    t_s3_public_access,
)
from .models import (
    ScanMetadata,
    EC2Instance,
    VPC,
    Subnet,
    SecurityGroup,
    S3Bucket,
    IAMUser,
    IAMRole,
    Route53HostedZone,
    Route53RecordSet,
    CostData,
    ProwlerFinding,
    LoadBalancer,
    NATGateway,
    InternetGateway,
    RouteTable,
    AutoScalingGroup,
    NetworkInterface,
    WorkSpace,
    LambdaFunction,
    VPCFlowLog,
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
    AccountSecurityPosture,
    IAMCredentialReportEntry,
    RegionSecurityServices,
    LambdaExposure,
    S3PublicAccess,
)

logger = logging.getLogger(__name__)


def json_serial(obj):
    """
    JSON serializer for objects not serializable by default json code.

    Args:
        obj: Object to serialize

    Returns:
        Serializable representation of the object
    """
    if isinstance(obj, datetime):
        return to_utc_iso(obj)
    raise TypeError(f"Type {type(obj)} not serializable")


class DatabaseOperations:
    """Handles all database operations for CloudLedger."""

    def __init__(self, db_path: str):
        """Initialise operations for a database path or URL."""
        self.db_path = db_path
        self._engine = make_engine(db_path)

    @property
    def engine(self):
        """The SQLAlchemy engine backing this operations instance."""
        return self._engine

    def insert_scan_metadata(self, metadata: ScanMetadata) -> None:
        """
        Insert scan metadata record.

        Args:
            metadata: Scan metadata to insert
        """
        row = {
            "scan_id": metadata.scan_id,
            "account_name": metadata.account_name,
            "account_number": metadata.account_number,
            "scan_timestamp": to_utc_iso(metadata.scan_timestamp),
            "prowler_level": metadata.prowler_level,
            "regions_scanned": json.dumps(
                metadata.regions_scanned, default=json_serial
            ),
            "scan_status": metadata.scan_status,
            "error_message": metadata.error_message,
            "scan_duration_seconds": metadata.scan_duration_seconds,
            "org_member": (
                None if metadata.org_member is None else (1 if metadata.org_member else 0)
            ),
            "is_management_account": (
                None
                if metadata.is_management_account is None
                else (1 if metadata.is_management_account else 0)
            ),
            "management_account_id": metadata.management_account_id,
            "management_account_name": metadata.management_account_name,
        }
        with self._engine.begin() as conn:
            conn.execute(t_scan_metadata.insert(), row)
        logger.debug(f"Inserted scan metadata: {metadata.scan_id}")

    def update_scan_status(
        self,
        scan_id: str,
        status: str,
        error_message: Optional[str] = None,
        duration: Optional[float] = None,
    ) -> None:
        """
        Update scan status and completion information.

        Args:
            scan_id: Scan identifier
            status: New status (completed, failed, etc.)
            error_message: Optional error message
            duration: Optional scan duration in seconds
        """
        stmt = (
            sa.update(t_scan_metadata)
            .where(t_scan_metadata.c.scan_id == scan_id)
            .values(
                scan_status=status,
                error_message=error_message,
                scan_duration_seconds=duration,
            )
        )
        with self._engine.begin() as conn:
            conn.execute(stmt)
        logger.debug(f"Updated scan status for {scan_id}: {status}")

    def insert_ec2_instances(self, instances: List[EC2Instance]) -> None:
        """
        Insert EC2 instance records.

        Args:
            instances: List of EC2 instances to insert
        """
        if not instances:
            return
        rows = [
            {
                "scan_id": instance.scan_id,
                "instance_id": instance.instance_id,
                "region": instance.region,
                "instance_type": instance.instance_type,
                "state": instance.state,
                "public_ip": instance.public_ip,
                "private_ip": instance.private_ip,
                "vpc_id": instance.vpc_id,
                "subnet_id": instance.subnet_id,
                "availability_zone": instance.availability_zone,
                "launch_time": instance.launch_time.isoformat(),
                "platform": instance.platform,
                "security_groups": json.dumps(
                    instance.security_groups, default=json_serial
                ),
                "tags": json.dumps(instance.tags, default=json_serial),
                "iam_instance_profile": instance.iam_instance_profile,
                "monitoring_state": instance.monitoring_state,
                "raw_data": json.dumps(instance.raw_data, default=json_serial),
            }
            for instance in instances
        ]
        with self._engine.begin() as conn:
            conn.execute(t_ec2_instances.insert(), rows)
        logger.debug(f"Inserted {len(instances)} EC2 instances")

    def insert_vpcs(self, vpcs: List[VPC]) -> None:
        """Insert VPC records."""
        if not vpcs:
            return
        rows = [
            {
                "scan_id": vpc.scan_id,
                "vpc_id": vpc.vpc_id,
                "region": vpc.region,
                "cidr_block": vpc.cidr_block,
                "state": vpc.state,
                "is_default": 1 if vpc.is_default else 0,
                "dhcp_options_id": vpc.dhcp_options_id,
                "instance_tenancy": vpc.instance_tenancy,
                "tags": json.dumps(vpc.tags, default=json_serial),
                "raw_data": json.dumps(vpc.raw_data, default=json_serial),
            }
            for vpc in vpcs
        ]
        with self._engine.begin() as conn:
            conn.execute(t_vpcs.insert(), rows)
        logger.debug(f"Inserted {len(vpcs)} VPCs")

    def insert_subnets(self, subnets: List[Subnet]) -> None:
        """Insert subnet records."""
        if not subnets:
            return
        rows = [
            {
                "scan_id": subnet.scan_id,
                "subnet_id": subnet.subnet_id,
                "vpc_id": subnet.vpc_id,
                "region": subnet.region,
                "cidr_block": subnet.cidr_block,
                "availability_zone": subnet.availability_zone,
                "available_ip_count": subnet.available_ip_count,
                "map_public_ip": 1 if subnet.map_public_ip else 0,
                "state": subnet.state,
                "tags": json.dumps(subnet.tags, default=json_serial),
                "raw_data": json.dumps(subnet.raw_data, default=json_serial),
            }
            for subnet in subnets
        ]
        with self._engine.begin() as conn:
            conn.execute(t_subnets.insert(), rows)
        logger.debug(f"Inserted {len(subnets)} subnets")

    def insert_security_groups(self, security_groups: List[SecurityGroup]) -> None:
        """Insert security group records."""
        if not security_groups:
            return
        rows = [
            {
                "scan_id": sg.scan_id,
                "group_id": sg.group_id,
                "group_name": sg.group_name,
                "vpc_id": sg.vpc_id,
                "region": sg.region,
                "description": sg.description,
                "ingress_rules": json.dumps(sg.ingress_rules, default=json_serial),
                "egress_rules": json.dumps(sg.egress_rules, default=json_serial),
                "tags": json.dumps(sg.tags, default=json_serial),
                "raw_data": json.dumps(sg.raw_data, default=json_serial),
            }
            for sg in security_groups
        ]
        with self._engine.begin() as conn:
            conn.execute(t_security_groups.insert(), rows)
        logger.debug(f"Inserted {len(security_groups)} security groups")

    def insert_s3_buckets(self, buckets: List[S3Bucket]) -> None:
        """Insert S3 bucket records."""
        if not buckets:
            return
        rows = [
            {
                "scan_id": bucket.scan_id,
                "bucket_name": bucket.bucket_name,
                "creation_date": bucket.creation_date.isoformat(),
                "region": bucket.region,
                "versioning_status": bucket.versioning_status,
                "public_access_block": json.dumps(
                    bucket.public_access_block, default=json_serial
                )
                if bucket.public_access_block
                else None,
                "encryption_config": json.dumps(
                    bucket.encryption_config, default=json_serial
                )
                if bucket.encryption_config
                else None,
                "lifecycle_rules": json.dumps(
                    bucket.lifecycle_rules, default=json_serial
                ),
                "logging_enabled": 1 if bucket.logging_enabled else 0,
                "size_bytes": bucket.size_bytes,
                "object_count": bucket.object_count,
                "tags": json.dumps(bucket.tags, default=json_serial),
                "raw_data": json.dumps(bucket.raw_data, default=json_serial),
            }
            for bucket in buckets
        ]
        with self._engine.begin() as conn:
            conn.execute(t_s3_buckets.insert(), rows)
        logger.debug(f"Inserted {len(buckets)} S3 buckets")

    def insert_iam_users(self, users: List[IAMUser]) -> None:
        """Insert IAM user records."""
        if not users:
            return
        rows = [
            {
                "scan_id": user.scan_id,
                "user_name": user.user_name,
                "user_id": user.user_id,
                "arn": user.arn,
                "create_date": user.create_date.isoformat(),
                "password_last_used": user.password_last_used.isoformat()
                if user.password_last_used
                else None,
                "mfa_enabled": 1 if user.mfa_enabled else 0,
                "access_keys": json.dumps(user.access_keys, default=json_serial),
                "attached_policies": json.dumps(
                    user.attached_policies, default=json_serial
                ),
                "groups": json.dumps(user.groups, default=json_serial),
                "tags": json.dumps(user.tags, default=json_serial),
                "raw_data": json.dumps(user.raw_data, default=json_serial),
            }
            for user in users
        ]
        with self._engine.begin() as conn:
            conn.execute(t_iam_users.insert(), rows)
        logger.debug(f"Inserted {len(users)} IAM users")

    def insert_iam_roles(self, roles: List[IAMRole]) -> None:
        """Insert IAM role records."""
        if not roles:
            return
        rows = [
            {
                "scan_id": role.scan_id,
                "role_name": role.role_name,
                "role_id": role.role_id,
                "arn": role.arn,
                "create_date": role.create_date.isoformat(),
                "assume_role_policy": json.dumps(
                    role.assume_role_policy, default=json_serial
                ),
                "attached_policies": json.dumps(
                    role.attached_policies, default=json_serial
                ),
                "max_session_duration": role.max_session_duration,
                "tags": json.dumps(role.tags, default=json_serial),
                "raw_data": json.dumps(role.raw_data, default=json_serial),
            }
            for role in roles
        ]
        with self._engine.begin() as conn:
            conn.execute(t_iam_roles.insert(), rows)
        logger.debug(f"Inserted {len(roles)} IAM roles")

    def insert_prowler_findings(self, findings: List[ProwlerFinding]) -> None:
        """Insert Prowler security findings."""
        if not findings:
            return
        rows = [
            {
                "scan_id": finding.scan_id,
                "check_id": finding.check_id,
                "check_title": finding.check_title,
                "severity": finding.severity,
                "status": finding.status,
                "region": finding.region,
                "resource_id": finding.resource_id,
                "resource_arn": finding.resource_arn,
                "resource_tags": json.dumps(finding.resource_tags, default=json_serial),
                "status_extended": finding.status_extended,
                "service_name": finding.service_name,
                "check_type": finding.check_type,
                "risk": finding.risk,
                "remediation": finding.remediation,
                "compliance_frameworks": json.dumps(
                    finding.compliance_frameworks, default=json_serial
                ),
                "raw_data": json.dumps(finding.raw_data, default=json_serial),
            }
            for finding in findings
        ]
        with self._engine.begin() as conn:
            conn.execute(t_prowler_findings.insert(), rows)
        logger.debug(f"Inserted {len(findings)} Prowler findings")

    def insert_load_balancers(self, load_balancers: List[LoadBalancer]) -> None:
        """Insert load balancer records."""
        if not load_balancers:
            return
        rows = [
            {
                "scan_id": lb.scan_id,
                "load_balancer_name": lb.load_balancer_name,
                "load_balancer_arn": lb.load_balancer_arn,
                "load_balancer_type": lb.load_balancer_type,
                "region": lb.region,
                "vpc_id": lb.vpc_id,
                "scheme": lb.scheme,
                "state": lb.state,
                "dns_name": lb.dns_name,
                "availability_zones": json.dumps(
                    lb.availability_zones, default=json_serial
                ),
                "security_groups": json.dumps(lb.security_groups, default=json_serial),
                "subnets": json.dumps(lb.subnets, default=json_serial),
                "created_time": lb.created_time.isoformat()
                if lb.created_time
                else None,
                "listeners": json.dumps(lb.listeners, default=json_serial),
                "target_groups": json.dumps(lb.target_groups, default=json_serial),
                "tags": json.dumps(lb.tags, default=json_serial),
                "raw_data": json.dumps(lb.raw_data, default=json_serial),
            }
            for lb in load_balancers
        ]
        with self._engine.begin() as conn:
            conn.execute(t_load_balancers.insert(), rows)
        logger.debug(f"Inserted {len(load_balancers)} load balancers")

    def insert_nat_gateways(self, nat_gateways: List[NATGateway]) -> None:
        """Insert NAT gateway records."""
        if not nat_gateways:
            return
        rows = [
            {
                "scan_id": nat.scan_id,
                "nat_gateway_id": nat.nat_gateway_id,
                "region": nat.region,
                "vpc_id": nat.vpc_id,
                "subnet_id": nat.subnet_id,
                "state": nat.state,
                "connectivity_type": nat.connectivity_type,
                "public_ip": nat.public_ip,
                "private_ip": nat.private_ip,
                "created_time": nat.created_time.isoformat()
                if nat.created_time
                else None,
                "nat_gateway_addresses": json.dumps(
                    nat.nat_gateway_addresses, default=json_serial
                ),
                "tags": json.dumps(nat.tags, default=json_serial),
                "raw_data": json.dumps(nat.raw_data, default=json_serial),
            }
            for nat in nat_gateways
        ]
        with self._engine.begin() as conn:
            conn.execute(t_nat_gateways.insert(), rows)
        logger.debug(f"Inserted {len(nat_gateways)} NAT gateways")

    def insert_internet_gateways(
        self, internet_gateways: List[InternetGateway]
    ) -> None:
        """Insert internet gateway records."""
        if not internet_gateways:
            return
        rows = [
            {
                "scan_id": igw.scan_id,
                "internet_gateway_id": igw.internet_gateway_id,
                "region": igw.region,
                "vpc_attachments": json.dumps(igw.vpc_attachments, default=json_serial),
                "tags": json.dumps(igw.tags, default=json_serial),
                "raw_data": json.dumps(igw.raw_data, default=json_serial),
            }
            for igw in internet_gateways
        ]
        with self._engine.begin() as conn:
            conn.execute(t_internet_gateways.insert(), rows)
        logger.debug(f"Inserted {len(internet_gateways)} internet gateways")

    def insert_route_tables(self, route_tables: List[RouteTable]) -> None:
        """Insert route table records."""
        if not route_tables:
            return
        rows = [
            {
                "scan_id": rt.scan_id,
                "route_table_id": rt.route_table_id,
                "region": rt.region,
                "vpc_id": rt.vpc_id,
                "is_main": 1 if rt.is_main else 0,
                "routes": json.dumps(rt.routes, default=json_serial),
                "subnet_associations": json.dumps(
                    rt.subnet_associations, default=json_serial
                ),
                "gateway_associations": json.dumps(
                    rt.gateway_associations, default=json_serial
                ),
                "tags": json.dumps(rt.tags, default=json_serial),
                "raw_data": json.dumps(rt.raw_data, default=json_serial),
            }
            for rt in route_tables
        ]
        with self._engine.begin() as conn:
            conn.execute(t_route_tables.insert(), rows)
        logger.debug(f"Inserted {len(route_tables)} route tables")

    def insert_auto_scaling_groups(
        self, auto_scaling_groups: List[AutoScalingGroup]
    ) -> None:
        """Insert Auto Scaling group records."""
        if not auto_scaling_groups:
            return
        rows = [
            {
                "scan_id": asg.scan_id,
                "auto_scaling_group_name": asg.auto_scaling_group_name,
                "auto_scaling_group_arn": asg.auto_scaling_group_arn,
                "region": asg.region,
                "launch_configuration_name": asg.launch_configuration_name,
                "launch_template": json.dumps(asg.launch_template, default=json_serial)
                if asg.launch_template
                else None,
                "min_size": asg.min_size,
                "max_size": asg.max_size,
                "desired_capacity": asg.desired_capacity,
                "default_cooldown": asg.default_cooldown,
                "availability_zones": json.dumps(
                    asg.availability_zones, default=json_serial
                ),
                "load_balancer_names": json.dumps(
                    asg.load_balancer_names, default=json_serial
                ),
                "target_group_arns": json.dumps(
                    asg.target_group_arns, default=json_serial
                ),
                "health_check_type": asg.health_check_type,
                "health_check_grace_period": asg.health_check_grace_period,
                "vpc_zone_identifier": asg.vpc_zone_identifier,
                "instances": json.dumps(asg.instances, default=json_serial),
                "created_time": asg.created_time.isoformat(),
                "tags": json.dumps(asg.tags, default=json_serial),
                "raw_data": json.dumps(asg.raw_data, default=json_serial),
            }
            for asg in auto_scaling_groups
        ]
        with self._engine.begin() as conn:
            conn.execute(t_auto_scaling_groups.insert(), rows)
        logger.debug(f"Inserted {len(auto_scaling_groups)} Auto Scaling groups")

    def insert_network_interfaces(
        self, network_interfaces: List[NetworkInterface]
    ) -> None:
        """Insert network interface records."""
        if not network_interfaces:
            return
        rows = [
            {
                "scan_id": eni.scan_id,
                "network_interface_id": eni.network_interface_id,
                "region": eni.region,
                "interface_type": eni.interface_type,
                "status": eni.status,
                "vpc_id": eni.vpc_id,
                "subnet_id": eni.subnet_id,
                "availability_zone": eni.availability_zone,
                "description": eni.description,
                "private_ip_address": eni.private_ip_address,
                "private_ip_addresses": json.dumps(
                    eni.private_ip_addresses, default=json_serial
                ),
                "public_ip": eni.public_ip,
                "mac_address": eni.mac_address,
                "source_dest_check": 1 if eni.source_dest_check else 0,
                "security_groups": json.dumps(eni.security_groups, default=json_serial),
                "attachment": json.dumps(eni.attachment, default=json_serial)
                if eni.attachment
                else None,
                "tags": json.dumps(eni.tags, default=json_serial),
                "raw_data": json.dumps(eni.raw_data, default=json_serial),
            }
            for eni in network_interfaces
        ]
        with self._engine.begin() as conn:
            conn.execute(t_network_interfaces.insert(), rows)
        logger.debug(f"Inserted {len(network_interfaces)} network interfaces")

    def insert_workspaces(self, workspaces: List[WorkSpace]) -> None:
        """Insert WorkSpaces records."""
        if not workspaces:
            return
        rows = [
            {
                "scan_id": workspace.scan_id,
                "workspace_id": workspace.workspace_id,
                "region": workspace.region,
                "directory_id": workspace.directory_id,
                "user_name": workspace.user_name,
                "bundle_id": workspace.bundle_id,
                "subnet_id": workspace.subnet_id,
                "vpc_id": workspace.vpc_id,
                "ip_address": workspace.ip_address,
                "state": workspace.state,
                "compute_type": workspace.compute_type,
                "volume_encryption_enabled": 1
                if workspace.volume_encryption_enabled
                else 0,
                "user_volume_size_gb": workspace.user_volume_size_gb,
                "root_volume_size_gb": workspace.root_volume_size_gb,
                "running_mode": workspace.running_mode,
                "tags": json.dumps(workspace.tags, default=json_serial),
                "raw_data": json.dumps(workspace.raw_data, default=json_serial),
            }
            for workspace in workspaces
        ]
        with self._engine.begin() as conn:
            conn.execute(t_workspaces.insert(), rows)
        logger.debug(f"Inserted {len(workspaces)} WorkSpaces")

    def insert_lambda_functions(self, lambda_functions: List[LambdaFunction]) -> None:
        """Insert Lambda function records."""
        if not lambda_functions:
            return
        rows = [
            {
                "scan_id": func.scan_id,
                "function_name": func.function_name,
                "function_arn": func.function_arn,
                "region": func.region,
                "runtime": func.runtime,
                "handler": func.handler,
                "code_size": func.code_size,
                "memory_size": func.memory_size,
                "timeout": func.timeout,
                "last_modified": func.last_modified.isoformat(),
                "role_arn": func.role_arn,
                "vpc_config": json.dumps(func.vpc_config, default=json_serial)
                if func.vpc_config
                else None,
                "environment_variables": json.dumps(
                    func.environment_variables, default=json_serial
                ),
                "layers": json.dumps(func.layers, default=json_serial),
                "state": func.state,
                "architectures": json.dumps(func.architectures, default=json_serial),
                "triggers": json.dumps(func.triggers, default=json_serial),
                "tags": json.dumps(func.tags, default=json_serial),
                "raw_data": json.dumps(func.raw_data, default=json_serial),
            }
            for func in lambda_functions
        ]
        with self._engine.begin() as conn:
            conn.execute(t_lambda_functions.insert(), rows)
        logger.debug(f"Inserted {len(lambda_functions)} Lambda functions")

    def insert_vpc_flow_logs(self, vpc_flow_logs: List[VPCFlowLog]) -> None:
        """Insert VPC Flow Log records."""
        if not vpc_flow_logs:
            return
        rows = [
            {
                "scan_id": flow_log.scan_id,
                "flow_log_id": flow_log.flow_log_id,
                "region": flow_log.region,
                "resource_id": flow_log.resource_id,
                "resource_type": flow_log.resource_type,
                "traffic_type": flow_log.traffic_type,
                "log_destination_type": flow_log.log_destination_type,
                "log_destination": flow_log.log_destination,
                "log_format": flow_log.log_format,
                "flow_log_status": flow_log.flow_log_status,
                "created_time": flow_log.created_time.isoformat()
                if flow_log.created_time
                else None,
                "tags": json.dumps(flow_log.tags, default=json_serial),
                "raw_data": json.dumps(flow_log.raw_data, default=json_serial),
            }
            for flow_log in vpc_flow_logs
        ]
        with self._engine.begin() as conn:
            conn.execute(t_vpc_flow_logs.insert(), rows)
        logger.debug(f"Inserted {len(vpc_flow_logs)} VPC Flow Logs")

    def insert_cost_data(self, cost_records: List[CostData]) -> None:
        """Insert cost and billing data records."""
        if not cost_records:
            return
        rows = [
            {
                "scan_id": cost.scan_id,
                "account_number": cost.account_number,
                "time_period_start": to_utc_iso(cost.time_period_start),
                "time_period_end": to_utc_iso(cost.time_period_end),
                "service_name": cost.service_name,
                "amount": cost.amount,
                "currency": cost.currency,
                "unit": cost.unit,
                "raw_data": json.dumps(cost.raw_data, default=json_serial),
            }
            for cost in cost_records
        ]
        with self._engine.begin() as conn:
            conn.execute(t_cost_data.insert(), rows)
        logger.debug(f"Inserted {len(cost_records)} cost data records")

    def insert_route53_hosted_zones(
        self, hosted_zones: List[Route53HostedZone]
    ) -> None:
        """Insert Route53 hosted zone records."""
        if not hosted_zones:
            return
        rows = [
            {
                "scan_id": zone.scan_id,
                "hosted_zone_id": zone.hosted_zone_id,
                "name": zone.name,
                "is_private": 1 if zone.is_private else 0,
                "resource_record_set_count": zone.resource_record_set_count,
                "vpc_associations": json.dumps(
                    zone.vpc_associations, default=json_serial
                ),
                "tags": json.dumps(zone.tags, default=json_serial),
                "raw_data": json.dumps(zone.raw_data, default=json_serial),
            }
            for zone in hosted_zones
        ]
        with self._engine.begin() as conn:
            conn.execute(t_route53_hosted_zones.insert(), rows)
        logger.debug(f"Inserted {len(hosted_zones)} Route53 hosted zones")

    def insert_route53_record_sets(self, record_sets: List[Route53RecordSet]) -> None:
        """Insert Route53 DNS record set records."""
        if not record_sets:
            return
        rows = [
            {
                "scan_id": record.scan_id,
                "hosted_zone_id": record.hosted_zone_id,
                "name": record.name,
                "record_type": record.record_type,
                "ttl": record.ttl,
                "resource_records": json.dumps(
                    record.resource_records, default=json_serial
                ),
                "alias_target": json.dumps(record.alias_target, default=json_serial)
                if record.alias_target
                else None,
                "raw_data": json.dumps(record.raw_data, default=json_serial),
            }
            for record in record_sets
        ]
        with self._engine.begin() as conn:
            conn.execute(t_route53_record_sets.insert(), rows)
        logger.debug(f"Inserted {len(record_sets)} Route53 record sets")

    def insert_ebs_volumes(self, volumes: List[EBSVolume]) -> None:
        """Insert EBS volume records."""
        if not volumes:
            return
        rows = [
            {
                "scan_id": volume.scan_id,
                "volume_id": volume.volume_id,
                "region": volume.region,
                "size": volume.size,
                "volume_type": volume.volume_type,
                "iops": volume.iops,
                "throughput": volume.throughput,
                "encrypted": 1 if volume.encrypted else 0,
                "kms_key_id": volume.kms_key_id,
                "state": volume.state,
                "create_time": volume.create_time.isoformat(),
                "availability_zone": volume.availability_zone,
                "snapshot_id": volume.snapshot_id,
                "attached_instance_id": volume.attached_instance_id,
                "device_name": volume.device_name,
                "attachment_state": volume.attachment_state,
                "multi_attach_enabled": 1 if volume.multi_attach_enabled else 0,
                "tags": json.dumps(volume.tags, default=json_serial),
                "raw_data": json.dumps(volume.raw_data, default=json_serial),
            }
            for volume in volumes
        ]
        with self._engine.begin() as conn:
            conn.execute(t_ebs_volumes.insert(), rows)
        logger.debug(f"Inserted {len(volumes)} EBS volumes")

    def insert_ebs_snapshots(self, snapshots: List[EBSSnapshot]) -> None:
        """Insert EBS snapshot records."""
        if not snapshots:
            return
        rows = [
            {
                "scan_id": snapshot.scan_id,
                "snapshot_id": snapshot.snapshot_id,
                "region": snapshot.region,
                "volume_id": snapshot.volume_id,
                "volume_size": snapshot.volume_size,
                "encrypted": 1 if snapshot.encrypted else 0,
                "kms_key_id": snapshot.kms_key_id,
                "state": snapshot.state,
                "start_time": snapshot.start_time.isoformat(),
                "progress": snapshot.progress,
                "owner_id": snapshot.owner_id,
                "description": snapshot.description,
                "tags": json.dumps(snapshot.tags, default=json_serial),
                "raw_data": json.dumps(snapshot.raw_data, default=json_serial),
            }
            for snapshot in snapshots
        ]
        with self._engine.begin() as conn:
            conn.execute(t_ebs_snapshots.insert(), rows)
        logger.debug(f"Inserted {len(snapshots)} EBS snapshots")

    def insert_rds_instances(self, rds_instances: List[RDSInstance]) -> None:
        """Insert RDS instance records."""
        if not rds_instances:
            return
        rows = [
            {
                "scan_id": instance.scan_id,
                "db_instance_identifier": instance.db_instance_identifier,
                "region": instance.region,
                "db_instance_arn": instance.db_instance_arn,
                "engine": instance.engine,
                "engine_version": instance.engine_version,
                "db_instance_class": instance.db_instance_class,
                "allocated_storage": instance.allocated_storage,
                "storage_type": instance.storage_type,
                "iops": instance.iops,
                "multi_az": 1 if instance.multi_az else 0,
                "availability_zone": instance.availability_zone,
                "secondary_availability_zone": instance.secondary_availability_zone,
                "publicly_accessible": 1 if instance.publicly_accessible else 0,
                "encrypted": 1 if instance.encrypted else 0,
                "kms_key_id": instance.kms_key_id,
                "vpc_id": instance.vpc_id,
                "subnet_group": instance.subnet_group,
                "vpc_security_groups": json.dumps(
                    instance.vpc_security_groups, default=json_serial
                ),
                "backup_retention_period": instance.backup_retention_period,
                "preferred_backup_window": instance.preferred_backup_window,
                "latest_restorable_time": instance.latest_restorable_time.isoformat()
                if instance.latest_restorable_time
                else None,
                "endpoint_address": instance.endpoint_address,
                "endpoint_port": instance.endpoint_port,
                "db_instance_status": instance.db_instance_status,
                "monitoring_interval": instance.monitoring_interval,
                "performance_insights_enabled": 1
                if instance.performance_insights_enabled
                else 0,
                "auto_minor_version_upgrade": 1
                if instance.auto_minor_version_upgrade
                else 0,
                "deletion_protection": 1 if instance.deletion_protection else 0,
                "tags": json.dumps(instance.tags, default=json_serial),
                "raw_data": json.dumps(instance.raw_data, default=json_serial),
            }
            for instance in rds_instances
        ]
        with self._engine.begin() as conn:
            conn.execute(t_rds_instances.insert(), rows)
        logger.debug(f"Inserted {len(rds_instances)} RDS instances")

    def insert_iam_policies(self, policies: List[IAMPolicy]) -> None:
        """Insert IAM policy records."""
        if not policies:
            return
        rows = [
            {
                "scan_id": policy.scan_id,
                "policy_arn": policy.policy_arn,
                "policy_name": policy.policy_name,
                "policy_id": policy.policy_id,
                "path": policy.path,
                "default_version_id": policy.default_version_id,
                "attachment_count": policy.attachment_count,
                "permissions_boundary_usage_count": policy.permissions_boundary_usage_count,
                "is_attachable": 1 if policy.is_attachable else 0,
                "description": policy.description,
                "create_date": policy.create_date.isoformat(),
                "update_date": policy.update_date.isoformat(),
                "policy_document": json.dumps(
                    policy.policy_document, default=json_serial
                ),
                "attached_users": json.dumps(
                    policy.attached_users, default=json_serial
                ),
                "attached_roles": json.dumps(
                    policy.attached_roles, default=json_serial
                ),
                "attached_groups": json.dumps(
                    policy.attached_groups, default=json_serial
                ),
                "tags": json.dumps(policy.tags, default=json_serial),
                "raw_data": json.dumps(policy.raw_data, default=json_serial),
            }
            for policy in policies
        ]
        with self._engine.begin() as conn:
            conn.execute(t_iam_policies.insert(), rows)
        logger.debug(f"Inserted {len(policies)} IAM policies")

    def insert_kms_keys(self, kms_keys: List[KMSKey]) -> None:
        """Insert KMS key records."""
        if not kms_keys:
            return
        rows = [
            {
                "scan_id": key.scan_id,
                "key_id": key.key_id,
                "key_arn": key.key_arn,
                "region": key.region,
                "aws_account_id": key.aws_account_id,
                "key_state": key.key_state,
                "creation_date": key.creation_date.isoformat(),
                "key_manager": key.key_manager,
                "key_usage": key.key_usage,
                "key_spec": key.key_spec,
                "description": key.description,
                "enabled": 1 if key.enabled else 0,
                "deletion_date": key.deletion_date.isoformat()
                if key.deletion_date
                else None,
                "rotation_enabled": 1 if key.rotation_enabled else 0,
                "key_policy": json.dumps(key.key_policy, default=json_serial),
                "aliases": json.dumps(key.aliases, default=json_serial),
                "tags": json.dumps(key.tags, default=json_serial),
                "raw_data": json.dumps(key.raw_data, default=json_serial),
            }
            for key in kms_keys
        ]
        with self._engine.begin() as conn:
            conn.execute(t_kms_keys.insert(), rows)
        logger.debug(f"Inserted {len(kms_keys)} KMS keys")

    def insert_elastic_ips(self, elastic_ips: List[ElasticIP]) -> None:
        """Insert Elastic IP records."""
        if not elastic_ips:
            return
        rows = [
            {
                "scan_id": eip.scan_id,
                "allocation_id": eip.allocation_id,
                "region": eip.region,
                "public_ip": eip.public_ip,
                "domain": eip.domain,
                "instance_id": eip.instance_id,
                "network_interface_id": eip.network_interface_id,
                "network_interface_owner_id": eip.network_interface_owner_id,
                "private_ip_address": eip.private_ip_address,
                "association_id": eip.association_id,
                "is_associated": 1 if eip.is_associated else 0,
                "tags": json.dumps(eip.tags, default=json_serial),
                "raw_data": json.dumps(eip.raw_data, default=json_serial),
            }
            for eip in elastic_ips
        ]
        with self._engine.begin() as conn:
            conn.execute(t_elastic_ips.insert(), rows)
        logger.debug(f"Inserted {len(elastic_ips)} Elastic IPs")

    # Phase 2: Containers & Application Services Insert Operations

    def insert_ecs_clusters(self, ecs_clusters: List[ECSCluster]) -> None:
        """Insert ECS cluster records."""
        if not ecs_clusters:
            return
        rows = [
            {
                "scan_id": cluster.scan_id,
                "cluster_arn": cluster.cluster_arn,
                "cluster_name": cluster.cluster_name,
                "region": cluster.region,
                "status": cluster.status,
                "registered_container_instances_count": cluster.registered_container_instances_count,
                "running_tasks_count": cluster.running_tasks_count,
                "pending_tasks_count": cluster.pending_tasks_count,
                "active_services_count": cluster.active_services_count,
                "capacity_providers": json.dumps(
                    cluster.capacity_providers, default=json_serial
                ),
                "default_capacity_provider_strategy": json.dumps(
                    cluster.default_capacity_provider_strategy,
                    default=json_serial,
                ),
                "settings": json.dumps(cluster.settings, default=json_serial),
                "statistics": json.dumps(cluster.statistics, default=json_serial),
                "tags": json.dumps(cluster.tags, default=json_serial),
                "raw_data": json.dumps(cluster.raw_data, default=json_serial),
            }
            for cluster in ecs_clusters
        ]
        with self._engine.begin() as conn:
            conn.execute(t_ecs_clusters.insert(), rows)
        logger.debug(f"Inserted {len(ecs_clusters)} ECS clusters")

    def insert_ecs_services(self, ecs_services: List[ECSService]) -> None:
        """Insert ECS service records."""
        if not ecs_services:
            return
        rows = [
            {
                "scan_id": service.scan_id,
                "service_arn": service.service_arn,
                "service_name": service.service_name,
                "cluster_arn": service.cluster_arn,
                "region": service.region,
                "status": service.status,
                "task_definition": service.task_definition,
                "desired_count": service.desired_count,
                "running_count": service.running_count,
                "pending_count": service.pending_count,
                "launch_type": service.launch_type,
                "platform_version": service.platform_version,
                "platform_family": service.platform_family,
                "capacity_provider_strategy": json.dumps(
                    service.capacity_provider_strategy, default=json_serial
                ),
                "network_configuration": json.dumps(
                    service.network_configuration, default=json_serial
                ),
                "load_balancers": json.dumps(
                    service.load_balancers, default=json_serial
                ),
                "service_registries": json.dumps(
                    service.service_registries, default=json_serial
                ),
                "deployment_configuration": json.dumps(
                    service.deployment_configuration, default=json_serial
                ),
                "deployments": json.dumps(service.deployments, default=json_serial),
                "health_check_grace_period_seconds": service.health_check_grace_period_seconds,
                "scheduling_strategy": service.scheduling_strategy,
                "created_at_svc": service.created_at.isoformat()
                if service.created_at
                else None,
                "tags": json.dumps(service.tags, default=json_serial),
                "raw_data": json.dumps(service.raw_data, default=json_serial),
            }
            for service in ecs_services
        ]
        with self._engine.begin() as conn:
            conn.execute(t_ecs_services.insert(), rows)
        logger.debug(f"Inserted {len(ecs_services)} ECS services")

    def insert_ecs_task_definitions(
        self, ecs_task_definitions: List[ECSTaskDefinition]
    ) -> None:
        """Insert ECS task definition records."""
        if not ecs_task_definitions:
            return
        rows = [
            {
                "scan_id": task_def.scan_id,
                "task_definition_arn": task_def.task_definition_arn,
                "family": task_def.family,
                "revision": task_def.revision,
                "region": task_def.region,
                "status": task_def.status,
                "requires_compatibilities": json.dumps(
                    task_def.requires_compatibilities, default=json_serial
                ),
                "network_mode": task_def.network_mode,
                "cpu": task_def.cpu,
                "memory": task_def.memory,
                "task_role_arn": task_def.task_role_arn,
                "execution_role_arn": task_def.execution_role_arn,
                "container_definitions": json.dumps(
                    task_def.container_definitions, default=json_serial
                ),
                "volumes": json.dumps(task_def.volumes, default=json_serial),
                "placement_constraints": json.dumps(
                    task_def.placement_constraints, default=json_serial
                ),
                "requires_attributes": json.dumps(
                    task_def.requires_attributes, default=json_serial
                ),
                "pid_mode": task_def.pid_mode,
                "ipc_mode": task_def.ipc_mode,
                "proxy_configuration": json.dumps(
                    task_def.proxy_configuration, default=json_serial
                )
                if task_def.proxy_configuration
                else None,
                "ephemeral_storage": json.dumps(
                    task_def.ephemeral_storage, default=json_serial
                )
                if task_def.ephemeral_storage
                else None,
                "runtime_platform": json.dumps(
                    task_def.runtime_platform, default=json_serial
                )
                if task_def.runtime_platform
                else None,
                "registered_at": task_def.registered_at.isoformat()
                if task_def.registered_at
                else None,
                "deregistered_at": task_def.deregistered_at.isoformat()
                if task_def.deregistered_at
                else None,
                "registered_by": task_def.registered_by,
                "tags": json.dumps(task_def.tags, default=json_serial),
                "raw_data": json.dumps(task_def.raw_data, default=json_serial),
            }
            for task_def in ecs_task_definitions
        ]
        with self._engine.begin() as conn:
            conn.execute(t_ecs_task_definitions.insert(), rows)
        logger.debug(f"Inserted {len(ecs_task_definitions)} ECS task definitions")

    def insert_eks_clusters(self, eks_clusters: List[EKSCluster]) -> None:
        """Insert EKS cluster records."""
        if not eks_clusters:
            return
        rows = [
            {
                "scan_id": cluster.scan_id,
                "cluster_name": cluster.cluster_name,
                "cluster_arn": cluster.cluster_arn,
                "region": cluster.region,
                "version": cluster.version,
                "endpoint": cluster.endpoint,
                "role_arn": cluster.role_arn,
                "status": cluster.status,
                "vpc_id": cluster.vpc_id,
                "subnet_ids": json.dumps(cluster.subnet_ids, default=json_serial),
                "security_group_ids": json.dumps(
                    cluster.security_group_ids, default=json_serial
                ),
                "cluster_security_group_id": cluster.cluster_security_group_id,
                "endpoint_public_access": 1 if cluster.endpoint_public_access else 0,
                "endpoint_private_access": 1 if cluster.endpoint_private_access else 0,
                "public_access_cidrs": json.dumps(
                    cluster.public_access_cidrs, default=json_serial
                ),
                "resources_vpc_config": json.dumps(
                    cluster.resources_vpc_config, default=json_serial
                ),
                "logging": json.dumps(cluster.logging, default=json_serial),
                "identity": json.dumps(cluster.identity, default=json_serial)
                if cluster.identity
                else None,
                "encryption_config": json.dumps(
                    cluster.encryption_config, default=json_serial
                ),
                "platform_version": cluster.platform_version,
                "created_at_eks": cluster.created_at.isoformat()
                if cluster.created_at
                else None,
                "tags": json.dumps(cluster.tags, default=json_serial),
                "raw_data": json.dumps(cluster.raw_data, default=json_serial),
            }
            for cluster in eks_clusters
        ]
        with self._engine.begin() as conn:
            conn.execute(t_eks_clusters.insert(), rows)
        logger.debug(f"Inserted {len(eks_clusters)} EKS clusters")

    def insert_eks_node_groups(self, eks_node_groups: List[EKSNodeGroup]) -> None:
        """Insert EKS node group records."""
        if not eks_node_groups:
            return
        rows = [
            {
                "scan_id": node_group.scan_id,
                "cluster_name": node_group.cluster_name,
                "nodegroup_name": node_group.nodegroup_name,
                "nodegroup_arn": node_group.nodegroup_arn,
                "region": node_group.region,
                "status": node_group.status,
                "scaling_config": json.dumps(
                    node_group.scaling_config, default=json_serial
                ),
                "instance_types": json.dumps(
                    node_group.instance_types, default=json_serial
                ),
                "ami_type": node_group.ami_type,
                "release_version": node_group.release_version,
                "subnets": json.dumps(node_group.subnets, default=json_serial),
                "remote_access": json.dumps(
                    node_group.remote_access, default=json_serial
                )
                if node_group.remote_access
                else None,
                "node_role": node_group.node_role,
                "labels": json.dumps(node_group.labels, default=json_serial),
                "taints": json.dumps(node_group.taints, default=json_serial),
                "disk_size": node_group.disk_size,
                "capacity_type": node_group.capacity_type,
                "launch_template": json.dumps(
                    node_group.launch_template, default=json_serial
                )
                if node_group.launch_template
                else None,
                "update_config": json.dumps(
                    node_group.update_config, default=json_serial
                )
                if node_group.update_config
                else None,
                "health": json.dumps(node_group.health, default=json_serial)
                if node_group.health
                else None,
                "created_at_ng": node_group.created_at.isoformat()
                if node_group.created_at
                else None,
                "modified_at": node_group.modified_at.isoformat()
                if node_group.modified_at
                else None,
                "tags": json.dumps(node_group.tags, default=json_serial),
                "raw_data": json.dumps(node_group.raw_data, default=json_serial),
            }
            for node_group in eks_node_groups
        ]
        with self._engine.begin() as conn:
            conn.execute(t_eks_node_groups.insert(), rows)
        logger.debug(f"Inserted {len(eks_node_groups)} EKS node groups")

    def insert_ecr_repositories(self, ecr_repositories: List[ECRRepository]) -> None:
        """Insert ECR repository records."""
        if not ecr_repositories:
            return
        rows = [
            {
                "scan_id": repo.scan_id,
                "repository_arn": repo.repository_arn,
                "repository_name": repo.repository_name,
                "repository_uri": repo.repository_uri,
                "region": repo.region,
                "registry_id": repo.registry_id,
                "image_scanning_configuration": json.dumps(
                    repo.image_scanning_configuration, default=json_serial
                ),
                "image_tag_mutability": repo.image_tag_mutability,
                "encryption_configuration": json.dumps(
                    repo.encryption_configuration, default=json_serial
                ),
                "created_at_repo": repo.created_at.isoformat()
                if repo.created_at
                else None,
                "tags": json.dumps(repo.tags, default=json_serial),
                "raw_data": json.dumps(repo.raw_data, default=json_serial),
            }
            for repo in ecr_repositories
        ]
        with self._engine.begin() as conn:
            conn.execute(t_ecr_repositories.insert(), rows)
        logger.debug(f"Inserted {len(ecr_repositories)} ECR repositories")

    def insert_ecr_images(self, ecr_images: List[ECRImage]) -> None:
        """Insert ECR image records."""
        if not ecr_images:
            return
        rows = [
            {
                "scan_id": image.scan_id,
                "repository_name": image.repository_name,
                "region": image.region,
                "registry_id": image.registry_id,
                "image_digest": image.image_digest,
                "image_tags": json.dumps(image.image_tags, default=json_serial),
                "image_size_in_bytes": image.image_size_in_bytes,
                "image_pushed_at": image.image_pushed_at.isoformat()
                if image.image_pushed_at
                else None,
                "image_scan_status": image.image_scan_status,
                "image_scan_findings_summary": json.dumps(
                    image.image_scan_findings_summary, default=json_serial
                )
                if image.image_scan_findings_summary
                else None,
                "last_recorded_pull_time": image.last_recorded_pull_time.isoformat()
                if image.last_recorded_pull_time
                else None,
                "artifact_media_type": image.artifact_media_type,
                "raw_data": json.dumps(image.raw_data, default=json_serial),
            }
            for image in ecr_images
        ]
        with self._engine.begin() as conn:
            conn.execute(t_ecr_images.insert(), rows)
        logger.debug(f"Inserted {len(ecr_images)} ECR images")

    def insert_api_gateway_rest_apis(
        self, api_gateway_rest_apis: List[APIGatewayRestAPI]
    ) -> None:
        """Insert API Gateway REST API records."""
        if not api_gateway_rest_apis:
            return
        rows = [
            {
                "scan_id": api.scan_id,
                "api_id": api.api_id,
                "name": api.name,
                "region": api.region,
                "description": api.description,
                "endpoint_configuration": json.dumps(
                    api.endpoint_configuration, default=json_serial
                ),
                "version": api.version,
                "created_date": api.created_date.isoformat()
                if api.created_date
                else None,
                "api_key_source": api.api_key_source,
                "policy": api.policy,
                "minimum_compression_size": api.minimum_compression_size,
                "binary_media_types": json.dumps(
                    api.binary_media_types, default=json_serial
                ),
                "disable_execute_api_endpoint": 1
                if api.disable_execute_api_endpoint
                else 0,
                "tags": json.dumps(api.tags, default=json_serial),
                "raw_data": json.dumps(api.raw_data, default=json_serial),
            }
            for api in api_gateway_rest_apis
        ]
        with self._engine.begin() as conn:
            conn.execute(t_api_gateway_rest_apis.insert(), rows)
        logger.debug(f"Inserted {len(api_gateway_rest_apis)} API Gateway REST APIs")

    def insert_api_gateway_http_apis(
        self, api_gateway_http_apis: List[APIGatewayHttpAPI]
    ) -> None:
        """Insert API Gateway HTTP API records."""
        if not api_gateway_http_apis:
            return
        rows = [
            {
                "scan_id": api.scan_id,
                "api_id": api.api_id,
                "name": api.name,
                "region": api.region,
                "protocol_type": api.protocol_type,
                "description": api.description,
                "api_endpoint": api.api_endpoint,
                "cors_configuration": json.dumps(
                    api.cors_configuration, default=json_serial
                )
                if api.cors_configuration
                else None,
                "version": api.version,
                "route_selection_expression": api.route_selection_expression,
                "disable_execute_api_endpoint": 1
                if api.disable_execute_api_endpoint
                else 0,
                "disable_schema_validation": 1 if api.disable_schema_validation else 0,
                "import_info": json.dumps(api.import_info, default=json_serial),
                "created_date": api.created_date.isoformat()
                if api.created_date
                else None,
                "tags": json.dumps(api.tags, default=json_serial),
                "raw_data": json.dumps(api.raw_data, default=json_serial),
            }
            for api in api_gateway_http_apis
        ]
        with self._engine.begin() as conn:
            conn.execute(t_api_gateway_http_apis.insert(), rows)
        logger.debug(f"Inserted {len(api_gateway_http_apis)} API Gateway HTTP APIs")

    def insert_api_gateway_stages(
        self, api_gateway_stages: List[APIGatewayStage]
    ) -> None:
        """Insert API Gateway stage records."""
        if not api_gateway_stages:
            return
        rows = [
            {
                "scan_id": stage.scan_id,
                "api_id": stage.api_id,
                "stage_name": stage.stage_name,
                "region": stage.region,
                "api_type": stage.api_type,
                "deployment_id": stage.deployment_id,
                "description": stage.description,
                "created_date": stage.created_date.isoformat()
                if stage.created_date
                else None,
                "last_updated_date": stage.last_updated_date.isoformat()
                if stage.last_updated_date
                else None,
                "access_log_settings": json.dumps(
                    stage.access_log_settings, default=json_serial
                )
                if stage.access_log_settings
                else None,
                "client_certificate_id": stage.client_certificate_id,
                "throttle_settings": json.dumps(
                    stage.throttle_settings, default=json_serial
                )
                if stage.throttle_settings
                else None,
                "method_settings": json.dumps(
                    stage.method_settings, default=json_serial
                ),
                "variables": json.dumps(stage.variables, default=json_serial),
                "tracing_enabled": 1 if stage.tracing_enabled else 0,
                "web_acl_arn": stage.web_acl_arn,
                "auto_deploy": 1 if stage.auto_deploy else 0,
                "route_settings": json.dumps(stage.route_settings, default=json_serial),
                "default_route_settings": json.dumps(
                    stage.default_route_settings, default=json_serial
                )
                if stage.default_route_settings
                else None,
                "tags": json.dumps(stage.tags, default=json_serial),
                "raw_data": json.dumps(stage.raw_data, default=json_serial),
            }
            for stage in api_gateway_stages
        ]
        with self._engine.begin() as conn:
            conn.execute(t_api_gateway_stages.insert(), rows)
        logger.debug(f"Inserted {len(api_gateway_stages)} API Gateway stages")

    def insert_cloudfront_distributions(
        self, cloudfront_distributions: List[CloudFrontDistribution]
    ) -> None:
        """Insert CloudFront distribution records."""
        if not cloudfront_distributions:
            return
        rows = [
            {
                "scan_id": dist.scan_id,
                "distribution_id": dist.distribution_id,
                "distribution_arn": dist.distribution_arn,
                "domain_name": dist.domain_name,
                "status": dist.status,
                "enabled": 1 if dist.enabled else 0,
                "aliases": json.dumps(dist.aliases, default=json_serial),
                "origins": json.dumps(dist.origins, default=json_serial),
                "origin_groups": json.dumps(dist.origin_groups, default=json_serial),
                "default_root_object": dist.default_root_object,
                "default_cache_behavior": json.dumps(
                    dist.default_cache_behavior, default=json_serial
                ),
                "cache_behaviors": json.dumps(
                    dist.cache_behaviors, default=json_serial
                ),
                "viewer_certificate": json.dumps(
                    dist.viewer_certificate, default=json_serial
                ),
                "geo_restriction": json.dumps(dist.geo_restriction, default=json_serial)
                if dist.geo_restriction
                else None,
                "web_acl_id": dist.web_acl_id,
                "http_version": dist.http_version,
                "is_ipv6_enabled": 1 if dist.is_ipv6_enabled else 0,
                "logging": json.dumps(dist.logging, default=json_serial)
                if dist.logging
                else None,
                "price_class": dist.price_class,
                "custom_error_responses": json.dumps(
                    dist.custom_error_responses, default=json_serial
                ),
                "comment": dist.comment,
                "last_modified_time": dist.last_modified_time.isoformat()
                if dist.last_modified_time
                else None,
                "tags": json.dumps(dist.tags, default=json_serial),
                "raw_data": json.dumps(dist.raw_data, default=json_serial),
            }
            for dist in cloudfront_distributions
        ]
        with self._engine.begin() as conn:
            conn.execute(t_cloudfront_distributions.insert(), rows)
        logger.debug(
            f"Inserted {len(cloudfront_distributions)} CloudFront distributions"
        )

    # Phase 3: Governance, Logging & Advanced Services Operations

    def insert_organizations(self, organizations: List["Organization"]) -> None:
        """Insert AWS Organization records."""
        if not organizations:
            return
        rows = [
            {
                "scan_id": org.scan_id,
                "organization_id": org.organization_id,
                "organization_arn": org.organization_arn,
                "master_account_id": org.master_account_id,
                "master_account_email": org.master_account_email,
                "feature_set": org.feature_set,
                "available_policy_types": json.dumps(
                    org.available_policy_types, default=json_serial
                ),
                "raw_data": json.dumps(org.raw_data, default=json_serial),
            }
            for org in organizations
        ]
        with self._engine.begin() as conn:
            conn.execute(t_organizations.insert(), rows)
        logger.debug(f"Inserted {len(organizations)} organizations")

    def insert_organizational_units(self, ous: List["OrganizationalUnit"]) -> None:
        """Insert organizational unit records."""
        if not ous:
            return
        rows = [
            {
                "scan_id": ou.scan_id,
                "ou_id": ou.ou_id,
                "ou_arn": ou.ou_arn,
                "ou_name": ou.ou_name,
                "parent_id": ou.parent_id,
                "raw_data": json.dumps(ou.raw_data, default=json_serial),
            }
            for ou in ous
        ]
        with self._engine.begin() as conn:
            conn.execute(t_organizational_units.insert(), rows)
        logger.debug(f"Inserted {len(ous)} organizational units")

    def insert_organization_accounts(
        self, accounts: List["OrganizationAccount"]
    ) -> None:
        """Insert organization account records."""
        if not accounts:
            return
        rows = [
            {
                "scan_id": account.scan_id,
                "account_id": account.account_id,
                "account_arn": account.account_arn,
                "account_name": account.account_name,
                "email": account.email,
                "status": account.status,
                "joined_method": account.joined_method,
                "joined_timestamp": account.joined_timestamp.isoformat()
                if account.joined_timestamp
                else None,
                "parent_ou_id": account.parent_ou_id,
                "raw_data": json.dumps(account.raw_data, default=json_serial),
            }
            for account in accounts
        ]
        with self._engine.begin() as conn:
            conn.execute(t_organization_accounts.insert(), rows)
        logger.debug(f"Inserted {len(accounts)} organization accounts")

    def insert_sso_permission_sets(
        self, permission_sets: List["SSOPermissionSet"]
    ) -> None:
        """Insert SSO permission set records."""
        if not permission_sets:
            return
        rows = [
            {
                "scan_id": ps.scan_id,
                "permission_set_arn": ps.permission_set_arn,
                "permission_set_name": ps.permission_set_name,
                "instance_arn": ps.instance_arn,
                "description": ps.description,
                "session_duration": ps.session_duration,
                "relay_state": ps.relay_state,
                "created_date": ps.created_date.isoformat()
                if ps.created_date
                else None,
                "managed_policies": json.dumps(
                    ps.managed_policies, default=json_serial
                ),
                "inline_policy": ps.inline_policy,
                "customer_managed_policies": json.dumps(
                    ps.customer_managed_policies, default=json_serial
                ),
                "permissions_boundary": json.dumps(
                    ps.permissions_boundary, default=json_serial
                )
                if ps.permissions_boundary
                else None,
                "tags": json.dumps(ps.tags, default=json_serial),
                "raw_data": json.dumps(ps.raw_data, default=json_serial),
            }
            for ps in permission_sets
        ]
        with self._engine.begin() as conn:
            conn.execute(t_sso_permission_sets.insert(), rows)
        logger.debug(f"Inserted {len(permission_sets)} SSO permission sets")

    def insert_sso_assignments(self, assignments: List["SSOAssignment"]) -> None:
        """Insert SSO assignment records."""
        if not assignments:
            return
        rows = [
            {
                "scan_id": assignment.scan_id,
                "instance_arn": assignment.instance_arn,
                "permission_set_arn": assignment.permission_set_arn,
                "principal_type": assignment.principal_type,
                "principal_id": assignment.principal_id,
                "target_type": assignment.target_type,
                "target_id": assignment.target_id,
                "raw_data": json.dumps(assignment.raw_data, default=json_serial),
            }
            for assignment in assignments
        ]
        with self._engine.begin() as conn:
            conn.execute(t_sso_assignments.insert(), rows)
        logger.debug(f"Inserted {len(assignments)} SSO assignments")

    def insert_cloudtrail_trails(self, trails: List["CloudTrail"]) -> None:
        """Insert CloudTrail trail records."""
        if not trails:
            return
        rows = [
            {
                "scan_id": trail.scan_id,
                "trail_name": trail.trail_name,
                "trail_arn": trail.trail_arn,
                "region": trail.region,
                "s3_bucket_name": trail.s3_bucket_name,
                "s3_key_prefix": trail.s3_key_prefix,
                "sns_topic_name": trail.sns_topic_name,
                "sns_topic_arn": trail.sns_topic_arn,
                "cloud_watch_logs_log_group_arn": trail.cloud_watch_logs_log_group_arn,
                "cloud_watch_logs_role_arn": trail.cloud_watch_logs_role_arn,
                "kms_key_id": trail.kms_key_id,
                "is_multi_region_trail": 1 if trail.is_multi_region_trail else 0,
                "is_organization_trail": 1 if trail.is_organization_trail else 0,
                "include_global_service_events": 1
                if trail.include_global_service_events
                else 0,
                "is_logging": 1 if trail.is_logging else 0,
                "has_event_selectors": 1 if trail.has_event_selectors else 0,
                "has_insight_selectors": 1 if trail.has_insight_selectors else 0,
                "home_region": trail.home_region,
                "tags": json.dumps(trail.tags, default=json_serial),
                "raw_data": json.dumps(trail.raw_data, default=json_serial),
            }
            for trail in trails
        ]
        with self._engine.begin() as conn:
            conn.execute(t_cloudtrail_trails.insert(), rows)
        logger.debug(f"Inserted {len(trails)} CloudTrail trails")

    def insert_cloudwatch_log_groups(
        self, log_groups: List["CloudWatchLogGroup"]
    ) -> None:
        """Insert CloudWatch log group records."""
        if not log_groups:
            return
        rows = [
            {
                "scan_id": lg.scan_id,
                "log_group_name": lg.log_group_name,
                "log_group_arn": lg.log_group_arn,
                "region": lg.region,
                "creation_time": lg.creation_time.isoformat()
                if lg.creation_time
                else None,
                "retention_in_days": lg.retention_in_days,
                "stored_bytes": lg.stored_bytes,
                "kms_key_id": lg.kms_key_id,
                "metric_filter_count": lg.metric_filter_count,
                "tags": json.dumps(lg.tags, default=json_serial),
                "raw_data": json.dumps(lg.raw_data, default=json_serial),
            }
            for lg in log_groups
        ]
        with self._engine.begin() as conn:
            conn.execute(t_cloudwatch_log_groups.insert(), rows)
        logger.debug(f"Inserted {len(log_groups)} CloudWatch log groups")

    def insert_config_recorders(self, recorders: List["ConfigRecorder"]) -> None:
        """Insert AWS Config recorder records."""
        if not recorders:
            return
        rows = [
            {
                "scan_id": recorder.scan_id,
                "recorder_name": recorder.recorder_name,
                "region": recorder.region,
                "role_arn": recorder.role_arn,
                "recording_group": json.dumps(
                    recorder.recording_group, default=json_serial
                ),
                "is_recording": 1 if recorder.is_recording else 0,
                "last_status": recorder.last_status,
                "last_start_time": recorder.last_start_time.isoformat()
                if recorder.last_start_time
                else None,
                "last_stop_time": recorder.last_stop_time.isoformat()
                if recorder.last_stop_time
                else None,
                "raw_data": json.dumps(recorder.raw_data, default=json_serial),
            }
            for recorder in recorders
        ]
        with self._engine.begin() as conn:
            conn.execute(t_config_recorders.insert(), rows)
        logger.debug(f"Inserted {len(recorders)} Config recorders")

    def insert_config_rules(self, rules: List["ConfigRule"]) -> None:
        """Insert AWS Config rule records."""
        if not rules:
            return
        rows = [
            {
                "scan_id": rule.scan_id,
                "rule_name": rule.rule_name,
                "rule_arn": rule.rule_arn,
                "rule_id": rule.rule_id,
                "region": rule.region,
                "description": rule.description,
                "scope": json.dumps(rule.scope, default=json_serial)
                if rule.scope
                else None,
                "source": json.dumps(rule.source, default=json_serial),
                "compliance_type": rule.compliance_type,
                "config_rule_state": rule.config_rule_state,
                "maximum_execution_frequency": rule.maximum_execution_frequency,
                "raw_data": json.dumps(rule.raw_data, default=json_serial),
            }
            for rule in rules
        ]
        with self._engine.begin() as conn:
            conn.execute(t_config_rules.insert(), rows)
        logger.debug(f"Inserted {len(rules)} Config rules")

    def insert_bedrock_models(self, models: List["BedrockModel"]) -> None:
        """Insert Bedrock model records."""
        if not models:
            return
        rows = [
            {
                "scan_id": model.scan_id,
                "model_id": model.model_id,
                "model_arn": model.model_arn,
                "model_name": model.model_name,
                "region": model.region,
                "provider_name": model.provider_name,
                "customization_type": model.customization_type,
                "base_model_arn": model.base_model_arn,
                "inference_types_supported": json.dumps(
                    model.inference_types_supported, default=json_serial
                ),
                "input_modalities": json.dumps(
                    model.input_modalities, default=json_serial
                ),
                "output_modalities": json.dumps(
                    model.output_modalities, default=json_serial
                ),
                "response_streaming_supported": 1
                if model.response_streaming_supported
                else 0,
                "raw_data": json.dumps(model.raw_data, default=json_serial),
            }
            for model in models
        ]
        with self._engine.begin() as conn:
            conn.execute(t_bedrock_models.insert(), rows)
        logger.debug(f"Inserted {len(models)} Bedrock models")

    def insert_bedrock_guardrails(self, guardrails: List["BedrockGuardrail"]) -> None:
        """Insert Bedrock guardrail records."""
        if not guardrails:
            return
        rows = [
            {
                "scan_id": gr.scan_id,
                "guardrail_id": gr.guardrail_id,
                "guardrail_arn": gr.guardrail_arn,
                "guardrail_name": gr.guardrail_name,
                "region": gr.region,
                "version": gr.version,
                "description": gr.description,
                "status": gr.status,
                "content_policy_config": json.dumps(
                    gr.content_policy_config, default=json_serial
                )
                if gr.content_policy_config
                else None,
                "topic_policy_config": json.dumps(
                    gr.topic_policy_config, default=json_serial
                )
                if gr.topic_policy_config
                else None,
                "word_policy_config": json.dumps(
                    gr.word_policy_config, default=json_serial
                )
                if gr.word_policy_config
                else None,
                "sensitive_information_policy_config": json.dumps(
                    gr.sensitive_information_policy_config, default=json_serial
                )
                if gr.sensitive_information_policy_config
                else None,
                "blocked_input_messaging": gr.blocked_input_messaging,
                "blocked_outputs_messaging": gr.blocked_outputs_messaging,
                "created_at_time": gr.created_at.isoformat() if gr.created_at else None,
                "updated_at_time": gr.updated_at.isoformat() if gr.updated_at else None,
                "tags": json.dumps(gr.tags, default=json_serial),
                "raw_data": json.dumps(gr.raw_data, default=json_serial),
            }
            for gr in guardrails
        ]
        with self._engine.begin() as conn:
            conn.execute(t_bedrock_guardrails.insert(), rows)
        logger.debug(f"Inserted {len(guardrails)} Bedrock guardrails")

    def insert_bedrock_knowledge_bases(
        self, knowledge_bases: List["BedrockKnowledgeBase"]
    ) -> None:
        """Insert Bedrock knowledge base records."""
        if not knowledge_bases:
            return
        rows = [
            {
                "scan_id": kb.scan_id,
                "knowledge_base_id": kb.knowledge_base_id,
                "knowledge_base_arn": kb.knowledge_base_arn,
                "knowledge_base_name": kb.knowledge_base_name,
                "region": kb.region,
                "description": kb.description,
                "role_arn": kb.role_arn,
                "knowledge_base_configuration": json.dumps(
                    kb.knowledge_base_configuration, default=json_serial
                ),
                "storage_configuration": json.dumps(
                    kb.storage_configuration, default=json_serial
                ),
                "status": kb.status,
                "created_at_time": kb.created_at.isoformat() if kb.created_at else None,
                "updated_at_time": kb.updated_at.isoformat() if kb.updated_at else None,
                "tags": json.dumps(kb.tags, default=json_serial),
                "raw_data": json.dumps(kb.raw_data, default=json_serial),
            }
            for kb in knowledge_bases
        ]
        with self._engine.begin() as conn:
            conn.execute(t_bedrock_knowledge_bases.insert(), rows)
        logger.debug(f"Inserted {len(knowledge_bases)} Bedrock knowledge bases")

    def insert_bedrock_agents(self, agents: List["BedrockAgent"]) -> None:
        """Insert Bedrock agent records."""
        if not agents:
            return
        rows = [
            {
                "scan_id": agent.scan_id,
                "agent_id": agent.agent_id,
                "agent_arn": agent.agent_arn,
                "agent_name": agent.agent_name,
                "region": agent.region,
                "agent_version": agent.agent_version,
                "description": agent.description,
                "agent_resource_role_arn": agent.agent_resource_role_arn,
                "foundation_model": agent.foundation_model,
                "instruction": agent.instruction,
                "idle_session_ttl_in_seconds": agent.idle_session_ttl_in_seconds,
                "agent_status": agent.agent_status,
                "created_at_time": agent.created_at.isoformat()
                if agent.created_at
                else None,
                "updated_at_time": agent.updated_at.isoformat()
                if agent.updated_at
                else None,
                "prepared_at_time": agent.prepared_at.isoformat()
                if agent.prepared_at
                else None,
                "tags": json.dumps(agent.tags, default=json_serial),
                "raw_data": json.dumps(agent.raw_data, default=json_serial),
            }
            for agent in agents
        ]
        with self._engine.begin() as conn:
            conn.execute(t_bedrock_agents.insert(), rows)
        logger.debug(f"Inserted {len(agents)} Bedrock agents")

    def insert_directory_services(self, directories: List["DirectoryService"]) -> None:
        """Insert Directory Service records."""
        if not directories:
            return
        rows = [
            {
                "scan_id": directory.scan_id,
                "directory_id": directory.directory_id,
                "directory_name": directory.directory_name,
                "region": directory.region,
                "directory_type": directory.directory_type,
                "size": directory.size,
                "edition": directory.edition,
                "vpc_id": directory.vpc_id,
                "subnet_ids": json.dumps(directory.subnet_ids, default=json_serial),
                "dns_ip_addresses": json.dumps(
                    directory.dns_ip_addresses, default=json_serial
                ),
                "access_url": directory.access_url,
                "stage": directory.stage,
                "sso_enabled": 1 if directory.sso_enabled else 0,
                "radius_status": directory.radius_status,
                "launch_time": directory.launch_time.isoformat()
                if directory.launch_time
                else None,
                "stage_last_updated_date_time": directory.stage_last_updated_date_time.isoformat()
                if directory.stage_last_updated_date_time
                else None,
                "description": directory.description,
                "alias": directory.alias,
                "short_name": directory.short_name,
                "tags": json.dumps(directory.tags, default=json_serial),
                "raw_data": json.dumps(directory.raw_data, default=json_serial),
            }
            for directory in directories
        ]
        with self._engine.begin() as conn:
            conn.execute(t_directory_services.insert(), rows)
        logger.debug(f"Inserted {len(directories)} directory services")

    def insert_transit_gateways(self, transit_gateways: List["TransitGateway"]) -> None:
        """Insert Transit Gateway records."""
        if not transit_gateways:
            return
        rows = [
            {
                "scan_id": tgw.scan_id,
                "transit_gateway_id": tgw.transit_gateway_id,
                "transit_gateway_arn": tgw.transit_gateway_arn,
                "region": tgw.region,
                "owner_id": tgw.owner_id,
                "description": tgw.description,
                "state": tgw.state,
                "amazon_side_asn": tgw.amazon_side_asn,
                "default_route_table_id": tgw.default_route_table_id,
                "default_route_table_association": tgw.default_route_table_association,
                "default_route_table_propagation": tgw.default_route_table_propagation,
                "vpn_ecmp_support": tgw.vpn_ecmp_support,
                "dns_support": tgw.dns_support,
                "multicast_support": tgw.multicast_support,
                "auto_accept_shared_attachments": tgw.auto_accept_shared_attachments,
                "transit_gateway_cidr_blocks": json.dumps(
                    tgw.transit_gateway_cidr_blocks, default=json_serial
                ),
                "creation_time": tgw.creation_time.isoformat()
                if tgw.creation_time
                else None,
                "tags": json.dumps(tgw.tags, default=json_serial),
                "raw_data": json.dumps(tgw.raw_data, default=json_serial),
            }
            for tgw in transit_gateways
        ]
        with self._engine.begin() as conn:
            conn.execute(t_transit_gateways.insert(), rows)
        logger.debug(f"Inserted {len(transit_gateways)} transit gateways")

    def insert_vpn_connections(self, vpn_connections: List["VPNConnection"]) -> None:
        """Insert VPN connection records."""
        if not vpn_connections:
            return
        rows = [
            {
                "scan_id": vpn.scan_id,
                "vpn_connection_id": vpn.vpn_connection_id,
                "region": vpn.region,
                "state": vpn.state,
                "vpn_connection_type": vpn.vpn_connection_type,
                "customer_gateway_id": vpn.customer_gateway_id,
                "vpn_gateway_id": vpn.vpn_gateway_id,
                "transit_gateway_id": vpn.transit_gateway_id,
                "customer_gateway_configuration": vpn.customer_gateway_configuration,
                "static_routes_only": 1 if vpn.static_routes_only else 0,
                "vgw_telemetry": json.dumps(vpn.vgw_telemetry, default=json_serial),
                "routes": json.dumps(vpn.routes, default=json_serial),
                "category": vpn.category,
                "tags": json.dumps(vpn.tags, default=json_serial),
                "raw_data": json.dumps(vpn.raw_data, default=json_serial),
            }
            for vpn in vpn_connections
        ]
        with self._engine.begin() as conn:
            conn.execute(t_vpn_connections.insert(), rows)
        logger.debug(f"Inserted {len(vpn_connections)} VPN connections")

    def insert_direct_connect_connections(
        self, dx_connections: List["DirectConnectConnection"]
    ) -> None:
        """Insert Direct Connect connection records."""
        if not dx_connections:
            return
        rows = [
            {
                "scan_id": dx.scan_id,
                "connection_id": dx.connection_id,
                "connection_name": dx.connection_name,
                "region": dx.region,
                "connection_state": dx.connection_state,
                "location": dx.location,
                "bandwidth": dx.bandwidth,
                "vlan": dx.vlan,
                "partner_name": dx.partner_name,
                "lag_id": dx.lag_id,
                "aws_device": dx.aws_device,
                "aws_device_v2": dx.aws_device_v2,
                "aws_logical_device_id": dx.aws_logical_device_id,
                "jumbo_frame_capable": 1 if dx.jumbo_frame_capable else 0,
                "has_logical_redundancy": dx.has_logical_redundancy,
                "provider_name": dx.provider_name,
                "mac_sec_capable": 1 if dx.mac_sec_capable else 0,
                "encryption_mode": dx.encryption_mode,
                "loa_issue_time": dx.loa_issue_time.isoformat()
                if dx.loa_issue_time
                else None,
                "tags": json.dumps(dx.tags, default=json_serial),
                "raw_data": json.dumps(dx.raw_data, default=json_serial),
            }
            for dx in dx_connections
        ]
        with self._engine.begin() as conn:
            conn.execute(t_direct_connect_connections.insert(), rows)
        logger.debug(f"Inserted {len(dx_connections)} Direct Connect connections")

    def insert_elasticache_clusters(self, clusters: List["ElastiCacheCluster"]) -> None:
        """Insert ElastiCache cluster records."""
        if not clusters:
            return
        rows = [
            {
                "scan_id": cluster.scan_id,
                "cache_cluster_id": cluster.cache_cluster_id,
                "cache_cluster_arn": cluster.cache_cluster_arn,
                "region": cluster.region,
                "engine": cluster.engine,
                "engine_version": cluster.engine_version,
                "cache_node_type": cluster.cache_node_type,
                "num_cache_nodes": cluster.num_cache_nodes,
                "preferred_availability_zone": cluster.preferred_availability_zone,
                "preferred_availability_zones": json.dumps(
                    cluster.preferred_availability_zones, default=json_serial
                ),
                "cache_cluster_status": cluster.cache_cluster_status,
                "cache_subnet_group_name": cluster.cache_subnet_group_name,
                "vpc_id": cluster.vpc_id,
                "security_groups": json.dumps(
                    cluster.security_groups, default=json_serial
                ),
                "at_rest_encryption_enabled": 1
                if cluster.at_rest_encryption_enabled
                else 0,
                "transit_encryption_enabled": 1
                if cluster.transit_encryption_enabled
                else 0,
                "auth_token_enabled": 1 if cluster.auth_token_enabled else 0,
                "replication_group_id": cluster.replication_group_id,
                "snapshot_retention_limit": cluster.snapshot_retention_limit,
                "snapshot_window": cluster.snapshot_window,
                "preferred_maintenance_window": cluster.preferred_maintenance_window,
                "notification_configuration": json.dumps(
                    cluster.notification_configuration, default=json_serial
                )
                if cluster.notification_configuration
                else None,
                "cache_parameter_group_name": cluster.cache_parameter_group_name,
                "cache_cluster_create_time": cluster.cache_cluster_create_time.isoformat()
                if cluster.cache_cluster_create_time
                else None,
                "tags": json.dumps(cluster.tags, default=json_serial),
                "raw_data": json.dumps(cluster.raw_data, default=json_serial),
            }
            for cluster in clusters
        ]
        with self._engine.begin() as conn:
            conn.execute(t_elasticache_clusters.insert(), rows)
        logger.debug(f"Inserted {len(clusters)} ElastiCache clusters")

    def insert_opensearch_domains(self, domains: List["OpenSearchDomain"]) -> None:
        """Insert OpenSearch domain records."""
        if not domains:
            return
        rows = [
            {
                "scan_id": domain.scan_id,
                "domain_id": domain.domain_id,
                "domain_name": domain.domain_name,
                "domain_arn": domain.domain_arn,
                "region": domain.region,
                "engine_type": domain.engine_type,
                "engine_version": domain.engine_version,
                "instance_type": domain.instance_type,
                "instance_count": domain.instance_count,
                "dedicated_master_enabled": 1 if domain.dedicated_master_enabled else 0,
                "dedicated_master_type": domain.dedicated_master_type,
                "dedicated_master_count": domain.dedicated_master_count,
                "zone_awareness_enabled": 1 if domain.zone_awareness_enabled else 0,
                "availability_zone_count": domain.availability_zone_count,
                "warm_enabled": 1 if domain.warm_enabled else 0,
                "warm_type": domain.warm_type,
                "warm_count": domain.warm_count,
                "cold_storage_enabled": 1 if domain.cold_storage_enabled else 0,
                "ebs_enabled": 1 if domain.ebs_enabled else 0,
                "volume_type": domain.volume_type,
                "volume_size": domain.volume_size,
                "iops": domain.iops,
                "throughput": domain.throughput,
                "vpc_id": domain.vpc_id,
                "subnet_ids": json.dumps(domain.subnet_ids, default=json_serial),
                "security_group_ids": json.dumps(
                    domain.security_group_ids, default=json_serial
                ),
                "endpoint": domain.endpoint,
                "endpoints": json.dumps(domain.endpoints, default=json_serial),
                "encryption_at_rest_enabled": 1
                if domain.encryption_at_rest_enabled
                else 0,
                "kms_key_id": domain.kms_key_id,
                "node_to_node_encryption_enabled": 1
                if domain.node_to_node_encryption_enabled
                else 0,
                "enforce_https": 1 if domain.enforce_https else 0,
                "tls_security_policy": domain.tls_security_policy,
                "custom_endpoint_enabled": 1 if domain.custom_endpoint_enabled else 0,
                "custom_endpoint": domain.custom_endpoint,
                "access_policies": domain.access_policies,
                "internal_user_database_enabled": 1
                if domain.internal_user_database_enabled
                else 0,
                "saml_enabled": 1 if domain.saml_enabled else 0,
                "auto_tune_enabled": 1 if domain.auto_tune_enabled else 0,
                "created": 1 if domain.created else 0,
                "deleted": 1 if domain.deleted else 0,
                "processing": 1 if domain.processing else 0,
                "upgrade_processing": 1 if domain.upgrade_processing else 0,
                "domain_processing_status": domain.domain_processing_status,
                "tags": json.dumps(domain.tags, default=json_serial),
                "raw_data": json.dumps(domain.raw_data, default=json_serial),
            }
            for domain in domains
        ]
        with self._engine.begin() as conn:
            conn.execute(t_opensearch_domains.insert(), rows)
        logger.debug(f"Inserted {len(domains)} OpenSearch domains")

    def insert_msk_clusters(self, clusters: List["MSKCluster"]) -> None:
        """Insert MSK cluster records."""
        if not clusters:
            return
        rows = [
            {
                "scan_id": cluster.scan_id,
                "cluster_arn": cluster.cluster_arn,
                "cluster_name": cluster.cluster_name,
                "region": cluster.region,
                "kafka_version": cluster.kafka_version,
                "state": cluster.state,
                "creation_time": cluster.creation_time.isoformat()
                if cluster.creation_time
                else None,
                "broker_node_group_info": json.dumps(
                    cluster.broker_node_group_info, default=json_serial
                ),
                "number_of_broker_nodes": cluster.number_of_broker_nodes,
                "encryption_in_transit": json.dumps(
                    cluster.encryption_in_transit, default=json_serial
                )
                if cluster.encryption_in_transit
                else None,
                "encryption_at_rest_kms_key_arn": cluster.encryption_at_rest_kms_key_arn,
                "enhanced_monitoring": cluster.enhanced_monitoring,
                "open_monitoring": json.dumps(
                    cluster.open_monitoring, default=json_serial
                )
                if cluster.open_monitoring
                else None,
                "logging_info": json.dumps(cluster.logging_info, default=json_serial)
                if cluster.logging_info
                else None,
                "cluster_type": cluster.cluster_type,
                "provisioned": json.dumps(cluster.provisioned, default=json_serial)
                if cluster.provisioned
                else None,
                "serverless": json.dumps(cluster.serverless, default=json_serial)
                if cluster.serverless
                else None,
                "current_version": cluster.current_version,
                "zookeeper_connect_string": cluster.zookeeper_connect_string,
                "zookeeper_connect_string_tls": cluster.zookeeper_connect_string_tls,
                "bootstrap_broker_string": cluster.bootstrap_broker_string,
                "bootstrap_broker_string_tls": cluster.bootstrap_broker_string_tls,
                "tags": json.dumps(cluster.tags, default=json_serial),
                "raw_data": json.dumps(cluster.raw_data, default=json_serial),
            }
            for cluster in clusters
        ]
        with self._engine.begin() as conn:
            conn.execute(t_msk_clusters.insert(), rows)
        logger.debug(f"Inserted {len(clusters)} MSK clusters")

    def insert_dynamodb_tables(self, tables: List["DynamoDBTable"]) -> None:
        """Insert DynamoDB table records."""
        if not tables:
            return
        rows = [
            {
                "scan_id": table.scan_id,
                "table_name": table.table_name,
                "table_arn": table.table_arn,
                "table_id": table.table_id,
                "region": table.region,
                "table_status": table.table_status,
                "creation_date_time": table.creation_date_time.isoformat()
                if table.creation_date_time
                else None,
                "key_schema": json.dumps(table.key_schema, default=json_serial),
                "attribute_definitions": json.dumps(
                    table.attribute_definitions, default=json_serial
                ),
                "billing_mode_summary": json.dumps(
                    table.billing_mode_summary, default=json_serial
                )
                if table.billing_mode_summary
                else None,
                "provisioned_throughput": json.dumps(
                    table.provisioned_throughput, default=json_serial
                )
                if table.provisioned_throughput
                else None,
                "table_size_bytes": table.table_size_bytes,
                "item_count": table.item_count,
                "global_secondary_indexes": json.dumps(
                    table.global_secondary_indexes, default=json_serial
                ),
                "local_secondary_indexes": json.dumps(
                    table.local_secondary_indexes, default=json_serial
                ),
                "stream_specification": json.dumps(
                    table.stream_specification, default=json_serial
                )
                if table.stream_specification
                else None,
                "latest_stream_arn": table.latest_stream_arn,
                "latest_stream_label": table.latest_stream_label,
                "restore_summary": json.dumps(
                    table.restore_summary, default=json_serial
                )
                if table.restore_summary
                else None,
                "sse_description": json.dumps(
                    table.sse_description, default=json_serial
                )
                if table.sse_description
                else None,
                "point_in_time_recovery_enabled": 1
                if table.point_in_time_recovery_enabled
                else 0,
                "global_table_version": table.global_table_version,
                "replicas": json.dumps(table.replicas, default=json_serial),
                "continuous_backups_status": table.continuous_backups_status,
                "table_class_summary": json.dumps(
                    table.table_class_summary, default=json_serial
                )
                if table.table_class_summary
                else None,
                "deletion_protection_enabled": 1
                if table.deletion_protection_enabled
                else 0,
                "tags": json.dumps(table.tags, default=json_serial),
                "raw_data": json.dumps(table.raw_data, default=json_serial),
            }
            for table in tables
        ]
        with self._engine.begin() as conn:
            conn.execute(t_dynamodb_tables.insert(), rows)
        logger.debug(f"Inserted {len(tables)} DynamoDB tables")

    def get_latest_scan_for_account(
        self, account_number: str
    ) -> Optional[Dict[str, Any]]:
        """
        Get the most recent scan for an account.

        Args:
            account_number: AWS account number

        Returns:
            Dictionary with scan metadata or None if not found
        """
        stmt = (
            sa.select(t_scan_metadata)
            .where(t_scan_metadata.c.account_number == account_number)
            .order_by(t_scan_metadata.c.scan_timestamp.desc())
            .limit(1)
        )
        with self._engine.begin() as conn:
            row = conn.execute(stmt).fetchone()
            return dict(row._mapping) if row else None

    def get_all_scans(self) -> List[Dict[str, Any]]:
        """
        Get all scan metadata records.

        Returns:
            List of scan metadata dictionaries
        """
        stmt = sa.select(t_scan_metadata).order_by(
            t_scan_metadata.c.scan_timestamp.desc()
        )
        with self._engine.begin() as conn:
            return [dict(row._mapping) for row in conn.execute(stmt).fetchall()]

    def delete_scan(self, scan_id: str) -> Dict[str, int]:
        """
        Delete a scan and all its associated data from the database.

        This method deletes the scan metadata and all related records from all tables
        that reference the scan_id. The deletion is performed in a transaction to
        ensure data consistency.

        Args:
            scan_id: The scan ID to delete

        Returns:
            Dictionary with counts of deleted records per table

        Raises:
            ValueError: If scan_id doesn't exist
        """
        # First verify the scan exists
        with self._engine.begin() as conn:
            scan = conn.execute(
                sa.text(
                    "SELECT scan_id, account_name, scan_timestamp "
                    "FROM scan_metadata WHERE scan_id = :scan_id"
                ),
                {"scan_id": scan_id},
            ).fetchone()

            if not scan:
                raise ValueError(f"Scan ID '{scan_id}' not found in database")

        # List of all tables that have scan_id foreign key
        # Ordered to handle dependencies correctly
        tables_with_scan_id = [
            "prowler_findings",
            "cost_data",
            "ec2_instances",
            "vpcs",
            "subnets",
            "security_groups",
            "load_balancers",
            "nat_gateways",
            "internet_gateways",
            "route_tables",
            "auto_scaling_groups",
            "network_interfaces",
            "workspaces",
            "lambda_functions",
            "vpc_flow_logs",
            "s3_buckets",
            "iam_users",
            "iam_roles",
            "iam_policies",
            "route53_hosted_zones",
            "route53_record_sets",
            "ebs_volumes",
            "ebs_snapshots",
            "rds_instances",
            "kms_keys",
            "elastic_ips",
            "ecs_clusters",
            "ecs_services",
            "ecs_task_definitions",
            "eks_clusters",
            "eks_node_groups",
            "ecr_repositories",
            "ecr_images",
            "api_gateway_rest_apis",
            "api_gateway_http_apis",
            "api_gateway_stages",
            "cloudfront_distributions",
            "organizations",
            "organizational_units",
            "organization_accounts",
            "sso_permission_sets",
            "sso_assignments",
            "cloudtrail_trails",
            "cloudwatch_log_groups",
            "config_recorders",
            "config_rules",
            "bedrock_models",
            "bedrock_guardrails",
            "bedrock_knowledge_bases",
            "bedrock_agents",
            "directory_services",
            "transit_gateways",
            "vpn_connections",
            "direct_connect_connections",
            "elasticache_clusters",
            "opensearch_domains",
            "msk_clusters",
            "dynamodb_tables",
        ]

        deleted_counts = {}

        # Delete from all related tables first, then scan_metadata
        with self._engine.begin() as conn:
            # Enable foreign key constraints
            conn.execute(sa.text("PRAGMA foreign_keys = ON"))

            # Delete from each table
            for table in tables_with_scan_id:
                result = conn.execute(
                    sa.text(f"DELETE FROM {table} WHERE scan_id = :scan_id"),
                    {"scan_id": scan_id},
                )
                deleted_count = result.rowcount
                if deleted_count > 0:
                    deleted_counts[table] = deleted_count

            # Finally delete the scan metadata
            result = conn.execute(
                sa.text("DELETE FROM scan_metadata WHERE scan_id = :scan_id"),
                {"scan_id": scan_id},
            )
            deleted_counts["scan_metadata"] = result.rowcount

        return deleted_counts

    def insert_account_security_posture(
        self, records: List[AccountSecurityPosture]
    ) -> None:
        """Insert account security posture records."""
        if not records:
            return
        rows = [
            {
                "scan_id": posture.scan_id,
                "account_summary": json.dumps(
                    posture.account_summary, default=json_serial
                ),
                "password_policy": json.dumps(
                    posture.password_policy, default=json_serial
                )
                if posture.password_policy is not None
                else None,
                "password_policy_exists": 1 if posture.password_policy_exists else 0,
                "account_public_access_block": json.dumps(
                    posture.account_public_access_block, default=json_serial
                )
                if posture.account_public_access_block is not None
                else None,
                "credential_report_generated": posture.credential_report_generated.isoformat()
                if posture.credential_report_generated
                else None,
                "raw_data": json.dumps(posture.raw_data, default=json_serial),
            }
            for posture in records
        ]
        with self._engine.begin() as conn:
            conn.execute(t_account_security_posture.insert(), rows)
        logger.debug(f"Inserted {len(records)} account security posture records")

    def insert_iam_credential_report(
        self, entries: List[IAMCredentialReportEntry]
    ) -> None:
        """Insert parsed IAM credential report rows."""
        if not entries:
            return
        rows = [
            {
                "scan_id": entry.scan_id,
                "user_name": entry.user_name,
                "arn": entry.arn,
                "user_creation_time": entry.user_creation_time,
                "password_enabled": None
                if entry.password_enabled is None
                else (1 if entry.password_enabled else 0),
                "password_last_used": entry.password_last_used,
                "mfa_active": 1 if entry.mfa_active else 0,
                "access_key_1_active": 1 if entry.access_key_1_active else 0,
                "access_key_1_last_rotated": entry.access_key_1_last_rotated,
                "access_key_1_last_used": entry.access_key_1_last_used,
                "access_key_2_active": 1 if entry.access_key_2_active else 0,
                "access_key_2_last_rotated": entry.access_key_2_last_rotated,
                "access_key_2_last_used": entry.access_key_2_last_used,
                "raw_data": json.dumps(entry.raw_data, default=json_serial),
            }
            for entry in entries
        ]
        with self._engine.begin() as conn:
            conn.execute(t_iam_credential_report.insert(), rows)
        logger.debug(f"Inserted {len(entries)} credential report rows")

    def insert_region_security_services(
        self, records: List[RegionSecurityServices]
    ) -> None:
        """Insert per-region security service status records."""
        if not records:
            return

        def tri(value: Optional[bool]) -> Optional[int]:
            return None if value is None else (1 if value else 0)

        rows = [
            {
                "scan_id": record.scan_id,
                "region": record.region,
                "guardduty_enabled": tri(record.guardduty_enabled),
                "guardduty_detector": json.dumps(
                    record.guardduty_detector, default=json_serial
                )
                if record.guardduty_detector is not None
                else None,
                "security_hub_enabled": tri(record.security_hub_enabled),
                "ebs_encryption_by_default": tri(record.ebs_encryption_by_default),
                "access_analyzers": json.dumps(
                    record.access_analyzers, default=json_serial
                ),
                "raw_data": json.dumps(record.raw_data, default=json_serial),
            }
            for record in records
        ]
        with self._engine.begin() as conn:
            conn.execute(t_region_security_services.insert(), rows)
        logger.debug(f"Inserted {len(records)} region security service records")

    def insert_lambda_exposure(self, records: List[LambdaExposure]) -> None:
        """Insert Lambda exposure records."""
        if not records:
            return
        rows = [
            {
                "scan_id": record.scan_id,
                "region": record.region,
                "function_name": record.function_name,
                "function_arn": record.function_arn,
                "url_config": json.dumps(record.url_config, default=json_serial)
                if record.url_config is not None
                else None,
                "url_auth_type": record.url_auth_type,
                "resource_policy": json.dumps(
                    record.resource_policy, default=json_serial
                )
                if record.resource_policy is not None
                else None,
                "raw_data": json.dumps(record.raw_data, default=json_serial),
            }
            for record in records
        ]
        with self._engine.begin() as conn:
            conn.execute(t_lambda_exposure.insert(), rows)
        logger.debug(f"Inserted {len(records)} Lambda exposure records")

    def insert_s3_public_access(self, records: List[S3PublicAccess]) -> None:
        """Insert per-bucket S3 public access records."""
        if not records:
            return
        rows = [
            {
                "scan_id": record.scan_id,
                "bucket_name": record.bucket_name,
                "public_access_block": json.dumps(
                    record.public_access_block, default=json_serial
                )
                if record.public_access_block is not None
                else None,
                "policy_is_public": None
                if record.policy_is_public is None
                else (1 if record.policy_is_public else 0),
                "raw_data": json.dumps(record.raw_data, default=json_serial),
            }
            for record in records
        ]
        with self._engine.begin() as conn:
            conn.execute(t_s3_public_access.insert(), rows)
        logger.debug(f"Inserted {len(records)} S3 public access records")
