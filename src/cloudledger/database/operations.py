"""
Database operations for CloudLedger.

This module provides functions for inserting and querying scan data.
Uses Australian English in all documentation and comments.
"""

import sqlite3
import json
from datetime import datetime
from typing import List, Dict, Any, Optional
from pathlib import Path
import logging

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
        return obj.isoformat()
    raise TypeError(f"Type {type(obj)} not serializable")


class DatabaseOperations:
    """Handles all database operations for CloudLedger."""

    def __init__(self, db_path: str):
        """
        Initialise database operations.

        Args:
            db_path: Full path to SQLite database file
        """
        self.db_path = Path(db_path)

    def _get_connection(self) -> sqlite3.Connection:
        """Get database connection with row factory."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def insert_scan_metadata(self, metadata: ScanMetadata) -> None:
        """
        Insert scan metadata record.

        Args:
            metadata: Scan metadata to insert
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO scan_metadata (
                    scan_id, account_name, account_number, scan_timestamp,
                    prowler_level, regions_scanned, scan_status,
                    error_message, scan_duration_seconds
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    metadata.scan_id,
                    metadata.account_name,
                    metadata.account_number,
                    metadata.scan_timestamp.isoformat(),
                    metadata.prowler_level,
                    json.dumps(metadata.regions_scanned, default=json_serial),
                    metadata.scan_status,
                    metadata.error_message,
                    metadata.scan_duration_seconds,
                ),
            )
            conn.commit()
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
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                UPDATE scan_metadata
                SET scan_status = ?, error_message = ?, scan_duration_seconds = ?
                WHERE scan_id = ?
            """,
                (status, error_message, duration, scan_id),
            )
            conn.commit()
            logger.debug(f"Updated scan status for {scan_id}: {status}")

    def insert_ec2_instances(self, instances: List[EC2Instance]) -> None:
        """
        Insert EC2 instance records.

        Args:
            instances: List of EC2 instances to insert
        """
        if not instances:
            return

        with self._get_connection() as conn:
            cursor = conn.cursor()
            for instance in instances:
                cursor.execute(
                    """
                    INSERT INTO ec2_instances (
                        scan_id, instance_id, region, instance_type, state,
                        public_ip, private_ip, vpc_id, subnet_id, availability_zone,
                        launch_time, platform, security_groups, tags,
                        iam_instance_profile, monitoring_state, raw_data
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        instance.scan_id,
                        instance.instance_id,
                        instance.region,
                        instance.instance_type,
                        instance.state,
                        instance.public_ip,
                        instance.private_ip,
                        instance.vpc_id,
                        instance.subnet_id,
                        instance.availability_zone,
                        instance.launch_time.isoformat(),
                        instance.platform,
                        json.dumps(instance.security_groups, default=json_serial),
                        json.dumps(instance.tags, default=json_serial),
                        instance.iam_instance_profile,
                        instance.monitoring_state,
                        json.dumps(instance.raw_data, default=json_serial),
                    ),
                )
            conn.commit()
            logger.debug(f"Inserted {len(instances)} EC2 instances")

    def insert_vpcs(self, vpcs: List[VPC]) -> None:
        """Insert VPC records."""
        if not vpcs:
            return

        with self._get_connection() as conn:
            cursor = conn.cursor()
            for vpc in vpcs:
                cursor.execute(
                    """
                    INSERT INTO vpcs (
                        scan_id, vpc_id, region, cidr_block, state,
                        is_default, dhcp_options_id, instance_tenancy, tags, raw_data
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        vpc.scan_id,
                        vpc.vpc_id,
                        vpc.region,
                        vpc.cidr_block,
                        vpc.state,
                        1 if vpc.is_default else 0,
                        vpc.dhcp_options_id,
                        vpc.instance_tenancy,
                        json.dumps(vpc.tags, default=json_serial),
                        json.dumps(vpc.raw_data, default=json_serial),
                    ),
                )
            conn.commit()
            logger.debug(f"Inserted {len(vpcs)} VPCs")

    def insert_subnets(self, subnets: List[Subnet]) -> None:
        """Insert subnet records."""
        if not subnets:
            return

        with self._get_connection() as conn:
            cursor = conn.cursor()
            for subnet in subnets:
                cursor.execute(
                    """
                    INSERT INTO subnets (
                        scan_id, subnet_id, vpc_id, region, cidr_block,
                        availability_zone, available_ip_count, map_public_ip,
                        state, tags, raw_data
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        subnet.scan_id,
                        subnet.subnet_id,
                        subnet.vpc_id,
                        subnet.region,
                        subnet.cidr_block,
                        subnet.availability_zone,
                        subnet.available_ip_count,
                        1 if subnet.map_public_ip else 0,
                        subnet.state,
                        json.dumps(subnet.tags, default=json_serial),
                        json.dumps(subnet.raw_data, default=json_serial),
                    ),
                )
            conn.commit()
            logger.debug(f"Inserted {len(subnets)} subnets")

    def insert_security_groups(self, security_groups: List[SecurityGroup]) -> None:
        """Insert security group records."""
        if not security_groups:
            return

        with self._get_connection() as conn:
            cursor = conn.cursor()
            for sg in security_groups:
                cursor.execute(
                    """
                    INSERT INTO security_groups (
                        scan_id, group_id, group_name, vpc_id, region,
                        description, ingress_rules, egress_rules, tags, raw_data
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        sg.scan_id,
                        sg.group_id,
                        sg.group_name,
                        sg.vpc_id,
                        sg.region,
                        sg.description,
                        json.dumps(sg.ingress_rules, default=json_serial),
                        json.dumps(sg.egress_rules, default=json_serial),
                        json.dumps(sg.tags, default=json_serial),
                        json.dumps(sg.raw_data, default=json_serial),
                    ),
                )
            conn.commit()
            logger.debug(f"Inserted {len(security_groups)} security groups")

    def insert_s3_buckets(self, buckets: List[S3Bucket]) -> None:
        """Insert S3 bucket records."""
        if not buckets:
            return

        with self._get_connection() as conn:
            cursor = conn.cursor()
            for bucket in buckets:
                cursor.execute(
                    """
                    INSERT INTO s3_buckets (
                        scan_id, bucket_name, creation_date, region,
                        versioning_status, public_access_block, encryption_config,
                        lifecycle_rules, logging_enabled, size_bytes, object_count,
                        tags, raw_data
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        bucket.scan_id,
                        bucket.bucket_name,
                        bucket.creation_date.isoformat(),
                        bucket.region,
                        bucket.versioning_status,
                        json.dumps(bucket.public_access_block, default=json_serial)
                        if bucket.public_access_block
                        else None,
                        json.dumps(bucket.encryption_config, default=json_serial)
                        if bucket.encryption_config
                        else None,
                        json.dumps(bucket.lifecycle_rules, default=json_serial),
                        1 if bucket.logging_enabled else 0,
                        bucket.size_bytes,
                        bucket.object_count,
                        json.dumps(bucket.tags, default=json_serial),
                        json.dumps(bucket.raw_data, default=json_serial),
                    ),
                )
            conn.commit()
            logger.debug(f"Inserted {len(buckets)} S3 buckets")

    def insert_iam_users(self, users: List[IAMUser]) -> None:
        """Insert IAM user records."""
        if not users:
            return

        with self._get_connection() as conn:
            cursor = conn.cursor()
            for user in users:
                cursor.execute(
                    """
                    INSERT INTO iam_users (
                        scan_id, user_name, user_id, arn, create_date,
                        password_last_used, mfa_enabled, access_keys,
                        attached_policies, groups, tags, raw_data
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        user.scan_id,
                        user.user_name,
                        user.user_id,
                        user.arn,
                        user.create_date.isoformat(),
                        user.password_last_used.isoformat()
                        if user.password_last_used
                        else None,
                        1 if user.mfa_enabled else 0,
                        json.dumps(user.access_keys, default=json_serial),
                        json.dumps(user.attached_policies, default=json_serial),
                        json.dumps(user.groups, default=json_serial),
                        json.dumps(user.tags, default=json_serial),
                        json.dumps(user.raw_data, default=json_serial),
                    ),
                )
            conn.commit()
            logger.debug(f"Inserted {len(users)} IAM users")

    def insert_iam_roles(self, roles: List[IAMRole]) -> None:
        """Insert IAM role records."""
        if not roles:
            return

        with self._get_connection() as conn:
            cursor = conn.cursor()
            for role in roles:
                cursor.execute(
                    """
                    INSERT INTO iam_roles (
                        scan_id, role_name, role_id, arn, create_date,
                        assume_role_policy, attached_policies, max_session_duration,
                        tags, raw_data
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        role.scan_id,
                        role.role_name,
                        role.role_id,
                        role.arn,
                        role.create_date.isoformat(),
                        json.dumps(role.assume_role_policy, default=json_serial),
                        json.dumps(role.attached_policies, default=json_serial),
                        role.max_session_duration,
                        json.dumps(role.tags, default=json_serial),
                        json.dumps(role.raw_data, default=json_serial),
                    ),
                )
            conn.commit()
            logger.debug(f"Inserted {len(roles)} IAM roles")

    def insert_prowler_findings(self, findings: List[ProwlerFinding]) -> None:
        """Insert Prowler security findings."""
        if not findings:
            return

        with self._get_connection() as conn:
            cursor = conn.cursor()
            for finding in findings:
                cursor.execute(
                    """
                    INSERT INTO prowler_findings (
                        scan_id, check_id, check_title, severity, status,
                        region, resource_id, resource_arn, resource_tags,
                        status_extended, service_name, check_type, risk,
                        remediation, compliance_frameworks, raw_data
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        finding.scan_id,
                        finding.check_id,
                        finding.check_title,
                        finding.severity,
                        finding.status,
                        finding.region,
                        finding.resource_id,
                        finding.resource_arn,
                        json.dumps(finding.resource_tags, default=json_serial),
                        finding.status_extended,
                        finding.service_name,
                        finding.check_type,
                        finding.risk,
                        finding.remediation,
                        json.dumps(finding.compliance_frameworks, default=json_serial),
                        json.dumps(finding.raw_data, default=json_serial),
                    ),
                )
            conn.commit()
            logger.debug(f"Inserted {len(findings)} Prowler findings")

    def insert_load_balancers(self, load_balancers: List[LoadBalancer]) -> None:
        """Insert load balancer records."""
        if not load_balancers:
            return

        with self._get_connection() as conn:
            cursor = conn.cursor()
            for lb in load_balancers:
                cursor.execute(
                    """
                    INSERT INTO load_balancers (
                        scan_id, load_balancer_name, load_balancer_arn, load_balancer_type,
                        region, vpc_id, scheme, state, dns_name, availability_zones,
                        security_groups, subnets, created_time, listeners, target_groups,
                        tags, raw_data
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        lb.scan_id,
                        lb.load_balancer_name,
                        lb.load_balancer_arn,
                        lb.load_balancer_type,
                        lb.region,
                        lb.vpc_id,
                        lb.scheme,
                        lb.state,
                        lb.dns_name,
                        json.dumps(lb.availability_zones, default=json_serial),
                        json.dumps(lb.security_groups, default=json_serial),
                        json.dumps(lb.subnets, default=json_serial),
                        lb.created_time.isoformat() if lb.created_time else None,
                        json.dumps(lb.listeners, default=json_serial),
                        json.dumps(lb.target_groups, default=json_serial),
                        json.dumps(lb.tags, default=json_serial),
                        json.dumps(lb.raw_data, default=json_serial),
                    ),
                )
            conn.commit()
            logger.debug(f"Inserted {len(load_balancers)} load balancers")

    def insert_nat_gateways(self, nat_gateways: List[NATGateway]) -> None:
        """Insert NAT gateway records."""
        if not nat_gateways:
            return

        with self._get_connection() as conn:
            cursor = conn.cursor()
            for nat in nat_gateways:
                cursor.execute(
                    """
                    INSERT INTO nat_gateways (
                        scan_id, nat_gateway_id, region, vpc_id, subnet_id, state,
                        connectivity_type, public_ip, private_ip, created_time,
                        nat_gateway_addresses, tags, raw_data
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        nat.scan_id,
                        nat.nat_gateway_id,
                        nat.region,
                        nat.vpc_id,
                        nat.subnet_id,
                        nat.state,
                        nat.connectivity_type,
                        nat.public_ip,
                        nat.private_ip,
                        nat.created_time.isoformat() if nat.created_time else None,
                        json.dumps(nat.nat_gateway_addresses, default=json_serial),
                        json.dumps(nat.tags, default=json_serial),
                        json.dumps(nat.raw_data, default=json_serial),
                    ),
                )
            conn.commit()
            logger.debug(f"Inserted {len(nat_gateways)} NAT gateways")

    def insert_internet_gateways(
        self, internet_gateways: List[InternetGateway]
    ) -> None:
        """Insert internet gateway records."""
        if not internet_gateways:
            return

        with self._get_connection() as conn:
            cursor = conn.cursor()
            for igw in internet_gateways:
                cursor.execute(
                    """
                    INSERT INTO internet_gateways (
                        scan_id, internet_gateway_id, region, vpc_attachments, tags, raw_data
                    ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                    (
                        igw.scan_id,
                        igw.internet_gateway_id,
                        igw.region,
                        json.dumps(igw.vpc_attachments, default=json_serial),
                        json.dumps(igw.tags, default=json_serial),
                        json.dumps(igw.raw_data, default=json_serial),
                    ),
                )
            conn.commit()
            logger.debug(f"Inserted {len(internet_gateways)} internet gateways")

    def insert_route_tables(self, route_tables: List[RouteTable]) -> None:
        """Insert route table records."""
        if not route_tables:
            return

        with self._get_connection() as conn:
            cursor = conn.cursor()
            for rt in route_tables:
                cursor.execute(
                    """
                    INSERT INTO route_tables (
                        scan_id, route_table_id, region, vpc_id, is_main, routes,
                        subnet_associations, gateway_associations, tags, raw_data
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        rt.scan_id,
                        rt.route_table_id,
                        rt.region,
                        rt.vpc_id,
                        1 if rt.is_main else 0,
                        json.dumps(rt.routes, default=json_serial),
                        json.dumps(rt.subnet_associations, default=json_serial),
                        json.dumps(rt.gateway_associations, default=json_serial),
                        json.dumps(rt.tags, default=json_serial),
                        json.dumps(rt.raw_data, default=json_serial),
                    ),
                )
            conn.commit()
            logger.debug(f"Inserted {len(route_tables)} route tables")

    def insert_auto_scaling_groups(
        self, auto_scaling_groups: List[AutoScalingGroup]
    ) -> None:
        """Insert Auto Scaling group records."""
        if not auto_scaling_groups:
            return

        with self._get_connection() as conn:
            cursor = conn.cursor()
            for asg in auto_scaling_groups:
                cursor.execute(
                    """
                    INSERT INTO auto_scaling_groups (
                        scan_id, auto_scaling_group_name, auto_scaling_group_arn, region,
                        launch_configuration_name, launch_template, min_size, max_size,
                        desired_capacity, default_cooldown, availability_zones, load_balancer_names,
                        target_group_arns, health_check_type, health_check_grace_period,
                        vpc_zone_identifier, instances, created_time, tags, raw_data
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        asg.scan_id,
                        asg.auto_scaling_group_name,
                        asg.auto_scaling_group_arn,
                        asg.region,
                        asg.launch_configuration_name,
                        json.dumps(asg.launch_template, default=json_serial)
                        if asg.launch_template
                        else None,
                        asg.min_size,
                        asg.max_size,
                        asg.desired_capacity,
                        asg.default_cooldown,
                        json.dumps(asg.availability_zones, default=json_serial),
                        json.dumps(asg.load_balancer_names, default=json_serial),
                        json.dumps(asg.target_group_arns, default=json_serial),
                        asg.health_check_type,
                        asg.health_check_grace_period,
                        asg.vpc_zone_identifier,
                        json.dumps(asg.instances, default=json_serial),
                        asg.created_time.isoformat(),
                        json.dumps(asg.tags, default=json_serial),
                        json.dumps(asg.raw_data, default=json_serial),
                    ),
                )
            conn.commit()
            logger.debug(f"Inserted {len(auto_scaling_groups)} Auto Scaling groups")

    def insert_network_interfaces(
        self, network_interfaces: List[NetworkInterface]
    ) -> None:
        """Insert network interface records."""
        if not network_interfaces:
            return

        with self._get_connection() as conn:
            cursor = conn.cursor()
            for eni in network_interfaces:
                cursor.execute(
                    """
                    INSERT INTO network_interfaces (
                        scan_id, network_interface_id, region, interface_type, status,
                        vpc_id, subnet_id, availability_zone, description, private_ip_address,
                        private_ip_addresses, public_ip, mac_address, source_dest_check,
                        security_groups, attachment, tags, raw_data
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        eni.scan_id,
                        eni.network_interface_id,
                        eni.region,
                        eni.interface_type,
                        eni.status,
                        eni.vpc_id,
                        eni.subnet_id,
                        eni.availability_zone,
                        eni.description,
                        eni.private_ip_address,
                        json.dumps(eni.private_ip_addresses, default=json_serial),
                        eni.public_ip,
                        eni.mac_address,
                        1 if eni.source_dest_check else 0,
                        json.dumps(eni.security_groups, default=json_serial),
                        json.dumps(eni.attachment, default=json_serial)
                        if eni.attachment
                        else None,
                        json.dumps(eni.tags, default=json_serial),
                        json.dumps(eni.raw_data, default=json_serial),
                    ),
                )
            conn.commit()
            logger.debug(f"Inserted {len(network_interfaces)} network interfaces")

    def insert_workspaces(self, workspaces: List[WorkSpace]) -> None:
        """Insert WorkSpaces records."""
        if not workspaces:
            return

        with self._get_connection() as conn:
            cursor = conn.cursor()
            for workspace in workspaces:
                cursor.execute(
                    """
                    INSERT INTO workspaces (
                        scan_id, workspace_id, region, directory_id, user_name,
                        bundle_id, subnet_id, vpc_id, ip_address, state,
                        compute_type, volume_encryption_enabled, user_volume_size_gb,
                        root_volume_size_gb, running_mode, tags, raw_data
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        workspace.scan_id,
                        workspace.workspace_id,
                        workspace.region,
                        workspace.directory_id,
                        workspace.user_name,
                        workspace.bundle_id,
                        workspace.subnet_id,
                        workspace.vpc_id,
                        workspace.ip_address,
                        workspace.state,
                        workspace.compute_type,
                        1 if workspace.volume_encryption_enabled else 0,
                        workspace.user_volume_size_gb,
                        workspace.root_volume_size_gb,
                        workspace.running_mode,
                        json.dumps(workspace.tags, default=json_serial),
                        json.dumps(workspace.raw_data, default=json_serial),
                    ),
                )
            conn.commit()
            logger.debug(f"Inserted {len(workspaces)} WorkSpaces")

    def insert_lambda_functions(self, lambda_functions: List[LambdaFunction]) -> None:
        """Insert Lambda function records."""
        if not lambda_functions:
            return

        with self._get_connection() as conn:
            cursor = conn.cursor()
            for func in lambda_functions:
                cursor.execute(
                    """
                    INSERT INTO lambda_functions (
                        scan_id, function_name, function_arn, region, runtime,
                        handler, code_size, memory_size, timeout, last_modified,
                        role_arn, vpc_config, environment_variables, layers,
                        state, architectures, triggers, tags, raw_data
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        func.scan_id,
                        func.function_name,
                        func.function_arn,
                        func.region,
                        func.runtime,
                        func.handler,
                        func.code_size,
                        func.memory_size,
                        func.timeout,
                        func.last_modified.isoformat(),
                        func.role_arn,
                        json.dumps(func.vpc_config, default=json_serial)
                        if func.vpc_config
                        else None,
                        json.dumps(func.environment_variables, default=json_serial),
                        json.dumps(func.layers, default=json_serial),
                        func.state,
                        json.dumps(func.architectures, default=json_serial),
                        json.dumps(func.triggers, default=json_serial),
                        json.dumps(func.tags, default=json_serial),
                        json.dumps(func.raw_data, default=json_serial),
                    ),
                )
            conn.commit()
            logger.debug(f"Inserted {len(lambda_functions)} Lambda functions")

    def insert_vpc_flow_logs(self, vpc_flow_logs: List[VPCFlowLog]) -> None:
        """Insert VPC Flow Log records."""
        if not vpc_flow_logs:
            return

        with self._get_connection() as conn:
            cursor = conn.cursor()
            for flow_log in vpc_flow_logs:
                cursor.execute(
                    """
                    INSERT INTO vpc_flow_logs (
                        scan_id, flow_log_id, region, resource_id, resource_type,
                        traffic_type, log_destination_type, log_destination,
                        log_format, flow_log_status, created_time, tags, raw_data
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        flow_log.scan_id,
                        flow_log.flow_log_id,
                        flow_log.region,
                        flow_log.resource_id,
                        flow_log.resource_type,
                        flow_log.traffic_type,
                        flow_log.log_destination_type,
                        flow_log.log_destination,
                        flow_log.log_format,
                        flow_log.flow_log_status,
                        flow_log.created_time.isoformat()
                        if flow_log.created_time
                        else None,
                        json.dumps(flow_log.tags, default=json_serial),
                        json.dumps(flow_log.raw_data, default=json_serial),
                    ),
                )
            conn.commit()
            logger.debug(f"Inserted {len(vpc_flow_logs)} VPC Flow Logs")

    def insert_cost_data(self, cost_records: List[CostData]) -> None:
        """Insert cost and billing data records."""
        if not cost_records:
            return

        with self._get_connection() as conn:
            cursor = conn.cursor()
            for cost in cost_records:
                cursor.execute(
                    """
                    INSERT INTO cost_data (
                        scan_id, account_number, time_period_start, time_period_end,
                        service_name, amount, currency, unit, raw_data
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        cost.scan_id,
                        cost.account_number,
                        cost.time_period_start.isoformat(),
                        cost.time_period_end.isoformat(),
                        cost.service_name,
                        cost.amount,
                        cost.currency,
                        cost.unit,
                        json.dumps(cost.raw_data, default=json_serial),
                    ),
                )
            conn.commit()
            logger.debug(f"Inserted {len(cost_records)} cost data records")

    def insert_route53_hosted_zones(
        self, hosted_zones: List[Route53HostedZone]
    ) -> None:
        """Insert Route53 hosted zone records."""
        if not hosted_zones:
            return

        with self._get_connection() as conn:
            cursor = conn.cursor()
            for zone in hosted_zones:
                cursor.execute(
                    """
                    INSERT INTO route53_hosted_zones (
                        scan_id, hosted_zone_id, name, is_private,
                        resource_record_set_count, vpc_associations, tags, raw_data
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        zone.scan_id,
                        zone.hosted_zone_id,
                        zone.name,
                        1 if zone.is_private else 0,
                        zone.resource_record_set_count,
                        json.dumps(zone.vpc_associations, default=json_serial),
                        json.dumps(zone.tags, default=json_serial),
                        json.dumps(zone.raw_data, default=json_serial),
                    ),
                )
            conn.commit()
            logger.debug(f"Inserted {len(hosted_zones)} Route53 hosted zones")

    def insert_route53_record_sets(self, record_sets: List[Route53RecordSet]) -> None:
        """Insert Route53 DNS record set records."""
        if not record_sets:
            return

        with self._get_connection() as conn:
            cursor = conn.cursor()
            for record in record_sets:
                cursor.execute(
                    """
                    INSERT INTO route53_record_sets (
                        scan_id, hosted_zone_id, name, record_type, ttl,
                        resource_records, alias_target, raw_data
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        record.scan_id,
                        record.hosted_zone_id,
                        record.name,
                        record.record_type,
                        record.ttl,
                        json.dumps(record.resource_records, default=json_serial),
                        json.dumps(record.alias_target, default=json_serial)
                        if record.alias_target
                        else None,
                        json.dumps(record.raw_data, default=json_serial),
                    ),
                )
            conn.commit()
            logger.debug(f"Inserted {len(record_sets)} Route53 record sets")

    def insert_ebs_volumes(self, volumes: List[EBSVolume]) -> None:
        """Insert EBS volume records."""
        if not volumes:
            return

        with self._get_connection() as conn:
            cursor = conn.cursor()
            for volume in volumes:
                cursor.execute(
                    """
                    INSERT INTO ebs_volumes (
                        scan_id, volume_id, region, size, volume_type,
                        iops, throughput, encrypted, kms_key_id, state,
                        create_time, availability_zone, snapshot_id,
                        attached_instance_id, device_name, attachment_state,
                        multi_attach_enabled, tags, raw_data
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        volume.scan_id,
                        volume.volume_id,
                        volume.region,
                        volume.size,
                        volume.volume_type,
                        volume.iops,
                        volume.throughput,
                        1 if volume.encrypted else 0,
                        volume.kms_key_id,
                        volume.state,
                        volume.create_time.isoformat(),
                        volume.availability_zone,
                        volume.snapshot_id,
                        volume.attached_instance_id,
                        volume.device_name,
                        volume.attachment_state,
                        1 if volume.multi_attach_enabled else 0,
                        json.dumps(volume.tags, default=json_serial),
                        json.dumps(volume.raw_data, default=json_serial),
                    ),
                )
            conn.commit()
            logger.debug(f"Inserted {len(volumes)} EBS volumes")

    def insert_ebs_snapshots(self, snapshots: List[EBSSnapshot]) -> None:
        """Insert EBS snapshot records."""
        if not snapshots:
            return

        with self._get_connection() as conn:
            cursor = conn.cursor()
            for snapshot in snapshots:
                cursor.execute(
                    """
                    INSERT INTO ebs_snapshots (
                        scan_id, snapshot_id, region, volume_id, volume_size,
                        encrypted, kms_key_id, state, start_time, progress,
                        owner_id, description, tags, raw_data
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        snapshot.scan_id,
                        snapshot.snapshot_id,
                        snapshot.region,
                        snapshot.volume_id,
                        snapshot.volume_size,
                        1 if snapshot.encrypted else 0,
                        snapshot.kms_key_id,
                        snapshot.state,
                        snapshot.start_time.isoformat(),
                        snapshot.progress,
                        snapshot.owner_id,
                        snapshot.description,
                        json.dumps(snapshot.tags, default=json_serial),
                        json.dumps(snapshot.raw_data, default=json_serial),
                    ),
                )
            conn.commit()
            logger.debug(f"Inserted {len(snapshots)} EBS snapshots")

    def insert_rds_instances(self, rds_instances: List[RDSInstance]) -> None:
        """Insert RDS instance records."""
        if not rds_instances:
            return

        with self._get_connection() as conn:
            cursor = conn.cursor()
            for instance in rds_instances:
                cursor.execute(
                    """
                    INSERT INTO rds_instances (
                        scan_id, db_instance_identifier, region, db_instance_arn,
                        engine, engine_version, db_instance_class, allocated_storage,
                        storage_type, iops, multi_az, availability_zone,
                        secondary_availability_zone, publicly_accessible, encrypted,
                        kms_key_id, vpc_id, subnet_group, vpc_security_groups,
                        backup_retention_period, preferred_backup_window,
                        latest_restorable_time, endpoint_address, endpoint_port,
                        db_instance_status, monitoring_interval,
                        performance_insights_enabled, auto_minor_version_upgrade,
                        deletion_protection, tags, raw_data
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        instance.scan_id,
                        instance.db_instance_identifier,
                        instance.region,
                        instance.db_instance_arn,
                        instance.engine,
                        instance.engine_version,
                        instance.db_instance_class,
                        instance.allocated_storage,
                        instance.storage_type,
                        instance.iops,
                        1 if instance.multi_az else 0,
                        instance.availability_zone,
                        instance.secondary_availability_zone,
                        1 if instance.publicly_accessible else 0,
                        1 if instance.encrypted else 0,
                        instance.kms_key_id,
                        instance.vpc_id,
                        instance.subnet_group,
                        json.dumps(instance.vpc_security_groups, default=json_serial),
                        instance.backup_retention_period,
                        instance.preferred_backup_window,
                        instance.latest_restorable_time.isoformat()
                        if instance.latest_restorable_time
                        else None,
                        instance.endpoint_address,
                        instance.endpoint_port,
                        instance.db_instance_status,
                        instance.monitoring_interval,
                        1 if instance.performance_insights_enabled else 0,
                        1 if instance.auto_minor_version_upgrade else 0,
                        1 if instance.deletion_protection else 0,
                        json.dumps(instance.tags, default=json_serial),
                        json.dumps(instance.raw_data, default=json_serial),
                    ),
                )
            conn.commit()
            logger.debug(f"Inserted {len(rds_instances)} RDS instances")

    def insert_iam_policies(self, policies: List[IAMPolicy]) -> None:
        """Insert IAM policy records."""
        if not policies:
            return

        with self._get_connection() as conn:
            cursor = conn.cursor()
            for policy in policies:
                cursor.execute(
                    """
                    INSERT INTO iam_policies (
                        scan_id, policy_arn, policy_name, policy_id, path,
                        default_version_id, attachment_count,
                        permissions_boundary_usage_count, is_attachable,
                        description, create_date, update_date, policy_document,
                        attached_users, attached_roles, attached_groups,
                        tags, raw_data
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        policy.scan_id,
                        policy.policy_arn,
                        policy.policy_name,
                        policy.policy_id,
                        policy.path,
                        policy.default_version_id,
                        policy.attachment_count,
                        policy.permissions_boundary_usage_count,
                        1 if policy.is_attachable else 0,
                        policy.description,
                        policy.create_date.isoformat(),
                        policy.update_date.isoformat(),
                        json.dumps(policy.policy_document, default=json_serial),
                        json.dumps(policy.attached_users, default=json_serial),
                        json.dumps(policy.attached_roles, default=json_serial),
                        json.dumps(policy.attached_groups, default=json_serial),
                        json.dumps(policy.tags, default=json_serial),
                        json.dumps(policy.raw_data, default=json_serial),
                    ),
                )
            conn.commit()
            logger.debug(f"Inserted {len(policies)} IAM policies")

    def insert_kms_keys(self, kms_keys: List[KMSKey]) -> None:
        """Insert KMS key records."""
        if not kms_keys:
            return

        with self._get_connection() as conn:
            cursor = conn.cursor()
            for key in kms_keys:
                cursor.execute(
                    """
                    INSERT INTO kms_keys (
                        scan_id, key_id, key_arn, region, aws_account_id,
                        key_state, creation_date, key_manager, key_usage,
                        key_spec, description, enabled, deletion_date,
                        rotation_enabled, key_policy, aliases, tags, raw_data
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        key.scan_id,
                        key.key_id,
                        key.key_arn,
                        key.region,
                        key.aws_account_id,
                        key.key_state,
                        key.creation_date.isoformat(),
                        key.key_manager,
                        key.key_usage,
                        key.key_spec,
                        key.description,
                        1 if key.enabled else 0,
                        key.deletion_date.isoformat() if key.deletion_date else None,
                        1 if key.rotation_enabled else 0,
                        json.dumps(key.key_policy, default=json_serial),
                        json.dumps(key.aliases, default=json_serial),
                        json.dumps(key.tags, default=json_serial),
                        json.dumps(key.raw_data, default=json_serial),
                    ),
                )
            conn.commit()
            logger.debug(f"Inserted {len(kms_keys)} KMS keys")

    def insert_elastic_ips(self, elastic_ips: List[ElasticIP]) -> None:
        """Insert Elastic IP records."""
        if not elastic_ips:
            return

        with self._get_connection() as conn:
            cursor = conn.cursor()
            for eip in elastic_ips:
                cursor.execute(
                    """
                    INSERT INTO elastic_ips (
                        scan_id, allocation_id, region, public_ip, domain,
                        instance_id, network_interface_id,
                        network_interface_owner_id, private_ip_address,
                        association_id, is_associated, tags, raw_data
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        eip.scan_id,
                        eip.allocation_id,
                        eip.region,
                        eip.public_ip,
                        eip.domain,
                        eip.instance_id,
                        eip.network_interface_id,
                        eip.network_interface_owner_id,
                        eip.private_ip_address,
                        eip.association_id,
                        1 if eip.is_associated else 0,
                        json.dumps(eip.tags, default=json_serial),
                        json.dumps(eip.raw_data, default=json_serial),
                    ),
                )
            conn.commit()
            logger.debug(f"Inserted {len(elastic_ips)} Elastic IPs")

    # Phase 2: Containers & Application Services Insert Operations

    def insert_ecs_clusters(self, ecs_clusters: List[ECSCluster]) -> None:
        """Insert ECS cluster records."""
        if not ecs_clusters:
            return

        with self._get_connection() as conn:
            cursor = conn.cursor()
            for cluster in ecs_clusters:
                cursor.execute(
                    """
                    INSERT INTO ecs_clusters (
                        scan_id, cluster_arn, cluster_name, region, status,
                        registered_container_instances_count, running_tasks_count,
                        pending_tasks_count, active_services_count,
                        capacity_providers, default_capacity_provider_strategy,
                        settings, statistics, tags, raw_data
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        cluster.scan_id,
                        cluster.cluster_arn,
                        cluster.cluster_name,
                        cluster.region,
                        cluster.status,
                        cluster.registered_container_instances_count,
                        cluster.running_tasks_count,
                        cluster.pending_tasks_count,
                        cluster.active_services_count,
                        json.dumps(cluster.capacity_providers, default=json_serial),
                        json.dumps(
                            cluster.default_capacity_provider_strategy,
                            default=json_serial,
                        ),
                        json.dumps(cluster.settings, default=json_serial),
                        json.dumps(cluster.statistics, default=json_serial),
                        json.dumps(cluster.tags, default=json_serial),
                        json.dumps(cluster.raw_data, default=json_serial),
                    ),
                )
            conn.commit()
            logger.debug(f"Inserted {len(ecs_clusters)} ECS clusters")

    def insert_ecs_services(self, ecs_services: List[ECSService]) -> None:
        """Insert ECS service records."""
        if not ecs_services:
            return

        with self._get_connection() as conn:
            cursor = conn.cursor()
            for service in ecs_services:
                cursor.execute(
                    """
                    INSERT INTO ecs_services (
                        scan_id, service_arn, service_name, cluster_arn, region, status,
                        task_definition, desired_count, running_count, pending_count,
                        launch_type, platform_version, platform_family,
                        capacity_provider_strategy, network_configuration,
                        load_balancers, service_registries, deployment_configuration,
                        deployments, health_check_grace_period_seconds,
                        scheduling_strategy, created_at_svc, tags, raw_data
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        service.scan_id,
                        service.service_arn,
                        service.service_name,
                        service.cluster_arn,
                        service.region,
                        service.status,
                        service.task_definition,
                        service.desired_count,
                        service.running_count,
                        service.pending_count,
                        service.launch_type,
                        service.platform_version,
                        service.platform_family,
                        json.dumps(
                            service.capacity_provider_strategy, default=json_serial
                        ),
                        json.dumps(service.network_configuration, default=json_serial),
                        json.dumps(service.load_balancers, default=json_serial),
                        json.dumps(service.service_registries, default=json_serial),
                        json.dumps(
                            service.deployment_configuration, default=json_serial
                        ),
                        json.dumps(service.deployments, default=json_serial),
                        service.health_check_grace_period_seconds,
                        service.scheduling_strategy,
                        service.created_at.isoformat() if service.created_at else None,
                        json.dumps(service.tags, default=json_serial),
                        json.dumps(service.raw_data, default=json_serial),
                    ),
                )
            conn.commit()
            logger.debug(f"Inserted {len(ecs_services)} ECS services")

    def insert_ecs_task_definitions(
        self, ecs_task_definitions: List[ECSTaskDefinition]
    ) -> None:
        """Insert ECS task definition records."""
        if not ecs_task_definitions:
            return

        with self._get_connection() as conn:
            cursor = conn.cursor()
            for task_def in ecs_task_definitions:
                cursor.execute(
                    """
                    INSERT INTO ecs_task_definitions (
                        scan_id, task_definition_arn, family, revision, region, status,
                        requires_compatibilities, network_mode, cpu, memory,
                        task_role_arn, execution_role_arn, container_definitions,
                        volumes, placement_constraints, requires_attributes,
                        pid_mode, ipc_mode, proxy_configuration, ephemeral_storage,
                        runtime_platform, registered_at, deregistered_at,
                        registered_by, tags, raw_data
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        task_def.scan_id,
                        task_def.task_definition_arn,
                        task_def.family,
                        task_def.revision,
                        task_def.region,
                        task_def.status,
                        json.dumps(
                            task_def.requires_compatibilities, default=json_serial
                        ),
                        task_def.network_mode,
                        task_def.cpu,
                        task_def.memory,
                        task_def.task_role_arn,
                        task_def.execution_role_arn,
                        json.dumps(task_def.container_definitions, default=json_serial),
                        json.dumps(task_def.volumes, default=json_serial),
                        json.dumps(task_def.placement_constraints, default=json_serial),
                        json.dumps(task_def.requires_attributes, default=json_serial),
                        task_def.pid_mode,
                        task_def.ipc_mode,
                        json.dumps(task_def.proxy_configuration, default=json_serial)
                        if task_def.proxy_configuration
                        else None,
                        json.dumps(task_def.ephemeral_storage, default=json_serial)
                        if task_def.ephemeral_storage
                        else None,
                        json.dumps(task_def.runtime_platform, default=json_serial)
                        if task_def.runtime_platform
                        else None,
                        task_def.registered_at.isoformat()
                        if task_def.registered_at
                        else None,
                        task_def.deregistered_at.isoformat()
                        if task_def.deregistered_at
                        else None,
                        task_def.registered_by,
                        json.dumps(task_def.tags, default=json_serial),
                        json.dumps(task_def.raw_data, default=json_serial),
                    ),
                )
            conn.commit()
            logger.debug(f"Inserted {len(ecs_task_definitions)} ECS task definitions")

    def insert_eks_clusters(self, eks_clusters: List[EKSCluster]) -> None:
        """Insert EKS cluster records."""
        if not eks_clusters:
            return

        with self._get_connection() as conn:
            cursor = conn.cursor()
            for cluster in eks_clusters:
                cursor.execute(
                    """
                    INSERT INTO eks_clusters (
                        scan_id, cluster_name, cluster_arn, region, version, endpoint,
                        role_arn, status, vpc_id, subnet_ids, security_group_ids,
                        cluster_security_group_id, endpoint_public_access,
                        endpoint_private_access, public_access_cidrs,
                        resources_vpc_config, logging, identity, encryption_config,
                        platform_version, created_at_eks, tags, raw_data
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        cluster.scan_id,
                        cluster.cluster_name,
                        cluster.cluster_arn,
                        cluster.region,
                        cluster.version,
                        cluster.endpoint,
                        cluster.role_arn,
                        cluster.status,
                        cluster.vpc_id,
                        json.dumps(cluster.subnet_ids, default=json_serial),
                        json.dumps(cluster.security_group_ids, default=json_serial),
                        cluster.cluster_security_group_id,
                        1 if cluster.endpoint_public_access else 0,
                        1 if cluster.endpoint_private_access else 0,
                        json.dumps(cluster.public_access_cidrs, default=json_serial),
                        json.dumps(cluster.resources_vpc_config, default=json_serial),
                        json.dumps(cluster.logging, default=json_serial),
                        json.dumps(cluster.identity, default=json_serial)
                        if cluster.identity
                        else None,
                        json.dumps(cluster.encryption_config, default=json_serial),
                        cluster.platform_version,
                        cluster.created_at.isoformat() if cluster.created_at else None,
                        json.dumps(cluster.tags, default=json_serial),
                        json.dumps(cluster.raw_data, default=json_serial),
                    ),
                )
            conn.commit()
            logger.debug(f"Inserted {len(eks_clusters)} EKS clusters")

    def insert_eks_node_groups(self, eks_node_groups: List[EKSNodeGroup]) -> None:
        """Insert EKS node group records."""
        if not eks_node_groups:
            return

        with self._get_connection() as conn:
            cursor = conn.cursor()
            for node_group in eks_node_groups:
                cursor.execute(
                    """
                    INSERT INTO eks_node_groups (
                        scan_id, cluster_name, nodegroup_name, nodegroup_arn, region,
                        status, scaling_config, instance_types, ami_type,
                        release_version, subnets, remote_access, node_role,
                        labels, taints, disk_size, capacity_type, launch_template,
                        update_config, health, created_at_ng, modified_at, tags, raw_data
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        node_group.scan_id,
                        node_group.cluster_name,
                        node_group.nodegroup_name,
                        node_group.nodegroup_arn,
                        node_group.region,
                        node_group.status,
                        json.dumps(node_group.scaling_config, default=json_serial),
                        json.dumps(node_group.instance_types, default=json_serial),
                        node_group.ami_type,
                        node_group.release_version,
                        json.dumps(node_group.subnets, default=json_serial),
                        json.dumps(node_group.remote_access, default=json_serial)
                        if node_group.remote_access
                        else None,
                        node_group.node_role,
                        json.dumps(node_group.labels, default=json_serial),
                        json.dumps(node_group.taints, default=json_serial),
                        node_group.disk_size,
                        node_group.capacity_type,
                        json.dumps(node_group.launch_template, default=json_serial)
                        if node_group.launch_template
                        else None,
                        json.dumps(node_group.update_config, default=json_serial)
                        if node_group.update_config
                        else None,
                        json.dumps(node_group.health, default=json_serial)
                        if node_group.health
                        else None,
                        node_group.created_at.isoformat()
                        if node_group.created_at
                        else None,
                        node_group.modified_at.isoformat()
                        if node_group.modified_at
                        else None,
                        json.dumps(node_group.tags, default=json_serial),
                        json.dumps(node_group.raw_data, default=json_serial),
                    ),
                )
            conn.commit()
            logger.debug(f"Inserted {len(eks_node_groups)} EKS node groups")

    def insert_ecr_repositories(self, ecr_repositories: List[ECRRepository]) -> None:
        """Insert ECR repository records."""
        if not ecr_repositories:
            return

        with self._get_connection() as conn:
            cursor = conn.cursor()
            for repo in ecr_repositories:
                cursor.execute(
                    """
                    INSERT INTO ecr_repositories (
                        scan_id, repository_arn, repository_name, repository_uri,
                        region, registry_id, image_scanning_configuration,
                        image_tag_mutability, encryption_configuration,
                        created_at_repo, tags, raw_data
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        repo.scan_id,
                        repo.repository_arn,
                        repo.repository_name,
                        repo.repository_uri,
                        repo.region,
                        repo.registry_id,
                        json.dumps(
                            repo.image_scanning_configuration, default=json_serial
                        ),
                        repo.image_tag_mutability,
                        json.dumps(repo.encryption_configuration, default=json_serial),
                        repo.created_at.isoformat() if repo.created_at else None,
                        json.dumps(repo.tags, default=json_serial),
                        json.dumps(repo.raw_data, default=json_serial),
                    ),
                )
            conn.commit()
            logger.debug(f"Inserted {len(ecr_repositories)} ECR repositories")

    def insert_ecr_images(self, ecr_images: List[ECRImage]) -> None:
        """Insert ECR image records."""
        if not ecr_images:
            return

        with self._get_connection() as conn:
            cursor = conn.cursor()
            for image in ecr_images:
                cursor.execute(
                    """
                    INSERT INTO ecr_images (
                        scan_id, repository_name, region, registry_id, image_digest,
                        image_tags, image_size_in_bytes, image_pushed_at,
                        image_scan_status, image_scan_findings_summary,
                        last_recorded_pull_time, artifact_media_type, raw_data
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        image.scan_id,
                        image.repository_name,
                        image.region,
                        image.registry_id,
                        image.image_digest,
                        json.dumps(image.image_tags, default=json_serial),
                        image.image_size_in_bytes,
                        image.image_pushed_at.isoformat()
                        if image.image_pushed_at
                        else None,
                        image.image_scan_status,
                        json.dumps(
                            image.image_scan_findings_summary, default=json_serial
                        )
                        if image.image_scan_findings_summary
                        else None,
                        image.last_recorded_pull_time.isoformat()
                        if image.last_recorded_pull_time
                        else None,
                        image.artifact_media_type,
                        json.dumps(image.raw_data, default=json_serial),
                    ),
                )
            conn.commit()
            logger.debug(f"Inserted {len(ecr_images)} ECR images")

    def insert_api_gateway_rest_apis(
        self, api_gateway_rest_apis: List[APIGatewayRestAPI]
    ) -> None:
        """Insert API Gateway REST API records."""
        if not api_gateway_rest_apis:
            return

        with self._get_connection() as conn:
            cursor = conn.cursor()
            for api in api_gateway_rest_apis:
                cursor.execute(
                    """
                    INSERT INTO api_gateway_rest_apis (
                        scan_id, api_id, name, region, description, endpoint_configuration,
                        version, created_date, api_key_source, policy,
                        minimum_compression_size, binary_media_types,
                        disable_execute_api_endpoint, tags, raw_data
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        api.scan_id,
                        api.api_id,
                        api.name,
                        api.region,
                        api.description,
                        json.dumps(api.endpoint_configuration, default=json_serial),
                        api.version,
                        api.created_date.isoformat() if api.created_date else None,
                        api.api_key_source,
                        api.policy,
                        api.minimum_compression_size,
                        json.dumps(api.binary_media_types, default=json_serial),
                        1 if api.disable_execute_api_endpoint else 0,
                        json.dumps(api.tags, default=json_serial),
                        json.dumps(api.raw_data, default=json_serial),
                    ),
                )
            conn.commit()
            logger.debug(f"Inserted {len(api_gateway_rest_apis)} API Gateway REST APIs")

    def insert_api_gateway_http_apis(
        self, api_gateway_http_apis: List[APIGatewayHttpAPI]
    ) -> None:
        """Insert API Gateway HTTP API records."""
        if not api_gateway_http_apis:
            return

        with self._get_connection() as conn:
            cursor = conn.cursor()
            for api in api_gateway_http_apis:
                cursor.execute(
                    """
                    INSERT INTO api_gateway_http_apis (
                        scan_id, api_id, name, region, protocol_type, description,
                        api_endpoint, cors_configuration, version,
                        route_selection_expression, disable_execute_api_endpoint,
                        disable_schema_validation, import_info, created_date,
                        tags, raw_data
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        api.scan_id,
                        api.api_id,
                        api.name,
                        api.region,
                        api.protocol_type,
                        api.description,
                        api.api_endpoint,
                        json.dumps(api.cors_configuration, default=json_serial)
                        if api.cors_configuration
                        else None,
                        api.version,
                        api.route_selection_expression,
                        1 if api.disable_execute_api_endpoint else 0,
                        1 if api.disable_schema_validation else 0,
                        json.dumps(api.import_info, default=json_serial),
                        api.created_date.isoformat() if api.created_date else None,
                        json.dumps(api.tags, default=json_serial),
                        json.dumps(api.raw_data, default=json_serial),
                    ),
                )
            conn.commit()
            logger.debug(f"Inserted {len(api_gateway_http_apis)} API Gateway HTTP APIs")

    def insert_api_gateway_stages(
        self, api_gateway_stages: List[APIGatewayStage]
    ) -> None:
        """Insert API Gateway stage records."""
        if not api_gateway_stages:
            return

        with self._get_connection() as conn:
            cursor = conn.cursor()
            for stage in api_gateway_stages:
                cursor.execute(
                    """
                    INSERT INTO api_gateway_stages (
                        scan_id, api_id, stage_name, region, api_type, deployment_id,
                        description, created_date, last_updated_date,
                        access_log_settings, client_certificate_id, throttle_settings,
                        method_settings, variables, tracing_enabled, web_acl_arn,
                        auto_deploy, route_settings, default_route_settings,
                        tags, raw_data
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        stage.scan_id,
                        stage.api_id,
                        stage.stage_name,
                        stage.region,
                        stage.api_type,
                        stage.deployment_id,
                        stage.description,
                        stage.created_date.isoformat() if stage.created_date else None,
                        stage.last_updated_date.isoformat()
                        if stage.last_updated_date
                        else None,
                        json.dumps(stage.access_log_settings, default=json_serial)
                        if stage.access_log_settings
                        else None,
                        stage.client_certificate_id,
                        json.dumps(stage.throttle_settings, default=json_serial)
                        if stage.throttle_settings
                        else None,
                        json.dumps(stage.method_settings, default=json_serial),
                        json.dumps(stage.variables, default=json_serial),
                        1 if stage.tracing_enabled else 0,
                        stage.web_acl_arn,
                        1 if stage.auto_deploy else 0,
                        json.dumps(stage.route_settings, default=json_serial),
                        json.dumps(stage.default_route_settings, default=json_serial)
                        if stage.default_route_settings
                        else None,
                        json.dumps(stage.tags, default=json_serial),
                        json.dumps(stage.raw_data, default=json_serial),
                    ),
                )
            conn.commit()
            logger.debug(f"Inserted {len(api_gateway_stages)} API Gateway stages")

    def insert_cloudfront_distributions(
        self, cloudfront_distributions: List[CloudFrontDistribution]
    ) -> None:
        """Insert CloudFront distribution records."""
        if not cloudfront_distributions:
            return

        with self._get_connection() as conn:
            cursor = conn.cursor()
            for dist in cloudfront_distributions:
                cursor.execute(
                    """
                    INSERT INTO cloudfront_distributions (
                        scan_id, distribution_id, distribution_arn, domain_name,
                        status, enabled, aliases, origins, origin_groups,
                        default_root_object, default_cache_behavior, cache_behaviors,
                        viewer_certificate, geo_restriction, web_acl_id, http_version,
                        is_ipv6_enabled, logging, price_class, custom_error_responses,
                        comment, last_modified_time, tags, raw_data
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        dist.scan_id,
                        dist.distribution_id,
                        dist.distribution_arn,
                        dist.domain_name,
                        dist.status,
                        1 if dist.enabled else 0,
                        json.dumps(dist.aliases, default=json_serial),
                        json.dumps(dist.origins, default=json_serial),
                        json.dumps(dist.origin_groups, default=json_serial),
                        dist.default_root_object,
                        json.dumps(dist.default_cache_behavior, default=json_serial),
                        json.dumps(dist.cache_behaviors, default=json_serial),
                        json.dumps(dist.viewer_certificate, default=json_serial),
                        json.dumps(dist.geo_restriction, default=json_serial)
                        if dist.geo_restriction
                        else None,
                        dist.web_acl_id,
                        dist.http_version,
                        1 if dist.is_ipv6_enabled else 0,
                        json.dumps(dist.logging, default=json_serial)
                        if dist.logging
                        else None,
                        dist.price_class,
                        json.dumps(dist.custom_error_responses, default=json_serial),
                        dist.comment,
                        dist.last_modified_time.isoformat()
                        if dist.last_modified_time
                        else None,
                        json.dumps(dist.tags, default=json_serial),
                        json.dumps(dist.raw_data, default=json_serial),
                    ),
                )
            conn.commit()
            logger.debug(
                f"Inserted {len(cloudfront_distributions)} CloudFront distributions"
            )

    # Phase 3: Governance, Logging & Advanced Services Operations

    def insert_organizations(self, organizations: List["Organization"]) -> None:
        """Insert AWS Organization records."""
        if not organizations:
            return

        with self._get_connection() as conn:
            cursor = conn.cursor()
            for org in organizations:
                cursor.execute(
                    """
                    INSERT INTO organizations (
                        scan_id, organization_id, organization_arn, master_account_id,
                        master_account_email, feature_set, available_policy_types, raw_data
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        org.scan_id,
                        org.organization_id,
                        org.organization_arn,
                        org.master_account_id,
                        org.master_account_email,
                        org.feature_set,
                        json.dumps(org.available_policy_types, default=json_serial),
                        json.dumps(org.raw_data, default=json_serial),
                    ),
                )
            conn.commit()
            logger.debug(f"Inserted {len(organizations)} organizations")

    def insert_organizational_units(self, ous: List["OrganizationalUnit"]) -> None:
        """Insert organizational unit records."""
        if not ous:
            return

        with self._get_connection() as conn:
            cursor = conn.cursor()
            for ou in ous:
                cursor.execute(
                    """
                    INSERT INTO organizational_units (
                        scan_id, ou_id, ou_arn, ou_name, parent_id, raw_data
                    ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                    (
                        ou.scan_id,
                        ou.ou_id,
                        ou.ou_arn,
                        ou.ou_name,
                        ou.parent_id,
                        json.dumps(ou.raw_data, default=json_serial),
                    ),
                )
            conn.commit()
            logger.debug(f"Inserted {len(ous)} organizational units")

    def insert_organization_accounts(
        self, accounts: List["OrganizationAccount"]
    ) -> None:
        """Insert organization account records."""
        if not accounts:
            return

        with self._get_connection() as conn:
            cursor = conn.cursor()
            for account in accounts:
                cursor.execute(
                    """
                    INSERT INTO organization_accounts (
                        scan_id, account_id, account_arn, account_name, email,
                        status, joined_method, joined_timestamp, parent_ou_id, raw_data
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        account.scan_id,
                        account.account_id,
                        account.account_arn,
                        account.account_name,
                        account.email,
                        account.status,
                        account.joined_method,
                        account.joined_timestamp.isoformat()
                        if account.joined_timestamp
                        else None,
                        account.parent_ou_id,
                        json.dumps(account.raw_data, default=json_serial),
                    ),
                )
            conn.commit()
            logger.debug(f"Inserted {len(accounts)} organization accounts")

    def insert_sso_permission_sets(
        self, permission_sets: List["SSOPermissionSet"]
    ) -> None:
        """Insert SSO permission set records."""
        if not permission_sets:
            return

        with self._get_connection() as conn:
            cursor = conn.cursor()
            for ps in permission_sets:
                cursor.execute(
                    """
                    INSERT INTO sso_permission_sets (
                        scan_id, permission_set_arn, permission_set_name, instance_arn,
                        description, session_duration, relay_state, created_date,
                        managed_policies, inline_policy, customer_managed_policies,
                        permissions_boundary, tags, raw_data
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        ps.scan_id,
                        ps.permission_set_arn,
                        ps.permission_set_name,
                        ps.instance_arn,
                        ps.description,
                        ps.session_duration,
                        ps.relay_state,
                        ps.created_date.isoformat() if ps.created_date else None,
                        json.dumps(ps.managed_policies, default=json_serial),
                        ps.inline_policy,
                        json.dumps(ps.customer_managed_policies, default=json_serial),
                        json.dumps(ps.permissions_boundary, default=json_serial)
                        if ps.permissions_boundary
                        else None,
                        json.dumps(ps.tags, default=json_serial),
                        json.dumps(ps.raw_data, default=json_serial),
                    ),
                )
            conn.commit()
            logger.debug(f"Inserted {len(permission_sets)} SSO permission sets")

    def insert_sso_assignments(self, assignments: List["SSOAssignment"]) -> None:
        """Insert SSO assignment records."""
        if not assignments:
            return

        with self._get_connection() as conn:
            cursor = conn.cursor()
            for assignment in assignments:
                cursor.execute(
                    """
                    INSERT INTO sso_assignments (
                        scan_id, instance_arn, permission_set_arn, principal_type,
                        principal_id, target_type, target_id, raw_data
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        assignment.scan_id,
                        assignment.instance_arn,
                        assignment.permission_set_arn,
                        assignment.principal_type,
                        assignment.principal_id,
                        assignment.target_type,
                        assignment.target_id,
                        json.dumps(assignment.raw_data, default=json_serial),
                    ),
                )
            conn.commit()
            logger.debug(f"Inserted {len(assignments)} SSO assignments")

    def insert_cloudtrail_trails(self, trails: List["CloudTrail"]) -> None:
        """Insert CloudTrail trail records."""
        if not trails:
            return

        with self._get_connection() as conn:
            cursor = conn.cursor()
            for trail in trails:
                cursor.execute(
                    """
                    INSERT INTO cloudtrail_trails (
                        scan_id, trail_name, trail_arn, region, s3_bucket_name,
                        s3_key_prefix, sns_topic_name, sns_topic_arn,
                        cloud_watch_logs_log_group_arn, cloud_watch_logs_role_arn,
                        kms_key_id, is_multi_region_trail, is_organization_trail,
                        include_global_service_events, is_logging, has_event_selectors,
                        has_insight_selectors, home_region, tags, raw_data
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        trail.scan_id,
                        trail.trail_name,
                        trail.trail_arn,
                        trail.region,
                        trail.s3_bucket_name,
                        trail.s3_key_prefix,
                        trail.sns_topic_name,
                        trail.sns_topic_arn,
                        trail.cloud_watch_logs_log_group_arn,
                        trail.cloud_watch_logs_role_arn,
                        trail.kms_key_id,
                        1 if trail.is_multi_region_trail else 0,
                        1 if trail.is_organization_trail else 0,
                        1 if trail.include_global_service_events else 0,
                        1 if trail.is_logging else 0,
                        1 if trail.has_event_selectors else 0,
                        1 if trail.has_insight_selectors else 0,
                        trail.home_region,
                        json.dumps(trail.tags, default=json_serial),
                        json.dumps(trail.raw_data, default=json_serial),
                    ),
                )
            conn.commit()
            logger.debug(f"Inserted {len(trails)} CloudTrail trails")

    def insert_cloudwatch_log_groups(
        self, log_groups: List["CloudWatchLogGroup"]
    ) -> None:
        """Insert CloudWatch log group records."""
        if not log_groups:
            return

        with self._get_connection() as conn:
            cursor = conn.cursor()
            for lg in log_groups:
                cursor.execute(
                    """
                    INSERT INTO cloudwatch_log_groups (
                        scan_id, log_group_name, log_group_arn, region, creation_time,
                        retention_in_days, stored_bytes, kms_key_id, metric_filter_count,
                        tags, raw_data
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        lg.scan_id,
                        lg.log_group_name,
                        lg.log_group_arn,
                        lg.region,
                        lg.creation_time.isoformat() if lg.creation_time else None,
                        lg.retention_in_days,
                        lg.stored_bytes,
                        lg.kms_key_id,
                        lg.metric_filter_count,
                        json.dumps(lg.tags, default=json_serial),
                        json.dumps(lg.raw_data, default=json_serial),
                    ),
                )
            conn.commit()
            logger.debug(f"Inserted {len(log_groups)} CloudWatch log groups")

    def insert_config_recorders(self, recorders: List["ConfigRecorder"]) -> None:
        """Insert AWS Config recorder records."""
        if not recorders:
            return

        with self._get_connection() as conn:
            cursor = conn.cursor()
            for recorder in recorders:
                cursor.execute(
                    """
                    INSERT INTO config_recorders (
                        scan_id, recorder_name, region, role_arn, recording_group,
                        is_recording, last_status, last_start_time, last_stop_time,
                        raw_data
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        recorder.scan_id,
                        recorder.recorder_name,
                        recorder.region,
                        recorder.role_arn,
                        json.dumps(recorder.recording_group, default=json_serial),
                        1 if recorder.is_recording else 0,
                        recorder.last_status,
                        recorder.last_start_time.isoformat()
                        if recorder.last_start_time
                        else None,
                        recorder.last_stop_time.isoformat()
                        if recorder.last_stop_time
                        else None,
                        json.dumps(recorder.raw_data, default=json_serial),
                    ),
                )
            conn.commit()
            logger.debug(f"Inserted {len(recorders)} Config recorders")

    def insert_config_rules(self, rules: List["ConfigRule"]) -> None:
        """Insert AWS Config rule records."""
        if not rules:
            return

        with self._get_connection() as conn:
            cursor = conn.cursor()
            for rule in rules:
                cursor.execute(
                    """
                    INSERT INTO config_rules (
                        scan_id, rule_name, rule_arn, rule_id, region, description,
                        scope, source, compliance_type, config_rule_state,
                        maximum_execution_frequency, raw_data
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        rule.scan_id,
                        rule.rule_name,
                        rule.rule_arn,
                        rule.rule_id,
                        rule.region,
                        rule.description,
                        json.dumps(rule.scope, default=json_serial)
                        if rule.scope
                        else None,
                        json.dumps(rule.source, default=json_serial),
                        rule.compliance_type,
                        rule.config_rule_state,
                        rule.maximum_execution_frequency,
                        json.dumps(rule.raw_data, default=json_serial),
                    ),
                )
            conn.commit()
            logger.debug(f"Inserted {len(rules)} Config rules")

    def insert_bedrock_models(self, models: List["BedrockModel"]) -> None:
        """Insert Bedrock model records."""
        if not models:
            return

        with self._get_connection() as conn:
            cursor = conn.cursor()
            for model in models:
                cursor.execute(
                    """
                    INSERT INTO bedrock_models (
                        scan_id, model_id, model_arn, model_name, region, provider_name,
                        customization_type, base_model_arn, inference_types_supported,
                        input_modalities, output_modalities, response_streaming_supported,
                        raw_data
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        model.scan_id,
                        model.model_id,
                        model.model_arn,
                        model.model_name,
                        model.region,
                        model.provider_name,
                        model.customization_type,
                        model.base_model_arn,
                        json.dumps(
                            model.inference_types_supported, default=json_serial
                        ),
                        json.dumps(model.input_modalities, default=json_serial),
                        json.dumps(model.output_modalities, default=json_serial),
                        1 if model.response_streaming_supported else 0,
                        json.dumps(model.raw_data, default=json_serial),
                    ),
                )
            conn.commit()
            logger.debug(f"Inserted {len(models)} Bedrock models")

    def insert_bedrock_guardrails(self, guardrails: List["BedrockGuardrail"]) -> None:
        """Insert Bedrock guardrail records."""
        if not guardrails:
            return

        with self._get_connection() as conn:
            cursor = conn.cursor()
            for gr in guardrails:
                cursor.execute(
                    """
                    INSERT INTO bedrock_guardrails (
                        scan_id, guardrail_id, guardrail_arn, guardrail_name, region,
                        version, description, status, content_policy_config,
                        topic_policy_config, word_policy_config,
                        sensitive_information_policy_config, blocked_input_messaging,
                        blocked_outputs_messaging, created_at_time, updated_at_time,
                        tags, raw_data
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        gr.scan_id,
                        gr.guardrail_id,
                        gr.guardrail_arn,
                        gr.guardrail_name,
                        gr.region,
                        gr.version,
                        gr.description,
                        gr.status,
                        json.dumps(gr.content_policy_config, default=json_serial)
                        if gr.content_policy_config
                        else None,
                        json.dumps(gr.topic_policy_config, default=json_serial)
                        if gr.topic_policy_config
                        else None,
                        json.dumps(gr.word_policy_config, default=json_serial)
                        if gr.word_policy_config
                        else None,
                        json.dumps(
                            gr.sensitive_information_policy_config, default=json_serial
                        )
                        if gr.sensitive_information_policy_config
                        else None,
                        gr.blocked_input_messaging,
                        gr.blocked_outputs_messaging,
                        gr.created_at.isoformat() if gr.created_at else None,
                        gr.updated_at.isoformat() if gr.updated_at else None,
                        json.dumps(gr.tags, default=json_serial),
                        json.dumps(gr.raw_data, default=json_serial),
                    ),
                )
            conn.commit()
            logger.debug(f"Inserted {len(guardrails)} Bedrock guardrails")

    def insert_bedrock_knowledge_bases(
        self, knowledge_bases: List["BedrockKnowledgeBase"]
    ) -> None:
        """Insert Bedrock knowledge base records."""
        if not knowledge_bases:
            return

        with self._get_connection() as conn:
            cursor = conn.cursor()
            for kb in knowledge_bases:
                cursor.execute(
                    """
                    INSERT INTO bedrock_knowledge_bases (
                        scan_id, knowledge_base_id, knowledge_base_arn, knowledge_base_name,
                        region, description, role_arn, knowledge_base_configuration,
                        storage_configuration, status, created_at_time, updated_at_time,
                        tags, raw_data
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        kb.scan_id,
                        kb.knowledge_base_id,
                        kb.knowledge_base_arn,
                        kb.knowledge_base_name,
                        kb.region,
                        kb.description,
                        kb.role_arn,
                        json.dumps(
                            kb.knowledge_base_configuration, default=json_serial
                        ),
                        json.dumps(kb.storage_configuration, default=json_serial),
                        kb.status,
                        kb.created_at.isoformat() if kb.created_at else None,
                        kb.updated_at.isoformat() if kb.updated_at else None,
                        json.dumps(kb.tags, default=json_serial),
                        json.dumps(kb.raw_data, default=json_serial),
                    ),
                )
            conn.commit()
            logger.debug(f"Inserted {len(knowledge_bases)} Bedrock knowledge bases")

    def insert_bedrock_agents(self, agents: List["BedrockAgent"]) -> None:
        """Insert Bedrock agent records."""
        if not agents:
            return

        with self._get_connection() as conn:
            cursor = conn.cursor()
            for agent in agents:
                cursor.execute(
                    """
                    INSERT INTO bedrock_agents (
                        scan_id, agent_id, agent_arn, agent_name, region, agent_version,
                        description, agent_resource_role_arn, foundation_model,
                        instruction, idle_session_ttl_in_seconds, agent_status,
                        created_at_time, updated_at_time, prepared_at_time, tags, raw_data
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        agent.scan_id,
                        agent.agent_id,
                        agent.agent_arn,
                        agent.agent_name,
                        agent.region,
                        agent.agent_version,
                        agent.description,
                        agent.agent_resource_role_arn,
                        agent.foundation_model,
                        agent.instruction,
                        agent.idle_session_ttl_in_seconds,
                        agent.agent_status,
                        agent.created_at.isoformat() if agent.created_at else None,
                        agent.updated_at.isoformat() if agent.updated_at else None,
                        agent.prepared_at.isoformat() if agent.prepared_at else None,
                        json.dumps(agent.tags, default=json_serial),
                        json.dumps(agent.raw_data, default=json_serial),
                    ),
                )
            conn.commit()
            logger.debug(f"Inserted {len(agents)} Bedrock agents")

    def insert_directory_services(self, directories: List["DirectoryService"]) -> None:
        """Insert Directory Service records."""
        if not directories:
            return

        with self._get_connection() as conn:
            cursor = conn.cursor()
            for directory in directories:
                cursor.execute(
                    """
                    INSERT INTO directory_services (
                        scan_id, directory_id, directory_name, region, directory_type,
                        size, edition, vpc_id, subnet_ids, dns_ip_addresses, access_url,
                        stage, sso_enabled, radius_status, launch_time,
                        stage_last_updated_date_time, description, alias, short_name,
                        tags, raw_data
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        directory.scan_id,
                        directory.directory_id,
                        directory.directory_name,
                        directory.region,
                        directory.directory_type,
                        directory.size,
                        directory.edition,
                        directory.vpc_id,
                        json.dumps(directory.subnet_ids, default=json_serial),
                        json.dumps(directory.dns_ip_addresses, default=json_serial),
                        directory.access_url,
                        directory.stage,
                        1 if directory.sso_enabled else 0,
                        directory.radius_status,
                        directory.launch_time.isoformat()
                        if directory.launch_time
                        else None,
                        directory.stage_last_updated_date_time.isoformat()
                        if directory.stage_last_updated_date_time
                        else None,
                        directory.description,
                        directory.alias,
                        directory.short_name,
                        json.dumps(directory.tags, default=json_serial),
                        json.dumps(directory.raw_data, default=json_serial),
                    ),
                )
            conn.commit()
            logger.debug(f"Inserted {len(directories)} directory services")

    def insert_transit_gateways(self, transit_gateways: List["TransitGateway"]) -> None:
        """Insert Transit Gateway records."""
        if not transit_gateways:
            return

        with self._get_connection() as conn:
            cursor = conn.cursor()
            for tgw in transit_gateways:
                cursor.execute(
                    """
                    INSERT INTO transit_gateways (
                        scan_id, transit_gateway_id, transit_gateway_arn, region, owner_id,
                        description, state, amazon_side_asn, default_route_table_id,
                        default_route_table_association, default_route_table_propagation,
                        vpn_ecmp_support, dns_support, multicast_support,
                        auto_accept_shared_attachments, transit_gateway_cidr_blocks,
                        creation_time, tags, raw_data
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        tgw.scan_id,
                        tgw.transit_gateway_id,
                        tgw.transit_gateway_arn,
                        tgw.region,
                        tgw.owner_id,
                        tgw.description,
                        tgw.state,
                        tgw.amazon_side_asn,
                        tgw.default_route_table_id,
                        tgw.default_route_table_association,
                        tgw.default_route_table_propagation,
                        tgw.vpn_ecmp_support,
                        tgw.dns_support,
                        tgw.multicast_support,
                        tgw.auto_accept_shared_attachments,
                        json.dumps(
                            tgw.transit_gateway_cidr_blocks, default=json_serial
                        ),
                        tgw.creation_time.isoformat() if tgw.creation_time else None,
                        json.dumps(tgw.tags, default=json_serial),
                        json.dumps(tgw.raw_data, default=json_serial),
                    ),
                )
            conn.commit()
            logger.debug(f"Inserted {len(transit_gateways)} transit gateways")

    def insert_vpn_connections(self, vpn_connections: List["VPNConnection"]) -> None:
        """Insert VPN connection records."""
        if not vpn_connections:
            return

        with self._get_connection() as conn:
            cursor = conn.cursor()
            for vpn in vpn_connections:
                cursor.execute(
                    """
                    INSERT INTO vpn_connections (
                        scan_id, vpn_connection_id, region, state, vpn_connection_type,
                        customer_gateway_id, vpn_gateway_id, transit_gateway_id,
                        customer_gateway_configuration, static_routes_only, vgw_telemetry,
                        routes, category, tags, raw_data
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        vpn.scan_id,
                        vpn.vpn_connection_id,
                        vpn.region,
                        vpn.state,
                        vpn.vpn_connection_type,
                        vpn.customer_gateway_id,
                        vpn.vpn_gateway_id,
                        vpn.transit_gateway_id,
                        vpn.customer_gateway_configuration,
                        1 if vpn.static_routes_only else 0,
                        json.dumps(vpn.vgw_telemetry, default=json_serial),
                        json.dumps(vpn.routes, default=json_serial),
                        vpn.category,
                        json.dumps(vpn.tags, default=json_serial),
                        json.dumps(vpn.raw_data, default=json_serial),
                    ),
                )
            conn.commit()
            logger.debug(f"Inserted {len(vpn_connections)} VPN connections")

    def insert_direct_connect_connections(
        self, dx_connections: List["DirectConnectConnection"]
    ) -> None:
        """Insert Direct Connect connection records."""
        if not dx_connections:
            return

        with self._get_connection() as conn:
            cursor = conn.cursor()
            for dx in dx_connections:
                cursor.execute(
                    """
                    INSERT INTO direct_connect_connections (
                        scan_id, connection_id, connection_name, region, connection_state,
                        location, bandwidth, vlan, partner_name, lag_id, aws_device,
                        aws_device_v2, aws_logical_device_id, jumbo_frame_capable,
                        has_logical_redundancy, provider_name, mac_sec_capable,
                        encryption_mode, loa_issue_time, tags, raw_data
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        dx.scan_id,
                        dx.connection_id,
                        dx.connection_name,
                        dx.region,
                        dx.connection_state,
                        dx.location,
                        dx.bandwidth,
                        dx.vlan,
                        dx.partner_name,
                        dx.lag_id,
                        dx.aws_device,
                        dx.aws_device_v2,
                        dx.aws_logical_device_id,
                        1 if dx.jumbo_frame_capable else 0,
                        dx.has_logical_redundancy,
                        dx.provider_name,
                        1 if dx.mac_sec_capable else 0,
                        dx.encryption_mode,
                        dx.loa_issue_time.isoformat() if dx.loa_issue_time else None,
                        json.dumps(dx.tags, default=json_serial),
                        json.dumps(dx.raw_data, default=json_serial),
                    ),
                )
            conn.commit()
            logger.debug(f"Inserted {len(dx_connections)} Direct Connect connections")

    def insert_elasticache_clusters(self, clusters: List["ElastiCacheCluster"]) -> None:
        """Insert ElastiCache cluster records."""
        if not clusters:
            return

        with self._get_connection() as conn:
            cursor = conn.cursor()
            for cluster in clusters:
                cursor.execute(
                    """
                    INSERT INTO elasticache_clusters (
                        scan_id, cache_cluster_id, cache_cluster_arn, region, engine,
                        engine_version, cache_node_type, num_cache_nodes,
                        preferred_availability_zone, preferred_availability_zones,
                        cache_cluster_status, cache_subnet_group_name, vpc_id,
                        security_groups, at_rest_encryption_enabled,
                        transit_encryption_enabled, auth_token_enabled, replication_group_id,
                        snapshot_retention_limit, snapshot_window, preferred_maintenance_window,
                        notification_configuration, cache_parameter_group_name,
                        cache_cluster_create_time, tags, raw_data
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        cluster.scan_id,
                        cluster.cache_cluster_id,
                        cluster.cache_cluster_arn,
                        cluster.region,
                        cluster.engine,
                        cluster.engine_version,
                        cluster.cache_node_type,
                        cluster.num_cache_nodes,
                        cluster.preferred_availability_zone,
                        json.dumps(
                            cluster.preferred_availability_zones, default=json_serial
                        ),
                        cluster.cache_cluster_status,
                        cluster.cache_subnet_group_name,
                        cluster.vpc_id,
                        json.dumps(cluster.security_groups, default=json_serial),
                        1 if cluster.at_rest_encryption_enabled else 0,
                        1 if cluster.transit_encryption_enabled else 0,
                        1 if cluster.auth_token_enabled else 0,
                        cluster.replication_group_id,
                        cluster.snapshot_retention_limit,
                        cluster.snapshot_window,
                        cluster.preferred_maintenance_window,
                        json.dumps(
                            cluster.notification_configuration, default=json_serial
                        )
                        if cluster.notification_configuration
                        else None,
                        cluster.cache_parameter_group_name,
                        cluster.cache_cluster_create_time.isoformat()
                        if cluster.cache_cluster_create_time
                        else None,
                        json.dumps(cluster.tags, default=json_serial),
                        json.dumps(cluster.raw_data, default=json_serial),
                    ),
                )
            conn.commit()
            logger.debug(f"Inserted {len(clusters)} ElastiCache clusters")

    def insert_opensearch_domains(self, domains: List["OpenSearchDomain"]) -> None:
        """Insert OpenSearch domain records."""
        if not domains:
            return

        with self._get_connection() as conn:
            cursor = conn.cursor()
            for domain in domains:
                cursor.execute(
                    """
                    INSERT INTO opensearch_domains (
                        scan_id, domain_id, domain_name, domain_arn, region, engine_type,
                        engine_version, instance_type, instance_count, dedicated_master_enabled,
                        dedicated_master_type, dedicated_master_count, zone_awareness_enabled,
                        availability_zone_count, warm_enabled, warm_type, warm_count,
                        cold_storage_enabled, ebs_enabled, volume_type, volume_size, iops,
                        throughput, vpc_id, subnet_ids, security_group_ids, endpoint,
                        endpoints, encryption_at_rest_enabled, kms_key_id,
                        node_to_node_encryption_enabled, enforce_https, tls_security_policy,
                        custom_endpoint_enabled, custom_endpoint, access_policies,
                        internal_user_database_enabled, saml_enabled, auto_tune_enabled,
                        created, deleted, processing, upgrade_processing,
                        domain_processing_status, tags, raw_data
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        domain.scan_id,
                        domain.domain_id,
                        domain.domain_name,
                        domain.domain_arn,
                        domain.region,
                        domain.engine_type,
                        domain.engine_version,
                        domain.instance_type,
                        domain.instance_count,
                        1 if domain.dedicated_master_enabled else 0,
                        domain.dedicated_master_type,
                        domain.dedicated_master_count,
                        1 if domain.zone_awareness_enabled else 0,
                        domain.availability_zone_count,
                        1 if domain.warm_enabled else 0,
                        domain.warm_type,
                        domain.warm_count,
                        1 if domain.cold_storage_enabled else 0,
                        1 if domain.ebs_enabled else 0,
                        domain.volume_type,
                        domain.volume_size,
                        domain.iops,
                        domain.throughput,
                        domain.vpc_id,
                        json.dumps(domain.subnet_ids, default=json_serial),
                        json.dumps(domain.security_group_ids, default=json_serial),
                        domain.endpoint,
                        json.dumps(domain.endpoints, default=json_serial),
                        1 if domain.encryption_at_rest_enabled else 0,
                        domain.kms_key_id,
                        1 if domain.node_to_node_encryption_enabled else 0,
                        1 if domain.enforce_https else 0,
                        domain.tls_security_policy,
                        1 if domain.custom_endpoint_enabled else 0,
                        domain.custom_endpoint,
                        domain.access_policies,
                        1 if domain.internal_user_database_enabled else 0,
                        1 if domain.saml_enabled else 0,
                        1 if domain.auto_tune_enabled else 0,
                        1 if domain.created else 0,
                        1 if domain.deleted else 0,
                        1 if domain.processing else 0,
                        1 if domain.upgrade_processing else 0,
                        domain.domain_processing_status,
                        json.dumps(domain.tags, default=json_serial),
                        json.dumps(domain.raw_data, default=json_serial),
                    ),
                )
            conn.commit()
            logger.debug(f"Inserted {len(domains)} OpenSearch domains")

    def insert_msk_clusters(self, clusters: List["MSKCluster"]) -> None:
        """Insert MSK cluster records."""
        if not clusters:
            return

        with self._get_connection() as conn:
            cursor = conn.cursor()
            for cluster in clusters:
                cursor.execute(
                    """
                    INSERT INTO msk_clusters (
                        scan_id, cluster_arn, cluster_name, region, kafka_version, state,
                        creation_time, broker_node_group_info, number_of_broker_nodes,
                        encryption_in_transit, encryption_at_rest_kms_key_arn,
                        enhanced_monitoring, open_monitoring, logging_info, cluster_type,
                        provisioned, serverless, current_version, zookeeper_connect_string,
                        zookeeper_connect_string_tls, bootstrap_broker_string,
                        bootstrap_broker_string_tls, tags, raw_data
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        cluster.scan_id,
                        cluster.cluster_arn,
                        cluster.cluster_name,
                        cluster.region,
                        cluster.kafka_version,
                        cluster.state,
                        cluster.creation_time.isoformat()
                        if cluster.creation_time
                        else None,
                        json.dumps(cluster.broker_node_group_info, default=json_serial),
                        cluster.number_of_broker_nodes,
                        json.dumps(cluster.encryption_in_transit, default=json_serial)
                        if cluster.encryption_in_transit
                        else None,
                        cluster.encryption_at_rest_kms_key_arn,
                        cluster.enhanced_monitoring,
                        json.dumps(cluster.open_monitoring, default=json_serial)
                        if cluster.open_monitoring
                        else None,
                        json.dumps(cluster.logging_info, default=json_serial)
                        if cluster.logging_info
                        else None,
                        cluster.cluster_type,
                        json.dumps(cluster.provisioned, default=json_serial)
                        if cluster.provisioned
                        else None,
                        json.dumps(cluster.serverless, default=json_serial)
                        if cluster.serverless
                        else None,
                        cluster.current_version,
                        cluster.zookeeper_connect_string,
                        cluster.zookeeper_connect_string_tls,
                        cluster.bootstrap_broker_string,
                        cluster.bootstrap_broker_string_tls,
                        json.dumps(cluster.tags, default=json_serial),
                        json.dumps(cluster.raw_data, default=json_serial),
                    ),
                )
            conn.commit()
            logger.debug(f"Inserted {len(clusters)} MSK clusters")

    def insert_dynamodb_tables(self, tables: List["DynamoDBTable"]) -> None:
        """Insert DynamoDB table records."""
        if not tables:
            return

        with self._get_connection() as conn:
            cursor = conn.cursor()
            for table in tables:
                cursor.execute(
                    """
                    INSERT INTO dynamodb_tables (
                        scan_id, table_name, table_arn, table_id, region, table_status,
                        creation_date_time, key_schema, attribute_definitions,
                        billing_mode_summary, provisioned_throughput, table_size_bytes,
                        item_count, global_secondary_indexes, local_secondary_indexes,
                        stream_specification, latest_stream_arn, latest_stream_label,
                        restore_summary, sse_description, point_in_time_recovery_enabled,
                        global_table_version, replicas, continuous_backups_status,
                        table_class_summary, deletion_protection_enabled, tags, raw_data
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        table.scan_id,
                        table.table_name,
                        table.table_arn,
                        table.table_id,
                        table.region,
                        table.table_status,
                        table.creation_date_time.isoformat()
                        if table.creation_date_time
                        else None,
                        json.dumps(table.key_schema, default=json_serial),
                        json.dumps(table.attribute_definitions, default=json_serial),
                        json.dumps(table.billing_mode_summary, default=json_serial)
                        if table.billing_mode_summary
                        else None,
                        json.dumps(table.provisioned_throughput, default=json_serial)
                        if table.provisioned_throughput
                        else None,
                        table.table_size_bytes,
                        table.item_count,
                        json.dumps(table.global_secondary_indexes, default=json_serial),
                        json.dumps(table.local_secondary_indexes, default=json_serial),
                        json.dumps(table.stream_specification, default=json_serial)
                        if table.stream_specification
                        else None,
                        table.latest_stream_arn,
                        table.latest_stream_label,
                        json.dumps(table.restore_summary, default=json_serial)
                        if table.restore_summary
                        else None,
                        json.dumps(table.sse_description, default=json_serial)
                        if table.sse_description
                        else None,
                        1 if table.point_in_time_recovery_enabled else 0,
                        table.global_table_version,
                        json.dumps(table.replicas, default=json_serial),
                        table.continuous_backups_status,
                        json.dumps(table.table_class_summary, default=json_serial)
                        if table.table_class_summary
                        else None,
                        1 if table.deletion_protection_enabled else 0,
                        json.dumps(table.tags, default=json_serial),
                        json.dumps(table.raw_data, default=json_serial),
                    ),
                )
            conn.commit()
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
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT * FROM scan_metadata
                WHERE account_number = ?
                ORDER BY scan_timestamp DESC
                LIMIT 1
            """,
                (account_number,),
            )
            row = cursor.fetchone()
            return dict(row) if row else None

    def get_all_scans(self) -> List[Dict[str, Any]]:
        """
        Get all scan metadata records.

        Returns:
            List of scan metadata dictionaries
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM scan_metadata
                ORDER BY scan_timestamp DESC
            """)
            return [dict(row) for row in cursor.fetchall()]

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
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT scan_id, account_name, scan_timestamp FROM scan_metadata WHERE scan_id = ?",
                (scan_id,),
            )
            scan = cursor.fetchone()

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
        with self._get_connection() as conn:
            cursor = conn.cursor()

            # Enable foreign key constraints
            cursor.execute("PRAGMA foreign_keys = ON")

            # Delete from each table
            for table in tables_with_scan_id:
                cursor.execute(f"DELETE FROM {table} WHERE scan_id = ?", (scan_id,))
                deleted_count = cursor.rowcount
                if deleted_count > 0:
                    deleted_counts[table] = deleted_count

            # Finally delete the scan metadata
            cursor.execute("DELETE FROM scan_metadata WHERE scan_id = ?", (scan_id,))
            deleted_counts["scan_metadata"] = cursor.rowcount

            conn.commit()

        return deleted_counts

    def insert_account_security_posture(self, records: List[AccountSecurityPosture]) -> None:
        """Insert account security posture records."""
        if not records:
            return
        with self._get_connection() as conn:
            cursor = conn.cursor()
            for posture in records:
                cursor.execute("""
                    INSERT INTO account_security_posture (
                        scan_id, account_summary, password_policy,
                        password_policy_exists, account_public_access_block,
                        credential_report_generated, raw_data
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    posture.scan_id,
                    json.dumps(posture.account_summary, default=json_serial),
                    json.dumps(posture.password_policy, default=json_serial) if posture.password_policy is not None else None,
                    1 if posture.password_policy_exists else 0,
                    json.dumps(posture.account_public_access_block, default=json_serial) if posture.account_public_access_block is not None else None,
                    posture.credential_report_generated.isoformat() if posture.credential_report_generated else None,
                    json.dumps(posture.raw_data, default=json_serial),
                ))
            conn.commit()
            logger.debug(f"Inserted {len(records)} account security posture records")

    def insert_iam_credential_report(self, entries: List[IAMCredentialReportEntry]) -> None:
        """Insert parsed IAM credential report rows."""
        if not entries:
            return
        with self._get_connection() as conn:
            cursor = conn.cursor()
            for entry in entries:
                cursor.execute("""
                    INSERT INTO iam_credential_report (
                        scan_id, user_name, arn, user_creation_time,
                        password_enabled, password_last_used, mfa_active,
                        access_key_1_active, access_key_1_last_rotated,
                        access_key_1_last_used, access_key_2_active,
                        access_key_2_last_rotated, access_key_2_last_used,
                        raw_data
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    entry.scan_id,
                    entry.user_name,
                    entry.arn,
                    entry.user_creation_time,
                    None if entry.password_enabled is None else (1 if entry.password_enabled else 0),
                    entry.password_last_used,
                    1 if entry.mfa_active else 0,
                    1 if entry.access_key_1_active else 0,
                    entry.access_key_1_last_rotated,
                    entry.access_key_1_last_used,
                    1 if entry.access_key_2_active else 0,
                    entry.access_key_2_last_rotated,
                    entry.access_key_2_last_used,
                    json.dumps(entry.raw_data, default=json_serial),
                ))
            conn.commit()
            logger.debug(f"Inserted {len(entries)} credential report rows")

    def insert_region_security_services(self, records: List[RegionSecurityServices]) -> None:
        """Insert per-region security service status records."""
        if not records:
            return

        def tri(value: Optional[bool]) -> Optional[int]:
            return None if value is None else (1 if value else 0)

        with self._get_connection() as conn:
            cursor = conn.cursor()
            for record in records:
                cursor.execute("""
                    INSERT INTO region_security_services (
                        scan_id, region, guardduty_enabled, guardduty_detector,
                        security_hub_enabled, ebs_encryption_by_default,
                        access_analyzers, raw_data
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    record.scan_id,
                    record.region,
                    tri(record.guardduty_enabled),
                    json.dumps(record.guardduty_detector, default=json_serial) if record.guardduty_detector is not None else None,
                    tri(record.security_hub_enabled),
                    tri(record.ebs_encryption_by_default),
                    json.dumps(record.access_analyzers, default=json_serial),
                    json.dumps(record.raw_data, default=json_serial),
                ))
            conn.commit()
            logger.debug(f"Inserted {len(records)} region security service records")

    def insert_lambda_exposure(self, records: List[LambdaExposure]) -> None:
        """Insert Lambda exposure records."""
        if not records:
            return
        with self._get_connection() as conn:
            cursor = conn.cursor()
            for record in records:
                cursor.execute("""
                    INSERT INTO lambda_exposure (
                        scan_id, region, function_name, function_arn,
                        url_config, url_auth_type, resource_policy, raw_data
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    record.scan_id,
                    record.region,
                    record.function_name,
                    record.function_arn,
                    json.dumps(record.url_config, default=json_serial) if record.url_config is not None else None,
                    record.url_auth_type,
                    json.dumps(record.resource_policy, default=json_serial) if record.resource_policy is not None else None,
                    json.dumps(record.raw_data, default=json_serial),
                ))
            conn.commit()
            logger.debug(f"Inserted {len(records)} Lambda exposure records")

    def insert_s3_public_access(self, records: List[S3PublicAccess]) -> None:
        """Insert per-bucket S3 public access records."""
        if not records:
            return
        with self._get_connection() as conn:
            cursor = conn.cursor()
            for record in records:
                cursor.execute("""
                    INSERT INTO s3_public_access (
                        scan_id, bucket_name, public_access_block,
                        policy_is_public, raw_data
                    ) VALUES (?, ?, ?, ?, ?)
                """, (
                    record.scan_id,
                    record.bucket_name,
                    json.dumps(record.public_access_block, default=json_serial) if record.public_access_block is not None else None,
                    None if record.policy_is_public is None else (1 if record.policy_is_public else 0),
                    json.dumps(record.raw_data, default=json_serial),
                ))
            conn.commit()
            logger.debug(f"Inserted {len(records)} S3 public access records")
