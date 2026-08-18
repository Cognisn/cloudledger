"""
Database schema definitions and initialisation.

This module creates and manages the SQLite database schema for CloudLedger.
Uses Australian English in all documentation and comments.
"""

import sqlite3
from pathlib import Path
from typing import Optional
import logging

logger = logging.getLogger(__name__)


class DatabaseSchema:
    """Manages database schema creation and versioning."""

    # Current schema version
    SCHEMA_VERSION = 1

    def __init__(self, db_path: str):
        """
        Initialise database schema manager.

        Args:
            db_path: Full path to SQLite database file
        """
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

    def initialise_database(self) -> None:
        """Create all database tables and indices if they don't exist."""
        logger.info(f"Initialising database at {self.db_path}")

        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()

            # Create schema version table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS schema_version (
                    version INTEGER PRIMARY KEY,
                    applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # Create scan metadata table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS scan_metadata (
                    scan_id TEXT PRIMARY KEY,
                    account_name TEXT NOT NULL,
                    account_number TEXT NOT NULL,
                    scan_timestamp TIMESTAMP NOT NULL,
                    prowler_level TEXT,
                    regions_scanned TEXT NOT NULL,
                    scan_status TEXT NOT NULL,
                    error_message TEXT,
                    scan_duration_seconds REAL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # Create EC2 instances table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS ec2_instances (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    instance_id TEXT NOT NULL,
                    region TEXT NOT NULL,
                    instance_type TEXT NOT NULL,
                    state TEXT NOT NULL,
                    public_ip TEXT,
                    private_ip TEXT,
                    vpc_id TEXT,
                    subnet_id TEXT,
                    availability_zone TEXT NOT NULL,
                    launch_time TIMESTAMP NOT NULL,
                    platform TEXT,
                    security_groups TEXT,
                    tags TEXT,
                    iam_instance_profile TEXT,
                    monitoring_state TEXT,
                    raw_data TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (scan_id) REFERENCES scan_metadata(scan_id)
                )
            """)

            # Create VPCs table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS vpcs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    vpc_id TEXT NOT NULL,
                    region TEXT NOT NULL,
                    cidr_block TEXT NOT NULL,
                    state TEXT NOT NULL,
                    is_default INTEGER NOT NULL,
                    dhcp_options_id TEXT,
                    instance_tenancy TEXT NOT NULL,
                    tags TEXT,
                    raw_data TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (scan_id) REFERENCES scan_metadata(scan_id)
                )
            """)

            # Create subnets table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS subnets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    subnet_id TEXT NOT NULL,
                    vpc_id TEXT NOT NULL,
                    region TEXT NOT NULL,
                    cidr_block TEXT NOT NULL,
                    availability_zone TEXT NOT NULL,
                    available_ip_count INTEGER NOT NULL,
                    map_public_ip INTEGER NOT NULL,
                    state TEXT NOT NULL,
                    tags TEXT,
                    raw_data TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (scan_id) REFERENCES scan_metadata(scan_id)
                )
            """)

            # Create security groups table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS security_groups (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    group_id TEXT NOT NULL,
                    group_name TEXT NOT NULL,
                    vpc_id TEXT,
                    region TEXT NOT NULL,
                    description TEXT NOT NULL,
                    ingress_rules TEXT,
                    egress_rules TEXT,
                    tags TEXT,
                    raw_data TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (scan_id) REFERENCES scan_metadata(scan_id)
                )
            """)

            # Create load balancers table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS load_balancers (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    load_balancer_name TEXT NOT NULL,
                    load_balancer_arn TEXT NOT NULL,
                    load_balancer_type TEXT NOT NULL,
                    region TEXT NOT NULL,
                    vpc_id TEXT,
                    scheme TEXT NOT NULL,
                    state TEXT NOT NULL,
                    dns_name TEXT NOT NULL,
                    availability_zones TEXT,
                    security_groups TEXT,
                    subnets TEXT,
                    created_time TIMESTAMP,
                    listeners TEXT,
                    target_groups TEXT,
                    tags TEXT,
                    raw_data TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (scan_id) REFERENCES scan_metadata(scan_id)
                )
            """)

            # Create NAT gateways table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS nat_gateways (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    nat_gateway_id TEXT NOT NULL,
                    region TEXT NOT NULL,
                    vpc_id TEXT NOT NULL,
                    subnet_id TEXT NOT NULL,
                    state TEXT NOT NULL,
                    connectivity_type TEXT NOT NULL,
                    public_ip TEXT,
                    private_ip TEXT,
                    created_time TIMESTAMP,
                    nat_gateway_addresses TEXT,
                    tags TEXT,
                    raw_data TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (scan_id) REFERENCES scan_metadata(scan_id)
                )
            """)

            # Create internet gateways table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS internet_gateways (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    internet_gateway_id TEXT NOT NULL,
                    region TEXT NOT NULL,
                    vpc_attachments TEXT,
                    tags TEXT,
                    raw_data TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (scan_id) REFERENCES scan_metadata(scan_id)
                )
            """)

            # Create route tables table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS route_tables (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    route_table_id TEXT NOT NULL,
                    region TEXT NOT NULL,
                    vpc_id TEXT NOT NULL,
                    is_main INTEGER NOT NULL,
                    routes TEXT,
                    subnet_associations TEXT,
                    gateway_associations TEXT,
                    tags TEXT,
                    raw_data TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (scan_id) REFERENCES scan_metadata(scan_id)
                )
            """)

            # Create auto scaling groups table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS auto_scaling_groups (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    auto_scaling_group_name TEXT NOT NULL,
                    auto_scaling_group_arn TEXT NOT NULL,
                    region TEXT NOT NULL,
                    launch_configuration_name TEXT,
                    launch_template TEXT,
                    min_size INTEGER NOT NULL,
                    max_size INTEGER NOT NULL,
                    desired_capacity INTEGER NOT NULL,
                    default_cooldown INTEGER NOT NULL,
                    availability_zones TEXT,
                    load_balancer_names TEXT,
                    target_group_arns TEXT,
                    health_check_type TEXT NOT NULL,
                    health_check_grace_period INTEGER NOT NULL,
                    vpc_zone_identifier TEXT,
                    instances TEXT,
                    created_time TIMESTAMP NOT NULL,
                    tags TEXT,
                    raw_data TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (scan_id) REFERENCES scan_metadata(scan_id)
                )
            """)

            # Create network interfaces table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS network_interfaces (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    network_interface_id TEXT NOT NULL,
                    region TEXT NOT NULL,
                    interface_type TEXT NOT NULL,
                    status TEXT NOT NULL,
                    vpc_id TEXT NOT NULL,
                    subnet_id TEXT NOT NULL,
                    availability_zone TEXT NOT NULL,
                    description TEXT,
                    private_ip_address TEXT,
                    private_ip_addresses TEXT,
                    public_ip TEXT,
                    mac_address TEXT,
                    source_dest_check INTEGER NOT NULL,
                    security_groups TEXT,
                    attachment TEXT,
                    tags TEXT,
                    raw_data TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (scan_id) REFERENCES scan_metadata(scan_id)
                )
            """)

            # Create WorkSpaces table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS workspaces (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    workspace_id TEXT NOT NULL,
                    region TEXT NOT NULL,
                    directory_id TEXT NOT NULL,
                    user_name TEXT NOT NULL,
                    bundle_id TEXT NOT NULL,
                    subnet_id TEXT NOT NULL,
                    vpc_id TEXT,
                    ip_address TEXT,
                    state TEXT NOT NULL,
                    compute_type TEXT NOT NULL,
                    volume_encryption_enabled INTEGER NOT NULL,
                    user_volume_size_gb INTEGER NOT NULL,
                    root_volume_size_gb INTEGER NOT NULL,
                    running_mode TEXT NOT NULL,
                    tags TEXT,
                    raw_data TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (scan_id) REFERENCES scan_metadata(scan_id)
                )
            """)

            # Create Lambda functions table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS lambda_functions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    function_name TEXT NOT NULL,
                    function_arn TEXT NOT NULL,
                    region TEXT NOT NULL,
                    runtime TEXT NOT NULL,
                    handler TEXT NOT NULL,
                    code_size INTEGER NOT NULL,
                    memory_size INTEGER NOT NULL,
                    timeout INTEGER NOT NULL,
                    last_modified TIMESTAMP NOT NULL,
                    role_arn TEXT NOT NULL,
                    vpc_config TEXT,
                    environment_variables TEXT,
                    layers TEXT,
                    state TEXT NOT NULL,
                    architectures TEXT,
                    triggers TEXT,
                    tags TEXT,
                    raw_data TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (scan_id) REFERENCES scan_metadata(scan_id)
                )
            """)

            # Create VPC Flow Logs table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS vpc_flow_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    flow_log_id TEXT NOT NULL,
                    region TEXT NOT NULL,
                    resource_id TEXT NOT NULL,
                    resource_type TEXT NOT NULL,
                    traffic_type TEXT NOT NULL,
                    log_destination_type TEXT NOT NULL,
                    log_destination TEXT NOT NULL,
                    log_format TEXT,
                    flow_log_status TEXT NOT NULL,
                    created_time TIMESTAMP,
                    tags TEXT,
                    raw_data TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (scan_id) REFERENCES scan_metadata(scan_id)
                )
            """)

            # Create S3 buckets table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS s3_buckets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    bucket_name TEXT NOT NULL,
                    creation_date TIMESTAMP NOT NULL,
                    region TEXT,
                    versioning_status TEXT,
                    public_access_block TEXT,
                    encryption_config TEXT,
                    lifecycle_rules TEXT,
                    logging_enabled INTEGER NOT NULL,
                    size_bytes INTEGER,
                    object_count INTEGER,
                    tags TEXT,
                    raw_data TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (scan_id) REFERENCES scan_metadata(scan_id)
                )
            """)

            # Create IAM users table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS iam_users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    user_name TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    arn TEXT NOT NULL,
                    create_date TIMESTAMP NOT NULL,
                    password_last_used TIMESTAMP,
                    mfa_enabled INTEGER NOT NULL,
                    access_keys TEXT,
                    attached_policies TEXT,
                    groups TEXT,
                    tags TEXT,
                    raw_data TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (scan_id) REFERENCES scan_metadata(scan_id)
                )
            """)

            # Create IAM roles table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS iam_roles (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    role_name TEXT NOT NULL,
                    role_id TEXT NOT NULL,
                    arn TEXT NOT NULL,
                    create_date TIMESTAMP NOT NULL,
                    assume_role_policy TEXT NOT NULL,
                    attached_policies TEXT,
                    max_session_duration INTEGER NOT NULL,
                    tags TEXT,
                    raw_data TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (scan_id) REFERENCES scan_metadata(scan_id)
                )
            """)

            # Create Route53 hosted zones table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS route53_hosted_zones (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    hosted_zone_id TEXT NOT NULL,
                    name TEXT NOT NULL,
                    is_private INTEGER NOT NULL,
                    resource_record_set_count INTEGER NOT NULL,
                    vpc_associations TEXT,
                    tags TEXT,
                    raw_data TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (scan_id) REFERENCES scan_metadata(scan_id)
                )
            """)

            # Create Route53 record sets table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS route53_record_sets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    hosted_zone_id TEXT NOT NULL,
                    name TEXT NOT NULL,
                    record_type TEXT NOT NULL,
                    ttl INTEGER,
                    resource_records TEXT,
                    alias_target TEXT,
                    raw_data TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (scan_id) REFERENCES scan_metadata(scan_id)
                )
            """)

            # Create cost data table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS cost_data (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    account_number TEXT NOT NULL,
                    time_period_start TIMESTAMP NOT NULL,
                    time_period_end TIMESTAMP NOT NULL,
                    service_name TEXT NOT NULL,
                    amount REAL NOT NULL,
                    currency TEXT NOT NULL,
                    unit TEXT NOT NULL,
                    raw_data TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (scan_id) REFERENCES scan_metadata(scan_id)
                )
            """)

            # Create Prowler findings table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS prowler_findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    check_id TEXT NOT NULL,
                    check_title TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    status TEXT NOT NULL,
                    region TEXT,
                    resource_id TEXT,
                    resource_arn TEXT,
                    resource_tags TEXT,
                    status_extended TEXT,
                    service_name TEXT NOT NULL,
                    check_type TEXT NOT NULL,
                    risk TEXT,
                    remediation TEXT,
                    compliance_frameworks TEXT,
                    raw_data TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (scan_id) REFERENCES scan_metadata(scan_id)
                )
            """)

            # Create EBS volumes table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS ebs_volumes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    volume_id TEXT NOT NULL,
                    region TEXT NOT NULL,
                    size INTEGER NOT NULL,
                    volume_type TEXT NOT NULL,
                    iops INTEGER,
                    throughput INTEGER,
                    encrypted INTEGER NOT NULL,
                    kms_key_id TEXT,
                    state TEXT NOT NULL,
                    create_time TIMESTAMP NOT NULL,
                    availability_zone TEXT NOT NULL,
                    snapshot_id TEXT,
                    attached_instance_id TEXT,
                    device_name TEXT,
                    attachment_state TEXT,
                    multi_attach_enabled INTEGER DEFAULT 0,
                    tags TEXT,
                    raw_data TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (scan_id) REFERENCES scan_metadata(scan_id)
                )
            """)

            # Create EBS snapshots table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS ebs_snapshots (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    snapshot_id TEXT NOT NULL,
                    region TEXT NOT NULL,
                    volume_id TEXT,
                    volume_size INTEGER NOT NULL,
                    encrypted INTEGER NOT NULL,
                    kms_key_id TEXT,
                    state TEXT NOT NULL,
                    start_time TIMESTAMP NOT NULL,
                    progress TEXT NOT NULL,
                    owner_id TEXT NOT NULL,
                    description TEXT,
                    tags TEXT,
                    raw_data TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (scan_id) REFERENCES scan_metadata(scan_id)
                )
            """)

            # Create RDS instances table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS rds_instances (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    db_instance_identifier TEXT NOT NULL,
                    region TEXT NOT NULL,
                    db_instance_arn TEXT NOT NULL,
                    engine TEXT NOT NULL,
                    engine_version TEXT NOT NULL,
                    db_instance_class TEXT NOT NULL,
                    allocated_storage INTEGER NOT NULL,
                    storage_type TEXT NOT NULL,
                    iops INTEGER,
                    multi_az INTEGER NOT NULL,
                    availability_zone TEXT,
                    secondary_availability_zone TEXT,
                    publicly_accessible INTEGER NOT NULL,
                    encrypted INTEGER NOT NULL,
                    kms_key_id TEXT,
                    vpc_id TEXT,
                    subnet_group TEXT,
                    vpc_security_groups TEXT,
                    backup_retention_period INTEGER NOT NULL,
                    preferred_backup_window TEXT,
                    latest_restorable_time TIMESTAMP,
                    endpoint_address TEXT,
                    endpoint_port INTEGER,
                    db_instance_status TEXT NOT NULL,
                    monitoring_interval INTEGER DEFAULT 0,
                    performance_insights_enabled INTEGER DEFAULT 0,
                    auto_minor_version_upgrade INTEGER DEFAULT 1,
                    deletion_protection INTEGER DEFAULT 0,
                    tags TEXT,
                    raw_data TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (scan_id) REFERENCES scan_metadata(scan_id)
                )
            """)

            # Create IAM policies table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS iam_policies (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    policy_arn TEXT NOT NULL,
                    policy_name TEXT NOT NULL,
                    policy_id TEXT NOT NULL,
                    path TEXT NOT NULL,
                    default_version_id TEXT NOT NULL,
                    attachment_count INTEGER NOT NULL,
                    permissions_boundary_usage_count INTEGER NOT NULL,
                    is_attachable INTEGER NOT NULL,
                    description TEXT,
                    create_date TIMESTAMP NOT NULL,
                    update_date TIMESTAMP NOT NULL,
                    policy_document TEXT NOT NULL,
                    attached_users TEXT,
                    attached_roles TEXT,
                    attached_groups TEXT,
                    tags TEXT,
                    raw_data TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (scan_id) REFERENCES scan_metadata(scan_id)
                )
            """)

            # Create KMS keys table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS kms_keys (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    key_id TEXT NOT NULL,
                    key_arn TEXT NOT NULL,
                    region TEXT NOT NULL,
                    aws_account_id TEXT NOT NULL,
                    key_state TEXT NOT NULL,
                    creation_date TIMESTAMP NOT NULL,
                    key_manager TEXT NOT NULL,
                    key_usage TEXT NOT NULL,
                    key_spec TEXT NOT NULL,
                    description TEXT,
                    enabled INTEGER NOT NULL,
                    deletion_date TIMESTAMP,
                    rotation_enabled INTEGER DEFAULT 0,
                    key_policy TEXT,
                    aliases TEXT,
                    tags TEXT,
                    raw_data TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (scan_id) REFERENCES scan_metadata(scan_id)
                )
            """)

            # Create Elastic IPs table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS elastic_ips (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    allocation_id TEXT NOT NULL,
                    region TEXT NOT NULL,
                    public_ip TEXT NOT NULL,
                    domain TEXT NOT NULL,
                    instance_id TEXT,
                    network_interface_id TEXT,
                    network_interface_owner_id TEXT,
                    private_ip_address TEXT,
                    association_id TEXT,
                    is_associated INTEGER NOT NULL,
                    tags TEXT,
                    raw_data TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (scan_id) REFERENCES scan_metadata(scan_id)
                )
            """)

            # Phase 2: Containers & Application Services tables

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS ecs_clusters (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    cluster_arn TEXT NOT NULL,
                    cluster_name TEXT NOT NULL,
                    region TEXT NOT NULL,
                    status TEXT NOT NULL,
                    registered_container_instances_count INTEGER DEFAULT 0,
                    running_tasks_count INTEGER DEFAULT 0,
                    pending_tasks_count INTEGER DEFAULT 0,
                    active_services_count INTEGER DEFAULT 0,
                    capacity_providers TEXT,
                    default_capacity_provider_strategy TEXT,
                    settings TEXT,
                    statistics TEXT,
                    tags TEXT,
                    raw_data TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (scan_id) REFERENCES scan_metadata(scan_id)
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS ecs_services (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    service_arn TEXT NOT NULL,
                    service_name TEXT NOT NULL,
                    cluster_arn TEXT NOT NULL,
                    region TEXT NOT NULL,
                    status TEXT NOT NULL,
                    task_definition TEXT NOT NULL,
                    desired_count INTEGER NOT NULL,
                    running_count INTEGER NOT NULL,
                    pending_count INTEGER NOT NULL,
                    launch_type TEXT,
                    platform_version TEXT,
                    platform_family TEXT,
                    capacity_provider_strategy TEXT,
                    network_configuration TEXT,
                    load_balancers TEXT,
                    service_registries TEXT,
                    deployment_configuration TEXT,
                    deployments TEXT,
                    health_check_grace_period_seconds INTEGER,
                    scheduling_strategy TEXT DEFAULT 'REPLICA',
                    created_at_svc TIMESTAMP,
                    tags TEXT,
                    raw_data TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (scan_id) REFERENCES scan_metadata(scan_id)
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS ecs_task_definitions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    task_definition_arn TEXT NOT NULL,
                    family TEXT NOT NULL,
                    revision INTEGER NOT NULL,
                    region TEXT NOT NULL,
                    status TEXT NOT NULL,
                    requires_compatibilities TEXT,
                    network_mode TEXT NOT NULL,
                    cpu TEXT,
                    memory TEXT,
                    task_role_arn TEXT,
                    execution_role_arn TEXT,
                    container_definitions TEXT,
                    volumes TEXT,
                    placement_constraints TEXT,
                    requires_attributes TEXT,
                    pid_mode TEXT,
                    ipc_mode TEXT,
                    proxy_configuration TEXT,
                    ephemeral_storage TEXT,
                    runtime_platform TEXT,
                    registered_at TIMESTAMP,
                    deregistered_at TIMESTAMP,
                    registered_by TEXT,
                    tags TEXT,
                    raw_data TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (scan_id) REFERENCES scan_metadata(scan_id)
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS eks_clusters (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    cluster_name TEXT NOT NULL,
                    cluster_arn TEXT NOT NULL,
                    region TEXT NOT NULL,
                    version TEXT NOT NULL,
                    endpoint TEXT,
                    role_arn TEXT NOT NULL,
                    status TEXT NOT NULL,
                    vpc_id TEXT NOT NULL,
                    subnet_ids TEXT,
                    security_group_ids TEXT,
                    cluster_security_group_id TEXT,
                    endpoint_public_access INTEGER DEFAULT 1,
                    endpoint_private_access INTEGER DEFAULT 0,
                    public_access_cidrs TEXT,
                    resources_vpc_config TEXT,
                    logging TEXT,
                    identity TEXT,
                    encryption_config TEXT,
                    platform_version TEXT,
                    created_at_eks TIMESTAMP,
                    tags TEXT,
                    raw_data TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (scan_id) REFERENCES scan_metadata(scan_id)
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS eks_node_groups (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    cluster_name TEXT NOT NULL,
                    nodegroup_name TEXT NOT NULL,
                    nodegroup_arn TEXT NOT NULL,
                    region TEXT NOT NULL,
                    status TEXT NOT NULL,
                    scaling_config TEXT,
                    instance_types TEXT,
                    ami_type TEXT,
                    release_version TEXT,
                    subnets TEXT,
                    remote_access TEXT,
                    node_role TEXT NOT NULL,
                    labels TEXT,
                    taints TEXT,
                    disk_size INTEGER,
                    capacity_type TEXT DEFAULT 'ON_DEMAND',
                    launch_template TEXT,
                    update_config TEXT,
                    health TEXT,
                    created_at_ng TIMESTAMP,
                    modified_at TIMESTAMP,
                    tags TEXT,
                    raw_data TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (scan_id) REFERENCES scan_metadata(scan_id)
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS ecr_repositories (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    repository_arn TEXT NOT NULL,
                    repository_name TEXT NOT NULL,
                    repository_uri TEXT NOT NULL,
                    region TEXT NOT NULL,
                    registry_id TEXT NOT NULL,
                    image_scanning_configuration TEXT,
                    image_tag_mutability TEXT DEFAULT 'MUTABLE',
                    encryption_configuration TEXT,
                    created_at_repo TIMESTAMP,
                    tags TEXT,
                    raw_data TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (scan_id) REFERENCES scan_metadata(scan_id)
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS ecr_images (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    repository_name TEXT NOT NULL,
                    region TEXT NOT NULL,
                    registry_id TEXT NOT NULL,
                    image_digest TEXT NOT NULL,
                    image_tags TEXT,
                    image_size_in_bytes INTEGER NOT NULL,
                    image_pushed_at TIMESTAMP,
                    image_scan_status TEXT,
                    image_scan_findings_summary TEXT,
                    last_recorded_pull_time TIMESTAMP,
                    artifact_media_type TEXT,
                    raw_data TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (scan_id) REFERENCES scan_metadata(scan_id)
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS api_gateway_rest_apis (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    api_id TEXT NOT NULL,
                    name TEXT NOT NULL,
                    region TEXT NOT NULL,
                    description TEXT,
                    endpoint_configuration TEXT,
                    version TEXT,
                    created_date TIMESTAMP,
                    api_key_source TEXT,
                    policy TEXT,
                    minimum_compression_size INTEGER,
                    binary_media_types TEXT,
                    disable_execute_api_endpoint INTEGER DEFAULT 0,
                    tags TEXT,
                    raw_data TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (scan_id) REFERENCES scan_metadata(scan_id)
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS api_gateway_http_apis (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    api_id TEXT NOT NULL,
                    name TEXT NOT NULL,
                    region TEXT NOT NULL,
                    protocol_type TEXT NOT NULL,
                    description TEXT,
                    api_endpoint TEXT,
                    cors_configuration TEXT,
                    version TEXT,
                    route_selection_expression TEXT,
                    disable_execute_api_endpoint INTEGER DEFAULT 0,
                    disable_schema_validation INTEGER DEFAULT 0,
                    import_info TEXT,
                    created_date TIMESTAMP,
                    tags TEXT,
                    raw_data TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (scan_id) REFERENCES scan_metadata(scan_id)
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS api_gateway_stages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    api_id TEXT NOT NULL,
                    stage_name TEXT NOT NULL,
                    region TEXT NOT NULL,
                    api_type TEXT NOT NULL,
                    deployment_id TEXT,
                    description TEXT,
                    created_date TIMESTAMP,
                    last_updated_date TIMESTAMP,
                    access_log_settings TEXT,
                    client_certificate_id TEXT,
                    throttle_settings TEXT,
                    method_settings TEXT,
                    variables TEXT,
                    tracing_enabled INTEGER DEFAULT 0,
                    web_acl_arn TEXT,
                    auto_deploy INTEGER DEFAULT 0,
                    route_settings TEXT,
                    default_route_settings TEXT,
                    tags TEXT,
                    raw_data TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (scan_id) REFERENCES scan_metadata(scan_id)
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS cloudfront_distributions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    distribution_id TEXT NOT NULL,
                    distribution_arn TEXT NOT NULL,
                    domain_name TEXT NOT NULL,
                    status TEXT NOT NULL,
                    enabled INTEGER NOT NULL,
                    aliases TEXT,
                    origins TEXT,
                    origin_groups TEXT,
                    default_root_object TEXT,
                    default_cache_behavior TEXT,
                    cache_behaviors TEXT,
                    viewer_certificate TEXT,
                    geo_restriction TEXT,
                    web_acl_id TEXT,
                    http_version TEXT DEFAULT 'http2',
                    is_ipv6_enabled INTEGER DEFAULT 1,
                    logging TEXT,
                    price_class TEXT DEFAULT 'PriceClass_All',
                    custom_error_responses TEXT,
                    comment TEXT,
                    last_modified_time TIMESTAMP,
                    tags TEXT,
                    raw_data TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (scan_id) REFERENCES scan_metadata(scan_id)
                )
            """)

            # Phase 3: Governance, Logging & Advanced Services

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS organizations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    organization_id TEXT NOT NULL,
                    organization_arn TEXT NOT NULL,
                    master_account_id TEXT NOT NULL,
                    master_account_email TEXT NOT NULL,
                    feature_set TEXT NOT NULL,
                    available_policy_types TEXT,
                    raw_data TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (scan_id) REFERENCES scan_metadata(scan_id)
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS organizational_units (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    ou_id TEXT NOT NULL,
                    ou_arn TEXT NOT NULL,
                    ou_name TEXT NOT NULL,
                    parent_id TEXT,
                    raw_data TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (scan_id) REFERENCES scan_metadata(scan_id)
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS organization_accounts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    account_id TEXT NOT NULL,
                    account_arn TEXT NOT NULL,
                    account_name TEXT NOT NULL,
                    email TEXT NOT NULL,
                    status TEXT NOT NULL,
                    joined_method TEXT NOT NULL,
                    joined_timestamp TIMESTAMP,
                    parent_ou_id TEXT,
                    raw_data TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (scan_id) REFERENCES scan_metadata(scan_id)
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS sso_permission_sets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    permission_set_arn TEXT NOT NULL,
                    permission_set_name TEXT NOT NULL,
                    instance_arn TEXT NOT NULL,
                    description TEXT,
                    session_duration TEXT,
                    relay_state TEXT,
                    created_date TIMESTAMP,
                    managed_policies TEXT,
                    inline_policy TEXT,
                    customer_managed_policies TEXT,
                    permissions_boundary TEXT,
                    tags TEXT,
                    raw_data TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (scan_id) REFERENCES scan_metadata(scan_id)
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS sso_assignments (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    instance_arn TEXT NOT NULL,
                    permission_set_arn TEXT NOT NULL,
                    principal_type TEXT NOT NULL,
                    principal_id TEXT NOT NULL,
                    target_type TEXT NOT NULL,
                    target_id TEXT NOT NULL,
                    raw_data TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (scan_id) REFERENCES scan_metadata(scan_id)
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS cloudtrail_trails (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    trail_name TEXT NOT NULL,
                    trail_arn TEXT NOT NULL,
                    region TEXT NOT NULL,
                    s3_bucket_name TEXT NOT NULL,
                    s3_key_prefix TEXT,
                    sns_topic_name TEXT,
                    sns_topic_arn TEXT,
                    cloud_watch_logs_log_group_arn TEXT,
                    cloud_watch_logs_role_arn TEXT,
                    kms_key_id TEXT,
                    is_multi_region_trail INTEGER NOT NULL DEFAULT 0,
                    is_organization_trail INTEGER NOT NULL DEFAULT 0,
                    include_global_service_events INTEGER NOT NULL DEFAULT 1,
                    is_logging INTEGER NOT NULL DEFAULT 0,
                    has_event_selectors INTEGER NOT NULL DEFAULT 0,
                    has_insight_selectors INTEGER NOT NULL DEFAULT 0,
                    home_region TEXT,
                    tags TEXT,
                    raw_data TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (scan_id) REFERENCES scan_metadata(scan_id)
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS cloudwatch_log_groups (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    log_group_name TEXT NOT NULL,
                    log_group_arn TEXT NOT NULL,
                    region TEXT NOT NULL,
                    creation_time TIMESTAMP,
                    retention_in_days INTEGER,
                    stored_bytes INTEGER DEFAULT 0,
                    kms_key_id TEXT,
                    metric_filter_count INTEGER DEFAULT 0,
                    tags TEXT,
                    raw_data TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (scan_id) REFERENCES scan_metadata(scan_id)
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS config_recorders (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    recorder_name TEXT NOT NULL,
                    region TEXT NOT NULL,
                    role_arn TEXT NOT NULL,
                    recording_group TEXT,
                    is_recording INTEGER NOT NULL DEFAULT 0,
                    last_status TEXT,
                    last_start_time TIMESTAMP,
                    last_stop_time TIMESTAMP,
                    raw_data TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (scan_id) REFERENCES scan_metadata(scan_id)
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS config_rules (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    rule_name TEXT NOT NULL,
                    rule_arn TEXT NOT NULL,
                    rule_id TEXT NOT NULL,
                    region TEXT NOT NULL,
                    description TEXT,
                    scope TEXT,
                    source TEXT,
                    compliance_type TEXT,
                    config_rule_state TEXT DEFAULT 'ACTIVE',
                    maximum_execution_frequency TEXT,
                    raw_data TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (scan_id) REFERENCES scan_metadata(scan_id)
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS bedrock_models (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    model_id TEXT NOT NULL,
                    model_arn TEXT NOT NULL,
                    model_name TEXT NOT NULL,
                    region TEXT NOT NULL,
                    provider_name TEXT NOT NULL,
                    customization_type TEXT,
                    base_model_arn TEXT,
                    inference_types_supported TEXT,
                    input_modalities TEXT,
                    output_modalities TEXT,
                    response_streaming_supported INTEGER DEFAULT 0,
                    raw_data TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (scan_id) REFERENCES scan_metadata(scan_id)
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS bedrock_guardrails (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    guardrail_id TEXT NOT NULL,
                    guardrail_arn TEXT NOT NULL,
                    guardrail_name TEXT NOT NULL,
                    region TEXT NOT NULL,
                    version TEXT NOT NULL,
                    description TEXT,
                    status TEXT NOT NULL,
                    content_policy_config TEXT,
                    topic_policy_config TEXT,
                    word_policy_config TEXT,
                    sensitive_information_policy_config TEXT,
                    blocked_input_messaging TEXT,
                    blocked_outputs_messaging TEXT,
                    created_at_time TIMESTAMP,
                    updated_at_time TIMESTAMP,
                    tags TEXT,
                    raw_data TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (scan_id) REFERENCES scan_metadata(scan_id)
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS bedrock_knowledge_bases (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    knowledge_base_id TEXT NOT NULL,
                    knowledge_base_arn TEXT NOT NULL,
                    knowledge_base_name TEXT NOT NULL,
                    region TEXT NOT NULL,
                    description TEXT,
                    role_arn TEXT NOT NULL,
                    knowledge_base_configuration TEXT,
                    storage_configuration TEXT,
                    status TEXT NOT NULL,
                    created_at_time TIMESTAMP,
                    updated_at_time TIMESTAMP,
                    tags TEXT,
                    raw_data TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (scan_id) REFERENCES scan_metadata(scan_id)
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS bedrock_agents (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    agent_id TEXT NOT NULL,
                    agent_arn TEXT NOT NULL,
                    agent_name TEXT NOT NULL,
                    region TEXT NOT NULL,
                    agent_version TEXT NOT NULL,
                    description TEXT,
                    agent_resource_role_arn TEXT NOT NULL,
                    foundation_model TEXT NOT NULL,
                    instruction TEXT,
                    idle_session_ttl_in_seconds INTEGER,
                    agent_status TEXT NOT NULL,
                    created_at_time TIMESTAMP,
                    updated_at_time TIMESTAMP,
                    prepared_at_time TIMESTAMP,
                    tags TEXT,
                    raw_data TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (scan_id) REFERENCES scan_metadata(scan_id)
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS directory_services (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    directory_id TEXT NOT NULL,
                    directory_name TEXT NOT NULL,
                    region TEXT NOT NULL,
                    directory_type TEXT NOT NULL,
                    size TEXT,
                    edition TEXT,
                    vpc_id TEXT,
                    subnet_ids TEXT,
                    dns_ip_addresses TEXT,
                    access_url TEXT,
                    stage TEXT NOT NULL,
                    sso_enabled INTEGER DEFAULT 0,
                    radius_status TEXT,
                    launch_time TIMESTAMP,
                    stage_last_updated_date_time TIMESTAMP,
                    description TEXT,
                    alias TEXT,
                    short_name TEXT,
                    tags TEXT,
                    raw_data TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (scan_id) REFERENCES scan_metadata(scan_id)
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS transit_gateways (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    transit_gateway_id TEXT NOT NULL,
                    transit_gateway_arn TEXT NOT NULL,
                    region TEXT NOT NULL,
                    owner_id TEXT NOT NULL,
                    description TEXT,
                    state TEXT NOT NULL,
                    amazon_side_asn INTEGER,
                    default_route_table_id TEXT,
                    default_route_table_association TEXT,
                    default_route_table_propagation TEXT,
                    vpn_ecmp_support TEXT,
                    dns_support TEXT,
                    multicast_support TEXT,
                    auto_accept_shared_attachments TEXT,
                    transit_gateway_cidr_blocks TEXT,
                    creation_time TIMESTAMP,
                    tags TEXT,
                    raw_data TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (scan_id) REFERENCES scan_metadata(scan_id)
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS vpn_connections (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    vpn_connection_id TEXT NOT NULL,
                    region TEXT NOT NULL,
                    state TEXT NOT NULL,
                    vpn_connection_type TEXT NOT NULL,
                    customer_gateway_id TEXT NOT NULL,
                    vpn_gateway_id TEXT,
                    transit_gateway_id TEXT,
                    customer_gateway_configuration TEXT,
                    static_routes_only INTEGER DEFAULT 0,
                    vgw_telemetry TEXT,
                    routes TEXT,
                    category TEXT,
                    tags TEXT,
                    raw_data TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (scan_id) REFERENCES scan_metadata(scan_id)
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS direct_connect_connections (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    connection_id TEXT NOT NULL,
                    connection_name TEXT NOT NULL,
                    region TEXT NOT NULL,
                    connection_state TEXT NOT NULL,
                    location TEXT NOT NULL,
                    bandwidth TEXT NOT NULL,
                    vlan INTEGER,
                    partner_name TEXT,
                    lag_id TEXT,
                    aws_device TEXT,
                    aws_device_v2 TEXT,
                    aws_logical_device_id TEXT,
                    jumbo_frame_capable INTEGER DEFAULT 0,
                    has_logical_redundancy TEXT,
                    provider_name TEXT,
                    mac_sec_capable INTEGER DEFAULT 0,
                    encryption_mode TEXT,
                    loa_issue_time TIMESTAMP,
                    tags TEXT,
                    raw_data TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (scan_id) REFERENCES scan_metadata(scan_id)
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS elasticache_clusters (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    cache_cluster_id TEXT NOT NULL,
                    cache_cluster_arn TEXT NOT NULL,
                    region TEXT NOT NULL,
                    engine TEXT NOT NULL,
                    engine_version TEXT NOT NULL,
                    cache_node_type TEXT NOT NULL,
                    num_cache_nodes INTEGER NOT NULL,
                    preferred_availability_zone TEXT,
                    preferred_availability_zones TEXT,
                    cache_cluster_status TEXT NOT NULL,
                    cache_subnet_group_name TEXT,
                    vpc_id TEXT,
                    security_groups TEXT,
                    at_rest_encryption_enabled INTEGER DEFAULT 0,
                    transit_encryption_enabled INTEGER DEFAULT 0,
                    auth_token_enabled INTEGER DEFAULT 0,
                    replication_group_id TEXT,
                    snapshot_retention_limit INTEGER,
                    snapshot_window TEXT,
                    preferred_maintenance_window TEXT,
                    notification_configuration TEXT,
                    cache_parameter_group_name TEXT,
                    cache_cluster_create_time TIMESTAMP,
                    tags TEXT,
                    raw_data TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (scan_id) REFERENCES scan_metadata(scan_id)
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS opensearch_domains (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    domain_id TEXT NOT NULL,
                    domain_name TEXT NOT NULL,
                    domain_arn TEXT NOT NULL,
                    region TEXT NOT NULL,
                    engine_type TEXT NOT NULL,
                    engine_version TEXT NOT NULL,
                    instance_type TEXT NOT NULL,
                    instance_count INTEGER NOT NULL,
                    dedicated_master_enabled INTEGER DEFAULT 0,
                    dedicated_master_type TEXT,
                    dedicated_master_count INTEGER,
                    zone_awareness_enabled INTEGER DEFAULT 0,
                    availability_zone_count INTEGER,
                    warm_enabled INTEGER DEFAULT 0,
                    warm_type TEXT,
                    warm_count INTEGER,
                    cold_storage_enabled INTEGER DEFAULT 0,
                    ebs_enabled INTEGER DEFAULT 0,
                    volume_type TEXT,
                    volume_size INTEGER,
                    iops INTEGER,
                    throughput INTEGER,
                    vpc_id TEXT,
                    subnet_ids TEXT,
                    security_group_ids TEXT,
                    endpoint TEXT,
                    endpoints TEXT,
                    encryption_at_rest_enabled INTEGER DEFAULT 0,
                    kms_key_id TEXT,
                    node_to_node_encryption_enabled INTEGER DEFAULT 0,
                    enforce_https INTEGER DEFAULT 0,
                    tls_security_policy TEXT,
                    custom_endpoint_enabled INTEGER DEFAULT 0,
                    custom_endpoint TEXT,
                    access_policies TEXT,
                    internal_user_database_enabled INTEGER DEFAULT 0,
                    saml_enabled INTEGER DEFAULT 0,
                    auto_tune_enabled INTEGER DEFAULT 0,
                    created INTEGER DEFAULT 0,
                    deleted INTEGER DEFAULT 0,
                    processing INTEGER DEFAULT 0,
                    upgrade_processing INTEGER DEFAULT 0,
                    domain_processing_status TEXT,
                    tags TEXT,
                    raw_data TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (scan_id) REFERENCES scan_metadata(scan_id)
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS msk_clusters (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    cluster_arn TEXT NOT NULL,
                    cluster_name TEXT NOT NULL,
                    region TEXT NOT NULL,
                    kafka_version TEXT NOT NULL,
                    state TEXT NOT NULL,
                    creation_time TIMESTAMP,
                    broker_node_group_info TEXT,
                    number_of_broker_nodes INTEGER NOT NULL,
                    encryption_in_transit TEXT,
                    encryption_at_rest_kms_key_arn TEXT,
                    enhanced_monitoring TEXT,
                    open_monitoring TEXT,
                    logging_info TEXT,
                    cluster_type TEXT,
                    provisioned TEXT,
                    serverless TEXT,
                    current_version TEXT,
                    zookeeper_connect_string TEXT,
                    zookeeper_connect_string_tls TEXT,
                    bootstrap_broker_string TEXT,
                    bootstrap_broker_string_tls TEXT,
                    tags TEXT,
                    raw_data TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (scan_id) REFERENCES scan_metadata(scan_id)
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS dynamodb_tables (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    table_name TEXT NOT NULL,
                    table_arn TEXT NOT NULL,
                    table_id TEXT NOT NULL,
                    region TEXT NOT NULL,
                    table_status TEXT NOT NULL,
                    creation_date_time TIMESTAMP,
                    key_schema TEXT,
                    attribute_definitions TEXT,
                    billing_mode_summary TEXT,
                    provisioned_throughput TEXT,
                    table_size_bytes INTEGER DEFAULT 0,
                    item_count INTEGER DEFAULT 0,
                    global_secondary_indexes TEXT,
                    local_secondary_indexes TEXT,
                    stream_specification TEXT,
                    latest_stream_arn TEXT,
                    latest_stream_label TEXT,
                    restore_summary TEXT,
                    sse_description TEXT,
                    point_in_time_recovery_enabled INTEGER DEFAULT 0,
                    global_table_version TEXT,
                    replicas TEXT,
                    continuous_backups_status TEXT,
                    table_class_summary TEXT,
                    deletion_protection_enabled INTEGER DEFAULT 0,
                    tags TEXT,
                    raw_data TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (scan_id) REFERENCES scan_metadata(scan_id)
                )
            """)

            # Account security posture (one row per scan)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS account_security_posture (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    account_summary TEXT,
                    password_policy TEXT,
                    password_policy_exists INTEGER NOT NULL DEFAULT 0,
                    account_public_access_block TEXT,
                    credential_report_generated TIMESTAMP,
                    raw_data TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (scan_id) REFERENCES scan_metadata(scan_id)
                )
            """)

            # Parsed IAM credential report rows (one per user plus root)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS iam_credential_report (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    user_name TEXT NOT NULL,
                    arn TEXT,
                    user_creation_time TEXT,
                    password_enabled INTEGER,
                    password_last_used TEXT,
                    mfa_active INTEGER NOT NULL DEFAULT 0,
                    access_key_1_active INTEGER NOT NULL DEFAULT 0,
                    access_key_1_last_rotated TEXT,
                    access_key_1_last_used TEXT,
                    access_key_2_active INTEGER NOT NULL DEFAULT 0,
                    access_key_2_last_rotated TEXT,
                    access_key_2_last_used TEXT,
                    raw_data TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (scan_id) REFERENCES scan_metadata(scan_id)
                )
            """)

            # Per-region security service enablement (one row per region per scan)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS region_security_services (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    region TEXT NOT NULL,
                    guardduty_enabled INTEGER,
                    guardduty_detector TEXT,
                    security_hub_enabled INTEGER,
                    ebs_encryption_by_default INTEGER,
                    access_analyzers TEXT,
                    raw_data TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (scan_id) REFERENCES scan_metadata(scan_id)
                )
            """)

            # Lambda exposure facts (URL configs and resource policies)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS lambda_exposure (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    region TEXT NOT NULL,
                    function_name TEXT NOT NULL,
                    function_arn TEXT NOT NULL,
                    url_config TEXT,
                    url_auth_type TEXT,
                    resource_policy TEXT,
                    raw_data TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (scan_id) REFERENCES scan_metadata(scan_id)
                )
            """)

            # Per-bucket S3 public access facts
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS s3_public_access (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    bucket_name TEXT NOT NULL,
                    public_access_block TEXT,
                    policy_is_public INTEGER,
                    raw_data TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (scan_id) REFERENCES scan_metadata(scan_id)
                )
            """)

            # Create indices for performance
            self._create_indices(cursor)

            # Record schema version
            cursor.execute(
                "INSERT OR IGNORE INTO schema_version (version) VALUES (?)",
                (self.SCHEMA_VERSION,),
            )

            conn.commit()
            logger.info("Database schema initialised successfully")

    def _create_indices(self, cursor: sqlite3.Cursor) -> None:
        """
        Create database indices for query performance.

        Args:
            cursor: SQLite cursor
        """
        indices = [
            # Scan metadata indices
            "CREATE INDEX IF NOT EXISTS idx_scan_account ON scan_metadata(account_number)",
            "CREATE INDEX IF NOT EXISTS idx_scan_timestamp ON scan_metadata(scan_timestamp)",
            # EC2 indices
            "CREATE INDEX IF NOT EXISTS idx_ec2_scan ON ec2_instances(scan_id)",
            "CREATE INDEX IF NOT EXISTS idx_ec2_instance ON ec2_instances(instance_id)",
            "CREATE INDEX IF NOT EXISTS idx_ec2_region ON ec2_instances(region)",
            "CREATE INDEX IF NOT EXISTS idx_ec2_vpc ON ec2_instances(vpc_id)",
            "CREATE INDEX IF NOT EXISTS idx_ec2_public_ip ON ec2_instances(public_ip)",
            # VPC indices
            "CREATE INDEX IF NOT EXISTS idx_vpc_scan ON vpcs(scan_id)",
            "CREATE INDEX IF NOT EXISTS idx_vpc_id ON vpcs(vpc_id)",
            "CREATE INDEX IF NOT EXISTS idx_vpc_region ON vpcs(region)",
            # Subnet indices
            "CREATE INDEX IF NOT EXISTS idx_subnet_scan ON subnets(scan_id)",
            "CREATE INDEX IF NOT EXISTS idx_subnet_vpc ON subnets(vpc_id)",
            "CREATE INDEX IF NOT EXISTS idx_subnet_region ON subnets(region)",
            # Security group indices
            "CREATE INDEX IF NOT EXISTS idx_sg_scan ON security_groups(scan_id)",
            "CREATE INDEX IF NOT EXISTS idx_sg_id ON security_groups(group_id)",
            "CREATE INDEX IF NOT EXISTS idx_sg_vpc ON security_groups(vpc_id)",
            # Load balancer indices
            "CREATE INDEX IF NOT EXISTS idx_lb_scan ON load_balancers(scan_id)",
            "CREATE INDEX IF NOT EXISTS idx_lb_arn ON load_balancers(load_balancer_arn)",
            "CREATE INDEX IF NOT EXISTS idx_lb_region ON load_balancers(region)",
            "CREATE INDEX IF NOT EXISTS idx_lb_vpc ON load_balancers(vpc_id)",
            "CREATE INDEX IF NOT EXISTS idx_lb_type ON load_balancers(load_balancer_type)",
            # NAT gateway indices
            "CREATE INDEX IF NOT EXISTS idx_nat_scan ON nat_gateways(scan_id)",
            "CREATE INDEX IF NOT EXISTS idx_nat_id ON nat_gateways(nat_gateway_id)",
            "CREATE INDEX IF NOT EXISTS idx_nat_region ON nat_gateways(region)",
            "CREATE INDEX IF NOT EXISTS idx_nat_vpc ON nat_gateways(vpc_id)",
            # Internet gateway indices
            "CREATE INDEX IF NOT EXISTS idx_igw_scan ON internet_gateways(scan_id)",
            "CREATE INDEX IF NOT EXISTS idx_igw_id ON internet_gateways(internet_gateway_id)",
            "CREATE INDEX IF NOT EXISTS idx_igw_region ON internet_gateways(region)",
            # Route table indices
            "CREATE INDEX IF NOT EXISTS idx_rt_scan ON route_tables(scan_id)",
            "CREATE INDEX IF NOT EXISTS idx_rt_id ON route_tables(route_table_id)",
            "CREATE INDEX IF NOT EXISTS idx_rt_region ON route_tables(region)",
            "CREATE INDEX IF NOT EXISTS idx_rt_vpc ON route_tables(vpc_id)",
            # Auto Scaling group indices
            "CREATE INDEX IF NOT EXISTS idx_asg_scan ON auto_scaling_groups(scan_id)",
            "CREATE INDEX IF NOT EXISTS idx_asg_name ON auto_scaling_groups(auto_scaling_group_name)",
            "CREATE INDEX IF NOT EXISTS idx_asg_region ON auto_scaling_groups(region)",
            # Network interface indices
            "CREATE INDEX IF NOT EXISTS idx_eni_scan ON network_interfaces(scan_id)",
            "CREATE INDEX IF NOT EXISTS idx_eni_id ON network_interfaces(network_interface_id)",
            "CREATE INDEX IF NOT EXISTS idx_eni_region ON network_interfaces(region)",
            "CREATE INDEX IF NOT EXISTS idx_eni_vpc ON network_interfaces(vpc_id)",
            "CREATE INDEX IF NOT EXISTS idx_eni_subnet ON network_interfaces(subnet_id)",
            # WorkSpaces indices
            "CREATE INDEX IF NOT EXISTS idx_ws_scan ON workspaces(scan_id)",
            "CREATE INDEX IF NOT EXISTS idx_ws_id ON workspaces(workspace_id)",
            "CREATE INDEX IF NOT EXISTS idx_ws_region ON workspaces(region)",
            "CREATE INDEX IF NOT EXISTS idx_ws_vpc ON workspaces(vpc_id)",
            "CREATE INDEX IF NOT EXISTS idx_ws_directory ON workspaces(directory_id)",
            # Lambda function indices
            "CREATE INDEX IF NOT EXISTS idx_lambda_scan ON lambda_functions(scan_id)",
            "CREATE INDEX IF NOT EXISTS idx_lambda_name ON lambda_functions(function_name)",
            "CREATE INDEX IF NOT EXISTS idx_lambda_region ON lambda_functions(region)",
            "CREATE INDEX IF NOT EXISTS idx_lambda_runtime ON lambda_functions(runtime)",
            # VPC Flow Log indices
            "CREATE INDEX IF NOT EXISTS idx_flowlog_scan ON vpc_flow_logs(scan_id)",
            "CREATE INDEX IF NOT EXISTS idx_flowlog_id ON vpc_flow_logs(flow_log_id)",
            "CREATE INDEX IF NOT EXISTS idx_flowlog_region ON vpc_flow_logs(region)",
            "CREATE INDEX IF NOT EXISTS idx_flowlog_resource ON vpc_flow_logs(resource_id)",
            "CREATE INDEX IF NOT EXISTS idx_flowlog_type ON vpc_flow_logs(resource_type)",
            # S3 indices
            "CREATE INDEX IF NOT EXISTS idx_s3_scan ON s3_buckets(scan_id)",
            "CREATE INDEX IF NOT EXISTS idx_s3_name ON s3_buckets(bucket_name)",
            # IAM indices
            "CREATE INDEX IF NOT EXISTS idx_iam_user_scan ON iam_users(scan_id)",
            "CREATE INDEX IF NOT EXISTS idx_iam_role_scan ON iam_roles(scan_id)",
            # Route53 indices
            "CREATE INDEX IF NOT EXISTS idx_r53_zone_scan ON route53_hosted_zones(scan_id)",
            "CREATE INDEX IF NOT EXISTS idx_r53_record_scan ON route53_record_sets(scan_id)",
            "CREATE INDEX IF NOT EXISTS idx_r53_record_zone ON route53_record_sets(hosted_zone_id)",
            # Cost data indices
            "CREATE INDEX IF NOT EXISTS idx_cost_scan ON cost_data(scan_id)",
            "CREATE INDEX IF NOT EXISTS idx_cost_account ON cost_data(account_number)",
            "CREATE INDEX IF NOT EXISTS idx_cost_service ON cost_data(service_name)",
            "CREATE INDEX IF NOT EXISTS idx_cost_period ON cost_data(time_period_start, time_period_end)",
            # Prowler findings indices
            "CREATE INDEX IF NOT EXISTS idx_prowler_scan ON prowler_findings(scan_id)",
            "CREATE INDEX IF NOT EXISTS idx_prowler_severity ON prowler_findings(severity)",
            "CREATE INDEX IF NOT EXISTS idx_prowler_status ON prowler_findings(status)",
            "CREATE INDEX IF NOT EXISTS idx_prowler_service ON prowler_findings(service_name)",
            # EBS volume indices
            "CREATE INDEX IF NOT EXISTS idx_ebs_vol_scan ON ebs_volumes(scan_id)",
            "CREATE INDEX IF NOT EXISTS idx_ebs_vol_id ON ebs_volumes(volume_id)",
            "CREATE INDEX IF NOT EXISTS idx_ebs_vol_region ON ebs_volumes(region)",
            "CREATE INDEX IF NOT EXISTS idx_ebs_vol_state ON ebs_volumes(state)",
            "CREATE INDEX IF NOT EXISTS idx_ebs_vol_instance ON ebs_volumes(attached_instance_id)",
            "CREATE INDEX IF NOT EXISTS idx_ebs_vol_encrypted ON ebs_volumes(encrypted)",
            # EBS snapshot indices
            "CREATE INDEX IF NOT EXISTS idx_ebs_snap_scan ON ebs_snapshots(scan_id)",
            "CREATE INDEX IF NOT EXISTS idx_ebs_snap_id ON ebs_snapshots(snapshot_id)",
            "CREATE INDEX IF NOT EXISTS idx_ebs_snap_region ON ebs_snapshots(region)",
            "CREATE INDEX IF NOT EXISTS idx_ebs_snap_volume ON ebs_snapshots(volume_id)",
            "CREATE INDEX IF NOT EXISTS idx_ebs_snap_encrypted ON ebs_snapshots(encrypted)",
            "CREATE INDEX IF NOT EXISTS idx_ebs_snap_start ON ebs_snapshots(start_time)",
            # RDS instance indices
            "CREATE INDEX IF NOT EXISTS idx_rds_scan ON rds_instances(scan_id)",
            "CREATE INDEX IF NOT EXISTS idx_rds_id ON rds_instances(db_instance_identifier)",
            "CREATE INDEX IF NOT EXISTS idx_rds_region ON rds_instances(region)",
            "CREATE INDEX IF NOT EXISTS idx_rds_engine ON rds_instances(engine)",
            "CREATE INDEX IF NOT EXISTS idx_rds_vpc ON rds_instances(vpc_id)",
            "CREATE INDEX IF NOT EXISTS idx_rds_public ON rds_instances(publicly_accessible)",
            "CREATE INDEX IF NOT EXISTS idx_rds_encrypted ON rds_instances(encrypted)",
            # IAM policy indices
            "CREATE INDEX IF NOT EXISTS idx_iam_policy_scan ON iam_policies(scan_id)",
            "CREATE INDEX IF NOT EXISTS idx_iam_policy_arn ON iam_policies(policy_arn)",
            "CREATE INDEX IF NOT EXISTS idx_iam_policy_name ON iam_policies(policy_name)",
            # KMS key indices
            "CREATE INDEX IF NOT EXISTS idx_kms_scan ON kms_keys(scan_id)",
            "CREATE INDEX IF NOT EXISTS idx_kms_id ON kms_keys(key_id)",
            "CREATE INDEX IF NOT EXISTS idx_kms_arn ON kms_keys(key_arn)",
            "CREATE INDEX IF NOT EXISTS idx_kms_region ON kms_keys(region)",
            "CREATE INDEX IF NOT EXISTS idx_kms_state ON kms_keys(key_state)",
            "CREATE INDEX IF NOT EXISTS idx_kms_manager ON kms_keys(key_manager)",
            # Elastic IP indices
            "CREATE INDEX IF NOT EXISTS idx_eip_scan ON elastic_ips(scan_id)",
            "CREATE INDEX IF NOT EXISTS idx_eip_alloc ON elastic_ips(allocation_id)",
            "CREATE INDEX IF NOT EXISTS idx_eip_region ON elastic_ips(region)",
            "CREATE INDEX IF NOT EXISTS idx_eip_instance ON elastic_ips(instance_id)",
            "CREATE INDEX IF NOT EXISTS idx_eip_associated ON elastic_ips(is_associated)",
            # Phase 2: ECS cluster indices
            "CREATE INDEX IF NOT EXISTS idx_ecs_cluster_scan ON ecs_clusters(scan_id)",
            "CREATE INDEX IF NOT EXISTS idx_ecs_cluster_arn ON ecs_clusters(cluster_arn)",
            "CREATE INDEX IF NOT EXISTS idx_ecs_cluster_name ON ecs_clusters(cluster_name)",
            "CREATE INDEX IF NOT EXISTS idx_ecs_cluster_region ON ecs_clusters(region)",
            "CREATE INDEX IF NOT EXISTS idx_ecs_cluster_status ON ecs_clusters(status)",
            # ECS service indices
            "CREATE INDEX IF NOT EXISTS idx_ecs_svc_scan ON ecs_services(scan_id)",
            "CREATE INDEX IF NOT EXISTS idx_ecs_svc_arn ON ecs_services(service_arn)",
            "CREATE INDEX IF NOT EXISTS idx_ecs_svc_name ON ecs_services(service_name)",
            "CREATE INDEX IF NOT EXISTS idx_ecs_svc_cluster ON ecs_services(cluster_arn)",
            "CREATE INDEX IF NOT EXISTS idx_ecs_svc_region ON ecs_services(region)",
            "CREATE INDEX IF NOT EXISTS idx_ecs_svc_status ON ecs_services(status)",
            # ECS task definition indices
            "CREATE INDEX IF NOT EXISTS idx_ecs_task_scan ON ecs_task_definitions(scan_id)",
            "CREATE INDEX IF NOT EXISTS idx_ecs_task_arn ON ecs_task_definitions(task_definition_arn)",
            "CREATE INDEX IF NOT EXISTS idx_ecs_task_family ON ecs_task_definitions(family)",
            "CREATE INDEX IF NOT EXISTS idx_ecs_task_region ON ecs_task_definitions(region)",
            "CREATE INDEX IF NOT EXISTS idx_ecs_task_status ON ecs_task_definitions(status)",
            # EKS cluster indices
            "CREATE INDEX IF NOT EXISTS idx_eks_cluster_scan ON eks_clusters(scan_id)",
            "CREATE INDEX IF NOT EXISTS idx_eks_cluster_name ON eks_clusters(cluster_name)",
            "CREATE INDEX IF NOT EXISTS idx_eks_cluster_arn ON eks_clusters(cluster_arn)",
            "CREATE INDEX IF NOT EXISTS idx_eks_cluster_region ON eks_clusters(region)",
            "CREATE INDEX IF NOT EXISTS idx_eks_cluster_vpc ON eks_clusters(vpc_id)",
            "CREATE INDEX IF NOT EXISTS idx_eks_cluster_status ON eks_clusters(status)",
            # EKS node group indices
            "CREATE INDEX IF NOT EXISTS idx_eks_ng_scan ON eks_node_groups(scan_id)",
            "CREATE INDEX IF NOT EXISTS idx_eks_ng_cluster ON eks_node_groups(cluster_name)",
            "CREATE INDEX IF NOT EXISTS idx_eks_ng_name ON eks_node_groups(nodegroup_name)",
            "CREATE INDEX IF NOT EXISTS idx_eks_ng_arn ON eks_node_groups(nodegroup_arn)",
            "CREATE INDEX IF NOT EXISTS idx_eks_ng_region ON eks_node_groups(region)",
            "CREATE INDEX IF NOT EXISTS idx_eks_ng_status ON eks_node_groups(status)",
            # ECR repository indices
            "CREATE INDEX IF NOT EXISTS idx_ecr_repo_scan ON ecr_repositories(scan_id)",
            "CREATE INDEX IF NOT EXISTS idx_ecr_repo_arn ON ecr_repositories(repository_arn)",
            "CREATE INDEX IF NOT EXISTS idx_ecr_repo_name ON ecr_repositories(repository_name)",
            "CREATE INDEX IF NOT EXISTS idx_ecr_repo_region ON ecr_repositories(region)",
            # ECR image indices
            "CREATE INDEX IF NOT EXISTS idx_ecr_img_scan ON ecr_images(scan_id)",
            "CREATE INDEX IF NOT EXISTS idx_ecr_img_repo ON ecr_images(repository_name)",
            "CREATE INDEX IF NOT EXISTS idx_ecr_img_digest ON ecr_images(image_digest)",
            "CREATE INDEX IF NOT EXISTS idx_ecr_img_region ON ecr_images(region)",
            # API Gateway REST API indices
            "CREATE INDEX IF NOT EXISTS idx_apigw_rest_scan ON api_gateway_rest_apis(scan_id)",
            "CREATE INDEX IF NOT EXISTS idx_apigw_rest_id ON api_gateway_rest_apis(api_id)",
            "CREATE INDEX IF NOT EXISTS idx_apigw_rest_name ON api_gateway_rest_apis(name)",
            "CREATE INDEX IF NOT EXISTS idx_apigw_rest_region ON api_gateway_rest_apis(region)",
            # API Gateway HTTP API indices
            "CREATE INDEX IF NOT EXISTS idx_apigw_http_scan ON api_gateway_http_apis(scan_id)",
            "CREATE INDEX IF NOT EXISTS idx_apigw_http_id ON api_gateway_http_apis(api_id)",
            "CREATE INDEX IF NOT EXISTS idx_apigw_http_name ON api_gateway_http_apis(name)",
            "CREATE INDEX IF NOT EXISTS idx_apigw_http_region ON api_gateway_http_apis(region)",
            # API Gateway stage indices
            "CREATE INDEX IF NOT EXISTS idx_apigw_stage_scan ON api_gateway_stages(scan_id)",
            "CREATE INDEX IF NOT EXISTS idx_apigw_stage_api ON api_gateway_stages(api_id)",
            "CREATE INDEX IF NOT EXISTS idx_apigw_stage_name ON api_gateway_stages(stage_name)",
            "CREATE INDEX IF NOT EXISTS idx_apigw_stage_region ON api_gateway_stages(region)",
            "CREATE INDEX IF NOT EXISTS idx_apigw_stage_type ON api_gateway_stages(api_type)",
            # CloudFront distribution indices
            "CREATE INDEX IF NOT EXISTS idx_cf_dist_scan ON cloudfront_distributions(scan_id)",
            "CREATE INDEX IF NOT EXISTS idx_cf_dist_id ON cloudfront_distributions(distribution_id)",
            "CREATE INDEX IF NOT EXISTS idx_cf_dist_arn ON cloudfront_distributions(distribution_arn)",
            "CREATE INDEX IF NOT EXISTS idx_cf_dist_status ON cloudfront_distributions(status)",
            "CREATE INDEX IF NOT EXISTS idx_cf_dist_enabled ON cloudfront_distributions(enabled)",
            # Phase 3: Governance, Logging & Advanced Services indices
            # Organizations indices
            "CREATE INDEX IF NOT EXISTS idx_org_scan ON organizations(scan_id)",
            "CREATE INDEX IF NOT EXISTS idx_org_id ON organizations(organization_id)",
            # Organizational units indices
            "CREATE INDEX IF NOT EXISTS idx_ou_scan ON organizational_units(scan_id)",
            "CREATE INDEX IF NOT EXISTS idx_ou_id ON organizational_units(ou_id)",
            "CREATE INDEX IF NOT EXISTS idx_ou_parent ON organizational_units(parent_id)",
            # Organization accounts indices
            "CREATE INDEX IF NOT EXISTS idx_org_acct_scan ON organization_accounts(scan_id)",
            "CREATE INDEX IF NOT EXISTS idx_org_acct_id ON organization_accounts(account_id)",
            "CREATE INDEX IF NOT EXISTS idx_org_acct_status ON organization_accounts(status)",
            "CREATE INDEX IF NOT EXISTS idx_org_acct_parent ON organization_accounts(parent_ou_id)",
            # SSO permission set indices
            "CREATE INDEX IF NOT EXISTS idx_sso_perm_scan ON sso_permission_sets(scan_id)",
            "CREATE INDEX IF NOT EXISTS idx_sso_perm_arn ON sso_permission_sets(permission_set_arn)",
            "CREATE INDEX IF NOT EXISTS idx_sso_perm_name ON sso_permission_sets(permission_set_name)",
            "CREATE INDEX IF NOT EXISTS idx_sso_perm_instance ON sso_permission_sets(instance_arn)",
            # SSO assignment indices
            "CREATE INDEX IF NOT EXISTS idx_sso_assign_scan ON sso_assignments(scan_id)",
            "CREATE INDEX IF NOT EXISTS idx_sso_assign_perm ON sso_assignments(permission_set_arn)",
            "CREATE INDEX IF NOT EXISTS idx_sso_assign_principal ON sso_assignments(principal_id)",
            "CREATE INDEX IF NOT EXISTS idx_sso_assign_target ON sso_assignments(target_id)",
            # CloudTrail indices
            "CREATE INDEX IF NOT EXISTS idx_ct_scan ON cloudtrail_trails(scan_id)",
            "CREATE INDEX IF NOT EXISTS idx_ct_name ON cloudtrail_trails(trail_name)",
            "CREATE INDEX IF NOT EXISTS idx_ct_arn ON cloudtrail_trails(trail_arn)",
            "CREATE INDEX IF NOT EXISTS idx_ct_region ON cloudtrail_trails(region)",
            "CREATE INDEX IF NOT EXISTS idx_ct_logging ON cloudtrail_trails(is_logging)",
            # CloudWatch log group indices
            "CREATE INDEX IF NOT EXISTS idx_cw_lg_scan ON cloudwatch_log_groups(scan_id)",
            "CREATE INDEX IF NOT EXISTS idx_cw_lg_name ON cloudwatch_log_groups(log_group_name)",
            "CREATE INDEX IF NOT EXISTS idx_cw_lg_arn ON cloudwatch_log_groups(log_group_arn)",
            "CREATE INDEX IF NOT EXISTS idx_cw_lg_region ON cloudwatch_log_groups(region)",
            # Config recorder indices
            "CREATE INDEX IF NOT EXISTS idx_cfg_rec_scan ON config_recorders(scan_id)",
            "CREATE INDEX IF NOT EXISTS idx_cfg_rec_name ON config_recorders(recorder_name)",
            "CREATE INDEX IF NOT EXISTS idx_cfg_rec_region ON config_recorders(region)",
            "CREATE INDEX IF NOT EXISTS idx_cfg_rec_recording ON config_recorders(is_recording)",
            # Config rule indices
            "CREATE INDEX IF NOT EXISTS idx_cfg_rule_scan ON config_rules(scan_id)",
            "CREATE INDEX IF NOT EXISTS idx_cfg_rule_name ON config_rules(rule_name)",
            "CREATE INDEX IF NOT EXISTS idx_cfg_rule_arn ON config_rules(rule_arn)",
            "CREATE INDEX IF NOT EXISTS idx_cfg_rule_region ON config_rules(region)",
            "CREATE INDEX IF NOT EXISTS idx_cfg_rule_compliance ON config_rules(compliance_type)",
            # Bedrock model indices
            "CREATE INDEX IF NOT EXISTS idx_br_model_scan ON bedrock_models(scan_id)",
            "CREATE INDEX IF NOT EXISTS idx_br_model_id ON bedrock_models(model_id)",
            "CREATE INDEX IF NOT EXISTS idx_br_model_arn ON bedrock_models(model_arn)",
            "CREATE INDEX IF NOT EXISTS idx_br_model_region ON bedrock_models(region)",
            "CREATE INDEX IF NOT EXISTS idx_br_model_provider ON bedrock_models(provider_name)",
            # Bedrock guardrail indices
            "CREATE INDEX IF NOT EXISTS idx_br_guard_scan ON bedrock_guardrails(scan_id)",
            "CREATE INDEX IF NOT EXISTS idx_br_guard_id ON bedrock_guardrails(guardrail_id)",
            "CREATE INDEX IF NOT EXISTS idx_br_guard_arn ON bedrock_guardrails(guardrail_arn)",
            "CREATE INDEX IF NOT EXISTS idx_br_guard_region ON bedrock_guardrails(region)",
            "CREATE INDEX IF NOT EXISTS idx_br_guard_status ON bedrock_guardrails(status)",
            # Bedrock knowledge base indices
            "CREATE INDEX IF NOT EXISTS idx_br_kb_scan ON bedrock_knowledge_bases(scan_id)",
            "CREATE INDEX IF NOT EXISTS idx_br_kb_id ON bedrock_knowledge_bases(knowledge_base_id)",
            "CREATE INDEX IF NOT EXISTS idx_br_kb_arn ON bedrock_knowledge_bases(knowledge_base_arn)",
            "CREATE INDEX IF NOT EXISTS idx_br_kb_region ON bedrock_knowledge_bases(region)",
            "CREATE INDEX IF NOT EXISTS idx_br_kb_status ON bedrock_knowledge_bases(status)",
            # Bedrock agent indices
            "CREATE INDEX IF NOT EXISTS idx_br_agent_scan ON bedrock_agents(scan_id)",
            "CREATE INDEX IF NOT EXISTS idx_br_agent_id ON bedrock_agents(agent_id)",
            "CREATE INDEX IF NOT EXISTS idx_br_agent_arn ON bedrock_agents(agent_arn)",
            "CREATE INDEX IF NOT EXISTS idx_br_agent_region ON bedrock_agents(region)",
            "CREATE INDEX IF NOT EXISTS idx_br_agent_status ON bedrock_agents(agent_status)",
            # Directory service indices
            "CREATE INDEX IF NOT EXISTS idx_ds_scan ON directory_services(scan_id)",
            "CREATE INDEX IF NOT EXISTS idx_ds_id ON directory_services(directory_id)",
            "CREATE INDEX IF NOT EXISTS idx_ds_name ON directory_services(directory_name)",
            "CREATE INDEX IF NOT EXISTS idx_ds_region ON directory_services(region)",
            "CREATE INDEX IF NOT EXISTS idx_ds_type ON directory_services(directory_type)",
            "CREATE INDEX IF NOT EXISTS idx_ds_vpc ON directory_services(vpc_id)",
            # Transit gateway indices
            "CREATE INDEX IF NOT EXISTS idx_tgw_scan ON transit_gateways(scan_id)",
            "CREATE INDEX IF NOT EXISTS idx_tgw_id ON transit_gateways(transit_gateway_id)",
            "CREATE INDEX IF NOT EXISTS idx_tgw_arn ON transit_gateways(transit_gateway_arn)",
            "CREATE INDEX IF NOT EXISTS idx_tgw_region ON transit_gateways(region)",
            "CREATE INDEX IF NOT EXISTS idx_tgw_state ON transit_gateways(state)",
            # VPN connection indices
            "CREATE INDEX IF NOT EXISTS idx_vpn_scan ON vpn_connections(scan_id)",
            "CREATE INDEX IF NOT EXISTS idx_vpn_id ON vpn_connections(vpn_connection_id)",
            "CREATE INDEX IF NOT EXISTS idx_vpn_region ON vpn_connections(region)",
            "CREATE INDEX IF NOT EXISTS idx_vpn_state ON vpn_connections(state)",
            # Direct Connect indices
            "CREATE INDEX IF NOT EXISTS idx_dx_scan ON direct_connect_connections(scan_id)",
            "CREATE INDEX IF NOT EXISTS idx_dx_id ON direct_connect_connections(connection_id)",
            "CREATE INDEX IF NOT EXISTS idx_dx_name ON direct_connect_connections(connection_name)",
            "CREATE INDEX IF NOT EXISTS idx_dx_region ON direct_connect_connections(region)",
            "CREATE INDEX IF NOT EXISTS idx_dx_state ON direct_connect_connections(connection_state)",
            # ElastiCache indices
            "CREATE INDEX IF NOT EXISTS idx_ec_scan ON elasticache_clusters(scan_id)",
            "CREATE INDEX IF NOT EXISTS idx_ec_id ON elasticache_clusters(cache_cluster_id)",
            "CREATE INDEX IF NOT EXISTS idx_ec_arn ON elasticache_clusters(cache_cluster_arn)",
            "CREATE INDEX IF NOT EXISTS idx_ec_region ON elasticache_clusters(region)",
            "CREATE INDEX IF NOT EXISTS idx_ec_engine ON elasticache_clusters(engine)",
            "CREATE INDEX IF NOT EXISTS idx_ec_vpc ON elasticache_clusters(vpc_id)",
            "CREATE INDEX IF NOT EXISTS idx_ec_status ON elasticache_clusters(cache_cluster_status)",
            # OpenSearch indices
            "CREATE INDEX IF NOT EXISTS idx_os_scan ON opensearch_domains(scan_id)",
            "CREATE INDEX IF NOT EXISTS idx_os_id ON opensearch_domains(domain_id)",
            "CREATE INDEX IF NOT EXISTS idx_os_name ON opensearch_domains(domain_name)",
            "CREATE INDEX IF NOT EXISTS idx_os_arn ON opensearch_domains(domain_arn)",
            "CREATE INDEX IF NOT EXISTS idx_os_region ON opensearch_domains(region)",
            "CREATE INDEX IF NOT EXISTS idx_os_vpc ON opensearch_domains(vpc_id)",
            # MSK indices
            "CREATE INDEX IF NOT EXISTS idx_msk_scan ON msk_clusters(scan_id)",
            "CREATE INDEX IF NOT EXISTS idx_msk_arn ON msk_clusters(cluster_arn)",
            "CREATE INDEX IF NOT EXISTS idx_msk_name ON msk_clusters(cluster_name)",
            "CREATE INDEX IF NOT EXISTS idx_msk_region ON msk_clusters(region)",
            "CREATE INDEX IF NOT EXISTS idx_msk_state ON msk_clusters(state)",
            # DynamoDB indices
            "CREATE INDEX IF NOT EXISTS idx_ddb_scan ON dynamodb_tables(scan_id)",
            "CREATE INDEX IF NOT EXISTS idx_ddb_name ON dynamodb_tables(table_name)",
            "CREATE INDEX IF NOT EXISTS idx_ddb_arn ON dynamodb_tables(table_arn)",
            "CREATE INDEX IF NOT EXISTS idx_ddb_region ON dynamodb_tables(region)",
            "CREATE INDEX IF NOT EXISTS idx_ddb_status ON dynamodb_tables(table_status)",

            # Security posture indices
            "CREATE INDEX IF NOT EXISTS idx_posture_scan ON account_security_posture(scan_id)",
            "CREATE INDEX IF NOT EXISTS idx_credreport_scan ON iam_credential_report(scan_id)",
            "CREATE INDEX IF NOT EXISTS idx_credreport_user ON iam_credential_report(user_name)",
            "CREATE INDEX IF NOT EXISTS idx_regionsec_scan ON region_security_services(scan_id)",
            "CREATE INDEX IF NOT EXISTS idx_regionsec_region ON region_security_services(region)",
            "CREATE INDEX IF NOT EXISTS idx_lambdaexp_scan ON lambda_exposure(scan_id)",
            "CREATE INDEX IF NOT EXISTS idx_lambdaexp_auth ON lambda_exposure(url_auth_type)",
            "CREATE INDEX IF NOT EXISTS idx_s3pab_scan ON s3_public_access(scan_id)",
            "CREATE INDEX IF NOT EXISTS idx_s3pab_bucket ON s3_public_access(bucket_name)",
        ]

        for index_sql in indices:
            cursor.execute(index_sql)

    def get_schema_version(self) -> Optional[int]:
        """
        Get current database schema version.

        Returns:
            Schema version number or None if not initialised
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT MAX(version) FROM schema_version")
                result = cursor.fetchone()
                return result[0] if result else None
        except sqlite3.OperationalError:
            return None
