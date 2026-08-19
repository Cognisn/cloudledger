"""
Database models for CloudLedger.

This module defines Pydantic models for data validation and SQLite schema representation.
All models use Australian English in documentation.
"""

from datetime import datetime
from typing import Optional, Dict, List, Any
from pydantic import BaseModel, Field, ConfigDict


class ScanMetadata(BaseModel):
    """Metadata for a scan operation."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    scan_id: str = Field(description="Unique identifier for the scan")
    account_name: str = Field(description="Friendly name for the AWS account")
    account_number: str = Field(description="12-digit AWS account ID")
    scan_timestamp: datetime = Field(description="When the scan was initiated")
    prowler_level: Optional[str] = Field(default=None, description="Prowler scan level (1, 2, 3, or skip)")
    regions_scanned: List[str] = Field(description="List of AWS regions scanned")
    scan_status: str = Field(default="in_progress", description="Status: in_progress, completed, failed")
    error_message: Optional[str] = Field(default=None, description="Error message if scan failed")
    scan_duration_seconds: Optional[float] = Field(default=None, description="Total scan duration")
    org_member: Optional[bool] = Field(default=None, description="Whether the scanned account belongs to an AWS Organization")
    is_management_account: Optional[bool] = Field(default=None, description="Whether the scanned account is the organisation's management account")
    management_account_id: Optional[str] = Field(default=None, description="12-digit account ID of the organisation's management account")
    management_account_name: Optional[str] = Field(default=None, description="Friendly name of the organisation's management account")


class EC2Instance(BaseModel):
    """EC2 instance resource."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    scan_id: str
    instance_id: str
    region: str
    instance_type: str
    state: str
    public_ip: Optional[str] = None
    private_ip: Optional[str] = None
    vpc_id: Optional[str] = None
    subnet_id: Optional[str] = None
    availability_zone: str
    launch_time: datetime
    platform: Optional[str] = None
    security_groups: List[str] = Field(default_factory=list)
    tags: Dict[str, str] = Field(default_factory=dict)
    iam_instance_profile: Optional[str] = None
    monitoring_state: Optional[str] = None
    raw_data: Dict[str, Any] = Field(default_factory=dict)


class VPC(BaseModel):
    """VPC resource."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    scan_id: str
    vpc_id: str
    region: str
    cidr_block: str
    state: str
    is_default: bool
    dhcp_options_id: Optional[str] = None
    instance_tenancy: str
    tags: Dict[str, str] = Field(default_factory=dict)
    raw_data: Dict[str, Any] = Field(default_factory=dict)


class Subnet(BaseModel):
    """Subnet resource."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    scan_id: str
    subnet_id: str
    vpc_id: str
    region: str
    cidr_block: str
    availability_zone: str
    available_ip_count: int
    map_public_ip: bool
    state: str
    tags: Dict[str, str] = Field(default_factory=dict)
    raw_data: Dict[str, Any] = Field(default_factory=dict)


class SecurityGroup(BaseModel):
    """Security group resource."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    scan_id: str
    group_id: str
    group_name: str
    vpc_id: Optional[str] = None
    region: str
    description: str
    ingress_rules: List[Dict[str, Any]] = Field(default_factory=list)
    egress_rules: List[Dict[str, Any]] = Field(default_factory=list)
    tags: Dict[str, str] = Field(default_factory=dict)
    raw_data: Dict[str, Any] = Field(default_factory=dict)


class S3Bucket(BaseModel):
    """S3 bucket resource."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    scan_id: str
    bucket_name: str
    creation_date: datetime
    region: Optional[str] = None
    versioning_status: Optional[str] = None
    public_access_block: Optional[Dict[str, bool]] = None
    encryption_config: Optional[Dict[str, Any]] = None
    lifecycle_rules: List[Dict[str, Any]] = Field(default_factory=list)
    logging_enabled: bool = False
    size_bytes: Optional[int] = None
    object_count: Optional[int] = None
    tags: Dict[str, str] = Field(default_factory=dict)
    raw_data: Dict[str, Any] = Field(default_factory=dict)


class IAMUser(BaseModel):
    """IAM user resource."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    scan_id: str
    user_name: str
    user_id: str
    arn: str
    create_date: datetime
    password_last_used: Optional[datetime] = None
    mfa_enabled: bool = False
    access_keys: List[Dict[str, Any]] = Field(default_factory=list)
    attached_policies: List[str] = Field(default_factory=list)
    groups: List[str] = Field(default_factory=list)
    tags: Dict[str, str] = Field(default_factory=dict)
    raw_data: Dict[str, Any] = Field(default_factory=dict)


class IAMRole(BaseModel):
    """IAM role resource."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    scan_id: str
    role_name: str
    role_id: str
    arn: str
    create_date: datetime
    assume_role_policy: Dict[str, Any]
    attached_policies: List[str] = Field(default_factory=list)
    max_session_duration: int
    tags: Dict[str, str] = Field(default_factory=dict)
    raw_data: Dict[str, Any] = Field(default_factory=dict)


class Route53HostedZone(BaseModel):
    """Route53 hosted zone resource."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    scan_id: str
    hosted_zone_id: str
    name: str
    is_private: bool
    resource_record_set_count: int
    vpc_associations: List[Dict[str, str]] = Field(default_factory=list)
    tags: Dict[str, str] = Field(default_factory=dict)
    raw_data: Dict[str, Any] = Field(default_factory=dict)


class Route53RecordSet(BaseModel):
    """Route53 DNS record set."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    scan_id: str
    hosted_zone_id: str
    name: str
    record_type: str
    ttl: Optional[int] = None
    resource_records: List[str] = Field(default_factory=list)
    alias_target: Optional[Dict[str, Any]] = None
    raw_data: Dict[str, Any] = Field(default_factory=dict)


class CostData(BaseModel):
    """Cost and billing data."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    scan_id: str
    account_number: str
    time_period_start: datetime
    time_period_end: datetime
    service_name: str
    amount: float
    currency: str
    unit: str
    raw_data: Dict[str, Any] = Field(default_factory=dict)


class LoadBalancer(BaseModel):
    """Load Balancer resource (ELB/ALB/NLB)."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    scan_id: str
    load_balancer_name: str
    load_balancer_arn: str
    load_balancer_type: str  # classic, application, network, gateway
    region: str
    vpc_id: Optional[str] = None
    scheme: str  # internet-facing or internal
    state: str
    dns_name: str
    availability_zones: List[str] = Field(default_factory=list)
    security_groups: List[str] = Field(default_factory=list)
    subnets: List[str] = Field(default_factory=list)
    created_time: Optional[datetime] = None
    listeners: List[Dict[str, Any]] = Field(default_factory=list)
    target_groups: List[Dict[str, Any]] = Field(default_factory=list)
    tags: Dict[str, str] = Field(default_factory=dict)
    raw_data: Dict[str, Any] = Field(default_factory=dict)


class NATGateway(BaseModel):
    """NAT Gateway resource."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    scan_id: str
    nat_gateway_id: str
    region: str
    vpc_id: str
    subnet_id: str
    state: str
    connectivity_type: str  # public or private
    public_ip: Optional[str] = None
    private_ip: Optional[str] = None
    created_time: Optional[datetime] = None
    nat_gateway_addresses: List[Dict[str, Any]] = Field(default_factory=list)
    tags: Dict[str, str] = Field(default_factory=dict)
    raw_data: Dict[str, Any] = Field(default_factory=dict)


class InternetGateway(BaseModel):
    """Internet Gateway resource."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    scan_id: str
    internet_gateway_id: str
    region: str
    vpc_attachments: List[Dict[str, str]] = Field(default_factory=list)
    tags: Dict[str, str] = Field(default_factory=dict)
    raw_data: Dict[str, Any] = Field(default_factory=dict)


class RouteTable(BaseModel):
    """Route Table resource."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    scan_id: str
    route_table_id: str
    region: str
    vpc_id: str
    is_main: bool = False
    routes: List[Dict[str, Any]] = Field(default_factory=list)
    subnet_associations: List[str] = Field(default_factory=list)
    gateway_associations: List[str] = Field(default_factory=list)
    tags: Dict[str, str] = Field(default_factory=dict)
    raw_data: Dict[str, Any] = Field(default_factory=dict)


class AutoScalingGroup(BaseModel):
    """Auto Scaling Group resource."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    scan_id: str
    auto_scaling_group_name: str
    auto_scaling_group_arn: str
    region: str
    launch_configuration_name: Optional[str] = None
    launch_template: Optional[Dict[str, Any]] = None
    min_size: int
    max_size: int
    desired_capacity: int
    default_cooldown: int
    availability_zones: List[str] = Field(default_factory=list)
    load_balancer_names: List[str] = Field(default_factory=list)
    target_group_arns: List[str] = Field(default_factory=list)
    health_check_type: str
    health_check_grace_period: int
    vpc_zone_identifier: Optional[str] = None
    instances: List[Dict[str, Any]] = Field(default_factory=list)
    created_time: datetime
    tags: Dict[str, str] = Field(default_factory=dict)
    raw_data: Dict[str, Any] = Field(default_factory=dict)


class NetworkInterface(BaseModel):
    """Network Interface (ENI) resource."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    scan_id: str
    network_interface_id: str
    region: str
    interface_type: str
    status: str
    vpc_id: str
    subnet_id: str
    availability_zone: str
    description: Optional[str] = None
    private_ip_address: Optional[str] = None
    private_ip_addresses: List[Dict[str, Any]] = Field(default_factory=list)
    public_ip: Optional[str] = None
    mac_address: Optional[str] = None
    source_dest_check: bool = True
    security_groups: List[str] = Field(default_factory=list)
    attachment: Optional[Dict[str, Any]] = None
    tags: Dict[str, str] = Field(default_factory=dict)
    raw_data: Dict[str, Any] = Field(default_factory=dict)


class WorkSpace(BaseModel):
    """WorkSpace resource."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    scan_id: str
    workspace_id: str
    region: str
    directory_id: str
    user_name: str
    bundle_id: str
    subnet_id: str
    vpc_id: Optional[str] = None
    ip_address: Optional[str] = None
    state: str
    compute_type: str
    volume_encryption_enabled: bool = False
    user_volume_size_gb: int
    root_volume_size_gb: int
    running_mode: str
    tags: Dict[str, str] = Field(default_factory=dict)
    raw_data: Dict[str, Any] = Field(default_factory=dict)


class LambdaFunction(BaseModel):
    """Lambda function resource."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    scan_id: str
    function_name: str
    function_arn: str
    region: str
    runtime: str
    handler: str
    code_size: int
    memory_size: int
    timeout: int
    last_modified: datetime
    role_arn: str
    vpc_config: Optional[Dict[str, Any]] = None
    environment_variables: Dict[str, str] = Field(default_factory=dict)
    layers: List[str] = Field(default_factory=list)
    state: str
    architectures: List[str] = Field(default_factory=list)
    triggers: List[Dict[str, Any]] = Field(default_factory=list)
    tags: Dict[str, str] = Field(default_factory=dict)
    raw_data: Dict[str, Any] = Field(default_factory=dict)


class VPCFlowLog(BaseModel):
    """VPC Flow Log resource."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    scan_id: str
    flow_log_id: str
    region: str
    resource_id: str  # VPC, Subnet, or ENI ID
    resource_type: str  # VPC, Subnet, NetworkInterface
    traffic_type: str  # ACCEPT, REJECT, ALL
    log_destination_type: str  # cloud-watch-logs, s3
    log_destination: str
    log_format: Optional[str] = None
    flow_log_status: str
    created_time: Optional[datetime] = None
    tags: Dict[str, str] = Field(default_factory=dict)
    raw_data: Dict[str, Any] = Field(default_factory=dict)


class ProwlerFinding(BaseModel):
    """Prowler security finding."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    scan_id: str
    check_id: str
    check_title: str
    severity: str
    status: str  # PASS, FAIL, WARNING
    region: Optional[str] = None
    resource_id: Optional[str] = None
    resource_arn: Optional[str] = None
    resource_tags: Dict[str, str] = Field(default_factory=dict)
    status_extended: Optional[str] = None
    service_name: str
    check_type: str
    risk: Optional[str] = None
    remediation: Optional[str] = None
    compliance_frameworks: List[str] = Field(default_factory=list)
    raw_data: Dict[str, Any] = Field(default_factory=dict)


class EBSVolume(BaseModel):
    """EBS volume resource."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    scan_id: str
    volume_id: str
    region: str
    size: int  # Size in GiB
    volume_type: str  # gp2, gp3, io1, io2, st1, sc1, standard
    iops: Optional[int] = None
    throughput: Optional[int] = None  # For gp3 volumes
    encrypted: bool
    kms_key_id: Optional[str] = None
    state: str  # creating, available, in-use, deleting, deleted, error
    create_time: datetime
    availability_zone: str
    snapshot_id: Optional[str] = None  # Source snapshot if created from snapshot
    # Attachment information
    attached_instance_id: Optional[str] = None
    device_name: Optional[str] = None
    attachment_state: Optional[str] = None  # attaching, attached, detaching, detached
    multi_attach_enabled: bool = False
    tags: Dict[str, str] = Field(default_factory=dict)
    raw_data: Dict[str, Any] = Field(default_factory=dict)


class EBSSnapshot(BaseModel):
    """EBS snapshot resource."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    scan_id: str
    snapshot_id: str
    region: str
    volume_id: Optional[str] = None  # Source volume (may be deleted)
    volume_size: int  # Size in GiB
    encrypted: bool
    kms_key_id: Optional[str] = None
    state: str  # pending, completed, error
    start_time: datetime
    progress: str  # Percentage completion
    owner_id: str
    description: Optional[str] = None
    tags: Dict[str, str] = Field(default_factory=dict)
    raw_data: Dict[str, Any] = Field(default_factory=dict)


class RDSInstance(BaseModel):
    """RDS database instance resource."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    scan_id: str
    db_instance_identifier: str
    region: str
    db_instance_arn: str
    engine: str  # mysql, postgres, mariadb, oracle-se2, sqlserver-ex, etc.
    engine_version: str
    db_instance_class: str  # db.t3.micro, db.r5.large, etc.
    allocated_storage: int  # GiB
    storage_type: str  # gp2, gp3, io1, standard
    iops: Optional[int] = None
    # Availability
    multi_az: bool
    availability_zone: Optional[str] = None
    secondary_availability_zone: Optional[str] = None
    publicly_accessible: bool
    # Security
    encrypted: bool
    kms_key_id: Optional[str] = None
    vpc_id: Optional[str] = None
    subnet_group: Optional[str] = None
    vpc_security_groups: List[str] = Field(default_factory=list)
    # Backup
    backup_retention_period: int  # Days
    preferred_backup_window: Optional[str] = None
    latest_restorable_time: Optional[datetime] = None
    # Endpoint
    endpoint_address: Optional[str] = None
    endpoint_port: Optional[int] = None
    # Status
    db_instance_status: str  # available, stopped, starting, stopping, etc.
    # Performance
    monitoring_interval: int = 0  # Enhanced monitoring interval in seconds
    performance_insights_enabled: bool = False
    # Additional
    auto_minor_version_upgrade: bool = True
    deletion_protection: bool = False
    tags: Dict[str, str] = Field(default_factory=dict)
    raw_data: Dict[str, Any] = Field(default_factory=dict)


class IAMPolicy(BaseModel):
    """IAM policy resource."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    scan_id: str
    policy_arn: str
    policy_name: str
    policy_id: str
    path: str
    default_version_id: str
    attachment_count: int
    permissions_boundary_usage_count: int
    is_attachable: bool
    description: Optional[str] = None
    create_date: datetime
    update_date: datetime
    policy_document: Dict[str, Any] = Field(default_factory=dict)  # The actual policy JSON
    attached_users: List[str] = Field(default_factory=list)  # List of user names
    attached_roles: List[str] = Field(default_factory=list)  # List of role names
    attached_groups: List[str] = Field(default_factory=list)  # List of group names
    tags: Dict[str, str] = Field(default_factory=dict)
    raw_data: Dict[str, Any] = Field(default_factory=dict)


class KMSKey(BaseModel):
    """KMS encryption key resource."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    scan_id: str
    key_id: str  # Key ID (not full ARN)
    key_arn: str
    region: str
    aws_account_id: str
    key_state: str  # Enabled, Disabled, PendingDeletion, PendingImport, Unavailable
    creation_date: datetime
    key_manager: str  # CUSTOMER, AWS, AWS-managed
    key_usage: str  # ENCRYPT_DECRYPT, SIGN_VERIFY, GENERATE_VERIFY_MAC
    key_spec: str  # SYMMETRIC_DEFAULT, RSA_2048, RSA_3072, RSA_4096, ECC_*, etc.
    description: Optional[str] = None
    enabled: bool
    deletion_date: Optional[datetime] = None
    # Rotation
    rotation_enabled: bool = False
    # Policy
    key_policy: Dict[str, Any] = Field(default_factory=dict)
    # Aliases
    aliases: List[str] = Field(default_factory=list)  # List of alias names
    tags: Dict[str, str] = Field(default_factory=dict)
    raw_data: Dict[str, Any] = Field(default_factory=dict)


class ElasticIP(BaseModel):
    """Elastic IP address resource."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    scan_id: str
    allocation_id: str
    region: str
    public_ip: str
    domain: str  # vpc or standard
    # Association information
    instance_id: Optional[str] = None
    network_interface_id: Optional[str] = None
    network_interface_owner_id: Optional[str] = None
    private_ip_address: Optional[str] = None
    association_id: Optional[str] = None
    # State
    is_associated: bool  # True if associated with a resource
    tags: Dict[str, str] = Field(default_factory=dict)
    raw_data: Dict[str, Any] = Field(default_factory=dict)


# Phase 2: Containers & Application Services


class ECSCluster(BaseModel):
    """ECS cluster resource."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    scan_id: str
    cluster_arn: str
    cluster_name: str
    region: str
    status: str  # ACTIVE, PROVISIONING, DEPROVISIONING, FAILED, INACTIVE
    # Capacity
    registered_container_instances_count: int = 0
    running_tasks_count: int = 0
    pending_tasks_count: int = 0
    active_services_count: int = 0
    # Configuration
    capacity_providers: List[str] = Field(default_factory=list)
    default_capacity_provider_strategy: List[Dict[str, Any]] = Field(default_factory=list)
    # Settings
    settings: List[Dict[str, str]] = Field(default_factory=list)  # containerInsights, etc.
    # Statistics
    statistics: List[Dict[str, Any]] = Field(default_factory=list)
    tags: Dict[str, str] = Field(default_factory=dict)
    raw_data: Dict[str, Any] = Field(default_factory=dict)


class ECSService(BaseModel):
    """ECS service resource."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    scan_id: str
    service_arn: str
    service_name: str
    cluster_arn: str
    region: str
    status: str  # ACTIVE, DRAINING, INACTIVE
    # Task configuration
    task_definition: str  # ARN of task definition
    desired_count: int
    running_count: int
    pending_count: int
    launch_type: Optional[str] = None  # EC2, FARGATE, EXTERNAL
    platform_version: Optional[str] = None  # For Fargate
    platform_family: Optional[str] = None  # LINUX, WINDOWS_SERVER_*
    # Capacity provider strategy
    capacity_provider_strategy: List[Dict[str, Any]] = Field(default_factory=list)
    # Networking
    network_configuration: Dict[str, Any] = Field(default_factory=dict)  # awsvpcConfiguration
    # Load balancing
    load_balancers: List[Dict[str, Any]] = Field(default_factory=list)  # target_group_arn, container_name, container_port
    # Service discovery
    service_registries: List[Dict[str, Any]] = Field(default_factory=list)
    # Deployment
    deployment_configuration: Dict[str, Any] = Field(default_factory=dict)  # max, min healthy percent
    deployments: List[Dict[str, Any]] = Field(default_factory=list)
    # Health
    health_check_grace_period_seconds: Optional[int] = None
    # Scheduling
    scheduling_strategy: str = 'REPLICA'  # REPLICA or DAEMON
    # Dates
    created_at: Optional[datetime] = None
    tags: Dict[str, str] = Field(default_factory=dict)
    raw_data: Dict[str, Any] = Field(default_factory=dict)


class ECSTaskDefinition(BaseModel):
    """ECS task definition resource."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    scan_id: str
    task_definition_arn: str
    family: str
    revision: int
    region: str
    status: str  # ACTIVE, INACTIVE, DELETE_IN_PROGRESS
    # Requirements
    requires_compatibilities: List[str] = Field(default_factory=list)  # EC2, FARGATE, EXTERNAL
    network_mode: str  # bridge, host, awsvpc, none
    cpu: Optional[str] = None  # For Fargate: '256', '512', '1024', etc.
    memory: Optional[str] = None  # For Fargate: '512', '1024', '2048', etc.
    # Execution
    task_role_arn: Optional[str] = None
    execution_role_arn: Optional[str] = None
    # Containers
    container_definitions: List[Dict[str, Any]] = Field(default_factory=list)
    # Volumes
    volumes: List[Dict[str, Any]] = Field(default_factory=list)
    # Placement constraints
    placement_constraints: List[Dict[str, Any]] = Field(default_factory=list)
    requires_attributes: List[Dict[str, str]] = Field(default_factory=list)
    # PID/IPC mode
    pid_mode: Optional[str] = None
    ipc_mode: Optional[str] = None
    # Proxy configuration
    proxy_configuration: Optional[Dict[str, Any]] = None
    # Ephemeral storage
    ephemeral_storage: Optional[Dict[str, int]] = None  # sizeInGiB
    # Runtime platform
    runtime_platform: Optional[Dict[str, str]] = None  # operatingSystemFamily, cpuArchitecture
    # Dates
    registered_at: Optional[datetime] = None
    deregistered_at: Optional[datetime] = None
    registered_by: Optional[str] = None
    tags: Dict[str, str] = Field(default_factory=dict)
    raw_data: Dict[str, Any] = Field(default_factory=dict)


class EKSCluster(BaseModel):
    """EKS cluster resource."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    scan_id: str
    cluster_name: str
    cluster_arn: str
    region: str
    version: str  # Kubernetes version: 1.27, 1.28, etc.
    endpoint: Optional[str] = None
    role_arn: str
    # Status
    status: str  # CREATING, ACTIVE, DELETING, FAILED, UPDATING
    # Networking
    vpc_id: str
    subnet_ids: List[str] = Field(default_factory=list)
    security_group_ids: List[str] = Field(default_factory=list)
    cluster_security_group_id: Optional[str] = None
    endpoint_public_access: bool = True
    endpoint_private_access: bool = False
    public_access_cidrs: List[str] = Field(default_factory=list)
    # Resources VPC config
    resources_vpc_config: Dict[str, Any] = Field(default_factory=dict)
    # Logging
    logging: Dict[str, Any] = Field(default_factory=dict)
    # Identity
    identity: Optional[Dict[str, Any]] = None  # OIDC issuer
    # Encryption
    encryption_config: List[Dict[str, Any]] = Field(default_factory=list)
    # Platform version
    platform_version: Optional[str] = None
    # Dates
    created_at: Optional[datetime] = None
    tags: Dict[str, str] = Field(default_factory=dict)
    raw_data: Dict[str, Any] = Field(default_factory=dict)


class EKSNodeGroup(BaseModel):
    """EKS node group resource."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    scan_id: str
    cluster_name: str
    nodegroup_name: str
    nodegroup_arn: str
    region: str
    # Status
    status: str  # CREATING, ACTIVE, UPDATING, DELETING, CREATE_FAILED, DELETE_FAILED, DEGRADED
    # Capacity
    scaling_config: Dict[str, int] = Field(default_factory=dict)  # minSize, maxSize, desiredSize
    instance_types: List[str] = Field(default_factory=list)
    # AMI
    ami_type: Optional[str] = None  # AL2_x86_64, AL2_x86_64_GPU, AL2_ARM_64, etc.
    release_version: Optional[str] = None
    # Networking
    subnets: List[str] = Field(default_factory=list)
    remote_access: Optional[Dict[str, Any]] = None  # ec2SshKey, sourceSecurityGroups
    # Configuration
    node_role: str  # IAM role ARN
    labels: Dict[str, str] = Field(default_factory=dict)
    taints: List[Dict[str, Any]] = Field(default_factory=list)
    # Disk
    disk_size: Optional[int] = None  # GiB
    # Capacity type
    capacity_type: str = 'ON_DEMAND'  # ON_DEMAND or SPOT
    # Launch template
    launch_template: Optional[Dict[str, Any]] = None
    # Update config
    update_config: Optional[Dict[str, int]] = None  # maxUnavailable, maxUnavailablePercentage
    # Health
    health: Optional[Dict[str, Any]] = None
    # Dates
    created_at: Optional[datetime] = None
    modified_at: Optional[datetime] = None
    tags: Dict[str, str] = Field(default_factory=dict)
    raw_data: Dict[str, Any] = Field(default_factory=dict)


class ECRRepository(BaseModel):
    """ECR repository resource."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    scan_id: str
    repository_arn: str
    repository_name: str
    repository_uri: str
    region: str
    registry_id: str
    # Scanning
    image_scanning_configuration: Dict[str, bool] = Field(default_factory=dict)  # scanOnPush
    # Tag mutability
    image_tag_mutability: str = 'MUTABLE'  # MUTABLE or IMMUTABLE
    # Encryption
    encryption_configuration: Dict[str, Any] = Field(default_factory=dict)  # encryptionType, kmsKey
    # Dates
    created_at: Optional[datetime] = None
    tags: Dict[str, str] = Field(default_factory=dict)
    raw_data: Dict[str, Any] = Field(default_factory=dict)


class ECRImage(BaseModel):
    """ECR image resource."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    scan_id: str
    repository_name: str
    region: str
    registry_id: str
    # Image identification
    image_digest: str  # sha256:...
    image_tags: List[str] = Field(default_factory=list)  # Can have multiple tags
    # Size
    image_size_in_bytes: int
    # Dates
    image_pushed_at: Optional[datetime] = None
    # Scan findings
    image_scan_status: Optional[str] = None  # IN_PROGRESS, COMPLETE, FAILED, etc.
    image_scan_findings_summary: Optional[Dict[str, Any]] = None  # findingSeverityCounts
    last_recorded_pull_time: Optional[datetime] = None
    # Artifact media type
    artifact_media_type: Optional[str] = None
    raw_data: Dict[str, Any] = Field(default_factory=dict)


class APIGatewayRestAPI(BaseModel):
    """API Gateway REST API resource."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    scan_id: str
    api_id: str
    name: str
    region: str
    description: Optional[str] = None
    # Endpoint configuration
    endpoint_configuration: Dict[str, Any] = Field(default_factory=dict)  # types: EDGE, REGIONAL, PRIVATE
    # Versioning
    version: Optional[str] = None
    # Dates
    created_date: Optional[datetime] = None
    # API key source
    api_key_source: Optional[str] = None  # HEADER, AUTHORIZER
    # Policy
    policy: Optional[str] = None  # IAM policy document (JSON string)
    # Minimum compression size
    minimum_compression_size: Optional[int] = None
    # Binary media types
    binary_media_types: List[str] = Field(default_factory=list)
    # Disable execute API endpoint
    disable_execute_api_endpoint: bool = False
    tags: Dict[str, str] = Field(default_factory=dict)
    raw_data: Dict[str, Any] = Field(default_factory=dict)


class APIGatewayHttpAPI(BaseModel):
    """API Gateway HTTP API (v2) resource."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    scan_id: str
    api_id: str
    name: str
    region: str
    protocol_type: str  # HTTP, WEBSOCKET
    description: Optional[str] = None
    # Endpoint
    api_endpoint: Optional[str] = None
    # CORS configuration
    cors_configuration: Optional[Dict[str, Any]] = None
    # Versions
    version: Optional[str] = None
    # Route selection expression
    route_selection_expression: Optional[str] = None
    # Disable execute API endpoint
    disable_execute_api_endpoint: bool = False
    # Disable schema validation
    disable_schema_validation: bool = False
    # Import info
    import_info: List[str] = Field(default_factory=list)
    # Dates
    created_date: Optional[datetime] = None
    tags: Dict[str, str] = Field(default_factory=dict)
    raw_data: Dict[str, Any] = Field(default_factory=dict)


class APIGatewayStage(BaseModel):
    """API Gateway stage resource."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    scan_id: str
    api_id: str
    stage_name: str
    region: str
    api_type: str  # REST or HTTP
    # Deployment
    deployment_id: Optional[str] = None
    # Description
    description: Optional[str] = None
    # Dates
    created_date: Optional[datetime] = None
    last_updated_date: Optional[datetime] = None
    # Access logging
    access_log_settings: Optional[Dict[str, str]] = None  # destinationArn, format
    # Client certificate
    client_certificate_id: Optional[str] = None
    # Throttling
    throttle_settings: Optional[Dict[str, float]] = None  # burstLimit, rateLimit
    # Method settings (for REST APIs)
    method_settings: Dict[str, Any] = Field(default_factory=dict)
    # Variables
    variables: Dict[str, str] = Field(default_factory=dict)
    # Tracing
    tracing_enabled: bool = False
    # Web ACL
    web_acl_arn: Optional[str] = None
    # Auto deploy (for HTTP APIs)
    auto_deploy: bool = False
    # Route settings (for HTTP APIs)
    route_settings: Dict[str, Any] = Field(default_factory=dict)
    # Default route settings (for HTTP APIs)
    default_route_settings: Optional[Dict[str, Any]] = None
    tags: Dict[str, str] = Field(default_factory=dict)
    raw_data: Dict[str, Any] = Field(default_factory=dict)


class CloudFrontDistribution(BaseModel):
    """CloudFront distribution resource."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    scan_id: str
    distribution_id: str
    distribution_arn: str
    domain_name: str  # d111111abcdef8.cloudfront.net
    # Status
    status: str  # Deployed, InProgress
    enabled: bool
    # Aliases (CNAMEs)
    aliases: List[str] = Field(default_factory=list)
    # Origins
    origins: List[Dict[str, Any]] = Field(default_factory=list)
    origin_groups: List[Dict[str, Any]] = Field(default_factory=list)
    default_root_object: Optional[str] = None
    # Cache behavior
    default_cache_behavior: Dict[str, Any] = Field(default_factory=dict)
    cache_behaviors: List[Dict[str, Any]] = Field(default_factory=list)
    # SSL/TLS
    viewer_certificate: Dict[str, Any] = Field(default_factory=dict)  # ACMCertificateArn, SSLSupportMethod, etc.
    # Restrictions
    geo_restriction: Optional[Dict[str, Any]] = None
    # WAF
    web_acl_id: Optional[str] = None  # AWS WAF Web ACL ID
    # HTTP version
    http_version: str = 'http2'  # http1.1, http2, http2and3, http3
    is_ipv6_enabled: bool = True
    # Logging
    logging: Optional[Dict[str, Any]] = None  # bucket, prefix, enabled
    # Price class
    price_class: str = 'PriceClass_All'  # PriceClass_100, PriceClass_200, PriceClass_All
    # Custom error responses
    custom_error_responses: List[Dict[str, Any]] = Field(default_factory=list)
    # Comment
    comment: Optional[str] = None
    # Dates
    last_modified_time: Optional[datetime] = None
    tags: Dict[str, str] = Field(default_factory=dict)
    raw_data: Dict[str, Any] = Field(default_factory=dict)


# Phase 3: Governance, Logging & Advanced Services


class Organization(BaseModel):
    """AWS Organization resource."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    scan_id: str
    organization_id: str
    organization_arn: str
    master_account_id: str
    master_account_email: str
    # Feature set
    feature_set: str  # ALL, CONSOLIDATED_BILLING
    # Available policy types
    available_policy_types: List[Dict[str, Any]] = Field(default_factory=list)
    raw_data: Dict[str, Any] = Field(default_factory=dict)


class OrganizationalUnit(BaseModel):
    """AWS Organizational Unit resource."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    scan_id: str
    ou_id: str
    ou_arn: str
    ou_name: str
    parent_id: Optional[str] = None  # Parent OU or root ID
    raw_data: Dict[str, Any] = Field(default_factory=dict)


class OrganizationAccount(BaseModel):
    """AWS Organization account resource."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    scan_id: str
    account_id: str
    account_arn: str
    account_name: str
    email: str
    status: str  # ACTIVE, SUSPENDED
    joined_method: str  # INVITED, CREATED
    joined_timestamp: Optional[datetime] = None
    parent_ou_id: Optional[str] = None
    raw_data: Dict[str, Any] = Field(default_factory=dict)


class SSOPermissionSet(BaseModel):
    """AWS SSO Permission Set resource."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    scan_id: str
    permission_set_arn: str
    permission_set_name: str
    instance_arn: str  # SSO instance ARN
    # Description
    description: Optional[str] = None
    # Session duration
    session_duration: Optional[str] = None  # ISO 8601 format (e.g., PT8H)
    # Relay state
    relay_state: Optional[str] = None
    # Created date
    created_date: Optional[datetime] = None
    # Managed policies
    managed_policies: List[str] = Field(default_factory=list)  # ARNs
    # Inline policy
    inline_policy: Optional[str] = None  # JSON string
    # Customer managed policy references
    customer_managed_policies: List[Dict[str, str]] = Field(default_factory=list)
    # Permissions boundary
    permissions_boundary: Optional[Dict[str, Any]] = None
    tags: Dict[str, str] = Field(default_factory=dict)
    raw_data: Dict[str, Any] = Field(default_factory=dict)


class SSOAssignment(BaseModel):
    """AWS SSO account assignment resource."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    scan_id: str
    instance_arn: str
    permission_set_arn: str
    principal_type: str  # USER, GROUP
    principal_id: str
    target_type: str  # AWS_ACCOUNT
    target_id: str  # Account ID
    raw_data: Dict[str, Any] = Field(default_factory=dict)


class CloudTrail(BaseModel):
    """AWS CloudTrail trail resource."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    scan_id: str
    trail_name: str
    trail_arn: str
    region: str
    # S3 bucket
    s3_bucket_name: str
    s3_key_prefix: Optional[str] = None
    # SNS topic
    sns_topic_name: Optional[str] = None
    sns_topic_arn: Optional[str] = None
    # CloudWatch Logs
    cloud_watch_logs_log_group_arn: Optional[str] = None
    cloud_watch_logs_role_arn: Optional[str] = None
    # KMS encryption
    kms_key_id: Optional[str] = None
    # Settings
    is_multi_region_trail: bool = False
    is_organization_trail: bool = False
    include_global_service_events: bool = True
    is_logging: bool = False
    # Event selectors
    has_event_selectors: bool = False
    has_insight_selectors: bool = False
    # Home region
    home_region: Optional[str] = None
    tags: Dict[str, str] = Field(default_factory=dict)
    raw_data: Dict[str, Any] = Field(default_factory=dict)


class CloudWatchLogGroup(BaseModel):
    """AWS CloudWatch Log Group resource."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    scan_id: str
    log_group_name: str
    log_group_arn: str
    region: str
    # Creation
    creation_time: Optional[datetime] = None
    # Retention
    retention_in_days: Optional[int] = None  # None means never expire
    # Size
    stored_bytes: int = 0
    # KMS encryption
    kms_key_id: Optional[str] = None
    # Metric filters count
    metric_filter_count: int = 0
    tags: Dict[str, str] = Field(default_factory=dict)
    raw_data: Dict[str, Any] = Field(default_factory=dict)


class ConfigRecorder(BaseModel):
    """AWS Config recorder resource."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    scan_id: str
    recorder_name: str
    region: str
    # Role ARN
    role_arn: str
    # Recording group
    recording_group: Dict[str, Any] = Field(default_factory=dict)  # allSupported, includeGlobalResourceTypes, resourceTypes
    # Status
    is_recording: bool = False
    last_status: Optional[str] = None
    last_start_time: Optional[datetime] = None
    last_stop_time: Optional[datetime] = None
    raw_data: Dict[str, Any] = Field(default_factory=dict)


class ConfigRule(BaseModel):
    """AWS Config rule resource."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    scan_id: str
    rule_name: str
    rule_arn: str
    rule_id: str
    region: str
    # Description
    description: Optional[str] = None
    # Scope
    scope: Optional[Dict[str, Any]] = None
    # Source
    source: Dict[str, Any] = Field(default_factory=dict)  # owner, sourceIdentifier, sourceDetails
    # Compliance
    compliance_type: Optional[str] = None  # COMPLIANT, NON_COMPLIANT, NOT_APPLICABLE, INSUFFICIENT_DATA
    # Config rule state
    config_rule_state: str = 'ACTIVE'  # ACTIVE, DELETING, DELETING_RESULTS, EVALUATING
    # Maximum execution frequency
    maximum_execution_frequency: Optional[str] = None
    raw_data: Dict[str, Any] = Field(default_factory=dict)


class BedrockModel(BaseModel):
    """AWS Bedrock foundation model resource."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    scan_id: str
    model_id: str
    model_arn: str
    model_name: str
    region: str
    # Provider
    provider_name: str  # Amazon, Anthropic, AI21 Labs, Cohere, Meta, Stability AI
    # Model customisation
    customization_type: Optional[str] = None  # FINE_TUNING, CONTINUED_PRE_TRAINING
    base_model_arn: Optional[str] = None
    # Inference types
    inference_types_supported: List[str] = Field(default_factory=list)  # ON_DEMAND, PROVISIONED
    # Input/output modalities
    input_modalities: List[str] = Field(default_factory=list)  # TEXT, IMAGE, EMBEDDING
    output_modalities: List[str] = Field(default_factory=list)
    # Streaming
    response_streaming_supported: bool = False
    raw_data: Dict[str, Any] = Field(default_factory=dict)


class BedrockGuardrail(BaseModel):
    """AWS Bedrock guardrail resource."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    scan_id: str
    guardrail_id: str
    guardrail_arn: str
    guardrail_name: str
    region: str
    # Version
    version: str
    # Description
    description: Optional[str] = None
    # Status
    status: str  # CREATING, READY, FAILED, DELETING
    # Content filters
    content_policy_config: Optional[Dict[str, Any]] = None
    # Topic filters
    topic_policy_config: Optional[Dict[str, Any]] = None
    # Word filters
    word_policy_config: Optional[Dict[str, Any]] = None
    # Sensitive information filters
    sensitive_information_policy_config: Optional[Dict[str, Any]] = None
    # Blocked input/output messaging
    blocked_input_messaging: Optional[str] = None
    blocked_outputs_messaging: Optional[str] = None
    # Dates
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    tags: Dict[str, str] = Field(default_factory=dict)
    raw_data: Dict[str, Any] = Field(default_factory=dict)


class BedrockKnowledgeBase(BaseModel):
    """AWS Bedrock knowledge base resource."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    scan_id: str
    knowledge_base_id: str
    knowledge_base_arn: str
    knowledge_base_name: str
    region: str
    # Description
    description: Optional[str] = None
    # Role ARN
    role_arn: str
    # Knowledge base configuration
    knowledge_base_configuration: Dict[str, Any] = Field(default_factory=dict)
    # Storage configuration
    storage_configuration: Dict[str, Any] = Field(default_factory=dict)
    # Status
    status: str  # CREATING, ACTIVE, DELETING, UPDATING, FAILED
    # Dates
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    tags: Dict[str, str] = Field(default_factory=dict)
    raw_data: Dict[str, Any] = Field(default_factory=dict)


class BedrockAgent(BaseModel):
    """AWS Bedrock agent resource."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    scan_id: str
    agent_id: str
    agent_arn: str
    agent_name: str
    region: str
    # Version
    agent_version: str
    # Description
    description: Optional[str] = None
    # Role ARN
    agent_resource_role_arn: str
    # Foundation model
    foundation_model: str
    # Instruction
    instruction: Optional[str] = None
    # Idle session TTL
    idle_session_ttl_in_seconds: Optional[int] = None
    # Status
    agent_status: str  # CREATING, PREPARING, PREPARED, NOT_PREPARED, DELETING, FAILED, VERSIONING, UPDATING
    # Dates
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    prepared_at: Optional[datetime] = None
    tags: Dict[str, str] = Field(default_factory=dict)
    raw_data: Dict[str, Any] = Field(default_factory=dict)


class DirectoryService(BaseModel):
    """AWS Directory Service resource."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    scan_id: str
    directory_id: str
    directory_name: str
    region: str
    # Type
    directory_type: str  # SimpleAD, MicrosoftAD, ADConnector, SharedMicrosoftAD
    # Size
    size: Optional[str] = None  # Small, Large
    # Edition (for MicrosoftAD)
    edition: Optional[str] = None  # Enterprise, Standard
    # VPC settings
    vpc_id: Optional[str] = None
    subnet_ids: List[str] = Field(default_factory=list)
    # DNS
    dns_ip_addresses: List[str] = Field(default_factory=list)
    access_url: Optional[str] = None
    # Status
    stage: str  # Requested, Creating, Created, Active, Inoperable, Impaired, Restoring, RestoreFailed, Deleting, Deleted, Failed
    # SSO
    sso_enabled: bool = False
    # RADIUS
    radius_status: Optional[str] = None
    # Dates
    launch_time: Optional[datetime] = None
    stage_last_updated_date_time: Optional[datetime] = None
    # Description
    description: Optional[str] = None
    # Alias
    alias: Optional[str] = None
    # Short name
    short_name: Optional[str] = None
    tags: Dict[str, str] = Field(default_factory=dict)
    raw_data: Dict[str, Any] = Field(default_factory=dict)


class TransitGateway(BaseModel):
    """AWS Transit Gateway resource."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    scan_id: str
    transit_gateway_id: str
    transit_gateway_arn: str
    region: str
    # Owner
    owner_id: str
    # Description
    description: Optional[str] = None
    # State
    state: str  # pending, available, modifying, deleting, deleted
    # Options
    amazon_side_asn: Optional[int] = None
    default_route_table_id: Optional[str] = None
    default_route_table_association: Optional[str] = None  # enable, disable
    default_route_table_propagation: Optional[str] = None  # enable, disable
    vpn_ecmp_support: Optional[str] = None  # enable, disable
    dns_support: Optional[str] = None  # enable, disable
    multicast_support: Optional[str] = None  # enable, disable
    auto_accept_shared_attachments: Optional[str] = None  # enable, disable
    # CIDR blocks
    transit_gateway_cidr_blocks: List[str] = Field(default_factory=list)
    # Dates
    creation_time: Optional[datetime] = None
    tags: Dict[str, str] = Field(default_factory=dict)
    raw_data: Dict[str, Any] = Field(default_factory=dict)


class VPNConnection(BaseModel):
    """AWS VPN Connection resource."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    scan_id: str
    vpn_connection_id: str
    region: str
    # State
    state: str  # pending, available, deleting, deleted
    # Type
    vpn_connection_type: str  # ipsec.1
    # Gateways
    customer_gateway_id: str
    vpn_gateway_id: Optional[str] = None  # Virtual private gateway
    transit_gateway_id: Optional[str] = None
    # Configuration
    customer_gateway_configuration: Optional[str] = None  # XML configuration
    # Options
    static_routes_only: bool = False
    # Tunnels
    vgw_telemetry: List[Dict[str, Any]] = Field(default_factory=list)
    # Routes
    routes: List[Dict[str, Any]] = Field(default_factory=list)
    # Category
    category: Optional[str] = None  # VPN
    tags: Dict[str, str] = Field(default_factory=dict)
    raw_data: Dict[str, Any] = Field(default_factory=dict)


class DirectConnectConnection(BaseModel):
    """AWS Direct Connect connection resource."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    scan_id: str
    connection_id: str
    connection_name: str
    region: str
    # State
    connection_state: str  # ordering, requested, pending, available, down, deleting, deleted, rejected, unknown
    # Location
    location: str  # DX location code
    # Bandwidth
    bandwidth: str  # 1Gbps, 10Gbps, 100Gbps
    # VLAN
    vlan: Optional[int] = None
    # Partner
    partner_name: Optional[str] = None
    # LAG
    lag_id: Optional[str] = None
    # AWS device
    aws_device: Optional[str] = None
    aws_device_v2: Optional[str] = None
    aws_logical_device_id: Optional[str] = None
    # Jumbo frame capability
    jumbo_frame_capable: bool = False
    # Has logical redundancy
    has_logical_redundancy: Optional[str] = None  # unknown, yes, no
    # Provider name
    provider_name: Optional[str] = None
    # MAC sec capable
    mac_sec_capable: bool = False
    # Encryption mode
    encryption_mode: Optional[str] = None  # no_encrypt, should_encrypt, must_encrypt
    # Dates
    loa_issue_time: Optional[datetime] = None
    tags: Dict[str, str] = Field(default_factory=dict)
    raw_data: Dict[str, Any] = Field(default_factory=dict)


class ElastiCacheCluster(BaseModel):
    """AWS ElastiCache cluster resource."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    scan_id: str
    cache_cluster_id: str
    cache_cluster_arn: str
    region: str
    # Engine
    engine: str  # redis, memcached
    engine_version: str
    # Node type
    cache_node_type: str  # cache.t3.micro, cache.r6g.large, etc.
    # Cluster configuration
    num_cache_nodes: int
    preferred_availability_zone: Optional[str] = None
    preferred_availability_zones: List[str] = Field(default_factory=list)
    # Status
    cache_cluster_status: str  # available, creating, deleted, deleting, modifying, etc.
    # Network
    cache_subnet_group_name: Optional[str] = None
    vpc_id: Optional[str] = None
    # Security
    security_groups: List[Dict[str, str]] = Field(default_factory=list)
    # Encryption
    at_rest_encryption_enabled: bool = False
    transit_encryption_enabled: bool = False
    auth_token_enabled: bool = False
    # Replication
    replication_group_id: Optional[str] = None
    # Snapshot
    snapshot_retention_limit: Optional[int] = None
    snapshot_window: Optional[str] = None
    # Maintenance
    preferred_maintenance_window: Optional[str] = None
    # Notification
    notification_configuration: Optional[Dict[str, str]] = None
    # Parameter group
    cache_parameter_group_name: Optional[str] = None
    # Dates
    cache_cluster_create_time: Optional[datetime] = None
    tags: Dict[str, str] = Field(default_factory=dict)
    raw_data: Dict[str, Any] = Field(default_factory=dict)


class OpenSearchDomain(BaseModel):
    """AWS OpenSearch Service domain resource."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    scan_id: str
    domain_id: str
    domain_name: str
    domain_arn: str
    region: str
    # Engine
    engine_type: str  # OpenSearch, Elasticsearch
    engine_version: str
    # Cluster configuration
    instance_type: str
    instance_count: int
    dedicated_master_enabled: bool = False
    dedicated_master_type: Optional[str] = None
    dedicated_master_count: Optional[int] = None
    zone_awareness_enabled: bool = False
    availability_zone_count: Optional[int] = None
    warm_enabled: bool = False
    warm_type: Optional[str] = None
    warm_count: Optional[int] = None
    cold_storage_enabled: bool = False
    # EBS options
    ebs_enabled: bool = False
    volume_type: Optional[str] = None  # standard, gp2, gp3, io1
    volume_size: Optional[int] = None
    iops: Optional[int] = None
    throughput: Optional[int] = None
    # VPC options
    vpc_id: Optional[str] = None
    subnet_ids: List[str] = Field(default_factory=list)
    security_group_ids: List[str] = Field(default_factory=list)
    # Endpoints
    endpoint: Optional[str] = None
    endpoints: Dict[str, str] = Field(default_factory=dict)
    # Encryption
    encryption_at_rest_enabled: bool = False
    kms_key_id: Optional[str] = None
    node_to_node_encryption_enabled: bool = False
    # Domain endpoint options
    enforce_https: bool = False
    tls_security_policy: Optional[str] = None
    custom_endpoint_enabled: bool = False
    custom_endpoint: Optional[str] = None
    # Access policies
    access_policies: Optional[str] = None  # JSON policy document
    # Advanced security options
    internal_user_database_enabled: bool = False
    saml_enabled: bool = False
    # Auto-tune
    auto_tune_enabled: bool = False
    # Status
    created: bool = False
    deleted: bool = False
    processing: bool = False
    # Upgrade processing
    upgrade_processing: bool = False
    # Dates
    domain_processing_status: Optional[str] = None
    tags: Dict[str, str] = Field(default_factory=dict)
    raw_data: Dict[str, Any] = Field(default_factory=dict)


class MSKCluster(BaseModel):
    """AWS MSK (Managed Streaming for Kafka) cluster resource."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    scan_id: str
    cluster_arn: str
    cluster_name: str
    region: str
    # Kafka version
    kafka_version: str
    # State
    state: str  # ACTIVE, CREATING, UPDATING, DELETING, FAILED, etc.
    # Creation time
    creation_time: Optional[datetime] = None
    # Broker node group info
    broker_node_group_info: Dict[str, Any] = Field(default_factory=dict)  # instanceType, clientSubnets, securityGroups, storageInfo
    # Number of broker nodes
    number_of_broker_nodes: int
    # Encryption
    encryption_in_transit: Optional[Dict[str, Any]] = None  # clientBroker, inCluster
    encryption_at_rest_kms_key_arn: Optional[str] = None
    # Enhanced monitoring
    enhanced_monitoring: Optional[str] = None  # DEFAULT, PER_BROKER, PER_TOPIC_PER_BROKER, PER_TOPIC_PER_PARTITION
    # Open monitoring (Prometheus)
    open_monitoring: Optional[Dict[str, Any]] = None
    # Logging
    logging_info: Optional[Dict[str, Any]] = None
    # Cluster type
    cluster_type: Optional[str] = None  # PROVISIONED, SERVERLESS
    # Provisioned throughput
    provisioned: Optional[Dict[str, Any]] = None
    # Serverless
    serverless: Optional[Dict[str, Any]] = None
    # Current version
    current_version: Optional[str] = None
    # Zookeeper connection string
    zookeeper_connect_string: Optional[str] = None
    zookeeper_connect_string_tls: Optional[str] = None
    # Bootstrap brokers
    bootstrap_broker_string: Optional[str] = None
    bootstrap_broker_string_tls: Optional[str] = None
    tags: Dict[str, str] = Field(default_factory=dict)
    raw_data: Dict[str, Any] = Field(default_factory=dict)


class DynamoDBTable(BaseModel):
    """AWS DynamoDB table resource."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    scan_id: str
    table_name: str
    table_arn: str
    table_id: str
    region: str
    # Status
    table_status: str  # CREATING, UPDATING, DELETING, ACTIVE, INACCESSIBLE_ENCRYPTION_CREDENTIALS, ARCHIVING, ARCHIVED
    # Creation
    creation_date_time: Optional[datetime] = None
    # Key schema
    key_schema: List[Dict[str, str]] = Field(default_factory=list)  # AttributeName, KeyType
    # Attribute definitions
    attribute_definitions: List[Dict[str, str]] = Field(default_factory=list)  # AttributeName, AttributeType
    # Billing mode
    billing_mode_summary: Optional[Dict[str, Any]] = None  # BillingMode, LastUpdateToPayPerRequestDateTime
    # Provisioned throughput
    provisioned_throughput: Optional[Dict[str, Any]] = None  # ReadCapacityUnits, WriteCapacityUnits
    # Table size
    table_size_bytes: int = 0
    item_count: int = 0
    # Global secondary indexes
    global_secondary_indexes: List[Dict[str, Any]] = Field(default_factory=list)
    # Local secondary indexes
    local_secondary_indexes: List[Dict[str, Any]] = Field(default_factory=list)
    # Stream specification
    stream_specification: Optional[Dict[str, Any]] = None
    latest_stream_arn: Optional[str] = None
    latest_stream_label: Optional[str] = None
    # Restore summary
    restore_summary: Optional[Dict[str, Any]] = None
    # SSE description
    sse_description: Optional[Dict[str, Any]] = None  # Status, SSEType, KMSMasterKeyArn
    # Point-in-time recovery
    point_in_time_recovery_enabled: bool = False
    # Global table
    global_table_version: Optional[str] = None
    replicas: List[Dict[str, Any]] = Field(default_factory=list)
    # Continuous backups
    continuous_backups_status: Optional[str] = None  # ENABLED, DISABLED
    # Table class
    table_class_summary: Optional[Dict[str, str]] = None  # TableClass, LastUpdateDateTime
    # Deletion protection
    deletion_protection_enabled: bool = False
    tags: Dict[str, str] = Field(default_factory=dict)
    raw_data: Dict[str, Any] = Field(default_factory=dict)


class AccountSecurityPosture(BaseModel):
    """Account-level security posture facts collected once per scan."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    scan_id: str
    account_summary: Dict[str, Any] = Field(default_factory=dict)
    password_policy: Optional[Dict[str, Any]] = None
    password_policy_exists: bool = False
    account_public_access_block: Optional[Dict[str, Any]] = None
    credential_report_generated: Optional[datetime] = None
    raw_data: Dict[str, Any] = Field(default_factory=dict)


class IAMCredentialReportEntry(BaseModel):
    """One row of the parsed IAM credential report (per user plus root)."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    scan_id: str
    user_name: str
    arn: Optional[str] = None
    user_creation_time: Optional[str] = None
    password_enabled: Optional[bool] = None
    password_last_used: Optional[str] = None
    mfa_active: bool = False
    access_key_1_active: bool = False
    access_key_1_last_rotated: Optional[str] = None
    access_key_1_last_used: Optional[str] = None
    access_key_2_active: bool = False
    access_key_2_last_rotated: Optional[str] = None
    access_key_2_last_used: Optional[str] = None
    raw_data: Dict[str, Any] = Field(default_factory=dict)


class RegionSecurityServices(BaseModel):
    """Per-region security service enablement facts."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    scan_id: str
    region: str
    guardduty_enabled: Optional[bool] = None
    guardduty_detector: Optional[Dict[str, Any]] = None
    security_hub_enabled: Optional[bool] = None
    ebs_encryption_by_default: Optional[bool] = None
    access_analyzers: List[Dict[str, Any]] = Field(default_factory=list)
    raw_data: Dict[str, Any] = Field(default_factory=dict)


class LambdaExposure(BaseModel):
    """Lambda function URL configuration and resource policy exposure facts."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    scan_id: str
    region: str
    function_name: str
    function_arn: str
    url_config: Optional[Dict[str, Any]] = None
    url_auth_type: Optional[str] = None
    resource_policy: Optional[Dict[str, Any]] = None
    raw_data: Dict[str, Any] = Field(default_factory=dict)


class S3PublicAccess(BaseModel):
    """Per-bucket S3 public access configuration facts."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    scan_id: str
    bucket_name: str
    public_access_block: Optional[Dict[str, Any]] = None
    policy_is_public: Optional[bool] = None
    raw_data: Dict[str, Any] = Field(default_factory=dict)
