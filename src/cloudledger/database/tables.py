"""
SQLAlchemy Core table metadata for CloudLedger.

Translated one-for-one from the legacy hand-written DDL. Stored formats are
unchanged: booleans are 0/1 integers, JSON payloads and timestamps are text.
Uses Australian English in all documentation and comments.
"""

import sqlalchemy as sa
from sqlalchemy.dialects import mssql as _mssql
from sqlalchemy.dialects import mysql as _mysql

metadata = sa.MetaData()


def _timestamp_column(name: str = "created_at") -> sa.Column:
    """Text timestamp with a server default, typed DATETIME on MySQL.

    MySQL forbids defaults on TEXT columns; every other supported dialect
    stores the same ISO-style value in a text column, so the SQLite schema
    (and its equivalence baseline) is unchanged.
    """
    return sa.Column(
        name,
        sa.Text().with_variant(_mysql.DATETIME(), "mysql"),
        server_default=sa.text("CURRENT_TIMESTAMP"),
    )


# Text on SQLite/PostgreSQL; bounded VARCHAR where the dialect forbids
# keys or indexes on unbounded text (MySQL error 1170, MSSQL VARCHAR(MAX)).
KeyText = (
    sa.Text()
    .with_variant(_mysql.VARCHAR(255), "mysql")
    .with_variant(_mssql.VARCHAR(450), "mssql")
)

# Text on every dialect except MySQL, which forbids defaults on TEXT
# columns; these hold short enum-like values with literal defaults.
EnumText = sa.Text().with_variant(_mysql.VARCHAR(64), "mysql")


t_account_security_posture = sa.Table(
    "account_security_posture",
    metadata,
    sa.Column("id", sa.Integer, primary_key=True, nullable=True),
    sa.Column(
        "scan_id", KeyText, sa.ForeignKey("scan_metadata.scan_id"), nullable=False
    ),
    sa.Column("account_summary", sa.Text),
    sa.Column("password_policy", sa.Text),
    sa.Column(
        "password_policy_exists",
        sa.Integer,
        nullable=False,
        server_default=sa.text("0"),
    ),
    sa.Column("account_public_access_block", sa.Text),
    sa.Column("credential_report_generated", sa.Text),
    sa.Column("raw_data", sa.Text),
    _timestamp_column(),
    sqlite_autoincrement=True,
)

t_api_gateway_http_apis = sa.Table(
    "api_gateway_http_apis",
    metadata,
    sa.Column("id", sa.Integer, primary_key=True, nullable=True),
    sa.Column(
        "scan_id", KeyText, sa.ForeignKey("scan_metadata.scan_id"), nullable=False
    ),
    sa.Column("api_id", KeyText, nullable=False),
    sa.Column("name", KeyText, nullable=False),
    sa.Column("region", KeyText, nullable=False),
    sa.Column("protocol_type", sa.Text, nullable=False),
    sa.Column("description", sa.Text),
    sa.Column("api_endpoint", sa.Text),
    sa.Column("cors_configuration", sa.Text),
    sa.Column("version", sa.Text),
    sa.Column("route_selection_expression", sa.Text),
    sa.Column("disable_execute_api_endpoint", sa.Integer, server_default=sa.text("0")),
    sa.Column("disable_schema_validation", sa.Integer, server_default=sa.text("0")),
    sa.Column("import_info", sa.Text),
    sa.Column("created_date", sa.Text),
    sa.Column("tags", sa.Text),
    sa.Column("raw_data", sa.Text),
    _timestamp_column(),
    sqlite_autoincrement=True,
)

t_api_gateway_rest_apis = sa.Table(
    "api_gateway_rest_apis",
    metadata,
    sa.Column("id", sa.Integer, primary_key=True, nullable=True),
    sa.Column(
        "scan_id", KeyText, sa.ForeignKey("scan_metadata.scan_id"), nullable=False
    ),
    sa.Column("api_id", KeyText, nullable=False),
    sa.Column("name", KeyText, nullable=False),
    sa.Column("region", KeyText, nullable=False),
    sa.Column("description", sa.Text),
    sa.Column("endpoint_configuration", sa.Text),
    sa.Column("version", sa.Text),
    sa.Column("created_date", sa.Text),
    sa.Column("api_key_source", sa.Text),
    sa.Column("policy", sa.Text),
    sa.Column("minimum_compression_size", sa.Integer),
    sa.Column("binary_media_types", sa.Text),
    sa.Column("disable_execute_api_endpoint", sa.Integer, server_default=sa.text("0")),
    sa.Column("tags", sa.Text),
    sa.Column("raw_data", sa.Text),
    _timestamp_column(),
    sqlite_autoincrement=True,
)

t_api_gateway_stages = sa.Table(
    "api_gateway_stages",
    metadata,
    sa.Column("id", sa.Integer, primary_key=True, nullable=True),
    sa.Column(
        "scan_id", KeyText, sa.ForeignKey("scan_metadata.scan_id"), nullable=False
    ),
    sa.Column("api_id", KeyText, nullable=False),
    sa.Column("stage_name", KeyText, nullable=False),
    sa.Column("region", KeyText, nullable=False),
    sa.Column("api_type", KeyText, nullable=False),
    sa.Column("deployment_id", sa.Text),
    sa.Column("description", sa.Text),
    sa.Column("created_date", sa.Text),
    sa.Column("last_updated_date", sa.Text),
    sa.Column("access_log_settings", sa.Text),
    sa.Column("client_certificate_id", sa.Text),
    sa.Column("throttle_settings", sa.Text),
    sa.Column("method_settings", sa.Text),
    sa.Column("variables", sa.Text),
    sa.Column("tracing_enabled", sa.Integer, server_default=sa.text("0")),
    sa.Column("web_acl_arn", sa.Text),
    sa.Column("auto_deploy", sa.Integer, server_default=sa.text("0")),
    sa.Column("route_settings", sa.Text),
    sa.Column("default_route_settings", sa.Text),
    sa.Column("tags", sa.Text),
    sa.Column("raw_data", sa.Text),
    _timestamp_column(),
    sqlite_autoincrement=True,
)

t_auto_scaling_groups = sa.Table(
    "auto_scaling_groups",
    metadata,
    sa.Column("id", sa.Integer, primary_key=True, nullable=True),
    sa.Column(
        "scan_id", KeyText, sa.ForeignKey("scan_metadata.scan_id"), nullable=False
    ),
    sa.Column("auto_scaling_group_name", KeyText, nullable=False),
    sa.Column("auto_scaling_group_arn", sa.Text, nullable=False),
    sa.Column("region", KeyText, nullable=False),
    sa.Column("launch_configuration_name", sa.Text),
    sa.Column("launch_template", sa.Text),
    sa.Column("min_size", sa.Integer, nullable=False),
    sa.Column("max_size", sa.Integer, nullable=False),
    sa.Column("desired_capacity", sa.Integer, nullable=False),
    sa.Column("default_cooldown", sa.Integer, nullable=False),
    sa.Column("availability_zones", sa.Text),
    sa.Column("load_balancer_names", sa.Text),
    sa.Column("target_group_arns", sa.Text),
    sa.Column("health_check_type", sa.Text, nullable=False),
    sa.Column("health_check_grace_period", sa.Integer, nullable=False),
    sa.Column("vpc_zone_identifier", sa.Text),
    sa.Column("instances", sa.Text),
    sa.Column("created_time", sa.Text, nullable=False),
    sa.Column("tags", sa.Text),
    sa.Column("raw_data", sa.Text),
    _timestamp_column(),
    sqlite_autoincrement=True,
)

t_bedrock_agents = sa.Table(
    "bedrock_agents",
    metadata,
    sa.Column("id", sa.Integer, primary_key=True, nullable=True),
    sa.Column(
        "scan_id", KeyText, sa.ForeignKey("scan_metadata.scan_id"), nullable=False
    ),
    sa.Column("agent_id", KeyText, nullable=False),
    sa.Column("agent_arn", KeyText, nullable=False),
    sa.Column("agent_name", sa.Text, nullable=False),
    sa.Column("region", KeyText, nullable=False),
    sa.Column("agent_version", sa.Text, nullable=False),
    sa.Column("description", sa.Text),
    sa.Column("agent_resource_role_arn", sa.Text, nullable=False),
    sa.Column("foundation_model", sa.Text, nullable=False),
    sa.Column("instruction", sa.Text),
    sa.Column("idle_session_ttl_in_seconds", sa.Integer),
    sa.Column("agent_status", KeyText, nullable=False),
    sa.Column("created_at_time", sa.Text),
    sa.Column("updated_at_time", sa.Text),
    sa.Column("prepared_at_time", sa.Text),
    sa.Column("tags", sa.Text),
    sa.Column("raw_data", sa.Text),
    _timestamp_column(),
    sqlite_autoincrement=True,
)

t_bedrock_guardrails = sa.Table(
    "bedrock_guardrails",
    metadata,
    sa.Column("id", sa.Integer, primary_key=True, nullable=True),
    sa.Column(
        "scan_id", KeyText, sa.ForeignKey("scan_metadata.scan_id"), nullable=False
    ),
    sa.Column("guardrail_id", KeyText, nullable=False),
    sa.Column("guardrail_arn", KeyText, nullable=False),
    sa.Column("guardrail_name", sa.Text, nullable=False),
    sa.Column("region", KeyText, nullable=False),
    sa.Column("version", sa.Text, nullable=False),
    sa.Column("description", sa.Text),
    sa.Column("status", KeyText, nullable=False),
    sa.Column("content_policy_config", sa.Text),
    sa.Column("topic_policy_config", sa.Text),
    sa.Column("word_policy_config", sa.Text),
    sa.Column("sensitive_information_policy_config", sa.Text),
    sa.Column("blocked_input_messaging", sa.Text),
    sa.Column("blocked_outputs_messaging", sa.Text),
    sa.Column("created_at_time", sa.Text),
    sa.Column("updated_at_time", sa.Text),
    sa.Column("tags", sa.Text),
    sa.Column("raw_data", sa.Text),
    _timestamp_column(),
    sqlite_autoincrement=True,
)

t_bedrock_knowledge_bases = sa.Table(
    "bedrock_knowledge_bases",
    metadata,
    sa.Column("id", sa.Integer, primary_key=True, nullable=True),
    sa.Column(
        "scan_id", KeyText, sa.ForeignKey("scan_metadata.scan_id"), nullable=False
    ),
    sa.Column("knowledge_base_id", KeyText, nullable=False),
    sa.Column("knowledge_base_arn", KeyText, nullable=False),
    sa.Column("knowledge_base_name", sa.Text, nullable=False),
    sa.Column("region", KeyText, nullable=False),
    sa.Column("description", sa.Text),
    sa.Column("role_arn", sa.Text, nullable=False),
    sa.Column("knowledge_base_configuration", sa.Text),
    sa.Column("storage_configuration", sa.Text),
    sa.Column("status", KeyText, nullable=False),
    sa.Column("created_at_time", sa.Text),
    sa.Column("updated_at_time", sa.Text),
    sa.Column("tags", sa.Text),
    sa.Column("raw_data", sa.Text),
    _timestamp_column(),
    sqlite_autoincrement=True,
)

t_bedrock_models = sa.Table(
    "bedrock_models",
    metadata,
    sa.Column("id", sa.Integer, primary_key=True, nullable=True),
    sa.Column(
        "scan_id", KeyText, sa.ForeignKey("scan_metadata.scan_id"), nullable=False
    ),
    sa.Column("model_id", KeyText, nullable=False),
    sa.Column("model_arn", KeyText, nullable=False),
    sa.Column("model_name", sa.Text, nullable=False),
    sa.Column("region", KeyText, nullable=False),
    sa.Column("provider_name", KeyText, nullable=False),
    sa.Column("customization_type", sa.Text),
    sa.Column("base_model_arn", sa.Text),
    sa.Column("inference_types_supported", sa.Text),
    sa.Column("input_modalities", sa.Text),
    sa.Column("output_modalities", sa.Text),
    sa.Column("response_streaming_supported", sa.Integer, server_default=sa.text("0")),
    sa.Column("raw_data", sa.Text),
    _timestamp_column(),
    sqlite_autoincrement=True,
)

t_cloudfront_distributions = sa.Table(
    "cloudfront_distributions",
    metadata,
    sa.Column("id", sa.Integer, primary_key=True, nullable=True),
    sa.Column(
        "scan_id", KeyText, sa.ForeignKey("scan_metadata.scan_id"), nullable=False
    ),
    sa.Column("distribution_id", KeyText, nullable=False),
    sa.Column("distribution_arn", KeyText, nullable=False),
    sa.Column("domain_name", sa.Text, nullable=False),
    sa.Column("status", KeyText, nullable=False),
    sa.Column("enabled", sa.Integer, nullable=False),
    sa.Column("aliases", sa.Text),
    sa.Column("origins", sa.Text),
    sa.Column("origin_groups", sa.Text),
    sa.Column("default_root_object", sa.Text),
    sa.Column("default_cache_behavior", sa.Text),
    sa.Column("cache_behaviors", sa.Text),
    sa.Column("viewer_certificate", sa.Text),
    sa.Column("geo_restriction", sa.Text),
    sa.Column("web_acl_id", sa.Text),
    sa.Column("http_version", EnumText, server_default=sa.text("'http2'")),
    sa.Column("is_ipv6_enabled", sa.Integer, server_default=sa.text("1")),
    sa.Column("logging", sa.Text),
    sa.Column("price_class", EnumText, server_default=sa.text("'PriceClass_All'")),
    sa.Column("custom_error_responses", sa.Text),
    sa.Column("comment", sa.Text),
    sa.Column("last_modified_time", sa.Text),
    sa.Column("tags", sa.Text),
    sa.Column("raw_data", sa.Text),
    _timestamp_column(),
    sqlite_autoincrement=True,
)

t_cloudtrail_trails = sa.Table(
    "cloudtrail_trails",
    metadata,
    sa.Column("id", sa.Integer, primary_key=True, nullable=True),
    sa.Column(
        "scan_id", KeyText, sa.ForeignKey("scan_metadata.scan_id"), nullable=False
    ),
    sa.Column("trail_name", KeyText, nullable=False),
    sa.Column("trail_arn", KeyText, nullable=False),
    sa.Column("region", KeyText, nullable=False),
    sa.Column("s3_bucket_name", sa.Text, nullable=False),
    sa.Column("s3_key_prefix", sa.Text),
    sa.Column("sns_topic_name", sa.Text),
    sa.Column("sns_topic_arn", sa.Text),
    sa.Column("cloud_watch_logs_log_group_arn", sa.Text),
    sa.Column("cloud_watch_logs_role_arn", sa.Text),
    sa.Column("kms_key_id", sa.Text),
    sa.Column(
        "is_multi_region_trail", sa.Integer, nullable=False, server_default=sa.text("0")
    ),
    sa.Column(
        "is_organization_trail", sa.Integer, nullable=False, server_default=sa.text("0")
    ),
    sa.Column(
        "include_global_service_events",
        sa.Integer,
        nullable=False,
        server_default=sa.text("1"),
    ),
    sa.Column("is_logging", sa.Integer, nullable=False, server_default=sa.text("0")),
    sa.Column(
        "has_event_selectors", sa.Integer, nullable=False, server_default=sa.text("0")
    ),
    sa.Column(
        "has_insight_selectors", sa.Integer, nullable=False, server_default=sa.text("0")
    ),
    sa.Column("home_region", sa.Text),
    sa.Column("tags", sa.Text),
    sa.Column("raw_data", sa.Text),
    _timestamp_column(),
    sqlite_autoincrement=True,
)

t_cloudwatch_log_groups = sa.Table(
    "cloudwatch_log_groups",
    metadata,
    sa.Column("id", sa.Integer, primary_key=True, nullable=True),
    sa.Column(
        "scan_id", KeyText, sa.ForeignKey("scan_metadata.scan_id"), nullable=False
    ),
    sa.Column("log_group_name", KeyText, nullable=False),
    sa.Column("log_group_arn", KeyText, nullable=False),
    sa.Column("region", KeyText, nullable=False),
    sa.Column("creation_time", sa.Text),
    sa.Column("retention_in_days", sa.Integer),
    sa.Column("stored_bytes", sa.Integer, server_default=sa.text("0")),
    sa.Column("kms_key_id", sa.Text),
    sa.Column("metric_filter_count", sa.Integer, server_default=sa.text("0")),
    sa.Column("tags", sa.Text),
    sa.Column("raw_data", sa.Text),
    _timestamp_column(),
    sqlite_autoincrement=True,
)

t_config_recorders = sa.Table(
    "config_recorders",
    metadata,
    sa.Column("id", sa.Integer, primary_key=True, nullable=True),
    sa.Column(
        "scan_id", KeyText, sa.ForeignKey("scan_metadata.scan_id"), nullable=False
    ),
    sa.Column("recorder_name", KeyText, nullable=False),
    sa.Column("region", KeyText, nullable=False),
    sa.Column("role_arn", sa.Text, nullable=False),
    sa.Column("recording_group", sa.Text),
    sa.Column("is_recording", sa.Integer, nullable=False, server_default=sa.text("0")),
    sa.Column("last_status", sa.Text),
    sa.Column("last_start_time", sa.Text),
    sa.Column("last_stop_time", sa.Text),
    sa.Column("raw_data", sa.Text),
    _timestamp_column(),
    sqlite_autoincrement=True,
)

t_config_rules = sa.Table(
    "config_rules",
    metadata,
    sa.Column("id", sa.Integer, primary_key=True, nullable=True),
    sa.Column(
        "scan_id", KeyText, sa.ForeignKey("scan_metadata.scan_id"), nullable=False
    ),
    sa.Column("rule_name", KeyText, nullable=False),
    sa.Column("rule_arn", KeyText, nullable=False),
    sa.Column("rule_id", sa.Text, nullable=False),
    sa.Column("region", KeyText, nullable=False),
    sa.Column("description", sa.Text),
    sa.Column("scope", sa.Text),
    sa.Column("source", sa.Text),
    sa.Column("compliance_type", KeyText),
    sa.Column("config_rule_state", EnumText, server_default=sa.text("'ACTIVE'")),
    sa.Column("maximum_execution_frequency", sa.Text),
    sa.Column("raw_data", sa.Text),
    _timestamp_column(),
    sqlite_autoincrement=True,
)

t_cost_data = sa.Table(
    "cost_data",
    metadata,
    sa.Column("id", sa.Integer, primary_key=True, nullable=True),
    sa.Column(
        "scan_id", KeyText, sa.ForeignKey("scan_metadata.scan_id"), nullable=False
    ),
    sa.Column("account_number", KeyText, nullable=False),
    sa.Column("time_period_start", KeyText, nullable=False),
    sa.Column("time_period_end", KeyText, nullable=False),
    sa.Column("service_name", KeyText, nullable=False),
    sa.Column("amount", sa.REAL, nullable=False),
    sa.Column("currency", sa.Text, nullable=False),
    sa.Column("unit", sa.Text, nullable=False),
    sa.Column("raw_data", sa.Text),
    _timestamp_column(),
    sqlite_autoincrement=True,
)

t_direct_connect_connections = sa.Table(
    "direct_connect_connections",
    metadata,
    sa.Column("id", sa.Integer, primary_key=True, nullable=True),
    sa.Column(
        "scan_id", KeyText, sa.ForeignKey("scan_metadata.scan_id"), nullable=False
    ),
    sa.Column("connection_id", KeyText, nullable=False),
    sa.Column("connection_name", KeyText, nullable=False),
    sa.Column("region", KeyText, nullable=False),
    sa.Column("connection_state", KeyText, nullable=False),
    sa.Column("location", sa.Text, nullable=False),
    sa.Column("bandwidth", sa.Text, nullable=False),
    sa.Column("vlan", sa.Integer),
    sa.Column("partner_name", sa.Text),
    sa.Column("lag_id", sa.Text),
    sa.Column("aws_device", sa.Text),
    sa.Column("aws_device_v2", sa.Text),
    sa.Column("aws_logical_device_id", sa.Text),
    sa.Column("jumbo_frame_capable", sa.Integer, server_default=sa.text("0")),
    sa.Column("has_logical_redundancy", sa.Text),
    sa.Column("provider_name", sa.Text),
    sa.Column("mac_sec_capable", sa.Integer, server_default=sa.text("0")),
    sa.Column("encryption_mode", sa.Text),
    sa.Column("loa_issue_time", sa.Text),
    sa.Column("tags", sa.Text),
    sa.Column("raw_data", sa.Text),
    _timestamp_column(),
    sqlite_autoincrement=True,
)

t_directory_services = sa.Table(
    "directory_services",
    metadata,
    sa.Column("id", sa.Integer, primary_key=True, nullable=True),
    sa.Column(
        "scan_id", KeyText, sa.ForeignKey("scan_metadata.scan_id"), nullable=False
    ),
    sa.Column("directory_id", KeyText, nullable=False),
    sa.Column("directory_name", KeyText, nullable=False),
    sa.Column("region", KeyText, nullable=False),
    sa.Column("directory_type", KeyText, nullable=False),
    sa.Column("size", sa.Text),
    sa.Column("edition", sa.Text),
    sa.Column("vpc_id", KeyText),
    sa.Column("subnet_ids", sa.Text),
    sa.Column("dns_ip_addresses", sa.Text),
    sa.Column("access_url", sa.Text),
    sa.Column("stage", sa.Text, nullable=False),
    sa.Column("sso_enabled", sa.Integer, server_default=sa.text("0")),
    sa.Column("radius_status", sa.Text),
    sa.Column("launch_time", sa.Text),
    sa.Column("stage_last_updated_date_time", sa.Text),
    sa.Column("description", sa.Text),
    sa.Column("alias", sa.Text),
    sa.Column("short_name", sa.Text),
    sa.Column("tags", sa.Text),
    sa.Column("raw_data", sa.Text),
    _timestamp_column(),
    sqlite_autoincrement=True,
)

t_dynamodb_tables = sa.Table(
    "dynamodb_tables",
    metadata,
    sa.Column("id", sa.Integer, primary_key=True, nullable=True),
    sa.Column(
        "scan_id", KeyText, sa.ForeignKey("scan_metadata.scan_id"), nullable=False
    ),
    sa.Column("table_name", KeyText, nullable=False),
    sa.Column("table_arn", KeyText, nullable=False),
    sa.Column("table_id", sa.Text, nullable=False),
    sa.Column("region", KeyText, nullable=False),
    sa.Column("table_status", KeyText, nullable=False),
    sa.Column("creation_date_time", sa.Text),
    sa.Column("key_schema", sa.Text),
    sa.Column("attribute_definitions", sa.Text),
    sa.Column("billing_mode_summary", sa.Text),
    sa.Column("provisioned_throughput", sa.Text),
    sa.Column("table_size_bytes", sa.Integer, server_default=sa.text("0")),
    sa.Column("item_count", sa.Integer, server_default=sa.text("0")),
    sa.Column("global_secondary_indexes", sa.Text),
    sa.Column("local_secondary_indexes", sa.Text),
    sa.Column("stream_specification", sa.Text),
    sa.Column("latest_stream_arn", sa.Text),
    sa.Column("latest_stream_label", sa.Text),
    sa.Column("restore_summary", sa.Text),
    sa.Column("sse_description", sa.Text),
    sa.Column(
        "point_in_time_recovery_enabled", sa.Integer, server_default=sa.text("0")
    ),
    sa.Column("global_table_version", sa.Text),
    sa.Column("replicas", sa.Text),
    sa.Column("continuous_backups_status", sa.Text),
    sa.Column("table_class_summary", sa.Text),
    sa.Column("deletion_protection_enabled", sa.Integer, server_default=sa.text("0")),
    sa.Column("tags", sa.Text),
    sa.Column("raw_data", sa.Text),
    _timestamp_column(),
    sqlite_autoincrement=True,
)

t_ebs_snapshots = sa.Table(
    "ebs_snapshots",
    metadata,
    sa.Column("id", sa.Integer, primary_key=True, nullable=True),
    sa.Column(
        "scan_id", KeyText, sa.ForeignKey("scan_metadata.scan_id"), nullable=False
    ),
    sa.Column("snapshot_id", KeyText, nullable=False),
    sa.Column("region", KeyText, nullable=False),
    sa.Column("volume_id", KeyText),
    sa.Column("volume_size", sa.Integer, nullable=False),
    sa.Column("encrypted", sa.Integer, nullable=False),
    sa.Column("kms_key_id", sa.Text),
    sa.Column("state", sa.Text, nullable=False),
    sa.Column("start_time", KeyText, nullable=False),
    sa.Column("progress", sa.Text, nullable=False),
    sa.Column("owner_id", sa.Text, nullable=False),
    sa.Column("description", sa.Text),
    sa.Column("tags", sa.Text),
    sa.Column("raw_data", sa.Text),
    _timestamp_column(),
    sqlite_autoincrement=True,
)

t_ebs_volumes = sa.Table(
    "ebs_volumes",
    metadata,
    sa.Column("id", sa.Integer, primary_key=True, nullable=True),
    sa.Column(
        "scan_id", KeyText, sa.ForeignKey("scan_metadata.scan_id"), nullable=False
    ),
    sa.Column("volume_id", KeyText, nullable=False),
    sa.Column("region", KeyText, nullable=False),
    sa.Column("size", sa.Integer, nullable=False),
    sa.Column("volume_type", sa.Text, nullable=False),
    sa.Column("iops", sa.Integer),
    sa.Column("throughput", sa.Integer),
    sa.Column("encrypted", sa.Integer, nullable=False),
    sa.Column("kms_key_id", sa.Text),
    sa.Column("state", KeyText, nullable=False),
    sa.Column("create_time", sa.Text, nullable=False),
    sa.Column("availability_zone", sa.Text, nullable=False),
    sa.Column("snapshot_id", sa.Text),
    sa.Column("attached_instance_id", KeyText),
    sa.Column("device_name", sa.Text),
    sa.Column("attachment_state", sa.Text),
    sa.Column("multi_attach_enabled", sa.Integer, server_default=sa.text("0")),
    sa.Column("tags", sa.Text),
    sa.Column("raw_data", sa.Text),
    _timestamp_column(),
    sqlite_autoincrement=True,
)

t_ec2_instances = sa.Table(
    "ec2_instances",
    metadata,
    sa.Column("id", sa.Integer, primary_key=True, nullable=True),
    sa.Column(
        "scan_id", KeyText, sa.ForeignKey("scan_metadata.scan_id"), nullable=False
    ),
    sa.Column("instance_id", KeyText, nullable=False),
    sa.Column("region", KeyText, nullable=False),
    sa.Column("instance_type", sa.Text, nullable=False),
    sa.Column("state", sa.Text, nullable=False),
    sa.Column("public_ip", KeyText),
    sa.Column("private_ip", sa.Text),
    sa.Column("vpc_id", KeyText),
    sa.Column("subnet_id", sa.Text),
    sa.Column("availability_zone", sa.Text, nullable=False),
    sa.Column("launch_time", sa.Text, nullable=False),
    sa.Column("platform", sa.Text),
    sa.Column("security_groups", sa.Text),
    sa.Column("tags", sa.Text),
    sa.Column("iam_instance_profile", sa.Text),
    sa.Column("monitoring_state", sa.Text),
    sa.Column("raw_data", sa.Text),
    _timestamp_column(),
    sqlite_autoincrement=True,
)

t_ecr_images = sa.Table(
    "ecr_images",
    metadata,
    sa.Column("id", sa.Integer, primary_key=True, nullable=True),
    sa.Column(
        "scan_id", KeyText, sa.ForeignKey("scan_metadata.scan_id"), nullable=False
    ),
    sa.Column("repository_name", KeyText, nullable=False),
    sa.Column("region", KeyText, nullable=False),
    sa.Column("registry_id", sa.Text, nullable=False),
    sa.Column("image_digest", KeyText, nullable=False),
    sa.Column("image_tags", sa.Text),
    sa.Column("image_size_in_bytes", sa.Integer, nullable=False),
    sa.Column("image_pushed_at", sa.Text),
    sa.Column("image_scan_status", sa.Text),
    sa.Column("image_scan_findings_summary", sa.Text),
    sa.Column("last_recorded_pull_time", sa.Text),
    sa.Column("artifact_media_type", sa.Text),
    sa.Column("raw_data", sa.Text),
    _timestamp_column(),
    sqlite_autoincrement=True,
)

t_ecr_repositories = sa.Table(
    "ecr_repositories",
    metadata,
    sa.Column("id", sa.Integer, primary_key=True, nullable=True),
    sa.Column(
        "scan_id", KeyText, sa.ForeignKey("scan_metadata.scan_id"), nullable=False
    ),
    sa.Column("repository_arn", KeyText, nullable=False),
    sa.Column("repository_name", KeyText, nullable=False),
    sa.Column("repository_uri", sa.Text, nullable=False),
    sa.Column("region", KeyText, nullable=False),
    sa.Column("registry_id", sa.Text, nullable=False),
    sa.Column("image_scanning_configuration", sa.Text),
    sa.Column("image_tag_mutability", EnumText, server_default=sa.text("'MUTABLE'")),
    sa.Column("encryption_configuration", sa.Text),
    sa.Column("created_at_repo", sa.Text),
    sa.Column("tags", sa.Text),
    sa.Column("raw_data", sa.Text),
    _timestamp_column(),
    sqlite_autoincrement=True,
)

t_ecs_clusters = sa.Table(
    "ecs_clusters",
    metadata,
    sa.Column("id", sa.Integer, primary_key=True, nullable=True),
    sa.Column(
        "scan_id", KeyText, sa.ForeignKey("scan_metadata.scan_id"), nullable=False
    ),
    sa.Column("cluster_arn", KeyText, nullable=False),
    sa.Column("cluster_name", KeyText, nullable=False),
    sa.Column("region", KeyText, nullable=False),
    sa.Column("status", KeyText, nullable=False),
    sa.Column(
        "registered_container_instances_count", sa.Integer, server_default=sa.text("0")
    ),
    sa.Column("running_tasks_count", sa.Integer, server_default=sa.text("0")),
    sa.Column("pending_tasks_count", sa.Integer, server_default=sa.text("0")),
    sa.Column("active_services_count", sa.Integer, server_default=sa.text("0")),
    sa.Column("capacity_providers", sa.Text),
    sa.Column("default_capacity_provider_strategy", sa.Text),
    sa.Column("settings", sa.Text),
    sa.Column("statistics", sa.Text),
    sa.Column("tags", sa.Text),
    sa.Column("raw_data", sa.Text),
    _timestamp_column(),
    sqlite_autoincrement=True,
)

t_ecs_services = sa.Table(
    "ecs_services",
    metadata,
    sa.Column("id", sa.Integer, primary_key=True, nullable=True),
    sa.Column(
        "scan_id", KeyText, sa.ForeignKey("scan_metadata.scan_id"), nullable=False
    ),
    sa.Column("service_arn", KeyText, nullable=False),
    sa.Column("service_name", KeyText, nullable=False),
    sa.Column("cluster_arn", KeyText, nullable=False),
    sa.Column("region", KeyText, nullable=False),
    sa.Column("status", KeyText, nullable=False),
    sa.Column("task_definition", sa.Text, nullable=False),
    sa.Column("desired_count", sa.Integer, nullable=False),
    sa.Column("running_count", sa.Integer, nullable=False),
    sa.Column("pending_count", sa.Integer, nullable=False),
    sa.Column("launch_type", sa.Text),
    sa.Column("platform_version", sa.Text),
    sa.Column("platform_family", sa.Text),
    sa.Column("capacity_provider_strategy", sa.Text),
    sa.Column("network_configuration", sa.Text),
    sa.Column("load_balancers", sa.Text),
    sa.Column("service_registries", sa.Text),
    sa.Column("deployment_configuration", sa.Text),
    sa.Column("deployments", sa.Text),
    sa.Column("health_check_grace_period_seconds", sa.Integer),
    sa.Column("scheduling_strategy", EnumText, server_default=sa.text("'REPLICA'")),
    sa.Column("created_at_svc", sa.Text),
    sa.Column("tags", sa.Text),
    sa.Column("raw_data", sa.Text),
    _timestamp_column(),
    sqlite_autoincrement=True,
)

t_ecs_task_definitions = sa.Table(
    "ecs_task_definitions",
    metadata,
    sa.Column("id", sa.Integer, primary_key=True, nullable=True),
    sa.Column(
        "scan_id", KeyText, sa.ForeignKey("scan_metadata.scan_id"), nullable=False
    ),
    sa.Column("task_definition_arn", KeyText, nullable=False),
    sa.Column("family", KeyText, nullable=False),
    sa.Column("revision", sa.Integer, nullable=False),
    sa.Column("region", KeyText, nullable=False),
    sa.Column("status", KeyText, nullable=False),
    sa.Column("requires_compatibilities", sa.Text),
    sa.Column("network_mode", sa.Text, nullable=False),
    sa.Column("cpu", sa.Text),
    sa.Column("memory", sa.Text),
    sa.Column("task_role_arn", sa.Text),
    sa.Column("execution_role_arn", sa.Text),
    sa.Column("container_definitions", sa.Text),
    sa.Column("volumes", sa.Text),
    sa.Column("placement_constraints", sa.Text),
    sa.Column("requires_attributes", sa.Text),
    sa.Column("pid_mode", sa.Text),
    sa.Column("ipc_mode", sa.Text),
    sa.Column("proxy_configuration", sa.Text),
    sa.Column("ephemeral_storage", sa.Text),
    sa.Column("runtime_platform", sa.Text),
    sa.Column("registered_at", sa.Text),
    sa.Column("deregistered_at", sa.Text),
    sa.Column("registered_by", sa.Text),
    sa.Column("tags", sa.Text),
    sa.Column("raw_data", sa.Text),
    _timestamp_column(),
    sqlite_autoincrement=True,
)

t_eks_clusters = sa.Table(
    "eks_clusters",
    metadata,
    sa.Column("id", sa.Integer, primary_key=True, nullable=True),
    sa.Column(
        "scan_id", KeyText, sa.ForeignKey("scan_metadata.scan_id"), nullable=False
    ),
    sa.Column("cluster_name", KeyText, nullable=False),
    sa.Column("cluster_arn", KeyText, nullable=False),
    sa.Column("region", KeyText, nullable=False),
    sa.Column("version", sa.Text, nullable=False),
    sa.Column("endpoint", sa.Text),
    sa.Column("role_arn", sa.Text, nullable=False),
    sa.Column("status", KeyText, nullable=False),
    sa.Column("vpc_id", KeyText, nullable=False),
    sa.Column("subnet_ids", sa.Text),
    sa.Column("security_group_ids", sa.Text),
    sa.Column("cluster_security_group_id", sa.Text),
    sa.Column("endpoint_public_access", sa.Integer, server_default=sa.text("1")),
    sa.Column("endpoint_private_access", sa.Integer, server_default=sa.text("0")),
    sa.Column("public_access_cidrs", sa.Text),
    sa.Column("resources_vpc_config", sa.Text),
    sa.Column("logging", sa.Text),
    sa.Column("identity", sa.Text),
    sa.Column("encryption_config", sa.Text),
    sa.Column("platform_version", sa.Text),
    sa.Column("created_at_eks", sa.Text),
    sa.Column("tags", sa.Text),
    sa.Column("raw_data", sa.Text),
    _timestamp_column(),
    sqlite_autoincrement=True,
)

t_eks_node_groups = sa.Table(
    "eks_node_groups",
    metadata,
    sa.Column("id", sa.Integer, primary_key=True, nullable=True),
    sa.Column(
        "scan_id", KeyText, sa.ForeignKey("scan_metadata.scan_id"), nullable=False
    ),
    sa.Column("cluster_name", KeyText, nullable=False),
    sa.Column("nodegroup_name", KeyText, nullable=False),
    sa.Column("nodegroup_arn", KeyText, nullable=False),
    sa.Column("region", KeyText, nullable=False),
    sa.Column("status", KeyText, nullable=False),
    sa.Column("scaling_config", sa.Text),
    sa.Column("instance_types", sa.Text),
    sa.Column("ami_type", sa.Text),
    sa.Column("release_version", sa.Text),
    sa.Column("subnets", sa.Text),
    sa.Column("remote_access", sa.Text),
    sa.Column("node_role", sa.Text, nullable=False),
    sa.Column("labels", sa.Text),
    sa.Column("taints", sa.Text),
    sa.Column("disk_size", sa.Integer),
    sa.Column("capacity_type", EnumText, server_default=sa.text("'ON_DEMAND'")),
    sa.Column("launch_template", sa.Text),
    sa.Column("update_config", sa.Text),
    sa.Column("health", sa.Text),
    sa.Column("created_at_ng", sa.Text),
    sa.Column("modified_at", sa.Text),
    sa.Column("tags", sa.Text),
    sa.Column("raw_data", sa.Text),
    _timestamp_column(),
    sqlite_autoincrement=True,
)

t_elastic_ips = sa.Table(
    "elastic_ips",
    metadata,
    sa.Column("id", sa.Integer, primary_key=True, nullable=True),
    sa.Column(
        "scan_id", KeyText, sa.ForeignKey("scan_metadata.scan_id"), nullable=False
    ),
    sa.Column("allocation_id", KeyText, nullable=False),
    sa.Column("region", KeyText, nullable=False),
    sa.Column("public_ip", sa.Text, nullable=False),
    sa.Column("domain", sa.Text, nullable=False),
    sa.Column("instance_id", KeyText),
    sa.Column("network_interface_id", sa.Text),
    sa.Column("network_interface_owner_id", sa.Text),
    sa.Column("private_ip_address", sa.Text),
    sa.Column("association_id", sa.Text),
    sa.Column("is_associated", sa.Integer, nullable=False),
    sa.Column("tags", sa.Text),
    sa.Column("raw_data", sa.Text),
    _timestamp_column(),
    sqlite_autoincrement=True,
)

t_elasticache_clusters = sa.Table(
    "elasticache_clusters",
    metadata,
    sa.Column("id", sa.Integer, primary_key=True, nullable=True),
    sa.Column(
        "scan_id", KeyText, sa.ForeignKey("scan_metadata.scan_id"), nullable=False
    ),
    sa.Column("cache_cluster_id", KeyText, nullable=False),
    sa.Column("cache_cluster_arn", KeyText, nullable=False),
    sa.Column("region", KeyText, nullable=False),
    sa.Column("engine", KeyText, nullable=False),
    sa.Column("engine_version", sa.Text, nullable=False),
    sa.Column("cache_node_type", sa.Text, nullable=False),
    sa.Column("num_cache_nodes", sa.Integer, nullable=False),
    sa.Column("preferred_availability_zone", sa.Text),
    sa.Column("preferred_availability_zones", sa.Text),
    sa.Column("cache_cluster_status", KeyText, nullable=False),
    sa.Column("cache_subnet_group_name", sa.Text),
    sa.Column("vpc_id", KeyText),
    sa.Column("security_groups", sa.Text),
    sa.Column("at_rest_encryption_enabled", sa.Integer, server_default=sa.text("0")),
    sa.Column("transit_encryption_enabled", sa.Integer, server_default=sa.text("0")),
    sa.Column("auth_token_enabled", sa.Integer, server_default=sa.text("0")),
    sa.Column("replication_group_id", sa.Text),
    sa.Column("snapshot_retention_limit", sa.Integer),
    sa.Column("snapshot_window", sa.Text),
    sa.Column("preferred_maintenance_window", sa.Text),
    sa.Column("notification_configuration", sa.Text),
    sa.Column("cache_parameter_group_name", sa.Text),
    sa.Column("cache_cluster_create_time", sa.Text),
    sa.Column("tags", sa.Text),
    sa.Column("raw_data", sa.Text),
    _timestamp_column(),
    sqlite_autoincrement=True,
)

t_iam_credential_report = sa.Table(
    "iam_credential_report",
    metadata,
    sa.Column("id", sa.Integer, primary_key=True, nullable=True),
    sa.Column(
        "scan_id", KeyText, sa.ForeignKey("scan_metadata.scan_id"), nullable=False
    ),
    sa.Column("user_name", KeyText, nullable=False),
    sa.Column("arn", sa.Text),
    sa.Column("user_creation_time", sa.Text),
    sa.Column("password_enabled", sa.Integer),
    sa.Column("password_last_used", sa.Text),
    sa.Column("mfa_active", sa.Integer, nullable=False, server_default=sa.text("0")),
    sa.Column(
        "access_key_1_active", sa.Integer, nullable=False, server_default=sa.text("0")
    ),
    sa.Column("access_key_1_last_rotated", sa.Text),
    sa.Column("access_key_1_last_used", sa.Text),
    sa.Column(
        "access_key_2_active", sa.Integer, nullable=False, server_default=sa.text("0")
    ),
    sa.Column("access_key_2_last_rotated", sa.Text),
    sa.Column("access_key_2_last_used", sa.Text),
    sa.Column("raw_data", sa.Text),
    _timestamp_column(),
    sqlite_autoincrement=True,
)

t_iam_policies = sa.Table(
    "iam_policies",
    metadata,
    sa.Column("id", sa.Integer, primary_key=True, nullable=True),
    sa.Column(
        "scan_id", KeyText, sa.ForeignKey("scan_metadata.scan_id"), nullable=False
    ),
    sa.Column("policy_arn", KeyText, nullable=False),
    sa.Column("policy_name", KeyText, nullable=False),
    sa.Column("policy_id", sa.Text, nullable=False),
    sa.Column("path", sa.Text, nullable=False),
    sa.Column("default_version_id", sa.Text, nullable=False),
    sa.Column("attachment_count", sa.Integer, nullable=False),
    sa.Column("permissions_boundary_usage_count", sa.Integer, nullable=False),
    sa.Column("is_attachable", sa.Integer, nullable=False),
    sa.Column("description", sa.Text),
    sa.Column("create_date", sa.Text, nullable=False),
    sa.Column("update_date", sa.Text, nullable=False),
    sa.Column("policy_document", sa.Text, nullable=False),
    sa.Column("attached_users", sa.Text),
    sa.Column("attached_roles", sa.Text),
    sa.Column("attached_groups", sa.Text),
    sa.Column("tags", sa.Text),
    sa.Column("raw_data", sa.Text),
    _timestamp_column(),
    sqlite_autoincrement=True,
)

t_iam_roles = sa.Table(
    "iam_roles",
    metadata,
    sa.Column("id", sa.Integer, primary_key=True, nullable=True),
    sa.Column(
        "scan_id", KeyText, sa.ForeignKey("scan_metadata.scan_id"), nullable=False
    ),
    sa.Column("role_name", sa.Text, nullable=False),
    sa.Column("role_id", sa.Text, nullable=False),
    sa.Column("arn", sa.Text, nullable=False),
    sa.Column("create_date", sa.Text, nullable=False),
    sa.Column("assume_role_policy", sa.Text, nullable=False),
    sa.Column("attached_policies", sa.Text),
    sa.Column("max_session_duration", sa.Integer, nullable=False),
    sa.Column("tags", sa.Text),
    sa.Column("raw_data", sa.Text),
    _timestamp_column(),
    sqlite_autoincrement=True,
)

t_iam_users = sa.Table(
    "iam_users",
    metadata,
    sa.Column("id", sa.Integer, primary_key=True, nullable=True),
    sa.Column(
        "scan_id", KeyText, sa.ForeignKey("scan_metadata.scan_id"), nullable=False
    ),
    sa.Column("user_name", sa.Text, nullable=False),
    sa.Column("user_id", sa.Text, nullable=False),
    sa.Column("arn", sa.Text, nullable=False),
    sa.Column("create_date", sa.Text, nullable=False),
    sa.Column("password_last_used", sa.Text),
    sa.Column("mfa_enabled", sa.Integer, nullable=False),
    sa.Column("access_keys", sa.Text),
    sa.Column("attached_policies", sa.Text),
    sa.Column("groups", sa.Text),
    sa.Column("tags", sa.Text),
    sa.Column("raw_data", sa.Text),
    _timestamp_column(),
    sqlite_autoincrement=True,
)

t_internet_gateways = sa.Table(
    "internet_gateways",
    metadata,
    sa.Column("id", sa.Integer, primary_key=True, nullable=True),
    sa.Column(
        "scan_id", KeyText, sa.ForeignKey("scan_metadata.scan_id"), nullable=False
    ),
    sa.Column("internet_gateway_id", KeyText, nullable=False),
    sa.Column("region", KeyText, nullable=False),
    sa.Column("vpc_attachments", sa.Text),
    sa.Column("tags", sa.Text),
    sa.Column("raw_data", sa.Text),
    _timestamp_column(),
    sqlite_autoincrement=True,
)

t_kms_keys = sa.Table(
    "kms_keys",
    metadata,
    sa.Column("id", sa.Integer, primary_key=True, nullable=True),
    sa.Column(
        "scan_id", KeyText, sa.ForeignKey("scan_metadata.scan_id"), nullable=False
    ),
    sa.Column("key_id", KeyText, nullable=False),
    sa.Column("key_arn", KeyText, nullable=False),
    sa.Column("region", KeyText, nullable=False),
    sa.Column("aws_account_id", sa.Text, nullable=False),
    sa.Column("key_state", KeyText, nullable=False),
    sa.Column("creation_date", sa.Text, nullable=False),
    sa.Column("key_manager", KeyText, nullable=False),
    sa.Column("key_usage", sa.Text, nullable=False),
    sa.Column("key_spec", sa.Text, nullable=False),
    sa.Column("description", sa.Text),
    sa.Column("enabled", sa.Integer, nullable=False),
    sa.Column("deletion_date", sa.Text),
    sa.Column("rotation_enabled", sa.Integer, server_default=sa.text("0")),
    sa.Column("key_policy", sa.Text),
    sa.Column("aliases", sa.Text),
    sa.Column("tags", sa.Text),
    sa.Column("raw_data", sa.Text),
    _timestamp_column(),
    sqlite_autoincrement=True,
)

t_lambda_exposure = sa.Table(
    "lambda_exposure",
    metadata,
    sa.Column("id", sa.Integer, primary_key=True, nullable=True),
    sa.Column(
        "scan_id", KeyText, sa.ForeignKey("scan_metadata.scan_id"), nullable=False
    ),
    sa.Column("region", sa.Text, nullable=False),
    sa.Column("function_name", sa.Text, nullable=False),
    sa.Column("function_arn", sa.Text, nullable=False),
    sa.Column("url_config", sa.Text),
    sa.Column("url_auth_type", KeyText),
    sa.Column("resource_policy", sa.Text),
    sa.Column("raw_data", sa.Text),
    _timestamp_column(),
    sqlite_autoincrement=True,
)

t_lambda_functions = sa.Table(
    "lambda_functions",
    metadata,
    sa.Column("id", sa.Integer, primary_key=True, nullable=True),
    sa.Column(
        "scan_id", KeyText, sa.ForeignKey("scan_metadata.scan_id"), nullable=False
    ),
    sa.Column("function_name", KeyText, nullable=False),
    sa.Column("function_arn", sa.Text, nullable=False),
    sa.Column("region", KeyText, nullable=False),
    sa.Column("runtime", KeyText, nullable=False),
    sa.Column("handler", sa.Text, nullable=False),
    sa.Column("code_size", sa.Integer, nullable=False),
    sa.Column("memory_size", sa.Integer, nullable=False),
    sa.Column("timeout", sa.Integer, nullable=False),
    sa.Column("last_modified", sa.Text, nullable=False),
    sa.Column("role_arn", sa.Text, nullable=False),
    sa.Column("vpc_config", sa.Text),
    sa.Column("environment_variables", sa.Text),
    sa.Column("layers", sa.Text),
    sa.Column("state", sa.Text, nullable=False),
    sa.Column("architectures", sa.Text),
    sa.Column("triggers", sa.Text),
    sa.Column("tags", sa.Text),
    sa.Column("raw_data", sa.Text),
    _timestamp_column(),
    sqlite_autoincrement=True,
)

t_load_balancers = sa.Table(
    "load_balancers",
    metadata,
    sa.Column("id", sa.Integer, primary_key=True, nullable=True),
    sa.Column(
        "scan_id", KeyText, sa.ForeignKey("scan_metadata.scan_id"), nullable=False
    ),
    sa.Column("load_balancer_name", sa.Text, nullable=False),
    sa.Column("load_balancer_arn", KeyText, nullable=False),
    sa.Column("load_balancer_type", KeyText, nullable=False),
    sa.Column("region", KeyText, nullable=False),
    sa.Column("vpc_id", KeyText),
    sa.Column("scheme", sa.Text, nullable=False),
    sa.Column("state", sa.Text, nullable=False),
    sa.Column("dns_name", sa.Text, nullable=False),
    sa.Column("availability_zones", sa.Text),
    sa.Column("security_groups", sa.Text),
    sa.Column("subnets", sa.Text),
    sa.Column("created_time", sa.Text),
    sa.Column("listeners", sa.Text),
    sa.Column("target_groups", sa.Text),
    sa.Column("tags", sa.Text),
    sa.Column("raw_data", sa.Text),
    _timestamp_column(),
    sqlite_autoincrement=True,
)

t_msk_clusters = sa.Table(
    "msk_clusters",
    metadata,
    sa.Column("id", sa.Integer, primary_key=True, nullable=True),
    sa.Column(
        "scan_id", KeyText, sa.ForeignKey("scan_metadata.scan_id"), nullable=False
    ),
    sa.Column("cluster_arn", KeyText, nullable=False),
    sa.Column("cluster_name", KeyText, nullable=False),
    sa.Column("region", KeyText, nullable=False),
    sa.Column("kafka_version", sa.Text, nullable=False),
    sa.Column("state", KeyText, nullable=False),
    sa.Column("creation_time", sa.Text),
    sa.Column("broker_node_group_info", sa.Text),
    sa.Column("number_of_broker_nodes", sa.Integer, nullable=False),
    sa.Column("encryption_in_transit", sa.Text),
    sa.Column("encryption_at_rest_kms_key_arn", sa.Text),
    sa.Column("enhanced_monitoring", sa.Text),
    sa.Column("open_monitoring", sa.Text),
    sa.Column("logging_info", sa.Text),
    sa.Column("cluster_type", sa.Text),
    sa.Column("provisioned", sa.Text),
    sa.Column("serverless", sa.Text),
    sa.Column("current_version", sa.Text),
    sa.Column("zookeeper_connect_string", sa.Text),
    sa.Column("zookeeper_connect_string_tls", sa.Text),
    sa.Column("bootstrap_broker_string", sa.Text),
    sa.Column("bootstrap_broker_string_tls", sa.Text),
    sa.Column("tags", sa.Text),
    sa.Column("raw_data", sa.Text),
    _timestamp_column(),
    sqlite_autoincrement=True,
)

t_nat_gateways = sa.Table(
    "nat_gateways",
    metadata,
    sa.Column("id", sa.Integer, primary_key=True, nullable=True),
    sa.Column(
        "scan_id", KeyText, sa.ForeignKey("scan_metadata.scan_id"), nullable=False
    ),
    sa.Column("nat_gateway_id", KeyText, nullable=False),
    sa.Column("region", KeyText, nullable=False),
    sa.Column("vpc_id", KeyText, nullable=False),
    sa.Column("subnet_id", sa.Text, nullable=False),
    sa.Column("state", sa.Text, nullable=False),
    sa.Column("connectivity_type", sa.Text, nullable=False),
    sa.Column("public_ip", sa.Text),
    sa.Column("private_ip", sa.Text),
    sa.Column("created_time", sa.Text),
    sa.Column("nat_gateway_addresses", sa.Text),
    sa.Column("tags", sa.Text),
    sa.Column("raw_data", sa.Text),
    _timestamp_column(),
    sqlite_autoincrement=True,
)

t_network_interfaces = sa.Table(
    "network_interfaces",
    metadata,
    sa.Column("id", sa.Integer, primary_key=True, nullable=True),
    sa.Column(
        "scan_id", KeyText, sa.ForeignKey("scan_metadata.scan_id"), nullable=False
    ),
    sa.Column("network_interface_id", KeyText, nullable=False),
    sa.Column("region", KeyText, nullable=False),
    sa.Column("interface_type", sa.Text, nullable=False),
    sa.Column("status", sa.Text, nullable=False),
    sa.Column("vpc_id", KeyText, nullable=False),
    sa.Column("subnet_id", KeyText, nullable=False),
    sa.Column("availability_zone", sa.Text, nullable=False),
    sa.Column("description", sa.Text),
    sa.Column("private_ip_address", sa.Text),
    sa.Column("private_ip_addresses", sa.Text),
    sa.Column("public_ip", sa.Text),
    sa.Column("mac_address", sa.Text),
    sa.Column("source_dest_check", sa.Integer, nullable=False),
    sa.Column("security_groups", sa.Text),
    sa.Column("attachment", sa.Text),
    sa.Column("tags", sa.Text),
    sa.Column("raw_data", sa.Text),
    _timestamp_column(),
    sqlite_autoincrement=True,
)

t_opensearch_domains = sa.Table(
    "opensearch_domains",
    metadata,
    sa.Column("id", sa.Integer, primary_key=True, nullable=True),
    sa.Column(
        "scan_id", KeyText, sa.ForeignKey("scan_metadata.scan_id"), nullable=False
    ),
    sa.Column("domain_id", KeyText, nullable=False),
    sa.Column("domain_name", KeyText, nullable=False),
    sa.Column("domain_arn", KeyText, nullable=False),
    sa.Column("region", KeyText, nullable=False),
    sa.Column("engine_type", sa.Text, nullable=False),
    sa.Column("engine_version", sa.Text, nullable=False),
    sa.Column("instance_type", sa.Text, nullable=False),
    sa.Column("instance_count", sa.Integer, nullable=False),
    sa.Column("dedicated_master_enabled", sa.Integer, server_default=sa.text("0")),
    sa.Column("dedicated_master_type", sa.Text),
    sa.Column("dedicated_master_count", sa.Integer),
    sa.Column("zone_awareness_enabled", sa.Integer, server_default=sa.text("0")),
    sa.Column("availability_zone_count", sa.Integer),
    sa.Column("warm_enabled", sa.Integer, server_default=sa.text("0")),
    sa.Column("warm_type", sa.Text),
    sa.Column("warm_count", sa.Integer),
    sa.Column("cold_storage_enabled", sa.Integer, server_default=sa.text("0")),
    sa.Column("ebs_enabled", sa.Integer, server_default=sa.text("0")),
    sa.Column("volume_type", sa.Text),
    sa.Column("volume_size", sa.Integer),
    sa.Column("iops", sa.Integer),
    sa.Column("throughput", sa.Integer),
    sa.Column("vpc_id", KeyText),
    sa.Column("subnet_ids", sa.Text),
    sa.Column("security_group_ids", sa.Text),
    sa.Column("endpoint", sa.Text),
    sa.Column("endpoints", sa.Text),
    sa.Column("encryption_at_rest_enabled", sa.Integer, server_default=sa.text("0")),
    sa.Column("kms_key_id", sa.Text),
    sa.Column(
        "node_to_node_encryption_enabled", sa.Integer, server_default=sa.text("0")
    ),
    sa.Column("enforce_https", sa.Integer, server_default=sa.text("0")),
    sa.Column("tls_security_policy", sa.Text),
    sa.Column("custom_endpoint_enabled", sa.Integer, server_default=sa.text("0")),
    sa.Column("custom_endpoint", sa.Text),
    sa.Column("access_policies", sa.Text),
    sa.Column(
        "internal_user_database_enabled", sa.Integer, server_default=sa.text("0")
    ),
    sa.Column("saml_enabled", sa.Integer, server_default=sa.text("0")),
    sa.Column("auto_tune_enabled", sa.Integer, server_default=sa.text("0")),
    sa.Column("created", sa.Integer, server_default=sa.text("0")),
    sa.Column("deleted", sa.Integer, server_default=sa.text("0")),
    sa.Column("processing", sa.Integer, server_default=sa.text("0")),
    sa.Column("upgrade_processing", sa.Integer, server_default=sa.text("0")),
    sa.Column("domain_processing_status", sa.Text),
    sa.Column("tags", sa.Text),
    sa.Column("raw_data", sa.Text),
    _timestamp_column(),
    sqlite_autoincrement=True,
)

t_organization_accounts = sa.Table(
    "organization_accounts",
    metadata,
    sa.Column("id", sa.Integer, primary_key=True, nullable=True),
    sa.Column(
        "scan_id", KeyText, sa.ForeignKey("scan_metadata.scan_id"), nullable=False
    ),
    sa.Column("account_id", KeyText, nullable=False),
    sa.Column("account_arn", sa.Text, nullable=False),
    sa.Column("account_name", sa.Text, nullable=False),
    sa.Column("email", sa.Text, nullable=False),
    sa.Column("status", KeyText, nullable=False),
    sa.Column("joined_method", sa.Text, nullable=False),
    sa.Column("joined_timestamp", sa.Text),
    sa.Column("parent_ou_id", KeyText),
    sa.Column("raw_data", sa.Text),
    _timestamp_column(),
    sqlite_autoincrement=True,
)

t_organizational_units = sa.Table(
    "organizational_units",
    metadata,
    sa.Column("id", sa.Integer, primary_key=True, nullable=True),
    sa.Column(
        "scan_id", KeyText, sa.ForeignKey("scan_metadata.scan_id"), nullable=False
    ),
    sa.Column("ou_id", KeyText, nullable=False),
    sa.Column("ou_arn", sa.Text, nullable=False),
    sa.Column("ou_name", sa.Text, nullable=False),
    sa.Column("parent_id", KeyText),
    sa.Column("raw_data", sa.Text),
    _timestamp_column(),
    sqlite_autoincrement=True,
)

t_organizations = sa.Table(
    "organizations",
    metadata,
    sa.Column("id", sa.Integer, primary_key=True, nullable=True),
    sa.Column(
        "scan_id", KeyText, sa.ForeignKey("scan_metadata.scan_id"), nullable=False
    ),
    sa.Column("organization_id", KeyText, nullable=False),
    sa.Column("organization_arn", sa.Text, nullable=False),
    sa.Column("master_account_id", sa.Text, nullable=False),
    sa.Column("master_account_email", sa.Text, nullable=False),
    sa.Column("feature_set", sa.Text, nullable=False),
    sa.Column("available_policy_types", sa.Text),
    sa.Column("raw_data", sa.Text),
    _timestamp_column(),
    sqlite_autoincrement=True,
)

t_prowler_findings = sa.Table(
    "prowler_findings",
    metadata,
    sa.Column("id", sa.Integer, primary_key=True, nullable=True),
    sa.Column(
        "scan_id", KeyText, sa.ForeignKey("scan_metadata.scan_id"), nullable=False
    ),
    sa.Column("check_id", sa.Text, nullable=False),
    sa.Column("check_title", sa.Text, nullable=False),
    sa.Column("severity", KeyText, nullable=False),
    sa.Column("status", KeyText, nullable=False),
    sa.Column("region", sa.Text),
    sa.Column("resource_id", sa.Text),
    sa.Column("resource_arn", sa.Text),
    sa.Column("resource_tags", sa.Text),
    sa.Column("status_extended", sa.Text),
    sa.Column("service_name", KeyText, nullable=False),
    sa.Column("check_type", sa.Text, nullable=False),
    sa.Column("risk", sa.Text),
    sa.Column("remediation", sa.Text),
    sa.Column("compliance_frameworks", sa.Text),
    sa.Column("raw_data", sa.Text),
    _timestamp_column(),
    sqlite_autoincrement=True,
)

t_rds_instances = sa.Table(
    "rds_instances",
    metadata,
    sa.Column("id", sa.Integer, primary_key=True, nullable=True),
    sa.Column(
        "scan_id", KeyText, sa.ForeignKey("scan_metadata.scan_id"), nullable=False
    ),
    sa.Column("db_instance_identifier", KeyText, nullable=False),
    sa.Column("region", KeyText, nullable=False),
    sa.Column("db_instance_arn", sa.Text, nullable=False),
    sa.Column("engine", KeyText, nullable=False),
    sa.Column("engine_version", sa.Text, nullable=False),
    sa.Column("db_instance_class", sa.Text, nullable=False),
    sa.Column("allocated_storage", sa.Integer, nullable=False),
    sa.Column("storage_type", sa.Text, nullable=False),
    sa.Column("iops", sa.Integer),
    sa.Column("multi_az", sa.Integer, nullable=False),
    sa.Column("availability_zone", sa.Text),
    sa.Column("secondary_availability_zone", sa.Text),
    sa.Column("publicly_accessible", sa.Integer, nullable=False),
    sa.Column("encrypted", sa.Integer, nullable=False),
    sa.Column("kms_key_id", sa.Text),
    sa.Column("vpc_id", KeyText),
    sa.Column("subnet_group", sa.Text),
    sa.Column("vpc_security_groups", sa.Text),
    sa.Column("backup_retention_period", sa.Integer, nullable=False),
    sa.Column("preferred_backup_window", sa.Text),
    sa.Column("latest_restorable_time", sa.Text),
    sa.Column("endpoint_address", sa.Text),
    sa.Column("endpoint_port", sa.Integer),
    sa.Column("db_instance_status", sa.Text, nullable=False),
    sa.Column("monitoring_interval", sa.Integer, server_default=sa.text("0")),
    sa.Column("performance_insights_enabled", sa.Integer, server_default=sa.text("0")),
    sa.Column("auto_minor_version_upgrade", sa.Integer, server_default=sa.text("1")),
    sa.Column("deletion_protection", sa.Integer, server_default=sa.text("0")),
    sa.Column("tags", sa.Text),
    sa.Column("raw_data", sa.Text),
    _timestamp_column(),
    sqlite_autoincrement=True,
)

t_region_security_services = sa.Table(
    "region_security_services",
    metadata,
    sa.Column("id", sa.Integer, primary_key=True, nullable=True),
    sa.Column(
        "scan_id", KeyText, sa.ForeignKey("scan_metadata.scan_id"), nullable=False
    ),
    sa.Column("region", KeyText, nullable=False),
    sa.Column("guardduty_enabled", sa.Integer),
    sa.Column("guardduty_detector", sa.Text),
    sa.Column("security_hub_enabled", sa.Integer),
    sa.Column("ebs_encryption_by_default", sa.Integer),
    sa.Column("access_analyzers", sa.Text),
    sa.Column("raw_data", sa.Text),
    _timestamp_column(),
    sqlite_autoincrement=True,
)

t_route53_hosted_zones = sa.Table(
    "route53_hosted_zones",
    metadata,
    sa.Column("id", sa.Integer, primary_key=True, nullable=True),
    sa.Column(
        "scan_id", KeyText, sa.ForeignKey("scan_metadata.scan_id"), nullable=False
    ),
    sa.Column("hosted_zone_id", sa.Text, nullable=False),
    sa.Column("name", sa.Text, nullable=False),
    sa.Column("is_private", sa.Integer, nullable=False),
    sa.Column("resource_record_set_count", sa.Integer, nullable=False),
    sa.Column("vpc_associations", sa.Text),
    sa.Column("tags", sa.Text),
    sa.Column("raw_data", sa.Text),
    _timestamp_column(),
    sqlite_autoincrement=True,
)

t_route53_record_sets = sa.Table(
    "route53_record_sets",
    metadata,
    sa.Column("id", sa.Integer, primary_key=True, nullable=True),
    sa.Column(
        "scan_id", KeyText, sa.ForeignKey("scan_metadata.scan_id"), nullable=False
    ),
    sa.Column("hosted_zone_id", KeyText, nullable=False),
    sa.Column("name", sa.Text, nullable=False),
    sa.Column("record_type", sa.Text, nullable=False),
    sa.Column("ttl", sa.Integer),
    sa.Column("resource_records", sa.Text),
    sa.Column("alias_target", sa.Text),
    sa.Column("raw_data", sa.Text),
    _timestamp_column(),
    sqlite_autoincrement=True,
)

t_route_tables = sa.Table(
    "route_tables",
    metadata,
    sa.Column("id", sa.Integer, primary_key=True, nullable=True),
    sa.Column(
        "scan_id", KeyText, sa.ForeignKey("scan_metadata.scan_id"), nullable=False
    ),
    sa.Column("route_table_id", KeyText, nullable=False),
    sa.Column("region", KeyText, nullable=False),
    sa.Column("vpc_id", KeyText, nullable=False),
    sa.Column("is_main", sa.Integer, nullable=False),
    sa.Column("routes", sa.Text),
    sa.Column("subnet_associations", sa.Text),
    sa.Column("gateway_associations", sa.Text),
    sa.Column("tags", sa.Text),
    sa.Column("raw_data", sa.Text),
    _timestamp_column(),
    sqlite_autoincrement=True,
)

t_s3_buckets = sa.Table(
    "s3_buckets",
    metadata,
    sa.Column("id", sa.Integer, primary_key=True, nullable=True),
    sa.Column(
        "scan_id", KeyText, sa.ForeignKey("scan_metadata.scan_id"), nullable=False
    ),
    sa.Column("bucket_name", KeyText, nullable=False),
    sa.Column("creation_date", sa.Text, nullable=False),
    sa.Column("region", sa.Text),
    sa.Column("versioning_status", sa.Text),
    sa.Column("public_access_block", sa.Text),
    sa.Column("encryption_config", sa.Text),
    sa.Column("lifecycle_rules", sa.Text),
    sa.Column("logging_enabled", sa.Integer, nullable=False),
    sa.Column("size_bytes", sa.Integer),
    sa.Column("object_count", sa.Integer),
    sa.Column("tags", sa.Text),
    sa.Column("raw_data", sa.Text),
    _timestamp_column(),
    sqlite_autoincrement=True,
)

t_s3_public_access = sa.Table(
    "s3_public_access",
    metadata,
    sa.Column("id", sa.Integer, primary_key=True, nullable=True),
    sa.Column(
        "scan_id", KeyText, sa.ForeignKey("scan_metadata.scan_id"), nullable=False
    ),
    sa.Column("bucket_name", KeyText, nullable=False),
    sa.Column("public_access_block", sa.Text),
    sa.Column("policy_is_public", sa.Integer),
    sa.Column("raw_data", sa.Text),
    _timestamp_column(),
    sqlite_autoincrement=True,
)

t_scan_metadata = sa.Table(
    "scan_metadata",
    metadata,
    sa.Column("scan_id", KeyText, primary_key=True, nullable=True),
    sa.Column("account_name", sa.Text, nullable=False),
    sa.Column("account_number", KeyText, nullable=False),
    sa.Column("scan_timestamp", KeyText, nullable=False),
    sa.Column("prowler_level", sa.Text),
    sa.Column("regions_scanned", sa.Text, nullable=False),
    sa.Column("scan_status", sa.Text, nullable=False),
    sa.Column("error_message", sa.Text),
    sa.Column("scan_duration_seconds", sa.REAL),
    _timestamp_column(),
)

t_schema_version = sa.Table(
    "schema_version",
    metadata,
    sa.Column("version", sa.Integer, primary_key=True, nullable=True),
    _timestamp_column("applied_at"),
)

t_security_groups = sa.Table(
    "security_groups",
    metadata,
    sa.Column("id", sa.Integer, primary_key=True, nullable=True),
    sa.Column(
        "scan_id", KeyText, sa.ForeignKey("scan_metadata.scan_id"), nullable=False
    ),
    sa.Column("group_id", KeyText, nullable=False),
    sa.Column("group_name", sa.Text, nullable=False),
    sa.Column("vpc_id", KeyText),
    sa.Column("region", sa.Text, nullable=False),
    sa.Column("description", sa.Text, nullable=False),
    sa.Column("ingress_rules", sa.Text),
    sa.Column("egress_rules", sa.Text),
    sa.Column("tags", sa.Text),
    sa.Column("raw_data", sa.Text),
    _timestamp_column(),
    sqlite_autoincrement=True,
)

t_sso_assignments = sa.Table(
    "sso_assignments",
    metadata,
    sa.Column("id", sa.Integer, primary_key=True, nullable=True),
    sa.Column(
        "scan_id", KeyText, sa.ForeignKey("scan_metadata.scan_id"), nullable=False
    ),
    sa.Column("instance_arn", sa.Text, nullable=False),
    sa.Column("permission_set_arn", KeyText, nullable=False),
    sa.Column("principal_type", sa.Text, nullable=False),
    sa.Column("principal_id", KeyText, nullable=False),
    sa.Column("target_type", sa.Text, nullable=False),
    sa.Column("target_id", KeyText, nullable=False),
    sa.Column("raw_data", sa.Text),
    _timestamp_column(),
    sqlite_autoincrement=True,
)

t_sso_permission_sets = sa.Table(
    "sso_permission_sets",
    metadata,
    sa.Column("id", sa.Integer, primary_key=True, nullable=True),
    sa.Column(
        "scan_id", KeyText, sa.ForeignKey("scan_metadata.scan_id"), nullable=False
    ),
    sa.Column("permission_set_arn", KeyText, nullable=False),
    sa.Column("permission_set_name", KeyText, nullable=False),
    sa.Column("instance_arn", KeyText, nullable=False),
    sa.Column("description", sa.Text),
    sa.Column("session_duration", sa.Text),
    sa.Column("relay_state", sa.Text),
    sa.Column("created_date", sa.Text),
    sa.Column("managed_policies", sa.Text),
    sa.Column("inline_policy", sa.Text),
    sa.Column("customer_managed_policies", sa.Text),
    sa.Column("permissions_boundary", sa.Text),
    sa.Column("tags", sa.Text),
    sa.Column("raw_data", sa.Text),
    _timestamp_column(),
    sqlite_autoincrement=True,
)

t_subnets = sa.Table(
    "subnets",
    metadata,
    sa.Column("id", sa.Integer, primary_key=True, nullable=True),
    sa.Column(
        "scan_id", KeyText, sa.ForeignKey("scan_metadata.scan_id"), nullable=False
    ),
    sa.Column("subnet_id", sa.Text, nullable=False),
    sa.Column("vpc_id", KeyText, nullable=False),
    sa.Column("region", KeyText, nullable=False),
    sa.Column("cidr_block", sa.Text, nullable=False),
    sa.Column("availability_zone", sa.Text, nullable=False),
    sa.Column("available_ip_count", sa.Integer, nullable=False),
    sa.Column("map_public_ip", sa.Integer, nullable=False),
    sa.Column("state", sa.Text, nullable=False),
    sa.Column("tags", sa.Text),
    sa.Column("raw_data", sa.Text),
    _timestamp_column(),
    sqlite_autoincrement=True,
)

t_transit_gateways = sa.Table(
    "transit_gateways",
    metadata,
    sa.Column("id", sa.Integer, primary_key=True, nullable=True),
    sa.Column(
        "scan_id", KeyText, sa.ForeignKey("scan_metadata.scan_id"), nullable=False
    ),
    sa.Column("transit_gateway_id", KeyText, nullable=False),
    sa.Column("transit_gateway_arn", KeyText, nullable=False),
    sa.Column("region", KeyText, nullable=False),
    sa.Column("owner_id", sa.Text, nullable=False),
    sa.Column("description", sa.Text),
    sa.Column("state", KeyText, nullable=False),
    sa.Column("amazon_side_asn", sa.Integer),
    sa.Column("default_route_table_id", sa.Text),
    sa.Column("default_route_table_association", sa.Text),
    sa.Column("default_route_table_propagation", sa.Text),
    sa.Column("vpn_ecmp_support", sa.Text),
    sa.Column("dns_support", sa.Text),
    sa.Column("multicast_support", sa.Text),
    sa.Column("auto_accept_shared_attachments", sa.Text),
    sa.Column("transit_gateway_cidr_blocks", sa.Text),
    sa.Column("creation_time", sa.Text),
    sa.Column("tags", sa.Text),
    sa.Column("raw_data", sa.Text),
    _timestamp_column(),
    sqlite_autoincrement=True,
)

t_vpc_flow_logs = sa.Table(
    "vpc_flow_logs",
    metadata,
    sa.Column("id", sa.Integer, primary_key=True, nullable=True),
    sa.Column(
        "scan_id", KeyText, sa.ForeignKey("scan_metadata.scan_id"), nullable=False
    ),
    sa.Column("flow_log_id", KeyText, nullable=False),
    sa.Column("region", KeyText, nullable=False),
    sa.Column("resource_id", KeyText, nullable=False),
    sa.Column("resource_type", KeyText, nullable=False),
    sa.Column("traffic_type", sa.Text, nullable=False),
    sa.Column("log_destination_type", sa.Text, nullable=False),
    sa.Column("log_destination", sa.Text, nullable=False),
    sa.Column("log_format", sa.Text),
    sa.Column("flow_log_status", sa.Text, nullable=False),
    sa.Column("created_time", sa.Text),
    sa.Column("tags", sa.Text),
    sa.Column("raw_data", sa.Text),
    _timestamp_column(),
    sqlite_autoincrement=True,
)

t_vpcs = sa.Table(
    "vpcs",
    metadata,
    sa.Column("id", sa.Integer, primary_key=True, nullable=True),
    sa.Column(
        "scan_id", KeyText, sa.ForeignKey("scan_metadata.scan_id"), nullable=False
    ),
    sa.Column("vpc_id", KeyText, nullable=False),
    sa.Column("region", KeyText, nullable=False),
    sa.Column("cidr_block", sa.Text, nullable=False),
    sa.Column("state", sa.Text, nullable=False),
    sa.Column("is_default", sa.Integer, nullable=False),
    sa.Column("dhcp_options_id", sa.Text),
    sa.Column("instance_tenancy", sa.Text, nullable=False),
    sa.Column("tags", sa.Text),
    sa.Column("raw_data", sa.Text),
    _timestamp_column(),
    sqlite_autoincrement=True,
)

t_vpn_connections = sa.Table(
    "vpn_connections",
    metadata,
    sa.Column("id", sa.Integer, primary_key=True, nullable=True),
    sa.Column(
        "scan_id", KeyText, sa.ForeignKey("scan_metadata.scan_id"), nullable=False
    ),
    sa.Column("vpn_connection_id", KeyText, nullable=False),
    sa.Column("region", KeyText, nullable=False),
    sa.Column("state", KeyText, nullable=False),
    sa.Column("vpn_connection_type", sa.Text, nullable=False),
    sa.Column("customer_gateway_id", sa.Text, nullable=False),
    sa.Column("vpn_gateway_id", sa.Text),
    sa.Column("transit_gateway_id", sa.Text),
    sa.Column("customer_gateway_configuration", sa.Text),
    sa.Column("static_routes_only", sa.Integer, server_default=sa.text("0")),
    sa.Column("vgw_telemetry", sa.Text),
    sa.Column("routes", sa.Text),
    sa.Column("category", sa.Text),
    sa.Column("tags", sa.Text),
    sa.Column("raw_data", sa.Text),
    _timestamp_column(),
    sqlite_autoincrement=True,
)

t_workspaces = sa.Table(
    "workspaces",
    metadata,
    sa.Column("id", sa.Integer, primary_key=True, nullable=True),
    sa.Column(
        "scan_id", KeyText, sa.ForeignKey("scan_metadata.scan_id"), nullable=False
    ),
    sa.Column("workspace_id", KeyText, nullable=False),
    sa.Column("region", KeyText, nullable=False),
    sa.Column("directory_id", KeyText, nullable=False),
    sa.Column("user_name", sa.Text, nullable=False),
    sa.Column("bundle_id", sa.Text, nullable=False),
    sa.Column("subnet_id", sa.Text, nullable=False),
    sa.Column("vpc_id", KeyText),
    sa.Column("ip_address", sa.Text),
    sa.Column("state", sa.Text, nullable=False),
    sa.Column("compute_type", sa.Text, nullable=False),
    sa.Column("volume_encryption_enabled", sa.Integer, nullable=False),
    sa.Column("user_volume_size_gb", sa.Integer, nullable=False),
    sa.Column("root_volume_size_gb", sa.Integer, nullable=False),
    sa.Column("running_mode", sa.Text, nullable=False),
    sa.Column("tags", sa.Text),
    sa.Column("raw_data", sa.Text),
    _timestamp_column(),
    sqlite_autoincrement=True,
)


# Indices, verbatim from the legacy DDL (names and column order preserved).

sa.Index("idx_posture_scan", t_account_security_posture.c.scan_id)

sa.Index("idx_apigw_http_scan", t_api_gateway_http_apis.c.scan_id)
sa.Index("idx_apigw_http_id", t_api_gateway_http_apis.c.api_id)
sa.Index("idx_apigw_http_name", t_api_gateway_http_apis.c.name)
sa.Index("idx_apigw_http_region", t_api_gateway_http_apis.c.region)

sa.Index("idx_apigw_rest_scan", t_api_gateway_rest_apis.c.scan_id)
sa.Index("idx_apigw_rest_id", t_api_gateway_rest_apis.c.api_id)
sa.Index("idx_apigw_rest_name", t_api_gateway_rest_apis.c.name)
sa.Index("idx_apigw_rest_region", t_api_gateway_rest_apis.c.region)

sa.Index("idx_apigw_stage_scan", t_api_gateway_stages.c.scan_id)
sa.Index("idx_apigw_stage_api", t_api_gateway_stages.c.api_id)
sa.Index("idx_apigw_stage_name", t_api_gateway_stages.c.stage_name)
sa.Index("idx_apigw_stage_region", t_api_gateway_stages.c.region)
sa.Index("idx_apigw_stage_type", t_api_gateway_stages.c.api_type)

sa.Index("idx_asg_scan", t_auto_scaling_groups.c.scan_id)
sa.Index("idx_asg_name", t_auto_scaling_groups.c.auto_scaling_group_name)
sa.Index("idx_asg_region", t_auto_scaling_groups.c.region)

sa.Index("idx_br_agent_scan", t_bedrock_agents.c.scan_id)
sa.Index("idx_br_agent_id", t_bedrock_agents.c.agent_id)
sa.Index("idx_br_agent_arn", t_bedrock_agents.c.agent_arn)
sa.Index("idx_br_agent_region", t_bedrock_agents.c.region)
sa.Index("idx_br_agent_status", t_bedrock_agents.c.agent_status)

sa.Index("idx_br_guard_scan", t_bedrock_guardrails.c.scan_id)
sa.Index("idx_br_guard_id", t_bedrock_guardrails.c.guardrail_id)
sa.Index("idx_br_guard_arn", t_bedrock_guardrails.c.guardrail_arn)
sa.Index("idx_br_guard_region", t_bedrock_guardrails.c.region)
sa.Index("idx_br_guard_status", t_bedrock_guardrails.c.status)

sa.Index("idx_br_kb_scan", t_bedrock_knowledge_bases.c.scan_id)
sa.Index("idx_br_kb_id", t_bedrock_knowledge_bases.c.knowledge_base_id)
sa.Index("idx_br_kb_arn", t_bedrock_knowledge_bases.c.knowledge_base_arn)
sa.Index("idx_br_kb_region", t_bedrock_knowledge_bases.c.region)
sa.Index("idx_br_kb_status", t_bedrock_knowledge_bases.c.status)

sa.Index("idx_br_model_scan", t_bedrock_models.c.scan_id)
sa.Index("idx_br_model_id", t_bedrock_models.c.model_id)
sa.Index("idx_br_model_arn", t_bedrock_models.c.model_arn)
sa.Index("idx_br_model_region", t_bedrock_models.c.region)
sa.Index("idx_br_model_provider", t_bedrock_models.c.provider_name)

sa.Index("idx_cf_dist_scan", t_cloudfront_distributions.c.scan_id)
sa.Index("idx_cf_dist_id", t_cloudfront_distributions.c.distribution_id)
sa.Index("idx_cf_dist_arn", t_cloudfront_distributions.c.distribution_arn)
sa.Index("idx_cf_dist_status", t_cloudfront_distributions.c.status)
sa.Index("idx_cf_dist_enabled", t_cloudfront_distributions.c.enabled)

sa.Index("idx_ct_scan", t_cloudtrail_trails.c.scan_id)
sa.Index("idx_ct_name", t_cloudtrail_trails.c.trail_name)
sa.Index("idx_ct_arn", t_cloudtrail_trails.c.trail_arn)
sa.Index("idx_ct_region", t_cloudtrail_trails.c.region)
sa.Index("idx_ct_logging", t_cloudtrail_trails.c.is_logging)

sa.Index("idx_cw_lg_scan", t_cloudwatch_log_groups.c.scan_id)
sa.Index("idx_cw_lg_name", t_cloudwatch_log_groups.c.log_group_name)
sa.Index("idx_cw_lg_arn", t_cloudwatch_log_groups.c.log_group_arn)
sa.Index("idx_cw_lg_region", t_cloudwatch_log_groups.c.region)

sa.Index("idx_cfg_rec_scan", t_config_recorders.c.scan_id)
sa.Index("idx_cfg_rec_name", t_config_recorders.c.recorder_name)
sa.Index("idx_cfg_rec_region", t_config_recorders.c.region)
sa.Index("idx_cfg_rec_recording", t_config_recorders.c.is_recording)

sa.Index("idx_cfg_rule_scan", t_config_rules.c.scan_id)
sa.Index("idx_cfg_rule_name", t_config_rules.c.rule_name)
sa.Index("idx_cfg_rule_arn", t_config_rules.c.rule_arn)
sa.Index("idx_cfg_rule_region", t_config_rules.c.region)
sa.Index("idx_cfg_rule_compliance", t_config_rules.c.compliance_type)

sa.Index("idx_cost_scan", t_cost_data.c.scan_id)
sa.Index("idx_cost_account", t_cost_data.c.account_number)
sa.Index("idx_cost_service", t_cost_data.c.service_name)
sa.Index(
    "idx_cost_period", t_cost_data.c.time_period_start, t_cost_data.c.time_period_end
)

sa.Index("idx_dx_scan", t_direct_connect_connections.c.scan_id)
sa.Index("idx_dx_id", t_direct_connect_connections.c.connection_id)
sa.Index("idx_dx_name", t_direct_connect_connections.c.connection_name)
sa.Index("idx_dx_region", t_direct_connect_connections.c.region)
sa.Index("idx_dx_state", t_direct_connect_connections.c.connection_state)

sa.Index("idx_ds_scan", t_directory_services.c.scan_id)
sa.Index("idx_ds_id", t_directory_services.c.directory_id)
sa.Index("idx_ds_name", t_directory_services.c.directory_name)
sa.Index("idx_ds_region", t_directory_services.c.region)
sa.Index("idx_ds_type", t_directory_services.c.directory_type)
sa.Index("idx_ds_vpc", t_directory_services.c.vpc_id)

sa.Index("idx_ddb_scan", t_dynamodb_tables.c.scan_id)
sa.Index("idx_ddb_name", t_dynamodb_tables.c.table_name)
sa.Index("idx_ddb_arn", t_dynamodb_tables.c.table_arn)
sa.Index("idx_ddb_region", t_dynamodb_tables.c.region)
sa.Index("idx_ddb_status", t_dynamodb_tables.c.table_status)

sa.Index("idx_ebs_snap_scan", t_ebs_snapshots.c.scan_id)
sa.Index("idx_ebs_snap_id", t_ebs_snapshots.c.snapshot_id)
sa.Index("idx_ebs_snap_region", t_ebs_snapshots.c.region)
sa.Index("idx_ebs_snap_volume", t_ebs_snapshots.c.volume_id)
sa.Index("idx_ebs_snap_encrypted", t_ebs_snapshots.c.encrypted)
sa.Index("idx_ebs_snap_start", t_ebs_snapshots.c.start_time)

sa.Index("idx_ebs_vol_scan", t_ebs_volumes.c.scan_id)
sa.Index("idx_ebs_vol_id", t_ebs_volumes.c.volume_id)
sa.Index("idx_ebs_vol_region", t_ebs_volumes.c.region)
sa.Index("idx_ebs_vol_state", t_ebs_volumes.c.state)
sa.Index("idx_ebs_vol_instance", t_ebs_volumes.c.attached_instance_id)
sa.Index("idx_ebs_vol_encrypted", t_ebs_volumes.c.encrypted)

sa.Index("idx_ec2_scan", t_ec2_instances.c.scan_id)
sa.Index("idx_ec2_instance", t_ec2_instances.c.instance_id)
sa.Index("idx_ec2_region", t_ec2_instances.c.region)
sa.Index("idx_ec2_vpc", t_ec2_instances.c.vpc_id)
sa.Index("idx_ec2_public_ip", t_ec2_instances.c.public_ip)

sa.Index("idx_ecr_img_scan", t_ecr_images.c.scan_id)
sa.Index("idx_ecr_img_repo", t_ecr_images.c.repository_name)
sa.Index("idx_ecr_img_digest", t_ecr_images.c.image_digest)
sa.Index("idx_ecr_img_region", t_ecr_images.c.region)

sa.Index("idx_ecr_repo_scan", t_ecr_repositories.c.scan_id)
sa.Index("idx_ecr_repo_arn", t_ecr_repositories.c.repository_arn)
sa.Index("idx_ecr_repo_name", t_ecr_repositories.c.repository_name)
sa.Index("idx_ecr_repo_region", t_ecr_repositories.c.region)

sa.Index("idx_ecs_cluster_scan", t_ecs_clusters.c.scan_id)
sa.Index("idx_ecs_cluster_arn", t_ecs_clusters.c.cluster_arn)
sa.Index("idx_ecs_cluster_name", t_ecs_clusters.c.cluster_name)
sa.Index("idx_ecs_cluster_region", t_ecs_clusters.c.region)
sa.Index("idx_ecs_cluster_status", t_ecs_clusters.c.status)

sa.Index("idx_ecs_svc_scan", t_ecs_services.c.scan_id)
sa.Index("idx_ecs_svc_arn", t_ecs_services.c.service_arn)
sa.Index("idx_ecs_svc_name", t_ecs_services.c.service_name)
sa.Index("idx_ecs_svc_cluster", t_ecs_services.c.cluster_arn)
sa.Index("idx_ecs_svc_region", t_ecs_services.c.region)
sa.Index("idx_ecs_svc_status", t_ecs_services.c.status)

sa.Index("idx_ecs_task_scan", t_ecs_task_definitions.c.scan_id)
sa.Index("idx_ecs_task_arn", t_ecs_task_definitions.c.task_definition_arn)
sa.Index("idx_ecs_task_family", t_ecs_task_definitions.c.family)
sa.Index("idx_ecs_task_region", t_ecs_task_definitions.c.region)
sa.Index("idx_ecs_task_status", t_ecs_task_definitions.c.status)

sa.Index("idx_eks_cluster_scan", t_eks_clusters.c.scan_id)
sa.Index("idx_eks_cluster_name", t_eks_clusters.c.cluster_name)
sa.Index("idx_eks_cluster_arn", t_eks_clusters.c.cluster_arn)
sa.Index("idx_eks_cluster_region", t_eks_clusters.c.region)
sa.Index("idx_eks_cluster_vpc", t_eks_clusters.c.vpc_id)
sa.Index("idx_eks_cluster_status", t_eks_clusters.c.status)

sa.Index("idx_eks_ng_scan", t_eks_node_groups.c.scan_id)
sa.Index("idx_eks_ng_cluster", t_eks_node_groups.c.cluster_name)
sa.Index("idx_eks_ng_name", t_eks_node_groups.c.nodegroup_name)
sa.Index("idx_eks_ng_arn", t_eks_node_groups.c.nodegroup_arn)
sa.Index("idx_eks_ng_region", t_eks_node_groups.c.region)
sa.Index("idx_eks_ng_status", t_eks_node_groups.c.status)

sa.Index("idx_eip_scan", t_elastic_ips.c.scan_id)
sa.Index("idx_eip_alloc", t_elastic_ips.c.allocation_id)
sa.Index("idx_eip_region", t_elastic_ips.c.region)
sa.Index("idx_eip_instance", t_elastic_ips.c.instance_id)
sa.Index("idx_eip_associated", t_elastic_ips.c.is_associated)

sa.Index("idx_ec_scan", t_elasticache_clusters.c.scan_id)
sa.Index("idx_ec_id", t_elasticache_clusters.c.cache_cluster_id)
sa.Index("idx_ec_arn", t_elasticache_clusters.c.cache_cluster_arn)
sa.Index("idx_ec_region", t_elasticache_clusters.c.region)
sa.Index("idx_ec_engine", t_elasticache_clusters.c.engine)
sa.Index("idx_ec_vpc", t_elasticache_clusters.c.vpc_id)
sa.Index("idx_ec_status", t_elasticache_clusters.c.cache_cluster_status)

sa.Index("idx_credreport_scan", t_iam_credential_report.c.scan_id)
sa.Index("idx_credreport_user", t_iam_credential_report.c.user_name)

sa.Index("idx_iam_policy_scan", t_iam_policies.c.scan_id)
sa.Index("idx_iam_policy_arn", t_iam_policies.c.policy_arn)
sa.Index("idx_iam_policy_name", t_iam_policies.c.policy_name)

sa.Index("idx_iam_role_scan", t_iam_roles.c.scan_id)

sa.Index("idx_iam_user_scan", t_iam_users.c.scan_id)

sa.Index("idx_igw_scan", t_internet_gateways.c.scan_id)
sa.Index("idx_igw_id", t_internet_gateways.c.internet_gateway_id)
sa.Index("idx_igw_region", t_internet_gateways.c.region)

sa.Index("idx_kms_scan", t_kms_keys.c.scan_id)
sa.Index("idx_kms_id", t_kms_keys.c.key_id)
sa.Index("idx_kms_arn", t_kms_keys.c.key_arn)
sa.Index("idx_kms_region", t_kms_keys.c.region)
sa.Index("idx_kms_state", t_kms_keys.c.key_state)
sa.Index("idx_kms_manager", t_kms_keys.c.key_manager)

sa.Index("idx_lambdaexp_scan", t_lambda_exposure.c.scan_id)
sa.Index("idx_lambdaexp_auth", t_lambda_exposure.c.url_auth_type)

sa.Index("idx_lambda_scan", t_lambda_functions.c.scan_id)
sa.Index("idx_lambda_name", t_lambda_functions.c.function_name)
sa.Index("idx_lambda_region", t_lambda_functions.c.region)
sa.Index("idx_lambda_runtime", t_lambda_functions.c.runtime)
sa.Index("idx_lb_scan", t_load_balancers.c.scan_id)
sa.Index("idx_lb_arn", t_load_balancers.c.load_balancer_arn)
sa.Index("idx_lb_region", t_load_balancers.c.region)
sa.Index("idx_lb_vpc", t_load_balancers.c.vpc_id)
sa.Index("idx_lb_type", t_load_balancers.c.load_balancer_type)

sa.Index("idx_msk_scan", t_msk_clusters.c.scan_id)
sa.Index("idx_msk_arn", t_msk_clusters.c.cluster_arn)
sa.Index("idx_msk_name", t_msk_clusters.c.cluster_name)
sa.Index("idx_msk_region", t_msk_clusters.c.region)
sa.Index("idx_msk_state", t_msk_clusters.c.state)

sa.Index("idx_nat_scan", t_nat_gateways.c.scan_id)
sa.Index("idx_nat_id", t_nat_gateways.c.nat_gateway_id)
sa.Index("idx_nat_region", t_nat_gateways.c.region)
sa.Index("idx_nat_vpc", t_nat_gateways.c.vpc_id)

sa.Index("idx_eni_scan", t_network_interfaces.c.scan_id)
sa.Index("idx_eni_id", t_network_interfaces.c.network_interface_id)
sa.Index("idx_eni_region", t_network_interfaces.c.region)
sa.Index("idx_eni_vpc", t_network_interfaces.c.vpc_id)
sa.Index("idx_eni_subnet", t_network_interfaces.c.subnet_id)

sa.Index("idx_os_scan", t_opensearch_domains.c.scan_id)
sa.Index("idx_os_id", t_opensearch_domains.c.domain_id)
sa.Index("idx_os_name", t_opensearch_domains.c.domain_name)
sa.Index("idx_os_arn", t_opensearch_domains.c.domain_arn)
sa.Index("idx_os_region", t_opensearch_domains.c.region)
sa.Index("idx_os_vpc", t_opensearch_domains.c.vpc_id)

sa.Index("idx_org_acct_scan", t_organization_accounts.c.scan_id)
sa.Index("idx_org_acct_id", t_organization_accounts.c.account_id)
sa.Index("idx_org_acct_status", t_organization_accounts.c.status)
sa.Index("idx_org_acct_parent", t_organization_accounts.c.parent_ou_id)

sa.Index("idx_ou_scan", t_organizational_units.c.scan_id)
sa.Index("idx_ou_id", t_organizational_units.c.ou_id)
sa.Index("idx_ou_parent", t_organizational_units.c.parent_id)

sa.Index("idx_org_scan", t_organizations.c.scan_id)
sa.Index("idx_org_id", t_organizations.c.organization_id)

sa.Index("idx_prowler_scan", t_prowler_findings.c.scan_id)
sa.Index("idx_prowler_severity", t_prowler_findings.c.severity)
sa.Index("idx_prowler_status", t_prowler_findings.c.status)
sa.Index("idx_prowler_service", t_prowler_findings.c.service_name)

sa.Index("idx_rds_scan", t_rds_instances.c.scan_id)
sa.Index("idx_rds_id", t_rds_instances.c.db_instance_identifier)
sa.Index("idx_rds_region", t_rds_instances.c.region)
sa.Index("idx_rds_engine", t_rds_instances.c.engine)
sa.Index("idx_rds_vpc", t_rds_instances.c.vpc_id)
sa.Index("idx_rds_public", t_rds_instances.c.publicly_accessible)
sa.Index("idx_rds_encrypted", t_rds_instances.c.encrypted)

sa.Index("idx_regionsec_scan", t_region_security_services.c.scan_id)
sa.Index("idx_regionsec_region", t_region_security_services.c.region)

sa.Index("idx_r53_zone_scan", t_route53_hosted_zones.c.scan_id)

sa.Index("idx_r53_record_scan", t_route53_record_sets.c.scan_id)
sa.Index("idx_r53_record_zone", t_route53_record_sets.c.hosted_zone_id)

sa.Index("idx_rt_scan", t_route_tables.c.scan_id)
sa.Index("idx_rt_id", t_route_tables.c.route_table_id)
sa.Index("idx_rt_region", t_route_tables.c.region)
sa.Index("idx_rt_vpc", t_route_tables.c.vpc_id)

sa.Index("idx_s3_scan", t_s3_buckets.c.scan_id)
sa.Index("idx_s3_name", t_s3_buckets.c.bucket_name)

sa.Index("idx_s3pab_scan", t_s3_public_access.c.scan_id)
sa.Index("idx_s3pab_bucket", t_s3_public_access.c.bucket_name)

sa.Index("idx_scan_account", t_scan_metadata.c.account_number)
sa.Index("idx_scan_timestamp", t_scan_metadata.c.scan_timestamp)

sa.Index("idx_sg_scan", t_security_groups.c.scan_id)
sa.Index("idx_sg_id", t_security_groups.c.group_id)
sa.Index("idx_sg_vpc", t_security_groups.c.vpc_id)

sa.Index("idx_sso_assign_scan", t_sso_assignments.c.scan_id)
sa.Index("idx_sso_assign_perm", t_sso_assignments.c.permission_set_arn)
sa.Index("idx_sso_assign_principal", t_sso_assignments.c.principal_id)
sa.Index("idx_sso_assign_target", t_sso_assignments.c.target_id)

sa.Index("idx_sso_perm_scan", t_sso_permission_sets.c.scan_id)
sa.Index("idx_sso_perm_arn", t_sso_permission_sets.c.permission_set_arn)
sa.Index("idx_sso_perm_name", t_sso_permission_sets.c.permission_set_name)
sa.Index("idx_sso_perm_instance", t_sso_permission_sets.c.instance_arn)

sa.Index("idx_subnet_scan", t_subnets.c.scan_id)
sa.Index("idx_subnet_vpc", t_subnets.c.vpc_id)
sa.Index("idx_subnet_region", t_subnets.c.region)

sa.Index("idx_tgw_scan", t_transit_gateways.c.scan_id)
sa.Index("idx_tgw_id", t_transit_gateways.c.transit_gateway_id)
sa.Index("idx_tgw_arn", t_transit_gateways.c.transit_gateway_arn)
sa.Index("idx_tgw_region", t_transit_gateways.c.region)
sa.Index("idx_tgw_state", t_transit_gateways.c.state)

sa.Index("idx_flowlog_scan", t_vpc_flow_logs.c.scan_id)
sa.Index("idx_flowlog_id", t_vpc_flow_logs.c.flow_log_id)
sa.Index("idx_flowlog_region", t_vpc_flow_logs.c.region)
sa.Index("idx_flowlog_resource", t_vpc_flow_logs.c.resource_id)
sa.Index("idx_flowlog_type", t_vpc_flow_logs.c.resource_type)

sa.Index("idx_vpc_scan", t_vpcs.c.scan_id)
sa.Index("idx_vpc_id", t_vpcs.c.vpc_id)
sa.Index("idx_vpc_region", t_vpcs.c.region)

sa.Index("idx_vpn_scan", t_vpn_connections.c.scan_id)
sa.Index("idx_vpn_id", t_vpn_connections.c.vpn_connection_id)
sa.Index("idx_vpn_region", t_vpn_connections.c.region)
sa.Index("idx_vpn_state", t_vpn_connections.c.state)

sa.Index("idx_ws_scan", t_workspaces.c.scan_id)
sa.Index("idx_ws_id", t_workspaces.c.workspace_id)
sa.Index("idx_ws_region", t_workspaces.c.region)
sa.Index("idx_ws_vpc", t_workspaces.c.vpc_id)
sa.Index("idx_ws_directory", t_workspaces.c.directory_id)
