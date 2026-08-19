"""
Query handlers for MCP server.

This module provides query handlers for different types of AWS data queries.
Uses Australian English in all documentation and comments.
"""

import json
import logging
from datetime import datetime, timedelta, UTC
from typing import Any, Dict
import ipaddress

import sqlalchemy as sa

from ..database.operations import DatabaseOperations
from ..database.tables import (
    t_auto_scaling_groups,
    t_bedrock_agents,
    t_bedrock_guardrails,
    t_bedrock_knowledge_bases,
    t_cloudwatch_log_groups,
    t_config_recorders,
    t_config_rules,
    t_cost_data,
    t_direct_connect_connections,
    t_directory_services,
    t_ebs_snapshots,
    t_ebs_volumes,
    t_ec2_instances,
    t_ecr_repositories,
    t_ecs_clusters,
    t_ecs_services,
    t_eks_clusters,
    t_elastic_ips,
    t_elasticache_clusters,
    t_iam_policies,
    t_iam_roles,
    t_iam_users,
    t_internet_gateways,
    t_lambda_functions,
    t_load_balancers,
    t_msk_clusters,
    t_nat_gateways,
    t_network_interfaces,
    t_opensearch_domains,
    t_organization_accounts,
    t_organizational_units,
    t_organizations,
    t_prowler_findings,
    t_rds_instances,
    t_route53_hosted_zones,
    t_route53_record_sets,
    t_route_tables,
    t_s3_buckets,
    t_scan_metadata,
    t_scan_tags,
    t_security_groups,
    t_sso_assignments,
    t_sso_permission_sets,
    t_subnets,
    t_transit_gateways,
    t_vpc_flow_logs,
    t_vpcs,
    t_vpn_connections,
    t_workspaces,
)
from ..assessment import get_catalogue, run_checks as run_assessment_checks
from ..assessment.exposure import run_exposure

logger = logging.getLogger(__name__)


class QueryHandler:
    """Handles MCP query requests and executes database queries."""

    def __init__(self, db_ops: DatabaseOperations):
        """
        Initialise query handler.

        Args:
            db_ops: Database operations instance
        """
        self.db_ops = db_ops
        # Default limits to prevent excessive data returns
        self.DEFAULT_LIMIT = 100
        self.MAX_LIMIT = 1000

    def _apply_pagination(self, parameters: Dict[str, Any]) -> tuple[int, int]:
        """
        Extract and validate pagination parameters.

        Args:
            parameters: Query parameters

        Returns:
            Tuple of (limit, offset)
        """
        limit = parameters.get("limit", self.DEFAULT_LIMIT)
        offset = parameters.get("offset", 0)

        # Validate and cap limit
        if limit:
            limit = min(int(limit), self.MAX_LIMIT)
        else:
            limit = self.DEFAULT_LIMIT

        offset = int(offset) if offset else 0

        return limit, offset

    def _build_limit_clause(
        self, stmt: sa.Select, limit: int, offset: int
    ) -> sa.Select:
        """Apply LIMIT/OFFSET to a Core select statement."""
        return stmt.limit(limit).offset(offset)

    def _add_pagination_info(
        self, results: Dict[str, Any], total_count: int, limit: int, offset: int
    ) -> None:
        """
        Add pagination metadata to results.

        Args:
            results: Results dictionary to modify
            total_count: Total number of records available
            limit: Number of records returned
            offset: Starting offset
        """
        results["pagination"] = {
            "total_count": total_count,
            "limit": limit,
            "offset": offset,
            "returned_count": (
                len(results.get("items", [])) if "items" in results else 0
            ),
            "has_more": (offset + limit) < total_count,
        }

        if results["pagination"]["has_more"]:
            results["pagination"]["next_offset"] = offset + limit

        # Add warning if result set is large
        if total_count > self.DEFAULT_LIMIT:
            if "warnings" not in results:
                results["warnings"] = []
            results["warnings"].append(
                f"Large dataset ({total_count} total records). "
                f"Showing {limit} records starting at offset {offset}. "
                f"Use 'limit' and 'offset' parameters to page through results."
            )

    def _is_summary_mode(self, parameters: Dict[str, Any]) -> bool:
        """Check if summary mode is requested."""
        return parameters.get("summary_mode", False) or parameters.get("summary", False)

    def handle_query(
        self, tool_name: str, parameters: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Route query to appropriate handler based on tool name.

        Args:
            tool_name: Name of the MCP tool being invoked
            parameters: Query parameters

        Returns:
            Query results
        """
        handlers = {
            "list_scans": self._list_scans,
            "get_scan_summary": self._get_scan_summary,
            "find_public_s3_buckets": self._find_public_s3_buckets,
            "find_public_ec2_instances": self._find_public_ec2_instances,
            "find_security_group_rules": self._find_security_group_rules,
            "search_by_ip": self._search_by_ip,
            "get_vpc_architecture": self._get_vpc_architecture,
            "get_iam_users": self._get_iam_users,
            "get_prowler_findings": self._get_prowler_findings,
            "compare_scans": self._compare_scans,
            "get_load_balancers": self._get_load_balancers,
            "get_nat_gateways": self._get_nat_gateways,
            "get_route_tables": self._get_route_tables,
            "get_internet_gateways": self._get_internet_gateways,
            "get_auto_scaling_groups": self._get_auto_scaling_groups,
            "get_network_interfaces_with_public_ips": self._get_network_interfaces_with_public_ips,
            "get_ec2_summary_by_account": self._get_ec2_summary_by_account,
            "get_ec2_changes": self._get_ec2_changes,
            "get_vpc_topology_detailed": self._get_vpc_topology_detailed,
            "get_workspaces_summary": self._get_workspaces_summary,
            "get_s3_lifecycle_policies": self._get_s3_lifecycle_policies,
            "get_lambda_summary": self._get_lambda_summary,
            "get_route53_zones": self._get_route53_zones,
            "get_route53_records": self._get_route53_records,
            "get_route53_changes": self._get_route53_changes,
            "get_vpc_flow_log_coverage": self._get_vpc_flow_log_coverage,
            "get_total_cost": self._get_total_cost,
            "get_cost_by_service": self._get_cost_by_service,
            "get_cost_trends": self._get_cost_trends,
            "get_cost_comparison": self._get_cost_comparison,
            "analyze_vpc_cidrs": self._analyze_vpc_cidrs,
            "find_unused_resources": self._find_unused_resources,
            "analyze_encryption_coverage": self._analyze_encryption_coverage,
            "find_publicly_accessible_databases": self._find_publicly_accessible_databases,
            "analyze_iam_permissions": self._analyze_iam_permissions,
            # Phase 2: Container & Application Services Query Tools
            "analyze_backup_coverage": self._analyze_backup_coverage,
            "find_security_group_violations": self._find_security_group_violations,
            "analyze_tag_compliance": self._analyze_tag_compliance,
            "analyze_container_vulnerabilities": self._analyze_container_vulnerabilities,
            "find_vpc_endpoint_opportunities": self._find_vpc_endpoint_opportunities,
            # Phase 3: Governance, Logging & Advanced Services Query Tools
            "get_organizations_structure": self._get_organizations_structure,
            "get_sso_permissions": self._get_sso_permissions,
            "analyze_cloudtrail_coverage": self._analyze_cloudtrail_coverage,
            "analyze_logging_coverage": self._analyze_logging_coverage,
            "get_bedrock_resources": self._get_bedrock_resources,
            "analyze_network_connectivity": self._analyze_network_connectivity,
            "get_directory_services": self._get_directory_services,
            "analyze_managed_services": self._analyze_managed_services,
            "get_organizations_cost_breakdown": self._get_organizations_cost_breakdown,
            # Security assessment tools
            "get_security_assessment_data": self._get_security_assessment_data,
            "analyze_service_exposure": self._analyze_service_exposure,
            "get_security_check_catalogue": self._get_security_check_catalogue,
            "search_scans_by_tag": self._search_scans_by_tag,
            "list_scan_tags": self._list_scan_tags,
        }

        handler = handlers.get(tool_name)
        if not handler:
            return {"error": f"Unknown tool: {tool_name}"}

        try:
            return handler(parameters)
        except Exception as e:
            logger.error(f"Query handler error for {tool_name}: {e}", exc_info=True)
            return {"error": str(e)}

    def _list_scans(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """List all scans or scans for a specific account."""
        account_number = params.get("account_number")

        stmt = sa.select(
            t_scan_metadata.c.scan_id,
            t_scan_metadata.c.account_name,
            t_scan_metadata.c.account_number,
            t_scan_metadata.c.scan_timestamp,
            t_scan_metadata.c.prowler_level,
            t_scan_metadata.c.scan_status,
            t_scan_metadata.c.scan_duration_seconds,
        ).order_by(t_scan_metadata.c.scan_timestamp.desc())
        if account_number:
            stmt = stmt.where(t_scan_metadata.c.account_number == account_number)
        with self.db_ops.engine.connect() as conn:
            scans = [dict(row._mapping) for row in conn.execute(stmt)]

            scan_ids = [scan["scan_id"] for scan in scans]
            tags_by_scan: Dict[str, list] = {scan_id: [] for scan_id in scan_ids}
            if scan_ids:
                tags_stmt = sa.select(t_scan_tags.c.scan_id, t_scan_tags.c.tag).where(
                    t_scan_tags.c.scan_id.in_(scan_ids)
                )
                for row in conn.execute(tags_stmt):
                    tags_by_scan[row.scan_id].append(row.tag)

        for scan in scans:
            scan["tags"] = sorted(tags_by_scan[scan["scan_id"]], key=str.lower)

        return {"scans": scans, "count": len(scans)}

    def _get_scan_summary(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Get summary of resources collected in a scan."""
        scan_id = params.get("scan_id")

        if not scan_id:
            return {"error": "scan_id parameter required"}

        # Count resources by type
        resource_tables = {
            "ec2_instances": t_ec2_instances,
            "vpcs": t_vpcs,
            "subnets": t_subnets,
            "security_groups": t_security_groups,
            "s3_buckets": t_s3_buckets,
            "iam_users": t_iam_users,
            "iam_roles": t_iam_roles,
            "route53_hosted_zones": t_route53_hosted_zones,
            "route53_record_sets": t_route53_record_sets,
            "prowler_findings": t_prowler_findings,
        }

        with self.db_ops.engine.connect() as conn:
            # Get scan metadata.
            scan_info = conn.execute(
                sa.select(t_scan_metadata).where(t_scan_metadata.c.scan_id == scan_id)
            ).fetchone()

            if not scan_info:
                return {"error": f"Scan not found: {scan_id}"}

            resource_counts = {}
            for table_name, table in resource_tables.items():
                count_stmt = (
                    sa.select(sa.func.count())
                    .select_from(table)
                    .where(table.c.scan_id == scan_id)
                )
                resource_counts[table_name] = conn.execute(count_stmt).scalar()

        scan_info_dict = dict(scan_info._mapping)
        scan_info_dict["tags"] = self.db_ops.get_tags_for_scan(scan_id)

        return {
            "scan_info": scan_info_dict,
            "resource_counts": resource_counts,
        }

    def _search_scans_by_tag(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Find scans matching a tag, case-insensitively, newest first."""
        tag = params.get("tag")

        if not tag:
            return {"error": "tag parameter required"}

        limit, _ = self._apply_pagination(params)
        scans = self.db_ops.find_scans_by_tag(tag)[:limit]

        return {"scans": scans, "count": len(scans)}

    def _list_scan_tags(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """List all distinct tags across all scans, with scan counts."""
        tags = self.db_ops.list_tags()
        return {"tags": tags, "count": len(tags)}

    def _find_public_s3_buckets(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Find S3 buckets that may be publicly accessible."""
        scan_id = params.get("scan_id")

        stmt = sa.select(
            t_s3_buckets.c.bucket_name,
            t_s3_buckets.c.region,
            t_s3_buckets.c.creation_date,
            t_s3_buckets.c.public_access_block,
            t_s3_buckets.c.scan_id,
            t_s3_buckets.c.tags,
        )

        if scan_id:
            stmt = stmt.where(t_s3_buckets.c.scan_id == scan_id)

        buckets = []
        with self.db_ops.engine.connect() as conn:
            for row in conn.execute(stmt):
                bucket = dict(row._mapping)

                # Parse public_access_block
                pab = json.loads(bucket.get("public_access_block") or "{}")

                # Check if potentially public
                is_potentially_public = not all(
                    [
                        pab.get("BlockPublicAcls", False),
                        pab.get("IgnorePublicAcls", False),
                        pab.get("BlockPublicPolicy", False),
                        pab.get("RestrictPublicBuckets", False),
                    ]
                )

                if is_potentially_public:
                    bucket["public_access_block"] = pab
                    bucket["tags"] = json.loads(bucket.get("tags") or "{}")
                    buckets.append(bucket)

        return {"buckets": buckets, "count": len(buckets)}

    def _find_public_ec2_instances(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Find EC2 instances filtered by IP address type (public, private, or all)."""
        scan_id = params.get("scan_id")
        region = params.get("region")
        ip_type = params.get(
            "ip_type", "public"
        )  # Default to 'public' for backwards compatibility

        # Get pagination parameters
        limit, offset = self._apply_pagination(params)
        summary_mode = self._is_summary_mode(params)

        conditions = []

        # Add IP type filter
        if ip_type == "public":
            conditions.append(t_ec2_instances.c.public_ip.isnot(None))
        elif ip_type == "private":
            conditions.append(
                sa.and_(
                    t_ec2_instances.c.public_ip.is_(None),
                    t_ec2_instances.c.private_ip.isnot(None),
                )
            )
        # 'all' means no IP filter

        if scan_id:
            conditions.append(t_ec2_instances.c.scan_id == scan_id)

        if region:
            conditions.append(t_ec2_instances.c.region == region)

        with self.db_ops.engine.connect() as conn:
            # Get total count first
            count_stmt = sa.select(sa.func.count()).select_from(t_ec2_instances)
            if conditions:
                count_stmt = count_stmt.where(*conditions)
            total_count = conn.execute(count_stmt).scalar()

            # In summary mode, return only counts and aggregates
            if summary_mode:
                summary_stmt = (
                    sa.select(t_ec2_instances.c.region, sa.func.count().label("count"))
                    .select_from(t_ec2_instances)
                    .group_by(t_ec2_instances.c.region)
                )
                if conditions:
                    summary_stmt = summary_stmt.where(*conditions)

                summary = {
                    "total_instances": total_count,
                    "by_region": {row[0]: row[1] for row in conn.execute(summary_stmt)},
                }
                return {"summary": summary, "mode": "summary"}

            # Full query with pagination
            stmt = sa.select(
                t_ec2_instances.c.instance_id,
                t_ec2_instances.c.public_ip,
                t_ec2_instances.c.private_ip,
                t_ec2_instances.c.instance_type,
                t_ec2_instances.c.state,
                t_ec2_instances.c.region,
                t_ec2_instances.c.vpc_id,
                t_ec2_instances.c.subnet_id,
                t_ec2_instances.c.security_groups,
                t_ec2_instances.c.tags,
                t_ec2_instances.c.scan_id,
            ).order_by(t_ec2_instances.c.instance_id)
            if conditions:
                stmt = stmt.where(*conditions)
            stmt = self._build_limit_clause(stmt, limit, offset)

            instances = []
            for row in conn.execute(stmt):
                instance = dict(row._mapping)
                instance["security_groups"] = json.loads(
                    instance.get("security_groups") or "[]"
                )
                instance["tags"] = json.loads(instance.get("tags") or "{}")
                instances.append(instance)

        results = {"instances": instances, "count": len(instances)}

        # Add pagination metadata
        self._add_pagination_info(results, total_count, limit, offset)

        return results

    def _find_security_group_rules(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Find security groups with specific rule characteristics."""
        scan_id = params.get("scan_id")
        allow_all_ingress = params.get("allow_all_ingress", False)

        stmt = sa.select(t_security_groups)

        if scan_id:
            stmt = stmt.where(t_security_groups.c.scan_id == scan_id)

        security_groups = []
        with self.db_ops.engine.connect() as conn:
            for row in conn.execute(stmt):
                sg = dict(row._mapping)
                sg["ingress_rules"] = json.loads(sg.get("ingress_rules") or "[]")
                sg["egress_rules"] = json.loads(sg.get("egress_rules") or "[]")
                sg["tags"] = json.loads(sg.get("tags") or "{}")

                # Check for overly permissive rules if requested
                if allow_all_ingress:
                    has_open_rule = any(
                        any(
                            ip_range.get("CidrIp") == "0.0.0.0/0"
                            for ip_range in rule.get("IpRanges", [])
                        )
                        for rule in sg["ingress_rules"]
                    )
                    if has_open_rule:
                        security_groups.append(sg)
                else:
                    security_groups.append(sg)

        return {"security_groups": security_groups, "count": len(security_groups)}

    def _search_by_ip(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Search for resources by IP address or CIDR range."""
        ip_address = params.get("ip_address")
        cidr_range = params.get("cidr_range")

        if not ip_address and not cidr_range:
            return {"error": "Either ip_address or cidr_range parameter required"}

        search_term = ip_address or cidr_range
        like_term = f"%{search_term}%"

        results = {"ec2_instances": [], "vpcs": [], "subnets": []}

        with self.db_ops.engine.connect() as conn:
            # Search EC2 instances
            ec2_stmt = sa.select(t_ec2_instances).where(
                sa.or_(
                    t_ec2_instances.c.public_ip.like(like_term),
                    t_ec2_instances.c.private_ip.like(like_term),
                )
            )
            results["ec2_instances"] = [
                dict(row._mapping) for row in conn.execute(ec2_stmt)
            ]

            # Search VPCs
            vpc_stmt = sa.select(t_vpcs).where(t_vpcs.c.cidr_block.like(like_term))
            results["vpcs"] = [dict(row._mapping) for row in conn.execute(vpc_stmt)]

            # Search Subnets
            subnet_stmt = sa.select(t_subnets).where(
                t_subnets.c.cidr_block.like(like_term)
            )
            results["subnets"] = [
                dict(row._mapping) for row in conn.execute(subnet_stmt)
            ]

        return results

    def _get_vpc_architecture(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Get VPC architecture details including subnets and routing."""
        vpc_id = params.get("vpc_id")
        scan_id = params.get("scan_id")

        if not vpc_id:
            return {"error": "vpc_id parameter required"}

        with self.db_ops.engine.connect() as conn:
            # Get VPC details
            vpc_stmt = sa.select(t_vpcs).where(t_vpcs.c.vpc_id == vpc_id)
            if scan_id:
                vpc_stmt = vpc_stmt.where(t_vpcs.c.scan_id == scan_id)

            vpc = conn.execute(vpc_stmt).fetchone()

            if not vpc:
                return {"error": f"VPC not found: {vpc_id}"}

            vpc_data = dict(vpc._mapping)
            vpc_data["tags"] = json.loads(vpc_data.get("tags") or "{}")

            # Get subnets
            subnets = []
            for row in conn.execute(
                sa.select(t_subnets).where(t_subnets.c.vpc_id == vpc_id)
            ):
                subnet = dict(row._mapping)
                subnet["tags"] = json.loads(subnet.get("tags") or "{}")
                subnets.append(subnet)

            # Get security groups
            security_groups = []
            for row in conn.execute(
                sa.select(t_security_groups).where(t_security_groups.c.vpc_id == vpc_id)
            ):
                sg = dict(row._mapping)
                sg["ingress_rules"] = json.loads(sg.get("ingress_rules") or "[]")
                sg["egress_rules"] = json.loads(sg.get("egress_rules") or "[]")
                sg["tags"] = json.loads(sg.get("tags") or "{}")
                security_groups.append(sg)

            # Get EC2 instances in VPC
            instances = []
            for row in conn.execute(
                sa.select(t_ec2_instances).where(t_ec2_instances.c.vpc_id == vpc_id)
            ):
                instance = dict(row._mapping)
                instance["security_groups"] = json.loads(
                    instance.get("security_groups") or "[]"
                )
                instance["tags"] = json.loads(instance.get("tags") or "{}")
                instances.append(instance)

        return {
            "vpc": vpc_data,
            "subnets": subnets,
            "security_groups": security_groups,
            "instances": instances,
        }

    def _get_iam_users(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Get IAM users, optionally filtering by MFA status."""
        scan_id = params.get("scan_id")
        no_mfa_only = params.get("no_mfa_only", False)

        stmt = sa.select(t_iam_users)
        conditions = []

        if scan_id:
            conditions.append(t_iam_users.c.scan_id == scan_id)

        if no_mfa_only:
            conditions.append(t_iam_users.c.mfa_enabled == 0)

        if conditions:
            stmt = stmt.where(*conditions)

        users = []
        with self.db_ops.engine.connect() as conn:
            for row in conn.execute(stmt):
                user = dict(row._mapping)
                user["access_keys"] = json.loads(user.get("access_keys") or "[]")
                user["attached_policies"] = json.loads(
                    user.get("attached_policies") or "[]"
                )
                user["groups"] = json.loads(user.get("groups") or "[]")
                user["tags"] = json.loads(user.get("tags") or "{}")
                users.append(user)

        return {"users": users, "count": len(users)}

    def _get_prowler_findings(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Get Prowler security findings with comprehensive summarisation.

        Always includes a summary with severity breakdown, top failing services,
        compliance coverage, and actionable insights. Use summary_mode=true to
        return only the summary without detailed findings.
        """
        scan_id = params.get("scan_id")
        severity = params.get("severity")
        status = params.get("status")

        # Get pagination parameters
        limit, offset = self._apply_pagination(params)
        summary_mode = self._is_summary_mode(params)

        conditions = []

        if scan_id:
            conditions.append(t_prowler_findings.c.scan_id == scan_id)

        if severity:
            conditions.append(t_prowler_findings.c.severity == severity.lower())

        if status:
            conditions.append(t_prowler_findings.c.status == status.upper())

        with self.db_ops.engine.connect() as conn:
            # Get total count
            count_stmt = sa.select(sa.func.count()).select_from(t_prowler_findings)
            if conditions:
                count_stmt = count_stmt.where(*conditions)
            total_count = conn.execute(count_stmt).scalar()

            # Build comprehensive summary
            summary = self._build_prowler_summary(conn, conditions, total_count)

            # If summary mode only, return summary
            if summary_mode:
                return {"summary": summary, "mode": "summary"}

            # Full query with pagination
            severity_order = sa.case(
                (t_prowler_findings.c.severity == "critical", 1),
                (t_prowler_findings.c.severity == "high", 2),
                (t_prowler_findings.c.severity == "medium", 3),
                (t_prowler_findings.c.severity == "low", 4),
                (t_prowler_findings.c.severity == "informational", 5),
                else_=6,
            )
            stmt = sa.select(t_prowler_findings).order_by(
                severity_order, t_prowler_findings.c.status
            )
            if conditions:
                stmt = stmt.where(*conditions)
            stmt = self._build_limit_clause(stmt, limit, offset)

            findings = []
            for row in conn.execute(stmt):
                finding = dict(row._mapping)
                finding["resource_tags"] = json.loads(
                    finding.get("resource_tags") or "{}"
                )
                finding["compliance_frameworks"] = json.loads(
                    finding.get("compliance_frameworks") or "[]"
                )
                findings.append(finding)

        results = {
            "summary": summary,  # Always include summary
            "findings": findings,
            "count": len(findings),
        }

        # Add pagination metadata
        self._add_pagination_info(results, total_count, limit, offset)

        return results

    def _build_prowler_summary(
        self, conn: sa.Connection, conditions: list, total_count: int
    ) -> Dict[str, Any]:
        """
        Build comprehensive Prowler findings summary.

        Args:
            conn: Database connection
            conditions: SQLAlchemy Core WHERE conditions
            total_count: Total findings count

        Returns:
            Dictionary with comprehensive summary including severity breakdown,
            top failing services, compliance coverage, and actionable insights
        """
        severity_order = sa.case(
            (t_prowler_findings.c.severity == "critical", 1),
            (t_prowler_findings.c.severity == "high", 2),
            (t_prowler_findings.c.severity == "medium", 3),
            (t_prowler_findings.c.severity == "low", 4),
            (t_prowler_findings.c.severity == "informational", 5),
            else_=6,
        )

        # Severity breakdown
        severity_stmt = (
            sa.select(t_prowler_findings.c.severity, sa.func.count().label("count"))
            .group_by(t_prowler_findings.c.severity)
            .order_by(severity_order)
        )
        if conditions:
            severity_stmt = severity_stmt.where(*conditions)

        severity_counts = {}
        for row in conn.execute(severity_stmt):
            severity_counts[row[0]] = row[1]

        # Status breakdown
        status_stmt = (
            sa.select(t_prowler_findings.c.status, sa.func.count().label("count"))
            .group_by(t_prowler_findings.c.status)
            .order_by(t_prowler_findings.c.status)
        )
        if conditions:
            status_stmt = status_stmt.where(*conditions)

        status_counts = {}
        for row in conn.execute(status_stmt):
            status_counts[row[0]] = row[1]

        # Top failing services (top 10)
        fail_count_col = sa.func.count().label("count")
        services_stmt = (
            sa.select(t_prowler_findings.c.service_name, fail_count_col)
            .where(t_prowler_findings.c.status == "FAIL")
            .group_by(t_prowler_findings.c.service_name)
            .order_by(fail_count_col.desc())
            .limit(10)
        )
        if conditions:
            services_stmt = services_stmt.where(*conditions)

        top_failing_services = [
            {"service": row[0], "fail_count": row[1]}
            for row in conn.execute(services_stmt)
        ]

        # Top failing check types (top 10)
        check_type_count_col = sa.func.count().label("count")
        check_types_stmt = (
            sa.select(t_prowler_findings.c.check_type, check_type_count_col)
            .where(t_prowler_findings.c.status == "FAIL")
            .group_by(t_prowler_findings.c.check_type)
            .order_by(check_type_count_col.desc())
            .limit(10)
        )
        if conditions:
            check_types_stmt = check_types_stmt.where(*conditions)

        top_failing_check_types = [
            {"check_type": row[0], "fail_count": row[1]}
            for row in conn.execute(check_types_stmt)
        ]

        # Compliance framework coverage
        frameworks_stmt = sa.select(t_prowler_findings.c.compliance_frameworks)
        if conditions:
            frameworks_stmt = frameworks_stmt.where(*conditions)

        all_frameworks = set()
        framework_fail_counts = {}

        for row in conn.execute(frameworks_stmt):
            if row[0]:
                frameworks = json.loads(row[0])
                for framework in frameworks:
                    all_frameworks.add(framework)

        # Count failures per framework
        if all_frameworks:
            fail_frameworks_stmt = sa.select(
                t_prowler_findings.c.compliance_frameworks,
                t_prowler_findings.c.status,
            )
            if conditions:
                fail_frameworks_stmt = fail_frameworks_stmt.where(*conditions)

            for row in conn.execute(fail_frameworks_stmt):
                if row[0] and row[1] == "FAIL":
                    frameworks = json.loads(row[0])
                    for framework in frameworks:
                        framework_fail_counts[framework] = (
                            framework_fail_counts.get(framework, 0) + 1
                        )

        compliance_summary = [
            {
                "framework": framework,
                "fail_count": framework_fail_counts.get(framework, 0),
            }
            for framework in sorted(all_frameworks)
        ]

        # Build actionable insights
        insights = []
        critical_count = severity_counts.get("critical", 0)
        high_count = severity_counts.get("high", 0)
        fail_count = status_counts.get("FAIL", 0)

        if critical_count > 0:
            insights.append(
                f"🚨 {critical_count} CRITICAL finding{'s' if critical_count != 1 else ''} require immediate attention"
            )

        if high_count > 0:
            insights.append(
                f"⚠️  {high_count} HIGH severity finding{'s' if high_count != 1 else ''} should be addressed soon"
            )

        if fail_count > 0:
            pass_count = status_counts.get("PASS", 0)
            total_checks = fail_count + pass_count
            if total_checks > 0:
                pass_rate = round((pass_count / total_checks) * 100, 1)
                insights.append(
                    f"✓ Security posture: {pass_rate}% of checks passing ({pass_count}/{total_checks})"
                )

        if top_failing_services:
            top_service = top_failing_services[0]
            insights.append(
                f"📊 Top concern: {top_service['service']} service has {top_service['fail_count']} failing check{'s' if top_service['fail_count'] != 1 else ''}"
            )

        # Build summary structure
        summary = {
            "total_findings": total_count,
            "severity_breakdown": {
                "critical": severity_counts.get("critical", 0),
                "high": severity_counts.get("high", 0),
                "medium": severity_counts.get("medium", 0),
                "low": severity_counts.get("low", 0),
                "informational": severity_counts.get("informational", 0),
            },
            "status_breakdown": status_counts,
            "top_failing_services": top_failing_services,
            "top_failing_check_types": top_failing_check_types,
            "compliance_frameworks": compliance_summary,
            "actionable_insights": insights,
        }

        return summary

    def _compare_scans(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Compare resource counts between two scans."""
        scan_id_1 = params.get("scan_id_1")
        scan_id_2 = params.get("scan_id_2")

        if not scan_id_1 or not scan_id_2:
            return {"error": "Both scan_id_1 and scan_id_2 parameters required"}

        tables = {
            "ec2_instances": t_ec2_instances,
            "vpcs": t_vpcs,
            "subnets": t_subnets,
            "security_groups": t_security_groups,
            "load_balancers": t_load_balancers,
            "nat_gateways": t_nat_gateways,
            "internet_gateways": t_internet_gateways,
            "route_tables": t_route_tables,
            "auto_scaling_groups": t_auto_scaling_groups,
            "network_interfaces": t_network_interfaces,
            "s3_buckets": t_s3_buckets,
            "iam_users": t_iam_users,
            "iam_roles": t_iam_roles,
        }

        comparison = {}

        with self.db_ops.engine.connect() as conn:
            for table_name, table in tables.items():
                count_1 = conn.execute(
                    sa.select(sa.func.count())
                    .select_from(table)
                    .where(table.c.scan_id == scan_id_1)
                ).scalar()

                count_2 = conn.execute(
                    sa.select(sa.func.count())
                    .select_from(table)
                    .where(table.c.scan_id == scan_id_2)
                ).scalar()

                comparison[table_name] = {
                    "scan_1_count": count_1,
                    "scan_2_count": count_2,
                    "difference": count_2 - count_1,
                }

        return {
            "scan_id_1": scan_id_1,
            "scan_id_2": scan_id_2,
            "comparison": comparison,
        }

    def _get_load_balancers(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Get load balancers for a scan, optionally filtered by VPC."""
        scan_id = params.get("scan_id")
        vpc_id = params.get("vpc_id")
        lb_type = params.get(
            "load_balancer_type"
        )  # filter by type: application, network, classic, gateway

        if not scan_id:
            return {"error": "scan_id parameter required"}

        stmt = sa.select(t_load_balancers).where(t_load_balancers.c.scan_id == scan_id)

        if vpc_id:
            stmt = stmt.where(t_load_balancers.c.vpc_id == vpc_id)

        if lb_type:
            stmt = stmt.where(t_load_balancers.c.load_balancer_type == lb_type)

        load_balancers = []
        with self.db_ops.engine.connect() as conn:
            for row in conn.execute(stmt):
                lb = dict(row._mapping)
                # Parse JSON fields
                for field in [
                    "availability_zones",
                    "security_groups",
                    "subnets",
                    "listeners",
                    "target_groups",
                    "tags",
                    "raw_data",
                ]:
                    if lb.get(field):
                        lb[field] = json.loads(lb[field])
                load_balancers.append(lb)

        return {"load_balancers": load_balancers, "count": len(load_balancers)}

    def _get_nat_gateways(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Get NAT gateways for a scan, optionally filtered by VPC."""
        scan_id = params.get("scan_id")
        vpc_id = params.get("vpc_id")

        if not scan_id:
            return {"error": "scan_id parameter required"}

        stmt = sa.select(t_nat_gateways).where(t_nat_gateways.c.scan_id == scan_id)

        if vpc_id:
            stmt = stmt.where(t_nat_gateways.c.vpc_id == vpc_id)

        nat_gateways = []
        with self.db_ops.engine.connect() as conn:
            for row in conn.execute(stmt):
                nat = dict(row._mapping)
                # Parse JSON fields
                for field in ["nat_gateway_addresses", "tags", "raw_data"]:
                    if nat.get(field):
                        nat[field] = json.loads(nat[field])
                nat_gateways.append(nat)

        return {"nat_gateways": nat_gateways, "count": len(nat_gateways)}

    def _get_route_tables(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Get route tables for a scan, optionally filtered by VPC."""
        scan_id = params.get("scan_id")
        vpc_id = params.get("vpc_id")

        if not scan_id:
            return {"error": "scan_id parameter required"}

        stmt = sa.select(t_route_tables).where(t_route_tables.c.scan_id == scan_id)

        if vpc_id:
            stmt = stmt.where(t_route_tables.c.vpc_id == vpc_id)

        route_tables = []
        with self.db_ops.engine.connect() as conn:
            for row in conn.execute(stmt):
                rt = dict(row._mapping)
                # Parse JSON fields
                for field in [
                    "routes",
                    "subnet_associations",
                    "gateway_associations",
                    "tags",
                    "raw_data",
                ]:
                    if rt.get(field):
                        rt[field] = json.loads(rt[field])
                route_tables.append(rt)

        return {"route_tables": route_tables, "count": len(route_tables)}

    def _get_internet_gateways(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Get internet gateways for a scan."""
        scan_id = params.get("scan_id")

        if not scan_id:
            return {"error": "scan_id parameter required"}

        stmt = sa.select(t_internet_gateways).where(
            t_internet_gateways.c.scan_id == scan_id
        )

        internet_gateways = []
        with self.db_ops.engine.connect() as conn:
            for row in conn.execute(stmt):
                igw = dict(row._mapping)
                # Parse JSON fields
                for field in ["vpc_attachments", "tags", "raw_data"]:
                    if igw.get(field):
                        igw[field] = json.loads(igw[field])
                internet_gateways.append(igw)

        return {"internet_gateways": internet_gateways, "count": len(internet_gateways)}

    def _get_auto_scaling_groups(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Get Auto Scaling groups for a scan."""
        scan_id = params.get("scan_id")
        region = params.get("region")

        if not scan_id:
            return {"error": "scan_id parameter required"}

        stmt = sa.select(t_auto_scaling_groups).where(
            t_auto_scaling_groups.c.scan_id == scan_id
        )

        if region:
            stmt = stmt.where(t_auto_scaling_groups.c.region == region)

        asgs = []
        with self.db_ops.engine.connect() as conn:
            for row in conn.execute(stmt):
                asg = dict(row._mapping)
                # Parse JSON fields
                for field in [
                    "launch_template",
                    "availability_zones",
                    "load_balancer_names",
                    "target_group_arns",
                    "instances",
                    "tags",
                    "raw_data",
                ]:
                    if asg.get(field):
                        asg[field] = json.loads(asg[field])
                asgs.append(asg)

        return {"auto_scaling_groups": asgs, "count": len(asgs)}

    def _get_network_interfaces_with_public_ips(
        self, params: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Get network interfaces that have public IP addresses."""
        scan_id = params.get("scan_id")
        vpc_id = params.get("vpc_id")

        if not scan_id:
            return {"error": "scan_id parameter required"}

        stmt = sa.select(t_network_interfaces).where(
            sa.and_(
                t_network_interfaces.c.scan_id == scan_id,
                t_network_interfaces.c.public_ip.isnot(None),
            )
        )

        if vpc_id:
            stmt = stmt.where(t_network_interfaces.c.vpc_id == vpc_id)

        interfaces = []
        with self.db_ops.engine.connect() as conn:
            for row in conn.execute(stmt):
                eni = dict(row._mapping)
                # Parse JSON fields
                for field in [
                    "private_ip_addresses",
                    "security_groups",
                    "attachment",
                    "tags",
                    "raw_data",
                ]:
                    if eni.get(field):
                        eni[field] = json.loads(eni[field])
                interfaces.append(eni)

        return {"network_interfaces": interfaces, "count": len(interfaces)}

    def _get_ec2_summary_by_account(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Get EC2 instance types breakdown by account for most recent scans."""
        sm2 = t_scan_metadata.alias("sm2")

        # Get latest scan for each account
        latest_scan_id = (
            sa.select(sm2.c.scan_id)
            .where(sm2.c.account_number == t_scan_metadata.c.account_number)
            .order_by(sm2.c.scan_timestamp.desc())
            .limit(1)
            .correlate(t_scan_metadata)
        )

        stmt = (
            sa.select(
                t_scan_metadata.c.account_name,
                t_scan_metadata.c.account_number,
                t_scan_metadata.c.scan_id,
                t_scan_metadata.c.scan_timestamp,
                t_ec2_instances.c.instance_type,
                t_ec2_instances.c.state,
                sa.func.count().label("count"),
            )
            .select_from(
                t_scan_metadata.join(
                    t_ec2_instances,
                    t_scan_metadata.c.scan_id == t_ec2_instances.c.scan_id,
                )
            )
            .where(t_scan_metadata.c.scan_id.in_(latest_scan_id))
            .group_by(
                t_scan_metadata.c.account_name,
                t_scan_metadata.c.account_number,
                t_scan_metadata.c.scan_id,
                t_ec2_instances.c.instance_type,
                t_ec2_instances.c.state,
            )
            .order_by(t_scan_metadata.c.account_name, t_ec2_instances.c.instance_type)
        )

        accounts = {}
        with self.db_ops.engine.connect() as conn:
            for row in conn.execute(stmt):
                mapping = row._mapping
                account_name = mapping["account_name"]
                if account_name not in accounts:
                    accounts[account_name] = {
                        "account_number": mapping["account_number"],
                        "scan_id": mapping["scan_id"],
                        "scan_timestamp": mapping["scan_timestamp"],
                        "instance_types": {},
                    }

                instance_type = mapping["instance_type"]
                state = mapping["state"]
                count = mapping["count"]

                if instance_type not in accounts[account_name]["instance_types"]:
                    accounts[account_name]["instance_types"][instance_type] = {}

                accounts[account_name]["instance_types"][instance_type][state] = count

        return {"accounts": accounts}

    def _get_ec2_changes(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Get EC2 instance changes across all scans for all accounts."""
        account_number = params.get("account_number")

        # Build query to track instance changes
        stmt = (
            sa.select(
                t_scan_metadata.c.account_name,
                t_scan_metadata.c.account_number,
                t_scan_metadata.c.scan_id,
                t_scan_metadata.c.scan_timestamp,
                t_ec2_instances.c.instance_id,
                t_ec2_instances.c.instance_type,
                t_ec2_instances.c.state,
                t_ec2_instances.c.region,
                t_ec2_instances.c.public_ip,
                t_ec2_instances.c.private_ip,
                t_ec2_instances.c.vpc_id,
                t_ec2_instances.c.subnet_id,
            )
            .select_from(
                t_scan_metadata.join(
                    t_ec2_instances,
                    t_scan_metadata.c.scan_id == t_ec2_instances.c.scan_id,
                )
            )
            .order_by(t_ec2_instances.c.instance_id, t_scan_metadata.c.scan_timestamp)
        )

        if account_number:
            stmt = stmt.where(t_scan_metadata.c.account_number == account_number)

        # Track instance history
        instance_history = {}
        with self.db_ops.engine.connect() as conn:
            for row in conn.execute(stmt):
                mapping = row._mapping
                instance_id = mapping["instance_id"]
                if instance_id not in instance_history:
                    instance_history[instance_id] = {
                        "instance_id": instance_id,
                        "instance_type": mapping["instance_type"],
                        "region": mapping["region"],
                        "scans": [],
                    }

                instance_history[instance_id]["scans"].append(
                    {
                        "scan_id": mapping["scan_id"],
                        "scan_timestamp": mapping["scan_timestamp"],
                        "account_name": mapping["account_name"],
                        "state": mapping["state"],
                        "public_ip": mapping["public_ip"],
                        "private_ip": mapping["private_ip"],
                        "vpc_id": mapping["vpc_id"],
                        "subnet_id": mapping["subnet_id"],
                    }
                )

        # Identify changes
        changes = []
        for instance_id, history in instance_history.items():
            if len(history["scans"]) > 1:
                # Check for state changes
                for i in range(1, len(history["scans"])):
                    prev_scan = history["scans"][i - 1]
                    curr_scan = history["scans"][i]

                    if prev_scan["state"] != curr_scan["state"]:
                        changes.append(
                            {
                                "instance_id": instance_id,
                                "change_type": "state_change",
                                "from_state": prev_scan["state"],
                                "to_state": curr_scan["state"],
                                "from_scan": prev_scan["scan_id"],
                                "to_scan": curr_scan["scan_id"],
                                "timestamp": curr_scan["scan_timestamp"],
                            }
                        )

                    if prev_scan.get("vpc_id") != curr_scan.get("vpc_id"):
                        changes.append(
                            {
                                "instance_id": instance_id,
                                "change_type": "vpc_change",
                                "from_vpc": prev_scan.get("vpc_id"),
                                "to_vpc": curr_scan.get("vpc_id"),
                                "from_scan": prev_scan["scan_id"],
                                "to_scan": curr_scan["scan_id"],
                                "timestamp": curr_scan["scan_timestamp"],
                            }
                        )

        return {
            "instance_history": instance_history,
            "changes": changes,
            "change_count": len(changes),
        }

    def _get_vpc_topology_detailed(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Get detailed VPC topology including EC2, Load Balancers, NAT Gateways, etc."""
        vpc_id = params.get("vpc_id")
        scan_id = params.get("scan_id")

        if not vpc_id:
            return {"error": "vpc_id parameter required"}

        with self.db_ops.engine.connect() as conn:
            # Get VPC details
            vpc_stmt = sa.select(t_vpcs).where(t_vpcs.c.vpc_id == vpc_id)
            if scan_id:
                vpc_stmt = vpc_stmt.where(t_vpcs.c.scan_id == scan_id)

            vpc = conn.execute(vpc_stmt).fetchone()

            if not vpc:
                return {"error": f"VPC not found: {vpc_id}"}

            vpc_data = dict(vpc._mapping)
            vpc_data["tags"] = json.loads(vpc_data.get("tags") or "{}")

            # Get subnets
            subnets = [
                dict(row._mapping)
                for row in conn.execute(
                    sa.select(t_subnets).where(t_subnets.c.vpc_id == vpc_id)
                )
            ]
            for subnet in subnets:
                subnet["tags"] = json.loads(subnet.get("tags") or "{}")

            # Get EC2 instances
            instances = [
                dict(row._mapping)
                for row in conn.execute(
                    sa.select(t_ec2_instances).where(t_ec2_instances.c.vpc_id == vpc_id)
                )
            ]
            for instance in instances:
                instance["security_groups"] = json.loads(
                    instance.get("security_groups") or "[]"
                )
                instance["tags"] = json.loads(instance.get("tags") or "{}")

            # Get Load Balancers
            load_balancers = [
                dict(row._mapping)
                for row in conn.execute(
                    sa.select(t_load_balancers).where(
                        t_load_balancers.c.vpc_id == vpc_id
                    )
                )
            ]
            for lb in load_balancers:
                for field in [
                    "availability_zones",
                    "security_groups",
                    "subnets",
                    "listeners",
                    "target_groups",
                    "tags",
                ]:
                    if lb.get(field):
                        lb[field] = json.loads(lb[field])

            # Get NAT Gateways
            nat_gateways = [
                dict(row._mapping)
                for row in conn.execute(
                    sa.select(t_nat_gateways).where(t_nat_gateways.c.vpc_id == vpc_id)
                )
            ]
            for nat in nat_gateways:
                for field in ["nat_gateway_addresses", "tags"]:
                    if nat.get(field):
                        nat[field] = json.loads(nat[field])

            # Get Internet Gateways
            # The legacy SQL matched on
            # json_extract(igw.vpc_attachments, '$[0].VpcId') = ?, which cannot be
            # bound portably through Core. Fetch all candidates and reproduce the
            # same predicate (first attachment's VpcId) in Python instead.
            igw_candidates = [
                dict(row._mapping)
                for row in conn.execute(sa.select(t_internet_gateways))
            ]
            internet_gateways = []
            for igw in igw_candidates:
                attachments = json.loads(igw.get("vpc_attachments") or "[]")
                if attachments and attachments[0].get("VpcId") == vpc_id:
                    internet_gateways.append(igw)
            for igw in internet_gateways:
                for field in ["vpc_attachments", "tags"]:
                    if igw.get(field):
                        igw[field] = json.loads(igw[field])

            # Get Route Tables
            route_tables = [
                dict(row._mapping)
                for row in conn.execute(
                    sa.select(t_route_tables).where(t_route_tables.c.vpc_id == vpc_id)
                )
            ]
            for rt in route_tables:
                for field in [
                    "routes",
                    "subnet_associations",
                    "gateway_associations",
                    "tags",
                ]:
                    if rt.get(field):
                        rt[field] = json.loads(rt[field])

            # Get Security Groups
            security_groups = [
                dict(row._mapping)
                for row in conn.execute(
                    sa.select(t_security_groups).where(
                        t_security_groups.c.vpc_id == vpc_id
                    )
                )
            ]
            for sg in security_groups:
                for field in ["ingress_rules", "egress_rules", "tags"]:
                    if sg.get(field):
                        sg[field] = json.loads(sg[field])

            # Get Network Interfaces
            network_interfaces = [
                dict(row._mapping)
                for row in conn.execute(
                    sa.select(t_network_interfaces).where(
                        t_network_interfaces.c.vpc_id == vpc_id
                    )
                )
            ]
            for eni in network_interfaces:
                for field in [
                    "private_ip_addresses",
                    "security_groups",
                    "attachment",
                    "tags",
                ]:
                    if eni.get(field):
                        eni[field] = json.loads(eni[field])

            # Get VPC Flow Logs
            flow_logs = [
                dict(row._mapping)
                for row in conn.execute(
                    sa.select(t_vpc_flow_logs).where(
                        t_vpc_flow_logs.c.resource_id == vpc_id
                    )
                )
            ]
            for log in flow_logs:
                if log.get("tags"):
                    log["tags"] = json.loads(log["tags"])

        return {
            "vpc": vpc_data,
            "subnets": subnets,
            "instances": instances,
            "load_balancers": load_balancers,
            "nat_gateways": nat_gateways,
            "internet_gateways": internet_gateways,
            "route_tables": route_tables,
            "security_groups": security_groups,
            "network_interfaces": network_interfaces,
            "flow_logs": flow_logs,
        }

    def _get_workspaces_summary(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Get WorkSpaces summary by account and VPC."""
        scan_id = params.get("scan_id")
        account_number = params.get("account_number")

        stmt = (
            sa.select(
                t_scan_metadata.c.account_name,
                t_scan_metadata.c.account_number,
                t_scan_metadata.c.scan_id,
                t_workspaces.c.workspace_id,
                t_workspaces.c.user_name,
                t_workspaces.c.state,
                t_workspaces.c.vpc_id,
                t_workspaces.c.region,
                t_workspaces.c.compute_type,
                t_workspaces.c.running_mode,
                t_workspaces.c.volume_encryption_enabled,
                t_workspaces.c.tags,
            )
            .select_from(
                t_workspaces.join(
                    t_scan_metadata,
                    t_workspaces.c.scan_id == t_scan_metadata.c.scan_id,
                )
            )
            .order_by(
                t_scan_metadata.c.account_name,
                t_workspaces.c.vpc_id,
                t_workspaces.c.workspace_id,
            )
        )

        conditions = []
        if scan_id:
            conditions.append(t_workspaces.c.scan_id == scan_id)
        if account_number:
            conditions.append(t_scan_metadata.c.account_number == account_number)
        if conditions:
            stmt = stmt.where(*conditions)

        # Group by account and VPC
        summary = {}
        with self.db_ops.engine.connect() as conn:
            for row in conn.execute(stmt):
                mapping = row._mapping
                account = mapping["account_name"]
                vpc_id = mapping["vpc_id"] or "no-vpc"

                if account not in summary:
                    summary[account] = {
                        "account_number": mapping["account_number"],
                        "vpcs": {},
                    }

                if vpc_id not in summary[account]["vpcs"]:
                    summary[account]["vpcs"][vpc_id] = {
                        "workspaces": [],
                        "count": 0,
                        "states": {},
                    }

                workspace = {
                    "workspace_id": mapping["workspace_id"],
                    "user_name": mapping["user_name"],
                    "state": mapping["state"],
                    "region": mapping["region"],
                    "compute_type": mapping["compute_type"],
                    "running_mode": mapping["running_mode"],
                    "volume_encryption_enabled": bool(
                        mapping["volume_encryption_enabled"]
                    ),
                    "tags": json.loads(mapping["tags"] or "{}"),
                }

                summary[account]["vpcs"][vpc_id]["workspaces"].append(workspace)
                summary[account]["vpcs"][vpc_id]["count"] += 1

                # Count states
                state = mapping["state"]
                if state not in summary[account]["vpcs"][vpc_id]["states"]:
                    summary[account]["vpcs"][vpc_id]["states"][state] = 0
                summary[account]["vpcs"][vpc_id]["states"][state] += 1

        return {"summary": summary}

    def _get_s3_lifecycle_policies(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Get S3 buckets with lifecycle policy details."""
        scan_id = params.get("scan_id")

        stmt = sa.select(t_s3_buckets).where(
            sa.and_(
                t_s3_buckets.c.lifecycle_rules.isnot(None),
                t_s3_buckets.c.lifecycle_rules != "[]",
            )
        )

        if scan_id:
            stmt = stmt.where(t_s3_buckets.c.scan_id == scan_id)

        buckets = []
        with self.db_ops.engine.connect() as conn:
            for row in conn.execute(stmt):
                bucket = dict(row._mapping)
                bucket["lifecycle_rules"] = json.loads(
                    bucket.get("lifecycle_rules") or "[]"
                )
                bucket["tags"] = json.loads(bucket.get("tags") or "{}")

                # Parse lifecycle rules for summary
                rules_summary = []
                for rule in bucket["lifecycle_rules"]:
                    rules_summary.append(
                        {
                            "id": rule.get("ID"),
                            "status": rule.get("Status"),
                            "transitions": rule.get("Transitions", []),
                            "expiration": rule.get("Expiration", {}),
                        }
                    )

                bucket["lifecycle_summary"] = rules_summary
                buckets.append(bucket)

        return {"buckets": buckets, "count": len(buckets)}

    def _get_lambda_summary(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Get Lambda functions with VPC integration details."""
        scan_id = params.get("scan_id")
        vpc_integrated_only = params.get("vpc_integrated_only", False)

        stmt = sa.select(t_lambda_functions)

        conditions = []
        if scan_id:
            conditions.append(t_lambda_functions.c.scan_id == scan_id)
        if vpc_integrated_only:
            conditions.append(
                sa.and_(
                    t_lambda_functions.c.vpc_config.isnot(None),
                    t_lambda_functions.c.vpc_config != "null",
                )
            )
        if conditions:
            stmt = stmt.where(*conditions)

        stmt = stmt.order_by(
            t_lambda_functions.c.region, t_lambda_functions.c.function_name
        )

        functions = []
        vpc_count = 0
        non_vpc_count = 0

        with self.db_ops.engine.connect() as conn:
            for row in conn.execute(stmt):
                func = dict(row._mapping)

                # Parse JSON fields
                func["vpc_config"] = json.loads(func.get("vpc_config") or "null")
                func["environment_variables"] = json.loads(
                    func.get("environment_variables") or "{}"
                )
                func["layers"] = json.loads(func.get("layers") or "[]")
                func["architectures"] = json.loads(func.get("architectures") or "[]")
                func["triggers"] = json.loads(func.get("triggers") or "[]")
                func["tags"] = json.loads(func.get("tags") or "{}")

                if func["vpc_config"]:
                    vpc_count += 1
                else:
                    non_vpc_count += 1

                functions.append(func)

        return {
            "functions": functions,
            "count": len(functions),
            "vpc_integrated_count": vpc_count,
            "non_vpc_count": non_vpc_count,
        }

    def _get_route53_zones(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Get Route53 hosted zones by account."""
        scan_id = params.get("scan_id")

        stmt = sa.select(
            t_scan_metadata.c.account_name,
            t_scan_metadata.c.account_number,
            t_scan_metadata.c.scan_id,
            t_route53_hosted_zones.c.hosted_zone_id,
            t_route53_hosted_zones.c.name,
            t_route53_hosted_zones.c.is_private,
            t_route53_hosted_zones.c.resource_record_set_count,
            t_route53_hosted_zones.c.tags,
        ).select_from(
            t_route53_hosted_zones.join(
                t_scan_metadata,
                t_route53_hosted_zones.c.scan_id == t_scan_metadata.c.scan_id,
            )
        )

        if scan_id:
            stmt = stmt.where(t_route53_hosted_zones.c.scan_id == scan_id)

        # Group by account
        accounts = {}
        with self.db_ops.engine.connect() as conn:
            for row in conn.execute(stmt):
                mapping = row._mapping
                account = mapping["account_name"]
                if account not in accounts:
                    accounts[account] = {
                        "account_number": mapping["account_number"],
                        "hosted_zones": [],
                        "zone_count": 0,
                        "private_zones": 0,
                        "public_zones": 0,
                    }

                zone = {
                    "hosted_zone_id": mapping["hosted_zone_id"],
                    "name": mapping["name"],
                    "is_private": bool(mapping["is_private"]),
                    "resource_record_set_count": mapping["resource_record_set_count"],
                    "tags": json.loads(mapping["tags"] or "{}"),
                }

                accounts[account]["hosted_zones"].append(zone)
                accounts[account]["zone_count"] += 1

                if zone["is_private"]:
                    accounts[account]["private_zones"] += 1
                else:
                    accounts[account]["public_zones"] += 1

        return {"accounts": accounts}

    def _get_route53_records(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Get DNS records for Route53 hosted zones."""
        hosted_zone_id = params.get("hosted_zone_id")
        record_type = params.get("record_type")

        if not hosted_zone_id:
            return {"error": "hosted_zone_id parameter required"}

        stmt = sa.select(t_route53_record_sets).where(
            t_route53_record_sets.c.hosted_zone_id == hosted_zone_id
        )

        if record_type:
            stmt = stmt.where(
                t_route53_record_sets.c.record_type == record_type.upper()
            )

        stmt = stmt.order_by(
            t_route53_record_sets.c.record_type, t_route53_record_sets.c.name
        )

        records = []
        with self.db_ops.engine.connect() as conn:
            for row in conn.execute(stmt):
                record = dict(row._mapping)
                record["resource_records"] = json.loads(
                    record.get("resource_records") or "[]"
                )
                record["alias_target"] = json.loads(
                    record.get("alias_target") or "null"
                )
                records.append(record)

        return {
            "hosted_zone_id": hosted_zone_id,
            "records": records,
            "count": len(records),
        }

    def _get_route53_changes(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Get Route53 zone and DNS configuration changes across scans."""
        account_number = params.get("account_number")

        # Get zone changes
        zone_stmt = sa.select(
            t_scan_metadata.c.account_name,
            t_scan_metadata.c.account_number,
            t_scan_metadata.c.scan_id,
            t_scan_metadata.c.scan_timestamp,
            t_route53_hosted_zones.c.hosted_zone_id,
            t_route53_hosted_zones.c.name,
            t_route53_hosted_zones.c.is_private,
            t_route53_hosted_zones.c.resource_record_set_count,
        ).select_from(
            t_route53_hosted_zones.join(
                t_scan_metadata,
                t_route53_hosted_zones.c.scan_id == t_scan_metadata.c.scan_id,
            )
        )

        if account_number:
            zone_stmt = zone_stmt.where(
                t_scan_metadata.c.account_number == account_number
            )

        # Track zone history
        zone_history = {}
        with self.db_ops.engine.connect() as conn:
            for row in conn.execute(zone_stmt):
                mapping = row._mapping
                zone_id = mapping["hosted_zone_id"]
                if zone_id not in zone_history:
                    zone_history[zone_id] = {
                        "hosted_zone_id": zone_id,
                        "name": mapping["name"],
                        "scans": [],
                    }

                zone_history[zone_id]["scans"].append(
                    {
                        "scan_id": mapping["scan_id"],
                        "scan_timestamp": mapping["scan_timestamp"],
                        "account_name": mapping["account_name"],
                        "is_private": bool(mapping["is_private"]),
                        "record_count": mapping["resource_record_set_count"],
                    }
                )

        # Identify changes
        changes = []
        for zone_id, history in zone_history.items():
            if len(history["scans"]) > 1:
                for i in range(1, len(history["scans"])):
                    prev_scan = history["scans"][i - 1]
                    curr_scan = history["scans"][i]

                    if prev_scan["record_count"] != curr_scan["record_count"]:
                        changes.append(
                            {
                                "zone_id": zone_id,
                                "zone_name": history["name"],
                                "change_type": "record_count_change",
                                "from_count": prev_scan["record_count"],
                                "to_count": curr_scan["record_count"],
                                "from_scan": prev_scan["scan_id"],
                                "to_scan": curr_scan["scan_id"],
                                "timestamp": curr_scan["scan_timestamp"],
                            }
                        )

        return {
            "zone_history": zone_history,
            "changes": changes,
            "change_count": len(changes),
        }

    def _get_vpc_flow_log_coverage(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Get VPC Flow Log coverage analysis - which VPCs have flow logs enabled."""
        scan_id = params.get("scan_id")

        if not scan_id:
            return {"error": "scan_id parameter required"}

        vpcs = {}
        with self.db_ops.engine.connect() as conn:
            # Get all VPCs
            vpc_stmt = sa.select(
                t_vpcs.c.vpc_id,
                t_vpcs.c.region,
                t_vpcs.c.cidr_block,
                t_vpcs.c.tags,
            ).where(t_vpcs.c.scan_id == scan_id)
            for row in conn.execute(vpc_stmt):
                mapping = row._mapping
                vpcs[mapping["vpc_id"]] = {
                    "vpc_id": mapping["vpc_id"],
                    "region": mapping["region"],
                    "cidr_block": mapping["cidr_block"],
                    "tags": json.loads(mapping["tags"] or "{}"),
                    "has_flow_logs": False,
                    "flow_logs": [],
                }

            # Get VPC flow logs
            flow_log_stmt = sa.select(
                t_vpc_flow_logs.c.flow_log_id,
                t_vpc_flow_logs.c.resource_id,
                t_vpc_flow_logs.c.resource_type,
                t_vpc_flow_logs.c.traffic_type,
                t_vpc_flow_logs.c.log_destination_type,
                t_vpc_flow_logs.c.flow_log_status,
                t_vpc_flow_logs.c.region,
            ).where(
                t_vpc_flow_logs.c.scan_id == scan_id,
                t_vpc_flow_logs.c.resource_type == "VPC",
            )

            for row in conn.execute(flow_log_stmt):
                mapping = row._mapping
                resource_id = mapping["resource_id"]
                if resource_id in vpcs:
                    vpcs[resource_id]["has_flow_logs"] = True
                    vpcs[resource_id]["flow_logs"].append(
                        {
                            "flow_log_id": mapping["flow_log_id"],
                            "traffic_type": mapping["traffic_type"],
                            "log_destination_type": mapping["log_destination_type"],
                            "status": mapping["flow_log_status"],
                        }
                    )

        # Categorise VPCs
        vpcs_with_logs = [vpc for vpc in vpcs.values() if vpc["has_flow_logs"]]
        vpcs_without_logs = [vpc for vpc in vpcs.values() if not vpc["has_flow_logs"]]

        return {
            "total_vpcs": len(vpcs),
            "vpcs_with_flow_logs": len(vpcs_with_logs),
            "vpcs_without_flow_logs": len(vpcs_without_logs),
            "coverage_percentage": (
                (len(vpcs_with_logs) / len(vpcs) * 100) if vpcs else 0
            ),
            "vpcs_with_logs": vpcs_with_logs,
            "vpcs_without_logs": vpcs_without_logs,
        }

    def _get_total_cost(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Get total cost across all or specific accounts for the past 12 months."""
        account_number = params.get("account_number")
        months = params.get("months", 12)  # Default to 12 months

        with self.db_ops.engine.connect() as conn:
            # First, identify master/payer accounts (those with AWS Organizations)
            master_accounts_stmt = (
                sa.select(
                    t_scan_metadata.c.account_number,
                    t_scan_metadata.c.account_name,
                    t_organizations.c.master_account_id,
                )
                .select_from(
                    t_scan_metadata.outerjoin(
                        t_organizations,
                        t_scan_metadata.c.scan_id == t_organizations.c.scan_id,
                    )
                )
                .where(t_organizations.c.organization_id.isnot(None))
                .distinct()
            )

            master_accounts = {}
            for row in conn.execute(master_accounts_stmt):
                mapping = row._mapping
                master_accounts[mapping["account_number"]] = {
                    "account_name": mapping["account_name"],
                    "is_payer": True,
                }

            # Build cost query
            stmt = (
                sa.select(
                    t_scan_metadata.c.account_name,
                    t_scan_metadata.c.account_number,
                    t_cost_data.c.currency,
                    sa.func.sum(t_cost_data.c.amount).label("total_cost"),
                    sa.func.min(t_cost_data.c.time_period_start).label(
                        "earliest_period"
                    ),
                    sa.func.max(t_cost_data.c.time_period_end).label("latest_period"),
                    sa.func.count(sa.distinct(t_cost_data.c.service_name)).label(
                        "service_count"
                    ),
                )
                .select_from(
                    t_cost_data.join(
                        t_scan_metadata,
                        t_cost_data.c.scan_id == t_scan_metadata.c.scan_id,
                    )
                )
                .group_by(
                    t_scan_metadata.c.account_name,
                    t_scan_metadata.c.account_number,
                    t_cost_data.c.currency,
                )
                .order_by(sa.desc("total_cost"))
            )

            if account_number:
                stmt = stmt.where(t_cost_data.c.account_number == account_number)

            accounts = []
            total_all_accounts = 0.0
            total_excluding_payer = 0.0
            currency = "USD"
            payer_account_cost = 0.0

            for row in conn.execute(stmt):
                mapping = row._mapping
                acct_num = mapping["account_number"]
                is_payer = acct_num in master_accounts

                account_cost = {
                    "account_name": mapping["account_name"],
                    "account_number": mapping["account_number"],
                    "total_cost": round(mapping["total_cost"], 2),
                    "currency": mapping["currency"],
                    "earliest_period": mapping["earliest_period"],
                    "latest_period": mapping["latest_period"],
                    "service_count": mapping["service_count"],
                    "is_master_payer_account": is_payer,
                }

                if is_payer:
                    account_cost["note"] = (
                        "Master payer account in AWS Organizations - costs shown here are direct costs for this account only. Member account costs are shown separately."
                    )
                    payer_account_cost = mapping["total_cost"]

                accounts.append(account_cost)
                total_all_accounts += mapping["total_cost"]
                if not is_payer:
                    total_excluding_payer += mapping["total_cost"]
                currency = mapping["currency"]

        result = {
            "accounts": accounts,
            "total_cost_all_accounts": round(total_all_accounts, 2),
            "currency": currency,
            "account_count": len(accounts),
        }

        # Add AWS Organizations context if applicable
        if master_accounts:
            result["aws_organizations_info"] = {
                "has_organizations": True,
                "master_payer_accounts": len(master_accounts),
                "total_member_account_costs": round(total_excluding_payer, 2),
                "note": "This AWS environment uses AWS Organizations with consolidated billing. The master payer account costs shown are direct costs only, not including member account costs which are listed separately.",
            }

        return result

    def _get_cost_by_service(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Get cost breakdown by service for all or specific accounts."""
        account_number = params.get("account_number")
        top_n = params.get("top_n", 20)  # Default to top 20 services

        # Build query to get cost by service
        stmt = (
            sa.select(
                t_cost_data.c.service_name,
                sa.func.sum(t_cost_data.c.amount).label("total_cost"),
                t_cost_data.c.currency,
                sa.func.count(sa.distinct(t_cost_data.c.account_number)).label(
                    "account_count"
                ),
                sa.func.min(t_cost_data.c.time_period_start).label("earliest_period"),
                sa.func.max(t_cost_data.c.time_period_end).label("latest_period"),
            )
            .group_by(t_cost_data.c.service_name, t_cost_data.c.currency)
            .order_by(sa.desc("total_cost"))
        )

        if account_number:
            stmt = stmt.where(t_cost_data.c.account_number == account_number)

        if top_n:
            stmt = stmt.limit(top_n)

        services = []
        total_cost = 0.0
        currency = "USD"

        with self.db_ops.engine.connect() as conn:
            for row in conn.execute(stmt):
                mapping = row._mapping
                service = {
                    "service_name": mapping["service_name"],
                    "total_cost": round(mapping["total_cost"], 2),
                    "currency": mapping["currency"],
                    "account_count": mapping["account_count"],
                    "earliest_period": mapping["earliest_period"],
                    "latest_period": mapping["latest_period"],
                }
                services.append(service)
                total_cost += mapping["total_cost"]
                currency = mapping["currency"]

        return {
            "services": services,
            "total_cost": round(total_cost, 2),
            "currency": currency,
            "service_count": len(services),
        }

    def _get_cost_trends(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Get cost trends over time with monthly breakdown."""
        account_number = params.get("account_number")
        service_name = params.get("service_name")

        # Build query to get monthly costs.
        # The legacy SQL uses strftime('%Y-%m', cd.time_period_start); the
        # column holds ISO date strings, so substr(col, 1, 7) is the binding
        # equivalent for a 'YYYY-MM' prefix.
        month_expr = sa.func.substr(t_cost_data.c.time_period_start, 1, 7).label(
            "month"
        )
        monthly_cost_expr = sa.func.sum(t_cost_data.c.amount).label("monthly_cost")
        stmt = (
            sa.select(
                month_expr,
                t_cost_data.c.account_number,
                t_scan_metadata.c.account_name,
                t_cost_data.c.service_name,
                monthly_cost_expr,
                t_cost_data.c.currency,
            )
            .select_from(
                t_cost_data.join(
                    t_scan_metadata, t_cost_data.c.scan_id == t_scan_metadata.c.scan_id
                )
            )
            .group_by(
                month_expr,
                t_cost_data.c.account_number,
                t_scan_metadata.c.account_name,
                t_cost_data.c.service_name,
                t_cost_data.c.currency,
            )
            .order_by(month_expr.desc(), monthly_cost_expr.desc())
        )

        conditions = []
        if account_number:
            conditions.append(t_cost_data.c.account_number == account_number)
        if service_name:
            conditions.append(t_cost_data.c.service_name == service_name)
        if conditions:
            stmt = stmt.where(*conditions)

        # Organize by month
        trends = {}
        with self.db_ops.engine.connect() as conn:
            for row in conn.execute(stmt):
                mapping = row._mapping
                month = mapping["month"]
                if month not in trends:
                    trends[month] = {
                        "month": month,
                        "accounts": {},
                        "total_monthly_cost": 0.0,
                        "currency": mapping["currency"],
                    }

                account = mapping["account_number"]
                if account not in trends[month]["accounts"]:
                    trends[month]["accounts"][account] = {
                        "account_name": mapping["account_name"],
                        "account_number": account,
                        "services": {},
                        "account_total": 0.0,
                    }

                service = mapping["service_name"]
                cost = mapping["monthly_cost"]

                trends[month]["accounts"][account]["services"][service] = round(cost, 2)
                trends[month]["accounts"][account]["account_total"] += cost
                trends[month]["total_monthly_cost"] += cost

        # Round totals
        for month_data in trends.values():
            month_data["total_monthly_cost"] = round(
                month_data["total_monthly_cost"], 2
            )
            for account_data in month_data["accounts"].values():
                account_data["account_total"] = round(account_data["account_total"], 2)

        # Convert to list sorted by month
        trends_list = sorted(trends.values(), key=lambda x: x["month"], reverse=True)

        return {"trends": trends_list, "month_count": len(trends_list)}

    def _get_cost_comparison(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Compare costs between accounts with service breakdown."""
        service_cost_expr = sa.func.sum(t_cost_data.c.amount).label("service_cost")
        stmt = (
            sa.select(
                t_scan_metadata.c.account_name,
                t_scan_metadata.c.account_number,
                t_cost_data.c.service_name,
                service_cost_expr,
                t_cost_data.c.currency,
            )
            .select_from(
                t_cost_data.join(
                    t_scan_metadata, t_cost_data.c.scan_id == t_scan_metadata.c.scan_id
                )
            )
            .group_by(
                t_scan_metadata.c.account_name,
                t_scan_metadata.c.account_number,
                t_cost_data.c.service_name,
                t_cost_data.c.currency,
            )
            .order_by(t_scan_metadata.c.account_name, service_cost_expr.desc())
        )

        # Organize by account
        accounts = {}
        with self.db_ops.engine.connect() as conn:
            for row in conn.execute(stmt):
                mapping = row._mapping
                account_num = mapping["account_number"]

                if account_num not in accounts:
                    accounts[account_num] = {
                        "account_name": mapping["account_name"],
                        "account_number": account_num,
                        "services": {},
                        "total_cost": 0.0,
                        "currency": mapping["currency"],
                    }

                service = mapping["service_name"]
                cost = mapping["service_cost"]

                accounts[account_num]["services"][service] = round(cost, 2)
                accounts[account_num]["total_cost"] += cost

        # Round account totals
        for account in accounts.values():
            account["total_cost"] = round(account["total_cost"], 2)

        # Convert to list sorted by total cost
        accounts_list = sorted(
            accounts.values(), key=lambda x: x["total_cost"], reverse=True
        )

        total_all = sum(acc["total_cost"] for acc in accounts_list)

        return {
            "accounts": accounts_list,
            "account_count": len(accounts_list),
            "total_cost_all_accounts": round(total_all, 2),
            "currency": accounts_list[0]["currency"] if accounts_list else "USD",
        }

    def _analyze_vpc_cidrs(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyse VPC CIDR allocations to identify overlaps and conflicts.

        Args:
            params: Query parameters with optional vpc_id and scan_id filters

        Returns:
            Dictionary with VPC CIDR analysis including overlaps
        """
        vpc_id = params.get("vpc_id")
        scan_id = params.get("scan_id")

        # Build VPC query
        vpc_stmt = sa.select(
            t_vpcs.c.vpc_id,
            t_vpcs.c.cidr_block,
            t_vpcs.c.region,
            t_vpcs.c.is_default,
            t_vpcs.c.tags,
            t_vpcs.c.scan_id,
            t_scan_metadata.c.account_name,
            t_scan_metadata.c.account_number,
        ).select_from(
            t_vpcs.join(t_scan_metadata, t_vpcs.c.scan_id == t_scan_metadata.c.scan_id)
        )

        vpc_conditions = []
        if vpc_id:
            vpc_conditions.append(t_vpcs.c.vpc_id == vpc_id)
        if scan_id:
            vpc_conditions.append(t_vpcs.c.scan_id == scan_id)
        if vpc_conditions:
            vpc_stmt = vpc_stmt.where(*vpc_conditions)

        vpc_stmt = vpc_stmt.order_by(
            t_scan_metadata.c.account_name, t_vpcs.c.region, t_vpcs.c.vpc_id
        )

        # Collect VPC data
        vpcs = []
        vpc_networks = {}  # For overlap detection

        with self.db_ops.engine.connect() as conn:
            for row in conn.execute(vpc_stmt):
                vpc_data = {
                    "vpc_id": row[0],
                    "cidr_block": row[1],
                    "region": row[2],
                    "is_default": bool(row[3]),
                    "tags": json.loads(row[4]) if row[4] else {},
                    "scan_id": row[5],
                    "account_name": row[6],
                    "account_number": row[7],
                    "subnets": [],
                }

                # Parse CIDR for overlap detection
                try:
                    vpc_network = ipaddress.ip_network(
                        vpc_data["cidr_block"], strict=False
                    )
                    vpc_networks[row[0]] = {"network": vpc_network, "data": vpc_data}
                except ValueError as e:
                    logger.warning(
                        f"Invalid CIDR block {vpc_data['cidr_block']} for VPC {row[0]}: {e}"
                    )

                vpcs.append(vpc_data)

            # Get subnets for each VPC
            if vpcs:
                vpc_ids = [v["vpc_id"] for v in vpcs]

                # The legacy SQL selects subnets.is_public, a column absent
                # from the subnets DDL (only map_public_ip exists). Kept
                # verbatim via sa.text() so the frozen "no such column:
                # is_public" baseline error still fires; the raw sqlite3
                # error is re-raised so handle_query's str(e) matches the
                # frozen baseline exactly.
                subnet_stmt = sa.text("""
                    SELECT vpc_id, subnet_id, cidr_block, availability_zone,
                           is_public, tags
                    FROM subnets
                    WHERE vpc_id IN :vpc_ids
                    ORDER BY vpc_id, cidr_block
                    """).bindparams(sa.bindparam("vpc_ids", expanding=True))

                try:
                    subnet_rows = conn.execute(
                        subnet_stmt, {"vpc_ids": vpc_ids}
                    ).fetchall()
                except sa.exc.DBAPIError as e:
                    raise e.orig from None

                # Group subnets by VPC
                subnets_by_vpc = {}
                for row in subnet_rows:
                    vpc_id_key = row[0]
                    subnet_data = {
                        "subnet_id": row[1],
                        "cidr_block": row[2],
                        "availability_zone": row[3],
                        "is_public": bool(row[4]),
                        "tags": json.loads(row[5]) if row[5] else {},
                    }

                    if vpc_id_key not in subnets_by_vpc:
                        subnets_by_vpc[vpc_id_key] = []
                    subnets_by_vpc[vpc_id_key].append(subnet_data)

                # Add subnets to VPCs
                for vpc in vpcs:
                    vpc["subnets"] = subnets_by_vpc.get(vpc["vpc_id"], [])

                    # Calculate CIDR utilization
                    if vpc["subnets"]:
                        try:
                            vpc_network = ipaddress.ip_network(
                                vpc["cidr_block"], strict=False
                            )
                            vpc_total_ips = vpc_network.num_addresses

                            subnet_ips = 0
                            for subnet in vpc["subnets"]:
                                try:
                                    subnet_network = ipaddress.ip_network(
                                        subnet["cidr_block"], strict=False
                                    )
                                    subnet_ips += subnet_network.num_addresses
                                except ValueError:
                                    pass

                            vpc["cidr_utilization"] = {
                                "total_ips": vpc_total_ips,
                                "allocated_ips": subnet_ips,
                                "available_ips": vpc_total_ips - subnet_ips,
                                "utilization_percentage": (
                                    round((subnet_ips / vpc_total_ips) * 100, 2)
                                    if vpc_total_ips > 0
                                    else 0
                                ),
                            }
                        except ValueError:
                            vpc["cidr_utilization"] = None

        # Detect overlaps between VPCs
        overlaps = []
        vpc_list = list(vpc_networks.items())

        for i in range(len(vpc_list)):
            for j in range(i + 1, len(vpc_list)):
                vpc1_id, vpc1 = vpc_list[i]
                vpc2_id, vpc2 = vpc_list[j]

                if vpc1["network"].overlaps(vpc2["network"]):
                    overlap = {
                        "vpc1": {
                            "vpc_id": vpc1_id,
                            "cidr_block": str(vpc1["network"]),
                            "account_name": vpc1["data"]["account_name"],
                            "account_number": vpc1["data"]["account_number"],
                            "region": vpc1["data"]["region"],
                        },
                        "vpc2": {
                            "vpc_id": vpc2_id,
                            "cidr_block": str(vpc2["network"]),
                            "account_name": vpc2["data"]["account_name"],
                            "account_number": vpc2["data"]["account_number"],
                            "region": vpc2["data"]["region"],
                        },
                        "overlap_type": (
                            "full"
                            if (vpc1["network"] == vpc2["network"])
                            else "partial"
                        ),
                    }
                    overlaps.append(overlap)

        # Calculate summary statistics
        total_vpcs = len(vpcs)
        total_subnets = sum(len(v["subnets"]) for v in vpcs)
        vpcs_with_overlaps = len(
            set(
                [o["vpc1"]["vpc_id"] for o in overlaps]
                + [o["vpc2"]["vpc_id"] for o in overlaps]
            )
        )

        # Group VPCs by account
        vpcs_by_account = {}
        for vpc in vpcs:
            account_key = f"{vpc['account_name']} ({vpc['account_number']})"
            if account_key not in vpcs_by_account:
                vpcs_by_account[account_key] = []
            vpcs_by_account[account_key].append(vpc)

        return {
            "summary": {
                "total_vpcs": total_vpcs,
                "total_subnets": total_subnets,
                "overlap_count": len(overlaps),
                "vpcs_with_overlaps": vpcs_with_overlaps,
                "accounts_scanned": len(vpcs_by_account),
            },
            "vpcs": vpcs,
            "vpcs_by_account": vpcs_by_account,
            "overlaps": overlaps,
            "has_conflicts": len(overlaps) > 0,
        }

    def _find_unused_resources(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Find unused AWS resources that are consuming cost.

        Args:
            params: Query parameters with optional scan_id, resource_type, age_days filters

        Returns:
            Dictionary with categorized unused resources
        """
        scan_id = params.get("scan_id")
        resource_type = params.get("resource_type")
        age_days = params.get("age_days", 90)  # Default: 90 days for old snapshots

        results = {
            "summary": {
                "total_unused": 0,
                "potential_monthly_savings": 0.0,
                "categories": {},
            },
            "unused_resources": {},
        }

        with self.db_ops.engine.connect() as conn:
            # 1. Unattached EBS volumes
            if not resource_type or resource_type == "ebs_volume":
                stmt = (
                    sa.select(
                        t_ebs_volumes.c.volume_id,
                        t_ebs_volumes.c.region,
                        t_ebs_volumes.c.size,
                        t_ebs_volumes.c.volume_type,
                        t_ebs_volumes.c.state,
                        t_ebs_volumes.c.create_time,
                        t_ebs_volumes.c.tags,
                        t_ebs_volumes.c.scan_id,
                        t_scan_metadata.c.account_name,
                        t_scan_metadata.c.account_number,
                    )
                    .select_from(
                        t_ebs_volumes.join(
                            t_scan_metadata,
                            t_ebs_volumes.c.scan_id == t_scan_metadata.c.scan_id,
                        )
                    )
                    .where(
                        t_ebs_volumes.c.attached_instance_id.is_(None),
                        t_ebs_volumes.c.state == "available",
                    )
                )
                if scan_id:
                    stmt = stmt.where(t_ebs_volumes.c.scan_id == scan_id)

                unattached_volumes = []
                for row in conn.execute(stmt):
                    tags = json.loads(row[6]) if row[6] else {}
                    unattached_volumes.append(
                        {
                            "volume_id": row[0],
                            "region": row[1],
                            "size_gb": row[2],
                            "volume_type": row[3],
                            "state": row[4],
                            "create_time": row[5],
                            "tags": tags,
                            "account_name": row[8],
                            "account_number": row[9],
                            "estimated_monthly_cost": row[2]
                            * 0.10,  # Rough estimate: $0.10/GB/month
                        }
                    )

                if unattached_volumes:
                    results["unused_resources"][
                        "unattached_ebs_volumes"
                    ] = unattached_volumes
                    results["summary"]["categories"]["unattached_ebs_volumes"] = len(
                        unattached_volumes
                    )
                    results["summary"]["potential_monthly_savings"] += sum(
                        v["estimated_monthly_cost"] for v in unattached_volumes
                    )

            # 2. Unassociated Elastic IPs
            if not resource_type or resource_type == "elastic_ip":
                stmt = (
                    sa.select(
                        t_elastic_ips.c.public_ip,
                        t_elastic_ips.c.allocation_id,
                        t_elastic_ips.c.region,
                        t_elastic_ips.c.tags,
                        t_elastic_ips.c.scan_id,
                        t_scan_metadata.c.account_name,
                        t_scan_metadata.c.account_number,
                    )
                    .select_from(
                        t_elastic_ips.join(
                            t_scan_metadata,
                            t_elastic_ips.c.scan_id == t_scan_metadata.c.scan_id,
                        )
                    )
                    .where(t_elastic_ips.c.is_associated == 0)
                )
                if scan_id:
                    stmt = stmt.where(t_elastic_ips.c.scan_id == scan_id)

                unassociated_eips = []
                for row in conn.execute(stmt):
                    tags = json.loads(row[3]) if row[3] else {}
                    unassociated_eips.append(
                        {
                            "public_ip": row[0],
                            "allocation_id": row[1],
                            "region": row[2],
                            "tags": tags,
                            "account_name": row[5],
                            "account_number": row[6],
                            "estimated_monthly_cost": 3.60,  # $0.005/hour = $3.60/month
                        }
                    )

                if unassociated_eips:
                    results["unused_resources"][
                        "unassociated_elastic_ips"
                    ] = unassociated_eips
                    results["summary"]["categories"]["unassociated_elastic_ips"] = len(
                        unassociated_eips
                    )
                    results["summary"]["potential_monthly_savings"] += (
                        len(unassociated_eips) * 3.60
                    )

            # 3. Old EBS snapshots
            if not resource_type or resource_type == "ebs_snapshot":
                # SQLite's julianday() is not portable across dialects. The
                # cutoff is computed in Python and compared against the
                # ISO-formatted start_time string lexicographically; age_days
                # is likewise derived in Python after fetch rather than in
                # SQL, preserving the same whole-number-of-days truncation
                # the legacy int(julianday_diff) produced.
                now = datetime.now(UTC)
                cutoff = (now - timedelta(days=age_days)).isoformat()
                stmt = (
                    sa.select(
                        t_ebs_snapshots.c.snapshot_id,
                        t_ebs_snapshots.c.region,
                        t_ebs_snapshots.c.volume_id,
                        t_ebs_snapshots.c.volume_size,
                        t_ebs_snapshots.c.start_time,
                        t_ebs_snapshots.c.description,
                        t_ebs_snapshots.c.tags,
                        t_ebs_snapshots.c.scan_id,
                        t_scan_metadata.c.account_name,
                        t_scan_metadata.c.account_number,
                    )
                    .select_from(
                        t_ebs_snapshots.join(
                            t_scan_metadata,
                            t_ebs_snapshots.c.scan_id == t_scan_metadata.c.scan_id,
                        )
                    )
                    .where(
                        t_ebs_snapshots.c.start_time < cutoff,
                        t_ebs_snapshots.c.state == "completed",
                    )
                )
                if scan_id:
                    stmt = stmt.where(t_ebs_snapshots.c.scan_id == scan_id)

                old_snapshots = []
                for row in conn.execute(stmt):
                    tags = json.loads(row[6]) if row[6] else {}
                    start_time = datetime.fromisoformat(row[4].replace("Z", "+00:00"))
                    old_snapshots.append(
                        {
                            "snapshot_id": row[0],
                            "region": row[1],
                            "volume_id": row[2],
                            "size_gb": row[3],
                            "start_time": row[4],
                            "description": row[5],
                            "tags": tags,
                            "account_name": row[8],
                            "account_number": row[9],
                            "age_days": (now - start_time).days,
                            "estimated_monthly_cost": row[3]
                            * 0.05,  # $0.05/GB/month for snapshots
                        }
                    )

                if old_snapshots:
                    results["unused_resources"]["old_snapshots"] = old_snapshots
                    results["summary"]["categories"]["old_snapshots"] = len(
                        old_snapshots
                    )
                    results["summary"]["potential_monthly_savings"] += sum(
                        s["estimated_monthly_cost"] for s in old_snapshots
                    )

            # 4. Stopped EC2 instances (still paying for attached EBS)
            if not resource_type or resource_type == "ec2_instance":
                stmt = (
                    sa.select(
                        t_ec2_instances.c.instance_id,
                        t_ec2_instances.c.instance_type,
                        t_ec2_instances.c.state,
                        t_ec2_instances.c.region,
                        t_ec2_instances.c.tags,
                        t_ec2_instances.c.scan_id,
                        t_scan_metadata.c.account_name,
                        t_scan_metadata.c.account_number,
                    )
                    .select_from(
                        t_ec2_instances.join(
                            t_scan_metadata,
                            t_ec2_instances.c.scan_id == t_scan_metadata.c.scan_id,
                        )
                    )
                    .where(t_ec2_instances.c.state == "stopped")
                )
                if scan_id:
                    stmt = stmt.where(t_ec2_instances.c.scan_id == scan_id)

                stopped_instances = []
                for row in conn.execute(stmt):
                    tags = json.loads(row[4]) if row[4] else {}
                    stopped_instances.append(
                        {
                            "instance_id": row[0],
                            "instance_type": row[1],
                            "state": row[2],
                            "region": row[3],
                            "tags": tags,
                            "account_name": row[6],
                            "account_number": row[7],
                            "note": "Still paying for attached EBS volumes",
                        }
                    )

                if stopped_instances:
                    results["unused_resources"][
                        "stopped_ec2_instances"
                    ] = stopped_instances
                    results["summary"]["categories"]["stopped_ec2_instances"] = len(
                        stopped_instances
                    )

        # Calculate totals
        results["summary"]["total_unused"] = sum(
            results["summary"]["categories"].values()
        )
        results["summary"]["potential_monthly_savings"] = round(
            results["summary"]["potential_monthly_savings"], 2
        )

        return results

    def _analyze_encryption_coverage(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyse encryption coverage across resources.

        Args:
            params: Query parameters with optional scan_id, account_number

        Returns:
            Dictionary with encryption analysis by resource type
        """
        scan_id = params.get("scan_id")
        account_number = params.get("account_number")

        results = {
            "summary": {
                "total_resources": 0,
                "encrypted_resources": 0,
                "unencrypted_resources": 0,
                "encryption_percentage": 0.0,
            },
            "by_resource_type": {},
            "unencrypted_resources": {},
        }

        with self.db_ops.engine.connect() as conn:
            # 1. EBS Volumes
            stmt = sa.select(
                t_ebs_volumes.c.volume_id,
                t_ebs_volumes.c.region,
                t_ebs_volumes.c.size,
                t_ebs_volumes.c.volume_type,
                t_ebs_volumes.c.encrypted,
                t_ebs_volumes.c.tags,
                t_scan_metadata.c.account_name,
                t_scan_metadata.c.account_number,
            ).select_from(
                t_ebs_volumes.join(
                    t_scan_metadata,
                    t_ebs_volumes.c.scan_id == t_scan_metadata.c.scan_id,
                )
            )
            conditions = []
            if scan_id:
                conditions.append(t_ebs_volumes.c.scan_id == scan_id)
            if account_number:
                conditions.append(t_scan_metadata.c.account_number == account_number)
            if conditions:
                stmt = stmt.where(*conditions)

            ebs_volumes = []
            ebs_encrypted = 0
            ebs_total = 0
            for row in conn.execute(stmt):
                ebs_total += 1
                encrypted = bool(row[4])
                if encrypted:
                    ebs_encrypted += 1
                else:
                    tags = json.loads(row[5]) if row[5] else {}
                    ebs_volumes.append(
                        {
                            "volume_id": row[0],
                            "region": row[1],
                            "size_gb": row[2],
                            "volume_type": row[3],
                            "tags": tags,
                            "account_name": row[6],
                            "account_number": row[7],
                        }
                    )

            if ebs_total > 0:
                results["by_resource_type"]["ebs_volumes"] = {
                    "total": ebs_total,
                    "encrypted": ebs_encrypted,
                    "unencrypted": ebs_total - ebs_encrypted,
                    "encryption_percentage": round(
                        (ebs_encrypted / ebs_total) * 100, 2
                    ),
                }
                if ebs_volumes:
                    results["unencrypted_resources"]["ebs_volumes"] = ebs_volumes

            # 2. EBS Snapshots
            stmt = sa.select(
                t_ebs_snapshots.c.snapshot_id,
                t_ebs_snapshots.c.region,
                t_ebs_snapshots.c.volume_size,
                t_ebs_snapshots.c.encrypted,
                t_ebs_snapshots.c.tags,
                t_scan_metadata.c.account_name,
                t_scan_metadata.c.account_number,
            ).select_from(
                t_ebs_snapshots.join(
                    t_scan_metadata,
                    t_ebs_snapshots.c.scan_id == t_scan_metadata.c.scan_id,
                )
            )
            conditions = []
            if scan_id:
                conditions.append(t_ebs_snapshots.c.scan_id == scan_id)
            if account_number:
                conditions.append(t_scan_metadata.c.account_number == account_number)
            if conditions:
                stmt = stmt.where(*conditions)

            ebs_snapshots = []
            snap_encrypted = 0
            snap_total = 0
            for row in conn.execute(stmt):
                snap_total += 1
                encrypted = bool(row[3])
                if encrypted:
                    snap_encrypted += 1
                else:
                    tags = json.loads(row[4]) if row[4] else {}
                    ebs_snapshots.append(
                        {
                            "snapshot_id": row[0],
                            "region": row[1],
                            "size_gb": row[2],
                            "tags": tags,
                            "account_name": row[5],
                            "account_number": row[6],
                        }
                    )

            if snap_total > 0:
                results["by_resource_type"]["ebs_snapshots"] = {
                    "total": snap_total,
                    "encrypted": snap_encrypted,
                    "unencrypted": snap_total - snap_encrypted,
                    "encryption_percentage": round(
                        (snap_encrypted / snap_total) * 100, 2
                    ),
                }
                if ebs_snapshots:
                    results["unencrypted_resources"]["ebs_snapshots"] = ebs_snapshots

            # 3. RDS Instances
            stmt = sa.select(
                t_rds_instances.c.db_instance_identifier,
                t_rds_instances.c.region,
                t_rds_instances.c.engine,
                t_rds_instances.c.db_instance_class,
                t_rds_instances.c.encrypted,
                t_rds_instances.c.tags,
                t_scan_metadata.c.account_name,
                t_scan_metadata.c.account_number,
            ).select_from(
                t_rds_instances.join(
                    t_scan_metadata,
                    t_rds_instances.c.scan_id == t_scan_metadata.c.scan_id,
                )
            )
            conditions = []
            if scan_id:
                conditions.append(t_rds_instances.c.scan_id == scan_id)
            if account_number:
                conditions.append(t_scan_metadata.c.account_number == account_number)
            if conditions:
                stmt = stmt.where(*conditions)

            rds_instances = []
            rds_encrypted = 0
            rds_total = 0
            for row in conn.execute(stmt):
                rds_total += 1
                encrypted = bool(row[4])
                if encrypted:
                    rds_encrypted += 1
                else:
                    tags = json.loads(row[5]) if row[5] else {}
                    rds_instances.append(
                        {
                            "db_instance_identifier": row[0],
                            "region": row[1],
                            "engine": row[2],
                            "instance_class": row[3],
                            "tags": tags,
                            "account_name": row[6],
                            "account_number": row[7],
                            "severity": "CRITICAL",
                        }
                    )

            if rds_total > 0:
                results["by_resource_type"]["rds_instances"] = {
                    "total": rds_total,
                    "encrypted": rds_encrypted,
                    "unencrypted": rds_total - rds_encrypted,
                    "encryption_percentage": round(
                        (rds_encrypted / rds_total) * 100, 2
                    ),
                }
                if rds_instances:
                    results["unencrypted_resources"]["rds_instances"] = rds_instances

            # 4. S3 Buckets (check for default encryption)
            stmt = sa.select(
                t_s3_buckets.c.bucket_name,
                t_s3_buckets.c.region,
                t_s3_buckets.c.encryption_config,
                t_s3_buckets.c.tags,
                t_scan_metadata.c.account_name,
                t_scan_metadata.c.account_number,
            ).select_from(
                t_s3_buckets.join(
                    t_scan_metadata, t_s3_buckets.c.scan_id == t_scan_metadata.c.scan_id
                )
            )
            conditions = []
            if scan_id:
                conditions.append(t_s3_buckets.c.scan_id == scan_id)
            if account_number:
                conditions.append(t_scan_metadata.c.account_number == account_number)
            if conditions:
                stmt = stmt.where(*conditions)

            s3_buckets = []
            s3_encrypted = 0
            s3_total = 0
            for row in conn.execute(stmt):
                s3_total += 1
                encryption_config = json.loads(row[2]) if row[2] else {}
                has_encryption = bool(encryption_config)

                if has_encryption:
                    s3_encrypted += 1
                else:
                    tags = json.loads(row[3]) if row[3] else {}
                    s3_buckets.append(
                        {
                            "bucket_name": row[0],
                            "region": row[1],
                            "tags": tags,
                            "account_name": row[4],
                            "account_number": row[5],
                            "severity": "HIGH",
                        }
                    )

            if s3_total > 0:
                results["by_resource_type"]["s3_buckets"] = {
                    "total": s3_total,
                    "encrypted": s3_encrypted,
                    "unencrypted": s3_total - s3_encrypted,
                    "encryption_percentage": round((s3_encrypted / s3_total) * 100, 2),
                }
                if s3_buckets:
                    results["unencrypted_resources"]["s3_buckets"] = s3_buckets

        # Calculate overall summary
        results["summary"]["total_resources"] = sum(
            rt["total"] for rt in results["by_resource_type"].values()
        )
        results["summary"]["encrypted_resources"] = sum(
            rt["encrypted"] for rt in results["by_resource_type"].values()
        )
        results["summary"]["unencrypted_resources"] = sum(
            rt["unencrypted"] for rt in results["by_resource_type"].values()
        )

        if results["summary"]["total_resources"] > 0:
            results["summary"]["encryption_percentage"] = round(
                (
                    results["summary"]["encrypted_resources"]
                    / results["summary"]["total_resources"]
                )
                * 100,
                2,
            )

        return results

    def _find_publicly_accessible_databases(
        self, params: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Find RDS databases that are publicly accessible.

        Args:
            params: Query parameters with optional scan_id, region

        Returns:
            Dictionary with publicly accessible databases and security details
        """
        scan_id = params.get("scan_id")
        region = params.get("region")

        stmt = (
            sa.select(
                t_rds_instances.c.db_instance_identifier,
                t_rds_instances.c.region,
                t_rds_instances.c.engine,
                t_rds_instances.c.engine_version,
                t_rds_instances.c.db_instance_class,
                t_rds_instances.c.publicly_accessible,
                t_rds_instances.c.vpc_id,
                t_rds_instances.c.subnet_group,
                t_rds_instances.c.vpc_security_groups,
                t_rds_instances.c.endpoint_address,
                t_rds_instances.c.endpoint_port,
                t_rds_instances.c.encrypted,
                t_rds_instances.c.multi_az,
                t_rds_instances.c.tags,
                t_rds_instances.c.scan_id,
                t_scan_metadata.c.account_name,
                t_scan_metadata.c.account_number,
            )
            .select_from(
                t_rds_instances.join(
                    t_scan_metadata,
                    t_rds_instances.c.scan_id == t_scan_metadata.c.scan_id,
                )
            )
            .where(t_rds_instances.c.publicly_accessible == 1)
        )

        conditions = []
        if scan_id:
            conditions.append(t_rds_instances.c.scan_id == scan_id)
        if region:
            conditions.append(t_rds_instances.c.region == region)
        if conditions:
            stmt = stmt.where(*conditions)

        public_databases = []
        with self.db_ops.engine.connect() as conn:
            for row in conn.execute(stmt):
                tags = json.loads(row[13]) if row[13] else {}
                vpc_security_groups = json.loads(row[8]) if row[8] else []

                public_databases.append(
                    {
                        "db_instance_identifier": row[0],
                        "region": row[1],
                        "engine": row[2],
                        "engine_version": row[3],
                        "instance_class": row[4],
                        "publicly_accessible": bool(row[5]),
                        "vpc_id": row[6],
                        "subnet_group": row[7],
                        "security_groups": vpc_security_groups,
                        "endpoint_address": row[9],
                        "endpoint_port": row[10],
                        "encrypted": bool(row[11]),
                        "multi_az": bool(row[12]),
                        "tags": tags,
                        "account_name": row[15],
                        "account_number": row[16],
                        "severity": "CRITICAL",
                        "risk_assessment": {
                            "publicly_accessible": "CRITICAL - Database is accessible from the internet",
                            "encryption_status": (
                                "OK - Encrypted"
                                if row[11]
                                else "CRITICAL - Not encrypted"
                            ),
                            "multi_az": (
                                "OK - Multi-AZ enabled"
                                if row[12]
                                else "WARNING - Single AZ"
                            ),
                        },
                    }
                )

        return {
            "summary": {
                "total_public_databases": len(public_databases),
                "severity": "CRITICAL" if public_databases else "OK",
                "recommendation": (
                    "Make databases private and use VPN/bastion host for access"
                    if public_databases
                    else "No publicly accessible databases found"
                ),
            },
            "public_databases": public_databases,
        }

    def _analyze_iam_permissions(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyse IAM permissions for security issues.

        Args:
            params: Query parameters with optional scan_id, check_type

        Returns:
            Dictionary with IAM permission analysis
        """
        scan_id = params.get("scan_id")
        check_type = params.get("check_type")  # admin, wildcards, unused, keys, mfa

        results = {
            "summary": {
                "total_issues": 0,
                "critical_issues": 0,
                "high_issues": 0,
                "medium_issues": 0,
            },
            "findings": {},
        }

        with self.db_ops.engine.connect() as conn:
            # 1. Find policies with AdministratorAccess or overly permissive wildcards
            if not check_type or check_type in ["admin", "wildcards"]:
                stmt = sa.select(
                    t_iam_policies.c.policy_name,
                    t_iam_policies.c.policy_arn,
                    t_iam_policies.c.policy_document,
                    t_iam_policies.c.attached_users,
                    t_iam_policies.c.attached_roles,
                    t_iam_policies.c.attached_groups,
                    t_iam_policies.c.attachment_count,
                    t_iam_policies.c.scan_id,
                    t_scan_metadata.c.account_name,
                    t_scan_metadata.c.account_number,
                ).select_from(
                    t_iam_policies.join(
                        t_scan_metadata,
                        t_iam_policies.c.scan_id == t_scan_metadata.c.scan_id,
                    )
                )
                if scan_id:
                    stmt = stmt.where(t_iam_policies.c.scan_id == scan_id)

                admin_policies = []
                wildcard_policies = []

                for row in conn.execute(stmt):
                    policy_doc = json.loads(row[2]) if row[2] else {}
                    attached_users = json.loads(row[3]) if row[3] else []
                    attached_roles = json.loads(row[4]) if row[4] else []
                    attached_groups = json.loads(row[5]) if row[5] else []

                    # Check for overly permissive policies
                    is_admin = False
                    has_wildcards = False

                    for statement in policy_doc.get("Statement", []):
                        if statement.get("Effect") == "Allow":
                            actions = statement.get("Action", [])
                            resources = statement.get("Resource", [])

                            # Convert to list if string
                            if isinstance(actions, str):
                                actions = [actions]
                            if isinstance(resources, str):
                                resources = [resources]

                            # Check for full admin access
                            if "*" in actions and "*" in resources:
                                is_admin = True

                            # Check for dangerous wildcards
                            for action in actions:
                                if action in ["s3:*", "ec2:*", "iam:*", "rds:*"]:
                                    has_wildcards = True

                    policy_info = {
                        "policy_name": row[0],
                        "policy_arn": row[1],
                        "attached_users": attached_users,
                        "attached_roles": attached_roles,
                        "attached_groups": attached_groups,
                        "attachment_count": row[6],
                        "account_name": row[8],
                        "account_number": row[9],
                    }

                    if is_admin:
                        policy_info["severity"] = "CRITICAL"
                        policy_info["issue"] = (
                            "Full administrator access (Action: *, Resource: *)"
                        )
                        admin_policies.append(policy_info)
                        results["summary"]["critical_issues"] += 1

                    elif has_wildcards:
                        policy_info["severity"] = "HIGH"
                        policy_info["issue"] = (
                            "Overly permissive wildcards (e.g., s3:*, ec2:*, iam:*)"
                        )
                        wildcard_policies.append(policy_info)
                        results["summary"]["high_issues"] += 1

                if admin_policies:
                    results["findings"][
                        "administrator_access_policies"
                    ] = admin_policies
                if wildcard_policies:
                    results["findings"]["wildcard_policies"] = wildcard_policies

            # 2. Find users without MFA
            if not check_type or check_type == "mfa":
                stmt = (
                    sa.select(
                        t_iam_users.c.user_name,
                        t_iam_users.c.mfa_enabled,
                        t_iam_users.c.tags,
                        t_iam_users.c.scan_id,
                        t_scan_metadata.c.account_name,
                        t_scan_metadata.c.account_number,
                    )
                    .select_from(
                        t_iam_users.join(
                            t_scan_metadata,
                            t_iam_users.c.scan_id == t_scan_metadata.c.scan_id,
                        )
                    )
                    .where(t_iam_users.c.mfa_enabled == 0)
                )
                if scan_id:
                    stmt = stmt.where(t_iam_users.c.scan_id == scan_id)

                users_without_mfa = []
                for row in conn.execute(stmt):
                    tags = json.loads(row[2]) if row[2] else {}
                    users_without_mfa.append(
                        {
                            "user_name": row[0],
                            "tags": tags,
                            "account_name": row[4],
                            "account_number": row[5],
                            "severity": "HIGH",
                            "issue": "MFA not enabled",
                        }
                    )

                if users_without_mfa:
                    results["findings"]["users_without_mfa"] = users_without_mfa
                    results["summary"]["high_issues"] += len(users_without_mfa)

        results["summary"]["total_issues"] = (
            results["summary"]["critical_issues"]
            + results["summary"]["high_issues"]
            + results["summary"]["medium_issues"]
        )

        return results

    def _analyze_backup_coverage(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyse backup coverage across resources.

        Checks for:
        - RDS instances without automated backups
        - EBS volumes without snapshots

        Args:
            params: Query parameters including optional scan_id filter

        Returns:
            Dictionary with backup coverage analysis
        """
        scan_id = params.get("scan_id")

        results = {
            "summary": {
                "total_rds_instances": 0,
                "rds_without_backups": 0,
                "protection_percentage": 100.0,
                "critical_issues": 0,
            },
            "unprotected_resources": [],
        }

        with self.db_ops.engine.connect() as conn:
            # Check RDS instances without automated backups
            stmt = (
                sa.select(
                    t_rds_instances.c.db_instance_identifier,
                    t_rds_instances.c.region,
                    t_rds_instances.c.engine,
                    t_rds_instances.c.db_instance_class,
                    t_rds_instances.c.multi_az,
                    t_rds_instances.c.encrypted,
                    t_rds_instances.c.backup_retention_period,
                    t_rds_instances.c.tags,
                    t_rds_instances.c.scan_id,
                    t_scan_metadata.c.account_name,
                    t_scan_metadata.c.account_number,
                )
                .select_from(
                    t_rds_instances.join(
                        t_scan_metadata,
                        t_rds_instances.c.scan_id == t_scan_metadata.c.scan_id,
                    )
                )
                .where(t_rds_instances.c.backup_retention_period == 0)
            )
            if scan_id:
                stmt = stmt.where(t_rds_instances.c.scan_id == scan_id)

            for row in conn.execute(stmt):
                tags = json.loads(row[7]) if row[7] else {}
                results["unprotected_resources"].append(
                    {
                        "resource_type": "RDS Instance",
                        "identifier": row[0],
                        "region": row[1],
                        "engine": row[2],
                        "instance_class": row[3],
                        "multi_az": bool(row[4]),
                        "encrypted": bool(row[5]),
                        "backup_retention_period": row[6],
                        "tags": tags,
                        "account_name": row[9],
                        "account_number": row[10],
                        "severity": "CRITICAL",
                        "issue": "No automated backups configured",
                    }
                )
                results["summary"]["critical_issues"] += 1

            results["summary"]["rds_without_backups"] = len(
                results["unprotected_resources"]
            )

            # Get total RDS instance count
            count_stmt = sa.select(sa.func.count()).select_from(
                t_rds_instances.join(
                    t_scan_metadata,
                    t_rds_instances.c.scan_id == t_scan_metadata.c.scan_id,
                )
            )
            if scan_id:
                count_stmt = count_stmt.where(t_rds_instances.c.scan_id == scan_id)

            results["summary"]["total_rds_instances"] = conn.execute(
                count_stmt
            ).scalar()

        # Calculate protection percentage
        if results["summary"]["total_rds_instances"] > 0:
            protected = (
                results["summary"]["total_rds_instances"]
                - results["summary"]["rds_without_backups"]
            )
            results["summary"]["protection_percentage"] = (
                protected / results["summary"]["total_rds_instances"] * 100
            )

        results["recommendations"] = [
            "Enable automated backups for all production RDS instances",
            "Set backup retention period to at least 7 days",
            "Consider Multi-AZ deployment for critical databases",
            "Enable encryption for sensitive data",
            "Test backup restoration procedures regularly",
        ]

        return results

    def _find_security_group_violations(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Find security group violations on sensitive ports.

        Detects 0.0.0.0/0 access on:
        - SSH (22)
        - RDP (3389)
        - Database ports (MySQL, PostgreSQL, SQL Server, etc.)

        Args:
            params: Query parameters including optional scan_id filter

        Returns:
            Dictionary with security group violations
        """
        scan_id = params.get("scan_id")

        # Define sensitive ports with severity levels
        sensitive_ports = {
            22: {"name": "SSH", "severity": "CRITICAL"},
            3389: {"name": "RDP", "severity": "CRITICAL"},
            3306: {"name": "MySQL", "severity": "CRITICAL"},
            5432: {"name": "PostgreSQL", "severity": "CRITICAL"},
            1433: {"name": "SQL Server", "severity": "CRITICAL"},
            27017: {"name": "MongoDB", "severity": "CRITICAL"},
            6379: {"name": "Redis", "severity": "HIGH"},
            9200: {"name": "Elasticsearch", "severity": "HIGH"},
            5984: {"name": "CouchDB", "severity": "HIGH"},
            8080: {"name": "HTTP Alt", "severity": "MEDIUM"},
            8443: {"name": "HTTPS Alt", "severity": "MEDIUM"},
        }

        results = {
            "summary": {
                "total_violations": 0,
                "critical_violations": 0,
                "high_violations": 0,
                "medium_violations": 0,
                "security_groups_affected": set(),
            },
            "violations_by_port": {},
            "security_groups_with_violations": [],
        }

        # Query all security groups
        stmt = sa.select(
            t_security_groups.c.group_id,
            t_security_groups.c.group_name,
            t_security_groups.c.vpc_id,
            t_security_groups.c.region,
            t_security_groups.c.ingress_rules,
            t_scan_metadata.c.account_name,
            t_scan_metadata.c.account_number,
        ).select_from(
            t_security_groups.join(
                t_scan_metadata,
                t_security_groups.c.scan_id == t_scan_metadata.c.scan_id,
            )
        )
        if scan_id:
            stmt = stmt.where(t_security_groups.c.scan_id == scan_id)

        with self.db_ops.engine.connect() as conn:
            rows = conn.execute(stmt).fetchall()

        for row in rows:
            group_id = row[0]
            group_name = row[1]
            vpc_id = row[2]
            region = row[3]
            ingress_rules = json.loads(row[4]) if row[4] else []
            account_name = row[5]
            account_number = row[6]

            sg_violations = []

            # Check each ingress rule
            for rule in ingress_rules:
                ip_protocol = rule.get("IpProtocol", "")
                from_port = rule.get("FromPort")
                to_port = rule.get("ToPort")
                ip_ranges = rule.get("IpRanges", [])

                # Check for 0.0.0.0/0 access
                has_public_access = any(
                    ip_range.get("CidrIp") == "0.0.0.0/0" for ip_range in ip_ranges
                )

                if has_public_access:
                    # Check if port is in sensitive ports list
                    for port, port_info in sensitive_ports.items():
                        if from_port and to_port and from_port <= port <= to_port:
                            violation = {
                                "port": port,
                                "port_name": port_info["name"],
                                "severity": port_info["severity"],
                                "protocol": ip_protocol,
                                "from_port": from_port,
                                "to_port": to_port,
                                "cidr": "0.0.0.0/0",
                            }
                            sg_violations.append(violation)

                            # Update summary counts
                            results["summary"]["total_violations"] += 1
                            if port_info["severity"] == "CRITICAL":
                                results["summary"]["critical_violations"] += 1
                            elif port_info["severity"] == "HIGH":
                                results["summary"]["high_violations"] += 1
                            elif port_info["severity"] == "MEDIUM":
                                results["summary"]["medium_violations"] += 1

                            # Track violations by port
                            port_key = f"{port} ({port_info['name']})"
                            if port_key not in results["violations_by_port"]:
                                results["violations_by_port"][port_key] = []
                            results["violations_by_port"][port_key].append(
                                {
                                    "security_group": f"{group_name} ({group_id})",
                                    "vpc_id": vpc_id,
                                    "region": region,
                                    "account_name": account_name,
                                    "account_number": account_number,
                                }
                            )

            if sg_violations:
                results["security_groups_with_violations"].append(
                    {
                        "group_id": group_id,
                        "group_name": group_name,
                        "vpc_id": vpc_id,
                        "region": region,
                        "violations": sg_violations,
                        "account_name": account_name,
                        "account_number": account_number,
                    }
                )
                results["summary"]["security_groups_affected"].add(group_id)

        # Convert set to count
        results["summary"]["security_groups_affected"] = len(
            results["summary"]["security_groups_affected"]
        )

        results["recommendations"] = [
            "Remove 0.0.0.0/0 access from all sensitive ports",
            "Use specific IP ranges or security group references instead",
            "Implement a bastion host or VPN for SSH/RDP access",
            "Place databases in private subnets with no direct internet access",
            "Review and document all security group rules regularly",
            "Use AWS Systems Manager Session Manager for EC2 access instead of SSH",
        ]

        return results

    def _analyze_tag_compliance(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyse tag compliance across resources.

        Checks for required tags on:
        - EC2 instances
        - RDS instances
        - EBS volumes
        - S3 buckets
        - ECS clusters
        - EKS clusters
        - ECR repositories
        - Load balancers

        Args:
            params: Query parameters including:
                - scan_id: Optional scan ID filter
                - required_tags: List of required tag keys (default: ['Environment', 'Owner', 'CostCentre', 'Project'])

        Returns:
            Dictionary with tag compliance analysis
        """
        scan_id = params.get("scan_id")
        required_tags = params.get(
            "required_tags", ["Environment", "Owner", "CostCentre", "Project"]
        )

        results = {
            "summary": {
                "total_resources": 0,
                "compliant_resources": 0,
                "non_compliant_resources": 0,
                "compliance_percentage": 0.0,
                "required_tags": required_tags,
            },
            "non_compliant_by_type": {},
            "non_compliant_resources": [],
        }

        # Define resource types and their table/column structure. Table
        # objects replace the legacy f-string table-name interpolation;
        # table.c[colname] replaces the legacy column-name interpolation.
        resource_types = [
            ("EC2 Instance", t_ec2_instances, "instance_id", "region", "tags"),
            (
                "RDS Instance",
                t_rds_instances,
                "db_instance_identifier",
                "region",
                "tags",
            ),
            ("EBS Volume", t_ebs_volumes, "volume_id", "availability_zone", "tags"),
            ("S3 Bucket", t_s3_buckets, "bucket_name", "region", "tags"),
            ("ECS Cluster", t_ecs_clusters, "cluster_name", "region", "tags"),
            ("EKS Cluster", t_eks_clusters, "cluster_name", "region", "tags"),
            (
                "ECR Repository",
                t_ecr_repositories,
                "repository_name",
                "region",
                "tags",
            ),
            (
                "Load Balancer",
                t_load_balancers,
                "load_balancer_name",
                "availability_zones",
                "tags",
            ),
        ]

        with self.db_ops.engine.connect() as conn:
            for resource_type, table, id_col, location_col, tags_col in resource_types:
                stmt = sa.select(
                    table.c[id_col],
                    table.c[location_col],
                    table.c[tags_col],
                    t_scan_metadata.c.account_name,
                    t_scan_metadata.c.account_number,
                ).select_from(
                    table.join(
                        t_scan_metadata, table.c.scan_id == t_scan_metadata.c.scan_id
                    )
                )
                if scan_id:
                    stmt = stmt.where(table.c.scan_id == scan_id)

                for row in conn.execute(stmt):
                    identifier = row[0]
                    location = row[1]
                    tags = json.loads(row[2]) if row[2] else {}
                    account_name = row[3]
                    account_number = row[4]

                    results["summary"]["total_resources"] += 1

                    # Check for missing required tags
                    missing_tags = [tag for tag in required_tags if tag not in tags]

                    if missing_tags:
                        results["summary"]["non_compliant_resources"] += 1

                        # Track by resource type
                        if resource_type not in results["non_compliant_by_type"]:
                            results["non_compliant_by_type"][resource_type] = 0
                        results["non_compliant_by_type"][resource_type] += 1

                        results["non_compliant_resources"].append(
                            {
                                "resource_type": resource_type,
                                "identifier": identifier,
                                "location": location,
                                "missing_tags": missing_tags,
                                "existing_tags": list(tags.keys()),
                                "account_name": account_name,
                                "account_number": account_number,
                                "severity": "MEDIUM",
                            }
                        )
                    else:
                        results["summary"]["compliant_resources"] += 1

        # Calculate compliance percentage
        if results["summary"]["total_resources"] > 0:
            results["summary"]["compliance_percentage"] = (
                results["summary"]["compliant_resources"]
                / results["summary"]["total_resources"]
                * 100
            )

        results["recommendations"] = [
            f"Ensure all resources have required tags: {', '.join(required_tags)}",
            "Implement tag policies using AWS Organizations",
            "Use AWS Config rules to enforce tagging compliance",
            "Create automated remediation workflows for untagged resources",
            "Document tagging standards in organisation wiki",
            "Include tagging in infrastructure-as-code templates",
        ]

        return results

    def _analyze_container_vulnerabilities(
        self, params: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Analyse container vulnerabilities from ECR image scans.

        Parses image scan findings for:
        - CRITICAL severity vulnerabilities
        - HIGH severity vulnerabilities
        - MEDIUM severity vulnerabilities
        - LOW severity vulnerabilities

        Args:
            params: Query parameters including:
                - scan_id: Optional scan ID filter
                - severity_threshold: Minimum severity to report (default: 'MEDIUM')

        Returns:
            Dictionary with vulnerability analysis
        """
        scan_id = params.get("scan_id")
        severity_threshold = params.get("severity_threshold", "MEDIUM")

        # Severity ranking for filtering
        severity_rank = {
            "CRITICAL": 4,
            "HIGH": 3,
            "MEDIUM": 2,
            "LOW": 1,
            "INFORMATIONAL": 0,
        }

        threshold_rank = severity_rank.get(severity_threshold, 2)

        results = {
            "summary": {
                "total_images": 0,
                "vulnerable_images": 0,
                "total_critical": 0,
                "total_high": 0,
                "total_medium": 0,
                "total_low": 0,
            },
            "by_repository": {},
            "vulnerable_images": [],
        }

        # The legacy SQL selects img.image_tag, a column absent from the
        # ecr_images DDL (only image_tags exists). Kept verbatim via
        # sa.text() so the frozen "no such column: img.image_tag" baseline
        # error still fires; the raw sqlite3 error is re-raised so
        # handle_query's str(e) matches the frozen baseline exactly.
        query = """
            SELECT img.repository_name, img.image_tag, img.image_digest,
                   img.image_scan_status, img.image_scan_findings_summary,
                   img.region, sm.account_name, sm.account_number
            FROM ecr_images img
            INNER JOIN scan_metadata sm ON img.scan_id = sm.scan_id
            WHERE img.image_scan_status = 'COMPLETE'
        """
        query_params: Dict[str, Any] = {}
        if scan_id:
            query += " AND img.scan_id = :scan_id"
            query_params["scan_id"] = scan_id

        with self.db_ops.engine.connect() as conn:
            try:
                rows = conn.execute(sa.text(query), query_params).fetchall()
            except sa.exc.DBAPIError as e:
                raise e.orig from None

        for row in rows:
            repository_name = row[0]
            image_tag = row[1]
            image_digest = row[2]
            scan_status = row[3]
            findings_summary = json.loads(row[4]) if row[4] else {}
            region = row[5]
            account_name = row[6]
            account_number = row[7]

            results["summary"]["total_images"] += 1

            # Parse finding severity counts
            severity_counts = findings_summary.get("findingSeverityCounts", {})
            critical = severity_counts.get("CRITICAL", 0)
            high = severity_counts.get("HIGH", 0)
            medium = severity_counts.get("MEDIUM", 0)
            low = severity_counts.get("LOW", 0)

            # Update totals
            results["summary"]["total_critical"] += critical
            results["summary"]["total_high"] += high
            results["summary"]["total_medium"] += medium
            results["summary"]["total_low"] += low

            # Check if image meets severity threshold
            has_findings = False
            if threshold_rank <= 4 and critical > 0:
                has_findings = True
            if threshold_rank <= 3 and high > 0:
                has_findings = True
            if threshold_rank <= 2 and medium > 0:
                has_findings = True
            if threshold_rank <= 1 and low > 0:
                has_findings = True

            if has_findings:
                results["summary"]["vulnerable_images"] += 1

                # Track by repository
                if repository_name not in results["by_repository"]:
                    results["by_repository"][repository_name] = {
                        "vulnerable_images": 0,
                        "total_critical": 0,
                        "total_high": 0,
                        "total_medium": 0,
                        "total_low": 0,
                    }

                results["by_repository"][repository_name]["vulnerable_images"] += 1
                results["by_repository"][repository_name]["total_critical"] += critical
                results["by_repository"][repository_name]["total_high"] += high
                results["by_repository"][repository_name]["total_medium"] += medium
                results["by_repository"][repository_name]["total_low"] += low

                # Add to vulnerable images list
                severity = (
                    "CRITICAL"
                    if critical > 0
                    else "HIGH" if high > 0 else "MEDIUM" if medium > 0 else "LOW"
                )

                results["vulnerable_images"].append(
                    {
                        "repository_name": repository_name,
                        "image_tag": image_tag,
                        "image_digest": (
                            image_digest[:19] + "..." if image_digest else None
                        ),
                        "region": region,
                        "critical": critical,
                        "high": high,
                        "medium": medium,
                        "low": low,
                        "severity": severity,
                        "account_name": account_name,
                        "account_number": account_number,
                    }
                )

        results["recommendations"] = [
            "Scan all container images before deployment",
            "Implement automated remediation for CRITICAL and HIGH vulnerabilities",
            "Use minimal base images (e.g., Alpine, Distroless) to reduce attack surface",
            "Keep base images and dependencies up to date",
            "Implement image signing and verification",
            "Use ECR lifecycle policies to remove old vulnerable images",
            "Consider using Amazon Inspector for continuous vulnerability scanning",
        ]

        return results

    def _find_vpc_endpoint_opportunities(
        self, params: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Find VPC endpoint opportunities for cost savings.

        Identifies VPCs that could benefit from VPC endpoints for:
        - S3 (Gateway endpoint - free)
        - DynamoDB (Gateway endpoint - free)
        - ECR (Interface endpoint - $0.01/hour)
        - ECS (Interface endpoint - $0.01/hour)

        Args:
            params: Query parameters including optional scan_id filter

        Returns:
            Dictionary with VPC endpoint opportunities
        """
        scan_id = params.get("scan_id")

        results = {
            "summary": {
                "total_vpcs": 0,
                "vpcs_with_opportunities": 0,
                "potential_monthly_savings": 0.0,
            },
            "endpoint_opportunities": [],
        }

        with self.db_ops.engine.connect() as conn:
            # Get all VPCs
            vpc_stmt = sa.select(
                t_vpcs.c.vpc_id,
                t_vpcs.c.region,
                t_scan_metadata.c.account_name,
                t_scan_metadata.c.account_number,
                t_vpcs.c.scan_id,
            ).select_from(
                t_vpcs.join(
                    t_scan_metadata, t_vpcs.c.scan_id == t_scan_metadata.c.scan_id
                )
            )
            if scan_id:
                vpc_stmt = vpc_stmt.where(t_vpcs.c.scan_id == scan_id)

            vpcs = conn.execute(vpc_stmt).fetchall()
            results["summary"]["total_vpcs"] = len(vpcs)

            for vpc_row in vpcs:
                vpc_id = vpc_row[0]
                region = vpc_row[1]
                account_name = vpc_row[2]
                account_number = vpc_row[3]
                vpc_scan_id = vpc_row[4]

                opportunities = {"s3": False, "ecr": False, "ecs": False}

                # Check for S3 buckets in same account
                s3_count = conn.execute(
                    sa.select(sa.func.count())
                    .select_from(t_s3_buckets)
                    .where(t_s3_buckets.c.scan_id == vpc_scan_id)
                ).scalar()
                if s3_count > 0:
                    opportunities["s3"] = True

                # Check for ECS services in this VPC
                ecs_count = conn.execute(
                    sa.select(sa.func.count())
                    .select_from(
                        t_ecs_services.join(
                            t_ecs_clusters,
                            t_ecs_services.c.cluster_arn
                            == t_ecs_clusters.c.cluster_arn,
                        )
                    )
                    .where(
                        t_ecs_services.c.scan_id == vpc_scan_id,
                        t_ecs_clusters.c.region == region,
                    )
                ).scalar()
                if ecs_count > 0:
                    opportunities["ecs"] = True
                    opportunities["ecr"] = True  # ECS typically uses ECR

                # Check for EKS clusters in this region
                eks_count = conn.execute(
                    sa.select(sa.func.count())
                    .select_from(t_eks_clusters)
                    .where(
                        t_eks_clusters.c.scan_id == vpc_scan_id,
                        t_eks_clusters.c.region == region,
                    )
                ).scalar()
                if eks_count > 0:
                    opportunities["ecr"] = True

                # Check for EC2 instances in this VPC
                ec2_count = conn.execute(
                    sa.select(sa.func.count())
                    .select_from(t_ec2_instances)
                    .where(
                        t_ec2_instances.c.scan_id == vpc_scan_id,
                        t_ec2_instances.c.vpc_id == vpc_id,
                    )
                ).scalar()

                # Calculate potential savings
                has_opportunities = any(opportunities.values())

                if has_opportunities:
                    results["summary"]["vpcs_with_opportunities"] += 1

                    estimated_savings = 0.0
                    recommendations = []

                    if opportunities["s3"]:
                        recommendations.append(
                            "S3 Gateway Endpoint (Free - eliminates data transfer costs)"
                        )
                        # Estimate $0.09/GB savings on data transfer (conservative estimate of 100GB/month)
                        estimated_savings += 9.0

                    if opportunities["ecr"]:
                        recommendations.append(
                            "ECR Interface Endpoint ($7.20/month - reduces data transfer costs)"
                        )
                        # $0.01/hour = $7.20/month, savings from data transfer can offset this
                        estimated_savings += 5.0  # Conservative net savings

                    if opportunities["ecs"]:
                        recommendations.append(
                            "ECS Interface Endpoints ($7.20/month each for ecs, ecs-telemetry, ecs-agent)"
                        )
                        # Multiple endpoints needed but significant data transfer savings
                        estimated_savings += 10.0

                    results["endpoint_opportunities"].append(
                        {
                            "vpc_id": vpc_id,
                            "region": region,
                            "account_name": account_name,
                            "account_number": account_number,
                            "opportunities": opportunities,
                            "ec2_instances": ec2_count,
                            "ecs_services": ecs_count,
                            "eks_clusters": eks_count,
                            "s3_buckets": s3_count,
                            "estimated_monthly_savings": round(estimated_savings, 2),
                            "recommendations": recommendations,
                        }
                    )

                    results["summary"]["potential_monthly_savings"] += estimated_savings

        results["summary"]["potential_monthly_savings"] = round(
            results["summary"]["potential_monthly_savings"], 2
        )

        results["recommendations"] = [
            "Create S3 Gateway Endpoints for all VPCs (free and eliminates NAT charges)",
            "Create DynamoDB Gateway Endpoints where applicable (free)",
            "Consider Interface Endpoints for high-traffic services (ECR, ECS, etc.)",
            "Monitor VPC Flow Logs to identify high data transfer to AWS services",
            "Use VPC Endpoint policies to control access",
            "Implement VPC endpoints in infrastructure-as-code templates",
        ]

        return results

    # Phase 3: Governance, Logging & Advanced Services Query Handlers

    def _get_organizations_structure(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Get AWS Organizations structure including OUs and accounts.

        Args:
            params: Query parameters (scan_id optional)

        Returns:
            Organization structure with OUs and accounts
        """
        scan_id = params.get("scan_id")

        results = {
            "organizations": [],
            "organizational_units": [],
            "accounts": [],
            "summary": {"total_accounts": 0, "total_ous": 0, "feature_set": None},
        }

        # Get organization details
        org_stmt = sa.select(
            t_organizations.c.organization_id,
            t_organizations.c.organization_arn,
            t_organizations.c.master_account_id,
            t_organizations.c.master_account_email,
            t_organizations.c.feature_set,
            t_organizations.c.available_policy_types,
            t_organizations.c.scan_id,
        )
        if scan_id:
            org_stmt = org_stmt.where(t_organizations.c.scan_id == scan_id)
        else:
            org_stmt = org_stmt.order_by(t_organizations.c.created_at.desc()).limit(1)

        with self.db_ops.engine.connect() as conn:
            for row in conn.execute(org_stmt):
                org_data = {
                    "organization_id": row[0],
                    "organization_arn": row[1],
                    "master_account_id": row[2],
                    "master_account_email": row[3],
                    "feature_set": row[4],
                    "available_policy_types": json.loads(row[5]) if row[5] else [],
                    "scan_id": row[6],
                }
                results["organizations"].append(org_data)
                results["summary"]["feature_set"] = row[4]

                org_scan_id = row[6]

                # Get organizational units for this organization
                ou_stmt = (
                    sa.select(
                        t_organizational_units.c.ou_id,
                        t_organizational_units.c.ou_arn,
                        t_organizational_units.c.ou_name,
                        t_organizational_units.c.parent_id,
                    )
                    .where(t_organizational_units.c.scan_id == org_scan_id)
                    .order_by(t_organizational_units.c.ou_name)
                )

                for ou_row in conn.execute(ou_stmt):
                    results["organizational_units"].append(
                        {
                            "ou_id": ou_row[0],
                            "ou_arn": ou_row[1],
                            "ou_name": ou_row[2],
                            "parent_id": ou_row[3],
                        }
                    )

                # Get accounts for this organization
                accounts_stmt = (
                    sa.select(
                        t_organization_accounts.c.account_id,
                        t_organization_accounts.c.account_arn,
                        t_organization_accounts.c.email,
                        t_organization_accounts.c.account_name,
                        t_organization_accounts.c.status,
                        t_organization_accounts.c.joined_method,
                        t_organization_accounts.c.joined_timestamp,
                    )
                    .where(t_organization_accounts.c.scan_id == org_scan_id)
                    .order_by(t_organization_accounts.c.account_name)
                )

                for acct_row in conn.execute(accounts_stmt):
                    results["accounts"].append(
                        {
                            "account_id": acct_row[0],
                            "account_arn": acct_row[1],
                            "account_email": acct_row[2],
                            "account_name": acct_row[3],
                            "status": acct_row[4],
                            "joined_method": acct_row[5],
                            "joined_timestamp": acct_row[6],
                        }
                    )

        results["summary"]["total_accounts"] = len(results["accounts"])
        results["summary"]["total_ous"] = len(results["organizational_units"])

        return results

    def _get_sso_permissions(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Get AWS SSO/Identity Center permission sets and assignments.

        Args:
            params: Query parameters (scan_id optional, account_id optional)

        Returns:
            SSO permission sets and assignments
        """
        scan_id = params.get("scan_id")
        account_id = params.get("account_id")

        results = {
            "permission_sets": [],
            "assignments": [],
            "summary": {
                "total_permission_sets": 0,
                "total_assignments": 0,
                "accounts_with_assignments": set(),
            },
        }

        # Get permission sets
        ps_stmt = sa.select(
            t_sso_permission_sets.c.permission_set_arn,
            t_sso_permission_sets.c.permission_set_name,
            t_sso_permission_sets.c.description,
            t_sso_permission_sets.c.instance_arn,
            t_sso_permission_sets.c.session_duration,
            t_sso_permission_sets.c.relay_state,
            t_sso_permission_sets.c.managed_policies,
            t_sso_permission_sets.c.inline_policy,
            t_sso_permission_sets.c.scan_id,
        )
        if scan_id:
            ps_stmt = ps_stmt.where(t_sso_permission_sets.c.scan_id == scan_id)

        # Get assignments
        assignment_stmt = sa.select(
            t_sso_assignments.c.instance_arn,
            t_sso_assignments.c.permission_set_arn,
            t_sso_assignments.c.target_id,
            t_sso_assignments.c.principal_type,
            t_sso_assignments.c.principal_id,
        )
        assignment_conditions = []
        if scan_id:
            assignment_conditions.append(t_sso_assignments.c.scan_id == scan_id)
        if account_id:
            assignment_conditions.append(t_sso_assignments.c.target_id == account_id)
        if assignment_conditions:
            assignment_stmt = assignment_stmt.where(*assignment_conditions)

        with self.db_ops.engine.connect() as conn:
            for row in conn.execute(ps_stmt):
                ps_data = {
                    "permission_set_arn": row[0],
                    "permission_set_name": row[1],
                    "description": row[2],
                    "instance_arn": row[3],
                    "session_duration": row[4],
                    "relay_state": row[5],
                    "managed_policies": json.loads(row[6]) if row[6] else [],
                    "has_inline_policy": row[7] is not None,
                    "scan_id": row[8],
                }
                results["permission_sets"].append(ps_data)

            for row in conn.execute(assignment_stmt):
                results["assignments"].append(
                    {
                        "instance_arn": row[0],
                        "permission_set_arn": row[1],
                        "account_id": row[2],
                        "principal_type": row[3],
                        "principal_id": row[4],
                    }
                )
                results["summary"]["accounts_with_assignments"].add(row[2])

        results["summary"]["total_permission_sets"] = len(results["permission_sets"])
        results["summary"]["total_assignments"] = len(results["assignments"])
        results["summary"]["total_accounts_with_assignments"] = len(
            results["summary"]["accounts_with_assignments"]
        )
        results["summary"]["accounts_with_assignments"] = list(
            results["summary"]["accounts_with_assignments"]
        )

        return results

    def _analyze_cloudtrail_coverage(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze CloudTrail coverage and compliance.

        Args:
            params: Query parameters (scan_id optional)

        Returns:
            CloudTrail coverage analysis
        """
        scan_id = params.get("scan_id")

        results = {
            "trails": [],
            "summary": {
                "total_trails": 0,
                "multi_region_trails": 0,
                "organization_trails": 0,
                "logging_enabled": 0,
                "log_file_validation_enabled": 0,
                "kms_encrypted": 0,
                "cloudwatch_logs_integration": 0,
                "regions_covered": set(),
                "compliance_issues": [],
            },
        }

        # The legacy SQL selects cloudtrail_trails.log_file_validation_enabled, a
        # column absent from the DDL (src/cloudledger/database/tables.py has no
        # such column on t_cloudtrail_trails). Kept verbatim via sa.text() so the
        # frozen "no such column: log_file_validation_enabled" baseline error
        # still fires; the raw sqlite3 error is re-raised so handle_query's
        # str(e) matches the frozen baseline exactly.
        condition = "WHERE scan_id = :scan_id" if scan_id else ""
        stmt = sa.text(f"""
            SELECT trail_arn, trail_name, region, s3_bucket_name,
                   is_multi_region_trail, is_organization_trail, is_logging,
                   log_file_validation_enabled, kms_key_id,
                   cloud_watch_logs_log_group_arn, home_region
            FROM cloudtrail_trails
            {condition}
        """)

        with self.db_ops.engine.connect() as conn:
            try:
                rows = conn.execute(
                    stmt, {"scan_id": scan_id} if scan_id else {}
                ).fetchall()
            except sa.exc.DBAPIError as e:
                raise e.orig from None

            for row in rows:
                trail_data = {
                    "trail_arn": row[0],
                    "trail_name": row[1],
                    "region": row[2],
                    "s3_bucket_name": row[3],
                    "is_multi_region": bool(row[4]),
                    "is_organization_trail": bool(row[5]),
                    "is_logging": bool(row[6]),
                    "log_file_validation_enabled": bool(row[7]),
                    "kms_encrypted": row[8] is not None,
                    "cloudwatch_logs_enabled": row[9] is not None,
                    "home_region": row[10],
                }
                results["trails"].append(trail_data)

                results["summary"]["total_trails"] += 1
                if trail_data["is_multi_region"]:
                    results["summary"]["multi_region_trails"] += 1
                if trail_data["is_organization_trail"]:
                    results["summary"]["organization_trails"] += 1
                if trail_data["is_logging"]:
                    results["summary"]["logging_enabled"] += 1
                if trail_data["log_file_validation_enabled"]:
                    results["summary"]["log_file_validation_enabled"] += 1
                if trail_data["kms_encrypted"]:
                    results["summary"]["kms_encrypted"] += 1
                if trail_data["cloudwatch_logs_enabled"]:
                    results["summary"]["cloudwatch_logs_integration"] += 1

                results["summary"]["regions_covered"].add(row[2])

                # Check for compliance issues
                if not trail_data["is_logging"]:
                    results["summary"]["compliance_issues"].append(
                        {
                            "trail": trail_data["trail_name"],
                            "issue": "Trail logging is disabled",
                            "severity": "HIGH",
                        }
                    )
                if not trail_data["log_file_validation_enabled"]:
                    results["summary"]["compliance_issues"].append(
                        {
                            "trail": trail_data["trail_name"],
                            "issue": "Log file validation is not enabled",
                            "severity": "MEDIUM",
                        }
                    )
                if not trail_data["kms_encrypted"]:
                    results["summary"]["compliance_issues"].append(
                        {
                            "trail": trail_data["trail_name"],
                            "issue": "CloudTrail logs are not encrypted with KMS",
                            "severity": "MEDIUM",
                        }
                    )

            results["summary"]["regions_covered"] = list(
                results["summary"]["regions_covered"]
            )
            results["summary"]["total_compliance_issues"] = len(
                results["summary"]["compliance_issues"]
            )

        return results

    def _analyze_logging_coverage(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze CloudWatch Logs and AWS Config coverage.

        Args:
            params: Query parameters (scan_id optional)

        Returns:
            Logging and Config coverage analysis
        """
        scan_id = params.get("scan_id")

        results = {
            "cloudwatch_log_groups": [],
            "config_recorders": [],
            "config_rules": [],
            "summary": {
                "total_log_groups": 0,
                "total_stored_bytes": 0,
                "log_groups_with_retention": 0,
                "log_groups_with_kms": 0,
                "total_config_recorders": 0,
                "config_recorders_recording": 0,
                "total_config_rules": 0,
                "compliant_rules": 0,
                "non_compliant_rules": 0,
            },
        }

        log_groups_stmt = sa.select(
            t_cloudwatch_log_groups.c.log_group_name,
            t_cloudwatch_log_groups.c.region,
            t_cloudwatch_log_groups.c.retention_in_days,
            t_cloudwatch_log_groups.c.stored_bytes,
            t_cloudwatch_log_groups.c.kms_key_id,
        )
        recorders_stmt = sa.select(
            t_config_recorders.c.recorder_name,
            t_config_recorders.c.region,
            t_config_recorders.c.role_arn,
            t_config_recorders.c.is_recording,
            t_config_recorders.c.last_status,
        )
        rules_stmt = sa.select(
            t_config_rules.c.rule_name,
            t_config_rules.c.region,
            t_config_rules.c.config_rule_state,
            t_config_rules.c.compliance_type,
        )
        if scan_id:
            log_groups_stmt = log_groups_stmt.where(
                t_cloudwatch_log_groups.c.scan_id == scan_id
            )
            recorders_stmt = recorders_stmt.where(
                t_config_recorders.c.scan_id == scan_id
            )
            rules_stmt = rules_stmt.where(t_config_rules.c.scan_id == scan_id)

        with self.db_ops.engine.connect() as conn:
            # Analyze CloudWatch Log Groups
            for row in conn.execute(log_groups_stmt):
                log_group_data = {
                    "log_group_name": row[0],
                    "region": row[1],
                    "retention_in_days": row[2],
                    "stored_bytes": row[3] or 0,
                    "has_kms_encryption": row[4] is not None,
                }
                results["cloudwatch_log_groups"].append(log_group_data)

                results["summary"]["total_log_groups"] += 1
                results["summary"]["total_stored_bytes"] += log_group_data[
                    "stored_bytes"
                ]
                if log_group_data["retention_in_days"]:
                    results["summary"]["log_groups_with_retention"] += 1
                if log_group_data["has_kms_encryption"]:
                    results["summary"]["log_groups_with_kms"] += 1

            # Analyze Config Recorders
            for row in conn.execute(recorders_stmt):
                results["config_recorders"].append(
                    {
                        "recorder_name": row[0],
                        "region": row[1],
                        "role_arn": row[2],
                        "is_recording": bool(row[3]),
                        "last_status": row[4],
                    }
                )

                results["summary"]["total_config_recorders"] += 1
                if bool(row[3]):
                    results["summary"]["config_recorders_recording"] += 1

            # Analyze Config Rules
            for row in conn.execute(rules_stmt):
                results["config_rules"].append(
                    {
                        "rule_name": row[0],
                        "region": row[1],
                        "state": row[2],
                        "compliance_type": row[3],
                    }
                )

                results["summary"]["total_config_rules"] += 1
                if row[3] == "COMPLIANT":
                    results["summary"]["compliant_rules"] += 1
                elif row[3] == "NON_COMPLIANT":
                    results["summary"]["non_compliant_rules"] += 1

        # Convert stored bytes to GB for readability
        results["summary"]["total_stored_gb"] = round(
            results["summary"]["total_stored_bytes"] / (1024**3), 2
        )

        return results

    def _get_bedrock_resources(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Get Amazon Bedrock resources (models, guardrails, agents, knowledge bases).

        Args:
            params: Query parameters (scan_id optional, region optional)

        Returns:
            Bedrock resources summary
        """
        scan_id = params.get("scan_id")
        region = params.get("region")

        results = {
            "models": [],
            "guardrails": [],
            "knowledge_bases": [],
            "agents": [],
            "summary": {
                "total_models": 0,
                "models_by_provider": {},
                "total_guardrails": 0,
                "total_knowledge_bases": 0,
                "total_agents": 0,
                "regions": set(),
            },
        }

        # The legacy SQL selects bedrock_models.model_lifecycle_status, a column
        # absent from the DDL (t_bedrock_models has no such column). Kept
        # verbatim via sa.text() so the frozen "no such column:
        # model_lifecycle_status" baseline error still fires; the raw sqlite3
        # error is re-raised so handle_query's str(e) matches the frozen
        # baseline exactly. As in the legacy code, this query runs first, so
        # the guardrails/knowledge-bases/agents sections below never execute
        # while the DDL mismatch stands.
        conditions_sql = []
        text_params = {}
        if scan_id:
            conditions_sql.append("scan_id = :scan_id")
            text_params["scan_id"] = scan_id
        if region:
            conditions_sql.append("region = :region")
            text_params["region"] = region
        condition = f"WHERE {' AND '.join(conditions_sql)}" if conditions_sql else ""

        models_stmt = sa.text(f"""
            SELECT model_id, model_name, region, provider_name,
                   input_modalities, output_modalities, model_lifecycle_status
            FROM bedrock_models
            {condition}
        """)

        guardrails_stmt = sa.select(
            t_bedrock_guardrails.c.guardrail_id,
            t_bedrock_guardrails.c.guardrail_name,
            t_bedrock_guardrails.c.region,
            t_bedrock_guardrails.c.description,
            t_bedrock_guardrails.c.status,
        )
        knowledge_bases_stmt = sa.select(
            t_bedrock_knowledge_bases.c.knowledge_base_id,
            t_bedrock_knowledge_bases.c.knowledge_base_name,
            t_bedrock_knowledge_bases.c.region,
            t_bedrock_knowledge_bases.c.description,
            t_bedrock_knowledge_bases.c.status,
        )
        agents_stmt = sa.select(
            t_bedrock_agents.c.agent_id,
            t_bedrock_agents.c.agent_name,
            t_bedrock_agents.c.region,
            t_bedrock_agents.c.description,
            t_bedrock_agents.c.agent_status,
            t_bedrock_agents.c.foundation_model,
        )
        if scan_id:
            guardrails_stmt = guardrails_stmt.where(
                t_bedrock_guardrails.c.scan_id == scan_id
            )
            knowledge_bases_stmt = knowledge_bases_stmt.where(
                t_bedrock_knowledge_bases.c.scan_id == scan_id
            )
            agents_stmt = agents_stmt.where(t_bedrock_agents.c.scan_id == scan_id)
        if region:
            guardrails_stmt = guardrails_stmt.where(
                t_bedrock_guardrails.c.region == region
            )
            knowledge_bases_stmt = knowledge_bases_stmt.where(
                t_bedrock_knowledge_bases.c.region == region
            )
            agents_stmt = agents_stmt.where(t_bedrock_agents.c.region == region)

        with self.db_ops.engine.connect() as conn:
            # Get Bedrock Models
            try:
                model_rows = conn.execute(models_stmt, text_params).fetchall()
            except sa.exc.DBAPIError as e:
                raise e.orig from None

            for row in model_rows:
                model_data = {
                    "model_id": row[0],
                    "model_name": row[1],
                    "region": row[2],
                    "provider_name": row[3],
                    "input_modalities": json.loads(row[4]) if row[4] else [],
                    "output_modalities": json.loads(row[5]) if row[5] else [],
                    "lifecycle_status": row[6],
                }
                results["models"].append(model_data)

                results["summary"]["total_models"] += 1
                provider = row[3]
                results["summary"]["models_by_provider"][provider] = (
                    results["summary"]["models_by_provider"].get(provider, 0) + 1
                )
                results["summary"]["regions"].add(row[2])

            # Get Bedrock Guardrails
            for row in conn.execute(guardrails_stmt):
                results["guardrails"].append(
                    {
                        "guardrail_id": row[0],
                        "guardrail_name": row[1],
                        "region": row[2],
                        "description": row[3],
                        "status": row[4],
                    }
                )
                results["summary"]["total_guardrails"] += 1

            # Get Bedrock Knowledge Bases
            for row in conn.execute(knowledge_bases_stmt):
                results["knowledge_bases"].append(
                    {
                        "knowledge_base_id": row[0],
                        "knowledge_base_name": row[1],
                        "region": row[2],
                        "description": row[3],
                        "status": row[4],
                    }
                )
                results["summary"]["total_knowledge_bases"] += 1

            # Get Bedrock Agents
            for row in conn.execute(agents_stmt):
                results["agents"].append(
                    {
                        "agent_id": row[0],
                        "agent_name": row[1],
                        "region": row[2],
                        "description": row[3],
                        "status": row[4],
                        "foundation_model": row[5],
                    }
                )
                results["summary"]["total_agents"] += 1

        results["summary"]["regions"] = list(results["summary"]["regions"])

        return results

    def _analyze_network_connectivity(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze network connectivity (Transit Gateways, VPN, Direct Connect).

        Args:
            params: Query parameters (scan_id optional)

        Returns:
            Network connectivity analysis
        """
        scan_id = params.get("scan_id")

        results = {
            "transit_gateways": [],
            "vpn_connections": [],
            "direct_connect_connections": [],
            "summary": {
                "total_transit_gateways": 0,
                "total_vpn_connections": 0,
                "active_vpn_connections": 0,
                "total_direct_connect_connections": 0,
                "active_direct_connect_connections": 0,
                "connectivity_types": [],
            },
        }

        transit_gateways_stmt = sa.select(
            t_transit_gateways.c.transit_gateway_id,
            t_transit_gateways.c.region,
            t_transit_gateways.c.state,
            t_transit_gateways.c.owner_id,
            t_transit_gateways.c.description,
        )
        vpn_stmt = sa.select(
            t_vpn_connections.c.vpn_connection_id,
            t_vpn_connections.c.region,
            t_vpn_connections.c.state,
            t_vpn_connections.c.vpn_gateway_id,
            t_vpn_connections.c.transit_gateway_id,
            t_vpn_connections.c.customer_gateway_id,
            t_vpn_connections.c.vpn_connection_type,
        )
        dx_stmt = sa.select(
            t_direct_connect_connections.c.connection_id,
            t_direct_connect_connections.c.connection_name,
            t_direct_connect_connections.c.region,
            t_direct_connect_connections.c.connection_state,
            t_direct_connect_connections.c.location,
            t_direct_connect_connections.c.bandwidth,
            t_direct_connect_connections.c.provider_name,
        )
        if scan_id:
            transit_gateways_stmt = transit_gateways_stmt.where(
                t_transit_gateways.c.scan_id == scan_id
            )
            vpn_stmt = vpn_stmt.where(t_vpn_connections.c.scan_id == scan_id)
            dx_stmt = dx_stmt.where(t_direct_connect_connections.c.scan_id == scan_id)

        with self.db_ops.engine.connect() as conn:
            # Get Transit Gateways
            for row in conn.execute(transit_gateways_stmt):
                results["transit_gateways"].append(
                    {
                        "transit_gateway_id": row[0],
                        "region": row[1],
                        "state": row[2],
                        "owner_id": row[3],
                        "description": row[4],
                    }
                )
                results["summary"]["total_transit_gateways"] += 1

            # Get VPN Connections
            for row in conn.execute(vpn_stmt):
                vpn_data = {
                    "vpn_connection_id": row[0],
                    "region": row[1],
                    "state": row[2],
                    "vpn_gateway_id": row[3],
                    "transit_gateway_id": row[4],
                    "customer_gateway_id": row[5],
                    "type": row[6],
                }
                results["vpn_connections"].append(vpn_data)

                results["summary"]["total_vpn_connections"] += 1
                if row[2] == "available":
                    results["summary"]["active_vpn_connections"] += 1

            # Get Direct Connect Connections
            for row in conn.execute(dx_stmt):
                dx_data = {
                    "connection_id": row[0],
                    "connection_name": row[1],
                    "region": row[2],
                    "connection_state": row[3],
                    "location": row[4],
                    "bandwidth": row[5],
                    "provider_name": row[6],
                }
                results["direct_connect_connections"].append(dx_data)

                results["summary"]["total_direct_connect_connections"] += 1
                if row[3] == "available":
                    results["summary"]["active_direct_connect_connections"] += 1

        # Determine connectivity types in use
        if results["summary"]["total_transit_gateways"] > 0:
            results["summary"]["connectivity_types"].append("Transit Gateway")
        if results["summary"]["total_vpn_connections"] > 0:
            results["summary"]["connectivity_types"].append("VPN")
        if results["summary"]["total_direct_connect_connections"] > 0:
            results["summary"]["connectivity_types"].append("Direct Connect")

        return results

    def _get_directory_services(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Get AWS Directory Service configurations.

        Args:
            params: Query parameters (scan_id optional, region optional)

        Returns:
            Directory services summary
        """
        scan_id = params.get("scan_id")
        region = params.get("region")

        results = {
            "directories": [],
            "summary": {
                "total_directories": 0,
                "directories_by_type": {},
                "directories_by_size": {},
                "sso_enabled_count": 0,
                "regions": set(),
            },
        }

        stmt = sa.select(
            t_directory_services.c.directory_id,
            t_directory_services.c.directory_name,
            t_directory_services.c.region,
            t_directory_services.c.directory_type,
            t_directory_services.c.size,
            t_directory_services.c.edition,
            t_directory_services.c.access_url,
            t_directory_services.c.stage,
            t_directory_services.c.sso_enabled,
        )
        conditions = []
        if scan_id:
            conditions.append(t_directory_services.c.scan_id == scan_id)
        if region:
            conditions.append(t_directory_services.c.region == region)
        if conditions:
            stmt = stmt.where(*conditions)

        with self.db_ops.engine.connect() as conn:
            for row in conn.execute(stmt):
                dir_data = {
                    "directory_id": row[0],
                    "directory_name": row[1],
                    "region": row[2],
                    "directory_type": row[3],
                    "size": row[4],
                    "edition": row[5],
                    "access_url": row[6],
                    "stage": row[7],
                    "sso_enabled": bool(row[8]),
                }
                results["directories"].append(dir_data)

                results["summary"]["total_directories"] += 1

                dir_type = row[3]
                results["summary"]["directories_by_type"][dir_type] = (
                    results["summary"]["directories_by_type"].get(dir_type, 0) + 1
                )

                if row[4]:
                    results["summary"]["directories_by_size"][row[4]] = (
                        results["summary"]["directories_by_size"].get(row[4], 0) + 1
                    )

                if bool(row[8]):
                    results["summary"]["sso_enabled_count"] += 1

                results["summary"]["regions"].add(row[2])

        results["summary"]["regions"] = list(results["summary"]["regions"])

        return results

    def _analyze_managed_services(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze managed services (ElastiCache, OpenSearch, MSK, DynamoDB).

        Args:
            params: Query parameters (scan_id optional, region optional)

        Returns:
            Managed services analysis
        """
        scan_id = params.get("scan_id")
        region = params.get("region")

        results = {
            "elasticache_clusters": [],
            "opensearch_domains": [],
            "msk_clusters": [],
            "dynamodb_tables": [],
            "summary": {
                "total_elasticache_clusters": 0,
                "elasticache_by_engine": {},
                "total_opensearch_domains": 0,
                "total_msk_clusters": 0,
                "total_dynamodb_tables": 0,
                "dynamodb_by_billing_mode": {},
                "encryption_coverage": {
                    "elasticache_encrypted": 0,
                    "opensearch_encrypted": 0,
                    "dynamodb_encrypted": 0,
                },
            },
        }

        elasticache_stmt = sa.select(
            t_elasticache_clusters.c.cache_cluster_id,
            t_elasticache_clusters.c.region,
            t_elasticache_clusters.c.cache_cluster_status,
            t_elasticache_clusters.c.engine,
            t_elasticache_clusters.c.engine_version,
            t_elasticache_clusters.c.cache_node_type,
            t_elasticache_clusters.c.num_cache_nodes,
            t_elasticache_clusters.c.transit_encryption_enabled,
            t_elasticache_clusters.c.at_rest_encryption_enabled,
        )
        opensearch_stmt = sa.select(
            t_opensearch_domains.c.domain_name,
            t_opensearch_domains.c.region,
            t_opensearch_domains.c.engine_version,
            t_opensearch_domains.c.endpoint,
            t_opensearch_domains.c.created,
            t_opensearch_domains.c.deleted,
            t_opensearch_domains.c.processing,
        )
        msk_stmt = sa.select(
            t_msk_clusters.c.cluster_name,
            t_msk_clusters.c.region,
            t_msk_clusters.c.cluster_type,
            t_msk_clusters.c.state,
            t_msk_clusters.c.current_version,
            t_msk_clusters.c.number_of_broker_nodes,
        )
        if scan_id:
            elasticache_stmt = elasticache_stmt.where(
                t_elasticache_clusters.c.scan_id == scan_id
            )
            opensearch_stmt = opensearch_stmt.where(
                t_opensearch_domains.c.scan_id == scan_id
            )
            msk_stmt = msk_stmt.where(t_msk_clusters.c.scan_id == scan_id)
        if region:
            elasticache_stmt = elasticache_stmt.where(
                t_elasticache_clusters.c.region == region
            )
            opensearch_stmt = opensearch_stmt.where(
                t_opensearch_domains.c.region == region
            )
            msk_stmt = msk_stmt.where(t_msk_clusters.c.region == region)

        # The legacy SQL selects dynamodb_tables.billing_mode, a column absent
        # from the DDL (t_dynamodb_tables has billing_mode_summary, not
        # billing_mode). Kept verbatim via sa.text() so the frozen "no such
        # column: billing_mode" baseline error still fires; the raw sqlite3
        # error is re-raised so handle_query's str(e) matches the frozen
        # baseline exactly. As in the legacy code, this query runs last, so
        # its failure discards the elasticache/opensearch/msk results already
        # gathered above (the exception propagates past this method entirely).
        conditions_sql = []
        text_params = {}
        if scan_id:
            conditions_sql.append("scan_id = :scan_id")
            text_params["scan_id"] = scan_id
        if region:
            conditions_sql.append("region = :region")
            text_params["region"] = region
        condition = f"WHERE {' AND '.join(conditions_sql)}" if conditions_sql else ""

        dynamodb_stmt = sa.text(f"""
            SELECT table_name, region, table_status, billing_mode,
                   table_size_bytes, item_count, deletion_protection_enabled
            FROM dynamodb_tables
            {condition}
        """)

        with self.db_ops.engine.connect() as conn:
            # Get ElastiCache Clusters
            for row in conn.execute(elasticache_stmt):
                cluster_data = {
                    "cache_cluster_id": row[0],
                    "region": row[1],
                    "status": row[2],
                    "engine": row[3],
                    "engine_version": row[4],
                    "node_type": row[5],
                    "num_nodes": row[6],
                    "transit_encryption_enabled": bool(row[7]),
                    "at_rest_encryption_enabled": bool(row[8]),
                }
                results["elasticache_clusters"].append(cluster_data)

                results["summary"]["total_elasticache_clusters"] += 1
                engine = row[3]
                results["summary"]["elasticache_by_engine"][engine] = (
                    results["summary"]["elasticache_by_engine"].get(engine, 0) + 1
                )

                if bool(row[7]) and bool(row[8]):
                    results["summary"]["encryption_coverage"][
                        "elasticache_encrypted"
                    ] += 1

            # Get OpenSearch Domains
            for row in conn.execute(opensearch_stmt):
                results["opensearch_domains"].append(
                    {
                        "domain_name": row[0],
                        "region": row[1],
                        "engine_version": row[2],
                        "endpoint": row[3],
                        "created": bool(row[4]),
                        "deleted": bool(row[5]),
                        "processing": bool(row[6]),
                    }
                )
                results["summary"]["total_opensearch_domains"] += 1

            # Get MSK Clusters
            for row in conn.execute(msk_stmt):
                results["msk_clusters"].append(
                    {
                        "cluster_name": row[0],
                        "region": row[1],
                        "cluster_type": row[2],
                        "state": row[3],
                        "kafka_version": row[4],
                        "broker_nodes": row[5],
                    }
                )
                results["summary"]["total_msk_clusters"] += 1

            # Get DynamoDB Tables
            try:
                dynamodb_rows = conn.execute(dynamodb_stmt, text_params).fetchall()
            except sa.exc.DBAPIError as e:
                raise e.orig from None

            for row in dynamodb_rows:
                table_data = {
                    "table_name": row[0],
                    "region": row[1],
                    "status": row[2],
                    "billing_mode": row[3],
                    "size_bytes": row[4] or 0,
                    "item_count": row[5] or 0,
                    "deletion_protection_enabled": bool(row[6]),
                }
                results["dynamodb_tables"].append(table_data)

                results["summary"]["total_dynamodb_tables"] += 1
                billing_mode = row[3]
                results["summary"]["dynamodb_by_billing_mode"][billing_mode] = (
                    results["summary"]["dynamodb_by_billing_mode"].get(billing_mode, 0)
                    + 1
                )

        return results

    def _get_organizations_cost_breakdown(
        self, params: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Get cost breakdown specifically for AWS Organizations environments.

        This query provides clear separation between master/payer account costs
        and member account costs, addressing consolidated billing confusion.
        """
        scan_id = params.get("scan_id")

        results = {
            "organization_info": {},
            "master_account_costs": {},
            "member_accounts": [],
            "cost_summary": {
                "total_all_accounts": 0.0,
                "total_member_accounts": 0.0,
                "master_account_direct_costs": 0.0,
                "currency": "USD",
            },
        }

        org_stmt = (
            sa.select(
                t_organizations.c.organization_id,
                t_organizations.c.organization_arn,
                t_organizations.c.master_account_id,
                t_organizations.c.master_account_email,
                t_organizations.c.feature_set,
            )
            .order_by(t_organizations.c.created_at.desc())
            .limit(1)
        )

        accounts_stmt = sa.select(
            t_organization_accounts.c.account_id,
            t_organization_accounts.c.account_name,
            t_organization_accounts.c.email,
            t_organization_accounts.c.status,
        )

        total_cost_expr = sa.func.sum(t_cost_data.c.amount).label("total_cost")
        service_count_expr = sa.func.count(
            sa.distinct(t_cost_data.c.service_name)
        ).label("service_count")
        cost_stmt = (
            sa.select(
                t_scan_metadata.c.account_name,
                t_scan_metadata.c.account_number,
                total_cost_expr,
                t_cost_data.c.currency,
                service_count_expr,
            )
            .select_from(
                t_cost_data.join(
                    t_scan_metadata, t_cost_data.c.scan_id == t_scan_metadata.c.scan_id
                )
            )
            .group_by(
                t_scan_metadata.c.account_name,
                t_scan_metadata.c.account_number,
                t_cost_data.c.currency,
            )
            .order_by(total_cost_expr.desc())
        )
        if scan_id:
            org_stmt = org_stmt.where(t_organizations.c.scan_id == scan_id)
            accounts_stmt = accounts_stmt.where(
                t_organization_accounts.c.scan_id == scan_id
            )
            cost_stmt = cost_stmt.where(t_cost_data.c.scan_id == scan_id)

        with self.db_ops.engine.connect() as conn:
            # Get organization information
            org_row = conn.execute(org_stmt).fetchone()
            if not org_row:
                return {
                    "error": "No AWS Organizations data found. This query is for Organizations environments only.",
                    "note": "Use get_total_cost for non-Organizations cost queries.",
                }

            results["organization_info"] = {
                "organization_id": org_row[0],
                "master_account_id": org_row[2],
                "master_account_email": org_row[3],
                "feature_set": org_row[4],
            }

            master_account_id = org_row[2]

            # Get all organization member accounts
            member_account_ids = {}
            for row in conn.execute(accounts_stmt):
                member_account_ids[row[0]] = {
                    "account_name": row[1],
                    "email": row[2],
                    "status": row[3],
                }

            # Get costs for all accounts
            for row in conn.execute(cost_stmt):
                account_number = row[1]
                account_name = row[0]
                total_cost = round(row[2], 2)
                currency = row[3]
                service_count = row[4]

                cost_data = {
                    "account_number": account_number,
                    "account_name": account_name,
                    "total_cost": total_cost,
                    "currency": currency,
                    "service_count": service_count,
                }

                # Classify as master or member
                if account_number == master_account_id:
                    results["master_account_costs"] = cost_data
                    results["master_account_costs"]["note"] = (
                        "This is the master/payer account. Costs shown are DIRECT costs "
                        "for resources in this account only, NOT consolidated costs from member accounts."
                    )
                    results["cost_summary"]["master_account_direct_costs"] = total_cost
                elif account_number in member_account_ids:
                    cost_data["organization_status"] = member_account_ids[
                        account_number
                    ]["status"]
                    results["member_accounts"].append(cost_data)
                    results["cost_summary"]["total_member_accounts"] += total_cost
                else:
                    # Account not in org structure but has costs
                    cost_data["note"] = (
                        "Account has costs but not found in organization structure"
                    )
                    results["member_accounts"].append(cost_data)
                    results["cost_summary"]["total_member_accounts"] += total_cost

                results["cost_summary"]["total_all_accounts"] += total_cost
                results["cost_summary"]["currency"] = currency

        # Round summary values
        results["cost_summary"]["total_all_accounts"] = round(
            results["cost_summary"]["total_all_accounts"], 2
        )
        results["cost_summary"]["total_member_accounts"] = round(
            results["cost_summary"]["total_member_accounts"], 2
        )

        # Add helpful context
        results["interpretation"] = {
            "note": (
                "In AWS Organizations with consolidated billing:\n"
                "- The master account pays for all member account usage\n"
                "- Cost data shown here reflects actual usage per account\n"
                "- Master account costs are its DIRECT costs only\n"
                "- Member account costs are their individual usage\n"
                '- When asking "which account costs most?", exclude the master account '
                "or look at member_accounts list to see actual usage by account"
            ),
            "highest_cost_member_account": (
                results["member_accounts"][0]["account_name"]
                if results["member_accounts"]
                else "N/A"
            ),
            "member_account_count": len(results["member_accounts"]),
        }

        return results

    def _get_security_assessment_data(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Run the native security checks and attach Prowler linkage."""
        try:
            result = run_assessment_checks(
                self.db_ops.engine,
                params.get("scan_id"),
                params.get("category"),
            )
        except ValueError as e:
            return {"error": str(e)}

        failed_stmt = (
            sa.select(t_prowler_findings.c.severity, sa.func.count())
            .where(
                t_prowler_findings.c.scan_id == result["scan_id"],
                sa.func.upper(t_prowler_findings.c.status) == "FAIL",
            )
            .group_by(t_prowler_findings.c.severity)
        )
        with self.db_ops.engine.connect() as conn:
            failed = {row[0]: row[1] for row in conn.execute(failed_stmt)}

        result["prowler"] = {
            "available": bool(failed),
            "failed_by_severity": failed,
            "detail_tool": "get_prowler_findings",
        }
        result["scoring_note"] = (
            "Severities are advisory facts. Scoring, weighting and report "
            "structure are the responsibility of the MCP client."
        )
        return result

    def _analyze_service_exposure(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Run the service exposure correlations."""
        try:
            return run_exposure(
                self.db_ops.engine,
                params.get("scan_id"),
                params.get("service"),
            )
        except ValueError as e:
            return {"error": str(e)}

    def _get_security_check_catalogue(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Return the catalogue of registered checks."""
        checks = get_catalogue()
        return {"checks": checks, "count": len(checks)}
