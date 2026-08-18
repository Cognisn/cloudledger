"""
Prowler integration for security scanning.

This module integrates Prowler v5 security scanning into the CloudLedger.
Uses Australian English in all documentation and comments.
"""

import logging
import json
import subprocess
import sys
import tempfile
import os
from pathlib import Path
from typing import List, Optional, Dict, Any
import boto3

from ..database.models import ProwlerFinding

logger = logging.getLogger(__name__)


class ProwlerIntegration:
    """Handles Prowler security scanning integration."""

    # Prowler scan level configurations
    SCAN_LEVELS = {
        "1": {
            "name": "Basic",
            "description": "Critical and High severity checks only",
            "severity_filter": ["critical", "high"],
        },
        "2": {
            "name": "Standard",
            "description": "CIS AWS Foundations Benchmark checks",
            "compliance": ["cis_2.0_aws"],
        },
        "3": {
            "name": "Comprehensive",
            "description": "All available security checks",
            "severity_filter": None,  # No filter = all checks
        },
    }

    def __init__(self, session: boto3.Session, scan_id: str, scan_level: str):
        """
        Initialise Prowler integration.

        Args:
            session: Boto3 session with valid credentials
            scan_id: Unique identifier for this scan
            scan_level: Prowler scan level ('1', '2', or '3')

        Raises:
            ValueError: If scan level is invalid
        """
        if scan_level not in self.SCAN_LEVELS:
            raise ValueError(f"Invalid Prowler scan level: {scan_level}")

        self.session = session
        self.scan_id = scan_id
        self.scan_level = scan_level
        self.level_config = self.SCAN_LEVELS[scan_level]

        logger.info(
            f"Initialised Prowler integration with level {scan_level} "
            f"({self.level_config['name']})"
        )

    def run_security_scan(self) -> List[ProwlerFinding]:
        """
        Run Prowler v5 security scan.

        Returns:
            List of Prowler findings
        """
        logger.info(
            f"Starting Prowler scan with level {self.scan_level} "
            f"({self.level_config['name']})"
        )

        findings = []

        try:
            # Create temporary directory for Prowler output
            with tempfile.TemporaryDirectory() as temp_dir:
                output_dir = Path(temp_dir)

                # Get AWS credentials from session
                credentials = self.session.get_credentials()
                frozen_creds = credentials.get_frozen_credentials()

                # Build Prowler command
                cmd = self._build_prowler_command(output_dir, frozen_creds)

                logger.debug(
                    f"Executing Prowler command: {' '.join(cmd[:3])}..."
                )  # Don't log credentials

                # Run Prowler as subprocess
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=3600,  # 1 hour timeout
                    env=self._get_prowler_env(frozen_creds),
                )

                if result.returncode != 0:
                    logger.warning(f"Prowler exited with code {result.returncode}")
                    self._log_prowler_failure(result.stderr)

                # Parse Prowler JSON output
                findings = self._parse_prowler_output(output_dir)

                logger.info(f"Prowler scan completed: {len(findings)} findings")

        except subprocess.TimeoutExpired:
            logger.error("Prowler scan timed out after 1 hour")
        except FileNotFoundError as e:
            logger.error(
                f"Could not launch Prowler via '{sys.executable} -m prowler': {e}. "
                "Ensure Prowler v5 is installed in this environment (uv sync, or "
                "pip install 'prowler>=5.0.0')."
            )
        except Exception as e:
            logger.error(f"Prowler scan failed: {e}", exc_info=True)

        return findings

    def _log_prowler_failure(self, stderr: str) -> None:
        """
        Surface why Prowler failed, at a visible log level.

        Prowler writes the underlying cause to stderr (often a single
        CRITICAL line). Log that so a non-zero exit is diagnosable without
        raising the log level, and call out the common expired-credentials
        case explicitly.

        Args:
            stderr: The captured Prowler stderr
        """
        stderr = (stderr or "").strip()
        if not stderr:
            logger.warning("Prowler produced no error output to explain the failure.")
            return

        # Prefer the CRITICAL line(s) — that is Prowler's own failure summary.
        critical_lines = [
            line.strip()
            for line in stderr.splitlines()
            if "CRITICAL" in line or "ERROR" in line
        ]
        detail = " | ".join(critical_lines) if critical_lines else stderr[-1000:]
        logger.error(f"Prowler failed: {detail}")

        # Temporary credentials expiring mid-scan is the most common cause,
        # because Prowler runs after all resource collection.
        if "InvalidClientTokenId" in stderr or "ExpiredToken" in stderr:
            logger.error(
                "The AWS credentials were rejected by Prowler. Temporary ASIA "
                "session tokens are short-lived, and Prowler runs last (after "
                "resource collection), so a long scan can outlive the token. "
                "Re-run with freshly issued credentials."
            )

    def _build_prowler_command(self, output_dir: Path, credentials: Any) -> List[str]:
        """
        Build Prowler CLI command with appropriate filters.

        Args:
            output_dir: Directory for Prowler output
            credentials: AWS credentials

        Returns:
            Command list for subprocess
        """
        # Run Prowler under the interpreter running the scanner, so it uses the
        # same environment that has Prowler installed (portable across platforms).
        cmd = [
            sys.executable,
            "-m",
            "prowler",
            "aws",
            "--output-formats",
            "json-asff",
            "--output-directory",
            str(output_dir),
            "--no-banner",
            "--no-color",
        ]

        # Add severity filter for level 1 (Basic)
        if (
            "severity_filter" in self.level_config
            and self.level_config["severity_filter"]
        ):
            severities = ",".join(self.level_config["severity_filter"])
            cmd.extend(["--severity", severities])

        # Add compliance filter for level 2 (Standard)
        if "compliance" in self.level_config:
            for compliance in self.level_config["compliance"]:
                cmd.extend(["--compliance", compliance])

        return cmd

    def _get_prowler_env(self, credentials: Any) -> Dict[str, str]:
        """
        Get environment variables for Prowler execution with AWS credentials.

        Args:
            credentials: AWS credentials

        Returns:
            Environment dictionary
        """
        env = os.environ.copy()

        # AWS credentials
        env["AWS_ACCESS_KEY_ID"] = credentials.access_key
        env["AWS_SECRET_ACCESS_KEY"] = credentials.secret_key

        if credentials.token:
            env["AWS_SESSION_TOKEN"] = credentials.token

        # Fix Unicode encoding issues on Windows
        env["PYTHONIOENCODING"] = "utf-8"
        env["PYTHONUTF8"] = "1"

        return env

    def _parse_prowler_output(self, output_dir: Path) -> List[ProwlerFinding]:
        """
        Parse Prowler JSON output files.

        Args:
            output_dir: Directory containing Prowler output

        Returns:
            List of ProwlerFinding models
        """
        findings = []

        # Prowler v5 creates JSON files in the output directory
        # Look for files matching prowler-output-*.json or compliance-*.json
        json_files = list(output_dir.glob("*.json"))

        if not json_files:
            logger.warning("No Prowler JSON output files found")
            return findings

        for json_file in json_files:
            try:
                logger.debug(f"Parsing Prowler output file: {json_file.name}")

                with open(json_file, "r") as f:
                    data = json.load(f)

                # Prowler v5 outputs an array of finding objects
                if isinstance(data, list):
                    for finding_data in data:
                        finding = self._parse_single_finding(finding_data)
                        if finding:
                            findings.append(finding)
                else:
                    logger.warning(f"Unexpected JSON format in {json_file.name}")

            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse JSON file {json_file.name}: {e}")
            except Exception as e:
                logger.error(f"Error processing {json_file.name}: {e}")

        return findings

    @staticmethod
    def _derive_service_name(data: Dict[str, Any], resource: Dict[str, Any]) -> str:
        """
        Derive the AWS service for a Prowler ASFF finding.

        Prowler v5 ASFF does not carry a ServiceName field, so recover it from
        the resource ARN (arn:aws:<service>:...), falling back to the check id
        in GeneratorId (e.g. "prowler-accessanalyzer_enabled").
        """
        arn = resource.get("Id", "") or ""
        if arn.startswith("arn:aws:"):
            parts = arn.split(":")
            if len(parts) > 2 and parts[2]:
                return parts[2]
        generator = data.get("GeneratorId", "") or ""
        if generator:
            slug = generator.replace("prowler-", "", 1)
            return slug.split("_")[0]
        return ""

    @staticmethod
    def _derive_check_id(data: Dict[str, Any], product_fields: Dict[str, Any]) -> str:
        """
        Derive the Prowler check id. Prefer ProductFields (older ASFF), then
        the GeneratorId slug (v5 ASFF), e.g. "accessanalyzer_enabled".
        """
        explicit = product_fields.get("CheckID") or product_fields.get("Provider/Type")
        if explicit:
            return explicit
        generator = data.get("GeneratorId", "") or ""
        return generator.replace("prowler-", "", 1) if generator else ""

    def _parse_single_finding(self, data: Dict[str, Any]) -> Optional[ProwlerFinding]:
        """
        Parse a single Prowler finding from ASFF (AWS Security Finding Format) JSON.

        Args:
            data: Finding data from Prowler ASFF JSON

        Returns:
            ProwlerFinding model or None if parsing fails
        """
        try:
            # ASFF format has different structure
            # Get ProductFields which contains Prowler-specific data
            product_fields = data.get("ProductFields", {})

            # Extract resource information
            resources = data.get("Resources", [{}])
            resource = resources[0] if resources else {}

            # Extract resource tags
            resource_tags = resource.get("Tags", {})

            # Extract compliance frameworks from RelatedRequirements
            compliance = []
            if "Compliance" in data and data["Compliance"]:
                compliance = data["Compliance"].get("RelatedRequirements", [])

            # Map ASFF Compliance Status to Prowler status
            compliance_status = data.get("Compliance", {}).get("Status", "UNKNOWN")
            status_map = {
                "PASSED": "PASS",
                "FAILED": "FAIL",
                "WARNING": "WARNING",
                "NOT_AVAILABLE": "MANUAL",
            }
            status = status_map.get(compliance_status, compliance_status)

            # Extract severity from nested structure
            severity_label = data.get("Severity", {}).get("Label", "INFORMATIONAL")

            # Extract region from resource or use from top-level
            region = resource.get("Region") or data.get("Region")

            finding = ProwlerFinding(
                scan_id=self.scan_id,
                check_id=self._derive_check_id(data, product_fields),
                check_title=data.get("Title", ""),
                severity=severity_label.lower(),
                status=status,
                region=region,
                resource_id=resource.get("Id", None),
                resource_arn=resource.get("Id", None),  # ASFF uses Id for ARN
                resource_tags=resource_tags,
                status_extended=data.get("Description", None),
                service_name=self._derive_service_name(data, resource),
                check_type=product_fields.get("CheckType", ""),
                risk=product_fields.get("Risk", None),
                remediation=data.get("Remediation", {})
                .get("Recommendation", {})
                .get("Text", None),
                compliance_frameworks=compliance,
                raw_data=data,
            )

            return finding

        except Exception as e:
            logger.error(f"Failed to parse ASFF finding: {e}")
            logger.debug(f"Finding data: {data}")
            return None

    @staticmethod
    def is_prowler_available() -> bool:
        """
        Check if Prowler is available.

        Returns:
            True if Prowler can be executed, False otherwise
        """
        try:
            result = subprocess.run(
                ["prowler", "--version"], capture_output=True, text=True, timeout=5
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    @staticmethod
    def get_prowler_version() -> Optional[str]:
        """
        Get installed Prowler version.

        Returns:
            Prowler version string or None if not installed
        """
        try:
            result = subprocess.run(
                ["prowler", "--version"], capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                # Parse version from output (format: "Prowler X.Y.Z")
                version_line = result.stdout.strip()
                return version_line
            return None
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return None


class ProwlerRunner:
    """
    Helper class to run Prowler scans with progress tracking.

    This provides a higher-level interface for running Prowler scans
    with better error handling and progress reporting.
    """

    def __init__(self, session: boto3.Session, scan_id: str):
        """
        Initialise Prowler runner.

        Args:
            session: Boto3 session
            scan_id: Scan identifier
        """
        self.session = session
        self.scan_id = scan_id

    def run_scan(self, scan_level: str) -> tuple[List[ProwlerFinding], Dict[str, Any]]:
        """
        Run Prowler scan with progress tracking.

        Args:
            scan_level: Prowler scan level ('1', '2', or '3')

        Returns:
            Tuple of (findings list, scan statistics dictionary)
        """
        logger.info(f"Starting Prowler scan with level {scan_level}")

        try:
            integration = ProwlerIntegration(
                session=self.session, scan_id=self.scan_id, scan_level=scan_level
            )

            findings = integration.run_security_scan()

            # Calculate statistics
            stats = self._calculate_statistics(findings)

            logger.info(
                f"Prowler scan completed: {stats['total_checks']} checks, "
                f"{stats['passed']} passed, {stats['failed']} failed"
            )

            return findings, stats

        except Exception as e:
            logger.error(f"Prowler scan failed: {e}", exc_info=True)
            raise

    def _calculate_statistics(self, findings: List[ProwlerFinding]) -> Dict[str, Any]:
        """
        Calculate statistics from Prowler findings.

        Args:
            findings: List of Prowler findings

        Returns:
            Dictionary with scan statistics
        """
        stats = {
            "total_checks": len(findings),
            "passed": 0,
            "failed": 0,
            "warnings": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "by_service": {},
        }

        for finding in findings:
            # Count by status
            if finding.status == "PASS":
                stats["passed"] += 1
            elif finding.status == "FAIL":
                stats["failed"] += 1
            elif finding.status == "WARNING":
                stats["warnings"] += 1

            # Count by severity
            severity = finding.severity.lower()
            if severity in stats:
                stats[severity] += 1

            # Count by service
            service = finding.service_name
            if service not in stats["by_service"]:
                stats["by_service"][service] = 0
            stats["by_service"][service] += 1

        return stats
