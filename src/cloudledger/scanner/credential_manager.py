"""
Credential management for CloudLedger.

This module handles AWS credential collection and session creation.
Uses Australian English in all documentation and comments.
"""

import boto3
import getpass
from typing import Optional, Dict, List
from dataclasses import dataclass, field
import logging

from ..utils.aws_helpers import validate_aws_credentials, get_account_id

logger = logging.getLogger(__name__)


@dataclass
class AWSCredentials:
    """Container for AWS credentials."""

    access_key_id: str
    secret_access_key: str
    session_token: Optional[str] = None


@dataclass
class AccountConfig:
    """Configuration for an AWS account to scan."""

    account_name: str
    account_number: str
    credentials: AWSCredentials
    prowler_level: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    org_member: Optional[bool] = None
    is_management_account: Optional[bool] = None
    management_account_id: Optional[str] = None
    management_account_name: Optional[str] = None


class CredentialManager:
    """Manages AWS credentials and session creation."""

    def __init__(self):
        """Initialise credential manager."""
        self._sessions: Dict[str, boto3.Session] = {}

    def create_session(
        self, credentials: AWSCredentials, region: str = "us-east-1"
    ) -> boto3.Session:
        """
        Create a boto3 session with the provided credentials.

        Args:
            credentials: AWS credentials
            region: AWS region for the session

        Returns:
            Configured boto3 session

        Raises:
            ValueError: If credentials are invalid
        """
        # Validate credentials
        if not validate_aws_credentials(
            credentials.access_key_id,
            credentials.secret_access_key,
            credentials.session_token,
        ):
            raise ValueError("Invalid AWS credentials")

        # Create session
        session = boto3.Session(
            aws_access_key_id=credentials.access_key_id,
            aws_secret_access_key=credentials.secret_access_key,
            aws_session_token=credentials.session_token,
            region_name=region,
        )

        logger.info(f"Created AWS session for region {region}")
        return session

    def get_client(
        self, session: boto3.Session, service: str, region: Optional[str] = None
    ):
        """
        Get an AWS service client from a session.

        Args:
            session: Boto3 session
            service: AWS service name (e.g., 'ec2', 's3', 'iam')
            region: Optional region override

        Returns:
            AWS service client
        """
        if region:
            return session.client(service, region_name=region)
        return session.client(service)

    def verify_account_number(
        self, session: boto3.Session, expected_account_number: str
    ) -> bool:
        """
        Verify that the session credentials match the expected account number.

        Args:
            session: Boto3 session
            expected_account_number: Expected AWS account number

        Returns:
            True if account number matches, False otherwise
        """
        try:
            actual_account_id = get_account_id(session)
            if actual_account_id != expected_account_number:
                logger.error(
                    f"Account mismatch: expected {expected_account_number}, "
                    f"got {actual_account_id}"
                )
                return False
            return True
        except Exception as e:
            logger.error(f"Failed to verify account number: {e}")
            return False

    @staticmethod
    def prompt_for_credentials() -> AWSCredentials:
        """
        Interactively prompt user for AWS credentials.

        Sensitive fields (secret key and session token) are masked during input.

        Returns:
            AWS credentials from user input
        """
        print("\nEnter AWS credentials:")
        access_key = input("AWS Access Key ID: ").strip()
        secret_key = getpass.getpass("AWS Secret Access Key: ").strip()
        session_token = getpass.getpass(
            "AWS Session Token (press Enter to skip): "
        ).strip()

        return AWSCredentials(
            access_key_id=access_key,
            secret_access_key=secret_key,
            session_token=session_token if session_token else None,
        )

    @staticmethod
    def prompt_for_prowler_level() -> Optional[str]:
        """
        Interactively prompt user for the Prowler scan level.

        Returns:
            Prowler scan level ("1", "2", or "3"), or None to skip Prowler
        """
        print("\nProwler Scan Level:")
        print("  1 - Basic security checks")
        print("  2 - Standard compliance checks (CIS Benchmarks)")
        print("  3 - Comprehensive security assessment")
        print("  skip - Skip Prowler scanning")
        prowler_choice = (
            input("Select Prowler scan level [1/2/3/skip]: ").strip().lower()
        )

        if prowler_choice in ["1", "2", "3"]:
            return prowler_choice
        if prowler_choice != "skip":
            print("Invalid choice, defaulting to skip Prowler scan")
        return None

    @staticmethod
    def _ask_yes_no(prompt: str) -> bool:
        """Ask a yes/no question that defaults to No on any other answer."""
        return input(prompt).strip().lower() == "y"

    @staticmethod
    def prompt_for_org_questions() -> Dict[str, Optional[object]]:
        """
        Interactively prompt user for AWS Organisation / control-tower details.

        Returns:
            Dictionary with keys `org_member`, `is_management_account`,
            `management_account_id`, `management_account_name`
        """
        org_member = CredentialManager._ask_yes_no(
            "Is this account a member of an AWS Organisation? [y/N]: "
        )

        is_management_account: Optional[bool] = None
        management_account_id: Optional[str] = None
        management_account_name: Optional[str] = None

        if org_member:
            is_management_account = CredentialManager._ask_yes_no(
                "Is this the control-tower (management) account? [y/N]: "
            )

            if not is_management_account:
                while True:
                    management_account_name = input(
                        "Management account name: "
                    ).strip()
                    if management_account_name:
                        break
                    print("Management account name must not be blank")

                while True:
                    management_account_id = input(
                        "Management account id (12-digit): "
                    ).strip()
                    if (
                        management_account_id.isdigit()
                        and len(management_account_id) == 12
                    ):
                        break
                    print("Management account id must be exactly 12 digits")

        return {
            "org_member": org_member,
            "is_management_account": is_management_account,
            "management_account_id": management_account_id,
            "management_account_name": management_account_name,
        }

    @staticmethod
    def prompt_for_account_config(include_org_questions: bool = True) -> AccountConfig:
        """
        Interactively prompt user for account configuration.

        Args:
            include_org_questions: Whether to ask the AWS Organisation /
                control-tower questions after the tags prompt. Set to False
                when building a queued management-account scan, whose org
                details are already known and must not be re-asked.

        Returns:
            Account configuration from user input
        """
        print("\n" + "=" * 60)
        print("AWS Account Configuration")
        print("=" * 60)

        account_name = input("Account Name (friendly identifier): ").strip()
        account_number = input("Account Number (12-digit): ").strip()

        # Validate account number format
        if not account_number.isdigit() or len(account_number) != 12:
            raise ValueError("Account number must be exactly 12 digits")

        credentials = CredentialManager.prompt_for_credentials()

        prowler_level = CredentialManager.prompt_for_prowler_level()

        tags_input = input("Tags (comma-separated, optional): ").strip()
        tags = [tag.strip() for tag in tags_input.split(",") if tag.strip()]

        org_fields: Dict[str, Optional[object]] = {
            "org_member": None,
            "is_management_account": None,
            "management_account_id": None,
            "management_account_name": None,
        }
        if include_org_questions:
            org_fields = CredentialManager.prompt_for_org_questions()

        return AccountConfig(
            account_name=account_name,
            account_number=account_number,
            credentials=credentials,
            prowler_level=prowler_level,
            tags=tags,
            org_member=org_fields["org_member"],
            is_management_account=org_fields["is_management_account"],
            management_account_id=org_fields["management_account_id"],
            management_account_name=org_fields["management_account_name"],
        )
