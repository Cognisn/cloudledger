"""
AWS helper utilities for CloudLedger.

This module provides utility functions for AWS API interactions.
Uses Australian English in all documentation and comments.
"""

import boto3
import time
from typing import List, Dict, Any, Optional, Callable
from botocore.exceptions import ClientError, BotoCoreError
import logging

logger = logging.getLogger(__name__)


def get_all_regions(service: str = 'ec2') -> List[str]:
    """
    Get list of all AWS regions for a service.

    Args:
        service: AWS service name (default: ec2)

    Returns:
        List of region names
    """
    try:
        ec2_client = boto3.client('ec2', region_name='us-east-1')
        response = ec2_client.describe_regions(AllRegions=True)
        regions = [region['RegionName'] for region in response['Regions']]
        logger.debug(f"Retrieved {len(regions)} regions for {service}")
        return sorted(regions)
    except (ClientError, BotoCoreError) as e:
        logger.error(f"Failed to retrieve regions: {e}")
        # Fallback to common regions
        return [
            'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2',
            'eu-west-1', 'eu-west-2', 'eu-central-1',
            'ap-southeast-1', 'ap-southeast-2', 'ap-northeast-1'
        ]


def retry_with_backoff(
    func: Callable,
    max_attempts: int = 3,
    initial_delay: float = 1.0,
    backoff_factor: float = 2.0,
    **kwargs
) -> Any:
    """
    Retry a function with exponential backoff.

    Args:
        func: Function to retry
        max_attempts: Maximum number of attempts
        initial_delay: Initial delay in seconds
        backoff_factor: Backoff multiplier
        **kwargs: Arguments to pass to the function

    Returns:
        Function result

    Raises:
        Last exception if all attempts fail
    """
    delay = initial_delay
    last_exception = None

    for attempt in range(1, max_attempts + 1):
        try:
            return func(**kwargs)
        except ClientError as e:
            last_exception = e
            error_code = e.response.get('Error', {}).get('Code', '')

            # Don't retry on access denied or resource not found
            if error_code in ['AccessDenied', 'UnauthorizedOperation', 'ResourceNotFoundException']:
                raise

            # Retry on throttling errors
            if error_code in ['Throttling', 'RequestLimitExceeded', 'TooManyRequestsException']:
                if attempt < max_attempts:
                    logger.warning(f"Throttled, retrying in {delay}s (attempt {attempt}/{max_attempts})")
                    time.sleep(delay)
                    delay *= backoff_factor
                    continue

            # Retry on other errors
            if attempt < max_attempts:
                logger.warning(f"Error: {error_code}, retrying in {delay}s (attempt {attempt}/{max_attempts})")
                time.sleep(delay)
                delay *= backoff_factor
            else:
                raise

    if last_exception:
        raise last_exception


def parse_tags(tags: Optional[List[Dict[str, str]]]) -> Dict[str, str]:
    """
    Parse AWS tags from list format to dictionary.

    Args:
        tags: List of tag dictionaries with 'Key' and 'Value'

    Returns:
        Dictionary mapping tag keys to values
    """
    if not tags:
        return {}

    return {tag['Key']: tag['Value'] for tag in tags if 'Key' in tag}


def is_public_ip(ip_address: Optional[str]) -> bool:
    """
    Check if an IP address is public (not private/reserved).

    Args:
        ip_address: IP address string

    Returns:
        True if public, False otherwise
    """
    if not ip_address:
        return False

    # Parse IP address
    try:
        octets = [int(octet) for octet in ip_address.split('.')]
    except (ValueError, AttributeError):
        return False

    # Check for private ranges
    # 10.0.0.0/8
    if octets[0] == 10:
        return False
    # 172.16.0.0/12
    if octets[0] == 172 and 16 <= octets[1] <= 31:
        return False
    # 192.168.0.0/16
    if octets[0] == 192 and octets[1] == 168:
        return False
    # 127.0.0.0/8 (loopback)
    if octets[0] == 127:
        return False
    # 169.254.0.0/16 (link-local)
    if octets[0] == 169 and octets[1] == 254:
        return False

    return True


def validate_aws_credentials(
    access_key: str,
    secret_key: str,
    session_token: Optional[str] = None
) -> bool:
    """
    Validate AWS credentials by making a test API call.

    Args:
        access_key: AWS access key ID
        secret_key: AWS secret access key
        session_token: Optional AWS session token

    Returns:
        True if credentials are valid, False otherwise
    """
    try:
        sts_client = boto3.client(
            'sts',
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            aws_session_token=session_token
        )
        sts_client.get_caller_identity()
        return True
    except (ClientError, BotoCoreError) as e:
        logger.error(f"Credential validation failed: {e}")
        return False


def get_account_id(session: boto3.Session) -> str:
    """
    Get AWS account ID from a boto3 session.

    Args:
        session: Boto3 session

    Returns:
        AWS account ID

    Raises:
        ClientError if unable to retrieve account ID
    """
    sts_client = session.client('sts')
    response = sts_client.get_caller_identity()
    return response['Account']
