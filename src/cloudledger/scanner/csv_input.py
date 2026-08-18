"""
CSV input handling for CloudLedger.

This module provides functionality to read account configurations from CSV files.
Uses Australian English in all documentation and comments.
"""

import csv
from pathlib import Path
from typing import List, Dict, Any
import logging

from .credential_manager import AccountConfig, AWSCredentials

logger = logging.getLogger(__name__)


class CSVInputError(Exception):
    """Exception raised for CSV input errors."""
    pass


class CSVAccountReader:
    """Reads and validates account configurations from CSV files."""

    REQUIRED_COLUMNS = [
        'account_name',
        'account_number',
        'access_key_id',
        'secret_access_key',
        'session_token'
    ]

    OPTIONAL_COLUMNS = [
        'prowler_level'
    ]

    def __init__(self, csv_path: str):
        """
        Initialise CSV account reader.

        Args:
            csv_path: Path to CSV file

        Raises:
            CSVInputError: If file doesn't exist or is invalid
        """
        self.csv_path = Path(csv_path)

        if not self.csv_path.exists():
            raise CSVInputError(f"CSV file not found: {csv_path}")

        if not self.csv_path.is_file():
            raise CSVInputError(f"Path is not a file: {csv_path}")

    def read_accounts(self) -> List[AccountConfig]:
        """
        Read all account configurations from the CSV file.

        Returns:
            List of account configurations

        Raises:
            CSVInputError: If CSV format is invalid
        """
        accounts = []

        try:
            with open(self.csv_path, 'r', encoding='utf-8') as csvfile:
                reader = csv.DictReader(csvfile)

                # Validate columns
                if not reader.fieldnames:
                    raise CSVInputError("CSV file is empty or has no headers")

                self._validate_columns(reader.fieldnames)

                # Read each row
                for row_num, row in enumerate(reader, start=2):  # Start at 2 (after header)
                    try:
                        account = self._parse_row(row, row_num)
                        accounts.append(account)
                    except ValueError as e:
                        logger.error(f"Error on row {row_num}: {e}")
                        raise CSVInputError(f"Invalid data on row {row_num}: {e}")

        except csv.Error as e:
            raise CSVInputError(f"CSV parsing error: {e}")
        except Exception as e:
            if isinstance(e, CSVInputError):
                raise
            raise CSVInputError(f"Error reading CSV file: {e}")

        logger.info(f"Successfully read {len(accounts)} account configurations from CSV")
        return accounts

    def _validate_columns(self, fieldnames: List[str]) -> None:
        """
        Validate that all required columns are present.

        Args:
            fieldnames: Column names from CSV

        Raises:
            CSVInputError: If required columns are missing
        """
        missing_columns = set(self.REQUIRED_COLUMNS) - set(fieldnames)

        if missing_columns:
            raise CSVInputError(
                f"Missing required columns: {', '.join(sorted(missing_columns))}"
            )

    def _parse_row(self, row: Dict[str, str], row_num: int) -> AccountConfig:
        """
        Parse a CSV row into an AccountConfig.

        Args:
            row: Dictionary of column values
            row_num: Row number (for error reporting)

        Returns:
            Account configuration

        Raises:
            ValueError: If row data is invalid
        """
        # Extract and validate account name
        account_name = row['account_name'].strip()
        if not account_name:
            raise ValueError("account_name cannot be empty")

        # Extract and validate account number
        account_number = row['account_number'].strip()
        if not account_number:
            raise ValueError("account_number cannot be empty")

        if not account_number.isdigit() or len(account_number) != 12:
            raise ValueError(
                f"account_number must be exactly 12 digits, got: {account_number}"
            )

        # Extract and validate credentials
        access_key_id = row['access_key_id'].strip()
        if not access_key_id:
            raise ValueError("access_key_id cannot be empty")

        secret_access_key = row['secret_access_key'].strip()
        if not secret_access_key:
            raise ValueError("secret_access_key cannot be empty")

        session_token = row['session_token'].strip()
        if not session_token:
            raise ValueError("session_token cannot be empty (required for temporary credentials)")

        credentials = AWSCredentials(
            access_key_id=access_key_id,
            secret_access_key=secret_access_key,
            session_token=session_token
        )

        # Extract optional Prowler level
        prowler_level = row.get('prowler_level', '').strip().lower()
        if prowler_level not in ['1', '2', '3', 'skip', '']:
            raise ValueError(
                f"prowler_level must be '1', '2', '3', or 'skip', got: {prowler_level}"
            )

        # Normalise prowler_level
        if prowler_level in ['1', '2', '3']:
            prowler_level_final = prowler_level
        else:
            prowler_level_final = None

        return AccountConfig(
            account_name=account_name,
            account_number=account_number,
            credentials=credentials,
            prowler_level=prowler_level_final
        )

    @staticmethod
    def create_example_csv(output_path: str) -> None:
        """
        Create an example CSV file with the required format.

        Args:
            output_path: Path where example CSV should be created
        """
        example_data = [
            {
                'account_name': 'Production Account',
                'account_number': '123456789012',
                'access_key_id': 'ASIA...',
                'secret_access_key': 'abc123...',
                'session_token': 'IQoJb3J...',
                'prowler_level': '2'
            },
            {
                'account_name': 'Development Account',
                'account_number': '987654321098',
                'access_key_id': 'ASIA...',
                'secret_access_key': 'xyz789...',
                'session_token': 'IQoJb3J...',
                'prowler_level': 'skip'
            }
        ]

        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)

        with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(
                csvfile,
                fieldnames=CSVAccountReader.REQUIRED_COLUMNS + CSVAccountReader.OPTIONAL_COLUMNS
            )
            writer.writeheader()
            writer.writerows(example_data)

        logger.info(f"Created example CSV file at {output_path}")
        print(f"Example CSV file created at: {output_path}")
