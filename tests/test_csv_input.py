"""
Unit tests for CSV input handling.

Uses Australian English in all documentation and comments.
"""

import pytest
import tempfile
import csv
from pathlib import Path

from cloudledger.scanner.csv_input import CSVAccountReader, CSVInputError


class TestCSVAccountReader:
    """Test CSV account reader functionality."""

    @pytest.fixture
    def valid_csv(self, tmp_path):
        """Create a valid CSV file for testing."""
        csv_path = tmp_path / "valid.csv"
        with open(csv_path, "w", newline="") as f:
            writer = csv.DictWriter(
                f,
                fieldnames=[
                    "account_name",
                    "account_number",
                    "access_key_id",
                    "secret_access_key",
                    "session_token",
                    "prowler_level",
                ],
            )
            writer.writeheader()
            writer.writerow(
                {
                    "account_name": "Test Account",
                    "account_number": "123456789012",
                    "access_key_id": "ASIAIOSFODNN7EXAMPLE",
                    "secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                    "session_token": "IQoJb3JpZ2luX2VjEHoaCXVzLXdlc3QtMiJHMEUCIQD",
                    "prowler_level": "2",
                }
            )

        return str(csv_path)

    @pytest.fixture
    def invalid_csv_missing_columns(self, tmp_path):
        """Create CSV with missing required columns."""
        csv_path = tmp_path / "missing_columns.csv"
        with open(csv_path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=["account_name", "account_number"])
            writer.writeheader()
            writer.writerow({"account_name": "Test", "account_number": "123456789012"})

        return str(csv_path)

    @pytest.fixture
    def invalid_csv_bad_account_number(self, tmp_path):
        """Create CSV with invalid account number."""
        csv_path = tmp_path / "bad_account_number.csv"
        with open(csv_path, "w", newline="") as f:
            writer = csv.DictWriter(
                f,
                fieldnames=[
                    "account_name",
                    "account_number",
                    "access_key_id",
                    "secret_access_key",
                    "session_token",
                ],
            )
            writer.writeheader()
            writer.writerow(
                {
                    "account_name": "Test Account",
                    "account_number": "12345",  # Too short
                    "access_key_id": "ASIAIOSFODNN7EXAMPLE",
                    "secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                    "session_token": "IQoJb3JpZ2luX2VjEHoaCXVzLXdlc3QtMiJHMEUCIQD",
                }
            )

        return str(csv_path)

    def test_read_valid_csv(self, valid_csv):
        """Test reading a valid CSV file."""
        reader = CSVAccountReader(valid_csv)
        accounts = reader.read_accounts()

        assert len(accounts) == 1
        assert accounts[0].account_name == "Test Account"
        assert accounts[0].account_number == "123456789012"
        assert accounts[0].prowler_level == "2"
        assert accounts[0].credentials.access_key_id == "ASIAIOSFODNN7EXAMPLE"

    def test_missing_columns(self, invalid_csv_missing_columns):
        """Test that missing columns raises error."""
        reader = CSVAccountReader(invalid_csv_missing_columns)

        with pytest.raises(CSVInputError) as exc_info:
            reader.read_accounts()

        assert "Missing required columns" in str(exc_info.value)

    def test_invalid_account_number(self, invalid_csv_bad_account_number):
        """Test that invalid account number raises error."""
        reader = CSVAccountReader(invalid_csv_bad_account_number)

        with pytest.raises(CSVInputError) as exc_info:
            reader.read_accounts()

        assert "must be exactly 12 digits" in str(exc_info.value)

    def test_file_not_found(self):
        """Test that non-existent file raises error."""
        with pytest.raises(CSVInputError) as exc_info:
            CSVAccountReader("/nonexistent/file.csv")

        assert "not found" in str(exc_info.value)

    def test_create_example_csv(self):
        """Test creating example CSV file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "example.csv"
            CSVAccountReader.create_example_csv(str(output_path))

            assert output_path.exists()

            # Verify it can be read
            reader = CSVAccountReader(str(output_path))
            accounts = reader.read_accounts()
            assert len(accounts) >= 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
