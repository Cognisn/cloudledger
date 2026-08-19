"""
Unit tests for database operations.

Uses Australian English in all documentation and comments.
"""

import pytest
import tempfile
import os
from datetime import datetime
from pathlib import Path

from cloudledger.database.schema import DatabaseSchema
from cloudledger.database.operations import DatabaseOperations
from cloudledger.database.models import ScanMetadata, EC2Instance, VPC


class TestDatabaseSchema:
    """Test database schema creation and management."""

    def test_database_initialisation(self):
        """Test that database is created with correct schema."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            schema = DatabaseSchema(str(db_path))
            schema.initialise_database()

            assert db_path.exists()
            assert schema.get_schema_version() == 1

    def test_schema_version(self):
        """Test schema version tracking."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            schema = DatabaseSchema(str(db_path))

            # Before initialisation
            assert schema.get_schema_version() is None

            # After initialisation
            schema.initialise_database()
            assert schema.get_schema_version() == 1


class TestDatabaseOperations:
    """Test database operations."""

    @pytest.fixture
    def db_ops(self):
        """Create database operations instance with temporary database."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            schema = DatabaseSchema(str(db_path))
            schema.initialise_database()
            yield DatabaseOperations(str(db_path))

    def test_insert_scan_metadata(self, db_ops):
        """Test inserting scan metadata."""
        metadata = ScanMetadata(
            scan_id="test-scan-123",
            account_name="Test Account",
            account_number="123456789012",
            scan_timestamp=datetime.utcnow(),
            prowler_level="2",
            regions_scanned=["us-east-1", "us-west-2"],
            scan_status="in_progress",
        )

        db_ops.insert_scan_metadata(metadata)

        # Verify insertion
        scans = db_ops.get_all_scans()
        assert len(scans) == 1
        assert scans[0]["scan_id"] == "test-scan-123"
        assert scans[0]["account_name"] == "Test Account"

    def test_insert_ec2_instances(self, db_ops):
        """Test inserting EC2 instances."""
        # First insert scan metadata
        metadata = ScanMetadata(
            scan_id="test-scan-456",
            account_name="Test Account",
            account_number="123456789012",
            scan_timestamp=datetime.utcnow(),
            prowler_level=None,
            regions_scanned=["us-east-1"],
            scan_status="in_progress",
        )
        db_ops.insert_scan_metadata(metadata)

        # Insert EC2 instances
        instances = [
            EC2Instance(
                scan_id="test-scan-456",
                instance_id="i-1234567890abcdef0",
                region="us-east-1",
                instance_type="t3.micro",
                state="running",
                public_ip="54.1.2.3",
                private_ip="10.0.1.50",
                vpc_id="vpc-12345678",
                subnet_id="subnet-12345678",
                availability_zone="us-east-1a",
                launch_time=datetime.utcnow(),
                security_groups=["sg-12345678"],
                tags={"Name": "Test Instance"},
                raw_data={},
            )
        ]

        db_ops.insert_ec2_instances(instances)

        # Verify insertion (would need additional query method)
        # This is a basic test structure

    def test_update_scan_status(self, db_ops):
        """Test updating scan status."""
        # Insert scan
        metadata = ScanMetadata(
            scan_id="test-scan-789",
            account_name="Test Account",
            account_number="123456789012",
            scan_timestamp=datetime.utcnow(),
            prowler_level="1",
            regions_scanned=["us-east-1"],
            scan_status="in_progress",
        )
        db_ops.insert_scan_metadata(metadata)

        # Update status
        db_ops.update_scan_status("test-scan-789", "completed", duration=300.5)

        # Verify update
        scans = db_ops.get_all_scans()
        assert scans[0]["scan_status"] == "completed"
        assert scans[0]["scan_duration_seconds"] == 300.5

    def test_get_latest_scan_for_account(self, db_ops):
        """Test retrieving latest scan for an account."""
        # Insert multiple scans for same account
        for i in range(3):
            metadata = ScanMetadata(
                scan_id=f"test-scan-{i}",
                account_name="Test Account",
                account_number="123456789012",
                scan_timestamp=datetime.utcnow(),
                prowler_level="2",
                regions_scanned=["us-east-1"],
                scan_status="completed",
            )
            db_ops.insert_scan_metadata(metadata)

        # Get latest scan
        latest = db_ops.get_latest_scan_for_account("123456789012")
        assert latest is not None
        assert latest["account_number"] == "123456789012"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
