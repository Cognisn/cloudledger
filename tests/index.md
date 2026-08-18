# Tests

Index of the tests in this folder. Keep it current as tests are added, changed, or removed.

| Test | Covers |
| --- | --- |
| `assessment_fixtures.py` / `test_assessment_fixtures.py` | Shared assessment fixtures and their self-checks |
| `test_assessment_registry.py` | Assessment check registry registration and lookup |
| `test_checks_data_logging.py` | Data-protection and logging assessment checks |
| `test_checks_identity.py` | Identity (IAM) assessment checks |
| `test_checks_network.py` | Network assessment checks |
| `test_collector_pagination.py` | AWS collector pagination across API pages |
| `test_csv_input.py` | CSV account-input parsing and validation |
| `test_database.py` | Database schema, inserts, and query operations |
| `test_exposure.py` | Public-exposure assessment logic |
| `test_lambda_exposure_collection.py` | Lambda function exposure collection |
| `test_mcp_security_tools.py` | MCP security query tools |
| `test_not_applicable.py` | Not-applicable result handling in assessments |
| `test_prowler_parsing.py` | Prowler output parsing into findings |
| `test_region_security_services.py` | Regional security-service detection |
| `test_s3_public_access_collection.py` | S3 public-access configuration collection |
| `test_security_posture_collection.py` | Account security-posture collection |
