# CloudLedger Tests

This directory contains unit tests for the CloudLedger project.

## Test Structure

```
tests/
├── README.md              # This file
├── test_database.py       # Database operations tests
├── test_csv_input.py      # CSV input handling tests
├── test_scanner.py        # Scanner functionality tests (to be added)
└── test_mcp.py           # MCP server tests (to be added)
```

## Running Tests

### All Tests

```bash
# Run all tests
pytest

# Run with verbose output
pytest -v

# Run with coverage
pytest --cov=src tests/
```

### Specific Test Files

```bash
# Run database tests only
pytest tests/test_database.py

# Run CSV input tests only
pytest tests/test_csv_input.py
```

### Specific Test Classes or Functions

```bash
# Run specific test class
pytest tests/test_database.py::TestDatabaseSchema

# Run specific test function
pytest tests/test_database.py::TestDatabaseSchema::test_database_initialisation
```

## Test Coverage

Generate HTML coverage report:

```bash
pytest --cov=src --cov-report=html tests/
# Open htmlcov/index.html in browser
```

## Test Descriptions

### test_database.py

Tests for database schema and operations:
- Database initialisation
- Schema versioning
- Scan metadata insertion and updates
- EC2 instance data storage
- VPC data storage
- Query operations

### test_csv_input.py

Tests for CSV file input handling:
- Valid CSV file parsing
- Missing column detection
- Invalid data validation
- Account number format validation
- Example CSV generation

### test_scanner.py (Planned)

Tests for scanner functionality:
- Credential validation
- AWS resource collection
- Region handling
- Error handling

### test_mcp.py (Planned)

Tests for MCP server:
- Query handler routing
- Tool definitions
- Database queries
- Result formatting

## Writing Tests

### Test Guidelines

1. **Use Australian English** in all comments and documentation
2. **Use pytest fixtures** for setup and teardown
3. **Use temporary files/databases** for isolation
4. **Clean up resources** after tests
5. **Test both success and failure cases**
6. **Use descriptive test names** that explain what is being tested

### Example Test Structure

```python
"""
Unit tests for module_name.

Uses Australian English in all documentation and comments.
"""

import pytest
from src.module import ClassName


class TestClassName:
    """Test ClassName functionality."""

    @pytest.fixture
    def setup_fixture(self):
        """Create test fixture."""
        # Setup code
        yield fixture_value
        # Teardown code

    def test_success_case(self, setup_fixture):
        """Test successful operation."""
        # Arrange
        expected = "value"

        # Act
        result = function_call()

        # Assert
        assert result == expected

    def test_error_case(self):
        """Test error handling."""
        with pytest.raises(ExceptionType) as exc_info:
            function_that_should_fail()

        assert "expected error message" in str(exc_info.value)
```

## Test Fixtures

### Temporary Databases

```python
@pytest.fixture
def temp_db():
    """Create temporary database for testing."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.db"
        schema = DatabaseSchema(str(db_path))
        schema.initialise_database()
        yield str(db_path)
```

### Mock AWS Credentials

```python
@pytest.fixture
def mock_credentials():
    """Create mock AWS credentials."""
    return AWSCredentials(
        access_key_id="ASIAIOSFODNN7EXAMPLE",
        secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        session_token="IQoJb3JpZ2luX2VjEHoaCXVzLXdlc3QtMiJHMEUCIQD"
    )
```

## Continuous Integration

### GitHub Actions (Planned)

```yaml
name: Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest

    steps:
    - uses: actions/checkout@v2
    - name: Set up Python
      uses: actions/setup-python@v2
      with:
        python-version: '3.12'
    - name: Install dependencies
      run: |
        pip install -r requirements.txt
        pip install -e ".[dev]"
    - name: Run tests
      run: pytest --cov=src tests/
    - name: Upload coverage
      uses: codecov/codecov-action@v2
```

## Troubleshooting

### Import Errors

If tests can't import project modules:

```bash
# Install project in development mode
pip install -e .

# Or set PYTHONPATH
export PYTHONPATH="${PYTHONPATH}:$(pwd)"
```

### Fixture Not Found

Ensure fixtures are in the same file or in `conftest.py`:

```python
# conftest.py
import pytest

@pytest.fixture
def shared_fixture():
    """Fixture available to all tests."""
    return "value"
```

### Test Discovery Issues

Ensure:
- Test files start with `test_`
- Test functions start with `test_`
- Test classes start with `Test`
- `__init__.py` exists in tests directory

## Future Enhancements

### Planned Tests

- **Integration tests**: Test complete scan workflows
- **Performance tests**: Measure scan duration and database performance
- **Mock AWS API tests**: Test AWS collection without real credentials
- **MCP server integration tests**: Test end-to-end query handling

### Test Utilities

- **Mock AWS responses**: Fixtures for common AWS API responses
- **Test data generators**: Create realistic test scan data
- **Custom assertions**: Domain-specific test assertions

## Best Practices

1. **Keep tests independent**: Each test should work in isolation
2. **Use meaningful assertions**: Clear failure messages
3. **Test edge cases**: Empty inputs, None values, large datasets
4. **Mock external dependencies**: Don't rely on AWS API in unit tests
5. **Maintain test documentation**: Keep this README updated

## Coverage Goals

Target coverage levels:
- **Overall**: >80%
- **Database operations**: >90%
- **CSV input**: >90%
- **Core scanner logic**: >75%
- **MCP queries**: >80%

## Running Tests in Development

### Watch Mode

```bash
# Install pytest-watch
pip install pytest-watch

# Run tests on file changes
ptw
```

### Debugging Tests

```bash
# Run with debugging
pytest -s  # Don't capture output
pytest --pdb  # Drop into debugger on failure
```

## Resources

- [pytest documentation](https://docs.pytest.org/)
- [pytest fixtures](https://docs.pytest.org/en/stable/fixture.html)
- [pytest coverage](https://pytest-cov.readthedocs.io/)
