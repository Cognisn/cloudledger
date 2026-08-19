"""Tests for Prowler ASFF finding parsing (service and check id derivation)."""

from cloudledger.scanner.prowler_integration import ProwlerIntegration


def test_service_and_check_id_from_arn_and_generator():
    """v5 ASFF carries no ServiceName; derive from ARN and GeneratorId."""
    data = {
        "GeneratorId": "prowler-awslambda_function_inside_vpc",
        "Resources": [{"Id": "arn:aws:lambda:ap-southeast-2:123456789012:function:x"}],
    }
    assert (
        ProwlerIntegration._derive_service_name(data, data["Resources"][0]) == "lambda"
    )
    assert (
        ProwlerIntegration._derive_check_id(data, {}) == "awslambda_function_inside_vpc"
    )


def test_service_falls_back_to_generator_when_no_arn():
    data = {"GeneratorId": "prowler-iam_root_mfa_enabled", "Resources": [{"Id": ""}]}
    assert ProwlerIntegration._derive_service_name(data, {"Id": ""}) == "iam"


def test_check_id_prefers_explicit_product_fields():
    data = {"GeneratorId": "prowler-something"}
    assert (
        ProwlerIntegration._derive_check_id(data, {"CheckID": "explicit_check"})
        == "explicit_check"
    )
