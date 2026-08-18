"""
Result types for the assessment evidence engine.

The engine emits findings with advisory severities; it never computes a
score — scoring is the MCP client's responsibility.
Uses Australian English in all documentation and comments.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class Finding:
    """A single affected resource with the evidence that triggered it."""

    resource_id: str
    resource_type: str
    region: Optional[str]
    evidence: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "resource_id": self.resource_id,
            "resource_type": self.resource_type,
            "region": self.region,
            "evidence": self.evidence,
        }


@dataclass
class CheckResult:
    """The outcome of one registered check for one scan."""

    check_id: str
    category: str
    # "findings" | "clean" | "not_applicable" | "not_evaluated"
    #  - not_applicable: the collector ran and the account has none of this
    #    resource (scanned, none found). Covered, never deducts.
    #  - not_evaluated: the data was never collected (e.g. an old scan or a
    #    denied permission), so the answer is genuinely unknown. A coverage gap.
    status: str
    default_severity: str  # advisory: critical/high/medium/low/informational
    recommendation: str
    findings: List[Finding] = field(default_factory=list)
    not_evaluated_reason: Optional[str] = None
    not_applicable_reason: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "check_id": self.check_id,
            "category": self.category,
            "status": self.status,
            "default_severity": self.default_severity,
            "recommendation": self.recommendation,
            "findings": [f.to_dict() for f in self.findings],
            "not_evaluated_reason": self.not_evaluated_reason,
            "not_applicable_reason": self.not_applicable_reason,
        }
