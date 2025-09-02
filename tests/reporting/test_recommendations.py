"""Unit tests for ReportingService recommendations generator."""

from typing import Any, Dict
from unittest.mock import MagicMock

import pytest

from sentinelprobe.reporting.models import SeverityLevel, VulnerabilityFindings
from sentinelprobe.reporting.service import ReportingService


def _service() -> ReportingService:
    # session isn't used by generator paths; pass a MagicMock
    return ReportingService(session=MagicMock())


def test_generate_recommendations_empty_findings() -> None:
    """No findings returns empty actions and by_finding arrays."""
    service = _service()
    result = service.generate_recommendations_for_findings([])
    assert result == {"actions": [], "by_finding": []}


def test_generate_recommendations_prioritized_actions() -> None:
    """Expected suggestions appear and critical issues are prioritized."""
    service = _service()

    findings = [
        VulnerabilityFindings(
            id=1,
            title="MongoDB No Authentication",
            description="",
            severity=SeverityLevel.CRITICAL,
            cvss_score=None,
            cve_id=None,
            affected_targets=[],
        ),
        VulnerabilityFindings(
            id=2,
            title="SSH Weak Ciphers",
            description="",
            severity=SeverityLevel.HIGH,
            cvss_score=None,
            cve_id=None,
            affected_targets=[],
        ),
        VulnerabilityFindings(
            id=3,
            title="TLS 1.0 Supported",
            description="",
            severity=SeverityLevel.MEDIUM,
            cvss_score=None,
            cve_id=None,
            affected_targets=[],
        ),
        VulnerabilityFindings(
            id=4,
            title="HTTP Server Information Disclosure",
            description="",
            severity=SeverityLevel.LOW,
            cvss_score=None,
            cve_id=None,
            affected_targets=[],
        ),
        VulnerabilityFindings(
            id=5,
            title="SQL Injection",
            description="",
            severity=SeverityLevel.HIGH,
            cvss_score=None,
            cve_id=None,
            affected_targets=[],
        ),
    ]

    recs = service.generate_recommendations_for_findings(findings)

    # Validate per-finding entries exist and are mapped
    assert len(recs["by_finding"]) == 5
    # Ensure some expected suggestions appear
    all_actions = {a["action"] for a in recs["actions"]}
    assert "Enable MongoDB authentication and role-based access control" in all_actions
    assert "Disable weak ciphers/MACs and enforce strong key exchange" in all_actions
    assert "Disable TLS 1.0 and 1.1; require TLS 1.2+" in all_actions
    assert "Hide server version headers and banner information" in all_actions
    assert "Use parameterized queries and input validation" in all_actions

    # Critical MongoDB action should have score >= High SSH/SQL
    def score_of(action: str) -> int:
        for item in recs["actions"]:
            if item["action"] == action:
                return int(item["score"])  # type: ignore
        return -1

    critical_score = score_of(
        "Enable MongoDB authentication and role-based access control"
    )
    ssh_score = score_of("Disable weak ciphers/MACs and enforce strong key exchange")
    sqlinj_score = score_of("Use parameterized queries and input validation")

    assert critical_score >= ssh_score
    assert critical_score >= sqlinj_score


def test_attach_recommendations_metadata_merges() -> None:
    """Recommendations are merged into metadata under the 'recommendations' key."""
    service = _service()
    base_meta: Dict[str, Any] = {"existing": True}
    recs = {"actions": [{"action": "x", "score": 1}], "by_finding": []}
    merged = service._attach_recommendations_metadata(base_meta, recs)
    assert merged["existing"] is True
    assert merged["recommendations"] == recs
