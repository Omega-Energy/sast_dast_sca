"""Tests for risk scoring model."""
from scorer import (
    calculate_risk_score,
    score_finding,
    VulnerabilityContext,
    ExploitMaturity,
    AssetCriticality,
    Exposure,
    DataSensitivity,
    RiskLevel,
)


def test_critical_vulnerability():
    """Critical: high CVSS + weaponized + internet-facing + mission-critical."""
    ctx = VulnerabilityContext(
        cvss_score=9.8,
        exploit_maturity=ExploitMaturity.WEAPONIZED,
        asset_criticality=AssetCriticality.MISSION_CRITICAL,
        exposure=Exposure.INTERNET_FACING,
        data_sensitivity=DataSensitivity.RESTRICTED,
    )
    result = calculate_risk_score(ctx)
    assert result.risk_level == RiskLevel.CRITICAL
    assert result.total_score >= 9.0
    assert result.sla_hours == 4


def test_high_vulnerability():
    """High: moderate CVSS + public PoC + DMZ."""
    ctx = VulnerabilityContext(
        cvss_score=7.5,
        exploit_maturity=ExploitMaturity.POC_PUBLIC,
        asset_criticality=AssetCriticality.BUSINESS_CRITICAL,
        exposure=Exposure.DMZ,
        data_sensitivity=DataSensitivity.CONFIDENTIAL,
    )
    result = calculate_risk_score(ctx)
    assert result.risk_level == RiskLevel.HIGH
    assert 7.0 <= result.total_score < 9.0
    assert result.sla_hours == 24


def test_medium_vulnerability():
    """Medium: moderate CVSS + no exploit + internal."""
    ctx = VulnerabilityContext(
        cvss_score=5.5,
        exploit_maturity=ExploitMaturity.THEORETICAL,
        asset_criticality=AssetCriticality.STANDARD,
        exposure=Exposure.INTERNAL,
        data_sensitivity=DataSensitivity.INTERNAL,
    )
    result = calculate_risk_score(ctx)
    assert result.risk_level == RiskLevel.MEDIUM
    assert 4.0 <= result.total_score < 7.0
    assert result.sla_hours == 168


def test_low_vulnerability():
    """Low: low CVSS + isolated + non-sensitive."""
    ctx = VulnerabilityContext(
        cvss_score=2.0,
        exploit_maturity=ExploitMaturity.THEORETICAL,
        asset_criticality=AssetCriticality.LOW,
        exposure=Exposure.ISOLATED,
        data_sensitivity=DataSensitivity.PUBLIC,
    )
    result = calculate_risk_score(ctx)
    assert result.risk_level == RiskLevel.LOW
    assert result.total_score < 4.0
    assert result.sla_hours == 720


def test_score_finding_simplified():
    """Test the simplified score_finding API."""
    result = score_finding(
        cvss=9.0,
        has_public_exploit=True,
        is_internet_facing=True,
        asset_type="mission_critical",
        data_type="restricted",
    )
    assert result["level"] == "CRITICAL"
    assert result["score"] >= 9.0
    assert result["sla_hours"] == 4


def test_breakdown_contains_all_factors():
    """Ensure breakdown includes all scoring factors."""
    ctx = VulnerabilityContext(cvss_score=5.0)
    result = calculate_risk_score(ctx)
    assert "factors" in result.breakdown
    assert "weights" in result.breakdown
    assert "weighted_scores" in result.breakdown
    assert all(k in result.breakdown["factors"] for k in [
        "cvss", "exploitability", "asset_criticality", "exposure", "data_sensitivity"
    ])


if __name__ == "__main__":
    test_critical_vulnerability()
    test_high_vulnerability()
    test_medium_vulnerability()
    test_low_vulnerability()
    test_score_finding_simplified()
    test_breakdown_contains_all_factors()
    print("All tests passed!")
