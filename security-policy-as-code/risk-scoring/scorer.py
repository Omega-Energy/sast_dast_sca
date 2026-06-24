"""
Risk scoring model for vulnerability prioritization.

Calculates a weighted risk score (0-10) based on multiple factors:
- CVSS base score
- Exploitability (public exploit available)
- Asset criticality
- Network exposure
- Data sensitivity
"""
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class RiskLevel(Enum):
    CRITICAL = "CRITICAL"  # 9.0 - 10.0
    HIGH = "HIGH"          # 7.0 - 8.9
    MEDIUM = "MEDIUM"      # 4.0 - 6.9
    LOW = "LOW"            # 0.1 - 3.9
    INFO = "INFO"          # 0.0


class ExploitMaturity(Enum):
    WEAPONIZED = "weaponized"      # Active exploitation in the wild
    POC_PUBLIC = "poc_public"      # Public proof-of-concept available
    POC_PRIVATE = "poc_private"    # Private/limited PoC
    THEORETICAL = "theoretical"    # No known exploit


class AssetCriticality(Enum):
    MISSION_CRITICAL = "mission_critical"  # Core business systems
    BUSINESS_CRITICAL = "business_critical"  # Important but not core
    STANDARD = "standard"                   # General systems
    LOW = "low"                             # Non-essential


class Exposure(Enum):
    INTERNET_FACING = "internet_facing"    # Publicly accessible
    DMZ = "dmz"                            # In DMZ
    INTERNAL = "internal"                  # Internal network only
    ISOLATED = "isolated"                  # Air-gapped/isolated


class DataSensitivity(Enum):
    RESTRICTED = "restricted"      # Top secret / regulated (PII, financial)
    CONFIDENTIAL = "confidential"  # Internal sensitive
    INTERNAL = "internal"          # Internal general
    PUBLIC = "public"              # Non-sensitive


# Weight configuration
WEIGHTS = {
    "cvss": 0.30,
    "exploitability": 0.25,
    "asset_criticality": 0.20,
    "exposure": 0.15,
    "data_sensitivity": 0.10,
}

# Factor score mappings (normalized to 0-10)
EXPLOIT_SCORES = {
    ExploitMaturity.WEAPONIZED: 10.0,
    ExploitMaturity.POC_PUBLIC: 7.5,
    ExploitMaturity.POC_PRIVATE: 5.0,
    ExploitMaturity.THEORETICAL: 2.0,
}

ASSET_SCORES = {
    AssetCriticality.MISSION_CRITICAL: 10.0,
    AssetCriticality.BUSINESS_CRITICAL: 7.0,
    AssetCriticality.STANDARD: 4.0,
    AssetCriticality.LOW: 1.0,
}

EXPOSURE_SCORES = {
    Exposure.INTERNET_FACING: 10.0,
    Exposure.DMZ: 7.0,
    Exposure.INTERNAL: 4.0,
    Exposure.ISOLATED: 1.0,
}

SENSITIVITY_SCORES = {
    DataSensitivity.RESTRICTED: 10.0,
    DataSensitivity.CONFIDENTIAL: 7.0,
    DataSensitivity.INTERNAL: 4.0,
    DataSensitivity.PUBLIC: 1.0,
}


@dataclass
class VulnerabilityContext:
    """Input context for risk scoring."""
    cvss_score: float = 0.0
    exploit_maturity: ExploitMaturity = ExploitMaturity.THEORETICAL
    asset_criticality: AssetCriticality = AssetCriticality.STANDARD
    exposure: Exposure = Exposure.INTERNAL
    data_sensitivity: DataSensitivity = DataSensitivity.INTERNAL
    # Optional overrides
    custom_weight_overrides: dict = field(default_factory=dict)


@dataclass
class RiskScore:
    """Output of risk scoring."""
    total_score: float
    risk_level: RiskLevel
    breakdown: dict
    recommendation: str
    sla_hours: int


def calculate_risk_score(ctx: VulnerabilityContext) -> RiskScore:
    """
    Calculate weighted risk score from vulnerability context.
    Returns a RiskScore with total 0-10, level, breakdown, and SLA.
    """
    weights = {**WEIGHTS, **ctx.custom_weight_overrides}

    # Normalize weights
    total_weight = sum(weights.values())
    weights = {k: v / total_weight for k, v in weights.items()}

    # Calculate factor scores
    factors = {
        "cvss": min(ctx.cvss_score, 10.0),
        "exploitability": EXPLOIT_SCORES[ctx.exploit_maturity],
        "asset_criticality": ASSET_SCORES[ctx.asset_criticality],
        "exposure": EXPOSURE_SCORES[ctx.exposure],
        "data_sensitivity": SENSITIVITY_SCORES[ctx.data_sensitivity],
    }

    # Weighted sum
    total = sum(factors[k] * weights[k] for k in factors)
    total = round(min(total, 10.0), 2)

    # Determine risk level
    if total >= 9.0:
        level = RiskLevel.CRITICAL
        sla = 4  # 4 hours
        recommendation = "Immediate response required. Escalate to security team."
    elif total >= 7.0:
        level = RiskLevel.HIGH
        sla = 24  # 24 hours
        recommendation = "Fix within 24 hours. Assign to senior engineer."
    elif total >= 4.0:
        level = RiskLevel.MEDIUM
        sla = 168  # 1 week
        recommendation = "Schedule fix in current sprint."
    elif total > 0.0:
        level = RiskLevel.LOW
        sla = 720  # 30 days
        recommendation = "Add to backlog. Fix in next maintenance window."
    else:
        level = RiskLevel.INFO
        sla = 0
        recommendation = "Informational only. No action required."

    breakdown = {
        "factors": {k: round(v, 2) for k, v in factors.items()},
        "weights": {k: round(v, 3) for k, v in weights.items()},
        "weighted_scores": {k: round(factors[k] * weights[k], 3) for k in factors},
    }

    return RiskScore(
        total_score=total,
        risk_level=level,
        breakdown=breakdown,
        recommendation=recommendation,
        sla_hours=sla,
    )


def score_finding(
    cvss: float,
    has_public_exploit: bool = False,
    is_internet_facing: bool = False,
    asset_type: str = "standard",
    data_type: str = "internal",
) -> dict:
    """
    Simplified scoring function for integration with scan results.
    Returns a dict with score, level, and sla.
    """
    exploit = ExploitMaturity.POC_PUBLIC if has_public_exploit else ExploitMaturity.THEORETICAL
    exposure = Exposure.INTERNET_FACING if is_internet_facing else Exposure.INTERNAL

    asset_map = {
        "mission_critical": AssetCriticality.MISSION_CRITICAL,
        "business_critical": AssetCriticality.BUSINESS_CRITICAL,
        "standard": AssetCriticality.STANDARD,
        "low": AssetCriticality.LOW,
    }

    data_map = {
        "restricted": DataSensitivity.RESTRICTED,
        "confidential": DataSensitivity.CONFIDENTIAL,
        "internal": DataSensitivity.INTERNAL,
        "public": DataSensitivity.PUBLIC,
    }

    ctx = VulnerabilityContext(
        cvss_score=cvss,
        exploit_maturity=exploit,
        asset_criticality=asset_map.get(asset_type, AssetCriticality.STANDARD),
        exposure=exposure,
        data_sensitivity=data_map.get(data_type, DataSensitivity.INTERNAL),
    )

    result = calculate_risk_score(ctx)
    return {
        "score": result.total_score,
        "level": result.risk_level.value,
        "sla_hours": result.sla_hours,
        "recommendation": result.recommendation,
    }
