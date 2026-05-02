"""
risk_engine/models.py

Pydantic v2 domain models for vendor risk assessment payloads.
Enforces input validation, range constraints, and field documentation
aligned with ISO 27001:2022 Annex A and NIST CSF 2.0 sub-categories.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, field_validator, model_validator


# ---------------------------------------------------------------------------
# Dimension-level input models
# ---------------------------------------------------------------------------

class SecurityProfile(BaseModel):
    """
    Maps to NIST CSF 2.0 — Protect (PR) and Detect (DE) function categories.
    Captures administrative and technical controls in scope for vendor assessment.
    """
    mfa_enforced: bool = Field(
        default=False,
        description="Multi-factor authentication enforced for all privileged accounts.",
    )
    pen_tested: bool = Field(
        default=False,
        description="External penetration test conducted within the last 12 months.",
    )
    vuln_sla_days: Annotated[int, Field(ge=0, le=365)] = Field(
        default=90,
        description="Contractual SLA (days) for critical vulnerability remediation.",
    )
    siem_deployed: bool = Field(
        default=False,
        description="Security Information and Event Management system actively monitored.",
    )
    zero_trust_arch: bool = Field(
        default=False,
        description="Zero Trust network architecture principles formally adopted.",
    )


class PrivacyProfile(BaseModel):
    """
    Maps to NDPA Article 24 (data processor obligations) and Kenya DPA Section 41
    (cross-border data transfers). Evaluates data governance posture.
    """
    ndpa_compliant: bool = Field(
        default=False,
        description="Vendor has documented NDPA compliance program in place.",
    )
    dpa_appointed: bool = Field(
        default=False,
        description="Data Protection Officer or equivalent formally appointed.",
    )
    cross_border_transfers: bool = Field(
        default=True,
        description="Personal data transferred outside the originating jurisdiction.",
    )
    data_minimization: bool = Field(
        default=False,
        description="Formal data minimization and retention policies enforced.",
    )


class ResilienceProfile(BaseModel):
    """
    Captures operational continuity posture per ISO 22301 and NIST CSF Recover (RC).
    """
    rto_hours: Annotated[int, Field(ge=0, le=720)] = Field(
        default=48,
        description="Recovery Time Objective in hours for critical business processes.",
    )
    rpo_hours: Annotated[int, Field(ge=0, le=720)] = Field(
        default=24,
        description="Recovery Point Objective in hours (maximum tolerable data loss).",
    )
    dr_tested: bool = Field(
        default=False,
        description="Disaster Recovery plan tested within the last 12 months.",
    )

    @field_validator("rpo_hours")
    @classmethod
    def rpo_must_not_exceed_rto(cls, v: int, info) -> int:
        rto = info.data.get("rto_hours")
        if rto is not None and v > rto:
            raise ValueError(
                f"RPO ({v}h) cannot exceed RTO ({rto}h) — logically inconsistent."
            )
        return v


class ComplianceProfile(BaseModel):
    """Tracks third-party certification and regulatory attestation status."""
    iso27001: bool = Field(
        default=False,
        description="ISO/IEC 27001:2022 certification current and in scope.",
    )
    soc2_type2: bool = Field(
        default=False,
        description="SOC 2 Type II report issued within the past 12 months.",
    )
    gdpr_adequate: bool = Field(
        default=False,
        description="Vendor operates from GDPR-adequate jurisdiction or has BCRs.",
    )


class FinancialProfile(BaseModel):
    """Proxy indicators for organizational stability and breach history."""
    years_operating: Annotated[int, Field(ge=0, le=200)] = Field(
        default=0,
        description="Number of years the vendor has been in continuous operation.",
    )
    public_company: bool = Field(
        default=False,
        description="Vendor is publicly listed (provides financial transparency).",
    )
    public_breach_history: bool = Field(
        default=False,
        description="Vendor has a publicly disclosed material data breach on record.",
    )


# ---------------------------------------------------------------------------
# Top-level request / response models
# ---------------------------------------------------------------------------

class VendorAssessmentRequest(BaseModel):
    """Full vendor assessment intake payload."""
    vendor_id: str = Field(
        ...,
        min_length=3,
        max_length=128,
        pattern=r"^[a-zA-Z0-9_\-]+$",
        description="Unique vendor identifier (slug format).",
    )
    security:   SecurityProfile   = Field(default_factory=SecurityProfile)
    privacy:    PrivacyProfile    = Field(default_factory=PrivacyProfile)
    resilience: ResilienceProfile = Field(default_factory=ResilienceProfile)
    compliance: ComplianceProfile = Field(default_factory=ComplianceProfile)
    financial:  FinancialProfile  = Field(default_factory=FinancialProfile)
    submitted_by: Optional[str] = Field(
        default=None,
        description="Analyst ID or email submitting this assessment.",
    )


class DimensionBreakdown(BaseModel):
    score:    float
    failures: list[str]


class VendorAssessmentResponse(BaseModel):
    """Structured risk score response returned to API consumers."""
    assessment_id:   str = Field(default_factory=lambda: str(uuid4()))
    vendor_id:       str
    composite_score: float = Field(ge=0.0, le=100.0)
    risk_band:       str
    dimension_scores: dict[str, float]
    failures:        dict[str, list[str]]
    assessed_at:     datetime = Field(default_factory=datetime.utcnow)
    report_url:      Optional[str] = None

    model_config = {"json_schema_extra": {
        "example": {
            "assessment_id": "3f7a1bc2-...",
            "vendor_id": "vendor-abc-123",
            "composite_score": 68.45,
            "risk_band": "MEDIUM",
            "dimension_scores": {
                "security": 72.5,
                "privacy": 60.0,
                "resilience": 85.0,
                "compliance": 50.0,
                "financial": 80.0,
            },
            "failures": {
                "security": ["zero_trust_arch"],
                "privacy": ["data_minimization"],
                "resilience": [],
                "compliance": ["soc2_type2", "gdpr_adequate"],
                "financial": [],
            },
        }
    }}
