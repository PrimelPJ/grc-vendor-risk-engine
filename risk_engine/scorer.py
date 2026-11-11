"""
risk_engine/scorer.py

Multi-dimensional vendor risk scoring engine exposed via gRPC.
Implements a weighted penalty-function model aligned with NIST CSF 2.0
and ISO/IEC 27001:2022 Annex A control domains.
"""

from __future__ import annotations

import logging
import math
from concurrent import futures
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

import grpc

# Stub imports — generated from proto/risk.proto via protoc
# from proto import risk_pb2, risk_pb2_grpc

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Domain enumerations
# ---------------------------------------------------------------------------

class RiskBand(str, Enum):
    LOW      = "LOW"
    MEDIUM   = "MEDIUM"
    HIGH     = "HIGH"
    CRITICAL = "CRITICAL"


# ---------------------------------------------------------------------------
# Dimension weight configuration
# ---------------------------------------------------------------------------

DIMENSION_WEIGHTS: dict[str, float] = {
    "security":    0.30,
    "privacy":     0.25,
    "resilience":  0.20,
    "compliance":  0.15,
    "financial":   0.10,
}

assert math.isclose(sum(DIMENSION_WEIGHTS.values()), 1.0), \
    "Dimension weights must sum to 1.0"


# ---------------------------------------------------------------------------
# Sub-criterion penalty definitions
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Criterion:
    """A single binary or scalar sub-criterion within a risk dimension."""
    name: str
    weight: float          # Relative importance within its dimension (0–1)
    critical: bool = False  # If True, failure here hard-floors the dimension score


SECURITY_CRITERIA: list[Criterion] = [
    Criterion("mfa_enforced",      weight=0.30, critical=True),
    Criterion("pen_tested",        weight=0.25, critical=False),
    Criterion("vuln_sla_met",      weight=0.25, critical=True),
    Criterion("siem_deployed",     weight=0.10, critical=False),
    Criterion("zero_trust_arch",   weight=0.10, critical=False),
]

PRIVACY_CRITERIA: list[Criterion] = [
    Criterion("ndpa_compliant",         weight=0.35, critical=True),
    Criterion("dpa_appointed",          weight=0.25, critical=False),
    Criterion("no_cross_border",        weight=0.25, critical=False),
    Criterion("data_minimization",      weight=0.15, critical=False),
]

RESILIENCE_CRITERIA: list[Criterion] = [
    Criterion("rto_acceptable",    weight=0.35, critical=False),
    Criterion("rpo_acceptable",    weight=0.35, critical=False),
    Criterion("dr_tested",         weight=0.30, critical=True),
]

COMPLIANCE_CRITERIA: list[Criterion] = [
    Criterion("iso27001",          weight=0.40, critical=False),
    Criterion("soc2_type2",        weight=0.25, critical=False),
    Criterion("gdpr_adequate",     weight=0.20, critical=False),
    Criterion("pci_dss",           weight=0.15, critical=False),
]

FINANCIAL_CRITERIA: list[Criterion] = [
    Criterion("years_adequate",    weight=0.50, critical=False),
    Criterion("publicly_traded",   weight=0.30, critical=False),
    Criterion("no_public_breach",  weight=0.20, critical=True),
]

DIMENSION_CRITERIA: dict[str, list[Criterion]] = {
    "security":   SECURITY_CRITERIA,
    "privacy":    PRIVACY_CRITERIA,
    "resilience": RESILIENCE_CRITERIA,
    "compliance": COMPLIANCE_CRITERIA,
    "financial":  FINANCIAL_CRITERIA,
}

# Threshold constants used by the normalizer methods
MIN_YEARS_OPERATING: int = 3   # Minimum years for a vendor to pass the financial stability check
MAX_VULN_SLA_DAYS:   int = 30  # Maximum acceptable critical vulnerability remediation SLA


# ---------------------------------------------------------------------------
# Score computation
# ---------------------------------------------------------------------------

class PenaltyScorer:
    """
    Computes a dimension score in [0, 100] using a multiplicative survival
    penalty model. For each failed criterion, a penalty proportional to its
    weight is compounded. Critical criterion failures impose a hard floor of 20.

    Score formula (adapted from fault-tree analysis):
        raw_score = 100 * prod(1 - p_j) for all failed criteria j
        if any critical criterion failed: score = max(raw_score, 20) applied as ceiling
    """

    CRITICAL_CEILING = 20.0  # Hard ceiling when a critical criterion fails

    def score_dimension(
        self,
        criteria: list[Criterion],
        responses: dict[str, bool],
    ) -> tuple[float, list[str]]:
        """
        Returns (dimension_score, list_of_failed_criteria).

        Args:
            criteria:  Ordered list of Criterion definitions for this dimension.
            responses: Map of criterion.name -> pass/fail boolean.
        """
        survival = 1.0
        failures: list[str] = []
        critical_failure = False

        for c in criteria:
            passed = responses.get(c.name, False)
            if not passed:
                failures.append(c.name)
                # Multiplicative penalty: each failure reduces the survival product
                survival *= (1.0 - c.weight)
                if c.critical:
                    critical_failure = True

        raw_score = 100.0 * survival

        if critical_failure:
            return min(raw_score, self.CRITICAL_CEILING), failures

        return raw_score, failures


class VendorRiskScorer:
    """
    Orchestrates multi-dimensional vendor risk scoring and produces a
    composite weighted score with classification band.
    """

    def __init__(self) -> None:
        self._penalty_scorer = PenaltyScorer()

    def _normalize_security(self, payload: dict) -> dict[str, bool]:
        vuln_sla_days = payload.get("vuln_sla_days", 999)
        return {
            "mfa_enforced":    bool(payload.get("mfa_enforced", False)),
            "pen_tested":      bool(payload.get("pen_tested", False)),
            "vuln_sla_met":    vuln_sla_days <= MAX_VULN_SLA_DAYS,
            "siem_deployed":   bool(payload.get("siem_deployed", False)),
            "zero_trust_arch": bool(payload.get("zero_trust_arch", False)),
        }

    def _normalize_privacy(self, payload: dict) -> dict[str, bool]:
        return {
            "ndpa_compliant":   bool(payload.get("ndpa_compliant", False)),
            "dpa_appointed":    bool(payload.get("dpa_appointed", False)),
            "no_cross_border":  not bool(payload.get("cross_border_transfers", True)),
            "data_minimization": bool(payload.get("data_minimization", False)),
        }

    def _normalize_resilience(self, payload: dict) -> dict[str, bool]:
        rto_hours = payload.get("rto_hours", 999)
        rpo_hours = payload.get("rpo_hours", 999)
        return {
            "rto_acceptable": rto_hours <= 8,
            "rpo_acceptable": rpo_hours <= 4,
            "dr_tested":      bool(payload.get("dr_tested", False)),
        }

    def _normalize_compliance(self, payload: dict) -> dict[str, bool]:
        return {
            "iso27001":     bool(payload.get("iso27001", False)),
            "soc2_type2":   bool(payload.get("soc2_type2", False)),
            "gdpr_adequate": bool(payload.get("gdpr_adequate", False)),
            "pci_dss":      bool(payload.get("pci_dss", False)),
        }

    def _normalize_financial(self, payload: dict) -> dict[str, bool]:
        years = payload.get("years_operating", 0)
        return {
            "years_adequate":   years >= MIN_YEARS_OPERATING,
            "publicly_traded":  bool(payload.get("public_company", False)),
            "no_public_breach": not bool(payload.get("public_breach_history", False)),
        }

    def _classify(self, score: float) -> RiskBand:
        if score >= 75:
            return RiskBand.LOW
        if score >= 50:
            return RiskBand.MEDIUM
        if score >= 25:
            return RiskBand.HIGH
        return RiskBand.CRITICAL

    def score(self, vendor_id: str, assessment_payload: dict) -> dict:
        """
        Entry point for a full vendor risk assessment.

        Returns a structured result dict:
        {
            "vendor_id":        str,
            "composite_score":  float,
            "risk_band":        str,
            "dimension_scores": { dimension: float },
            "failures":         { dimension: [str] },
        }
        """
        normalizers = {
            "security":   self._normalize_security,
            "privacy":    self._normalize_privacy,
            "resilience": self._normalize_resilience,
            "compliance": self._normalize_compliance,
            "financial":  self._normalize_financial,
        }

        dimension_scores: dict[str, float] = {}
        all_failures: dict[str, list[str]] = {}

        for dim, normalize_fn in normalizers.items():
            dim_payload = assessment_payload.get(dim, {})
            responses = normalize_fn(dim_payload)
            score, failures = self._penalty_scorer.score_dimension(
                DIMENSION_CRITERIA[dim], responses
            )
            dimension_scores[dim] = round(score, 2)
            all_failures[dim] = failures

        composite = sum(
            DIMENSION_WEIGHTS[dim] * score
            for dim, score in dimension_scores.items()
        )

        result = {
            "vendor_id":        vendor_id,
            "composite_score":  round(composite, 2),
            "risk_band":        self._classify(composite).value,
            "dimension_scores": dimension_scores,
            "failures":         all_failures,
        }

        logger.info(
            "Assessment complete | vendor=%s score=%.2f band=%s",
            vendor_id, composite, result["risk_band"],
        )
        return result


# ---------------------------------------------------------------------------
# gRPC service implementation (stub — wire up after protoc codegen)
# ---------------------------------------------------------------------------

class RiskScoringServicer:
    """gRPC servicer wrapping VendorRiskScorer."""

    def __init__(self) -> None:
        self._scorer = VendorRiskScorer()

    def ScoreVendor(self, request, context):
        """Handles RPC ScoreVendor(VendorProfile) returns RiskScoreResponse."""
        payload = {
            "security":   dict(request.security.__dict__),
            "privacy":    dict(request.privacy.__dict__),
            "resilience": dict(request.resilience.__dict__),
            "compliance": dict(request.compliance.__dict__),
            "financial":  dict(request.financial.__dict__),
        }
        result = self._scorer.score(request.vendor_id, payload)
        # Construct and return protobuf response
        # return risk_pb2.RiskScoreResponse(**result)
        return result


def serve(port: int = 50051) -> None:
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=8))
    # risk_pb2_grpc.add_RiskScoringServicer_to_server(RiskScoringServicer(), server)
    server.add_insecure_port(f"[::]:{port}")
    server.start()
    logger.info("Risk scoring gRPC server listening on :%d", port)
    server.wait_for_termination()


if __name__ == "__main__":
    serve()
