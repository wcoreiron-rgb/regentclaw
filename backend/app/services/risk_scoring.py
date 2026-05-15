"""
CoreOS — Risk Scoring Engine
Weighted scoring across events, identities, and modules.
"""
from typing import Optional


# Risk weights per event/signal
RISK_WEIGHTS = {
    "identity_anomaly": 30,
    "sensitive_target": 25,
    "new_connector": 20,
    "blocked_policy": 35,
    "privileged_request": 20,
    "off_hours_access": 15,
    "unusual_volume": 25,
    "ai_sensitive_pattern": 30,
    "orphaned_identity": 40,
    "shell_access_attempt": 50,
    "credential_access_attempt": 45,
    "exfiltration_pattern": 60,
    "new_external_domain": 20,
    "anomaly_detected": 35,
}

MAX_SCORE = 100.0


def calculate_event_risk(signals: list[str], base_score: float = 0.0) -> float:
    """Calculate risk score for an event given a list of signal keys."""
    score = base_score
    for signal in signals:
        score += RISK_WEIGHTS.get(signal, 5)
    return min(score, MAX_SCORE)


def severity_from_score(score: float) -> str:
    """Convert numeric risk score to severity label."""
    if score >= 70:
        return "critical"
    elif score >= 50:
        return "high"
    elif score >= 25:
        return "medium"
    elif score > 0:
        return "low"
    return "info"


def aggregate_module_risk(event_scores: list[float]) -> float:
    """Aggregate individual event scores into a module-level risk score."""
    if not event_scores:
        return 0.0
    # Weight recent events more, but keep it simple for MVP
    recent = event_scores[-10:]
    return min(sum(recent) / len(recent) if recent else 0.0, MAX_SCORE)


def compliance_weighted_score(base_score: float, frameworks: Optional[list[str]] = None) -> float:
    """
    Adjust score based on compliance framework relevance.
    E.g., HIPAA or PCI findings are weighted higher.
    """
    if not frameworks:
        return base_score
    high_weight_frameworks = {"HIPAA", "PCI-DSS", "FedRAMP"}
    if any(f in high_weight_frameworks for f in frameworks):
        return min(base_score * 1.25, MAX_SCORE)
    return base_score
