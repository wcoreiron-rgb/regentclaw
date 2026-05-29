"""
pytest tests for RegentClaw ring policy.
Pure Python — no async, no database, no fixtures required.

Run:
    pytest backend/tests/test_ring_policy.py -v
"""
import pytest
import sys
import os

# Allow running from repo root without installing the package
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from app.services.ring_policy import (
    classify_ring,
    evaluate_ring,
    ring_to_int,
    ACTION_RING_MAP,
    CHANNEL_RING_MAP,
    RING_REQUIREMENTS,
)


# ─── ring0 ────────────────────────────────────────────────────────────────────

def test_ring0_always_blocked():
    """ring0 actions must be unconditionally denied with execution_ring_violation policy."""
    result = evaluate_ring("ring0", trust_score=100.0, caller_role="super_admin")
    assert result["allowed"] is False
    assert result["requires_approval"] is False
    assert result["approvals_required"] == 0
    assert result["policy_name"] == "execution_ring_violation"
    assert result["deny_reason"] is not None
    assert len(result["deny_reason"]) > 0


def test_ring0_blocked_regardless_of_role():
    """Even the highest privilege role cannot execute ring0 actions."""
    for role in ("super_admin", "admin", "security_admin", "root", "viewer"):
        result = evaluate_ring("ring0", trust_score=100.0, caller_role=role)
        assert result["allowed"] is False, f"ring0 should be blocked for role={role}"
        assert result["policy_name"] == "execution_ring_violation"


def test_ring0_blocked_kernel_action():
    """kernel_exec maps to ring0 and must be blocked."""
    ring = classify_ring("kernel_exec")
    assert ring == "ring0"
    result = evaluate_ring(ring, trust_score=99.0, caller_role="admin")
    assert result["allowed"] is False
    assert result["policy_name"] == "execution_ring_violation"


# ─── ring1 ────────────────────────────────────────────────────────────────────

def test_ring1_requires_two_approvals():
    """ring1 action with admin role requires 2 approvals and is not yet allowed."""
    result = evaluate_ring("ring1", trust_score=95.0, caller_role="admin")
    assert result["allowed"] is False
    assert result["requires_approval"] is True
    assert result["approvals_required"] == 2
    assert result["deny_reason"] is None  # not a hard deny — pending approval


def test_ring1_high_trust_still_requires_approval():
    """ring1 cannot be bypassed by trust score alone — always requires 2 approvals."""
    result = evaluate_ring("ring1", trust_score=100.0, caller_role="security_admin")
    assert result["requires_approval"] is True
    assert result["approvals_required"] == 2
    assert result["allowed"] is False


def test_ring1_privileged_actions_mapped():
    """All ring1 action types must resolve to ring1."""
    ring1_actions = [
        "quarantine_device", "suspend_user", "revoke_sessions",
        "disable_iam_user", "deactivate_access_key", "attach_deny_policy",
        "delete_secret", "revoke_token",
    ]
    for action in ring1_actions:
        ring = classify_ring(action)
        assert ring == "ring1", f"Expected ring1 for action={action}, got {ring}"


# ─── ring2 ────────────────────────────────────────────────────────────────────

def test_ring2_auto_allowed_high_trust():
    """ring2 action with trust_score >= 80 and admin role should be auto-allowed."""
    result = evaluate_ring("ring2", trust_score=90.0, caller_role="admin")
    assert result["allowed"] is True
    assert result["requires_approval"] is False
    assert result["approvals_required"] == 0
    assert result["deny_reason"] is None


def test_ring2_auto_allowed_at_threshold():
    """ring2 is auto-allowed at exactly trust_score=80."""
    result = evaluate_ring("ring2", trust_score=80.0, caller_role="analyst")
    assert result["allowed"] is True
    assert result["requires_approval"] is False


def test_ring2_requires_approval_low_trust():
    """ring2 action with trust_score < 80 requires 1 approval."""
    result = evaluate_ring("ring2", trust_score=40.0, caller_role="analyst")
    assert result["allowed"] is False
    assert result["requires_approval"] is True
    assert result["approvals_required"] == 1
    assert result["deny_reason"] is None


def test_ring2_requires_approval_zero_trust():
    """ring2 with trust_score=0 requires 1 approval."""
    result = evaluate_ring("ring2", trust_score=0.0, caller_role="admin")
    assert result["requires_approval"] is True
    assert result["approvals_required"] == 1


def test_ring2_standard_actions_mapped():
    """All ring2 action types must resolve to ring2."""
    ring2_actions = [
        "create_ticket", "send_alert", "slack_message", "force_mfa_reset",
        "remove_group_member", "kill_process", "unquarantine_device", "webhook",
    ]
    for action in ring2_actions:
        ring = classify_ring(action)
        assert ring == "ring2", f"Expected ring2 for action={action}, got {ring}"


# ─── ring3 ────────────────────────────────────────────────────────────────────

def test_ring3_always_allowed():
    """ring3 actions are auto-allowed for any caller."""
    result = evaluate_ring("ring3", trust_score=0.0, caller_role="viewer")
    assert result["allowed"] is True
    assert result["requires_approval"] is False
    assert result["approvals_required"] == 0
    assert result["deny_reason"] is None


def test_ring3_unprivileged_actions_mapped():
    """All ring3 action types must resolve to ring3."""
    ring3_actions = ["read_logs", "get_findings", "lookup_cve", "list_resources", "get_status"]
    for action in ring3_actions:
        ring = classify_ring(action)
        assert ring == "ring3", f"Expected ring3 for action={action}, got {ring}"


# ─── classify_ring ────────────────────────────────────────────────────────────

def test_classify_ring_shell_channel():
    """channel='shell' must map to ring1."""
    ring = classify_ring(action_type="", channel="shell")
    assert ring == "ring1"


def test_classify_ring_kernel_channel():
    """channel='kernel' must map to ring0."""
    ring = classify_ring(action_type="", channel="kernel")
    assert ring == "ring0"


def test_classify_ring_unknown_action():
    """Unknown action_type with no channel defaults to ring2."""
    ring = classify_ring("totally_unknown_action_xyz")
    assert ring == "ring2"


def test_classify_ring_unknown_action_and_channel():
    """Completely unknown action and channel defaults to ring2."""
    ring = classify_ring("mystery_op", "mystery_channel")
    assert ring == "ring2"


def test_classify_ring_action_overrides_channel_more_restrictive():
    """When action is ring1 and channel is ring3, ring1 (more restrictive) wins."""
    ring = classify_ring("quarantine_device", "api")
    assert ring == "ring1"


def test_classify_ring_channel_overrides_action_more_restrictive():
    """When action is ring3 and channel is ring1 (shell), ring1 wins."""
    ring = classify_ring("read_logs", "shell")
    assert ring == "ring1"


def test_classify_ring_api_channel():
    """channel='api' maps to ring3."""
    ring = classify_ring(action_type="", channel="api")
    assert ring == "ring3"


def test_classify_ring_browser_channel():
    """channel='browser' maps to ring2."""
    ring = classify_ring(action_type="", channel="browser")
    assert ring == "ring2"


# ─── ring_to_int ──────────────────────────────────────────────────────────────

def test_ring_to_int_values():
    """ring_to_int must return correct integers 0-3."""
    assert ring_to_int("ring0") == 0
    assert ring_to_int("ring1") == 1
    assert ring_to_int("ring2") == 2
    assert ring_to_int("ring3") == 3


def test_ring_to_int_unknown_defaults_to_2():
    """Unknown ring string defaults to 2."""
    assert ring_to_int("ringX") == 2
    assert ring_to_int("") == 2


# ─── role escalation ─────────────────────────────────────────────────────────

def test_ring_escalation_blocked_viewer():
    """caller_role='viewer' requesting ring1 action is denied (ring violation)."""
    result = evaluate_ring("ring1", trust_score=100.0, caller_role="viewer")
    assert result["allowed"] is False
    assert result["requires_approval"] is False
    assert result["policy_name"] == "execution_ring_violation"
    assert "viewer" in result["deny_reason"]


def test_ring_escalation_blocked_readonly():
    """caller_role='readonly' requesting ring1 action is denied."""
    result = evaluate_ring("ring1", trust_score=100.0, caller_role="readonly")
    assert result["allowed"] is False
    assert result["policy_name"] == "execution_ring_violation"


def test_ring_escalation_blocked_guest():
    """caller_role='guest' requesting ring1 action is denied."""
    result = evaluate_ring("ring1", trust_score=100.0, caller_role="guest")
    assert result["allowed"] is False
    assert result["policy_name"] == "execution_ring_violation"


def test_ring3_viewer_allowed():
    """Viewer can still execute ring3 (read-only) actions."""
    result = evaluate_ring("ring3", trust_score=10.0, caller_role="viewer")
    assert result["allowed"] is True


# ─── RING_REQUIREMENTS schema ─────────────────────────────────────────────────

def test_ring_requirements_all_rings_present():
    """All four rings must be present in RING_REQUIREMENTS."""
    for ring in ("ring0", "ring1", "ring2", "ring3"):
        assert ring in RING_REQUIREMENTS, f"Missing {ring} in RING_REQUIREMENTS"


def test_ring0_is_blocked_in_requirements():
    """RING_REQUIREMENTS[ring0] must have blocked=True."""
    assert RING_REQUIREMENTS["ring0"]["blocked"] is True


def test_ring1_approvals_required():
    """RING_REQUIREMENTS[ring1] approvals_required must be 2."""
    assert RING_REQUIREMENTS["ring1"]["approvals_required"] == 2


def test_ring2_approvals_required():
    """RING_REQUIREMENTS[ring2] approvals_required must be 1."""
    assert RING_REQUIREMENTS["ring2"]["approvals_required"] == 1


def test_ring3_approvals_required():
    """RING_REQUIREMENTS[ring3] approvals_required must be 0."""
    assert RING_REQUIREMENTS["ring3"]["approvals_required"] == 0
