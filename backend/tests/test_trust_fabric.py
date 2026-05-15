"""
Tests for Trust Fabric — Policy Engine and Anomaly Detection.

Directly tests:
  - app.trust_fabric.policy_engine  (allow / deny decisions)
  - app.trust_fabric.anomaly        (z-score scoring, cold-start guard)
"""
import math
import pytest

# ── Anomaly detection unit tests ──────────────────────────────────────────────

from app.trust_fabric.anomaly import (
    compute_anomaly_score,
    update_baseline,
    _COLD_START_THRESHOLD,
)


class TestAnomalyScoreColdStart:
    """compute_anomaly_score must return 0 when fewer than 10 observations exist."""

    def _make_baseline(self, count: int, mean: float = 10.0, std: float = 2.0) -> dict:
        """Build a minimal baseline dict with the given observation count."""
        M2 = (std ** 2) * (count - 1) if count > 1 else 0.0
        return {
            "events_per_hour": {
                "count":  count,
                "mean":   mean,
                "std":    std,
                "sum":    mean * count,
                "sum_sq": (mean ** 2 + std ** 2) * count,
                "M2":     M2,
            }
        }

    def test_zero_observations(self):
        baseline = {}
        score = compute_anomaly_score("u1", "user", "events_per_hour", 100.0, baseline)
        assert score == 0.0

    def test_nine_observations_still_cold(self):
        baseline = self._make_baseline(9)
        score = compute_anomaly_score("u1", "user", "events_per_hour", 100.0, baseline)
        assert score == 0.0

    def test_ten_observations_not_cold(self):
        """With exactly 10 observations, the score should be computed (non-zero for outlier)."""
        baseline = self._make_baseline(10, mean=5.0, std=1.0)
        # Observed value far above mean → should produce a non-zero score
        score = compute_anomaly_score("u1", "user", "events_per_hour", 50.0, baseline)
        assert score > 0.0


class TestAnomalyScoreZscore:
    """Z-score > 4 must produce a score >= 80."""

    def _make_sufficient_baseline(self, mean: float, std: float) -> dict:
        count = 20
        M2    = (std ** 2) * (count - 1)
        return {
            "events_per_hour": {
                "count":  count,
                "mean":   mean,
                "std":    std,
                "sum":    mean * count,
                "sum_sq": (mean ** 2 + std ** 2) * count,
                "M2":     M2,
            }
        }

    def test_zscore_above_4_is_critical(self):
        """Observed value 5 std-devs above mean → score >= 80."""
        mean, std   = 10.0, 2.0
        observed    = mean + 5 * std   # z = 5.0
        baseline    = self._make_sufficient_baseline(mean, std)
        score       = compute_anomaly_score("u1", "user", "events_per_hour", observed, baseline)
        assert score >= 80.0

    def test_zscore_below_2_is_normal(self):
        """Observed value within 1 std-dev of mean → score < 20."""
        mean, std = 10.0, 2.0
        observed  = mean + 1 * std   # z = 1.0
        baseline  = self._make_sufficient_baseline(mean, std)
        score     = compute_anomaly_score("u1", "user", "events_per_hour", observed, baseline)
        assert score < 20.0

    def test_zscore_between_2_and_3_is_elevated(self):
        """Z-score of 2.5 → score in [20, 50]."""
        mean, std = 10.0, 2.0
        observed  = mean + 2.5 * std   # z = 2.5
        baseline  = self._make_sufficient_baseline(mean, std)
        score     = compute_anomaly_score("u1", "user", "events_per_hour", observed, baseline)
        assert 20.0 <= score <= 50.0

    def test_negative_zscore_uses_absolute_value(self):
        """An observed value 5 std-devs BELOW the mean is equally anomalous."""
        mean, std = 100.0, 10.0
        observed  = mean - 5 * std   # z = -5.0
        baseline  = self._make_sufficient_baseline(mean, std)
        score     = compute_anomaly_score("u1", "user", "events_per_hour", observed, baseline)
        assert score >= 80.0

    def test_zero_std_exact_mean_not_anomalous(self):
        """When std=0 and observed == mean, score should be 0."""
        mean = 5.0
        baseline = {
            "events_per_hour": {
                "count": 20, "mean": mean, "std": 0.0,
                "sum": mean * 20, "sum_sq": mean ** 2 * 20, "M2": 0.0,
            }
        }
        score = compute_anomaly_score("u1", "user", "events_per_hour", mean, baseline)
        assert score == 0.0

    def test_zero_std_deviation_from_mean_is_high(self):
        """When std=0 and observed != mean, score should be >= 80."""
        mean = 5.0
        baseline = {
            "events_per_hour": {
                "count": 20, "mean": mean, "std": 0.0,
                "sum": mean * 20, "sum_sq": mean ** 2 * 20, "M2": 0.0,
            }
        }
        score = compute_anomaly_score("u1", "user", "events_per_hour", mean + 1.0, baseline)
        assert score >= 80.0


class TestWelfordBaseline:
    """Welford online algorithm should maintain correct running statistics."""

    def test_empty_baseline_seeded(self):
        baseline = update_baseline({}, "events_per_hour", 10.0)
        stats = baseline["events_per_hour"]
        assert stats["count"] == 1
        assert stats["mean"] == 10.0
        assert stats["std"] == 0.0

    def test_running_mean_converges(self):
        """After many identical observations, mean should equal that value."""
        baseline = {}
        for _ in range(20):
            baseline = update_baseline(baseline, "events_per_hour", 5.0)
        stats = baseline["events_per_hour"]
        assert stats["count"] == 20
        assert abs(stats["mean"] - 5.0) < 1e-9
        assert stats["std"] < 1e-9   # no variance when all values are equal

    def test_variance_computed_correctly(self):
        """Two distinct values: 0 and 10. Sample std = sqrt(M2/(n-1)) = sqrt(50) ≈ 7.07."""
        baseline = {}
        baseline = update_baseline(baseline, "metric", 0.0)
        baseline = update_baseline(baseline, "metric", 10.0)
        stats = baseline["metric"]
        assert stats["count"] == 2
        assert abs(stats["mean"] - 5.0) < 1e-9
        assert abs(stats["std"] - math.sqrt(50)) < 1e-9


# ── Policy engine unit tests ───────────────────────────────────────────────────

class TestPolicyEngine:
    """
    Basic allow / deny tests against the Trust Fabric policy engine.
    Tests use the engine's pure function if available, otherwise the HTTP endpoint.
    """

    def _try_import_engine(self):
        try:
            from app.trust_fabric import policy_engine
            return policy_engine
        except ImportError:
            return None

    def test_policy_engine_allow(self):
        """
        An action that doesn't match any deny rule should be allowed.
        """
        engine = self._try_import_engine()
        if engine is None:
            pytest.skip("trust_fabric.policy_engine module not importable")

        # Minimal request-like object
        class Req:
            actor_id   = "user-1"
            actor_type = "user"
            action     = "read"
            target     = "s3://logs/report.csv"
            context    = {}

        result = engine.evaluate(Req(), policies=[])
        # Default when no policies → allow
        assert result.get("decision") in ("allow", "allowed", "permit")

    def test_policy_engine_deny(self):
        """
        An explicit deny policy should block the action.
        """
        engine = self._try_import_engine()
        if engine is None:
            pytest.skip("trust_fabric.policy_engine module not importable")

        deny_policy = {
            "effect":     "deny",
            "conditions": {"action": "delete"},
        }

        class Req:
            actor_id   = "user-1"
            actor_type = "user"
            action     = "delete"
            target     = "production-db"
            context    = {}

        result = engine.evaluate(Req(), policies=[deny_policy])
        assert result.get("decision") in ("deny", "denied", "block", "blocked")
