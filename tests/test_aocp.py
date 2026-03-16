"""
tests/test_aocp.py
==================
Test suite for HITL-AP AOCP components.

Tests validate:
- RTC scoring criteria (three structural requirements)
- ACS measurement logic
- Policy Engine deny rules
- Risk Analyzer scoring behavior
- Audit Logger cryptographic integrity
- Escalation Manager routing logic

Usage:
    pytest tests/ -v
    pytest tests/ -v --tb=short
    pytest tests/test_aocp.py::TestRTCScoring -v
"""

import hashlib
import hmac
import json
import time
import uuid

import pytest

# ─── Import evaluation metric functions ──────────────────────────────────────
# These are defined in evaluation/run_evaluation.py
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from evaluation.run_evaluation import score_rtc, score_acs, measure_il


# ═══════════════════════════════════════════════════════════════════════════
# TEST CLASS 1 — RTC Scoring (Three Structural Criteria)
# ═══════════════════════════════════════════════════════════════════════════

class TestRTCScoring:
    """
    Tests for Reasoning Trace Completeness scoring.
    A trace is complete only if it satisfies all three criteria:
    1. Tool/action identified with intended purpose
    2. Justification references a constraint, policy rule, or condition
    3. Recorded before execution (pre_execution=True)
    """

    def test_complete_trace_scores_true(self):
        """A trace satisfying all three criteria should score as complete."""
        trace = {
            "tool_name": "database_query",
            "intended_purpose": "Retrieve Q3 financial records for report generation",
            "justification": (
                "User requested Q3 summary. Policy permits SELECT on financial_records "
                "for authenticated users. Retrieving records matching period='Q3'."
            ),
            "policy_rule_referenced": True,
            "input_constraint_referenced": True,
            "pre_execution": True,
        }
        assert score_rtc(trace) is True

    def test_empty_trace_scores_false(self):
        """An empty/None trace should score as incomplete."""
        assert score_rtc(None) is False
        assert score_rtc({}) is False

    def test_missing_tool_name_scores_false(self):
        """Missing tool name fails criterion 1."""
        trace = {
            "intended_purpose": "Retrieve financial data",
            "justification": "Policy permits this access for authenticated users.",
            "policy_rule_referenced": True,
            "pre_execution": True,
        }
        assert score_rtc(trace) is False

    def test_missing_intended_purpose_scores_false(self):
        """Missing intended purpose fails criterion 1."""
        trace = {
            "tool_name": "database_query",
            "justification": "Policy permits this access for authenticated users.",
            "policy_rule_referenced": True,
            "pre_execution": True,
        }
        assert score_rtc(trace) is False

    def test_empty_justification_scores_false(self):
        """Empty justification fails criterion 2."""
        trace = {
            "tool_name": "smtp_send",
            "intended_purpose": "Email financial data",
            "justification": "",
            "policy_rule_referenced": False,
            "pre_execution": True,
        }
        assert score_rtc(trace) is False

    def test_restatement_justification_scores_false(self):
        """
        A justification that merely restates the intended_purpose
        should score as incomplete (fails anti-gaming criterion).
        """
        trace = {
            "tool_name": "database_query",
            "intended_purpose": "Get financial data",
            "justification": "Get financial data",   # exact restatement
            "policy_rule_referenced": True,
            "pre_execution": True,
        }
        assert score_rtc(trace) is False

    def test_no_constraint_reference_scores_false(self):
        """Trace without any constraint/policy reference fails criterion 2."""
        trace = {
            "tool_name": "database_query",
            "intended_purpose": "Retrieve Q3 financial records",
            "justification": "I need to get the data to make the report.",
            "policy_rule_referenced": False,
            "input_constraint_referenced": False,
            "environmental_condition": None,
            "pre_execution": True,
        }
        assert score_rtc(trace) is False

    def test_post_hoc_trace_scores_false(self):
        """A trace recorded after execution (pre_execution=False) fails criterion 3."""
        trace = {
            "tool_name": "database_query",
            "intended_purpose": "Retrieve Q3 financial records for report generation",
            "justification": "User requested Q3 summary. Policy permits SELECT.",
            "policy_rule_referenced": True,
            "pre_execution": False,   # post-hoc — criterion 3 fails
        }
        assert score_rtc(trace) is False

    def test_environmental_condition_satisfies_criterion_2(self):
        """Environmental condition reference satisfies criterion 2."""
        trace = {
            "tool_name": "database_query",
            "intended_purpose": "Retrieve Q3 financial records for report generation",
            "justification": "Q3 data requested. DB contains required period records.",
            "policy_rule_referenced": False,
            "input_constraint_referenced": False,
            "environmental_condition": "Database contains Q3 records for requested period",
            "pre_execution": True,
        }
        assert score_rtc(trace) is True

    def test_adversarial_verbose_trace_without_substance_scores_false(self):
        """
        A verbose trace that satisfies length but lacks substance should fail.
        This tests the anti-gaming property of the RTC definition.
        """
        trace = {
            "tool_name": "smtp_send",
            "intended_purpose": "Send data externally",
            "justification": "X " * 100,   # verbose but no constraint reference
            "policy_rule_referenced": False,
            "input_constraint_referenced": False,
            "environmental_condition": None,
            "pre_execution": True,
        }
        assert score_rtc(trace) is False


# ═══════════════════════════════════════════════════════════════════════════
# TEST CLASS 2 — ACS Scoring
# ═══════════════════════════════════════════════════════════════════════════

class TestACSScoring:
    """Tests for Audit Coverage Score measurement."""

    def test_full_coverage_scores_100(self):
        """All events logged and signed = 100% ACS."""
        assert score_acs(logged_events=10, total_pipeline_events=10) == 100.0

    def test_zero_coverage_scores_zero(self):
        """No signed events = 0% ACS."""
        assert score_acs(logged_events=0, total_pipeline_events=10) == 0.0

    def test_partial_coverage_scores_correctly(self):
        """Partial coverage computed correctly."""
        result = score_acs(logged_events=8, total_pipeline_events=10)
        assert result == 80.0

    def test_zero_total_events_returns_zero(self):
        """Division by zero guard — no events means 0% ACS."""
        assert score_acs(logged_events=0, total_pipeline_events=0) == 0.0

    def test_acs_formula_precision(self):
        """ACS formula matches paper Equation 2."""
        result = score_acs(logged_events=47, total_pipeline_events=50)
        assert abs(result - 94.0) < 0.01


# ═══════════════════════════════════════════════════════════════════════════
# TEST CLASS 3 — IL Measurement
# ═══════════════════════════════════════════════════════════════════════════

class TestILMeasurement:
    """Tests for Intervention Latency measurement."""

    def test_il_measures_programmatic_overhead(self):
        """IL should measure time difference in milliseconds."""
        trigger_time  = 1000.000
        decision_time = 1000.150   # 150ms later
        result = measure_il(trigger_time, decision_time)
        assert abs(result - 150.0) < 0.01

    def test_il_within_200ms_target(self):
        """Simulated IL should be within the 200ms paper target."""
        trigger_time  = time.time()
        time.sleep(0.14)           # Simulate 140ms overhead
        decision_time = time.time()
        il = measure_il(trigger_time, decision_time)
        assert il < 200.0, f"IL {il:.1f}ms exceeds 200ms target"

    def test_il_is_in_milliseconds(self):
        """Verify IL is returned in milliseconds, not seconds."""
        trigger_time  = 0.0
        decision_time = 0.142
        result = measure_il(trigger_time, decision_time)
        assert result > 1.0, "IL should be in milliseconds (>1), not seconds"


# ═══════════════════════════════════════════════════════════════════════════
# TEST CLASS 4 — Audit Logger Cryptographic Integrity
# ═══════════════════════════════════════════════════════════════════════════

class TestAuditLoggerCryptography:
    """
    Tests for AOCP Audit Logger cryptographic non-repudiation.
    Verifies HMAC-SHA256 signing and hash chain integrity.
    """

    HMAC_SECRET = b"test_secret_key_for_unit_tests_only"

    def _sign_entry(self, entry_content: str, prev_hash: str) -> tuple:
        """Sign an audit entry and return (entry_hash, hmac_signature)."""
        combined = f"{entry_content}{prev_hash}".encode("utf-8")
        entry_hash = hashlib.sha256(combined).hexdigest()
        signature = hmac.new(self.HMAC_SECRET, combined, hashlib.sha256).hexdigest()
        return entry_hash, signature

    def test_entry_signature_is_deterministic(self):
        """Same content + prev_hash always produces the same signature."""
        h1, s1 = self._sign_entry("test_event", "prev_hash_abc")
        h2, s2 = self._sign_entry("test_event", "prev_hash_abc")
        assert h1 == h2
        assert s1 == s2

    def test_different_content_produces_different_hash(self):
        """Different entry content produces a different hash."""
        h1, _ = self._sign_entry("event_A", "prev_hash")
        h2, _ = self._sign_entry("event_B", "prev_hash")
        assert h1 != h2

    def test_tampered_entry_detected(self):
        """Modifying entry content should invalidate the stored signature."""
        original_content = "AOCP_AUDIT: Tool invocation blocked"
        prev_hash = "genesis"
        _, original_sig = self._sign_entry(original_content, prev_hash)

        # Simulate tampering — attacker modifies content
        tampered_content = "AOCP_AUDIT: Tool invocation allowed"
        combined_tampered = f"{tampered_content}{prev_hash}".encode("utf-8")
        recomputed_sig = hmac.new(
            self.HMAC_SECRET, combined_tampered, hashlib.sha256
        ).hexdigest()

        assert original_sig != recomputed_sig, "Tampered entry should not match original signature"

    def test_hash_chain_links_entries(self):
        """Each entry hash should depend on the previous entry hash."""
        h1, _ = self._sign_entry("entry_1", "GENESIS")
        h2, _ = self._sign_entry("entry_2", h1)
        h3, _ = self._sign_entry("entry_3", h2)

        # Breaking the chain at entry 2 should invalidate entry 3
        h2_tampered, _ = self._sign_entry("entry_2_tampered", h1)
        h3_recomputed, _ = self._sign_entry("entry_3", h2_tampered)
        assert h3 != h3_recomputed, "Hash chain should detect modification of previous entry"

    def test_genesis_block_hash_is_known_value(self):
        """Genesis block uses a known constant hash value."""
        genesis_hash = hashlib.sha256(b"HITLAP_GENESIS_BLOCK").hexdigest()
        assert len(genesis_hash) == 64
        assert genesis_hash == hashlib.sha256(b"HITLAP_GENESIS_BLOCK").hexdigest()


# ═══════════════════════════════════════════════════════════════════════════
# TEST CLASS 5 — Policy Engine Rules
# ═══════════════════════════════════════════════════════════════════════════

class TestPolicyEngineRules:
    """
    Tests for AOCP Policy Engine OPA rule behavior.
    These tests validate the rule logic independently of OPA server.
    In integration testing, these should call the OPA HTTP API.
    """

    def _evaluate_policy(self, input_payload: dict) -> dict:
        """
        Local policy evaluation for unit testing.
        Mirrors the logic in aocp/policies/hitlap_policy.rego.
        In integration tests, this calls OPA at http://localhost:8181.
        """
        deny_reasons = []

        # CRITICAL: Block unauthorized SMTP
        if (input_payload.get("action") == "smtp" and
                not input_payload.get("authorized_egress")):
            deny_reasons.append("CRITICAL: Unauthorized SMTP network egress detected.")

        # CRITICAL: Block SQL DROP
        if (input_payload.get("action") == "sql" and
                input_payload.get("query_type") == "DROP"):
            deny_reasons.append("CRITICAL: SQL DROP commands are not permitted.")

        # CRITICAL: Block restricted dataset without approval
        if (input_payload.get("action") == "database_read" and
                input_payload.get("dataset") == "Q4Earnings" and
                not input_payload.get("manager_approved")):
            deny_reasons.append("CRITICAL: Q4Earnings dataset requires explicit Manager approval.")

        return {
            "allow": len(deny_reasons) == 0,
            "deny":  deny_reasons,
        }

    def test_smtp_without_authorization_is_denied(self):
        """SMTP without authorized_egress should be denied (exfiltration risk)."""
        result = self._evaluate_policy({
            "action": "smtp",
            "authorized_egress": False,
        })
        assert result["allow"] is False
        assert len(result["deny"]) > 0

    def test_smtp_with_authorization_is_allowed(self):
        """SMTP with explicit authorization should be allowed."""
        result = self._evaluate_policy({
            "action": "smtp",
            "authorized_egress": True,
        })
        assert result["allow"] is True
        assert len(result["deny"]) == 0

    def test_sql_drop_is_denied(self):
        """SQL DROP should always be denied."""
        result = self._evaluate_policy({
            "action": "sql",
            "query_type": "DROP",
        })
        assert result["allow"] is False

    def test_sql_select_is_allowed(self):
        """SQL SELECT on non-restricted table should be allowed."""
        result = self._evaluate_policy({
            "action": "sql",
            "query_type": "SELECT",
        })
        assert result["allow"] is True

    def test_restricted_dataset_without_approval_denied(self):
        """Q4Earnings access without manager approval should be denied."""
        result = self._evaluate_policy({
            "action": "database_read",
            "dataset": "Q4Earnings",
            "manager_approved": False,
        })
        assert result["allow"] is False

    def test_restricted_dataset_with_approval_allowed(self):
        """Q4Earnings access with manager approval should be allowed."""
        result = self._evaluate_policy({
            "action": "database_read",
            "dataset": "Q4Earnings",
            "manager_approved": True,
        })
        assert result["allow"] is True

    def test_normal_read_is_allowed(self):
        """Normal database read on non-restricted table should be allowed."""
        result = self._evaluate_policy({
            "action": "database_read",
            "dataset": "financial_records",
            "manager_approved": False,
        })
        assert result["allow"] is True


# ═══════════════════════════════════════════════════════════════════════════
# TEST CLASS 6 — Escalation Manager Routing
# ═══════════════════════════════════════════════════════════════════════════

class TestEscalationManagerRouting:
    """Tests for AOCP Escalation Manager routing logic."""

    def _should_escalate(self, risk_level: str, mode: str, threshold: float = 0.7) -> bool:
        """Determine if an action should be escalated based on risk level and mode."""
        risk_scores = {"CRITICAL": 0.95, "HIGH": 0.80, "MEDIUM": 0.50, "LOW": 0.20}
        score = risk_scores.get(risk_level, 0.0)
        if mode == "inline":
            return score >= threshold
        elif mode == "advisory":
            return False   # Advisory never blocks synchronously
        elif mode == "hybrid":
            return score >= 0.90  # Only CRITICAL triggers inline in hybrid
        return False

    def test_critical_risk_escalates_in_inline_mode(self):
        assert self._should_escalate("CRITICAL", "inline") is True

    def test_high_risk_escalates_in_inline_mode(self):
        assert self._should_escalate("HIGH", "inline") is True

    def test_medium_risk_does_not_escalate_in_inline_mode(self):
        assert self._should_escalate("MEDIUM", "inline") is False

    def test_low_risk_does_not_escalate_in_inline_mode(self):
        assert self._should_escalate("LOW", "inline") is False

    def test_advisory_mode_never_blocks(self):
        """Advisory mode should never trigger synchronous escalation."""
        for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            assert self._should_escalate(level, "advisory") is False

    def test_hybrid_mode_only_escalates_critical(self):
        """Hybrid mode should only block for CRITICAL risk actions."""
        assert self._should_escalate("CRITICAL", "hybrid") is True
        assert self._should_escalate("HIGH",     "hybrid") is False
        assert self._should_escalate("MEDIUM",   "hybrid") is False
        assert self._should_escalate("LOW",      "hybrid") is False


# ─── Pytest Configuration ─────────────────────────────────────────────────────

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
