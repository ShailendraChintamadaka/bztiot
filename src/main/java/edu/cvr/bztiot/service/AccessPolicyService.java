package edu.cvr.bztiot.service;

import edu.cvr.bztiot.model.AccessDecision;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

/**
 * Maps a trust score to an access decision, with hard security gates that
 * override the score when certain conditions are true.
 *
 * THE CRUCIAL DISTINCTION FOR YOUR VIVA:
 *   Trust score  → "How much do we trust this device right now?"
 *   Access decision → "What are we actually going to let it do?"
 *
 *   They are related but not identical. Hard gates mean some conditions result
 *   in DENY regardless of how high the trust score is.
 *
 * HARD GATES (always DENY, score is irrelevant):
 *   1. Device is REVOKED — administrator manually revoked it.
 *   2. Device is unknown (not in registry) — handled before this service is called.
 *   3. Message is a detected replay — cryptographic integrity violation.
 *
 * SOFT POLICY (based on configurable thresholds):
 *   trust >= 80   → ALLOW
 *   trust >= 60   → RESTRICT
 *   trust >= 40   → QUARANTINE
 *   trust <  40   → DENY
 *
 * Configuration:
 *   Thresholds are set in application.yaml under trust.threshold.*
 *   Change them to experiment with stricter or more lenient policies.
 */
@Service
public class AccessPolicyService {

    @Value("${trust.threshold.allow:80}")
    private int allowThreshold;

    @Value("${trust.threshold.restrict:60}")
    private int restrictThreshold;

    @Value("${trust.threshold.quarantine:40}")
    private int quarantineThreshold;

    /**
     * Determines the access decision for a device.
     *
     * @param inputs     The same TrustInputs used by RiskScoreCalculator.
     * @param trustScore The composite trust score from RiskScoreCalculator.
     * @return DecisionResult with the decision and a human-readable reason.
     */
    public DecisionResult decide(TrustInputs inputs, int trustScore) {

        // ── Hard gate 1: Revoked device ──────────────────────────────────────
        if (inputs.isRevoked()) {
            return new DecisionResult(AccessDecision.DENY,
                "HARD GATE: Device is REVOKED. All access permanently denied until administrator action.",
                true);
        }

        // ── Hard gate 2: Replay attack detected ───────────────────────────────
        // A replay means someone is re-sending an old captured message.
        // This is an active attack — trust score is irrelevant.
        if (inputs.isReplayDetected()) {
            return new DecisionResult(AccessDecision.DENY,
                "HARD GATE: Replay attack detected. Message with duplicate sequence rejected regardless of trust score.",
                true);
        }

        // ── Soft policy: score-based thresholds ───────────────────────────────
        if (trustScore >= allowThreshold) {
            return new DecisionResult(AccessDecision.ALLOW,
                buildReason("ALLOW", trustScore, allowThreshold, inputs),
                false);
        }

        if (trustScore >= restrictThreshold) {
            return new DecisionResult(AccessDecision.RESTRICT,
                buildReason("RESTRICT", trustScore, allowThreshold, inputs),
                true);
        }

        if (trustScore >= quarantineThreshold) {
            return new DecisionResult(AccessDecision.QUARANTINE,
                buildReason("QUARANTINE", trustScore, restrictThreshold, inputs),
                true);
        }

        return new DecisionResult(AccessDecision.DENY,
            buildReason("DENY", trustScore, quarantineThreshold, inputs),
            true);
    }

    private String buildReason(String decision, int score, int threshold, TrustInputs inputs) {
        StringBuilder sb = new StringBuilder();
        sb.append(decision).append(": trust=").append(score)
          .append(" (threshold=").append(threshold).append(").");

        if (inputs.isRateLimitExceeded())          sb.append(" Rate limit exceeded.");
        if (inputs.isFirmwareHashMismatch())       sb.append(" Firmware hash mismatch.");
        if (inputs.isUnauthorizedTopicAttempted()) sb.append(" Unauthorized topic attempt.");
        if (inputs.getAuthFailureCount() > 0)
            sb.append(" Auth failures=").append(inputs.getAuthFailureCount()).append(".");
        if (inputs.getRecentViolationCount() > 0)
            sb.append(" Recent violations=").append(inputs.getRecentViolationCount()).append(".");

        return sb.toString();
    }

    /**
     * Immutable result of a policy decision.
     *
     * @param decision  The access decision (ALLOW/RESTRICT/QUARANTINE/DENY).
     * @param reason    Human-readable explanation stored in the audit log.
     * @param enforced  True if this decision blocks the operation.
     *                  ALLOW decisions are not "enforced" — they permit the action.
     */
    public record DecisionResult(
            AccessDecision decision,
            String reason,
            boolean enforced
    ) {
        public boolean blocks() {
            return decision == AccessDecision.QUARANTINE || decision == AccessDecision.DENY;
        }

        public boolean isAllow()     { return decision == AccessDecision.ALLOW; }
        public boolean isRestrict()  { return decision == AccessDecision.RESTRICT; }
    }
}
