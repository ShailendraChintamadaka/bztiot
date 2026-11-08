package edu.cvr.bztiot.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * Implements the paper's weighted trust formula:
 *
 *   T = w1 * I  +  w2 * B  +  w3 * H  +  w4 * S
 *
 * Where:
 *   T  = composite trust score (0–100)
 *   I  = Identity/authentication confidence (0–100)
 *   B  = Behavioral trust (0–100)
 *   H  = Historical trust (0–100)
 *   S  = Current security state (0–100)
 *   w1…w4 = configurable weights in application.yaml (must sum to 1.0)
 *
 * DESIGN PRINCIPLE — Pure calculation:
 *   This class does NOT read from the database, does NOT call other services,
 *   and does NOT produce side effects. It is a pure function: same inputs → same output.
 *   This makes it trivial to unit test (see RiskScoreCalculatorTest).
 *
 * VIVA EXPLANATION:
 *   "The trust score is not a binary authenticated/unauthenticated flag.
 *    It is a continuous value that reflects the device's current security posture
 *    across four independent dimensions. A device that authenticated successfully
 *    yesterday but is now flooding MQTT messages will see its behavioral score
 *    drop, pulling the composite score down even though its identity score is high."
 *
 * HOW TO TUNE THE WEIGHTS (for your project report):
 *   - To emphasize authentication: increase w1, decrease others proportionally.
 *   - To emphasize real-time behavior: increase w2.
 *   - Run the unit tests after any change to see the effect on edge cases.
 *   - Document your reasoning in the project report.
 */
@Component
public class RiskScoreCalculator {

    @Value("${trust.weight.identity:0.35}")
    private double w1;

    @Value("${trust.weight.behavioral:0.30}")
    private double w2;

    @Value("${trust.weight.historical:0.15}")
    private double w3;

    @Value("${trust.weight.security-state:0.20}")
    private double w4;

    /**
     * Result record — holds all four factor scores plus the composite.
     * Using a Java record keeps this immutable and compact.
     *
     * @param identityScore       I factor (0–100)
     * @param behavioralScore     B factor (0–100)
     * @param historicalScore     H factor (0–100)
     * @param securityStateScore  S factor (0–100)
     * @param trustScore          T composite (0–100)
     * @param explanation         Human-readable breakdown for the audit log
     */
    public record TrustComponents(
            int identityScore,
            int behavioralScore,
            int historicalScore,
            int securityStateScore,
            int trustScore,
            String explanation
    ) {}

    // ─────────────────────────────────────────────────────────────────────────
    // Main calculation entry point
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Calculates the composite trust score from the provided inputs.
     * Call this every time a meaningful security event occurs for a device.
     *
     * @param inputs All signals for one device at one point in time.
     * @return TrustComponents with all factor scores and the composite.
     */
    public TrustComponents calculate(TrustInputs inputs) {
        int I = computeIdentityScore(inputs);
        int B = computeBehavioralScore(inputs);
        int H = computeHistoricalScore(inputs);
        int S = computeSecurityStateScore(inputs);

        // Apply the paper's formula
        double T = w1 * I + w2 * B + w3 * H + w4 * S;

        // Clamp to [0, 100] — weighted sum cannot exceed 100 with valid inputs,
        // but clamping guards against future weight misconfiguration.
        int trustScore = (int) Math.round(Math.max(0.0, Math.min(100.0, T)));

        String explanation = buildExplanation(I, B, H, S, trustScore, inputs);

        return new TrustComponents(I, B, H, S, trustScore, explanation);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Factor I — Identity / Authentication confidence
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Scores the device's authentication status and history.
     *
     * Scoring logic:
     *   - Never authenticated → 10 (not 0, because it might just be newly registered)
     *   - 5+ consecutive failures → 0 (likely under attack or compromised)
     *   - 3-4 failures → 20 (suspicious, significantly reduced)
     *   - 1-2 failures → 50 (one mistake, moderate trust)
     *   - Authenticated recently (< 30 min) → 100
     *   - Authenticated 30-60 min ago → 85 (slight decay)
     *   - Authenticated 60-120 min ago → 70
     *   - Authenticated > 2 hours ago → 55 (still valid but decaying)
     *
     * WHY DECAY?: Zero Trust assumes that past authentication provides decreasing
     * assurance over time. A device that authenticated 3 hours ago might have been
     * physically tampered with since then.
     */
    int computeIdentityScore(TrustInputs inputs) {
        int failures = inputs.getAuthFailureCount();

        // Hard failure cases — multiple consecutive failures indicate a problem
        if (failures >= 5) return 0;
        if (failures >= 3) return 20;
        if (failures >= 1) return 50;

        // Device has never authenticated
        if (!inputs.hasEverAuthenticated()) return 10;

        // Authenticated with no failures — apply time decay
        long minutesSince = inputs.getMinutesSinceLastAuth();
        if (minutesSince < 30)  return 100;
        if (minutesSince < 60)  return 85;
        if (minutesSince < 120) return 70;
        return 55;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Factor B — Behavioral trust
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Scores the device's current behavioral pattern.
     *
     * Deductions (cumulative, capped at 0):
     *   - Rate limit exceeded:            -40 points
     *   - Replay detected:                -50 points (most serious — active attack)
     *   - Unauthorized topic attempted:   -30 points
     *
     * WHY THESE DEDUCTIONS?
     *   Replay attacks are the most dangerous — they mean someone is replaying
     *   old messages to confuse the server. Rate abuse wastes resources and may
     *   indicate a compromised device flooding the network.
     *
     * IMPORTANT: Temperature and humidity values alone do NOT affect this score.
     * Unusual sensor readings are an application concern, not a security violation.
     */
    int computeBehavioralScore(TrustInputs inputs) {
        int score = 100;
        if (inputs.isRateLimitExceeded())          score -= 40;
        if (inputs.isReplayDetected())             score -= 50;
        if (inputs.isUnauthorizedTopicAttempted()) score -= 30;
        return Math.max(0, score);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Factor H — Historical trust
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Scores the device based on its security violation history in the recent window.
     *
     * Violations counted: FIRMWARE_MISMATCH, RATE_LIMIT_EXCEEDED, AUTH_FAILED,
     *   REPLAY_DETECTED, UNAUTHORIZED_TOPIC — see SecurityEventService.
     *
     * Scoring:
     *   0 violations → 100 (clean history)
     *   1 violation  → 75  (one incident in the window)
     *   2 violations → 50
     *   3-5          → 25
     *   6+           → 0   (persistent violator)
     *
     * Note: This window is configurable (default: 60 minutes). A device can
     * recover its historical score simply by not violating for a full window period.
     * This is intentional — permanent punishment with no recovery path would
     * incentivise operators to disable monitoring.
     */
    int computeHistoricalScore(TrustInputs inputs) {
        int violations = inputs.getRecentViolationCount();
        if (violations == 0) return 100;
        if (violations == 1) return 75;
        if (violations == 2) return 50;
        if (violations <= 5) return 25;
        return 0;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Factor S — Current security state
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Scores the device's current administrative and firmware security state.
     *
     * This factor captures things the device itself cannot change — only an
     * administrator can revoke a device or update the expected firmware hash.
     *
     * Scoring:
     *   REVOKED              → 0   (hard gate, also enforced separately)
     *   QUARANTINED          → 10  (severely restricted, admin action needed)
     *   Firmware hash mismatch → 30 (possible tampering or unauthorized update)
     *   Everything normal    → 100
     *
     * WHY BOTH REVOKED CHECK AND SCORE=0?
     *   REVOKED is also a hard gate in AccessPolicyService — the decision is
     *   always DENY regardless of score. Setting S=0 here means the trust score
     *   is also 0, making the audit trail consistent: a revoked device's score
     *   reflects its true security state.
     */
    int computeSecurityStateScore(TrustInputs inputs) {
        if (inputs.isRevoked())              return 0;
        if (inputs.isQuarantined())          return 10;
        if (inputs.isFirmwareHashMismatch()) return 30;
        return 100;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Explanation builder
    // ─────────────────────────────────────────────────────────────────────────

    private String buildExplanation(int I, int B, int H, int S, int T, TrustInputs in) {
        return String.format(
            "T=%.0f*(I=%d) + %.0f*(B=%d) + %.0f*(H=%d) + %.0f*(S=%d) = %d | " +
            "auth=%s failures=%d minSince=%s | rate=%s replay=%s topic=%s | " +
            "violations=%d | revoked=%s quarantined=%s firmwareMismatch=%s",
            w1 * 100, I, w2 * 100, B, w3 * 100, H, w4 * 100, S, T,
            in.hasEverAuthenticated(), in.getAuthFailureCount(),
            in.getMinutesSinceLastAuth() == Long.MAX_VALUE ? "never" : in.getMinutesSinceLastAuth() + "m",
            in.isRateLimitExceeded(), in.isReplayDetected(), in.isUnauthorizedTopicAttempted(),
            in.getRecentViolationCount(),
            in.isRevoked(), in.isQuarantined(), in.isFirmwareHashMismatch()
        );
    }
}
