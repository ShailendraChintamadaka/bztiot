package edu.cvr.bztiot.model;

/**
 * The four possible outcomes of a Zero Trust policy evaluation.
 *
 * This maps directly to the trust score thresholds defined in AccessPolicyService.
 * These are configurable in application.yaml under trust.threshold.*
 *
 * For your viva:
 *   Trust score is NOT the same as access decision.
 *   Trust score is a number (0-100).
 *   Access decision is what the system DOES based on that number.
 *   The mapping is: score → threshold comparison → enum value → enforcement action.
 */
public enum AccessDecision {

    /**
     * Trust 80-100. All mandatory hard-security checks passed.
     * The device is authenticated, behaving normally, and has a clean history.
     * Action: allow the MQTT message to be processed and stored normally.
     */
    ALLOW,

    /**
     * Trust 60-79. The device passes hard checks but has shown some anomalies.
     * Action: accept the message, but log extra detail and flag for monitoring.
     * Example cause: one authentication failure in the last hour.
     */
    RESTRICT,

    /**
     * Trust 40-59. The device has significant behavioral or historical concerns.
     * Action: drop the sensor data message. The device's status is changed to
     * QUARANTINED, which blocks further MQTT messages automatically.
     * A quarantined device can only be re-enabled by an administrator.
     * Example cause: exceeded message rate limit twice in an hour.
     */
    QUARANTINE,

    /**
     * Trust 0-39. The device is considered actively malicious or compromised.
     * Action: drop the message, log a critical event, require admin review before
     * any access is restored. The device is NOT automatically revoked — revocation
     * is always an explicit administrator action to prevent accidental lockout.
     * Example cause: 5+ consecutive authentication failures.
     */
    DENY
}
