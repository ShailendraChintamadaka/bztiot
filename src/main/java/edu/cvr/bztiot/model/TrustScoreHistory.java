package edu.cvr.bztiot.model;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.Instant;

/**
 * Snapshot of a device's trust score at a specific point in time.
 *
 * WHY THIS TABLE EXISTS:
 *   The current trust score on the Device entity tells you where a device stands
 *   right NOW. This table lets you answer: "How did this device's trust change
 *   over the past 24 hours? What events drove it down?"
 *
 *   This is the audit trail that makes the Zero Trust model explainable — you
 *   can replay the trust history for any device and show exactly which events
 *   caused each change.
 *
 * Paper reference: Section on "dynamic trust evaluation" and "trust history".
 */
@Getter
@Setter
@NoArgsConstructor
@Entity
@Table(name = "trust_score_history")
public class TrustScoreHistory {

    @Id
    @GeneratedValue
    @Column(name = "id")
    private Long id;

    /** The device this snapshot belongs to. */
    @Column(name = "device_code", nullable = false)
    private String deviceCode;

    // ── The four trust factors from the paper: T = w1*I + w2*B + w3*H + w4*S ──

    /** I — Identity/authentication confidence (0–100). */
    @Column(name = "identity_score", nullable = false)
    private int identityScore;

    /** B — Behavioral trust: rate, replay, topic compliance (0–100). */
    @Column(name = "behavioral_score", nullable = false)
    private int behavioralScore;

    /** H — Historical trust: past violations, track record (0–100). */
    @Column(name = "historical_score", nullable = false)
    private int historicalScore;

    /** S — Current security state: firmware, quarantine, revocation (0–100). */
    @Column(name = "security_state_score", nullable = false)
    private int securityStateScore;

    /** T — Weighted composite trust score (0–100). */
    @Column(name = "trust_score", nullable = false)
    private int trustScore;

    /** The access decision that resulted from this trust score. */
    @Column(name = "access_decision")
    private String accessDecision;

    /** What triggered this re-evaluation (e.g. "MQTT_MESSAGE", "AUTH_SUCCESS"). */
    @Column(name = "trigger_event")
    private String triggerEvent;

    @Column(name = "recorded_at", nullable = false, updatable = false)
    private Instant recordedAt;
}
