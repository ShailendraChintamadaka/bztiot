package edu.cvr.bztiot.model;

import java.time.Instant;
import java.util.UUID;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * Represents a single security observation or enforcement action.
 *
 * Severity levels (low to high): INFO, LOW, MEDIUM, HIGH, CRITICAL
 *
 * trustScoreBefore / trustScoreAfter let you replay the trust history for any
 * device — critical for the explainable Zero Trust audit trail.
 */
@Getter
@Setter
@NoArgsConstructor
@Entity
@Table(name = "security_events")
public class SecurityEvent {

    @Id
    @GeneratedValue
    @Column(name = "id")
    private UUID id;

    /** The short device identifier (e.g. "ESP32_001"). Never a private key or secret. */
    @Column(name = "device_code", nullable = false)
    private String deviceCode;

    /**
     * Machine-readable event type.
     * Examples: UNREGISTERED_DEVICE, FIRMWARE_MISMATCH, AUTH_FAILED,
     *           RATE_LIMIT_EXCEEDED, QUARANTINE_ENFORCED, AUTH_SUCCESS
     */
    @Column(name = "event_type", nullable = false)
    private String eventType;

    /**
     * Severity level used by the dashboard to colour-code and filter events.
     * Values: INFO | LOW | MEDIUM | HIGH | CRITICAL
     */
    @Column(name = "severity")
    private String severity;

    /** Human-readable explanation of what was detected and why it matters. */
    @Column(name = "detail")
    private String detail;

    /** Trust score immediately before this event was processed. */
    @Column(name = "trust_score_before")
    private Integer trustScoreBefore;

    /** Trust score after this event was applied. */
    @Column(name = "trust_score_after")
    private Integer trustScoreAfter;

    /**
     * The policy decision that resulted from the trust evaluation at this moment.
     * Values: ALLOW | RESTRICT | QUARANTINE | DENY
     * Null means the event did not trigger a policy evaluation (e.g. INFO events).
     */
    @Column(name = "access_decision")
    private String accessDecision;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;
}