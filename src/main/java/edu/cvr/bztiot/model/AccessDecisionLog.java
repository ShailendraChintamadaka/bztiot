package edu.cvr.bztiot.model;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.Instant;

/**
 * A permanent log of every access policy decision made by the Zero Trust engine.
 *
 * WHY THIS TABLE EXISTS:
 *   Authentication tells you IF a device is who it claims to be.
 *   Authorization tells you WHAT it is allowed to do.
 *   This table records every authorization decision with full reasoning.
 *
 *   This is critical for the viva: you can point to this table and say
 *   "here is every access decision the system made, with the trust score that
 *   justified it and whether the decision was actually enforced."
 *
 * IMPORTANT DISTINCTION for your report:
 *   Authentication (challenge-response) → one-time event in security_events
 *   Authorization (access decision)     → every MQTT message, recorded HERE
 *   A device can be authenticated but still get DENY if trust drops later.
 */
@Getter
@Setter
@NoArgsConstructor
@Entity
@Table(name = "access_decisions")
public class AccessDecisionLog {

    @Id
    @GeneratedValue
    @Column(name = "id")
    private Long id;

    @Column(name = "device_code", nullable = false)
    private String deviceCode;

    /** What the device was trying to do, e.g. "PUBLISH:iot/ESP32_001/temperature". */
    @Column(name = "operation")
    private String operation;

    /** The trust score at the moment of this decision. */
    @Column(name = "trust_score", nullable = false)
    private int trustScore;

    /**
     * The policy decision: ALLOW | RESTRICT | QUARANTINE | DENY
     *   ALLOW      — trust 80-100, full access
     *   RESTRICT   — trust 60-79, throttled, extra logging
     *   QUARANTINE — trust 40-59, data blocked, diagnostics only
     *   DENY       — trust  0-39, all access blocked, admin review required
     */
    @Column(name = "decision", nullable = false)
    private String decision;

    /** Human-readable explanation of why this decision was made. */
    @Column(name = "reason", nullable = false, columnDefinition = "TEXT")
    private String reason;

    /** True if the decision was actively enforced (e.g. message was dropped). */
    @Column(name = "enforced", nullable = false)
    private boolean enforced;

    @Column(name = "decided_at", nullable = false, updatable = false)
    private Instant decidedAt;
}
