package edu.cvr.bztiot.model;

import java.time.Instant;
import java.util.UUID;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
@Entity
@Table(name = "devices")
public class Device {

    @Id
    @GeneratedValue
    @Column(name = "id")
    private UUID deviceId;

    @Column(name = "device_code", unique = true, nullable = false)
    private String deviceCode;

    @Column(name = "public_key", unique = true, nullable = false, columnDefinition = "TEXT")
    private String publicKey;

    @Column(name = "expected_firmware_hash", columnDefinition = "TEXT")
    private String expectedFirmwareHash;

    @Column(name = "device_type", nullable = false)
    private String deviceType;

    @Enumerated(EnumType.STRING)
    @Column(name = "device_status", nullable = false)
    private DeviceStatus status;

    /**
     * Trust score from 0–100. Starts at 50 (neutral: registered but not yet
     * authenticated). Maps to the same column as the old currentRiskScore field
     * so no database migration is needed.
     *
     * Note for the paper: riskScore = 100 - trustScore.
     * The engine stores trust; the dashboard can compute risk for display.
     */
    @Column(name = "current_risk_score")
    private Integer trustScore;

    /**
     * Timestamp of the last successful device challenge-response authentication.
     * Null means the device has never completed authentication.
     */
    @Column(name = "last_auth_at")
    private Instant lastAuthAt;

    /**
     * Number of consecutive authentication failures since the last success.
     * Reset to 0 on a successful authentication.
     * Used by the trust engine as a negative signal.
     */
    @Column(name = "auth_failure_count", nullable = false)
    private int authFailureCount = 0;

    @Column(name = "registered_at", nullable = false, updatable = false)
    private Instant registeredAt;

    @Column(name = "last_seen_at")
    private Instant lastSeenAt;
}
