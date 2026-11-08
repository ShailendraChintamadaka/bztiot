package edu.cvr.bztiot.service;

import edu.cvr.bztiot.model.SecurityEvent;
import edu.cvr.bztiot.repository.SecurityEventRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;

/**
 * Central service for recording all security events.
 *
 * WHY A DEDICATED SERVICE?
 *   Previously, security events were recorded inline in MqttConfig via a private
 *   logEvent() helper that only set 3 fields. Now that SecurityEvent has 8 fields
 *   (including severity, trust scores, and access decision), every recording point
 *   in the system should go through this service to ensure consistency.
 *
 *   This also means event recording is transactional — if the database write fails,
 *   the calling method will be aware of it.
 *
 * USAGE:
 *   // Simple info event (no trust score change)
 *   eventService.record("ESP32_001", "SENSOR_ACCEPTED", "INFO", "Normal reading accepted.");
 *
 *   // Full event with trust scores and decision
 *   eventService.record("ESP32_001", "FIRMWARE_MISMATCH", "HIGH",
 *       "Hash mismatch detected.", 75, 45, "QUARANTINE");
 */
@Service
public class SecurityEventService {

    private final SecurityEventRepository repository;

    public SecurityEventService(SecurityEventRepository repository) {
        this.repository = repository;
    }

    /**
     * Records a simple event without trust score information.
     * Use for informational events that don't change trust (e.g. AUTH_SUCCESS info note).
     */
    @Transactional
    public SecurityEvent record(String deviceCode, String eventType,
                                String severity, String detail) {
        return record(deviceCode, eventType, severity, detail, null, null, null);
    }

    /**
     * Records a full security event with trust score context and access decision.
     * Use whenever the trust score changes or a policy decision is made.
     *
     * @param deviceCode     The device's identifier (never a private key or secret).
     * @param eventType      Machine-readable type (e.g. "RATE_LIMIT_EXCEEDED").
     * @param severity       INFO | LOW | MEDIUM | HIGH | CRITICAL
     * @param detail         Human-readable explanation of what was detected.
     * @param scoreBefore    Trust score before this event was processed. Null if unknown.
     * @param scoreAfter     Trust score after this event. Null if score did not change.
     * @param accessDecision ALLOW | RESTRICT | QUARANTINE | DENY. Null if not applicable.
     */
    @Transactional
    public SecurityEvent record(String deviceCode, String eventType, String severity,
                                String detail, Integer scoreBefore, Integer scoreAfter,
                                String accessDecision) {
        SecurityEvent event = new SecurityEvent();
        event.setDeviceCode(deviceCode);
        event.setEventType(eventType);
        event.setSeverity(severity);
        event.setDetail(detail);
        event.setTrustScoreBefore(scoreBefore);
        event.setTrustScoreAfter(scoreAfter);
        event.setAccessDecision(accessDecision);
        event.setCreatedAt(Instant.now());
        return repository.save(event);
    }

    // ── Convenience methods for common event types ─────────────────────────

    public SecurityEvent recordAuthSuccess(String deviceCode, int scoreBefore, int scoreAfter) {
        return record(deviceCode, "AUTH_SUCCESS", "INFO",
            "Challenge-response authentication succeeded. Trust score: " + scoreBefore + " → " + scoreAfter + ".",
            scoreBefore, scoreAfter, "ALLOW");
    }

    public SecurityEvent recordAuthFailed(String deviceCode, int failures,
                                          int scoreBefore, int scoreAfter, String decision) {
        String sev = failures >= 3 ? "HIGH" : "MEDIUM";
        return record(deviceCode, "AUTH_FAILED", sev,
            "Authentication failed. Consecutive failure #" + failures
                + ". Trust score: " + scoreBefore + " → " + scoreAfter + ".",
            scoreBefore, scoreAfter, decision);
    }

    public SecurityEvent recordRateLimitExceeded(String deviceCode,
                                                  long messagesInWindow, long limit,
                                                  int scoreBefore, int scoreAfter) {
        return record(deviceCode, "RATE_LIMIT_EXCEEDED", "HIGH",
            "Device sent " + messagesInWindow + " messages in the last minute (limit: " + limit + "). "
                + "Trust score: " + scoreBefore + " → " + scoreAfter + ".",
            scoreBefore, scoreAfter, "QUARANTINE");
    }

    public SecurityEvent recordFirmwareMismatch(String deviceCode, String reported,
                                                 int scoreBefore, int scoreAfter) {
        return record(deviceCode, "FIRMWARE_MISMATCH", "HIGH",
            "Reported firmware hash '" + reported + "' does not match registered expected hash. "
                + "Possible tampering or unauthorized firmware update. "
                + "Trust score: " + scoreBefore + " → " + scoreAfter + ".",
            scoreBefore, scoreAfter, "RESTRICT");
    }

    public SecurityEvent recordReplayDetected(String deviceCode,
                                               int scoreBefore, int scoreAfter) {
        return record(deviceCode, "REPLAY_DETECTED", "CRITICAL",
            "Message with a previously-seen sequence number was received. "
                + "Possible replay attack. Message rejected. "
                + "Trust score: " + scoreBefore + " → " + scoreAfter + ".",
            scoreBefore, scoreAfter, "DENY");
    }

    public SecurityEvent recordQuarantineEnforced(String deviceCode,
                                                   int trustScore, String reason) {
        return record(deviceCode, "QUARANTINE_ENFORCED", "HIGH",
            "Device moved to QUARANTINE status. Trust score: " + trustScore + ". Reason: " + reason,
            trustScore, trustScore, "QUARANTINE");
    }
}
