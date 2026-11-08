package edu.cvr.bztiot.service;

import edu.cvr.bztiot.model.*;
import edu.cvr.bztiot.repository.AccessDecisionLogRepository;
import edu.cvr.bztiot.repository.DeviceRepository;
import edu.cvr.bztiot.repository.SecurityEventRepository;
import edu.cvr.bztiot.repository.TrustScoreHistoryRepository;
import edu.cvr.bztiot.service.AccessPolicyService.DecisionResult;
import edu.cvr.bztiot.service.RiskScoreCalculator.TrustComponents;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Optional;

/**
 * The Zero Trust Security Engine orchestrator.
 *
 * This is the single entry point for the MQTT handler to:
 *   1. Collect all behavioral signals for the device.
 *   2. Build TrustInputs from the device's database record.
 *   3. Call RiskScoreCalculator → get trust score.
 *   4. Call AccessPolicyService → get access decision.
 *   5. Enforce the decision (update device status if needed).
 *   6. Persist the trust score snapshot and access decision log.
 *   7. Return the decision to the MQTT handler.
 *
 * WHAT "EVALUATE" MEANS:
 *   One call to evaluate() = one complete Zero Trust policy check.
 *   It is called every time a sensor message arrives — this is the
 *   "continuous evaluation" that distinguishes Zero Trust from traditional
 *   perimeter security (which only checks at the door, not inside).
 *
 * VIVA EXPLANATION:
 *   "Traditional security authenticates once at the boundary and then trusts
 *    everything inside. Zero Trust says: never trust, always verify. Every
 *    single MQTT message triggers a full trust evaluation — the device must
 *    continuously justify its access, not just prove it once."
 */
@Service
public class TrustEvaluationService {

    private final RiskScoreCalculator     calculator;
    private final AccessPolicyService     policyService;
    private final DeviceBehaviorMonitor   behaviorMonitor;
    private final SecurityEventService    eventService;
    private final DeviceRepository        deviceRepository;
    private final TrustScoreHistoryRepository historyRepository;
    private final AccessDecisionLogRepository decisionRepository;
    private final SecurityEventRepository securityEventRepository;

    @Value("${trust.behavior.violation-window-minutes:60}")
    private int violationWindowMinutes;

    public TrustEvaluationService(
            RiskScoreCalculator calculator,
            AccessPolicyService policyService,
            DeviceBehaviorMonitor behaviorMonitor,
            SecurityEventService eventService,
            DeviceRepository deviceRepository,
            TrustScoreHistoryRepository historyRepository,
            AccessDecisionLogRepository decisionRepository,
            SecurityEventRepository securityEventRepository) {

        this.calculator             = calculator;
        this.policyService          = policyService;
        this.behaviorMonitor        = behaviorMonitor;
        this.eventService           = eventService;
        this.deviceRepository       = deviceRepository;
        this.historyRepository      = historyRepository;
        this.decisionRepository     = decisionRepository;
        this.securityEventRepository = securityEventRepository;
    }

    /**
     * Full Zero Trust evaluation for one incoming MQTT message.
     *
     * RETURNS:
     *   An EvaluationResult containing:
     *   - The access decision (ALLOW/RESTRICT/QUARANTINE/DENY)
     *   - Whether the message should be blocked
     *   - The trust score at decision time
     *   - A human-readable reason
     *
     * The MQTT handler uses result.blocks() to decide whether to save the
     * sensor reading or drop it.
     *
     * @param deviceCode         The device's identifier from the MQTT message.
     * @param reportedFirmwareHash The hash reported in the MQTT payload.
     * @param messageTimestampMs  The epoch-millisecond timestamp from the payload.
     * @param triggerEvent       Label for what triggered this evaluation.
     */
    @Transactional
    public EvaluationResult evaluate(String deviceCode,
                                     String reportedFirmwareHash,
                                     long messageTimestampMs,
                                     String triggerEvent) {

        // ── Step 1: Load the device ──────────────────────────────────────────
        Optional<Device> deviceOpt = deviceRepository.findByDeviceCode(deviceCode);
        if (deviceOpt.isEmpty()) {
            // Unknown device — hard deny, no database record needed
            return EvaluationResult.denied("Unknown device code. Not in registry.", 0);
        }
        Device device = deviceOpt.get();
        int scoreBefore = device.getTrustScore() != null ? device.getTrustScore() : 50;

        // ── Step 2: Run behavior checks ──────────────────────────────────────
        boolean rateLimitExceeded = behaviorMonitor.recordMessageAndCheckRate(deviceCode);
        boolean replayDetected    = messageTimestampMs > 0
                && behaviorMonitor.checkAndRecordTimestamp(deviceCode, messageTimestampMs);
        boolean unauthorizedTopic = behaviorMonitor.hasUnauthorizedTopicAttempt(deviceCode);

        // Firmware hash mismatch check
        boolean firmwareMismatch = reportedFirmwareHash != null
                && device.getExpectedFirmwareHash() != null
                && !reportedFirmwareHash.equals(device.getExpectedFirmwareHash());

        // Count recent security violations in the violation window
        Instant windowStart = Instant.now().minusSeconds((long) violationWindowMinutes * 60);
        long recentViolations = securityEventRepository
                .countByDeviceCodeAndCreatedAtAfter(deviceCode, windowStart);

        // ── Step 3: Build TrustInputs ────────────────────────────────────────
        boolean everAuthenticated = device.getLastAuthAt() != null;
        long minutesSinceAuth = Long.MAX_VALUE;
        if (everAuthenticated) {
            minutesSinceAuth = (Instant.now().getEpochSecond()
                    - device.getLastAuthAt().getEpochSecond()) / 60;
        }

        TrustInputs inputs = TrustInputs.forDevice(deviceCode)
                .authenticated(everAuthenticated, device.getAuthFailureCount(), minutesSinceAuth)
                .rateLimitExceeded(rateLimitExceeded)
                .replayDetected(replayDetected)
                .unauthorizedTopicAttempted(unauthorizedTopic)
                .recentViolations((int) Math.min(recentViolations, Integer.MAX_VALUE))
                .deviceStatus(device.getStatus() == DeviceStatus.REVOKED,
                              device.getStatus() == DeviceStatus.QUARANTINED)
                .firmwareHashMismatch(firmwareMismatch)
                .build();

        // ── Step 4: Calculate trust score ────────────────────────────────────
        TrustComponents components = calculator.calculate(inputs);
        int newScore = components.trustScore();

        // ── Step 5: Make access decision ─────────────────────────────────────
        DecisionResult decision = policyService.decide(inputs, newScore);

        // ── Step 6: Log behavioral anomalies as security events ──────────────
        if (rateLimitExceeded) {
            long count = behaviorMonitor.getMessageCountInLastMinute(deviceCode);
            eventService.recordRateLimitExceeded(deviceCode, count,
                    20 /* max — TODO inject from config */, scoreBefore, newScore);
        }
        if (replayDetected) {
            eventService.recordReplayDetected(deviceCode, scoreBefore, newScore);
        }
        if (firmwareMismatch) {
            eventService.recordFirmwareMismatch(deviceCode, reportedFirmwareHash,
                    scoreBefore, newScore);
        }

        // ── Step 7: Enforce decision — update device status if needed ─────────
        boolean statusChanged = false;
        if (decision.decision() == AccessDecision.QUARANTINE
                && device.getStatus() == DeviceStatus.ACTIVE) {
            device.setStatus(DeviceStatus.QUARANTINED);
            eventService.recordQuarantineEnforced(deviceCode, newScore, decision.reason());
            statusChanged = true;
        }
        // Note: DENY does NOT automatically revoke. Revocation is always an
        // explicit administrator action. Automatic revocation could lock out
        // a legitimate device due to a transient network anomaly.

        // ── Step 8: Persist updated trust score and snapshot ──────────────────
        device.setTrustScore(newScore);
        device.setLastSeenAt(Instant.now());
        deviceRepository.save(device);

        // Persist the trust score history snapshot
        TrustScoreHistory snapshot = new TrustScoreHistory();
        snapshot.setDeviceCode(deviceCode);
        snapshot.setIdentityScore(components.identityScore());
        snapshot.setBehavioralScore(components.behavioralScore());
        snapshot.setHistoricalScore(components.historicalScore());
        snapshot.setSecurityStateScore(components.securityStateScore());
        snapshot.setTrustScore(newScore);
        snapshot.setAccessDecision(decision.decision().name());
        snapshot.setTriggerEvent(triggerEvent);
        snapshot.setRecordedAt(Instant.now());
        historyRepository.save(snapshot);

        // Persist the access decision log
        AccessDecisionLog log = new AccessDecisionLog();
        log.setDeviceCode(deviceCode);
        log.setOperation("PUBLISH:" + "iot/" + deviceCode + "/temperature");
        log.setTrustScore(newScore);
        log.setDecision(decision.decision().name());
        log.setReason(decision.reason());
        log.setEnforced(decision.enforced());
        log.setDecidedAt(Instant.now());
        decisionRepository.save(log);

        // Clear per-evaluation flags
        behaviorMonitor.clearFlags(deviceCode);

        return new EvaluationResult(
                decision.decision(),
                decision.blocks(),
                newScore,
                decision.reason(),
                components,
                statusChanged
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Result record
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * The outcome of one trust evaluation.
     * The MQTT handler checks result.blocked() to decide whether to save the reading.
     */
    public record EvaluationResult(
            AccessDecision decision,
            boolean blocked,
            int trustScore,
            String reason,
            TrustComponents components,
            boolean deviceStatusChanged
    ) {
        /** Convenience factory for hard-deny cases where no device record exists. */
        static EvaluationResult denied(String reason, int score) {
            return new EvaluationResult(AccessDecision.DENY, true, score, reason, null, false);
        }
    }
}
