package edu.cvr.bztiot.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.Deque;
import java.util.LinkedList;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Monitors device behavior in real time and detects anomalies.
 *
 * WHAT IT TRACKS (per device, in memory):
 *   1. Message rate   — timestamps of recent messages in a sliding window.
 *   2. Sequence numbers — to detect replayed messages.
 *   3. Unauthorized topic attempts — flagged when firmware publishes off-spec.
 *
 * WHY IN-MEMORY?
 *   For this prototype, behavior state is stored in ConcurrentHashMaps. This is
 *   fast and sufficient for a single-server deployment. Limitations:
 *     - State is lost on server restart.
 *     - Does not work across multiple server instances (no distributed cache).
 *   Production option: replace with Redis for shared, persistent behavior state.
 *
 * THREAD SAFETY:
 *   All maps use ConcurrentHashMap. The per-device Deque of timestamps is
 *   synchronized individually during access to prevent race conditions when
 *   multiple MQTT messages arrive simultaneously for the same device.
 *
 * CONFIGURATION:
 *   Limits are in application.yaml under trust.behavior.*
 */
@Component
public class DeviceBehaviorMonitor {

    @Value("${trust.behavior.max-messages-per-minute:20}")
    private int maxMessagesPerMinute;

    // Sliding window of message reception timestamps per device
    // Key: deviceCode, Value: queue of Instant timestamps
    private final Map<String, Deque<Instant>> messageTimestamps = new ConcurrentHashMap<>();

    // Last seen sequence number per device (for replay detection)
    // Key: deviceCode, Value: last sequence number seen
    private final Map<String, Long> lastSequenceNumbers = new ConcurrentHashMap<>();

    // Devices that have attempted to publish to unauthorized topics this window
    private final Map<String, Boolean> unauthorizedTopicFlags = new ConcurrentHashMap<>();

    // ── Rate limiting ─────────────────────────────────────────────────────

    /**
     * Records that a message was received from a device and checks the rate limit.
     *
     * HOW IT WORKS (sliding window):
     *   - Each arrival time is added to a queue for this device.
     *   - Old entries (older than 60 seconds) are purged on each call.
     *   - If the remaining queue size exceeds the limit, rate abuse is detected.
     *
     * @param deviceCode The device sending the message.
     * @return true if the device has exceeded its rate limit.
     */
    public boolean recordMessageAndCheckRate(String deviceCode) {
        Instant now = Instant.now();
        Instant oneMinuteAgo = now.minusSeconds(60);

        // Get or create the timestamp queue for this device
        Deque<Instant> timestamps = messageTimestamps.computeIfAbsent(
                deviceCode, k -> new LinkedList<>());

        synchronized (timestamps) {
            // Purge timestamps older than 60 seconds (sliding window)
            while (!timestamps.isEmpty() && timestamps.peekFirst().isBefore(oneMinuteAgo)) {
                timestamps.pollFirst();
            }
            // Record this message
            timestamps.addLast(now);

            long count = timestamps.size();
            return count > maxMessagesPerMinute;
        }
    }

    /**
     * Returns how many messages the device sent in the last 60 seconds.
     * Used for logging and audit details.
     */
    public long getMessageCountInLastMinute(String deviceCode) {
        Deque<Instant> timestamps = messageTimestamps.get(deviceCode);
        if (timestamps == null) return 0;
        Instant oneMinuteAgo = Instant.now().minusSeconds(60);
        synchronized (timestamps) {
            return timestamps.stream().filter(t -> t.isAfter(oneMinuteAgo)).count();
        }
    }

    // ── Replay detection ─────────────────────────────────────────────────

    /**
     * Checks whether a message sequence number has been seen before.
     *
     * WHAT IS REPLAY DETECTION?
     *   If a device includes a strictly increasing sequence number in its messages
     *   and an attacker captures and re-sends an old message, the sequence number
     *   will be equal to or lower than what the server has already seen.
     *
     * CURRENT LIMITATION:
     *   The existing Wokwi firmware does not include a sequence number field.
     *   This monitor uses the message timestamp as a proxy: if a timestamp is
     *   within 10 seconds of the last seen timestamp for this device, it is
     *   considered a potential replay. This is a simplification — Phase 4 will
     *   add explicit sequence numbers to the firmware.
     *
     * @param deviceCode The device code.
     * @param messageTimestampMs The message's own timestamp in epoch milliseconds.
     * @return true if this appears to be a replayed message.
     */
    public boolean checkAndRecordTimestamp(String deviceCode, long messageTimestampMs) {
        Long lastSeen = lastSequenceNumbers.get(deviceCode);

        if (lastSeen != null) {
            // If the incoming timestamp is older than or equal to the last one we saw,
            // and the difference is less than 30 seconds, treat it as a potential replay.
            long diff = messageTimestampMs - lastSeen;
            if (diff <= 0) {
                // Timestamp went backwards — definitely a replay or clock issue
                return true;
            }
        }

        // Update the last-seen timestamp
        lastSequenceNumbers.put(deviceCode, messageTimestampMs);
        return false;
    }

    // ── Unauthorized topic tracking ───────────────────────────────────────

    /**
     * Records that a device attempted to publish to an unauthorized topic.
     * The flag is cleared when the trust score is recalculated (by TrustEvaluationService).
     */
    public void recordUnauthorizedTopicAttempt(String deviceCode) {
        unauthorizedTopicFlags.put(deviceCode, Boolean.TRUE);
    }

    /**
     * Returns whether the device has attempted an unauthorized topic this window.
     * Cleared by clearFlags() after trust recalculation.
     */
    public boolean hasUnauthorizedTopicAttempt(String deviceCode) {
        return Boolean.TRUE.equals(unauthorizedTopicFlags.get(deviceCode));
    }

    /**
     * Clears per-window behavioral flags for a device after trust recalculation.
     * Rate timestamps are NOT cleared — they use the sliding window for decay.
     */
    public void clearFlags(String deviceCode) {
        unauthorizedTopicFlags.remove(deviceCode);
    }

    /**
     * Resets all state for a device — called when a device is re-registered or
     * its trust score is manually reset by an administrator.
     */
    public void resetDevice(String deviceCode) {
        messageTimestamps.remove(deviceCode);
        lastSequenceNumbers.remove(deviceCode);
        unauthorizedTopicFlags.remove(deviceCode);
    }
}
