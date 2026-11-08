package edu.cvr.bztiot.service;

/**
 * All inputs required to calculate the trust score for one device at one moment.
 *
 * WHY A SEPARATE DATA CLASS?
 *   The trust calculator is a pure function — given the same inputs, it always
 *   returns the same output. By separating inputs from the calculation, we can:
 *     1. Unit test the calculator without a database.
 *     2. Easily add new input signals without changing the calculator interface.
 *     3. Log the exact inputs that produced a given trust score.
 *
 * This class uses the Builder pattern to construct instances with only the
 * relevant fields set. Fields not set default to "safe" values that do not
 * penalise the device for things we have not checked.
 *
 * Paper mapping:
 *   identityFactor fields    → I (Identity/Authentication confidence)
 *   behavioralFactor fields  → B (Behavioral trust)
 *   historicalFactor fields  → H (Historical trust)
 *   securityStateFactor fields → S (Current security state)
 */
public class TrustInputs {

    // ── Identity factor inputs (I) ─────────────────────────────────────────
    /** True if the device has ever completed a successful challenge-response. */
    private final boolean hasEverAuthenticated;

    /** Consecutive authentication failures since the last success. */
    private final int authFailureCount;

    /** Minutes elapsed since the last successful authentication.
     *  Long.MAX_VALUE means the device has never authenticated. */
    private final long minutesSinceLastAuth;

    // ── Behavioral factor inputs (B) ──────────────────────────────────────
    /** True if the device exceeded the message-rate limit in the current window. */
    private final boolean rateLimitExceeded;

    /** True if a message with a previously-seen sequence number was received. */
    private final boolean replayDetected;

    /** True if the device attempted to publish to a topic it is not authorised for. */
    private final boolean unauthorizedTopicAttempted;

    // ── Historical factor inputs (H) ──────────────────────────────────────
    /** Count of security violations in the configured time window (e.g. past 60 min). */
    private final int recentViolationCount;

    // ── Security state factor inputs (S) ──────────────────────────────────
    /** True if the device's status is REVOKED in the database. */
    private final boolean revoked;

    /** True if the device's status is QUARANTINED in the database. */
    private final boolean quarantined;

    /** True if the reported firmware hash does not match the registered expected hash. */
    private final boolean firmwareHashMismatch;

    // ── Metadata ──────────────────────────────────────────────────────────
    /** The device code this evaluation is for. Stored for logging. */
    private final String deviceCode;

    // Private constructor — use Builder
    private TrustInputs(Builder b) {
        this.deviceCode               = b.deviceCode;
        this.hasEverAuthenticated     = b.hasEverAuthenticated;
        this.authFailureCount         = b.authFailureCount;
        this.minutesSinceLastAuth     = b.minutesSinceLastAuth;
        this.rateLimitExceeded        = b.rateLimitExceeded;
        this.replayDetected           = b.replayDetected;
        this.unauthorizedTopicAttempted = b.unauthorizedTopicAttempted;
        this.recentViolationCount     = b.recentViolationCount;
        this.revoked                  = b.revoked;
        this.quarantined              = b.quarantined;
        this.firmwareHashMismatch     = b.firmwareHashMismatch;
    }

    // ── Getters ───────────────────────────────────────────────────────────
    public String  getDeviceCode()                { return deviceCode; }
    public boolean hasEverAuthenticated()         { return hasEverAuthenticated; }
    public int     getAuthFailureCount()          { return authFailureCount; }
    public long    getMinutesSinceLastAuth()      { return minutesSinceLastAuth; }
    public boolean isRateLimitExceeded()          { return rateLimitExceeded; }
    public boolean isReplayDetected()             { return replayDetected; }
    public boolean isUnauthorizedTopicAttempted() { return unauthorizedTopicAttempted; }
    public int     getRecentViolationCount()      { return recentViolationCount; }
    public boolean isRevoked()                    { return revoked; }
    public boolean isQuarantined()                { return quarantined; }
    public boolean isFirmwareHashMismatch()       { return firmwareHashMismatch; }

    // ── Builder ───────────────────────────────────────────────────────────
    public static Builder forDevice(String deviceCode) {
        return new Builder(deviceCode);
    }

    public static final class Builder {
        private final String deviceCode;
        private boolean hasEverAuthenticated     = false;
        private int     authFailureCount         = 0;
        private long    minutesSinceLastAuth     = Long.MAX_VALUE;
        private boolean rateLimitExceeded        = false;
        private boolean replayDetected           = false;
        private boolean unauthorizedTopicAttempted = false;
        private int     recentViolationCount     = 0;
        private boolean revoked                  = false;
        private boolean quarantined              = false;
        private boolean firmwareHashMismatch     = false;

        private Builder(String deviceCode) { this.deviceCode = deviceCode; }

        public Builder authenticated(boolean everAuthenticated, int failures, long minutesSince) {
            this.hasEverAuthenticated = everAuthenticated;
            this.authFailureCount     = failures;
            this.minutesSinceLastAuth = minutesSince;
            return this;
        }
        public Builder rateLimitExceeded(boolean exceeded) {
            this.rateLimitExceeded = exceeded;
            return this;
        }
        public Builder replayDetected(boolean detected) {
            this.replayDetected = detected;
            return this;
        }
        public Builder unauthorizedTopicAttempted(boolean attempted) {
            this.unauthorizedTopicAttempted = attempted;
            return this;
        }
        public Builder recentViolations(int count) {
            this.recentViolationCount = count;
            return this;
        }
        public Builder deviceStatus(boolean revoked, boolean quarantined) {
            this.revoked     = revoked;
            this.quarantined = quarantined;
            return this;
        }
        public Builder firmwareHashMismatch(boolean mismatch) {
            this.firmwareHashMismatch = mismatch;
            return this;
        }
        public TrustInputs build() { return new TrustInputs(this); }
    }
}
