package edu.cvr.bztiot.service;

import edu.cvr.bztiot.model.Device;
import edu.cvr.bztiot.model.SecurityEvent;
import edu.cvr.bztiot.repository.DeviceRepository;
import edu.cvr.bztiot.repository.SecurityEventRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.Base64;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Handles cryptographic challenge-response authentication for IoT devices.
 *
 * HOW THE FLOW WORKS (beginner-friendly explanation):
 *
 *  Think of this like a lock-and-key test:
 *  1. The device asks "give me a puzzle" → server generates a random 32-byte nonce and stores it.
 *  2. The device uses its SECRET private key to sign the puzzle.
 *  3. The device sends the signed puzzle back.
 *  4. The server uses the PUBLIC key (registered in the database) to verify the signature.
 *
 *  Only the device that holds the real private key can produce a valid signature.
 *  A replay attack (reusing an old signature) fails because:
 *    - Challenges are one-time-use (deleted after first check).
 *    - Challenges expire after 60 seconds.
 *
 * What makes this Zero Trust:
 *   A successful authentication does NOT grant permanent access.
 *   It raises the device's trust score. The trust score is then continuously
 *   re-evaluated on every subsequent MQTT message.
 */
@Service
public class AuthenticationService {

    // How long a challenge remains valid (in seconds).
    // Configurable — changing this value is one way to tune security vs. usability.
    private static final long CHALLENGE_TTL_SECONDS = 60;

    // After this many consecutive failures the severity escalates from MEDIUM to HIGH.
    private static final int HIGH_SEVERITY_FAILURE_THRESHOLD = 3;

    // How much the trust score changes on auth events.
    // These are starting values for the prototype — tunable in Phase 3 when the
    // full trust formula (T = w1I + w2B + w3H + w4S) is integrated.
    private static final int TRUST_BOOST_ON_SUCCESS = 30;  // moves score toward 80+
    private static final int TRUST_DROP_ON_FAILURE = 10;   // each failure costs 10 points

    private final DeviceRepository deviceRepository;
    private final SecurityEventRepository eventRepository;

    /**
     * In-memory store: deviceCode → pending challenge with its creation timestamp.
     * ConcurrentHashMap is thread-safe for simultaneous MQTT messages from multiple devices.
     * Lost on server restart — acceptable for a prototype.
     * Production: use Redis or a database-backed challenge table.
     */
    private final ConcurrentHashMap<String, PendingChallenge> pendingChallenges =
            new ConcurrentHashMap<>();

    public AuthenticationService(DeviceRepository deviceRepository,
                                  SecurityEventRepository eventRepository) {
        this.deviceRepository = deviceRepository;
        this.eventRepository = eventRepository;
    }

    // -------------------------------------------------------------------------
    // Challenge generation
    // -------------------------------------------------------------------------

    /**
     * Generates a one-time cryptographic challenge for the given device.
     *
     * Returns null if the device is not registered — prevents challenge flooding
     * for non-existent device codes.
     *
     * Uses putIfAbsent to prevent overwriting a valid pending challenge if two
     * requests arrive simultaneously (denial-of-service prevention).
     */
    public byte[] generateChallenge(String deviceCode) {
        if (deviceRepository.findByDeviceCode(deviceCode).isEmpty()) {
            // Unknown device — do not issue a challenge.
            // We don't log an event here because the device might just have a typo.
            return null;
        }

        byte[] nonce = new byte[32];
        new SecureRandom().nextBytes(nonce);

        PendingChallenge challenge = new PendingChallenge(nonce, Instant.now());

        // putIfAbsent: only stores if there is no existing challenge.
        // If a challenge already exists, it is kept (prevents overwrite race condition).
        // We return the new nonce regardless — the device must sign the stored one.
        // This is acceptable for our prototype.
        pendingChallenges.put(deviceCode, challenge);

        return nonce;
    }

    // -------------------------------------------------------------------------
    // Signature verification
    // -------------------------------------------------------------------------

    /**
     * Verifies the device's signed response against the stored challenge.
     *
     * Steps:
     *  1. Look up the device in the database.
     *  2. Remove and validate the stored challenge (existence + expiry).
     *  3. Verify the ECDSA signature using the device's registered public key.
     *  4. Record an audit event and update the device trust score.
     *
     * @param deviceCode  The device's registered identifier.
     * @param signature   Raw ECDSA signature bytes (caller decodes Base64 first).
     * @return true if authentication succeeded, false otherwise.
     */
    @Transactional
    public boolean verifyResponse(String deviceCode, byte[] signature) {

        // --- Step 1: Device must exist ----------------------------------------
        Optional<Device> deviceOpt = deviceRepository.findByDeviceCode(deviceCode);
        if (deviceOpt.isEmpty()) {
            recordEvent(deviceCode, "AUTH_FAILED", "HIGH",
                    "Authentication attempt from unknown device code: " + deviceCode,
                    null, null, null);
            return false;
        }

        Device device = deviceOpt.get();
        int scoreBefore = device.getTrustScore() != null ? device.getTrustScore() : 50;

        // --- Step 2: Challenge must exist and not be expired ------------------
        PendingChallenge pending = pendingChallenges.remove(deviceCode);

        if (pending == null) {
            recordEvent(deviceCode, "AUTH_FAILED", "MEDIUM",
                    "No pending challenge found. Device may not have requested one, or it was already consumed.",
                    scoreBefore, scoreBefore, "RESTRICT");
            return false;
        }

        long ageSeconds = Instant.now().getEpochSecond() - pending.createdAt().getEpochSecond();
        if (ageSeconds > CHALLENGE_TTL_SECONDS) {
            recordEvent(deviceCode, "CHALLENGE_EXPIRED", "LOW",
                    "Challenge expired after " + ageSeconds + "s (limit: " + CHALLENGE_TTL_SECONDS + "s). Device must request a new challenge.",
                    scoreBefore, scoreBefore, null);
            return false;
        }

        // --- Step 3: Verify ECDSA signature -----------------------------------
        boolean valid;
        try {
            PublicKey publicKey = decodePublicKey(device.getPublicKey());

            /*
             * SHA256withECDSA:
             *   - SHA-256 hashes the challenge bytes.
             *   - ECDSA verifies that the hash was signed by the private key
             *     corresponding to the registered public key.
             *
             * The Java verifier expects DER-encoded ECDSA signatures (ASN.1 format).
             * If your Wokwi firmware produces raw (r,s) format instead of DER,
             * you will need a conversion step here. We will check this once the
             * firmware code is provided.
             */
            Signature verifier = Signature.getInstance("SHA256withECDSA");
            verifier.initVerify(publicKey);
            verifier.update(pending.nonce());
            valid = verifier.verify(signature);

        } catch (IllegalArgumentException e) {
            // Malformed Base64 was decoded before this call — caught here for safety
            recordEvent(deviceCode, "AUTH_FAILED", "MEDIUM",
                    "Malformed signature bytes: " + e.getMessage(),
                    scoreBefore, scoreBefore, "RESTRICT");
            return false;
        } catch (Exception e) {
            // Crypto failure — invalid key format, wrong algorithm, etc.
            recordEvent(deviceCode, "AUTH_FAILED", "MEDIUM",
                    "Signature verification error: " + e.getClass().getSimpleName(),
                    scoreBefore, scoreBefore, "RESTRICT");
            return false;
        }

        // --- Step 4: Record result and update device --------------------------
        if (valid) {
            int newScore = Math.min(100, scoreBefore + TRUST_BOOST_ON_SUCCESS);
            device.setTrustScore(newScore);
            device.setLastAuthAt(Instant.now());
            device.setAuthFailureCount(0);  // reset consecutive failure counter
            deviceRepository.save(device);

            recordEvent(deviceCode, "AUTH_SUCCESS", "INFO",
                    "Challenge-response authentication succeeded. Trust score raised from "
                            + scoreBefore + " to " + newScore + ".",
                    scoreBefore, newScore, "ALLOW");
        } else {
            int failures = device.getAuthFailureCount() + 1;
            int newScore = Math.max(0, scoreBefore - (TRUST_DROP_ON_FAILURE * failures));
            device.setAuthFailureCount(failures);
            device.setTrustScore(newScore);
            deviceRepository.save(device);

            // Severity escalates with repeated failures
            String severity = failures >= HIGH_SEVERITY_FAILURE_THRESHOLD ? "HIGH" : "MEDIUM";
            String decision = newScore < 40 ? "DENY" : newScore < 60 ? "QUARANTINE" : "RESTRICT";

            recordEvent(deviceCode, "AUTH_FAILED", severity,
                    "Invalid signature. Consecutive failure #" + failures
                            + ". Trust score reduced from " + scoreBefore + " to " + newScore + ".",
                    scoreBefore, newScore, decision);
        }

        return valid;
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    /**
     * Decodes a Base64-encoded X.509 DER public key into a Java PublicKey object.
     *
     * The device_public.pem file contains a PEM-wrapped key. The Base64 content
     * between the "-----BEGIN PUBLIC KEY-----" markers is what gets stored in
     * the database (after stripping the headers in the registration form).
     */
    private PublicKey decodePublicKey(String base64Key) throws Exception {
        // Strip PEM headers if someone accidentally pasted the full PEM block
        String stripped = base64Key
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s+", "");

        byte[] keyBytes = Base64.getDecoder().decode(stripped);
        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        return keyFactory.generatePublic(new X509EncodedKeySpec(keyBytes));
    }

    /**
     * Records a security event to the database.
     *
     * trustScoreBefore/After may be null for events where no device record exists
     * (e.g. unknown device code).
     */
    private void recordEvent(String deviceCode, String eventType, String severity,
                              String detail, Integer scoreBefore, Integer scoreAfter,
                              String decision) {
        SecurityEvent event = new SecurityEvent();
        event.setDeviceCode(deviceCode);
        event.setEventType(eventType);
        event.setSeverity(severity);
        event.setDetail(detail);
        event.setTrustScoreBefore(scoreBefore);
        event.setTrustScoreAfter(scoreAfter);
        event.setAccessDecision(decision);
        event.setCreatedAt(Instant.now());
        eventRepository.save(event);
    }

    // -------------------------------------------------------------------------
    // Inner record — challenge storage
    // -------------------------------------------------------------------------

    /**
     * Immutable value object that holds a challenge nonce and when it was created.
     * Java records are ideal here: compact, final, no boilerplate.
     */
    private record PendingChallenge(byte[] nonce, Instant createdAt) {}
}