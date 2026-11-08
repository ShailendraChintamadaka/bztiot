package edu.cvr.bztiot.controller;

import edu.cvr.bztiot.dto.AuthChallengeResponse;
import edu.cvr.bztiot.dto.AuthVerifyRequest;
import edu.cvr.bztiot.service.AuthenticationService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Base64;
import java.util.Map;

/**
 * Public endpoints for IoT device challenge-response authentication.
 *
 * These endpoints are explicitly permitted in SecurityConfig without requiring
 * the administrator session cookie — IoT devices have no browser session.
 *
 * Flow:
 *   GET  /api/devices/auth/challenge/{deviceCode} → receive Base64 nonce
 *   POST /api/devices/auth/verify                 → submit Base64 signature
 */
@RestController
@RequestMapping("/api/devices/auth")
public class DeviceAuthController {

    private final AuthenticationService authenticationService;

    public DeviceAuthController(AuthenticationService authenticationService) {
        this.authenticationService = authenticationService;
    }

    /**
     * Step 1: Device requests a challenge.
     *
     * Returns 200 with a Base64-encoded 32-byte nonce if the device is registered.
     * Returns 404 if the device code is not in the registry.
     *
     * The device must sign the raw bytes (Base64-decoded) with its private key
     * using SHA256withECDSA, then call /verify.
     */
    @GetMapping("/challenge/{deviceCode}")
    public ResponseEntity<?> challenge(@PathVariable String deviceCode) {
        byte[] nonce = authenticationService.generateChallenge(deviceCode);

        if (nonce == null) {
            // Device not registered — return 404, not 200 with an error body.
            // This prevents challenge flooding for non-existent devices.
            return ResponseEntity.notFound().build();
        }

        AuthChallengeResponse response = new AuthChallengeResponse();
        response.setChallenge(Base64.getEncoder().encodeToString(nonce));
        return ResponseEntity.ok(response);
    }

    /**
     * Step 2: Device submits its signed challenge.
     *
     * Returns 200 + JSON on success.
     * Returns 401 + JSON on failure (invalid signature, expired, unknown device).
     *
     * The response body includes a "status" field so the firmware can parse it:
     *   { "status": "AUTHENTICATED" }
     *   { "status": "AUTHENTICATION_FAILED", "reason": "..." }
     */
    @PostMapping("/verify")
    public ResponseEntity<Map<String, String>> verify(@RequestBody AuthVerifyRequest request) {

        // Guard against missing fields
        if (request.getDeviceCode() == null || request.getSignature() == null) {
            return ResponseEntity.badRequest()
                    .body(Map.of("status", "AUTHENTICATION_FAILED",
                                 "reason", "deviceCode and signature are required"));
        }

        // Decode the Base64 signature safely
        byte[] signatureBytes;
        try {
            signatureBytes = Base64.getDecoder().decode(request.getSignature());
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest()
                    .body(Map.of("status", "AUTHENTICATION_FAILED",
                                 "reason", "Signature is not valid Base64"));
        }

        boolean valid = authenticationService.verifyResponse(request.getDeviceCode(), signatureBytes);

        if (valid) {
            return ResponseEntity.ok(Map.of("status", "AUTHENTICATED"));
        } else {
            return ResponseEntity.status(401)
                    .body(Map.of("status", "AUTHENTICATION_FAILED",
                                 "reason", "Invalid or expired challenge response"));
        }
    }
}