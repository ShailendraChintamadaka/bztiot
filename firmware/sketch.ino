/*
 * BZTIoT Framework — ESP32 Authenticated IoT Firmware
 * Wokwi simulation | ESP32 + DHT22
 *
 * What this firmware does:
 *   1. Connects to WiFi and syncs time via NTP.
 *   2. Computes a firmware identity hash (SHA-256 of a constant string).
 *   3. Performs Zero Trust challenge-response authentication with the
 *      Spring Boot backend before publishing any sensor data.
 *   4. Publishes temperature/humidity JSON to MQTT every 5 seconds — BUT
 *      only if the device is authenticated.
 *   5. Re-authenticates every 30 minutes (simulates session refresh).
 *
 * ─── IMPORTANT SECURITY NOTE (for your viva) ────────────────────────────────
 *   In this Wokwi simulation the private key is embedded as a hardcoded
 *   constant. This is ONLY acceptable for simulation. A real ESP32 deployment
 *   would store the private key in:
 *     • ESP32 eFuse (one-time programmable, read-only after provisioning)
 *     • An ATECC608A/ATECC608B hardware secure element (Microchip)
 *     • ESP32-S3 with a dedicated secure vault
 *   The private key would NEVER be embedded in firmware source code in a
 *   production system.
 * ────────────────────────────────────────────────────────────────────────────
 *
 * ─── NETWORKING REQUIREMENT ─────────────────────────────────────────────────
 *   Wokwi runs in the cloud. It cannot reach "localhost:8080" on your PC.
 *   You MUST expose your Spring Boot backend with ngrok before running this:
 *
 *     ngrok http 8080
 *
 *   Then copy the https URL (e.g. https://abc123.ngrok-free.app) and paste
 *   it into BACKEND_URL below (no trailing slash).
 * ────────────────────────────────────────────────────────────────────────────
 */

#include <WiFi.h>
#include <PubSubClient.h>
#include <HTTPClient.h>          // for challenge-response HTTP calls
#include <DHT.h>
#include "time.h"
#include "mbedtls/md.h"
#include "mbedtls/sha256.h"      // NEW: explicit SHA-256 include for signing
#include "mbedtls/pk.h"          // NEW: PK context for ECDSA key loading
#include "mbedtls/ecdsa.h"       // NEW: ECDSA signing
#include "mbedtls/base64.h"      // NEW: Base64 encode/decode
#include "mbedtls/entropy.h"     // NEW: entropy source for RNG
#include "mbedtls/ctr_drbg.h"   // NEW: deterministic RNG

// ─── Pin / sensor config ───────────────────────────────────────────────────
#define DHTPIN   15
#define DHTTYPE  DHT22

// ─── Network config ────────────────────────────────────────────────────────
const char* ssid     = "Wokwi-GUEST";
const char* password = "";

// ─── CHANGE THIS: paste your ngrok URL (no trailing slash) ────────────────
//   ⚠️  Use http:// NOT https:// — Wokwi cloud simulator cannot do TLS.
//   ngrok exposes both HTTP and HTTPS; use the HTTP version.
//   Example: "http://abc123.ngrok-free.app"
//   Get it by running:  ngrok http 8080
const char* BACKEND_URL = "http://cb69-103-88-239-114.ngrok-free.app";

// ─── MQTT config ──────────────────────────────────────────────────────────
const char* mqtt_server = "test.mosquitto.org";
const int   mqtt_port   = 1883;

// ─── Device identity ──────────────────────────────────────────────────────
const char* deviceId = "ESP32_001";

// ─── NTP config ───────────────────────────────────────────────────────────
const char* ntpServer        = "pool.ntp.org";
const long  gmtOffset_sec    = 0;
const int   daylightOffset_sec = 0;

// ─── Authentication timing ────────────────────────────────────────────────
// Re-authenticate every 30 minutes. A Zero Trust system does not grant
// permanent access after one successful authentication.
const unsigned long RE_AUTH_INTERVAL_MS = 30UL * 60UL * 1000UL;

// ─── Private key ──────────────────────────────────────────────────────────
// ⚠️  SIMULATION ONLY — see the security note at the top of this file.
//     In production the private key never appears in source code.
//     This key corresponds to the public key registered in the backend UI.
static const char DEVICE_PRIVATE_KEY[] =
    "-----BEGIN EC PRIVATE KEY-----\n"
    "MHcCAQEEIKNAeKhpbk8vPEw1HjHJS5Yy4mPWphwT7lbaDYM3y+evoAoGCCqGSM49\n"
    "AwEHoUQDQgAESTxixEko1oNgU/rbo3OFkZie17vj1frOIMOnvov66xLcaDpeb/6L\n"
    "gUY2GXwL4LZESvlIdzO2o+fBsadh4pLSQw==\n"
    "-----END EC PRIVATE KEY-----\n";

// ─── Global state ─────────────────────────────────────────────────────────
DHT         dht(DHTPIN, DHTTYPE);
WiFiClient  espClient;
PubSubClient client(espClient);
String      firmwareHash;
bool        isAuthenticated    = false;   // gates MQTT publishing
unsigned long lastAuthTime     = 0;       // millis() of last successful auth
int         authFailureCount   = 0;       // consecutive authentication failures

// ─── mbedtls RNG context (shared; initialized once in setup) ──────────────
mbedtls_entropy_context  entropy;
mbedtls_ctr_drbg_context ctr_drbg;

// ═══════════════════════════════════════════════════════════════════════════
// FIRMWARE HASH
// ═══════════════════════════════════════════════════════════════════════════

/*
 * Computes SHA-256("BZT-IoT-ESP32-v1.0.0") as a hex string.
 * This acts as a firmware identity fingerprint.
 *
 * IMPORTANT: copy this value from the Serial monitor and paste it into
 * "Expected Firmware Hash" when registering the device in the admin UI.
 * It is always the same for the same firmware version string.
 *
 * Note for your viva: This is NOT a real firmware integrity check — hashing
 * a hardcoded string verifies nothing about the actual binary. A real system
 * would compute a hash of its own flash memory or use a bootloader-provided
 * value signed by the vendor. It serves as a concept demonstration here.
 */
String computeFirmwareHash() {
    const char* firmwareIdentity = "BZT-IoT-ESP32-v1.0.0";
    byte shaResult[32];

    mbedtls_md_context_t ctx;
    mbedtls_md_type_t    md_type = MBEDTLS_MD_SHA256;
    mbedtls_md_init(&ctx);
    mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(md_type), 0);
    mbedtls_md_starts(&ctx);
    mbedtls_md_update(&ctx, (const unsigned char*)firmwareIdentity, strlen(firmwareIdentity));
    mbedtls_md_finish(&ctx, shaResult);
    mbedtls_md_free(&ctx);

    String hashStr = "";
    for (int i = 0; i < 32; i++) {
        char hex[3];
        sprintf(hex, "%02x", shaResult[i]);
        hashStr += hex;
    }
    return hashStr;
}

// ═══════════════════════════════════════════════════════════════════════════
// NETWORK SETUP
// ═══════════════════════════════════════════════════════════════════════════

void setup_wifi() {
    delay(10);
    Serial.print("Connecting to WiFi: ");
    Serial.println(ssid);
    WiFi.begin(ssid, password);
    while (WiFi.status() != WL_CONNECTED) {
        delay(500);
        Serial.print(".");
    }
    Serial.println("\nWiFi connected — IP: " + WiFi.localIP().toString());
}

void setup_time() {
    configTime(gmtOffset_sec, daylightOffset_sec, ntpServer);
    struct tm timeinfo;
    Serial.println("Syncing NTP time...");
    int attempts = 0;
    while (!getLocalTime(&timeinfo) && attempts < 20) {
        Serial.println("Waiting for NTP...");
        delay(1000);
        attempts++;
    }
    if (attempts < 20) Serial.println("Time synchronized.");
    else               Serial.println("NTP sync failed — timestamps may be inaccurate.");
}

unsigned long long getEpochMillis() {
    time_t now;
    time(&now);
    return (unsigned long long)now * 1000ULL;
}

void reconnect_mqtt() {
    while (!client.connected()) {
        Serial.print("Connecting to MQTT broker...");
        String clientId = "ESP32Client-" + String(deviceId);
        if (client.connect(clientId.c_str())) {
            Serial.println(" connected.");
        } else {
            Serial.print(" failed (rc=");
            Serial.print(client.state());
            Serial.println("). Retrying in 5s...");
            delay(5000);
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// CRYPTOGRAPHIC HELPERS
// ═══════════════════════════════════════════════════════════════════════════

/*
 * Decodes a Base64 string into raw bytes.
 * Returns the number of output bytes, or -1 on failure.
 *
 * Used to decode the challenge nonce received from the backend.
 */
int base64Decode(const char* input, size_t inputLen,
                 uint8_t* output, size_t outputMaxLen) {
    size_t outLen = 0;
    int ret = mbedtls_base64_decode(output, outputMaxLen, &outLen,
                                    (const unsigned char*)input, inputLen);
    if (ret != 0) {
        Serial.printf("Base64 decode failed: -0x%04X\n", -ret);
        return -1;
    }
    return (int)outLen;
}

/*
 * Encodes raw bytes as a Base64 string (null-terminated).
 * Returns true on success.
 *
 * Used to encode the ECDSA signature for the verify request body.
 */
bool base64Encode(const uint8_t* input, size_t inputLen,
                  char* output, size_t outputMaxLen) {
    size_t outLen = 0;
    int ret = mbedtls_base64_encode((unsigned char*)output, outputMaxLen, &outLen,
                                    input, inputLen);
    if (ret != 0) {
        Serial.printf("Base64 encode failed: -0x%04X\n", -ret);
        return false;
    }
    output[outLen] = '\0';
    return true;
}

/*
 * Signs the given challenge bytes using ECDSA with the device's private key.
 *
 * HOW IT WORKS (beginner explanation):
 *   1. SHA-256 hashes the challenge bytes (the nonce) into a 32-byte digest.
 *   2. ECDSA signs that digest using the private key.
 *   3. The output is a DER-encoded signature — the same format Java's
 *      SHA256withECDSA verifier expects. No conversion needed! ✓
 *
 * Parameters:
 *   challengeBytes — raw bytes of the nonce (NOT Base64-encoded)
 *   challengeLen   — length of challengeBytes (expected: 32)
 *   sigOut         — output buffer for the DER signature
 *   sigOutLen      — on return, the actual length of the signature
 *
 * Returns true on success.
 */
bool signChallenge(const uint8_t* challengeBytes, size_t challengeLen,
                   uint8_t* sigOut, size_t* sigOutLen) {

    // Step 1: SHA-256 hash the challenge bytes
    uint8_t digest[32];
    mbedtls_sha256(challengeBytes, challengeLen, digest, 0 /* is224=false */);

    // Step 2: Load the private key from the PEM constant
    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);

    // mbedtls 3.x (ESP32 core >= 3.x / ESP-IDF 5.x) requires two extra
    // arguments at the end: an RNG callback and its context.
    int ret = mbedtls_pk_parse_key(
        &pk,
        (const unsigned char*)DEVICE_PRIVATE_KEY,
        sizeof(DEVICE_PRIVATE_KEY),       // includes the null terminator
        NULL, 0,                          // no password
        mbedtls_ctr_drbg_random, &ctr_drbg  // RNG — required by mbedTLS 3.x
    );

    if (ret != 0) {
        Serial.printf("Private key parse failed: -0x%04X\n", -ret);
        mbedtls_pk_free(&pk);
        return false;
    }

    // Step 3: Sign the digest with ECDSA (output is DER-encoded).
    // mbedTLS 3.x mbedtls_pk_sign() signature:
    //   (..., sig, sig_size, sig_len*, f_rng, p_rng)
    // sig_size is the capacity of the output buffer (72 bytes for P-256 DER).
    // sig_len* receives the actual written length.
    *sigOutLen = 0;
    ret = mbedtls_pk_sign(
        &pk,
        MBEDTLS_MD_SHA256,
        digest, sizeof(digest),
        sigOut, 72,                          // sig_size: max DER P-256 sig bytes
        sigOutLen,                           // receives actual length written
        mbedtls_ctr_drbg_random, &ctr_drbg  // RNG for randomised signing
    );

    mbedtls_pk_free(&pk);

    if (ret != 0) {
        Serial.printf("ECDSA sign failed: -0x%04X\n", -ret);
        return false;
    }

    Serial.printf("Signature produced: %d bytes (DER-encoded)\n", *sigOutLen);
    return true;
}

// ═══════════════════════════════════════════════════════════════════════════
// AUTHENTICATION FLOW
// ═══════════════════════════════════════════════════════════════════════════

/*
 * Simple JSON field extractor — finds the value of a given key in a JSON string.
 * This avoids adding the ArduinoJson library dependency.
 *
 * Works for flat JSON objects with string values.
 * Example: extractJsonString("{\"challenge\":\"abc123\"}", "challenge") → "abc123"
 */
String extractJsonString(const String& json, const char* key) {
    String searchKey = "\"" + String(key) + "\":\"";
    int start = json.indexOf(searchKey);
    if (start < 0) return "";
    start += searchKey.length();
    int end = json.indexOf("\"", start);
    if (end < 0) return "";
    return json.substring(start, end);
}

/*
 * Full Zero Trust device authentication:
 *   GET  {BACKEND_URL}/api/devices/auth/challenge/{deviceId}
 *     → receive Base64 nonce
 *   POST {BACKEND_URL}/api/devices/auth/verify
 *     → body: {"deviceCode":"ESP32_001","signature":"<base64 DER sig>"}
 *     → expect: {"status":"AUTHENTICATED"}
 *
 * Returns true if the backend confirms authentication.
 */
bool authenticate() {
    if (WiFi.status() != WL_CONNECTED) {
        Serial.println("[AUTH] WiFi not connected — cannot authenticate.");
        return false;
    }

    HTTPClient http;

    // ── Use plain WiFiClient (no SSL). The BACKEND_URL must start with http://
    //    Wokwi's cloud simulator cannot complete TLS handshakes to external hosts
    //    (WiFiClientSecure fails). We expose the backend over plain HTTP via ngrok's
    //    HTTP tunnel (http://xyz.ngrok-free.app → localhost:8080). No SSL needed
    //    here because the data is a nonce + a public-key-verified signature — there
    //    is no secret in transit. ─────────────────────────────────────────────────
    WiFiClient plainClient;

    // ── Step 1: Request a challenge ────────────────────────────────────────
    String challengeUrl = String(BACKEND_URL)
                        + "/api/devices/auth/challenge/"
                        + String(deviceId);

    Serial.println("[AUTH] Requesting challenge from: " + challengeUrl);
    http.begin(plainClient, challengeUrl);
    http.addHeader("Content-Type", "application/json");
    // ngrok requires this header to avoid the browser-redirect interstitial
    http.addHeader("ngrok-skip-browser-warning", "true");

    int httpCode = http.GET();
    if (httpCode != 200) {
        Serial.printf("[AUTH] Challenge request failed — HTTP %d\n", httpCode);
        if (httpCode == 404) {
            Serial.println("[AUTH] Device not registered in backend. Register it first.");
        }
        http.end();
        return false;
    }

    String challengeResponse = http.getString();
    http.end();
    Serial.println("[AUTH] Challenge response: " + challengeResponse);

    // ── Step 2: Extract and decode the Base64 challenge nonce ──────────────
    String challengeB64 = extractJsonString(challengeResponse, "challenge");
    if (challengeB64.isEmpty()) {
        Serial.println("[AUTH] Could not parse challenge from response.");
        return false;
    }
    Serial.println("[AUTH] Challenge (Base64): " + challengeB64);

    // Decode Base64 → raw bytes (the 32-byte nonce)
    uint8_t nonce[64];  // 32 bytes decoded, 64 is safe upper bound
    int nonceLen = base64Decode(challengeB64.c_str(), challengeB64.length(),
                                nonce, sizeof(nonce));
    if (nonceLen < 0) {
        Serial.println("[AUTH] Failed to decode challenge nonce.");
        return false;
    }
    Serial.printf("[AUTH] Nonce decoded: %d bytes\n", nonceLen);

    // ── Step 3: Sign the nonce with the device private key ─────────────────
    // Maximum DER-encoded P-256 signature: 72 bytes
    uint8_t signature[72];
    size_t  sigLen = 0;

    if (!signChallenge(nonce, nonceLen, signature, &sigLen)) {
        Serial.println("[AUTH] ECDSA signing failed.");
        return false;
    }

    // ── Step 4: Base64-encode the DER signature ────────────────────────────
    // Base64 output is (sigLen * 4/3 + 4) bytes, rounded up. 100 bytes is safe.
    char sigBase64[128];
    if (!base64Encode(signature, sigLen, sigBase64, sizeof(sigBase64))) {
        Serial.println("[AUTH] Failed to Base64-encode signature.");
        return false;
    }
    Serial.println("[AUTH] Signature (Base64): " + String(sigBase64));

    // ── Step 5: Send the signed response to the verify endpoint ───────────
    String verifyUrl = String(BACKEND_URL) + "/api/devices/auth/verify";
    Serial.println("[AUTH] Sending verify request to: " + verifyUrl);

    http.begin(plainClient, verifyUrl);
    http.addHeader("Content-Type", "application/json");
    http.addHeader("ngrok-skip-browser-warning", "true");

    // Build JSON body: {"deviceCode":"ESP32_001","signature":"<base64>"}
    String body = "{\"deviceCode\":\"" + String(deviceId)
                + "\",\"signature\":\"" + String(sigBase64) + "\"}";

    httpCode = http.POST(body);
    String verifyResponse = http.getString();
    http.end();

    Serial.printf("[AUTH] Verify HTTP status: %d\n", httpCode);
    Serial.println("[AUTH] Verify response: " + verifyResponse);

    // ── Step 6: Check result ───────────────────────────────────────────────
    if (httpCode == 200) {
        String status = extractJsonString(verifyResponse, "status");
        if (status == "AUTHENTICATED") {
            Serial.println("[AUTH] ✓ Device authenticated successfully.");
            return true;
        }
    }

    Serial.println("[AUTH] ✗ Authentication rejected by backend.");
    return false;
}

/*
 * Called from setup() and periodically from loop().
 * Retries up to 3 times before entering an error state.
 *
 * Zero Trust principle: if authentication fails repeatedly, the device
 * stops publishing data entirely. It does not silently continue.
 */
void ensureAuthenticated() {
    const int MAX_RETRIES = 3;

    for (int attempt = 1; attempt <= MAX_RETRIES; attempt++) {
        Serial.printf("[AUTH] Attempt %d of %d...\n", attempt, MAX_RETRIES);
        if (authenticate()) {
            isAuthenticated  = true;
            authFailureCount = 0;
            lastAuthTime     = millis();
            return;
        }
        Serial.println("[AUTH] Waiting 3s before retry...");
        delay(3000);
    }

    // All retries exhausted — enter unauthenticated state
    isAuthenticated = false;
    authFailureCount++;
    Serial.printf("[AUTH] ✗ All %d attempts failed. Device will NOT publish data.\n", MAX_RETRIES);
    Serial.println("[AUTH] Check: Is the backend running? Is ngrok active? Is the device registered?");
}

// ═══════════════════════════════════════════════════════════════════════════
// SETUP
// ═══════════════════════════════════════════════════════════════════════════

void setup() {
    Serial.begin(115200);
    dht.begin();

    // Initialise the mbedtls RNG — used by ECDSA signing.
    // This must happen before any call to signChallenge().
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    const char* pers = "bztiot_esp32";  // personalization string (any unique text)
    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                           (const unsigned char*)pers, strlen(pers));

    setup_wifi();
    setup_time();

    // Compute and print firmware hash — copy this into the admin UI
    firmwareHash = computeFirmwareHash();
    Serial.println("═══════════════════════════════════════════");
    Serial.println("Firmware hash: " + firmwareHash);
    Serial.println("Register this device with the hash above.");
    Serial.println("═══════════════════════════════════════════");

    // MQTT broker connection
    client.setServer(mqtt_server, mqtt_port);

    // ── ZERO TRUST: authenticate BEFORE any data is published ──────────────
    // This is what makes the system Zero Trust — the device proves its identity
    // cryptographically before it is allowed to send any sensor data.
    Serial.println("[AUTH] Starting Zero Trust device authentication...");
    ensureAuthenticated();

    if (isAuthenticated) {
        Serial.println("Device is authenticated and ready to publish sensor data.");
    } else {
        Serial.println("WARNING: Device could not authenticate. Data publishing is BLOCKED.");
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// MAIN LOOP
// ═══════════════════════════════════════════════════════════════════════════

void loop() {
    // ── Periodic re-authentication ─────────────────────────────────────────
    // Zero Trust: authentication is not one-time. Re-authenticate periodically.
    if (millis() - lastAuthTime > RE_AUTH_INTERVAL_MS) {
        Serial.println("[AUTH] Re-authentication interval reached. Re-authenticating...");
        ensureAuthenticated();
    }

    // ── MQTT connection ────────────────────────────────────────────────────
    if (!client.connected()) {
        reconnect_mqtt();
    }
    client.loop();

    // ── Sensor reading ─────────────────────────────────────────────────────
    float temperature = dht.readTemperature();
    float humidity    = dht.readHumidity();

    if (isnan(temperature) || isnan(humidity)) {
        Serial.println("Failed to read DHT22 sensor — skipping publish.");
        delay(2000);
        return;
    }

    // Wokwi-specific: add small random variation to simulate real sensor noise
    temperature += random(-20, 21) / 10.0;
    humidity    += random(-30, 31) / 10.0;

    unsigned long long epochMillis = getEpochMillis();

    // ── ZERO TRUST GATE: only publish if authenticated ────────────────────
    if (!isAuthenticated) {
        Serial.println("[BLOCK] Device not authenticated — MQTT publish suppressed.");
        delay(5000);
        return;
    }

    // ── Build and publish MQTT payload ─────────────────────────────────────
    char payload[300];
    snprintf(payload, sizeof(payload),
        "{\"deviceCode\":\"%s\","
        "\"temperature\":%.1f,"
        "\"humidity\":%.1f,"
        "\"firmwareHash\":\"%s\","
        "\"timestamp\":%llu}",
        deviceId, temperature, humidity, firmwareHash.c_str(), epochMillis);

    char topic[60];
    snprintf(topic, sizeof(topic), "iot/%s/temperature", deviceId);

    bool published = client.publish(topic, payload);
    if (published) {
        Serial.println("[MQTT] Published: " + String(payload));
    } else {
        Serial.println("[MQTT] Publish failed — MQTT client error.");
    }

    delay(5000);
}
