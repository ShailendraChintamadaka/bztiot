package edu.cvr.bztiot.config;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import edu.cvr.bztiot.model.SensorReading;
import edu.cvr.bztiot.repository.DeviceRepository;
import edu.cvr.bztiot.repository.SensorReadingRepository;
import edu.cvr.bztiot.repository.SecurityEventRepository;
import edu.cvr.bztiot.service.SecurityEventService;
import edu.cvr.bztiot.service.TrustEvaluationService;
import org.eclipse.paho.client.mqttv3.MqttConnectOptions;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.integration.annotation.ServiceActivator;
import org.springframework.integration.channel.DirectChannel;
import org.springframework.integration.config.EnableIntegration;
import org.springframework.integration.core.MessageProducer;
import org.springframework.integration.mqtt.core.DefaultMqttPahoClientFactory;
import org.springframework.integration.mqtt.core.MqttPahoClientFactory;
import org.springframework.integration.mqtt.inbound.MqttPahoMessageDrivenChannelAdapter;
import org.springframework.messaging.MessageChannel;
import org.springframework.messaging.MessageHandler;

import java.time.Instant;
import java.util.Iterator;
import java.util.Set;

/**
 * MQTT subscriber configuration.
 *
 * WHAT CHANGED IN PHASE 3:
 *   The handler() method previously made all security decisions inline:
 *   checking device status, logging events, etc. This violated separation
 *   of concerns — security logic does not belong in a configuration class.
 *
 *   It now delegates entirely to TrustEvaluationService.evaluate(), which:
 *     1. Collects behavioral signals (rate, replay, topic).
 *     2. Computes the trust score (T = w1*I + w2*B + w3*H + w4*S).
 *     3. Makes the access decision (ALLOW/RESTRICT/QUARANTINE/DENY).
 *     4. Persists the audit trail.
 *     5. Returns whether the message should be blocked.
 *
 *   The handler's only job is now:
 *     1. Parse the MQTT JSON payload.
 *     2. Call evaluate().
 *     3. If not blocked → save sensor readings.
 *
 * FLOW (one MQTT message):
 *   MQTT broker → mqttInputChannel → handler() → evaluate() → save/drop
 */
@Configuration
@EnableIntegration
public class MqttConfig {

    @Value("${mqtt.broker.url}")
    private String brokerUrl;

    @Value("${mqtt.client.id}")
    private String clientId;

    @Value("${mqtt.topic}")
    private String topic;

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Bean
    public MqttPahoClientFactory mqttClientFactory() {
        DefaultMqttPahoClientFactory factory = new DefaultMqttPahoClientFactory();
        MqttConnectOptions options = new MqttConnectOptions();
        options.setServerURIs(new String[]{brokerUrl});
        options.setCleanSession(true);
        options.setAutomaticReconnect(true);
        factory.setConnectionOptions(options);
        return factory;
    }

    @Bean
    public MessageChannel mqttInputChannel() {
        return new DirectChannel();
    }

    @Bean
    public MessageProducer inbound() {
        MqttPahoMessageDrivenChannelAdapter adapter =
                new MqttPahoMessageDrivenChannelAdapter(clientId, mqttClientFactory(), topic);
        adapter.setCompletionTimeout(5000);
        adapter.setQos(1);
        adapter.setOutputChannel(mqttInputChannel());
        return adapter;
    }

    /**
     * Core MQTT message handler.
     *
     * The TrustEvaluationService is injected as a parameter rather than a field.
     * This is necessary because @ServiceActivator beans are instantiated early
     * and Spring Integration resolves handler bean arguments at channel subscription
     * time — using a field would require MqttConfig to be eagerly initialized
     * before all trust services are ready.
     *
     * For unregistered devices the evaluation service itself returns DENY.
     * For registered devices, the full trust pipeline runs.
     */
    @Bean
    @ServiceActivator(inputChannel = "mqttInputChannel")
    public MessageHandler handler(SensorReadingRepository sensorRepo,
                                  DeviceRepository deviceRepo,
                                  SecurityEventRepository eventRepo,
                                  TrustEvaluationService trustEngine,
                                  SecurityEventService eventService) {
        return message -> {
            String payload = null;
            try {
                payload = message.getPayload().toString();
                System.out.println("[MQTT] Raw: " + payload);

                JsonNode json = objectMapper.readTree(payload);

                // Extract fields needed by both the trust engine and sensor storage
                String deviceCode    = json.has("deviceCode")
                        ? json.get("deviceCode").asText() : "UNKNOWN";
                String reportedHash  = json.has("firmwareHash")
                        ? json.get("firmwareHash").asText() : null;
                long   timestampMs   = json.has("timestamp")
                        ? json.get("timestamp").asLong() : 0L;

                // ── ZERO TRUST EVALUATION ───────────────────────────────────
                // This single call replaces all the previous inline status checks,
                // logEvent calls, firmware hash checks, and quarantine logic.
                // Every decision is now tracked in the trust_score_history and
                // access_decisions tables with full reasoning.
                TrustEvaluationService.EvaluationResult result =
                        trustEngine.evaluate(deviceCode, reportedHash, timestampMs, "MQTT_MESSAGE");

                System.out.printf("[MQTT] %s → trust=%d decision=%s%n",
                        deviceCode, result.trustScore(), result.decision());

                if (result.deviceStatusChanged()) {
                    System.out.println("[MQTT] Device status updated to QUARANTINED for: " + deviceCode);
                }

                // ── ENFORCEMENT GATE ────────────────────────────────────────
                // If the trust engine says block, drop the message here.
                // The sensor reading is NEVER saved for a DENY or QUARANTINE decision.
                if (result.blocked()) {
                    System.out.println("[MQTT] BLOCKED: " + deviceCode + " — " + result.reason());
                    return;
                }

                // ── SAVE SENSOR READINGS ─────────────────────────────────────
                // Only reached if decision is ALLOW or RESTRICT.
                // RESTRICT logs extra detail but still saves the reading.
                if (result.decision().name().equals("RESTRICT")) {
                    System.out.println("[MQTT] RESTRICT: saving reading with elevated monitoring for: " + deviceCode);
                    eventService.record(deviceCode, "RESTRICTED_ACCEPT", "LOW",
                            "Message accepted under RESTRICT policy. Trust=" + result.trustScore()
                                    + ". " + result.reason());
                }

                // Reload device (TrustEvaluationService may have updated lastSeenAt already,
                // but we need the entity reference for the SensorReading relationship)
                deviceRepo.findByDeviceCode(deviceCode).ifPresent(device -> {
                    Instant deviceTimestamp = timestampMs > 0
                            ? Instant.ofEpochMilli(timestampMs) : null;

                    Set<String> skipFields = Set.of("deviceCode", "firmwareHash", "timestamp");
                    Iterator<String> fieldNames = json.fieldNames();

                    while (fieldNames.hasNext()) {
                        String field = fieldNames.next();
                        if (skipFields.contains(field)) continue;
                        JsonNode valueNode = json.get(field);
                        if (!valueNode.isNumber()) continue;

                        SensorReading reading = new SensorReading();
                        reading.setDevice(device);
                        reading.setMetricType(field);
                        reading.setMetricValue(valueNode.asDouble());
                        reading.setReportedFirmwareHash(reportedHash);
                        reading.setDeviceTimestamp(deviceTimestamp);
                        reading.setReceivedAt(Instant.now());
                        sensorRepo.save(reading);
                    }

                    System.out.println("[MQTT] Saved readings for: " + deviceCode);
                });

            } catch (Exception e) {
                System.err.println("[MQTT] Processing error: " + e.getMessage());
                if (payload != null) {
                    System.err.println("[MQTT] Payload was: " + payload);
                }
            }
        };
    }
}