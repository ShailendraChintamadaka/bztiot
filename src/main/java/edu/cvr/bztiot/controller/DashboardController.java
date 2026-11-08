package edu.cvr.bztiot.controller;

import edu.cvr.bztiot.model.DeviceStatus;
import edu.cvr.bztiot.model.SecurityEvent;
import edu.cvr.bztiot.repository.DeviceRepository;
import edu.cvr.bztiot.repository.SecurityEventRepository;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

/**
 * Provides aggregated data for the React dashboard.
 *
 * All queries hit existing repository methods — no raw SQL needed.
 */
@RestController
@RequestMapping("/api/dashboard")
public class DashboardController {

    private final DeviceRepository deviceRepository;
    private final SecurityEventRepository eventRepository;

    public DashboardController(DeviceRepository deviceRepository,
                               SecurityEventRepository eventRepository) {
        this.deviceRepository = deviceRepository;
        this.eventRepository  = eventRepository;
    }

    /**
     * GET /api/dashboard/stats
     *
     * Returns the four top-of-page stat cards:
     *   totalDevices   – count of all registered devices
     *   activeDevices  – count of ACTIVE status devices
     *   highRisk       – devices with trust score < 60 (RESTRICT zone or below)
     *   quarantined    – count of QUARANTINED status devices
     *
     * Also returns the risk distribution buckets (Low / Medium / High / Critical)
     * based on trust score ranges:
     *   Low      ≥ 80
     *   Medium   60–79
     *   High     40–59
     *   Critical < 40
     */
    @GetMapping("/stats")
    public ResponseEntity<Map<String, Object>> stats() {

        long total       = deviceRepository.count();
        long active      = deviceRepository.countByStatus(DeviceStatus.ACTIVE);
        long quarantined = deviceRepository.countByStatus(DeviceStatus.QUARANTINED);
        long revoked     = deviceRepository.countByStatus(DeviceStatus.REVOKED);

        // Risk distribution by trust score
        long low      = deviceRepository.countByTrustScoreGreaterThan(79);           // ≥ 80
        long medium   = deviceRepository.countByTrustScoreLessThanEqual(79)
                      - deviceRepository.countByTrustScoreLessThanEqual(59);        // 60–79
        long high     = deviceRepository.countByTrustScoreLessThanEqual(59)
                      - deviceRepository.countByTrustScoreLessThanEqual(39);        // 40–59
        long critical = deviceRepository.countByTrustScoreLessThanEqual(39);        // < 40

        Map<String, Object> body = Map.of(
            "totalDevices",   total,
            "activeDevices",  active,
            "highRisk",       high + critical,
            "quarantined",    quarantined,
            "revoked",        revoked,
            "riskDistribution", Map.of(
                "low",      low,
                "medium",   medium,
                "high",     high,
                "critical", critical
            )
        );

        return ResponseEntity.ok(body);
    }

    /**
     * GET /api/dashboard/events
     *
     * Returns the 20 most recent security events across all devices.
     * Used by the Security Activity card on the dashboard.
     */
    @GetMapping("/events")
    public ResponseEntity<List<SecurityEvent>> recentEvents() {
        return ResponseEntity.ok(eventRepository.findTop20ByOrderByCreatedAtDesc());
    }
}

