package edu.cvr.bztiot.controller;

import edu.cvr.bztiot.model.SecurityEvent;
import edu.cvr.bztiot.model.TrustScoreHistory;
import edu.cvr.bztiot.model.AccessDecisionLog;
import edu.cvr.bztiot.repository.SecurityEventRepository;
import edu.cvr.bztiot.repository.TrustScoreHistoryRepository;
import edu.cvr.bztiot.repository.AccessDecisionLogRepository;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * REST endpoints for the Security Monitoring page and Device Detail page.
 *
 * GET /api/security/events               – recent 20 events (all devices)
 * GET /api/security/events/{deviceCode}  – all events for one device
 * GET /api/security/history/{deviceCode} – trust score timeline for one device
 * GET /api/security/decisions/{deviceCode} – access decision log for one device
 */
@RestController
@RequestMapping("/api/security")
public class SecurityController {

    private final SecurityEventRepository      eventRepository;
    private final TrustScoreHistoryRepository  historyRepository;
    private final AccessDecisionLogRepository  decisionRepository;

    public SecurityController(SecurityEventRepository eventRepository,
                              TrustScoreHistoryRepository historyRepository,
                              AccessDecisionLogRepository decisionRepository) {
        this.eventRepository   = eventRepository;
        this.historyRepository = historyRepository;
        this.decisionRepository = decisionRepository;
    }

    /** All security events, newest first (capped at 20). Used by dashboard + security page. */
    @GetMapping("/events")
    public ResponseEntity<List<SecurityEvent>> allEvents() {
        return ResponseEntity.ok(eventRepository.findTop20ByOrderByCreatedAtDesc());
    }

    /** Security events for a single device. Used on the device detail page. */
    @GetMapping("/events/{deviceCode}")
    public ResponseEntity<List<SecurityEvent>> deviceEvents(
            @PathVariable String deviceCode) {
        return ResponseEntity.ok(
            eventRepository.findByDeviceCodeOrderByCreatedAtDesc(deviceCode)
        );
    }

    /** Trust score history for a single device (most recent 50). */
    @GetMapping("/history/{deviceCode}")
    public ResponseEntity<List<TrustScoreHistory>> trustHistory(
            @PathVariable String deviceCode) {
        return ResponseEntity.ok(
            historyRepository.findTop50ByDeviceCodeOrderByRecordedAtDesc(deviceCode)
        );
    }

    /** Access decision log for a single device (most recent 50). */
    @GetMapping("/decisions/{deviceCode}")
    public ResponseEntity<List<AccessDecisionLog>> decisions(
            @PathVariable String deviceCode) {
        return ResponseEntity.ok(
            decisionRepository.findTop50ByDeviceCodeOrderByDecidedAtDesc(deviceCode)
        );
    }
}

