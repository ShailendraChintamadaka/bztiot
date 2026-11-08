package edu.cvr.bztiot.repository;

import edu.cvr.bztiot.model.SecurityEvent;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

@Repository
public interface SecurityEventRepository extends JpaRepository<SecurityEvent, UUID> {

    /** All events for one device, newest first. Used on the device detail page. */
    List<SecurityEvent> findByDeviceCodeOrderByCreatedAtDesc(String deviceCode);

    /** Most recent 20 events across all devices. Used on the dashboard. */
    List<SecurityEvent> findTop20ByOrderByCreatedAtDesc();

    /** Events newer than a given timestamp. Used for live alert polling. */
    List<SecurityEvent> findByCreatedAtAfterOrderByCreatedAtDesc(Instant since);

    /** Filter by severity (e.g. "HIGH", "CRITICAL") for the alerts page. */
    List<SecurityEvent> findBySeverityOrderByCreatedAtDesc(String severity);

    /** Count of events for a device in a time window — used by behavior monitor. */
    long countByDeviceCodeAndCreatedAtAfter(String deviceCode, Instant since);
}