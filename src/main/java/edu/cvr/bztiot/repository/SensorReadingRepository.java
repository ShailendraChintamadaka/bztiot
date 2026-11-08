package edu.cvr.bztiot.repository;

import edu.cvr.bztiot.model.Device;
import edu.cvr.bztiot.model.SensorReading;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

@Repository
public interface SensorReadingRepository extends JpaRepository<SensorReading, Long> {

    /** Most recent 50 readings for a specific device, newest first. */
    List<SensorReading> findTop50ByDeviceOrderByReceivedAtDesc(Device device);

    /** Count of readings from a device since a given time — used by rate-limit monitor. */
    long countByDeviceAndReceivedAtAfter(Device device, Instant since);
}