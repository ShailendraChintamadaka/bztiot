package edu.cvr.bztiot.repository;

import edu.cvr.bztiot.model.Device;
import edu.cvr.bztiot.model.DeviceStatus;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface DeviceRepository extends JpaRepository<Device, UUID> {

    List<Device> findByDeviceType(String deviceType);

    Optional<Device> findByDeviceCode(String deviceCode);

    /** Count devices by status — used by the dashboard summary API. */
    long countByStatus(DeviceStatus status);

    /** All devices in a given status — used for enforcement and monitoring. */
    List<Device> findByStatus(DeviceStatus status);

    /** Devices with a trust score at or below a threshold — used for risk distribution. */
    long countByTrustScoreLessThanEqual(int maxScore);

    /** Devices with a trust score above a threshold. */
    long countByTrustScoreGreaterThan(int minScore);
}
