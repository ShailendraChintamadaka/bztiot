package edu.cvr.bztiot.service;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import org.springframework.stereotype.Service;

import edu.cvr.bztiot.dto.DeviceRegistrationRequest;
import edu.cvr.bztiot.dto.DeviceStatusRequest;
import edu.cvr.bztiot.dto.DeviceUpdateRequest;
import edu.cvr.bztiot.model.Device;
import edu.cvr.bztiot.model.DeviceStatus;
import edu.cvr.bztiot.repository.DeviceRepository;

@Service
public class DeviceService {

    private final DeviceRepository deviceRepository;

    public DeviceService(DeviceRepository deviceRepository) {
        this.deviceRepository = deviceRepository;
    }

    // ---------------------------------------------------------
    // Register a new device
    // ---------------------------------------------------------
    public Device registerDevice(DeviceRegistrationRequest request) {

        // Check whether device code already exists
        if (deviceRepository.findByDeviceCode(request.getDeviceCode()).isPresent()) {
            throw new IllegalArgumentException(
                    "Device code already exists: " + request.getDeviceCode()
            );
        }

        Device device = new Device();

        device.setDeviceCode(request.getDeviceCode());
        device.setPublicKey(request.getPublicKey());
        device.setExpectedFirmwareHash(request.getExpectedFirmwareHash());
        device.setDeviceType(request.getDeviceType());

        // Initial security state:
        // ACTIVE — the device is registered but not yet authenticated.
        // Trust score starts at 50 (neutral/unknown).
        // A score of 0 would mean "completely malicious", which is wrong for a fresh device.
        // Authentication success will drive the score toward 80+.
        device.setStatus(DeviceStatus.ACTIVE);
        device.setTrustScore(50);
        device.setAuthFailureCount(0);

        device.setRegisteredAt(Instant.now());
        device.setLastSeenAt(null);
        device.setLastAuthAt(null);

        return deviceRepository.save(device);
    }

    // ---------------------------------------------------------
    // Get all devices
    // ---------------------------------------------------------
    public List<Device> getAllDevices() {
        return deviceRepository.findAll();
    }

    // ---------------------------------------------------------
    // Get device by UUID
    // ---------------------------------------------------------
    public Optional<Device> getDeviceById(UUID deviceId) {
        return deviceRepository.findById(deviceId);
    }

    // ---------------------------------------------------------
    // Get device by device code
    // ---------------------------------------------------------
    public Optional<Device> getDeviceByCode(String deviceCode) {
        return deviceRepository.findByDeviceCode(deviceCode);
    }

    // ---------------------------------------------------------
    // Get devices by type
    // ---------------------------------------------------------
    public List<Device> getDevicesByType(String deviceType) {
        return deviceRepository.findByDeviceType(deviceType);
    }

    // ---------------------------------------------------------
    // Update device information
    // ---------------------------------------------------------
    public Optional<Device> updateDevice(
            UUID deviceId,
            DeviceUpdateRequest request) {

        return deviceRepository.findById(deviceId)
                .map(device -> {

                    device.setDeviceCode(request.getDeviceCode());
                    device.setPublicKey(request.getPublicKey());
                    device.setExpectedFirmwareHash(
                            request.getExpectedFirmwareHash()
                    );
                    device.setDeviceType(request.getDeviceType());

                    return deviceRepository.save(device);
                });
    }

    // ---------------------------------------------------------
    // Update device status
    // ---------------------------------------------------------
    public Optional<Device> updateDeviceStatus(
            UUID deviceId,
            DeviceStatusRequest request) {

        return deviceRepository.findById(deviceId)
                .map(device -> {

                    device.setStatus(request.getStatus());

                    return deviceRepository.save(device);
                });
    }

    // ---------------------------------------------------------
    // Delete device
    // ---------------------------------------------------------
    public boolean deleteDevice(UUID deviceId) {

        if (!deviceRepository.existsById(deviceId)) {
            return false;
        }

        deviceRepository.deleteById(deviceId);

        return true;
    }
}