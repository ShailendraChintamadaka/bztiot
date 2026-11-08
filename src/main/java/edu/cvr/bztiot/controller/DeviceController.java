package edu.cvr.bztiot.controller;

import java.util.List;
import java.util.UUID;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import edu.cvr.bztiot.dto.DeviceRegistrationRequest;
import edu.cvr.bztiot.dto.DeviceStatusRequest;
import edu.cvr.bztiot.dto.DeviceUpdateRequest;
import edu.cvr.bztiot.model.Device;
import edu.cvr.bztiot.service.DeviceService;

@RestController
@RequestMapping("/api/devices")
public class DeviceController {

    private final DeviceService deviceService;

    public DeviceController(DeviceService deviceService) {
        this.deviceService = deviceService;
    }

    // =========================================================
    // DEVICE REGISTRATION
    // =========================================================

    // Register one IoT device through the admin registration form
    //
    // Future:
    // CSV bulk device registration will be added separately.
    // Do NOT implement CSV processing yet.

    @PostMapping
    public ResponseEntity<Device> registerDevice(
            @RequestBody DeviceRegistrationRequest request) {

        try {

            Device device = deviceService.registerDevice(request);

            return ResponseEntity
                    .status(HttpStatus.CREATED)
                    .body(device);

        } catch (IllegalArgumentException exception) {

            return ResponseEntity
                    .status(HttpStatus.CONFLICT)
                    .build();
        }
    }

    // =========================================================
    // GET ALL DEVICES
    // =========================================================

    @GetMapping
    public ResponseEntity<List<Device>> getAllDevices() {

        return ResponseEntity.ok(
                deviceService.getAllDevices()
        );
    }

    // =========================================================
    // GET DEVICE BY UUID
    // =========================================================

    @GetMapping("/{deviceId}")
    public ResponseEntity<Device> getDeviceById(
            @PathVariable UUID deviceId) {

        return deviceService.getDeviceById(deviceId)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    // =========================================================
    // GET DEVICE BY DEVICE CODE
    // =========================================================

    @GetMapping("/code/{deviceCode}")
    public ResponseEntity<Device> getDeviceByCode(
            @PathVariable String deviceCode) {

        return deviceService.getDeviceByCode(deviceCode)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    // =========================================================
    // GET DEVICES BY TYPE
    // =========================================================

    @GetMapping("/type/{deviceType}")
    public ResponseEntity<List<Device>> getDevicesByType(
            @PathVariable String deviceType) {

        return ResponseEntity.ok(
                deviceService.getDevicesByType(deviceType)
        );
    }

    // =========================================================
    // UPDATE DEVICE
    // =========================================================

    @PutMapping("/{deviceId}")
    public ResponseEntity<Device> updateDevice(
            @PathVariable UUID deviceId,
            @RequestBody DeviceUpdateRequest request) {

        return deviceService
                .updateDevice(deviceId, request)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    // =========================================================
    // UPDATE DEVICE STATUS
    // =========================================================

    @PatchMapping("/{deviceId}/status")
    public ResponseEntity<Device> updateDeviceStatus(
            @PathVariable UUID deviceId,
            @RequestBody DeviceStatusRequest request) {

        return deviceService
                .updateDeviceStatus(deviceId, request)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    // =========================================================
    // DELETE DEVICE
    // =========================================================

    @DeleteMapping("/{deviceId}")
    public ResponseEntity<Void> deleteDevice(
            @PathVariable UUID deviceId) {

        boolean deleted = deviceService.deleteDevice(deviceId);

        if (!deleted) {
            return ResponseEntity.notFound().build();
        }

        return ResponseEntity.noContent().build();
    }
}