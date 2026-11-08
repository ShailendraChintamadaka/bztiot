package edu.cvr.bztiot.model;

import java.time.Instant;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
@Entity
@Table(name = "sensor_readings")
public class SensorReading {

    @Id
    @GeneratedValue
    @Column(name = "id")
    private Long id;

    @ManyToOne
    @JoinColumn(name = "device_id", referencedColumnName = "id", nullable = false)
    private Device device;

    @Column(name = "metric_type", nullable = false)
    private String metricType;      

    @Column(name = "metric_value", nullable = false)
    private Double metricValue;

    @Column(name = "reported_firmware_hash")
    private String reportedFirmwareHash;

    @Column(name = "device_timestamp")
    private Instant deviceTimestamp;

    @Column(name = "received_at", nullable = false, updatable = false)
    private Instant receivedAt;
}