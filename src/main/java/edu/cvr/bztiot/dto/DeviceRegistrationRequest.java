package edu.cvr.bztiot.dto;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
public class DeviceRegistrationRequest {

    private String deviceCode;

    private String publicKey;

    private String expectedFirmwareHash;

    private String deviceType;
}