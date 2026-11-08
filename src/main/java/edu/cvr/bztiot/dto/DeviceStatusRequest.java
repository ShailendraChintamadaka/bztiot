package edu.cvr.bztiot.dto;

import edu.cvr.bztiot.model.DeviceStatus;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
public class DeviceStatusRequest {

    private DeviceStatus status;
}