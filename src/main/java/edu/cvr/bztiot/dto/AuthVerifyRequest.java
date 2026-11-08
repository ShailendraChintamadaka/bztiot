package edu.cvr.bztiot.dto;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
public class AuthVerifyRequest {
    private String deviceCode;
    private String signature; // base64-encoded
}