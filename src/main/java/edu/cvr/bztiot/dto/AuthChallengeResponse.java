package edu.cvr.bztiot.dto;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
public class AuthChallengeResponse {
    private String challenge;
}