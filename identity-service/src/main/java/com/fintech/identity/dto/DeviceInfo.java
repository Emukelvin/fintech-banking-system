package com.fintech.identity.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class DeviceInfo {
    private String deviceId;
    private String deviceName;
    private String deviceType;
    private String osName;
    private String osVersion;
    private String appVersion;
    private String fingerprint;
    private String pushToken;
}
