package com.fintech.identity.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class VerifyOtpRequest {

    @Email(message = "Email must be valid")
    private String email;

    private String phoneNumber;

    @NotBlank(message = "OTP code is required")
    @Size(min = 4, max = 10, message = "OTP code must be between 4 and 10 characters")
    private String otpCode;

    @NotBlank(message = "Purpose is required")
    private String purpose;

    // Device information
    private DeviceInfo deviceInfo;
}
