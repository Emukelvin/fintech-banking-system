package com.fintech.identity.controller;

import com.fintech.identity.dto.*;
import com.fintech.identity.service.AuthenticationService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private static final Logger logger = LoggerFactory.getLogger(AuthController.class);

    private final AuthenticationService authenticationService;

    public AuthController(AuthenticationService authenticationService) {
        this.authenticationService = authenticationService;
    }

    /**
     * POST /auth/register
     * Registers a new user and binds their device.
     */
    @PostMapping("/register")
    public ResponseEntity<ApiResponse<RegisterResponse>> register(
            @Valid @RequestBody RegisterRequest request,
            HttpServletRequest httpRequest) {

        logger.info("Registration request received for email: {}", request.getEmail());

        String ipAddress = getClientIpAddress(httpRequest);
        RegisterResponse response = authenticationService.register(request, ipAddress);

        return ResponseEntity.status(HttpStatus.CREATED)
                .body(ApiResponse.success(response, "Registration successful"));
    }

    /**
     * POST /auth/login
     * Authenticates the user with their credentials.
     */
    @PostMapping("/login")
    public ResponseEntity<ApiResponse<LoginResponse>> login(
            @Valid @RequestBody LoginRequest request,
            HttpServletRequest httpRequest) {

        logger.info("Login request received for email: {}", request.getEmail());

        String ipAddress = getClientIpAddress(httpRequest);
        String userAgent = httpRequest.getHeader("User-Agent");

        LoginResponse response = authenticationService.login(request, ipAddress, userAgent);

        if (response.isMfaRequired()) {
            return ResponseEntity.ok(ApiResponse.success(response, "MFA verification required"));
        }

        return ResponseEntity.ok(ApiResponse.success(response, "Login successful"));
    }

    /**
     * POST /auth/verify-otp
     * Handles OTP verification for registration, login, and other purposes.
     */
    @PostMapping("/verify-otp")
    public ResponseEntity<ApiResponse<VerifyOtpResponse>> verifyOtp(
            @Valid @RequestBody VerifyOtpRequest request,
            HttpServletRequest httpRequest) {

        logger.info("OTP verification request received for email: {}", request.getEmail());

        String ipAddress = getClientIpAddress(httpRequest);
        String userAgent = httpRequest.getHeader("User-Agent");

        VerifyOtpResponse response = authenticationService.verifyOtp(request, ipAddress, userAgent);

        return ResponseEntity.ok(ApiResponse.success(response, "OTP verified successfully"));
    }

    /**
     * POST /auth/refresh-token
     * Issues a new access token using a refresh token.
     */
    @PostMapping("/refresh-token")
    public ResponseEntity<ApiResponse<RefreshTokenResponse>> refreshToken(
            @Valid @RequestBody RefreshTokenRequest request,
            HttpServletRequest httpRequest) {

        logger.debug("Token refresh request received");

        String ipAddress = getClientIpAddress(httpRequest);
        String userAgent = httpRequest.getHeader("User-Agent");

        RefreshTokenResponse response = authenticationService.refreshToken(request, ipAddress, userAgent);

        return ResponseEntity.ok(ApiResponse.success(response, "Token refreshed successfully"));
    }

    /**
     * Extracts the client IP address from the request.
     * Handles cases where the application is behind a proxy.
     */
    private String getClientIpAddress(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            return xForwardedFor.split(",")[0].trim();
        }
        String xRealIp = request.getHeader("X-Real-IP");
        if (xRealIp != null && !xRealIp.isEmpty()) {
            return xRealIp;
        }
        return request.getRemoteAddr();
    }
}
