package com.fintech.identity.service;

import com.fintech.identity.dto.*;
import com.fintech.identity.entity.*;
import com.fintech.identity.entity.OtpVerification.OtpPurpose;
import com.fintech.identity.entity.User.UserStatus;
import com.fintech.identity.exception.AuthenticationException;
import com.fintech.identity.exception.RegistrationException;
import com.fintech.identity.exception.TokenException;
import com.fintech.identity.kafka.event.UserEvent;
import com.fintech.identity.kafka.producer.UserEventProducer;
import com.fintech.identity.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

@Service
public class AuthenticationService {

    private static final Logger logger = LoggerFactory.getLogger(AuthenticationService.class);
    private static final int MAX_FAILED_ATTEMPTS = 5;
    private static final int LOCK_DURATION_MINUTES = 30;

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenService jwtTokenService;
    private final OtpService otpService;
    private final DeviceService deviceService;
    private final SessionService sessionService;
    private final FraudDetectionService fraudDetectionService;
    private final UserEventProducer userEventProducer;

    public AuthenticationService(
            UserRepository userRepository,
            PasswordEncoder passwordEncoder,
            JwtTokenService jwtTokenService,
            OtpService otpService,
            DeviceService deviceService,
            SessionService sessionService,
            FraudDetectionService fraudDetectionService,
            UserEventProducer userEventProducer) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtTokenService = jwtTokenService;
        this.otpService = otpService;
        this.deviceService = deviceService;
        this.sessionService = sessionService;
        this.fraudDetectionService = fraudDetectionService;
        this.userEventProducer = userEventProducer;
    }

    @Transactional
    public RegisterResponse register(RegisterRequest request, String ipAddress) {
        // Check if user already exists
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new RegistrationException("Email is already registered", HttpStatus.CONFLICT);
        }

        if (request.getPhoneNumber() != null && userRepository.existsByPhoneNumber(request.getPhoneNumber())) {
            throw new RegistrationException("Phone number is already registered", HttpStatus.CONFLICT);
        }

        // Create new user
        User user = User.builder()
                .email(request.getEmail())
                .phoneNumber(request.getPhoneNumber())
                .passwordHash(passwordEncoder.encode(request.getPassword()))
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .status(UserStatus.PENDING_VERIFICATION)
                .build();

        User savedUser = userRepository.save(user);
        logger.info("User registered: {}", savedUser.getEmail());

        // Register device if provided
        if (request.getDeviceInfo() != null) {
            deviceService.registerDevice(savedUser, request.getDeviceInfo(), ipAddress);
        }

        // Generate OTP for email verification
        otpService.generateOtp(savedUser.getEmail(), savedUser.getPhoneNumber(), OtpPurpose.REGISTRATION);
        logger.debug("OTP generated for user registration verification");

        // Publish user registration event
        userEventProducer.sendUserRegisteredEvent(savedUser);

        return RegisterResponse.builder()
                .userId(savedUser.getId())
                .email(savedUser.getEmail())
                .firstName(savedUser.getFirstName())
                .lastName(savedUser.getLastName())
                .status(savedUser.getStatus().name())
                .message("Registration successful. Please verify your email with the OTP sent.")
                .otpRequired(true)
                .build();
    }

    @Transactional
    public LoginResponse login(LoginRequest request, String ipAddress, String userAgent) {
        String email = request.getEmail();

        // Fraud detection check
        FraudDetectionService.FraudCheckResult fraudCheck = fraudDetectionService.performFraudCheck(
                email, ipAddress, request.getDeviceInfo() != null ? request.getDeviceInfo().getFingerprint() : null);

        if (fraudCheck.isBlocked()) {
            fraudDetectionService.recordLoginAttempt(null, email, ipAddress, userAgent, null, false, fraudCheck.getReason());
            throw new AuthenticationException(fraudCheck.getReason(), HttpStatus.TOO_MANY_REQUESTS);
        }

        // Find user
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> {
                    fraudDetectionService.recordLoginAttempt(null, email, ipAddress, userAgent, null, false, "User not found");
                    return new AuthenticationException("Invalid email or password");
                });

        // Check if account is locked
        if (user.isAccountLocked()) {
            fraudDetectionService.recordLoginAttempt(user, email, ipAddress, userAgent, null, false, "Account locked");
            throw new AuthenticationException("Account is temporarily locked. Please try again later.", HttpStatus.FORBIDDEN);
        }

        // Check if account is active
        if (user.getStatus() == UserStatus.SUSPENDED || user.getStatus() == UserStatus.DEACTIVATED) {
            fraudDetectionService.recordLoginAttempt(user, email, ipAddress, userAgent, null, false, "Account not active");
            throw new AuthenticationException("Account is not active. Please contact support.", HttpStatus.FORBIDDEN);
        }

        // Verify password
        if (!passwordEncoder.matches(request.getPassword(), user.getPasswordHash())) {
            handleFailedLogin(user, email, ipAddress, userAgent);
            throw new AuthenticationException("Invalid email or password");
        }

        // Check if MFA is required
        if (user.getMfaEnabled()) {
            otpService.generateOtp(email, null, OtpPurpose.LOGIN);
            logger.debug("MFA OTP generated for user: {}", email);

            return LoginResponse.builder()
                    .userId(user.getId())
                    .email(user.getEmail())
                    .firstName(user.getFirstName())
                    .lastName(user.getLastName())
                    .mfaRequired(true)
                    .mfaType("OTP")
                    .message("MFA verification required")
                    .build();
        }

        // Check if email verification is pending
        if (user.getStatus() == UserStatus.PENDING_VERIFICATION) {
            otpService.generateOtp(email, null, OtpPurpose.REGISTRATION);
            logger.debug("Verification OTP regenerated for user: {}", email);

            return LoginResponse.builder()
                    .userId(user.getId())
                    .email(user.getEmail())
                    .firstName(user.getFirstName())
                    .lastName(user.getLastName())
                    .mfaRequired(true)
                    .mfaType("EMAIL_VERIFICATION")
                    .message("Please verify your email first")
                    .build();
        }

        // Successful login - generate tokens
        return completeLogin(user, request.getDeviceInfo(), ipAddress, userAgent);
    }

    @Transactional
    public VerifyOtpResponse verifyOtp(VerifyOtpRequest request, String ipAddress, String userAgent) {
        OtpPurpose purpose = OtpPurpose.valueOf(request.getPurpose().toUpperCase());

        // Verify OTP
        otpService.verifyOtp(request.getEmail(), request.getPhoneNumber(), request.getOtpCode(), purpose);

        // Find user
        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new AuthenticationException("User not found"));

        // Handle based on purpose
        if (purpose == OtpPurpose.REGISTRATION) {
            user.setStatus(UserStatus.ACTIVE);
            userRepository.save(user);
            logger.info("User email verified: {}", user.getEmail());

            // Publish email verification event
            userEventProducer.sendUserVerifiedEvent(user);
        }

        // Generate tokens for successful verification
        Device device = null;
        if (request.getDeviceInfo() != null) {
            device = deviceService.validateAndUpdateDevice(user, request.getDeviceInfo(), ipAddress);
            if (device != null && purpose == OtpPurpose.DEVICE_VERIFICATION) {
                deviceService.markDeviceAsTrusted(user.getId(), device.getDeviceId());
            }
        }

        String accessToken = jwtTokenService.generateAccessToken(user.getId(), user.getEmail(), buildUserClaims(user));
        String refreshToken = jwtTokenService.generateRefreshToken(user.getId(), user.getEmail());

        sessionService.createSession(user, device, refreshToken, ipAddress, userAgent);

        // Update last login
        user.setLastLoginAt(LocalDateTime.now());
        user.resetFailedLoginAttempts();
        userRepository.save(user);

        // Record successful login
        fraudDetectionService.recordLoginAttempt(user, user.getEmail(), ipAddress, userAgent, null, true, null);

        return VerifyOtpResponse.builder()
                .verified(true)
                .message("OTP verified successfully")
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .accessTokenExpiresIn(jwtTokenService.getAccessTokenExpiration())
                .refreshTokenExpiresIn(jwtTokenService.getRefreshTokenExpiration())
                .build();
    }

    @Transactional
    public RefreshTokenResponse refreshToken(RefreshTokenRequest request, String ipAddress, String userAgent) {
        // Validate the refresh token
        Session session = sessionService.validateAndRefreshSession(request.getRefreshToken());
        User user = session.getUser();

        // Verify JWT signature is still valid
        if (!jwtTokenService.isTokenValid(request.getRefreshToken())) {
            throw new TokenException("Invalid refresh token");
        }

        // Generate new tokens
        String newAccessToken = jwtTokenService.generateAccessToken(user.getId(), user.getEmail(), buildUserClaims(user));
        String newRefreshToken = jwtTokenService.generateRefreshToken(user.getId(), user.getEmail());

        // Revoke old session and create new one
        sessionService.revokeSession(request.getRefreshToken(), "Token refreshed");

        Device device = session.getDevice();
        if (request.getDeviceInfo() != null && device != null) {
            device = deviceService.validateAndUpdateDevice(user, request.getDeviceInfo(), ipAddress);
        }

        sessionService.createSession(user, device, newRefreshToken, ipAddress, userAgent);

        logger.info("Token refreshed for user: {}", user.getEmail());

        return RefreshTokenResponse.builder()
                .accessToken(newAccessToken)
                .refreshToken(newRefreshToken)
                .accessTokenExpiresIn(jwtTokenService.getAccessTokenExpiration())
                .refreshTokenExpiresIn(jwtTokenService.getRefreshTokenExpiration())
                .message("Token refreshed successfully")
                .build();
    }

    private LoginResponse completeLogin(User user, DeviceInfo deviceInfo, String ipAddress, String userAgent) {
        // Reset failed attempts on successful login
        user.resetFailedLoginAttempts();
        user.setLastLoginAt(LocalDateTime.now());
        userRepository.save(user);

        // Register/update device
        Device device = null;
        if (deviceInfo != null) {
            device = deviceService.validateAndUpdateDevice(user, deviceInfo, ipAddress);
        }

        // Generate tokens
        String accessToken = jwtTokenService.generateAccessToken(user.getId(), user.getEmail(), buildUserClaims(user));
        String refreshToken = jwtTokenService.generateRefreshToken(user.getId(), user.getEmail());

        // Create session
        sessionService.createSession(user, device, refreshToken, ipAddress, userAgent);

        // Record successful login
        fraudDetectionService.recordLoginAttempt(user, user.getEmail(), ipAddress, userAgent,
                deviceInfo != null ? deviceInfo.getFingerprint() : null, true, null);

        // Publish login event
        userEventProducer.sendUserLoggedInEvent(user, ipAddress, deviceInfo);

        logger.info("User logged in successfully: {}", user.getEmail());

        return LoginResponse.builder()
                .userId(user.getId())
                .email(user.getEmail())
                .firstName(user.getFirstName())
                .lastName(user.getLastName())
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .accessTokenExpiresIn(jwtTokenService.getAccessTokenExpiration())
                .refreshTokenExpiresIn(jwtTokenService.getRefreshTokenExpiration())
                .mfaRequired(false)
                .message("Login successful")
                .build();
    }

    private void handleFailedLogin(User user, String email, String ipAddress, String userAgent) {
        user.incrementFailedLoginAttempts();

        if (user.getFailedLoginAttempts() >= MAX_FAILED_ATTEMPTS) {
            user.setLockedUntil(LocalDateTime.now().plusMinutes(LOCK_DURATION_MINUTES));
            user.setStatus(UserStatus.LOCKED);
            logger.warn("Account locked due to too many failed attempts: {}", email);
        }

        userRepository.save(user);
        fraudDetectionService.recordLoginAttempt(user, email, ipAddress, userAgent, null, false, "Invalid password");
    }

    private Map<String, Object> buildUserClaims(User user) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("firstName", user.getFirstName());
        claims.put("lastName", user.getLastName());
        claims.put("status", user.getStatus().name());
        claims.put("kycStatus", user.getKycStatus().name());
        return claims;
    }
}
