package com.fintech.identity.service;

import com.fintech.identity.dto.DeviceInfo;
import com.fintech.identity.dto.LoginRequest;
import com.fintech.identity.dto.LoginResponse;
import com.fintech.identity.dto.RegisterRequest;
import com.fintech.identity.dto.RegisterResponse;
import com.fintech.identity.entity.User;
import com.fintech.identity.entity.User.UserStatus;
import com.fintech.identity.exception.AuthenticationException;
import com.fintech.identity.exception.RegistrationException;
import com.fintech.identity.kafka.producer.UserEventProducer;
import com.fintech.identity.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthenticationServiceTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private JwtTokenService jwtTokenService;

    @Mock
    private OtpService otpService;

    @Mock
    private DeviceService deviceService;

    @Mock
    private SessionService sessionService;

    @Mock
    private FraudDetectionService fraudDetectionService;

    @Mock
    private UserEventProducer userEventProducer;

    private AuthenticationService authenticationService;
    private PasswordEncoder passwordEncoder;

    @BeforeEach
    void setUp() {
        passwordEncoder = new BCryptPasswordEncoder(12);
        authenticationService = new AuthenticationService(
                userRepository,
                passwordEncoder,
                jwtTokenService,
                otpService,
                deviceService,
                sessionService,
                fraudDetectionService,
                userEventProducer
        );
    }

    @Test
    void register_Success() {
        // Given
        RegisterRequest request = RegisterRequest.builder()
                .firstName("John")
                .lastName("Doe")
                .email("john.doe@example.com")
                .phoneNumber("+1234567890")
                .password("Password@123")
                .build();

        when(userRepository.existsByEmail(anyString())).thenReturn(false);
        when(userRepository.existsByPhoneNumber(anyString())).thenReturn(false);
        when(userRepository.save(any(User.class))).thenAnswer(invocation -> {
            User user = invocation.getArgument(0);
            user.setId(UUID.randomUUID());
            return user;
        });
        when(otpService.generateOtp(anyString(), anyString(), any())).thenReturn("123456");

        // When
        RegisterResponse response = authenticationService.register(request, "127.0.0.1");

        // Then
        assertNotNull(response);
        assertEquals("john.doe@example.com", response.getEmail());
        assertEquals("John", response.getFirstName());
        assertEquals("Doe", response.getLastName());
        assertTrue(response.isOtpRequired());
        assertEquals("PENDING_VERIFICATION", response.getStatus());

        verify(userRepository).save(any(User.class));
        verify(otpService).generateOtp(anyString(), anyString(), any());
        verify(userEventProducer).sendUserRegisteredEvent(any(User.class));
    }

    @Test
    void register_DuplicateEmail_ThrowsException() {
        // Given
        RegisterRequest request = RegisterRequest.builder()
                .firstName("John")
                .lastName("Doe")
                .email("existing@example.com")
                .password("Password@123")
                .build();

        when(userRepository.existsByEmail("existing@example.com")).thenReturn(true);

        // When & Then
        RegistrationException exception = assertThrows(
                RegistrationException.class,
                () -> authenticationService.register(request, "127.0.0.1")
        );

        assertEquals("Email is already registered", exception.getMessage());
        verify(userRepository, never()).save(any(User.class));
    }

    @Test
    void login_Success() {
        // Given
        String email = "john.doe@example.com";
        String password = "Password@123";
        String encodedPassword = passwordEncoder.encode(password);

        User user = User.builder()
                .id(UUID.randomUUID())
                .email(email)
                .passwordHash(encodedPassword)
                .firstName("John")
                .lastName("Doe")
                .status(UserStatus.ACTIVE)
                .mfaEnabled(false)
                .failedLoginAttempts(0)
                .build();

        LoginRequest request = LoginRequest.builder()
                .email(email)
                .password(password)
                .build();

        FraudDetectionService.FraudCheckResult fraudCheckResult = new FraudDetectionService.FraudCheckResult();
        fraudCheckResult.setBlocked(false);

        when(fraudDetectionService.performFraudCheck(anyString(), anyString(), any())).thenReturn(fraudCheckResult);
        when(userRepository.findByEmail(email)).thenReturn(Optional.of(user));
        when(userRepository.save(any(User.class))).thenReturn(user);
        when(jwtTokenService.generateAccessToken(any(UUID.class), anyString(), any())).thenReturn("access-token");
        when(jwtTokenService.generateRefreshToken(any(UUID.class), anyString())).thenReturn("refresh-token");
        when(jwtTokenService.getAccessTokenExpiration()).thenReturn(900000L);
        when(jwtTokenService.getRefreshTokenExpiration()).thenReturn(604800000L);

        // When
        LoginResponse response = authenticationService.login(request, "127.0.0.1", "Mozilla/5.0");

        // Then
        assertNotNull(response);
        assertEquals(email, response.getEmail());
        assertEquals("John", response.getFirstName());
        assertEquals("access-token", response.getAccessToken());
        assertEquals("refresh-token", response.getRefreshToken());
        assertFalse(response.isMfaRequired());

        verify(sessionService).createSession(any(), any(), anyString(), anyString(), anyString());
        verify(fraudDetectionService).recordLoginAttempt(any(), anyString(), anyString(), anyString(), any(), eq(true), any());
    }

    @Test
    void login_InvalidPassword_ThrowsException() {
        // Given
        String email = "john.doe@example.com";
        String correctPassword = "Password@123";
        String wrongPassword = "WrongPassword@123";
        String encodedPassword = passwordEncoder.encode(correctPassword);

        User user = User.builder()
                .id(UUID.randomUUID())
                .email(email)
                .passwordHash(encodedPassword)
                .firstName("John")
                .lastName("Doe")
                .status(UserStatus.ACTIVE)
                .mfaEnabled(false)
                .failedLoginAttempts(0)
                .build();

        LoginRequest request = LoginRequest.builder()
                .email(email)
                .password(wrongPassword)
                .build();

        FraudDetectionService.FraudCheckResult fraudCheckResult = new FraudDetectionService.FraudCheckResult();
        fraudCheckResult.setBlocked(false);

        when(fraudDetectionService.performFraudCheck(anyString(), anyString(), any())).thenReturn(fraudCheckResult);
        when(userRepository.findByEmail(email)).thenReturn(Optional.of(user));
        when(userRepository.save(any(User.class))).thenReturn(user);

        // When & Then
        AuthenticationException exception = assertThrows(
                AuthenticationException.class,
                () -> authenticationService.login(request, "127.0.0.1", "Mozilla/5.0")
        );

        assertEquals("Invalid email or password", exception.getMessage());
        verify(fraudDetectionService).recordLoginAttempt(any(), anyString(), anyString(), anyString(), any(), eq(false), anyString());
    }

    @Test
    void login_AccountLocked_ThrowsException() {
        // Given
        String email = "locked@example.com";
        String password = "Password@123";

        User user = User.builder()
                .id(UUID.randomUUID())
                .email(email)
                .passwordHash(passwordEncoder.encode(password))
                .firstName("John")
                .lastName("Doe")
                .status(UserStatus.LOCKED)
                .failedLoginAttempts(5)
                .lockedUntil(java.time.LocalDateTime.now().plusMinutes(30))
                .build();

        LoginRequest request = LoginRequest.builder()
                .email(email)
                .password(password)
                .build();

        FraudDetectionService.FraudCheckResult fraudCheckResult = new FraudDetectionService.FraudCheckResult();
        fraudCheckResult.setBlocked(false);

        when(fraudDetectionService.performFraudCheck(anyString(), anyString(), any())).thenReturn(fraudCheckResult);
        when(userRepository.findByEmail(email)).thenReturn(Optional.of(user));

        // When & Then
        AuthenticationException exception = assertThrows(
                AuthenticationException.class,
                () -> authenticationService.login(request, "127.0.0.1", "Mozilla/5.0")
        );

        assertTrue(exception.getMessage().contains("locked"));
    }

    @Test
    void login_MfaRequired() {
        // Given
        String email = "mfa@example.com";
        String password = "Password@123";

        User user = User.builder()
                .id(UUID.randomUUID())
                .email(email)
                .passwordHash(passwordEncoder.encode(password))
                .firstName("John")
                .lastName("Doe")
                .status(UserStatus.ACTIVE)
                .mfaEnabled(true)
                .failedLoginAttempts(0)
                .build();

        LoginRequest request = LoginRequest.builder()
                .email(email)
                .password(password)
                .build();

        FraudDetectionService.FraudCheckResult fraudCheckResult = new FraudDetectionService.FraudCheckResult();
        fraudCheckResult.setBlocked(false);

        when(fraudDetectionService.performFraudCheck(anyString(), anyString(), any())).thenReturn(fraudCheckResult);
        when(userRepository.findByEmail(email)).thenReturn(Optional.of(user));
        when(otpService.generateOtp(anyString(), any(), any())).thenReturn("123456");

        // When
        LoginResponse response = authenticationService.login(request, "127.0.0.1", "Mozilla/5.0");

        // Then
        assertNotNull(response);
        assertTrue(response.isMfaRequired());
        assertEquals("OTP", response.getMfaType());
        assertNull(response.getAccessToken());
        assertNull(response.getRefreshToken());
    }
}
