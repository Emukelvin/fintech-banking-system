package com.fintech.identity.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

class JwtTokenServiceTest {

    private JwtTokenService jwtTokenService;
    private static final String SECRET = "test-256-bit-secret-key-here-must-be-at-least-32-characters-long";
    private static final long ACCESS_TOKEN_EXPIRATION = 900000L; // 15 minutes
    private static final long REFRESH_TOKEN_EXPIRATION = 604800000L; // 7 days

    @BeforeEach
    void setUp() {
        jwtTokenService = new JwtTokenService(SECRET, ACCESS_TOKEN_EXPIRATION, REFRESH_TOKEN_EXPIRATION);
    }

    @Test
    void generateAccessToken_Success() {
        // Given
        UUID userId = UUID.randomUUID();
        String email = "test@example.com";
        Map<String, Object> claims = new HashMap<>();
        claims.put("firstName", "John");
        claims.put("lastName", "Doe");

        // When
        String token = jwtTokenService.generateAccessToken(userId, email, claims);

        // Then
        assertNotNull(token);
        assertEquals(3, token.split("\\.").length, "JWT should have 3 parts separated by dots");
    }

    @Test
    void generateRefreshToken_Success() {
        // Given
        UUID userId = UUID.randomUUID();
        String email = "test@example.com";

        // When
        String token = jwtTokenService.generateRefreshToken(userId, email);

        // Then
        assertNotNull(token);
        assertEquals(3, token.split("\\.").length, "JWT should have 3 parts separated by dots");
    }

    @Test
    void validateToken_ValidToken_Success() {
        // Given
        UUID userId = UUID.randomUUID();
        String email = "test@example.com";
        Map<String, Object> claims = new HashMap<>();
        String token = jwtTokenService.generateAccessToken(userId, email, claims);

        // When
        Claims parsedClaims = jwtTokenService.validateToken(token);

        // Then
        assertNotNull(parsedClaims);
        assertEquals(email, parsedClaims.getSubject());
        assertEquals(userId.toString(), parsedClaims.get("userId"));
        assertEquals("access", parsedClaims.get("type"));
    }

    @Test
    void validateToken_InvalidToken_ThrowsException() {
        // Given
        String invalidToken = "invalid.token.here";

        // When & Then
        assertThrows(Exception.class, () -> jwtTokenService.validateToken(invalidToken));
    }

    @Test
    void isTokenValid_ValidToken_ReturnsTrue() {
        // Given
        UUID userId = UUID.randomUUID();
        String email = "test@example.com";
        String token = jwtTokenService.generateAccessToken(userId, email, new HashMap<>());

        // When
        boolean isValid = jwtTokenService.isTokenValid(token);

        // Then
        assertTrue(isValid);
    }

    @Test
    void isTokenValid_InvalidToken_ReturnsFalse() {
        // Given
        String invalidToken = "invalid.token.here";

        // When
        boolean isValid = jwtTokenService.isTokenValid(invalidToken);

        // Then
        assertFalse(isValid);
    }

    @Test
    void getEmailFromToken_Success() {
        // Given
        UUID userId = UUID.randomUUID();
        String email = "test@example.com";
        String token = jwtTokenService.generateAccessToken(userId, email, new HashMap<>());

        // When
        String extractedEmail = jwtTokenService.getEmailFromToken(token);

        // Then
        assertEquals(email, extractedEmail);
    }

    @Test
    void getUserIdFromToken_Success() {
        // Given
        UUID userId = UUID.randomUUID();
        String email = "test@example.com";
        String token = jwtTokenService.generateAccessToken(userId, email, new HashMap<>());

        // When
        UUID extractedUserId = jwtTokenService.getUserIdFromToken(token);

        // Then
        assertEquals(userId, extractedUserId);
    }

    @Test
    void getTokenType_AccessToken_ReturnsAccess() {
        // Given
        UUID userId = UUID.randomUUID();
        String email = "test@example.com";
        String token = jwtTokenService.generateAccessToken(userId, email, new HashMap<>());

        // When
        String tokenType = jwtTokenService.getTokenType(token);

        // Then
        assertEquals("access", tokenType);
    }

    @Test
    void getTokenType_RefreshToken_ReturnsRefresh() {
        // Given
        UUID userId = UUID.randomUUID();
        String email = "test@example.com";
        String token = jwtTokenService.generateRefreshToken(userId, email);

        // When
        String tokenType = jwtTokenService.getTokenType(token);

        // Then
        assertEquals("refresh", tokenType);
    }

    @Test
    void validateToken_ExpiredToken_ThrowsExpiredJwtException() {
        // Given - create a service with 0ms expiration
        JwtTokenService expiredTokenService = new JwtTokenService(SECRET, 0L, 0L);
        UUID userId = UUID.randomUUID();
        String email = "test@example.com";
        String token = expiredTokenService.generateAccessToken(userId, email, new HashMap<>());

        // When & Then
        assertThrows(ExpiredJwtException.class, () -> jwtTokenService.validateToken(token));
    }
}
