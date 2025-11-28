package com.fintech.identity.service;

import com.fintech.identity.entity.Device;
import com.fintech.identity.entity.Session;
import com.fintech.identity.entity.User;
import com.fintech.identity.exception.TokenException;
import com.fintech.identity.repository.SessionRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.Optional;
import java.util.UUID;

@Service
public class SessionService {

    private static final Logger logger = LoggerFactory.getLogger(SessionService.class);

    private final SessionRepository sessionRepository;
    private final long refreshTokenExpirationMs;

    public SessionService(
            SessionRepository sessionRepository,
            @Value("${jwt.refresh-token-expiration}") long refreshTokenExpirationMs) {
        this.sessionRepository = sessionRepository;
        this.refreshTokenExpirationMs = refreshTokenExpirationMs;
    }

    @Transactional
    public Session createSession(User user, Device device, String refreshToken, String ipAddress, String userAgent) {
        String refreshTokenHash = hashToken(refreshToken);

        Session session = Session.builder()
                .user(user)
                .device(device)
                .refreshToken(refreshTokenHash) // Store hash only, not plain text
                .refreshTokenHash(refreshTokenHash)
                .ipAddress(ipAddress)
                .userAgent(userAgent)
                .expiresAt(LocalDateTime.now().plusSeconds(refreshTokenExpirationMs / 1000))
                .isActive(true)
                .build();

        Session savedSession = sessionRepository.save(session);
        logger.info("Created new session for user: {}, sessionId: {}", user.getEmail(), savedSession.getId());

        return savedSession;
    }

    @Transactional
    public Session validateAndRefreshSession(String refreshToken) {
        String tokenHash = hashToken(refreshToken);
        Optional<Session> sessionOptional = sessionRepository.findByRefreshTokenHash(tokenHash);

        if (sessionOptional.isEmpty()) {
            throw new TokenException("Invalid refresh token");
        }

        Session session = sessionOptional.get();

        if (!session.getIsActive()) {
            throw new TokenException("Session has been revoked");
        }

        if (session.isExpired()) {
            session.revoke("Expired");
            sessionRepository.save(session);
            throw new TokenException("Refresh token has expired");
        }

        return session;
    }

    @Transactional
    public void revokeSession(String refreshToken, String reason) {
        String tokenHash = hashToken(refreshToken);
        sessionRepository.findByRefreshTokenHash(tokenHash)
                .ifPresent(session -> {
                    session.revoke(reason);
                    sessionRepository.save(session);
                    logger.info("Revoked session: {}, reason: {}", session.getId(), reason);
                });
    }

    @Transactional
    public int revokeAllUserSessions(UUID userId, String reason) {
        int count = sessionRepository.revokeAllUserSessions(userId, LocalDateTime.now(), reason);
        logger.info("Revoked {} sessions for user: {}, reason: {}", count, userId, reason);
        return count;
    }

    @Transactional
    public int revokeExpiredSessions() {
        int count = sessionRepository.revokeExpiredSessions(LocalDateTime.now(), LocalDateTime.now());
        logger.info("Revoked {} expired sessions", count);
        return count;
    }

    public Optional<Session> findActiveSession(String refreshToken) {
        String tokenHash = hashToken(refreshToken);
        return sessionRepository.findByRefreshTokenHash(tokenHash)
                .filter(Session::getIsActive)
                .filter(session -> !session.isExpired());
    }

    /**
     * Creates a SHA-256 hash of the token for secure storage and lookup.
     * SHA-256 is deterministic, allowing us to look up sessions by the hash.
     */
    private String hashToken(String token) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(token.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 algorithm not available", e);
        }
    }
}
