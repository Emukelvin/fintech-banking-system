package com.fintech.identity.service;

import com.fintech.identity.entity.Device;
import com.fintech.identity.entity.Session;
import com.fintech.identity.entity.User;
import com.fintech.identity.exception.TokenException;
import com.fintech.identity.repository.SessionRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;

@Service
public class SessionService {

    private static final Logger logger = LoggerFactory.getLogger(SessionService.class);

    private final SessionRepository sessionRepository;
    private final PasswordEncoder passwordEncoder;
    private final long refreshTokenExpirationMs;

    public SessionService(
            SessionRepository sessionRepository,
            PasswordEncoder passwordEncoder,
            @Value("${jwt.refresh-token-expiration}") long refreshTokenExpirationMs) {
        this.sessionRepository = sessionRepository;
        this.passwordEncoder = passwordEncoder;
        this.refreshTokenExpirationMs = refreshTokenExpirationMs;
    }

    @Transactional
    public Session createSession(User user, Device device, String refreshToken, String ipAddress, String userAgent) {
        String refreshTokenHash = passwordEncoder.encode(refreshToken);

        Session session = Session.builder()
                .user(user)
                .device(device)
                .refreshToken(refreshToken)
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
        Optional<Session> sessionOptional = sessionRepository.findByRefreshToken(refreshToken);

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
        sessionRepository.findByRefreshToken(refreshToken)
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
        return sessionRepository.findByRefreshToken(refreshToken)
                .filter(Session::getIsActive)
                .filter(session -> !session.isExpired());
    }
}
