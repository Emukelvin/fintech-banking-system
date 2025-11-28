package com.fintech.identity.repository;

import com.fintech.identity.entity.Session;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface SessionRepository extends JpaRepository<Session, UUID> {
    
    Optional<Session> findByRefreshToken(String refreshToken);
    
    Optional<Session> findByRefreshTokenHash(String refreshTokenHash);
    
    List<Session> findByUserIdAndIsActiveTrue(UUID userId);
    
    @Modifying
    @Query("UPDATE Session s SET s.isActive = false, s.revokedAt = :revokedAt, s.revokedReason = :reason WHERE s.user.id = :userId AND s.isActive = true")
    int revokeAllUserSessions(@Param("userId") UUID userId, @Param("revokedAt") LocalDateTime revokedAt, @Param("reason") String reason);
    
    @Modifying
    @Query("UPDATE Session s SET s.isActive = false, s.revokedAt = :revokedAt, s.revokedReason = 'Expired' WHERE s.expiresAt < :now AND s.isActive = true")
    int revokeExpiredSessions(@Param("now") LocalDateTime now, @Param("revokedAt") LocalDateTime revokedAt);
}
