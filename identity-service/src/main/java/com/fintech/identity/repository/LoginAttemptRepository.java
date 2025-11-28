package com.fintech.identity.repository;

import com.fintech.identity.entity.LoginAttempt;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.UUID;

@Repository
public interface LoginAttemptRepository extends JpaRepository<LoginAttempt, UUID> {
    
    @Query("SELECT COUNT(la) FROM LoginAttempt la WHERE la.email = :email AND la.success = false AND la.createdAt > :since")
    long countFailedAttemptsByEmailSince(@Param("email") String email, @Param("since") LocalDateTime since);
    
    @Query("SELECT COUNT(la) FROM LoginAttempt la WHERE la.ipAddress = :ipAddress AND la.success = false AND la.createdAt > :since")
    long countFailedAttemptsByIpSince(@Param("ipAddress") String ipAddress, @Param("since") LocalDateTime since);
    
    @Query("SELECT COUNT(la) FROM LoginAttempt la WHERE la.user.id = :userId AND la.success = false AND la.createdAt > :since")
    long countFailedAttemptsByUserIdSince(@Param("userId") UUID userId, @Param("since") LocalDateTime since);
}
