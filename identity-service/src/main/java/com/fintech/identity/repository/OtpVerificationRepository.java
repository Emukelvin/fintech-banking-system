package com.fintech.identity.repository;

import com.fintech.identity.entity.OtpVerification;
import com.fintech.identity.entity.OtpVerification.OtpPurpose;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface OtpVerificationRepository extends JpaRepository<OtpVerification, UUID> {
    
    @Query("SELECT o FROM OtpVerification o WHERE o.email = :email AND o.purpose = :purpose AND o.isVerified = false AND o.expiresAt > :now ORDER BY o.createdAt DESC LIMIT 1")
    Optional<OtpVerification> findLatestValidOtpByEmail(@Param("email") String email, @Param("purpose") OtpPurpose purpose, @Param("now") LocalDateTime now);
    
    @Query("SELECT o FROM OtpVerification o WHERE o.phoneNumber = :phoneNumber AND o.purpose = :purpose AND o.isVerified = false AND o.expiresAt > :now ORDER BY o.createdAt DESC LIMIT 1")
    Optional<OtpVerification> findLatestValidOtpByPhoneNumber(@Param("phoneNumber") String phoneNumber, @Param("purpose") OtpPurpose purpose, @Param("now") LocalDateTime now);
    
    @Query("SELECT o FROM OtpVerification o WHERE o.user.id = :userId AND o.purpose = :purpose AND o.isVerified = false AND o.expiresAt > :now ORDER BY o.createdAt DESC LIMIT 1")
    Optional<OtpVerification> findLatestValidOtpByUserId(@Param("userId") UUID userId, @Param("purpose") OtpPurpose purpose, @Param("now") LocalDateTime now);
}
