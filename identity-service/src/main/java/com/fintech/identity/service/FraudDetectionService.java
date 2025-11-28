package com.fintech.identity.service;

import com.fintech.identity.entity.LoginAttempt;
import com.fintech.identity.entity.User;
import com.fintech.identity.repository.LoginAttemptRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

@Service
public class FraudDetectionService {

    private static final Logger logger = LoggerFactory.getLogger(FraudDetectionService.class);

    private final LoginAttemptRepository loginAttemptRepository;
    private final boolean velocityCheckEnabled;
    private final int maxLoginAttempts;
    private final int timeWindowMinutes;

    public FraudDetectionService(
            LoginAttemptRepository loginAttemptRepository,
            @Value("${fraud-detection.velocity-check.enabled:true}") boolean velocityCheckEnabled,
            @Value("${fraud-detection.velocity-check.max-login-attempts:5}") int maxLoginAttempts,
            @Value("${fraud-detection.velocity-check.time-window-minutes:15}") int timeWindowMinutes) {
        this.loginAttemptRepository = loginAttemptRepository;
        this.velocityCheckEnabled = velocityCheckEnabled;
        this.maxLoginAttempts = maxLoginAttempts;
        this.timeWindowMinutes = timeWindowMinutes;
    }

    @Transactional
    public void recordLoginAttempt(User user, String email, String ipAddress, String userAgent,
                                    String deviceFingerprint, boolean success, String failureReason) {
        LoginAttempt attempt = LoginAttempt.builder()
                .user(user)
                .email(email)
                .ipAddress(ipAddress)
                .userAgent(userAgent)
                .deviceFingerprint(deviceFingerprint)
                .success(success)
                .failureReason(failureReason)
                .build();

        loginAttemptRepository.save(attempt);
        logger.debug("Recorded login attempt for email: {}, success: {}", email, success);
    }

    public boolean isVelocityCheckTriggered(String email, String ipAddress) {
        if (!velocityCheckEnabled) {
            return false;
        }

        LocalDateTime since = LocalDateTime.now().minusMinutes(timeWindowMinutes);

        long failedAttemptsByEmail = loginAttemptRepository.countFailedAttemptsByEmailSince(email, since);
        long failedAttemptsByIp = loginAttemptRepository.countFailedAttemptsByIpSince(ipAddress, since);

        if (failedAttemptsByEmail >= maxLoginAttempts) {
            logger.warn("Velocity check triggered for email: {}, attempts: {}", email, failedAttemptsByEmail);
            return true;
        }

        if (failedAttemptsByIp >= maxLoginAttempts * 2) {
            logger.warn("Velocity check triggered for IP: {}, attempts: {}", ipAddress, failedAttemptsByIp);
            return true;
        }

        return false;
    }

    /**
     * Placeholder for Geo-IP analysis.
     * In production, integrate with a Geo-IP service to detect anomalies.
     */
    public boolean isLocationSuspicious(String ipAddress, String expectedCountry) {
        // TODO: Integrate with Geo-IP service (e.g., MaxMind GeoIP2)
        // For now, return false (not suspicious)
        logger.debug("Geo-IP check for IP: {} (stub implementation)", ipAddress);
        return false;
    }

    /**
     * Checks if the device is associated with suspicious activity.
     */
    public boolean isDeviceSuspicious(String deviceFingerprint) {
        // TODO: Implement device reputation check
        logger.debug("Device check for fingerprint: {} (stub implementation)", deviceFingerprint);
        return false;
    }

    /**
     * Comprehensive fraud check combining multiple signals.
     */
    public FraudCheckResult performFraudCheck(String email, String ipAddress, String deviceFingerprint) {
        boolean velocityTriggered = isVelocityCheckTriggered(email, ipAddress);
        boolean locationSuspicious = isLocationSuspicious(ipAddress, null);
        boolean deviceSuspicious = isDeviceSuspicious(deviceFingerprint);

        FraudCheckResult result = new FraudCheckResult();
        result.setBlocked(velocityTriggered);
        result.setRequiresAdditionalVerification(locationSuspicious || deviceSuspicious);
        result.setReason(buildReason(velocityTriggered, locationSuspicious, deviceSuspicious));

        return result;
    }

    private String buildReason(boolean velocityTriggered, boolean locationSuspicious, boolean deviceSuspicious) {
        StringBuilder reason = new StringBuilder();
        if (velocityTriggered) {
            reason.append("Too many failed login attempts. ");
        }
        if (locationSuspicious) {
            reason.append("Suspicious login location. ");
        }
        if (deviceSuspicious) {
            reason.append("Suspicious device. ");
        }
        return reason.toString().trim();
    }

    public static class FraudCheckResult {
        private boolean blocked;
        private boolean requiresAdditionalVerification;
        private String reason;

        public boolean isBlocked() {
            return blocked;
        }

        public void setBlocked(boolean blocked) {
            this.blocked = blocked;
        }

        public boolean isRequiresAdditionalVerification() {
            return requiresAdditionalVerification;
        }

        public void setRequiresAdditionalVerification(boolean requiresAdditionalVerification) {
            this.requiresAdditionalVerification = requiresAdditionalVerification;
        }

        public String getReason() {
            return reason;
        }

        public void setReason(String reason) {
            this.reason = reason;
        }
    }
}
