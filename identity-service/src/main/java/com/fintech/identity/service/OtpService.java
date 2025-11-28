package com.fintech.identity.service;

import com.fintech.identity.entity.OtpVerification;
import com.fintech.identity.entity.OtpVerification.OtpPurpose;
import com.fintech.identity.exception.OtpVerificationException;
import com.fintech.identity.repository.OtpVerificationRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.Optional;

@Service
public class OtpService {

    private static final Logger logger = LoggerFactory.getLogger(OtpService.class);
    private static final SecureRandom secureRandom = new SecureRandom();

    private final OtpVerificationRepository otpVerificationRepository;
    private final PasswordEncoder passwordEncoder;
    private final int otpLength;
    private final int otpExpirationMinutes;

    public OtpService(
            OtpVerificationRepository otpVerificationRepository,
            PasswordEncoder passwordEncoder,
            @Value("${otp.length:6}") int otpLength,
            @Value("${otp.expiration-minutes:5}") int otpExpirationMinutes) {
        this.otpVerificationRepository = otpVerificationRepository;
        this.passwordEncoder = passwordEncoder;
        this.otpLength = otpLength;
        this.otpExpirationMinutes = otpExpirationMinutes;
    }

    @Transactional
    public String generateOtp(String email, String phoneNumber, OtpPurpose purpose) {
        String otp = generateRandomOtp();
        String otpHash = passwordEncoder.encode(otp);

        OtpVerification otpVerification = OtpVerification.builder()
                .email(email)
                .phoneNumber(phoneNumber)
                .otpCode(otp) // In production, this should NOT be stored in plain text
                .otpHash(otpHash)
                .purpose(purpose)
                .expiresAt(LocalDateTime.now().plusMinutes(otpExpirationMinutes))
                .build();

        otpVerificationRepository.save(otpVerification);
        logger.info("Generated OTP for email: {}, purpose: {}", email, purpose);

        // In production, send OTP via SMS or Email service
        // For now, we return it (only for development/testing)
        return otp;
    }

    @Transactional
    public boolean verifyOtp(String email, String phoneNumber, String otpCode, OtpPurpose purpose) {
        Optional<OtpVerification> otpOptional;

        if (email != null) {
            otpOptional = otpVerificationRepository.findLatestValidOtpByEmail(email, purpose, LocalDateTime.now());
        } else if (phoneNumber != null) {
            otpOptional = otpVerificationRepository.findLatestValidOtpByPhoneNumber(phoneNumber, purpose, LocalDateTime.now());
        } else {
            throw new OtpVerificationException("Email or phone number is required");
        }

        if (otpOptional.isEmpty()) {
            throw new OtpVerificationException("No valid OTP found. Please request a new OTP.");
        }

        OtpVerification otp = otpOptional.get();

        if (otp.isExpired()) {
            throw new OtpVerificationException("OTP has expired. Please request a new OTP.");
        }

        if (otp.hasExceededMaxAttempts()) {
            throw new OtpVerificationException("Maximum verification attempts exceeded. Please request a new OTP.");
        }

        otp.incrementAttempts();

        if (!passwordEncoder.matches(otpCode, otp.getOtpHash())) {
            otpVerificationRepository.save(otp);
            int remainingAttempts = otp.getMaxAttempts() - otp.getAttempts();
            throw new OtpVerificationException("Invalid OTP. " + remainingAttempts + " attempts remaining.");
        }

        otp.markAsVerified();
        otpVerificationRepository.save(otp);
        logger.info("OTP verified successfully for email: {}, purpose: {}", email, purpose);

        return true;
    }

    private String generateRandomOtp() {
        StringBuilder otp = new StringBuilder();
        for (int i = 0; i < otpLength; i++) {
            otp.append(secureRandom.nextInt(10));
        }
        return otp.toString();
    }
}
