package com.fintech.identity.exception;

import org.springframework.http.HttpStatus;

public class OtpVerificationException extends RuntimeException {
    private final HttpStatus status;

    public OtpVerificationException(String message) {
        super(message);
        this.status = HttpStatus.BAD_REQUEST;
    }

    public OtpVerificationException(String message, HttpStatus status) {
        super(message);
        this.status = status;
    }

    public HttpStatus getStatus() {
        return status;
    }
}
