package com.fintech.identity.exception;

import org.springframework.http.HttpStatus;

public class RegistrationException extends RuntimeException {
    private final HttpStatus status;

    public RegistrationException(String message) {
        super(message);
        this.status = HttpStatus.BAD_REQUEST;
    }

    public RegistrationException(String message, HttpStatus status) {
        super(message);
        this.status = status;
    }

    public HttpStatus getStatus() {
        return status;
    }
}
