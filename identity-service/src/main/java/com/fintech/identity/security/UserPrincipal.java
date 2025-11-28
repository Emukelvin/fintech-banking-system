package com.fintech.identity.security;

import io.jsonwebtoken.Claims;
import lombok.Getter;

import java.security.Principal;
import java.util.UUID;

@Getter
public class UserPrincipal implements Principal {
    private final UUID userId;
    private final String email;
    private final Claims claims;

    public UserPrincipal(UUID userId, String email, Claims claims) {
        this.userId = userId;
        this.email = email;
        this.claims = claims;
    }

    @Override
    public String getName() {
        return email;
    }

    public String getFirstName() {
        return claims.get("firstName", String.class);
    }

    public String getLastName() {
        return claims.get("lastName", String.class);
    }

    public String getStatus() {
        return claims.get("status", String.class);
    }

    public String getKycStatus() {
        return claims.get("kycStatus", String.class);
    }
}
