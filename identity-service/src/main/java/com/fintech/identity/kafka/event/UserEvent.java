package com.fintech.identity.kafka.event;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.Map;
import java.util.UUID;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserEvent {
    private UUID eventId;
    private String eventType;
    private UUID userId;
    private String email;
    private LocalDateTime timestamp;
    private Map<String, Object> metadata;

    public static class EventType {
        public static final String USER_REGISTERED = "USER_REGISTERED";
        public static final String USER_VERIFIED = "USER_VERIFIED";
        public static final String USER_LOGGED_IN = "USER_LOGGED_IN";
        public static final String USER_LOGGED_OUT = "USER_LOGGED_OUT";
        public static final String USER_PASSWORD_CHANGED = "USER_PASSWORD_CHANGED";
        public static final String USER_LOCKED = "USER_LOCKED";
        public static final String USER_UNLOCKED = "USER_UNLOCKED";
        public static final String SESSION_CREATED = "SESSION_CREATED";
        public static final String SESSION_REVOKED = "SESSION_REVOKED";

        private EventType() {
        }
    }
}
