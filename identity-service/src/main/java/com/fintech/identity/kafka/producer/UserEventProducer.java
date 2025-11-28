package com.fintech.identity.kafka.producer;

import com.fintech.identity.dto.DeviceInfo;
import com.fintech.identity.entity.User;
import com.fintech.identity.kafka.event.UserEvent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@Service
public class UserEventProducer {

    private static final Logger logger = LoggerFactory.getLogger(UserEventProducer.class);

    private final KafkaTemplate<String, UserEvent> kafkaTemplate;
    private final String userEventsTopic;
    private final boolean kafkaEnabled;

    public UserEventProducer(
            KafkaTemplate<String, UserEvent> kafkaTemplate,
            @Value("${spring.kafka.topics.user-events:user-events}") String userEventsTopic,
            @Value("${spring.kafka.enabled:true}") boolean kafkaEnabled) {
        this.kafkaTemplate = kafkaTemplate;
        this.userEventsTopic = userEventsTopic;
        this.kafkaEnabled = kafkaEnabled;
    }

    public void sendUserRegisteredEvent(User user) {
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("firstName", user.getFirstName());
        metadata.put("lastName", user.getLastName());
        metadata.put("phoneNumber", user.getPhoneNumber());

        sendEvent(UserEvent.EventType.USER_REGISTERED, user, metadata);
    }

    public void sendUserVerifiedEvent(User user) {
        sendEvent(UserEvent.EventType.USER_VERIFIED, user, new HashMap<>());
    }

    public void sendUserLoggedInEvent(User user, String ipAddress, DeviceInfo deviceInfo) {
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("ipAddress", ipAddress);
        if (deviceInfo != null) {
            metadata.put("deviceId", deviceInfo.getDeviceId());
            metadata.put("deviceType", deviceInfo.getDeviceType());
        }

        sendEvent(UserEvent.EventType.USER_LOGGED_IN, user, metadata);
    }

    public void sendUserLockedEvent(User user, String reason) {
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("reason", reason);

        sendEvent(UserEvent.EventType.USER_LOCKED, user, metadata);
    }

    public void sendSessionCreatedEvent(User user, String sessionId) {
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("sessionId", sessionId);

        sendEvent(UserEvent.EventType.SESSION_CREATED, user, metadata);
    }

    public void sendSessionRevokedEvent(User user, String sessionId, String reason) {
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("sessionId", sessionId);
        metadata.put("reason", reason);

        sendEvent(UserEvent.EventType.SESSION_REVOKED, user, metadata);
    }

    private void sendEvent(String eventType, User user, Map<String, Object> metadata) {
        if (!kafkaEnabled) {
            logger.debug("Kafka disabled, skipping event: {} for user: {}", eventType, user.getEmail());
            return;
        }

        UserEvent event = UserEvent.builder()
                .eventId(UUID.randomUUID())
                .eventType(eventType)
                .userId(user.getId())
                .email(user.getEmail())
                .timestamp(LocalDateTime.now())
                .metadata(metadata)
                .build();

        try {
            kafkaTemplate.send(userEventsTopic, user.getId().toString(), event);
            logger.info("Event sent: {} for user: {}", eventType, user.getEmail());
        } catch (Exception e) {
            logger.error("Failed to send event: {} for user: {}", eventType, user.getEmail(), e);
        }
    }
}
