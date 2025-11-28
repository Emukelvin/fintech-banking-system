package com.fintech.identity.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fintech.identity.dto.ApiResponse;
import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.Refill;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class RateLimitFilter extends OncePerRequestFilter {

    private static final Logger logger = LoggerFactory.getLogger(RateLimitFilter.class);

    private final Map<String, Bucket> buckets = new ConcurrentHashMap<>();
    private final Map<String, Bucket> loginBuckets = new ConcurrentHashMap<>();
    private final ObjectMapper objectMapper = new ObjectMapper();

    private final int requestsPerMinute;
    private final int loginAttemptsPerMinute;

    public RateLimitFilter(
            @Value("${rate-limit.requests-per-minute:60}") int requestsPerMinute,
            @Value("${rate-limit.login-attempts-per-minute:5}") int loginAttemptsPerMinute) {
        this.requestsPerMinute = requestsPerMinute;
        this.loginAttemptsPerMinute = loginAttemptsPerMinute;
    }

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain) throws ServletException, IOException {

        String clientId = getClientIdentifier(request);
        String path = request.getRequestURI();

        // Apply stricter rate limiting for login endpoint
        if (path.equals("/auth/login")) {
            Bucket loginBucket = loginBuckets.computeIfAbsent(clientId, this::createLoginBucket);
            if (!loginBucket.tryConsume(1)) {
                logger.warn("Login rate limit exceeded for client: {}", clientId);
                sendRateLimitResponse(response, "Too many login attempts. Please try again later.");
                return;
            }
        }

        // General rate limiting
        Bucket bucket = buckets.computeIfAbsent(clientId, this::createBucket);
        if (!bucket.tryConsume(1)) {
            logger.warn("Rate limit exceeded for client: {}", clientId);
            sendRateLimitResponse(response, "Too many requests. Please try again later.");
            return;
        }

        filterChain.doFilter(request, response);
    }

    private Bucket createBucket(String key) {
        Bandwidth limit = Bandwidth.classic(requestsPerMinute, Refill.greedy(requestsPerMinute, Duration.ofMinutes(1)));
        return Bucket.builder().addLimit(limit).build();
    }

    private Bucket createLoginBucket(String key) {
        Bandwidth limit = Bandwidth.classic(loginAttemptsPerMinute, Refill.greedy(loginAttemptsPerMinute, Duration.ofMinutes(1)));
        return Bucket.builder().addLimit(limit).build();
    }

    private String getClientIdentifier(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            return xForwardedFor.split(",")[0].trim();
        }
        String xRealIp = request.getHeader("X-Real-IP");
        if (xRealIp != null && !xRealIp.isEmpty()) {
            return xRealIp;
        }
        return request.getRemoteAddr();
    }

    private void sendRateLimitResponse(HttpServletResponse response, String message) throws IOException {
        response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);

        ApiResponse<Void> apiResponse = ApiResponse.error(message);
        objectMapper.findAndRegisterModules();
        response.getWriter().write(objectMapper.writeValueAsString(apiResponse));
    }
}
