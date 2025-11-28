# Fintech Banking System

## Identity & Authentication Service

The Identity & Authentication Service is a core component of the Fintech Banking System responsible for user authentication, registration, fraud mitigation, and session management.

### Features

#### User Registration
- Basic data capture (name, email, phone number, password)
- Password validation with security requirements (uppercase, lowercase, digit, special character)
- Device binding during registration
- OTP-based email verification
- Integration hooks for KYC verification service

#### Login
- Password-based authentication
- Support for OTP-based Multi-Factor Authentication (MFA)
- Account lockout after multiple failed attempts
- Device validation and tracking

#### Access Management
- JWT-based access tokens (15-minute expiration)
- Refresh tokens (7-day expiration)
- Session management with token revocation
- Expired session cleanup

#### Fraud Mitigation
- Velocity checks for failed login attempts
- IP-based rate limiting
- Device fingerprinting
- Geo-IP analysis hooks (placeholder for integration)

### API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/auth/register` | POST | Registers a new user and binds their device |
| `/auth/login` | POST | Authenticates the user with their credentials |
| `/auth/verify-otp` | POST | Handles OTP verification for registration/login |
| `/auth/refresh-token` | POST | Issues a new access token using a refresh token |

### Database Schema

The service uses PostgreSQL with the following tables:
- `users` - User information and authentication data
- `devices` - Registered user devices for device binding
- `sessions` - User sessions and refresh tokens
- `otp_verifications` - Temporary OTP storage
- `login_attempts` - Login attempt history for fraud detection

### Tech Stack

- **Framework**: Java 17 with Spring Boot 3.2.0
- **Database**: PostgreSQL with Flyway migrations
- **Session Management**: Redis (optional)
- **Message Queue**: Apache Kafka for user events
- **Security**: BCrypt password hashing, JWT tokens

### Middleware

- **JWT Authentication Filter**: Validates JWT tokens for protected endpoints
- **Rate Limiting Filter**: Prevents brute-force attacks with configurable limits

### Configuration

Key configuration properties in `application.yml`:

```yaml
jwt:
  secret: ${JWT_SECRET}
  access-token-expiration: 900000  # 15 minutes
  refresh-token-expiration: 604800000  # 7 days

rate-limit:
  requests-per-minute: 60
  login-attempts-per-minute: 5

fraud-detection:
  velocity-check:
    max-login-attempts: 5
    time-window-minutes: 15
```

### Getting Started

#### Prerequisites
- Java 17+
- Maven 3.8+
- PostgreSQL 14+
- Redis (optional)
- Kafka (optional)

#### Build and Run

```bash
cd identity-service
mvn clean install
mvn spring-boot:run
```

#### Run Tests

```bash
mvn test
```

### Project Structure

```
identity-service/
├── src/main/java/com/fintech/identity/
│   ├── config/         # Configuration classes
│   ├── controller/     # REST API controllers
│   ├── dto/            # Data Transfer Objects
│   ├── entity/         # JPA entities
│   ├── exception/      # Exception handling
│   ├── kafka/          # Kafka event producers
│   ├── repository/     # JPA repositories
│   ├── security/       # Security filters
│   └── service/        # Business logic services
├── src/main/resources/
│   ├── application.yml # Application configuration
│   └── db/migration/   # Flyway database migrations
└── src/test/           # Unit and integration tests
```