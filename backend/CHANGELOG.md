# CHANGELOG

All notable changes to the Phishing Guardian backend are documented here.

---

# Step 1 - Project Refactoring & Clean Architecture ✅

## Added

- Introduced a modular project structure following FastAPI best practices.
- Created separate layers for API routes, services, core utilities, schemas, and ML engine.
- Added dedicated route modules for health checks and URL scanning.
- Introduced a service layer to separate business logic from API endpoints.
- Added package initialization files (`__init__.py`) for proper module organization.

## Changed

- Refactored `main.py` to focus only on application startup, middleware, and router registration.
- Moved URL scanning logic from `main.py` into a dedicated service layer.
- Relocated machine learning components into the `ml_engine` package.
- Organized API endpoints into separate route files.

## Benefits

- Improved code readability and maintainability.
- Clear separation of responsibilities.
- Easier feature development and testing.
- Scalable architecture suitable for production applications.

---

# Step 2 - Configuration & Model Management ✅

## Added

- Introduced centralized configuration using `.env`.
- Added `config.py` for application settings management.
- Implemented intelligent ML model loading through `model_loader.py`.
- Added automatic local model detection.
- Added automatic S3 fallback when the local model is unavailable.
- Cached the ML model in memory after application startup.
- Configured FastAPI lifespan events for application startup and shutdown.

## Changed

- Removed direct model loading from `detector.py`.
- Centralized model initialization into a dedicated loader.
- Replaced hardcoded configuration values with environment variables.
- Updated the application startup process to preload the ML model.

## Benefits

- Same codebase works for both development and production.
- No code changes required when switching environments.
- Faster API responses by loading the model only once.
- Cleaner separation between configuration and business logic.
- Easier future model upgrades and version management.

# Step 4 - Production Logging ✅

## Added

- Introduced centralized application logger.
- Added console logging with structured formatting.
- Added persistent file logging.
- Automatic creation of the `logs` directory.
- Implemented rotating log files with automatic cleanup.

## Changed

- Replaced all `print()` statements with structured logging.
- Configured environment-aware log levels.

## Benefits

- Persistent application logs.
- Easier debugging and monitoring.
- Controlled disk usage through log rotation.
- Production-ready logging infrastructure.

---

# Step 3 - Logging & Monitoring ✅

## Added

- Introduced a centralized logging utility.
- Configured application-wide logging with custom formatting.
- Added console logging for development.
- Added persistent file logging.
- Automatically created the `logs` directory on application startup.
- Implemented rotating log files using `RotatingFileHandler`.

## Changed

- Replaced all `print()` statements with structured logger calls.
- Configured environment-aware log levels based on application settings.

## Benefits

- Centralized logging across the application.
- Persistent logs for debugging and auditing.
- Controlled disk usage through automatic log rotation.
- Production-ready logging infrastructure.

---

# Step 4 - Global Exception Handling & Standardized API Responses ✅

## Added

- Introduced a global exception handling mechanism.
- Added custom application exceptions.
- Added centralized exception registration.
- Implemented standardized API response schema.
- Added reusable response builder utilities.

## Changed

- Replaced ad-hoc exception handling with centralized handlers.
- Standardized success and error responses across all endpoints.
- Updated API routes to use the unified response format.

## Benefits

- Consistent API responses.
- Simplified error management.
- Improved client-side integration.
- Easier debugging and maintenance.

---

# Step 5 - Database Infrastructure & SQLAlchemy Integration ✅

## Added

- Integrated PostgreSQL as the primary relational database.
- Added centralized database configuration through environment variables.
- Configured SQLAlchemy Engine and Session Factory.
- Implemented dependency injection for database sessions.
- Created the SQLAlchemy Declarative Base.
- Added reusable `BaseEntity` with common fields:
  - UUID primary key
  - `created_at`
  - `updated_at`
- Added database connectivity verification scripts:
  - `test_connection.py`
  - `test_psycopg2.py`

## Changed

- Centralized database connection management within the `database` package.
- Configured connection pooling with `pool_pre_ping=True`.
- Removed hardcoded database configuration from the application.

## Benefits

- Production-ready database infrastructure.
- Reusable ORM foundation for future entities.
- Efficient connection management.
- Simplified dependency injection.
- Verified PostgreSQL and SQLAlchemy integration.

Step 6 - Authentication System (JWT + Email Verification + Redis OTP) ✅
Added
Implemented a complete JWT-based authentication system.
Added user registration and login APIs.
Introduced secure password hashing using BCrypt.
Implemented JWT Access Token and Refresh Token generation.
Added email verification during user registration.
Integrated Redis for temporary OTP storage.
Configured OTP expiration with automatic TTL (5 minutes).
Added HTML email templates for verification emails using Jinja2.
Integrated FastAPI-Mail with Gmail SMTP for email delivery.
Added email verification endpoint.
Added role support for authenticated users.
Introduced dedicated authentication schemas for request and response validation.
Added reusable services:
AuthService
EmailService
OTPService
RedisService
JwtService
Changed
User registration now requires email verification before login.
Login now validates:
Email existence
Password correctness
Account status
Email verification status
Centralized authentication business logic into the service layer.
Integrated Redis into the authentication workflow for OTP management.
Benefits
Production-ready authentication architecture.
Secure password storage using BCrypt.
Stateless authentication using JWT.
Email ownership verification before account activation.
Fast temporary OTP storage with automatic expiration.
Modular authentication services following Clean Architecture.
Easily extensible for password reset, resend OTP, and MFA in future releases.