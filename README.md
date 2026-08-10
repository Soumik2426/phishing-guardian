# Phishing Guardian

Phishing Guardian is a phishing URL detection backend built with FastAPI. It combines a machine learning classifier with a rule-based analysis engine to score URLs, explain the result, and support a broader security platform that now includes authentication, database models, Redis-backed OTP verification, and Alembic migrations.

At the moment, this repository is primarily a backend codebase. A `frontend/` directory exists, but it is currently empty, so the working product in this repo is the API inside `backend/`.

## What This Project Does

The main product goal is to inspect a URL and answer three practical questions:

1. Is this URL likely phishing or safe?
2. Why did the system reach that conclusion?
3. How should a user respond to that result?

The backend currently supports:

- Hybrid phishing detection using ML + forensic rules
- Structured scan results with findings, guidance, and score breakdowns
- User registration and login
- Email verification with OTP
- JWT-based authentication primitives
- PostgreSQL models and Alembic migrations for persistence
- Redis integration for short-lived OTP storage
- Centralized logging, configuration, and exception handling

## Current Repository Status

This README reflects the code that is currently in the repository as of August 10, 2026.

What is fully present:

- FastAPI backend under `backend/app`
- Heuristic detection engine under `backend/engine`
- ML risk computation and explanation flow
- Authentication, email, Redis, and database layers
- Alembic migration history

What is partial or still evolving:

- The scan endpoint analyzes URLs but does not yet persist scan history
- Database models for scans and metrics exist, but they are not yet connected to the scan request flow
- A `health.py` route module exists, but it is not currently mounted in `backend/app/main.py`
- The `frontend/` folder is empty
- Some development/test utility endpoints are still exposed in the auth router

## High-Level Architecture

The application is organized into clear layers:

- `app/api/routes/`: FastAPI route definitions
- `app/services/`: business logic and integrations
- `app/security/`: password hashing, JWT handling, auth dependencies
- `app/database/`: SQLAlchemy base, engine, and session management
- `app/models/`: ORM entities for users, scans, and metrics
- `app/schemas/`: request/response validation using Pydantic
- `app/core/`: configuration, logging, model loading, and shared infrastructure
- `app/ml_engine/`: ML-driven risk calculation, explanation building, and brand handling
- `engine/`: rule-based phishing detection modules
- `alembic/`: schema migration history

## Request Flow

### URL scanning flow

1. Client sends a URL to `POST /scan/`
2. `app/services/detector_service.py` delegates to the ML engine
3. `app/ml_engine/detector.py` gets the cached model
4. `app/ml_engine/risk_engine.py`:
   - runs the forensic engine
   - extracts ML features
   - gets model probability
   - combines ML score and rule score
5. `engine/orchestrator.py` runs the rule modules
6. `engine/breakdown_analysis.py` builds category-level score breakdowns
7. `app/ml_engine/explanation_builder.py` generates the human-facing summary
8. API returns a standardized success response

### Authentication flow

1. User registers through `POST /api/v1/auth/register`
2. Password is hashed before storage
3. User record is created in PostgreSQL
4. OTP is generated and stored in Redis with TTL
5. Verification email is sent using the HTML email template
6. User verifies email through `POST /api/v1/auth/verify-email`
7. Verified users can log in through `POST /api/v1/auth/login`
8. Access and refresh tokens are returned

## Detection Strategy

Phishing Guardian uses a hybrid scoring model.

### 1. Machine learning score

The ML layer extracts handcrafted URL features and runs a trained classifier to estimate phishing probability.

From the current code:

- `ml_score = predict_proba(...) * 100`

### 2. Rule-based score

The forensic engine checks for suspicious patterns and structural indicators such as:

- brand impersonation
- Unicode abuse
- homoglyph attacks
- suspicious subdomains
- risky TLD usage
- IP-address-based URLs
- entropy and randomness patterns
- character substitution
- linguistic phishing signals

The breakdown layer computes safety-oriented category scores, then converts them into a risk contribution.

From the current code:

- `rule_score = 100 - average(breakdown_scores)`

### 3. Final score

The final score is currently weighted toward ML:

- `final_score = 0.6 * ml_score + 0.4 * rule_score`

### 4. Risk bands

Current thresholds in `backend/app/ml_engine/risk_engine.py`:

- `>= 80`: `High`
- `>= 60`: `Medium`
- `>= 30`: `Low`
- `< 30`: `Safe`

### 5. Brand whitelist adjustment

`backend/app/ml_engine/detector.py` contains additional logic to protect legitimate known-brand domains from being over-flagged when there is no strong evidence of impersonation or structural abuse.

## Project Structure

```text
phishing-guardian/
|-- README.md
|-- backend/
|   |-- CHANGELOG.md
|   |-- requirements.txt
|   |-- alembic.ini
|   |-- app/
|   |   |-- main.py
|   |   |-- api/routes/
|   |   |-- core/
|   |   |-- database/
|   |   |-- enums/
|   |   |-- exceptions/
|   |   |-- ml_engine/
|   |   |-- models/
|   |   |-- repositories/
|   |   |-- schemas/
|   |   |-- security/
|   |   |-- services/
|   |   |-- templates/
|   |   `-- utils/
|   |-- engine/
|   |-- alembic/versions/
|   |-- test_connection.py
|   `-- test_psycopg2.py
`-- frontend/
```

## Important Backend Modules

### API routes

- `backend/app/api/routes/auth.py`
  - registration
  - login
  - email verification
  - some development test endpoints

- `backend/app/api/routes/scan.py`
  - URL analysis endpoint

- `backend/app/api/routes/health.py`
  - root and health routes exist in code
  - currently not included in `app/main.py`

### ML engine

- `backend/app/ml_engine/detector.py`
  - top-level phishing prediction flow

- `backend/app/ml_engine/risk_engine.py`
  - hybrid score calculation

- `backend/app/ml_engine/explanation_builder.py`
  - creates human-readable output

- `backend/app/ml_engine/brand_loader.py`
  - loads trusted brands from `backend/app/brands.txt`

### Rule engine

The `backend/engine/` package contains modular analyzers, including:

- `impersonation.py`
- `character_substitution.py`
- `homoglyph_analysis.py`
- `unicode_analysis.py`
- `subdomain_analysis.py`
- `tld_analysis.py`
- `ip_analysis.py`
- `pattern_analysis.py`
- `linguistic_analysis.py`
- `entropy_analysis.py`
- `dga_detection.py`
- `breakdown_analysis.py`
- `parser.py`
- `orchestrator.py`

### Persistence

The current ORM layer includes:

- `User`
- `Scan`
- `MetricType`
- `ScanMetric`

This shows the repo is moving toward storing scan history and metric-level evidence, even though the live scan endpoint does not yet write those records.

## Active API Surface

Based on `backend/app/main.py`, the application currently mounts:

- `/api/v1/auth/*`
- `/scan/*`

The health routes are defined but not mounted right now.

### Authentication endpoints

#### `POST /api/v1/auth/register`

Registers a user and sends an email verification OTP.

Request body:

```json
{
  "first_name": "Soumik",
  "last_name": "Maity",
  "email": "soumik@example.com",
  "password": "Password@123"
}
```

#### `POST /api/v1/auth/login`

Logs in a verified active user and returns JWT tokens.

Request body:

```json
{
  "email": "soumik@example.com",
  "password": "Password@123"
}
```

#### `POST /api/v1/auth/verify-email`

Verifies a user's email using a 6-digit OTP.

Request body:

```json
{
  "email": "soumik@example.com",
  "otp": "123456"
}
```

### Scan endpoint

#### `POST /scan/`

Analyzes a URL for phishing risk.

Request body:

```json
{
  "url": "https://example.com/login"
}
```

### Response format

The project uses a standardized API response envelope:

```json
{
  "success": true,
  "message": "URL analyzed successfully.",
  "data": {}
}
```

## Example Scan Response

The exact values depend on model output and rule findings, but the response shape is designed to look like this:

```json
{
  "success": true,
  "message": "URL analyzed successfully.",
  "data": {
    "url": "https://secure-paypa1.com/login",
    "is_safe": false,
    "risk_level": "High",
    "risk_score": 92.5,
    "ml_probability": 0.94,
    "rule_score": 88.0,
    "summary": "This website shows clear signs of impersonation or potential phishing.",
    "findings": [
      {
        "category": "character_substitution",
        "severity": "high"
      }
    ],
    "guidance": "This website shows signs of impersonation or deception. Avoid entering passwords or personal information.",
    "breakdown": {
      "domain_structure": 22,
      "ssl_certificate": 100,
      "ip_reputation": 100,
      "phishing_keywords": 45,
      "redirect_chains": 60,
      "domain_age": 10
    }
  }
}
```

## Tech Stack

Backend framework and API:

- FastAPI
- Uvicorn
- Pydantic v2

Machine learning and data:

- scikit-learn
- joblib
- pandas
- numpy
- Hugging Face `datasets`

Persistence and infra:

- PostgreSQL
- SQLAlchemy 2.x
- Alembic
- Redis

Security and auth:

- passlib / bcrypt
- python-jose
- FastAPI-Mail
- Jinja2 email templates

Cloud and model distribution:

- boto3
- S3 fallback for model download

## Environment Configuration

The app expects a `.env` file in `backend/` because `Settings` uses:

- `env_file=".env"`

### Required environment variables

#### Application

- `APP_NAME`
- `APP_VERSION`
- `ENVIRONMENT`
- `DEBUG`
- `HOST`
- `PORT`
- `ALLOWED_ORIGINS`

#### Model loading

- `LOCAL_MODEL_PATH`
- `AWS_REGION`
- `S3_BUCKET`
- `S3_MODEL_KEY`

#### Database

- `DATABASE_HOST`
- `DATABASE_PORT`
- `DATABASE_NAME`
- `DATABASE_USERNAME`
- `DATABASE_PASSWORD`

#### JWT

- `JWT_SECRET_KEY`
- `JWT_ALGORITHM` (optional, defaults to `HS256`)
- `JWT_ACCESS_TOKEN_EXPIRE_MINUTES` (optional)
- `JWT_REFRESH_TOKEN_EXPIRE_DAYS` (optional)

#### Email

- `MAIL_USERNAME`
- `MAIL_PASSWORD`
- `MAIL_FROM`
- `MAIL_PORT`
- `MAIL_SERVER`
- `MAIL_STARTTLS`
- `MAIL_SSL_TLS`
- `MAIL_FROM_NAME`

#### Redis

- `REDIS_HOST`
- `REDIS_PORT`
- `REDIS_DB`
- `REDIS_PASSWORD`

## Local Setup

### 1. Create a virtual environment

From `backend/`:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### 2. Install dependencies

```powershell
pip install -r requirements.txt
```

### 3. Configure infrastructure

Before running the app, make sure these services are available:

- PostgreSQL
- Redis
- SMTP credentials for email sending
- ML model artifact, either:
  - present locally at the path defined by `LOCAL_MODEL_PATH`, or
  - downloadable from S3 using valid AWS credentials

### 4. Run database migrations

From `backend/`:

```powershell
alembic upgrade head
```

### 5. Start the API

From `backend/`:

```powershell
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

Swagger UI should then be available at:

- `http://127.0.0.1:8000/docs`

## Model Loading Behavior

The model loader follows this sequence:

1. Check whether the local model file exists
2. If not, attempt S3 download
3. Load the model into memory
4. Reuse the cached model for future requests

This behavior is implemented in `backend/app/core/model_loader.py`.

Implication for deployment:

- startup will fail if the local model is missing and S3 access is unavailable

## Database Schema

Current migration history shows the following progression:

1. `5beaaa397ee2_create_users_table.py`
   - creates the `users` table

2. `11480bac1122_add_metric_tables.py`
   - creates `metric_types`
   - creates `scans`
   - creates `scan_metrics`

3. `aee27930acfa_add_role_and_last_login_at_to_users.py`
   - adds `role`
   - adds `last_login_at`

This matches the broader direction of the codebase: moving from a pure detector API toward a platform with users, persisted scan records, and future analytics/reporting support.

## Authentication and Security Notes

The authentication layer currently includes:

- password hashing
- JWT access token generation
- JWT refresh token generation
- email verification before login
- user role enum (`USER`, `ADMIN`)
- last login tracking

Operationally important details:

- email verification is required before login succeeds
- OTPs are stored in Redis with expiration
- the app currently enables permissive CORS in `app/main.py` with `allow_origins=["*"]`

## Development Utilities and Gaps

There are a few things worth knowing before using this repo in production:

- `backend/app/api/routes/auth.py` still contains test endpoints:
  - `/api/v1/auth/test-email`
  - `/api/v1/auth/test-redis`
  - `/api/v1/auth/test-otp`
- `backend/app/api/routes/health.py` is not currently included in the FastAPI app
- the scan service currently delegates to prediction only and does not save results
- `frontend/` is present as a directory but contains no implementation

These are not blockers for local development, but they are important for repo visitors evaluating maturity and deployment readiness.

## Changelog Summary

The backend changelog shows the project evolved through a set of major refactors and platform additions:

- clean FastAPI-oriented restructuring
- centralized configuration and model management
- production-style logging
- standardized exception handling and API responses
- PostgreSQL and SQLAlchemy integration
- JWT auth with email verification and Redis-backed OTP

The source changelog is available at [backend/CHANGELOG.md](backend/CHANGELOG.md).
