# Changelog

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

---