from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    PROJECT_NAME: str = "GraphQL Shield"
    VERSION: str = "0.1.0"
    API_PREFIX: str = "/api/v1"
    DATABASE_URL: str = "sqlite:///./shield.db"

    # Development-only fallback.
    # Set a securely generated JWT_SECRET in your local .env file.
    # Do not use this fallback secret in production.
    JWT_SECRET: str = (
        "dev-only-change-this-secret-in-env-use-32-random-bytes-minimum"
    )
    JWT_ALGORITHM: str = "HS256"

    # "development" or "production". Production refuses to start with the
    # development JWT secret above.
    ENVIRONMENT: str = "development"

    # Defense-in-depth controls.
    # The vulnerable /graphql-insecure baseline exists only for benchmarking; it still
    # requires a valid token and is off unless enabled (ENABLE_INSECURE_BASELINE=true).
    ENABLE_INSECURE_BASELINE: bool = False
    # Allows an ADMIN to switch Layer 1 / Layer 2 on and off from the dashboard so the
    # layer ablation can be demonstrated live. The switch is process-wide (it affects
    # every user), so it is off unless enabled (ENABLE_LAYER_TOGGLE=true) for a demo.
    ENABLE_LAYER_TOGGLE: bool = False
    # Maximum operations accepted in one batched (JSON array) request.
    MAX_BATCH_OPERATIONS: int = 5

    # Query cost limits applied to every GraphQL operation.
    MAX_QUERY_DEPTH: int = 10
    MAX_QUERY_ALIASES: int = 15
    MAX_QUERY_TOKENS: int = 2000
    ENABLE_INTROSPECTION: bool = True

    # Account protection (app/core/accounts.py).
    ACCESS_TOKEN_MINUTES: int = 60
    # Wrong passwords for one username, or from one client address, within the window
    # lock that username or address for LOGIN_LOCK_SECONDS.
    LOGIN_MAX_FAILURES: int = 5
    LOGIN_IP_MAX_FAILURES: int = 20
    LOGIN_WINDOW_SECONDS: int = 900
    LOGIN_LOCK_SECONDS: int = 900

    # Pydantic v2 configuration replaces the deprecated inner Config class.
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
    )


DEV_JWT_SECRET = Settings.model_fields["JWT_SECRET"].default

settings = Settings()


def check_production_settings() -> None:
    """Refuse to run in production with the published development JWT secret."""
    if settings.ENVIRONMENT.lower() == "production" and settings.JWT_SECRET == DEV_JWT_SECRET:
        raise RuntimeError("JWT_SECRET must be set when ENVIRONMENT=production")

