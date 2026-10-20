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

    # Defense-in-depth controls.
    # The vulnerable /graphql-insecure baseline exists only for benchmarking; it still
    # requires a valid token and can be switched off entirely (e.g. for deployment).
    ENABLE_INSECURE_BASELINE: bool = True
    # Allows an ADMIN to switch Layer 1 / Layer 2 on and off from the dashboard so the
    # layer ablation can be demonstrated live. Disable outside demos.
    ENABLE_LAYER_TOGGLE: bool = True
    # Maximum operations accepted in one batched (JSON array) request.
    MAX_BATCH_OPERATIONS: int = 5

    # Pydantic v2 configuration replaces the deprecated inner Config class.
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
    )


settings = Settings()

