from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    PROJECT_NAME: str = "GraphQL Shield"
    VERSION: str = "0.1.0"
    API_PREFIX: str = "/api/v1"
    DATABASE_URL: str = "sqlite:///./shield.db"
    JWT_SECRET: str = "super_secret_dev_key"
    JWT_ALGORITHM: str = "HS256"

    class Config:
        env_file = ".env"

settings = Settings()
