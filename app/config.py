from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    DATABASE_URL: str = "sqlite:///netsentinel.db"
    ABUSEIPDB_API_KEY: str = ""
    VIRUSTOTAL_API_KEY: str = ""
    OTX_API_KEY: str = ""
    LOG_LEVEL: str = "INFO"
    LOG_FILE: str = ""


Config = Settings()
