from pydantic_settings import BaseSettings
from typing import Optional

class Settings(BaseSettings):
    APP_NAME: str = "AI Code Vulnerability Detector"
    DEBUG: bool = True
    MONGO_URI: str = "mongodb://localhost:27017"
    MONGO_DB: str = "vuln_detector"
    MAX_FILE_SIZE_MB: int = 50
    MODEL_PATH: str = "app/ml/trained_model.joblib"

    class Config:
        env_file = ".env"

settings = Settings()
