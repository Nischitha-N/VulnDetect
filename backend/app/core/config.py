from typing import Optional

try:
    from pydantic_settings import BaseSettings
except ImportError:
    from pydantic import BaseModel as BaseSettings


class Settings(BaseSettings):
    APP_NAME: str = "VulnDetect Security Analysis Engine"
    DEBUG: bool = True
    MONGO_URI: str = "mongodb://localhost:27017"
    MONGO_DB: str = "vuln_detector"
    MAX_FILE_SIZE_MB: int = 50
    MODEL_PATH: str = "app/ml/models/final_model.joblib"

    class Config:
        env_file = ".env"


settings = Settings()

