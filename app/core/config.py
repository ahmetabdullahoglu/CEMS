"""
Module: config
Purpose: Application settings and configuration management using Pydantic
Author: CEMS Development Team
Date: 2024
"""

import secrets
from typing import List, Optional, Union, Any, Dict
from pydantic import BaseSettings, PostgresDsn, validator, Field
from pydantic.networks import AnyHttpUrl


class Settings(BaseSettings):
    """
    Application settings loaded from environment variables.
    Uses Pydantic for validation and type conversion.
    """
    
    # Application Info
    PROJECT_NAME: str = "CEMS - Currency Exchange Management System"
    VERSION: str = "1.0.0"
    DESCRIPTION: str = "Comprehensive Currency Exchange Management System"
    API_V1_STR: str = "/api/v1"
    
    # Environment
    ENVIRONMENT: str = Field(default="development", env="ENVIRONMENT")
    DEBUG: bool = Field(default=True, env="DEBUG")
    
    # Security
    SECRET_KEY: str = Field(default_factory=lambda: secrets.token_urlsafe(32))
    ACCESS_TOKEN_EXPIRE_MINUTES: int = Field(default=30, env="ACCESS_TOKEN_EXPIRE_MINUTES")
    REFRESH_TOKEN_EXPIRE_DAYS: int = Field(default=7, env="REFRESH_TOKEN_EXPIRE_DAYS")
    PASSWORD_MIN_LENGTH: int = Field(default=8, env="PASSWORD_MIN_LENGTH")
    
    # CORS
    BACKEND_CORS_ORIGINS: List[AnyHttpUrl] = Field(
        default=[
            "http://localhost:3000",  # React dev server
            "http://localhost:8080",  # Vue dev server
            "http://localhost:4200",  # Angular dev server
            "http://127.0.0.1:3000",
            "http://127.0.0.1:8080",
            "http://127.0.0.1:4200"
        ],
        env="BACKEND_CORS_ORIGINS"
    )
    
    @validator("BACKEND_CORS_ORIGINS", pre=True)
    def assemble_cors_origins(cls, v: Union[str, List[str]]) -> Union[List[str], str]:
        """
        Parse CORS origins from environment variable.
        
        Args:
            v: CORS origins as string or list
            
        Returns:
            List of parsed CORS origins
        """
        if isinstance(v, str) and not v.startswith("["):
            return [i.strip() for i in v.split(",")]
        elif isinstance(v, (list, str)):
            return v
        raise ValueError(v)
    
    # Trusted Hosts (for production)
    ALLOWED_HOSTS: List[str] = Field(
        default=["localhost", "127.0.0.1", "0.0.0.0"],
        env="ALLOWED_HOSTS"
    )
    
    @validator("ALLOWED_HOSTS", pre=True)
    def assemble_allowed_hosts(cls, v: Union[str, List[str]]) -> Union[List[str], str]:
        """
        Parse allowed hosts from environment variable.
        
        Args:
            v: Allowed hosts as string or list
            
        Returns:
            List of parsed allowed hosts
        """
        if isinstance(v, str):
            return [i.strip() for i in v.split(",")]
        return v
    
    # Database Configuration
    POSTGRES_SERVER: str = Field(env="POSTGRES_SERVER", default="localhost")
    POSTGRES_USER: str = Field(env="POSTGRES_USER", default="cems_user")
    POSTGRES_PASSWORD: str = Field(env="POSTGRES_PASSWORD", default="cems_password")
    POSTGRES_DB: str = Field(env="POSTGRES_DB", default="cems_db")
    POSTGRES_PORT: str = Field(env="POSTGRES_PORT", default="5432")
    DATABASE_URL: Optional[PostgresDsn] = None
    
    @validator("DATABASE_URL", pre=True)
    def assemble_db_connection(cls, v: Optional[str], values: Dict[str, Any]) -> Any:
        """
        Construct PostgreSQL connection URL from components.
        
        Args:
            v: Existing DATABASE_URL if provided
            values: Other configuration values
            
        Returns:
            Complete PostgreSQL connection URL
        """
        if isinstance(v, str):
            return v
        return PostgresDsn.build(
            scheme="postgresql",
            user=values.get("POSTGRES_USER"),
            password=values.get("POSTGRES_PASSWORD"),
            host=values.get("POSTGRES_SERVER"),
            port=values.get("POSTGRES_PORT"),
            path=f"/{values.get('POSTGRES_DB') or ''}",
        )
    
    # Redis Configuration (for caching and sessions)
    REDIS_URL: str = Field(default="redis://localhost:6379/0", env="REDIS_URL")
    REDIS_EXPIRE_SECONDS: int = Field(default=3600, env="REDIS_EXPIRE_SECONDS")
    
    # JWT Configuration
    ALGORITHM: str = "HS256"
    JWT_SUBJECT: str = "access"
    JWT_TOKEN_PREFIX: str = "Bearer"
    
    # File Upload Configuration
    MAX_FILE_SIZE: int = Field(default=10 * 1024 * 1024, env="MAX_FILE_SIZE")  # 10MB
    ALLOWED_FILE_EXTENSIONS: List[str] = Field(
        default=[".jpg", ".jpeg", ".png", ".pdf", ".xlsx", ".csv"],
        env="ALLOWED_FILE_EXTENSIONS"
    )
    UPLOAD_DIRECTORY: str = Field(default="uploads", env="UPLOAD_DIRECTORY")
    
    # Email Configuration
    SMTP_TLS: bool = Field(default=True, env="SMTP_TLS")
    SMTP_PORT: Optional[int] = Field(default=587, env="SMTP_PORT")
    SMTP_HOST: Optional[str] = Field(env="SMTP_HOST")
    SMTP_USER: Optional[str] = Field(env="SMTP_USER")
    SMTP_PASSWORD: Optional[str] = Field(env="SMTP_PASSWORD")
    EMAILS_FROM_EMAIL: Optional[str] = Field(env="EMAILS_FROM_EMAIL")
    EMAILS_FROM_NAME: Optional[str] = Field(default="CEMS System", env="EMAILS_FROM_NAME")
    
    # Logging Configuration
    LOG_LEVEL: str = Field(default="INFO", env="LOG_LEVEL")
    LOG_FORMAT: str = Field(
        default="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        env="LOG_FORMAT"
    )
    LOG_FILE: Optional[str] = Field(default="logs/cems.log", env="LOG_FILE")
    LOG_MAX_SIZE: int = Field(default=10 * 1024 * 1024, env="LOG_MAX_SIZE")  # 10MB
    LOG_BACKUP_COUNT: int = Field(default=5, env="LOG_BACKUP_COUNT")
    
    # Business Logic Configuration
    DEFAULT_CURRENCY: str = Field(default="USD", env="DEFAULT_CURRENCY")
    EXCHANGE_RATE_PRECISION: int = Field(default=4, env="EXCHANGE_RATE_PRECISION")
    AMOUNT_PRECISION: int = Field(default=2, env="AMOUNT_PRECISION")
    
    # Rate Limiting
    RATE_LIMIT_PER_MINUTE: int = Field(default=60, env="RATE_LIMIT_PER_MINUTE")
    RATE_LIMIT_BURST: int = Field(default=10, env="RATE_LIMIT_BURST")
    
    # External APIs Configuration
    EXCHANGE_RATE_API_KEY: Optional[str] = Field(env="EXCHANGE_RATE_API_KEY")
    EXCHANGE_RATE_API_URL: str = Field(
        default="https://api.exchangerate-api.com/v4/latest/",
        env="EXCHANGE_RATE_API_URL"
    )
    
    # Monitoring and Health Checks
    HEALTH_CHECK_TIMEOUT: int = Field(default=30, env="HEALTH_CHECK_TIMEOUT")
    METRICS_ENABLED: bool = Field(default=True, env="METRICS_ENABLED")
    
    # Backup Configuration
    BACKUP_ENABLED: bool = Field(default=True, env="BACKUP_ENABLED")
    BACKUP_SCHEDULE: str = Field(default="0 2 * * *", env="BACKUP_SCHEDULE")  # Daily at 2 AM
    BACKUP_RETENTION_DAYS: int = Field(default=30, env="BACKUP_RETENTION_DAYS")
    
    # Testing Configuration
    TESTING: bool = Field(default=False, env="TESTING")
    TEST_DATABASE_URL: Optional[str] = Field(env="TEST_DATABASE_URL")
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = True


# Global settings instance
settings = Settings()


def get_settings() -> Settings:
    """
    Dependency to get settings instance.
    
    Returns:
        Settings: Application settings
    """
    return settings