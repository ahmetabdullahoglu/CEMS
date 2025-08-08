"""
Module: config
Purpose: Enhanced application settings and configuration management using Pydantic
Author: CEMS Development Team
Date: 2024
"""

import secrets
from typing import List, Optional, Union, Any, Dict
from pydantic import BaseSettings, PostgresDsn, validator, Field
from pydantic.networks import AnyHttpUrl


class Settings(BaseSettings):
    """
    Enhanced application settings loaded from environment variables.
    Uses Pydantic for validation and type conversion with security focus.
    """
    
    # ==================== APPLICATION INFO ====================
    PROJECT_NAME: str = "CEMS - Currency Exchange Management System"
    VERSION: str = "1.0.0"
    DESCRIPTION: str = "Comprehensive Currency Exchange Management System"
    API_V1_STR: str = "/api/v1"
    
    # Environment
    ENVIRONMENT: str = Field(default="development", env="ENVIRONMENT")
    DEBUG: bool = Field(default=True, env="DEBUG")
    
    # ==================== ENHANCED SECURITY SETTINGS ====================
    
    # JWT Configuration
    SECRET_KEY: str = Field(default_factory=lambda: secrets.token_urlsafe(32))
    ALGORITHM: str = Field(default="HS256", env="ALGORITHM")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = Field(default=30, env="ACCESS_TOKEN_EXPIRE_MINUTES")
    REFRESH_TOKEN_EXPIRE_DAYS: int = Field(default=7, env="REFRESH_TOKEN_EXPIRE_DAYS")
    
    # Additional JWT Settings
    JWT_TOKEN_URL: str = Field(default="/api/v1/auth/login", env="JWT_TOKEN_URL")
    JWT_REFRESH_URL: str = Field(default="/api/v1/auth/refresh", env="JWT_REFRESH_URL")
    JWT_AUDIENCE: str = Field(default="cems:users", env="JWT_AUDIENCE")
    JWT_ISSUER: str = Field(default="cems", env="JWT_ISSUER")
    
    # Password Policy
    PASSWORD_MIN_LENGTH: int = Field(default=8, env="PASSWORD_MIN_LENGTH")
    PASSWORD_MAX_LENGTH: int = Field(default=128, env="PASSWORD_MAX_LENGTH")
    PASSWORD_REQUIRE_UPPERCASE: bool = Field(default=True, env="PASSWORD_REQUIRE_UPPERCASE")
    PASSWORD_REQUIRE_LOWERCASE: bool = Field(default=True, env="PASSWORD_REQUIRE_LOWERCASE")
    PASSWORD_REQUIRE_DIGIT: bool = Field(default=True, env="PASSWORD_REQUIRE_DIGIT")
    PASSWORD_REQUIRE_SPECIAL: bool = Field(default=True, env="PASSWORD_REQUIRE_SPECIAL")
    PASSWORD_HISTORY_COUNT: int = Field(default=5, env="PASSWORD_HISTORY_COUNT")  # Remember last N passwords
    
    # Account Security
    MAX_LOGIN_ATTEMPTS: int = Field(default=5, env="MAX_LOGIN_ATTEMPTS")
    ACCOUNT_LOCKOUT_DURATION_MINUTES: int = Field(default=15, env="ACCOUNT_LOCKOUT_DURATION_MINUTES")
    PASSWORD_RESET_TOKEN_EXPIRE_HOURS: int = Field(default=1, env="PASSWORD_RESET_TOKEN_EXPIRE_HOURS")
    FORCE_PASSWORD_CHANGE_DAYS: int = Field(default=90, env="FORCE_PASSWORD_CHANGE_DAYS")  # Force password change every N days
    
    # Session Management
    SESSION_TIMEOUT_MINUTES: int = Field(default=30, env="SESSION_TIMEOUT_MINUTES")
    MAX_CONCURRENT_SESSIONS: int = Field(default=3, env="MAX_CONCURRENT_SESSIONS")
    SESSION_CLEANUP_INTERVAL_HOURS: int = Field(default=1, env="SESSION_CLEANUP_INTERVAL_HOURS")
    REMEMBER_ME_DAYS: int = Field(default=30, env="REMEMBER_ME_DAYS")
    
    # Rate Limiting
    RATE_LIMIT_PER_MINUTE: int = Field(default=60, env="RATE_LIMIT_PER_MINUTE")
    RATE_LIMIT_BURST: int = Field(default=10, env="RATE_LIMIT_BURST")
    LOGIN_RATE_LIMIT_PER_MINUTE: int = Field(default=5, env="LOGIN_RATE_LIMIT_PER_MINUTE")
    API_RATE_LIMIT_PER_MINUTE: int = Field(default=1000, env="API_RATE_LIMIT_PER_MINUTE")
    
    # Two-Factor Authentication
    TWO_FACTOR_ENABLED: bool = Field(default=False, env="TWO_FACTOR_ENABLED")
    TWO_FACTOR_ISSUER: str = Field(default="CEMS", env="TWO_FACTOR_ISSUER")
    TWO_FACTOR_BACKUP_CODES_COUNT: int = Field(default=10, env="TWO_FACTOR_BACKUP_CODES_COUNT")
    TWO_FACTOR_TOKEN_VALIDITY_WINDOW: int = Field(default=1, env="TWO_FACTOR_TOKEN_VALIDITY_WINDOW")  # Time windows
    
    # API Key Settings
    API_KEY_EXPIRE_DAYS: int = Field(default=365, env="API_KEY_EXPIRE_DAYS")
    API_KEY_PREFIX: str = Field(default="cems", env="API_KEY_PREFIX")
    
    # CSRF Protection
    CSRF_ENABLED: bool = Field(default=True, env="CSRF_ENABLED")
    CSRF_TOKEN_EXPIRE_HOURS: int = Field(default=1, env="CSRF_TOKEN_EXPIRE_HOURS")
    
    # ==================== CORS CONFIGURATION ====================
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
            List of allowed hosts
        """
        if isinstance(v, str) and not v.startswith("["):
            return [i.strip() for i in v.split(",")]
        elif isinstance(v, (list, str)):
            return v
        raise ValueError(v)
    
    # ==================== DATABASE CONFIGURATION ====================
    
    # Database URLs
    DATABASE_URL: Optional[PostgresDsn] = Field(env="DATABASE_URL")
    
    # Individual PostgreSQL components (for Docker Compose)
    POSTGRES_SERVER: str = Field(default="localhost", env="POSTGRES_SERVER")
    POSTGRES_USER: str = Field(default="cems_user", env="POSTGRES_USER")
    POSTGRES_PASSWORD: str = Field(default="cems_password", env="POSTGRES_PASSWORD")
    POSTGRES_DB: str = Field(default="cems_db", env="POSTGRES_DB")
    POSTGRES_PORT: int = Field(default=5432, env="POSTGRES_PORT")
    
    @validator("DATABASE_URL", pre=True)
    def assemble_db_connection(cls, v: Optional[str], values: Dict[str, Any]) -> Any:
        """
        Assemble database URL from individual components if not provided.
        
        Args:
            v: DATABASE_URL if provided
            values: Other configuration values
            
        Returns:
            Complete database URL
        """
        if isinstance(v, str):
            return v
        
        return PostgresDsn.build(
            scheme="postgresql",
            user=values.get("POSTGRES_USER"),
            password=values.get("POSTGRES_PASSWORD"),
            host=values.get("POSTGRES_SERVER"),
            port=str(values.get("POSTGRES_PORT")),
            path=f"/{values.get('POSTGRES_DB') or ''}",
        )
    
    # Database Pool Settings
    DB_POOL_SIZE: int = Field(default=20, env="DB_POOL_SIZE")
    DB_MAX_OVERFLOW: int = Field(default=30, env="DB_MAX_OVERFLOW")
    DB_POOL_TIMEOUT: int = Field(default=30, env="DB_POOL_TIMEOUT")
    DB_POOL_RECYCLE: int = Field(default=3600, env="DB_POOL_RECYCLE")  # 1 hour
    
    # ==================== SUPERUSER CONFIGURATION ====================
    FIRST_SUPERUSER: str = Field(default="admin@cems.com", env="FIRST_SUPERUSER")
    FIRST_SUPERUSER_PASSWORD: str = Field(default="changeme123!", env="FIRST_SUPERUSER_PASSWORD")
    
    # ==================== FILE STORAGE ====================
    UPLOAD_DIRECTORY: str = Field(default="uploads/", env="UPLOAD_DIRECTORY")
    MAX_FILE_SIZE: int = Field(default=10 * 1024 * 1024, env="MAX_FILE_SIZE")  # 10MB
    ALLOWED_FILE_EXTENSIONS: List[str] = Field(
        default=["pdf", "jpg", "jpeg", "png", "xlsx", "csv"],
        env="ALLOWED_FILE_EXTENSIONS"
    )
    
    @validator("ALLOWED_FILE_EXTENSIONS", pre=True)
    def parse_file_extensions(cls, v):
        """Parse file extensions from environment variable."""
        if isinstance(v, str):
            return [ext.strip().lower() for ext in v.split(",")]
        return v
    
    # ==================== EMAIL CONFIGURATION ====================
    SMTP_TLS: bool = Field(default=True, env="SMTP_TLS")
    SMTP_PORT: Optional[int] = Field(default=587, env="SMTP_PORT")
    SMTP_HOST: Optional[str] = Field(env="SMTP_HOST")
    SMTP_USER: Optional[str] = Field(env="SMTP_USER")
    SMTP_PASSWORD: Optional[str] = Field(env="SMTP_PASSWORD")
    EMAILS_FROM_EMAIL: Optional[str] = Field(env="EMAILS_FROM_EMAIL")
    EMAILS_FROM_NAME: Optional[str] = Field(default="CEMS System", env="EMAILS_FROM_NAME")
    
    # Email Templates
    EMAIL_RESET_TOKEN_EXPIRE_HOURS: int = Field(default=48, env="EMAIL_RESET_TOKEN_EXPIRE_HOURS")
    EMAIL_VERIFICATION_TOKEN_EXPIRE_HOURS: int = Field(default=24, env="EMAIL_VERIFICATION_TOKEN_EXPIRE_HOURS")
    
    # ==================== LOGGING CONFIGURATION ====================
    LOG_LEVEL: str = Field(default="INFO", env="LOG_LEVEL")
    LOG_FORMAT: str = Field(
        default="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        env="LOG_FORMAT"
    )
    LOG_FILE: Optional[str] = Field(default="logs/cems.log", env="LOG_FILE")
    LOG_MAX_SIZE: int = Field(default=10 * 1024 * 1024, env="LOG_MAX_SIZE")  # 10MB
    LOG_BACKUP_COUNT: int = Field(default=5, env="LOG_BACKUP_COUNT")
    LOG_JSON_FORMAT: bool = Field(default=False, env="LOG_JSON_FORMAT")
    
    # Security Logging
    SECURITY_LOG_ENABLED: bool = Field(default=True, env="SECURITY_LOG_ENABLED")
    SECURITY_LOG_FILE: str = Field(default="logs/security.log", env="SECURITY_LOG_FILE")
    AUDIT_LOG_ENABLED: bool = Field(default=True, env="AUDIT_LOG_ENABLED")
    AUDIT_LOG_FILE: str = Field(default="logs/audit.log", env="AUDIT_LOG_FILE")
    
    # ==================== BUSINESS LOGIC CONFIGURATION ====================
    DEFAULT_CURRENCY: str = Field(default="USD", env="DEFAULT_CURRENCY")
    EXCHANGE_RATE_PRECISION: int = Field(default=4, env="EXCHANGE_RATE_PRECISION")
    AMOUNT_PRECISION: int = Field(default=2, env="AMOUNT_PRECISION")
    
    # Transaction Limits
    MAX_TRANSACTION_AMOUNT: float = Field(default=1000000.0, env="MAX_TRANSACTION_AMOUNT")
    MIN_TRANSACTION_AMOUNT: float = Field(default=1.0, env="MIN_TRANSACTION_AMOUNT")
    DAILY_TRANSACTION_LIMIT: float = Field(default=100000.0, env="DAILY_TRANSACTION_LIMIT")
    
    # ==================== EXTERNAL APIS CONFIGURATION ====================
    EXCHANGE_RATE_API_KEY: Optional[str] = Field(env="EXCHANGE_RATE_API_KEY")
    EXCHANGE_RATE_API_URL: str = Field(
        default="https://api.exchangerate-api.com/v4/latest/",
        env="EXCHANGE_RATE_API_URL"
    )
    EXCHANGE_RATE_CACHE_TTL: int = Field(default=300, env="EXCHANGE_RATE_CACHE_TTL")  # 5 minutes
    
    # ==================== MONITORING AND HEALTH CHECKS ====================
    HEALTH_CHECK_TIMEOUT: int = Field(default=30, env="HEALTH_CHECK_TIMEOUT")
    METRICS_ENABLED: bool = Field(default=True, env="METRICS_ENABLED")
    PERFORMANCE_MONITORING: bool = Field(default=True, env="PERFORMANCE_MONITORING")
    
    # ==================== BACKUP CONFIGURATION ====================
    BACKUP_ENABLED: bool = Field(default=True, env="BACKUP_ENABLED")
    BACKUP_SCHEDULE: str = Field(default="0 2 * * *", env="BACKUP_SCHEDULE")  # Daily at 2 AM
    BACKUP_RETENTION_DAYS: int = Field(default=30, env="BACKUP_RETENTION_DAYS")
    BACKUP_DIRECTORY: str = Field(default="backups/", env="BACKUP_DIRECTORY")
    
    # ==================== TESTING CONFIGURATION ====================
    TESTING: bool = Field(default=False, env="TESTING")
    TEST_DATABASE_URL: Optional[str] = Field(env="TEST_DATABASE_URL")
    
    # ==================== REDIS CONFIGURATION (for caching and sessions) ====================
    REDIS_URL: Optional[str] = Field(env="REDIS_URL")
    REDIS_HOST: str = Field(default="localhost", env="REDIS_HOST")
    REDIS_PORT: int = Field(default=6379, env="REDIS_PORT")
    REDIS_DB: int = Field(default=0, env="REDIS_DB")
    REDIS_PASSWORD: Optional[str] = Field(env="REDIS_PASSWORD")
    
    # Cache Settings
    CACHE_TTL_SECONDS: int = Field(default=300, env="CACHE_TTL_SECONDS")  # 5 minutes
    CACHE_ENABLED: bool = Field(default=True, env="CACHE_ENABLED")
    
    # ==================== WEBHOOKS AND NOTIFICATIONS ====================
    WEBHOOK_SECRET: Optional[str] = Field(env="WEBHOOK_SECRET")
    WEBHOOK_TIMEOUT: int = Field(default=30, env="WEBHOOK_TIMEOUT")
    
    # Notification Settings
    SLACK_WEBHOOK_URL: Optional[str] = Field(env="SLACK_WEBHOOK_URL")
    TELEGRAM_BOT_TOKEN: Optional[str] = Field(env="TELEGRAM_BOT_TOKEN")
    TELEGRAM_CHAT_ID: Optional[str] = Field(env="TELEGRAM_CHAT_ID")
    
    # ==================== FEATURE FLAGS ====================
    FEATURE_TWO_FACTOR_AUTH: bool = Field(default=False, env="FEATURE_TWO_FACTOR_AUTH")
    FEATURE_EMAIL_VERIFICATION: bool = Field(default=True, env="FEATURE_EMAIL_VERIFICATION")
    FEATURE_API_VERSIONING: bool = Field(default=True, env="FEATURE_API_VERSIONING")
    FEATURE_RATE_LIMITING: bool = Field(default=True, env="FEATURE_RATE_LIMITING")
    FEATURE_AUDIT_LOGGING: bool = Field(default=True, env="FEATURE_AUDIT_LOGGING")
    FEATURE_ADVANCED_SECURITY: bool = Field(default=True, env="FEATURE_ADVANCED_SECURITY")
    
    # ==================== VALIDATION METHODS ====================
    
    @validator("SECRET_KEY")
    def validate_secret_key(cls, v):
        """Ensure secret key is long enough for production."""
        if len(v) < 32:
            raise ValueError("SECRET_KEY must be at least 32 characters long")
        return v
    
    @validator("PASSWORD_MIN_LENGTH")
    def validate_password_min_length(cls, v):
        """Ensure minimum password length is reasonable."""
        if v < 6:
            raise ValueError("PASSWORD_MIN_LENGTH must be at least 6")
        if v > 50:
            raise ValueError("PASSWORD_MIN_LENGTH must not exceed 50")
        return v
    
    @validator("ACCESS_TOKEN_EXPIRE_MINUTES")
    def validate_token_expiry(cls, v):
        """Ensure token expiry is reasonable."""
        if v < 5:
            raise ValueError("ACCESS_TOKEN_EXPIRE_MINUTES must be at least 5")
        if v > 1440:  # 24 hours
            raise ValueError("ACCESS_TOKEN_EXPIRE_MINUTES should not exceed 1440 (24 hours)")
        return v
    
    @validator("MAX_LOGIN_ATTEMPTS")
    def validate_max_login_attempts(cls, v):
        """Ensure login attempts limit is reasonable."""
        if v < 3:
            raise ValueError("MAX_LOGIN_ATTEMPTS must be at least 3")
        if v > 20:
            raise ValueError("MAX_LOGIN_ATTEMPTS should not exceed 20")
        return v
    
    @validator("DEFAULT_CURRENCY")
    def validate_default_currency(cls, v):
        """Ensure default currency is valid ISO code."""
        if len(v) != 3 or not v.isupper():
            raise ValueError("DEFAULT_CURRENCY must be a 3-letter uppercase ISO currency code")
        return v
    
    # ==================== COMPUTED PROPERTIES ====================
    
    @property
    def is_production(self) -> bool:
        """Check if running in production environment."""
        return self.ENVIRONMENT.lower() == "production"
    
    @property
    def is_development(self) -> bool:
        """Check if running in development environment."""
        return self.ENVIRONMENT.lower() == "development"
    
    @property
    def is_testing(self) -> bool:
        """Check if running in testing mode."""
        return self.TESTING or self.ENVIRONMENT.lower() == "test"
    
    @property
    def database_url_sync(self) -> str:
        """Get synchronous database URL."""
        return str(self.DATABASE_URL)
    
    @property
    def database_url_async(self) -> str:
        """Get asynchronous database URL."""
        return str(self.DATABASE_URL).replace("postgresql://", "postgresql+asyncpg://")
    
    @property
    def security_headers(self) -> Dict[str, str]:
        """Get security headers for responses."""
        headers = {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "X-XSS-Protection": "1; mode=block",
            "Referrer-Policy": "strict-origin-when-cross-origin",
        }
        
        if self.is_production:
            headers.update({
                "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
                "Content-Security-Policy": "default-src 'self'",
            })
        
        return headers
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = True
        
    # ==================== HELPER METHODS ====================
    
    def get_jwt_settings(self) -> Dict[str, Any]:
        """Get JWT configuration as dictionary."""
        return {
            "secret_key": self.SECRET_KEY,
            "algorithm": self.ALGORITHM,
            "access_token_expire_minutes": self.ACCESS_TOKEN_EXPIRE_MINUTES,
            "refresh_token_expire_days": self.REFRESH_TOKEN_EXPIRE_DAYS,
            "token_url": self.JWT_TOKEN_URL,
            "refresh_url": self.JWT_REFRESH_URL,
            "audience": self.JWT_AUDIENCE,
            "issuer": self.JWT_ISSUER,
        }
    
    def get_password_policy(self) -> Dict[str, Any]:
        """Get password policy as dictionary."""
        return {
            "min_length": self.PASSWORD_MIN_LENGTH,
            "max_length": self.PASSWORD_MAX_LENGTH,
            "require_uppercase": self.PASSWORD_REQUIRE_UPPERCASE,
            "require_lowercase": self.PASSWORD_REQUIRE_LOWERCASE,
            "require_digit": self.PASSWORD_REQUIRE_DIGIT,
            "require_special": self.PASSWORD_REQUIRE_SPECIAL,
            "history_count": self.PASSWORD_HISTORY_COUNT,
        }
    
    def get_rate_limiting_settings(self) -> Dict[str, Any]:
        """Get rate limiting configuration."""
        return {
            "global_per_minute": self.RATE_LIMIT_PER_MINUTE,
            "burst": self.RATE_LIMIT_BURST,
            "login_per_minute": self.LOGIN_RATE_LIMIT_PER_MINUTE,
            "api_per_minute": self.API_RATE_LIMIT_PER_MINUTE,
        }
    
    def get_security_settings(self) -> Dict[str, Any]:
        """Get comprehensive security settings."""
        return {
            "max_login_attempts": self.MAX_LOGIN_ATTEMPTS,
            "lockout_duration_minutes": self.ACCOUNT_LOCKOUT_DURATION_MINUTES,
            "session_timeout_minutes": self.SESSION_TIMEOUT_MINUTES,
            "max_concurrent_sessions": self.MAX_CONCURRENT_SESSIONS,
            "two_factor_enabled": self.TWO_FACTOR_ENABLED,
            "csrf_enabled": self.CSRF_ENABLED,
            "force_password_change_days": self.FORCE_PASSWORD_CHANGE_DAYS,
        }


# Global settings instance
settings = Settings()


def get_settings() -> Settings:
    """
    Dependency to get settings instance.
    
    Returns:
        Settings: Application settings
    """
    return settings


# Validation functions for runtime checks
def validate_security_configuration() -> List[str]:
    """
    Validate security configuration and return warnings.
    
    Returns:
        List of security warnings
    """
    warnings = []
    
    if settings.is_production:
        if settings.SECRET_KEY == "your-secret-key-here-change-in-production":
            warnings.append("SECRET_KEY is using default value in production")
        
        if settings.DEBUG:
            warnings.append("DEBUG is enabled in production")
        
        if settings.FIRST_SUPERUSER_PASSWORD == "changeme123!":
            warnings.append("Default superuser password is being used in production")
        
        if not settings.SMTP_HOST:
            warnings.append("SMTP is not configured for email notifications")
        
        if settings.ACCESS_TOKEN_EXPIRE_MINUTES > 60:
            warnings.append("Access token expiry is longer than recommended for production")
    
    if settings.PASSWORD_MIN_LENGTH < 8:
        warnings.append("Password minimum length is below recommended 8 characters")
    
    if settings.MAX_LOGIN_ATTEMPTS > 10:
        warnings.append("Max login attempts is higher than recommended")
    
    return warnings


def get_cors_origins() -> List[str]:
    """Get CORS origins as list of strings."""
    return [str(origin) for origin in settings.BACKEND_CORS_ORIGINS]


def get_trusted_hosts() -> List[str]:
    """Get trusted hosts for production."""
    return settings.ALLOWED_HOSTS if settings.is_production else ["*"]