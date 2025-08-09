"""
Module: constants
Purpose: System-wide constants for CEMS application
Author: CEMS Development Team
Date: 2024
"""

from enum import Enum
from typing import Dict, List


# ==================== USER & AUTHENTICATION CONSTANTS ====================

class UserRole(str, Enum):
    """User roles in the system."""
    SUPER_ADMIN = "super_admin"
    ADMIN = "admin"
    BRANCH_MANAGER = "branch_manager"
    CASHIER = "cashier"
    ACCOUNTANT = "accountant"
    AUDITOR = "auditor"


class UserStatus(str, Enum):
    """User account status."""
    ACTIVE = "active"
    INACTIVE = "inactive"
    SUSPENDED = "suspended"
    PENDING = "pending"


# ==================== CURRENCY CONSTANTS ====================

class CurrencyCode(str, Enum):
    """Supported currency codes (ISO 4217)."""
    USD = "USD"  # US Dollar
    EUR = "EUR"  # Euro
    GBP = "GBP"  # British Pound
    SAR = "SAR"  # Saudi Riyal
    AED = "AED"  # UAE Dirham
    EGP = "EGP"  # Egyptian Pound
    JOD = "JOD"  # Jordanian Dinar
    KWD = "KWD"  # Kuwaiti Dinar
    QAR = "QAR"  # Qatari Riyal
    BHD = "BHD"  # Bahraini Dinar
    TRY = "TRY"  # Turkish Lira
    JPY = "JPY"  # Japanese Yen
    CHF = "CHF"  # Swiss Franc
    CAD = "CAD"  # Canadian Dollar
    AUD = "AUD"  # Australian Dollar


class ExchangeRateType(str, Enum):
    """Exchange rate types."""
    BUY = "buy"      # Rate for buying foreign currency
    SELL = "sell"    # Rate for selling foreign currency
    MID = "mid"      # Middle rate (average of buy/sell)


# Currency symbols mapping
CURRENCY_SYMBOLS: Dict[str, str] = {
    "USD": "$",
    "EUR": "€",
    "GBP": "£",
    "SAR": "﷼",
    "AED": "د.إ",
    "EGP": "£",
    "JOD": "د.أ",
    "KWD": "د.ك",
    "QAR": "ر.ق",
    "BHD": "د.ب",
    "TRY": "₺",
    "JPY": "¥",
    "CHF": "CHF",
    "CAD": "C$",
    "AUD": "A$"
}

# Currency names mapping
CURRENCY_NAMES: Dict[str, str] = {
    "USD": "US Dollar",
    "EUR": "Euro",
    "GBP": "British Pound",
    "SAR": "Saudi Riyal",
    "AED": "UAE Dirham",
    "EGP": "Egyptian Pound",
    "JOD": "Jordanian Dinar",
    "KWD": "Kuwaiti Dinar",
    "QAR": "Qatari Riyal",
    "BHD": "Bahraini Dinar",
    "TRY": "Turkish Lira",
    "JPY": "Japanese Yen",
    "CHF": "Swiss Franc",
    "CAD": "Canadian Dollar",
    "AUD": "Australian Dollar"
}


# ==================== TRANSACTION CONSTANTS ====================

class TransactionType(str, Enum):
    """Transaction types in the system."""
    CURRENCY_EXCHANGE = "currency_exchange"
    CASH_DEPOSIT = "cash_deposit"
    CASH_WITHDRAWAL = "cash_withdrawal"
    TRANSFER = "transfer"
    COMMISSION = "commission"
    VAULT_DEPOSIT = "vault_deposit"
    VAULT_WITHDRAWAL = "vault_withdrawal"
    BALANCE_ADJUSTMENT = "balance_adjustment"
    REFUND = "refund"


class TransactionStatus(str, Enum):
    """Transaction status."""
    PENDING = "pending"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    FAILED = "failed"
    REVERSED = "reversed"


class PaymentMethod(str, Enum):
    """Payment methods."""
    CASH = "cash"
    BANK_TRANSFER = "bank_transfer"
    CREDIT_CARD = "credit_card"
    DEBIT_CARD = "debit_card"
    DIGITAL_WALLET = "digital_wallet"
    CHECK = "check"


# ==================== BUSINESS RULES CONSTANTS ====================

# Transaction limits
TRANSACTION_LIMITS: Dict[str, Dict[str, float]] = {
    "DAILY": {
        "USD": 50000.00,
        "EUR": 45000.00,
        "GBP": 40000.00,
        "SAR": 187500.00,
        "AED": 183750.00,
        "DEFAULT": 10000.00
    },
    "SINGLE": {
        "USD": 10000.00,
        "EUR": 9000.00,
        "GBP": 8000.00,
        "SAR": 37500.00,
        "AED": 36750.00,
        "DEFAULT": 2000.00
    }
}

# Commission rates (percentage)
COMMISSION_RATES: Dict[str, float] = {
    "STANDARD": 0.25,      # 0.25%
    "VIP": 0.15,           # 0.15%
    "PREMIUM": 0.10,       # 0.10%
    "MINIMUM": 1.00,       # Minimum commission amount
}

# Exchange rate margins (percentage)
EXCHANGE_RATE_MARGINS: Dict[str, float] = {
    "BUY": 0.02,    # 2% margin for buying
    "SELL": 0.02,   # 2% margin for selling
}

# Working hours
WORKING_HOURS: Dict[str, str] = {
    "OPEN": "08:00",
    "CLOSE": "18:00",
    "TIMEZONE": "UTC+3"
}


# ==================== SYSTEM CONSTANTS ====================

class LogLevel(str, Enum):
    """Logging levels."""
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class NotificationType(str, Enum):
    """Notification types."""
    EMAIL = "email"
    SMS = "sms"
    PUSH = "push"
    IN_APP = "in_app"
    SYSTEM_ALERT = "system_alert"


class ReportType(str, Enum):
    """Report types."""
    DAILY_SUMMARY = "daily_summary"
    TRANSACTION_REPORT = "transaction_report"
    CURRENCY_REPORT = "currency_report"
    USER_ACTIVITY = "user_activity"
    COMMISSION_REPORT = "commission_report"
    VAULT_REPORT = "vault_report"
    AUDIT_REPORT = "audit_report"
    FINANCIAL_STATEMENT = "financial_statement"


class AuditAction(str, Enum):
    """Audit trail actions."""
    CREATE = "create"
    UPDATE = "update"
    DELETE = "delete"
    LOGIN = "login"
    LOGOUT = "logout"
    TRANSACTION = "transaction"
    RATE_UPDATE = "rate_update"
    SYSTEM_CONFIG = "system_config"


# ==================== ERROR CODES ====================

class ErrorCode(str, Enum):
    """System error codes."""
    # Authentication errors
    INVALID_CREDENTIALS = "AUTH_001"
    TOKEN_EXPIRED = "AUTH_002"
    INSUFFICIENT_PERMISSIONS = "AUTH_003"
    ACCOUNT_SUSPENDED = "AUTH_004"
    
    # Validation errors
    INVALID_INPUT = "VAL_001"
    REQUIRED_FIELD_MISSING = "VAL_002"
    INVALID_CURRENCY_CODE = "VAL_003"
    INVALID_AMOUNT = "VAL_004"
    
    # Business logic errors
    INSUFFICIENT_BALANCE = "BIZ_001"
    RATE_NOT_AVAILABLE = "BIZ_002"
    TRANSACTION_LIMIT_EXCEEDED = "BIZ_003"
    DUPLICATE_TRANSACTION = "BIZ_004"
    BRANCH_CLOSED = "BIZ_005"
    
    # System errors
    DATABASE_ERROR = "SYS_001"
    EXTERNAL_API_ERROR = "SYS_002"
    FILE_UPLOAD_ERROR = "SYS_003"
    NETWORK_ERROR = "SYS_004"
    INTERNAL_ERROR = "SYS_005"


# ==================== FORMATTING CONSTANTS ====================

# Number formatting
DECIMAL_PLACES: Dict[str, int] = {
    "AMOUNT": 2,
    "RATE": 4,
    "COMMISSION": 2,
    "PERCENTAGE": 2
}

# Date/Time formats
DATE_FORMATS: Dict[str, str] = {
    "API": "%Y-%m-%d",
    "DISPLAY": "%d/%m/%Y",
    "DATETIME": "%Y-%m-%d %H:%M:%S",
    "TIMESTAMP": "%Y%m%d_%H%M%S"
}

# File formats
SUPPORTED_FILE_FORMATS: List[str] = [
    "application/pdf",
    "image/jpeg",
    "image/png",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "text/csv"
]

# API Response formats
API_RESPONSE_FORMATS: Dict[str, str] = {
    "SUCCESS": "success",
    "ERROR": "error",
    "WARNING": "warning",
    "INFO": "info"
}


# ==================== REGEX PATTERNS ====================

REGEX_PATTERNS: Dict[str, str] = {
    "EMAIL": r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$",
    "PHONE": r"^\+?[1-9]\d{1,14}$",
    "CURRENCY_CODE": r"^[A-Z]{3}$",
    "TRANSACTION_ID": r"^TXN\d{10}$",
    "USER_ID": r"^USR\d{8}$",
    "BRANCH_ID": r"^BRN\d{6}$"
}


# ==================== DEFAULT VALUES ====================

DEFAULT_VALUES: Dict[str, any] = {
    "PAGE_SIZE": 20,
    "MAX_PAGE_SIZE": 100,
    "SESSION_TIMEOUT": 1800,  # 30 minutes
    "TOKEN_REFRESH_BUFFER": 300,  # 5 minutes
    "RATE_CACHE_TTL": 300,  # 5 minutes
    "MAX_LOGIN_ATTEMPTS": 5,
    "ACCOUNT_LOCKOUT_DURATION": 900,  # 15 minutes
}

# ==================== ADDITIONAL SECURITY CONSTANTS ====================
# إضافات للملف الموجود app/core/constants.py

# Security Event Types for Audit Logging
class SecurityEventType(str, Enum):
    """Security event types for audit logging."""
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILED = "login_failed"
    LOGOUT = "logout"
    PASSWORD_CHANGE = "password_change"
    PASSWORD_RESET_REQUEST = "password_reset_request"
    PASSWORD_RESET_CONFIRM = "password_reset_confirm"
    TOKEN_REFRESH = "token_refresh"
    TOKEN_REVOKED = "token_revoked"
    ACCOUNT_LOCKED = "account_locked"
    ACCOUNT_UNLOCKED = "account_unlocked"
    ROLE_ASSIGNED = "role_assigned"
    ROLE_REMOVED = "role_removed"
    PERMISSION_DENIED = "permission_denied"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    TWO_FACTOR_ENABLED = "two_factor_enabled"
    TWO_FACTOR_DISABLED = "two_factor_disabled"
    SESSION_CREATED = "session_created"
    SESSION_TERMINATED = "session_terminated"
    API_KEY_CREATED = "api_key_created"
    API_KEY_REVOKED = "api_key_revoked"


# Password Strength Levels
class PasswordStrength(str, Enum):
    """Password strength levels."""
    VERY_WEAK = "very_weak"
    WEAK = "weak"
    MODERATE = "moderate"
    STRONG = "strong"
    VERY_STRONG = "very_strong"


# Token Types
class TokenType(str, Enum):
    """JWT token types."""
    ACCESS = "access"
    REFRESH = "refresh"
    RESET = "reset"
    VERIFICATION = "verification"
    ACTIVATION = "activation"
    TWO_FACTOR = "two_factor"


# Session Status
class SessionStatus(str, Enum):
    """User session status."""
    ACTIVE = "active"
    EXPIRED = "expired"
    TERMINATED = "terminated"
    INVALID = "invalid"


# Rate Limit Types
class RateLimitType(str, Enum):
    """Rate limit types for different operations."""
    LOGIN = "login"
    PASSWORD_RESET = "password_reset"
    API_GENERAL = "api_general"
    TOKEN_REFRESH = "token_refresh"
    TWO_FACTOR = "two_factor"


# Additional Error Codes for Security
class SecurityErrorCode(str, Enum):
    """Security-specific error codes."""
    # Authentication errors (AUTH_xxx)
    INVALID_CREDENTIALS = "AUTH_001"
    TOKEN_EXPIRED = "AUTH_002"
    INSUFFICIENT_PERMISSIONS = "AUTH_003"
    ACCOUNT_SUSPENDED = "AUTH_004"
    REFRESH_TOKEN_INVALID = "AUTH_005"
    TOKEN_REVOKED = "AUTH_006"
    SESSION_EXPIRED = "AUTH_007"
    INVALID_SESSION = "AUTH_008"
    ACCOUNT_LOCKED = "AUTH_009"
    TWO_FACTOR_REQUIRED = "AUTH_010"
    INVALID_2FA_TOKEN = "AUTH_011"
    WEAK_PASSWORD = "AUTH_012"
    RATE_LIMIT_EXCEEDED = "AUTH_013"
    ACCOUNT_DISABLED = "AUTH_014"
    EMAIL_NOT_VERIFIED = "AUTH_015"
    PASSWORD_RESET_REQUIRED = "AUTH_016"
    
    # Validation errors (VAL_xxx)
    INVALID_INPUT = "VAL_001"
    REQUIRED_FIELD_MISSING = "VAL_002"
    INVALID_FORMAT = "VAL_003"
    VALUE_TOO_LONG = "VAL_004"
    VALUE_TOO_SHORT = "VAL_005"
    DUPLICATE_VALUE = "VAL_006"


# Security Configuration Defaults
SECURITY_DEFAULTS: Dict[str, Any] = {
    # Password Policy
    "password_min_length": 8,
    "password_max_length": 128,
    "password_require_uppercase": True,
    "password_require_lowercase": True,
    "password_require_digit": True,
    "password_require_special": True,
    "password_history_count": 5,
    
    # Account Security
    "max_login_attempts": 5,
    "account_lockout_duration_minutes": 30,
    "session_timeout_minutes": 60,
    "max_concurrent_sessions": 3,
    "force_password_change_days": 90,
    
    # Token Configuration
    "access_token_expire_minutes": 30,
    "refresh_token_expire_days": 7,
    "reset_token_expire_minutes": 60,
    "verification_token_expire_hours": 24,
    
    # Rate Limiting
    "rate_limit_per_minute": 100,
    "login_rate_limit_per_minute": 10,
    "password_reset_rate_limit_per_hour": 3,
    "api_rate_limit_per_minute": 1000,
    
    # Two-Factor Authentication
    "totp_issuer": "CEMS",
    "totp_algorithm": "SHA1",
    "totp_digits": 6,
    "totp_period": 30,
    "backup_codes_count": 10,
    
    # Security Headers
    "csrf_enabled": True,
    "csrf_cookie_secure": True,
    "csrf_cookie_httponly": True,
    "secure_headers_enabled": True,
}


# Permission Categories
PERMISSION_CATEGORIES: Dict[str, List[str]] = {
    # User Management
    "user": [
        "user.view",
        "user.create", 
        "user.update",
        "user.delete",
        "user.manage_roles",
        "user.reset_password",
        "user.activate",
        "user.deactivate"
    ],
    
    # Role Management
    "role": [
        "role.view",
        "role.create",
        "role.update", 
        "role.delete",
        "role.assign",
        "role.revoke"
    ],
    
    # Branch Management
    "branch": [
        "branch.view",
        "branch.create",
        "branch.update",
        "branch.delete",
        "branch.manage",
        "branch.balance_view",
        "branch.balance_update"
    ],
    
    # Transaction Operations
    "transaction": [
        "transaction.view",
        "transaction.create",
        "transaction.update",
        "transaction.delete",
        "transaction.approve",
        "transaction.reverse",
        "transaction.export"
    ],
    
    # Customer Management
    "customer": [
        "customer.view",
        "customer.create",
        "customer.update",
        "customer.delete",
        "customer.search"
    ],
    
    # Currency Management
    "currency": [
        "currency.view",
        "currency.create",
        "currency.update",
        "currency.delete",
        "currency.rate_update"
    ],
    
    # Vault Operations
    "vault": [
        "vault.view",
        "vault.deposit",
        "vault.withdraw",
        "vault.balance_view",
        "vault.transfer"
    ],
    
    # Reporting
    "report": [
        "report.view",
        "report.generate",
        "report.export",
        "report.branch",
        "report.financial",
        "report.audit"
    ],
    
    # Administration
    "admin": [
        "admin.system_config",
        "admin.user_management",
        "admin.security_settings",
        "admin.audit_logs",
        "admin.maintenance"
    ],
    
    # Security Operations
    "security": [
        "security.audit_logs",
        "security.session_management",
        "security.role_management",
        "security.password_policy",
        "security.two_factor_management"
    ]
}


# Default Role Permissions
DEFAULT_ROLE_PERMISSIONS: Dict[str, List[str]] = {
    UserRole.SUPER_ADMIN.value: ["*"],  # All permissions
    
    UserRole.ADMIN.value: [
        "admin.*",
        "user.*", 
        "role.*",
        "branch.*",
        "currency.*",
        "transaction.*",
        "customer.*",
        "vault.*",
        "report.*",
        "security.*"
    ],
    
    UserRole.BRANCH_MANAGER.value: [
        "branch.manage",
        "branch.balance_view",
        "user.view",
        "transaction.*",
        "customer.*",
        "report.branch",
        "report.financial",
        "vault.view",
        "vault.balance_view"
    ],
    
    UserRole.CASHIER.value: [
        "transaction.view",
        "transaction.create",
        "customer.view",
        "customer.create",
        "customer.update",
        "currency.view",
        "branch.balance_view"
    ],
    
    UserRole.ACCOUNTANT.value: [
        "transaction.view",
        "transaction.export",
        "report.financial",
        "report.generate",
        "customer.view",
        "branch.balance_view",
        "vault.balance_view"
    ],
    
    UserRole.AUDITOR.value: [
        "transaction.view",
        "report.audit",
        "report.view",
        "user.view",
        "branch.view",
        "security.audit_logs"
    ]
}


# Security Validation Patterns
SECURITY_PATTERNS: Dict[str, str] = {
    "password_strong": r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$",
    "username_valid": r"^[a-zA-Z0-9_.-]{3,50}$",
    "session_id": r"^[a-zA-Z0-9]{32,}$",
    "token_jwt": r"^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_.+/=]*$",
    "ip_address": r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$",
    "user_agent": r"^[a-zA-Z0-9\s\(\)\[\]\{\};:,.\-_/\\]{1,500}$"
}


# Security HTTP Status Codes
SECURITY_HTTP_CODES: Dict[str, int] = {
    "unauthorized": 401,
    "forbidden": 403,
    "account_locked": 423,
    "rate_limited": 429,
    "token_expired": 401,
    "invalid_credentials": 401,
    "insufficient_permissions": 403,
    "account_suspended": 401,
    "session_expired": 401,
    "two_factor_required": 202,  # Accepted but additional action required
    "password_reset_required": 403
}


# Security Headers Configuration
SECURITY_HEADERS: Dict[str, str] = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY", 
    "X-XSS-Protection": "1; mode=block",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
    "Cache-Control": "no-store, no-cache, must-revalidate, private",
    "Pragma": "no-cache"
}


# Production Security Headers (additional)
PRODUCTION_SECURITY_HEADERS: Dict[str, str] = {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
    "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'",
    "Expect-CT": "max-age=86400, enforce"
}


# Audit Log Categories  
AUDIT_CATEGORIES: Dict[str, List[str]] = {
    "authentication": [
        SecurityEventType.LOGIN_SUCCESS.value,
        SecurityEventType.LOGIN_FAILED.value,
        SecurityEventType.LOGOUT.value,
        SecurityEventType.TOKEN_REFRESH.value
    ],
    
    "authorization": [
        SecurityEventType.PERMISSION_DENIED.value,
        SecurityEventType.ROLE_ASSIGNED.value,
        SecurityEventType.ROLE_REMOVED.value
    ],
    
    "account_management": [
        SecurityEventType.PASSWORD_CHANGE.value,
        SecurityEventType.ACCOUNT_LOCKED.value,
        SecurityEventType.ACCOUNT_UNLOCKED.value
    ],
    
    "security_features": [
        SecurityEventType.TWO_FACTOR_ENABLED.value,
        SecurityEventType.TWO_FACTOR_DISABLED.value,
        SecurityEventType.API_KEY_CREATED.value,
        SecurityEventType.API_KEY_REVOKED.value
    ]
}


# Risk Levels for Security Events
SECURITY_RISK_LEVELS: Dict[str, str] = {
    SecurityEventType.LOGIN_SUCCESS.value: "low",
    SecurityEventType.LOGIN_FAILED.value: "medium", 
    SecurityEventType.ACCOUNT_LOCKED.value: "high",
    SecurityEventType.PERMISSION_DENIED.value: "medium",
    SecurityEventType.SUSPICIOUS_ACTIVITY.value: "critical",
    SecurityEventType.PASSWORD_CHANGE.value: "medium",
    SecurityEventType.ROLE_ASSIGNED.value: "high",
    SecurityEventType.ROLE_REMOVED.value: "high",
    SecurityEventType.TWO_FACTOR_DISABLED.value: "high"
}