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