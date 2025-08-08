"""
Module: exceptions
Purpose: Enhanced custom exception classes for CEMS application with security features
Author: CEMS Development Team
Date: 2024
"""

from typing import Optional, Dict, Any
from fastapi import HTTPException, status
from app.core.constants import ErrorCode


class CEMSException(HTTPException):
    """
    Base exception class for CEMS application.
    Extends FastAPI HTTPException with additional features.
    """
    
    def __init__(
        self,
        status_code: int,
        message: str,
        error_code: str,
        details: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None
    ):
        """
        Initialize CEMS exception.
        
        Args:
            status_code: HTTP status code
            message: Human-readable error message
            error_code: Application-specific error code
            details: Additional error details
            headers: Optional HTTP headers
        """
        super().__init__(status_code=status_code, detail=message, headers=headers)
        self.message = message
        self.error_code = error_code
        self.details = details or {}


# ==================== AUTHENTICATION EXCEPTIONS ====================

class AuthenticationException(CEMSException):
    """Base authentication exception."""
    
    def __init__(
        self,
        message: str = "Authentication failed",
        error_code: str = "AUTH_001",  # ErrorCode.INVALID_CREDENTIALS
        details: Optional[Dict[str, Any]] = None
    ):
        super().__init__(
            status_code=status.HTTP_401_UNAUTHORIZED,
            message=message,
            error_code=error_code,
            details=details,
            headers={"WWW-Authenticate": "Bearer"}
        )


class InvalidCredentialsException(AuthenticationException):
    """Exception raised for invalid login credentials."""
    
    def __init__(self, details: Optional[Dict[str, Any]] = None):
        super().__init__(
            message="Invalid username or password",
            error_code="AUTH_001",  # ErrorCode.INVALID_CREDENTIALS
            details=details
        )


class TokenExpiredException(AuthenticationException):
    """Exception raised when JWT token is expired."""
    
    def __init__(self, details: Optional[Dict[str, Any]] = None):
        super().__init__(
            message="Access token has expired",
            error_code="AUTH_002",  # ErrorCode.TOKEN_EXPIRED
            details=details
        )


class RefreshTokenException(AuthenticationException):
    """Exception raised for refresh token errors."""
    
    def __init__(
        self, 
        message: str = "Refresh token is invalid or expired",
        details: Optional[Dict[str, Any]] = None
    ):
        super().__init__(
            message=message,
            error_code="AUTH_005",  # ErrorCode.REFRESH_TOKEN_INVALID
            details=details
        )


class TokenRevokedException(AuthenticationException):
    """Exception raised when token has been revoked/blacklisted."""
    
    def __init__(self, details: Optional[Dict[str, Any]] = None):
        super().__init__(
            message="Token has been revoked",
            error_code="AUTH_006",  # ErrorCode.TOKEN_REVOKED
            details=details
        )


class SessionExpiredException(AuthenticationException):
    """Exception raised when user session has expired."""
    
    def __init__(self, details: Optional[Dict[str, Any]] = None):
        super().__init__(
            message="Session has expired. Please login again",
            error_code="AUTH_007",  # ErrorCode.SESSION_EXPIRED
            details=details
        )


class InvalidSessionException(AuthenticationException):
    """Exception raised for invalid session."""
    
    def __init__(self, details: Optional[Dict[str, Any]] = None):
        super().__init__(
            message="Invalid session",
            error_code="AUTH_008",  # ErrorCode.INVALID_SESSION
            details=details
        )


class AccountLockedException(AuthenticationException):
    """Exception raised when user account is locked due to failed attempts."""
    
    def __init__(
        self, 
        unlock_time: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ):
        message = "Account is temporarily locked due to multiple failed login attempts"
        if unlock_time:
            message += f". Try again after {unlock_time}"
        
        super().__init__(
            message=message,
            error_code="AUTH_009",  # ErrorCode.ACCOUNT_LOCKED
            details=details or {"unlock_time": unlock_time}
        )


class TwoFactorRequiredException(AuthenticationException):
    """Exception raised when 2FA is required."""
    
    def __init__(self, details: Optional[Dict[str, Any]] = None):
        super().__init__(
            message="Two-factor authentication is required",
            error_code="AUTH_010",  # ErrorCode.TWO_FACTOR_REQUIRED
            details=details
        )


class Invalid2FATokenException(AuthenticationException):
    """Exception raised for invalid 2FA token."""
    
    def __init__(self, details: Optional[Dict[str, Any]] = None):
        super().__init__(
            message="Invalid two-factor authentication token",
            error_code="AUTH_011",  # ErrorCode.INVALID_2FA_TOKEN
            details=details
        )


class PasswordStrengthException(CEMSException):
    """Exception raised when password doesn't meet strength requirements."""
    
    def __init__(
        self, 
        requirements: Optional[Dict[str, Any]] = None,
        details: Optional[Dict[str, Any]] = None
    ):
        message = "Password does not meet strength requirements"
        if requirements and requirements.get("suggestions"):
            suggestions = requirements["suggestions"][:3]  # Limit to 3 suggestions
            message += f": {', '.join(suggestions)}"
        
        super().__init__(
            status_code=status.HTTP_400_BAD_REQUEST,
            message=message,
            error_code="AUTH_012",  # ErrorCode.WEAK_PASSWORD
            details=details or {"requirements": requirements}
        )


class RateLimitExceededException(CEMSException):
    """Exception raised when rate limit is exceeded."""
    
    def __init__(
        self, 
        retry_after: Optional[float] = None,
        details: Optional[Dict[str, Any]] = None
    ):
        message = "Rate limit exceeded. Too many requests"
        if retry_after:
            message += f". Try again in {retry_after:.1f} seconds"
        
        headers = {}
        if retry_after:
            headers["Retry-After"] = str(int(retry_after))
        
        super().__init__(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            message=message,
            error_code="AUTH_013",  # ErrorCode.RATE_LIMIT_EXCEEDED
            details=details,
            headers=headers
        )


class InsufficientPermissionsException(CEMSException):
    """Exception raised when user lacks required permissions."""
    
    def __init__(
        self,
        required_permission: str,
        details: Optional[Dict[str, Any]] = None
    ):
        super().__init__(
            status_code=status.HTTP_403_FORBIDDEN,
            message=f"Insufficient permissions. Required: {required_permission}",
            error_code="AUTH_003",  # ErrorCode.INSUFFICIENT_PERMISSIONS
            details=details or {"required_permission": required_permission}
        )


class AccountSuspendedException(AuthenticationException):
    """Exception raised when user account is suspended."""
    
    def __init__(self, details: Optional[Dict[str, Any]] = None):
        super().__init__(
            message="User account is suspended",
            error_code="AUTH_004",  # ErrorCode.ACCOUNT_SUSPENDED
            details=details
        )


class AccountDisabledException(AuthenticationException):
    """Exception raised when user account is disabled."""
    
    def __init__(self, details: Optional[Dict[str, Any]] = None):
        super().__init__(
            message="User account is disabled",
            error_code="AUTH_014",  # ErrorCode.ACCOUNT_DISABLED
            details=details
        )


class EmailNotVerifiedException(AuthenticationException):
    """Exception raised when user email is not verified."""
    
    def __init__(self, details: Optional[Dict[str, Any]] = None):
        super().__init__(
            message="Email address is not verified. Please check your email and verify your account",
            error_code="AUTH_015",  # ErrorCode.EMAIL_NOT_VERIFIED
            details=details
        )


class PasswordResetRequiredException(AuthenticationException):
    """Exception raised when password reset is required."""
    
    def __init__(self, details: Optional[Dict[str, Any]] = None):
        super().__init__(
            message="Password reset is required",
            error_code="AUTH_016",  # ErrorCode.PASSWORD_RESET_REQUIRED
            details=details
        )


# ==================== VALIDATION EXCEPTIONS ====================

class ValidationException(CEMSException):
    """Base validation exception."""
    
    def __init__(
        self,
        message: str,
        error_code: str = "VAL_001",  # ErrorCode.INVALID_INPUT
        details: Optional[Dict[str, Any]] = None
    ):
        super().__init__(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            message=message,
            error_code=error_code,
            details=details
        )


class RequiredFieldMissingException(ValidationException):
    """Exception raised when required field is missing."""
    
    def __init__(self, field_name: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(
            message=f"Required field '{field_name}' is missing",
            error_code="VAL_002",  # ErrorCode.REQUIRED_FIELD_MISSING
            details=details or {"field_name": field_name}
        )


class InvalidFormatException(ValidationException):
    """Exception raised for invalid data format."""
    
    def __init__(
        self, 
        field_name: str, 
        expected_format: str,
        details: Optional[Dict[str, Any]] = None
    ):
        super().__init__(
            message=f"Invalid format for '{field_name}'. Expected: {expected_format}",
            error_code="VAL_003",  # ErrorCode.INVALID_FORMAT
            details=details or {
                "field_name": field_name,
                "expected_format": expected_format
            }
        )


class InvalidEmailException(ValidationException):
    """Exception raised for invalid email format."""
    
    def __init__(self, email: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(
            message=f"Invalid email format: {email}",
            error_code="VAL_004",  # ErrorCode.INVALID_EMAIL
            details=details or {"email": email}
        )


class InvalidPhoneException(ValidationException):
    """Exception raised for invalid phone number format."""
    
    def __init__(self, phone: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(
            message=f"Invalid phone number format: {phone}",
            error_code="VAL_005",  # ErrorCode.INVALID_PHONE
            details=details or {"phone": phone}
        )


class InvalidCurrencyCodeException(ValidationException):
    """Exception raised for invalid currency code."""
    
    def __init__(self, currency_code: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(
            message=f"Invalid currency code: {currency_code}",
            error_code="VAL_006",  # ErrorCode.INVALID_CURRENCY_CODE
            details=details or {"currency_code": currency_code}
        )


class InvalidAmountException(ValidationException):
    """Exception raised for invalid amount values."""
    
    def __init__(
        self, 
        amount: Any, 
        reason: str = "Invalid amount",
        details: Optional[Dict[str, Any]] = None
    ):
        super().__init__(
            message=f"{reason}: {amount}",
            error_code="VAL_007",  # ErrorCode.INVALID_AMOUNT
            details=details or {"amount": amount, "reason": reason}
        )


class ValueTooSmallException(ValidationException):
    """Exception raised when value is below minimum."""
    
    def __init__(
        self, 
        field_name: str, 
        value: Any, 
        minimum: Any,
        details: Optional[Dict[str, Any]] = None
    ):
        super().__init__(
            message=f"{field_name} value {value} is below minimum {minimum}",
            error_code="VAL_008",  # ErrorCode.VALUE_TOO_SMALL
            details=details or {
                "field_name": field_name,
                "value": value,
                "minimum": minimum
            }
        )


class ValueTooLargeException(ValidationException):
    """Exception raised when value exceeds maximum."""
    
    def __init__(
        self, 
        field_name: str, 
        value: Any, 
        maximum: Any,
        details: Optional[Dict[str, Any]] = None
    ):
        super().__init__(
            message=f"{field_name} value {value} exceeds maximum {maximum}",
            error_code="VAL_009",  # ErrorCode.VALUE_TOO_LARGE
            details=details or {
                "field_name": field_name,
                "value": value,
                "maximum": maximum
            }
        )


# ==================== BUSINESS LOGIC EXCEPTIONS ====================

class BusinessLogicException(CEMSException):
    """Base business logic exception."""
    
    def __init__(
        self,
        message: str,
        error_code: str,
        details: Optional[Dict[str, Any]] = None
    ):
        super().__init__(
            status_code=status.HTTP_400_BAD_REQUEST,
            message=message,
            error_code=error_code,
            details=details
        )


class InsufficientBalanceException(BusinessLogicException):
    """Exception raised when account has insufficient balance."""
    
    def __init__(
        self,
        available_balance: float,
        required_amount: float,
        currency: str,
        details: Optional[Dict[str, Any]] = None
    ):
        super().__init__(
            message=f"Insufficient balance. Available: {available_balance} {currency}, Required: {required_amount} {currency}",
            error_code="BIZ_001",  # ErrorCode.INSUFFICIENT_BALANCE
            details=details or {
                "available_balance": available_balance,
                "required_amount": required_amount,
                "currency": currency
            }
        )


class ExchangeRateNotAvailableException(BusinessLogicException):
    """Exception raised when exchange rate is not available."""
    
    def __init__(
        self,
        from_currency: str,
        to_currency: str,
        details: Optional[Dict[str, Any]] = None
    ):
        super().__init__(
            message=f"Exchange rate not available for {from_currency} to {to_currency}",
            error_code="BIZ_002",  # ErrorCode.RATE_NOT_AVAILABLE
            details=details or {
                "from_currency": from_currency,
                "to_currency": to_currency
            }
        )


class TransactionLimitExceededException(BusinessLogicException):
    """Exception raised when transaction limit is exceeded."""
    
    def __init__(
        self,
        limit_type: str,
        limit_amount: float,
        requested_amount: float,
        currency: str,
        details: Optional[Dict[str, Any]] = None
    ):
        super().__init__(
            message=f"{limit_type} limit exceeded. Limit: {limit_amount} {currency}, Requested: {requested_amount} {currency}",
            error_code="BIZ_003",  # ErrorCode.TRANSACTION_LIMIT_EXCEEDED
            details=details or {
                "limit_type": limit_type,
                "limit_amount": limit_amount,
                "requested_amount": requested_amount,
                "currency": currency
            }
        )


class DuplicateTransactionException(BusinessLogicException):
    """Exception raised for duplicate transaction attempts."""
    
    def __init__(
        self,
        transaction_reference: str,
        details: Optional[Dict[str, Any]] = None
    ):
        super().__init__(
            message=f"Duplicate transaction detected: {transaction_reference}",
            error_code="BIZ_004",  # ErrorCode.DUPLICATE_TRANSACTION
            details=details or {"transaction_reference": transaction_reference}
        )


class BranchClosedException(BusinessLogicException):
    """Exception raised when branch is closed for operations."""
    
    def __init__(
        self,
        branch_id: str,
        current_time: str,
        details: Optional[Dict[str, Any]] = None
    ):
        super().__init__(
            message=f"Branch {branch_id} is closed for operations at {current_time}",
            error_code="BIZ_005",  # ErrorCode.BRANCH_CLOSED
            details=details or {
                "branch_id": branch_id,
                "current_time": current_time
            }
        )


class OperationNotAllowedException(BusinessLogicException):
    """Exception raised when operation is not allowed in current state."""
    
    def __init__(
        self,
        operation: str,
        reason: str,
        details: Optional[Dict[str, Any]] = None
    ):
        super().__init__(
            message=f"Operation '{operation}' not allowed: {reason}",
            error_code="BIZ_006",  # ErrorCode.OPERATION_NOT_ALLOWED
            details=details or {
                "operation": operation,
                "reason": reason
            }
        )


# ==================== SYSTEM EXCEPTIONS ====================

class SystemException(CEMSException):
    """Base system exception."""
    
    def __init__(
        self,
        message: str,
        error_code: str,
        details: Optional[Dict[str, Any]] = None
    ):
        super().__init__(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            message=message,
            error_code=error_code,
            details=details
        )


class DatabaseException(SystemException):
    """Exception raised for database-related errors."""
    
    def __init__(
        self,
        operation: str,
        original_error: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ):
        super().__init__(
            message=f"Database error during {operation}",
            error_code="SYS_001",  # ErrorCode.DATABASE_ERROR
            details=details or {
                "operation": operation,
                "original_error": original_error
            }
        )


class ExternalAPIException(SystemException):
    """Exception raised for external API errors."""
    
    def __init__(
        self,
        api_name: str,
        status_code: Optional[int] = None,
        original_error: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ):
        super().__init__(
            message=f"External API error: {api_name}",
            error_code="SYS_002",  # ErrorCode.EXTERNAL_API_ERROR
            details=details or {
                "api_name": api_name,
                "status_code": status_code,
                "original_error": original_error
            }
        )


class FileUploadException(CEMSException):
    """Exception raised for file upload errors."""
    
    def __init__(
        self,
        reason: str,
        filename: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ):
        super().__init__(
            status_code=status.HTTP_400_BAD_REQUEST,
            message=f"File upload failed: {reason}",
            error_code="SYS_003",  # ErrorCode.FILE_UPLOAD_ERROR
            details=details or {
                "reason": reason,
                "filename": filename
            }
        )


class NetworkException(SystemException):
    """Exception raised for network-related errors."""
    
    def __init__(
        self,
        operation: str,
        original_error: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ):
        super().__init__(
            message=f"Network error during {operation}",
            error_code="SYS_004",  # ErrorCode.NETWORK_ERROR
            details=details or {
                "operation": operation,
                "original_error": original_error
            }
        )


class ServiceUnavailableException(SystemException):
    """Exception raised when service is temporarily unavailable."""
    
    def __init__(
        self,
        service_name: str,
        details: Optional[Dict[str, Any]] = None
    ):
        super().__init__(
            message=f"Service temporarily unavailable: {service_name}",
            error_code="SYS_005",  # ErrorCode.SERVICE_UNAVAILABLE
            details=details or {"service_name": service_name}
        )


# ==================== RESOURCE EXCEPTIONS ====================

class ResourceNotFoundException(CEMSException):
    """Exception raised when requested resource is not found."""
    
    def __init__(
        self,
        resource_type: str,
        resource_id: str,
        details: Optional[Dict[str, Any]] = None
    ):
        super().__init__(
            status_code=status.HTTP_404_NOT_FOUND,
            message=f"{resource_type} with ID '{resource_id}' not found",
            error_code="RES_001",  # ErrorCode.RESOURCE_NOT_FOUND
            details=details or {
                "resource_type": resource_type,
                "resource_id": resource_id
            }
        )


class ResourceConflictException(CEMSException):
    """Exception raised when resource conflict occurs."""
    
    def __init__(
        self,
        resource_type: str,
        conflict_reason: str,
        details: Optional[Dict[str, Any]] = None
    ):
        super().__init__(
            status_code=status.HTTP_409_CONFLICT,
            message=f"{resource_type} conflict: {conflict_reason}",
            error_code="RES_002",  # ErrorCode.RESOURCE_CONFLICT
            details=details or {
                "resource_type": resource_type,
                "conflict_reason": conflict_reason
            }
        )


class ResourceAlreadyExistsException(CEMSException):
    """Exception raised when trying to create a resource that already exists."""
    
    def __init__(
        self,
        resource_type: str,
        identifier: str,
        details: Optional[Dict[str, Any]] = None
    ):
        super().__init__(
            status_code=status.HTTP_409_CONFLICT,
            message=f"{resource_type} with identifier '{identifier}' already exists",
            error_code="RES_003",  # ErrorCode.RESOURCE_ALREADY_EXISTS
            details=details or {
                "resource_type": resource_type,
                "identifier": identifier
            }
        )


# ==================== UTILITY FUNCTIONS ====================

def handle_database_exception(error: Exception, operation: str) -> DatabaseException:
    """
    Convert database errors to CEMS DatabaseException.
    
    Args:
        error: Original database exception
        operation: Operation that caused the error
        
    Returns:
        DatabaseException: Formatted CEMS exception
    """
    return DatabaseException(
        operation=operation,
        original_error=str(error),
        details={"error_type": type(error).__name__}
    )


def handle_validation_error(field_errors: Dict[str, Any]) -> ValidationException:
    """
    Convert Pydantic validation errors to CEMS ValidationException.
    
    Args:
        field_errors: Field validation errors
        
    Returns:
        ValidationException: Formatted CEMS exception
    """
    error_messages = []
    for field, errors in field_errors.items():
        if isinstance(errors, list):
            error_messages.extend([f"{field}: {error}" for error in errors])
        else:
            error_messages.append(f"{field}: {errors}")
    
    return ValidationException(
        message=f"Validation failed: {'; '.join(error_messages)}",
        details={"field_errors": field_errors}
    )


def create_authentication_exception(
    error_type: str,
    details: Optional[Dict[str, Any]] = None
) -> AuthenticationException:
    """
    Factory function to create appropriate authentication exception.
    
    Args:
        error_type: Type of authentication error
        details: Additional error details
        
    Returns:
        AuthenticationException: Appropriate exception instance
    """
    error_map = {
        "invalid_credentials": InvalidCredentialsException,
        "token_expired": TokenExpiredException,
        "refresh_token_invalid": RefreshTokenException,
        "account_locked": AccountLockedException,
        "account_suspended": AccountSuspendedException,
        "account_disabled": AccountDisabledException,
        "2fa_required": TwoFactorRequiredException,
        "invalid_2fa": Invalid2FATokenException,
        "session_expired": SessionExpiredException,
        "email_not_verified": EmailNotVerifiedException,
    }
    
    exception_class = error_map.get(error_type, AuthenticationException)
    return exception_class(details=details)


def create_validation_exception(
    validation_type: str,
    field_name: str = None,
    value: Any = None,
    details: Optional[Dict[str, Any]] = None
) -> ValidationException:
    """
    Factory function to create appropriate validation exception.
    
    Args:
        validation_type: Type of validation error
        field_name: Name of the field with validation error
        value: Invalid value
        details: Additional error details
        
    Returns:
        ValidationException: Appropriate exception instance
    """
    if validation_type == "required_field":
        return RequiredFieldMissingException(field_name, details)
    elif validation_type == "invalid_email":
        return InvalidEmailException(value, details)
    elif validation_type == "invalid_phone":
        return InvalidPhoneException(value, details)
    elif validation_type == "invalid_currency":
        return InvalidCurrencyCodeException(value, details)
    elif validation_type == "invalid_amount":
        return InvalidAmountException(value, details=details)
    else:
        return ValidationException(
            f"Validation failed for {field_name}: {value}",
            details=details
        )