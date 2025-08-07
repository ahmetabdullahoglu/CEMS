"""
Module: exceptions
Purpose: Custom exception classes for CEMS application
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
        error_code: str = ErrorCode.INVALID_CREDENTIALS,
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
            error_code=ErrorCode.INVALID_CREDENTIALS,
            details=details
        )


class TokenExpiredException(AuthenticationException):
    """Exception raised when JWT token is expired."""
    
    def __init__(self, details: Optional[Dict[str, Any]] = None):
        super().__init__(
            message="Access token has expired",
            error_code=ErrorCode.TOKEN_EXPIRED,
            details=details
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
            error_code=ErrorCode.INSUFFICIENT_PERMISSIONS,
            details=details or {"required_permission": required_permission}
        )


class AccountSuspendedException(AuthenticationException):
    """Exception raised when user account is suspended."""
    
    def __init__(self, details: Optional[Dict[str, Any]] = None):
        super().__init__(
            message="User account is suspended",
            error_code=ErrorCode.ACCOUNT_SUSPENDED,
            details=details
        )


# ==================== VALIDATION EXCEPTIONS ====================

class ValidationException(CEMSException):
    """Base validation exception."""
    
    def __init__(
        self,
        message: str,
        error_code: str = ErrorCode.INVALID_INPUT,
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
            error_code=ErrorCode.REQUIRED_FIELD_MISSING,
            details=details or {"field_name": field_name}
        )


class InvalidCurrencyCodeException(ValidationException):
    """Exception raised for invalid currency code."""
    
    def __init__(self, currency_code: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(
            message=f"Invalid currency code: {currency_code}",
            error_code=ErrorCode.INVALID_CURRENCY_CODE,
            details=details or {"currency_code": currency_code}
        )


class InvalidAmountException(ValidationException):
    """Exception raised for invalid amount values."""
    
    def __init__(
        self,
        amount: Any,
        reason: str = "Invalid amount format or value",
        details: Optional[Dict[str, Any]] = None
    ):
        super().__init__(
            message=f"{reason}: {amount}",
            error_code=ErrorCode.INVALID_AMOUNT,
            details=details or {"amount": str(amount), "reason": reason}
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
    """Exception raised when account balance is insufficient."""
    
    def __init__(
        self,
        available_balance: float,
        requested_amount: float,
        currency: str,
        details: Optional[Dict[str, Any]] = None
    ):
        super().__init__(
            message=f"Insufficient balance. Available: {available_balance} {currency}, Requested: {requested_amount} {currency}",
            error_code=ErrorCode.INSUFFICIENT_BALANCE,
            details=details or {
                "available_balance": available_balance,
                "requested_amount": requested_amount,
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
            error_code=ErrorCode.RATE_NOT_AVAILABLE,
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
            error_code=ErrorCode.TRANSACTION_LIMIT_EXCEEDED,
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
            error_code=ErrorCode.DUPLICATE_TRANSACTION,
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
            error_code=ErrorCode.BRANCH_CLOSED,
            details=details or {
                "branch_id": branch_id,
                "current_time": current_time
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
            error_code=ErrorCode.DATABASE_ERROR,
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
            error_code=ErrorCode.EXTERNAL_API_ERROR,
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
            error_code=ErrorCode.FILE_UPLOAD_ERROR,
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
            error_code=ErrorCode.NETWORK_ERROR,
            details=details or {
                "operation": operation,
                "original_error": original_error
            }
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
            error_code="RESOURCE_NOT_FOUND",
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
            error_code="RESOURCE_CONFLICT",
            details=details or {
                "resource_type": resource_type,
                "conflict_reason": conflict_reason
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