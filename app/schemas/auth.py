"""
Module: auth
Purpose: Authentication and authorization schemas for CEMS application
Author: CEMS Development Team
Date: 2024
"""

from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field, EmailStr, validator, SecretStr
from app.core.constants import UserRole, UserStatus


# ==================== BASE SCHEMAS ====================

class BaseResponse(BaseModel):
    """Base response schema with common fields."""
    
    success: bool = Field(default=True, description="Operation success status")
    message: str = Field(default="Operation completed successfully", description="Response message")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Response timestamp")


class ErrorResponse(BaseResponse):
    """Error response schema."""
    
    success: bool = Field(default=False, description="Operation success status")
    error_code: str = Field(description="Application-specific error code")
    details: Optional[Dict[str, Any]] = Field(default=None, description="Additional error details")


# ==================== LOGIN SCHEMAS ====================

class LoginRequest(BaseModel):
    """Schema for login requests."""
    
    username: str = Field(
        ...,
        min_length=3,
        max_length=50,
        description="Username or email address",
        example="admin"
    )
    password: SecretStr = Field(
        ...,
        min_length=6,
        max_length=128,
        description="User password",
        example="password123"
    )
    remember_me: bool = Field(
        default=False,
        description="Whether to create a longer-lived session"
    )
    ip_address: Optional[str] = Field(
        default=None,
        description="Client IP address (auto-detected if not provided)"
    )
    user_agent: Optional[str] = Field(
        default=None,
        description="Client user agent (auto-detected if not provided)"
    )
    
    @validator('username')
    def validate_username(cls, v):
        """Validate username format."""
        v = v.strip()
        if not v:
            raise ValueError("Username cannot be empty")
        return v.lower()


class LoginWith2FARequest(LoginRequest):
    """Schema for login requests with 2FA."""
    
    two_factor_token: str = Field(
        ...,
        min_length=6,
        max_length=6,
        regex=r"^\d{6}$",
        description="6-digit 2FA token",
        example="123456"
    )


class LoginResponse(BaseResponse):
    """Schema for successful login responses."""
    
    access_token: str = Field(description="JWT access token")
    refresh_token: str = Field(description="JWT refresh token")
    token_type: str = Field(default="bearer", description="Token type")
    expires_in: int = Field(description="Token expiry time in seconds")
    refresh_expires_in: int = Field(description="Refresh token expiry time in seconds")
    
    # User information
    user_id: int = Field(description="User ID")
    username: str = Field(description="Username")
    email: EmailStr = Field(description="User email")
    full_name: str = Field(description="User's full name")
    roles: List[str] = Field(description="User roles")
    permissions: List[str] = Field(description="User permissions")
    
    # Session information
    session_id: str = Field(description="Session identifier")
    last_login: Optional[datetime] = Field(description="Previous login timestamp")
    
    # Security flags
    is_2fa_enabled: bool = Field(description="Whether 2FA is enabled")
    must_change_password: bool = Field(default=False, description="Whether password change is required")
    password_expires_in_days: Optional[int] = Field(description="Days until password expires")


class Login2FARequiredResponse(BaseResponse):
    """Schema for responses requiring 2FA."""
    
    message: str = Field(default="Two-factor authentication required")
    temp_token: str = Field(description="Temporary token for 2FA completion")
    backup_codes_available: int = Field(description="Number of backup codes available")


# ==================== TOKEN SCHEMAS ====================

class TokenRequest(BaseModel):
    """Base schema for token requests."""
    
    grant_type: str = Field(description="OAuth2 grant type")


class RefreshTokenRequest(TokenRequest):
    """Schema for refresh token requests."""
    
    grant_type: str = Field(default="refresh_token", description="Grant type")
    refresh_token: str = Field(description="Refresh token")


class TokenResponse(BaseModel):
    """Schema for token responses."""
    
    access_token: str = Field(description="JWT access token")
    token_type: str = Field(default="bearer", description="Token type")
    expires_in: int = Field(description="Token expiry time in seconds")
    refresh_token: Optional[str] = Field(description="Refresh token (if applicable)")
    scope: Optional[str] = Field(description="Token scope")


class TokenValidationRequest(BaseModel):
    """Schema for token validation requests."""
    
    token: str = Field(description="Token to validate")
    token_type: str = Field(default="access", description="Type of token (access/refresh)")


class TokenValidationResponse(BaseModel):
    """Schema for token validation responses."""
    
    valid: bool = Field(description="Whether token is valid")
    user_id: Optional[int] = Field(description="User ID if token is valid")
    username: Optional[str] = Field(description="Username if token is valid")
    expires_at: Optional[datetime] = Field(description="Token expiration time")
    roles: Optional[List[str]] = Field(description="User roles if token is valid")


class TokenRevocationRequest(BaseModel):
    """Schema for token revocation requests."""
    
    token: str = Field(description="Token to revoke")
    token_type_hint: Optional[str] = Field(description="Hint about token type")


# ==================== PASSWORD MANAGEMENT SCHEMAS ====================

class PasswordChangeRequest(BaseModel):
    """Schema for password change requests."""
    
    current_password: SecretStr = Field(
        description="Current password for verification"
    )
    new_password: SecretStr = Field(
        min_length=8,
        max_length=128,
        description="New password"
    )
    confirm_password: SecretStr = Field(
        description="Password confirmation"
    )
    
    @validator('confirm_password')
    def passwords_match(cls, v, values):
        """Validate that passwords match."""
        if 'new_password' in values and v.get_secret_value() != values['new_password'].get_secret_value():
            raise ValueError('Passwords do not match')
        return v
    
    @validator('new_password')
    def validate_new_password(cls, v, values):
        """Validate new password is different from current."""
        if 'current_password' in values and v.get_secret_value() == values['current_password'].get_secret_value():
            raise ValueError('New password must be different from current password')
        return v


class PasswordResetRequest(BaseModel):
    """Schema for password reset requests."""
    
    email: EmailStr = Field(description="User email address")
    
    @validator('email')
    def validate_email(cls, v):
        """Normalize email."""
        return v.lower().strip()


class PasswordResetConfirmRequest(BaseModel):
    """Schema for password reset confirmation."""
    
    token: str = Field(description="Password reset token")
    new_password: SecretStr = Field(
        min_length=8,
        max_length=128,
        description="New password"
    )
    confirm_password: SecretStr = Field(
        description="Password confirmation"
    )
    
    @validator('confirm_password')
    def passwords_match(cls, v, values):
        """Validate that passwords match."""
        if 'new_password' in values and v.get_secret_value() != values['new_password'].get_secret_value():
            raise ValueError('Passwords do not match')
        return v


class PasswordStrengthRequest(BaseModel):
    """Schema for password strength validation requests."""
    
    password: str = Field(description="Password to validate")


class PasswordStrengthResponse(BaseModel):
    """Schema for password strength validation responses."""
    
    is_valid: bool = Field(description="Whether password meets requirements")
    score: int = Field(description="Password strength score")
    max_score: int = Field(description="Maximum possible score")
    strength: str = Field(description="Strength level (weak/moderate/strong/very_strong)")
    requirements_met: Dict[str, bool] = Field(description="Which requirements are met")
    suggestions: List[str] = Field(description="Suggestions for improvement")
    estimated_crack_time: str = Field(description="Estimated time to crack")


# ==================== TWO-FACTOR AUTHENTICATION SCHEMAS ====================

class Enable2FARequest(BaseModel):
    """Schema for enabling 2FA."""
    
    password: SecretStr = Field(description="Current password for verification")


class Enable2FAResponse(BaseModel):
    """Schema for 2FA enablement response."""
    
    secret: str = Field(description="TOTP secret key")
    qr_code_url: str = Field(description="QR code URL for authenticator apps")
    backup_codes: List[str] = Field(description="Backup codes for recovery")
    manual_entry_key: str = Field(description="Manual entry key for authenticator apps")


class Confirm2FARequest(BaseModel):
    """Schema for confirming 2FA setup."""
    
    secret: str = Field(description="TOTP secret key")
    token: str = Field(
        min_length=6,
        max_length=6,
        regex=r"^\d{6}$",
        description="6-digit 2FA token"
    )


class Disable2FARequest(BaseModel):
    """Schema for disabling 2FA."""
    
    password: SecretStr = Field(description="Current password for verification")
    token: Optional[str] = Field(
        default=None,
        min_length=6,
        max_length=8,
        description="2FA token or backup code"
    )


class Verify2FARequest(BaseModel):
    """Schema for 2FA verification."""
    
    token: str = Field(
        min_length=6,
        max_length=8,
        description="6-digit 2FA token or backup code"
    )


class Generate2FABackupCodesRequest(BaseModel):
    """Schema for generating new 2FA backup codes."""
    
    password: SecretStr = Field(description="Current password for verification")


class Generate2FABackupCodesResponse(BaseModel):
    """Schema for 2FA backup codes response."""
    
    backup_codes: List[str] = Field(description="New backup codes")
    codes_remaining: int = Field(description="Number of unused backup codes")


# ==================== SESSION MANAGEMENT SCHEMAS ====================

class SessionInfo(BaseModel):
    """Schema for session information."""
    
    session_id: str = Field(description="Session identifier")
    user_id: int = Field(description="User ID")
    ip_address: str = Field(description="IP address")
    user_agent: Optional[str] = Field(description="User agent")
    created_at: datetime = Field(description="Session creation time")
    last_activity: datetime = Field(description="Last activity time")
    is_current: bool = Field(description="Whether this is the current session")


class ActiveSessionsResponse(BaseModel):
    """Schema for active sessions response."""
    
    sessions: List[SessionInfo] = Field(description="List of active sessions")
    total_sessions: int = Field(description="Total number of active sessions")
    current_session_id: str = Field(description="Current session ID")


class TerminateSessionRequest(BaseModel):
    """Schema for session termination requests."""
    
    session_id: str = Field(description="Session ID to terminate")


class TerminateAllSessionsRequest(BaseModel):
    """Schema for terminating all other sessions."""
    
    keep_current: bool = Field(default=True, description="Whether to keep current session")


# ==================== LOGOUT SCHEMAS ====================

class LogoutRequest(BaseModel):
    """Schema for logout requests."""
    
    revoke_refresh_token: bool = Field(
        default=True,
        description="Whether to revoke refresh token"
    )
    terminate_all_sessions: bool = Field(
        default=False,
        description="Whether to terminate all user sessions"
    )


class LogoutResponse(BaseResponse):
    """Schema for logout responses."""
    
    message: str = Field(default="Logged out successfully")
    sessions_terminated: int = Field(description="Number of sessions terminated")


# ==================== USER STATUS AND VERIFICATION SCHEMAS ====================

class EmailVerificationRequest(BaseModel):
    """Schema for email verification requests."""
    
    email: EmailStr = Field(description="Email address to verify")


class EmailVerificationConfirmRequest(BaseModel):
    """Schema for email verification confirmation."""
    
    token: str = Field(description="Email verification token")


class AccountActivationRequest(BaseModel):
    """Schema for account activation requests."""
    
    token: str = Field(description="Account activation token")


class AccountLockoutInfo(BaseModel):
    """Schema for account lockout information."""
    
    is_locked: bool = Field(description="Whether account is locked")
    locked_until: Optional[datetime] = Field(description="Lock expiration time")
    failed_attempts: int = Field(description="Number of failed attempts")
    remaining_attempts: int = Field(description="Remaining attempts before lockout")


# ==================== PERMISSION AND ROLE SCHEMAS ====================

class UserPermissions(BaseModel):
    """Schema for user permissions information."""
    
    user_id: int = Field(description="User ID")
    roles: List[str] = Field(description="User roles")
    permissions: List[str] = Field(description="Effective permissions")
    is_superuser: bool = Field(description="Whether user is superuser")


class PermissionCheckRequest(BaseModel):
    """Schema for permission check requests."""
    
    permission: str = Field(description="Permission to check")
    resource_id: Optional[str] = Field(description="Resource ID (if applicable)")


class PermissionCheckResponse(BaseModel):
    """Schema for permission check responses."""
    
    has_permission: bool = Field(description="Whether user has permission")
    reason: Optional[str] = Field(description="Reason if permission denied")


# ==================== RATE LIMITING SCHEMAS ====================

class RateLimitInfo(BaseModel):
    """Schema for rate limit information."""
    
    allowed: bool = Field(description="Whether request is allowed")
    current_requests: int = Field(description="Current request count")
    max_requests: int = Field(description="Maximum requests allowed")
    window_minutes: int = Field(description="Time window in minutes")
    remaining_requests: int = Field(description="Remaining requests in window")
    reset_at: Optional[datetime] = Field(description="When rate limit resets")
    retry_after: Optional[float] = Field(description="Seconds to wait before retry")


# ==================== SECURITY EVENT SCHEMAS ====================

class SecurityEvent(BaseModel):
    """Schema for security events."""
    
    event_type: str = Field(description="Type of security event")
    user_id: Optional[int] = Field(description="User ID (if applicable)")
    ip_address: str = Field(description="IP address")
    user_agent: Optional[str] = Field(description="User agent")
    details: Dict[str, Any] = Field(description="Additional event details")
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    severity: str = Field(description="Event severity (low/medium/high/critical)")


class SecurityEventResponse(BaseModel):
    """Schema for security event responses."""
    
    events: List[SecurityEvent] = Field(description="List of security events")
    total_events: int = Field(description="Total number of events")
    high_risk_events: int = Field(description="Number of high-risk events")


# ==================== API KEY MANAGEMENT SCHEMAS ====================

class CreateAPIKeyRequest(BaseModel):
    """Schema for API key creation requests."""
    
    name: str = Field(
        min_length=1,
        max_length=100,
        description="Name for the API key"
    )
    description: Optional[str] = Field(
        max_length=500,
        description="Description of API key purpose"
    )
    expires_in_days: Optional[int] = Field(
        default=365,
        ge=1,
        le=3650,
        description="Number of days until key expires"
    )
    permissions: Optional[List[str]] = Field(
        default=None,
        description="Specific permissions for this key"
    )


class APIKeyResponse(BaseModel):
    """Schema for API key responses."""
    
    key_id: str = Field(description="API key identifier")
    name: str = Field(description="API key name")
    key: str = Field(description="The actual API key (only shown once)")
    expires_at: datetime = Field(description="Key expiration time")
    permissions: List[str] = Field(description="Key permissions")
    created_at: datetime = Field(description="Key creation time")


class APIKeyInfo(BaseModel):
    """Schema for API key information (without the actual key)."""
    
    key_id: str = Field(description="API key identifier")
    name: str = Field(description="API key name")
    description: Optional[str] = Field(description="Key description")
    expires_at: datetime = Field(description="Key expiration time")
    last_used: Optional[datetime] = Field(description="Last usage time")
    is_active: bool = Field(description="Whether key is active")
    created_at: datetime = Field(description="Key creation time")


class ListAPIKeysResponse(BaseModel):
    """Schema for listing API keys."""
    
    keys: List[APIKeyInfo] = Field(description="List of API keys")
    total_keys: int = Field(description="Total number of keys")
    active_keys: int = Field(description="Number of active keys")


class RevokeAPIKeyRequest(BaseModel):
    """Schema for API key revocation."""
    
    key_id: str = Field(description="API key identifier to revoke")


# ==================== CONFIGURATION SCHEMAS ====================

class AuthConfig(BaseModel):
    """Schema for authentication configuration."""
    
    password_policy: Dict[str, Any] = Field(description="Password policy settings")
    session_settings: Dict[str, Any] = Field(description="Session management settings")
    rate_limiting: Dict[str, Any] = Field(description="Rate limiting configuration")
    two_factor_settings: Dict[str, Any] = Field(description="2FA configuration")
    security_headers: Dict[str, str] = Field(description="Security headers")


# ==================== UTILITY SCHEMAS ====================

class HealthCheckAuth(BaseModel):
    """Schema for authentication health check."""
    
    service: str = Field(default="authentication")
    status: str = Field(description="Service status")
    version: str = Field(description="Service version")
    uptime: float = Field(description="Service uptime in seconds")
    checks: Dict[str, Any] = Field(description="Individual health checks")


# Model configuration for all schemas
class Config:
    """Common configuration for all schemas."""
    
    # Allow extra fields in input (useful for extensibility)
    extra = "forbid"
    
    # Use enum values instead of enum names
    use_enum_values = True
    
    # Validate assignment
    validate_assignment = True
    
    # JSON encoding configuration
    json_encoders = {
        datetime: lambda v: v.isoformat(),
        SecretStr: lambda v: v.get_secret_value() if v else None
    }
    
    # Schema examples
    schema_extra = {
        "examples": [
            {
                "username": "admin",
                "password": "secure_password_123",
                "remember_me": False
            }
        ]
    }


# Apply configuration to all schemas
for cls_name in list(globals().keys()):
    cls = globals()[cls_name]
    if isinstance(cls, type) and issubclass(cls, BaseModel) and cls != BaseModel:
        if not hasattr(cls, 'Config'):
            cls.Config = Config