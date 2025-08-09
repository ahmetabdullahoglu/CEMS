"""
Module: auth_service
Purpose: Complete authentication service with comprehensive security features for CEMS
Author: CEMS Development Team
Date: 2024
"""

from typing import Dict, Any, Optional, Tuple, List
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from sqlalchemy.exc import SQLAlchemyError
import secrets
import ipaddress
import json

from app.repositories.user_repository import UserRepository
from app.core.security import (
    security_manager, verify_password, get_password_hash,
    create_access_token, create_refresh_token, verify_token
)
from app.core.config import settings
from app.core.constants import UserStatus, UserRole
from app.core.exceptions import (
    AuthenticationException, AccountLockedException, AccountSuspendedException,
    RateLimitExceededException, ValidationException, NotFoundError,
    InsufficientPermissionsException, TokenExpiredException, RefreshTokenException,
    PasswordStrengthException, InvalidCredentialsException, SessionExpiredException
)
from app.schemas.auth import (
    LoginRequest, LoginResponse, RefreshTokenRequest, RefreshTokenResponse,
    PasswordChangeRequest, PasswordResetRequest, LogoutRequest, LogoutResponse,
    Login2FARequiredResponse, TokenValidationResponse, SecurityEvent,
    PasswordStrengthRequest, PasswordStrengthResponse
)
from app.schemas.user import UserResponse
from app.db.models.user import User, Role, UserRole as UserRoleAssoc
from app.utils.logger import get_logger
from app.utils.validators import validate_password_strength, validate_ip_address

logger = get_logger(__name__)


class AuthenticationService:
    """
    Complete authentication service providing comprehensive authentication and authorization.
    Handles login, logout, token management, security policies, and account protection.
    """
    
    def __init__(self, db: Session):
        """
        Initialize authentication service.
        
        Args:
            db: Database session
        """
        self.db = db
        self.user_repo = UserRepository(db)
        self.logger = get_logger(self.__class__.__name__)
        
        # Load security settings from config
        self.max_login_attempts = getattr(settings, 'MAX_LOGIN_ATTEMPTS', 5)
        self.lockout_duration = getattr(settings, 'ACCOUNT_LOCKOUT_DURATION_MINUTES', 30)
        self.session_timeout = getattr(settings, 'SESSION_TIMEOUT_MINUTES', 60)
        self.max_concurrent_sessions = getattr(settings, 'MAX_CONCURRENT_SESSIONS', 3)
        self.password_min_length = getattr(settings, 'PASSWORD_MIN_LENGTH', 8)
        self.password_max_age_days = getattr(settings, 'PASSWORD_MAX_AGE_DAYS', 90)
    
    # ==================== AUTHENTICATION METHODS ====================
    
    def authenticate_user(
        self,
        login_data: LoginRequest,
        client_info: Dict[str, Any]
    ) -> LoginResponse:
        """
        Authenticate user with comprehensive security checks using database models.
        
        Args:
            login_data: Login request data containing credentials
            client_info: Client information (IP, user agent, etc.)
            
        Returns:
            LoginResponse: Complete authentication response with tokens and user info
            
        Raises:
            AuthenticationException: For authentication failures
            AccountLockedException: If account is locked
            RateLimitExceededException: If rate limit exceeded
        """
        username_or_email = login_data.username.strip().lower()
        ip_address = client_info.get("ip_address", "unknown")
        
        try:
            # Check rate limiting for IP and username
            self._check_rate_limits(username_or_email, ip_address)
            
            # Get user by username or email
            user = self._get_user_for_login(username_or_email)
            if not user:
                self._handle_failed_login_attempt(username_or_email, ip_address, "user_not_found")
                raise InvalidCredentialsException("Invalid username or password")
            
            # Validate account status before checking password
            self._validate_user_account_status(user)
            
            # Verify password
            if not verify_password(login_data.password.get_secret_value(), user.hashed_password):
                self._handle_failed_login(user, ip_address)
                raise InvalidCredentialsException("Invalid username or password")
            
            # Check if 2FA is required
            if self._is_2fa_required(user):
                if not hasattr(login_data, 'two_factor_token') or not login_data.two_factor_token:
                    # Return 2FA required response
                    return self._create_2fa_required_response(user)
                
                # Verify 2FA token
                if not self._verify_2fa_token(user, login_data.two_factor_token):
                    self._handle_failed_login(user, ip_address)
                    raise AuthenticationException("Invalid 2FA token")
            
            # Check password expiry
            if self._is_password_expired(user):
                return self._create_password_change_required_response(user)
            
            # Authentication successful - create session and tokens
            return self._create_successful_login_response(user, client_info)
            
        except (AuthenticationException, AccountLockedException, RateLimitExceededException):
            raise
        except Exception as e:
            self.logger.error(f"Unexpected authentication error: {str(e)}")
            raise AuthenticationException("Authentication failed")
    
    def _get_user_for_login(self, username_or_email: str) -> Optional[User]:
        """
        Get user for login by username or email.
        
        Args:
            username_or_email: Username or email address
            
        Returns:
            Optional[User]: User object or None
        """
        # Try to get by username first
        user = self.user_repo.get_by_username(username_or_email)
        if not user and "@" in username_or_email:
            # Try by email if it looks like an email
            user = self.user_repo.get_by_email(username_or_email)
        
        return user
    
    def _validate_user_account_status(self, user: User) -> None:
        """
        Validate user account status for login.
        
        Args:
            user: User model instance
            
        Raises:
            AccountLockedException: If account is locked
            AccountSuspendedException: If account is suspended
            AuthenticationException: For other status issues
        """
        if not user.is_active:
            raise AccountSuspendedException("Account is deactivated")
        
        if user.status == UserStatus.SUSPENDED.value:
            raise AccountSuspendedException("Account is suspended")
        
        if user.status == UserStatus.LOCKED.value:
            # Check if lock period has expired
            if user.locked_until and user.locked_until > datetime.utcnow():
                remaining_time = user.locked_until - datetime.utcnow()
                raise AccountLockedException(
                    f"Account is locked for {remaining_time.seconds // 60} more minutes"
                )
            elif user.locked_until and user.locked_until <= datetime.utcnow():
                # Auto-unlock expired lock
                self.user_repo.unlock_user_account(user.id)
            else:
                raise AccountLockedException("Account is locked")
        
        if user.status == UserStatus.PENDING.value:
            raise AuthenticationException("Account is pending activation")
        
        if not user.is_verified:
            raise AuthenticationException("Email verification required")
    
    def _check_rate_limits(self, username: str, ip_address: str) -> None:
        """
        Check rate limits for login attempts.
        
        Args:
            username: Username attempting login
            ip_address: Client IP address
            
        Raises:
            RateLimitExceededException: If rate limit exceeded
        """
        # Check IP-based rate limiting
        if hasattr(security_manager, 'rate_limiter'):
            if not security_manager.rate_limiter.check_ip_limit(ip_address):
                raise RateLimitExceededException("Too many login attempts from this IP")
            
            # Check username-based rate limiting
            if not security_manager.rate_limiter.check_username_limit(username):
                raise RateLimitExceededException("Too many login attempts for this account")
    
    def _handle_failed_login(self, user: User, ip_address: str) -> None:
        """
        Handle failed login attempt with account locking logic.
        
        Args:
            user: User model instance
            ip_address: Client IP address
        """
        # Increment failed attempts
        failed_attempts = self.user_repo.increment_failed_attempts(user.id)
        
        # Log failed attempt
        self._log_security_event(
            user_id=user.id,
            event_type="login_failed",
            details={
                "ip_address": ip_address,
                "failed_attempts": failed_attempts,
                "username": user.username
            }
        )
        
        # Lock account if max attempts reached
        if failed_attempts >= self.max_login_attempts:
            locked_until = datetime.utcnow() + timedelta(minutes=self.lockout_duration)
            self.user_repo.lock_user_account(
                user_id=user.id,
                reason=f"Too many failed login attempts ({failed_attempts})",
                locked_until=locked_until
            )
            
            self.logger.warning(f"Account {user.username} locked due to failed login attempts")
    
    def _handle_failed_login_attempt(self, username: str, ip_address: str, reason: str) -> None:
        """
        Handle failed login attempt for non-existent users.
        
        Args:
            username: Attempted username
            ip_address: Client IP address
            reason: Failure reason
        """
        # Log failed attempt
        self._log_security_event(
            user_id=None,
            event_type="login_failed",
            details={
                "ip_address": ip_address,
                "username": username,
                "reason": reason
            }
        )
        
        # Record in rate limiter if available
        if hasattr(security_manager, 'rate_limiter'):
            security_manager.rate_limiter.record_failed_attempt(ip_address, username)
    
    def _is_2fa_required(self, user: User) -> bool:
        """
        Check if 2FA is required for user.
        
        Args:
            user: User model instance
            
        Returns:
            bool: True if 2FA is required
        """
        return getattr(user, 'two_factor_enabled', False) and getattr(user, 'two_factor_secret', None)
    
    def _verify_2fa_token(self, user: User, token: str) -> bool:
        """
        Verify 2FA token for user.
        
        Args:
            user: User model instance
            token: 2FA token to verify
            
        Returns:
            bool: True if token is valid
        """
        if not hasattr(security_manager, 'verify_totp'):
            return False
        
        return security_manager.verify_totp(user.two_factor_secret, token)
    
    def _is_password_expired(self, user: User) -> bool:
        """
        Check if user password has expired.
        
        Args:
            user: User model instance
            
        Returns:
            bool: True if password is expired
        """
        if not getattr(user, 'password_changed_at', None):
            return False
        
        expiry_date = user.password_changed_at + timedelta(days=self.password_max_age_days)
        return datetime.utcnow() > expiry_date
    
    def _create_2fa_required_response(self, user: User) -> Login2FARequiredResponse:
        """
        Create 2FA required response.
        
        Args:
            user: User model instance
            
        Returns:
            Login2FARequiredResponse: 2FA challenge response
        """
        temp_token = secrets.token_urlsafe(32)
        
        # Store temp token for 2FA verification (in cache/memory)
        if hasattr(security_manager, 'temp_token_store'):
            security_manager.temp_token_store[temp_token] = {
                "user_id": user.id,
                "expires_at": datetime.utcnow() + timedelta(minutes=5)
            }
        
        return Login2FARequiredResponse(
            requires_2fa=True,
            temp_token=temp_token,
            message="Two-factor authentication required"
        )
    
    def _create_password_change_required_response(self, user: User) -> LoginResponse:
        """
        Create password change required response.
        
        Args:
            user: User model instance
            
        Returns:
            LoginResponse: Response indicating password change required
        """
        # Create limited token for password change
        token_data = {
            "sub": str(user.id),
            "username": user.username,
            "permissions": ["change_password_only"]
        }
        
        access_token = create_access_token(token_data, expires_delta=timedelta(minutes=30))
        
        return LoginResponse(
            access_token=access_token,
            token_type="bearer",
            expires_in=30 * 60,
            user_id=user.id,
            username=user.username,
            must_change_password=True,
            message="Password change required"
        )
    
    def _create_successful_login_response(
        self,
        user: User,
        client_info: Dict[str, Any]
    ) -> LoginResponse:
        """
        Create successful login response with tokens and user info.
        
        Args:
            user: User model instance
            client_info: Client information
            
        Returns:
            LoginResponse: Complete login response
        """
        ip_address = client_info.get("ip_address", "unknown")
        
        # Update user login information
        self.user_repo.update_last_login(
            user_id=user.id,
            ip_address=ip_address,
            user_agent=client_info.get("user_agent")
        )
        
        # Create session
        session_id = security_manager.session_manager.create_session(
            user_id=user.id,
            ip_address=ip_address,
            user_agent=client_info.get("user_agent", "unknown")
        )
        
        # Get user roles and permissions
        user_roles = [role.name for role in self.user_repo.get_user_roles(user.id)]
        user_permissions = self.user_repo.get_user_permissions(user.id)
        
        # Create tokens
        token_data = {
            "sub": str(user.id),
            "username": user.username,
            "email": user.email,
            "roles": user_roles,
            "permissions": user_permissions,
            "session_id": session_id
        }
        
        access_token = create_access_token(token_data)
        refresh_token = create_refresh_token({"sub": str(user.id)})
        
        # Reset failed attempts on successful login
        self.user_repo.reset_failed_attempts(user.id)
        
        # Log successful login
        self._log_security_event(
            user_id=user.id,
            event_type="login_success",
            details={
                **client_info,
                "session_id": session_id,
                "roles": user_roles
            }
        )
        
        return LoginResponse(
            access_token=access_token,
            refresh_token=refresh_token,
            token_type="bearer",
            expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            refresh_expires_in=settings.REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60,
            
            # User information
            user_id=user.id,
            username=user.username,
            email=user.email,
            full_name=f"{user.first_name} {user.last_name}",
            roles=user_roles,
            permissions=user_permissions,
            
            # Session information
            session_id=session_id,
            last_login=user.last_login_at,
            
            # Security flags
            is_2fa_enabled=self._is_2fa_required(user),
            must_change_password=getattr(user, 'force_password_change', False),
            password_expires_in_days=self._calculate_password_expiry_days(user)
        )
    
    def _calculate_password_expiry_days(self, user: User) -> Optional[int]:
        """
        Calculate days until password expires.
        
        Args:
            user: User model instance
            
        Returns:
            Optional[int]: Days until expiry or None
        """
        if not getattr(user, 'password_changed_at', None):
            return None
        
        expiry_date = user.password_changed_at + timedelta(days=self.password_max_age_days)
        days_remaining = (expiry_date - datetime.utcnow()).days
        
        return max(0, days_remaining)
    
    # ==================== TOKEN MANAGEMENT ====================
    
    def refresh_access_token(
        self,
        refresh_data: RefreshTokenRequest,
        client_info: Dict[str, Any]
    ) -> RefreshTokenResponse:
        """
        Refresh access token using refresh token.
        
        Args:
            refresh_data: Refresh token request
            client_info: Client information
            
        Returns:
            RefreshTokenResponse: New access token and optionally new refresh token
            
        Raises:
            RefreshTokenException: If refresh token is invalid
            AccountSuspendedException: If account is suspended
        """
        try:
            # Verify refresh token
            payload = verify_token(refresh_data.refresh_token, token_type="refresh")
            user_id = payload.get("sub")
            
            if not user_id:
                raise RefreshTokenException("Invalid token payload")
            
            # Get user and validate status
            user = self.user_repo.get_by_id_with_roles(int(user_id))
            if not user:
                raise RefreshTokenException("User not found")
            
            self._validate_user_account_status(user)
            
            # Create new access token
            user_roles = [role.name for role in self.user_repo.get_user_roles(user.id)]
            user_permissions = self.user_repo.get_user_permissions(user.id)
            
            access_token_data = {
                "sub": str(user.id),
                "username": user.username,
                "email": user.email,
                "roles": user_roles,
                "permissions": user_permissions
            }
            
            access_token = create_access_token(access_token_data)
            
            # Optionally create new refresh token (rotation)
            new_refresh_token = None
            if getattr(settings, 'ROTATE_REFRESH_TOKENS', True):
                new_refresh_token = create_refresh_token({"sub": str(user.id)})
                
                # Blacklist old refresh token
                if hasattr(security_manager, 'token_blacklist'):
                    security_manager.token_blacklist.add_token(
                        refresh_data.refresh_token,
                        datetime.utcnow() + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
                    )
            
            # Log token refresh
            self._log_security_event(
                user_id=user.id,
                event_type="token_refresh",
                details=client_info
            )
            
            return RefreshTokenResponse(
                access_token=access_token,
                token_type="bearer",
                expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
                refresh_token=new_refresh_token or refresh_data.refresh_token
            )
            
        except TokenExpiredException:
            raise RefreshTokenException("Refresh token has expired")
        except Exception as e:
            self.logger.error(f"Token refresh error: {str(e)}")
            raise RefreshTokenException(f"Token refresh failed: {str(e)}")
    
    def validate_token(self, token: str) -> TokenValidationResponse:
        """
        Validate access token and return user information.
        
        Args:
            token: Access token to validate
            
        Returns:
            TokenValidationResponse: Token validation result
        """
        try:
            payload = verify_token(token, token_type="access")
            user_id = payload.get("sub")
            
            if not user_id:
                return TokenValidationResponse(
                    is_valid=False,
                    error="Invalid token payload"
                )
            
            user = self.user_repo.get_by_id_with_roles(int(user_id))
            if not user:
                return TokenValidationResponse(
                    is_valid=False,
                    error="User not found"
                )
            
            # Check if user is still active
            if not user.is_active or user.status != UserStatus.ACTIVE.value:
                return TokenValidationResponse(
                    is_valid=False,
                    error="User account is no longer active"
                )
            
            return TokenValidationResponse(
                is_valid=True,
                user_id=user.id,
                username=user.username,
                email=user.email,
                roles=payload.get("roles", []),
                permissions=payload.get("permissions", []),
                expires_at=datetime.fromtimestamp(payload.get("exp", 0))
            )
            
        except TokenExpiredException:
            return TokenValidationResponse(
                is_valid=False,
                error="Token has expired"
            )
        except Exception as e:
            self.logger.error(f"Token validation error: {str(e)}")
            return TokenValidationResponse(
                is_valid=False,
                error="Token validation failed"
            )
    
    # ==================== LOGOUT MANAGEMENT ====================
    
    def logout_user(
        self,
        user: User,
        logout_data: LogoutRequest,
        client_info: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Logout user and handle token/session cleanup.
        
        Args:
            user: Authenticated user model
            logout_data: Logout request data
            client_info: Client information
            
        Returns:
            Dictionary with logout status and statistics
        """
        sessions_terminated = 0
        
        try:
            # Terminate sessions based on request
            if logout_data.terminate_all_sessions:
                if hasattr(security_manager, 'session_manager'):
                    sessions_terminated = security_manager.session_manager.invalidate_user_sessions(user.id)
            else:
                # Terminate current session only
                session_id = client_info.get("session_id")
                if session_id and hasattr(security_manager, 'session_manager'):
                    if security_manager.session_manager.invalidate_session(session_id):
                        sessions_terminated = 1
            
            # Revoke refresh token if requested
            if logout_data.revoke_refresh_token:
                refresh_token = client_info.get("refresh_token")
                if refresh_token and hasattr(security_manager, 'token_blacklist'):
                    security_manager.token_blacklist.add_token(
                        refresh_token,
                        datetime.utcnow() + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
                    )
            
            # Log logout event
            self._log_security_event(
                user_id=user.id,
                event_type="logout",
                details={
                    **client_info,
                    "sessions_terminated": sessions_terminated,
                    "refresh_token_revoked": logout_data.revoke_refresh_token
                }
            )
            
            return {
                "message": "Logged out successfully",
                "sessions_terminated": sessions_terminated
            }
            
        except Exception as e:
            self.logger.error(f"Logout error for user {user.id}: {str(e)}")
            raise AuthenticationException(
                message="Logout failed",
                details={"error": str(e)}
            )
    
    # ==================== PASSWORD MANAGEMENT ====================
    
    def change_password(
        self,
        user: User,
        password_data: PasswordChangeRequest
    ) -> Dict[str, Any]:
        """
        Change user password with validation and security checks.
        
        Args:
            user: User model instance
            password_data: Password change request
            
        Returns:
            Dictionary with change status
            
        Raises:
            ValidationException: If current password is invalid
            PasswordStrengthException: If new password is weak
        """
        try:
            # Verify current password
            if not verify_password(password_data.current_password.get_secret_value(), user.hashed_password):
                raise ValidationException("Current password is incorrect")
            
            # Validate new password strength
            strength_result = validate_password_strength(password_data.new_password.get_secret_value())
            if not strength_result["is_strong"]:
                raise PasswordStrengthException(
                    "Password does not meet strength requirements",
                    details=strength_result
                )
            
            # Check if new password is different from current
            if verify_password(password_data.new_password.get_secret_value(), user.hashed_password):
                raise ValidationException("New password must be different from current password")
            
            # Update password
            new_hashed_password = get_password_hash(password_data.new_password.get_secret_value())
            
            self.user_repo.update_user(user.id, {
                "hashed_password": new_hashed_password,
                "password_changed_at": datetime.utcnow(),
                "force_password_change": False
            })
            
            # Invalidate all sessions except current if requested
            if password_data.invalidate_sessions:
                if hasattr(security_manager, 'session_manager'):
                    current_session = password_data.keep_current_session
                    security_manager.session_manager.invalidate_user_sessions(
                        user.id,
                        except_session=current_session
                    )
            
            # Log password change
            self._log_security_event(
                user_id=user.id,
                event_type="password_change",
                details={"sessions_invalidated": password_data.invalidate_sessions}
            )
            
            self.logger.info(f"Password changed for user {user.username}")
            
            return {
                "message": "Password changed successfully",
                "sessions_invalidated": password_data.invalidate_sessions
            }
            
        except (ValidationException, PasswordStrengthException):
            raise
        except Exception as e:
            self.logger.error(f"Password change error for user {user.id}: {str(e)}")
            raise AuthenticationException("Password change failed")
    
    def check_password_strength(self, password_data: PasswordStrengthRequest) -> PasswordStrengthResponse:
        """
        Check password strength and provide feedback.
        
        Args:
            password_data: Password strength check request
            
        Returns:
            PasswordStrengthResponse: Password strength analysis
        """
        try:
            result = validate_password_strength(password_data.password.get_secret_value())
            
            return PasswordStrengthResponse(
                is_strong=result["is_strong"],
                score=result["score"],
                feedback=result["feedback"],
                requirements_met=result["requirements_met"]
            )
            
        except Exception as e:
            self.logger.error(f"Password strength check error: {str(e)}")
            return PasswordStrengthResponse(
                is_strong=False,
                score=0,
                feedback=["Unable to check password strength"],
                requirements_met={}
            )
    
    def initiate_password_reset(self, email: str) -> Dict[str, Any]:
        """
        Initiate password reset process.
        
        Args:
            email: User email address
            
        Returns:
            Dictionary with reset initiation status
        """
        try:
            user = self.user_repo.get_by_email(email)
            if not user:
                # Don't reveal if email exists
                return {"message": "Password reset instructions sent if email exists"}
            
            # Generate reset token
            reset_token = secrets.token_urlsafe(32)
            reset_expires = datetime.utcnow() + timedelta(hours=1)
            
            # Store reset token (in database or cache)
            self.user_repo.update_user(user.id, {
                "password_reset_token": reset_token,
                "password_reset_expires": reset_expires
            })
            
            # Log password reset request
            self._log_security_event(
                user_id=user.id,
                event_type="password_reset_requested",
                details={"email": email}
            )
            
            # TODO: Send reset email (implement email service)
            self.logger.info(f"Password reset initiated for user {user.username}")
            
            return {
                "message": "Password reset instructions sent",
                "reset_token": reset_token  # Remove in production - send via email
            }
            
        except Exception as e:
            self.logger.error(f"Password reset initiation error: {str(e)}")
            return {"message": "Password reset instructions sent if email exists"}
    
    # ==================== SECURITY EVENT LOGGING ====================
    
    def _log_security_event(
        self,
        event_type: str,
        user_id: Optional[int] = None,
        details: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Log security event for audit trail.
        
        Args:
            event_type: Type of security event
            user_id: Optional user ID
            details: Optional event details
        """
        try:
            event_data = {
                "event_type": event_type,
                "user_id": user_id,
                "timestamp": datetime.utcnow().isoformat(),
                "details": details or {}
            }
            
            # Log to application logger
            self.logger.info(f"Security event: {event_type}", extra=event_data)
            
            # TODO: Store in security audit table
            # security_audit_repo.create_event(event_data)
            
        except Exception as e:
            self.logger.error(f"Failed to log security event: {str(e)}")
    
    # ==================== UTILITY METHODS ====================
    
    def get_user_sessions(self, user_id: int) -> List[Dict[str, Any]]:
        """
        Get active sessions for user.
        
        Args:
            user_id: User ID
            
        Returns:
            List of active session information
        """
        try:
            if hasattr(security_manager, 'session_manager'):
                return security_manager.session_manager.get_user_sessions(user_id)
            return []
        except Exception as e:
            self.logger.error(f"Error getting user sessions: {str(e)}")
            return []
    
    def terminate_user_session(self, user_id: int, session_id: str) -> bool:
        """
        Terminate specific user session.
        
        Args:
            user_id: User ID
            session_id: Session ID to terminate
            
        Returns:
            bool: True if session terminated successfully
        """
        try:
            if hasattr(security_manager, 'session_manager'):
                return security_manager.session_manager.invalidate_session(session_id)
            return False
        except Exception as e:
            self.logger.error(f"Error terminating session: {str(e)}")
            return False
    
    def check_permission(self, user: User, permission: str, resource_id: Optional[str] = None) -> bool:
        """
        Check if user has specific permission.
        
        Args:
            user: User model instance
            permission: Permission to check
            resource_id: Optional resource ID
            
        Returns:
            bool: True if user has permission
        """
        try:
            # Superuser has all permissions
            if user.is_superuser:
                return True
            
            # Get user permissions
            user_permissions = self.user_repo.get_user_permissions(user.id)
            
            # Check exact permission or wildcard
            if permission in user_permissions or "*" in user_permissions:
                return True
            
            # Check pattern matching (e.g., "user.*" matches "user.create")
            for perm in user_permissions:
                if perm.endswith("*") and permission.startswith(perm[:-1]):
                    return True
            
            return False
            
        except Exception as e:
            self.logger.error(f"Permission check error: {str(e)}")
            return False