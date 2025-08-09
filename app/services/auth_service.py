"""
Module: auth_service
Purpose: Enhanced authentication service with complete model integration for CEMS
Author: CEMS Development Team
Date: 2024
"""

from typing import Dict, Any, Optional, Tuple, List
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from sqlalchemy.exc import SQLAlchemyError
import secrets
import ipaddress

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
    PasswordChangeRequest, PasswordResetRequest, LogoutRequest,
    Login2FARequiredResponse, TokenValidationResponse, SecurityEvent
)
from app.schemas.user import UserResponse
from app.db.models import User, Role, UserRole as UserRoleAssoc
from app.utils.logger import get_logger
from app.utils.validators import validate_password_strength, validate_ip_address

logger = get_logger(__name__)


class AuthenticationService:
    """
    Enhanced authentication service providing comprehensive authentication and authorization.
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
        
        # Load security settings
        self.max_login_attempts = getattr(settings, 'MAX_LOGIN_ATTEMPTS', 5)
        self.lockout_duration = getattr(settings, 'ACCOUNT_LOCKOUT_DURATION_MINUTES', 30)
        self.session_timeout = getattr(settings, 'SESSION_TIMEOUT_MINUTES', 60)
        self.max_concurrent_sessions = getattr(settings, 'MAX_CONCURRENT_SESSIONS', 3)
    
    # ==================== AUTHENTICATION METHODS ====================
    
    def authenticate_user(
        self,
        login_data: LoginRequest,
        client_info: Dict[str, Any]
    ) -> LoginResponse:
        """
        Authenticate user with comprehensive security checks using database models.
        
        Args:
            login_data: Login request data
            client_info: Client information (IP, user agent, etc.)
            
        Returns:
            LoginResponse: Complete login response with tokens and user info
            
        Raises:
            InvalidCredentialsException: If credentials are invalid
            AccountLockedException: If account is locked
            RateLimitExceededException: If rate limit exceeded
        """
        ip_address = client_info.get("ip_address", "unknown")
        user_agent = client_info.get("user_agent", "unknown")
        
        try:
            # Rate limiting check
            self._check_login_rate_limit(ip_address)
            
            # Get user by username or email
            user = self._get_user_by_login_identifier(login_data.username)
            
            # Validate user account status
            self._validate_user_for_login(user)
            
            # Verify password
            if not verify_password(login_data.password.get_secret_value(), user.hashed_password):
                self._handle_failed_login(user, ip_address)
                raise InvalidCredentialsException(
                    details={
                        "reason": "invalid_password",
                        "user_id": user.id if user else None
                    }
                )
            
            # Check if 2FA is required
            if user.two_factor_enabled:
                return self._handle_2fa_required(user, login_data, client_info)
            
            # Successful login
            return self._complete_successful_login(user, client_info)
            
        except AuthenticationException:
            raise
        except Exception as e:
            self.logger.error(f"Unexpected error during authentication: {str(e)}")
            raise AuthenticationException(
                message="Authentication failed due to system error",
                details={"error": str(e)}
            )
    
    def refresh_access_token(
        self,
        refresh_data: RefreshTokenRequest,
        client_info: Dict[str, Any]
    ) -> RefreshTokenResponse:
        """
        Refresh access token using refresh token with model validation.
        
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
            payload = security_manager.verify_token(refresh_data.refresh_token, "refresh")
            user_id = payload.get("sub")
            
            if not user_id:
                raise RefreshTokenException("Invalid token payload")
            
            # Get user and validate status
            user = self.user_repo.get_by_id_or_raise(int(user_id))
            self._validate_user_account_status(user)
            
            # Create new access token
            access_token_data = {
                "sub": str(user.id),
                "username": user.username,
                "email": user.email,
                "roles": self.user_repo.get_user_roles(user.id),
                "permissions": self.user_repo.get_user_permissions(user.id)
            }
            
            access_token = create_access_token(access_token_data)
            
            # Optionally create new refresh token (rotation)
            new_refresh_token = None
            if getattr(settings, 'ROTATE_REFRESH_TOKENS', True):
                new_refresh_token = create_refresh_token({"sub": str(user.id)})
                # Blacklist old refresh token
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
                sessions_terminated = security_manager.session_manager.invalidate_all_user_sessions(
                    user.id
                )
            else:
                # Terminate current session only
                session_id = client_info.get("session_id")
                if session_id:
                    security_manager.session_manager.invalidate_session(session_id)
                    sessions_terminated = 1
            
            # Revoke refresh token if requested
            if logout_data.revoke_refresh_token:
                refresh_token = client_info.get("refresh_token")
                if refresh_token:
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
            InvalidCredentialsException: If current password is wrong
            PasswordStrengthException: If new password is weak
        """
        try:
            # Verify current password
            if not verify_password(
                password_data.current_password.get_secret_value(),
                user.hashed_password
            ):
                raise InvalidCredentialsException(
                    details={"reason": "invalid_current_password"}
                )
            
            # Validate new password strength
            new_password = password_data.new_password.get_secret_value()
            strength_check = security_manager.check_password_strength(new_password)
            
            if not strength_check["is_valid"]:
                raise PasswordStrengthException(
                    requirements=strength_check,
                    details={"suggestions": strength_check.get("suggestions", [])}
                )
            
            # Update password
            user.hashed_password = get_password_hash(new_password)
            user.password_changed_at = datetime.utcnow()
            user.force_password_change = False
            
            # Update password history if enabled
            if getattr(settings, 'PASSWORD_HISTORY_COUNT', 0) > 0:
                self._update_password_history(user, user.hashed_password)
            
            self.db.commit()
            
            # Log password change
            self._log_security_event(
                user_id=user.id,
                event_type="password_change",
                details={"strength_score": strength_check.get("score", 0)}
            )
            
            return {
                "message": "Password changed successfully",
                "strength_score": strength_check.get("score", 0)
            }
            
        except (InvalidCredentialsException, PasswordStrengthException):
            raise
        except Exception as e:
            self.db.rollback()
            self.logger.error(f"Password change error for user {user.id}: {str(e)}")
            raise AuthenticationException(
                message="Password change failed",
                details={"error": str(e)}
            )
    
    def validate_token(
        self,
        token: str,
        token_type: str = "access"
    ) -> TokenValidationResponse:
        """
        Validate token and return user information.
        
        Args:
            token: JWT token to validate
            token_type: Type of token (access/refresh)
            
        Returns:
            TokenValidationResponse: Validation result with user info
        """
        try:
            payload = security_manager.verify_token(token, token_type)
            user_id = payload.get("sub")
            
            if user_id:
                user = self.user_repo.get_by_id(int(user_id))
                if user and self._is_user_account_valid(user):
                    return TokenValidationResponse(
                        valid=True,
                        user_id=user.id,
                        username=user.username,
                        expires_at=datetime.fromtimestamp(payload.get("exp", 0)),
                        roles=self.user_repo.get_user_roles(user.id)
                    )
            
            return TokenValidationResponse(valid=False)
            
        except Exception as e:
            self.logger.debug(f"Token validation failed: {str(e)}")
            return TokenValidationResponse(valid=False)
    
    # ==================== PRIVATE HELPER METHODS ====================
    
    def _get_user_by_login_identifier(self, identifier: str) -> User:
        """
        Get user by username or email using repository.
        
        Args:
            identifier: Username or email
            
        Returns:
            User model instance
            
        Raises:
            InvalidCredentialsException: If user not found
        """
        user = None
        
        # Try by username first
        if "@" not in identifier:
            user = self.user_repo.get_by_username(identifier)
        else:
            # Try by email
            user = self.user_repo.get_by_email(identifier)
        
        if not user:
            # Log potential security issue
            self.logger.warning(f"Login attempt with unknown identifier: {identifier}")
            raise InvalidCredentialsException(
                details={"reason": "user_not_found"}
            )
        
        return user
    
    def _validate_user_for_login(self, user: User) -> None:
        """
        Validate user account status for login using model properties.
        
        Args:
            user: User model instance
            
        Raises:
            Various authentication exceptions based on status
        """
        # Check if account is locked using model property
        if user.is_locked:
            raise AccountLockedException(
                unlock_time=user.locked_until.isoformat() if user.locked_until else None,
                details={
                    "user_id": user.id,
                    "locked_until": user.locked_until
                }
            )
        
        # Check account status using enum comparison
        if user.status == UserStatus.SUSPENDED:
            raise AccountSuspendedException(
                details={"user_id": user.id, "status": user.status}
            )
        
        if user.status not in [UserStatus.ACTIVE, UserStatus.PENDING]:
            raise AuthenticationException(
                message=f"Account status does not allow login: {user.status}",
                details={
                    "user_id": user.id,
                    "status": user.status
                }
            )
        
        if not user.is_active:
            raise AuthenticationException(
                message="Account is deactivated",
                details={"user_id": user.id}
            )
    
    def _complete_successful_login(
        self,
        user: User,
        client_info: Dict[str, Any]
    ) -> LoginResponse:
        """
        Complete successful login process with model updates.
        
        Args:
            user: User model instance
            client_info: Client information
            
        Returns:
            LoginResponse: Complete login response
        """
        ip_address = client_info.get("ip_address", "unknown")
        
        # Record successful login in model
        user.record_login(ip_address)
        
        # Create session
        session_id = security_manager.session_manager.create_session(
            user_id=user.id,
            ip_address=ip_address,
            user_agent=client_info.get("user_agent", "unknown")
        )
        
        # Get user roles and permissions using repository
        user_roles = self.user_repo.get_user_roles(user.id)
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
        
        # Commit changes
        self.db.commit()
        
        # Log successful login
        self._log_security_event(
            user_id=user.id,
            event_type="login",
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
            
            # User information from model
            user_id=user.id,
            username=user.username,
            email=user.email,
            full_name=user.full_name,
            roles=user_roles,
            permissions=user_permissions,
            
            # Session information
            session_id=session_id,
            last_login=user.last_login_at,
            
            # Security flags
            is_2fa_enabled=getattr(user, 'two_factor_enabled', False),
            must_change_password=user.force_password_change,
            password_expires_in_days=self._calculate_password_expiry_days(user)
        )
    
    def _handle_failed_login(self, user: User, ip_address: str) -> None:
        """
        Handle failed login attempt with model updates.
        
        Args:
            user: User model instance
            ip_address: Client IP address
        """
        if user:
            # Record failed attempt using model method
            user.record_failed_login()
            self.db.commit()
            
            # Log failed attempt
            self._log_security_event(
                user_id=user.id,
                event_type="failed_login",
                details={
                    "ip_address": ip_address,
                    "failed_attempts": int(user.failed_login_attempts or '0')
                }
            )
    
    def _validate_user_account_status(self, user: User) -> None:
        """
        Validate user account status using model properties.
        
        Args:
            user: User model instance
            
        Raises:
            Various authentication exceptions
        """
        if user.status == UserStatus.SUSPENDED:
            raise AccountSuspendedException(
                details={"user_id": user.id, "status": user.status}
            )
        
        if not user.is_active:
            raise AuthenticationException(
                message="Account is inactive",
                details={"user_id": user.id}
            )
    
    def _is_user_account_valid(self, user: User) -> bool:
        """
        Check if user account is valid (non-raising version).
        
        Args:
            user: User model instance
            
        Returns:
            True if account is valid
        """
        try:
            self._validate_user_account_status(user)
            return True
        except AuthenticationException:
            return False
    
    def _check_login_rate_limit(self, ip_address: str) -> None:
        """
        Check login rate limit for IP address.
        
        Args:
            ip_address: Client IP address
            
        Raises:
            RateLimitExceededException: If rate limit exceeded
        """
        try:
            max_attempts = getattr(settings, 'LOGIN_RATE_LIMIT_PER_MINUTE', 10)
            security_manager.check_rate_limit(
                identifier=f"login:{ip_address}",
                max_requests=max_attempts,
                window_minutes=1
            )
        except RateLimitExceededException:
            self.logger.warning(f"Login rate limit exceeded for IP: {ip_address}")
            raise
    
    def _calculate_password_expiry_days(self, user: User) -> Optional[int]:
        """
        Calculate days until password expires.
        
        Args:
            user: User model instance
            
        Returns:
            Days until expiry or None if no expiry
        """
        if not user.password_changed_at:
            return None
        
        expiry_days = getattr(settings, 'FORCE_PASSWORD_CHANGE_DAYS', 0)
        if expiry_days <= 0:
            return None
        
        expiry_date = user.password_changed_at + timedelta(days=expiry_days)
        days_remaining = (expiry_date - datetime.utcnow()).days
        
        return max(0, days_remaining)
    
    def _log_security_event(
        self,
        user_id: int,
        event_type: str,
        details: Dict[str, Any]
    ) -> None:
        """
        Log security event for audit trail.
        
        Args:
            user_id: User ID
            event_type: Type of security event
            details: Event details
        """
        self.logger.info(
            f"Security event - User: {user_id}, Event: {event_type}, Details: {details}"
        )
        
        # TODO: Implement audit log table for persistent security events
        # This could be enhanced to store in database audit log
    
    def _handle_2fa_required(
        self,
        user: User,
        login_data: LoginRequest,
        client_info: Dict[str, Any]
    ) -> Login2FARequiredResponse:
        """
        Handle 2FA requirement during login.
        
        Args:
            user: User model instance
            login_data: Login request
            client_info: Client information
            
        Returns:
            2FA required response
        """
        # Create temporary token for 2FA completion
        temp_token_data = {
            "sub": str(user.id),
            "temp": True,
            "purpose": "2fa_completion"
        }
        temp_token = create_access_token(
            temp_token_data,
            expires_delta=timedelta(minutes=5)  # Short-lived temp token
        )
        
        return Login2FARequiredResponse(
            message="Two-factor authentication required",
            temp_token=temp_token,
            backup_codes_available=getattr(user, 'backup_codes_count', 0)
        )
    
    def _update_password_history(self, user: User, new_password_hash: str) -> None:
        """
        Update password history for user.
        
        Args:
            user: User model instance
            new_password_hash: New password hash to add to history
        """
        # TODO: Implement password history table
        # This would prevent password reuse
        pass