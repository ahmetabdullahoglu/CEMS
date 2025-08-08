"""
Module: auth_service
Purpose: Authentication service providing complete authentication workflow for CEMS
Author: CEMS Development Team
Date: 2024
"""

from typing import Dict, Any, Optional, Tuple, List
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
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
    AuthenticationError, AccountLockedException, AccountInactiveError,
    RateLimitExceededException, ValidationError, NotFoundError,
    PermissionError, SecurityError
)
from app.schemas.auth import (
    LoginRequest, LoginResponse, RefreshTokenRequest, RefreshTokenResponse,
    PasswordChangeRequest, PasswordResetRequest, LogoutRequest,
    TwoFactorVerifyRequest, TwoFactorSetupResponse, SecurityEvent
)
from app.schemas.user import UserResponse
from app.utils.logger import get_logger
from app.utils.validators import validate_password_strength, validate_ip_address

logger = get_logger(__name__)


class AuthenticationService:
    """
    Authentication service providing comprehensive authentication and authorization.
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
        ip_address: str,
        user_agent: str = None
    ) -> LoginResponse:
        """
        Authenticate user with comprehensive security checks.
        
        Args:
            login_data: Login credentials and options
            ip_address: Client IP address
            user_agent: Client user agent
            
        Returns:
            LoginResponse: Authentication response with tokens
            
        Raises:
            AuthenticationError: If authentication fails
            AccountLockedException: If account is locked
            RateLimitExceededException: If rate limit exceeded
        """
        try:
            # Validate IP address
            if not validate_ip_address(ip_address):
                raise SecurityError("Invalid IP address")
            
            # Check rate limiting
            rate_limit_key = f"login:{ip_address}"
            self._check_rate_limit(rate_limit_key, max_requests=10, window_minutes=15)
            
            # Get user
            user = self.user_repo.get_by_username_or_email(login_data.username)
            if not user:
                self._record_failed_login(None, ip_address, "User not found")
                raise AuthenticationError("Invalid credentials")
            
            # Check account status
            self._validate_account_status(user)
            
            # Check account lock
            if self._is_account_locked(user):
                self._record_security_event(
                    user.id, ip_address, user_agent,
                    "login_attempt_locked_account",
                    {"username": login_data.username}
                )
                raise AccountLockedException(
                    f"Account is locked until {user.locked_until}",
                    locked_until=user.locked_until
                )
            
            # Verify password
            if not verify_password(login_data.password, user.hashed_password):
                self._handle_failed_login(user, ip_address, user_agent)
                raise AuthenticationError("Invalid credentials")
            
            # Check if password change is required
            if user.force_password_change:
                return LoginResponse(
                    user=UserResponse.from_orm(user),
                    access_token="",
                    refresh_token="",
                    token_type="bearer",
                    expires_in=0,
                    requires_password_change=True,
                    message="Password change required before login"
                )
            
            # Generate tokens
            access_token_data = {
                "sub": str(user.id),
                "username": user.username,
                "email": user.email,
                "roles": self.user_repo.get_user_roles(user.id),
                "session_id": secrets.token_urlsafe(32),
                "ip": ip_address
            }
            
            access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
            access_token = create_access_token(
                data=access_token_data,
                expires_delta=access_token_expires
            )
            
            refresh_token_expires = timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
            refresh_token = create_refresh_token(
                data={"sub": str(user.id), "session_id": access_token_data["session_id"]},
                expires_delta=refresh_token_expires
            )
            
            # Create session
            session_id = security_manager.session_manager.create_session(
                user_id=user.id,
                ip_address=ip_address,
                user_agent=user_agent
            )
            
            # Record successful login
            self.user_repo.record_successful_login(user.id, ip_address)
            
            # Record security event
            self._record_security_event(
                user.id, ip_address, user_agent,
                "successful_login",
                {
                    "username": user.username,
                    "remember_me": login_data.remember_me,
                    "session_id": session_id
                }
            )
            
            self.logger.info(f"Successful login for user {user.id} from {ip_address}")
            
            # Handle "Remember Me" option
            if login_data.remember_me:
                access_token_expires = timedelta(days=7)  # Extended expiry
            
            return LoginResponse(
                user=UserResponse.from_orm(user),
                access_token=access_token,
                refresh_token=refresh_token,
                token_type="bearer",
                expires_in=int(access_token_expires.total_seconds()),
                session_id=session_id,
                requires_two_factor=user.two_factor_enabled and not login_data.two_factor_code,
                message="Login successful"
            )
            
        except (AuthenticationError, AccountLockedException, RateLimitExceededException):
            raise
        except Exception as e:
            self.logger.error(f"Unexpected error during authentication: {str(e)}")
            raise AuthenticationError("Authentication failed")
    
    def verify_two_factor(
        self,
        two_factor_data: TwoFactorVerifyRequest,
        user_id: int,
        ip_address: str
    ) -> LoginResponse:
        """
        Verify two-factor authentication code.
        
        Args:
            two_factor_data: 2FA verification data
            user_id: User ID
            ip_address: Client IP address
            
        Returns:
            LoginResponse: Complete authentication response
            
        Raises:
            AuthenticationError: If 2FA verification fails
        """
        try:
            # Get user
            user = self.user_repo.get_by_id_or_raise(user_id)
            
            # Verify 2FA code
            if not self._verify_2fa_code(user, two_factor_data.code):
                self._record_security_event(
                    user.id, ip_address, None,
                    "failed_2fa_verification",
                    {"code_length": len(two_factor_data.code)}
                )
                raise AuthenticationError("Invalid 2FA code")
            
            # Generate final tokens (similar to regular login)
            access_token_data = {
                "sub": str(user.id),
                "username": user.username,
                "email": user.email,
                "roles": self.user_repo.get_user_roles(user.id),
                "session_id": secrets.token_urlsafe(32),
                "ip": ip_address,
                "2fa_verified": True
            }
            
            access_token = create_access_token(data=access_token_data)
            refresh_token = create_refresh_token(data={"sub": str(user.id)})
            
            self._record_security_event(
                user.id, ip_address, None,
                "successful_2fa_verification",
                {"verification_method": "totp"}
            )
            
            return LoginResponse(
                user=UserResponse.from_orm(user),
                access_token=access_token,
                refresh_token=refresh_token,
                token_type="bearer",
                expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
                requires_two_factor=False,
                message="2FA verification successful"
            )
            
        except Exception as e:
            self.logger.error(f"Error during 2FA verification: {str(e)}")
            raise AuthenticationError("2FA verification failed")
    
    def refresh_access_token(
        self,
        refresh_data: RefreshTokenRequest,
        ip_address: str
    ) -> RefreshTokenResponse:
        """
        Refresh access token using refresh token.
        
        Args:
            refresh_data: Refresh token request
            ip_address: Client IP address
            
        Returns:
            RefreshTokenResponse: New access token
            
        Raises:
            AuthenticationError: If refresh fails
        """
        try:
            # Verify refresh token
            payload = verify_token(refresh_data.refresh_token, token_type="refresh")
            user_id = int(payload["sub"])
            
            # Get user
            user = self.user_repo.get_by_id(user_id)
            if not user or not user.is_active:
                raise AuthenticationError("Invalid refresh token")
            
            # Check session if available
            session_id = payload.get("session_id")
            if session_id:
                session = security_manager.session_manager.get_session(session_id)
                if not session or not session["is_active"]:
                    raise AuthenticationError("Session has expired")
                
                # Update session activity
                security_manager.session_manager.update_session_activity(session_id)
            
            # Generate new access token
            access_token_data = {
                "sub": str(user.id),
                "username": user.username,
                "email": user.email,
                "roles": self.user_repo.get_user_roles(user.id),
                "session_id": session_id,
                "ip": ip_address
            }
            
            new_access_token = create_access_token(data=access_token_data)
            
            self._record_security_event(
                user.id, ip_address, None,
                "token_refresh",
                {"session_id": session_id}
            )
            
            return RefreshTokenResponse(
                access_token=new_access_token,
                token_type="bearer",
                expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
            )
            
        except Exception as e:
            self.logger.error(f"Error refreshing token: {str(e)}")
            raise AuthenticationError("Token refresh failed")
    
    def logout_user(
        self,
        logout_data: LogoutRequest,
        user_id: int,
        ip_address: str
    ) -> Dict[str, Any]:
        """
        Logout user and invalidate session/tokens.
        
        Args:
            logout_data: Logout request data
            user_id: User ID
            ip_address: Client IP address
            
        Returns:
            Dict[str, Any]: Logout response
        """
        try:
            # Get user
            user = self.user_repo.get_by_id(user_id)
            if not user:
                return {"message": "Logout successful"}
            
            # Invalidate tokens
            if logout_data.access_token:
                security_manager.token_blacklist.blacklist_token(logout_data.access_token)
            
            if logout_data.refresh_token:
                security_manager.token_blacklist.blacklist_token(logout_data.refresh_token)
            
            # Invalidate sessions
            if logout_data.all_sessions:
                # Logout from all sessions
                invalidated_count = security_manager.session_manager.invalidate_user_sessions(user_id)
                message = f"Logged out from all {invalidated_count} sessions"
            else:
                # Logout from current session only
                if logout_data.session_id:
                    security_manager.session_manager.invalidate_session(logout_data.session_id)
                message = "Logged out successfully"
            
            # Record security event
            self._record_security_event(
                user.id, ip_address, None,
                "user_logout",
                {
                    "all_sessions": logout_data.all_sessions,
                    "session_id": logout_data.session_id
                }
            )
            
            self.logger.info(f"User {user_id} logged out from {ip_address}")
            
            return {
                "message": message,
                "logged_out_at": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Error during logout: {str(e)}")
            return {"message": "Logout completed"}
    
    # ==================== PASSWORD MANAGEMENT ====================
    
    def change_password(
        self,
        password_data: PasswordChangeRequest,
        user_id: int,
        ip_address: str
    ) -> Dict[str, Any]:
        """
        Change user password with validation.
        
        Args:
            password_data: Password change request
            user_id: User ID
            ip_address: Client IP address
            
        Returns:
            Dict[str, Any]: Password change response
            
        Raises:
            AuthenticationError: If current password is wrong
            ValidationError: If new password doesn't meet requirements
        """
        try:
            # Get user
            user = self.user_repo.get_by_id_or_raise(user_id)
            
            # Verify current password
            if not verify_password(password_data.current_password, user.hashed_password):
                self._record_security_event(
                    user.id, ip_address, None,
                    "failed_password_change",
                    {"reason": "incorrect_current_password"}
                )
                raise AuthenticationError("Current password is incorrect")
            
            # Validate new password
            password_validation = validate_password_strength(password_data.new_password)
            if not password_validation["is_valid"]:
                raise ValidationError(f"Password requirements not met: {password_validation['message']}")
            
            # Check password history (if enabled)
            if hasattr(user, 'password_history') and user.password_history:
                for old_password_hash in user.password_history[-5:]:  # Check last 5 passwords
                    if verify_password(password_data.new_password, old_password_hash):
                        raise ValidationError("Cannot reuse recent passwords")
            
            # Update password
            new_password_hash = get_password_hash(password_data.new_password)
            success = self.user_repo.update_password(user_id, new_password_hash)
            
            if not success:
                raise ValidationError("Failed to update password")
            
            # Invalidate all sessions except current (if specified)
            current_session = getattr(password_data, 'current_session_id', None)
            security_manager.session_manager.invalidate_user_sessions(
                user_id, 
                except_session=current_session
            )
            
            # Record security event
            self._record_security_event(
                user.id, ip_address, None,
                "password_changed",
                {"force_change": user.force_password_change}
            )
            
            self.logger.info(f"Password changed for user {user_id}")
            
            return {
                "message": "Password changed successfully",
                "password_strength": password_validation["strength"],
                "sessions_invalidated": True,
                "changed_at": datetime.utcnow().isoformat()
            }
            
        except (AuthenticationError, ValidationError):
            raise
        except Exception as e:
            self.logger.error(f"Error changing password: {str(e)}")
            raise ValidationError("Password change failed")
    
    def initiate_password_reset(
        self,
        reset_data: PasswordResetRequest,
        ip_address: str
    ) -> Dict[str, Any]:
        """
        Initiate password reset process.
        
        Args:
            reset_data: Password reset request
            ip_address: Client IP address
            
        Returns:
            Dict[str, Any]: Reset initiation response
        """
        try:
            # Check rate limiting for password reset
            rate_limit_key = f"password_reset:{ip_address}"
            self._check_rate_limit(rate_limit_key, max_requests=3, window_minutes=60)
            
            # Get user
            user = self.user_repo.get_by_email(reset_data.email)
            
            # Always return success to prevent email enumeration
            response = {
                "message": "If the email exists, a reset link has been sent",
                "reset_initiated_at": datetime.utcnow().isoformat()
            }
            
            if not user or not user.is_active:
                # Log potential attack
                self._record_security_event(
                    None, ip_address, None,
                    "password_reset_invalid_email",
                    {"email": reset_data.email}
                )
                return response
            
            # Generate reset token
            reset_token = secrets.token_urlsafe(32)
            reset_expires = datetime.utcnow() + timedelta(hours=1)  # 1 hour expiry
            
            # Store reset token (in production, store in database)
            # For now, we'll store in security manager's memory
            reset_data_dict = {
                "user_id": user.id,
                "token": reset_token,
                "expires_at": reset_expires,
                "ip_address": ip_address,
                "used": False
            }
            
            # In a real implementation, you'd store this in the database
            # security_manager.store_password_reset(reset_token, reset_data_dict)
            
            # Record security event
            self._record_security_event(
                user.id, ip_address, None,
                "password_reset_initiated",
                {"email": user.email}
            )
            
            # TODO: Send email with reset link
            # email_service.send_password_reset_email(user.email, reset_token)
            
            self.logger.info(f"Password reset initiated for user {user.id}")
            
            return response
            
        except RateLimitExceededException:
            raise
        except Exception as e:
            self.logger.error(f"Error initiating password reset: {str(e)}")
            return {
                "message": "If the email exists, a reset link has been sent",
                "reset_initiated_at": datetime.utcnow().isoformat()
            }
    
    # ==================== TWO-FACTOR AUTHENTICATION ====================
    
    def setup_two_factor(self, user_id: int) -> TwoFactorSetupResponse:
        """
        Setup two-factor authentication for user.
        
        Args:
            user_id: User ID
            
        Returns:
            TwoFactorSetupResponse: 2FA setup data
        """
        try:
            # Get user
            user = self.user_repo.get_by_id_or_raise(user_id)
            
            if user.two_factor_enabled:
                raise ValidationError("Two-factor authentication is already enabled")
            
            # Generate 2FA secret
            secret = security_manager.generate_2fa_secret()
            qr_code_url = security_manager.generate_2fa_qr_code(
                secret, 
                user.email, 
                settings.PROJECT_NAME
            )
            
            # Generate backup codes
            backup_codes = security_manager.generate_backup_codes()
            
            # Store secret temporarily (user must verify before enabling)
            # In production, store this securely in database
            temp_2fa_data = {
                "user_id": user_id,
                "secret": secret,
                "backup_codes": backup_codes,
                "verified": False,
                "created_at": datetime.utcnow()
            }
            
            return TwoFactorSetupResponse(
                secret=secret,
                qr_code_url=qr_code_url,
                backup_codes=backup_codes,
                manual_entry_key=secret,
                instructions="Scan the QR code with your authenticator app"
            )
            
        except Exception as e:
            self.logger.error(f"Error setting up 2FA for user {user_id}: {str(e)}")
            raise ValidationError("Failed to setup two-factor authentication")
    
    def verify_and_enable_two_factor(
        self,
        user_id: int,
        verification_code: str,
        ip_address: str
    ) -> Dict[str, Any]:
        """
        Verify 2FA setup and enable two-factor authentication.
        
        Args:
            user_id: User ID
            verification_code: 6-digit verification code
            ip_address: Client IP address
            
        Returns:
            Dict[str, Any]: Verification response
        """
        try:
            # Get user
            user = self.user_repo.get_by_id_or_raise(user_id)
            
            # Get temporary 2FA data
            # In production, retrieve from database
            # temp_2fa_data = get_temp_2fa_data(user_id)
            
            # For demo, assume secret is available
            if not hasattr(user, 'temp_2fa_secret'):
                raise ValidationError("No pending 2FA setup found")
            
            # Verify code
            if not self._verify_2fa_code_with_secret(user.temp_2fa_secret, verification_code):
                raise AuthenticationError("Invalid verification code")
            
            # Enable 2FA
            self.user_repo.update_user(user_id, {
                "two_factor_enabled": True,
                "two_factor_secret": user.temp_2fa_secret,
                "two_factor_backup_codes": user.temp_backup_codes
            })
            
            # Record security event
            self._record_security_event(
                user.id, ip_address, None,
                "2fa_enabled",
                {"verification_method": "totp"}
            )
            
            self.logger.info(f"Two-factor authentication enabled for user {user_id}")
            
            return {
                "message": "Two-factor authentication enabled successfully",
                "enabled_at": datetime.utcnow().isoformat(),
                "backup_codes_generated": True
            }
            
        except Exception as e:
            self.logger.error(f"Error enabling 2FA for user {user_id}: {str(e)}")
            raise ValidationError("Failed to enable two-factor authentication")
    
    def disable_two_factor(
        self,
        user_id: int,
        password: str,
        ip_address: str
    ) -> Dict[str, Any]:
        """
        Disable two-factor authentication.
        
        Args:
            user_id: User ID
            password: User's password for verification
            ip_address: Client IP address
            
        Returns:
            Dict[str, Any]: Disable response
        """
        try:
            # Get user
            user = self.user_repo.get_by_id_or_raise(user_id)
            
            # Verify password
            if not verify_password(password, user.hashed_password):
                raise AuthenticationError("Password verification failed")
            
            # Disable 2FA
            self.user_repo.update_user(user_id, {
                "two_factor_enabled": False,
                "two_factor_secret": None,
                "two_factor_backup_codes": None
            })
            
            # Record security event
            self._record_security_event(
                user.id, ip_address, None,
                "2fa_disabled",
                {"verification_method": "password"}
            )
            
            self.logger.warning(f"Two-factor authentication disabled for user {user_id}")
            
            return {
                "message": "Two-factor authentication disabled",
                "disabled_at": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Error disabling 2FA for user {user_id}: {str(e)}")
            raise ValidationError("Failed to disable two-factor authentication")
    
    # ==================== SECURITY VALIDATION METHODS ====================
    
    def _validate_account_status(self, user) -> None:
        """Validate user account status."""
        if not user.is_active:
            raise AccountInactiveError("Account is deactivated")
        
        if user.status == UserStatus.SUSPENDED.value:
            raise AccountInactiveError("Account is suspended")
        
        if user.status == UserStatus.PENDING.value:
            raise AccountInactiveError("Account is pending verification")
        
        if user.status != UserStatus.ACTIVE.value:
            raise AccountInactiveError(f"Account status: {user.status}")
    
    def _is_account_locked(self, user) -> bool:
        """Check if account is locked."""
        if user.locked_until and user.locked_until > datetime.utcnow():
            return True
        
        # Check failed login attempts
        if (user.failed_login_attempts or 0) >= self.max_login_attempts:
            # Auto-lock account
            self.user_repo.lock_user(user.id, self.lockout_duration)
            return True
        
        return False
    
    def _handle_failed_login(self, user, ip_address: str, user_agent: str = None) -> None:
        """Handle failed login attempt."""
        # Increment failed login attempts
        failed_count = self.user_repo.increment_failed_login(user.id)
        
        # Check if account should be locked
        if failed_count >= self.max_login_attempts:
            self.user_repo.lock_user(user.id, self.lockout_duration)
            self.logger.warning(f"Account {user.id} locked after {failed_count} failed attempts")
        
        # Record security event
        self._record_security_event(
            user.id, ip_address, user_agent,
            "failed_login_attempt",
            {
                "failed_count": failed_count,
                "max_attempts": self.max_login_attempts,
                "locked": failed_count >= self.max_login_attempts
            }
        )
    
    def _record_failed_login(self, user_id: Optional[int], ip_address: str, reason: str) -> None:
        """Record failed login attempt."""
        self._record_security_event(
            user_id, ip_address, None,
            "failed_login_invalid_user",
            {"reason": reason}
        )
    
    def _check_rate_limit(
        self, 
        identifier: str, 
        max_requests: int = 10, 
        window_minutes: int = 15
    ) -> None:
        """Check rate limit for identifier."""
        try:
            security_manager.check_rate_limit(identifier, max_requests, window_minutes)
        except Exception as e:
            self.logger.warning(f"Rate limit exceeded for {identifier}: {str(e)}")
            raise RateLimitExceededException(f"Too many requests. Try again later.")
    
    def _verify_2fa_code(self, user, code: str) -> bool:
        """Verify 2FA code for user."""
        if not user.two_factor_enabled or not user.two_factor_secret:
            return False
        
        return security_manager.verify_2fa_token(user.two_factor_secret, code)
    
    def _verify_2fa_code_with_secret(self, secret: str, code: str) -> bool:
        """Verify 2FA code with provided secret."""
        return security_manager.verify_2fa_token(secret, code)
    
    def _record_security_event(
        self,
        user_id: Optional[int],
        ip_address: str,
        user_agent: Optional[str],
        event_type: str,
        details: Dict[str, Any]
    ) -> None:
        """Record security event for monitoring."""
        try:
            security_event = SecurityEvent(
                event_type=event_type,
                user_id=user_id,
                ip_address=ip_address,
                user_agent=user_agent,
                details=details,
                timestamp=datetime.utcnow(),
                severity=self._get_event_severity(event_type)
            )
            
            # In production, store in database or send to monitoring system
            self.logger.info(f"Security event: {event_type} for user {user_id} from {ip_address}")
            
        except Exception as e:
            self.logger.error(f"Failed to record security event: {str(e)}")
    
    def _get_event_severity(self, event_type: str) -> str:
        """Get severity level for security event."""
        high_severity_events = [
            "multiple_failed_logins", "account_locked", "2fa_disabled",
            "password_reset_invalid_email", "failed_login_locked_account"
        ]
        
        medium_severity_events = [
            "failed_login_attempt", "failed_2fa_verification", "password_changed"
        ]
        
        if event_type in high_severity_events:
            return "high"
        elif event_type in medium_severity_events:
            return "medium"
        else:
            return "low"
    
    # ==================== UTILITY METHODS ====================
    
    def get_user_sessions(self, user_id: int) -> List[Dict[str, Any]]:
        """
        Get active sessions for user.
        
        Args:
            user_id: User ID
            
        Returns:
            List[Dict[str, Any]]: Active sessions
        """
        try:
            # Get sessions from session manager
            sessions = []
            with security_manager.session_manager._lock:
                user_session_ids = security_manager.session_manager._user_sessions.get(user_id, set())
                
                for session_id in user_session_ids:
                    session_data = security_manager.session_manager._active_sessions.get(session_id)
                    if session_data and session_data["is_active"]:
                        sessions.append({
                            "session_id": session_id,
                            "ip_address": session_data["ip_address"],
                            "user_agent": session_data.get("user_agent"),
                            "created_at": session_data["created_at"],
                            "last_activity": session_data["last_activity"]
                        })
            
            return sessions
            
        except Exception as e:
            self.logger.error(f"Error getting user sessions: {str(e)}")
            return []
    
    def cleanup_expired_sessions(self) -> Dict[str, int]:
        """
        Cleanup expired sessions and tokens.
        
        Returns:
            Dict[str, int]: Cleanup statistics
        """
        try:
            # Cleanup expired sessions
            expired_sessions = security_manager.session_manager.cleanup_expired_sessions()
            
            # Cleanup blacklisted tokens
            security_manager.token_blacklist.cleanup_expired()
            
            # Cleanup expired account locks
            unlocked_accounts = self.user_repo.unlock_expired_accounts()
            
            # Cleanup expired role assignments
            expired_roles = self.user_repo.cleanup_expired_role_assignments()
            
            stats = {
                "expired_sessions": expired_sessions,
                "unlocked_accounts": unlocked_accounts,
                "expired_role_assignments": expired_roles,
                "cleanup_timestamp": datetime.utcnow().isoformat()
            }
            
            self.logger.info(f"Security cleanup completed: {stats}")
            return stats
            
        except Exception as e:
            self.logger.error(f"Error during security cleanup: {str(e)}")
            return {"error": str(e)}