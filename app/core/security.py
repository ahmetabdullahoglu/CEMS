"""
Module: security
Purpose: Enhanced authentication, authorization, and security utilities for CEMS
Author: CEMS Development Team
Date: 2024
"""

from datetime import datetime, timedelta
from typing import Any, Union, Optional, Dict, List, Set
from collections import defaultdict, deque
import time
import threading
from jose import JWTError, jwt
from passlib.context import CryptContext
from passlib.exc import InvalidHashError
import secrets
import hashlib
import hmac
import re
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from app.core.config import settings
from app.core.exceptions import (
    AuthenticationException, 
    TokenExpiredException,
    InvalidCredentialsException,
    AccountLockedException,
    PasswordStrengthException,
    RateLimitExceededException
)

# Password hashing context with enhanced security
pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto",
    bcrypt__rounds=12,  # Increased rounds for better security
    bcrypt__ident="2b"  # Use bcrypt variant 2b
)


class TokenBlacklist:
    """
    In-memory token blacklist for logged out tokens.
    In production, should use Redis or similar external store.
    """
    
    def __init__(self):
        """Initialize token blacklist."""
        self._blacklisted_tokens: Set[str] = set()
        self._token_expiry: Dict[str, datetime] = {}
        self._lock = threading.Lock()
    
    def add_token(self, token: str, expiry: datetime) -> None:
        """
        Add token to blacklist.
        
        Args:
            token: JWT token to blacklist
            expiry: Token expiry time
        """
        with self._lock:
            self._blacklisted_tokens.add(token)
            self._token_expiry[token] = expiry
    
    def is_blacklisted(self, token: str) -> bool:
        """
        Check if token is blacklisted.
        
        Args:
            token: JWT token to check
            
        Returns:
            bool: True if token is blacklisted
        """
        with self._lock:
            return token in self._blacklisted_tokens
    
    def cleanup_expired(self) -> None:
        """Remove expired tokens from blacklist."""
        now = datetime.utcnow()
        with self._lock:
            expired_tokens = [
                token for token, expiry in self._token_expiry.items()
                if expiry <= now
            ]
            for token in expired_tokens:
                self._blacklisted_tokens.discard(token)
                self._token_expiry.pop(token, None)


class RateLimiter:
    """
    Enhanced in-memory rate limiter for API endpoints.
    In production, should use Redis or similar external store.
    """
    
    def __init__(self):
        """Initialize rate limiter."""
        self._requests: Dict[str, deque] = defaultdict(deque)
        self._lock = threading.Lock()
    
    def is_allowed(
        self, 
        identifier: str, 
        max_requests: int = None,
        window_minutes: int = 1
    ) -> tuple[bool, Dict[str, Any]]:
        """
        Check if request is allowed under rate limit.
        
        Args:
            identifier: Unique identifier (IP, user_id, etc.)
            max_requests: Maximum requests allowed
            window_minutes: Time window in minutes
            
        Returns:
            tuple: (is_allowed, rate_limit_info)
        """
        max_requests = max_requests or settings.RATE_LIMIT_PER_MINUTE
        window_seconds = window_minutes * 60
        now = time.time()
        cutoff = now - window_seconds
        
        with self._lock:
            # Clean old requests
            request_times = self._requests[identifier]
            while request_times and request_times[0] < cutoff:
                request_times.popleft()
            
            current_count = len(request_times)
            
            if current_count >= max_requests:
                # Rate limit exceeded
                oldest_request = request_times[0] if request_times else now
                reset_time = oldest_request + window_seconds
                
                return False, {
                    "allowed": False,
                    "current_requests": current_count,
                    "max_requests": max_requests,
                    "window_minutes": window_minutes,
                    "reset_at": reset_time,
                    "retry_after": max(0, reset_time - now)
                }
            
            # Allow request and record it
            request_times.append(now)
            
            return True, {
                "allowed": True,
                "current_requests": current_count + 1,
                "max_requests": max_requests,
                "window_minutes": window_minutes,
                "remaining_requests": max_requests - current_count - 1
            }


class SessionManager:
    """
    Enhanced session management for tracking active user sessions.
    """
    
    def __init__(self):
        """Initialize session manager."""
        self._active_sessions: Dict[str, Dict[str, Any]] = {}
        self._user_sessions: Dict[int, Set[str]] = defaultdict(set)
        self._lock = threading.Lock()
    
    def create_session(
        self, 
        user_id: int, 
        ip_address: str,
        user_agent: str = None
    ) -> str:
        """
        Create a new user session.
        
        Args:
            user_id: User ID
            ip_address: Client IP address
            user_agent: Client user agent
            
        Returns:
            str: Session ID
        """
        session_id = secrets.token_urlsafe(32)
        session_data = {
            "user_id": user_id,
            "ip_address": ip_address,
            "user_agent": user_agent,
            "created_at": datetime.utcnow(),
            "last_activity": datetime.utcnow(),
            "is_active": True
        }
        
        with self._lock:
            self._active_sessions[session_id] = session_data
            self._user_sessions[user_id].add(session_id)
        
        return session_id
    
    def update_session_activity(self, session_id: str) -> bool:
        """
        Update session last activity.
        
        Args:
            session_id: Session ID
            
        Returns:
            bool: True if session updated successfully
        """
        with self._lock:
            if session_id in self._active_sessions:
                self._active_sessions[session_id]["last_activity"] = datetime.utcnow()
                return True
            return False
    
    def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """
        Get session data.
        
        Args:
            session_id: Session ID
            
        Returns:
            dict: Session data or None
        """
        with self._lock:
            return self._active_sessions.get(session_id)
    
    def invalidate_session(self, session_id: str) -> bool:
        """
        Invalidate a specific session.
        
        Args:
            session_id: Session ID
            
        Returns:
            bool: True if session invalidated successfully
        """
        with self._lock:
            if session_id in self._active_sessions:
                session_data = self._active_sessions[session_id]
                user_id = session_data["user_id"]
                
                # Remove from active sessions
                del self._active_sessions[session_id]
                
                # Remove from user sessions
                self._user_sessions[user_id].discard(session_id)
                
                return True
            return False
    
    def invalidate_user_sessions(self, user_id: int, except_session: str = None) -> int:
        """
        Invalidate all sessions for a user.
        
        Args:
            user_id: User ID
            except_session: Session ID to keep active
            
        Returns:
            int: Number of sessions invalidated
        """
        invalidated_count = 0
        
        with self._lock:
            session_ids = self._user_sessions[user_id].copy()
            
            for session_id in session_ids:
                if except_session and session_id == except_session:
                    continue
                
                if self.invalidate_session(session_id):
                    invalidated_count += 1
        
        return invalidated_count
    
    def cleanup_expired_sessions(self, max_idle_hours: int = 24) -> int:
        """
        Remove expired sessions.
        
        Args:
            max_idle_hours: Maximum idle time in hours
            
        Returns:
            int: Number of sessions cleaned up
        """
        cutoff_time = datetime.utcnow() - timedelta(hours=max_idle_hours)
        expired_sessions = []
        
        with self._lock:
            for session_id, session_data in self._active_sessions.items():
                if session_data["last_activity"] < cutoff_time:
                    expired_sessions.append(session_id)
            
            for session_id in expired_sessions:
                self.invalidate_session(session_id)
        
        return len(expired_sessions)


class SecurityManager:
    """
    Enhanced centralized security manager for CEMS application.
    Handles password hashing, JWT tokens, sessions, and security utilities.
    """
    
    def __init__(self):
        """Initialize security manager with configuration."""
        self.algorithm = getattr(settings, 'ALGORITHM', 'HS256')
        self.secret_key = settings.SECRET_KEY
        self.access_token_expire_minutes = getattr(settings, 'ACCESS_TOKEN_EXPIRE_MINUTES', 30)
        self.refresh_token_expire_days = getattr(settings, 'REFRESH_TOKEN_EXPIRE_DAYS', 7)
        
        # Initialize components
        self.token_blacklist = TokenBlacklist()
        self.rate_limiter = RateLimiter()
        self.session_manager = SessionManager()
        
        # Password policy
        self.password_min_length = getattr(settings, 'PASSWORD_MIN_LENGTH', 8)
        self.password_max_length = getattr(settings, 'PASSWORD_MAX_LENGTH', 128)
        self.password_require_upper = getattr(settings, 'PASSWORD_REQUIRE_UPPERCASE', True)
        self.password_require_lower = getattr(settings, 'PASSWORD_REQUIRE_LOWERCASE', True)
        self.password_require_digit = getattr(settings, 'PASSWORD_REQUIRE_DIGIT', True)
        self.password_require_special = getattr(settings, 'PASSWORD_REQUIRE_SPECIAL', True)
    
    # Password handling methods
    def get_password_hash(self, password: str) -> str:
        """
        Hash a password using bcrypt.
        
        Args:
            password: Plain text password
            
        Returns:
            str: Hashed password
        """
        return pwd_context.hash(password)
    
    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """
        Verify a password against its hash.
        
        Args:
            plain_password: Plain text password
            hashed_password: Stored hash
            
        Returns:
            bool: True if password matches
        """
        try:
            return pwd_context.verify(plain_password, hashed_password)
        except (InvalidHashError, ValueError):
            return False
    
    def check_password_strength(self, password: str) -> Dict[str, Any]:
        """
        Enhanced password strength validation.
        
        Args:
            password: Password to validate
            
        Returns:
            dict: Validation result with detailed feedback
        """
        result = {
            "is_valid": False,
            "score": 0,
            "max_score": 8,
            "strength": "weak",
            "requirements_met": {
                "min_length": False,
                "max_length": False,
                "has_lowercase": False,
                "has_uppercase": False,
                "has_digit": False,
                "has_special": False,
                "no_common_patterns": False,
                "no_repeated_chars": False
            },
            "suggestions": [],
            "estimated_crack_time": "seconds"
        }
        
        if not password:
            result["suggestions"].append("Password is required")
            return result
        
        # Length validation
        length_req = self.password_min_length <= len(password) <= self.password_max_length
        result["requirements_met"]["min_length"] = len(password) >= self.password_min_length
        result["requirements_met"]["max_length"] = len(password) <= self.password_max_length
        
        if not result["requirements_met"]["min_length"]:
            result["suggestions"].append(f"Password must be at least {self.password_min_length} characters")
        
        if not result["requirements_met"]["max_length"]:
            result["suggestions"].append(f"Password must be no more than {self.password_max_length} characters")
        
        # Character type validation
        has_lower = any(c.islower() for c in password)
        has_upper = any(c.isupper() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password)
        
        result["requirements_met"].update({
            "has_lowercase": has_lower,
            "has_uppercase": has_upper,
            "has_digit": has_digit,
            "has_special": has_special
        })
        
        # Score calculation
        if has_lower:
            result["score"] += 1
        elif self.password_require_lower:
            result["suggestions"].append("Include at least one lowercase letter")
        
        if has_upper:
            result["score"] += 1
        elif self.password_require_upper:
            result["suggestions"].append("Include at least one uppercase letter")
        
        if has_digit:
            result["score"] += 1
        elif self.password_require_digit:
            result["suggestions"].append("Include at least one number")
        
        if has_special:
            result["score"] += 1
        elif self.password_require_special:
            result["suggestions"].append("Include at least one special character (!@#$%^&*)")
        
        # Length bonus
        if len(password) >= 12:
            result["score"] += 1
        
        if len(password) >= 16:
            result["score"] += 1
        
        # Pattern analysis
        # Check for repeated characters (more than 2 consecutive)
        repeated_pattern = re.search(r'(.)\1{2,}', password)
        if not repeated_pattern:
            result["score"] += 1
            result["requirements_met"]["no_repeated_chars"] = True
        else:
            result["suggestions"].append("Avoid repeated characters")
        
        # Check for common patterns
        common_patterns = [
            r'123+', r'abc+', r'qwe+', r'password', r'admin', 
            r'user', r'login', r'welcome', r'secret'
        ]
        
        has_common_pattern = any(
            re.search(pattern, password.lower()) for pattern in common_patterns
        )
        
        if not has_common_pattern:
            result["score"] += 1
            result["requirements_met"]["no_common_patterns"] = True
        else:
            result["suggestions"].append("Avoid common words and patterns")
        
        # Determine strength level
        if result["score"] >= 7:
            result["strength"] = "very_strong"
            result["estimated_crack_time"] = "centuries"
        elif result["score"] >= 6:
            result["strength"] = "strong"
            result["estimated_crack_time"] = "years"
        elif result["score"] >= 4:
            result["strength"] = "moderate"
            result["estimated_crack_time"] = "days"
        elif result["score"] >= 2:
            result["strength"] = "weak"
            result["estimated_crack_time"] = "hours"
        else:
            result["strength"] = "very_weak"
            result["estimated_crack_time"] = "seconds"
        
        # Overall validation
        required_score = 4  # Minimum acceptable score
        result["is_valid"] = (
            length_req and 
            result["score"] >= required_score and
            (not self.password_require_lower or has_lower) and
            (not self.password_require_upper or has_upper) and
            (not self.password_require_digit or has_digit) and
            (not self.password_require_special or has_special)
        )
        
        return result
    
    # Enhanced JWT Token methods
    def create_access_token(
        self, 
        data: Dict[str, Any], 
        expires_delta: Optional[timedelta] = None
    ) -> str:
        """
        Create JWT access token with enhanced security.
        
        Args:
            data: Data to encode in token
            expires_delta: Custom expiration time
            
        Returns:
            str: JWT access token
        """
        to_encode = data.copy()
        
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(minutes=self.access_token_expire_minutes)
        
        to_encode.update({
            "exp": expire,
            "iat": datetime.utcnow(),
            "type": "access",
            "jti": secrets.token_urlsafe(16)  # JWT ID for tracking
        })
        
        encoded_jwt = jwt.encode(to_encode, self.secret_key, algorithm=self.algorithm)
        return encoded_jwt
    
    def create_refresh_token(
        self, 
        data: Dict[str, Any], 
        expires_delta: Optional[timedelta] = None
    ) -> str:
        """
        Create JWT refresh token with enhanced security.
        
        Args:
            data: Data to encode in token
            expires_delta: Custom expiration time
            
        Returns:
            str: JWT refresh token
        """
        to_encode = data.copy()
        
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(days=self.refresh_token_expire_days)
        
        to_encode.update({
            "exp": expire,
            "iat": datetime.utcnow(),
            "type": "refresh",
            "jti": secrets.token_urlsafe(16)  # JWT ID for tracking
        })
        
        encoded_jwt = jwt.encode(to_encode, self.secret_key, algorithm=self.algorithm)
        return encoded_jwt
    
    def verify_token(self, token: str, token_type: str = "access") -> Dict[str, Any]:
        """
        Enhanced token verification with blacklist checking.
        
        Args:
            token: JWT token to verify
            token_type: Expected token type (access/refresh)
            
        Returns:
            dict: Decoded token payload
            
        Raises:
            AuthenticationException: If token is invalid
            TokenExpiredException: If token is expired
        """
        # Check blacklist first
        if self.token_blacklist.is_blacklisted(token):
            raise AuthenticationException(
                message="Token has been revoked",
                details={"reason": "blacklisted"}
            )
        
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            
            # Check token type
            if payload.get("type") != token_type:
                raise AuthenticationException(
                    message=f"Invalid token type. Expected: {token_type}",
                    details={"expected_type": token_type, "actual_type": payload.get("type")}
                )
            
            # Check expiration
            exp_timestamp = payload.get("exp")
            if exp_timestamp and datetime.utcnow().timestamp() > exp_timestamp:
                raise TokenExpiredException(
                    details={"expired_at": datetime.fromtimestamp(exp_timestamp).isoformat()}
                )
            
            return payload
            
        except JWTError as e:
            if "expired" in str(e).lower():
                raise TokenExpiredException()
            else:
                raise AuthenticationException(
                    message="Invalid token",
                    details={"jwt_error": str(e)}
                )
    
    def revoke_token(self, token: str) -> bool:
        """
        Revoke (blacklist) a token.
        
        Args:
            token: JWT token to revoke
            
        Returns:
            bool: True if token was revoked successfully
        """
        try:
            # Decode token to get expiry (without verification for blacklisting)
            unverified_payload = jwt.get_unverified_claims(token)
            exp_timestamp = unverified_payload.get("exp")
            
            if exp_timestamp:
                expiry = datetime.fromtimestamp(exp_timestamp)
                self.token_blacklist.add_token(token, expiry)
                return True
            
        except Exception:
            pass
        
        return False
    
    def create_reset_token(self, user_id: int) -> str:
        """
        Create password reset token with enhanced security.
        
        Args:
            user_id: User ID for password reset
            
        Returns:
            str: Reset token
        """
        data = {
            "user_id": user_id,
            "purpose": "password_reset",
            "exp": datetime.utcnow() + timedelta(hours=1),  # 1 hour expiry
            "jti": secrets.token_urlsafe(16)
        }
        return jwt.encode(data, self.secret_key, algorithm=self.algorithm)
    
    def verify_reset_token(self, token: str) -> Optional[int]:
        """
        Verify password reset token and return user ID.
        
        Args:
            token: Reset token to verify
            
        Returns:
            int: User ID if token is valid, None otherwise
        """
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            
            if payload.get("purpose") != "password_reset":
                return None
            
            return payload.get("user_id")
            
        except JWTError:
            return None
    
    # Security utilities
    def generate_secure_token(self, length: int = 32) -> str:
        """
        Generate a secure random token.
        
        Args:
            length: Length of token in bytes
            
        Returns:
            str: Secure random token (hex encoded)
        """
        return secrets.token_hex(length)
    
    def generate_api_key(self, prefix: str = "cems") -> str:
        """
        Generate API key with prefix.
        
        Args:
            prefix: Prefix for API key
            
        Returns:
            str: Generated API key
        """
        random_part = secrets.token_urlsafe(32)
        return f"{prefix}_{random_part}"
    
    def hash_api_key(self, api_key: str) -> str:
        """
        Hash API key for storage.
        
        Args:
            api_key: API key to hash
            
        Returns:
            str: Hashed API key
        """
        return hashlib.sha256(api_key.encode()).hexdigest()
    
    def verify_api_key(self, api_key: str, hashed_key: str) -> bool:
        """
        Verify API key against stored hash.
        
        Args:
            api_key: API key to verify
            hashed_key: Stored hash
            
        Returns:
            bool: True if API key is valid
        """
        return hmac.compare_digest(
            hashlib.sha256(api_key.encode()).hexdigest(),
            hashed_key
        )
    
    def create_csrf_token(self, session_id: str) -> str:
        """
        Create CSRF protection token.
        
        Args:
            session_id: Session identifier
            
        Returns:
            str: CSRF token
        """
        timestamp = str(int(datetime.utcnow().timestamp()))
        message = f"{session_id}:{timestamp}"
        signature = hmac.new(
            self.secret_key.encode(),
            message.encode(),
            hashlib.sha256
        ).hexdigest()
        
        return f"{timestamp}:{signature}"
    
    def verify_csrf_token(self, token: str, session_id: str, max_age: int = 3600) -> bool:
        """
        Verify CSRF token.
        
        Args:
            token: CSRF token to verify
            session_id: Session identifier
            max_age: Maximum age in seconds
            
        Returns:
            bool: True if token is valid
        """
        try:
            timestamp_str, signature = token.split(':', 1)
            timestamp = int(timestamp_str)
            
            # Check age
            if datetime.utcnow().timestamp() - timestamp > max_age:
                return False
            
            # Verify signature
            message = f"{session_id}:{timestamp_str}"
            expected_signature = hmac.new(
                self.secret_key.encode(),
                message.encode(),
                hashlib.sha256
            ).hexdigest()
            
            return hmac.compare_digest(signature, expected_signature)
            
        except (ValueError, AttributeError):
            return False
    
    # Two-factor authentication utilities
    def generate_2fa_secret(self) -> str:
        """
        Generate base32 secret for TOTP 2FA.
        
        Returns:
            str: Base32 encoded secret
        """
        import base64
        random_bytes = secrets.token_bytes(20)
        return base64.b32encode(random_bytes).decode('utf-8')
    
    def verify_2fa_token(self, secret: str, token: str, window: int = 1) -> bool:
        """
        Verify TOTP 2FA token.
        
        Args:
            secret: Base32 encoded secret
            token: 6-digit TOTP token
            window: Time window tolerance
            
        Returns:
            bool: True if token is valid
        """
        try:
            import pyotp
            totp = pyotp.TOTP(secret)
            return totp.verify(token, valid_window=window)
        except ImportError:
            # Fallback implementation without pyotp
            return False
    
    def generate_backup_codes(self, count: int = 10) -> List[str]:
        """
        Generate backup codes for 2FA recovery.
        
        Args:
            count: Number of backup codes to generate
            
        Returns:
            list: List of backup codes
        """
        codes = []
        for _ in range(count):
            # Generate 8-character alphanumeric code
            code = secrets.token_hex(4).upper()
            # Format as XXXX-XXXX
            formatted_code = f"{code[:4]}-{code[4:]}"
            codes.append(formatted_code)
        
        return codes
    
    # Rate limiting methods
    def check_rate_limit(
        self, 
        identifier: str, 
        max_requests: int = None,
        window_minutes: int = 1
    ) -> Dict[str, Any]:
        """
        Check rate limit for identifier.
        
        Args:
            identifier: Unique identifier (IP, user_id, etc.)
            max_requests: Maximum requests allowed
            window_minutes: Time window in minutes
            
        Returns:
            dict: Rate limit information
            
        Raises:
            RateLimitExceededException: If rate limit is exceeded
        """
        is_allowed, rate_info = self.rate_limiter.is_allowed(
            identifier, max_requests, window_minutes
        )
        
        if not is_allowed:
            raise RateLimitExceededException(
                details=rate_info
            )
        
        return rate_info
    
    # Cleanup methods
    def cleanup_expired_data(self) -> Dict[str, int]:
        """
        Cleanup expired tokens and sessions.
        
        Returns:
            dict: Cleanup statistics
        """
        self.token_blacklist.cleanup_expired()
        expired_sessions = self.session_manager.cleanup_expired_sessions()
        
        return {
            "expired_sessions_cleaned": expired_sessions
        }


# Global security manager instance
security_manager = SecurityManager()

# Convenience functions for backward compatibility
def get_password_hash(password: str) -> str:
    """Hash a password using bcrypt."""
    return security_manager.get_password_hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash."""
    return security_manager.verify_password(plain_password, hashed_password)


def create_access_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    """Create JWT access token."""
    return security_manager.create_access_token(data, expires_delta)


def create_refresh_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    """Create JWT refresh token."""
    return security_manager.create_refresh_token(data, expires_delta)


def verify_token(token: str, token_type: str = "access") -> Dict[str, Any]:
    """Verify and decode JWT token."""
    return security_manager.verify_token(token, token_type)


def check_password_strength(password: str) -> Dict[str, Any]:
    """Check password strength and return validation result."""
    return security_manager.check_password_strength(password)


def generate_secure_token(length: int = 32) -> str:
    """Generate a secure random token."""
    return security_manager.generate_secure_token(length)


def generate_api_key(prefix: str = "cems") -> str:
    """Generate API key with prefix."""
    return security_manager.generate_api_key(prefix)


def check_rate_limit(identifier: str, max_requests: int = None, window_minutes: int = 1) -> Dict[str, Any]:
    """Check rate limit for identifier."""
    return security_manager.check_rate_limit(identifier, max_requests, window_minutes)


# Additional security utilities
def generate_otp(length: int = 6) -> str:
    """
    Generate numeric OTP (One-Time Password).
    
    Args:
        length: Length of OTP
        
    Returns:
        str: Generated OTP
    """
    return ''.join(secrets.choice('0123456789') for _ in range(length))


def mask_sensitive_data(data: str, visible_chars: int = 4) -> str:
    """
    Mask sensitive data for logging/display.
    
    Args:
        data: Sensitive data to mask
        visible_chars: Number of characters to show
        
    Returns:
        str: Masked data
    """
    if len(data) <= visible_chars:
        return '*' * len(data)
    
    return data[:visible_chars] + '*' * (len(data) - visible_chars)


def secure_compare(a: str, b: str) -> bool:
    """
    Secure string comparison to prevent timing attacks.
    
    Args:
        a: First string
        b: Second string
        
    Returns:
        bool: True if strings are equal
    """
    return hmac.compare_digest(a.encode(), b.encode())