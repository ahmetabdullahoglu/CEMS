"""
Module: security
Purpose: Authentication, authorization, and security utilities for CEMS
Author: CEMS Development Team
Date: 2024
"""

from datetime import datetime, timedelta
from typing import Any, Union, Optional, Dict
from jose import JWTError, jwt
from passlib.context import CryptContext
from passlib.exc import InvalidHashError
import secrets
import hashlib
import hmac
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from app.core.config import settings
from app.core.exceptions import AuthenticationException, TokenExpiredException

# Password hashing context
pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto",
    bcrypt__rounds=12  # Increased rounds for better security
)


class SecurityManager:
    """
    Centralized security manager for CEMS application.
    Handles password hashing, JWT tokens, and security utilities.
    """
    
    def __init__(self):
        """Initialize security manager with configuration."""
        self.algorithm = settings.ALGORITHM
        self.secret_key = settings.SECRET_KEY
        self.access_token_expire_minutes = settings.ACCESS_TOKEN_EXPIRE_MINUTES
        self.refresh_token_expire_days = settings.REFRESH_TOKEN_EXPIRE_DAYS
    
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
        Check password strength and return validation result.
        
        Args:
            password: Password to validate
            
        Returns:
            dict: Validation result with strength score and requirements
        """
        result = {
            "is_valid": False,
            "score": 0,
            "requirements_met": {},
            "suggestions": []
        }
        
        if not password:
            result["suggestions"].append("Password is required")
            return result
        
        # Length requirement
        length_req = len(password) >= settings.PASSWORD_MIN_LENGTH
        result["requirements_met"]["min_length"] = length_req
        if length_req:
            result["score"] += 1
        else:
            result["suggestions"].append(f"Password must be at least {settings.PASSWORD_MIN_LENGTH} characters long")
        
        # Character type requirements
        has_lower = any(c.islower() for c in password)
        has_upper = any(c.isupper() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(c in "!@#$%^&*()_+-=[]{}|;':\",./<>?" for c in password)
        
        result["requirements_met"].update({
            "has_lowercase": has_lower,
            "has_uppercase": has_upper,
            "has_digit": has_digit,
            "has_special": has_special
        })
        
        # Score calculation
        if has_lower:
            result["score"] += 1
        else:
            result["suggestions"].append("Include at least one lowercase letter")
        
        if has_upper:
            result["score"] += 1
        else:
            result["suggestions"].append("Include at least one uppercase letter")
        
        if has_digit:
            result["score"] += 1
        else:
            result["suggestions"].append("Include at least one number")
        
        if has_special:
            result["score"] += 1
        else:
            result["suggestions"].append("Include at least one special character")
        
        # Common passwords check (basic implementation)
        common_passwords = ["password", "123456", "password123", "admin", "user"]
        if password.lower() in common_passwords:
            result["suggestions"].append("Avoid common passwords")
            result["score"] -= 1
        
        # Overall validation
        result["is_valid"] = (
            length_req and has_lower and has_upper and 
            has_digit and result["score"] >= 4
        )
        
        return result
    
    # JWT Token methods
    def create_access_token(
        self, 
        data: Dict[str, Any], 
        expires_delta: Optional[timedelta] = None
    ) -> str:
        """
        Create JWT access token.
        
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
            "type": "access"
        })
        
        encoded_jwt = jwt.encode(to_encode, self.secret_key, algorithm=self.algorithm)
        return encoded_jwt
    
    def create_refresh_token(
        self, 
        data: Dict[str, Any], 
        expires_delta: Optional[timedelta] = None
    ) -> str:
        """
        Create JWT refresh token.
        
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
            "type": "refresh"
        })
        
        encoded_jwt = jwt.encode(to_encode, self.secret_key, algorithm=self.algorithm)
        return encoded_jwt
    
    def verify_token(self, token: str, token_type: str = "access") -> Dict[str, Any]:
        """
        Verify and decode JWT token.
        
        Args:
            token: JWT token to verify
            token_type: Expected token type (access/refresh)
            
        Returns:
            dict: Decoded token payload
            
        Raises:
            AuthenticationException: If token is invalid
            TokenExpiredException: If token is expired
        """
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
    
    def create_reset_token(self, user_id: int) -> str:
        """
        Create password reset token.
        
        Args:
            user_id: User ID for password reset
            
        Returns:
            str: Reset token
        """
        data = {
            "user_id": user_id,
            "purpose": "password_reset",
            "exp": datetime.utcnow() + timedelta(hours=1)  # 1 hour expiry
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
    
    def generate_backup_codes(self, count: int = 10) -> list[str]:
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


# Rate limiting utilities
class RateLimiter:
    """
    Simple in-memory rate limiter for API endpoints.
    In production, should use Redis or similar external store.
    """
    
    def __init__(self):
        """Initialize rate limiter."""
        self.requests = {}  # {key: [(timestamp, count), ...]}
        self.cleanup_interval = 3600  # 1 hour
        self.last_cleanup = datetime.utcnow()
    
    def is_allowed(
        self, 
        key: str, 
        limit: int, 
        window: int = 60,
        burst: int = None
    ) -> tuple[bool, Dict[str, Any]]:
        """
        Check if request is allowed under rate limit.
        
        Args:
            key: Unique identifier for rate limiting
            limit: Number of requests allowed per window
            window: Time window in seconds
            burst: Burst limit (optional)
            
        Returns:
            tuple: (is_allowed, rate_limit_info)
        """
        now = datetime.utcnow()
        
        # Cleanup old entries
        if (now - self.last_cleanup).seconds > self.cleanup_interval:
            self._cleanup()
        
        # Get current window start
        window_start = now - timedelta(seconds=window)
        
        # Initialize or get existing requests for this key
        if key not in self.requests:
            self.requests[key] = []
        
        # Remove requests outside current window
        self.requests[key] = [
            (timestamp, count) for timestamp, count in self.requests[key]
            if timestamp > window_start
        ]
        
        # Count current requests
        current_count = sum(count for _, count in self.requests[key])
        
        # Check limits
        is_allowed = current_count < limit
        if burst and current_count < burst:
            is_allowed = True
        
        # Record this request if allowed
        if is_allowed:
            self.requests[key].append((now, 1))
        
        # Prepare response info
        rate_limit_info = {
            "limit": limit,
            "remaining": max(0, limit - current_count - (1 if is_allowed else 0)),
            "reset": int((now + timedelta(seconds=window)).timestamp()),
            "window": window
        }
        
        return is_allowed, rate_limit_info
    
    def _cleanup(self):
        """Clean up old rate limit entries."""
        cutoff = datetime.utcnow() - timedelta(hours=2)
        
        for key in list(self.requests.keys()):
            self.requests[key] = [
                (timestamp, count) for timestamp, count in self.requests[key]
                if timestamp > cutoff
            ]
            
            # Remove empty entries
            if not self.requests[key]:
                del self.requests[key]
        
        self.last_cleanup = datetime.utcnow()


# Global rate limiter instance
rate_limiter = RateLimiter()


# Security headers utility
def get_security_headers() -> Dict[str, str]:
    """
    Get recommended security headers.
    
    Returns:
        dict: Security headers for HTTP responses
    """
    return {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "X-XSS-Protection": "1; mode=block",
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "Content-Security-Policy": "default-src 'self'",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "geolocation=(), microphone=(), camera=()"
    }


# Input sanitization utilities
def sanitize_input(text: str, max_length: int = 1000) -> str:
    """
    Sanitize user input to prevent injection attacks.
    
    Args:
        text: Input text to sanitize
        max_length: Maximum allowed length
        
    Returns:
        str: Sanitized text
    """
    if not isinstance(text, str):
        text = str(text)
    
    # Truncate to max length
    text = text[:max_length]
    
    # Remove null bytes
    text = text.replace('\x00', '')
    
    # Basic HTML entity encoding for common dangerous characters
    dangerous_chars = {
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#x27;',
        '&': '&amp;'
    }
    
    for char, entity in dangerous_chars.items():
        text = text.replace(char, entity)
    
    return text.strip()


def validate_email_format(email: str) -> bool:
    """
    Validate email format.
    
    Args:
        email: Email to validate
        
    Returns:
        bool: True if email format is valid
    """
    import re
    
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))


def validate_phone_format(phone: str) -> bool:
    """
    Validate phone number format.
    
    Args:
        phone: Phone number to validate
        
    Returns:
        bool: True if phone format is valid
    """
    import re
    
    # Remove common separators
    cleaned = re.sub(r'[\s\-\(\)]+', '', phone)
    
    # Check if it's a valid international format
    pattern = r'^\+?[1-9]\d{1,14}$'
    return bool(re.match(pattern, cleaned))