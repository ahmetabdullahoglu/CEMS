"""
Module: validators
Purpose: Comprehensive validation utilities for CEMS application
Author: CEMS Development Team
Date: 2024
"""

import re
import ipaddress
from typing import Dict, Any, List, Optional, Union
from datetime import datetime, date
from decimal import Decimal, InvalidOperation
from urllib.parse import urlparse

from app.core.config import settings
from app.core.constants import UserRole, UserStatus, CurrencyCode, REGEX_PATTERNS
from app.utils.logger import get_logger

logger = get_logger(__name__)


# ==================== PASSWORD VALIDATION ====================

def validate_password_strength(
    password: str,
    username: str = None,
    email: str = None
) -> Dict[str, Any]:
    """
    Comprehensive password strength validation according to security policy.
    
    Args:
        password: Password to validate
        username: Optional username to check for similarity
        email: Optional email to check for similarity
        
    Returns:
        Dict[str, Any]: Validation result with detailed feedback
    """
    if not password:
        return {
            "is_strong": False,
            "is_valid": False,
            "strength": "invalid",
            "score": 0,
            "feedback": ["Password is required"],
            "requirements_met": {},
            "estimated_crack_time": "instantly"
        }
    
    # Get policy settings
    min_length = getattr(settings, 'PASSWORD_MIN_LENGTH', 8)
    max_length = getattr(settings, 'PASSWORD_MAX_LENGTH', 128)
    require_upper = getattr(settings, 'PASSWORD_REQUIRE_UPPERCASE', True)
    require_lower = getattr(settings, 'PASSWORD_REQUIRE_LOWERCASE', True)
    require_digit = getattr(settings, 'PASSWORD_REQUIRE_DIGIT', True)
    require_special = getattr(settings, 'PASSWORD_REQUIRE_SPECIAL', True)
    
    requirements_met = {}
    feedback = []
    score = 0
    
    # Length validation
    requirements_met["min_length"] = len(password) >= min_length
    requirements_met["max_length"] = len(password) <= max_length
    
    if not requirements_met["min_length"]:
        feedback.append(f"Password must be at least {min_length} characters long")
    else:
        score += 20
    
    if not requirements_met["max_length"]:
        feedback.append(f"Password must not exceed {max_length} characters")
        return {
            "is_strong": False,
            "is_valid": False,
            "strength": "invalid",
            "score": 0,
            "feedback": feedback,
            "requirements_met": requirements_met,
            "estimated_crack_time": "invalid"
        }
    
    # Character type requirements
    requirements_met["has_uppercase"] = bool(re.search(r'[A-Z]', password))
    requirements_met["has_lowercase"] = bool(re.search(r'[a-z]', password))
    requirements_met["has_digit"] = bool(re.search(r'\d', password))
    requirements_met["has_special"] = bool(re.search(r'[!@#$%^&*(),.?":{}|<>_\-+=\[\]\\\/~`]', password))
    
    if require_upper and not requirements_met["has_uppercase"]:
        feedback.append("Password must contain at least one uppercase letter")
    elif requirements_met["has_uppercase"]:
        score += 15
    
    if require_lower and not requirements_met["has_lowercase"]:
        feedback.append("Password must contain at least one lowercase letter")
    elif requirements_met["has_lowercase"]:
        score += 15
    
    if require_digit and not requirements_met["has_digit"]:
        feedback.append("Password must contain at least one number")
    elif requirements_met["has_digit"]:
        score += 15
    
    if require_special and not requirements_met["has_special"]:
        feedback.append("Password must contain at least one special character (!@#$%^&*(),.?\":{}|<>)")
    elif requirements_met["has_special"]:
        score += 15
    
    # Additional strength checks
    requirements_met["no_repeated_chars"] = not bool(re.search(r'(.)\1{2,}', password))
    requirements_met["no_sequential_chars"] = not bool(re.search(r'(012|123|234|345|456|567|678|789|890|abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)', password.lower()))
    requirements_met["no_common_patterns"] = not _check_common_patterns(password)
    
    if not requirements_met["no_repeated_chars"]:
        feedback.append("Avoid using repeated characters (e.g., 'aaa', '111')")
        score -= 10
    else:
        score += 5
    
    if not requirements_met["no_sequential_chars"]:
        feedback.append("Avoid using sequential characters (e.g., '123', 'abc')")
        score -= 10
    else:
        score += 5
    
    if not requirements_met["no_common_patterns"]:
        feedback.append("Password contains common patterns or dictionary words")
        score -= 20
    else:
        score += 10
    
    # Check similarity to username/email
    if username:
        requirements_met["not_similar_to_username"] = not _is_similar_to_string(password, username)
        if not requirements_met["not_similar_to_username"]:
            feedback.append("Password should not be similar to username")
            score -= 15
        else:
            score += 5
    
    if email:
        email_local = email.split('@')[0] if '@' in email else email
        requirements_met["not_similar_to_email"] = not _is_similar_to_string(password, email_local)
        if not requirements_met["not_similar_to_email"]:
            feedback.append("Password should not be similar to email address")
            score -= 15
        else:
            score += 5
    
    # Bonus points for extra length
    if len(password) >= 12:
        score += 10
    if len(password) >= 16:
        score += 10
    
    # Character diversity bonus
    unique_chars = len(set(password))
    diversity_ratio = unique_chars / len(password)
    if diversity_ratio > 0.7:
        score += 10
    elif diversity_ratio > 0.5:
        score += 5
    
    # Determine strength and validity
    score = max(0, min(100, score))
    
    if score >= 80:
        strength = "very_strong"
    elif score >= 60:
        strength = "strong"
    elif score >= 40:
        strength = "medium"
    elif score >= 20:
        strength = "weak"
    else:
        strength = "very_weak"
    
    # Check if all required criteria are met
    required_criteria = []
    if require_upper:
        required_criteria.append("has_uppercase")
    if require_lower:
        required_criteria.append("has_lowercase")
    if require_digit:
        required_criteria.append("has_digit")
    if require_special:
        required_criteria.append("has_special")
    
    required_criteria.extend(["min_length", "max_length"])
    
    is_valid = all(requirements_met.get(req, False) for req in required_criteria)
    is_strong = is_valid and score >= 60
    
    # Estimate crack time
    crack_time = _estimate_crack_time(password, score)
    
    if not feedback:
        if is_strong:
            feedback.append(f"Strong password! Security score: {score}/100")
        elif is_valid:
            feedback.append(f"Password meets requirements but could be stronger. Score: {score}/100")
    
    return {
        "is_strong": is_strong,
        "is_valid": is_valid,
        "strength": strength,
        "score": score,
        "feedback": feedback,
        "requirements_met": requirements_met,
        "estimated_crack_time": crack_time
    }


def _check_common_patterns(password: str) -> bool:
    """Check for common password patterns."""
    password_lower = password.lower()
    
    # Common passwords
    common_passwords = [
        'password', '123456', 'password123', 'admin', 'letmein',
        'welcome', 'monkey', '1234567890', 'qwerty', 'abc123',
        'iloveyou', 'adobe123', '123123', 'sunshine', 'princess',
        'azerty', 'trustno1', '000000'
    ]
    
    if password_lower in common_passwords:
        return True
    
    # Keyboard patterns
    keyboard_patterns = [
        'qwerty', 'asdf', 'zxcv', '1234', 'abcd'
    ]
    
    for pattern in keyboard_patterns:
        if pattern in password_lower:
            return True
    
    # Date patterns (YYYY, MM/DD/YYYY, etc.)
    date_patterns = [
        r'\d{4}',  # Year
        r'\d{2}/\d{2}/\d{4}',  # MM/DD/YYYY
        r'\d{2}-\d{2}-\d{4}'   # MM-DD-YYYY
    ]
    
    for pattern in date_patterns:
        if re.search(pattern, password):
            return True
    
    return False


def _is_similar_to_string(password: str, compare_string: str, threshold: float = 0.6) -> bool:
    """Check if password is too similar to another string."""
    if not compare_string:
        return False
    
    password_lower = password.lower()
    compare_lower = compare_string.lower()
    
    # Direct substring check
    if len(compare_lower) >= 4 and compare_lower in password_lower:
        return True
    
    if len(password_lower) >= 4 and password_lower in compare_lower:
        return True
    
    # Levenshtein distance similarity (simplified)
    if len(password_lower) > 0 and len(compare_lower) > 0:
        similarity = _calculate_similarity(password_lower, compare_lower)
        return similarity > threshold
    
    return False


def _calculate_similarity(s1: str, s2: str) -> float:
    """Calculate similarity ratio between two strings."""
    if not s1 or not s2:
        return 0.0
    
    # Simple character overlap ratio
    common_chars = set(s1) & set(s2)
    total_chars = set(s1) | set(s2)
    
    if not total_chars:
        return 0.0
    
    return len(common_chars) / len(total_chars)


def _estimate_crack_time(password: str, score: int) -> str:
    """Estimate time to crack password based on complexity."""
    if score >= 80:
        return "centuries"
    elif score >= 60:
        return "decades"
    elif score >= 40:
        return "years"
    elif score >= 20:
        return "months"
    else:
        return "days"


# ==================== EMAIL VALIDATION ====================

def validate_email_format(email: str) -> bool:
    """
    Validate email format using comprehensive validation.
    
    Args:
        email: Email address to validate
        
    Returns:
        bool: True if email is valid
    """
    if not email or not email.strip():
        return False
    
    email = email.strip().lower()
    
    # Basic format check
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(email_pattern, email):
        return False
    
    # Length check
    if len(email) > 254:  # RFC 5321 limit
        return False
    
    local_part, domain = email.rsplit('@', 1)
    
    # Local part validation
    if len(local_part) > 64:  # RFC 5321 limit
        return False
    
    if local_part.startswith('.') or local_part.endswith('.'):
        return False
    
    if '..' in local_part:
        return False
    
    # Domain validation
    if len(domain) > 253:
        return False
    
    if domain.startswith('.') or domain.endswith('.'):
        return False
    
    if '..' in domain:
        return False
    
    # Check for valid domain format
    domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$'
    if not re.match(domain_pattern, domain):
        return False
    
    return True


def validate_email_domain(email: str, allowed_domains: List[str] = None, blocked_domains: List[str] = None) -> bool:
    """
    Validate email domain against allowed/blocked domains.
    
    Args:
        email: Email address to validate
        allowed_domains: List of allowed domains (if None, all domains allowed)
        blocked_domains: List of blocked domains
        
    Returns:
        bool: True if domain is allowed
    """
    if not validate_email_format(email):
        return False
    
    domain = email.split('@')[1].lower()
    
    # Check blocked domains
    if blocked_domains and domain in [d.lower() for d in blocked_domains]:
        return False
    
    # Check allowed domains
    if allowed_domains and domain not in [d.lower() for d in allowed_domains]:
        return False
    
    return True


# ==================== USERNAME VALIDATION ====================

def validate_username_format(username: str) -> bool:
    """
    Validate username format according to business rules.
    
    Args:
        username: Username to validate
        
    Returns:
        bool: True if username is valid
    """
    if not username or not username.strip():
        return False
    
    username = username.strip()
    
    # Length validation
    if len(username) < 3 or len(username) > 50:
        return False
    
    # Character validation (letters, numbers, dots, underscores, hyphens)
    if not re.match(r'^[a-zA-Z0-9._-]+$', username):
        return False
    
    # Must start and end with alphanumeric
    if not re.match(r'^[a-zA-Z0-9].*[a-zA-Z0-9]$', username) and len(username) > 1:
        return False
    
    if len(username) == 1 and not re.match(r'^[a-zA-Z0-9]$', username):
        return False
    
    # No consecutive special characters
    if re.search(r'[._-]{2,}', username):
        return False
    
    # Check reserved usernames
    reserved_usernames = {
        'admin', 'administrator', 'root', 'system', 'api', 'www',
        'mail', 'email', 'support', 'help', 'info', 'contact',
        'cems', 'test', 'demo', 'null', 'undefined', 'anonymous',
        'guest', 'public', 'private', 'secure', 'config', 'settings'
    }
    
    if username.lower() in reserved_usernames:
        return False
    
    # No profanity or inappropriate content (basic check)
    inappropriate_words = {
        'fuck', 'shit', 'damn', 'hell', 'bastard', 'bitch',
        'asshole', 'motherfucker', 'cocksucker', 'pussy'
    }
    
    username_lower = username.lower()
    for word in inappropriate_words:
        if word in username_lower:
            return False
    
    return True


# ==================== PHONE NUMBER VALIDATION ====================

def validate_phone_number(phone: str, country_code: str = None) -> bool:
    """
    Validate phone number format.
    
    Args:
        phone: Phone number to validate
        country_code: Optional country code for specific validation
        
    Returns:
        bool: True if phone number is valid
    """
    if not phone or not phone.strip():
        return False
    
    # Clean phone number
    cleaned_phone = re.sub(r'[^\d+]', '', phone.strip())
    
    # Basic international format validation
    if cleaned_phone.startswith('+'):
        # International format: +[country code][number]
        if len(cleaned_phone) < 8 or len(cleaned_phone) > 15:
            return False
        
        # Country code should be 1-3 digits
        country_part = cleaned_phone[1:4]
        if not country_part.isdigit():
            return False
        
        # Remaining should be digits
        number_part = cleaned_phone[4:]
        if len(number_part) < 4:
            return False
    
    else:
        # Local format validation
        if len(cleaned_phone) < 7 or len(cleaned_phone) > 15:
            return False
        
        if not cleaned_phone.isdigit():
            return False
    
    # Country-specific validation
    if country_code:
        return _validate_country_specific_phone(cleaned_phone, country_code)
    
    return True


def _validate_country_specific_phone(phone: str, country_code: str) -> bool:
    """Validate phone number for specific countries."""
    patterns = {
        'US': r'^\+?1[2-9]\d{2}[2-9]\d{2}\d{4}$',
        'UK': r'^\+?44[1-9]\d{8,9}$',
        'DE': r'^\+?49[1-9]\d{10,11}$',
        'FR': r'^\+?33[1-9]\d{8}$',
        'CA': r'^\+?1[2-9]\d{2}[2-9]\d{2}\d{4}$',
        'AU': r'^\+?61[2-478]\d{8}$',
        'SA': r'^\+?966[5]\d{8}$',  # Saudi Arabia mobile
        'EG': r'^\+?20[1]\d{9}$',   # Egypt mobile
        'AE': r'^\+?971[5]\d{8}$'   # UAE mobile
    }
    
    pattern = patterns.get(country_code.upper())
    if pattern:
        return bool(re.match(pattern, phone))
    
    return True  # Default to valid if country not in patterns


# ==================== IP ADDRESS VALIDATION ====================

def validate_ip_address(ip: str) -> bool:
    """
    Validate IP address (IPv4 or IPv6).
    
    Args:
        ip: IP address to validate
        
    Returns:
        bool: True if IP address is valid
    """
    if not ip or not ip.strip():
        return False
    
    try:
        ipaddress.ip_address(ip.strip())
        return True
    except ValueError:
        return False


def validate_ipv4_address(ip: str) -> bool:
    """
    Validate IPv4 address specifically.
    
    Args:
        ip: IPv4 address to validate
        
    Returns:
        bool: True if IPv4 address is valid
    """
    if not ip or not ip.strip():
        return False
    
    try:
        ipaddress.IPv4Address(ip.strip())
        return True
    except ValueError:
        return False


def validate_ipv6_address(ip: str) -> bool:
    """
    Validate IPv6 address specifically.
    
    Args:
        ip: IPv6 address to validate
        
    Returns:
        bool: True if IPv6 address is valid
    """
    if not ip or not ip.strip():
        return False
    
    try:
        ipaddress.IPv6Address(ip.strip())
        return True
    except ValueError:
        return False


def is_private_ip(ip: str) -> bool:
    """
    Check if IP address is private.
    
    Args:
        ip: IP address to check
        
    Returns:
        bool: True if IP is private
    """
    try:
        ip_obj = ipaddress.ip_address(ip.strip())
        return ip_obj.is_private
    except ValueError:
        return False


# ==================== FINANCIAL VALIDATION ====================

def validate_amount(amount: Union[str, int, float, Decimal], min_amount: float = 0.01, max_amount: float = None) -> bool:
    """
    Validate monetary amount.
    
    Args:
        amount: Amount to validate
        min_amount: Minimum allowed amount
        max_amount: Maximum allowed amount
        
    Returns:
        bool: True if amount is valid
    """
    try:
        if isinstance(amount, str):
            # Remove currency symbols and whitespace
            cleaned_amount = re.sub(r'[^\d.-]', '', amount.strip())
            if not cleaned_amount:
                return False
            decimal_amount = Decimal(cleaned_amount)
        else:
            decimal_amount = Decimal(str(amount))
        
        # Check if positive (or zero if min_amount is 0)
        if decimal_amount < Decimal(str(min_amount)):
            return False
        
        # Check maximum limit
        if max_amount is not None and decimal_amount > Decimal(str(max_amount)):
            return False
        
        # Check decimal places (max 2 for currency)
        if decimal_amount.as_tuple().exponent < -2:
            return False
        
        return True
        
    except (InvalidOperation, ValueError, TypeError):
        return False


def validate_currency_code(currency_code: str) -> bool:
    """
    Validate currency code format and existence.
    
    Args:
        currency_code: Currency code to validate (e.g., 'USD', 'EUR')
        
    Returns:
        bool: True if currency code is valid
    """
    if not currency_code or not currency_code.strip():
        return False
    
    currency_code = currency_code.strip().upper()
    
    # Check format (3 uppercase letters)
    if not re.match(r'^[A-Z]{3}$', currency_code):
        return False
    
    # Check if it's a supported currency
    try:
        return hasattr(CurrencyCode, currency_code)
    except:
        # Fallback to common currency codes
        common_currencies = {
            'USD', 'EUR', 'GBP', 'JPY', 'CHF', 'CAD', 'AUD', 'NZD',
            'SEK', 'NOK', 'DKK', 'PLN', 'CZK', 'HUF', 'RUB', 'CNY',
            'INR', 'KRW', 'SGD', 'HKD', 'MXN', 'BRL', 'ZAR', 'TRY',
            'SAR', 'AED', 'QAR', 'KWD', 'BHD', 'OMR', 'JOD', 'EGP'
        }
        return currency_code in common_currencies


def validate_exchange_rate(rate: Union[str, float, Decimal]) -> bool:
    """
    Validate exchange rate value.
    
    Args:
        rate: Exchange rate to validate
        
    Returns:
        bool: True if exchange rate is valid
    """
    try:
        decimal_rate = Decimal(str(rate))
        
        # Rate must be positive
        if decimal_rate <= 0:
            return False
        
        # Rate should be reasonable (between 0.0001 and 10000)
        if decimal_rate < Decimal('0.0001') or decimal_rate > Decimal('10000'):
            return False
        
        # Check decimal places (max 6 for exchange rates)
        if decimal_rate.as_tuple().exponent < -6:
            return False
        
        return True
        
    except (InvalidOperation, ValueError, TypeError):
        return False


# ==================== BUSINESS VALIDATION ====================

def validate_transaction_reference(reference: str) -> bool:
    """
    Validate transaction reference format.
    
    Args:
        reference: Transaction reference to validate
        
    Returns:
        bool: True if reference is valid
    """
    if not reference or not reference.strip():
        return False
    
    reference = reference.strip()
    
    # Check length
    if len(reference) < 6 or len(reference) > 50:
        return False
    
    # Check format (alphanumeric, hyphens, underscores allowed)
    if not re.match(r'^[A-Za-z0-9_-]+$', reference):
        return False
    
    return True


def validate_branch_code(branch_code: str) -> bool:
    """
    Validate branch code format.
    
    Args:
        branch_code: Branch code to validate
        
    Returns:
        bool: True if branch code is valid
    """
    if not branch_code or not branch_code.strip():
        return False
    
    branch_code = branch_code.strip().upper()
    
    # Check format (3-6 uppercase letters/numbers)
    if not re.match(r'^[A-Z0-9]{3,6}$', branch_code):
        return False
    
    return True


def validate_customer_id(customer_id: str) -> bool:
    """
    Validate customer ID format.
    
    Args:
        customer_id: Customer ID to validate
        
    Returns:
        bool: True if customer ID is valid
    """
    if not customer_id or not customer_id.strip():
        return False
    
    customer_id = customer_id.strip()
    
    # Check length
    if len(customer_id) < 5 or len(customer_id) > 20:
        return False
    
    # Check format (alphanumeric)
    if not re.match(r'^[A-Za-z0-9]+$', customer_id):
        return False
    
    return True


# ==================== URL AND FILE VALIDATION ====================

def validate_url(url: str, allowed_schemes: List[str] = None) -> bool:
    """
    Validate URL format.
    
    Args:
        url: URL to validate
        allowed_schemes: List of allowed schemes (default: http, https)
        
    Returns:
        bool: True if URL is valid
    """
    if not url or not url.strip():
        return False
    
    if allowed_schemes is None:
        allowed_schemes = ['http', 'https']
    
    try:
        parsed = urlparse(url.strip())
        
        # Check scheme
        if parsed.scheme.lower() not in [s.lower() for s in allowed_schemes]:
            return False
        
        # Check netloc (domain)
        if not parsed.netloc:
            return False
        
        # Basic domain validation
        domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$'
        domain = parsed.netloc.split(':')[0]  # Remove port if present
        
        if not re.match(domain_pattern, domain):
            return False
        
        return True
        
    except Exception:
        return False


def validate_file_extension(filename: str, allowed_extensions: List[str]) -> bool:
    """
    Validate file extension.
    
    Args:
        filename: Filename to validate
        allowed_extensions: List of allowed extensions (with or without dots)
        
    Returns:
        bool: True if file extension is valid
    """
    if not filename or not filename.strip():
        return False
    
    if not allowed_extensions:
        return True
    
    # Normalize extensions (ensure they start with dot)
    normalized_extensions = []
    for ext in allowed_extensions:
        if not ext.startswith('.'):
            ext = '.' + ext
        normalized_extensions.append(ext.lower())
    
    # Get file extension
    file_ext = filename.lower().split('.')[-1] if '.' in filename else ''
    if file_ext:
        file_ext = '.' + file_ext
    
    return file_ext in normalized_extensions


# ==================== DATE AND TIME VALIDATION ====================

def validate_date_range(start_date: Union[str, date, datetime], end_date: Union[str, date, datetime]) -> bool:
    """
    Validate date range (start_date <= end_date).
    
    Args:
        start_date: Start date
        end_date: End date
        
    Returns:
        bool: True if date range is valid
    """
    try:
        # Convert strings to date objects
        if isinstance(start_date, str):
            start_date = datetime.strptime(start_date, '%Y-%m-%d').date()
        elif isinstance(start_date, datetime):
            start_date = start_date.date()
        
        if isinstance(end_date, str):
            end_date = datetime.strptime(end_date, '%Y-%m-%d').date()
        elif isinstance(end_date, datetime):
            end_date = end_date.date()
        
        return start_date <= end_date
        
    except (ValueError, TypeError):
        return False


def validate_future_date(target_date: Union[str, date, datetime]) -> bool:
    """
    Validate that date is in the future.
    
    Args:
        target_date: Date to validate
        
    Returns:
        bool: True if date is in the future
    """
    try:
        if isinstance(target_date, str):
            target_date = datetime.strptime(target_date, '%Y-%m-%d').date()
        elif isinstance(target_date, datetime):
            target_date = target_date.date()
        
        return target_date > date.today()
        
    except (ValueError, TypeError):
        return False


# ==================== PERMISSION VALIDATION ====================

def validate_user_permission(user_roles: List[str], required_permission: str, permissions_map: Dict[str, List[str]]) -> bool:
    """
    Validate if user has required permission based on roles.
    
    Args:
        user_roles: List of user roles
        required_permission: Permission to check
        permissions_map: Mapping of roles to permissions
        
    Returns:
        bool: True if user has permission
    """
    if not user_roles or not required_permission:
        return False
    
    # Check if any role has the required permission
    for role in user_roles:
        role_permissions = permissions_map.get(role, [])
        
        # Check exact permission
        if required_permission in role_permissions:
            return True
        
        # Check wildcard permissions
        if '*' in role_permissions:
            return True
        
        # Check pattern matching (e.g., "user.*" matches "user.create")
        for permission in role_permissions:
            if permission.endswith('*'):
                if required_permission.startswith(permission[:-1]):
                    return True
    
    return False


# ==================== COMPOSITE VALIDATION ====================

def validate_user_registration_data(
    username: str,
    email: str,
    password: str,
    first_name: str,
    last_name: str,
    phone_number: str = None
) -> Dict[str, Any]:
    """
    Comprehensive validation for user registration data.
    
    Args:
        username: Username
        email: Email address
        password: Password
        first_name: First name
        last_name: Last name
        phone_number: Optional phone number
        
    Returns:
        Dict with validation results
    """
    errors = []
    warnings = []
    
    # Username validation
    if not validate_username_format(username):
        errors.append("Invalid username format")
    
    # Email validation
    if not validate_email_format(email):
        errors.append("Invalid email format")
    
    # Password validation
    password_result = validate_password_strength(password, username, email)
    if not password_result["is_valid"]:
        errors.extend(password_result["feedback"])
    elif not password_result["is_strong"]:
        warnings.extend(password_result["feedback"])
    
    # Name validation
    if not first_name or not first_name.strip() or len(first_name.strip()) < 2:
        errors.append("First name must be at least 2 characters")
    
    if not last_name or not last_name.strip() or len(last_name.strip()) < 2:
        errors.append("Last name must be at least 2 characters")
    
    # Phone validation (if provided)
    if phone_number and not validate_phone_number(phone_number):
        errors.append("Invalid phone number format")
    
    return {
        "is_valid": len(errors) == 0,
        "errors": errors,
        "warnings": warnings,
        "password_score": password_result.get("score", 0)
    }


def sanitize_input(input_str: str, max_length: int = None, allowed_chars: str = None) -> str:
    """
    Sanitize user input by removing/escaping potentially dangerous characters.
    
    Args:
        input_str: Input string to sanitize
        max_length: Maximum allowed length
        allowed_chars: Pattern of allowed characters
        
    Returns:
        str: Sanitized input string
    """
    if not input_str:
        return ""
    
    # Remove control characters
    sanitized = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', input_str)
    
    # Trim whitespace
    sanitized = sanitized.strip()
    
    # Apply length limit
    if max_length and len(sanitized) > max_length:
        sanitized = sanitized[:max_length]
    
    # Apply character filter
    if allowed_chars:
        sanitized = re.sub(f'[^{allowed_chars}]', '', sanitized)
    
    # Escape HTML special characters
    html_escape_map = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#x27;'
    }
    
    for char, escape in html_escape_map.items():
        sanitized = sanitized.replace(char, escape)
    
    return sanitized