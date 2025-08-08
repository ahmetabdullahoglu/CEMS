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
from email_validator import validate_email, EmailNotValidError

from app.core.config import settings
from app.core.constants import UserRole, UserStatus, CurrencyCode
from app.utils.logger import get_logger

logger = get_logger(__name__)


# ==================== PASSWORD VALIDATION ====================

def validate_password_strength(password: str) -> Dict[str, Any]:
    """
    Validate password strength according to security policy.
    
    Args:
        password: Password to validate
        
    Returns:
        Dict[str, Any]: Validation result with strength score
    """
    if not password:
        return {
            "is_valid": False,
            "strength": "very_weak",
            "score": 0,
            "message": "Password is required",
            "requirements_met": [],
            "requirements_failed": ["password_required"]
        }
    
    # Get policy settings
    min_length = getattr(settings, 'PASSWORD_MIN_LENGTH', 8)
    max_length = getattr(settings, 'PASSWORD_MAX_LENGTH', 128)
    require_upper = getattr(settings, 'PASSWORD_REQUIRE_UPPERCASE', True)
    require_lower = getattr(settings, 'PASSWORD_REQUIRE_LOWERCASE', True)
    require_digit = getattr(settings, 'PASSWORD_REQUIRE_DIGIT', True)
    require_special = getattr(settings, 'PASSWORD_REQUIRE_SPECIAL', True)
    
    requirements_met = []
    requirements_failed = []
    score = 0
    
    # Length validation
    if len(password) >= min_length:
        requirements_met.append("min_length")
        score += 20
    else:
        requirements_failed.append(f"min_length_{min_length}")
    
    if len(password) <= max_length:
        requirements_met.append("max_length")
    else:
        requirements_failed.append(f"max_length_{max_length}")
        return {
            "is_valid": False,
            "strength": "invalid",
            "score": 0,
            "message": f"Password must not exceed {max_length} characters",
            "requirements_met": requirements_met,
            "requirements_failed": requirements_failed
        }
    
    # Uppercase validation
    if require_upper:
        if re.search(r'[A-Z]', password):
            requirements_met.append("uppercase")
            score += 15
        else:
            requirements_failed.append("uppercase")
    
    # Lowercase validation
    if require_lower:
        if re.search(r'[a-z]', password):
            requirements_met.append("lowercase")
            score += 15
        else:
            requirements_failed.append("lowercase")
    
    # Digit validation
    if require_digit:
        if re.search(r'\d', password):
            requirements_met.append("digit")
            score += 15
        else:
            requirements_failed.append("digit")
    
    # Special character validation
    if require_special:
        special_chars = r'[!@#$%^&*(),.?":{}|<>]'
        if re.search(special_chars, password):
            requirements_met.append("special_char")
            score += 15
        else:
            requirements_failed.append("special_char")
    
    # Additional strength factors
    # Bonus for length
    if len(password) >= 12:
        score += 10
    if len(password) >= 16:
        score += 10
    
    # Bonus for character diversity
    char_types = 0
    if re.search(r'[a-z]', password):
        char_types += 1
    if re.search(r'[A-Z]', password):
        char_types += 1
    if re.search(r'\d', password):
        char_types += 1
    if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        char_types += 1
    
    score += char_types * 5
    
    # Penalty for common patterns
    if re.search(r'(.)\1{2,}', password):  # Repeated characters
        score -= 10
    if re.search(r'(012|123|234|345|456|567|678|789|890)', password):  # Sequential numbers
        score -= 10
    if re.search(r'(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)', password.lower()):  # Sequential letters
        score -= 10
    
    # Common passwords check (basic)
    common_passwords = [
        'password', '123456', 'password123', 'admin', 'letmein',
        'welcome', 'monkey', '1234567890', 'qwerty', 'abc123'
    ]
    if password.lower() in common_passwords:
        score -= 30
    
    # Determine strength
    if score < 30:
        strength = "very_weak"
    elif score < 50:
        strength = "weak"
    elif score < 70:
        strength = "medium"
    elif score < 85:
        strength = "strong"
    else:
        strength = "very_strong"
    
    # Determine validity
    is_valid = len(requirements_failed) == 0
    
    # Generate message
    if is_valid:
        message = f"Password strength: {strength.replace('_', ' ').title()}"
    else:
        failed_requirements = []
        for req in requirements_failed:
            if req.startswith("min_length"):
                failed_requirements.append(f"at least {min_length} characters")
            elif req == "uppercase":
                failed_requirements.append("uppercase letter")
            elif req == "lowercase":
                failed_requirements.append("lowercase letter")
            elif req == "digit":
                failed_requirements.append("number")
            elif req == "special_char":
                failed_requirements.append("special character")
        
        message = f"Password must contain: {', '.join(failed_requirements)}"
    
    return {
        "is_valid": is_valid,
        "strength": strength,
        "score": max(0, min(100, score)),
        "message": message,
        "requirements_met": requirements_met,
        "requirements_failed": requirements_failed
    }


# ==================== EMAIL VALIDATION ====================

def validate_email_format(email: str) -> bool:
    """
    Validate email format using comprehensive validation.
    
    Args:
        email: Email address to validate
        
    Returns:
        bool: True if email is valid
    """
    try:
        if not email or not email.strip():
            return False
        
        # Use email-validator library for comprehensive validation
        valid = validate_email(email.strip())
        return True
        
    except EmailNotValidError:
        return False
    except Exception as e:
        logger.warning(f"Email validation error: {str(e)}")
        return False


def validate_email_domain(email: str, allowed_domains: List[str] = None) -> bool:
    """
    Validate email domain against allowed domains.
    
    Args:
        email: Email address to validate
        allowed_domains: List of allowed domains
        
    Returns:
        bool: True if domain is allowed
    """
    try:
        if not validate_email_format(email):
            return False
        
        if not allowed_domains:
            return True
        
        domain = email.split('@')[1].lower()
        return domain in [d.lower() for d in allowed_domains]
        
    except Exception:
        return False


# ==================== USERNAME VALIDATION ====================

def validate_username_format(username: str) -> bool:
    """
    Validate username format according to rules.
    
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
    
    # Must start with letter or number
    if not re.match(r'^[a-zA-Z0-9]', username):
        return False
    
    # Must end with letter or number
    if not re.match(r'[a-zA-Z0-9]$', username):
        return False
    
    # No consecutive special characters
    if re.search(r'[._-]{2,}', username):
        return False
    
    # Reserved usernames
    reserved_usernames = [
        'admin', 'administrator', 'root', 'system', 'api', 'www',
        'mail', 'email', 'support', 'help', 'info', 'contact',
        'cems', 'test', 'demo', 'null', 'undefined'
    ]
    
    if username.lower() in reserved_usernames:
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
    
    # Remove all non-digit characters except +
    clean_phone = re.sub(r'[^\d+]', '', phone.strip())
    
    # Basic format validation
    if not clean_phone:
        return False
    
    # International format (with +)
    if clean_phone.startswith('+'):
        # Remove + and validate
        digits = clean_phone[1:]
        if not digits.isdigit():
            return False
        
        # Length validation (7-15 digits for international numbers)
        if len(digits) < 7 or len(digits) > 15:
            return False
        
        return True
    
    # Local format validation
    if clean_phone.isdigit():
        # Common length ranges
        if len(clean_phone) >= 7 and len(clean_phone) <= 15:
            return True
    
    return False


# ==================== IP ADDRESS VALIDATION ====================

def validate_ip_address(ip: str) -> bool:
    """
    Validate IP address (IPv4 or IPv6).
    
    Args:
        ip: IP address to validate
        
    Returns:
        bool: True if IP address is valid
    """
    try:
        if not ip or not ip.strip():
            return False
        
        ipaddress.ip_address(ip.strip())
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


# ==================== CURRENCY AND AMOUNT VALIDATION ====================

def validate_currency_code(currency_code: str) -> bool:
    """
    Validate currency code against supported currencies.
    
    Args:
        currency_code: Currency code to validate
        
    Returns:
        bool: True if currency code is valid
    """
    if not currency_code or len(currency_code) != 3:
        return False
    
    # Check against enum values
    try:
        CurrencyCode(currency_code.upper())
        return True
    except ValueError:
        return False


def validate_amount(amount: Union[str, int, float, Decimal], currency: str = None) -> Dict[str, Any]:
    """
    Validate monetary amount.
    
    Args:
        amount: Amount to validate
        currency: Currency code for currency-specific validation
        
    Returns:
        Dict[str, Any]: Validation result
    """
    try:
        # Convert to Decimal for precise validation
        if isinstance(amount, str):
            amount = amount.strip()
            if not amount:
                return {"is_valid": False, "message": "Amount is required"}
            
            # Remove currency symbols and spaces
            clean_amount = re.sub(r'[^\d.-]', '', amount)
            decimal_amount = Decimal(clean_amount)
        else:
            decimal_amount = Decimal(str(amount))
        
        # Basic validation
        if decimal_amount < 0:
            return {"is_valid": False, "message": "Amount cannot be negative"}
        
        if decimal_amount == 0:
            return {"is_valid": False, "message": "Amount must be greater than zero"}
        
        # Check decimal places (typically 2 for most currencies)
        decimal_places = abs(decimal_amount.as_tuple().exponent)
        max_decimal_places = 2
        
        # Some currencies have different decimal place requirements
        if currency:
            currency_decimal_places = {
                'JPY': 0,  # Japanese Yen
                'KRW': 0,  # Korean Won
                'BHD': 3,  # Bahraini Dinar
                'KWD': 3,  # Kuwaiti Dinar
                'OMR': 3,  # Omani Rial
            }
            max_decimal_places = currency_decimal_places.get(currency.upper(), 2)
        
        if decimal_places > max_decimal_places:
            return {
                "is_valid": False, 
                "message": f"Amount can have maximum {max_decimal_places} decimal places"
            }
        
        # Check maximum amount (business rule)
        max_amount = Decimal('999999999.99')  # Adjust based on business needs
        if decimal_amount > max_amount:
            return {"is_valid": False, "message": "Amount exceeds maximum limit"}
        
        return {
            "is_valid": True,
            "amount": decimal_amount,
            "formatted_amount": str(decimal_amount),
            "currency": currency,
            "decimal_places": decimal_places
        }
        
    except (InvalidOperation, ValueError) as e:
        return {"is_valid": False, "message": "Invalid amount format"}


# ==================== DATE AND TIME VALIDATION ====================

def validate_date_range(start_date: date, end_date: date) -> Dict[str, Any]:
    """
    Validate date range.
    
    Args:
        start_date: Start date
        end_date: End date
        
    Returns:
        Dict[str, Any]: Validation result
    """
    if not start_date or not end_date:
        return {"is_valid": False, "message": "Both start and end dates are required"}
    
    if start_date > end_date:
        return {"is_valid": False, "message": "Start date cannot be after end date"}
    
    # Check if date range is reasonable (not too far in the past or future)
    today = date.today()
    max_past_years = 10
    max_future_years = 5
    
    min_date = date(today.year - max_past_years, 1, 1)
    max_date = date(today.year + max_future_years, 12, 31)
    
    if start_date < min_date:
        return {"is_valid": False, "message": f"Start date cannot be before {min_date}"}
    
    if end_date > max_date:
        return {"is_valid": False, "message": f"End date cannot be after {max_date}"}
    
    # Check maximum range (e.g., 1 year)
    max_range_days = 366
    if (end_date - start_date).days > max_range_days:
        return {"is_valid": False, "message": "Date range cannot exceed 1 year"}
    
    return {"is_valid": True, "days_difference": (end_date - start_date).days}


def validate_business_hours(time_str: str) -> bool:
    """
    Validate time format for business hours.
    
    Args:
        time_str: Time string (HH:MM format)
        
    Returns:
        bool: True if time format is valid
    """
    try:
        if not time_str or not time_str.strip():
            return False
        
        # Parse time
        time_obj = datetime.strptime(time_str.strip(), '%H:%M').time()
        
        # Business hours validation (6 AM to 10 PM)
        min_time = datetime.strptime('06:00', '%H:%M').time()
        max_time = datetime.strptime('22:00', '%H:%M').time()
        
        return min_time <= time_obj <= max_time
        
    except ValueError:
        return False


# ==================== BUSINESS LOGIC VALIDATION ====================

def validate_user_role_assignment(current_roles: List[str], new_roles: List[str]) -> Dict[str, Any]:
    """
    Validate user role assignment according to business rules.
    
    Args:
        current_roles: Current user roles
        new_roles: New roles to assign
        
    Returns:
        Dict[str, Any]: Validation result
    """
    # Convert to uppercase for comparison
    current_roles = [role.upper() for role in current_roles]
    new_roles = [role.upper() for role in new_roles]
    
    # Validate that roles exist
    valid_roles = [role.value for role in UserRole]
    invalid_roles = [role for role in new_roles if role not in valid_roles]
    
    if invalid_roles:
        return {"is_valid": False, "message": f"Invalid roles: {', '.join(invalid_roles)}"}
    
    # Business rules
    # 1. Super admin can have any combination
    if UserRole.SUPER_ADMIN.value in new_roles:
        return {"is_valid": True, "message": "Super admin role validated"}
    
    # 2. Admin cannot have cashier role (business separation)
    if UserRole.ADMIN.value in new_roles and UserRole.CASHIER.value in new_roles:
        return {"is_valid": False, "message": "Admin and Cashier roles cannot be combined"}
    
    # 3. Branch manager should have at least one operational role
    if UserRole.BRANCH_MANAGER.value in new_roles:
        operational_roles = [UserRole.CASHIER.value, UserRole.ACCOUNTANT.value]
        if not any(role in new_roles for role in operational_roles):
            return {"is_valid": False, "message": "Branch manager must have at least one operational role"}
    
    # 4. User must have at least one role
    if not new_roles:
        return {"is_valid": False, "message": "User must have at least one role"}
    
    return {"is_valid": True, "message": "Role assignment validated"}


def validate_branch_assignment(user_roles: List[str], branch_id: Optional[int]) -> Dict[str, Any]:
    """
    Validate branch assignment according to user roles.
    
    Args:
        user_roles: User roles
        branch_id: Branch ID to assign
        
    Returns:
        Dict[str, Any]: Validation result
    """
    # Super admin and admin can work without branch assignment
    admin_roles = [UserRole.SUPER_ADMIN.value, UserRole.ADMIN.value]
    if any(role in user_roles for role in admin_roles):
        return {"is_valid": True, "message": "Admin users can work without branch assignment"}
    
    # Other roles require branch assignment
    if not branch_id:
        return {"is_valid": False, "message": "Branch assignment is required for non-admin users"}
    
    return {"is_valid": True, "message": "Branch assignment validated"}


# ==================== FILE AND DATA VALIDATION ====================

def validate_file_type(filename: str, allowed_types: List[str]) -> bool:
    """
    Validate file type by extension.
    
    Args:
        filename: File name to validate
        allowed_types: List of allowed file extensions
        
    Returns:
        bool: True if file type is allowed
    """
    if not filename or not filename.strip():
        return False
    
    # Get file extension
    file_extension = filename.lower().split('.')[-1] if '.' in filename else ''
    
    # Normalize allowed types
    allowed_extensions = [ext.lower().replace('.', '') for ext in allowed_types]
    
    return file_extension in allowed_extensions


def validate_file_size(file_size: int, max_size_mb: int = 10) -> bool:
    """
    Validate file size.
    
    Args:
        file_size: File size in bytes
        max_size_mb: Maximum size in MB
        
    Returns:
        bool: True if file size is within limit
    """
    max_size_bytes = max_size_mb * 1024 * 1024  # Convert MB to bytes
    return file_size <= max_size_bytes


# ==================== SEARCH AND FILTER VALIDATION ====================

def validate_search_query(query: str, max_length: int = 100) -> Dict[str, Any]:
    """
    Validate search query.
    
    Args:
        query: Search query string
        max_length: Maximum query length
        
    Returns:
        Dict[str, Any]: Validation result
    """
    if not query or not query.strip():
        return {"is_valid": False, "message": "Search query cannot be empty"}
    
    query = query.strip()
    
    if len(query) < 2:
        return {"is_valid": False, "message": "Search query must be at least 2 characters"}
    
    if len(query) > max_length:
        return {"is_valid": False, "message": f"Search query cannot exceed {max_length} characters"}
    
    # Check for potentially dangerous characters
    dangerous_chars = ['<', '>', ';', '&', '|', '`', '$']
    if any(char in query for char in dangerous_chars):
        return {"is_valid": False, "message": "Search query contains invalid characters"}
    
    return {"is_valid": True, "cleaned_query": query}


def validate_sort_parameters(sort_by: str, sort_order: str, valid_fields: List[str]) -> Dict[str, Any]:
    """
    Validate sorting parameters.
    
    Args:
        sort_by: Field to sort by
        sort_order: Sort order (asc/desc)
        valid_fields: List of valid sort fields
        
    Returns:
        Dict[str, Any]: Validation result
    """
    if sort_by not in valid_fields:
        return {
            "is_valid": False, 
            "message": f"Invalid sort field. Valid fields: {', '.join(valid_fields)}"
        }
    
    if sort_order.lower() not in ['asc', 'desc']:
        return {"is_valid": False, "message": "Sort order must be 'asc' or 'desc'"}
    
    return {"is_valid": True, "sort_by": sort_by, "sort_order": sort_order.lower()}


# ==================== COMPREHENSIVE VALIDATION UTILITIES ====================

def validate_pagination(page: int, page_size: int, max_page_size: int = 100) -> Dict[str, Any]:
    """
    Validate pagination parameters.
    
    Args:
        page: Page number
        page_size: Items per page
        max_page_size: Maximum allowed page size
        
    Returns:
        Dict[str, Any]: Validation result
    """
    if page < 1:
        return {"is_valid": False, "message": "Page number must be at least 1"}
    
    if page_size < 1:
        return {"is_valid": False, "message": "Page size must be at least 1"}
    
    if page_size > max_page_size:
        return {"is_valid": False, "message": f"Page size cannot exceed {max_page_size}"}
    
    return {"is_valid": True, "page": page, "page_size": page_size}


def sanitize_input(input_str: str, max_length: int = None) -> str:
    """
    Sanitize user input by removing dangerous characters.
    
    Args:
        input_str: Input string to sanitize
        max_length: Maximum length to truncate to
        
    Returns:
        str: Sanitized input
    """
    if not input_str:
        return ""
    
    # Remove potentially dangerous characters
    sanitized = re.sub(r'[<>"\';\\&|`$]', '', input_str)
    
    # Trim whitespace
    sanitized = sanitized.strip()
    
    # Truncate if necessary
    if max_length and len(sanitized) > max_length:
        sanitized = sanitized[:max_length]
    
    return sanitized


def validate_required_fields(data: Dict[str, Any], required_fields: List[str]) -> Dict[str, Any]:
    """
    Validate that required fields are present and not empty.
    
    Args:
        data: Data dictionary to validate
        required_fields: List of required field names
        
    Returns:
        Dict[str, Any]: Validation result
    """
    missing_fields = []
    empty_fields = []
    
    for field in required_fields:
        if field not in data:
            missing_fields.append(field)
        elif not data[field] or (isinstance(data[field], str) and not data[field].strip()):
            empty_fields.append(field)
    
    if missing_fields or empty_fields:
        error_parts = []
        if missing_fields:
            error_parts.append(f"Missing fields: {', '.join(missing_fields)}")
        if empty_fields:
            error_parts.append(f"Empty fields: {', '.join(empty_fields)}")
        
        return {
            "is_valid": False,
            "message": ". ".join(error_parts),
            "missing_fields": missing_fields,
            "empty_fields": empty_fields
        }
    
    return {"is_valid": True, "message": "All required fields are present"}


# ==================== UTILITY FUNCTIONS ====================

def is_valid_uuid(uuid_string: str) -> bool:
    """
    Validate UUID format.
    
    Args:
        uuid_string: UUID string to validate
        
    Returns:
        bool: True if UUID is valid
    """
    try:
        import uuid
        uuid.UUID(uuid_string)
        return True
    except (ValueError, TypeError):
        return False


def validate_json_structure(json_data: Dict[str, Any], required_structure: Dict[str, type]) -> Dict[str, Any]:
    """
    Validate JSON data structure.
    
    Args:
        json_data: JSON data to validate
        required_structure: Expected structure with field types
        
    Returns:
        Dict[str, Any]: Validation result
    """
    errors = []
    
    for field, expected_type in required_structure.items():
        if field not in json_data:
            errors.append(f"Missing field: {field}")
        elif not isinstance(json_data[field], expected_type):
            errors.append(f"Field '{field}' must be of type {expected_type.__name__}")
    
    if errors:
        return {"is_valid": False, "message": "; ".join(errors), "errors": errors}
    
    return {"is_valid": True, "message": "JSON structure is valid"}