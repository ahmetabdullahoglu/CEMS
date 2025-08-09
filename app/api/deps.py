"""
Module: deps
Purpose: Enhanced FastAPI dependencies for authentication, permissions, and DB session
Author: CEMS Development Team
Date: 2024
"""

from typing import Generator, List, Optional, Dict, Any
from fastapi import Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from jose import JWTError

from app.db.database import SessionLocal
from app.core.security import verify_token, security_manager
from app.core.constants import UserRole, UserStatus
from app.core.exceptions import (
    AuthenticationException, TokenExpiredException, InvalidCredentialsException,
    InsufficientPermissionsException, AccountLockedException, AccountSuspendedException
)
from app.repositories.user_repository import UserRepository
from app.db.models import User
from app.schemas.user import UserInDB
from app.utils.logger import get_logger

logger = get_logger(__name__)

# Security scheme for token authentication
security = HTTPBearer()


def get_db() -> Generator[Session, None, None]:
    """
    Provides a SQLAlchemy DB session per request.
    
    Yields:
        Database session object
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
) -> User:
    """
    Enhanced dependency to get current user from JWT token.
    
    Args:
        credentials: Bearer token credentials
        db: Database session
        
    Returns:
        The current authenticated user
        
    Raises:
        AuthenticationException: If authentication fails
        TokenExpiredException: If token is expired
        AccountLockedException: If account is locked
    """
    token = credentials.credentials
    
    try:
        # Verify token using enhanced security manager
        payload = security_manager.verify_token(token, "access")
        user_id = payload.get("sub")
        
        if user_id is None:
            raise InvalidCredentialsException(
                details={"reason": "invalid_token_payload"}
            )
        
        # Get user from database
        user_repo = UserRepository(db)
        user = user_repo.get_by_id(int(user_id))
        
        if user is None:
            raise InvalidCredentialsException(
                details={"reason": "user_not_found"}
            )
        
        # Check user account status
        _validate_user_account_status(user)
        
        # Update last activity
        user_repo.update_last_activity(user.id)
        
        return user
        
    except JWTError as e:
        logger.warning(f"JWT error during authentication: {str(e)}")
        raise TokenExpiredException(
            details={"reason": "jwt_decode_error", "error": str(e)}
        )
    except AuthenticationException:
        raise
    except Exception as e:
        logger.error(f"Unexpected error during authentication: {str(e)}")
        raise AuthenticationException(
            message="Authentication failed",
            details={"reason": "unexpected_error"}
        )


def get_current_active_user(
    current_user: User = Depends(get_current_user)
) -> User:
    """
    Enhanced dependency to ensure the user is active and verified.
    
    Args:
        current_user: The current authenticated user
        
    Returns:
        The current active user
        
    Raises:
        AccountSuspendedException: If account is suspended
        AuthenticationException: If account requirements not met
    """
    # Additional checks for active status
    if current_user.status == UserStatus.SUSPENDED:
        raise AccountSuspendedException(
            details={
                "user_id": current_user.id,
                "status": current_user.status
            }
        )
    
    if not current_user.is_active:
        raise AuthenticationException(
            message="Account is inactive",
            details={
                "user_id": current_user.id,
                "is_active": current_user.is_active
            }
        )
    
    return current_user


def get_current_superuser(
    current_user: User = Depends(get_current_active_user)
) -> User:
    """
    Dependency to ensure current user is a superuser.
    
    Args:
        current_user: The current authenticated user
        
    Returns:
        The current superuser
        
    Raises:
        InsufficientPermissionsException: If user is not superuser
    """
    if not current_user.is_superuser:
        raise InsufficientPermissionsException(
            required_permission="superuser_access"
        )
    
    return current_user


def require_roles(required_roles: List[UserRole]) -> callable:
    """
    Factory dependency to check if user has required roles.
    
    Args:
        required_roles: List of required user roles
        
    Returns:
        Dependency function that validates roles
    """
    def role_checker(
        current_user: User = Depends(get_current_active_user),
        db: Session = Depends(get_db)
    ) -> User:
        """
        Check if user has required roles.
        
        Args:
            current_user: Current authenticated user
            db: Database session
            
        Returns:
            User if has required roles
            
        Raises:
            InsufficientPermissionsException: If user lacks required roles
        """
        user_repo = UserRepository(db)
        user_roles = user_repo.get_user_roles(current_user.id)
        
        # Convert role names to UserRole enums for comparison
        user_role_enums = []
        for role_name in user_roles:
            try:
                user_role_enums.append(UserRole(role_name))
            except ValueError:
                logger.warning(f"Unknown role found for user {current_user.id}: {role_name}")
        
        # Check if user has any of the required roles
        has_required_role = any(role in user_role_enums for role in required_roles)
        
        # Superusers bypass role checks
        if not has_required_role and not current_user.is_superuser:
            raise InsufficientPermissionsException(
                required_permission=f"roles: {[role.value for role in required_roles]}"
            )
        
        return current_user
    
    return role_checker


def require_permissions(required_permissions: List[str]) -> callable:
    """
    Factory dependency to check if user has required permissions.
    
    Args:
        required_permissions: List of required permission strings
        
    Returns:
        Dependency function that validates permissions
    """
    def permission_checker(
        current_user: User = Depends(get_current_active_user),
        db: Session = Depends(get_db)
    ) -> User:
        """
        Check if user has required permissions.
        
        Args:
            current_user: Current authenticated user
            db: Database session
            
        Returns:
            User if has required permissions
            
        Raises:
            InsufficientPermissionsException: If user lacks required permissions
        """
        user_repo = UserRepository(db)
        user_permissions = user_repo.get_user_permissions(current_user.id)
        
        # Superusers have all permissions
        if current_user.is_superuser:
            return current_user
        
        # Check if user has all required permissions
        missing_permissions = set(required_permissions) - set(user_permissions)
        
        if missing_permissions:
            raise InsufficientPermissionsException(
                required_permission=f"permissions: {list(missing_permissions)}"
            )
        
        return current_user
    
    return permission_checker


def require_branch_access(branch_id: Optional[int] = None) -> callable:
    """
    Factory dependency to check if user has access to specific branch.
    
    Args:
        branch_id: Specific branch ID to check (None for user's own branch)
        
    Returns:
        Dependency function that validates branch access
    """
    def branch_checker(
        current_user: User = Depends(get_current_active_user),
        db: Session = Depends(get_db)
    ) -> User:
        """
        Check if user has access to branch.
        
        Args:
            current_user: Current authenticated user
            db: Database session
            
        Returns:
            User if has branch access
            
        Raises:
            InsufficientPermissionsException: If user lacks branch access
        """
        # Superusers and admins have access to all branches
        user_repo = UserRepository(db)
        user_roles = user_repo.get_user_roles(current_user.id)
        
        admin_roles = [UserRole.SUPER_ADMIN.value, UserRole.ADMIN.value]
        if current_user.is_superuser or any(role in admin_roles for role in user_roles):
            return current_user
        
        # Check specific branch access
        target_branch_id = branch_id or current_user.branch_id
        
        if target_branch_id and current_user.branch_id != target_branch_id:
            raise InsufficientPermissionsException(
                required_permission=f"branch_access: {target_branch_id}"
            )
        
        return current_user
    
    return branch_checker


def get_optional_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(HTTPBearer(auto_error=False)),
    db: Session = Depends(get_db)
) -> Optional[User]:
    """
    Optional dependency to get current user (doesn't raise if no token).
    
    Args:
        credentials: Optional bearer token credentials
        db: Database session
        
    Returns:
        User if authenticated, None otherwise
    """
    if not credentials:
        return None
    
    try:
        # Use the main get_current_user logic but catch exceptions
        payload = security_manager.verify_token(credentials.credentials, "access")
        user_id = payload.get("sub")
        
        if user_id:
            user_repo = UserRepository(db)
            user = user_repo.get_by_id(int(user_id))
            
            if user and _is_user_account_valid(user):
                return user
    except Exception as e:
        logger.debug(f"Optional authentication failed: {str(e)}")
    
    return None


def extract_client_info(request: Request) -> Dict[str, Any]:
    """
    Extract client information from request for security logging.
    
    Args:
        request: FastAPI request object
        
    Returns:
        Dictionary containing client information
    """
    return {
        "ip_address": request.client.host if request.client else "unknown",
        "user_agent": request.headers.get("user-agent", "unknown"),
        "forwarded_for": request.headers.get("x-forwarded-for"),
        "real_ip": request.headers.get("x-real-ip"),
        "request_id": request.headers.get("x-request-id"),
    }


# ==================== PRIVATE HELPER FUNCTIONS ====================

def _validate_user_account_status(user: User) -> None:
    """
    Validate user account status and constraints.
    
    Args:
        user: User object to validate
        
    Raises:
        Various authentication exceptions based on account status
    """
    # Check if account is locked
    if user.is_locked:
        raise AccountLockedException(
            details={
                "user_id": user.id,
                "locked_until": user.locked_until.isoformat() if user.locked_until else None
            }
        )
    
    # Check account status
    if user.status == UserStatus.SUSPENDED:
        raise AccountSuspendedException(
            details={
                "user_id": user.id,
                "status": user.status
            }
        )
    
    if user.status not in [UserStatus.ACTIVE, UserStatus.PENDING]:
        raise AuthenticationException(
            message=f"Account status does not allow login: {user.status}",
            details={
                "user_id": user.id,
                "status": user.status
            }
        )


def _is_user_account_valid(user: User) -> bool:
    """
    Check if user account is in valid state (non-raising version).
    
    Args:
        user: User object to check
        
    Returns:
        True if account is valid for authentication
    """
    try:
        _validate_user_account_status(user)
        return True
    except AuthenticationException:
        return False