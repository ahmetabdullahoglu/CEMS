'''
Module: deps
Purpose: Common FastAPI dependencies for authentication, permissions, and DB session
Author: CEMS Development Team
Date: 2024
'''

# Standard library imports
from typing import Generator, List

# Third-party imports
from fastapi import Depends, HTTPException, status
from sqlalchemy.orm import Session
from jose import JWTError

# Local imports
from app.db.database import SessionLocal
from app.core.security import verify_token
from app.services.user_service import UserService
from app.schemas.user import UserInDB
from app.core import exceptions

def get_db() -> Generator:
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
    token: str = Depends(verify_token),
    db: Session = Depends(get_db)
) -> UserInDB:
    """
    Dependency to get current user from JWT token.

    Args:
        token: JWT access token
        db: Database session

    Returns:
        The current authenticated user
    """
    user_service = UserService(db)
    try:
        user = user_service.get_user_from_token(token)
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
        )

    if user is None:
        raise exceptions.UnauthorizedException("User not found")

    return user

def get_current_active_user(
    current_user: UserInDB = Depends(get_current_user),
) -> UserInDB:
    """
    Dependency to ensure the user is active.

    Args:
        current_user: The current authenticated user

    Returns:
        The current active user
    """
    if not current_user.is_active:
        raise exceptions.InactiveUserException("Inactive user")

    return current_user

def require_permissions(required_perms: List[str]):
    """
    Factory dependency to check if user has required permissions.

    Args:
        required_perms: List of required permission strings

    Returns:
        Dependency function
    """

    def permission_checker(
        current_user: UserInDB = Depends(get_current_active_user)
    ):
        user_perms = current_user.permissions or []
        if not set(required_perms).issubset(set(user_perms)):
            raise exceptions.ForbiddenException("Insufficient permissions")

    return permission_checker
