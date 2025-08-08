"""
Module: auth
Purpose: Authentication endpoints - login, logout, token management, password operations
Author: CEMS Development Team
Date: 2024
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.schemas.auth import (
    LoginRequest,
    TokenResponse,
    RefreshTokenRequest,
    ChangePasswordRequest,
    ForgotPasswordRequest,
    ResetPasswordRequest
)
from app.services.auth_service import AuthService
from app.api.deps import get_db, get_current_active_user
from app.schemas.user import UserInDB

router = APIRouter(prefix="/auth", tags=["Authentication"])

@router.post("/login", response_model=TokenResponse)
def login(data: LoginRequest, db: Session = Depends(get_db)):
    service = AuthService(db)
    return service.login(data)

@router.post("/refresh-token", response_model=TokenResponse)
def refresh_token(data: RefreshTokenRequest, db: Session = Depends(get_db)):
    service = AuthService(db)
    return service.refresh_token(data)

@router.post("/logout")
def logout(current_user: UserInDB = Depends(get_current_active_user)):
    # Token revocation logic (if used)
    return {"detail": "Logged out successfully"}

@router.post("/forgot-password")
def forgot_password(data: ForgotPasswordRequest, db: Session = Depends(get_db)):
    service = AuthService(db)
    service.forgot_password(data)
    return {"detail": "Password reset instructions sent"}

@router.post("/reset-password")
def reset_password(data: ResetPasswordRequest, db: Session = Depends(get_db)):
    service = AuthService(db)
    service.reset_password(data)
    return {"detail": "Password reset successful"}

@router.post("/change-password")
def change_password(
    data: ChangePasswordRequest,
    current_user: UserInDB = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    service = AuthService(db)
    service.change_password(current_user.id, data)
    return {"detail": "Password changed successfully"}
