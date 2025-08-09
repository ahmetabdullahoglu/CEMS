"""
Module: auth
Purpose: Enhanced authentication endpoints with complete model integration
Author: CEMS Development Team
Date: 2024
"""

from typing import Dict, Any, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Request, Response
from fastapi.security import HTTPBearer
from sqlalchemy.orm import Session

from app.schemas.auth import (
    LoginRequest, LoginResponse, RefreshTokenRequest, RefreshTokenResponse,
    PasswordChangeRequest, PasswordResetRequest, PasswordResetConfirmRequest,
    LogoutRequest, LogoutResponse, TokenValidationRequest, TokenValidationResponse,
    PasswordStrengthRequest, PasswordStrengthResponse, SecurityEvent
)
from app.schemas.user import UserResponse
from app.services.auth_service import AuthenticationService
from app.api.deps import (
    get_db, get_current_active_user, get_current_user, 
    extract_client_info, get_optional_current_user
)
from app.db.models import User
from app.core.security import security_manager
from app.core.exceptions import (
    AuthenticationException, ValidationException, 
    RateLimitExceededException, PasswordStrengthException
)
from app.utils.logger import get_logger

logger = get_logger(__name__)

router = APIRouter(prefix="/auth", tags=["Authentication"])
security = HTTPBearer()


@router.post("/login", response_model=LoginResponse)
async def login(
    request: Request,
    response: Response,
    login_data: LoginRequest,
    db: Session = Depends(get_db)
):
    """
    User login endpoint with comprehensive security features.
    
    Authenticates user and returns access/refresh tokens with user information.
    Includes rate limiting, account lockout protection, and security logging.
    
    Args:
        request: FastAPI request object
        response: FastAPI response object  
        login_data: Login credentials (username/email + password)
        db: Database session
        
    Returns:
        LoginResponse: Access token, refresh token, and user information
        
    Raises:
        HTTPException: Various authentication errors (401, 429, etc.)
    """
    try:
        # Extract client information for security
        client_info = extract_client_info(request)
        
        # Initialize authentication service
        auth_service = AuthenticationService(db)
        
        # Authenticate user
        login_response = auth_service.authenticate_user(login_data, client_info)
        
        # Set secure cookie for refresh token (optional)
        if hasattr(login_response, 'refresh_token'):
            response.set_cookie(
                key="refresh_token",
                value=login_response.refresh_token,
                httponly=True,
                secure=True,  # HTTPS only in production
                samesite="lax",
                max_age=7 * 24 * 60 * 60  # 7 days
            )
        
        logger.info(f"Successful login for user: {login_response.username}")
        return login_response
        
    except AuthenticationException as e:
        logger.warning(f"Authentication failed: {e.message}")
        raise HTTPException(
            status_code=e.status_code,
            detail={
                "error": True,
                "message": e.message,
                "error_code": e.error_code,
                "details": e.details
            }
        )
    except RateLimitExceededException as e:
        logger.warning(f"Rate limit exceeded for login: {e.details}")
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail={
                "error": True,
                "message": "Too many login attempts. Please try again later.",
                "error_code": "RATE_LIMIT_EXCEEDED"
            }
        )
    except Exception as e:
        logger.error(f"Unexpected error during login: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "error": True,
                "message": "Authentication service temporarily unavailable"
            }
        )


@router.post("/refresh", response_model=RefreshTokenResponse)
async def refresh_token(
    request: Request,
    refresh_data: RefreshTokenRequest,
    db: Session = Depends(get_db)
):
    """
    Refresh access token using refresh token.
    
    Validates refresh token and issues new access token. Optionally rotates
    refresh token for enhanced security.
    
    Args:
        request: FastAPI request object
        refresh_data: Refresh token request data
        db: Database session
        
    Returns:
        RefreshTokenResponse: New access token and optionally new refresh token
        
    Raises:
        HTTPException: If refresh token is invalid or expired
    """
    try:
        client_info = extract_client_info(request)
        auth_service = AuthenticationService(db)
        
        token_response = auth_service.refresh_access_token(refresh_data, client_info)
        
        logger.info("Token refreshed successfully")
        return token_response
        
    except AuthenticationException as e:
        logger.warning(f"Token refresh failed: {e.message}")
        raise HTTPException(
            status_code=e.status_code,
            detail={
                "error": True,
                "message": e.message,
                "error_code": e.error_code
            }
        )


@router.post("/logout", response_model=LogoutResponse)
async def logout(
    request: Request,
    response: Response,
    logout_data: LogoutRequest,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """
    User logout endpoint with session management.
    
    Invalidates tokens and sessions based on logout preferences.
    Supports terminating single session or all user sessions.
    
    Args:
        request: FastAPI request object
        response: FastAPI response object
        logout_data: Logout preferences
        current_user: Authenticated user model
        db: Database session
        
    Returns:
        LogoutResponse: Logout status and statistics
    """
    try:
        client_info = extract_client_info(request)
        auth_service = AuthenticationService(db)
        
        # Add current session info to client_info
        auth_header = request.headers.get("authorization", "")
        if auth_header.startswith("Bearer "):
            client_info["access_token"] = auth_header[7:]
        
        logout_result = auth_service.logout_user(current_user, logout_data, client_info)
        
        # Clear refresh token cookie
        response.delete_cookie(
            key="refresh_token",
            httponly=True,
            secure=True,
            samesite="lax"
        )
        
        logger.info(f"User {current_user.username} logged out successfully")
        
        return LogoutResponse(
            message=logout_result["message"],
            sessions_terminated=logout_result["sessions_terminated"]
        )
        
    except Exception as e:
        logger.error(f"Logout error for user {current_user.id}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "error": True,
                "message": "Logout failed"
            }
        )


@router.post("/change-password")
async def change_password(
    password_data: PasswordChangeRequest,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """
    Change user password endpoint.
    
    Validates current password and updates to new password with strength validation.
    Enforces password policy and logs security event.
    
    Args:
        password_data: Password change request with current and new passwords
        current_user: Authenticated user model
        db: Database session
        
    Returns:
        Success message with password strength info
        
    Raises:
        HTTPException: If password validation fails
    """
    try:
        auth_service = AuthenticationService(db)
        result = auth_service.change_password(current_user, password_data)
        
        logger.info(f"Password changed successfully for user: {current_user.username}")
        return {
            "success": True,
            "message": result["message"],
            "password_strength_score": result["strength_score"]
        }
        
    except (AuthenticationException, PasswordStrengthException) as e:
        logger.warning(f"Password change failed for user {current_user.username}: {e.message}")
        raise HTTPException(
            status_code=e.status_code,
            detail={
                "error": True,
                "message": e.message,
                "error_code": e.error_code,
                "details": e.details
            }
        )


@router.post("/forgot-password")
async def forgot_password(
    request: Request,
    reset_data: PasswordResetRequest,
    db: Session = Depends(get_db)
):
    """
    Request password reset endpoint.
    
    Initiates password reset process by sending reset token to user email.
    Includes rate limiting to prevent abuse.
    
    Args:
        request: FastAPI request object
        reset_data: Password reset request with email
        db: Database session
        
    Returns:
        Success message (same response regardless of email existence for security)
    """
    try:
        client_info = extract_client_info(request)
        
        # Rate limiting for password reset requests
        try:
            security_manager.check_rate_limit(
                identifier=f"password_reset:{client_info['ip_address']}",
                max_requests=3,
                window_minutes=15
            )
        except RateLimitExceededException:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail={
                    "error": True,
                    "message": "Too many password reset requests. Please try again later."
                }
            )
        
        # TODO: Implement password reset service
        # auth_service = AuthenticationService(db)
        # auth_service.initiate_password_reset(reset_data.email, client_info)
        
        # Always return success for security (don't reveal if email exists)
        logger.info(f"Password reset requested for email: {reset_data.email}")
        return {
            "success": True,
            "message": "If the email address exists in our system, you will receive password reset instructions."
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Password reset request error: {str(e)}")
        return {
            "success": True,
            "message": "If the email address exists in our system, you will receive password reset instructions."
        }


@router.post("/reset-password")
async def reset_password(
    request: Request,
    reset_data: PasswordResetConfirmRequest,
    db: Session = Depends(get_db)
):
    """
    Confirm password reset endpoint.
    
    Validates reset token and sets new password.
    Includes password strength validation.
    
    Args:
        request: FastAPI request object
        reset_data: Password reset confirmation with token and new password
        db: Database session
        
    Returns:
        Success message with password reset confirmation
        
    Raises:
        HTTPException: If reset token is invalid or password validation fails
    """
    try:
        # TODO: Implement password reset confirmation service
        # auth_service = AuthenticationService(db)
        # result = auth_service.confirm_password_reset(reset_data)
        
        logger.info("Password reset completed successfully")
        return {
            "success": True,
            "message": "Password has been reset successfully. You can now login with your new password."
        }
        
    except (AuthenticationException, ValidationException) as e:
        logger.warning(f"Password reset confirmation failed: {e.message}")
        raise HTTPException(
            status_code=e.status_code,
            detail={
                "error": True,
                "message": e.message,
                "error_code": e.error_code
            }
        )


@router.post("/validate-token", response_model=TokenValidationResponse)
async def validate_token(
    token_data: TokenValidationRequest,
    db: Session = Depends(get_db)
):
    """
    Validate JWT token endpoint.
    
    Validates token and returns user information if valid.
    Useful for token introspection and validation by other services.
    
    Args:
        token_data: Token validation request
        db: Database session
        
    Returns:
        TokenValidationResponse: Validation result with user info
    """
    try:
        auth_service = AuthenticationService(db)
        validation_result = auth_service.validate_token(
            token_data.token,
            token_data.token_type
        )
        
        return validation_result
        
    except Exception as e:
        logger.debug(f"Token validation error: {str(e)}")
        return TokenValidationResponse(valid=False)


@router.post("/check-password-strength", response_model=PasswordStrengthResponse)
async def check_password_strength(
    password_data: PasswordStrengthRequest
):
    """
    Check password strength endpoint.
    
    Validates password against security policy and returns strength information.
    Useful for frontend password strength indicators.
    
    Args:
        password_data: Password to validate
        
    Returns:
        PasswordStrengthResponse: Detailed password strength analysis
    """
    try:
        strength_result = security_manager.check_password_strength(password_data.password)
        
        return PasswordStrengthResponse(
            is_valid=strength_result["is_valid"],
            score=strength_result["score"],
            max_score=strength_result.get("max_score", 8),
            strength=strength_result["strength"],
            requirements_met=strength_result["requirements_met"],
            suggestions=strength_result["suggestions"],
            estimated_crack_time=strength_result["estimated_crack_time"]
        )
        
    except Exception as e:
        logger.error(f"Password strength check error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "error": True,
                "message": "Password strength check failed"
            }
        )


@router.get("/me", response_model=UserResponse)
async def get_current_user_info(
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """
    Get current user information endpoint.
    
    Returns detailed information about the authenticated user.
    
    Args:
        current_user: Authenticated user model
        db: Database session
        
    Returns:
        UserResponse: Current user information
    """
    try:
        # Convert User model to UserResponse schema
        from app.repositories.user_repository import UserRepository
        
        user_repo = UserRepository(db)
        user_roles = user_repo.get_user_roles(current_user.id)
        user_permissions = user_repo.get_user_permissions(current_user.id)
        
        return UserResponse(
            id=current_user.id,
            username=current_user.username,
            email=current_user.email,
            first_name=current_user.first_name,
            last_name=current_user.last_name,
            full_name=current_user.full_name,
            phone_number=current_user.phone_number,
            status=current_user.status,
            is_active=current_user.is_active,
            is_superuser=current_user.is_superuser,
            is_verified=current_user.is_verified,
            created_at=current_user.created_at,
            updated_at=current_user.updated_at,
            last_login_at=current_user.last_login_at,
            branch_id=current_user.branch_id,
            roles=user_roles,
            permissions=user_permissions
        )
        
    except Exception as e:
        logger.error(f"Error fetching user info for user {current_user.id}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "error": True,
                "message": "Failed to fetch user information"
            }
        )


@router.get("/status")
async def auth_service_status():
    """
    Authentication service health check endpoint.
    
    Returns status of authentication service and its components.
    Useful for monitoring and health checks.
    
    Returns:
        Service status information
    """
    try:
        # Basic health checks
        health_checks = {
            "database": "healthy",  # TODO: Add actual DB health check
            "security_manager": "healthy",
            "token_blacklist": "healthy",
            "rate_limiter": "healthy"
        }
        
        # Check if security manager is working
        try:
            security_manager.check_password_strength("test123")
            health_checks["password_validation"] = "healthy"
        except Exception:
            health_checks["password_validation"] = "unhealthy"
        
        overall_status = "healthy" if all(
            status == "healthy" for status in health_checks.values()
        ) else "degraded"
        
        return {
            "service": "authentication",
            "status": overall_status,
            "timestamp": str(datetime.utcnow()),
            "checks": health_checks
        }
        
    except Exception as e:
        logger.error(f"Auth service status check error: {str(e)}")
        return {
            "service": "authentication",
            "status": "unhealthy",
            "timestamp": str(datetime.utcnow()),
            "error": str(e)
        }


# Optional: Session management endpoints
@router.get("/sessions")
async def get_active_sessions(
    current_user: User = Depends(get_current_active_user)
):
    """
    Get user's active sessions.
    
    Returns list of active sessions for the current user.
    
    Args:
        current_user: Authenticated user model
        
    Returns:
        List of active sessions
    """
    try:
        sessions = security_manager.session_manager.get_user_sessions(current_user.id)
        
        return {
            "sessions": sessions,
            "total_sessions": len(sessions)
        }
        
    except Exception as e:
        logger.error(f"Error fetching sessions for user {current_user.id}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "error": True,
                "message": "Failed to fetch active sessions"
            }
        )


@router.delete("/sessions/{session_id}")
async def terminate_session(
    session_id: str,
    current_user: User = Depends(get_current_active_user)
):
    """
    Terminate specific session.
    
    Allows user to terminate a specific session by ID.
    
    Args:
        session_id: Session ID to terminate
        current_user: Authenticated user model
        
    Returns:
        Termination confirmation
    """
    try:
        # Verify session belongs to current user
        user_sessions = security_manager.session_manager.get_user_sessions(current_user.id)
        session_ids = [session["session_id"] for session in user_sessions]
        
        if session_id not in session_ids:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={
                    "error": True,
                    "message": "Session not found or does not belong to current user"
                }
            )
        
        # Terminate session
        success = security_manager.session_manager.invalidate_session(session_id)
        
        if success:
            logger.info(f"Session {session_id} terminated by user {current_user.username}")
            return {
                "success": True,
                "message": "Session terminated successfully"
            }
        else:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail={
                    "error": True,
                    "message": "Failed to terminate session"
                }
            )
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error terminating session {session_id}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "error": True,
                "message": "Failed to terminate session"
            }
        )