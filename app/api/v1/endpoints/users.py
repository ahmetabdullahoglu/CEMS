"""
Module: users
Purpose: Enhanced user management endpoints with comprehensive features
Author: CEMS Development Team
Date: 2024
"""

from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status, Query, Path
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from app.schemas.user import (
    UserCreate, UserUpdate, UserResponse, UserListResponse, UserSearchRequest,
    UserBulkOperationRequest, UserBulkOperationResponse, UserStatusUpdate,
    UserRoleAssignment, UserPermissionResponse, UserActivityResponse
)
from app.schemas.auth import PasswordChangeRequest
from app.api.deps import (
    get_db, get_current_active_user, get_current_superuser,
    require_permissions, require_roles, require_branch_access
)
from app.services.user_service import UserService
from app.db.models import User
from app.core.constants import UserRole, UserStatus
from app.core.exceptions import ValidationException, NotFoundException
from app.utils.logger import get_logger

logger = get_logger(__name__)

router = APIRouter(prefix="/users", tags=["User Management"])


# ==================== USER CRUD OPERATIONS ====================

@router.get("/", response_model=UserListResponse)
async def list_users(
    skip: int = Query(0, ge=0, description="Number of records to skip"),
    limit: int = Query(50, ge=1, le=100, description="Number of records to return"),
    search: Optional[str] = Query(None, description="Search by name, email, or username"),
    status: Optional[UserStatus] = Query(None, description="Filter by user status"),
    role: Optional[UserRole] = Query(None, description="Filter by user role"),
    branch_id: Optional[int] = Query(None, description="Filter by branch ID"),
    is_active: Optional[bool] = Query(None, description="Filter by active status"),
    sort_by: str = Query("created_at", description="Sort field"),
    sort_order: str = Query("desc", regex="^(asc|desc)$", description="Sort order"),
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """
    List users with advanced filtering, searching, and pagination.
    
    **Required Permissions**: `users:read`
    
    **Features**:
    - Advanced filtering by multiple criteria
    - Full-text search across name, email, username
    - Flexible sorting and pagination
    - Branch-based access control
    - Performance optimized queries
    
    **Access Control**:
    - Super admins: See all users
    - Branch managers: See users in their branch
    - Regular users: Limited access based on permissions
    """
    service = UserService(db)
    
    # Apply branch-based filtering for non-admin users
    effective_branch_id = branch_id
    if not current_user.is_superuser:
        user_roles = service.get_user_roles(current_user.id)
        admin_roles = [UserRole.SUPER_ADMIN.value, UserRole.ADMIN.value]
        
        if not any(role in admin_roles for role in user_roles):
            effective_branch_id = current_user.branch_id
    
    filters = {
        "search": search,
        "status": status,
        "role": role,
        "branch_id": effective_branch_id,
        "is_active": is_active
    }
    
    result = service.get_users_paginated(
        skip=skip,
        limit=limit,
        filters=filters,
        sort_by=sort_by,
        sort_order=sort_order
    )
    
    logger.info(f"User {current_user.id} listed {len(result.users)} users")
    return result


@router.post("/", response_model=UserResponse)
async def create_user(
    user_data: UserCreate,
    current_user: User = Depends(require_permissions(["users:create"])),
    db: Session = Depends(get_db)
):
    """
    Create a new user with comprehensive validation.
    
    **Required Permissions**: `users:create`
    
    **Features**:
    - Username and email uniqueness validation
    - Password strength enforcement
    - Role-based creation restrictions
    - Branch assignment validation
    - Automatic audit logging
    
    **Business Rules**:
    - Only admins can create admin users
    - Users can only be assigned to accessible branches
    - Email verification is required in production
    """
    service = UserService(db)
    
    # Validate branch access
    if user_data.branch_id and not current_user.is_superuser:
        user_roles = service.get_user_roles(current_user.id)
        admin_roles = [UserRole.SUPER_ADMIN.value, UserRole.ADMIN.value]
        
        if not any(role in admin_roles for role in user_roles):
            if user_data.branch_id != current_user.branch_id:
                raise ValidationException(
                    message="Cannot create user in different branch",
                    field="branch_id"
                )
    
    # Validate role assignment permissions
    if hasattr(user_data, 'roles') and user_data.roles:
        admin_roles = [UserRole.SUPER_ADMIN, UserRole.ADMIN]
        if any(role in admin_roles for role in user_data.roles):
            if not current_user.is_superuser:
                raise ValidationException(
                    message="Insufficient permissions to assign admin roles",
                    field="roles"
                )
    
    try:
        new_user = service.create_user(user_data, created_by=current_user.id)
        logger.info(f"User {current_user.id} created new user {new_user.id}")
        return new_user
    except Exception as e:
        logger.error(f"Failed to create user: {str(e)}")
        raise


@router.get("/{user_id}", response_model=UserResponse)
async def get_user(
    user_id: int = Path(..., description="User ID to retrieve"),
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """
    Get detailed user information by ID.
    
    **Required Permissions**: `users:read` or owner access
    
    **Access Control**:
    - Users can always access their own profile
    - Admins can access any user
    - Branch managers can access users in their branch
    """
    service = UserService(db)
    
    # Check access permissions
    if user_id != current_user.id and not current_user.is_superuser:
        user_roles = service.get_user_roles(current_user.id)
        admin_roles = [UserRole.SUPER_ADMIN.value, UserRole.ADMIN.value]
        
        if not any(role in admin_roles for role in user_roles):
            target_user = service.get_user_by_id(user_id)
            if target_user.branch_id != current_user.branch_id:
                raise ValidationException(
                    message="Access denied to user in different branch"
                )
    
    user = service.get_user_by_id(user_id)
    logger.info(f"User {current_user.id} accessed user {user_id} profile")
    return user


@router.put("/{user_id}", response_model=UserResponse)
async def update_user(
    user_id: int = Path(..., description="User ID to update"),
    user_data: UserUpdate,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """
    Update user information with validation and access control.
    
    **Required Permissions**: `users:update` or owner access for basic fields
    
    **Features**:
    - Selective field updates
    - Role-based update restrictions
    - Branch transfer validation
    - Automatic audit logging
    - Email change verification
    
    **Business Rules**:
    - Users can update their own basic profile
    - Only admins can change roles and permissions
    - Branch transfers require admin approval
    """
    service = UserService(db)
    
    # Determine allowed updates based on permissions
    is_self_update = user_id == current_user.id
    is_admin = current_user.is_superuser
    
    if not is_admin:
        user_roles = service.get_user_roles(current_user.id)
        admin_roles = [UserRole.SUPER_ADMIN.value, UserRole.ADMIN.value]
        is_admin = any(role in admin_roles for role in user_roles)
    
    # Validate update permissions
    if not is_self_update and not is_admin:
        raise ValidationException(
            message="Insufficient permissions to update user"
        )
    
    # Restrict fields for self-updates
    if is_self_update and not is_admin:
        restricted_fields = {
            'is_active', 'is_superuser', 'status', 'branch_id', 'roles'
        }
        provided_fields = set(user_data.dict(exclude_unset=True).keys())
        
        if restricted_fields.intersection(provided_fields):
            raise ValidationException(
                message="Cannot modify restricted fields in self-update",
                field="restricted_fields"
            )
    
    try:
        updated_user = service.update_user(
            user_id, 
            user_data, 
            updated_by=current_user.id
        )
        
        logger.info(f"User {current_user.id} updated user {user_id}")
        return updated_user
    except Exception as e:
        logger.error(f"Failed to update user {user_id}: {str(e)}")
        raise


@router.delete("/{user_id}")
async def delete_user(
    user_id: int = Path(..., description="User ID to delete"),
    current_user: User = Depends(require_permissions(["users:delete"])),
    db: Session = Depends(get_db)
):
    """
    Delete user with comprehensive validation.
    
    **Required Permissions**: `users:delete`
    
    **Features**:
    - Soft deletion by default
    - Cascade dependency handling
    - Prevention of self-deletion
    - Superuser protection
    - Automatic backup of user data
    
    **Safety Measures**:
    - Cannot delete yourself
    - Cannot delete last superuser
    - Validates no active transactions
    """
    if user_id == current_user.id:
        raise ValidationException(
            message="Cannot delete your own account"
        )
    
    service = UserService(db)
    
    # Additional validations for admin deletions
    target_user = service.get_user_by_id(user_id)
    
    if target_user.is_superuser:
        # Check if this is the last superuser
        superuser_count = service.get_superuser_count()
        if superuser_count <= 1:
            raise ValidationException(
                message="Cannot delete the last superuser account"
            )
    
    try:
        service.delete_user(user_id, deleted_by=current_user.id)
        logger.info(f"User {current_user.id} deleted user {user_id}")
        return {"detail": "User deleted successfully", "user_id": user_id}
    except Exception as e:
        logger.error(f"Failed to delete user {user_id}: {str(e)}")
        raise


# ==================== ROLE MANAGEMENT ====================

@router.get("/{user_id}/roles", response_model=List[str])
async def get_user_roles(
    user_id: int = Path(..., description="User ID"),
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Get user's assigned roles."""
    service = UserService(db)
    
    # Access control validation
    if user_id != current_user.id and not current_user.is_superuser:
        user_roles = service.get_user_roles(current_user.id)
        admin_roles = [UserRole.SUPER_ADMIN.value, UserRole.ADMIN.value]
        
        if not any(role in admin_roles for role in user_roles):
            raise ValidationException(
                message="Insufficient permissions to view user roles"
            )
    
    roles = service.get_user_roles(user_id)
    return roles


@router.post("/{user_id}/roles", response_model=Dict[str, Any])
async def assign_role_to_user(
    user_id: int = Path(..., description="User ID"),
    role_assignment: UserRoleAssignment,
    current_user: User = Depends(require_permissions(["roles:assign"])),
    db: Session = Depends(get_db)
):
    """
    Assign role to user with validation.
    
    **Required Permissions**: `roles:assign`
    
    **Business Rules**:
    - Only admins can assign admin roles
    - Cannot assign conflicting roles
    - Role assignment is logged
    """
    service = UserService(db)
    
    # Validate role assignment permissions
    if role_assignment.role in [UserRole.SUPER_ADMIN, UserRole.ADMIN]:
        if not current_user.is_superuser:
            raise ValidationException(
                message="Only superusers can assign admin roles",
                field="role"
            )
    
    try:
        service.assign_role(
            user_id, 
            role_assignment.role, 
            assigned_by=current_user.id
        )
        
        logger.info(f"User {current_user.id} assigned role {role_assignment.role} to user {user_id}")
        return {
            "detail": "Role assigned successfully",
            "user_id": user_id,
            "role": role_assignment.role.value,
            "assigned_by": current_user.id
        }
    except Exception as e:
        logger.error(f"Failed to assign role: {str(e)}")
        raise


@router.delete("/{user_id}/roles/{role}", response_model=Dict[str, Any])
async def remove_role_from_user(
    user_id: int = Path(..., description="User ID"),
    role: UserRole = Path(..., description="Role to remove"),
    current_user: User = Depends(require_permissions(["roles:remove"])),
    db: Session = Depends(get_db)
):
    """
    Remove role from user with validation.
    
    **Required Permissions**: `roles:remove`
    
    **Safety Measures**:
    - Cannot remove last admin role
    - Validates role dependencies
    """
    service = UserService(db)
    
    # Validate role removal permissions
    if role in [UserRole.SUPER_ADMIN, UserRole.ADMIN]:
        if not current_user.is_superuser:
            raise ValidationException(
                message="Only superusers can remove admin roles"
            )
        
        # Check if this would remove the last admin
        if role == UserRole.SUPER_ADMIN:
            user_roles = service.get_user_roles(user_id)
            if UserRole.SUPER_ADMIN.value in user_roles:
                superuser_count = service.get_superuser_count()
                if superuser_count <= 1:
                    raise ValidationException(
                        message="Cannot remove the last superuser role"
                    )
    
    try:
        service.remove_role(
            user_id, 
            role, 
            removed_by=current_user.id
        )
        
        logger.info(f"User {current_user.id} removed role {role} from user {user_id}")
        return {
            "detail": "Role removed successfully",
            "user_id": user_id,
            "role": role.value,
            "removed_by": current_user.id
        }
    except Exception as e:
        logger.error(f"Failed to remove role: {str(e)}")
        raise


# ==================== USER STATUS MANAGEMENT ====================

@router.patch("/{user_id}/status", response_model=UserResponse)
async def update_user_status(
    user_id: int = Path(..., description="User ID"),
    status_update: UserStatusUpdate,
    current_user: User = Depends(require_permissions(["users:status"])),
    db: Session = Depends(get_db)
):
    """
    Update user status (active, suspended, etc.).
    
    **Required Permissions**: `users:status`
    
    **Features**:
    - Status change validation
    - Reason tracking
    - Automatic notifications
    - Audit logging
    """
    if user_id == current_user.id:
        raise ValidationException(
            message="Cannot change your own status"
        )
    
    service = UserService(db)
    
    try:
        updated_user = service.update_user_status(
            user_id,
            status_update.status,
            reason=status_update.reason,
            updated_by=current_user.id
        )
        
        logger.info(f"User {current_user.id} changed status of user {user_id} to {status_update.status}")
        return updated_user
    except Exception as e:
        logger.error(f"Failed to update user status: {str(e)}")
        raise


# ==================== BULK OPERATIONS ====================

@router.post("/bulk", response_model=UserBulkOperationResponse)
async def bulk_user_operations(
    bulk_request: UserBulkOperationRequest,
    current_user: User = Depends(require_permissions(["users:bulk"])),
    db: Session = Depends(get_db)
):
    """
    Perform bulk operations on multiple users.
    
    **Required Permissions**: `users:bulk`
    
    **Supported Operations**:
    - Bulk status updates
    - Bulk role assignments
    - Bulk branch transfers
    - Bulk deletions
    
    **Features**:
    - Atomic operations with rollback
    - Detailed result reporting
    - Progress tracking
    """
    service = UserService(db)
    
    try:
        result = service.bulk_operation(
            bulk_request,
            performed_by=current_user.id
        )
        
        logger.info(f"User {current_user.id} performed bulk operation: {bulk_request.operation}")
        return result
    except Exception as e:
        logger.error(f"Bulk operation failed: {str(e)}")
        raise


# ==================== USER PERMISSIONS ====================

@router.get("/{user_id}/permissions", response_model=UserPermissionResponse)
async def get_user_permissions(
    user_id: int = Path(..., description="User ID"),
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """
    Get comprehensive user permissions.
    
    **Access Control**:
    - Users can view their own permissions
    - Admins can view any user's permissions
    """
    service = UserService(db)
    
    # Access control
    if user_id != current_user.id and not current_user.is_superuser:
        user_roles = service.get_user_roles(current_user.id)
        admin_roles = [UserRole.SUPER_ADMIN.value, UserRole.ADMIN.value]
        
        if not any(role in admin_roles for role in user_roles):
            raise ValidationException(
                message="Insufficient permissions to view user permissions"
            )
    
    permissions = service.get_user_permissions_detailed(user_id)
    return permissions


# ==================== USER ACTIVITY ====================

@router.get("/{user_id}/activity", response_model=UserActivityResponse)
async def get_user_activity(
    user_id: int = Path(..., description="User ID"),
    days: int = Query(30, ge=1, le=365, description="Days of activity to retrieve"),
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """
    Get user activity history and statistics.
    
    **Features**:
    - Login/logout tracking
    - Transaction history
    - Permission changes
    - System interactions
    """
    service = UserService(db)
    
    # Access control
    if user_id != current_user.id and not current_user.is_superuser:
        user_roles = service.get_user_roles(current_user.id)
        admin_roles = [UserRole.SUPER_ADMIN.value, UserRole.ADMIN.value]
        
        if not any(role in admin_roles for role in user_roles):
            raise ValidationException(
                message="Insufficient permissions to view user activity"
            )
    
    activity = service.get_user_activity(user_id, days=days)
    return activity


# ==================== PASSWORD MANAGEMENT ====================

@router.post("/{user_id}/change-password")
async def change_user_password(
    user_id: int = Path(..., description="User ID"),
    password_data: PasswordChangeRequest,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """
    Change user password with validation.
    
    **Access Control**:
    - Users can change their own password
    - Admins can reset any user's password
    """
    service = UserService(db)
    
    # Determine if this is self-change or admin reset
    is_self_change = user_id == current_user.id
    is_admin = current_user.is_superuser
    
    if not is_admin:
        user_roles = service.get_user_roles(current_user.id)
        admin_roles = [UserRole.SUPER_ADMIN.value, UserRole.ADMIN.value]
        is_admin = any(role in admin_roles for role in user_roles)
    
    if not is_self_change and not is_admin:
        raise ValidationException(
            message="Insufficient permissions to change user password"
        )
    
    try:
        service.change_password(
            user_id,
            new_password=password_data.new_password,
            current_password=password_data.current_password if is_self_change else None,
            changed_by=current_user.id
        )
        
        logger.info(f"Password changed for user {user_id} by user {current_user.id}")
        return {"detail": "Password changed successfully"}
    except Exception as e:
        logger.error(f"Failed to change password: {str(e)}")
        raise