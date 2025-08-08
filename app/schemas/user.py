"""
Module: user
Purpose: User management and profile schemas for CEMS application
Author: CEMS Development Team
Date: 2024
"""

from datetime import datetime
from typing import Optional, List, Dict, Any, Union
from pydantic import BaseModel, Field, EmailStr, validator, SecretStr, HttpUrl
from app.core.constants import UserRole, UserStatus


# ==================== BASE USER SCHEMAS ====================

class UserBase(BaseModel):
    """Base user schema with common fields."""
    
    username: str = Field(
        min_length=3,
        max_length=50,
        regex=r"^[a-zA-Z0-9_.-]+$",
        description="Unique username for login",
        example="john_doe"
    )
    email: EmailStr = Field(
        description="User email address (must be unique)",
        example="john.doe@example.com"
    )
    first_name: str = Field(
        min_length=1,
        max_length=100,
        description="User's first name",
        example="John"
    )
    last_name: str = Field(
        min_length=1,
        max_length=100,
        description="User's last name",
        example="Doe"
    )
    phone_number: Optional[str] = Field(
        default=None,
        max_length=20,
        regex=r"^\+?[1-9]\d{1,14}$",
        description="User's phone number in international format",
        example="+1234567890"
    )
    
    @validator('username')
    def validate_username(cls, v):
        """Validate and normalize username."""
        v = v.strip().lower()
        if not v:
            raise ValueError("Username cannot be empty")
        return v
    
    @validator('email')
    def validate_email(cls, v):
        """Normalize email."""
        return v.lower().strip()
    
    @validator('first_name', 'last_name')
    def validate_names(cls, v):
        """Validate and normalize names."""
        v = v.strip()
        if not v:
            raise ValueError("Name cannot be empty")
        return v.title()


class UserProfile(BaseModel):
    """Schema for user profile information."""
    
    profile_image_url: Optional[HttpUrl] = Field(
        default=None,
        description="URL to user's profile image"
    )
    language_preference: str = Field(
        default="en",
        max_length=10,
        regex=r"^[a-z]{2}(-[A-Z]{2})?$",
        description="User's preferred language (ISO 639-1)",
        example="en"
    )
    timezone: str = Field(
        default="UTC",
        max_length=50,
        description="User's preferred timezone",
        example="America/New_York"
    )
    
    @validator('language_preference')
    def validate_language(cls, v):
        """Validate language preference."""
        supported_languages = ["en", "ar", "es", "fr", "de"]
        if v not in supported_languages:
            raise ValueError(f"Language must be one of: {supported_languages}")
        return v


# ==================== USER CREATION SCHEMAS ====================

class UserCreateRequest(UserBase):
    """Schema for user creation requests."""
    
    password: SecretStr = Field(
        min_length=8,
        max_length=128,
        description="User password"
    )
    confirm_password: SecretStr = Field(
        description="Password confirmation"
    )
    
    # Role assignment
    roles: Optional[List[UserRole]] = Field(
        default=None,
        description="Roles to assign to the user"
    )
    
    # Branch assignment
    branch_id: Optional[int] = Field(
        default=None,
        description="ID of the branch to assign user to"
    )
    
    # Account settings
    is_active: bool = Field(
        default=True,
        description="Whether user account should be active"
    )
    is_verified: bool = Field(
        default=False,
        description="Whether user email is pre-verified"
    )
    send_welcome_email: bool = Field(
        default=True,
        description="Whether to send welcome email"
    )
    force_password_change: bool = Field(
        default=False,
        description="Whether to force password change on first login"
    )
    
    # Profile information
    profile: Optional[UserProfile] = Field(
        default=None,
        description="User profile information"
    )
    
    @validator('confirm_password')
    def passwords_match(cls, v, values):
        """Validate that passwords match."""
        if 'password' in values and v.get_secret_value() != values['password'].get_secret_value():
            raise ValueError('Passwords do not match')
        return v
    
    @validator('roles')
    def validate_roles(cls, v):
        """Validate role assignments."""
        if v is not None:
            # Remove duplicates while preserving order
            seen = set()
            unique_roles = []
            for role in v:
                if role not in seen:
                    seen.add(role)
                    unique_roles.append(role)
            return unique_roles
        return v


class UserCreateByAdminRequest(UserCreateRequest):
    """Schema for user creation by administrators."""
    
    status: UserStatus = Field(
        default=UserStatus.ACTIVE,
        description="User account status"
    )
    is_superuser: bool = Field(
        default=False,
        description="Whether user has superuser privileges"
    )
    skip_email_verification: bool = Field(
        default=False,
        description="Whether to skip email verification requirement"
    )


class UserCreateResponse(BaseModel):
    """Schema for user creation responses."""
    
    user_id: int = Field(description="Created user ID")
    username: str = Field(description="Username")
    email: EmailStr = Field(description="Email address")
    full_name: str = Field(description="Full name")
    status: UserStatus = Field(description="Account status")
    roles: List[str] = Field(description="Assigned roles")
    branch_id: Optional[int] = Field(description="Assigned branch ID")
    created_at: datetime = Field(description="Creation timestamp")
    verification_required: bool = Field(description="Whether email verification is required")


# ==================== USER READ SCHEMAS ====================

class UserRead(UserBase):
    """Schema for reading user information."""
    
    id: int = Field(description="User ID")
    status: UserStatus = Field(description="User account status")
    is_active: bool = Field(description="Whether user account is active")
    is_superuser: bool = Field(description="Whether user has superuser privileges")
    is_verified: bool = Field(description="Whether user email is verified")
    
    # Timestamps
    created_at: datetime = Field(description="Account creation timestamp")
    updated_at: datetime = Field(description="Last update timestamp")
    last_login_at: Optional[datetime] = Field(description="Last login timestamp")
    password_changed_at: Optional[datetime] = Field(description="Last password change timestamp")
    
    # Security information
    failed_login_attempts: int = Field(description="Number of failed login attempts")
    locked_until: Optional[datetime] = Field(description="Account lock expiration time")
    
    # Profile information
    profile_image_url: Optional[HttpUrl] = Field(description="Profile image URL")
    language_preference: str = Field(description="Preferred language")
    timezone: str = Field(description="Preferred timezone")
    
    # Branch assignment
    branch_id: Optional[int] = Field(description="Assigned branch ID")
    
    # Two-factor authentication
    two_factor_enabled: bool = Field(description="Whether 2FA is enabled")
    
    # Computed fields
    full_name: str = Field(description="Full name (computed)")
    is_locked: bool = Field(description="Whether account is currently locked (computed)")
    password_expires_in_days: Optional[int] = Field(description="Days until password expires")
    
    @validator('full_name', pre=True, always=True)
    def compute_full_name(cls, v, values):
        """Compute full name from first and last name."""
        if v:
            return v
        first_name = values.get('first_name', '')
        last_name = values.get('last_name', '')
        return f"{first_name} {last_name}".strip()
    
    @validator('is_locked', pre=True, always=True)
    def compute_is_locked(cls, v, values):
        """Compute whether account is currently locked."""
        if v is not None:
            return v
        locked_until = values.get('locked_until')
        if locked_until:
            return datetime.utcnow() < locked_until
        return False


class UserDetailRead(UserRead):
    """Schema for detailed user information (admin view)."""
    
    # Additional admin-only fields
    last_login_ip: Optional[str] = Field(description="Last login IP address")
    email_verification_sent_at: Optional[datetime] = Field(description="Last email verification sent")
    password_reset_sent_at: Optional[datetime] = Field(description="Last password reset sent")
    
    # Role information
    roles: List['UserRoleInfo'] = Field(description="User roles with details")
    permissions: List[str] = Field(description="Effective permissions")
    
    # Statistics
    total_logins: Optional[int] = Field(description="Total number of logins")
    total_failed_logins: Optional[int] = Field(description="Total failed login attempts")


class UserRoleInfo(BaseModel):
    """Schema for user role information."""
    
    role_id: int = Field(description="Role ID")
    role_name: str = Field(description="Role name")
    role_display_name: str = Field(description="Role display name")
    assigned_at: datetime = Field(description="When role was assigned")
    assigned_by: Optional[int] = Field(description="User ID who assigned the role")
    expires_at: Optional[datetime] = Field(description="Role expiration time")
    is_active: bool = Field(description="Whether role assignment is active")
    is_expired: bool = Field(description="Whether role assignment has expired")


# ==================== USER UPDATE SCHEMAS ====================

class UserUpdateRequest(BaseModel):
    """Schema for user update requests."""
    
    first_name: Optional[str] = Field(
        default=None,
        min_length=1,
        max_length=100,
        description="User's first name"
    )
    last_name: Optional[str] = Field(
        default=None,
        min_length=1,
        max_length=100,
        description="User's last name"
    )
    phone_number: Optional[str] = Field(
        default=None,
        max_length=20,
        regex=r"^\+?[1-9]\d{1,14}$",
        description="User's phone number"
    )
    profile_image_url: Optional[HttpUrl] = Field(
        default=None,
        description="Profile image URL"
    )
    language_preference: Optional[str] = Field(
        default=None,
        max_length=10,
        description="Preferred language"
    )
    timezone: Optional[str] = Field(
        default=None,
        max_length=50,
        description="Preferred timezone"
    )
    
    @validator('first_name', 'last_name')
    def validate_names(cls, v):
        """Validate names if provided."""
        if v is not None:
            v = v.strip()
            if not v:
                raise ValueError("Name cannot be empty")
            return v.title()
        return v


class UserUpdateByAdminRequest(UserUpdateRequest):
    """Schema for user updates by administrators."""
    
    username: Optional[str] = Field(
        default=None,
        min_length=3,
        max_length=50,
        description="Username"
    )
    email: Optional[EmailStr] = Field(
        default=None,
        description="Email address"
    )
    status: Optional[UserStatus] = Field(
        default=None,
        description="Account status"
    )
    is_active: Optional[bool] = Field(
        default=None,
        description="Whether account is active"
    )
    is_superuser: Optional[bool] = Field(
        default=None,
        description="Whether user has superuser privileges"
    )
    is_verified: Optional[bool] = Field(
        default=None,
        description="Whether email is verified"
    )
    branch_id: Optional[int] = Field(
        default=None,
        description="Branch assignment"
    )
    force_password_change: Optional[bool] = Field(
        default=None,
        description="Whether to force password change"
    )


class UserUpdateResponse(BaseModel):
    """Schema for user update responses."""
    
    user_id: int = Field(description="Updated user ID")
    updated_fields: List[str] = Field(description="Fields that were updated")
    updated_at: datetime = Field(description="Update timestamp")


# ==================== USER ROLE MANAGEMENT SCHEMAS ====================

class UserRoleAssignRequest(BaseModel):
    """Schema for assigning roles to users."""
    
    role_names: List[UserRole] = Field(
        description="Role names to assign"
    )
    expires_at: Optional[datetime] = Field(
        default=None,
        description="Role expiration time (optional)"
    )
    
    @validator('role_names')
    def validate_roles(cls, v):
        """Remove duplicate roles."""
        return list(set(v))


class UserRoleRemoveRequest(BaseModel):
    """Schema for removing roles from users."""
    
    role_names: List[UserRole] = Field(
        description="Role names to remove"
    )


class UserRoleUpdateRequest(BaseModel):
    """Schema for updating user role assignments."""
    
    role_assignments: List['RoleAssignment'] = Field(
        description="Role assignments to update"
    )


class RoleAssignment(BaseModel):
    """Schema for individual role assignment."""
    
    role_name: UserRole = Field(description="Role name")
    action: str = Field(
        regex=r"^(assign|remove|update)$",
        description="Action to perform (assign/remove/update)"
    )
    expires_at: Optional[datetime] = Field(
        default=None,
        description="Role expiration time"
    )


class UserRoleResponse(BaseModel):
    """Schema for user role operation responses."""
    
    user_id: int = Field(description="User ID")
    roles_assigned: List[str] = Field(description="Roles that were assigned")
    roles_removed: List[str] = Field(description="Roles that were removed")
    effective_roles: List[str] = Field(description="Current effective roles")
    updated_at: datetime = Field(description="Update timestamp")


# ==================== USER LISTING AND SEARCH SCHEMAS ====================

class UserSearchFilter(BaseModel):
    """Schema for user search filters."""
    
    search: Optional[str] = Field(
        default=None,
        description="Search term (username, email, or name)"
    )
    status: Optional[UserStatus] = Field(
        default=None,
        description="Filter by user status"
    )
    role: Optional[UserRole] = Field(
        default=None,
        description="Filter by user role"
    )
    branch_id: Optional[int] = Field(
        default=None,
        description="Filter by branch ID"
    )
    is_active: Optional[bool] = Field(
        default=None,
        description="Filter by active status"
    )
    is_verified: Optional[bool] = Field(
        default=None,
        description="Filter by verification status"
    )
    is_superuser: Optional[bool] = Field(
        default=None,
        description="Filter by superuser status"
    )
    created_after: Optional[datetime] = Field(
        default=None,
        description="Filter users created after this date"
    )
    created_before: Optional[datetime] = Field(
        default=None,
        description="Filter users created before this date"
    )
    last_login_after: Optional[datetime] = Field(
        default=None,
        description="Filter users who logged in after this date"
    )
    has_2fa: Optional[bool] = Field(
        default=None,
        description="Filter by 2FA enabled status"
    )


class UserListRequest(BaseModel):
    """Schema for user listing requests."""
    
    page: int = Field(
        default=1,
        ge=1,
        description="Page number"
    )
    page_size: int = Field(
        default=20,
        ge=1,
        le=100,
        description="Number of items per page"
    )
    sort_by: str = Field(
        default="created_at",
        regex=r"^(id|username|email|first_name|last_name|created_at|last_login_at|status)$",
        description="Field to sort by"
    )
    sort_order: str = Field(
        default="desc",
        regex=r"^(asc|desc)$",
        description="Sort order"
    )
    filters: Optional[UserSearchFilter] = Field(
        default=None,
        description="Search filters"
    )
    include_deleted: bool = Field(
        default=False,
        description="Whether to include soft-deleted users"
    )


class UserListItem(BaseModel):
    """Schema for user list items."""
    
    id: int = Field(description="User ID")
    username: str = Field(description="Username")
    email: EmailStr = Field(description="Email address")
    full_name: str = Field(description="Full name")
    status: UserStatus = Field(description="Account status")
    roles: List[str] = Field(description="User roles")
    branch_id: Optional[int] = Field(description="Branch ID")
    is_active: bool = Field(description="Whether account is active")
    is_verified: bool = Field(description="Whether email is verified")
    is_superuser: bool = Field(description="Whether user is superuser")
    two_factor_enabled: bool = Field(description="Whether 2FA is enabled")
    created_at: datetime = Field(description="Creation timestamp")
    last_login_at: Optional[datetime] = Field(description="Last login timestamp")
    is_locked: bool = Field(description="Whether account is locked")


class UserListResponse(BaseModel):
    """Schema for user listing responses."""
    
    users: List[UserListItem] = Field(description="List of users")
    pagination: 'PaginationInfo' = Field(description="Pagination information")
    total_count: int = Field(description="Total number of users")
    filters_applied: Dict[str, Any] = Field(description="Applied filters")


class PaginationInfo(BaseModel):
    """Schema for pagination information."""
    
    page: int = Field(description="Current page")
    page_size: int = Field(description="Items per page")
    total_pages: int = Field(description="Total number of pages")
    has_next: bool = Field(description="Whether there is a next page")
    has_previous: bool = Field(description="Whether there is a previous page")
    next_page: Optional[int] = Field(description="Next page number")
    previous_page: Optional[int] = Field(description="Previous page number")


# ==================== USER STATISTICS SCHEMAS ====================

class UserStatistics(BaseModel):
    """Schema for user statistics."""
    
    total_users: int = Field(description="Total number of users")
    active_users: int = Field(description="Number of active users")
    inactive_users: int = Field(description="Number of inactive users")
    suspended_users: int = Field(description="Number of suspended users")
    pending_users: int = Field(description="Number of pending users")
    verified_users: int = Field(description="Number of verified users")
    users_with_2fa: int = Field(description="Number of users with 2FA enabled")
    superusers: int = Field(description="Number of superusers")
    locked_users: int = Field(description="Number of locked users")
    recent_registrations: int = Field(description="Registrations in last 30 days")
    recent_logins: int = Field(description="Users who logged in last 30 days")


class UserActivityStats(BaseModel):
    """Schema for user activity statistics."""
    
    user_id: int = Field(description="User ID")
    total_logins: int = Field(description="Total number of logins")
    successful_logins: int = Field(description="Number of successful logins")
    failed_logins: int = Field(description="Number of failed login attempts")
    last_login: Optional[datetime] = Field(description="Last login timestamp")
    password_changes: int = Field(description="Number of password changes")
    profile_updates: int = Field(description="Number of profile updates")
    account_age_days: int = Field(description="Account age in days")


# ==================== USER BULK OPERATIONS SCHEMAS ====================

class BulkUserActionRequest(BaseModel):
    """Schema for bulk user operations."""
    
    user_ids: List[int] = Field(
        min_items=1,
        max_items=100,
        description="List of user IDs to perform action on"
    )
    action: str = Field(
        regex=r"^(activate|deactivate|suspend|verify|send_verification|reset_password|force_logout)$",
        description="Action to perform"
    )
    reason: Optional[str] = Field(
        max_length=500,
        description="Reason for the action"
    )
    notify_users: bool = Field(
        default=True,
        description="Whether to notify affected users"
    )


class BulkUserActionResponse(BaseModel):
    """Schema for bulk user operation responses."""
    
    total_requested: int = Field(description="Total number of users requested")
    successful: int = Field(description="Number of successful operations")
    failed: int = Field(description="Number of failed operations")
    skipped: int = Field(description="Number of skipped operations")
    errors: List['BulkActionError'] = Field(description="List of errors")
    updated_at: datetime = Field(description="Operation timestamp")


class BulkActionError(BaseModel):
    """Schema for bulk action errors."""
    
    user_id: int = Field(description="User ID that failed")
    error_code: str = Field(description="Error code")
    error_message: str = Field(description="Error message")


# ==================== USER EXPORT/IMPORT SCHEMAS ====================

class UserExportRequest(BaseModel):
    """Schema for user export requests."""
    
    format: str = Field(
        default="csv",
        regex=r"^(csv|xlsx|json)$",
        description="Export format"
    )
    filters: Optional[UserSearchFilter] = Field(
        default=None,
        description="Filters to apply"
    )
    include_personal_data: bool = Field(
        default=False,
        description="Whether to include personal data (admin only)"
    )
    fields: Optional[List[str]] = Field(
        default=None,
        description="Specific fields to export"
    )


class UserImportRequest(BaseModel):
    """Schema for user import requests."""
    
    file_format: str = Field(
        regex=r"^(csv|xlsx)$",
        description="File format"
    )
    update_existing: bool = Field(
        default=False,
        description="Whether to update existing users"
    )
    send_welcome_emails: bool = Field(
        default=True,
        description="Whether to send welcome emails to new users"
    )
    default_role: Optional[UserRole] = Field(
        default=None,
        description="Default role for imported users"
    )
    default_branch_id: Optional[int] = Field(
        default=None,
        description="Default branch for imported users"
    )


class UserImportResponse(BaseModel):
    """Schema for user import responses."""
    
    total_rows: int = Field(description="Total rows processed")
    successful_imports: int = Field(description="Successful imports")
    successful_updates: int = Field(description="Successful updates")
    failed_imports: int = Field(description="Failed imports")
    skipped_rows: int = Field(description="Skipped rows")
    errors: List['ImportError'] = Field(description="Import errors")
    imported_user_ids: List[int] = Field(description="IDs of imported users")


class ImportError(BaseModel):
    """Schema for import errors."""
    
    row_number: int = Field(description="Row number in source file")
    field_name: Optional[str] = Field(description="Field that caused error")
    error_message: str = Field(description="Error description")
    row_data: Dict[str, Any] = Field(description="Original row data")


# ==================== USER PREFERENCES SCHEMAS ====================

class UserPreferences(BaseModel):
    """Schema for user preferences."""
    
    theme: str = Field(
        default="light",
        regex=r"^(light|dark|auto)$",
        description="UI theme preference"
    )
    notifications: 'NotificationPreferences' = Field(
        description="Notification preferences"
    )
    dashboard_layout: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Custom dashboard layout"
    )
    default_currency: str = Field(
        default="USD",
        regex=r"^[A-Z]{3}$",
        description="Default currency for transactions"
    )
    items_per_page: int = Field(
        default=20,
        ge=10,
        le=100,
        description="Default items per page in lists"
    )


class NotificationPreferences(BaseModel):
    """Schema for notification preferences."""
    
    email_notifications: bool = Field(
        default=True,
        description="Enable email notifications"
    )
    sms_notifications: bool = Field(
        default=False,
        description="Enable SMS notifications"
    )
    push_notifications: bool = Field(
        default=True,
        description="Enable push notifications"
    )
    security_alerts: bool = Field(
        default=True,
        description="Enable security alert notifications"
    )
    transaction_alerts: bool = Field(
        default=True,
        description="Enable transaction alert notifications"
    )
    marketing_emails: bool = Field(
        default=False,
        description="Enable marketing emails"
    )


# ==================== CONFIGURATION ====================

# Forward references
UserDetailRead.update_forward_refs()
UserListResponse.update_forward_refs()
UserRoleUpdateRequest.update_forward_refs()
BulkUserActionResponse.update_forward_refs()
UserImportResponse.update_forward_refs()
UserPreferences.update_forward_refs()

# Model configuration
class Config:
    """Common configuration for all user schemas."""
    
    extra = "forbid"
    use_enum_values = True
    validate_assignment = True
    allow_population_by_field_name = True
    
    json_encoders = {
        datetime: lambda v: v.isoformat(),
        SecretStr: lambda v: v.get_secret_value() if v else None
    }
    
    schema_extra = {
        "examples": [
            {
                "username": "john_doe",
                "email": "john.doe@example.com",
                "first_name": "John",
                "last_name": "Doe",
                "phone_number": "+1234567890"
            }
        ]
    }


# Apply configuration to all schemas
for cls_name in list(globals().keys()):
    cls = globals()[cls_name]
    if isinstance(cls, type) and issubclass(cls, BaseModel) and cls != BaseModel:
        if not hasattr(cls, 'Config'):
            cls.Config = Config