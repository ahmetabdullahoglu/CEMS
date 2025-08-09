"""
Module: user_service
Purpose: Complete user management service providing comprehensive user operations for CEMS
Author: CEMS Development Team
Date: 2024
"""

from typing import List, Optional, Dict, Any, Tuple, Union
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from sqlalchemy.exc import SQLAlchemyError

from app.repositories.user_repository import UserRepository
from app.core.security import get_password_hash, security_manager
from app.core.config import settings
from app.core.constants import UserRole, UserStatus
from app.core.exceptions import (
    ValidationException, NotFoundError, DuplicateResourceException, 
    InsufficientPermissionsException, DatabaseException, BusinessLogicException
)
from app.schemas.user import (
    UserCreateRequest, UserResponse, UserUpdateRequest, UserUpdateByAdminRequest,
    UserRoleAssignRequest, UserRoleRemoveRequest, UserSearchFilter, UserListRequest,
    UserListResponse, UserStatistics, PaginationInfo, UserUpdateResponse,
    UserRoleResponse, UserListItem
)
from app.schemas.auth import SecurityEvent
from app.db.models.user import User, Role
from app.utils.logger import get_logger
from app.utils.validators import (
    validate_password_strength, validate_email_format, 
    validate_username_format, validate_phone_number
)
from app.utils.generators import generate_user_code, generate_temporary_password

logger = get_logger(__name__)


class UserService:
    """
    Complete user service providing comprehensive user management functionality.
    Handles user creation, updates, role management, profile management, and analytics.
    """
    
    def __init__(self, db: Session):
        """
        Initialize user service.
        
        Args:
            db: Database session
        """
        self.db = db
        self.user_repo = UserRepository(db)
        self.logger = get_logger(self.__class__.__name__)
        
        # Load configuration
        self.default_user_role = getattr(settings, 'DEFAULT_USER_ROLE', UserRole.CASHIER.value)
        self.require_email_verification = getattr(settings, 'REQUIRE_EMAIL_VERIFICATION', True)
        self.auto_generate_username = getattr(settings, 'AUTO_GENERATE_USERNAME', False)
        self.default_password_length = getattr(settings, 'DEFAULT_PASSWORD_LENGTH', 12)
    
    # ==================== USER CREATION AND MANAGEMENT ====================
    
    def create_user(
        self,
        user_data: UserCreateRequest,
        created_by_user_id: Optional[int] = None,
        auto_assign_role: bool = True
    ) -> UserResponse:
        """
        Create a new user with validation and role assignment.
        
        Args:
            user_data: User creation data
            created_by_user_id: ID of user creating this user
            auto_assign_role: Whether to auto-assign default role
            
        Returns:
            UserResponse: Created user information
            
        Raises:
            ValidationException: If validation fails
            DuplicateResourceException: If user already exists
            InsufficientPermissionsException: If creator lacks permissions
        """
        try:
            # Validate user creation data
            self._validate_user_creation_data(user_data)
            
            # Check permissions if creator specified
            if created_by_user_id:
                self._validate_user_creation_permissions(
                    created_by_user_id, 
                    user_data.roles or []
                )
            
            # Generate username if not provided and auto-generation enabled
            username = user_data.username
            if not username and self.auto_generate_username:
                username = self._generate_unique_username(user_data.first_name, user_data.last_name)
            
            # Hash password
            hashed_password = get_password_hash(user_data.password.get_secret_value())
            
            # Determine initial status
            initial_status = UserStatus.PENDING if self.require_email_verification else UserStatus.ACTIVE
            
            # Create user
            user = self.user_repo.create_user(
                username=username,
                email=user_data.email,
                hashed_password=hashed_password,
                first_name=user_data.first_name,
                last_name=user_data.last_name,
                phone_number=user_data.phone_number,
                status=initial_status,
                is_active=True,
                is_verified=not self.require_email_verification,
                branch_id=user_data.branch_id
            )
            
            # Assign roles
            roles_to_assign = user_data.roles or []
            if auto_assign_role and not roles_to_assign:
                roles_to_assign = [UserRole(self.default_user_role)]
            
            for role in roles_to_assign:
                try:
                    self.user_repo.assign_role(user.id, role.value)
                except Exception as e:
                    self.logger.warning(f"Failed to assign role {role.value} to user {user.id}: {str(e)}")
            
            # Get user with roles for response
            created_user = self.user_repo.get_by_id_with_roles(user.id)
            user_roles = [role.name for role in self.user_repo.get_user_roles(user.id)]
            
            # Record activity
            self._record_user_activity(
                user.id, created_by_user_id,
                "user_created",
                {
                    "username": username,
                    "email": user_data.email,
                    "roles": user_roles,
                    "auto_assign_role": auto_assign_role
                }
            )
            
            self.logger.info(f"Created user: {username} (ID: {user.id})")
            
            # Convert to response
            return self._user_to_response(created_user, include_sensitive=False)
            
        except (ValidationException, DuplicateResourceException, InsufficientPermissionsException):
            raise
        except Exception as e:
            self.logger.error(f"Error creating user: {str(e)}")
            raise BusinessLogicException(f"Failed to create user: {str(e)}")
    
    def get_user_by_id(
        self,
        user_id: int,
        requesting_user_id: Optional[int] = None,
        include_sensitive: bool = False
    ) -> UserResponse:
        """
        Get user by ID with permission validation.
        
        Args:
            user_id: User ID to retrieve
            requesting_user_id: ID of user making request
            include_sensitive: Whether to include sensitive information
            
        Returns:
            UserResponse: User information
            
        Raises:
            NotFoundError: If user not found
            InsufficientPermissionsException: If insufficient permissions
        """
        try:
            # Get user
            user = self.user_repo.get_by_id_with_roles(user_id)
            if not user:
                raise NotFoundError(f"User with ID {user_id} not found")
            
            # Check permissions
            if requesting_user_id:
                self._validate_user_access_permissions(requesting_user_id, user_id, include_sensitive)
            
            return self._user_to_response(user, include_sensitive)
            
        except (NotFoundError, InsufficientPermissionsException):
            raise
        except Exception as e:
            self.logger.error(f"Error getting user {user_id}: {str(e)}")
            raise BusinessLogicException(f"Failed to get user: {str(e)}")
    
    def update_user(
        self,
        user_id: int,
        update_data: Union[UserUpdateRequest, UserUpdateByAdminRequest],
        updated_by_user_id: Optional[int] = None
    ) -> UserUpdateResponse:
        """
        Update user information with validation.
        
        Args:
            user_id: User ID to update
            update_data: Update data (regular or admin)
            updated_by_user_id: ID of user making update
            
        Returns:
            UserUpdateResponse: Update result
            
        Raises:
            NotFoundError: If user not found
            ValidationException: If validation fails
            InsufficientPermissionsException: If insufficient permissions
        """
        try:
            # Get existing user
            existing_user = self.user_repo.get_by_id_with_roles(user_id)
            if not existing_user:
                raise NotFoundError(f"User with ID {user_id} not found")
            
            # Check permissions
            is_admin_update = isinstance(update_data, UserUpdateByAdminRequest)
            if updated_by_user_id:
                self._validate_user_update_permissions(
                    updated_by_user_id, user_id, update_data, is_admin_update
                )
            
            # Validate update data
            self._validate_user_update_data(update_data, existing_user)
            
            # Prepare update dictionary
            update_dict = {}
            updated_fields = []
            
            # Process regular fields
            for field, value in update_data.dict(exclude_unset=True).items():
                if value is not None and hasattr(existing_user, field):
                    if getattr(existing_user, field) != value:
                        update_dict[field] = value
                        updated_fields.append(field)
            
            # Handle password update if provided
            if hasattr(update_data, 'password') and update_data.password:
                # Validate password strength
                password_validation = validate_password_strength(update_data.password.get_secret_value())
                if not password_validation["is_strong"]:
                    raise ValidationException("Password does not meet strength requirements")
                
                update_dict['hashed_password'] = get_password_hash(update_data.password.get_secret_value())
                update_dict['password_changed_at'] = datetime.utcnow()
                updated_fields.append('password')
            
            # Perform update if there are changes
            if update_dict:
                updated_user = self.user_repo.update_user(user_id, update_dict)
            else:
                updated_user = existing_user
            
            # Record activity
            self._record_user_activity(
                user_id, updated_by_user_id,
                "user_updated",
                {
                    "updated_fields": updated_fields,
                    "is_admin_update": is_admin_update
                }
            )
            
            self.logger.info(f"Updated user {user_id}: {updated_fields}")
            
            return UserUpdateResponse(
                user_id=user_id,
                updated_fields=updated_fields,
                updated_at=datetime.utcnow()
            )
            
        except (NotFoundError, ValidationException, InsufficientPermissionsException):
            raise
        except Exception as e:
            self.logger.error(f"Error updating user {user_id}: {str(e)}")
            raise BusinessLogicException(f"Failed to update user: {str(e)}")
    
    def delete_user(
        self,
        user_id: int,
        deleted_by_user_id: Optional[int] = None,
        hard_delete: bool = False
    ) -> Dict[str, Any]:
        """
        Delete user (soft delete by default).
        
        Args:
            user_id: User ID to delete
            deleted_by_user_id: ID of user performing deletion
            hard_delete: Whether to perform hard delete
            
        Returns:
            Dictionary with deletion status
            
        Raises:
            NotFoundError: If user not found
            InsufficientPermissionsException: If insufficient permissions
        """
        try:
            # Get user
            user = self.user_repo.get_by_id_with_roles(user_id)
            if not user:
                raise NotFoundError(f"User with ID {user_id} not found")
            
            # Check permissions
            if deleted_by_user_id:
                self._validate_user_deletion_permissions(deleted_by_user_id, user_id)
            
            # Prevent self-deletion
            if deleted_by_user_id == user_id:
                raise ValidationException("Cannot delete your own account")
            
            # Perform deletion
            if hard_delete:
                # Hard delete (actual database deletion)
                self.user_repo.hard_delete(user_id)
                deletion_type = "hard_delete"
            else:
                # Soft delete
                self.user_repo.soft_delete(user_id)
                deletion_type = "soft_delete"
            
            # Record activity
            self._record_user_activity(
                user_id, deleted_by_user_id,
                "user_deleted",
                {
                    "username": user.username,
                    "deletion_type": deletion_type
                }
            )
            
            self.logger.warning(f"Deleted user {user_id} ({deletion_type})")
            
            return {
                "message": f"User {deletion_type.replace('_', ' ')} successfully",
                "user_id": user_id,
                "deletion_type": deletion_type
            }
            
        except (NotFoundError, ValidationException, InsufficientPermissionsException):
            raise
        except Exception as e:
            self.logger.error(f"Error deleting user {user_id}: {str(e)}")
            raise BusinessLogicException(f"Failed to delete user: {str(e)}")
    
    # ==================== USER LISTING AND SEARCH ====================
    
    def list_users(
        self,
        request: UserListRequest,
        requesting_user_id: Optional[int] = None
    ) -> UserListResponse:
        """
        Get paginated list of users with filtering and sorting.
        
        Args:
            request: List request with pagination and filters
            requesting_user_id: ID of user making request
            
        Returns:
            UserListResponse: Paginated user list
            
        Raises:
            InsufficientPermissionsException: If insufficient permissions
        """
        try:
            # Check permissions
            if requesting_user_id:
                self._validate_user_list_permissions(requesting_user_id, request.filters)
            
            # Get paginated users
            users, total_count = self.user_repo.get_users_paginated(
                request, 
                include_deleted=request.include_deleted
            )
            
            # Convert to list items
            user_items = []
            for user in users:
                user_roles = [role.name for role in self.user_repo.get_user_roles(user.id)]
                
                user_item = UserListItem(
                    id=user.id,
                    username=user.username,
                    email=user.email,
                    full_name=f"{user.first_name} {user.last_name}",
                    status=UserStatus(user.status),
                    is_active=user.is_active,
                    is_verified=user.is_verified,
                    roles=user_roles,
                    branch_id=user.branch_id,
                    last_login_at=user.last_login_at,
                    created_at=user.created_at
                )
                user_items.append(user_item)
            
            # Calculate pagination info
            total_pages = (total_count + request.page_size - 1) // request.page_size
            pagination = PaginationInfo(
                page=request.page,
                page_size=request.page_size,
                total_items=total_count,
                total_pages=total_pages,
                has_next=request.page < total_pages,
                has_previous=request.page > 1
            )
            
            return UserListResponse(
                users=user_items,
                pagination=pagination,
                filters_applied=request.filters is not None
            )
            
        except InsufficientPermissionsException:
            raise
        except Exception as e:
            self.logger.error(f"Error listing users: {str(e)}")
            raise BusinessLogicException(f"Failed to list users: {str(e)}")
    
    def search_users(
        self,
        search_term: str,
        filters: Optional[UserSearchFilter] = None,
        requesting_user_id: Optional[int] = None
    ) -> List[UserResponse]:
        """
        Search users by term with optional filters.
        
        Args:
            search_term: Search term
            filters: Optional search filters
            requesting_user_id: ID of user making request
            
        Returns:
            List[UserResponse]: Matching users
        """
        try:
            # Check permissions
            if requesting_user_id:
                self._validate_user_list_permissions(requesting_user_id, filters)
            
            # Search users
            users = self.user_repo.search_users(search_term, filters)
            
            # Convert to responses
            user_responses = []
            for user in users:
                user_response = self._user_to_response(user, include_sensitive=False)
                user_responses.append(user_response)
            
            return user_responses
            
        except InsufficientPermissionsException:
            raise
        except Exception as e:
            self.logger.error(f"Error searching users: {str(e)}")
            raise BusinessLogicException(f"Failed to search users: {str(e)}")
    
    # ==================== ROLE MANAGEMENT ====================
    
    def assign_roles(
        self,
        user_id: int,
        role_data: UserRoleAssignRequest,
        assigned_by_user_id: Optional[int] = None
    ) -> UserRoleResponse:
        """
        Assign roles to user.
        
        Args:
            user_id: User ID
            role_data: Role assignment data
            assigned_by_user_id: ID of user assigning roles
            
        Returns:
            UserRoleResponse: Role assignment result
        """
        try:
            # Validate permissions
            if assigned_by_user_id:
                self._validate_role_management_permissions(assigned_by_user_id, role_data.role_names)
            
            # Get user
            user = self.user_repo.get_by_id_with_roles(user_id)
            if not user:
                raise NotFoundError(f"User with ID {user_id} not found")
            
            # Get current roles
            current_roles = [role.name for role in self.user_repo.get_user_roles(user_id)]
            
            # Assign new roles
            assigned_roles = []
            for role_name in role_data.role_names:
                if role_name.value not in current_roles:
                    try:
                        self.user_repo.assign_role(user_id, role_name.value)
                        assigned_roles.append(role_name.value)
                    except DuplicateResourceException:
                        # Role already assigned, skip
                        continue
            
            # Get updated roles
            updated_roles = [role.name for role in self.user_repo.get_user_roles(user_id)]
            
            # Record activity
            self._record_user_activity(
                user_id, assigned_by_user_id,
                "roles_assigned",
                {
                    "assigned_roles": assigned_roles,
                    "expires_at": role_data.expires_at.isoformat() if role_data.expires_at else None
                }
            )
            
            self.logger.info(f"Assigned roles {assigned_roles} to user {user_id}")
            
            return UserRoleResponse(
                user_id=user_id,
                roles_assigned=assigned_roles,
                roles_removed=[],
                effective_roles=updated_roles,
                updated_at=datetime.utcnow()
            )
            
        except (NotFoundError, InsufficientPermissionsException, DuplicateResourceException):
            raise
        except Exception as e:
            self.logger.error(f"Error assigning roles to user {user_id}: {str(e)}")
            raise BusinessLogicException(f"Failed to assign roles: {str(e)}")
    
    def remove_roles(
        self,
        user_id: int,
        role_data: UserRoleRemoveRequest,
        removed_by_user_id: Optional[int] = None
    ) -> UserRoleResponse:
        """
        Remove roles from user.
        
        Args:
            user_id: User ID
            role_data: Role removal data
            removed_by_user_id: ID of user removing roles
            
        Returns:
            UserRoleResponse: Role removal result
        """
        try:
            # Validate permissions
            if removed_by_user_id:
                self._validate_role_management_permissions(removed_by_user_id, role_data.role_names)
            
            # Get user
            user = self.user_repo.get_by_id_with_roles(user_id)
            if not user:
                raise NotFoundError(f"User with ID {user_id} not found")
            
            # Remove roles
            removed_roles = []
            for role_name in role_data.role_names:
                try:
                    self.user_repo.remove_role(user_id, role_name.value)
                    removed_roles.append(role_name.value)
                except NotFoundError:
                    # Role not assigned, skip
                    continue
            
            # Get updated roles
            updated_roles = [role.name for role in self.user_repo.get_user_roles(user_id)]
            
            # Record activity
            self._record_user_activity(
                user_id, removed_by_user_id,
                "roles_removed",
                {"removed_roles": removed_roles}
            )
            
            self.logger.info(f"Removed roles {removed_roles} from user {user_id}")
            
            return UserRoleResponse(
                user_id=user_id,
                roles_assigned=[],
                roles_removed=removed_roles,
                effective_roles=updated_roles,
                updated_at=datetime.utcnow()
            )
            
        except (NotFoundError, InsufficientPermissionsException):
            raise
        except Exception as e:
            self.logger.error(f"Error removing roles from user {user_id}: {str(e)}")
            raise BusinessLogicException(f"Failed to remove roles: {str(e)}")
    
    def get_user_roles(self, user_id: int) -> List[str]:
        """
        Get user roles.
        
        Args:
            user_id: User ID
            
        Returns:
            List[str]: User role names
        """
        try:
            roles = self.user_repo.get_user_roles(user_id)
            return [role.name for role in roles]
        except Exception as e:
            self.logger.error(f"Error getting user roles for {user_id}: {str(e)}")
            return []
    
    def get_users_by_role(
        self,
        role_name: str,
        requesting_user_id: Optional[int] = None
    ) -> List[UserResponse]:
        """
        Get all users with specific role.
        
        Args:
            role_name: Role name
            requesting_user_id: ID of user making request
            
        Returns:
            List[UserResponse]: Users with the role
        """
        try:
            # Validate permissions
            if requesting_user_id:
                self._validate_admin_permissions(requesting_user_id)
            
            # Get users
            users = self.user_repo.get_users_by_role(role_name)
            
            # Convert to response objects
            user_responses = []
            for user in users:
                user_response = self._user_to_response(user, include_sensitive=False)
                user_responses.append(user_response)
            
            return user_responses
            
        except InsufficientPermissionsException:
            raise
        except Exception as e:
            self.logger.error(f"Error getting users by role {role_name}: {str(e)}")
            raise BusinessLogicException(f"Failed to get users by role: {str(e)}")
    
    # ==================== ACCOUNT MANAGEMENT ====================
    
    def activate_user(
        self,
        user_id: int,
        activated_by_user_id: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Activate user account.
        
        Args:
            user_id: User ID to activate
            activated_by_user_id: ID of user performing activation
            
        Returns:
            Dictionary with activation status
        """
        try:
            # Get user
            user = self.user_repo.get_by_id_with_roles(user_id)
            if not user:
                raise NotFoundError(f"User with ID {user_id} not found")
            
            # Check permissions
            if activated_by_user_id:
                self._validate_admin_permissions(activated_by_user_id)
            
            # Update user status
            self.user_repo.update_user(user_id, {
                "status": UserStatus.ACTIVE.value,
                "is_active": True,
                "is_verified": True
            })
            
            # Record activity
            self._record_user_activity(
                user_id, activated_by_user_id,
                "user_activated",
                {"previous_status": user.status}
            )
            
            self.logger.info(f"Activated user account {user_id}")
            
            return {
                "message": "User account activated successfully",
                "user_id": user_id,
                "status": UserStatus.ACTIVE.value
            }
            
        except (NotFoundError, InsufficientPermissionsException):
            raise
        except Exception as e:
            self.logger.error(f"Error activating user {user_id}: {str(e)}")
            raise BusinessLogicException(f"Failed to activate user: {str(e)}")
    
    def deactivate_user(
        self,
        user_id: int,
        reason: str,
        deactivated_by_user_id: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Deactivate user account.
        
        Args:
            user_id: User ID to deactivate
            reason: Deactivation reason
            deactivated_by_user_id: ID of user performing deactivation
            
        Returns:
            Dictionary with deactivation status
        """
        try:
            # Get user
            user = self.user_repo.get_by_id_with_roles(user_id)
            if not user:
                raise NotFoundError(f"User with ID {user_id} not found")
            
            # Check permissions
            if deactivated_by_user_id:
                self._validate_admin_permissions(deactivated_by_user_id)
            
            # Prevent self-deactivation
            if deactivated_by_user_id == user_id:
                raise ValidationException("Cannot deactivate your own account")
            
            # Update user status
            self.user_repo.update_user(user_id, {
                "status": UserStatus.SUSPENDED.value,
                "is_active": False
            })
            
            # Invalidate user sessions
            if hasattr(security_manager, 'session_manager'):
                security_manager.session_manager.invalidate_user_sessions(user_id)
            
            # Record activity
            self._record_user_activity(
                user_id, deactivated_by_user_id,
                "user_deactivated",
                {
                    "reason": reason,
                    "previous_status": user.status
                }
            )
            
            self.logger.warning(f"Deactivated user account {user_id}: {reason}")
            
            return {
                "message": "User account deactivated successfully",
                "user_id": user_id,
                "reason": reason,
                "status": UserStatus.SUSPENDED.value
            }
            
        except (NotFoundError, ValidationException, InsufficientPermissionsException):
            raise
        except Exception as e:
            self.logger.error(f"Error deactivating user {user_id}: {str(e)}")
            raise BusinessLogicException(f"Failed to deactivate user: {str(e)}")
    
    def lock_user_account(
        self,
        user_id: int,
        reason: str,
        locked_until: Optional[datetime] = None,
        locked_by_user_id: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Lock user account.
        
        Args:
            user_id: User ID to lock
            reason: Lock reason
            locked_until: Optional unlock time
            locked_by_user_id: ID of user performing lock
            
        Returns:
            Dictionary with lock status
        """
        try:
            # Check permissions
            if locked_by_user_id:
                self._validate_admin_permissions(locked_by_user_id)
            
            # Lock account using repository
            success = self.user_repo.lock_user_account(user_id, reason, locked_until)
            
            if success:
                # Invalidate user sessions
                if hasattr(security_manager, 'session_manager'):
                    security_manager.session_manager.invalidate_user_sessions(user_id)
                
                # Record activity
                self._record_user_activity(
                    user_id, locked_by_user_id,
                    "user_locked",
                    {
                        "reason": reason,
                        "locked_until": locked_until.isoformat() if locked_until else None
                    }
                )
                
                return {
                    "message": "User account locked successfully",
                    "user_id": user_id,
                    "reason": reason,
                    "locked_until": locked_until
                }
            else:
                raise BusinessLogicException("Failed to lock user account")
                
        except InsufficientPermissionsException:
            raise
        except Exception as e:
            self.logger.error(f"Error locking user {user_id}: {str(e)}")
            raise BusinessLogicException(f"Failed to lock user: {str(e)}")
    
    def unlock_user_account(
        self,
        user_id: int,
        unlocked_by_user_id: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Unlock user account.
        
        Args:
            user_id: User ID to unlock
            unlocked_by_user_id: ID of user performing unlock
            
        Returns:
            Dictionary with unlock status
        """
        try:
            # Check permissions
            if unlocked_by_user_id:
                self._validate_admin_permissions(unlocked_by_user_id)
            
            # Unlock account using repository
            success = self.user_repo.unlock_user_account(user_id)
            
            if success:
                # Record activity
                self._record_user_activity(
                    user_id, unlocked_by_user_id,
                    "user_unlocked",
                    {}
                )
                
                return {
                    "message": "User account unlocked successfully",
                    "user_id": user_id,
                    "status": UserStatus.ACTIVE.value
                }
            else:
                raise BusinessLogicException("Failed to unlock user account")
                
        except InsufficientPermissionsException:
            raise
        except Exception as e:
            self.logger.error(f"Error unlocking user {user_id}: {str(e)}")
            raise BusinessLogicException(f"Failed to unlock user: {str(e)}")
    
    # ==================== USER ANALYTICS ====================
    
    def get_user_statistics(
        self,
        requesting_user_id: Optional[int] = None
    ) -> UserStatistics:
        """
        Get user statistics for analytics.
        
        Args:
            requesting_user_id: ID of user requesting statistics
            
        Returns:
            UserStatistics: User statistics
        """
        try:
            # Check permissions
            if requesting_user_id:
                self._validate_admin_permissions(requesting_user_id)
            
            # Get statistics
            total_users = self.user_repo.get_total_count()
            active_users = self.user_repo.get_active_users_count()
            
            # Get users by status
            pending_users = len(self.user_repo.get_users_by_status(UserStatus.PENDING))
            suspended_users = len(self.user_repo.get_users_by_status(UserStatus.SUSPENDED))
            locked_users = len(self.user_repo.get_users_by_status(UserStatus.LOCKED))
            
            # Get users by role
            admin_users = len(self.user_repo.get_users_by_role(UserRole.ADMIN.value))
            manager_users = len(self.user_repo.get_users_by_role(UserRole.BRANCH_MANAGER.value))
            cashier_users = len(self.user_repo.get_users_by_role(UserRole.CASHIER.value))
            
            return UserStatistics(
                total_users=total_users,
                active_users=active_users,
                inactive_users=total_users - active_users,
                pending_users=pending_users,
                suspended_users=suspended_users,
                locked_users=locked_users,
                admin_users=admin_users,
                manager_users=manager_users,
                cashier_users=cashier_users,
                verified_users=total_users - pending_users,  # Approximation
                unverified_users=pending_users
            )
            
        except InsufficientPermissionsException:
            raise
        except Exception as e:
            self.logger.error(f"Error getting user statistics: {str(e)}")
            raise BusinessLogicException(f"Failed to get user statistics: {str(e)}")
    
    # ==================== UTILITY AND HELPER METHODS ====================
    
    def _user_to_response(self, user: User, include_sensitive: bool = False) -> UserResponse:
        """
        Convert User model to UserResponse.
        
        Args:
            user: User model instance
            include_sensitive: Whether to include sensitive information
            
        Returns:
            UserResponse: User response object
        """
        user_roles = [role.name for role in self.user_repo.get_user_roles(user.id)]
        user_permissions = self.user_repo.get_user_permissions(user.id) if include_sensitive else []
        
        return UserResponse(
            id=user.id,
            username=user.username,
            email=user.email,
            first_name=user.first_name,
            last_name=user.last_name,
            full_name=f"{user.first_name} {user.last_name}",
            phone_number=user.phone_number,
            status=UserStatus(user.status),
            is_active=user.is_active,
            is_superuser=user.is_superuser,
            is_verified=user.is_verified,
            roles=user_roles,
            permissions=user_permissions,
            branch_id=user.branch_id,
            last_login_at=user.last_login_at,
            last_login_ip=user.last_login_ip if include_sensitive else None,
            created_at=user.created_at,
            updated_at=user.updated_at
        )
    
    def _generate_unique_username(self, first_name: str, last_name: str) -> str:
        """
        Generate unique username from names.
        
        Args:
            first_name: User's first name
            last_name: User's last name
            
        Returns:
            str: Unique username
        """
        base_username = f"{first_name.lower()}.{last_name.lower()}"
        username = base_username
        counter = 1
        
        while self.user_repo.check_username_exists(username):
            username = f"{base_username}{counter}"
            counter += 1
        
        return username
    
    def _record_user_activity(
        self,
        user_id: int,
        performed_by_user_id: Optional[int],
        activity_type: str,
        details: Dict[str, Any]
    ) -> None:
        """
        Record user activity for audit trail.
        
        Args:
            user_id: User ID the activity relates to
            performed_by_user_id: ID of user who performed the activity
            activity_type: Type of activity
            details: Activity details
        """
        try:
            activity_data = {
                "user_id": user_id,
                "performed_by_user_id": performed_by_user_id,
                "activity_type": activity_type,
                "timestamp": datetime.utcnow().isoformat(),
                "details": details
            }
            
            # Log activity
            self.logger.info(f"User activity: {activity_type}", extra=activity_data)
            
            # TODO: Store in activity audit table
            # activity_audit_repo.create_activity(activity_data)
            
        except Exception as e:
            self.logger.error(f"Failed to record user activity: {str(e)}")
    
    # ==================== VALIDATION METHODS ====================
    
    def _validate_user_creation_data(self, user_data: UserCreateRequest) -> None:
        """
        Validate user creation data.
        
        Args:
            user_data: User creation data
            
        Raises:
            ValidationException: If validation fails
        """
        # Validate email format
        if not validate_email_format(user_data.email):
            raise ValidationException("Invalid email format")
        
        # Validate username format if provided
        if user_data.username and not validate_username_format(user_data.username):
            raise ValidationException("Invalid username format")
        
        # Validate password strength
        password_validation = validate_password_strength(user_data.password.get_secret_value())
        if not password_validation["is_strong"]:
            raise ValidationException(f"Password requirements not met: {password_validation['feedback']}")
        
        # Validate phone number if provided
        if user_data.phone_number and not validate_phone_number(user_data.phone_number):
            raise ValidationException("Invalid phone number format")
        
        # Validate roles if provided
        if user_data.roles:
            for role in user_data.roles:
                if role not in [r for r in UserRole]:
                    raise ValidationException(f"Invalid role: {role}")
    
    def _validate_user_update_data(self, update_data, existing_user) -> None:
        """
        Validate user update data.
        
        Args:
            update_data: Update data
            existing_user: Existing user model
            
        Raises:
            ValidationException: If validation fails
        """
        # Validate email format if provided
        if hasattr(update_data, 'email') and update_data.email:
            if not validate_email_format(update_data.email):
                raise ValidationException("Invalid email format")
        
        # Validate username format if provided
        if hasattr(update_data, 'username') and update_data.username:
            if not validate_username_format(update_data.username):
                raise ValidationException("Invalid username format")
        
        # Validate phone number if provided
        if hasattr(update_data, 'phone_number') and update_data.phone_number:
            if not validate_phone_number(update_data.phone_number):
                raise ValidationException("Invalid phone number format")
    
    def _validate_user_creation_permissions(self, creator_id: int, roles: List[UserRole]) -> None:
        """
        Validate user creation permissions.
        
        Args:
            creator_id: ID of user creating the user
            roles: Roles to assign to new user
            
        Raises:
            InsufficientPermissionsException: If insufficient permissions
        """
        creator_roles = [role.name for role in self.user_repo.get_user_roles(creator_id)]
        
        # Only admins can create users
        if not any(role in [UserRole.SUPER_ADMIN.value, UserRole.ADMIN.value] for role in creator_roles):
            raise InsufficientPermissionsException("Insufficient permissions to create users")
        
        # Only super admins can create admin users
        if roles and any(role in [UserRole.ADMIN, UserRole.SUPER_ADMIN] for role in roles):
            if UserRole.SUPER_ADMIN.value not in creator_roles:
                raise InsufficientPermissionsException("Only super admins can create admin users")
    
    def _validate_user_update_permissions(
        self, 
        updater_id: int, 
        user_id: int, 
        update_data, 
        is_admin_update: bool
    ) -> None:
        """
        Validate user update permissions.
        
        Args:
            updater_id: ID of user performing update
            user_id: ID of user being updated
            update_data: Update data
            is_admin_update: Whether this is an admin update
            
        Raises:
            InsufficientPermissionsException: If insufficient permissions
        """
        updater_roles = [role.name for role in self.user_repo.get_user_roles(updater_id)]
        
        # Users can update their own basic profile
        if updater_id == user_id and not is_admin_update:
            return
        
        # Admin updates require admin permissions
        if is_admin_update:
            if not any(role in [UserRole.SUPER_ADMIN.value, UserRole.ADMIN.value] for role in updater_roles):
                raise InsufficientPermissionsException("Insufficient permissions for admin updates")
    
    def _validate_user_deletion_permissions(self, deleter_id: int, user_id: int) -> None:
        """
        Validate user deletion permissions.
        
        Args:
            deleter_id: ID of user performing deletion
            user_id: ID of user being deleted
            
        Raises:
            InsufficientPermissionsException: If insufficient permissions
        """
        deleter_roles = [role.name for role in self.user_repo.get_user_roles(deleter_id)]
        
        if not any(role in [UserRole.SUPER_ADMIN.value, UserRole.ADMIN.value] for role in deleter_roles):
            raise InsufficientPermissionsException("Insufficient permissions to delete users")
    
    def _validate_admin_permissions(self, user_id: int) -> None:
        """
        Validate admin permissions.
        
        Args:
            user_id: User ID to check
            
        Raises:
            InsufficientPermissionsException: If insufficient permissions
        """
        user_roles = [role.name for role in self.user_repo.get_user_roles(user_id)]
        
        if not any(role in [UserRole.SUPER_ADMIN.value, UserRole.ADMIN.value] for role in user_roles):
            raise InsufficientPermissionsException("Admin permissions required")
    
    def _validate_role_management_permissions(self, manager_id: int, roles: List[UserRole]) -> None:
        """
        Validate role management permissions.
        
        Args:
            manager_id: ID of user managing roles
            roles: Roles being managed
            
        Raises:
            InsufficientPermissionsException: If insufficient permissions
        """
        manager_roles = [role.name for role in self.user_repo.get_user_roles(manager_id)]
        
        # Only admins can manage roles
        if not any(role in [UserRole.SUPER_ADMIN.value, UserRole.ADMIN.value] for role in manager_roles):
            raise InsufficientPermissionsException("Insufficient permissions to manage roles")
        
        # Only super admins can assign admin roles
        admin_roles = [UserRole.SUPER_ADMIN, UserRole.ADMIN]
        if any(role in admin_roles for role in roles):
            if UserRole.SUPER_ADMIN.value not in manager_roles:
                raise InsufficientPermissionsException("Only super admins can manage admin roles")
    
    def _validate_user_access_permissions(
        self, 
        requesting_user_id: int, 
        target_user_id: int, 
        include_sensitive: bool
    ) -> None:
        """
        Validate user access permissions.
        
        Args:
            requesting_user_id: ID of user making request
            target_user_id: ID of user being accessed
            include_sensitive: Whether sensitive info is requested
            
        Raises:
            InsufficientPermissionsException: If insufficient permissions
        """
        # Users can access their own information
        if requesting_user_id == target_user_id:
            return
        
        # Admin access for other users
        requesting_user_roles = [role.name for role in self.user_repo.get_user_roles(requesting_user_id)]
        
        if not any(role in [UserRole.SUPER_ADMIN.value, UserRole.ADMIN.value] for role in requesting_user_roles):
            raise InsufficientPermissionsException("Insufficient permissions to access user information")
        
        # Sensitive information requires higher permissions
        if include_sensitive:
            if UserRole.SUPER_ADMIN.value not in requesting_user_roles:
                raise InsufficientPermissionsException("Insufficient permissions for sensitive information")
    
    def _validate_user_list_permissions(self, user_id: int, filters: Optional[UserSearchFilter]) -> None:
        """
        Validate user listing permissions.
        
        Args:
            user_id: ID of user requesting list
            filters: Optional filters being applied
            
        Raises:
            InsufficientPermissionsException: If insufficient permissions
        """
        user_roles = [role.name for role in self.user_repo.get_user_roles(user_id)]
        
        # Only admins can list users
        if not any(role in [UserRole.SUPER_ADMIN.value, UserRole.ADMIN.value] for role in user_roles):
            raise InsufficientPermissionsException("Insufficient permissions to list users")