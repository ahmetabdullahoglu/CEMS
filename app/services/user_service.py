"""
Module: user_service
Purpose: User management service providing comprehensive user operations for CEMS
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
    ValidationError, NotFoundError, DuplicateError, 
    PermissionError, DatabaseError, BusinessLogicError
)
from app.schemas.user import (
    UserCreateRequest, UserResponse, UserUpdateRequest, UserUpdateByAdminRequest,
    UserRoleAssignRequest, UserRoleRemoveRequest, UserSearchFilter, UserListRequest,
    UserListResponse, UserStatistics, PaginationInfo, UserUpdateResponse,
    UserRoleResponse
)
from app.schemas.auth import SecurityEvent
from app.utils.logger import get_logger
from app.utils.validators import (
    validate_password_strength, validate_email_format, 
    validate_username_format, validate_phone_number
)
from app.utils.generators import generate_user_code, generate_temporary_password

logger = get_logger(__name__)


class UserService:
    """
    User service providing comprehensive user management functionality.
    Handles user creation, updates, role management, and business logic.
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
            created_by_user_id: ID of user creating this account
            auto_assign_role: Whether to auto-assign default role
            
        Returns:
            UserResponse: Created user information
            
        Raises:
            ValidationError: If validation fails
            DuplicateError: If user already exists
            PermissionError: If creator lacks permission
        """
        try:
            # Validate creator permissions
            if created_by_user_id:
                self._validate_user_creation_permissions(created_by_user_id, user_data.roles)
            
            # Validate input data
            self._validate_user_creation_data(user_data)
            
            # Generate username if needed
            username = user_data.username
            if not username and self.auto_generate_username:
                username = self._generate_username(user_data.first_name, user_data.last_name)
            
            # Hash password
            hashed_password = get_password_hash(user_data.password)
            
            # Prepare user data
            user_create_data = {
                "username": username,
                "email": user_data.email.lower(),
                "hashed_password": hashed_password,
                "first_name": user_data.first_name.strip().title(),
                "last_name": user_data.last_name.strip().title(),
                "phone_number": user_data.phone_number,
                "branch_id": user_data.branch_id,
                "status": UserStatus.PENDING.value if self.require_email_verification else UserStatus.ACTIVE.value,
                "is_verified": not self.require_email_verification,
                "force_password_change": user_data.force_password_change,
                "created_by": created_by_user_id
            }
            
            # Add optional fields
            if hasattr(user_data, 'language_preference') and user_data.language_preference:
                user_create_data["language_preference"] = user_data.language_preference
                
            if hasattr(user_data, 'timezone') and user_data.timezone:
                user_create_data["timezone"] = user_data.timezone
            
            # Create user
            user = self.user_repo.create_user(**user_create_data)
            
            # Assign roles
            if auto_assign_role:
                roles_to_assign = user_data.roles if user_data.roles else [self.default_user_role]
                for role_name in roles_to_assign:
                    try:
                        self.user_repo.assign_role(user.id, role_name)
                    except Exception as e:
                        self.logger.warning(f"Failed to assign role {role_name} to user {user.id}: {str(e)}")
            
            # Commit transaction
            self.user_repo.commit()
            
            # Send welcome email if verification not required
            if not self.require_email_verification:
                self._send_welcome_email(user)
            else:
                self._send_verification_email(user)
            
            # Record activity
            self._record_user_activity(
                user.id, created_by_user_id,
                "user_created",
                {"username": username, "email": user_data.email}
            )
            
            self.logger.info(f"Created user {user.id} ({username}) by user {created_by_user_id}")
            
            return UserResponse.from_orm(user)
            
        except (ValidationError, DuplicateError, PermissionError):
            self.user_repo.rollback()
            raise
        except Exception as e:
            self.user_repo.rollback()
            self.logger.error(f"Error creating user: {str(e)}")
            raise BusinessLogicError(f"Failed to create user: {str(e)}")
    
    def update_user(
        self,
        user_id: int,
        update_data: Union[UserUpdateRequest, UserUpdateByAdminRequest],
        updated_by_user_id: Optional[int] = None,
        is_admin_update: bool = False
    ) -> UserUpdateResponse:
        """
        Update user information with validation.
        
        Args:
            user_id: User ID to update
            update_data: Update data
            updated_by_user_id: ID of user performing update
            is_admin_update: Whether this is an admin update
            
        Returns:
            UserUpdateResponse: Update result
            
        Raises:
            NotFoundError: If user not found
            PermissionError: If insufficient permissions
            ValidationError: If validation fails
        """
        try:
            # Get existing user
            user = self.user_repo.get_by_id_or_raise(user_id)
            
            # Validate permissions
            if updated_by_user_id:
                self._validate_user_update_permissions(
                    updated_by_user_id, user_id, update_data, is_admin_update
                )
            
            # Validate update data
            self._validate_user_update_data(update_data, user)
            
            # Prepare update fields
            update_fields = {}
            updated_field_names = []
            
            # Handle basic fields
            basic_fields = ['first_name', 'last_name', 'phone_number', 'language_preference', 'timezone']
            for field in basic_fields:
                if hasattr(update_data, field) and getattr(update_data, field) is not None:
                    value = getattr(update_data, field)
                    if field in ['first_name', 'last_name'] and value:
                        value = value.strip().title()
                    update_fields[field] = value
                    updated_field_names.append(field)
            
            # Handle admin-only fields
            if is_admin_update and isinstance(update_data, UserUpdateByAdminRequest):
                admin_fields = [
                    'username', 'email', 'status', 'is_active', 
                    'is_superuser', 'is_verified', 'branch_id', 'force_password_change'
                ]
                
                for field in admin_fields:
                    if hasattr(update_data, field) and getattr(update_data, field) is not None:
                        value = getattr(update_data, field)
                        if field in ['username', 'email'] and value:
                            value = value.lower()
                        update_fields[field] = value
                        updated_field_names.append(field)
            
            # Update user
            updated_user = self.user_repo.update_user(user_id, update_fields)
            if not updated_user:
                raise NotFoundError("User not found")
            
            # Commit transaction
            self.user_repo.commit()
            
            # Record activity
            self._record_user_activity(
                user_id, updated_by_user_id,
                "user_updated",
                {
                    "updated_fields": updated_field_names,
                    "is_admin_update": is_admin_update
                }
            )
            
            self.logger.info(f"Updated user {user_id} fields: {updated_field_names}")
            
            return UserUpdateResponse(
                user_id=user_id,
                updated_fields=updated_field_names,
                updated_at=datetime.utcnow()
            )
            
        except (NotFoundError, PermissionError, ValidationError):
            self.user_repo.rollback()
            raise
        except Exception as e:
            self.user_repo.rollback()
            self.logger.error(f"Error updating user {user_id}: {str(e)}")
            raise BusinessLogicError(f"Failed to update user: {str(e)}")
    
    def delete_user(
        self,
        user_id: int,
        deleted_by_user_id: Optional[int] = None,
        soft_delete: bool = True
    ) -> Dict[str, Any]:
        """
        Delete user account.
        
        Args:
            user_id: User ID to delete
            deleted_by_user_id: ID of user performing deletion
            soft_delete: Whether to use soft delete
            
        Returns:
            Dict[str, Any]: Deletion result
            
        Raises:
            NotFoundError: If user not found
            PermissionError: If insufficient permissions
        """
        try:
            # Get user
            user = self.user_repo.get_by_id_or_raise(user_id)
            
            # Validate permissions
            if deleted_by_user_id:
                self._validate_user_deletion_permissions(deleted_by_user_id, user_id)
            
            # Cannot delete yourself
            if deleted_by_user_id == user_id:
                raise PermissionError("Cannot delete your own account")
            
            # Cannot delete superuser unless you're also a superuser
            if user.is_superuser and deleted_by_user_id:
                deleter = self.user_repo.get_by_id(deleted_by_user_id)
                if not deleter or not deleter.is_superuser:
                    raise PermissionError("Cannot delete superuser account")
            
            # Invalidate all user sessions
            security_manager.session_manager.invalidate_user_sessions(user_id)
            
            # Delete user
            success = self.user_repo.delete(user_id, soft_delete=soft_delete)
            
            if not success:
                raise NotFoundError("User not found")
            
            # Commit transaction
            self.user_repo.commit()
            
            # Record activity
            self._record_user_activity(
                user_id, deleted_by_user_id,
                "user_deleted",
                {
                    "username": user.username,
                    "soft_delete": soft_delete
                }
            )
            
            delete_type = "soft deleted" if soft_delete else "permanently deleted"
            self.logger.warning(f"User {user_id} ({user.username}) {delete_type} by user {deleted_by_user_id}")
            
            return {
                "message": f"User {delete_type} successfully",
                "user_id": user_id,
                "username": user.username,
                "deleted_at": datetime.utcnow().isoformat(),
                "soft_delete": soft_delete
            }
            
        except (NotFoundError, PermissionError):
            self.user_repo.rollback()
            raise
        except Exception as e:
            self.user_repo.rollback()
            self.logger.error(f"Error deleting user {user_id}: {str(e)}")
            raise BusinessLogicError(f"Failed to delete user: {str(e)}")
    
    def restore_user(
        self,
        user_id: int,
        restored_by_user_id: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Restore soft-deleted user.
        
        Args:
            user_id: User ID to restore
            restored_by_user_id: ID of user performing restoration
            
        Returns:
            Dict[str, Any]: Restoration result
        """
        try:
            # Validate permissions
            if restored_by_user_id:
                self._validate_admin_permissions(restored_by_user_id)
            
            # Restore user
            success = self.user_repo.restore(user_id)
            
            if not success:
                raise NotFoundError("User not found or not deleted")
            
            # Commit transaction
            self.user_repo.commit()
            
            # Record activity
            self._record_user_activity(
                user_id, restored_by_user_id,
                "user_restored",
                {}
            )
            
            self.logger.info(f"User {user_id} restored by user {restored_by_user_id}")
            
            return {
                "message": "User restored successfully",
                "user_id": user_id,
                "restored_at": datetime.utcnow().isoformat()
            }
            
        except (NotFoundError, PermissionError):
            self.user_repo.rollback()
            raise
        except Exception as e:
            self.user_repo.rollback()
            self.logger.error(f"Error restoring user {user_id}: {str(e)}")
            raise BusinessLogicError(f"Failed to restore user: {str(e)}")
    
    # ==================== USER ROLE MANAGEMENT ====================
    
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
            user = self.user_repo.get_by_id_or_raise(user_id)
            
            # Get current roles
            current_roles = self.user_repo.get_user_roles(user_id)
            
            # Assign new roles
            assigned_roles = []
            for role_name in role_data.role_names:
                if role_name.value not in current_roles:
                    try:
                        self.user_repo.assign_role(
                            user_id, 
                            role_name.value, 
                            role_data.expires_at
                        )
                        assigned_roles.append(role_name.value)
                    except DuplicateError:
                        # Role already assigned, skip
                        continue
            
            # Get updated roles
            updated_roles = self.user_repo.get_user_roles(user_id)
            
            # Commit transaction
            self.user_repo.commit()
            
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
            
        except (NotFoundError, PermissionError, DuplicateError):
            self.user_repo.rollback()
            raise
        except Exception as e:
            self.user_repo.rollback()
            self.logger.error(f"Error assigning roles to user {user_id}: {str(e)}")
            raise BusinessLogicError(f"Failed to assign roles: {str(e)}")
    
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
            user = self.user_repo.get_by_id_or_raise(user_id)
            
            # Get current roles
            current_roles = self.user_repo.get_user_roles(user_id)
            
            # Remove roles
            removed_roles = []
            for role_name in role_data.role_names:
                if role_name.value in current_roles:
                    success = self.user_repo.remove_role(user_id, role_name.value)
                    if success:
                        removed_roles.append(role_name.value)
            
            # Get updated roles
            updated_roles = self.user_repo.get_user_roles(user_id)
            
            # Ensure user always has at least one role
            if not updated_roles:
                self.user_repo.assign_role(user_id, self.default_user_role)
                updated_roles = [self.default_user_role]
                self.logger.info(f"Auto-assigned default role {self.default_user_role} to user {user_id}")
            
            # Commit transaction
            self.user_repo.commit()
            
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
            
        except (NotFoundError, PermissionError):
            self.user_repo.rollback()
            raise
        except Exception as e:
            self.user_repo.rollback()
            self.logger.error(f"Error removing roles from user {user_id}: {str(e)}")
            raise BusinessLogicError(f"Failed to remove roles: {str(e)}")
    
    # ==================== USER SEARCH AND LISTING ====================
    
    def search_users(
        self,
        list_request: UserListRequest,
        requesting_user_id: Optional[int] = None
    ) -> UserListResponse:
        """
        Search and list users with advanced filtering.
        
        Args:
            list_request: Search and pagination parameters
            requesting_user_id: ID of user making request
            
        Returns:
            UserListResponse: Search results with pagination
        """
        try:
            # Validate permissions
            if requesting_user_id:
                self._validate_user_list_permissions(requesting_user_id, list_request.filters)
            
            # Validate request parameters
            self._validate_list_request(list_request)
            
            # Calculate pagination
            skip = (list_request.page - 1) * list_request.page_size
            
            # Search users
            users, total_count = self.user_repo.search_users(
                filters=list_request.filters or UserSearchFilter(),
                skip=skip,
                limit=list_request.page_size,
                sort_by=list_request.sort_by,
                sort_desc=list_request.sort_order == "desc"
            )
            
            # Convert to response objects
            user_items = []
            for user in users:
                user_roles = self.user_repo.get_user_roles(user.id)
                
                # Create list item
                user_item = {
                    "id": user.id,
                    "username": user.username,
                    "email": user.email,
                    "full_name": f"{user.first_name} {user.last_name}",
                    "status": user.status,
                    "roles": user_roles,
                    "branch_id": user.branch_id,
                    "is_active": user.is_active,
                    "is_verified": user.is_verified,
                    "is_superuser": user.is_superuser,
                    "two_factor_enabled": user.two_factor_enabled,
                    "created_at": user.created_at,
                    "last_login_at": user.last_login_at,
                    "is_locked": user.locked_until > datetime.utcnow() if user.locked_until else False
                }
                user_items.append(user_item)
            
            # Calculate pagination info
            total_pages = (total_count + list_request.page_size - 1) // list_request.page_size
            
            pagination = PaginationInfo(
                page=list_request.page,
                page_size=list_request.page_size,
                total_pages=total_pages,
                has_next=list_request.page < total_pages,
                has_previous=list_request.page > 1,
                next_page=list_request.page + 1 if list_request.page < total_pages else None,
                previous_page=list_request.page - 1 if list_request.page > 1 else None
            )
            
            # Record search activity
            if requesting_user_id:
                self._record_user_activity(
                    requesting_user_id, None,
                    "users_searched",
                    {
                        "filters_applied": bool(list_request.filters),
                        "results_count": len(user_items),
                        "total_count": total_count
                    }
                )
            
            return UserListResponse(
                users=user_items,
                pagination=pagination,
                total_count=total_count,
                filters_applied=list_request.filters.dict() if list_request.filters else {}
            )
            
        except (PermissionError, ValidationError):
            raise
        except Exception as e:
            self.logger.error(f"Error searching users: {str(e)}")
            raise BusinessLogicError(f"Failed to search users: {str(e)}")
    
    def get_user_by_id(
        self,
        user_id: int,
        requesting_user_id: Optional[int] = None,
        include_roles: bool = True
    ) -> UserResponse:
        """
        Get user by ID with role information.
        
        Args:
            user_id: User ID to retrieve
            requesting_user_id: ID of user making request
            include_roles: Whether to include role information
            
        Returns:
            UserResponse: User information
        """
        try:
            # Validate permissions
            if requesting_user_id:
                self._validate_user_view_permissions(requesting_user_id, user_id)
            
            # Get user
            if include_roles:
                user = self.user_repo.get_user_with_roles(user_id)
            else:
                user = self.user_repo.get_by_id(user_id)
            
            if not user:
                raise NotFoundError(f"User with ID {user_id} not found")
            
            # Convert to response
            user_response = UserResponse.from_orm(user)
            
            # Add roles if requested
            if include_roles:
                user_response.roles = self.user_repo.get_user_roles(user_id)
            
            return user_response
            
        except (NotFoundError, PermissionError):
            raise
        except Exception as e:
            self.logger.error(f"Error getting user {user_id}: {str(e)}")
            raise BusinessLogicError(f"Failed to get user: {str(e)}")
    
    # ==================== USER STATISTICS AND ANALYTICS ====================
    
    def get_user_statistics(
        self,
        requesting_user_id: Optional[int] = None
    ) -> UserStatistics:
        """
        Get comprehensive user statistics.
        
        Args:
            requesting_user_id: ID of user requesting statistics
            
        Returns:
            UserStatistics: User statistics
        """
        try:
            # Validate permissions
            if requesting_user_id:
                self._validate_admin_permissions(requesting_user_id)
            
            # Get statistics from repository
            stats = self.user_repo.get_user_statistics()
            
            # Convert to schema
            user_stats = UserStatistics(
                total_users=stats['total_users'],
                active_users=stats['active_users'],
                inactive_users=stats['inactive_users'],
                verified_users=stats['verified_users'],
                superusers=stats['superusers'],
                locked_users=stats['locked_users'],
                users_with_2fa=stats['users_with_2fa'],
                recent_registrations=stats['recent_registrations'],
                recent_logins=stats['recent_logins'],
                **stats.get('status_breakdown', {})
            )
            
            self.logger.info(f"User statistics retrieved by user {requesting_user_id}")
            
            return user_stats
            
        except PermissionError:
            raise
        except Exception as e:
            self.logger.error(f"Error getting user statistics: {str(e)}")
            raise BusinessLogicError(f"Failed to get user statistics: {str(e)}")
    
    def get_users_by_branch(
        self,
        branch_id: int,
        requesting_user_id: Optional[int] = None
    ) -> List[UserResponse]:
        """
        Get all users in a specific branch.
        
        Args:
            branch_id: Branch ID
            requesting_user_id: ID of user making request
            
        Returns:
            List[UserResponse]: Users in the branch
        """
        try:
            # Validate permissions
            if requesting_user_id:
                self._validate_branch_access_permissions(requesting_user_id, branch_id)
            
            # Get users
            users = self.user_repo.get_users_by_branch(branch_id)
            
            # Convert to response objects
            user_responses = []
            for user in users:
                user_response = UserResponse.from_orm(user)
                user_response.roles = self.user_repo.get_user_roles(user.id)
                user_responses.append(user_response)
            
            return user_responses
            
        except PermissionError:
            raise
        except Exception as e:
            self.logger.error(f"Error getting users by branch {branch_id}: {str(e)}")
            raise BusinessLogicError(f"Failed to get users by branch: {str(e)}")
    
    def get_users_by_role(
        self,
        role_name: str,
        requesting_user_id: Optional[int] = None
    ) -> List[UserResponse]:
        """
        Get all users with a specific role.
        
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
                user_response = UserResponse.from_orm(user)
                user_response.roles = self.user_repo.get_user_roles(user.id)
                user_responses.append(user_response)
            
            return user_responses
            
        except PermissionError:
            raise
        except Exception as e:
            self.logger.error(f"Error getting users by role {role_name}: {str(e)}")
            raise BusinessLogicError(f"Failed to get users by role: {str(e)}")
    
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
            Dict[str, Any]: Activation result
        """
        try:
            # Validate permissions
            if activated_by_user_id:
                self._validate_admin_permissions(activated_by_user_id)
            
            # Update user status
            updated_user = self.user_repo.update_user(user_id, {
                "is_active": True,
                "status": UserStatus.ACTIVE.value,
                "locked_until": None,
                "lock_reason": None
            })
            
            if not updated_user:
                raise NotFoundError("User not found")
            
            # Commit transaction
            self.user_repo.commit()
            
            # Record activity
            self._record_user_activity(
                user_id, activated_by_user_id,
                "user_activated",
                {}
            )
            
            self.logger.info(f"User {user_id} activated by user {activated_by_user_id}")
            
            return {
                "message": "User activated successfully",
                "user_id": user_id,
                "activated_at": datetime.utcnow().isoformat()
            }
            
        except (NotFoundError, PermissionError):
            self.user_repo.rollback()
            raise
        except Exception as e:
            self.user_repo.rollback()
            self.logger.error(f"Error activating user {user_id}: {str(e)}")
            raise BusinessLogicError(f"Failed to activate user: {str(e)}")
    
    def deactivate_user(
        self,
        user_id: int,
        deactivated_by_user_id: Optional[int] = None,
        reason: str = None
    ) -> Dict[str, Any]:
        """
        Deactivate user account.
        
        Args:
            user_id: User ID to deactivate
            deactivated_by_user_id: ID of user performing deactivation
            reason: Deactivation reason
            
        Returns:
            Dict[str, Any]: Deactivation result
        """
        try:
            # Validate permissions
            if deactivated_by_user_id:
                self._validate_admin_permissions(deactivated_by_user_id)
            
            # Cannot deactivate yourself
            if deactivated_by_user_id == user_id:
                raise PermissionError("Cannot deactivate your own account")
            
            # Update user status
            updated_user = self.user_repo.update_user(user_id, {
                "is_active": False,
                "status": UserStatus.SUSPENDED.value
            })
            
            if not updated_user:
                raise NotFoundError("User not found")
            
            # Invalidate all user sessions
            security_manager.session_manager.invalidate_user_sessions(user_id)
            
            # Commit transaction
            self.user_repo.commit()
            
            # Record activity
            self._record_user_activity(
                user_id, deactivated_by_user_id,
                "user_deactivated",
                {"reason": reason}
            )
            
            self.logger.warning(f"User {user_id} deactivated by user {deactivated_by_user_id}. Reason: {reason}")
            
            return {
                "message": "User deactivated successfully",
                "user_id": user_id,
                "reason": reason,
                "deactivated_at": datetime.utcnow().isoformat()
            }
            
        except (NotFoundError, PermissionError):
            self.user_repo.rollback()
            raise
        except Exception as e:
            self.user_repo.rollback()
            self.logger.error(f"Error deactivating user {user_id}: {str(e)}")
            raise BusinessLogicError(f"Failed to deactivate user: {str(e)}")
    
    # ==================== VALIDATION METHODS ====================
    
    def _validate_user_creation_data(self, user_data: UserCreateRequest) -> None:
        """Validate user creation data."""
        # Validate email format
        if not validate_email_format(user_data.email):
            raise ValidationError("Invalid email format")
        
        # Validate username format
        if user_data.username and not validate_username_format(user_data.username):
            raise ValidationError("Invalid username format")
        
        # Validate password strength
        password_validation = validate_password_strength(user_data.password)
        if not password_validation["is_valid"]:
            raise ValidationError(f"Password requirements not met: {password_validation['message']}")
        
        # Validate phone number
        if user_data.phone_number and not validate_phone_number(user_data.phone_number):
            raise ValidationError("Invalid phone number format")
        
        # Validate roles
        if user_data.roles:
            for role in user_data.roles:
                if role not in [r.value for r in UserRole]:
                    raise ValidationError(f"Invalid role: {role}")
    
    def _validate_user_update_data(self, update_data, existing_user) -> None:
        """Validate user update data."""
        # Validate email format if provided
        if hasattr(update_data, 'email') and update_data.email:
            if not validate_email_format(update_data.email):
                raise ValidationError("Invalid email format")
        
        # Validate username format if provided
        if hasattr(update_data, 'username') and update_data.username:
            if not validate_username_format(update_data.username):
                raise ValidationError("Invalid username format")
        
        # Validate phone number if provided
        if hasattr(update_data, 'phone_number') and update_data.phone_number:
            if not validate_phone_number(update_data.phone_number):
                raise ValidationError("Invalid phone number format")
    
    def _validate_user_creation_permissions(self, creator_id: int, roles: List[str]) -> None:
        """Validate user creation permissions."""
        creator = self.user_repo.get_by_id_or_raise(creator_id)
        creator_roles = self.user_repo.get_user_roles(creator_id)
        
        # Only admins can create users
        if not any(role in [UserRole.SUPER_ADMIN.value, UserRole.ADMIN.value] for role in creator_roles):
            raise PermissionError("Insufficient permissions to create users")
        
        # Only super admins can create admin users
        if roles and UserRole.ADMIN.value in roles:
            if UserRole.SUPER_ADMIN.value not in creator_roles:
                raise PermissionError("Only super admins can create admin users")
    
    def _validate_user_update_permissions(
        self, 
        updater_id: int, 
        user_id: int, 
        update_data, 
        is_admin_update: bool
    ) -> None:
        """Validate user update permissions."""
        updater = self.user_repo.get_by_id_or_raise(updater_id)
        updater_roles = self.user_repo.get_user_roles(updater_id)
        
        # Users can update their own basic profile
        if updater_id == user_id and not is_admin_update:
            return
        
        # Admin updates require admin permissions
        if is_admin_update:
            if not any(role in [UserRole.SUPER_ADMIN.value, UserRole.ADMIN.value] for role in updater_roles):
                raise PermissionError("Insufficient permissions for admin updates")
    
    def _validate_user_deletion_permissions(self, deleter_id: int, user_id: int) -> None:
        """Validate user deletion permissions."""
        deleter_roles = self.user_repo.get_user_roles(deleter_id)
        
        if not any(role in [UserRole.SUPER_ADMIN.value, UserRole.ADMIN.value] for role in deleter_roles):
            raise PermissionError("Insufficient permissions to delete users")
    
    def _validate_admin_permissions(self, user_id: int) -> None:
        """Validate admin permissions."""
        user_roles = self.user_repo.get_user_roles(user_id)
        
        if not any(role in [UserRole.SUPER_ADMIN.value, UserRole.ADMIN.value] for role in user_roles):
            raise PermissionError("Admin permissions required")
    
    def _validate_role_management_permissions(self, manager_id: int, roles: List[UserRole]) -> None:
        """Validate role management permissions."""
        manager_roles = self.user_repo.get_user_roles(manager_id)
        
        # Only admins can manage roles
        if not any(role in [UserRole.SUPER_ADMIN.value, UserRole.ADMIN.value] for role in manager_roles):
            raise PermissionError("Insufficient permissions to manage roles")
        
        # Only super admins can assign admin roles
        admin_roles = [UserRole.SUPER_ADMIN.value, UserRole.ADMIN.value]
        if any(role.value in admin_roles for role in roles):
            if UserRole.SUPER_ADMIN.value not in manager_roles:
                raise PermissionError("Only super admins can manage admin roles")
    
    def _validate_user_list_permissions(self, user_id: int, filters: Optional[UserSearchFilter]) -> None:
        """Validate user listing permissions."""
        user_roles = self.user_repo.get_user_roles(user_id)
        
        # Branch managers can view users in their branch
        if UserRole.BRANCH_MANAGER.value in user_roles:
            user = self.user_repo.get_by_id(user_id)
            if user and filters and filters.branch_id and filters.branch_id != user.branch_id:
                raise PermissionError("Can only view users in your branch")
        
        # Non-admin users have limited access
        elif not any(role in [UserRole.SUPER_ADMIN.value, UserRole.ADMIN.value] for role in user_roles):
            raise PermissionError("Insufficient permissions to list users")
    
    def _validate_user_view_permissions(self, viewer_id: int, user_id: int) -> None:
        """Validate user view permissions."""
        # Users can view their own profile
        if viewer_id == user_id:
            return
        
        viewer_roles = self.user_repo.get_user_roles(viewer_id)
        
        # Admins can view all users
        if any(role in [UserRole.SUPER_ADMIN.value, UserRole.ADMIN.value] for role in viewer_roles):
            return
        
        # Branch managers can view users in their branch
        if UserRole.BRANCH_MANAGER.value in viewer_roles:
            viewer = self.user_repo.get_by_id(viewer_id)
            target_user = self.user_repo.get_by_id(user_id)
            if viewer and target_user and viewer.branch_id == target_user.branch_id:
                return
        
        raise PermissionError("Insufficient permissions to view user")
    
    def _validate_branch_access_permissions(self, user_id: int, branch_id: int) -> None:
        """Validate branch access permissions."""
        user_roles = self.user_repo.get_user_roles(user_id)
        
        # Admins can access all branches
        if any(role in [UserRole.SUPER_ADMIN.value, UserRole.ADMIN.value] for role in user_roles):
            return
        
        # Users can only access their own branch
        user = self.user_repo.get_by_id(user_id)
        if user and user.branch_id == branch_id:
            return
        
        raise PermissionError("Insufficient permissions to access branch")
    
    def _validate_list_request(self, list_request: UserListRequest) -> None:
        """Validate list request parameters."""
        if list_request.page < 1:
            raise ValidationError("Page number must be at least 1")
        
        if list_request.page_size < 1 or list_request.page_size > 100:
            raise ValidationError("Page size must be between 1 and 100")
        
        valid_sort_fields = ['id', 'username', 'email', 'first_name', 'last_name', 'created_at', 'last_login_at', 'status']
        if list_request.sort_by not in valid_sort_fields:
            raise ValidationError(f"Invalid sort field: {list_request.sort_by}")
    
    # ==================== UTILITY METHODS ====================
    
    def _generate_username(self, first_name: str, last_name: str) -> str:
        """Generate unique username from name."""
        base_username = f"{first_name.lower()}.{last_name.lower()}"
        base_username = ''.join(c for c in base_username if c.isalnum() or c == '.')
        
        # Ensure uniqueness
        username = base_username
        counter = 1
        while self.user_repo.get_by_username(username):
            username = f"{base_username}{counter}"
            counter += 1
        
        return username
    
    def _send_welcome_email(self, user) -> None:
        """Send welcome email to user."""
        # TODO: Implement email sending
        self.logger.info(f"Welcome email would be sent to {user.email}")
    
    def _send_verification_email(self, user) -> None:
        """Send email verification to user."""
        # TODO: Implement email verification
        self.logger.info(f"Verification email would be sent to {user.email}")
    
    def _record_user_activity(
        self,
        user_id: int,
        actor_id: Optional[int],
        activity_type: str,
        details: Dict[str, Any]
    ) -> None:
        """Record user activity for auditing."""
        try:
            # In production, store in audit log table
            activity_data = {
                "user_id": user_id,
                "actor_id": actor_id,
                "activity_type": activity_type,
                "details": details,
                "timestamp": datetime.utcnow(),
                "ip_address": getattr(details, 'ip_address', None)
            }
            
            self.logger.info(f"User activity: {activity_type} for user {user_id} by {actor_id}")
            
        except Exception as e:
            self.logger.error(f"Failed to record user activity: {str(e)}")