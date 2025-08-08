"""
Module: user_repository
Purpose: User repository for CEMS user management and authentication data access
Author: CEMS Development Team
Date: 2024
"""

from typing import List, Optional, Dict, Any, Tuple, Union
from datetime import datetime, timedelta
from sqlalchemy.orm import Session, joinedload, selectinload
from sqlalchemy import and_, or_, func, text, desc, asc
from sqlalchemy.exc import SQLAlchemyError, IntegrityError

from app.repositories.base import BaseRepository
from app.db.models.user import User, Role, UserRole
from app.core.constants import UserRole as UserRoleEnum, UserStatus
from app.core.exceptions import (
    DatabaseError, NotFoundError, ValidationError, 
    DuplicateError, AuthenticationError
)
from app.schemas.user import UserSearchFilter, UserListRequest
from app.utils.logger import get_logger

logger = get_logger(__name__)


class UserRepository(BaseRepository[User]):
    """
    User repository providing specialized data access operations for users.
    Extends BaseRepository with user-specific functionality.
    """
    
    def __init__(self, db: Session):
        """
        Initialize user repository.
        
        Args:
            db: Database session
        """
        super().__init__(User, db)
        self.role_model = Role
        self.user_role_model = UserRole
    
    # ==================== USER AUTHENTICATION METHODS ====================
    
    def get_by_username(self, username: str, include_deleted: bool = False) -> Optional[User]:
        """
        Get user by username.
        
        Args:
            username: Username to search for
            include_deleted: Whether to include soft-deleted users
            
        Returns:
            User or None: Found user or None
        """
        try:
            query = self.db.query(User).filter(User.username == username.lower())
            
            if not include_deleted:
                query = query.filter(User.deleted_at.is_(None))
            
            return query.first()
            
        except SQLAlchemyError as e:
            self.logger.error(f"Database error getting user by username {username}: {str(e)}")
            raise DatabaseError(f"Failed to get user by username: {str(e)}")
    
    def get_by_email(self, email: str, include_deleted: bool = False) -> Optional[User]:
        """
        Get user by email address.
        
        Args:
            email: Email address to search for
            include_deleted: Whether to include soft-deleted users
            
        Returns:
            User or None: Found user or None
        """
        try:
            query = self.db.query(User).filter(User.email == email.lower())
            
            if not include_deleted:
                query = query.filter(User.deleted_at.is_(None))
            
            return query.first()
            
        except SQLAlchemyError as e:
            self.logger.error(f"Database error getting user by email {email}: {str(e)}")
            raise DatabaseError(f"Failed to get user by email: {str(e)}")
    
    def get_by_username_or_email(
        self, 
        identifier: str, 
        include_deleted: bool = False
    ) -> Optional[User]:
        """
        Get user by username or email.
        
        Args:
            identifier: Username or email to search for
            include_deleted: Whether to include soft-deleted users
            
        Returns:
            User or None: Found user or None
        """
        try:
            query = self.db.query(User).filter(
                or_(
                    User.username == identifier.lower(),
                    User.email == identifier.lower()
                )
            )
            
            if not include_deleted:
                query = query.filter(User.deleted_at.is_(None))
            
            return query.first()
            
        except SQLAlchemyError as e:
            self.logger.error(f"Database error getting user by identifier {identifier}: {str(e)}")
            raise DatabaseError(f"Failed to get user by identifier: {str(e)}")
    
    def authenticate_user(self, identifier: str, password: str) -> Optional[User]:
        """
        Authenticate user by username/email and password.
        Note: This method only returns the user; password verification 
        should be done in the service layer.
        
        Args:
            identifier: Username or email
            password: Plain password (will be verified in service layer)
            
        Returns:
            User or None: User if found and active
        """
        user = self.get_by_username_or_email(identifier)
        
        if not user:
            return None
        
        # Check if user is active and not locked
        if not user.is_active or user.status != UserStatus.ACTIVE.value:
            return None
        
        return user
    
    # ==================== USER CREATION AND MANAGEMENT ====================
    
    def create_user(
        self,
        username: str,
        email: str,
        hashed_password: str,
        first_name: str,
        last_name: str,
        **kwargs
    ) -> User:
        """
        Create a new user with validation.
        
        Args:
            username: Unique username
            email: Unique email address
            hashed_password: Pre-hashed password
            first_name: User's first name
            last_name: User's last name
            **kwargs: Additional user fields
            
        Returns:
            User: Created user
            
        Raises:
            DuplicateError: If username or email already exists
            ValidationError: If validation fails
        """
        try:
            # Check for existing username
            if self.get_by_username(username):
                raise DuplicateError(f"Username '{username}' already exists")
            
            # Check for existing email
            if self.get_by_email(email):
                raise DuplicateError(f"Email '{email}' already exists")
            
            # Create user
            user_data = {
                'username': username.lower(),
                'email': email.lower(),
                'hashed_password': hashed_password,
                'first_name': first_name.strip().title(),
                'last_name': last_name.strip().title(),
                **kwargs
            }
            
            user = self.create(**user_data)
            
            self.logger.info(f"Created user {username} with ID {user.id}")
            return user
            
        except (DuplicateError, ValidationError):
            raise
        except Exception as e:
            self.logger.error(f"Error creating user {username}: {str(e)}")
            raise DatabaseError(f"Failed to create user: {str(e)}")
    
    def update_user(
        self, 
        user_id: int, 
        updates: Dict[str, Any],
        exclude_fields: List[str] = None
    ) -> Optional[User]:
        """
        Update user with field validation.
        
        Args:
            user_id: User ID to update
            updates: Fields to update
            exclude_fields: Fields to exclude from update
            
        Returns:
            User or None: Updated user or None if not found
            
        Raises:
            DuplicateError: If username or email conflicts
            ValidationError: If validation fails
        """
        try:
            exclude_fields = exclude_fields or ['id', 'created_at', 'hashed_password']
            
            # Remove excluded fields
            clean_updates = {k: v for k, v in updates.items() if k not in exclude_fields}
            
            # Validate unique fields if being updated
            if 'username' in clean_updates:
                existing_user = self.get_by_username(clean_updates['username'])
                if existing_user and existing_user.id != user_id:
                    raise DuplicateError(f"Username '{clean_updates['username']}' already exists")
                clean_updates['username'] = clean_updates['username'].lower()
            
            if 'email' in clean_updates:
                existing_user = self.get_by_email(clean_updates['email'])
                if existing_user and existing_user.id != user_id:
                    raise DuplicateError(f"Email '{clean_updates['email']}' already exists")
                clean_updates['email'] = clean_updates['email'].lower()
            
            # Format names
            if 'first_name' in clean_updates and clean_updates['first_name']:
                clean_updates['first_name'] = clean_updates['first_name'].strip().title()
            
            if 'last_name' in clean_updates and clean_updates['last_name']:
                clean_updates['last_name'] = clean_updates['last_name'].strip().title()
            
            return self.update(user_id, **clean_updates)
            
        except (DuplicateError, ValidationError):
            raise
        except Exception as e:
            self.logger.error(f"Error updating user {user_id}: {str(e)}")
            raise DatabaseError(f"Failed to update user: {str(e)}")
    
    # ==================== USER SECURITY METHODS ====================
    
    def update_password(self, user_id: int, new_hashed_password: str) -> bool:
        """
        Update user password.
        
        Args:
            user_id: User ID
            new_hashed_password: New hashed password
            
        Returns:
            bool: True if password updated successfully
        """
        try:
            user = self.get_by_id(user_id)
            if not user:
                return False
            
            user.hashed_password = new_hashed_password
            user.password_changed_at = datetime.utcnow()
            user.force_password_change = False
            
            # Clear failed login attempts
            user.failed_login_attempts = 0
            user.locked_until = None
            
            self.db.flush()
            self.logger.info(f"Updated password for user {user_id}")
            return True
            
        except SQLAlchemyError as e:
            self.db.rollback()
            self.logger.error(f"Database error updating password for user {user_id}: {str(e)}")
            raise DatabaseError(f"Failed to update password: {str(e)}")
    
    def lock_user(self, user_id: int, lock_duration_minutes: int = 30) -> bool:
        """
        Lock user account.
        
        Args:
            user_id: User ID to lock
            lock_duration_minutes: Lock duration in minutes
            
        Returns:
            bool: True if user locked successfully
        """
        try:
            user = self.get_by_id(user_id)
            if not user:
                return False
            
            user.locked_until = datetime.utcnow() + timedelta(minutes=lock_duration_minutes)
            user.lock_reason = "Account locked due to security policy"
            
            self.db.flush()
            self.logger.warning(f"Locked user {user_id} until {user.locked_until}")
            return True
            
        except SQLAlchemyError as e:
            self.db.rollback()
            self.logger.error(f"Database error locking user {user_id}: {str(e)}")
            raise DatabaseError(f"Failed to lock user: {str(e)}")
    
    def unlock_user(self, user_id: int) -> bool:
        """
        Unlock user account.
        
        Args:
            user_id: User ID to unlock
            
        Returns:
            bool: True if user unlocked successfully
        """
        try:
            user = self.get_by_id(user_id)
            if not user:
                return False
            
            user.locked_until = None
            user.lock_reason = None
            user.failed_login_attempts = 0
            
            self.db.flush()
            self.logger.info(f"Unlocked user {user_id}")
            return True
            
        except SQLAlchemyError as e:
            self.db.rollback()
            self.logger.error(f"Database error unlocking user {user_id}: {str(e)}")
            raise DatabaseError(f"Failed to unlock user: {str(e)}")
    
    def increment_failed_login(self, user_id: int) -> int:
        """
        Increment failed login attempts.
        
        Args:
            user_id: User ID
            
        Returns:
            int: Current failed login count
        """
        try:
            user = self.get_by_id(user_id)
            if not user:
                return 0
            
            user.failed_login_attempts = (user.failed_login_attempts or 0) + 1
            user.last_failed_login_at = datetime.utcnow()
            
            self.db.flush()
            self.logger.warning(f"Failed login attempt {user.failed_login_attempts} for user {user_id}")
            return user.failed_login_attempts
            
        except SQLAlchemyError as e:
            self.db.rollback()
            self.logger.error(f"Database error incrementing failed login for user {user_id}: {str(e)}")
            raise DatabaseError(f"Failed to update failed login count: {str(e)}")
    
    def record_successful_login(self, user_id: int, ip_address: str = None) -> bool:
        """
        Record successful login.
        
        Args:
            user_id: User ID
            ip_address: Login IP address
            
        Returns:
            bool: True if login recorded successfully
        """
        try:
            user = self.get_by_id(user_id)
            if not user:
                return False
            
            user.last_login_at = datetime.utcnow()
            user.last_login_ip = ip_address
            user.failed_login_attempts = 0
            user.locked_until = None
            
            self.db.flush()
            self.logger.info(f"Recorded successful login for user {user_id} from {ip_address}")
            return True
            
        except SQLAlchemyError as e:
            self.db.rollback()
            self.logger.error(f"Database error recording login for user {user_id}: {str(e)}")
            raise DatabaseError(f"Failed to record login: {str(e)}")
    
    # ==================== USER ROLE MANAGEMENT ====================
    
    def get_user_with_roles(self, user_id: int) -> Optional[User]:
        """
        Get user with loaded roles.
        
        Args:
            user_id: User ID
            
        Returns:
            User or None: User with roles loaded
        """
        try:
            return self.db.query(User)\
                .options(
                    selectinload(User.user_roles).selectinload(UserRole.role)
                )\
                .filter(User.id == user_id)\
                .filter(User.deleted_at.is_(None))\
                .first()
                
        except SQLAlchemyError as e:
            self.logger.error(f"Database error getting user with roles {user_id}: {str(e)}")
            raise DatabaseError(f"Failed to get user with roles: {str(e)}")
    
    def assign_role(self, user_id: int, role_name: str, expires_at: datetime = None) -> bool:
        """
        Assign role to user.
        
        Args:
            user_id: User ID
            role_name: Role name to assign
            expires_at: Optional expiration datetime
            
        Returns:
            bool: True if role assigned successfully
            
        Raises:
            NotFoundError: If user or role not found
            DuplicateError: If role already assigned
        """
        try:
            # Get user
            user = self.get_by_id_or_raise(user_id)
            
            # Get role
            role = self.db.query(Role)\
                .filter(Role.name == role_name.lower())\
                .filter(Role.deleted_at.is_(None))\
                .first()
            
            if not role:
                raise NotFoundError(f"Role '{role_name}' not found")
            
            # Check if already assigned
            existing = self.db.query(UserRole)\
                .filter(UserRole.user_id == user_id)\
                .filter(UserRole.role_id == role.id)\
                .filter(UserRole.deleted_at.is_(None))\
                .first()
            
            if existing:
                raise DuplicateError(f"Role '{role_name}' already assigned to user")
            
            # Create assignment
            user_role = UserRole(
                user_id=user_id,
                role_id=role.id,
                assigned_at=datetime.utcnow(),
                expires_at=expires_at
            )
            
            self.db.add(user_role)
            self.db.flush()
            
            self.logger.info(f"Assigned role '{role_name}' to user {user_id}")
            return True
            
        except (NotFoundError, DuplicateError):
            raise
        except SQLAlchemyError as e:
            self.db.rollback()
            self.logger.error(f"Database error assigning role to user {user_id}: {str(e)}")
            raise DatabaseError(f"Failed to assign role: {str(e)}")
    
    def remove_role(self, user_id: int, role_name: str) -> bool:
        """
        Remove role from user.
        
        Args:
            user_id: User ID
            role_name: Role name to remove
            
        Returns:
            bool: True if role removed successfully
        """
        try:
            # Get role
            role = self.db.query(Role)\
                .filter(Role.name == role_name.lower())\
                .filter(Role.deleted_at.is_(None))\
                .first()
            
            if not role:
                return False
            
            # Find assignment
            user_role = self.db.query(UserRole)\
                .filter(UserRole.user_id == user_id)\
                .filter(UserRole.role_id == role.id)\
                .filter(UserRole.deleted_at.is_(None))\
                .first()
            
            if not user_role:
                return False
            
            # Soft delete assignment
            user_role.deleted_at = datetime.utcnow()
            self.db.flush()
            
            self.logger.info(f"Removed role '{role_name}' from user {user_id}")
            return True
            
        except SQLAlchemyError as e:
            self.db.rollback()
            self.logger.error(f"Database error removing role from user {user_id}: {str(e)}")
            raise DatabaseError(f"Failed to remove role: {str(e)}")
    
    def get_user_roles(self, user_id: int) -> List[str]:
        """
        Get list of role names for user.
        
        Args:
            user_id: User ID
            
        Returns:
            List[str]: List of role names
        """
        try:
            roles = self.db.query(Role.name)\
                .join(UserRole, Role.id == UserRole.role_id)\
                .filter(UserRole.user_id == user_id)\
                .filter(UserRole.deleted_at.is_(None))\
                .filter(Role.deleted_at.is_(None))\
                .filter(
                    or_(
                        UserRole.expires_at.is_(None),
                        UserRole.expires_at > datetime.utcnow()
                    )
                )\
                .all()
            
            return [role.name for role in roles]
            
        except SQLAlchemyError as e:
            self.logger.error(f"Database error getting user roles {user_id}: {str(e)}")
            raise DatabaseError(f"Failed to get user roles: {str(e)}")
    
    def has_role(self, user_id: int, role_name: str) -> bool:
        """
        Check if user has specific role.
        
        Args:
            user_id: User ID
            role_name: Role name to check
            
        Returns:
            bool: True if user has role
        """
        try:
            count = self.db.query(UserRole)\
                .join(Role, UserRole.role_id == Role.id)\
                .filter(UserRole.user_id == user_id)\
                .filter(Role.name == role_name.lower())\
                .filter(UserRole.deleted_at.is_(None))\
                .filter(Role.deleted_at.is_(None))\
                .filter(
                    or_(
                        UserRole.expires_at.is_(None),
                        UserRole.expires_at > datetime.utcnow()
                    )
                )\
                .count()
            
            return count > 0
            
        except SQLAlchemyError as e:
            self.logger.error(f"Database error checking user role {user_id}: {str(e)}")
            raise DatabaseError(f"Failed to check user role: {str(e)}")
    
    # ==================== USER SEARCH AND FILTERING ====================
    
    def search_users(
        self,
        filters: UserSearchFilter,
        skip: int = 0,
        limit: int = 100,
        sort_by: str = "created_at",
        sort_desc: bool = True
    ) -> Tuple[List[User], int]:
        """
        Search users with advanced filtering.
        
        Args:
            filters: Search filter criteria
            skip: Number of records to skip
            limit: Maximum number of records to return
            sort_by: Field to sort by
            sort_desc: Whether to sort in descending order
            
        Returns:
            Tuple[List[User], int]: Users and total count
        """
        try:
            # Base query
            query = self.db.query(User)
            count_query = self.db.query(func.count(User.id))
            
            # Apply filters
            if filters.search:
                search_term = f"%{filters.search.lower()}%"
                search_conditions = or_(
                    User.username.ilike(search_term),
                    User.email.ilike(search_term),
                    User.first_name.ilike(search_term),
                    User.last_name.ilike(search_term),
                    func.concat(User.first_name, ' ', User.last_name).ilike(search_term)
                )
                query = query.filter(search_conditions)
                count_query = count_query.filter(search_conditions)
            
            if filters.status is not None:
                query = query.filter(User.status == filters.status.value)
                count_query = count_query.filter(User.status == filters.status.value)
            
            if filters.is_active is not None:
                query = query.filter(User.is_active == filters.is_active)
                count_query = count_query.filter(User.is_active == filters.is_active)
            
            if filters.is_verified is not None:
                query = query.filter(User.is_verified == filters.is_verified)
                count_query = count_query.filter(User.is_verified == filters.is_verified)
            
            if filters.is_superuser is not None:
                query = query.filter(User.is_superuser == filters.is_superuser)
                count_query = count_query.filter(User.is_superuser == filters.is_superuser)
            
            if filters.branch_id is not None:
                query = query.filter(User.branch_id == filters.branch_id)
                count_query = count_query.filter(User.branch_id == filters.branch_id)
            
            if filters.created_after:
                query = query.filter(User.created_at >= filters.created_after)
                count_query = count_query.filter(User.created_at >= filters.created_after)
            
            if filters.created_before:
                query = query.filter(User.created_at <= filters.created_before)
                count_query = count_query.filter(User.created_at <= filters.created_before)
            
            if filters.last_login_after:
                query = query.filter(User.last_login_at >= filters.last_login_after)
                count_query = count_query.filter(User.last_login_at >= filters.last_login_after)
            
            if filters.has_2fa is not None:
                query = query.filter(User.two_factor_enabled == filters.has_2fa)
                count_query = count_query.filter(User.two_factor_enabled == filters.has_2fa)
            
            # Role filtering
            if filters.role is not None:
                role_subquery = self.db.query(UserRole.user_id)\
                    .join(Role, UserRole.role_id == Role.id)\
                    .filter(Role.name == filters.role.value)\
                    .filter(UserRole.deleted_at.is_(None))\
                    .filter(Role.deleted_at.is_(None))\
                    .subquery()
                
                query = query.filter(User.id.in_(role_subquery))
                count_query = count_query.filter(User.id.in_(role_subquery))
            
            # Soft delete handling
            if not getattr(filters, 'include_deleted', False):
                query = query.filter(User.deleted_at.is_(None))
                count_query = count_query.filter(User.deleted_at.is_(None))
            
            # Get total count
            total_count = count_query.scalar()
            
            # Apply sorting
            if hasattr(User, sort_by):
                sort_field = getattr(User, sort_by)
                if sort_desc:
                    query = query.order_by(desc(sort_field))
                else:
                    query = query.order_by(asc(sort_field))
            else:
                query = query.order_by(desc(User.created_at))
            
            # Apply pagination
            users = query.offset(skip).limit(limit).all()
            
            return users, total_count
            
        except SQLAlchemyError as e:
            self.logger.error(f"Database error searching users: {str(e)}")
            raise DatabaseError(f"Failed to search users: {str(e)}")
    
    # ==================== USER STATISTICS ====================
    
    def get_user_statistics(self) -> Dict[str, Any]:
        """
        Get comprehensive user statistics.
        
        Returns:
            Dict[str, Any]: User statistics
        """
        try:
            base_query = self.db.query(User).filter(User.deleted_at.is_(None))
            
            # Basic counts
            total_users = base_query.count()
            active_users = base_query.filter(User.is_active == True).count()
            verified_users = base_query.filter(User.is_verified == True).count()
            superusers = base_query.filter(User.is_superuser == True).count()
            locked_users = base_query.filter(User.locked_until > datetime.utcnow()).count()
            
            # Status counts
            status_counts = {}
            for status in UserStatus:
                count = base_query.filter(User.status == status.value).count()
                status_counts[status.value] = count
            
            # Recent activity
            thirty_days_ago = datetime.utcnow() - timedelta(days=30)
            recent_registrations = base_query.filter(User.created_at >= thirty_days_ago).count()
            recent_logins = base_query.filter(User.last_login_at >= thirty_days_ago).count()
            
            # 2FA enabled count
            users_with_2fa = base_query.filter(User.two_factor_enabled == True).count()
            
            return {
                'total_users': total_users,
                'active_users': active_users,
                'inactive_users': total_users - active_users,
                'verified_users': verified_users,
                'superusers': superusers,
                'locked_users': locked_users,
                'users_with_2fa': users_with_2fa,
                'recent_registrations': recent_registrations,
                'recent_logins': recent_logins,
                'status_breakdown': status_counts,
                'calculated_at': datetime.utcnow()
            }
            
        except SQLAlchemyError as e:
            self.logger.error(f"Database error getting user statistics: {str(e)}")
            raise DatabaseError(f"Failed to get user statistics: {str(e)}")
    
    def get_users_by_branch(self, branch_id: int) -> List[User]:
        """
        Get all users in a specific branch.
        
        Args:
            branch_id: Branch ID
            
        Returns:
            List[User]: Users in the branch
        """
        try:
            return self.db.query(User)\
                .filter(User.branch_id == branch_id)\
                .filter(User.deleted_at.is_(None))\
                .filter(User.is_active == True)\
                .order_by(User.first_name, User.last_name)\
                .all()
                
        except SQLAlchemyError as e:
            self.logger.error(f"Database error getting users by branch {branch_id}: {str(e)}")
            raise DatabaseError(f"Failed to get users by branch: {str(e)}")
    
    def get_users_by_role(self, role_name: str) -> List[User]:
        """
        Get all users with a specific role.
        
        Args:
            role_name: Role name
            
        Returns:
            List[User]: Users with the role
        """
        try:
            return self.db.query(User)\
                .join(UserRole, User.id == UserRole.user_id)\
                .join(Role, UserRole.role_id == Role.id)\
                .filter(Role.name == role_name.lower())\
                .filter(User.deleted_at.is_(None))\
                .filter(UserRole.deleted_at.is_(None))\
                .filter(Role.deleted_at.is_(None))\
                .filter(
                    or_(
                        UserRole.expires_at.is_(None),
                        UserRole.expires_at > datetime.utcnow()
                    )
                )\
                .order_by(User.first_name, User.last_name)\
                .all()
                
        except SQLAlchemyError as e:
            self.logger.error(f"Database error getting users by role {role_name}: {str(e)}")
            raise DatabaseError(f"Failed to get users by role: {str(e)}")
    
    # ==================== CLEANUP AND MAINTENANCE ====================
    
    def cleanup_expired_role_assignments(self) -> int:
        """
        Remove expired role assignments.
        
        Returns:
            int: Number of assignments cleaned up
        """
        try:
            count = self.db.query(UserRole)\
                .filter(UserRole.expires_at < datetime.utcnow())\
                .filter(UserRole.deleted_at.is_(None))\
                .update({'deleted_at': datetime.utcnow()}, synchronize_session=False)
            
            self.db.flush()
            self.logger.info(f"Cleaned up {count} expired role assignments")
            return count
            
        except SQLAlchemyError as e:
            self.db.rollback()
            self.logger.error(f"Database error cleaning up role assignments: {str(e)}")
            raise DatabaseError(f"Failed to cleanup role assignments: {str(e)}")
    
    def unlock_expired_accounts(self) -> int:
        """
        Unlock accounts where lock time has expired.
        
        Returns:
            int: Number of accounts unlocked
        """
        try:
            count = self.db.query(User)\
                .filter(User.locked_until < datetime.utcnow())\
                .filter(User.locked_until.isnot(None))\
                .update({
                    'locked_until': None,
                    'lock_reason': None,
                    'updated_at': datetime.utcnow()
                }, synchronize_session=False)
            
            self.db.flush()
            self.logger.info(f"Unlocked {count} expired account locks")
            return count
            
        except SQLAlchemyError as e:
            self.db.rollback()
            self.logger.error(f"Database error unlocking expired accounts: {str(e)}")
            raise DatabaseError(f"Failed to unlock expired accounts: {str(e)}")