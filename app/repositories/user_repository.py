"""
Module: user_repository
Purpose: User data access layer for CEMS authentication and user management
Author: CEMS Development Team
Date: 2024
"""

from typing import List, Optional, Tuple, Dict, Any, Set
from datetime import datetime, timedelta
from sqlalchemy.orm import Session, joinedload, selectinload
from sqlalchemy.exc import SQLAlchemyError, IntegrityError
from sqlalchemy import and_, or_, func, desc, asc, text

from app.repositories.base import BaseRepository
from app.db.models.user import User, Role, UserRole as UserRoleAssoc
from app.core.constants import UserRole, UserStatus
from app.core.exceptions import (
    NotFoundError, ValidationException, DatabaseException,
    DuplicateResourceException, IntegrityException
)
from app.schemas.user import UserSearchFilter, UserListRequest
from app.utils.logger import get_logger

logger = get_logger(__name__)


class UserRepository(BaseRepository[User]):
    """
    User repository providing comprehensive data access operations.
    Handles CRUD operations, search, filtering, role management, and security operations.
    """
    
    def __init__(self, db: Session):
        """
        Initialize user repository.
        
        Args:
            db: Database session
        """
        super().__init__(User, db)
        self.logger = get_logger(self.__class__.__name__)
    
    # ==================== BASIC CRUD OPERATIONS ====================
    
    def create_user(
        self,
        username: str,
        email: str,
        hashed_password: str,
        first_name: str,
        last_name: str,
        phone_number: Optional[str] = None,
        status: UserStatus = UserStatus.PENDING,
        is_active: bool = True,
        is_superuser: bool = False,
        is_verified: bool = False,
        branch_id: Optional[int] = None,
        **kwargs
    ) -> User:
        """
        Create a new user with comprehensive validation.
        
        Args:
            username: Unique username
            email: User email address
            hashed_password: Pre-hashed password
            first_name: User's first name
            last_name: User's last name
            phone_number: Optional phone number
            status: User account status
            is_active: Whether user is active
            is_superuser: Whether user has superuser privileges
            is_verified: Whether email is verified
            branch_id: Associated branch ID
            **kwargs: Additional user fields
            
        Returns:
            User: Created user object
            
        Raises:
            DuplicateResourceException: If username/email already exists
            ValidationException: If data validation fails
            DatabaseException: If database operation fails
        """
        try:
            # Check for existing username
            existing_user = self.get_by_username(username)
            if existing_user:
                raise DuplicateResourceException(f"Username '{username}' already exists")
            
            # Check for existing email
            existing_email = self.get_by_email(email)
            if existing_email:
                raise DuplicateResourceException(f"Email '{email}' already exists")
            
            # Create user object
            user = User(
                username=username.lower().strip(),
                email=email.lower().strip(),
                hashed_password=hashed_password,
                first_name=first_name.strip(),
                last_name=last_name.strip(),
                phone_number=phone_number.strip() if phone_number else None,
                status=status.value if isinstance(status, UserStatus) else status,
                is_active=is_active,
                is_superuser=is_superuser,
                is_verified=is_verified,
                branch_id=branch_id,
                **kwargs
            )
            
            self.db.add(user)
            self.db.commit()
            self.db.refresh(user)
            
            self.logger.info(f"Created user: {username} (ID: {user.id})")
            return user
            
        except IntegrityError as e:
            self.db.rollback()
            self.logger.error(f"Integrity error creating user {username}: {str(e)}")
            raise DuplicateResourceException(f"User creation failed: duplicate data")
        except SQLAlchemyError as e:
            self.db.rollback()
            self.logger.error(f"Database error creating user {username}: {str(e)}")
            raise DatabaseException(f"Failed to create user: {str(e)}")
    
    def get_by_username(self, username: str) -> Optional[User]:
        """
        Get user by username with role information.
        
        Args:
            username: Username to search for
            
        Returns:
            Optional[User]: User object or None
        """
        try:
            return self.db.query(User)\
                .options(
                    selectinload(User.user_roles).joinedload(UserRoleAssoc.role),
                    joinedload(User.branch)
                )\
                .filter(
                    and_(
                        func.lower(User.username) == username.lower().strip(),
                        User.deleted_at.is_(None)
                    )
                )\
                .first()
        except SQLAlchemyError as e:
            self.logger.error(f"Error getting user by username {username}: {str(e)}")
            return None
    
    def get_by_email(self, email: str) -> Optional[User]:
        """
        Get user by email address with role information.
        
        Args:
            email: Email address to search for
            
        Returns:
            Optional[User]: User object or None
        """
        try:
            return self.db.query(User)\
                .options(
                    selectinload(User.user_roles).joinedload(UserRoleAssoc.role),
                    joinedload(User.branch)
                )\
                .filter(
                    and_(
                        func.lower(User.email) == email.lower().strip(),
                        User.deleted_at.is_(None)
                    )
                )\
                .first()
        except SQLAlchemyError as e:
            self.logger.error(f"Error getting user by email {email}: {str(e)}")
            return None
    
    def get_by_id_with_roles(self, user_id: int) -> Optional[User]:
        """
        Get user by ID with complete role and permission information.
        
        Args:
            user_id: User ID
            
        Returns:
            Optional[User]: User object with roles or None
        """
        try:
            return self.db.query(User)\
                .options(
                    selectinload(User.user_roles).joinedload(UserRoleAssoc.role),
                    joinedload(User.branch)
                )\
                .filter(
                    and_(
                        User.id == user_id,
                        User.deleted_at.is_(None)
                    )
                )\
                .first()
        except SQLAlchemyError as e:
            self.logger.error(f"Error getting user by ID {user_id}: {str(e)}")
            return None
    
    def update_user(
        self,
        user_id: int,
        update_data: Dict[str, Any]
    ) -> User:
        """
        Update user information with validation.
        
        Args:
            user_id: User ID to update
            update_data: Dictionary of fields to update
            
        Returns:
            User: Updated user object
            
        Raises:
            NotFoundError: If user not found
            ValidationException: If validation fails
            DatabaseException: If update fails
        """
        try:
            user = self.get_by_id(user_id)
            if not user:
                raise NotFoundError(f"User with ID {user_id} not found")
            
            # Validate unique constraints if updating username/email
            if 'username' in update_data:
                existing = self.get_by_username(update_data['username'])
                if existing and existing.id != user_id:
                    raise ValidationException(f"Username '{update_data['username']}' already exists")
                update_data['username'] = update_data['username'].lower().strip()
            
            if 'email' in update_data:
                existing = self.get_by_email(update_data['email'])
                if existing and existing.id != user_id:
                    raise ValidationException(f"Email '{update_data['email']}' already exists")
                update_data['email'] = update_data['email'].lower().strip()
            
            # Update user fields
            for field, value in update_data.items():
                if hasattr(user, field):
                    setattr(user, field, value)
            
            user.updated_at = datetime.utcnow()
            self.db.commit()
            self.db.refresh(user)
            
            self.logger.info(f"Updated user {user_id}: {list(update_data.keys())}")
            return user
            
        except (NotFoundError, ValidationException):
            raise
        except SQLAlchemyError as e:
            self.db.rollback()
            self.logger.error(f"Database error updating user {user_id}: {str(e)}")
            raise DatabaseException(f"Failed to update user: {str(e)}")
    
    # ==================== SEARCH AND FILTERING ====================
    
    def search_users(
        self,
        search_term: str,
        filters: Optional[UserSearchFilter] = None,
        include_deleted: bool = False
    ) -> List[User]:
        """
        Search users by various criteria.
        
        Args:
            search_term: Search term for username, email, or name
            filters: Additional search filters
            include_deleted: Whether to include soft-deleted users
            
        Returns:
            List[User]: List of matching users
        """
        try:
            query = self.db.query(User)\
                .options(
                    selectinload(User.user_roles).joinedload(UserRoleAssoc.role),
                    joinedload(User.branch)
                )
            
            # Base condition for non-deleted users
            if not include_deleted:
                query = query.filter(User.deleted_at.is_(None))
            
            # Search term condition
            if search_term:
                search_term = f"%{search_term.strip()}%"
                search_condition = or_(
                    func.lower(User.username).like(func.lower(search_term)),
                    func.lower(User.email).like(func.lower(search_term)),
                    func.lower(User.first_name).like(func.lower(search_term)),
                    func.lower(User.last_name).like(func.lower(search_term)),
                    func.lower(func.concat(User.first_name, ' ', User.last_name)).like(func.lower(search_term))
                )
                query = query.filter(search_condition)
            
            # Apply additional filters
            if filters:
                query = self._apply_user_filters(query, filters)
            
            return query.all()
            
        except SQLAlchemyError as e:
            self.logger.error(f"Error searching users: {str(e)}")
            return []
    
    def get_users_paginated(
        self,
        request: UserListRequest,
        include_deleted: bool = False
    ) -> Tuple[List[User], int]:
        """
        Get paginated list of users with filtering and sorting.
        
        Args:
            request: Pagination and filter request
            include_deleted: Whether to include soft-deleted users
            
        Returns:
            Tuple[List[User], int]: (users, total_count)
        """
        try:
            query = self.db.query(User)\
                .options(
                    selectinload(User.user_roles).joinedload(UserRoleAssoc.role),
                    joinedload(User.branch)
                )
            
            # Base condition
            if not include_deleted:
                query = query.filter(User.deleted_at.is_(None))
            
            # Apply filters
            if request.filters:
                query = self._apply_user_filters(query, request.filters)
            
            # Get total count before pagination
            total_count = query.count()
            
            # Apply sorting
            sort_column = getattr(User, request.sort_by, User.created_at)
            if request.sort_order == 'desc':
                query = query.order_by(desc(sort_column))
            else:
                query = query.order_by(asc(sort_column))
            
            # Apply pagination
            offset = (request.page - 1) * request.page_size
            users = query.offset(offset).limit(request.page_size).all()
            
            return users, total_count
            
        except SQLAlchemyError as e:
            self.logger.error(f"Error getting paginated users: {str(e)}")
            return [], 0
    
    def _apply_user_filters(self, query, filters: UserSearchFilter):
        """
        Apply search filters to user query.
        
        Args:
            query: SQLAlchemy query object
            filters: Search filters to apply
            
        Returns:
            Modified query object
        """
        if filters.search:
            search_term = f"%{filters.search.strip()}%"
            search_condition = or_(
                func.lower(User.username).like(func.lower(search_term)),
                func.lower(User.email).like(func.lower(search_term)),
                func.lower(User.first_name).like(func.lower(search_term)),
                func.lower(User.last_name).like(func.lower(search_term))
            )
            query = query.filter(search_condition)
        
        if filters.status:
            query = query.filter(User.status == filters.status.value)
        
        if filters.role:
            query = query.join(UserRoleAssoc).join(Role)\
                .filter(Role.name == filters.role.value)
        
        if filters.branch_id:
            query = query.filter(User.branch_id == filters.branch_id)
        
        if filters.is_active is not None:
            query = query.filter(User.is_active == filters.is_active)
        
        if filters.is_verified is not None:
            query = query.filter(User.is_verified == filters.is_verified)
        
        if filters.is_superuser is not None:
            query = query.filter(User.is_superuser == filters.is_superuser)
        
        if filters.created_after:
            query = query.filter(User.created_at >= filters.created_after)
        
        if filters.created_before:
            query = query.filter(User.created_at <= filters.created_before)
        
        if filters.last_login_after:
            query = query.filter(User.last_login_at >= filters.last_login_after)
        
        if filters.has_2fa is not None:
            if filters.has_2fa:
                query = query.filter(User.two_factor_secret.isnot(None))
            else:
                query = query.filter(User.two_factor_secret.is_(None))
        
        return query
    
    # ==================== ROLE MANAGEMENT ====================
    
    def assign_role(self, user_id: int, role_name: str) -> bool:
        """
        Assign a role to a user.
        
        Args:
            user_id: User ID
            role_name: Role name to assign
            
        Returns:
            bool: True if role assigned successfully
            
        Raises:
            NotFoundError: If user or role not found
            ValidationException: If role already assigned
        """
        try:
            user = self.get_by_id(user_id)
            if not user:
                raise NotFoundError(f"User with ID {user_id} not found")
            
            role = self.db.query(Role)\
                .filter(and_(Role.name == role_name, Role.deleted_at.is_(None)))\
                .first()
            if not role:
                raise NotFoundError(f"Role '{role_name}' not found")
            
            # Check if role already assigned
            existing = self.db.query(UserRoleAssoc)\
                .filter(and_(
                    UserRoleAssoc.user_id == user_id,
                    UserRoleAssoc.role_id == role.id,
                    UserRoleAssoc.deleted_at.is_(None)
                ))\
                .first()
            
            if existing:
                raise ValidationException(f"Role '{role_name}' already assigned to user")
            
            # Create role assignment
            user_role = UserRoleAssoc(
                user_id=user_id,
                role_id=role.id,
                assigned_at=datetime.utcnow()
            )
            
            self.db.add(user_role)
            self.db.commit()
            
            self.logger.info(f"Assigned role '{role_name}' to user {user_id}")
            return True
            
        except (NotFoundError, ValidationException):
            raise
        except SQLAlchemyError as e:
            self.db.rollback()
            self.logger.error(f"Error assigning role to user {user_id}: {str(e)}")
            raise DatabaseException(f"Failed to assign role: {str(e)}")
    
    def remove_role(self, user_id: int, role_name: str) -> bool:
        """
        Remove a role from a user.
        
        Args:
            user_id: User ID
            role_name: Role name to remove
            
        Returns:
            bool: True if role removed successfully
            
        Raises:
            NotFoundError: If user, role, or assignment not found
        """
        try:
            user_role = self.db.query(UserRoleAssoc)\
                .join(Role)\
                .filter(and_(
                    UserRoleAssoc.user_id == user_id,
                    Role.name == role_name,
                    UserRoleAssoc.deleted_at.is_(None)
                ))\
                .first()
            
            if not user_role:
                raise NotFoundError(f"Role assignment not found")
            
            # Soft delete the role assignment
            user_role.deleted_at = datetime.utcnow()
            self.db.commit()
            
            self.logger.info(f"Removed role '{role_name}' from user {user_id}")
            return True
            
        except NotFoundError:
            raise
        except SQLAlchemyError as e:
            self.db.rollback()
            self.logger.error(f"Error removing role from user {user_id}: {str(e)}")
            raise DatabaseException(f"Failed to remove role: {str(e)}")
    
    def get_user_roles(self, user_id: int) -> List[Role]:
        """
        Get all roles assigned to a user.
        
        Args:
            user_id: User ID
            
        Returns:
            List[Role]: List of assigned roles
        """
        try:
            return self.db.query(Role)\
                .join(UserRoleAssoc)\
                .filter(and_(
                    UserRoleAssoc.user_id == user_id,
                    UserRoleAssoc.deleted_at.is_(None),
                    Role.deleted_at.is_(None)
                ))\
                .all()
        except SQLAlchemyError as e:
            self.logger.error(f"Error getting user roles for {user_id}: {str(e)}")
            return []
    
    def get_user_permissions(self, user_id: int) -> List[str]:
        """
        Get all effective permissions for a user.
        
        Args:
            user_id: User ID
            
        Returns:
            List[str]: List of permission strings
        """
        try:
            user = self.get_by_id_with_roles(user_id)
            if not user:
                return []
            
            # Superuser has all permissions
            if user.is_superuser:
                return ["*"]
            
            permissions = set()
            for user_role in user.user_roles:
                if user_role.role and user_role.role.permissions:
                    import json
                    role_permissions = json.loads(user_role.role.permissions)
                    permissions.update(role_permissions)
            
            return list(permissions)
            
        except Exception as e:
            self.logger.error(f"Error getting user permissions for {user_id}: {str(e)}")
            return []
    
    # ==================== SECURITY OPERATIONS ====================
    
    def lock_user_account(
        self,
        user_id: int,
        reason: str = "Security policy violation",
        locked_until: Optional[datetime] = None
    ) -> bool:
        """
        Lock user account for security reasons.
        
        Args:
            user_id: User ID
            reason: Reason for locking
            locked_until: Optional unlock time
            
        Returns:
            bool: True if account locked successfully
        """
        try:
            user = self.get_by_id(user_id)
            if not user:
                raise NotFoundError(f"User with ID {user_id} not found")
            
            user.status = UserStatus.LOCKED.value
            user.is_active = False
            user.locked_at = datetime.utcnow()
            user.locked_until = locked_until
            user.lock_reason = reason
            user.updated_at = datetime.utcnow()
            
            self.db.commit()
            
            self.logger.warning(f"Locked user account {user_id}: {reason}")
            return True
            
        except NotFoundError:
            raise
        except SQLAlchemyError as e:
            self.db.rollback()
            self.logger.error(f"Error locking user account {user_id}: {str(e)}")
            return False
    
    def unlock_user_account(self, user_id: int) -> bool:
        """
        Unlock user account.
        
        Args:
            user_id: User ID
            
        Returns:
            bool: True if account unlocked successfully
        """
        try:
            user = self.get_by_id(user_id)
            if not user:
                raise NotFoundError(f"User with ID {user_id} not found")
            
            user.status = UserStatus.ACTIVE.value
            user.is_active = True
            user.locked_at = None
            user.locked_until = None
            user.lock_reason = None
            user.failed_login_attempts = 0
            user.updated_at = datetime.utcnow()
            
            self.db.commit()
            
            self.logger.info(f"Unlocked user account {user_id}")
            return True
            
        except NotFoundError:
            raise
        except SQLAlchemyError as e:
            self.db.rollback()
            self.logger.error(f"Error unlocking user account {user_id}: {str(e)}")
            return False
    
    def update_last_login(
        self,
        user_id: int,
        ip_address: str,
        user_agent: Optional[str] = None
    ) -> bool:
        """
        Update user's last login information.
        
        Args:
            user_id: User ID
            ip_address: Client IP address
            user_agent: Client user agent
            
        Returns:
            bool: True if updated successfully
        """
        try:
            user = self.get_by_id(user_id)
            if not user:
                return False
            
            user.last_login_at = datetime.utcnow()
            user.last_login_ip = ip_address
            user.last_login_user_agent = user_agent
            user.failed_login_attempts = 0  # Reset failed attempts on successful login
            user.updated_at = datetime.utcnow()
            
            self.db.commit()
            return True
            
        except SQLAlchemyError as e:
            self.db.rollback()
            self.logger.error(f"Error updating last login for user {user_id}: {str(e)}")
            return False
    
    def increment_failed_attempts(self, user_id: int) -> int:
        """
        Increment failed login attempts counter.
        
        Args:
            user_id: User ID
            
        Returns:
            int: Current number of failed attempts
        """
        try:
            user = self.get_by_id(user_id)
            if not user:
                return 0
            
            user.failed_login_attempts = (user.failed_login_attempts or 0) + 1
            user.last_failed_login = datetime.utcnow()
            user.updated_at = datetime.utcnow()
            
            self.db.commit()
            
            return user.failed_login_attempts
            
        except SQLAlchemyError as e:
            self.db.rollback()
            self.logger.error(f"Error incrementing failed attempts for user {user_id}: {str(e)}")
            return 0
    
    def reset_failed_attempts(self, user_id: int) -> bool:
        """
        Reset failed login attempts counter.
        
        Args:
            user_id: User ID
            
        Returns:
            bool: True if reset successfully
        """
        try:
            user = self.get_by_id(user_id)
            if not user:
                return False
            
            user.failed_login_attempts = 0
            user.last_failed_login = None
            user.updated_at = datetime.utcnow()
            
            self.db.commit()
            return True
            
        except SQLAlchemyError as e:
            self.db.rollback()
            self.logger.error(f"Error resetting failed attempts for user {user_id}: {str(e)}")
            return False
    
    # ==================== UTILITY METHODS ====================
    
    def get_users_by_status(self, status: UserStatus) -> List[User]:
        """
        Get all users with specific status.
        
        Args:
            status: User status to filter by
            
        Returns:
            List[User]: List of users with the specified status
        """
        try:
            return self.db.query(User)\
                .filter(and_(
                    User.status == status.value,
                    User.deleted_at.is_(None)
                ))\
                .all()
        except SQLAlchemyError as e:
            self.logger.error(f"Error getting users by status {status}: {str(e)}")
            return []
    
    def get_users_by_role(self, role_name: str) -> List[User]:
        """
        Get all users with specific role.
        
        Args:
            role_name: Role name to filter by
            
        Returns:
            List[User]: List of users with the specified role
        """
        try:
            return self.db.query(User)\
                .join(UserRoleAssoc)\
                .join(Role)\
                .filter(and_(
                    Role.name == role_name,
                    UserRoleAssoc.deleted_at.is_(None),
                    User.deleted_at.is_(None)
                ))\
                .all()
        except SQLAlchemyError as e:
            self.logger.error(f"Error getting users by role {role_name}: {str(e)}")
            return []
    
    def check_username_exists(self, username: str, exclude_user_id: Optional[int] = None) -> bool:
        """
        Check if username exists in the system.
        
        Args:
            username: Username to check
            exclude_user_id: User ID to exclude from check (for updates)
            
        Returns:
            bool: True if username exists
        """
        try:
            query = self.db.query(User)\
                .filter(and_(
                    func.lower(User.username) == username.lower().strip(),
                    User.deleted_at.is_(None)
                ))
            
            if exclude_user_id:
                query = query.filter(User.id != exclude_user_id)
            
            return query.first() is not None
            
        except SQLAlchemyError as e:
            self.logger.error(f"Error checking username existence: {str(e)}")
            return False
    
    def check_email_exists(self, email: str, exclude_user_id: Optional[int] = None) -> bool:
        """
        Check if email exists in the system.
        
        Args:
            email: Email to check
            exclude_user_id: User ID to exclude from check (for updates)
            
        Returns:
            bool: True if email exists
        """
        try:
            query = self.db.query(User)\
                .filter(and_(
                    func.lower(User.email) == email.lower().strip(),
                    User.deleted_at.is_(None)
                ))
            
            if exclude_user_id:
                query = query.filter(User.id != exclude_user_id)
            
            return query.first() is not None
            
        except SQLAlchemyError as e:
            self.logger.error(f"Error checking email existence: {str(e)}")
            return False
    
    def get_active_users_count(self) -> int:
        """
        Get count of active users in the system.
        
        Returns:
            int: Number of active users
        """
        try:
            return self.db.query(User)\
                .filter(and_(
                    User.is_active == True,
                    User.deleted_at.is_(None)
                ))\
                .count()
        except SQLAlchemyError as e:
            self.logger.error(f"Error getting active users count: {str(e)}")
            return 0