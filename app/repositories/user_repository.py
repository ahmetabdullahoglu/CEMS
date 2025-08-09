"""
Module: user_repository
Purpose: Enhanced user repository with complete model integration for CEMS
Author: CEMS Development Team
Date: 2024
"""

from typing import List, Optional, Dict, Any, Tuple
from datetime import datetime, timedelta
from sqlalchemy.orm import Session, joinedload, selectinload
from sqlalchemy import and_, or_, func, desc, asc, text
from sqlalchemy.exc import SQLAlchemyError

from app.repositories.base import BaseRepository
from app.db.models import User, Role, UserRole as UserRoleAssoc
from app.core.constants import UserRole, UserStatus
from app.core.exceptions import NotFoundError, DuplicateError, DatabaseError
from app.schemas.user import UserSearchFilter, UserListRequest
from app.utils.logger import get_logger

logger = get_logger(__name__)


class UserRepository(BaseRepository[User]):
    """
    Enhanced user repository providing comprehensive user data access operations.
    Handles all database operations related to users, roles, and permissions.
    """
    
    def __init__(self, db: Session):
        """
        Initialize user repository.
        
        Args:
            db: Database session
        """
        super().__init__(User, db)
        self.logger = get_logger(self.__class__.__name__)
    
    # ==================== USER BASIC OPERATIONS ====================
    
    def get_by_username(self, username: str) -> Optional[User]:
        """
        Get user by username with optimized loading.
        
        Args:
            username: Username to search for
            
        Returns:
            User model instance or None if not found
        """
        try:
            return self.db.query(User).filter(
                and_(
                    User.username == username.lower(),
                    User.deleted_at.is_(None)
                )
            ).options(
                selectinload(User.user_roles).joinedload(UserRoleAssoc.role)
            ).first()
            
        except SQLAlchemyError as e:
            self.logger.error(f"Error getting user by username {username}: {str(e)}")
            raise DatabaseError(f"Failed to retrieve user: {str(e)}")
    
    def get_by_email(self, email: str) -> Optional[User]:
        """
        Get user by email with optimized loading.
        
        Args:
            email: Email address to search for
            
        Returns:
            User model instance or None if not found
        """
        try:
            return self.db.query(User).filter(
                and_(
                    User.email == email.lower(),
                    User.deleted_at.is_(None)
                )
            ).options(
                selectinload(User.user_roles).joinedload(UserRoleAssoc.role)
            ).first()
            
        except SQLAlchemyError as e:
            self.logger.error(f"Error getting user by email {email}: {str(e)}")
            raise DatabaseError(f"Failed to retrieve user: {str(e)}")
    
    def get_by_id_with_roles(self, user_id: int) -> Optional[User]:
        """
        Get user by ID with roles and permissions loaded.
        
        Args:
            user_id: User ID
            
        Returns:
            User model with roles loaded or None if not found
        """
        try:
            return self.db.query(User).filter(
                and_(
                    User.id == user_id,
                    User.deleted_at.is_(None)
                )
            ).options(
                selectinload(User.user_roles).joinedload(UserRoleAssoc.role)
            ).first()
            
        except SQLAlchemyError as e:
            self.logger.error(f"Error getting user {user_id} with roles: {str(e)}")
            raise DatabaseError(f"Failed to retrieve user: {str(e)}")
    
    def check_username_exists(self, username: str, exclude_user_id: Optional[int] = None) -> bool:
        """
        Check if username already exists.
        
        Args:
            username: Username to check
            exclude_user_id: User ID to exclude from check (for updates)
            
        Returns:
            True if username exists, False otherwise
        """
        try:
            query = self.db.query(User).filter(
                and_(
                    User.username == username.lower(),
                    User.deleted_at.is_(None)
                )
            )
            
            if exclude_user_id:
                query = query.filter(User.id != exclude_user_id)
            
            return query.first() is not None
            
        except SQLAlchemyError as e:
            self.logger.error(f"Error checking username existence: {str(e)}")
            raise DatabaseError(f"Failed to check username: {str(e)}")
    
    def check_email_exists(self, email: str, exclude_user_id: Optional[int] = None) -> bool:
        """
        Check if email already exists.
        
        Args:
            email: Email to check
            exclude_user_id: User ID to exclude from check (for updates)
            
        Returns:
            True if email exists, False otherwise
        """
        try:
            query = self.db.query(User).filter(
                and_(
                    User.email == email.lower(),
                    User.deleted_at.is_(None)
                )
            )
            
            if exclude_user_id:
                query = query.filter(User.id != exclude_user_id)
            
            return query.first() is not None
            
        except SQLAlchemyError as e:
            self.logger.error(f"Error checking email existence: {str(e)}")
            raise DatabaseError(f"Failed to check email: {str(e)}")
    
    # ==================== ROLE AND PERMISSION OPERATIONS ====================
    
    def get_user_roles(self, user_id: int) -> List[str]:
        """
        Get active role names for a user.
        
        Args:
            user_id: User ID
            
        Returns:
            List of role names
        """
        try:
            roles = self.db.query(Role.name).join(
                UserRoleAssoc, Role.id == UserRoleAssoc.role_id
            ).filter(
                and_(
                    UserRoleAssoc.user_id == user_id,
                    UserRoleAssoc.is_active == True,
                    or_(
                        UserRoleAssoc.expires_at.is_(None),
                        UserRoleAssoc.expires_at > datetime.utcnow()
                    ),
                    Role.is_active == True,
                    Role.deleted_at.is_(None)
                )
            ).all()
            
            return [role.name for role in roles]
            
        except SQLAlchemyError as e:
            self.logger.error(f"Error getting roles for user {user_id}: {str(e)}")
            raise DatabaseError(f"Failed to retrieve user roles: {str(e)}")
    
    def get_user_permissions(self, user_id: int) -> List[str]:
        """
        Get effective permissions for a user based on their roles.
        
        Args:
            user_id: User ID
            
        Returns:
            List of permission strings
        """
        try:
            # Get user to check if superuser
            user = self.get_by_id(user_id)
            if user and user.is_superuser:
                return ["*"]  # Superuser has all permissions
            
            # Get permissions from active roles
            role_permissions = self.db.query(Role.permissions).join(
                UserRoleAssoc, Role.id == UserRoleAssoc.role_id
            ).filter(
                and_(
                    UserRoleAssoc.user_id == user_id,
                    UserRoleAssoc.is_active == True,
                    or_(
                        UserRoleAssoc.expires_at.is_(None),
                        UserRoleAssoc.expires_at > datetime.utcnow()
                    ),
                    Role.is_active == True,
                    Role.deleted_at.is_(None)
                )
            ).all()
            
            # Combine all permissions from all roles
            all_permissions = set()
            for role_perms in role_permissions:
                if role_perms.permissions:
                    import json
                    try:
                        perms = json.loads(role_perms.permissions)
                        if isinstance(perms, list):
                            all_permissions.update(perms)
                    except (json.JSONDecodeError, TypeError):
                        continue
            
            return list(all_permissions)
            
        except SQLAlchemyError as e:
            self.logger.error(f"Error getting permissions for user {user_id}: {str(e)}")
            raise DatabaseError(f"Failed to retrieve user permissions: {str(e)}")
    
    def assign_role_to_user(
        self,
        user_id: int,
        role_name: str,
        assigned_by: Optional[int] = None,
        expires_at: Optional[datetime] = None
    ) -> bool:
        """
        Assign a role to a user using model relationships.
        
        Args:
            user_id: User ID
            role_name: Role name to assign
            assigned_by: ID of user making the assignment
            expires_at: Optional expiration time for role
            
        Returns:
            True if role was assigned successfully
            
        Raises:
            NotFoundError: If user or role not found
            DatabaseError: If database operation fails
        """
        try:
            # Get user and role
            user = self.get_by_id_or_raise(user_id)
            role = self.db.query(Role).filter(
                and_(
                    Role.name == role_name,
                    Role.is_active == True,
                    Role.deleted_at.is_(None)
                )
            ).first()
            
            if not role:
                raise NotFoundError(f"Role '{role_name}' not found")
            
            # Check if user already has this role
            existing_assignment = self.db.query(UserRoleAssoc).filter(
                and_(
                    UserRoleAssoc.user_id == user_id,
                    UserRoleAssoc.role_id == role.id
                )
            ).first()
            
            if existing_assignment:
                # Reactivate if inactive
                existing_assignment.is_active = True
                existing_assignment.assigned_at = datetime.utcnow()
                existing_assignment.assigned_by = assigned_by
                existing_assignment.expires_at = expires_at
            else:
                # Create new assignment
                user_role = UserRoleAssoc(
                    user_id=user_id,
                    role_id=role.id,
                    assigned_by=assigned_by,
                    assigned_at=datetime.utcnow(),
                    expires_at=expires_at,
                    is_active=True
                )
                self.db.add(user_role)
            
            self.db.commit()
            
            self.logger.info(f"Role '{role_name}' assigned to user {user_id}")
            return True
            
        except (NotFoundError, DatabaseError):
            raise
        except SQLAlchemyError as e:
            self.db.rollback()
            self.logger.error(f"Error assigning role {role_name} to user {user_id}: {str(e)}")
            raise DatabaseError(f"Failed to assign role: {str(e)}")
    
    def remove_role_from_user(self, user_id: int, role_name: str) -> bool:
        """
        Remove a role from a user.
        
        Args:
            user_id: User ID
            role_name: Role name to remove
            
        Returns:
            True if role was removed successfully
        """
        try:
            # Get role
            role = self.db.query(Role).filter(Role.name == role_name).first()
            if not role:
                raise NotFoundError(f"Role '{role_name}' not found")
            
            # Deactivate role assignment
            assignment = self.db.query(UserRoleAssoc).filter(
                and_(
                    UserRoleAssoc.user_id == user_id,
                    UserRoleAssoc.role_id == role.id,
                    UserRoleAssoc.is_active == True
                )
            ).first()
            
            if assignment:
                assignment.is_active = False
                self.db.commit()
                
                self.logger.info(f"Role '{role_name}' removed from user {user_id}")
                return True
            
            return False
            
        except (NotFoundError, DatabaseError):
            raise
        except SQLAlchemyError as e:
            self.db.rollback()
            self.logger.error(f"Error removing role {role_name} from user {user_id}: {str(e)}")
            raise DatabaseError(f"Failed to remove role: {str(e)}")
    
    def has_role(self, user_id: int, role_name: str) -> bool:
        """
        Check if user has a specific role.
        
        Args:
            user_id: User ID
            role_name: Role name to check
            
        Returns:
            True if user has the role
        """
        try:
            user_roles = self.get_user_roles(user_id)
            return role_name in user_roles
            
        except DatabaseError:
            return False
    
    def has_permission(self, user_id: int, permission: str) -> bool:
        """
        Check if user has a specific permission.
        
        Args:
            user_id: User ID
            permission: Permission to check
            
        Returns:
            True if user has the permission
        """
        try:
            user_permissions = self.get_user_permissions(user_id)
            
            # Check for wildcard permission
            if "*" in user_permissions:
                return True
            
            # Check for exact permission
            if permission in user_permissions:
                return True
            
            # Check for wildcard patterns (e.g., "admin.*")
            for perm in user_permissions:
                if perm.endswith(".*"):
                    prefix = perm[:-2]
                    if permission.startswith(prefix + "."):
                        return True
            
            return False
            
        except DatabaseError:
            return False
    
    # ==================== USER SEARCH AND LISTING ====================
    
    def search_users(
        self,
        filters: Optional[UserSearchFilter] = None,
        page: int = 1,
        page_size: int = 20,
        sort_by: str = "created_at",
        sort_order: str = "desc"
    ) -> Tuple[List[User], int]:
        """
        Search users with advanced filtering and pagination.
        
        Args:
            filters: Search filters
            page: Page number (1-based)
            page_size: Number of items per page
            sort_by: Field to sort by
            sort_order: Sort order (asc/desc)
            
        Returns:
            Tuple of (users list, total count)
        """
        try:
            query = self.db.query(User).filter(User.deleted_at.is_(None))
            
            # Apply filters
            if filters:
                query = self._apply_user_filters(query, filters)
            
            # Get total count before pagination
            total_count = query.count()
            
            # Apply sorting
            if hasattr(User, sort_by):
                order_column = getattr(User, sort_by)
                if sort_order.lower() == "desc":
                    query = query.order_by(desc(order_column))
                else:
                    query = query.order_by(asc(order_column))
            
            # Apply pagination
            offset = (page - 1) * page_size
            users = query.offset(offset).limit(page_size).options(
                selectinload(User.user_roles).joinedload(UserRoleAssoc.role)
            ).all()
            
            return users, total_count
            
        except SQLAlchemyError as e:
            self.logger.error(f"Error searching users: {str(e)}")
            raise DatabaseError(f"Failed to search users: {str(e)}")
    
    def _apply_user_filters(self, query, filters: UserSearchFilter):
        """
        Apply search filters to user query.
        
        Args:
            query: SQLAlchemy query object
            filters: Search filters
            
        Returns:
            Filtered query object
        """
        # Text search (username, email, or name)
        if filters.search:
            search_term = f"%{filters.search.lower()}%"
            query = query.filter(
                or_(
                    User.username.ilike(search_term),
                    User.email.ilike(search_term),
                    User.first_name.ilike(search_term),
                    User.last_name.ilike(search_term)
                )
            )
        
        # Status filter
        if filters.status:
            query = query.filter(User.status == filters.status)
        
        # Active status filter
        if filters.is_active is not None:
            query = query.filter(User.is_active == filters.is_active)
        
        # Verified status filter
        if filters.is_verified is not None:
            query = query.filter(User.is_verified == filters.is_verified)
        
        # Superuser filter
        if filters.is_superuser is not None:
            query = query.filter(User.is_superuser == filters.is_superuser)
        
        # Branch filter
        if filters.branch_id:
            query = query.filter(User.branch_id == filters.branch_id)
        
        # Date range filters
        if filters.created_after:
            query = query.filter(User.created_at >= filters.created_after)
        
        if filters.created_before:
            query = query.filter(User.created_at <= filters.created_before)
        
        if filters.last_login_after:
            query = query.filter(User.last_login_at >= filters.last_login_after)
        
        # Role filter
        if filters.role:
            query = query.join(UserRoleAssoc).join(Role).filter(
                and_(
                    Role.name == filters.role.value,
                    UserRoleAssoc.is_active == True,
                    or_(
                        UserRoleAssoc.expires_at.is_(None),
                        UserRoleAssoc.expires_at > datetime.utcnow()
                    )
                )
            )
        
        # 2FA filter
        if filters.has_2fa is not None:
            if hasattr(User, 'two_factor_enabled'):
                query = query.filter(User.two_factor_enabled == filters.has_2fa)
        
        return query
    
    # ==================== USER STATISTICS AND ANALYTICS ====================
    
    def get_user_statistics(self) -> Dict[str, Any]:
        """
        Get comprehensive user statistics.
        
        Returns:
            Dictionary with user statistics
        """
        try:
            stats = {}
            
            # Basic counts
            stats["total_users"] = self.db.query(User).filter(
                User.deleted_at.is_(None)
            ).count()
            
            stats["active_users"] = self.db.query(User).filter(
                and_(
                    User.is_active == True,
                    User.deleted_at.is_(None)
                )
            ).count()
            
            # Status breakdown
            status_counts = self.db.query(
                User.status, func.count(User.id)
            ).filter(
                User.deleted_at.is_(None)
            ).group_by(User.status).all()
            
            stats["status_breakdown"] = {
                status: count for status, count in status_counts
            }
            
            # Role breakdown
            role_counts = self.db.query(
                Role.name, func.count(UserRoleAssoc.user_id)
            ).join(
                UserRoleAssoc, Role.id == UserRoleAssoc.role_id
            ).filter(
                and_(
                    UserRoleAssoc.is_active == True,
                    Role.is_active == True,
                    Role.deleted_at.is_(None)
                )
            ).group_by(Role.name).all()
            
            stats["role_breakdown"] = {
                role: count for role, count in role_counts
            }
            
            # Recent activity
            last_24h = datetime.utcnow() - timedelta(hours=24)
            stats["logins_last_24h"] = self.db.query(User).filter(
                and_(
                    User.last_login_at >= last_24h,
                    User.deleted_at.is_(None)
                )
            ).count()
            
            # Registration trends (last 30 days by day)
            last_30d = datetime.utcnow() - timedelta(days=30)
            registration_trends = self.db.query(
                func.date(User.created_at).label('date'),
                func.count(User.id).label('count')
            ).filter(
                User.created_at >= last_30d
            ).group_by(
                func.date(User.created_at)
            ).order_by(
                func.date(User.created_at)
            ).all()
            
            stats["registration_trends"] = [
                {"date": str(date), "count": count}
                for date, count in registration_trends
            ]
            
            return stats
            
        except SQLAlchemyError as e:
            self.logger.error(f"Error getting user statistics: {str(e)}")
            raise DatabaseError(f"Failed to retrieve statistics: {str(e)}")
    
    # ==================== MAINTENANCE AND UTILITIES ====================
    
    def update_last_activity(self, user_id: int) -> None:
        """
        Update user's last activity timestamp.
        
        Args:
            user_id: User ID
        """
        try:
            self.db.query(User).filter(User.id == user_id).update({
                User.last_login_at: datetime.utcnow()
            })
            self.db.commit()
            
        except SQLAlchemyError as e:
            self.db.rollback()
            self.logger.error(f"Error updating last activity for user {user_id}: {str(e)}")
    
    def cleanup_expired_role_assignments(self) -> int:
        """
        Clean up expired role assignments.
        
        Returns:
            Number of assignments cleaned up
        """
        try:
            expired_count = self.db.query(UserRoleAssoc).filter(
                and_(
                    UserRoleAssoc.expires_at <= datetime.utcnow(),
                    UserRoleAssoc.is_active == True
                )
            ).update({
                UserRoleAssoc.is_active: False
            })
            
            self.db.commit()
            
            if expired_count > 0:
                self.logger.info(f"Cleaned up {expired_count} expired role assignments")
            
            return expired_count
            
        except SQLAlchemyError as e:
            self.db.rollback()
            self.logger.error(f"Error cleaning up expired role assignments: {str(e)}")
            return 0
    
    def get_users_by_role(self, role_name: str) -> List[User]:
        """
        Get all users with a specific role.
        
        Args:
            role_name: Role name
            
        Returns:
            List of users with the role
        """
        try:
            return self.db.query(User).join(
                UserRoleAssoc, User.id == UserRoleAssoc.user_id
            ).join(
                Role, UserRoleAssoc.role_id == Role.id
            ).filter(
                and_(
                    Role.name == role_name,
                    UserRoleAssoc.is_active == True,
                    or_(
                        UserRoleAssoc.expires_at.is_(None),
                        UserRoleAssoc.expires_at > datetime.utcnow()
                    ),
                    User.deleted_at.is_(None)
                )
            ).options(
                selectinload(User.user_roles).joinedload(UserRoleAssoc.role)
            ).all()
            
        except SQLAlchemyError as e:
            self.logger.error(f"Error getting users by role {role_name}: {str(e)}")
            raise DatabaseError(f"Failed to retrieve users: {str(e)}")
    
    def get_users_with_permission(self, permission: str) -> List[User]:
        """
        Get all users with a specific permission.
        
        Args:
            permission: Permission string
            
        Returns:
            List of users with the permission
        """
        try:
            # Get all superusers first
            superusers = self.db.query(User).filter(
                and_(
                    User.is_superuser == True,
                    User.deleted_at.is_(None)
                )
            ).all()
            
            # Get users with roles that have the permission
            users_with_permission = []
            
            # Get all active roles that might have this permission
            roles = self.db.query(Role).filter(
                and_(
                    Role.is_active == True,
                    Role.deleted_at.is_(None)
                )
            ).all()
            
            for role in roles:
                if role.permissions:
                    import json
                    try:
                        perms = json.loads(role.permissions)
                        if isinstance(perms, list):
                            # Check for exact permission or wildcard
                            has_permission = (
                                permission in perms or
                                "*" in perms or
                                any(perm.endswith(".*") and permission.startswith(perm[:-2] + ".") for perm in perms)
                            )
                            
                            if has_permission:
                                role_users = self.get_users_by_role(role.name)
                                users_with_permission.extend(role_users)
                    except (json.JSONDecodeError, TypeError):
                        continue
            
            # Combine and deduplicate
            all_users = list(set(superusers + users_with_permission))
            return all_users
            
        except SQLAlchemyError as e:
            self.logger.error(f"Error getting users with permission {permission}: {str(e)}")
            raise DatabaseError(f"Failed to retrieve users: {str(e)}")