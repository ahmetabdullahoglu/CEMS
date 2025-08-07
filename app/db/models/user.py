"""
Module: user
Purpose: User and role models for CEMS authentication and authorization
Author: CEMS Development Team
Date: 2024
"""

from datetime import datetime
from typing import List, Optional
from sqlalchemy import (
    Column, String, Boolean, DateTime, Text, ForeignKey, 
    UniqueConstraint, Index, CheckConstraint, func
)
from sqlalchemy.orm import relationship, validates
from sqlalchemy.ext.hybrid import hybrid_property

from app.db.base import BaseModelWithSoftDelete
from app.core.constants import UserRole, UserStatus


class Role(BaseModelWithSoftDelete):
    """
    Role model for role-based access control (RBAC).
    Defines system roles with permissions.
    """
    
    __tablename__ = "roles"
    
    # Basic role information
    name = Column(
        String(50),
        nullable=False,
        unique=True,
        index=True,
        comment="Role name (unique identifier)"
    )
    
    display_name = Column(
        String(100),
        nullable=False,
        comment="Human-readable role name"
    )
    
    description = Column(
        Text,
        nullable=True,
        comment="Role description and responsibilities"
    )
    
    # Role status and hierarchy
    is_active = Column(
        Boolean,
        nullable=False,
        default=True,
        server_default='true',
        comment="Whether role is active and can be assigned"
    )
    
    is_system_role = Column(
        Boolean,
        nullable=False,
        default=False,
        server_default='false',
        comment="System-defined role (cannot be modified by users)"
    )
    
    hierarchy_level = Column(
        String(10),
        nullable=False,
        default='0',
        comment="Role hierarchy level for permission inheritance"
    )
    
    # Permissions (JSON or separate table can be used for complex permissions)
    permissions = Column(
        Text,
        nullable=True,
        comment="JSON array of permissions assigned to this role"
    )
    
    # Relationships
    users = relationship(
        "User",
        secondary="user_roles",
        back_populates="roles",
        lazy="dynamic"
    )
    
    # Table constraints
    __table_args__ = (
        CheckConstraint(
            name.in_([role.value for role in UserRole]),
            name="valid_role_name"
        ),
        Index("idx_role_name_active", name, is_active),
        Index("idx_role_hierarchy", hierarchy_level),
    )
    
    @validates('name')
    def validate_name(self, key, name):
        """Validate role name against allowed values."""
        if name not in [role.value for role in UserRole]:
            raise ValueError(f"Invalid role name: {name}")
        return name.lower()
    
    def __repr__(self) -> str:
        return f"<Role(name='{self.name}', display_name='{self.display_name}')>"


class User(BaseModelWithSoftDelete):
    """
    User model for system authentication and user management.
    Supports multiple roles and detailed user information.
    """
    
    __tablename__ = "users"
    
    # Authentication fields
    username = Column(
        String(50),
        nullable=False,
        unique=True,
        index=True,
        comment="Unique username for login"
    )
    
    email = Column(
        String(255),
        nullable=False,
        unique=True,
        index=True,
        comment="User email address (must be unique)"
    )
    
    hashed_password = Column(
        String(255),
        nullable=False,
        comment="Bcrypt hashed password"
    )
    
    # Personal information
    first_name = Column(
        String(100),
        nullable=False,
        comment="User's first name"
    )
    
    last_name = Column(
        String(100),
        nullable=False,
        comment="User's last name"
    )
    
    phone_number = Column(
        String(20),
        nullable=True,
        comment="User's phone number"
    )
    
    # Account status and settings
    status = Column(
        String(20),
        nullable=False,
        default=UserStatus.PENDING.value,
        comment="User account status"
    )
    
    is_active = Column(
        Boolean,
        nullable=False,
        default=True,
        server_default='true',
        comment="Whether user account is active"
    )
    
    is_superuser = Column(
        Boolean,
        nullable=False,
        default=False,
        server_default='false',
        comment="Whether user has superuser privileges"
    )
    
    is_verified = Column(
        Boolean,
        nullable=False,
        default=False,
        server_default='false',
        comment="Whether user email is verified"
    )
    
    # Security fields
    last_login_at = Column(
        DateTime,
        nullable=True,
        comment="Last successful login timestamp"
    )
    
    last_login_ip = Column(
        String(45),  # IPv6 compatible
        nullable=True,
        comment="IP address of last login"
    )
    
    failed_login_attempts = Column(
        String(10),
        nullable=False,
        default='0',
        comment="Number of consecutive failed login attempts"
    )
    
    locked_until = Column(
        DateTime,
        nullable=True,
        comment="Account lock expiration time"
    )
    
    password_changed_at = Column(
        DateTime,
        nullable=True,
        default=func.now(),
        comment="Last password change timestamp"
    )
    
    # Profile and preferences
    profile_image_url = Column(
        String(500),
        nullable=True,
        comment="URL to user's profile image"
    )
    
    language_preference = Column(
        String(10),
        nullable=False,
        default='en',
        comment="User's preferred language"
    )
    
    timezone = Column(
        String(50),
        nullable=False,
        default='UTC',
        comment="User's preferred timezone"
    )
    
    # Branch assignment (foreign key to be added when Branch model is created)
    branch_id = Column(
        Integer,  # Will be ForeignKey('branches.id') when Branch model exists
        nullable=True,
        index=True,
        comment="ID of the branch user is assigned to"
    )
    
    # Two-factor authentication
    two_factor_enabled = Column(
        Boolean,
        nullable=False,
        default=False,
        server_default='false',
        comment="Whether 2FA is enabled for this user"
    )
    
    two_factor_secret = Column(
        String(100),
        nullable=True,
        comment="TOTP secret for 2FA (encrypted)"
    )
    
    # Email verification
    email_verification_token = Column(
        String(100),
        nullable=True,
        comment="Token for email verification"
    )
    
    email_verification_sent_at = Column(
        DateTime,
        nullable=True,
        comment="When email verification was last sent"
    )
    
    # Password reset
    password_reset_token = Column(
        String(100),
        nullable=True,
        comment="Token for password reset"
    )
    
    password_reset_sent_at = Column(
        DateTime,
        nullable=True,
        comment="When password reset was requested"
    )
    
    # Relationships
    roles = relationship(
        "Role",
        secondary="user_roles",
        back_populates="users",
        lazy="select"
    )
    
    # Table constraints and indexes
    __table_args__ = (
        CheckConstraint(
            status.in_([status.value for status in UserStatus]),
            name="valid_user_status"
        ),
        CheckConstraint(
            "length(username) >= 3",
            name="username_min_length"
        ),
        CheckConstraint(
            "length(first_name) >= 1",
            name="first_name_not_empty"
        ),
        CheckConstraint(
            "length(last_name) >= 1",
            name="last_name_not_empty"
        ),
        Index("idx_user_email_status", email, status),
        Index("idx_user_status_active", status, is_active),
        Index("idx_user_branch", branch_id),
        Index("idx_user_last_login", last_login_at),
    )
    
    # Hybrid properties for computed fields
    @hybrid_property
    def full_name(self) -> str:
        """Get user's full name."""
        return f"{self.first_name} {self.last_name}"
    
    @hybrid_property
    def is_locked(self) -> bool:
        """Check if user account is locked."""
        if not self.locked_until:
            return False
        return datetime.utcnow() < self.locked_until
    
    @hybrid_property
    def is_password_expired(self) -> bool:
        """Check if user's password has expired (implement based on business rules)."""
        if not self.password_changed_at:
            return True
        # Example: Password expires after 90 days
        from datetime import timedelta
        expiry_date = self.password_changed_at + timedelta(days=90)
        return datetime.utcnow() > expiry_date
    
    # Validation methods
    @validates('email')
    def validate_email(self, key, email):
        """Validate email format."""
        import re
        if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
            raise ValueError("Invalid email format")
        return email.lower()
    
    @validates('username')
    def validate_username(self, key, username):
        """Validate username format and length."""
        if not username or len(username) < 3:
            raise ValueError("Username must be at least 3 characters long")
        
        import re
        if not re.match(r'^[a-zA-Z0-9_.-]+$', username):
            raise ValueError("Username can only contain letters, numbers, dots, hyphens, and underscores")
        
        return username.lower()
    
    @validates('phone_number')
    def validate_phone(self, key, phone):
        """Validate phone number format."""
        if not phone:
            return phone
        
        import re
        # Basic phone validation - can be enhanced based on requirements
        if not re.match(r'^\+?[1-9]\d{1,14}$', phone):
            raise ValueError("Invalid phone number format")
        
        return phone
    
    # Business logic methods
    def has_role(self, role_name: str) -> bool:
        """
        Check if user has a specific role.
        
        Args:
            role_name: Name of the role to check
            
        Returns:
            bool: True if user has the role
        """
        return any(role.name == role_name for role in self.roles)
    
    def has_permission(self, permission: str) -> bool:
        """
        Check if user has a specific permission.
        
        Args:
            permission: Permission to check
            
        Returns:
            bool: True if user has the permission
        """
        if self.is_superuser:
            return True
        
        for role in self.roles:
            if role.permissions and permission in role.permissions:
                return True
        
        return False
    
    def add_role(self, role: Role) -> None:
        """
        Add a role to the user.
        
        Args:
            role: Role to add
        """
        if role not in self.roles:
            self.roles.append(role)
    
    def remove_role(self, role: Role) -> None:
        """
        Remove a role from the user.
        
        Args:
            role: Role to remove
        """
        if role in self.roles:
            self.roles.remove(role)
    
    def lock_account(self, duration_minutes: int = 15) -> None:
        """
        Lock user account for specified duration.
        
        Args:
            duration_minutes: Lock duration in minutes
        """
        from datetime import timedelta
        self.locked_until = datetime.utcnow() + timedelta(minutes=duration_minutes)
    
    def unlock_account(self) -> None:
        """Unlock user account."""
        self.locked_until = None
        self.failed_login_attempts = '0'
    
    def record_login(self, ip_address: str) -> None:
        """
        Record successful login.
        
        Args:
            ip_address: IP address of the login
        """
        self.last_login_at = datetime.utcnow()
        self.last_login_ip = ip_address
        self.failed_login_attempts = '0'
    
    def record_failed_login(self) -> None:
        """Record failed login attempt."""
        current_attempts = int(self.failed_login_attempts or '0')
        self.failed_login_attempts = str(current_attempts + 1)
        
        # Lock account after 5 failed attempts
        if current_attempts + 1 >= 5:
            self.lock_account(15)  # Lock for 15 minutes
    
    def __repr__(self) -> str:
        return f"<User(username='{self.username}', email='{self.email}', status='{self.status}')>"


class UserRole(BaseModelWithSoftDelete):
    """
    Association table for many-to-many relationship between User and Role.
    Includes additional fields for role assignment tracking.
    """
    
    __tablename__ = "user_roles"
    
    # Foreign keys
    user_id = Column(
        Integer,  # ForeignKey('users.id')
        nullable=False,
        index=True,
        comment="Reference to user"
    )
    
    role_id = Column(
        Integer,  # ForeignKey('roles.id')
        nullable=False,
        index=True,
        comment="Reference to role"
    )
    
    # Assignment metadata
    assigned_by = Column(
        Integer,
        nullable=True,
        comment="ID of user who assigned this role"
    )
    
    assigned_at = Column(
        DateTime,
        nullable=False,
        default=func.now(),
        comment="When this role was assigned"
    )
    
    expires_at = Column(
        DateTime,
        nullable=True,
        comment="When this role assignment expires (optional)"
    )
    
    is_active = Column(
        Boolean,
        nullable=False,
        default=True,
        server_default='true',
        comment="Whether this role assignment is active"
    )
    
    # Table constraints
    __table_args__ = (
        UniqueConstraint('user_id', 'role_id', name='unique_user_role'),
        Index('idx_user_role_active', user_id, role_id, is_active),
        Index('idx_role_expiry', expires_at),
    )
    
    @hybrid_property
    def is_expired(self) -> bool:
        """Check if role assignment has expired."""
        if not self.expires_at:
            return False
        return datetime.utcnow() > self.expires_at
    
    def __repr__(self) -> str:
        return f"<UserRole(user_id='{self.user_id}', role_id='{self.role_id}')>"