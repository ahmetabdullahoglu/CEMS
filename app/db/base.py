"""
Module: base
Purpose: Base database model classes and common functionality for CEMS
Author: CEMS Development Team
Date: 2024
"""

from datetime import datetime
from typing import Any, Dict, Optional
from sqlalchemy import Column, DateTime, String, Integer, Boolean, func
from sqlalchemy.ext.declarative import declarative_base, declared_attr
from sqlalchemy.orm import Session

# SQLAlchemy declarative base
Base = declarative_base()


class TimestampMixin:
    """
    Mixin that adds timestamp fields to models.
    Provides created_at and updated_at fields with automatic handling.
    """
    
    created_at = Column(
        DateTime,
        nullable=False,
        default=func.now(),
        server_default=func.now(),
        comment="Record creation timestamp"
    )
    
    updated_at = Column(
        DateTime,
        nullable=False,
        default=func.now(),
        onupdate=func.now(),
        server_default=func.now(),
        comment="Record last update timestamp"
    )


class ActiveRecordMixin:
    """
    Mixin that adds active record pattern methods to models.
    Provides common database operations.
    """
    
    def save(self, db_session: Session) -> "ActiveRecordMixin":
        """
        Save the current instance to the database.
        
        Args:
            db_session: Database session
            
        Returns:
            self: The saved instance
        """
        db_session.add(self)
        db_session.commit()
        db_session.refresh(self)
        return self
    
    def delete(self, db_session: Session) -> None:
        """
        Delete the current instance from the database.
        
        Args:
            db_session: Database session
        """
        db_session.delete(self)
        db_session.commit()
    
    def update(self, db_session: Session, **kwargs) -> "ActiveRecordMixin":
        """
        Update the current instance with new values.
        
        Args:
            db_session: Database session
            **kwargs: Fields to update
            
        Returns:
            self: The updated instance
        """
        for key, value in kwargs.items():
            if hasattr(self, key):
                setattr(self, key, value)
        
        db_session.commit()
        db_session.refresh(self)
        return self


class SoftDeleteMixin:
    """
    Mixin that adds soft delete functionality.
    Records are marked as deleted instead of being physically removed.
    """
    
    is_deleted = Column(
        Boolean,
        nullable=False,
        default=False,
        server_default='false',
        comment="Soft delete flag"
    )
    
    deleted_at = Column(
        DateTime,
        nullable=True,
        comment="Soft delete timestamp"
    )
    
    def soft_delete(self, db_session: Session) -> None:
        """
        Mark the record as deleted without removing it from database.
        
        Args:
            db_session: Database session
        """
        self.is_deleted = True
        self.deleted_at = func.now()
        db_session.commit()
    
    def restore(self, db_session: Session) -> None:
        """
        Restore a soft deleted record.
        
        Args:
            db_session: Database session
        """
        self.is_deleted = False
        self.deleted_at = None
        db_session.commit()


class AuditMixin:
    """
    Mixin that adds audit trail fields.
    Tracks who created and last modified the record.
    """
    
    created_by = Column(
        String(50),
        nullable=True,
        comment="User ID who created this record"
    )
    
    updated_by = Column(
        String(50),
        nullable=True,
        comment="User ID who last updated this record"
    )


class BaseModel(Base, TimestampMixin, ActiveRecordMixin):
    """
    Base model class that all CEMS models inherit from.
    Provides common functionality and fields.
    """
    
    __abstract__ = True
    
    id = Column(
        Integer,
        primary_key=True,
        index=True,
        autoincrement=True,
        comment="Primary key"
    )
    
    @declared_attr
    def __tablename__(cls) -> str:
        """
        Generate table name from class name.
        Converts CamelCase to snake_case.
        """
        import re
        # Convert CamelCase to snake_case
        name = re.sub('(.)([A-Z][a-z]+)', r'\1_\2', cls.__name__)
        return re.sub('([a-z0-9])([A-Z])', r'\1_\2', name).lower()
    
    def to_dict(self, exclude: Optional[list] = None) -> Dict[str, Any]:
        """
        Convert model instance to dictionary.
        
        Args:
            exclude: List of fields to exclude from the dictionary
            
        Returns:
            dict: Model data as dictionary
        """
        exclude = exclude or []
        result = {}
        
        for column in self.__table__.columns:
            if column.name not in exclude:
                value = getattr(self, column.name)
                # Convert datetime to ISO format string
                if isinstance(value, datetime):
                    value = value.isoformat()
                result[column.name] = value
        
        return result
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "BaseModel":
        """
        Create model instance from dictionary.
        
        Args:
            data: Dictionary with model data
            
        Returns:
            BaseModel: New model instance
        """
        # Filter out keys that don't correspond to model attributes
        valid_keys = {column.name for column in cls.__table__.columns}
        filtered_data = {k: v for k, v in data.items() if k in valid_keys}
        
        return cls(**filtered_data)
    
    def __repr__(self) -> str:
        """
        String representation of the model.
        
        Returns:
            str: Model representation
        """
        return f"<{self.__class__.__name__}(id={self.id})>"


class BaseModelWithSoftDelete(BaseModel, SoftDeleteMixin, AuditMixin):
    """
    Base model with soft delete and audit functionality.
    Use this for models that need soft delete capability.
    """
    
    __abstract__ = True


# Utility functions for database operations
def get_or_create(
    db_session: Session,
    model_class: BaseModel,
    defaults: Optional[Dict[str, Any]] = None,
    **kwargs
) -> tuple[BaseModel, bool]:
    """
    Get an existing record or create a new one.
    
    Args:
        db_session: Database session
        model_class: Model class to query/create
        defaults: Default values for creation
        **kwargs: Query parameters
        
    Returns:
        tuple: (instance, created_flag)
    """
    instance = db_session.query(model_class).filter_by(**kwargs).first()
    
    if instance:
        return instance, False
    
    params = kwargs.copy()
    if defaults:
        params.update(defaults)
    
    instance = model_class(**params)
    db_session.add(instance)
    db_session.commit()
    db_session.refresh(instance)
    
    return instance, True


def bulk_create(
    db_session: Session,
    model_class: BaseModel,
    data_list: list[Dict[str, Any]]
) -> list[BaseModel]:
    """
    Create multiple records in bulk.
    
    Args:
        db_session: Database session
        model_class: Model class to create
        data_list: List of dictionaries with record data
        
    Returns:
        list: Created model instances
    """
    instances = [model_class(**data) for data in data_list]
    db_session.add_all(instances)
    db_session.commit()
    
    for instance in instances:
        db_session.refresh(instance)
    
    return instances