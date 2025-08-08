"""
Module: base
Purpose: Base repository class providing common CRUD operations for CEMS
Author: CEMS Development Team
Date: 2024
"""

from typing import Type, TypeVar, Generic, List, Optional, Dict, Any, Union
from abc import ABC, abstractmethod
from sqlalchemy.orm import Session
from sqlalchemy.exc import SQLAlchemyError, IntegrityError
from sqlalchemy import desc, asc, func, and_, or_
from datetime import datetime

from app.db.base import BaseModelWithSoftDelete
from app.core.exceptions import (
    DatabaseError, NotFoundError, ValidationError, 
    DuplicateError, PermissionError
)
from app.utils.logger import get_logger

# Generic type for model classes
ModelType = TypeVar("ModelType", bound=BaseModelWithSoftDelete)

logger = get_logger(__name__)


class BaseRepository(Generic[ModelType], ABC):
    """
    Abstract base repository providing common CRUD operations.
    All specific repositories should inherit from this class.
    """
    
    def __init__(self, model: Type[ModelType], db: Session):
        """
        Initialize repository with model and database session.
        
        Args:
            model: SQLAlchemy model class
            db: Database session
        """
        self.model = model
        self.db = db
        self.logger = get_logger(self.__class__.__name__)
    
    # ==================== CREATE OPERATIONS ====================
    
    def create(self, **kwargs) -> ModelType:
        """
        Create a new record.
        
        Args:
            **kwargs: Field values for the new record
            
        Returns:
            ModelType: Created record
            
        Raises:
            ValidationError: If validation fails
            DuplicateError: If record already exists
            DatabaseError: If database operation fails
        """
        try:
            # Create instance
            instance = self.model(**kwargs)
            
            # Add to session
            self.db.add(instance)
            self.db.flush()  # Get ID without committing
            
            # Refresh to get all fields
            self.db.refresh(instance)
            
            self.logger.info(f"Created {self.model.__name__} with ID {instance.id}")
            return instance
            
        except IntegrityError as e:
            self.db.rollback()
            self.logger.error(f"Integrity error creating {self.model.__name__}: {str(e)}")
            raise DuplicateError(f"Record already exists: {str(e)}")
        except SQLAlchemyError as e:
            self.db.rollback()
            self.logger.error(f"Database error creating {self.model.__name__}: {str(e)}")
            raise DatabaseError(f"Failed to create record: {str(e)}")
        except Exception as e:
            self.db.rollback()
            self.logger.error(f"Unexpected error creating {self.model.__name__}: {str(e)}")
            raise ValidationError(f"Invalid data: {str(e)}")
    
    def create_many(self, records: List[Dict[str, Any]]) -> List[ModelType]:
        """
        Create multiple records in a single transaction.
        
        Args:
            records: List of dictionaries with field values
            
        Returns:
            List[ModelType]: List of created records
            
        Raises:
            DatabaseError: If database operation fails
        """
        try:
            instances = []
            for record_data in records:
                instance = self.model(**record_data)
                instances.append(instance)
                self.db.add(instance)
            
            self.db.flush()
            
            # Refresh all instances
            for instance in instances:
                self.db.refresh(instance)
            
            self.logger.info(f"Created {len(instances)} {self.model.__name__} records")
            return instances
            
        except SQLAlchemyError as e:
            self.db.rollback()
            self.logger.error(f"Database error creating multiple {self.model.__name__}: {str(e)}")
            raise DatabaseError(f"Failed to create records: {str(e)}")
    
    # ==================== READ OPERATIONS ====================
    
    def get_by_id(self, record_id: int, include_deleted: bool = False) -> Optional[ModelType]:
        """
        Get record by ID.
        
        Args:
            record_id: Record ID
            include_deleted: Whether to include soft-deleted records
            
        Returns:
            ModelType or None: Found record or None
        """
        try:
            query = self.db.query(self.model).filter(self.model.id == record_id)
            
            # Handle soft deletes
            if not include_deleted and hasattr(self.model, 'deleted_at'):
                query = query.filter(self.model.deleted_at.is_(None))
            
            return query.first()
            
        except SQLAlchemyError as e:
            self.logger.error(f"Database error getting {self.model.__name__} by ID {record_id}: {str(e)}")
            raise DatabaseError(f"Failed to get record: {str(e)}")
    
    def get_by_id_or_raise(self, record_id: int, include_deleted: bool = False) -> ModelType:
        """
        Get record by ID or raise NotFoundError.
        
        Args:
            record_id: Record ID
            include_deleted: Whether to include soft-deleted records
            
        Returns:
            ModelType: Found record
            
        Raises:
            NotFoundError: If record not found
        """
        record = self.get_by_id(record_id, include_deleted)
        if not record:
            raise NotFoundError(f"{self.model.__name__} with ID {record_id} not found")
        return record
    
    def get_all(
        self,
        skip: int = 0,
        limit: int = 100,
        include_deleted: bool = False,
        order_by: Optional[str] = None,
        order_desc: bool = False
    ) -> List[ModelType]:
        """
        Get all records with pagination and ordering.
        
        Args:
            skip: Number of records to skip
            limit: Maximum number of records to return
            include_deleted: Whether to include soft-deleted records
            order_by: Field name to order by
            order_desc: Whether to order in descending order
            
        Returns:
            List[ModelType]: List of records
        """
        try:
            query = self.db.query(self.model)
            
            # Handle soft deletes
            if not include_deleted and hasattr(self.model, 'deleted_at'):
                query = query.filter(self.model.deleted_at.is_(None))
            
            # Apply ordering
            if order_by and hasattr(self.model, order_by):
                order_field = getattr(self.model, order_by)
                if order_desc:
                    query = query.order_by(desc(order_field))
                else:
                    query = query.order_by(asc(order_field))
            else:
                # Default ordering by id descending
                query = query.order_by(desc(self.model.id))
            
            # Apply pagination
            return query.offset(skip).limit(limit).all()
            
        except SQLAlchemyError as e:
            self.logger.error(f"Database error getting all {self.model.__name__}: {str(e)}")
            raise DatabaseError(f"Failed to get records: {str(e)}")
    
    def count(self, include_deleted: bool = False) -> int:
        """
        Count total records.
        
        Args:
            include_deleted: Whether to include soft-deleted records
            
        Returns:
            int: Total count
        """
        try:
            query = self.db.query(func.count(self.model.id))
            
            # Handle soft deletes
            if not include_deleted and hasattr(self.model, 'deleted_at'):
                query = query.filter(self.model.deleted_at.is_(None))
            
            return query.scalar()
            
        except SQLAlchemyError as e:
            self.logger.error(f"Database error counting {self.model.__name__}: {str(e)}")
            raise DatabaseError(f"Failed to count records: {str(e)}")
    
    def exists(self, **filters) -> bool:
        """
        Check if record exists with given filters.
        
        Args:
            **filters: Filter conditions
            
        Returns:
            bool: True if record exists
        """
        try:
            query = self.db.query(self.model.id)
            
            # Apply filters
            for field, value in filters.items():
                if hasattr(self.model, field):
                    query = query.filter(getattr(self.model, field) == value)
            
            # Handle soft deletes
            if hasattr(self.model, 'deleted_at'):
                query = query.filter(self.model.deleted_at.is_(None))
            
            return query.first() is not None
            
        except SQLAlchemyError as e:
            self.logger.error(f"Database error checking existence of {self.model.__name__}: {str(e)}")
            raise DatabaseError(f"Failed to check existence: {str(e)}")
    
    def find_by(self, include_deleted: bool = False, **filters) -> List[ModelType]:
        """
        Find records by filter conditions.
        
        Args:
            include_deleted: Whether to include soft-deleted records
            **filters: Filter conditions
            
        Returns:
            List[ModelType]: Matching records
        """
        try:
            query = self.db.query(self.model)
            
            # Apply filters
            for field, value in filters.items():
                if hasattr(self.model, field):
                    if isinstance(value, list):
                        query = query.filter(getattr(self.model, field).in_(value))
                    else:
                        query = query.filter(getattr(self.model, field) == value)
            
            # Handle soft deletes
            if not include_deleted and hasattr(self.model, 'deleted_at'):
                query = query.filter(self.model.deleted_at.is_(None))
            
            return query.all()
            
        except SQLAlchemyError as e:
            self.logger.error(f"Database error finding {self.model.__name__}: {str(e)}")
            raise DatabaseError(f"Failed to find records: {str(e)}")
    
    def find_one_by(self, include_deleted: bool = False, **filters) -> Optional[ModelType]:
        """
        Find single record by filter conditions.
        
        Args:
            include_deleted: Whether to include soft-deleted records
            **filters: Filter conditions
            
        Returns:
            ModelType or None: Matching record or None
        """
        try:
            query = self.db.query(self.model)
            
            # Apply filters
            for field, value in filters.items():
                if hasattr(self.model, field):
                    query = query.filter(getattr(self.model, field) == value)
            
            # Handle soft deletes
            if not include_deleted and hasattr(self.model, 'deleted_at'):
                query = query.filter(self.model.deleted_at.is_(None))
            
            return query.first()
            
        except SQLAlchemyError as e:
            self.logger.error(f"Database error finding one {self.model.__name__}: {str(e)}")
            raise DatabaseError(f"Failed to find record: {str(e)}")
    
    # ==================== UPDATE OPERATIONS ====================
    
    def update(self, record_id: int, **kwargs) -> Optional[ModelType]:
        """
        Update record by ID.
        
        Args:
            record_id: Record ID to update
            **kwargs: Fields to update
            
        Returns:
            ModelType or None: Updated record or None if not found
            
        Raises:
            ValidationError: If validation fails
            DatabaseError: If database operation fails
        """
        try:
            # Get existing record
            record = self.get_by_id(record_id)
            if not record:
                return None
            
            # Update fields
            for field, value in kwargs.items():
                if hasattr(record, field):
                    setattr(record, field, value)
            
            # Update modified timestamp
            if hasattr(record, 'updated_at'):
                record.updated_at = datetime.utcnow()
            
            self.db.flush()
            self.db.refresh(record)
            
            self.logger.info(f"Updated {self.model.__name__} with ID {record_id}")
            return record
            
        except IntegrityError as e:
            self.db.rollback()
            self.logger.error(f"Integrity error updating {self.model.__name__}: {str(e)}")
            raise DuplicateError(f"Update violates constraints: {str(e)}")
        except SQLAlchemyError as e:
            self.db.rollback()
            self.logger.error(f"Database error updating {self.model.__name__}: {str(e)}")
            raise DatabaseError(f"Failed to update record: {str(e)}")
    
    def update_many(self, filters: Dict[str, Any], updates: Dict[str, Any]) -> int:
        """
        Update multiple records matching filters.
        
        Args:
            filters: Filter conditions
            updates: Fields to update
            
        Returns:
            int: Number of updated records
            
        Raises:
            DatabaseError: If database operation fails
        """
        try:
            query = self.db.query(self.model)
            
            # Apply filters
            for field, value in filters.items():
                if hasattr(self.model, field):
                    query = query.filter(getattr(self.model, field) == value)
            
            # Add updated timestamp
            if hasattr(self.model, 'updated_at'):
                updates['updated_at'] = datetime.utcnow()
            
            # Execute update
            count = query.update(updates, synchronize_session=False)
            self.db.flush()
            
            self.logger.info(f"Updated {count} {self.model.__name__} records")
            return count
            
        except SQLAlchemyError as e:
            self.db.rollback()
            self.logger.error(f"Database error bulk updating {self.model.__name__}: {str(e)}")
            raise DatabaseError(f"Failed to update records: {str(e)}")
    
    # ==================== DELETE OPERATIONS ====================
    
    def delete(self, record_id: int, soft_delete: bool = True) -> bool:
        """
        Delete record by ID.
        
        Args:
            record_id: Record ID to delete
            soft_delete: Whether to use soft delete (if supported)
            
        Returns:
            bool: True if record was deleted
            
        Raises:
            DatabaseError: If database operation fails
        """
        try:
            record = self.get_by_id(record_id)
            if not record:
                return False
            
            if soft_delete and hasattr(record, 'deleted_at'):
                # Soft delete
                record.deleted_at = datetime.utcnow()
                if hasattr(record, 'updated_at'):
                    record.updated_at = datetime.utcnow()
                self.db.flush()
                self.logger.info(f"Soft deleted {self.model.__name__} with ID {record_id}")
            else:
                # Hard delete
                self.db.delete(record)
                self.db.flush()
                self.logger.info(f"Hard deleted {self.model.__name__} with ID {record_id}")
            
            return True
            
        except SQLAlchemyError as e:
            self.db.rollback()
            self.logger.error(f"Database error deleting {self.model.__name__}: {str(e)}")
            raise DatabaseError(f"Failed to delete record: {str(e)}")
    
    def delete_many(self, filters: Dict[str, Any], soft_delete: bool = True) -> int:
        """
        Delete multiple records matching filters.
        
        Args:
            filters: Filter conditions
            soft_delete: Whether to use soft delete (if supported)
            
        Returns:
            int: Number of deleted records
            
        Raises:
            DatabaseError: If database operation fails
        """
        try:
            query = self.db.query(self.model)
            
            # Apply filters
            for field, value in filters.items():
                if hasattr(self.model, field):
                    query = query.filter(getattr(self.model, field) == value)
            
            if soft_delete and hasattr(self.model, 'deleted_at'):
                # Soft delete
                updates = {'deleted_at': datetime.utcnow()}
                if hasattr(self.model, 'updated_at'):
                    updates['updated_at'] = datetime.utcnow()
                count = query.update(updates, synchronize_session=False)
                self.logger.info(f"Soft deleted {count} {self.model.__name__} records")
            else:
                # Hard delete
                count = query.delete(synchronize_session=False)
                self.logger.info(f"Hard deleted {count} {self.model.__name__} records")
            
            self.db.flush()
            return count
            
        except SQLAlchemyError as e:
            self.db.rollback()
            self.logger.error(f"Database error bulk deleting {self.model.__name__}: {str(e)}")
            raise DatabaseError(f"Failed to delete records: {str(e)}")
    
    def restore(self, record_id: int) -> bool:
        """
        Restore soft-deleted record.
        
        Args:
            record_id: Record ID to restore
            
        Returns:
            bool: True if record was restored
            
        Raises:
            DatabaseError: If database operation fails
        """
        try:
            if not hasattr(self.model, 'deleted_at'):
                raise ValidationError("Model does not support soft delete")
            
            record = self.get_by_id(record_id, include_deleted=True)
            if not record or not record.deleted_at:
                return False
            
            record.deleted_at = None
            if hasattr(record, 'updated_at'):
                record.updated_at = datetime.utcnow()
            
            self.db.flush()
            self.logger.info(f"Restored {self.model.__name__} with ID {record_id}")
            return True
            
        except SQLAlchemyError as e:
            self.db.rollback()
            self.logger.error(f"Database error restoring {self.model.__name__}: {str(e)}")
            raise DatabaseError(f"Failed to restore record: {str(e)}")
    
    # ==================== TRANSACTION OPERATIONS ====================
    
    def commit(self) -> None:
        """Commit current transaction."""
        try:
            self.db.commit()
        except SQLAlchemyError as e:
            self.db.rollback()
            self.logger.error(f"Database error committing transaction: {str(e)}")
            raise DatabaseError(f"Failed to commit transaction: {str(e)}")
    
    def rollback(self) -> None:
        """Rollback current transaction."""
        try:
            self.db.rollback()
        except SQLAlchemyError as e:
            self.logger.error(f"Database error rolling back transaction: {str(e)}")
            raise DatabaseError(f"Failed to rollback transaction: {str(e)}")
    
    def flush(self) -> None:
        """Flush changes to database without committing."""
        try:
            self.db.flush()
        except SQLAlchemyError as e:
            self.db.rollback()
            self.logger.error(f"Database error flushing changes: {str(e)}")
            raise DatabaseError(f"Failed to flush changes: {str(e)}")
    
    # ==================== UTILITY METHODS ====================
    
    def get_field_names(self) -> List[str]:
        """
        Get list of model field names.
        
        Returns:
            List[str]: Field names
        """
        return [column.name for column in self.model.__table__.columns]
    
    def validate_filters(self, filters: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate and clean filter conditions.
        
        Args:
            filters: Filter conditions to validate
            
        Returns:
            Dict[str, Any]: Validated filters
            
        Raises:
            ValidationError: If filters are invalid
        """
        valid_filters = {}
        field_names = self.get_field_names()
        
        for field, value in filters.items():
            if field not in field_names:
                raise ValidationError(f"Invalid filter field: {field}")
            valid_filters[field] = value
        
        return valid_filters