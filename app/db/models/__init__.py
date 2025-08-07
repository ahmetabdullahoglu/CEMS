"""
Module: models
Purpose: Central import for all database models in CEMS
Author: CEMS Development Team
Date: 2024
"""

# Import all models to ensure they're registered with SQLAlchemy
from app.db.models.user import User, Role, UserRole
from app.db.models.currency import Currency, ExchangeRate

# Export all models for easy importing
__all__ = [
    # User models
    "User",
    "Role", 
    "UserRole",
    
    # Currency models
    "Currency",
    "ExchangeRate",
]

# Model registry for dynamic model access
MODEL_REGISTRY = {
    # User models
    "user": User,
    "role": Role,
    "user_role": UserRole,
    
    # Currency models
    "currency": Currency,
    "exchange_rate": ExchangeRate,
}

# Table names mapping
TABLE_NAMES = {
    "users": User,
    "roles": Role,
    "user_roles": UserRole,
    "currencies": Currency,
    "exchange_rates": ExchangeRate,
}


def get_model_by_name(model_name: str):
    """
    Get model class by name.
    
    Args:
        model_name: Name of the model
        
    Returns:
        Model class or None
    """
    return MODEL_REGISTRY.get(model_name.lower())


def get_model_by_table_name(table_name: str):
    """
    Get model class by table name.
    
    Args:
        table_name: Name of the database table
        
    Returns:
        Model class or None
    """
    return TABLE_NAMES.get(table_name.lower())


def get_all_models():
    """
    Get list of all model classes.
    
    Returns:
        list: All model classes
    """
    return list(MODEL_REGISTRY.values())


def get_all_table_names():
    """
    Get list of all table names.
    
    Returns:
        list: All table names
    """
    return list(TABLE_NAMES.keys())