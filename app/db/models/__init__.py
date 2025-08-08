"""
Module: models
Purpose: Database models package for CEMS - Clean exports only
Author: CEMS Development Team
Date: 2024
"""

# Import all model classes for easy access
from app.db.models.user import User, Role, UserRole
from app.db.models.currency import Currency, ExchangeRate
from app.db.models.branch import Branch, BranchBalance
from app.db.models.customer import Customer
from app.db.models.vault import Vault, VaultBalance, VaultTransaction
from app.db.models.transaction import (
    Transaction, 
    CurrencyExchange, 
    CashTransaction, 
    Transfer, 
    Commission
)

# Package metadata
__version__ = "1.0.0"
__author__ = "CEMS Development Team"

# Export all models for external use
__all__ = [
    # User & Authentication Models
    "User",
    "Role", 
    "UserRole",
    
    # Currency Models
    "Currency",
    "ExchangeRate",
    
    # Branch Models
    "Branch",
    "BranchBalance",
    
    # Customer Models
    "Customer",
    
    # Vault Models
    "Vault",
    "VaultBalance",
    "VaultTransaction",
    
    # Transaction Models
    "Transaction",
    "CurrencyExchange",
    "CashTransaction", 
    "Transfer",
    "Commission",
]


def get_all_models():
    """
    Get list of all model classes.
    
    Returns:
        list: All model classes
    """
    return [
        User, Role, UserRole,
        Currency, ExchangeRate,
        Branch, BranchBalance,
        Customer,
        Vault, VaultBalance, VaultTransaction,
        Transaction, CurrencyExchange, CashTransaction, Transfer, Commission
    ]


def get_model_names():
    """
    Get list of all model names.
    
    Returns:
        list: All model class names
    """
    return [model.__name__ for model in get_all_models()]


def get_table_names():
    """
    Get list of all table names.
    
    Returns:
        list: All database table names
    """
    return [model.__tablename__ for model in get_all_models()]


# Model categories for organization
MODEL_CATEGORIES = {
    "auth": [User, Role, UserRole],
    "currency": [Currency, ExchangeRate], 
    "branch": [Branch, BranchBalance],
    "customer": [Customer],
    "vault": [Vault, VaultBalance, VaultTransaction],
    "transaction": [Transaction, CurrencyExchange, CashTransaction, Transfer, Commission]
}


def get_models_by_category(category: str):
    """
    Get models by category.
    
    Args:
        category: Category name (auth, currency, branch, customer, vault, transaction)
        
    Returns:
        list: Models in the specified category
    """
    return MODEL_CATEGORIES.get(category, [])


# Model dependency order for initialization
DEPENDENCY_ORDER = [
    # Level 0: No dependencies
    Role,
    Currency,
    
    # Level 1: Depend on Level 0
    Branch,  # No FK to User yet
    
    # Level 2: Can reference Level 0 and 1
    User,  # References Branch
    ExchangeRate,  # References Currency and User
    
    # Level 3: Can reference up to Level 2
    Customer,  # References Branch and User
    Vault,  # References User
    
    # Level 4: Can reference up to Level 3
    UserRole,  # References User and Role
    BranchBalance,  # References Branch and Currency
    VaultBalance,  # References Vault and Currency
    
    # Level 5: Can reference up to Level 4
    Transaction,  # References User, Branch, Customer, ExchangeRate
    VaultTransaction,  # References Vault and User
    
    # Level 6: Specialized transaction types
    CurrencyExchange,  # Inherits from Transaction
    CashTransaction,  # Inherits from Transaction
    Transfer,  # Inherits from Transaction
    Commission,  # References Transaction
]


def get_models_in_dependency_order():
    """
    Get models in dependency order for safe creation/deletion.
    
    Returns:
        list: Models ordered by dependencies
    """
    return DEPENDENCY_ORDER


def get_models_in_reverse_dependency_order():
    """
    Get models in reverse dependency order for safe deletion.
    
    Returns:
        list: Models ordered for safe deletion
    """
    return list(reversed(DEPENDENCY_ORDER))