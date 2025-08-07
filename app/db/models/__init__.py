"""
Module: models
Purpose: Central import for all database models in CEMS
Author: CEMS Development Team
Date: 2024
"""

# Import all models to ensure they're registered with SQLAlchemy
from app.db.models.user import User, Role, UserRole
from app.db.models.currency import Currency, ExchangeRate
from app.db.models.branch import Branch, BranchBalance
from app.db.models.customer import Customer
from app.db.models.transaction import (
    Transaction, CurrencyExchange, CashTransaction, 
    CashDeposit, CashWithdrawal, Transfer, Commission
)
from app.db.models.vault import Vault, VaultBalance, VaultTransaction

# Export all models for easy importing
__all__ = [
    # User models
    "User",
    "Role", 
    "UserRole",
    
    # Currency models
    "Currency",
    "ExchangeRate",
    
    # Branch models
    "Branch",
    "BranchBalance",
    
    # Customer models
    "Customer",
    
    # Transaction models
    "Transaction",
    "CurrencyExchange",
    "CashTransaction",
    "CashDeposit",
    "CashWithdrawal",
    "Transfer",
    "Commission",
    
    # Vault models
    "Vault",
    "VaultBalance",
    "VaultTransaction",
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
    
    # Branch models
    "branch": Branch,
    "branch_balance": BranchBalance,
    
    # Customer models
    "customer": Customer,
    
    # Transaction models
    "transaction": Transaction,
    "currency_exchange": CurrencyExchange,
    "cash_transaction": CashTransaction,
    "cash_deposit": CashDeposit,
    "cash_withdrawal": CashWithdrawal,
    "transfer": Transfer,
    "commission": Commission,
    
    # Vault models
    "vault": Vault,
    "vault_balance": VaultBalance,
    "vault_transaction": VaultTransaction,
}

# Table names mapping
TABLE_NAMES = {
    "users": User,
    "roles": Role,
    "user_roles": UserRole,
    "currencies": Currency,
    "exchange_rates": ExchangeRate,
    "branches": Branch,
    "branch_balances": BranchBalance,
    "customers": Customer,
    "transactions": Transaction,
    "currency_exchanges": CurrencyExchange,
    "cash_transactions": CashTransaction,
    "cash_deposits": CashDeposit,
    "cash_withdrawals": CashWithdrawal,
    "transfers": Transfer,
    "commissions": Commission,
    "vaults": Vault,
    "vault_balances": VaultBalance,
    "vault_transactions": VaultTransaction,
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


def get_models_by_category():
    """
    Get models grouped by category.
    
    Returns:
        dict: Models grouped by functional categories
    """
    return {
        "authentication": [User, Role, UserRole],
        "financial": [Currency, ExchangeRate],
        "operations": [Branch, BranchBalance],
        "customers": [Customer],
        "transactions": [Transaction, CurrencyExchange, CashTransaction, 
                        CashDeposit, CashWithdrawal, Transfer, Commission],
        "vault": [Vault, VaultBalance, VaultTransaction],
    }


def validate_model_relationships():
    """
    Validate that all model relationships are properly configured.
    Useful for debugging and setup verification.
    
    Returns:
        dict: Validation results
    """
    results = {
        "total_models": len(__all__),
        "registry_count": len(MODEL_REGISTRY),
        "table_mapping_count": len(TABLE_NAMES),
        "issues": []
    }
    
    # Check if all models are in registry
    for model_name in __all__:
        model_class = globals().get(model_name)
        if model_class and model_name.lower() not in [k.replace('_', '') for k in MODEL_REGISTRY.keys()]:
            results["issues"].append(f"Model {model_name} not in registry")
    
    return results