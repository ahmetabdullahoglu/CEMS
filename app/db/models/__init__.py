"""
Module: models
Purpose: Central import for all database models in CEMS
Author: CEMS Development Team
Date: 2024
"""

# Import all models to ensure they're registered with SQLAlchemy
# Order matters for Foreign Key dependencies

# Base models (no dependencies)
from app.db.models.user import Role, User, UserRole
from app.db.models.currency import Currency, ExchangeRate

# Branch models (depends on User for manager_id)
from app.db.models.branch import Branch, BranchBalance

# Customer models (depends on Branch and User for registration)
from app.db.models.customer import Customer

# Vault models (depends on Branch and User)
from app.db.models.vault import Vault, VaultBalance, VaultTransaction

# Transaction models (depends on all above models)
from app.db.models.transaction import (
    Transaction, CurrencyExchange, CashTransaction, 
    Transfer, Commission
)

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
    
    # Vault models
    "Vault",
    "VaultBalance",
    "VaultTransaction",
    
    # Transaction models
    "Transaction",
    "CurrencyExchange",
    "CashTransaction",
    "Transfer",
    "Commission",
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
    
    # Vault models
    "vault": Vault,
    "vault_balance": VaultBalance,
    "vault_transaction": VaultTransaction,
    
    # Transaction models
    "transaction": Transaction,
    "currency_exchange": CurrencyExchange,
    "cash_transaction": CashTransaction,
    "transfer": Transfer,
    "commission": Commission,
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
    "vaults": Vault,
    "vault_balances": VaultBalance,
    "vault_transactions": VaultTransaction,
    "transactions": Transaction,
    "currency_exchanges": CurrencyExchange,
    "cash_transactions": CashTransaction,
    "transfers": Transfer,
    "commissions": Commission,
}

# Model dependencies for migration ordering
MODEL_DEPENDENCIES = {
    # Level 0: No dependencies
    "roles": [],
    "currencies": [],
    
    # Level 1: Depend on Level 0
    "users": ["roles"],
    "exchange_rates": ["currencies", "users"],
    
    # Level 2: Depend on Level 1
    "user_roles": ["users", "roles"],
    "branches": ["users"],
    
    # Level 3: Depend on Level 2
    "branch_balances": ["branches", "currencies"],
    "customers": ["branches", "users"],
    "vaults": ["branches", "users"],
    
    # Level 4: Depend on Level 3
    "vault_balances": ["vaults", "currencies", "users"],
    "transactions": ["customers", "branches", "users", "exchange_rates"],
    
    # Level 5: Depend on Level 4
    "vault_transactions": ["vaults", "users", "transactions"],
    "currency_exchanges": ["transactions"],
    "cash_transactions": ["transactions", "users", "vault_transactions"],
    "transfers": ["transactions"],
    "commissions": ["transactions"],
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
                        Transfer, Commission],
        "vault": [Vault, VaultBalance, VaultTransaction],
    }


def get_models_by_dependency_level():
    """
    Get models grouped by dependency level for migration ordering.
    
    Returns:
        dict: Models grouped by dependency level
    """
    dependency_levels = {}
    
    # Calculate dependency levels
    for table_name, dependencies in MODEL_DEPENDENCIES.items():
        level = 0
        if dependencies:
            # Find maximum level of dependencies + 1
            max_dep_level = 0
            for dep in dependencies:
                dep_level = get_dependency_level(dep, MODEL_DEPENDENCIES)
                max_dep_level = max(max_dep_level, dep_level)
            level = max_dep_level + 1
        
        if level not in dependency_levels:
            dependency_levels[level] = []
        
        model_class = TABLE_NAMES.get(table_name)
        if model_class:
            dependency_levels[level].append(model_class)
    
    return dependency_levels


def get_dependency_level(table_name: str, dependencies_map: dict) -> int:
    """
    Calculate dependency level for a table.
    
    Args:
        table_name: Name of the table
        dependencies_map: Map of table dependencies
        
    Returns:
        int: Dependency level
    """
    if table_name not in dependencies_map:
        return 0
    
    dependencies = dependencies_map[table_name]
    if not dependencies:
        return 0
    
    max_level = 0
    for dep in dependencies:
        dep_level = get_dependency_level(dep, dependencies_map)
        max_level = max(max_level, dep_level)
    
    return max_level + 1


def get_creation_order():
    """
    Get list of models in creation order (respecting dependencies).
    
    Returns:
        list: Models in dependency order
    """
    levels = get_models_by_dependency_level()
    ordered_models = []
    
    for level in sorted(levels.keys()):
        ordered_models.extend(levels[level])
    
    return ordered_models


def get_foreign_key_relationships():
    """
    Get all foreign key relationships between models.
    
    Returns:
        dict: Foreign key relationships
    """
    relationships = {
        "users": {
            "branch_id": "branches.id"
        },
        "user_roles": {
            "user_id": "users.id",
            "role_id": "roles.id",
            "assigned_by": "users.id"
        },
        "exchange_rates": {
            "from_currency_id": "currencies.id",
            "to_currency_id": "currencies.id",
            "approved_by": "users.id"
        },
        "branches": {
            "branch_manager_id": "users.id"
        },
        "branch_balances": {
            "branch_id": "branches.id",
            "currency_id": "currencies.id",
            "last_transaction_id": "transactions.id",
            "frozen_by": "users.id"
        },
        "customers": {
            "registration_branch_id": "branches.id",
            "registered_by": "users.id",
            "kyc_verified_by": "users.id"
        },
        "vaults": {
            "branch_id": "branches.id",
            "primary_custodian_id": "users.id",
            "secondary_custodian_id": "users.id",
            "last_audit_by": "users.id"
        },
        "vault_balances": {
            "vault_id": "vaults.id",
            "currency_id": "currencies.id",
            "last_transaction_id": "vault_transactions.id",
            "last_counted_by": "users.id",
            "reconciled_by": "users.id"
        },
        "transactions": {
            "customer_id": "customers.id",
            "branch_id": "branches.id",
            "user_id": "users.id",
            "approved_by": "users.id",
            "exchange_rate_id": "exchange_rates.id",
            "original_transaction_id": "transactions.id",
            "reversed_transaction_id": "transactions.id"
        },
        "vault_transactions": {
            "vault_id": "vaults.id",
            "processed_by": "users.id",
            "approved_by": "users.id",
            "first_authorizer_id": "users.id",
            "second_authorizer_id": "users.id",
            "verified_by": "users.id",
            "related_transaction_id": "transactions.id"
        },
        "currency_exchanges": {
            "id": "transactions.id"
        },
        "cash_transactions": {
            "id": "transactions.id",
            "counted_by": "users.id",
            "verified_by": "users.id",
            "vault_transaction_id": "vault_transactions.id"
        },
        "transfers": {
            "id": "transactions.id"
        },
        "commissions": {
            "id": "transactions.id",
            "source_transaction_id": "transactions.id"
        }
    }
    
    return relationships


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
        "dependency_levels": len(get_models_by_dependency_level()),
        "issues": []
    }
    
    # Check if all models are in registry
    for model_name in __all__:
        model_class = globals().get(model_name)
        if model_class and model_name.lower() not in [k.replace('_', '') for k in MODEL_REGISTRY.keys()]:
            results["issues"].append(f"Model {model_name} not in registry")
    
    # Check for circular dependencies
    try:
        creation_order = get_creation_order()
        results["creation_order_length"] = len(creation_order)
    except RecursionError:
        results["issues"].append("Circular dependency detected in model relationships")
    
    # Validate foreign key relationships
    fk_relationships = get_foreign_key_relationships()
    for table_name, foreign_keys in fk_relationships.items():
        if table_name not in TABLE_NAMES:
            results["issues"].append(f"Table {table_name} not found in TABLE_NAMES")
        
        for fk_column, referenced_table_column in foreign_keys.items():
            referenced_table = referenced_table_column.split('.')[0]
            if referenced_table not in TABLE_NAMES:
                results["issues"].append(f"Referenced table {referenced_table} not found")
    
    return results


def get_model_statistics():
    """
    Get statistics about the model structure.
    
    Returns:
        dict: Model statistics
    """
    stats = {
        "total_models": len(__all__),
        "models_by_category": {},
        "models_by_level": {},
        "foreign_key_count": 0,
        "inheritance_models": []
    }
    
    # Count models by category
    categories = get_models_by_category()
    for category, models in categories.items():
        stats["models_by_category"][category] = len(models)
    
    # Count models by dependency level
    levels = get_models_by_dependency_level()
    for level, models in levels.items():
        stats["models_by_level"][level] = len(models)
    
    # Count foreign keys
    fk_relationships = get_foreign_key_relationships()
    for table_name, foreign_keys in fk_relationships.items():
        stats["foreign_key_count"] += len(foreign_keys)
    
    # Identify inheritance models (models that inherit from Transaction)
    inheritance_models = [
        "CurrencyExchange",
        "CashTransaction", 
        "Transfer",
        "Commission"
    ]
    stats["inheritance_models"] = inheritance_models
    stats["inheritance_count"] = len(inheritance_models)
    
    return stats


# Pre-compute commonly used values
_CREATION_ORDER = None
_DEPENDENCY_LEVELS = None


def get_cached_creation_order():
    """
    Get cached creation order for better performance.
    
    Returns:
        list: Models in creation order
    """
    global _CREATION_ORDER
    if _CREATION_ORDER is None:
        _CREATION_ORDER = get_creation_order()
    return _CREATION_ORDER


def get_cached_dependency_levels():
    """
    Get cached dependency levels for better performance.
    
    Returns:
        dict: Models grouped by dependency level
    """
    global _DEPENDENCY_LEVELS
    if _DEPENDENCY_LEVELS is None:
        _DEPENDENCY_LEVELS = get_models_by_dependency_level()
    return _DEPENDENCY_LEVELS


# Export utility functions
__all__.extend([
    "get_model_by_name",
    "get_model_by_table_name", 
    "get_all_models",
    "get_all_table_names",
    "get_models_by_category",
    "get_models_by_dependency_level",
    "get_creation_order",
    "get_foreign_key_relationships",
    "validate_model_relationships",
    "get_model_statistics",
    "MODEL_REGISTRY",
    "TABLE_NAMES",
    "MODEL_DEPENDENCIES"
])