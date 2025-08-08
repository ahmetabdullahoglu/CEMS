"""
Module: db
Purpose: Database package initialization for CEMS
Author: CEMS Development Team
Date: 2024
"""

# Import core database components
from app.db.database import db_manager, get_db, get_db_with_commit, check_database_health
from app.db.base import Base, BaseModel, BaseModelWithSoftDelete
from app.db.init_db import init_db, reset_db, verify_initialization

# Import all models
from app.db.models import *

# Version information
__version__ = "1.0.0"
__author__ = "CEMS Development Team"

# Export main components for easy importing
__all__ = [
    # Database management
    "db_manager",
    "get_db", 
    "get_db_with_commit",
    "check_database_health",
    
    # Base classes
    "Base",
    "BaseModel",
    "BaseModelWithSoftDelete",
    
    # Initialization functions
    "init_db",
    "reset_db", 
    "verify_initialization",
    
    # All models (imported from models.__init__)
    "User", "Role", "UserRole",
    "Currency", "ExchangeRate", 
    "Branch", "BranchBalance",
    "Customer",
    "Vault", "VaultBalance", "VaultTransaction",
    "Transaction", "CurrencyExchange", "CashTransaction", "Transfer", "Commission",
    
    # Utility functions
    "quick_setup",
    "get_database_info",
    "check_system_health"
]


def quick_setup(reset: bool = False, verify: bool = True) -> dict:
    """
    Quick setup function for CEMS database.
    
    Args:
        reset: Whether to reset database before setup
        verify: Whether to verify setup after initialization
        
    Returns:
        dict: Setup results
    """
    from app.utils.logger import get_logger
    
    logger = get_logger(__name__)
    results = {
        "success": False,
        "steps_completed": [],
        "errors": [],
        "verification": None
    }
    
    try:
        if reset:
            logger.info("Resetting database...")
            reset_db()
            results["steps_completed"].append("database_reset")
        
        logger.info("Initializing database...")
        init_db()
        results["steps_completed"].append("database_init")
        
        if verify:
            logger.info("Verifying database...")
            verification = verify_initialization()
            results["verification"] = verification
            results["steps_completed"].append("verification")
            
            if verification["status"] == "success":
                results["success"] = True
        else:
            results["success"] = True
    
    except Exception as e:
        results["errors"].append(str(e))
        logger.error(f"Quick setup failed: {e}")
    
    return results


def get_database_info() -> dict:
    """
    Get comprehensive database information.
    
    Returns:
        dict: Database information
    """
    info = {
        "connection": db_manager.get_connection_info(),
        "models": {
            "total_models": len(__all__) - 8,  # Subtract non-model exports
            "table_count": 0,
            "relationship_count": 0
        },
        "status": "unknown"
    }
    
    try:
        # Check if database is accessible
        if db_manager.check_connection():
            info["status"] = "connected"
            
            # Get additional info if possible
            with db_manager.get_session_context() as db:
                # This could be expanded with actual table introspection
                info["models"]["table_count"] = "N/A"  # Would need metadata inspection
        else:
            info["status"] = "disconnected"
    
    except Exception as e:
        info["status"] = "error"
        info["error"] = str(e)
    
    return info


def check_system_health() -> dict:
    """
    Check overall system health.
    
    Returns:
        dict: Health check results
    """
    from datetime import datetime
    
    health = {
        "timestamp": datetime.now().isoformat(),
        "overall_status": "healthy",
        "checks": {},
        "issues": []
    }
    
    try:
        # Database connection check
        health["checks"]["database_connection"] = db_manager.check_connection()
        
        # Models accessibility check
        try:
            from app.db.models import get_all_models
            models = get_all_models()
            health["checks"]["models_accessible"] = len(models) > 0
        except Exception:
            health["checks"]["models_accessible"] = False
            health["issues"].append("Models not accessible")
        
        # Configuration check
        from app.core.config import settings
        health["checks"]["configuration_loaded"] = bool(settings.DATABASE_URL)
        
        # Overall status determination
        if not all(health["checks"].values()):
            health["overall_status"] = "unhealthy"
        elif health["issues"]:
            health["overall_status"] = "degraded"
    
    except Exception as e:
        health["overall_status"] = "error"
        health["error"] = str(e)
    
    return health


# Package initialization
def _initialize_package():
    """Initialize the database package."""
    from app.utils.logger import get_logger
    
    logger = get_logger(__name__)
    logger.info(f"CEMS Database Package v{__version__} loaded")
    
    # Perform basic checks
    try:
        # Check if database connection is possible
        if db_manager.check_connection():
            logger.info("Database connection established successfully")
        else:
            logger.warning("Database connection not available")
    except Exception as e:
        logger.warning(f"Database connection check failed: {e}")


# Initialize when package is imported
_initialize_package()