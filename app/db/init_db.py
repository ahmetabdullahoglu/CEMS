"""
Module: init_db
Purpose: Database initialization and initial data seeding for CEMS
Author: CEMS Development Team
Date: 2024
"""

import logging
from decimal import Decimal
from typing import Optional
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.constants import UserRole, UserStatus, CurrencyCode, CURRENCY_NAMES, CURRENCY_SYMBOLS
from app.core.security import get_password_hash
from app.db.database import db_manager
from app.db.models import User, Role, Currency, ExchangeRate
from app.utils.logger import get_logger

# Setup logging
logger = get_logger(__name__)


def create_initial_roles(db: Session) -> None:
    """
    Create initial system roles.
    
    Args:
        db: Database session
    """
    logger.info("Creating initial roles...")
    
    roles_data = [
        {
            "name": UserRole.SUPER_ADMIN.value,
            "display_name": "Super Administrator",
            "description": "System administrator with full access to all features",
            "is_system_role": True,
            "hierarchy_level": "1",
            "permissions": '["*"]'  # All permissions
        },
        {
            "name": UserRole.ADMIN.value,
            "display_name": "Administrator",
            "description": "System administrator with administrative privileges",
            "is_system_role": True,
            "hierarchy_level": "2",
            "permissions": '["admin.*", "user.*", "branch.*", "currency.*", "transaction.*", "report.*"]'
        },
        {
            "name": UserRole.BRANCH_MANAGER.value,
            "display_name": "Branch Manager",
            "description": "Manager of a specific branch with branch-level administrative access",
            "is_system_role": True,
            "hierarchy_level": "3",
            "permissions": '["branch.manage", "user.view", "transaction.*", "customer.*", "report.branch"]'
        },
        {
            "name": UserRole.CASHIER.value,
            "display_name": "Cashier",
            "description": "Front desk staff who handle customer transactions",
            "is_system_role": True,
            "hierarchy_level": "4",
            "permissions": '["transaction.create", "transaction.view", "customer.*", "currency.view"]'
        },
        {
            "name": UserRole.ACCOUNTANT.value,
            "display_name": "Accountant", 
            "description": "Accounting staff with access to financial records and reports",
            "is_system_role": True,
            "hierarchy_level": "4",
            "permissions": '["transaction.view", "report.*", "currency.view", "vault.view"]'
        },
        {
            "name": UserRole.AUDITOR.value,
            "display_name": "Auditor",
            "description": "Audit staff with read-only access to all records",
            "is_system_role": True,
            "hierarchy_level": "5",
            "permissions": '["*.view", "report.*"]'
        }
    ]
    
    created_count = 0
    for role_data in roles_data:
        # Check if role already exists
        existing_role = db.query(Role).filter_by(name=role_data["name"]).first()
        
        if not existing_role:
            role = Role(**role_data)
            db.add(role)
            created_count += 1
            logger.info(f"Created role: {role_data['display_name']}")
        else:
            logger.info(f"Role already exists: {role_data['display_name']}")
    
    if created_count > 0:
        db.commit()
        logger.info(f"Successfully created {created_count} roles")
    else:
        logger.info("No new roles created")


def create_initial_currencies(db: Session) -> None:
    """
    Create initial supported currencies.
    
    Args:
        db: Database session
    """
    logger.info("Creating initial currencies...")
    
    # Define currency data with priorities for display order
    currency_priorities = {
        CurrencyCode.USD: 1,
        CurrencyCode.EUR: 2,
        CurrencyCode.GBP: 3,
        CurrencyCode.SAR: 4,
        CurrencyCode.AED: 5,
        CurrencyCode.EGP: 6,
        CurrencyCode.JOD: 7,
        CurrencyCode.KWD: 8,
        CurrencyCode.QAR: 9,
        CurrencyCode.BHD: 10,
    }
    
    # Special decimal places for certain currencies
    special_decimal_places = {
        CurrencyCode.JPY: 0,  # Yen doesn't use decimal places
        CurrencyCode.KWD: 3,  # Kuwaiti Dinar uses 3 decimal places
        CurrencyCode.BHD: 3,  # Bahraini Dinar uses 3 decimal places
    }
    
    created_count = 0
    for currency_code in CurrencyCode:
        # Check if currency already exists
        existing_currency = db.query(Currency).filter_by(code=currency_code.value).first()
        
        if not existing_currency:
            # Set display order
            display_order = currency_priorities.get(currency_code, 99)
            
            # Set decimal places
            decimal_places = special_decimal_places.get(currency_code, 2)
            
            # Set base currency (USD by default)
            is_base = currency_code.value == settings.DEFAULT_CURRENCY
            
            currency = Currency(
                code=currency_code.value,
                name=CURRENCY_NAMES[currency_code.value],
                symbol=CURRENCY_SYMBOLS[currency_code.value],
                decimal_places=str(decimal_places),
                display_order=str(display_order),
                is_base_currency=is_base,
                min_exchange_amount=Decimal('1.0000'),
                description=f"Official currency: {CURRENCY_NAMES[currency_code.value]}"
            )
            
            db.add(currency)
            created_count += 1
            logger.info(f"Created currency: {currency_code.value} - {CURRENCY_NAMES[currency_code.value]}")
        else:
            logger.info(f"Currency already exists: {currency_code.value}")
    
    if created_count > 0:
        db.commit()
        logger.info(f"Successfully created {created_count} currencies")
    else:
        logger.info("No new currencies created")


def create_initial_exchange_rates(db: Session) -> None:
    """
    Create initial exchange rates (sample rates for testing).
    
    Args:
        db: Database session
    """
    logger.info("Creating initial exchange rates...")
    
    # Get base currency
    base_currency = db.query(Currency).filter_by(code=settings.DEFAULT_CURRENCY).first()
    if not base_currency:
        logger.error(f"Base currency {settings.DEFAULT_CURRENCY} not found")
        return
    
    # Sample exchange rates (these should be replaced with real rates from an API)
    sample_rates = {
        "EUR": Decimal("0.85"),
        "GBP": Decimal("0.73"),
        "SAR": Decimal("3.75"),
        "AED": Decimal("3.67"),
        "EGP": Decimal("30.85"),
        "JOD": Decimal("0.71"),
        "KWD": Decimal("0.30"),
        "QAR": Decimal("3.64"),
        "BHD": Decimal("0.38"),
        "TRY": Decimal("28.50"),
        "JPY": Decimal("149.50"),
        "CHF": Decimal("0.88"),
        "CAD": Decimal("1.35"),
        "AUD": Decimal("1.52"),
    }
    
    created_count = 0
    for currency_code, rate in sample_rates.items():
        # Get target currency
        target_currency = db.query(Currency).filter_by(code=currency_code).first()
        if not target_currency:
            continue
        
        # Check if rate already exists
        existing_rate = db.query(ExchangeRate).filter_by(
            from_currency_code=base_currency.code,
            to_currency_code=currency_code,
            rate_type="mid"
        ).first()
        
        if not existing_rate:
            exchange_rate = ExchangeRate(
                from_currency_id=str(base_currency.id),
                to_currency_id=str(target_currency.id),
                from_currency_code=base_currency.code,
                to_currency_code=currency_code,
                rate=rate,
                rate_type="mid",
                source="initial_seed",
                buy_margin=Decimal("0.0200"),  # 2% margin
                sell_margin=Decimal("0.0200"),  # 2% margin
                reliability_score="80",  # Sample rates have lower reliability
                notes="Initial sample rate for testing purposes"
            )
            
            db.add(exchange_rate)
            created_count += 1
            logger.info(f"Created exchange rate: {base_currency.code}/{currency_code} = {rate}")
        else:
            logger.info(f"Exchange rate already exists: {base_currency.code}/{currency_code}")
    
    if created_count > 0:
        db.commit()
        logger.info(f"Successfully created {created_count} exchange rates")
    else:
        logger.info("No new exchange rates created")


def create_superuser(
    db: Session, 
    email: Optional[str] = None, 
    password: Optional[str] = None,
    username: Optional[str] = None
) -> Optional[User]:
    """
    Create initial superuser account.
    
    Args:
        db: Database session
        email: Superuser email (from settings if not provided)
        password: Superuser password (from settings if not provided)
        username: Superuser username (generated if not provided)
        
    Returns:
        User: Created superuser or None if already exists
    """
    logger.info("Creating superuser account...")
    
    # Use settings or provided values
    admin_email = email or getattr(settings, 'FIRST_SUPERUSER', 'admin@cems.com')
    admin_password = password or getattr(settings, 'FIRST_SUPERUSER_PASSWORD', 'changeme123!')
    admin_username = username or 'admin'
    
    # Check if superuser already exists
    existing_user = db.query(User).filter_by(email=admin_email).first()
    if existing_user:
        logger.info(f"Superuser already exists: {admin_email}")
        return existing_user
    
    # Get super admin role
    super_admin_role = db.query(Role).filter_by(name=UserRole.SUPER_ADMIN.value).first()
    if not super_admin_role:
        logger.error("Super admin role not found. Create roles first.")
        return None
    
    # Create superuser
    superuser = User(
        username=admin_username,
        email=admin_email,
        hashed_password=get_password_hash(admin_password),
        first_name="System",
        last_name="Administrator",
        status=UserStatus.ACTIVE.value,
        is_active=True,
        is_superuser=True,
        is_verified=True
    )
    
    db.add(superuser)
    db.commit()
    db.refresh(superuser)
    
    # Assign super admin role
    superuser.add_role(super_admin_role)
    db.commit()
    
    logger.info(f"Superuser created successfully: {admin_email}")
    logger.warning(f"Default password is '{admin_password}' - CHANGE THIS IMMEDIATELY IN PRODUCTION!")
    
    return superuser


def init_db() -> None:
    """
    Initialize database with initial data.
    This function should be called during application startup.
    """
    logger.info("Starting database initialization...")
    
    try:
        # Check database connection
        if not db_manager.check_connection():
            logger.error("Database connection failed")
            return
        
        # Create tables if they don't exist (for development only)
        if settings.ENVIRONMENT == "development":
            db_manager.create_tables()
            logger.info("Database tables created/verified")
        
        # Get database session
        with db_manager.get_session_context() as db:
            # Create initial data
            create_initial_roles(db)
            create_initial_currencies(db)
            create_initial_exchange_rates(db)
            create_superuser(db)
        
        logger.info("Database initialization completed successfully")
        
    except Exception as e:
        logger.error(f"Database initialization failed: {e}", exc_info=True)
        raise


def reset_db() -> None:
    """
    Reset database by dropping and recreating all tables.
    WARNING: This will delete all data!
    """
    if settings.ENVIRONMENT == "production":
        raise RuntimeError("Cannot reset database in production environment")
    
    logger.warning("Resetting database - ALL DATA WILL BE LOST!")
    
    try:
        # Drop and recreate tables
        db_manager.drop_tables()
        db_manager.create_tables()
        
        # Reinitialize with seed data
        init_db()
        
        logger.info("Database reset completed successfully")
        
    except Exception as e:
        logger.error(f"Database reset failed: {e}", exc_info=True)
        raise


if __name__ == "__main__":
    """Run database initialization from command line."""
    import sys
    import argparse
    
    parser = argparse.ArgumentParser(description="Initialize CEMS database")
    parser.add_argument(
        "--reset", 
        action="store_true", 
        help="Reset database (WARNING: Deletes all data)"
    )
    
    args = parser.parse_args()
    
    if args.reset:
        if input("Are you sure you want to reset the database? (yes/no): ").lower() != 'yes':
            print("Database reset cancelled.")
            sys.exit(0)
        reset_db()
    else:
        init_db()
    
    print("Database initialization completed.")