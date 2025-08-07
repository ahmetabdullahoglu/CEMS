"""
Module: init_db
Purpose: Database initialization and initial data seeding for CEMS
Author: CEMS Development Team
Date: 2024
"""

import logging
from datetime import date, datetime, time
from decimal import Decimal
from typing import Optional
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.constants import UserRole, UserStatus, CurrencyCode, CURRENCY_NAMES, CURRENCY_SYMBOLS
from app.core.security import get_password_hash
from app.db.database import db_manager
from app.db.models import (
    User, Role, UserRole, Currency, ExchangeRate, 
    Branch, BranchBalance, Customer, Vault, VaultBalance
)
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
                from_currency_id=base_currency.id,
                to_currency_id=target_currency.id,
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
    user_role = UserRole(
        user_id=superuser.id,
        role_id=super_admin_role.id,
        assigned_by=superuser.id,  # Self-assigned
        is_active=True
    )
    db.add(user_role)
    db.commit()
    
    logger.info(f"Superuser created successfully: {admin_email}")
    if settings.ENVIRONMENT != "production":
        logger.warning(f"Default password is '{admin_password}' - CHANGE THIS IMMEDIATELY IN PRODUCTION!")
    
    return superuser


def create_initial_branches(db: Session) -> None:
    """
    Create initial branches for testing.
    
    Args:
        db: Database session
    """
    logger.info("Creating initial branches...")
    
    branches_data = [
        {
            "branch_code": "BR001",
            "name": "Main Branch",
            "name_arabic": "الفرع الرئيسي",
            "address_line1": "King Fahd Road",
            "city": "Riyadh",
            "country_code": "SAU",
            "phone_number": "+966112345678",
            "email": "main@cems.com",
            "branch_type": "main",
            "status": "active",
            "is_main_branch": True,
            "opening_time": time(8, 0),
            "closing_time": time(18, 0),
            "daily_transaction_limit": Decimal('100000.00'),
            "single_transaction_limit": Decimal('25000.00'),
            "has_vault": True,
            "vault_capacity_usd": Decimal('500000.00'),
            "notes": "Main headquarters branch with full services"
        },
        {
            "branch_code": "BR002", 
            "name": "Al-Olaya Branch",
            "name_arabic": "فرع العليا",
            "address_line1": "Olaya Street",
            "city": "Riyadh",
            "country_code": "SAU",
            "phone_number": "+966112345679",
            "email": "olaya@cems.com",
            "branch_type": "standard",
            "status": "active",
            "is_main_branch": False,
            "opening_time": time(9, 0),
            "closing_time": time(17, 0),
            "daily_transaction_limit": Decimal('50000.00'),
            "single_transaction_limit": Decimal('10000.00'),
            "has_vault": True,
            "vault_capacity_usd": Decimal('200000.00'),
            "notes": "Business district branch serving corporate clients"
        },
        {
            "branch_code": "BR003",
            "name": "Jeddah Branch", 
            "name_arabic": "فرع جدة",
            "address_line1": "Corniche Road",
            "city": "Jeddah",
            "country_code": "SAU",
            "phone_number": "+966122345678",
            "email": "jeddah@cems.com",
            "branch_type": "standard",
            "status": "active",
            "is_main_branch": False,
            "opening_time": time(8, 30),
            "closing_time": time(17, 30),
            "daily_transaction_limit": Decimal('75000.00'),
            "single_transaction_limit": Decimal('15000.00'),
            "has_vault": True,
            "vault_capacity_usd": Decimal('300000.00'),
            "notes": "Coastal branch serving tourism and trade"
        }
    ]
    
    created_count = 0
    for branch_data in branches_data:
        # Check if branch already exists
        existing_branch = db.query(Branch).filter_by(branch_code=branch_data["branch_code"]).first()
        
        if not existing_branch:            
            branch = Branch(**branch_data)
            db.add(branch)
            created_count += 1
            logger.info(f"Created branch: {branch_data['name']}")
        else:
            logger.info(f"Branch already exists: {branch_data['name']}")
    
    if created_count > 0:
        db.commit()
        logger.info(f"Successfully created {created_count} branches")
    else:
        logger.info("No new branches created")


def create_initial_vault(db: Session) -> None:
    """
    Create main vault and initial balances.
    
    Args:
        db: Database session
    """
    logger.info("Creating main vault...")
    
    # Check if main vault already exists
    existing_vault = db.query(Vault).filter_by(vault_code="VLT001").first()
    
    if not existing_vault:
        main_vault = Vault(
            vault_code="VLT001",
            vault_name="Main Central Vault",
            vault_type="main",
            location_description="Central vault located in main headquarters building",
            building="CEMS Headquarters",
            floor="B1",
            room="V001",
            capacity_rating="High Security - Class III",
            security_level="maximum",
            status="active",
            is_main_vault=True,
            requires_dual_control=True,
            operating_hours_start="06:00",
            operating_hours_end="22:00",
            audit_frequency_days=30,
            insurance_coverage_amount=Decimal('10000000.00'),
            notes="Main vault for all currency exchange operations"
        )
        
        db.add(main_vault)
        db.commit()
        db.refresh(main_vault)
        
        logger.info("Created main vault: VLT001")
        
        # Create initial vault balances for major currencies
        major_currencies = ["USD", "EUR", "GBP", "SAR"]
        initial_balances = {
            "USD": Decimal('100000.0000'),
            "EUR": Decimal('75000.0000'),
            "GBP": Decimal('50000.0000'),
            "SAR": Decimal('375000.0000')
        }
        
        for currency_code in major_currencies:
            currency = db.query(Currency).filter_by(code=currency_code).first()
            if currency:
                vault_balance = VaultBalance(
                    vault_id=main_vault.id,
                    currency_id=currency.id,
                    currency_code=currency_code,
                    current_balance=initial_balances.get(currency_code, Decimal('0.0000')),
                    minimum_balance=Decimal('5000.0000'),
                    reorder_threshold=Decimal('20000.0000'),
                    critical_threshold=Decimal('10000.0000'),
                    is_active=True
                )
                db.add(vault_balance)
                logger.info(f"Created vault balance: {currency_code} = {initial_balances.get(currency_code, 0)}")
        
        db.commit()
        logger.info("Main vault and balances created successfully")
    else:
        logger.info("Main vault already exists")


def create_initial_branch_balances(db: Session) -> None:
    """
    Create initial branch balances for all branches.
    
    Args:
        db: Database session
    """
    logger.info("Creating initial branch balances...")
    
    # Get all branches
    branches = db.query(Branch).all()
    major_currencies = ["USD", "EUR", "GBP", "SAR"]
    
    # Initial balance amounts by branch type
    balance_amounts = {
        "main": {
            "USD": Decimal('50000.0000'),
            "EUR": Decimal('30000.0000'),
            "GBP": Decimal('20000.0000'),
            "SAR": Decimal('100000.0000')
        },
        "standard": {
            "USD": Decimal('25000.0000'),
            "EUR": Decimal('15000.0000'),
            "GBP": Decimal('10000.0000'),
            "SAR": Decimal('50000.0000')
        }
    }
    
    created_count = 0
    for branch in branches:
        for currency_code in major_currencies:
            # Check if balance already exists
            existing_balance = db.query(BranchBalance).filter_by(
                branch_id=branch.id,
                currency_code=currency_code
            ).first()
            
            if not existing_balance:
                currency = db.query(Currency).filter_by(code=currency_code).first()
                if currency:
                    amounts = balance_amounts.get(branch.branch_type, balance_amounts["standard"])
                    
                    branch_balance = BranchBalance(
                        branch_id=branch.id,
                        currency_id=currency.id,
                        currency_code=currency_code,
                        current_balance=amounts.get(currency_code, Decimal('0.0000')),
                        minimum_balance=Decimal('1000.0000'),
                        reorder_threshold=Decimal('5000.0000'),
                        critical_threshold=Decimal('2000.0000'),
                        is_active=True
                    )
                    
                    db.add(branch_balance)
                    created_count += 1
                    logger.info(f"Created balance for {branch.branch_code} - {currency_code}")
    
    if created_count > 0:
        db.commit()
        logger.info(f"Successfully created {created_count} branch balances")
    else:
        logger.info("No new branch balances created")


def create_sample_customers(db: Session) -> None:
    """
    Create sample customers for testing.
    
    Args:
        db: Database session
    """
    logger.info("Creating sample customers...")
    
    customers_data = [
        {
            "customer_code": "CUS0000001",
            "customer_type": "individual",
            "first_name": "Ahmed",
            "last_name": "Al-Saudi",
            "first_name_arabic": "أحمد",
            "last_name_arabic": "السعودي",
            "id_type": "national_id",
            "id_number": "1234567890",
            "date_of_birth": date(1985, 5, 15),
            "gender": "male",
            "nationality": "SAU",
            "mobile_number": "+966501234567",
            "email": "ahmed.alsaudi@email.com",
            "address_line1": "King Abdul Aziz Road",
            "city": "Riyadh",
            "country_code": "SAU",
            "status": "active",
            "classification": "standard",
            "risk_level": "low",
            "kyc_status": "completed",
            "kyc_completed_date": datetime.now(),
            "preferred_language": "ar",
            "total_transactions": "0",
            "total_volume": Decimal('0.00')
        },
        {
            "customer_code": "CUS0000002", 
            "customer_type": "individual",
            "first_name": "Sarah",
            "last_name": "Johnson",
            "id_type": "passport",
            "id_number": "US123456789",
            "date_of_birth": date(1990, 8, 22),
            "gender": "female",
            "nationality": "USA",
            "mobile_number": "+966502345678",
            "email": "sarah.johnson@email.com",
            "address_line1": "Diplomatic Quarter",
            "city": "Riyadh",
            "country_code": "SAU",
            "status": "active",
            "classification": "vip",
            "risk_level": "low",
            "kyc_status": "completed",
            "kyc_completed_date": datetime.now(),
            "preferred_language": "en",
            "is_vip": True,
            "total_transactions": "0",
            "total_volume": Decimal('0.00')
        },
        {
            "customer_code": "CUS0000003",
            "customer_type": "business",
            "company_name": "Al-Tijara Trading Company",
            "company_name_arabic": "شركة التجارة للتجارة",
            "business_type": "import_export",
            "id_type": "national_id",
            "id_number": "CR123456789",
            "mobile_number": "+966503456789",
            "email": "info@altijara.com",
            "address_line1": "Industrial District",
            "city": "Jeddah",
            "country_code": "SAU",
            "status": "active",
            "classification": "corporate",
            "risk_level": "medium",
            "kyc_status": "completed",
            "kyc_completed_date": datetime.now(),
            "estimated_monthly_volume": Decimal('500000.00'),
            "preferred_language": "ar",
            "total_transactions": "0",
            "total_volume": Decimal('0.00')
        }
    ]
    
    # Get registration branch (first branch for simplicity)
    registration_branch = db.query(Branch).first()
    
    created_count = 0
    for customer_data in customers_data:
        # Add registration branch
        if registration_branch:
            customer_data["registration_branch_id"] = registration_branch.id
            
        # Check if customer already exists
        existing_customer = db.query(Customer).filter_by(
            customer_code=customer_data["customer_code"]
        ).first()
        
        if not existing_customer:
            customer = Customer(**customer_data)
            db.add(customer)
            created_count += 1
            logger.info(f"Created customer: {customer_data['customer_code']} - {customer_data.get('first_name', customer_data.get('company_name', 'Unknown'))}")
        else:
            logger.info(f"Customer already exists: {customer_data['customer_code']}")
    
    if created_count > 0:
        db.commit()
        logger.info(f"Successfully created {created_count} sample customers")
    else:
        logger.info("No new sample customers created")


def assign_users_to_branches(db: Session) -> None:
    """
    Assign superuser to main branch.
    
    Args:
        db: Database session
    """
    logger.info("Assigning users to branches...")
    
    # Get superuser and main branch
    superuser = db.query(User).filter_by(is_superuser=True).first()
    main_branch = db.query(Branch).filter_by(is_main_branch=True).first()
    
    if superuser and main_branch and not superuser.branch_id:
        superuser.branch_id = main_branch.id
        main_branch.branch_manager_id = superuser.id
        db.commit()
        logger.info(f"Assigned superuser to main branch: {main_branch.name}")
    else:
        logger.info("User-branch assignments already exist or entities not found")


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
            # Create initial data in correct order
            create_initial_roles(db)
            create_initial_currencies(db)
            create_initial_exchange_rates(db)
            create_superuser(db)
            create_initial_branches(db)
            create_initial_vault(db)
            create_initial_branch_balances(db)
            create_sample_customers(db)
            assign_users_to_branches(db)
        
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


def verify_initialization() -> dict:
    """
    Verify that database initialization was successful.
    
    Returns:
        dict: Verification results
    """
    logger.info("Verifying database initialization...")
    
    results = {
        "status": "success",
        "counts": {},
        "issues": []
    }
    
    try:
        with db_manager.get_session_context() as db:
            # Count records in each main table
            results["counts"]["roles"] = db.query(Role).count()
            results["counts"]["currencies"] = db.query(Currency).count()
            results["counts"]["exchange_rates"] = db.query(ExchangeRate).count()
            results["counts"]["users"] = db.query(User).count()
            results["counts"]["branches"] = db.query(Branch).count()
            results["counts"]["branch_balances"] = db.query(BranchBalance).count()
            results["counts"]["customers"] = db.query(Customer).count()
            results["counts"]["vaults"] = db.query(Vault).count()
            results["counts"]["vault_balances"] = db.query(VaultBalance).count()
            
            # Check critical entities
            superuser = db.query(User).filter_by(is_superuser=True).first()
            if not superuser:
                results["issues"].append("No superuser found")
            
            main_branch = db.query(Branch).filter_by(is_main_branch=True).first()
            if not main_branch:
                results["issues"].append("No main branch found")
            
            main_vault = db.query(Vault).filter_by(is_main_vault=True).first()
            if not main_vault:
                results["issues"].append("No main vault found")
            
            base_currency = db.query(Currency).filter_by(is_base_currency=True).first()
            if not base_currency:
                results["issues"].append("No base currency found")
        
        if results["issues"]:
            results["status"] = "warning"
        
        logger.info(f"Verification completed: {results['status']}")
        
    except Exception as e:
        results["status"] = "error"
        results["error"] = str(e)
        logger.error(f"Verification failed: {e}")
    
    return results


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
    parser.add_argument(
        "--verify",
        action="store_true",
        help="Verify database initialization"
    )
    
    args = parser.parse_args()
    
    try:
        if args.reset:
            if input("Are you sure you want to reset the database? This will DELETE ALL DATA! (yes/no): ").lower() != 'yes':
                print("Database reset cancelled.")
                sys.exit(0)
            print("Resetting database...")
            reset_db()
            print("✅ Database reset completed successfully!")
            
        elif args.verify:
            print("Verifying database initialization...")
            results = verify_initialization()
            print(f"\n📊 Verification Results:")
            print(f"Status: {results['status'].upper()}")
            print(f"\n📈 Record Counts:")
            for table, count in results['counts'].items():
                print(f"  {table}: {count}")
            
            if results.get('issues'):
                print(f"\n⚠️  Issues Found:")
                for issue in results['issues']:
                    print(f"  - {issue}")
            else:
                print(f"\n✅ No issues found!")
            
            if results.get('error'):
                print(f"\n❌ Error: {results['error']}")
                sys.exit(1)
                
        else:
            print("Initializing database...")
            init_db()
            print("✅ Database initialization completed successfully!")
            
            # Automatically verify after initialization
            print("\nVerifying initialization...")
            results = verify_initialization()
            if results['status'] == 'success':
                print("✅ Verification passed!")
                print(f"📊 Created: {sum(results['counts'].values())} total records")
            else:
                print("⚠️  Verification completed with warnings")
                
    except KeyboardInterrupt:
        print("\n\n⚠️  Operation cancelled by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Error: {e}")
        sys.exit(1)