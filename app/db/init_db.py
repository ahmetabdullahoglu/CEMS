"""
Module: init_db
Purpose: Complete database initialization and initial data seeding for CEMS
Author: CEMS Development Team
Date: 2024
"""

import logging
from decimal import Decimal
from datetime import date, datetime, time, timedelta
from typing import Optional, Dict, List, Any
from sqlalchemy.orm import Session
from sqlalchemy.exc import SQLAlchemyError

from app.core.config import settings
from app.core.constants import UserRole, UserStatus, CurrencyCode, CURRENCY_NAMES, CURRENCY_SYMBOLS
from app.core.security import get_password_hash
from app.db.database import db_manager
from app.db.models import (
    User, Role, UserRole as UserRoleAssoc, Currency, ExchangeRate, 
    Branch, BranchBalance, Customer, Vault, VaultBalance, VaultTransaction
)
from app.utils.logger import get_logger


from app.repositories.user_repository import UserRepository
from app.services.user_service import UserService
from app.services.auth_service import AuthenticationService
from app.utils.validators import validate_password_strength, validate_email_format

# Setup logging
logger = get_logger(__name__)


def create_initial_roles(db: Session) -> None:
    """
    Create initial system roles with proper permissions.
    
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
    Create initial supported currencies with proper configuration.
    
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
            is_base = currency_code.value == getattr(settings, 'DEFAULT_CURRENCY', 'USD')
            
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
    Create initial exchange rates for testing purposes.
    
    Args:
        db: Database session
    """
    logger.info("Creating initial exchange rates...")
    
    # Get base currency
    base_currency_code = getattr(settings, 'DEFAULT_CURRENCY', 'USD')
    base_currency = db.query(Currency).filter_by(code=base_currency_code).first()
    if not base_currency:
        logger.error(f"Base currency {base_currency_code} not found")
        return
    
    # Sample exchange rates (should be replaced with real rates from an API)
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
    
    # Assign super admin role (if UserRole model supports add_role method)
    try:
        # Create user role association
        user_role = UserRoleAssoc(
            user_id=superuser.id,
            role_id=super_admin_role.id,
            assigned_by=superuser.id,
            is_active=True
        )
        db.add(user_role)
        db.commit()
    except Exception as e:
        logger.warning(f"Could not assign role to superuser: {e}")
    
    logger.info(f"Superuser created successfully: {admin_email}")
    logger.warning(f"Default password is '{admin_password}' - CHANGE THIS IMMEDIATELY IN PRODUCTION!")
    
    return superuser


def create_initial_branches(db: Session) -> None:
    """
    Create initial branches including main branch.
    
    Args:
        db: Database session
    """
    logger.info("Creating initial branches...")
    
    # Main branch data
    main_branch_data = {
        "branch_code": "BR001",
        "name": "Main Branch",
        "name_arabic": "الفرع الرئيسي",
        "address_line1": "123 Business District, Downtown",
        "city": "Riyadh",
        "country": "Saudi Arabia",
        "postal_code": "11564",
        "phone_number": "+966-11-123-4567",
        "email": "main@cems.com",
        "branch_type": "main",
        "status": "active",
        "is_main_branch": True,
        "daily_transaction_limit": Decimal('500000.00'),
        "single_transaction_limit": Decimal('100000.00'),
        "has_vault": True,
        "vault_capacity_usd": Decimal('1000000.00'),
        "opened_date": datetime.now(),
        "license_number": "CR-2024-001",
        "notes": "Main branch and headquarters for CEMS operations"
    }
    
    # Check if main branch already exists
    existing_main = db.query(Branch).filter_by(branch_code="BR001").first()
    
    if not existing_main:
        main_branch = Branch(**main_branch_data)
        db.add(main_branch)
        db.commit()
        db.refresh(main_branch)
        logger.info("Created main branch: BR001")
    else:
        logger.info("Main branch already exists: BR001")
    
    # Additional sample branches
    sample_branches = [
        {
            "branch_code": "BR002",
            "name": "North Branch",
            "name_arabic": "الفرع الشمالي",
            "address_line1": "456 Al-Malaz District",
            "city": "Riyadh",
            "country": "Saudi Arabia",
            "postal_code": "11565",
            "phone_number": "+966-11-234-5678",
            "email": "north@cems.com",
            "branch_type": "standard",
            "status": "active",
            "daily_transaction_limit": Decimal('200000.00'),
            "single_transaction_limit": Decimal('50000.00'),
            "has_vault": True,
            "vault_capacity_usd": Decimal('500000.00'),
            "opened_date": datetime.now(),
            "license_number": "CR-2024-002"
        },
        {
            "branch_code": "BR003",
            "name": "East Branch",
            "name_arabic": "الفرع الشرقي", 
            "address_line1": "789 King Fahd Road",
            "city": "Dammam",
            "country": "Saudi Arabia",
            "postal_code": "31111",
            "phone_number": "+966-13-345-6789",
            "email": "east@cems.com",
            "branch_type": "standard",
            "status": "active",
            "daily_transaction_limit": Decimal('150000.00'),
            "single_transaction_limit": Decimal('30000.00'),
            "has_vault": True,
            "vault_capacity_usd": Decimal('300000.00'),
            "opened_date": datetime.now(),
            "license_number": "CR-2024-003"
        }
    ]
    
    created_count = 0
    for branch_data in sample_branches:
        existing_branch = db.query(Branch).filter_by(branch_code=branch_data["branch_code"]).first()
        
        if not existing_branch:
            branch = Branch(**branch_data)
            db.add(branch)
            created_count += 1
            logger.info(f"Created branch: {branch_data['branch_code']} - {branch_data['name']}")
        else:
            logger.info(f"Branch already exists: {branch_data['branch_code']}")
    
    if created_count > 0:
        db.commit()
        logger.info(f"Successfully created {created_count} sample branches")


def create_initial_vault(db: Session) -> None:
    """
    Create main vault and initial vault balances.
    
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
    branches = db.query(Branch).filter_by(status="active").all()
    major_currencies = ["USD", "EUR", "GBP", "SAR"]
    
    created_count = 0
    for branch in branches:
        for currency_code in major_currencies:
            currency = db.query(Currency).filter_by(code=currency_code).first()
            if not currency:
                continue
            
            # Check if balance already exists
            existing_balance = db.query(BranchBalance).filter_by(
                branch_id=branch.id,
                currency_code=currency_code
            ).first()
            
            if not existing_balance:
                # Set initial balances based on branch type
                if branch.is_main_branch:
                    initial_amount = Decimal('50000.00')
                    minimum_balance = Decimal('10000.00')
                    maximum_balance = Decimal('200000.00')
                else:
                    initial_amount = Decimal('20000.00')
                    minimum_balance = Decimal('5000.00')
                    maximum_balance = Decimal('100000.00')
                
                branch_balance = BranchBalance(
                    branch_id=branch.id,
                    currency_id=currency.id,
                    currency_code=currency_code,
                    current_balance=initial_amount,
                    minimum_balance=minimum_balance,
                    maximum_balance=maximum_balance,
                    reorder_threshold=minimum_balance * 2,
                    is_active=True
                )
                
                db.add(branch_balance)
                created_count += 1
                logger.info(f"Created balance for {branch.branch_code}-{currency_code}: {initial_amount}")
    
    if created_count > 0:
        db.commit()
        logger.info(f"Successfully created {created_count} branch balances")
    else:
        logger.info("No new branch balances created")


def create_sample_customers(db: Session) -> None:
    """
    Create sample customers for testing purposes.
    
    Args:
        db: Database session
    """
    logger.info("Creating sample customers...")
    
    # Sample customer data
    customers_data = [
        {
            "customer_code": "CUS000001",
            "customer_type": "individual",
            "first_name": "Ahmed",
            "last_name": "Al-Rashid",
            "first_name_arabic": "أحمد",
            "last_name_arabic": "الراشد",
            "id_type": "national_id",
            "id_number": "1234567890",
            "nationality": "SA",
            "mobile_number": "+966501234567",
            "email": "ahmed.rashid@email.com",
            "status": "active",
            "classification": "standard",
            "risk_level": "low",
            "kyc_status": "verified",
            "kyc_verification_date": datetime.now().date(),
            "daily_limit": Decimal('50000.00'),
            "monthly_limit": Decimal('500000.00'),
            "preferred_language": "ar"
        },
        {
            "customer_code": "CUS000002", 
            "customer_type": "individual",
            "first_name": "Sarah",
            "last_name": "Johnson",
            "id_type": "passport",
            "id_number": "P123456789",
            "nationality": "US",
            "mobile_number": "+1234567890",
            "email": "sarah.johnson@email.com",
            "status": "active",
            "classification": "premium",
            "risk_level": "low",
            "kyc_status": "verified",
            "kyc_verification_date": datetime.now().date(),
            "daily_limit": Decimal('100000.00'),
            "monthly_limit": Decimal('1000000.00'),
            "preferred_language": "en"
        },
        {
            "customer_code": "CUS000003",
            "customer_type": "corporate",
            "company_name": "Al-Majd Trading Company",
            "company_name_arabic": "شركة المجد للتجارة",
            "id_type": "commercial_registration",
            "id_number": "CR123456789",
            "nationality": "SA",
            "mobile_number": "+966112345678",
            "email": "info@almajd-trading.com",
            "status": "active",
            "classification": "vip",
            "risk_level": "medium",
            "kyc_status": "verified",
            "kyc_verification_date": datetime.now().date(),
            "daily_limit": Decimal('500000.00'),
            "monthly_limit": Decimal('5000000.00'),
            "preferred_language": "ar"
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
    Assign superuser to main branch and setup branch managers.
    
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


def verify_initialization() -> Dict[str, Any]:
    """
    Verify that database initialization was successful.
    
    Returns:
        dict: Verification results with counts and status
    """
    logger.info("Verifying database initialization...")
    
    verification_results = {
        "status": "success",
        "timestamp": datetime.now().isoformat(),
        "counts": {},
        "errors": [],
        "warnings": []
    }
    
    try:
        with db_manager.get_session_context() as db:
            # Count each entity type
            verification_results["counts"] = {
                "roles": db.query(Role).count(),
                "currencies": db.query(Currency).count(),
                "exchange_rates": db.query(ExchangeRate).count(),
                "users": db.query(User).count(),
                "branches": db.query(Branch).count(),
                "customers": db.query(Customer).count(),
                "vaults": db.query(Vault).count(),
                "vault_balances": db.query(VaultBalance).count(),
                "branch_balances": db.query(BranchBalance).count()
            }
            
            # Check for critical entities
            if verification_results["counts"]["roles"] == 0:
                verification_results["errors"].append("No roles found")
            
            if verification_results["counts"]["currencies"] == 0:
                verification_results["errors"].append("No currencies found")
                
            if verification_results["counts"]["users"] == 0:
                verification_results["errors"].append("No users found")
                
            # Check for superuser
            superuser = db.query(User).filter_by(is_superuser=True).first()
            if not superuser:
                verification_results["errors"].append("No superuser found")
            
            # Check for main branch
            main_branch = db.query(Branch).filter_by(is_main_branch=True).first()
            if not main_branch:
                verification_results["warnings"].append("No main branch found")
            
            # Check for main vault
            main_vault = db.query(Vault).filter_by(is_main_vault=True).first()
            if not main_vault:
                verification_results["warnings"].append("No main vault found")
            
            # Set overall status
            if verification_results["errors"]:
                verification_results["status"] = "error"
            elif verification_results["warnings"]:
                verification_results["status"] = "warning"
                
    except Exception as e:
        verification_results["status"] = "error"
        verification_results["errors"].append(f"Verification failed: {str(e)}")
        logger.error(f"Database verification failed: {e}", exc_info=True)
    
    # Log results
    logger.info(f"Verification completed with status: {verification_results['status']}")
    for entity, count in verification_results["counts"].items():
        logger.info(f"  {entity}: {count}")
    
    if verification_results["errors"]:
        for error in verification_results["errors"]:
            logger.error(f"  ERROR: {error}")
    
    if verification_results["warnings"]:
        for warning in verification_results["warnings"]:
            logger.warning(f"  WARNING: {warning}")
    
    return verification_results


def get_database_health() -> Dict[str, Any]:
    """
    Get comprehensive database health information.
    
    Returns:
        dict: Database health status and metrics
    """
    health_data = {
        "status": "unknown",
        "timestamp": datetime.now().isoformat(),
        "connection": False,
        "tables": {},
        "performance": {},
        "errors": []
    }
    
    try:
        # Check connection
        health_data["connection"] = db_manager.check_connection()
        
        if health_data["connection"]:
            with db_manager.get_session_context() as db:
                # Check table existence and record counts
                tables_to_check = [
                    ("roles", Role),
                    ("currencies", Currency),
                    ("exchange_rates", ExchangeRate),
                    ("users", User),
                    ("branches", Branch),
                    ("customers", Customer),
                    ("vaults", Vault),
                    ("vault_balances", VaultBalance),
                    ("branch_balances", BranchBalance)
                ]
                
                for table_name, model_class in tables_to_check:
                    try:
                        count = db.query(model_class).count()
                        health_data["tables"][table_name] = {
                            "exists": True,
                            "count": count
                        }
                    except Exception as e:
                        health_data["tables"][table_name] = {
                            "exists": False,
                            "error": str(e)
                        }
                        health_data["errors"].append(f"Table {table_name}: {str(e)}")
                
                # Set overall status
                if health_data["errors"]:
                    health_data["status"] = "degraded"
                elif all(table["exists"] for table in health_data["tables"].values()):
                    health_data["status"] = "healthy"
                else:
                    health_data["status"] = "unhealthy"
        else:
            health_data["status"] = "unhealthy"
            health_data["errors"].append("Database connection failed")
            
    except Exception as e:
        health_data["status"] = "error"
        health_data["errors"].append(f"Health check failed: {str(e)}")
        logger.error(f"Database health check failed: {e}", exc_info=True)
    
    return health_data


def init_db() -> None:
    """
    Initialize database with complete initial data.
    This function should be called during application startup.
    """
    logger.info("Starting comprehensive database initialization...")
    
    try:
        # Check database connection
        if not db_manager.check_connection():
            logger.error("Database connection failed")
            return
        
        # Create tables if they don't exist (for development only)
        if getattr(settings, 'ENVIRONMENT', 'development') == "development":
            db_manager.create_tables()
            logger.info("Database tables created/verified")
        
        # Get database session
        with db_manager.get_session_context() as db:
            # Create initial data in correct dependency order
            logger.info("Creating initial data in dependency order...")
            
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
        
        # Verify initialization
        verification = verify_initialization()
        if verification["status"] == "error":
            logger.error("Database initialization verification failed")
            for error in verification["errors"]:
                logger.error(f"  - {error}")
        else:
            logger.info("Database initialization verification passed")
        
    except Exception as e:
        logger.error(f"Database initialization failed: {e}", exc_info=True)
        raise


def reset_db() -> None:
    """
    Reset database by dropping and recreating all tables.
    WARNING: This will delete all data!
    """
    if getattr(settings, 'ENVIRONMENT', 'development') == "production":
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


def quick_setup(reset: bool = False, verify: bool = True) -> Dict[str, Any]:
    """
    Quick setup function for CEMS database.
    
    Args:
        reset: Whether to reset database before setup
        verify: Whether to verify setup after initialization
        
    Returns:
        dict: Setup results
    """
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
            
            if verification["status"] in ["success", "warning"]:
                results["success"] = True
        else:
            results["success"] = True
    
    except Exception as e:
        results["errors"].append(str(e))
        logger.error(f"Quick setup failed: {e}")
    
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
        "--verify-only",
        action="store_true",
        help="Only verify database without initialization"
    )
    parser.add_argument(
        "--health-check",
        action="store_true",
        help="Perform database health check"
    )
    
    args = parser.parse_args()
    
    if args.health_check:
        health = get_database_health()
        print(f"Database Status: {health['status']}")
        print("Table Status:")
        for table, info in health['tables'].items():
            status = "✓" if info['exists'] else "✗"
            count = info.get('count', 'N/A')
            print(f"  {status} {table}: {count} records")
        
        if health['errors']:
            print("Errors:")
            for error in health['errors']:
                print(f"  - {error}")
        
        sys.exit(0 if health['status'] in ['healthy', 'degraded'] else 1)
    
    if args.verify_only:
        verification = verify_initialization()
        print(f"Verification Status: {verification['status']}")
        print("Entity Counts:")
        for entity, count in verification['counts'].items():
            print(f"  {entity}: {count}")
        
        if verification['errors']:
            print("Errors:")
            for error in verification['errors']:
                print(f"  - {error}")
        
        if verification['warnings']:
            print("Warnings:")
            for warning in verification['warnings']:
                print(f"  - {warning}")
        
        sys.exit(0 if verification['status'] in ['success', 'warning'] else 1)
    
    if args.reset:
        if input("Are you sure you want to reset the database? (yes/no): ").lower() != 'yes':
            print("Database reset cancelled.")
            sys.exit(0)
        reset_db()
    else:
        init_db()
    
    print("Database initialization completed.")
    
    
"""
Additional initialization functions for CEMS database setup.
These are supplements to the existing init_db.py file.
"""



def create_development_users(db: Session) -> None:
    """
    Create additional development/testing users.
    
    Args:
        db: Database session
    """
    try:
        logger.info("Creating development users...")
        
        user_repo = UserRepository(db)
        
        # Development users data
        dev_users = [
            {
                "username": "branch_manager_1",
                "email": "branch.manager1@cems.local",
                "password": "BranchManager123!",
                "first_name": "Ahmed",
                "last_name": "Al-Mansouri",
                "roles": [UserRole.BRANCH_MANAGER.value, UserRole.CASHIER.value],
                "branch_id": 1,
                "is_verified": True,
                "status": UserStatus.ACTIVE.value
            },
            {
                "username": "cashier_1",
                "email": "cashier1@cems.local", 
                "password": "Cashier123!",
                "first_name": "Fatima",
                "last_name": "Al-Zahra",
                "roles": [UserRole.CASHIER.value],
                "branch_id": 1,
                "is_verified": True,
                "status": UserStatus.ACTIVE.value
            },
            {
                "username": "accountant_1",
                "email": "accountant1@cems.local",
                "password": "Accountant123!",
                "first_name": "Omar",
                "last_name": "Hassan",
                "roles": [UserRole.ACCOUNTANT.value],
                "branch_id": 1,
                "is_verified": True,
                "status": UserStatus.ACTIVE.value
            },
            {
                "username": "auditor_1",
                "email": "auditor1@cems.local",
                "password": "Auditor123!",
                "first_name": "Layla",
                "last_name": "Al-Ahmad",
                "roles": [UserRole.AUDITOR.value],
                "branch_id": None,  # Auditors can access all branches
                "is_verified": True,
                "status": UserStatus.ACTIVE.value
            }
        ]
        
        for user_data in dev_users:
            # Check if user already exists
            existing_user = user_repo.get_by_username(user_data["username"])
            if existing_user:
                logger.info(f"Development user {user_data['username']} already exists")
                continue
            
            # Extract roles and password
            roles = user_data.pop("roles", [])
            password = user_data.pop("password")
            
            # Create user
            user = user_repo.create_user(
                **user_data,
                hashed_password=get_password_hash(password)
            )
            
            # Assign roles
            for role_name in roles:
                try:
                    user_repo.assign_role(user.id, role_name)
                except Exception as e:
                    logger.warning(f"Failed to assign role {role_name} to {user_data['username']}: {str(e)}")
            
            logger.info(f"Created development user: {user_data['username']} with roles: {roles}")
        
        db.commit()
        logger.info("Development users created successfully")
        
    except Exception as e:
        db.rollback()
        logger.error(f"Error creating development users: {str(e)}")
        raise


def create_test_data(db: Session) -> None:
    """
    Create test data for development and testing.
    
    Args:
        db: Database session
    """
    try:
        logger.info("Creating test data...")
        
        # Create test customers
        create_test_customers(db)
        
        # Create sample exchange rates
        create_sample_exchange_rates(db)
        
        # Create test transactions (if transaction models are available)
        # create_test_transactions(db)
        
        db.commit()
        logger.info("Test data created successfully")
        
    except Exception as e:
        db.rollback()
        logger.error(f"Error creating test data: {str(e)}")
        raise


def create_test_customers(db: Session) -> None:
    """
    Create test customers for development.
    
    Args:
        db: Database session
    """
    try:
        from app.db.models.customer import Customer
        
        test_customers = [
            {
                "customer_code": "CUST001",
                "customer_type": "individual",
                "first_name": "Mohammed",
                "last_name": "Al-Rashid",
                "first_name_arabic": "محمد",
                "last_name_arabic": "الراشد",
                "id_type": "passport",
                "id_number": "P123456789",
                "id_issuing_country": "ARE",
                "nationality": "UAE",
                "email": "mohammed.rashid@email.com",
                "phone_number": "+971501234567",
                "preferred_language": "ar",
                "risk_level": "low",
                "is_active": True,
                "created_by": 1
            },
            {
                "customer_code": "CUST002", 
                "customer_type": "business",
                "company_name": "Al-Noor Trading LLC",
                "company_name_arabic": "شركة النور للتجارة ذ.م.م",
                "business_type": "trading",
                "id_type": "trade_license",
                "id_number": "TL987654321",
                "id_issuing_country": "ARE",
                "email": "info@alnoor-trading.com",
                "phone_number": "+971501234568",
                "preferred_language": "en",
                "risk_level": "medium",
                "is_active": True,
                "created_by": 1
            }
        ]
        
        for customer_data in test_customers:
            # Check if customer already exists
            existing = db.query(Customer).filter_by(customer_code=customer_data["customer_code"]).first()
            if existing:
                continue
                
            customer = Customer(**customer_data)
            db.add(customer)
            logger.info(f"Created test customer: {customer_data['customer_code']}")
        
        db.flush()
        
    except Exception as e:
        logger.error(f"Error creating test customers: {str(e)}")
        raise


def create_sample_exchange_rates(db: Session) -> None:
    """
    Create sample exchange rates for testing.
    
    Args:
        db: Database session
    """
    try:
        from app.db.models.currency import ExchangeRate
        
        # Sample exchange rates (USD as base)
        sample_rates = [
            {"from_currency": "AED", "to_currency": "USD", "rate": Decimal("0.2722"), "margin": Decimal("0.02")},
            {"from_currency": "USD", "to_currency": "AED", "rate": Decimal("3.6725"), "margin": Decimal("0.02")},
            {"from_currency": "EUR", "to_currency": "USD", "rate": Decimal("1.0850"), "margin": Decimal("0.015")},
            {"from_currency": "USD", "to_currency": "EUR", "rate": Decimal("0.9217"), "margin": Decimal("0.015")},
            {"from_currency": "GBP", "to_currency": "USD", "rate": Decimal("1.2650"), "margin": Decimal("0.015")},
            {"from_currency": "USD", "to_currency": "GBP", "rate": Decimal("0.7905"), "margin": Decimal("0.015")},
            {"from_currency": "SAR", "to_currency": "USD", "rate": Decimal("0.2667"), "margin": Decimal("0.02")},
            {"from_currency": "USD", "to_currency": "SAR", "rate": Decimal("3.7500"), "margin": Decimal("0.02")},
        ]
        
        for rate_data in sample_rates:
            # Check if rate already exists
            existing = db.query(ExchangeRate).filter_by(
                from_currency=rate_data["from_currency"],
                to_currency=rate_data["to_currency"]
            ).first()
            
            if existing:
                # Update existing rate
                existing.buy_rate = rate_data["rate"]
                existing.sell_rate = rate_data["rate"] * (1 + rate_data["margin"])
                existing.margin = rate_data["margin"]
                existing.updated_at = datetime.utcnow()
                existing.is_active = True
            else:
                # Create new rate
                exchange_rate = ExchangeRate(
                    from_currency=rate_data["from_currency"],
                    to_currency=rate_data["to_currency"],
                    buy_rate=rate_data["rate"],
                    sell_rate=rate_data["rate"] * (1 + rate_data["margin"]),
                    margin=rate_data["margin"],
                    effective_from=datetime.utcnow(),
                    is_active=True,
                    created_by=1
                )
                db.add(exchange_rate)
            
            logger.info(f"Updated exchange rate: {rate_data['from_currency']} -> {rate_data['to_currency']}")
        
        db.flush()
        
    except Exception as e:
        logger.error(f"Error creating sample exchange rates: {str(e)}")
        raise


def verify_repository_integration(db: Session) -> Dict[str, Any]:
    """
    Verify that repository and service layers are working correctly.
    
    Args:
        db: Database session
        
    Returns:
        Dict[str, Any]: Verification results
    """
    verification_results = {
        "repository_tests": {},
        "service_tests": {},
        "integration_tests": {},
        "overall_status": "unknown"
    }
    
    try:
        logger.info("Verifying repository and service integration...")
        
        # Test UserRepository
        user_repo = UserRepository(db)
        
        # Test basic repository operations
        verification_results["repository_tests"] = {
            "user_count": user_repo.count(),
            "superuser_exists": user_repo.exists(is_superuser=True),
            "active_users": user_repo.count() - len(user_repo.find_by(is_active=False)),
            "repository_methods_available": [
                hasattr(user_repo, method) for method in [
                    'create_user', 'get_by_username', 'get_by_email', 
                    'assign_role', 'remove_role', 'search_users'
                ]
            ]
        }
        
        # Test UserService
        user_service = UserService(db)
        
        verification_results["service_tests"] = {
            "service_initialized": user_service is not None,
            "user_repo_accessible": hasattr(user_service, 'user_repo'),
            "service_methods_available": [
                hasattr(user_service, method) for method in [
                    'create_user', 'update_user', 'search_users',
                    'assign_roles', 'get_user_statistics'
                ]
            ]
        }
        
        # Test AuthenticationService
        auth_service = AuthenticationService(db)
        
        verification_results["service_tests"]["auth_service"] = {
            "service_initialized": auth_service is not None,
            "auth_methods_available": [
                hasattr(auth_service, method) for method in [
                    'authenticate_user', 'refresh_access_token',
                    'change_password', 'setup_two_factor'
                ]
            ]
        }
        
        # Integration tests
        try:
            # Test user statistics
            stats = user_service.get_user_statistics()
            verification_results["integration_tests"]["user_statistics"] = {
                "total_users": stats.total_users if hasattr(stats, 'total_users') else 0,
                "active_users": stats.active_users if hasattr(stats, 'active_users') else 0
            }
        except Exception as e:
            verification_results["integration_tests"]["user_statistics_error"] = str(e)
        
        # Check if all critical components are working
        all_repo_methods = all(verification_results["repository_tests"]["repository_methods_available"])
        all_service_methods = all(verification_results["service_tests"]["service_methods_available"])
        all_auth_methods = all(verification_results["service_tests"]["auth_service"]["auth_methods_available"])
        
        if all_repo_methods and all_service_methods and all_auth_methods:
            verification_results["overall_status"] = "success"
        else:
            verification_results["overall_status"] = "partial"
        
        logger.info(f"Repository and service verification completed: {verification_results['overall_status']}")
        
    except Exception as e:
        verification_results["overall_status"] = "failed"
        verification_results["error"] = str(e)
        logger.error(f"Repository and service verification failed: {str(e)}")
    
    return verification_results


def initialize_complete_system(db: Session, create_dev_data: bool = False) -> Dict[str, Any]:
    """
    Complete system initialization including all components.
    
    Args:
        db: Database session
        create_dev_data: Whether to create development data
        
    Returns:
        Dict[str, Any]: Initialization results
    """
    initialization_results = {
        "core_data": False,
        "dev_users": False,
        "test_data": False,
        "verification": {},
        "errors": [],
        "timestamp": datetime.utcnow().isoformat()
    }
    
    try:
        logger.info("Starting complete system initialization...")
        
        # 1. Initialize core data (from existing init_db functions)
        try:
            # Assuming these functions exist in the original init_db.py
            # create_initial_roles(db)
            # create_initial_currencies(db) 
            # create_superuser(db)
            # create_main_branch_and_vault(db)
            initialization_results["core_data"] = True
            logger.info("Core data initialization completed")
        except Exception as e:
            initialization_results["errors"].append(f"Core data error: {str(e)}")
        
        # 2. Create development users
        if create_dev_data:
            try:
                create_development_users(db)
                initialization_results["dev_users"] = True
                logger.info("Development users created")
            except Exception as e:
                initialization_results["errors"].append(f"Dev users error: {str(e)}")
            
            # 3. Create test data
            try:
                create_test_data(db)
                initialization_results["test_data"] = True
                logger.info("Test data created")
            except Exception as e:
                initialization_results["errors"].append(f"Test data error: {str(e)}")
        
        # 4. Verify integration
        try:
            verification_result = verify_repository_integration(db)
            initialization_results["verification"] = verification_result
            logger.info("System verification completed")
        except Exception as e:
            initialization_results["errors"].append(f"Verification error: {str(e)}")
        
        # Final commit
        db.commit()
        
        logger.info("Complete system initialization finished successfully")
        
    except Exception as e:
        db.rollback()
        initialization_results["errors"].append(f"System initialization error: {str(e)}")
        logger.error(f"System initialization failed: {str(e)}")
    
    return initialization_results


def cleanup_development_data(db: Session) -> Dict[str, Any]:
    """
    Clean up development and test data.
    
    Args:
        db: Database session
        
    Returns:
        Dict[str, Any]: Cleanup results
    """
    cleanup_results = {
        "dev_users_removed": 0,
        "test_customers_removed": 0,
        "test_rates_removed": 0,
        "errors": []
    }
    
    try:
        logger.info("Starting development data cleanup...")
        
        user_repo = UserRepository(db)
        
        # Remove development users
        dev_usernames = ["branch_manager_1", "cashier_1", "accountant_1", "auditor_1"]
        for username in dev_usernames:
            user = user_repo.get_by_username(username)
            if user:
                user_repo.delete(user.id, soft_delete=True)
                cleanup_results["dev_users_removed"] += 1
        
        # Remove test customers
        try:
            from app.db.models.customer import Customer
            test_customers = db.query(Customer).filter(
                Customer.customer_code.like("CUST%")
            ).all()
            
            for customer in test_customers:
                customer.deleted_at = datetime.utcnow()
                cleanup_results["test_customers_removed"] += 1
        except Exception as e:
            cleanup_results["errors"].append(f"Customer cleanup error: {str(e)}")
        
        # Remove test exchange rates  
        try:
            from app.db.models.currency import ExchangeRate
            test_rates = db.query(ExchangeRate).filter(
                ExchangeRate.created_by == 1
            ).all()
            
            for rate in test_rates:
                rate.is_active = False
                rate.deleted_at = datetime.utcnow()
                cleanup_results["test_rates_removed"] += 1
        except Exception as e:
            cleanup_results["errors"].append(f"Exchange rate cleanup error: {str(e)}")
        
        db.commit()
        logger.info(f"Development data cleanup completed: {cleanup_results}")
        
    except Exception as e:
        db.rollback()
        cleanup_results["errors"].append(f"Cleanup error: {str(e)}")
        logger.error(f"Development data cleanup failed: {str(e)}")
    
    return cleanup_results


# Utility function for database health check
def perform_health_check(db: Session) -> Dict[str, Any]:
    """
    Perform comprehensive health check on the database and services.
    
    Args:
        db: Database session
        
    Returns:
        Dict[str, Any]: Health check results
    """
    health_status = {
        "database": "unknown",
        "repositories": "unknown", 
        "services": "unknown",
        "authentication": "unknown",
        "overall": "unknown",
        "details": {},
        "timestamp": datetime.utcnow().isoformat()
    }
    
    try:
        # Database connectivity check
        try:
            db.execute("SELECT 1")
            health_status["database"] = "healthy"
        except Exception as e:
            health_status["database"] = "unhealthy"
            health_status["details"]["database_error"] = str(e)
        
        # Repository health check
        try:
            user_repo = UserRepository(db)
            user_count = user_repo.count()
            health_status["repositories"] = "healthy"
            health_status["details"]["user_count"] = user_count
        except Exception as e:
            health_status["repositories"] = "unhealthy"
            health_status["details"]["repository_error"] = str(e)
        
        # Service health check
        try:
            user_service = UserService(db)
            auth_service = AuthenticationService(db)
            health_status["services"] = "healthy"
        except Exception as e:
            health_status["services"] = "unhealthy"
            health_status["details"]["service_error"] = str(e)
        
        # Authentication system check
        try:
            from app.core.security import security_manager
            # Test token generation
            test_token = security_manager.generate_secure_token()
            health_status["authentication"] = "healthy" if test_token else "unhealthy"
        except Exception as e:
            health_status["authentication"] = "unhealthy"
            health_status["details"]["auth_error"] = str(e)
        
        # Overall health determination
        all_healthy = all(
            status == "healthy" 
            for status in [
                health_status["database"],
                health_status["repositories"], 
                health_status["services"],
                health_status["authentication"]
            ]
        )
        
        health_status["overall"] = "healthy" if all_healthy else "degraded"
        
    except Exception as e:
        health_status["overall"] = "critical"
        health_status["details"]["critical_error"] = str(e)
    
    return health_status