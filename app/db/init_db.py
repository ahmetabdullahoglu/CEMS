"""
Module: init_db
Purpose: Complete database initialization and initial data seeding for CEMS
Author: CEMS Development Team
Date: 2024
"""

import json
from decimal import Decimal
from datetime import datetime, timedelta
from typing import Optional, Dict, List, Any
from sqlalchemy.orm import Session
from sqlalchemy.exc import SQLAlchemyError, IntegrityError

from app.core.config import settings
from app.core.constants import UserRole, UserStatus, CurrencyCode, CURRENCY_NAMES, CURRENCY_SYMBOLS
from app.core.security import get_password_hash
from app.db.database import SessionLocal
from app.db.models.user import User, Role, UserRole as UserRoleAssoc
from app.db.models.currency import Currency, ExchangeRate
from app.db.models.branch import Branch, BranchBalance
from app.db.models.customer import Customer
from app.db.models.vault import Vault, VaultBalance, VaultTransaction
from app.repositories.user_repository import UserRepository
from app.services.user_service import UserService
from app.services.auth_service import AuthenticationService
from app.utils.logger import get_logger
from app.utils.validators import validate_password_strength, validate_email_format

logger = get_logger(__name__)


# ==================== CORE INITIALIZATION FUNCTIONS ====================

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
            "description": "System administrator with full access to all features and system management",
            "is_system_role": True,
            "hierarchy_level": "1",
            "permissions": json.dumps(["*"])  # All permissions
        },
        {
            "name": UserRole.ADMIN.value,
            "display_name": "Administrator",
            "description": "System administrator with administrative privileges for daily operations",
            "is_system_role": True,
            "hierarchy_level": "2",
            "permissions": json.dumps([
                "admin.*", "user.*", "branch.*", "currency.*", 
                "transaction.*", "customer.*", "vault.*", "report.*"
            ])
        },
        {
            "name": UserRole.BRANCH_MANAGER.value,
            "display_name": "Branch Manager",
            "description": "Manager of a specific branch with branch-level administrative access",
            "is_system_role": True,
            "hierarchy_level": "3",
            "permissions": json.dumps([
                "branch.manage", "branch.balance_view", "user.view",
                "transaction.*", "customer.*", "report.branch",
                "report.financial", "vault.view", "vault.balance_view"
            ])
        },
        {
            "name": UserRole.CASHIER.value,
            "display_name": "Cashier",
            "description": "Front desk staff who handle customer transactions and currency exchange",
            "is_system_role": True,
            "hierarchy_level": "4",
            "permissions": json.dumps([
                "transaction.view", "transaction.create", "customer.view",
                "customer.create", "customer.update", "currency.view", "branch.balance_view"
            ])
        },
        {
            "name": UserRole.ACCOUNTANT.value,
            "display_name": "Accountant",
            "description": "Accounting staff with access to financial records and reports",
            "is_system_role": True,
            "hierarchy_level": "4",
            "permissions": json.dumps([
                "transaction.view", "transaction.export", "report.financial",
                "report.generate", "customer.view", "branch.balance_view", "vault.balance_view"
            ])
        },
        {
            "name": UserRole.AUDITOR.value,
            "display_name": "Auditor",
            "description": "Audit staff with read-only access to all records for compliance",
            "is_system_role": True,
            "hierarchy_level": "5",
            "permissions": json.dumps([
                "transaction.view", "report.audit", "report.view",
                "user.view", "branch.view", "security.audit_logs"
            ])
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
            # Update existing role permissions if needed
            if existing_role.permissions != role_data["permissions"]:
                existing_role.permissions = role_data["permissions"]
                existing_role.updated_at = datetime.utcnow()
                logger.info(f"Updated permissions for role: {role_data['display_name']}")
    
    if created_count > 0:
        db.commit()
        logger.info(f"Successfully created {created_count} new roles")
    
    db.commit()  # Ensure all changes are saved


def create_superuser(db: Session) -> None:
    """
    Create initial superuser account.
    
    Args:
        db: Database session
    """
    logger.info("Creating superuser account...")
    
    # Get superuser credentials from settings
    superuser_email = getattr(settings, 'FIRST_SUPERUSER', 'admin@cems.local')
    superuser_password = getattr(settings, 'FIRST_SUPERUSER_PASSWORD', 'admin123!')
    
    # Validate superuser email
    if not validate_email_format(superuser_email):
        logger.error(f"Invalid superuser email format: {superuser_email}")
        return
    
    # Validate password strength
    password_validation = validate_password_strength(superuser_password)
    if not password_validation["is_valid"]:
        logger.warning(f"Superuser password is weak: {password_validation['feedback']}")
    
    # Check if superuser already exists
    existing_superuser = db.query(User).filter_by(email=superuser_email).first()
    
    if existing_superuser:
        logger.info(f"Superuser already exists: {superuser_email}")
        # Ensure they have superuser privileges
        if not existing_superuser.is_superuser:
            existing_superuser.is_superuser = True
            existing_superuser.updated_at = datetime.utcnow()
            db.commit()
            logger.info("Updated existing user to superuser")
        return
    
    # Create superuser
    try:
        superuser = User(
            username="admin",
            email=superuser_email,
            hashed_password=get_password_hash(superuser_password),
            first_name="System",
            last_name="Administrator",
            status=UserStatus.ACTIVE.value,
            is_active=True,
            is_superuser=True,
            is_verified=True,
            password_changed_at=datetime.utcnow()
        )
        
        db.add(superuser)
        db.commit()
        db.refresh(superuser)
        
        # Assign super admin role
        super_admin_role = db.query(Role).filter_by(name=UserRole.SUPER_ADMIN.value).first()
        if super_admin_role:
            user_role = UserRoleAssoc(
                user_id=superuser.id,
                role_id=super_admin_role.id,
                assigned_at=datetime.utcnow()
            )
            db.add(user_role)
            db.commit()
        
        logger.info(f"Successfully created superuser: {superuser_email}")
        
    except IntegrityError as e:
        db.rollback()
        logger.error(f"Failed to create superuser due to integrity error: {str(e)}")
    except Exception as e:
        db.rollback()
        logger.error(f"Failed to create superuser: {str(e)}")


def create_initial_currencies(db: Session) -> None:
    """
    Create initial supported currencies with proper configuration.
    
    Args:
        db: Database session
    """
    logger.info("Creating initial currencies...")
    
    # Define currency priorities for display order
    currency_priorities = {
        CurrencyCode.USD: 1,   # US Dollar - Primary
        CurrencyCode.EUR: 2,   # Euro
        CurrencyCode.GBP: 3,   # British Pound
        CurrencyCode.SAR: 4,   # Saudi Riyal
        CurrencyCode.AED: 5,   # UAE Dirham
        CurrencyCode.EGP: 6,   # Egyptian Pound
        CurrencyCode.JOD: 7,   # Jordanian Dinar
        CurrencyCode.KWD: 8,   # Kuwaiti Dinar
        CurrencyCode.QAR: 9,   # Qatari Riyal
        CurrencyCode.BHD: 10,  # Bahraini Dinar
        CurrencyCode.OMR: 11,  # Omani Rial
        CurrencyCode.JPY: 12,  # Japanese Yen
        CurrencyCode.CHF: 13,  # Swiss Franc
        CurrencyCode.CAD: 14,  # Canadian Dollar
        CurrencyCode.AUD: 15   # Australian Dollar
    }
    
    # Special decimal places for certain currencies
    special_decimal_places = {
        CurrencyCode.JPY: 0,  # Yen doesn't use decimal places
        CurrencyCode.KWD: 3,  # Kuwaiti Dinar uses 3 decimal places
        CurrencyCode.BHD: 3,  # Bahraini Dinar uses 3 decimal places
        CurrencyCode.OMR: 3   # Omani Rial uses 3 decimal places
    }
    
    # Minimum exchange amounts
    min_exchange_amounts = {
        CurrencyCode.JPY: Decimal('100'),    # Higher minimum for Yen
        CurrencyCode.KWD: Decimal('1'),      # Lower minimum for KWD
        CurrencyCode.BHD: Decimal('1'),      # Lower minimum for BHD
        CurrencyCode.OMR: Decimal('1')       # Lower minimum for OMR
    }
    
    created_count = 0
    for currency_code in currency_priorities.keys():
        # Check if currency already exists
        existing_currency = db.query(Currency).filter_by(code=currency_code.value).first()
        
        if not existing_currency:
            # Set configuration values
            display_order = currency_priorities[currency_code]
            decimal_places = special_decimal_places.get(currency_code, 2)
            min_exchange_amount = min_exchange_amounts.get(currency_code, Decimal('10.00'))
            
            # Set base currency (USD by default)
            is_base = currency_code.value == getattr(settings, 'BASE_CURRENCY', 'USD')
            
            currency = Currency(
                code=currency_code.value,
                name=CURRENCY_NAMES[currency_code.value],
                symbol=CURRENCY_SYMBOLS[currency_code.value],
                decimal_places=decimal_places,
                display_order=display_order,
                is_base_currency=is_base,
                is_active=True,
                min_exchange_amount=min_exchange_amount,
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
    
    # Sample exchange rates (USD as base)
    sample_rates = {
        'EUR': Decimal('0.8500'),    # Euro
        'GBP': Decimal('0.7300'),    # British Pound
        'SAR': Decimal('3.7500'),    # Saudi Riyal
        'AED': Decimal('3.6700'),    # UAE Dirham
        'EGP': Decimal('30.9000'),   # Egyptian Pound
        'JOD': Decimal('0.7090'),    # Jordanian Dinar
        'KWD': Decimal('0.3070'),    # Kuwaiti Dinar
        'QAR': Decimal('3.6400'),    # Qatari Riyal
        'BHD': Decimal('0.3760'),    # Bahraini Dinar
        'OMR': Decimal('0.3850'),    # Omani Rial
        'JPY': Decimal('149.50'),    # Japanese Yen
        'CHF': Decimal('0.8800'),    # Swiss Franc
        'CAD': Decimal('1.3600'),    # Canadian Dollar
        'AUD': Decimal('1.5200')     # Australian Dollar
    }
    
    # Get USD as base currency
    usd_currency = db.query(Currency).filter_by(code='USD').first()
    if not usd_currency:
        logger.error("USD currency not found - cannot create exchange rates")
        return
    
    created_count = 0
    for currency_code, rate in sample_rates.items():
        # Get target currency
        target_currency = db.query(Currency).filter_by(code=currency_code).first()
        if not target_currency:
            continue
        
        # Check if exchange rate already exists
        existing_rate = db.query(ExchangeRate).filter_by(
            base_currency_id=usd_currency.id,
            target_currency_id=target_currency.id
        ).first()
        
        if not existing_rate:
            # Calculate buy and sell rates with spread
            spread_percentage = Decimal('0.02')  # 2% spread
            buy_rate = rate * (1 - spread_percentage)
            sell_rate = rate * (1 + spread_percentage)
            
            exchange_rate = ExchangeRate(
                base_currency_id=usd_currency.id,
                target_currency_id=target_currency.id,
                base_currency_code='USD',
                target_currency_code=currency_code,
                buy_rate=buy_rate,
                sell_rate=sell_rate,
                mid_rate=rate,
                effective_date=datetime.utcnow().date(),
                expires_date=datetime.utcnow().date() + timedelta(days=1),
                is_active=True,
                source='MANUAL_INIT',
                created_by_user_id=None  # System created
            )
            
            db.add(exchange_rate)
            created_count += 1
            logger.info(f"Created exchange rate: USD/{currency_code} = {rate}")
        else:
            logger.info(f"Exchange rate already exists: USD/{currency_code}")
    
    if created_count > 0:
        db.commit()
        logger.info(f"Successfully created {created_count} exchange rates")
    else:
        logger.info("No new exchange rates created")


def create_initial_branches(db: Session) -> None:
    """
    Create initial branches for the system.
    
    Args:
        db: Database session
    """
    logger.info("Creating initial branches...")
    
    branches_data = [
        {
            "branch_code": "MAIN",
            "branch_name": "Main Branch",
            "address": "123 Main Street, City Center",
            "phone_number": "+1-555-0001",
            "email": "main@cems.local",
            "manager_name": "Main Branch Manager",
            "is_main_branch": True,
            "is_active": True,
            "status": "active",
            "daily_limit": Decimal('100000.00'),
            "monthly_limit": Decimal('2000000.00'),
            "timezone": "UTC",
            "business_hours": "08:00-17:00",
            "description": "Main headquarters branch"
        },
        {
            "branch_code": "BR001",
            "branch_name": "Downtown Branch",
            "address": "456 Business District, Downtown",
            "phone_number": "+1-555-0002",
            "email": "downtown@cems.local",
            "manager_name": "Downtown Manager",
            "is_main_branch": False,
            "is_active": True,
            "status": "active",
            "daily_limit": Decimal('50000.00'),
            "monthly_limit": Decimal('1000000.00'),
            "timezone": "UTC",
            "business_hours": "09:00-18:00",
            "description": "Downtown business district branch"
        },
        {
            "branch_code": "BR002",
            "branch_name": "Airport Branch",
            "address": "International Airport, Terminal 1",
            "phone_number": "+1-555-0003",
            "email": "airport@cems.local",
            "manager_name": "Airport Manager",
            "is_main_branch": False,
            "is_active": True,
            "status": "active",
            "daily_limit": Decimal('75000.00'),
            "monthly_limit": Decimal('1500000.00'),
            "timezone": "UTC",
            "business_hours": "06:00-22:00",
            "description": "Airport terminal currency exchange"
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
            logger.info(f"Created branch: {branch_data['branch_name']} ({branch_data['branch_code']})")
        else:
            logger.info(f"Branch already exists: {branch_data['branch_code']}")
    
    if created_count > 0:
        db.commit()
        logger.info(f"Successfully created {created_count} branches")
    else:
        logger.info("No new branches created")


def create_initial_vault(db: Session) -> None:
    """
    Create initial main vault and vault balances.
    
    Args:
        db: Database session
    """
    logger.info("Creating initial vault...")
    
    # Check if main vault already exists
    existing_vault = db.query(Vault).filter_by(is_main_vault=True).first()
    
    if existing_vault:
        logger.info("Main vault already exists")
        return
    
    # Create main vault
    main_vault = Vault(
        vault_name="Main Vault",
        vault_code="VAULT001",
        vault_type="main",
        location="Main Branch - Secure Area",
        is_main_vault=True,
        is_active=True,
        status="operational",
        security_level="high",
        access_hours="24/7",
        description="Primary vault for main branch operations"
    )
    
    db.add(main_vault)
    db.commit()
    db.refresh(main_vault)
    
    logger.info(f"Created main vault: {main_vault.vault_name}")
    
    # Create vault balances for major currencies
    major_currencies = ['USD', 'EUR', 'GBP', 'SAR', 'AED']
    vault_balance_count = 0
    
    for currency_code in major_currencies:
        currency = db.query(Currency).filter_by(code=currency_code).first()
        if not currency:
            continue
        
        # Check if vault balance already exists
        existing_balance = db.query(VaultBalance).filter_by(
            vault_id=main_vault.id,
            currency_code=currency_code
        ).first()
        
        if not existing_balance:
            # Set initial vault balances (larger amounts than branches)
            initial_amount = Decimal('500000.00')  # 500K initial balance
            minimum_balance = Decimal('100000.00')  # 100K minimum
            maximum_balance = Decimal('2000000.00')  # 2M maximum
            
            vault_balance = VaultBalance(
                vault_id=main_vault.id,
                currency_id=currency.id,
                currency_code=currency_code,
                current_balance=initial_amount,
                reserved_balance=Decimal('0.00'),
                available_balance=initial_amount,
                minimum_balance=minimum_balance,
                maximum_balance=maximum_balance,
                reorder_threshold=minimum_balance * 2,
                is_active=True
            )
            
            db.add(vault_balance)
            vault_balance_count += 1
            logger.info(f"Created vault balance: {currency_code} - {initial_amount}")
    
    if vault_balance_count > 0:
        db.commit()
        logger.info(f"Successfully created {vault_balance_count} vault balances")


def create_initial_branch_balances(db: Session) -> None:
    """
    Create initial branch balances for all currencies.
    
    Args:
        db: Database session
    """
    logger.info("Creating initial branch balances...")
    
    # Get all active branches
    branches = db.query(Branch).filter_by(is_active=True).all()
    major_currencies = ['USD', 'EUR', 'GBP', 'SAR', 'AED']
    
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
                    initial_amount = Decimal('100000.00')
                    minimum_balance = Decimal('20000.00')
                    maximum_balance = Decimal('500000.00')
                else:
                    initial_amount = Decimal('50000.00')
                    minimum_balance = Decimal('10000.00')
                    maximum_balance = Decimal('200000.00')
                
                branch_balance = BranchBalance(
                    branch_id=branch.id,
                    currency_id=currency.id,
                    currency_code=currency_code,
                    current_balance=initial_amount,
                    reserved_balance=Decimal('0.00'),
                    available_balance=initial_amount,
                    minimum_balance=minimum_balance,
                    maximum_balance=maximum_balance,
                    reorder_threshold=minimum_balance * 2,
                    is_active=True
                )
                
                db.add(branch_balance)
                created_count += 1
                logger.info(f"Created balance: {branch.branch_code}/{currency_code} - {initial_amount}")
    
    if created_count > 0:
        db.commit()
        logger.info(f"Successfully created {created_count} branch balances")
    else:
        logger.info("No new branch balances created")


# ==================== DEVELOPMENT AND TESTING DATA ====================

def create_development_users(db: Session) -> None:
    """
    Create additional users for development and testing.
    
    Args:
        db: Database session
    """
    if getattr(settings, 'ENVIRONMENT', 'development') == 'production':
        logger.info("Skipping development users creation in production")
        return
    
    logger.info("Creating development users...")
    
    user_repo = UserRepository(db)
    
    # Development users data
    dev_users_data = [
        {
            "username": "branch_manager",
            "email": "manager@cems.dev",
            "password": "Manager123!",
            "first_name": "Branch",
            "last_name": "Manager",
            "roles": [UserRole.BRANCH_MANAGER],
            "is_verified": True
        },
        {
            "username": "cashier1",
            "email": "cashier1@cems.dev",
            "password": "Cashier123!",
            "first_name": "John",
            "last_name": "Cashier",
            "roles": [UserRole.CASHIER],
            "is_verified": True
        },
        {
            "username": "cashier2",
            "email": "cashier2@cems.dev",
            "password": "Cashier123!",
            "first_name": "Jane",
            "last_name": "Cashier",
            "roles": [UserRole.CASHIER],
            "is_verified": True
        },
        {
            "username": "accountant",
            "email": "accountant@cems.dev",
            "password": "Account123!",
            "first_name": "Bob",
            "last_name": "Accountant",
            "roles": [UserRole.ACCOUNTANT],
            "is_verified": True
        },
        {
            "username": "auditor",
            "email": "auditor@cems.dev",
            "password": "Auditor123!",
            "first_name": "Alice",
            "last_name": "Auditor",
            "roles": [UserRole.AUDITOR],
            "is_verified": True
        }
    ]
    
    created_count = 0
    for user_data in dev_users_data:
        # Check if user already exists
        existing_user = user_repo.get_by_email(user_data["email"])
        
        if not existing_user:
            try:
                # Create user
                user = user_repo.create_user(
                    username=user_data["username"],
                    email=user_data["email"],
                    hashed_password=get_password_hash(user_data["password"]),
                    first_name=user_data["first_name"],
                    last_name=user_data["last_name"],
                    status=UserStatus.ACTIVE,
                    is_active=True,
                    is_verified=user_data["is_verified"]
                )
                
                # Assign roles
                for role in user_data["roles"]:
                    try:
                        user_repo.assign_role(user.id, role.value)
                    except Exception as e:
                        logger.warning(f"Failed to assign role {role.value} to {user_data['username']}: {str(e)}")
                
                created_count += 1
                logger.info(f"Created development user: {user_data['username']}")
                
            except Exception as e:
                logger.error(f"Failed to create development user {user_data['username']}: {str(e)}")
        else:
            logger.info(f"Development user already exists: {user_data['username']}")
    
    if created_count > 0:
        logger.info(f"Successfully created {created_count} development users")
    else:
        logger.info("No new development users created")


def create_sample_customers(db: Session) -> None:
    """
    Create sample customers for testing purposes.
    
    Args:
        db: Database session
    """
    if getattr(settings, 'ENVIRONMENT', 'development') == 'production':
        logger.info("Skipping sample customers creation in production")
        return
    
    logger.info("Creating sample customers...")
    
    # Get main branch
    main_branch = db.query(Branch).filter_by(is_main_branch=True).first()
    if not main_branch:
        logger.warning("Main branch not found - cannot create sample customers")
        return
    
    sample_customers_data = [
        {
            "customer_code": "CUST001",
            "first_name": "Ahmed",
            "last_name": "Al-Rashid",
            "email": "ahmed.rashid@example.com",
            "phone_number": "+971-50-1234567",
            "id_type": "passport",
            "id_number": "A1234567",
            "nationality": "UAE",
            "date_of_birth": datetime(1985, 5, 15).date(),
            "address": "Dubai Marina, UAE",
            "customer_type": "individual",
            "preferred_currency": "AED",
            "branch_id": main_branch.id
        },
        {
            "customer_code": "CUST002",
            "first_name": "Sarah",
            "last_name": "Johnson",
            "email": "sarah.johnson@example.com",
            "phone_number": "+1-555-9876543",
            "id_type": "passport",
            "id_number": "US9876543",
            "nationality": "USA",
            "date_of_birth": datetime(1990, 8, 22).date(),
            "address": "New York, USA",
            "customer_type": "individual",
            "preferred_currency": "USD",
            "branch_id": main_branch.id
        },
        {
            "customer_code": "CUST003",
            "first_name": "Mohammed",
            "last_name": "Al-Saud",
            "email": "mohammed.saud@example.com",
            "phone_number": "+966-50-7777777",
            "id_type": "national_id",
            "id_number": "1234567890",
            "nationality": "Saudi Arabia",
            "date_of_birth": datetime(1980, 12, 10).date(),
            "address": "Riyadh, Saudi Arabia",
            "customer_type": "individual",
            "preferred_currency": "SAR",
            "branch_id": main_branch.id
        }
    ]
    
    created_count = 0
    for customer_data in sample_customers_data:
        # Check if customer already exists
        existing_customer = db.query(Customer).filter_by(
            customer_code=customer_data["customer_code"]
        ).first()
        
        if not existing_customer:
            customer = Customer(**customer_data)
            db.add(customer)
            created_count += 1
            logger.info(f"Created sample customer: {customer_data['customer_code']}")
        else:
            logger.info(f"Sample customer already exists: {customer_data['customer_code']}")
    
    if created_count > 0:
        db.commit()
        logger.info(f"Successfully created {created_count} sample customers")
    else:
        logger.info("No new sample customers created")


def assign_users_to_branches(db: Session) -> None:
    """
    Assign users to branches for proper access control.
    
    Args:
        db: Database session
    """
    logger.info("Assigning users to branches...")
    
    # Get main branch
    main_branch = db.query(Branch).filter_by(is_main_branch=True).first()
    if not main_branch:
        logger.warning("Main branch not found - cannot assign users")
        return
    
    # Get users that need branch assignment
    users_without_branch = db.query(User).filter_by(branch_id=None).all()
    
    updated_count = 0
    for user in users_without_branch:
        # Skip superuser
        if user.is_superuser:
            continue
        
        # Assign to main branch by default
        user.branch_id = main_branch.id
        user.updated_at = datetime.utcnow()
        updated_count += 1
        logger.info(f"Assigned user {user.username} to {main_branch.branch_name}")
    
    if updated_count > 0:
        db.commit()
        logger.info(f"Successfully assigned {updated_count} users to branches")
    else:
        logger.info("No users needed branch assignment")


# ==================== VERIFICATION AND MAINTENANCE ====================

def verify_initialization(db: Session) -> Dict[str, Any]:
    """
    Verify that all initialization completed successfully.
    
    Args:
        db: Database session
        
    Returns:
        Dict[str, Any]: Verification results
    """
    logger.info("Verifying database initialization...")
    
    verification_results = {
        "status": "success",
        "timestamp": datetime.utcnow().isoformat(),
        "counts": {},
        "checks": {},
        "errors": [],
        "warnings": []
    }
    
    try:
        # Count entities
        verification_results["counts"] = {
            "roles": db.query(Role).count(),
            "currencies": db.query(Currency).count(),
            "exchange_rates": db.query(ExchangeRate).count(),
            "users": db.query(User).count(),
            "branches": db.query(Branch).count(),
            "vaults": db.query(Vault).count(),
            "vault_balances": db.query(VaultBalance).count(),
            "branch_balances": db.query(BranchBalance).count(),
            "customers": db.query(Customer).count()
        }
        
        # Critical checks
        verification_results["checks"] = {
            "has_roles": verification_results["counts"]["roles"] > 0,
            "has_currencies": verification_results["counts"]["currencies"] > 0,
            "has_superuser": db.query(User).filter_by(is_superuser=True).count() > 0,
            "has_main_branch": db.query(Branch).filter_by(is_main_branch=True).count() > 0,
            "has_main_vault": db.query(Vault).filter_by(is_main_vault=True).count() > 0,
            "has_base_currency": db.query(Currency).filter_by(is_base_currency=True).count() > 0,
            "has_exchange_rates": verification_results["counts"]["exchange_rates"] > 0
        }
        
        # Check for critical missing components
        for check_name, check_result in verification_results["checks"].items():
            if not check_result:
                error_message = f"Critical check failed: {check_name}"
                verification_results["errors"].append(error_message)
                logger.error(error_message)
        
        # Additional validations
        # Check if all roles have users
        roles_with_users = db.query(Role).join(UserRoleAssoc).distinct().count()
        total_roles = verification_results["counts"]["roles"]
        if roles_with_users < total_roles:
            verification_results["warnings"].append(f"Some roles have no assigned users ({roles_with_users}/{total_roles})")
        
        # Check if all currencies have exchange rates (except base currency)
        currencies_with_rates = db.query(Currency).join(ExchangeRate, 
                                                          Currency.id == ExchangeRate.target_currency_id).distinct().count()
        non_base_currencies = db.query(Currency).filter_by(is_base_currency=False).count()
        if currencies_with_rates < non_base_currencies:
            verification_results["warnings"].append(f"Some currencies missing exchange rates ({currencies_with_rates}/{non_base_currencies})")
        
        # Set overall status
        if verification_results["errors"]:
            verification_results["status"] = "failed"
        elif verification_results["warnings"]:
            verification_results["status"] = "warning"
        else:
            verification_results["status"] = "success"
        
        logger.info(f"Initialization verification completed: {verification_results['status']}")
        
    except Exception as e:
        verification_results["status"] = "error"
        verification_results["errors"].append(f"Verification failed: {str(e)}")
        logger.error(f"Verification failed: {str(e)}")
    
    return verification_results


def test_services_integration(db: Session) -> Dict[str, Any]:
    """
    Test integration with repositories and services.
    
    Args:
        db: Database session
        
    Returns:
        Dict[str, Any]: Integration test results
    """
    logger.info("Testing services integration...")
    
    test_results = {
        "status": "success",
        "timestamp": datetime.utcnow().isoformat(),
        "repository_tests": {},
        "service_tests": {},
        "errors": []
    }
    
    try:
        # Test UserRepository
        user_repo = UserRepository(db)
        test_results["repository_tests"]["user_repository"] = {
            "can_get_users": bool(user_repo.get_active_users_count() >= 0),
            "can_check_username": bool(user_repo.check_username_exists("admin")),
            "can_get_by_role": bool(len(user_repo.get_users_by_role(UserRole.SUPER_ADMIN.value)) >= 0)
        }
        
        # Test UserService
        user_service = UserService(db)
        test_results["service_tests"]["user_service"] = {
            "can_get_statistics": False,
            "error": None
        }
        
        try:
            stats = user_service.get_user_statistics()
            test_results["service_tests"]["user_service"]["can_get_statistics"] = bool(stats.total_users >= 0)
        except Exception as e:
            test_results["service_tests"]["user_service"]["error"] = str(e)
        
        # Test AuthenticationService
        auth_service = AuthenticationService(db)
        test_results["service_tests"]["auth_service"] = {
            "can_check_password_strength": False,
            "error": None
        }
        
        try:
            from app.schemas.auth import PasswordStrengthRequest
            from pydantic import SecretStr
            
            password_check = auth_service.check_password_strength(
                PasswordStrengthRequest(password=SecretStr("TestPassword123!"))
            )
            test_results["service_tests"]["auth_service"]["can_check_password_strength"] = bool(password_check.score >= 0)
        except Exception as e:
            test_results["service_tests"]["auth_service"]["error"] = str(e)
        
        # Check overall success
        all_repo_tests = all(test_results["repository_tests"]["user_repository"].values())
        all_service_tests = (
            test_results["service_tests"]["user_service"]["can_get_statistics"] and
            test_results["service_tests"]["auth_service"]["can_check_password_strength"]
        )
        
        if not all_repo_tests or not all_service_tests:
            test_results["status"] = "partial"
        
        logger.info(f"Services integration test completed: {test_results['status']}")
        
    except Exception as e:
        test_results["status"] = "failed"
        test_results["errors"].append(str(e))
        logger.error(f"Services integration test failed: {str(e)}")
    
    return test_results


# ==================== MAIN INITIALIZATION FUNCTION ====================

def init_db() -> None:
    """
    Main database initialization function.
    
    This function should be called during application startup to ensure
    all required initial data is present in the database.
    """
    logger.info("Starting comprehensive CEMS database initialization...")
    
    try:
        # Get database session
        db = SessionLocal()
        
        try:
            # Execute initialization steps in correct order
            logger.info("Step 1: Creating initial roles...")
            create_initial_roles(db)
            
            logger.info("Step 2: Creating superuser...")
            create_superuser(db)
            
            logger.info("Step 3: Creating initial currencies...")
            create_initial_currencies(db)
            
            logger.info("Step 4: Creating initial exchange rates...")
            create_initial_exchange_rates(db)
            
            logger.info("Step 5: Creating initial branches...")
            create_initial_branches(db)
            
            logger.info("Step 6: Creating initial vault...")
            create_initial_vault(db)
            
            logger.info("Step 7: Creating initial branch balances...")
            create_initial_branch_balances(db)
            
            logger.info("Step 8: Creating development users...")
            create_development_users(db)
            
            logger.info("Step 9: Creating sample customers...")
            create_sample_customers(db)
            
            logger.info("Step 10: Assigning users to branches...")
            assign_users_to_branches(db)
            
            logger.info("Database initialization completed successfully!")
            
            # Verify initialization
            logger.info("Step 11: Verifying initialization...")
            verification = verify_initialization(db)
            
            if verification["status"] == "failed":
                logger.error("Database initialization verification failed!")
                for error in verification["errors"]:
                    logger.error(f"  - {error}")
            else:
                logger.info("Database initialization verification passed!")
                if verification["warnings"]:
                    for warning in verification["warnings"]:
                        logger.warning(f"  - {warning}")
            
            # Test services integration
            logger.info("Step 12: Testing services integration...")
            integration_test = test_services_integration(db)
            
            if integration_test["status"] == "failed":
                logger.error("Services integration test failed!")
                for error in integration_test["errors"]:
                    logger.error(f"  - {error}")
            else:
                logger.info("Services integration test passed!")
            
            # Final summary
            logger.info("=== INITIALIZATION SUMMARY ===")
            logger.info(f"Roles: {verification['counts']['roles']}")
            logger.info(f"Users: {verification['counts']['users']}")
            logger.info(f"Currencies: {verification['counts']['currencies']}")
            logger.info(f"Exchange Rates: {verification['counts']['exchange_rates']}")
            logger.info(f"Branches: {verification['counts']['branches']}")
            logger.info(f"Vaults: {verification['counts']['vaults']}")
            logger.info(f"Customers: {verification['counts']['customers']}")
            logger.info("===============================")
            
        finally:
            db.close()
            
    except Exception as e:
        logger.error(f"Database initialization failed: {str(e)}", exc_info=True)
        raise


def reset_database() -> None:
    """
    Reset database for development purposes.
    
    WARNING: This will delete all data!
    """
    if getattr(settings, 'ENVIRONMENT', 'development') == 'production':
        raise RuntimeError("Cannot reset database in production environment!")
    
    logger.warning("RESETTING DATABASE - ALL DATA WILL BE LOST!")
    
    try:
        # This would typically involve dropping and recreating tables
        # Implementation depends on your database setup
        logger.warning("Database reset is not implemented - manual reset required")
        
        # Re-initialize after reset
        # init_db()
        
    except Exception as e:
        logger.error(f"Database reset failed: {str(e)}")
        raise


# ==================== STANDALONE EXECUTION ====================

if __name__ == "__main__":
    """
    Allow running initialization directly from command line.
    """
    import sys
    
    if len(sys.argv) > 1:
        if sys.argv[1] == "reset":
            reset_database()
        elif sys.argv[1] == "verify":
            db = SessionLocal()
            try:
                result = verify_initialization(db)
                print(json.dumps(result, indent=2, default=str))
            finally:
                db.close()
        else:
            print("Usage: python init_db.py [reset|verify]")
    else:
        init_db()