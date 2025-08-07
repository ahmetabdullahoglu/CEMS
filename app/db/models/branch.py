"""
Module: branch
Purpose: Branch and branch balance models for CEMS
Author: CEMS Development Team
Date: 2024
"""

from datetime import datetime, time
from decimal import Decimal
from typing import Optional, List, Dict, Any
from sqlalchemy import (
    Column, String, Numeric, Boolean, DateTime, Text, ForeignKey, Time,
    Index, CheckConstraint, UniqueConstraint, func, Integer
)
from sqlalchemy.orm import relationship, validates
from sqlalchemy.ext.hybrid import hybrid_property

from app.db.base import BaseModelWithSoftDelete
from app.core.constants import CurrencyCode


class Branch(BaseModelWithSoftDelete):
    """
    Branch model for managing physical branch locations.
    Each branch can handle multiple currencies and has operational settings.
    """
    
    __tablename__ = "branches"
    
    # Branch identification
    branch_code = Column(
        String(10),
        nullable=False,
        unique=True,
        index=True,
        comment="Unique branch code (e.g., BR001, BR002)"
    )
    
    name = Column(
        String(100),
        nullable=False,
        comment="Branch display name"
    )
    
    name_arabic = Column(
        String(100),
        nullable=True,
        comment="Branch name in Arabic"
    )
    
    # Location information
    address_line1 = Column(
        String(200),
        nullable=False,
        comment="Primary address line"
    )
    
    address_line2 = Column(
        String(200),
        nullable=True,
        comment="Secondary address line"
    )
    
    city = Column(
        String(100),
        nullable=False,
        comment="City name"
    )
    
    state_province = Column(
        String(100),
        nullable=True,
        comment="State or province"
    )
    
    postal_code = Column(
        String(20),
        nullable=True,
        comment="Postal/ZIP code"
    )
    
    country_code = Column(
        String(3),
        nullable=False,
        default='SAU',
        comment="ISO 3166 country code"
    )
    
    # Geographic coordinates for mapping
    latitude = Column(
        Numeric(precision=10, scale=8),
        nullable=True,
        comment="Latitude coordinate"
    )
    
    longitude = Column(
        Numeric(precision=11, scale=8),
        nullable=True,
        comment="Longitude coordinate"
    )
    
    # Contact information
    phone_number = Column(
        String(20),
        nullable=True,
        comment="Primary phone number"
    )
    
    fax_number = Column(
        String(20),
        nullable=True,
        comment="Fax number"
    )
    
    email = Column(
        String(255),
        nullable=True,
        comment="Branch email address"
    )
    
    # Operational information
    branch_type = Column(
        String(20),
        nullable=False,
        default='standard',
        comment="Type of branch (main, standard, kiosk)"
    )
    
    status = Column(
        String(20),
        nullable=False,
        default='active',
        comment="Branch operational status"
    )
    
    is_main_branch = Column(
        Boolean,
        nullable=False,
        default=False,
        server_default='false',
        comment="Whether this is the main/headquarters branch"
    )
    
    is_24_hours = Column(
        Boolean,
        nullable=False,
        default=False,
        server_default='false',
        comment="Whether branch operates 24/7"
    )
    
    # Operating hours
    opening_time = Column(
        Time,
        nullable=True,
        comment="Daily opening time"
    )
    
    closing_time = Column(
        Time,
        nullable=True,
        comment="Daily closing time"
    )
    
    # Weekend and holiday settings
    weekend_days = Column(
        String(20),
        nullable=False,
        default='friday,saturday',
        comment="Comma-separated weekend days"
    )
    
    operates_on_weekends = Column(
        Boolean,
        nullable=False,
        default=False,
        server_default='false',
        comment="Whether branch operates on weekends"
    )
    
    operates_on_holidays = Column(
        Boolean,
        nullable=False,
        default=False,
        server_default='false',
        comment="Whether branch operates on public holidays"
    )
    
    # Transaction limits and settings
    daily_transaction_limit = Column(
        Numeric(precision=15, scale=2),
        nullable=True,
        comment="Daily transaction limit for this branch"
    )
    
    single_transaction_limit = Column(
        Numeric(precision=15, scale=2),
        nullable=True,
        comment="Single transaction limit for this branch"
    )
    
    requires_manager_approval = Column(
        Boolean,
        nullable=False,
        default=False,
        server_default='false',
        comment="Whether large transactions require manager approval"
    )
    
    manager_approval_threshold = Column(
        Numeric(precision=15, scale=2),
        nullable=True,
        comment="Amount threshold requiring manager approval"
    )
    
    # Vault connection
    has_vault = Column(
        Boolean,
        nullable=False,
        default=True,
        server_default='true',
        comment="Whether branch has its own vault"
    )
    
    vault_capacity_usd = Column(
        Numeric(precision=15, scale=2),
        nullable=True,
        comment="Vault capacity in USD equivalent"
    )
    
    # Administrative information
    branch_manager_id = Column(
        Integer,  # ForeignKey('users.id')
        nullable=True,
        comment="Branch manager user ID"
    )
    
    opened_date = Column(
        DateTime,
        nullable=True,
        comment="Branch opening date"
    )
    
    license_number = Column(
        String(100),
        nullable=True,
        comment="Government license number"
    )
    
    license_expiry_date = Column(
        DateTime,
        nullable=True,
        comment="License expiry date"
    )
    
    # Additional settings
    notes = Column(
        Text,
        nullable=True,
        comment="Additional branch information"
    )
    
    # Relationships
    balances = relationship(
        "BranchBalance",
        back_populates="branch",
        lazy="dynamic",
        cascade="all, delete-orphan"
    )
    
    users = relationship(
        "User",
        foreign_keys="User.branch_id",
        back_populates="branch",
        lazy="dynamic"
    )
    
    transactions = relationship(
        "Transaction",
        back_populates="branch",
        lazy="dynamic"
    )
    
    # Table constraints and indexes
    __table_args__ = (
        CheckConstraint(
            "branch_type IN ('main', 'standard', 'kiosk', 'mobile')",
            name="valid_branch_type"
        ),
        CheckConstraint(
            "status IN ('active', 'inactive', 'maintenance', 'closed')",
            name="valid_branch_status"
        ),
        CheckConstraint(
            "daily_transaction_limit IS NULL OR daily_transaction_limit > 0",
            name="positive_daily_limit"
        ),
        CheckConstraint(
            "single_transaction_limit IS NULL OR single_transaction_limit > 0",
            name="positive_single_limit"
        ),
        CheckConstraint(
            "manager_approval_threshold IS NULL OR manager_approval_threshold > 0",
            name="positive_approval_threshold"
        ),
        CheckConstraint(
            "latitude IS NULL OR (latitude >= -90 AND latitude <= 90)",
            name="valid_latitude"
        ),
        CheckConstraint(
            "longitude IS NULL OR (longitude >= -180 AND longitude <= 180)",
            name="valid_longitude"
        ),
        Index("idx_branch_code_status", branch_code, status),
        Index("idx_branch_city_status", city, status),
        Index("idx_branch_manager", branch_manager_id),
        Index("idx_branch_type", branch_type),
    )
    
    # Hybrid properties
    @hybrid_property
    def full_address(self) -> str:
        """Get formatted full address."""
        address_parts = [self.address_line1]
        
        if self.address_line2:
            address_parts.append(self.address_line2)
        
        address_parts.extend([
            self.city,
            self.state_province,
            self.postal_code
        ])
        
        return ", ".join(filter(None, address_parts))
    
    @hybrid_property
    def is_operational(self) -> bool:
        """Check if branch is currently operational."""
        return self.status == 'active' and not self.is_deleted
    
    @hybrid_property
    def is_open_now(self) -> bool:
        """Check if branch is currently open (simplified check)."""
        if not self.is_operational or self.is_24_hours:
            return self.is_operational
        
        if not self.opening_time or not self.closing_time:
            return True  # Assume open if no times set
        
        current_time = datetime.now().time()
        return self.opening_time <= current_time <= self.closing_time
    
    # Validation methods
    @validates('branch_code')
    def validate_branch_code(self, key, code):
        """Validate branch code format."""
        if not code:
            raise ValueError("Branch code is required")
        
        # Format: BR followed by 3-6 digits
        import re
        if not re.match(r'^BR\d{3,6}$', code.upper()):
            raise ValueError("Branch code must be in format: BR + 3-6 digits (e.g., BR001)")
        
        return code.upper()
    
    @validates('email')
    def validate_email(self, key, email):
        """Validate email format."""
        if not email:
            return email
        
        import re
        if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
            raise ValueError("Invalid email format")
        
        return email.lower()
    
    @validates('phone_number', 'fax_number')
    def validate_phone(self, key, phone):
        """Validate phone number format."""
        if not phone:
            return phone
        
        import re
        if not re.match(r'^\+?[1-9]\d{1,14}$', phone.replace(' ', '').replace('-', '')):
            raise ValueError(f"Invalid {key} format")
        
        return phone
    
    # Business logic methods
    def get_balance(self, currency_code: str) -> Optional['BranchBalance']:
        """
        Get branch balance for specific currency.
        
        Args:
            currency_code: Currency code to get balance for
            
        Returns:
            BranchBalance or None: Balance record if exists
        """
        return self.balances.filter_by(
            currency_code=currency_code.upper(),
            is_active=True
        ).first()
    
    def get_all_balances(self) -> List['BranchBalance']:
        """
        Get all active balances for this branch.
        
        Returns:
            List[BranchBalance]: List of active balance records
        """
        return self.balances.filter_by(is_active=True).all()
    
    def has_sufficient_balance(self, currency_code: str, amount: Decimal) -> bool:
        """
        Check if branch has sufficient balance for transaction.
        
        Args:
            currency_code: Currency to check
            amount: Amount to check against
            
        Returns:
            bool: True if sufficient balance exists
        """
        balance = self.get_balance(currency_code)
        if not balance:
            return False
        
        return balance.available_amount >= amount
    
    def is_within_transaction_limit(self, amount: Decimal) -> bool:
        """
        Check if transaction amount is within branch limits.
        
        Args:
            amount: Transaction amount to check
            
        Returns:
            bool: True if within limits
        """
        if self.single_transaction_limit and amount > self.single_transaction_limit:
            return False
        
        # Could add daily limit check here if needed
        return True
    
    def requires_approval(self, amount: Decimal) -> bool:
        """
        Check if transaction amount requires manager approval.
        
        Args:
            amount: Transaction amount
            
        Returns:
            bool: True if approval required
        """
        if not self.requires_manager_approval or not self.manager_approval_threshold:
            return False
        
        return amount >= self.manager_approval_threshold
    
    def set_operating_hours(self, opening: str, closing: str) -> None:
        """
        Set branch operating hours.
        
        Args:
            opening: Opening time in HH:MM format
            closing: Closing time in HH:MM format
        """
        from datetime import datetime
        
        try:
            self.opening_time = datetime.strptime(opening, '%H:%M').time()
            self.closing_time = datetime.strptime(closing, '%H:%M').time()
        except ValueError as e:
            raise ValueError(f"Invalid time format. Use HH:MM format: {e}")
    
    def __repr__(self) -> str:
        return f"<Branch(code='{self.branch_code}', name='{self.name}', status='{self.status}')>"


class BranchBalance(BaseModelWithSoftDelete):
    """
    Branch balance model for tracking currency balances at each branch.
    Maintains current balance and transaction history.
    """
    
    __tablename__ = "branch_balances"
    
    # Branch and currency references
    branch_id = Column(
        Integer,  # ForeignKey('branches.id')
        nullable=False,
        index=True,
        comment="Reference to branch"
    )
    
    currency_id = Column(
        Integer,  # ForeignKey('currencies.id')
        nullable=False,
        index=True,
        comment="Reference to currency"
    )
    
    currency_code = Column(
        String(3),
        nullable=False,
        index=True,
        comment="Currency code for easier querying"
    )
    
    # Balance information
    current_balance = Column(
        Numeric(precision=15, scale=4),
        nullable=False,
        default=Decimal('0.0000'),
        comment="Current available balance"
    )
    
    reserved_balance = Column(
        Numeric(precision=15, scale=4),
        nullable=False,
        default=Decimal('0.0000'),
        comment="Amount reserved for pending transactions"
    )
    
    # Calculated available amount
    @hybrid_property
    def available_amount(self) -> Decimal:
        """Calculate available amount (current - reserved)."""
        return self.current_balance - self.reserved_balance
    
    # Balance limits and thresholds
    minimum_balance = Column(
        Numeric(precision=15, scale=4),
        nullable=False,
        default=Decimal('0.0000'),
        comment="Minimum balance to maintain"
    )
    
    maximum_balance = Column(
        Numeric(precision=15, scale=4),
        nullable=True,
        comment="Maximum balance allowed (null = no limit)"
    )
    
    reorder_threshold = Column(
        Numeric(precision=15, scale=4),
        nullable=True,
        comment="Threshold for automatic reorder alerts"
    )
    
    critical_threshold = Column(
        Numeric(precision=15, scale=4),
        nullable=True,
        comment="Critical low balance threshold"
    )
    
    # Balance tracking
    last_transaction_id = Column(
        Integer,  # ForeignKey('transactions.id')
        nullable=True,
        comment="ID of last transaction affecting this balance"
    )
    
    last_updated_at = Column(
        DateTime,
        nullable=False,
        default=func.now(),
        onupdate=func.now(),
        comment="Last balance update timestamp"
    )
    
    last_reconciliation_at = Column(
        DateTime,
        nullable=True,
        comment="Last manual reconciliation timestamp"
    )
    
    reconciliation_variance = Column(
        Numeric(precision=15, scale=4),
        nullable=True,
        comment="Variance found during last reconciliation"
    )
    
    # Status and flags
    is_active = Column(
        Boolean,
        nullable=False,
        default=True,
        server_default='true',
        comment="Whether this balance record is active"
    )
    
    is_frozen = Column(
        Boolean,
        nullable=False,
        default=False,
        server_default='false',
        comment="Whether transactions are frozen for this currency"
    )
    
    freeze_reason = Column(
        String(255),
        nullable=True,
        comment="Reason for balance freeze"
    )
    
    frozen_at = Column(
        DateTime,
        nullable=True,
        comment="When balance was frozen"
    )
    
    frozen_by = Column(
        Integer,  # ForeignKey('users.id')
        nullable=True,
        comment="User who froze the balance"
    )
    
    # Additional information
    notes = Column(
        Text,
        nullable=True,
        comment="Additional notes about this balance"
    )
    
    # Relationships
    branch = relationship(
        "Branch",
        back_populates="balances"
    )
    
    currency = relationship(
        "Currency",
        foreign_keys=[currency_id]
    )
    
    # Table constraints and indexes
    __table_args__ = (
        UniqueConstraint('branch_id', 'currency_code', name='unique_branch_currency'),
        CheckConstraint(
            "current_balance >= 0",
            name="non_negative_current_balance"
        ),
        CheckConstraint(
            "reserved_balance >= 0",
            name="non_negative_reserved_balance"
        ),
        CheckConstraint(
            "minimum_balance >= 0",
            name="non_negative_minimum_balance"
        ),
        CheckConstraint(
            "maximum_balance IS NULL OR maximum_balance > minimum_balance",
            name="valid_maximum_balance"
        ),
        CheckConstraint(
            "reserved_balance <= current_balance",
            name="reserved_not_exceed_current"
        ),
        Index("idx_branch_currency_active", branch_id, currency_code, is_active),
        Index("idx_balance_thresholds", minimum_balance, reorder_threshold, critical_threshold),
        Index("idx_balance_frozen", is_frozen, frozen_at),
    )
    
    # Hybrid properties
    @hybrid_property
    def is_below_minimum(self) -> bool:
        """Check if balance is below minimum threshold."""
        return self.available_amount < self.minimum_balance
    
    @hybrid_property
    def is_below_reorder(self) -> bool:
        """Check if balance is below reorder threshold."""
        if not self.reorder_threshold:
            return False
        return self.available_amount < self.reorder_threshold
    
    @hybrid_property
    def is_critical(self) -> bool:
        """Check if balance is at critical level."""
        if not self.critical_threshold:
            return False
        return self.available_amount < self.critical_threshold
    
    @hybrid_property
    def utilization_percentage(self) -> float:
        """Calculate balance utilization percentage."""
        if not self.maximum_balance or self.maximum_balance == 0:
            return 0.0
        
        return float((self.current_balance / self.maximum_balance) * 100)
    
    # Validation methods
    @validates('currency_code')
    def validate_currency_code(self, key, code):
        """Validate currency code."""
        if not code or len(code) != 3:
            raise ValueError("Currency code must be exactly 3 characters")
        return code.upper()
    
    # Business logic methods
    def can_debit(self, amount: Decimal) -> bool:
        """
        Check if amount can be debited from balance.
        
        Args:
            amount: Amount to debit
            
        Returns:
            bool: True if debit is possible
        """
        if self.is_frozen:
            return False
        
        return self.available_amount >= amount
    
    def reserve_amount(self, amount: Decimal) -> bool:
        """
        Reserve amount for pending transaction.
        
        Args:
            amount: Amount to reserve
            
        Returns:
            bool: True if reservation successful
        """
        if not self.can_debit(amount):
            return False
        
        self.reserved_balance += amount
        return True
    
    def release_reservation(self, amount: Decimal) -> bool:
        """
        Release reserved amount.
        
        Args:
            amount: Amount to release
            
        Returns:
            bool: True if release successful
        """
        if amount > self.reserved_balance:
            return False
        
        self.reserved_balance -= amount
        return True
    
    def credit_balance(self, amount: Decimal, transaction_id: Optional[int] = None) -> None:
        """
        Credit amount to balance.
        
        Args:
            amount: Amount to credit
            transaction_id: ID of associated transaction
        """
        if amount <= 0:
            raise ValueError("Credit amount must be positive")
        
        self.current_balance += amount
        self.last_updated_at = func.now()
        
        if transaction_id:
            self.last_transaction_id = transaction_id
    
    def debit_balance(self, amount: Decimal, transaction_id: Optional[int] = None) -> bool:
        """
        Debit amount from balance.
        
        Args:
            amount: Amount to debit
            transaction_id: ID of associated transaction
            
        Returns:
            bool: True if debit successful
        """
        if amount <= 0:
            raise ValueError("Debit amount must be positive")
        
        if not self.can_debit(amount):
            return False
        
        self.current_balance -= amount
        self.last_updated_at = func.now()
        
        if transaction_id:
            self.last_transaction_id = transaction_id
        
        return True
    
    def freeze_balance(self, reason: str, user_id: int) -> None:
        """
        Freeze balance for this currency.
        
        Args:
            reason: Reason for freezing
            user_id: ID of user who froze the balance
        """
        self.is_frozen = True
        self.freeze_reason = reason
        self.frozen_at = func.now()
        self.frozen_by = user_id
    
    def unfreeze_balance(self) -> None:
        """Unfreeze balance."""
        self.is_frozen = False
        self.freeze_reason = None
        self.frozen_at = None
        self.frozen_by = None
    
    def reconcile_balance(self, actual_amount: Decimal, user_id: int) -> Decimal:
        """
        Reconcile balance with actual counted amount.
        
        Args:
            actual_amount: Actual counted amount
            user_id: ID of user performing reconciliation
            
        Returns:
            Decimal: Variance amount (positive = overage, negative = shortage)
        """
        variance = actual_amount - self.current_balance
        
        self.reconciliation_variance = variance
        self.last_reconciliation_at = func.now()
        
        # Adjust balance to actual amount
        self.current_balance = actual_amount
        self.last_updated_at = func.now()
        
        return variance
    
    def get_balance_status(self) -> Dict[str, Any]:
        """
        Get comprehensive balance status.
        
        Returns:
            Dict: Balance status information
        """
        return {
            'current_balance': float(self.current_balance),
            'reserved_balance': float(self.reserved_balance),
            'available_amount': float(self.available_amount),
            'is_below_minimum': self.is_below_minimum,
            'is_below_reorder': self.is_below_reorder,
            'is_critical': self.is_critical,
            'is_frozen': self.is_frozen,
            'utilization_percentage': self.utilization_percentage,
            'last_updated_at': self.last_updated_at.isoformat() if self.last_updated_at else None
        }
    
    def __repr__(self) -> str:
        return (f"<BranchBalance(branch_id={self.branch_id}, "
                f"currency='{self.currency_code}', balance={self.current_balance})>")