"""
Module: vault
Purpose: Vault and vault transaction models for CEMS main vault management
Author: CEMS Development Team
Date: 2024
"""

from datetime import datetime
from decimal import Decimal
from typing import Optional, Dict, Any, List
from sqlalchemy import (
    Column, String, Numeric, Boolean, DateTime, Text, ForeignKey,
    Index, CheckConstraint, UniqueConstraint, func, Integer, JSON
)
from sqlalchemy.orm import relationship, validates
from sqlalchemy.ext.hybrid import hybrid_property

from app.db.base import BaseModelWithSoftDelete


class Vault(BaseModelWithSoftDelete):
    """
    Main vault model for managing central cash reserves.
    Tracks cash balances across all currencies for the main vault.
    """
    
    __tablename__ = "vaults"
    
    # Vault identification
    vault_code = Column(
        String(20),
        nullable=False,
        unique=True,
        index=True,
        comment="Unique vault identifier"
    )
    
    vault_name = Column(
        String(100),
        nullable=False,
        comment="Vault display name"
    )
    
    vault_type = Column(
        String(20),
        nullable=False,
        default='main',
        comment="Type of vault (main, branch, mobile)"
    )
    
    # Location information
    location_description = Column(
        Text,
        nullable=True,
        comment="Physical location description"
    )
    
    building = Column(
        String(100),
        nullable=True,
        comment="Building name or address"
    )
    
    floor = Column(
        String(10),
        nullable=True,
        comment="Floor number"
    )
    
    room = Column(
        String(20),
        nullable=True,
        comment="Room number"
    )
    
    # Vault specifications
    capacity_rating = Column(
        String(50),
        nullable=True,
        comment="Vault capacity rating"
    )
    
    security_level = Column(
        String(20),
        nullable=False,
        default='high',
        comment="Security classification"
    )
    
    # Operational information
    status = Column(
        String(20),
        nullable=False,
        default='active',
        comment="Vault operational status"
    )
    
    is_main_vault = Column(
        Boolean,
        nullable=False,
        default=False,
        server_default='false',
        comment="Whether this is the main system vault"
    )
    
    branch_id = Column(
        Integer,
        ForeignKey('branches.id'),
        nullable=True,
        comment="Associated branch (if applicable)"
    )
    
    # Access control
    requires_dual_control = Column(
        Boolean,
        nullable=False,
        default=True,
        server_default='true',
        comment="Whether vault requires dual control access"
    )
    
    authorized_users = Column(
        Text,
        nullable=True,
        comment="JSON array of authorized user IDs"
    )
    
    # Vault custodians (Fixed Foreign Keys)
    primary_custodian_id = Column(
        Integer,
        ForeignKey('users.id'),
        nullable=True,
        comment="Primary vault custodian"
    )
    
    secondary_custodian_id = Column(
        Integer,
        ForeignKey('users.id'),
        nullable=True,
        comment="Secondary vault custodian"
    )
    
    # Operating schedule
    operating_hours_start = Column(
        String(5),
        nullable=True,
        comment="Daily opening time (HH:MM)"
    )
    
    operating_hours_end = Column(
        String(5),
        nullable=True,
        comment="Daily closing time (HH:MM)"
    )
    
    # Audit and security
    last_audit_date = Column(
        DateTime,
        nullable=True,
        comment="Last vault audit date"
    )
    
    last_audit_by = Column(
        Integer,
        ForeignKey('users.id'),
        nullable=True,
        comment="User who conducted last audit"
    )
    
    audit_frequency_days = Column(
        Integer,
        nullable=False,
        default=30,
        comment="Required audit frequency in days"
    )
    
    next_audit_due = Column(
        DateTime,
        nullable=True,
        comment="Next scheduled audit date"
    )
    
    security_system_id = Column(
        String(100),
        nullable=True,
        comment="Security system identifier"
    )
    
    # Insurance and compliance
    insurance_policy_number = Column(
        String(100),
        nullable=True,
        comment="Insurance policy covering this vault"
    )
    
    insurance_coverage_amount = Column(
        Numeric(precision=15, scale=2),
        nullable=True,
        comment="Insurance coverage amount"
    )
    
    compliance_certifications = Column(
        Text,
        nullable=True,
        comment="JSON array of compliance certifications"
    )
    
    # Emergency procedures
    emergency_contact_1 = Column(
        String(100),
        nullable=True,
        comment="Primary emergency contact"
    )
    
    emergency_contact_2 = Column(
        String(100),
        nullable=True,
        comment="Secondary emergency contact"
    )
    
    emergency_procedures = Column(
        Text,
        nullable=True,
        comment="Emergency procedures documentation"
    )
    
    # Additional information
    notes = Column(
        Text,
        nullable=True,
        comment="Additional vault information"
    )
    
    # Relationships (Fixed)
    balances = relationship(
        "VaultBalance",
        back_populates="vault",
        lazy="dynamic",
        cascade="all, delete-orphan"
    )
    
    transactions = relationship(
        "VaultTransaction",
        back_populates="vault",
        lazy="dynamic"
    )
    
    branch = relationship(
        "Branch",
        foreign_keys=[branch_id],
        back_populates="vaults"
    )
    
    primary_custodian = relationship(
        "User",
        foreign_keys=[primary_custodian_id],
        backref="primary_vaults"
    )
    
    secondary_custodian = relationship(
        "User",
        foreign_keys=[secondary_custodian_id],
        backref="secondary_vaults"
    )
    
    last_auditor = relationship(
        "User",
        foreign_keys=[last_audit_by],
        backref="audited_vaults"
    )
    
    # Table constraints and indexes
    __table_args__ = (
        CheckConstraint(
            "vault_type IN ('main', 'branch', 'mobile', 'temporary')",
            name="valid_vault_type"
        ),
        CheckConstraint(
            "status IN ('active', 'inactive', 'maintenance', 'emergency_locked')",
            name="valid_vault_status"
        ),
        CheckConstraint(
            "security_level IN ('low', 'medium', 'high', 'maximum')",
            name="valid_security_level"
        ),
        CheckConstraint(
            "audit_frequency_days > 0",
            name="positive_audit_frequency"
        ),
        Index("idx_vault_type_status", vault_type, status),
        Index("idx_vault_custodian", primary_custodian_id, secondary_custodian_id),
        Index("idx_vault_audit", last_audit_date, next_audit_due),
        Index("idx_vault_branch", branch_id),
    )
    
    # Hybrid properties
    @hybrid_property
    def is_operational(self) -> bool:
        """Check if vault is operational."""
        return self.status == 'active' and not self.is_deleted
    
    @hybrid_property
    def is_audit_overdue(self) -> bool:
        """Check if vault audit is overdue."""
        if not self.next_audit_due:
            return True
        return datetime.now() > self.next_audit_due
    
    @hybrid_property
    def days_since_audit(self) -> Optional[int]:
        """Calculate days since last audit."""
        if not self.last_audit_date:
            return None
        return (datetime.now() - self.last_audit_date).days
    
    # Validation methods
    @validates('vault_code')
    def validate_vault_code(self, key, code):
        """Validate vault code format."""
        if not code:
            raise ValueError("Vault code is required")
        
        import re
        if not re.match(r'^VLT\d{3,6}, code.upper()):
            raise ValueError("Vault code must be in format: VLT + 3-6 digits")
        
        return code.upper()
    
    # Business logic methods
    def get_balance(self, currency_code: str) -> Optional['VaultBalance']:
        """
        Get vault balance for specific currency.
        
        Args:
            currency_code: Currency code
            
        Returns:
            VaultBalance or None
        """
        return self.balances.filter_by(
            currency_code=currency_code.upper(),
            is_active=True
        ).first()
    
    def get_all_balances(self) -> List['VaultBalance']:
        """Get all active balances for this vault."""
        return self.balances.filter_by(is_active=True).all()
    
    def get_total_value_usd(self) -> Decimal:
        """Calculate total vault value in USD."""
        # This would require exchange rates calculation
        # Implementation depends on exchange rate service
        return Decimal('0.00')
    
    def is_user_authorized(self, user_id: int) -> bool:
        """
        Check if user is authorized to access vault.
        
        Args:
            user_id: User ID to check
            
        Returns:
            bool: True if authorized
        """
        if not self.authorized_users:
            return False
        
        import json
        try:
            authorized_list = json.loads(self.authorized_users)
            return user_id in authorized_list
        except json.JSONDecodeError:
            return False
    
    def add_authorized_user(self, user_id: int) -> None:
        """
        Add user to authorized list.
        
        Args:
            user_id: User ID to authorize
        """
        import json
        
        authorized_list = []
        if self.authorized_users:
            try:
                authorized_list = json.loads(self.authorized_users)
            except json.JSONDecodeError:
                authorized_list = []
        
        if user_id not in authorized_list:
            authorized_list.append(user_id)
            self.authorized_users = json.dumps(authorized_list)
    
    def schedule_next_audit(self, from_date: Optional[datetime] = None) -> None:
        """
        Schedule next audit based on frequency.
        
        Args:
            from_date: Base date for calculation (default: now)
        """
        from datetime import timedelta
        
        base_date = from_date or datetime.now()
        self.next_audit_due = base_date + timedelta(days=self.audit_frequency_days)
    
    def __repr__(self) -> str:
        return f"<Vault(code='{self.vault_code}', name='{self.vault_name}', type='{self.vault_type}')>"


class VaultBalance(BaseModelWithSoftDelete):
    """
    Vault balance model for tracking currency balances in each vault.
    """
    
    __tablename__ = "vault_balances"
    
    # Vault and currency references (Fixed Foreign Keys)
    vault_id = Column(
        Integer,
        ForeignKey('vaults.id'),
        nullable=False,
        index=True,
        comment="Reference to vault"
    )
    
    currency_id = Column(
        Integer,
        ForeignKey('currencies.id'),
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
        Numeric(precision=18, scale=4),
        nullable=False,
        default=Decimal('0.0000'),
        comment="Current vault balance"
    )
    
    reserved_balance = Column(
        Numeric(precision=18, scale=4),
        nullable=False,
        default=Decimal('0.0000'),
        comment="Reserved amount for pending operations"
    )
    
    # Physical denomination tracking
    denomination_breakdown = Column(
        JSON,
        nullable=True,
        comment="Physical denomination breakdown"
    )
    
    last_count_amount = Column(
        Numeric(precision=18, scale=4),
        nullable=True,
        comment="Last physically counted amount"
    )
    
    last_count_date = Column(
        DateTime,
        nullable=True,
        comment="Last physical count date"
    )
    
    last_counted_by = Column(
        Integer,
        ForeignKey('users.id'),
        nullable=True,
        comment="User who performed last count"
    )
    
    count_variance = Column(
        Numeric(precision=18, scale=4),
        nullable=True,
        comment="Variance from last count"
    )
    
    # Balance limits and thresholds
    minimum_balance = Column(
        Numeric(precision=18, scale=4),
        nullable=False,
        default=Decimal('0.0000'),
        comment="Minimum balance to maintain"
    )
    
    maximum_balance = Column(
        Numeric(precision=18, scale=4),
        nullable=True,
        comment="Maximum balance allowed"
    )
    
    reorder_threshold = Column(
        Numeric(precision=18, scale=4),
        nullable=True,
        comment="Threshold for reorder alerts"
    )
    
    critical_threshold = Column(
        Numeric(precision=18, scale=4),
        nullable=True,
        comment="Critical low balance threshold"
    )
    
    # Status and tracking
    is_active = Column(
        Boolean,
        nullable=False,
        default=True,
        server_default='true',
        comment="Whether this balance is active"
    )
    
    last_transaction_id = Column(
        Integer,
        ForeignKey('vault_transactions.id'),
        nullable=True,
        comment="Last transaction affecting this balance"
    )
    
    last_updated_at = Column(
        DateTime,
        nullable=False,
        default=func.now(),
        onupdate=func.now(),
        comment="Last balance update timestamp"
    )
    
    # Reconciliation tracking
    last_reconciliation_date = Column(
        DateTime,
        nullable=True,
        comment="Last reconciliation date"
    )
    
    reconciliation_variance = Column(
        Numeric(precision=18, scale=4),
        nullable=True,
        comment="Variance from last reconciliation"
    )
    
    reconciled_by = Column(
        Integer,
        ForeignKey('users.id'),
        nullable=True,
        comment="User who performed last reconciliation"
    )
    
    # Additional information
    notes = Column(
        Text,
        nullable=True,
        comment="Additional balance notes"
    )
    
    # Relationships (Fixed)
    vault = relationship(
        "Vault",
        back_populates="balances"
    )
    
    currency = relationship(
        "Currency",
        foreign_keys=[currency_id],
        back_populates="vault_balances"
    )
    
    last_transaction = relationship(
        "VaultTransaction",
        foreign_keys=[last_transaction_id],
        back_populates="affected_balances"
    )
    
    last_counter = relationship(
        "User",
        foreign_keys=[last_counted_by],
        backref="counted_vault_balances"
    )
    
    reconciler = relationship(
        "User",
        foreign_keys=[reconciled_by],
        backref="reconciled_vault_balances"
    )
    
    # Table constraints and indexes
    __table_args__ = (
        UniqueConstraint('vault_id', 'currency_code', name='unique_vault_currency'),
        CheckConstraint(
            "current_balance >= 0",
            name="non_negative_current_balance_vault"
        ),
        CheckConstraint(
            "reserved_balance >= 0",
            name="non_negative_reserved_balance_vault"
        ),
        CheckConstraint(
            "minimum_balance >= 0",
            name="non_negative_minimum_balance_vault"
        ),
        CheckConstraint(
            "reserved_balance <= current_balance",
            name="reserved_not_exceed_current_vault"
        ),
        Index("idx_vault_currency_active", vault_id, currency_code, is_active),
        Index("idx_vault_balance_thresholds", minimum_balance, reorder_threshold, critical_threshold),
        Index("idx_vault_balance_updated", last_updated_at),
    )
    
    # Hybrid properties
    @hybrid_property
    def available_amount(self) -> Decimal:
        """Calculate available amount (current - reserved)."""
        return self.current_balance - self.reserved_balance
    
    @hybrid_property
    def is_below_minimum(self) -> bool:
        """Check if balance is below minimum."""
        return self.available_amount < self.minimum_balance
    
    @hybrid_property
    def is_critical(self) -> bool:
        """Check if balance is at critical level."""
        if not self.critical_threshold:
            return False
        return self.available_amount < self.critical_threshold
    
    # Business logic methods
    def can_withdraw(self, amount: Decimal) -> bool:
        """Check if amount can be withdrawn."""
        return self.available_amount >= amount
    
    def credit_balance(self, amount: Decimal, transaction_id: Optional[int] = None) -> None:
        """Credit amount to balance."""
        if amount <= 0:
            raise ValueError("Credit amount must be positive")
        
        self.current_balance += amount
        self.last_updated_at = func.now()
        
        if transaction_id:
            self.last_transaction_id = transaction_id
    
    def debit_balance(self, amount: Decimal, transaction_id: Optional[int] = None) -> bool:
        """Debit amount from balance."""
        if amount <= 0:
            raise ValueError("Debit amount must be positive")
        
        if not self.can_withdraw(amount):
            return False
        
        self.current_balance -= amount
        self.last_updated_at = func.now()
        
        if transaction_id:
            self.last_transaction_id = transaction_id
        
        return True
    
    def perform_count(self, counted_amount: Decimal, user_id: int, denomination_breakdown: Optional[Dict] = None) -> Decimal:
        """
        Record physical count results.
        
        Args:
            counted_amount: Physically counted amount
            user_id: User performing count
            denomination_breakdown: Breakdown by denomination
            
        Returns:
            Decimal: Variance amount
        """
        variance = counted_amount - self.current_balance
        
        self.last_count_amount = counted_amount
        self.last_count_date = func.now()
        self.last_counted_by = user_id
        self.count_variance = variance
        
        if denomination_breakdown:
            self.denomination_breakdown = denomination_breakdown
        
        return variance
    
    def reconcile_balance(self, actual_amount: Decimal, user_id: int) -> Decimal:
        """
        Reconcile balance with actual amount.
        
        Args:
            actual_amount: Actual amount after reconciliation
            user_id: User performing reconciliation
            
        Returns:
            Decimal: Variance amount
        """
        variance = actual_amount - self.current_balance
        
        self.reconciliation_variance = variance
        self.last_reconciliation_date = func.now()
        self.reconciled_by = user_id
        
        # Adjust balance to actual
        self.current_balance = actual_amount
        self.last_updated_at = func.now()
        
        return variance
    
    def __repr__(self) -> str:
        return (f"<VaultBalance(vault_id={self.vault_id}, "
                f"currency='{self.currency_code}', balance={self.current_balance})>")


class VaultTransaction(BaseModelWithSoftDelete):
    """
    Vault transaction model for tracking vault operations.
    Records all movements in and out of vaults.
    """
    
    __tablename__ = "vault_transactions"
    
    # Transaction identification
    transaction_id = Column(
        String(20),
        nullable=False,
        unique=True,
        index=True,
        comment="Unique vault transaction ID"
    )
    
    vault_id = Column(
        Integer,
        ForeignKey('vaults.id'),
        nullable=False,
        index=True,
        comment="Vault involved in transaction"
    )
    
    # Transaction details
    transaction_type = Column(
        String(30),
        nullable=False,
        comment="Type of vault transaction"
    )
    
    direction = Column(
        String(10),
        nullable=False,
        comment="Transaction direction (in, out)"
    )
    
    currency_code = Column(
        String(3),
        nullable=False,
        index=True,
        comment="Currency involved"
    )
    
    amount = Column(
        Numeric(precision=18, scale=4),
        nullable=False,
        comment="Transaction amount"
    )
    
    # Source and destination
    source_type = Column(
        String(20),
        nullable=True,
        comment="Source type (branch, bank, external)"
    )
    
    source_id = Column(
        Integer,
        nullable=True,
        comment="Source ID (branch_id, etc.)"
    )
    
    source_reference = Column(
        String(100),
        nullable=True,
        comment="Source reference number"
    )
    
    destination_type = Column(
        String(20),
        nullable=True,
        comment="Destination type"
    )
    
    destination_id = Column(
        Integer,
        nullable=True,
        comment="Destination ID"
    )
    
    destination_reference = Column(
        String(100),
        nullable=True,
        comment="Destination reference"
    )
    
    # Transaction processing (Fixed Foreign Keys)
    status = Column(
        String(20),
        nullable=False,
        default='pending',
        comment="Transaction status"
    )
    
    processed_by = Column(
        Integer,
        ForeignKey('users.id'),
        nullable=False,
        comment="User who processed transaction"
    )
    
    approved_by = Column(
        Integer,
        ForeignKey('users.id'),
        nullable=True,
        comment="User who approved transaction"
    )
    
    transaction_date = Column(
        DateTime,
        nullable=False,
        default=func.now(),
        comment="Transaction date"
    )
    
    completed_at = Column(
        DateTime,
        nullable=True,
        comment="Completion timestamp"
    )
    
    # Physical handling
    denomination_breakdown = Column(
        JSON,
        nullable=True,
        comment="Physical denomination breakdown"
    )
    
    containers_used = Column(
        String(255),
        nullable=True,
        comment="Containers or bags used for transport"
    )
    
    seal_numbers = Column(
        String(255),
        nullable=True,
        comment="Security seal numbers"
    )
    
    # Security and verification (Fixed Foreign Keys)
    requires_dual_authorization = Column(
        Boolean,
        nullable=False,
        default=True,
        server_default='true',
        comment="Requires dual authorization"
    )
    
    first_authorizer_id = Column(
        Integer,
        ForeignKey('users.id'),
        nullable=True,
        comment="First authorizing user"
    )
    
    second_authorizer_id = Column(
        Integer,
        ForeignKey('users.id'),
        nullable=True,
        comment="Second authorizing user"
    )
    
    verified_by = Column(
        Integer,
        ForeignKey('users.id'),
        nullable=True,
        comment="User who verified the transaction"
    )
    
    verification_date = Column(
        DateTime,
        nullable=True,
        comment="Verification timestamp"
    )
    
    # Related transactions
    related_transaction_id = Column(
        Integer,
        ForeignKey('transactions.id'),
        nullable=True,
        comment="Related customer transaction"
    )
    
    batch_id = Column(
        String(50),
        nullable=True,
        comment="Batch ID for grouped transactions"
    )
    
    # Additional information
    purpose = Column(
        String(255),
        nullable=True,
        comment="Purpose of the transaction"
    )
    
    notes = Column(
        Text,
        nullable=True,
        comment="Transaction notes"
    )
    
    # Relationships (Fixed)
    vault = relationship(
        "Vault",
        back_populates="transactions"
    )
    
    processor = relationship(
        "User",
        foreign_keys=[processed_by],
        backref="processed_vault_transactions"
    )
    
    approver = relationship(
        "User",
        foreign_keys=[approved_by],
        backref="approved_vault_transactions"
    )
    
    first_authorizer = relationship(
        "User",
        foreign_keys=[first_authorizer_id],
        backref="first_authorized_vault_transactions"
    )
    
    second_authorizer = relationship(
        "User",
        foreign_keys=[second_authorizer_id],
        backref="second_authorized_vault_transactions"
    )
    
    verifier = relationship(
        "User",
        foreign_keys=[verified_by],
        backref="verified_vault_transactions"
    )
    
    related_transaction = relationship(
        "Transaction",
        foreign_keys=[related_transaction_id],
        backref="related_vault_transactions"
    )
    
    affected_balances = relationship(
        "VaultBalance",
        foreign_keys="VaultBalance.last_transaction_id",
        back_populates="last_transaction"
    )
    
    # Table constraints and indexes
    __table_args__ = (
        CheckConstraint(
            "transaction_type IN ('vault_deposit', 'vault_withdrawal', 'branch_transfer', 'bank_deposit', 'bank_withdrawal', 'reconciliation_adjustment')",
            name="valid_vault_transaction_type"
        ),
        CheckConstraint(
            "direction IN ('in', 'out')",
            name="valid_direction"
        ),
        CheckConstraint(
            "status IN ('pending', 'authorized', 'completed', 'cancelled', 'failed')",
            name="valid_vault_status"
        ),
        CheckConstraint(
            "amount > 0",
            name="positive_amount_vault"
        ),
        Index("idx_vault_transaction_date", vault_id, transaction_date),
        Index("idx_vault_currency_amount", vault_id, currency_code, amount),
        Index("idx_vault_transaction_status", status, transaction_date),
        Index("idx_vault_transaction_batch", batch_id),
        Index("idx_vault_transaction_related", related_transaction_id),
    )
    
    # Hybrid properties
    @hybrid_property
    def is_completed(self) -> bool:
        """Check if transaction is completed."""
        return self.status == 'completed'
    
    @hybrid_property
    def is_authorized(self) -> bool:
        """Check if transaction is properly authorized."""
        if not self.requires_dual_authorization:
            return bool(self.first_authorizer_id)
        
        return bool(self.first_authorizer_id and self.second_authorizer_id)
    
    # Business logic methods
    def authorize_transaction(self, authorizer_id: int) -> bool:
        """
        Authorize transaction.
        
        Args:
            authorizer_id: ID of authorizing user
            
        Returns:
            bool: True if fully authorized
        """
        if not self.requires_dual_authorization:
            self.first_authorizer_id = authorizer_id
            self.status = 'authorized'
            return True
        
        if not self.first_authorizer_id:
            self.first_authorizer_id = authorizer_id
            return False
        elif not self.second_authorizer_id and self.first_authorizer_id != authorizer_id:
            self.second_authorizer_id = authorizer_id
            self.status = 'authorized'
            return True
        
        return False
    
    def complete_transaction(self, verifier_id: Optional[int] = None) -> None:
        """Complete the transaction."""
        if not self.is_authorized:
            raise ValueError("Transaction must be authorized before completion")
        
        self.status = 'completed'
        self.completed_at = func.now()
        
        if verifier_id:
            self.verified_by = verifier_id
            self.verification_date = func.now()
    
    def __repr__(self) -> str:
        return (f"<VaultTransaction(id='{self.transaction_id}', "
                f"type='{self.transaction_type}', amount={self.amount}, "
                f"status='{self.status}')>")