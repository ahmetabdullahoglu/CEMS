"""
Module: transaction
Purpose: Transaction models for CEMS - handles all types of financial transactions
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
from sqlalchemy.orm import relationship, validates, backref
from sqlalchemy.ext.hybrid import hybrid_property

from app.db.base import BaseModelWithSoftDelete
from app.core.constants import TransactionType, TransactionStatus, PaymentMethod


class Transaction(BaseModelWithSoftDelete):
    """
    Base transaction model for all financial transactions in CEMS.
    Uses single table inheritance for different transaction types.
    """
    
    __tablename__ = "transactions"
    
    # Transaction identification
    transaction_id = Column(
        String(20),
        nullable=False,
        unique=True,
        index=True,
        comment="Unique transaction identifier (auto-generated)"
    )
    
    transaction_type = Column(
        String(30),
        nullable=False,
        index=True,
        comment="Type of transaction"
    )
    
    reference_number = Column(
        String(50),
        nullable=True,
        index=True,
        comment="External reference number"
    )
    
    # Transaction parties
    customer_id = Column(
        Integer,  # ForeignKey('customers.id')
        nullable=True,
        index=True,
        comment="Customer involved in transaction"
    )
    
    branch_id = Column(
        Integer,  # ForeignKey('branches.id')
        nullable=False,
        index=True,
        comment="Branch where transaction occurred"
    )
    
    user_id = Column(
        Integer,  # ForeignKey('users.id')
        nullable=False,
        index=True,
        comment="User who processed the transaction"
    )
    
    # Financial information
    from_currency_code = Column(
        String(3),
        nullable=True,
        index=True,
        comment="Source currency code"
    )
    
    to_currency_code = Column(
        String(3),
        nullable=True,
        index=True,
        comment="Target currency code"
    )
    
    from_amount = Column(
        Numeric(precision=15, scale=4),
        nullable=False,
        comment="Amount in source currency"
    )
    
    to_amount = Column(
        Numeric(precision=15, scale=4),
        nullable=True,
        comment="Amount in target currency"
    )
    
    exchange_rate = Column(
        Numeric(precision=15, scale=8),
        nullable=True,
        comment="Exchange rate used (if applicable)"
    )
    
    exchange_rate_id = Column(
        Integer,  # ForeignKey('exchange_rates.id')
        nullable=True,
        comment="Reference to exchange rate record used"
    )
    
    # Commission and fees
    commission_rate = Column(
        Numeric(precision=5, scale=4),
        nullable=True,
        comment="Commission rate applied"
    )
    
    commission_amount = Column(
        Numeric(precision=10, scale=2),
        nullable=False,
        default=Decimal('0.00'),
        comment="Commission amount charged"
    )
    
    fee_amount = Column(
        Numeric(precision=10, scale=2),
        nullable=False,
        default=Decimal('0.00'),
        comment="Additional fees charged"
    )
    
    net_amount = Column(
        Numeric(precision=15, scale=4),
        nullable=False,
        comment="Net amount after all charges"
    )
    
    # Transaction status and timing
    status = Column(
        String(20),
        nullable=False,
        default=TransactionStatus.PENDING.value,
        index=True,
        comment="Current transaction status"
    )
    
    transaction_date = Column(
        DateTime,
        nullable=False,
        default=func.now(),
        index=True,
        comment="When transaction was initiated"
    )
    
    value_date = Column(
        DateTime,
        nullable=True,
        comment="Value date for the transaction"
    )
    
    completed_at = Column(
        DateTime,
        nullable=True,
        comment="When transaction was completed"
    )
    
    # Payment method and details
    payment_method = Column(
        String(20),
        nullable=False,
        default=PaymentMethod.CASH.value,
        comment="Payment method used"
    )
    
    payment_reference = Column(
        String(100),
        nullable=True,
        comment="Payment reference (check number, card reference, etc.)"
    )
    
    # Approval workflow
    requires_approval = Column(
        Boolean,
        nullable=False,
        default=False,
        server_default='false',
        comment="Whether transaction requires approval"
    )
    
    approved_by = Column(
        Integer,  # ForeignKey('users.id')
        nullable=True,
        comment="User who approved the transaction"
    )
    
    approved_at = Column(
        DateTime,
        nullable=True,
        comment="When transaction was approved"
    )
    
    approval_notes = Column(
        Text,
        nullable=True,
        comment="Notes from approver"
    )
    
    # Additional transaction details
    description = Column(
        Text,
        nullable=True,
        comment="Transaction description/purpose"
    )
    
    notes = Column(
        Text,
        nullable=True,
        comment="Internal notes about the transaction"
    )
    
    additional_data = Column(
        JSON,
        nullable=True,
        comment="Additional transaction-specific data (JSON)"
    )
    
    # Risk and compliance
    aml_checked = Column(
        Boolean,
        nullable=False,
        default=False,
        server_default='false',
        comment="Whether AML checks were performed"
    )
    
    aml_risk_score = Column(
        String(10),
        nullable=False,
        default='0',
        comment="AML risk score (0-100)"
    )
    
    compliance_flags = Column(
        Text,
        nullable=True,
        comment="Compliance flags or alerts (JSON array)"
    )
    
    # Reversal information
    original_transaction_id = Column(
        Integer,  # ForeignKey('transactions.id')
        nullable=True,
        comment="Original transaction if this is a reversal"
    )
    
    reversed_transaction_id = Column(
        Integer,  # ForeignKey('transactions.id')
        nullable=True,
        comment="Reversal transaction ID if this was reversed"
    )
    
    reversal_reason = Column(
        String(255),
        nullable=True,
        comment="Reason for reversal"
    )
    
    # Receipt and documentation
    receipt_number = Column(
        String(50),
        nullable=True,
        comment="Receipt number issued to customer"
    )
    
    receipt_printed = Column(
        Boolean,
        nullable=False,
        default=False,
        server_default='false',
        comment="Whether receipt was printed"
    )
    
    # External system integration
    external_system_id = Column(
        String(100),
        nullable=True,
        comment="ID in external system (if integrated)"
    )
    
    external_status = Column(
        String(50),
        nullable=True,
        comment="Status in external system"
    )
    
    # Relationships
    customer = relationship(
        "Customer",
        back_populates="transactions",
        foreign_keys=[customer_id]
    )
    
    branch = relationship(
        "Branch",
        back_populates="transactions",
        foreign_keys=[branch_id]
    )
    
    user = relationship(
        "User",
        foreign_keys=[user_id],
        backref="processed_transactions"
    )
    
    approver = relationship(
        "User",
        foreign_keys=[approved_by],
        backref="approved_transactions"
    )
    
    original_transaction = relationship(
        "Transaction",
        remote_side=[id],
        foreign_keys=[original_transaction_id],
        backref="reversals"
    )
    
    # Table constraints and indexes
    __table_args__ = (
        CheckConstraint(
            transaction_type.in_([t.value for t in TransactionType]),
            name="valid_transaction_type"
        ),
        CheckConstraint(
            status.in_([s.value for s in TransactionStatus]),
            name="valid_transaction_status"
        ),
        CheckConstraint(
            payment_method.in_([p.value for p in PaymentMethod]),
            name="valid_payment_method"
        ),
        CheckConstraint(
            "from_amount > 0",
            name="positive_from_amount"
        ),
        CheckConstraint(
            "to_amount IS NULL OR to_amount > 0",
            name="positive_to_amount"
        ),
        CheckConstraint(
            "commission_amount >= 0",
            name="non_negative_commission"
        ),
        CheckConstraint(
            "fee_amount >= 0",
            name="non_negative_fee"
        ),
        CheckConstraint(
            "exchange_rate IS NULL OR exchange_rate > 0",
            name="positive_exchange_rate"
        ),
        CheckConstraint(
            "aml_risk_score::integer >= 0 AND aml_risk_score::integer <= 100",
            name="valid_aml_risk_score"
        ),
        Index("idx_transaction_date_status", transaction_date, status),
        Index("idx_transaction_customer_date", customer_id, transaction_date),
        Index("idx_transaction_branch_date", branch_id, transaction_date),
        Index("idx_transaction_currencies", from_currency_code, to_currency_code),
        Index("idx_transaction_amount", from_amount),
        Index("idx_transaction_reference", reference_number),
        Index("idx_transaction_receipt", receipt_number),
        Index("idx_transaction_approval", requires_approval, approved_at),
        Index("idx_transaction_aml", aml_checked, aml_risk_score),
    )
    
    # Hybrid properties
    @hybrid_property
    def total_amount(self) -> Decimal:
        """Calculate total amount including commission and fees."""
        return self.from_amount + self.commission_amount + self.fee_amount
    
    @hybrid_property
    def is_completed(self) -> bool:
        """Check if transaction is completed."""
        return self.status == TransactionStatus.COMPLETED.value
    
    @hybrid_property
    def is_pending_approval(self) -> bool:
        """Check if transaction is pending approval."""
        return self.requires_approval and not self.approved_at
    
    @hybrid_property
    def is_currency_exchange(self) -> bool:
        """Check if this is a currency exchange transaction."""
        return (
            self.transaction_type == TransactionType.CURRENCY_EXCHANGE.value and
            self.from_currency_code and
            self.to_currency_code and
            self.from_currency_code != self.to_currency_code
        )
    
    @hybrid_property
    def processing_time_minutes(self) -> Optional[float]:
        """Calculate transaction processing time in minutes."""
        if not self.completed_at:
            return None
        
        delta = self.completed_at - self.transaction_date
        return delta.total_seconds() / 60
    
    # Validation methods
    @validates('transaction_id')
    def validate_transaction_id(self, key, transaction_id):
        """Validate transaction ID format."""
        if not transaction_id:
            return transaction_id
        
        import re
        if not re.match(r'^TXN\d{10}$', transaction_id.upper()):
            raise ValueError("Transaction ID must be in format: TXN + 10 digits")
        
        return transaction_id.upper()
    
    @validates('from_currency_code', 'to_currency_code')
    def validate_currency_codes(self, key, code):
        """Validate currency codes."""
        if not code:
            return code
        
        if len(code) != 3:
            raise ValueError("Currency code must be exactly 3 characters")
        
        return code.upper()
    
    # Business logic methods
    def calculate_commission(self, rate: Decimal, minimum: Optional[Decimal] = None) -> Decimal:
        """
        Calculate commission based on rate and minimum.
        
        Args:
            rate: Commission rate (percentage)
            minimum: Minimum commission amount
            
        Returns:
            Decimal: Calculated commission amount
        """
        calculated = self.from_amount * rate
        
        if minimum and calculated < minimum:
            calculated = minimum
        
        self.commission_rate = rate
        self.commission_amount = calculated
        return calculated
    
    def approve_transaction(self, approver_id: int, notes: Optional[str] = None) -> None:
        """
        Approve the transaction.
        
        Args:
            approver_id: ID of user approving the transaction
            notes: Approval notes
        """
        if not self.requires_approval:
            raise ValueError("Transaction does not require approval")
        
        if self.approved_at:
            raise ValueError("Transaction already approved")
        
        self.approved_by = approver_id
        self.approved_at = func.now()
        self.approval_notes = notes
        
        # Auto-complete if no other conditions prevent it
        if self.status == TransactionStatus.PENDING.value:
            self.status = TransactionStatus.COMPLETED.value
            self.completed_at = func.now()
    
    def complete_transaction(self) -> None:
        """Mark transaction as completed."""
        if self.requires_approval and not self.approved_at:
            raise ValueError("Transaction requires approval before completion")
        
        self.status = TransactionStatus.COMPLETED.value
        self.completed_at = func.now()
        
        # Update net amount
        self.net_amount = self.from_amount - self.commission_amount - self.fee_amount
    
    def cancel_transaction(self, reason: str) -> None:
        """
        Cancel the transaction.
        
        Args:
            reason: Reason for cancellation
        """
        if self.status == TransactionStatus.COMPLETED.value:
            raise ValueError("Cannot cancel completed transaction")
        
        self.status = TransactionStatus.CANCELLED.value
        self.notes = f"{self.notes or ''}\nCancelled: {reason}".strip()
    
    def reverse_transaction(self, reason: str, reversal_transaction_id: int) -> None:
        """
        Mark transaction as reversed.
        
        Args:
            reason: Reason for reversal
            reversal_transaction_id: ID of the reversal transaction
        """
        if self.status != TransactionStatus.COMPLETED.value:
            raise ValueError("Can only reverse completed transactions")
        
        self.status = TransactionStatus.REVERSED.value
        self.reversal_reason = reason
        self.reversed_transaction_id = reversal_transaction_id
    
    def add_compliance_flag(self, flag: str) -> None:
        """
        Add compliance flag to transaction.
        
        Args:
            flag: Compliance flag to add
        """
        import json
        
        flags = []
        if self.compliance_flags:
            try:
                flags = json.loads(self.compliance_flags)
            except json.JSONDecodeError:
                flags = []
        
        if flag not in flags:
            flags.append(flag)
        
        self.compliance_flags = json.dumps(flags)
    
    def perform_aml_check(self, risk_score: int) -> None:
        """
        Perform AML check on transaction.
        
        Args:
            risk_score: AML risk score (0-100)
        """
        self.aml_checked = True
        self.aml_risk_score = str(risk_score)
        
        # Add compliance flags based on risk score
        if risk_score >= 80:
            self.add_compliance_flag("HIGH_RISK")
        elif risk_score >= 50:
            self.add_compliance_flag("MEDIUM_RISK")
    
    def generate_receipt_number(self) -> str:
        """
        Generate receipt number for transaction.
        
        Returns:
            str: Generated receipt number
        """
        if self.receipt_number:
            return self.receipt_number
        
        # Format: RCP-YYYYMMDD-XXXXXX
        from datetime import datetime
        date_str = datetime.now().strftime("%Y%m%d")
        sequence = str(self.id).zfill(6)
        
        self.receipt_number = f"RCP-{date_str}-{sequence}"
        return self.receipt_number
    
    def to_dict(self, include_sensitive: bool = False) -> Dict[str, Any]:
        """
        Convert transaction to dictionary.
        
        Args:
            include_sensitive: Whether to include sensitive information
            
        Returns:
            Dict: Transaction data
        """
        data = {
            'transaction_id': self.transaction_id,
            'transaction_type': self.transaction_type,
            'status': self.status,
            'from_currency': self.from_currency_code,
            'to_currency': self.to_currency_code,
            'from_amount': float(self.from_amount),
            'to_amount': float(self.to_amount) if self.to_amount else None,
            'exchange_rate': float(self.exchange_rate) if self.exchange_rate else None,
            'commission_amount': float(self.commission_amount),
            'fee_amount': float(self.fee_amount),
            'net_amount': float(self.net_amount),
            'transaction_date': self.transaction_date.isoformat(),
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'payment_method': self.payment_method,
            'customer_id': self.customer_id,
            'branch_id': self.branch_id,
            'receipt_number': self.receipt_number
        }
        
        if include_sensitive:
            data.update({
                'user_id': self.user_id,
                'aml_risk_score': self.aml_risk_score,
                'compliance_flags': self.compliance_flags,
                'notes': self.notes
            })
        
        return data
    
    def __repr__(self) -> str:
        return (f"<Transaction(id='{self.transaction_id}', "
                f"type='{self.transaction_type}', status='{self.status}', "
                f"amount={self.from_amount})>")


class CurrencyExchange(Transaction):
    """
    Currency exchange transaction model.
    Inherits from Transaction with additional exchange-specific fields.
    """
    
    __tablename__ = "currency_exchanges"
    
    # Inheritance relationship
    id = Column(
        Integer,
        ForeignKey('transactions.id'),
        primary_key=True,
        comment="Reference to parent transaction"
    )
    
    # Exchange-specific fields
    buy_rate = Column(
        Numeric(precision=15, scale=8),
        nullable=True,
        comment="Buy rate offered to customer"
    )
    
    sell_rate = Column(
        Numeric(precision=15, scale=8),
        nullable=True,
        comment="Sell rate offered to customer"
    )
    
    spread = Column(
        Numeric(precision=8, scale=4),
        nullable=True,
        comment="Spread applied (difference from mid rate)"
    )
    
    margin_percentage = Column(
        Numeric(precision=5, scale=4),
        nullable=True,
        comment="Margin percentage applied"
    )
    
    # Rate source information
    rate_source = Column(
        String(100),
        nullable=True,
        comment="Source of the exchange rate"
    )
    
    rate_timestamp = Column(
        DateTime,
        nullable=True,
        comment="When the rate was quoted"
    )
    
    rate_valid_until = Column(
        DateTime,
        nullable=True,
        comment="Rate validity expiry"
    )
    
    # Physical currency handling
    delivered_amount = Column(
        Numeric(precision=15, scale=4),
        nullable=True,
        comment="Actual amount delivered (may differ due to denominations)"
    )
    
    denomination_breakdown = Column(
        JSON,
        nullable=True,
        comment="Breakdown of currency denominations"
    )
    
    __mapper_args__ = {
        'polymorphic_identity': TransactionType.CURRENCY_EXCHANGE.value
    }
    
    def calculate_spread(self, mid_rate: Decimal) -> Decimal:
        """
        Calculate spread from mid rate.
        
        Args:
            mid_rate: Mid market rate
            
        Returns:
            Decimal: Calculated spread
        """
        if self.exchange_rate and mid_rate:
            self.spread = abs(self.exchange_rate - mid_rate)
        return self.spread or Decimal('0')


class CashTransaction(Transaction):
    """
    Base class for cash deposit and withdrawal transactions.
    """
    
    __tablename__ = "cash_transactions"
    
    # Inheritance relationship
    id = Column(
        Integer,
        ForeignKey('transactions.id'),
        primary_key=True,
        comment="Reference to parent transaction"
    )
    
    # Cash-specific fields
    denomination_breakdown = Column(
        JSON,
        nullable=True,
        comment="Breakdown of cash denominations"
    )
    
    counted_by = Column(
        Integer,  # ForeignKey('users.id')
        nullable=True,
        comment="User who counted the cash"
    )
    
    verified_by = Column(
        Integer,  # ForeignKey('users.id')
        nullable=True,
        comment="User who verified the cash count"
    )
    
    vault_transaction_id = Column(
        Integer,  # ForeignKey('vault_transactions.id')
        nullable=True,
        comment="Related vault transaction"
    )


class CashDeposit(CashTransaction):
    """Cash deposit transaction model."""
    
    __mapper_args__ = {
        'polymorphic_identity': TransactionType.CASH_DEPOSIT.value
    }
    
    # Deposit source information
    deposit_source = Column(
        String(100),
        nullable=True,
        comment="Source of the deposited funds"
    )
    
    source_account = Column(
        String(100),
        nullable=True,
        comment="Source account reference"
    )


class CashWithdrawal(CashTransaction):
    """Cash withdrawal transaction model."""
    
    __mapper_args__ = {
        'polymorphic_identity': TransactionType.CASH_WITHDRAWAL.value
    }
    
    # Withdrawal destination
    withdrawal_purpose = Column(
        String(255),
        nullable=True,
        comment="Purpose of withdrawal"
    )
    
    authorized_by = Column(
        Integer,  # ForeignKey('users.id')
        nullable=True,
        comment="User who authorized large withdrawal"
    )


class Transfer(Transaction):
    """
    Transfer transaction model for money transfers.
    """
    
    __tablename__ = "transfers"
    
    # Inheritance relationship
    id = Column(
        Integer,
        ForeignKey('transactions.id'),
        primary_key=True,
        comment="Reference to parent transaction"
    )
    
    # Transfer parties
    sender_name = Column(
        String(200),
        nullable=True,
        comment="Name of sender"
    )
    
    sender_id_number = Column(
        String(50),
        nullable=True,
        comment="Sender identification number"
    )
    
    sender_phone = Column(
        String(20),
        nullable=True,
        comment="Sender phone number"
    )
    
    beneficiary_name = Column(
        String(200),
        nullable=True,
        comment="Name of beneficiary"
    )
    
    beneficiary_id_number = Column(
        String(50),
        nullable=True,
        comment="Beneficiary identification number"
    )
    
    beneficiary_phone = Column(
        String(20),
        nullable=True,
        comment="Beneficiary phone number"
    )
    
    # Transfer details
    transfer_purpose = Column(
        String(255),
        nullable=True,
        comment="Purpose of transfer"
    )
    
    destination_country = Column(
        String(3),
        nullable=True,
        comment="Destination country code"
    )
    
    correspondent_bank = Column(
        String(200),
        nullable=True,
        comment="Correspondent bank information"
    )
    
    # Delivery information
    delivery_method = Column(
        String(50),
        nullable=True,
        comment="How transfer will be delivered"
    )
    
    pickup_location = Column(
        String(255),
        nullable=True,
        comment="Pickup location for beneficiary"
    )
    
    tracking_number = Column(
        String(100),
        nullable=True,
        unique=True,
        comment="Transfer tracking number"
    )
    
    expected_delivery_date = Column(
        DateTime,
        nullable=True,
        comment="Expected delivery date"
    )
    
    delivered_at = Column(
        DateTime,
        nullable=True,
        comment="When transfer was delivered"
    )
    
    delivered_to = Column(
        String(200),
        nullable=True,
        comment="Who received the transfer"
    )
    
    __mapper_args__ = {
        'polymorphic_identity': TransactionType.TRANSFER.value
    }


class Commission(Transaction):
    """
    Commission transaction model for tracking commission earnings.
    """
    
    __tablename__ = "commissions"
    
    # Inheritance relationship
    id = Column(
        Integer,
        ForeignKey('transactions.id'),
        primary_key=True,
        comment="Reference to parent transaction"
    )
    
    # Commission details
    source_transaction_id = Column(
        Integer,  # ForeignKey('transactions.id')
        nullable=False,
        comment="Transaction that generated this commission"
    )
    
    commission_type = Column(
        String(50),
        nullable=False,
        comment="Type of commission (exchange, transfer, etc.)"
    )
    
    rate_applied = Column(
        Numeric(precision=5, scale=4),
        nullable=False,
        comment="Commission rate that was applied"
    )
    
    base_amount = Column(
        Numeric(precision=15, scale=4),
        nullable=False,
        comment="Base amount commission was calculated on"
    )
    
    __mapper_args__ = {
        'polymorphic_identity': TransactionType.COMMISSION.value
    }
    
    # Relationship to source transaction
    source_transaction = relationship(
        "Transaction",
        foreign_keys=[source_transaction_id],
        backref="generated_commissions"
    )