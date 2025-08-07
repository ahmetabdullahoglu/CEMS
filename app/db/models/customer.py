"""
Module: customer
Purpose: Customer model for CEMS customer management
Author: CEMS Development Team
Date: 2024
"""

from datetime import datetime, date
from decimal import Decimal
from typing import Optional, List, Dict, Any
from sqlalchemy import (
    Column, String, Numeric, Boolean, DateTime, Date, Text, ForeignKey,
    Index, CheckConstraint, UniqueConstraint, func, Integer
)
from sqlalchemy.orm import relationship, validates
from sqlalchemy.ext.hybrid import hybrid_property

from app.db.base import BaseModelWithSoftDelete


class Customer(BaseModelWithSoftDelete):
    """
    Customer model for managing currency exchange customers.
    Stores personal/business information, preferences, and transaction history.
    """
    
    __tablename__ = "customers"
    
    # Customer identification
    customer_code = Column(
        String(20),
        nullable=False,
        unique=True,
        index=True,
        comment="Unique customer code (auto-generated)"
    )
    
    customer_type = Column(
        String(20),
        nullable=False,
        default='individual',
        comment="Type of customer (individual, business, corporate)"
    )
    
    # Personal information (for individuals)
    first_name = Column(
        String(100),
        nullable=True,
        comment="Customer's first name"
    )
    
    middle_name = Column(
        String(100),
        nullable=True,
        comment="Customer's middle name"
    )
    
    last_name = Column(
        String(100),
        nullable=True,
        comment="Customer's last name"
    )
    
    first_name_arabic = Column(
        String(100),
        nullable=True,
        comment="Customer's first name in Arabic"
    )
    
    last_name_arabic = Column(
        String(100),
        nullable=True,
        comment="Customer's last name in Arabic"
    )
    
    # Business information (for business customers)
    company_name = Column(
        String(200),
        nullable=True,
        comment="Company name for business customers"
    )
    
    company_name_arabic = Column(
        String(200),
        nullable=True,
        comment="Company name in Arabic"
    )
    
    business_type = Column(
        String(50),
        nullable=True,
        comment="Type of business"
    )
    
    # Identification documents
    id_type = Column(
        String(20),
        nullable=False,
        comment="Type of identification document"
    )
    
    id_number = Column(
        String(50),
        nullable=False,
        index=True,
        comment="Identification document number"
    )
    
    id_expiry_date = Column(
        Date,
        nullable=True,
        comment="ID document expiry date"
    )
    
    id_issuing_country = Column(
        String(3),
        nullable=True,
        comment="Country that issued the ID"
    )
    
    # Secondary identification
    secondary_id_type = Column(
        String(20),
        nullable=True,
        comment="Secondary ID type (passport, etc.)"
    )
    
    secondary_id_number = Column(
        String(50),
        nullable=True,
        comment="Secondary ID number"
    )
    
    passport_number = Column(
        String(50),
        nullable=True,
        comment="Passport number if applicable"
    )
    
    # Personal details
    date_of_birth = Column(
        Date,
        nullable=True,
        comment="Date of birth"
    )
    
    gender = Column(
        String(10),
        nullable=True,
        comment="Customer gender"
    )
    
    nationality = Column(
        String(3),
        nullable=True,
        comment="Customer nationality (country code)"
    )
    
    marital_status = Column(
        String(20),
        nullable=True,
        comment="Marital status"
    )
    
    occupation = Column(
        String(100),
        nullable=True,
        comment="Customer occupation"
    )
    
    # Contact information
    phone_number = Column(
        String(20),
        nullable=True,
        comment="Primary phone number"
    )
    
    mobile_number = Column(
        String(20),
        nullable=False,
        index=True,
        comment="Mobile phone number (required)"
    )
    
    email = Column(
        String(255),
        nullable=True,
        index=True,
        comment="Email address"
    )
    
    # Address information
    address_line1 = Column(
        String(200),
        nullable=True,
        comment="Primary address line"
    )
    
    address_line2 = Column(
        String(200),
        nullable=True,
        comment="Secondary address line"
    )
    
    city = Column(
        String(100),
        nullable=True,
        comment="City"
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
        nullable=True,
        comment="Country code"
    )
    
    # Customer status and classification
    status = Column(
        String(20),
        nullable=False,
        default='active',
        comment="Customer account status"
    )
    
    classification = Column(
        String(20),
        nullable=False,
        default='standard',
        comment="Customer classification for pricing"
    )
    
    risk_level = Column(
        String(20),
        nullable=False,
        default='low',
        comment="Customer risk assessment level"
    )
    
    # KYC (Know Your Customer) information
    kyc_status = Column(
        String(20),
        nullable=False,
        default='pending',
        comment="KYC verification status"
    )
    
    kyc_completed_date = Column(
        DateTime,
        nullable=True,
        comment="Date when KYC was completed"
    )
    
    kyc_expiry_date = Column(
        DateTime,
        nullable=True,
        comment="Date when KYC needs renewal"
    )
    
    kyc_verified_by = Column(
        Integer,
        ForeignKey('users.id'),
        nullable=True,
        comment="User who verified the KYC"
    )
    
    # AML (Anti-Money Laundering) flags
    is_pep = Column(
        Boolean,
        nullable=False,
        default=False,
        server_default='false',
        comment="Politically Exposed Person flag"
    )
    
    aml_risk_score = Column(
        String(10),
        nullable=False,
        default='0',
        comment="AML risk score (0-100)"
    )
    
    sanctions_checked = Column(
        Boolean,
        nullable=False,
        default=False,
        server_default='false',
        comment="Whether sanctions list was checked"
    )
    
    sanctions_check_date = Column(
        DateTime,
        nullable=True,
        comment="Last sanctions check date"
    )
    
    # Financial information
    estimated_monthly_volume = Column(
        Numeric(precision=15, scale=2),
        nullable=True,
        comment="Estimated monthly transaction volume"
    )
    
    source_of_funds = Column(
        String(100),
        nullable=True,
        comment="Source of customer funds"
    )
    
    # Transaction limits
    daily_limit = Column(
        Numeric(precision=15, scale=2),
        nullable=True,
        comment="Daily transaction limit for this customer"
    )
    
    monthly_limit = Column(
        Numeric(precision=15, scale=2),
        nullable=True,
        comment="Monthly transaction limit"
    )
    
    single_transaction_limit = Column(
        Numeric(precision=15, scale=2),
        nullable=True,
        comment="Single transaction limit"
    )
    
    # Commission and pricing
    commission_rate = Column(
        Numeric(precision=5, scale=4),
        nullable=True,
        comment="Custom commission rate (overrides standard rates)"
    )
    
    minimum_commission = Column(
        Numeric(precision=8, scale=2),
        nullable=True,
        comment="Minimum commission amount"
    )
    
    # Customer preferences
    preferred_language = Column(
        String(10),
        nullable=False,
        default='en',
        comment="Customer's preferred language"
    )
    
    preferred_currency = Column(
        String(3),
        nullable=True,
        comment="Customer's preferred currency"
    )
    
    notification_preferences = Column(
        String(100),
        nullable=False,
        default='sms,email',
        comment="Notification preferences (comma-separated)"
    )
    
    # Registration and referral (Fixed Foreign Keys)
    registration_date = Column(
        DateTime,
        nullable=False,
        default=func.now(),
        comment="Customer registration date"
    )
    
    registration_branch_id = Column(
        Integer,
        ForeignKey('branches.id'),
        nullable=True,
        comment="Branch where customer was registered"
    )
    
    registered_by = Column(
        Integer,
        ForeignKey('users.id'),
        nullable=True,
        comment="User who registered the customer"
    )
    
    referral_source = Column(
        String(100),
        nullable=True,
        comment="How customer found out about the service"
    )
    
    referral_code = Column(
        String(50),
        nullable=True,
        comment="Referral code used by customer"
    )
    
    # Activity tracking
    last_transaction_date = Column(
        DateTime,
        nullable=True,
        comment="Date of last transaction"
    )
    
    total_transactions = Column(
        String(10),
        nullable=False,
        default='0',
        comment="Total number of transactions"
    )
    
    total_volume = Column(
        Numeric(precision=20, scale=2),
        nullable=False,
        default=Decimal('0.00'),
        comment="Total transaction volume (base currency)"
    )
    
    last_login_date = Column(
        DateTime,
        nullable=True,
        comment="Last login date (if customer has online access)"
    )
    
    # Document attachments
    profile_image_url = Column(
        String(500),
        nullable=True,
        comment="Customer profile image URL"
    )
    
    id_document_front_url = Column(
        String(500),
        nullable=True,
        comment="Front side of ID document"
    )
    
    id_document_back_url = Column(
        String(500),
        nullable=True,
        comment="Back side of ID document"
    )
    
    additional_documents = Column(
        Text,
        nullable=True,
        comment="JSON array of additional document URLs"
    )
    
    # Special notes and flags
    is_vip = Column(
        Boolean,
        nullable=False,
        default=False,
        server_default='false',
        comment="VIP customer flag"
    )
    
    is_blacklisted = Column(
        Boolean,
        nullable=False,
        default=False,
        server_default='false',
        comment="Blacklisted customer flag"
    )
    
    blacklist_reason = Column(
        String(255),
        nullable=True,
        comment="Reason for blacklisting"
    )
    
    blacklisted_date = Column(
        DateTime,
        nullable=True,
        comment="Date when customer was blacklisted"
    )
    
    requires_approval = Column(
        Boolean,
        nullable=False,
        default=False,
        server_default='false',
        comment="Whether transactions require special approval"
    )
    
    notes = Column(
        Text,
        nullable=True,
        comment="Additional notes about the customer"
    )
    
    # Relationships (Fixed)
    transactions = relationship(
        "Transaction",
        foreign_keys="Transaction.customer_id",
        back_populates="customer",
        lazy="dynamic"
    )
    
    registration_branch = relationship(
        "Branch",
        foreign_keys=[registration_branch_id],
        back_populates="customers"
    )
    
    registered_by_user = relationship(
        "User",
        foreign_keys=[registered_by],
        backref="registered_customers"
    )
    
    kyc_verifier = relationship(
        "User",
        foreign_keys=[kyc_verified_by],
        backref="verified_customers"
    )
    
    # Table constraints and indexes
    __table_args__ = (
        CheckConstraint(
            "customer_type IN ('individual', 'business', 'corporate')",
            name="valid_customer_type"
        ),
        CheckConstraint(
            "status IN ('active', 'inactive', 'suspended', 'closed')",
            name="valid_customer_status"
        ),
        CheckConstraint(
            "classification IN ('standard', 'vip', 'premium', 'corporate')",
            name="valid_classification"
        ),
        CheckConstraint(
            "risk_level IN ('low', 'medium', 'high')",
            name="valid_risk_level"
        ),
        CheckConstraint(
            "kyc_status IN ('pending', 'in_progress', 'completed', 'rejected', 'expired')",
            name="valid_kyc_status"
        ),
        CheckConstraint(
            "id_type IN ('national_id', 'passport', 'driving_license', 'residence_permit')",
            name="valid_id_type"
        ),
        CheckConstraint(
            "gender IN ('male', 'female', 'other')",
            name="valid_gender"
        ),
        CheckConstraint(
            "daily_limit IS NULL OR daily_limit > 0",
            name="positive_daily_limit"
        ),
        CheckConstraint(
            "monthly_limit IS NULL OR monthly_limit > 0",
            name="positive_monthly_limit"
        ),
        CheckConstraint(
            "commission_rate IS NULL OR (commission_rate >= 0 AND commission_rate <= 1)",
            name="valid_commission_rate"
        ),
        CheckConstraint(
            "aml_risk_score::integer >= 0 AND aml_risk_score::integer <= 100",
            name="valid_aml_risk_score"
        ),
        UniqueConstraint('id_type', 'id_number', name='unique_customer_id'),
        Index("idx_customer_mobile", mobile_number),
        Index("idx_customer_email", email),
        Index("idx_customer_status_type", status, customer_type),
        Index("idx_customer_classification", classification),
        Index("idx_customer_kyc", kyc_status, kyc_expiry_date),
        Index("idx_customer_risk", risk_level, is_blacklisted),
        Index("idx_customer_activity", last_transaction_date, status),
    )
    
    # Hybrid properties
    @hybrid_property
    def full_name(self) -> str:
        """Get customer's full name."""
        if self.customer_type == 'individual':
            name_parts = [self.first_name, self.middle_name, self.last_name]
            return " ".join(filter(None, name_parts))
        else:
            return self.company_name or "Unknown Company"
    
    @hybrid_property
    def display_name(self) -> str:
        """Get display name for UI."""
        if self.customer_type == 'individual':
            return f"{self.first_name} {self.last_name}" if self.first_name and self.last_name else self.customer_code
        else:
            return self.company_name or self.customer_code
    
    @hybrid_property
    def age(self) -> Optional[int]:
        """Calculate customer age."""
        if not self.date_of_birth:
            return None
        
        today = date.today()
        return today.year - self.date_of_birth.year - (
            (today.month, today.day) < (self.date_of_birth.month, self.date_of_birth.day)
        )
    
    @hybrid_property
    def is_kyc_valid(self) -> bool:
        """Check if KYC is valid and not expired."""
        if self.kyc_status != 'completed':
            return False
        
        if self.kyc_expiry_date and datetime.now() > self.kyc_expiry_date:
            return False
        
        return True
    
    @hybrid_property
    def is_id_expired(self) -> bool:
        """Check if customer's ID has expired."""
        if not self.id_expiry_date:
            return False
        
        return date.today() > self.id_expiry_date
    
    @hybrid_property
    def can_transact(self) -> bool:
        """Check if customer can perform transactions."""
        return (
            self.status == 'active' and
            not self.is_blacklisted and
            self.is_kyc_valid and
            not self.is_deleted
        )
    
    # Validation methods
    @validates('mobile_number', 'phone_number')
    def validate_phone(self, key, phone):
        """Validate phone number format."""
        if not phone:
            return phone
        
        import re
        cleaned_phone = phone.replace(' ', '').replace('-', '').replace('(', '').replace(')', '')
        if not re.match(r'^\+?[1-9]\d{1,14}$', cleaned_phone):
            raise ValueError(f"Invalid {key} format")
        
        return cleaned_phone
    
    @validates('email')
    def validate_email(self, key, email):
        """Validate email format."""
        if not email:
            return email
        
        import re
        if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
            raise ValueError("Invalid email format")
        
        return email.lower()
    
    @validates('customer_code')
    def validate_customer_code(self, key, code):
        """Validate customer code format."""
        if not code:
            return code
        
        import re
        if not re.match(r'^CUS\d{6,10}$', code.upper()):
            raise ValueError("Customer code must be in format: CUS + 6-10 digits")
        
        return code.upper()
    
    # Business logic methods
    def update_activity_stats(self, transaction_amount: Decimal) -> None:
        """
        Update customer activity statistics.
        
        Args:
            transaction_amount: Amount of the transaction
        """
        self.last_transaction_date = func.now()
        self.total_transactions = str(int(self.total_transactions) + 1)
        self.total_volume += transaction_amount
    
    def is_within_limits(self, amount: Decimal, period: str = 'single') -> bool:
        """
        Check if transaction amount is within customer limits.
        
        Args:
            amount: Transaction amount
            period: Limit period ('single', 'daily', 'monthly')
            
        Returns:
            bool: True if within limits
        """
        if period == 'single' and self.single_transaction_limit:
            return amount <= self.single_transaction_limit
        elif period == 'daily' and self.daily_limit:
            return amount <= self.daily_limit
        elif period == 'monthly' and self.monthly_limit:
            return amount <= self.monthly_limit
        
        return True
    
    def get_effective_commission_rate(self, base_rate: Decimal) -> Decimal:
        """
        Get effective commission rate for customer.
        
        Args:
            base_rate: Base commission rate
            
        Returns:
            Decimal: Effective commission rate
        """
        if self.commission_rate is not None:
            return self.commission_rate
        
        # Apply classification-based rates
        if self.classification == 'vip':
            return base_rate * Decimal('0.75')  # 25% discount
        elif self.classification == 'premium':
            return base_rate * Decimal('0.60')  # 40% discount
        elif self.classification == 'corporate':
            return base_rate * Decimal('0.50')  # 50% discount
        
        return base_rate
    
    def blacklist_customer(self, reason: str, user_id: int) -> None:
        """
        Blacklist customer.
        
        Args:
            reason: Reason for blacklisting
            user_id: ID of user who blacklisted the customer
        """
        self.is_blacklisted = True
        self.blacklist_reason = reason
        self.blacklisted_date = func.now()
        self.status = 'suspended'
    
    def remove_from_blacklist(self) -> None:
        """Remove customer from blacklist."""
        self.is_blacklisted = False
        self.blacklist_reason = None
        self.blacklisted_date = None
        if self.status == 'suspended':
            self.status = 'active'
    
    def upgrade_to_vip(self) -> None:
        """Upgrade customer to VIP status."""
        self.is_vip = True
        self.classification = 'vip'
    
    def complete_kyc(self, verified_by: int, expiry_months: int = 24) -> None:
        """
        Mark KYC as completed.
        
        Args:
            verified_by: ID of user who verified KYC
            expiry_months: KYC validity in months
        """
        from datetime import datetime, timedelta
        
        self.kyc_status = 'completed'
        self.kyc_completed_date = func.now()
        self.kyc_verified_by = verified_by
        self.kyc_expiry_date = datetime.now() + timedelta(days=expiry_months * 30)
    
    def get_transaction_summary(self) -> Dict[str, Any]:
        """
        Get customer transaction summary.
        
        Returns:
            Dict: Transaction summary statistics
        """
        return {
            'total_transactions': int(self.total_transactions),
            'total_volume': float(self.total_volume),
            'last_transaction_date': self.last_transaction_date.isoformat() if self.last_transaction_date else None,
            'registration_date': self.registration_date.isoformat(),
            'average_transaction_size': float(self.total_volume / max(int(self.total_transactions), 1)),
            'is_active': self.can_transact,
            'classification': self.classification,
            'risk_level': self.risk_level
        }
    
    def get_kyc_status_info(self) -> Dict[str, Any]:
        """
        Get KYC status information.
        
        Returns:
            Dict: KYC status details
        """
        return {
            'kyc_status': self.kyc_status,
            'is_valid': self.is_kyc_valid,
            'completed_date': self.kyc_completed_date.isoformat() if self.kyc_completed_date else None,
            'expiry_date': self.kyc_expiry_date.isoformat() if self.kyc_expiry_date else None,
            'days_until_expiry': (self.kyc_expiry_date - datetime.now()).days if self.kyc_expiry_date else None,
            'is_id_expired': self.is_id_expired,
            'id_expiry_date': self.id_expiry_date.isoformat() if self.id_expiry_date else None
        }
    
    def __repr__(self) -> str:
        return (f"<Customer(code='{self.customer_code}', "
                f"name='{self.display_name}', status='{self.status}')>")