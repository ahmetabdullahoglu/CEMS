"""
Module: currency
Purpose: Currency and exchange rate models for CEMS
Author: CEMS Development Team
Date: 2024
"""

from datetime import datetime, timedelta
from decimal import Decimal
from typing import Optional, Dict, Any
from sqlalchemy import (
    Column, String, Numeric, Boolean, DateTime, Text, ForeignKey,
    Index, CheckConstraint, UniqueConstraint, func
)
from sqlalchemy.orm import relationship, validates
from sqlalchemy.ext.hybrid import hybrid_property

from app.db.base import BaseModelWithSoftDelete
from app.core.constants import CurrencyCode, ExchangeRateType


class Currency(BaseModelWithSoftDelete):
    """
    Currency model for managing supported currencies in the system.
    Stores currency information and configuration.
    """
    
    __tablename__ = "currencies"
    
    # Currency identification
    code = Column(
        String(3),
        nullable=False,
        unique=True,
        index=True,
        comment="ISO 4217 currency code (e.g., USD, EUR)"
    )
    
    name = Column(
        String(100),
        nullable=False,
        comment="Full currency name (e.g., US Dollar)"
    )
    
    symbol = Column(
        String(10),
        nullable=False,
        comment="Currency symbol (e.g., $, €)"
    )
    
    # Currency properties
    decimal_places = Column(
        String(10),
        nullable=False,
        default='2',
        comment="Number of decimal places for this currency"
    )
    
    is_base_currency = Column(
        Boolean,
        nullable=False,
        default=False,
        server_default='false',
        comment="Whether this is the system's base currency"
    )
    
    is_active = Column(
        Boolean,
        nullable=False,
        default=True,
        server_default='true',
        comment="Whether currency is active for transactions"
    )
    
    # Display and formatting
    display_order = Column(
        String(10),
        nullable=False,
        default='999',
        comment="Order for currency display in UI"
    )
    
    # Minimum transaction amounts
    min_exchange_amount = Column(
        Numeric(precision=15, scale=4),
        nullable=False,
        default=Decimal('1.0000'),
        comment="Minimum amount for exchange transactions"
    )
    
    max_exchange_amount = Column(
        Numeric(precision=15, scale=4),
        nullable=True,
        comment="Maximum amount for exchange transactions (null = no limit)"
    )
    
    # Currency metadata
    country_code = Column(
        String(3),
        nullable=True,
        comment="ISO 3166 country code where currency is primary"
    )
    
    description = Column(
        Text,
        nullable=True,
        comment="Additional currency information"
    )
    
    # Configuration flags
    allow_cash_transactions = Column(
        Boolean,
        nullable=False,
        default=True,
        server_default='true',
        comment="Whether currency supports cash transactions"
    )
    
    allow_digital_transactions = Column(
        Boolean,
        nullable=False,
        default=True,
        server_default='true',
        comment="Whether currency supports digital transactions"
    )
    
    requires_special_handling = Column(
        Boolean,
        nullable=False,
        default=False,
        server_default='false',
        comment="Whether currency requires special handling procedures"
    )
    
    # Relationships
    exchange_rates_from = relationship(
        "ExchangeRate",
        foreign_keys="ExchangeRate.from_currency_id",
        back_populates="from_currency",
        lazy="dynamic"
    )
    
    exchange_rates_to = relationship(
        "ExchangeRate",
        foreign_keys="ExchangeRate.to_currency_id", 
        back_populates="to_currency",
        lazy="dynamic"
    )
    
    # Table constraints
    __table_args__ = (
        CheckConstraint(
            code.in_([currency.value for currency in CurrencyCode]),
            name="valid_currency_code"
        ),
        CheckConstraint(
            "length(code) = 3",
            name="currency_code_length"
        ),
        CheckConstraint(
            "decimal_places::integer >= 0 AND decimal_places::integer <= 6",
            name="valid_decimal_places"
        ),
        CheckConstraint(
            "min_exchange_amount > 0",
            name="positive_min_amount"
        ),
        CheckConstraint(
            "max_exchange_amount IS NULL OR max_exchange_amount > min_exchange_amount",
            name="valid_max_amount"
        ),
        Index("idx_currency_code_active", code, is_active),
        Index("idx_currency_base", is_base_currency),
        Index("idx_currency_display_order", display_order),
    )
    
    @validates('code')
    def validate_code(self, key, code):
        """Validate currency code format and value."""
        if not code or len(code) != 3:
            raise ValueError("Currency code must be exactly 3 characters")
        
        code = code.upper()
        if code not in [currency.value for currency in CurrencyCode]:
            raise ValueError(f"Unsupported currency code: {code}")
        
        return code
    
    @validates('decimal_places')
    def validate_decimal_places(self, key, decimal_places):
        """Validate decimal places value."""
        try:
            places = int(decimal_places)
            if places < 0 or places > 6:
                raise ValueError("Decimal places must be between 0 and 6")
            return str(places)
        except (ValueError, TypeError):
            raise ValueError("Invalid decimal places value")
    
    # Helper methods
    def format_amount(self, amount: Decimal) -> str:
        """
        Format amount according to currency's decimal places.
        
        Args:
            amount: Amount to format
            
        Returns:
            str: Formatted amount
        """
        decimal_places = int(self.decimal_places)
        return f"{amount:.{decimal_places}f}"
    
    def get_latest_rate_to(self, target_currency_code: str) -> Optional['ExchangeRate']:
        """
        Get latest exchange rate to target currency.
        
        Args:
            target_currency_code: Target currency code
            
        Returns:
            ExchangeRate or None: Latest exchange rate
        """
        return (self.exchange_rates_from
                .filter_by(to_currency_code=target_currency_code, is_active=True)
                .order_by(ExchangeRate.effective_from.desc())
                .first())
    
    def __repr__(self) -> str:
        return f"<Currency(code='{self.code}', name='{self.name}')>"


class ExchangeRate(BaseModelWithSoftDelete):
    """
    Exchange rate model for storing currency conversion rates.
    Supports historical rates and different rate types.
    """
    
    __tablename__ = "exchange_rates"
    
    # Currency references
    from_currency_id = Column(
        Integer,  # ForeignKey('currencies.id')
        nullable=False,
        index=True,
        comment="Source currency ID"
    )
    
    to_currency_id = Column(
        Integer,  # ForeignKey('currencies.id')
        nullable=False,
        index=True,
        comment="Target currency ID"
    )
    
    # For easier querying, also store currency codes
    from_currency_code = Column(
        String(3),
        nullable=False,
        index=True,
        comment="Source currency code"
    )
    
    to_currency_code = Column(
        String(3),
        nullable=False,
        index=True,
        comment="Target currency code"
    )
    
    # Rate information
    rate = Column(
        Numeric(precision=15, scale=8),
        nullable=False,
        comment="Exchange rate (1 from_currency = rate * to_currency)"
    )
    
    rate_type = Column(
        String(10),
        nullable=False,
        default=ExchangeRateType.MID.value,
        comment="Type of exchange rate (buy, sell, mid)"
    )
    
    # Rate validity and timing
    effective_from = Column(
        DateTime,
        nullable=False,
        default=func.now(),
        index=True,
        comment="When this rate becomes effective"
    )
    
    effective_until = Column(
        DateTime,
        nullable=True,
        index=True,
        comment="When this rate expires (null = no expiry)"
    )
    
    is_active = Column(
        Boolean,
        nullable=False,
        default=True,
        server_default='true',
        comment="Whether this rate is currently active"
    )
    
    # Rate source and metadata
    source = Column(
        String(100),
        nullable=True,
        comment="Source of the exchange rate (e.g., 'central_bank', 'api_provider')"
    )
    
    source_reference = Column(
        String(255),
        nullable=True,
        comment="Reference/ID from the rate source"
    )
    
    # Rate margins and spreads
    buy_margin = Column(
        Numeric(precision=5, scale=4),
        nullable=True,
        default=Decimal('0.0200'),
        comment="Margin applied for buy transactions (percentage)"
    )
    
    sell_margin = Column(
        Numeric(precision=5, scale=4),
        nullable=True,
        default=Decimal('0.0200'),
        comment="Margin applied for sell transactions (percentage)"
    )
    
    # Quality and confidence indicators
    reliability_score = Column(
        String(10),
        nullable=False,
        default='100',
        comment="Reliability score of this rate (0-100)"
    )
    
    last_updated_at = Column(
        DateTime,
        nullable=False,
        default=func.now(),
        onupdate=func.now(),
        comment="When this rate was last updated"
    )
    
    # Administrative fields
    approved_by = Column(
        Integer,
        nullable=True,
        comment="User ID who approved this rate"
    )
    
    approved_at = Column(
        DateTime,
        nullable=True,
        comment="When this rate was approved"
    )
    
    notes = Column(
        Text,
        nullable=True,
        comment="Additional notes about this rate"
    )
    
    # Relationships
    from_currency = relationship(
        "Currency",
        foreign_keys=[from_currency_id],
        back_populates="exchange_rates_from"
    )
    
    to_currency = relationship(
        "Currency", 
        foreign_keys=[to_currency_id],
        back_populates="exchange_rates_to"
    )
    
    # Table constraints and indexes
    __table_args__ = (
        CheckConstraint(
            rate_type.in_([rate_type.value for rate_type in ExchangeRateType]),
            name="valid_rate_type"
        ),
        CheckConstraint(
            "rate > 0",
            name="positive_rate"
        ),
        CheckConstraint(
            "buy_margin IS NULL OR (buy_margin >= 0 AND buy_margin <= 1)",
            name="valid_buy_margin"
        ),
        CheckConstraint(
            "sell_margin IS NULL OR (sell_margin >= 0 AND sell_margin <= 1)",
            name="valid_sell_margin"
        ),
        CheckConstraint(
            "reliability_score::integer >= 0 AND reliability_score::integer <= 100",
            name="valid_reliability_score"
        ),
        CheckConstraint(
            "from_currency_id != to_currency_id",
            name="different_currencies"
        ),
        CheckConstraint(
            "effective_until IS NULL OR effective_until > effective_from",
            name="valid_effective_period"
        ),
        UniqueConstraint(
            'from_currency_code', 'to_currency_code', 'rate_type', 'effective_from',
            name='unique_rate_per_period'
        ),
        Index('idx_rate_currencies_active', from_currency_code, to_currency_code, is_active),
        Index('idx_rate_effective_period', effective_from, effective_until),
        Index('idx_rate_type_active', rate_type, is_active),
        Index('idx_rate_source', source),
    )
    
    # Hybrid properties
    @hybrid_property
    def is_current(self) -> bool:
        """Check if rate is currently valid."""
        now = datetime.utcnow()
        return (self.is_active and 
                self.effective_from <= now and
                (self.effective_until is None or self.effective_until > now))
    
    @hybrid_property
    def is_expired(self) -> bool:
        """Check if rate has expired."""
        if not self.effective_until:
            return False
        return datetime.utcnow() > self.effective_until
    
    @hybrid_property
    def inverse_rate(self) -> Decimal:
        """Calculate inverse exchange rate."""
        return Decimal('1') / self.rate if self.rate != 0 else Decimal('0')
    
    # Validation methods
    @validates('from_currency_code', 'to_currency_code')
    def validate_currency_codes(self, key, code):
        """Validate currency code format."""
        if not code or len(code) != 3:
            raise ValueError("Currency code must be exactly 3 characters")
        return code.upper()
    
    @validates('rate')
    def validate_rate(self, key, rate):
        """Validate exchange rate value."""
        if rate <= 0:
            raise ValueError("Exchange rate must be positive")
        return rate
    
    # Business logic methods
    def calculate_buy_rate(self) -> Decimal:
        """
        Calculate buy rate with margin applied.
        
        Returns:
            Decimal: Rate for buying the from_currency
        """
        if not self.buy_margin:
            return self.rate
        
        margin_factor = Decimal('1') + self.buy_margin
        return self.rate * margin_factor
    
    def calculate_sell_rate(self) -> Decimal:
        """
        Calculate sell rate with margin applied.
        
        Returns:
            Decimal: Rate for selling the from_currency
        """
        if not self.sell_margin:
            return self.rate
        
        margin_factor = Decimal('1') - self.sell_margin
        return self.rate * margin_factor
    
    def convert_amount(self, amount: Decimal, rate_type: str = 'mid') -> Decimal:
        """
        Convert amount using this exchange rate.
        
        Args:
            amount: Amount in from_currency
            rate_type: Type of rate to use ('buy', 'sell', 'mid')
            
        Returns:
            Decimal: Converted amount in to_currency
        """
        if rate_type == 'buy':
            rate = self.calculate_buy_rate()
        elif rate_type == 'sell':
            rate = self.calculate_sell_rate()
        else:
            rate = self.rate
        
        return amount * rate
    
    def expire_rate(self, expire_time: Optional[datetime] = None) -> None:
        """
        Expire this exchange rate.
        
        Args:
            expire_time: When to expire the rate (default: now)
        """
        self.effective_until = expire_time or datetime.utcnow()
        self.is_active = False
    
    def extend_validity(self, new_expiry: datetime) -> None:
        """
        Extend the validity of this exchange rate.
        
        Args:
            new_expiry: New expiry date
        """
        if new_expiry <= datetime.utcnow():
            raise ValueError("New expiry must be in the future")
        
        self.effective_until = new_expiry
        if not self.is_active:
            self.is_active = True
    
    def get_age_in_hours(self) -> float:
        """
        Get the age of this rate in hours.
        
        Returns:
            float: Hours since the rate was last updated
        """
        now = datetime.utcnow()
        delta = now - self.last_updated_at
        return delta.total_seconds() / 3600
    
    def is_stale(self, max_age_hours: int = 24) -> bool:
        """
        Check if the rate is stale (too old).
        
        Args:
            max_age_hours: Maximum age in hours before considering stale
            
        Returns:
            bool: True if rate is stale
        """
        return self.get_age_in_hours() > max_age_hours
    
    @classmethod
    def get_latest_rate(
        cls, 
        session, 
        from_currency: str, 
        to_currency: str, 
        rate_type: str = ExchangeRateType.MID.value
    ) -> Optional['ExchangeRate']:
        """
        Get the latest active exchange rate between two currencies.
        
        Args:
            session: Database session
            from_currency: Source currency code
            to_currency: Target currency code
            rate_type: Type of rate to retrieve
            
        Returns:
            ExchangeRate or None: Latest rate if found
        """
        now = datetime.utcnow()
        
        return session.query(cls).filter(
            cls.from_currency_code == from_currency.upper(),
            cls.to_currency_code == to_currency.upper(),
            cls.rate_type == rate_type,
            cls.is_active == True,
            cls.effective_from <= now,
            (cls.effective_until == None) | (cls.effective_until > now)
        ).order_by(cls.effective_from.desc()).first()
    
    @classmethod
    def get_cross_rate(
        cls, 
        session, 
        from_currency: str, 
        to_currency: str, 
        base_currency: str = 'USD',
        rate_type: str = ExchangeRateType.MID.value
    ) -> Optional[Decimal]:
        """
        Calculate cross rate between two currencies using a base currency.
        
        Args:
            session: Database session
            from_currency: Source currency code
            to_currency: Target currency code
            base_currency: Base currency for cross calculation
            rate_type: Type of rate to use
            
        Returns:
            Decimal or None: Cross rate if calculable
        """
        # Direct rate
        direct_rate = cls.get_latest_rate(session, from_currency, to_currency, rate_type)
        if direct_rate:
            return direct_rate.rate
        
        # Cross rate via base currency
        from_to_base = cls.get_latest_rate(session, from_currency, base_currency, rate_type)
        to_to_base = cls.get_latest_rate(session, to_currency, base_currency, rate_type)
        
        if from_to_base and to_to_base and to_to_base.rate != 0:
            return from_to_base.rate / to_to_base.rate
        
        # Try inverse cross rate
        base_to_from = cls.get_latest_rate(session, base_currency, from_currency, rate_type)
        base_to_to = cls.get_latest_rate(session, base_currency, to_currency, rate_type)
        
        if base_to_from and base_to_to and base_to_from.rate != 0:
            return base_to_to.rate / base_to_from.rate
        
        return None
    
    def __repr__(self) -> str:
        return (f"<ExchangeRate({self.from_currency_code}/{self.to_currency_code}="
                f"{self.rate}, type={self.rate_type})>")