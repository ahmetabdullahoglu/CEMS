"""Initial migration: Create users, roles, currencies and exchange rates tables

Revision ID: 001
Revises: 
Create Date: 2024-01-15 10:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '001'
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create initial database schema."""
    
    # Create roles table
    op.create_table(
        'roles',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False, comment='Primary key'),
        sa.Column('created_at', sa.DateTime(), server_default=sa.text('now()'), nullable=False, comment='Record creation timestamp'),
        sa.Column('updated_at', sa.DateTime(), server_default=sa.text('now()'), nullable=False, comment='Record last update timestamp'),
        sa.Column('is_deleted', sa.Boolean(), server_default='false', nullable=False, comment='Soft delete flag'),
        sa.Column('deleted_at', sa.DateTime(), nullable=True, comment='Soft delete timestamp'),
        sa.Column('created_by', sa.Integer(), nullable=True, comment='User ID who created this record'),
        sa.Column('updated_by', sa.Integer(), nullable=True, comment='User ID who last updated this record'),
        sa.Column('name', sa.String(length=50), nullable=False, comment='Role name (unique identifier)'),
        sa.Column('display_name', sa.String(length=100), nullable=False, comment='Human-readable role name'),
        sa.Column('description', sa.Text(), nullable=True, comment='Role description and responsibilities'),
        sa.Column('is_active', sa.Boolean(), server_default='true', nullable=False, comment='Whether role is active and can be assigned'),
        sa.Column('is_system_role', sa.Boolean(), server_default='false', nullable=False, comment='System-defined role (cannot be modified by users)'),
        sa.Column('hierarchy_level', sa.String(length=10), nullable=False, server_default='0', comment='Role hierarchy level for permission inheritance'),
        sa.Column('permissions', sa.Text(), nullable=True, comment='JSON array of permissions assigned to this role'),
        sa.CheckConstraint("name IN ('super_admin', 'admin', 'branch_manager', 'cashier', 'accountant', 'auditor')", name='valid_role_name'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('name')
    )
    op.create_index('idx_role_hierarchy', 'roles', ['hierarchy_level'])
    op.create_index('idx_role_name_active', 'roles', ['name', 'is_active'])
    op.create_index(op.f('ix_roles_name'), 'roles', ['name'])

    # Create users table
    op.create_table(
        'users',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False, comment='Primary key'),
        sa.Column('created_at', sa.DateTime(), server_default=sa.text('now()'), nullable=False, comment='Record creation timestamp'),
        sa.Column('updated_at', sa.DateTime(), server_default=sa.text('now()'), nullable=False, comment='Record last update timestamp'),
        sa.Column('is_deleted', sa.Boolean(), server_default='false', nullable=False, comment='Soft delete flag'),
        sa.Column('deleted_at', sa.DateTime(), nullable=True, comment='Soft delete timestamp'),
        sa.Column('created_by', sa.Integer(), nullable=True, comment='User ID who created this record'),
        sa.Column('updated_by', sa.Integer(), nullable=True, comment='User ID who last updated this record'),
        sa.Column('username', sa.String(length=50), nullable=False, comment='Unique username for login'),
        sa.Column('email', sa.String(length=255), nullable=False, comment='User email address (must be unique)'),
        sa.Column('hashed_password', sa.String(length=255), nullable=False, comment='Bcrypt hashed password'),
        sa.Column('first_name', sa.String(length=100), nullable=False, comment="User's first name"),
        sa.Column('last_name', sa.String(length=100), nullable=False, comment="User's last name"),
        sa.Column('phone_number', sa.String(length=20), nullable=True, comment="User's phone number"),
        sa.Column('status', sa.String(length=20), nullable=False, server_default='pending', comment='User account status'),
        sa.Column('is_active', sa.Boolean(), server_default='true', nullable=False, comment='Whether user account is active'),
        sa.Column('is_superuser', sa.Boolean(), server_default='false', nullable=False, comment='Whether user has superuser privileges'),
        sa.Column('is_verified', sa.Boolean(), server_default='false', nullable=False, comment='Whether user email is verified'),
        sa.Column('last_login_at', sa.DateTime(), nullable=True, comment='Last successful login timestamp'),
        sa.Column('last_login_ip', sa.String(length=45), nullable=True, comment='IP address of last login'),
        sa.Column('failed_login_attempts', sa.String(length=10), nullable=False, server_default='0', comment='Number of consecutive failed login attempts'),
        sa.Column('locked_until', sa.DateTime(), nullable=True, comment='Account lock expiration time'),
        sa.Column('password_changed_at', sa.DateTime(), server_default=sa.text('now()'), nullable=True, comment='Last password change timestamp'),
        sa.Column('profile_image_url', sa.String(length=500), nullable=True, comment="URL to user's profile image"),
        sa.Column('language_preference', sa.String(length=10), nullable=False, server_default='en', comment="User's preferred language"),
        sa.Column('timezone', sa.String(length=50), nullable=False, server_default='UTC', comment="User's preferred timezone"),
        sa.Column('branch_id', sa.String(length=50), nullable=True, comment='ID of the branch user is assigned to'),
        sa.Column('two_factor_enabled', sa.Boolean(), server_default='false', nullable=False, comment='Whether 2FA is enabled for this user'),
        sa.Column('two_factor_secret', sa.String(length=100), nullable=True, comment='TOTP secret for 2FA (encrypted)'),
        sa.Column('email_verification_token', sa.String(length=100), nullable=True, comment='Token for email verification'),
        sa.Column('email_verification_sent_at', sa.DateTime(), nullable=True, comment='When email verification was last sent'),
        sa.Column('password_reset_token', sa.String(length=100), nullable=True, comment='Token for password reset'),
        sa.Column('password_reset_sent_at', sa.DateTime(), nullable=True, comment='When password reset was requested'),
        sa.CheckConstraint("status IN ('active', 'inactive', 'suspended', 'pending')", name='valid_user_status'),
        sa.CheckConstraint('length(username) >= 3', name='username_min_length'),
        sa.CheckConstraint('length(first_name) >= 1', name='first_name_not_empty'),
        sa.CheckConstraint('length(last_name) >= 1', name='last_name_not_empty'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('email'),
        sa.UniqueConstraint('username')
    )
    op.create_index('idx_user_branch', 'users', ['branch_id'])
    op.create_index('idx_user_email_status', 'users', ['email', 'status'])
    op.create_index('idx_user_last_login', 'users', ['last_login_at'])
    op.create_index('idx_user_status_active', 'users', ['status', 'is_active'])
    op.create_index(op.f('ix_users_email'), 'users', ['email'])
    op.create_index(op.f('ix_users_username'), 'users', ['username'])

    # Create currencies table
    op.create_table(
        'currencies',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False, comment='Primary key'),
        sa.Column('created_at', sa.DateTime(), server_default=sa.text('now()'), nullable=False, comment='Record creation timestamp'),
        sa.Column('updated_at', sa.DateTime(), server_default=sa.text('now()'), nullable=False, comment='Record last update timestamp'),
        sa.Column('is_deleted', sa.Boolean(), server_default='false', nullable=False, comment='Soft delete flag'),
        sa.Column('deleted_at', sa.DateTime(), nullable=True, comment='Soft delete timestamp'),
        sa.Column('created_by', sa.Integer(), nullable=True, comment='User ID who created this record'),
        sa.Column('updated_by', sa.Integer(), nullable=True, comment='User ID who last updated this record'),
        sa.Column('code', sa.String(length=3), nullable=False, comment='ISO 4217 currency code (e.g., USD, EUR)'),
        sa.Column('name', sa.String(length=100), nullable=False, comment='Full currency name (e.g., US Dollar)'),
        sa.Column('symbol', sa.String(length=10), nullable=False, comment='Currency symbol (e.g., $, €)'),
        sa.Column('decimal_places', sa.String(length=10), nullable=False, server_default='2', comment='Number of decimal places for this currency'),
        sa.Column('is_base_currency', sa.Boolean(), server_default='false', nullable=False, comment="Whether this is the system's base currency"),
        sa.Column('is_active', sa.Boolean(), server_default='true', nullable=False, comment='Whether currency is active for transactions'),
        sa.Column('display_order', sa.String(length=10), nullable=False, server_default='999', comment='Order for currency display in UI'),
        sa.Column('min_exchange_amount', sa.Numeric(precision=15, scale=4), nullable=False, server_default='1.0000', comment='Minimum amount for exchange transactions'),
        sa.Column('max_exchange_amount', sa.Numeric(precision=15, scale=4), nullable=True, comment='Maximum amount for exchange transactions (null = no limit)'),
        sa.Column('country_code', sa.String(length=3), nullable=True, comment='ISO 3166 country code where currency is primary'),
        sa.Column('description', sa.Text(), nullable=True, comment='Additional currency information'),
        sa.Column('allow_cash_transactions', sa.Boolean(), server_default='true', nullable=False, comment='Whether currency supports cash transactions'),
        sa.Column('allow_digital_transactions', sa.Boolean(), server_default='true', nullable=False, comment='Whether currency supports digital transactions'),
        sa.Column('requires_special_handling', sa.Boolean(), server_default='false', nullable=False, comment='Whether currency requires special handling procedures'),
        sa.CheckConstraint("code IN ('USD', 'EUR', 'GBP', 'SAR', 'AED', 'EGP', 'JOD', 'KWD', 'QAR', 'BHD', 'TRY', 'JPY', 'CHF', 'CAD', 'AUD')", name='valid_currency_code'),
        sa.CheckConstraint('length(code) = 3', name='currency_code_length'),
        sa.CheckConstraint('decimal_places::integer >= 0 AND decimal_places::integer <= 6', name='valid_decimal_places'),
        sa.CheckConstraint('min_exchange_amount > 0', name='positive_min_amount'),
        sa.CheckConstraint('max_exchange_amount IS NULL OR max_exchange_amount > min_exchange_amount', name='valid_max_amount'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('code')
    )
    op.create_index('idx_currency_base', 'currencies', ['is_base_currency'])
    op.create_index('idx_currency_code_active', 'currencies', ['code', 'is_active'])
    op.create_index('idx_currency_display_order', 'currencies', ['display_order'])
    op.create_index(op.f('ix_currencies_code'), 'currencies', ['code'])

    # Create user_roles association table
    op.create_table(
        'user_roles',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False, comment='Primary key'),
        sa.Column('created_at', sa.DateTime(), server_default=sa.text('now()'), nullable=False, comment='Record creation timestamp'),
        sa.Column('updated_at', sa.DateTime(), server_default=sa.text('now()'), nullable=False, comment='Record last update timestamp'),
        sa.Column('is_deleted', sa.Boolean(), server_default='false', nullable=False, comment='Soft delete flag'),
        sa.Column('deleted_at', sa.DateTime(), nullable=True, comment='Soft delete timestamp'),
        sa.Column('created_by', sa.Integer(), nullable=True, comment='User ID who created this record'),
        sa.Column('updated_by', sa.Integer(), nullable=True, comment='User ID who last updated this record'),
        sa.Column('user_id', sa.Integer(), nullable=False, comment='Reference to user'),
        sa.Column('role_id', sa.Integer(), nullable=False, comment='Reference to role'),
        sa.Column('assigned_by', sa.Integer(), nullable=True, comment='ID of user who assigned this role'),
        sa.Column('assigned_at', sa.DateTime(), server_default=sa.text('now()'), nullable=False, comment='When this role was assigned'),
        sa.Column('expires_at', sa.DateTime(), nullable=True, comment='When this role assignment expires (optional)'),
        sa.Column('is_active', sa.Boolean(), server_default='true', nullable=False, comment='Whether this role assignment is active'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('user_id', 'role_id', name='unique_user_role')
    )
    op.create_index('idx_role_expiry', 'user_roles', ['expires_at'])
    op.create_index('idx_user_role_active', 'user_roles', ['user_id', 'role_id', 'is_active'])
    op.create_index(op.f('ix_user_roles_role_id'), 'user_roles', ['role_id'])
    op.create_index(op.f('ix_user_roles_user_id'), 'user_roles', ['user_id'])

    # Create exchange_rates table
    op.create_table(
        'exchange_rates',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False, comment='Primary key'),
        sa.Column('created_at', sa.DateTime(), server_default=sa.text('now()'), nullable=False, comment='Record creation timestamp'),
        sa.Column('updated_at', sa.DateTime(), server_default=sa.text('now()'), nullable=False, comment='Record last update timestamp'),
        sa.Column('is_deleted', sa.Boolean(), server_default='false', nullable=False, comment='Soft delete flag'),
        sa.Column('deleted_at', sa.DateTime(), nullable=True, comment='Soft delete timestamp'),
        sa.Column('created_by', sa.Integer(), nullable=True, comment='User ID who created this record'),
        sa.Column('updated_by', sa.Integer(), nullable=True, comment='User ID who last updated this record'),
        sa.Column('from_currency_id', sa.Integer(), nullable=False, comment='Source currency ID'),
        sa.Column('to_currency_id', sa.Integer(), nullable=False, comment='Target currency ID'),
        sa.Column('from_currency_code', sa.String(length=3), nullable=False, comment='Source currency code'),
        sa.Column('to_currency_code', sa.String(length=3), nullable=False, comment='Target currency code'),
        sa.Column('rate', sa.Numeric(precision=15, scale=8), nullable=False, comment='Exchange rate (1 from_currency = rate * to_currency)'),
        sa.Column('rate_type', sa.String(length=10), nullable=False, server_default='mid', comment='Type of exchange rate (buy, sell, mid)'),
        sa.Column('effective_from', sa.DateTime(), server_default=sa.text('now()'), nullable=False, comment='When this rate becomes effective'),
        sa.Column('effective_until', sa.DateTime(), nullable=True, comment='When this rate expires (null = no expiry)'),
        sa.Column('is_active', sa.Boolean(), server_default='true', nullable=False, comment='Whether this rate is currently active'),
        sa.Column('source', sa.String(length=100), nullable=True, comment="Source of the exchange rate (e.g., 'central_bank', 'api_provider')"),
        sa.Column('source_reference', sa.String(length=255), nullable=True, comment='Reference/ID from the rate source'),
        sa.Column('buy_margin', sa.Numeric(precision=5, scale=4), nullable=True, server_default='0.0200', comment='Margin applied for buy transactions (percentage)'),
        sa.Column('sell_margin', sa.Numeric(precision=5, scale=4), nullable=True, server_default='0.0200', comment='Margin applied for sell transactions (percentage)'),
        sa.Column('reliability_score', sa.String(length=10), nullable=False, server_default='100', comment='Reliability score of this rate (0-100)'),
        sa.Column('last_updated_at', sa.DateTime(), server_default=sa.text('now()'), nullable=False, comment='When this rate was last updated'),
        sa.Column('approved_by', sa.Integer(), nullable=True, comment='User ID who approved this rate'),
        sa.Column('approved_at', sa.DateTime(), nullable=True, comment='When this rate was approved'),
        sa.Column('notes', sa.Text(), nullable=True, comment='Additional notes about this rate'),
        sa.CheckConstraint("rate_type IN ('buy', 'sell', 'mid')", name='valid_rate_type'),
        sa.CheckConstraint('rate > 0', name='positive_rate'),
        sa.CheckConstraint('buy_margin IS NULL OR (buy_margin >= 0 AND buy_margin <= 1)', name='valid_buy_margin'),
        sa.CheckConstraint('sell_margin IS NULL OR (sell_margin >= 0 AND sell_margin <= 1)', name='valid_sell_margin'),
        sa.CheckConstraint('reliability_score::integer >= 0 AND reliability_score::integer <= 100', name='valid_reliability_score'),
        sa.CheckConstraint('from_currency_id != to_currency_id', name='different_currencies'),
        sa.CheckConstraint('effective_until IS NULL OR effective_until > effective_from', name='valid_effective_period'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('from_currency_code', 'to_currency_code', 'rate_type', 'effective_from', name='unique_rate_per_period')
    )
    op.create_index('idx_rate_currencies_active', 'exchange_rates', ['from_currency_code', 'to_currency_code', 'is_active'])
    op.create_index('idx_rate_effective_period', 'exchange_rates', ['effective_from', 'effective_until'])
    op.create_index('idx_rate_source', 'exchange_rates', ['source'])
    op.create_index('idx_rate_type_active', 'exchange_rates', ['rate_type', 'is_active'])
    op.create_index(op.f('ix_exchange_rates_effective_from'), 'exchange_rates', ['effective_from'])
    op.create_index(op.f('ix_exchange_rates_effective_until'), 'exchange_rates', ['effective_until'])
    op.create_index(op.f('ix_exchange_rates_from_currency_code'), 'exchange_rates', ['from_currency_code'])
    op.create_index(op.f('ix_exchange_rates_from_currency_id'), 'exchange_rates', ['from_currency_id'])
    op.create_index(op.f('ix_exchange_rates_to_currency_code'), 'exchange_rates', ['to_currency_code'])
    op.create_index(op.f('ix_exchange_rates_to_currency_id'), 'exchange_rates', ['to_currency_id'])


def downgrade() -> None:
    """Drop all tables created in upgrade."""
    
    # Drop tables in reverse order of creation to handle dependencies
    op.drop_table('exchange_rates')
    op.drop_table('user_roles')
    op.drop_table('currencies')
    op.drop_table('users')
    op.drop_table('roles')