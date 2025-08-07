"""Add branches, customers, transactions, and vault tables

Revision ID: 002
Revises: 001
Create Date: 2024-01-15 12:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '002'
down_revision = '001'
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create branches, customers, transactions, and vault tables."""
    
    # Create branches table
    op.create_table(
        'branches',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False, comment='Primary key'),
        sa.Column('created_at', sa.DateTime(), server_default=sa.text('now()'), nullable=False, comment='Record creation timestamp'),
        sa.Column('updated_at', sa.DateTime(), server_default=sa.text('now()'), nullable=False, comment='Record last update timestamp'),
        sa.Column('is_deleted', sa.Boolean(), server_default='false', nullable=False, comment='Soft delete flag'),
        sa.Column('deleted_at', sa.DateTime(), nullable=True, comment='Soft delete timestamp'),
        sa.Column('created_by', sa.Integer(), nullable=True, comment='User ID who created this record'),
        sa.Column('updated_by', sa.Integer(), nullable=True, comment='User ID who last updated this record'),
        sa.Column('branch_code', sa.String(length=10), nullable=False, comment='Unique branch code (e.g., BR001, BR002)'),
        sa.Column('name', sa.String(length=100), nullable=False, comment='Branch display name'),
        sa.Column('name_arabic', sa.String(length=100), nullable=True, comment='Branch name in Arabic'),
        sa.Column('address_line1', sa.String(length=200), nullable=False, comment='Primary address line'),
        sa.Column('address_line2', sa.String(length=200), nullable=True, comment='Secondary address line'),
        sa.Column('city', sa.String(length=100), nullable=False, comment='City name'),
        sa.Column('state_province', sa.String(length=100), nullable=True, comment='State or province'),
        sa.Column('postal_code', sa.String(length=20), nullable=True, comment='Postal/ZIP code'),
        sa.Column('country_code', sa.String(length=3), nullable=False, server_default='SAU', comment='ISO 3166 country code'),
        sa.Column('latitude', sa.Numeric(precision=10, scale=8), nullable=True, comment='Latitude coordinate'),
        sa.Column('longitude', sa.Numeric(precision=11, scale=8), nullable=True, comment='Longitude coordinate'),
        sa.Column('phone_number', sa.String(length=20), nullable=True, comment='Primary phone number'),
        sa.Column('fax_number', sa.String(length=20), nullable=True, comment='Fax number'),
        sa.Column('email', sa.String(length=255), nullable=True, comment='Branch email address'),
        sa.Column('branch_type', sa.String(length=20), nullable=False, server_default='standard', comment='Type of branch (main, standard, kiosk)'),
        sa.Column('status', sa.String(length=20), nullable=False, server_default='active', comment='Branch operational status'),
        sa.Column('is_main_branch', sa.Boolean(), server_default='false', nullable=False, comment='Whether this is the main/headquarters branch'),
        sa.Column('is_24_hours', sa.Boolean(), server_default='false', nullable=False, comment='Whether branch operates 24/7'),
        sa.Column('opening_time', sa.Time(), nullable=True, comment='Daily opening time'),
        sa.Column('closing_time', sa.Time(), nullable=True, comment='Daily closing time'),
        sa.Column('weekend_days', sa.String(length=20), nullable=False, server_default='friday,saturday', comment='Comma-separated weekend days'),
        sa.Column('operates_on_weekends', sa.Boolean(), server_default='false', nullable=False, comment='Whether branch operates on weekends'),
        sa.Column('operates_on_holidays', sa.Boolean(), server_default='false', nullable=False, comment='Whether branch operates on public holidays'),
        sa.Column('daily_transaction_limit', sa.Numeric(precision=15, scale=2), nullable=True, comment='Daily transaction limit for this branch'),
        sa.Column('single_transaction_limit', sa.Numeric(precision=15, scale=2), nullable=True, comment='Single transaction limit for this branch'),
        sa.Column('requires_manager_approval', sa.Boolean(), server_default='false', nullable=False, comment='Whether large transactions require manager approval'),
        sa.Column('manager_approval_threshold', sa.Numeric(precision=15, scale=2), nullable=True, comment='Amount threshold requiring manager approval'),
        sa.Column('has_vault', sa.Boolean(), server_default='true', nullable=False, comment='Whether branch has its own vault'),
        sa.Column('vault_capacity_usd', sa.Numeric(precision=15, scale=2), nullable=True, comment='Vault capacity in USD equivalent'),
        sa.Column('branch_manager_id', sa.Integer(), nullable=True, comment='Branch manager user ID'),
        sa.Column('opened_date', sa.DateTime(), nullable=True, comment='Branch opening date'),
        sa.Column('license_number', sa.String(length=100), nullable=True, comment='Government license number'),
        sa.Column('license_expiry_date', sa.DateTime(), nullable=True, comment='License expiry date'),
        sa.Column('notes', sa.Text(), nullable=True, comment='Additional branch information'),
        sa.CheckConstraint("branch_type IN ('main', 'standard', 'kiosk', 'mobile')", name='valid_branch_type'),
        sa.CheckConstraint("status IN ('active', 'inactive', 'maintenance', 'closed')", name='valid_branch_status'),
        sa.CheckConstraint('daily_transaction_limit IS NULL OR daily_transaction_limit > 0', name='positive_daily_limit'),
        sa.CheckConstraint('single_transaction_limit IS NULL OR single_transaction_limit > 0', name='positive_single_limit'),
        sa.CheckConstraint('manager_approval_threshold IS NULL OR manager_approval_threshold > 0', name='positive_approval_threshold'),
        sa.CheckConstraint('latitude IS NULL OR (latitude >= -90 AND latitude <= 90)', name='valid_latitude'),
        sa.CheckConstraint('longitude IS NULL OR (longitude >= -180 AND longitude <= 180)', name='valid_longitude'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('branch_code')
    )
    op.create_index('idx_branch_code_status', 'branches', ['branch_code', 'status'])
    op.create_index('idx_branch_city_status', 'branches', ['city', 'status'])
    op.create_index('idx_branch_manager', 'branches', ['branch_manager_id'])
    op.create_index('idx_branch_type', 'branches', ['branch_type'])
    op.create_index(op.f('ix_branches_branch_code'), 'branches', ['branch_code'])

    # Create branch_balances table
    op.create_table(
        'branch_balances',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False, comment='Primary key'),
        sa.Column('created_at', sa.DateTime(), server_default=sa.text('now()'), nullable=False, comment='Record creation timestamp'),
        sa.Column('updated_at', sa.DateTime(), server_default=sa.text('now()'), nullable=False, comment='Record last update timestamp'),
        sa.Column('is_deleted', sa.Boolean(), server_default='false', nullable=False, comment='Soft delete flag'),
        sa.Column('deleted_at', sa.DateTime(), nullable=True, comment='Soft delete timestamp'),
        sa.Column('created_by', sa.Integer(), nullable=True, comment='User ID who created this record'),
        sa.Column('updated_by', sa.Integer(), nullable=True, comment='User ID who last updated this record'),
        sa.Column('branch_id', sa.Integer(), nullable=False, comment='Reference to branch'),
        sa.Column('currency_id', sa.Integer(), nullable=False, comment='Reference to currency'),
        sa.Column('currency_code', sa.String(length=3), nullable=False, comment='Currency code for easier querying'),
        sa.Column('current_balance', sa.Numeric(precision=15, scale=4), nullable=False, server_default='0.0000', comment='Current available balance'),
        sa.Column('reserved_balance', sa.Numeric(precision=15, scale=4), nullable=False, server_default='0.0000', comment='Amount reserved for pending transactions'),
        sa.Column('minimum_balance', sa.Numeric(precision=15, scale=4), nullable=False, server_default='0.0000', comment='Minimum balance to maintain'),
        sa.Column('maximum_balance', sa.Numeric(precision=15, scale=4), nullable=True, comment='Maximum balance allowed (null = no limit)'),
        sa.Column('reorder_threshold', sa.Numeric(precision=15, scale=4), nullable=True, comment='Threshold for automatic reorder alerts'),
        sa.Column('critical_threshold', sa.Numeric(precision=15, scale=4), nullable=True, comment='Critical low balance threshold'),
        sa.Column('last_transaction_id', sa.Integer(), nullable=True, comment='ID of last transaction affecting this balance'),
        sa.Column('last_updated_at', sa.DateTime(), server_default=sa.text('now()'), nullable=False, comment='Last balance update timestamp'),
        sa.Column('last_reconciliation_at', sa.DateTime(), nullable=True, comment='Last manual reconciliation timestamp'),
        sa.Column('reconciliation_variance', sa.Numeric(precision=15, scale=4), nullable=True, comment='Variance found during last reconciliation'),
        sa.Column('is_active', sa.Boolean(), server_default='true', nullable=False, comment='Whether this balance record is active'),
        sa.Column('is_frozen', sa.Boolean(), server_default='false', nullable=False, comment='Whether transactions are frozen for this currency'),
        sa.Column('freeze_reason', sa.String(length=255), nullable=True, comment='Reason for balance freeze'),
        sa.Column('frozen_at', sa.DateTime(), nullable=True, comment='When balance was frozen'),
        sa.Column('frozen_by', sa.Integer(), nullable=True, comment='User who froze the balance'),
        sa.Column('notes', sa.Text(), nullable=True, comment='Additional notes about this balance'),
        sa.CheckConstraint('current_balance >= 0', name='non_negative_current_balance'),
        sa.CheckConstraint('reserved_balance >= 0', name='non_negative_reserved_balance'),
        sa.CheckConstraint('minimum_balance >= 0', name='non_negative_minimum_balance'),
        sa.CheckConstraint('maximum_balance IS NULL OR maximum_balance > minimum_balance', name='valid_maximum_balance'),
        sa.CheckConstraint('reserved_balance <= current_balance', name='reserved_not_exceed_current'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('branch_id', 'currency_code', name='unique_branch_currency')
    )
    op.create_index('idx_branch_currency_active', 'branch_balances', ['branch_id', 'currency_code', 'is_active'])
    op.create_index('idx_balance_thresholds', 'branch_balances', ['minimum_balance', 'reorder_threshold', 'critical_threshold'])
    op.create_index('idx_balance_frozen', 'branch_balances', ['is_frozen', 'frozen_at'])

    # Create customers table
    op.create_table(
        'customers',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False, comment='Primary key'),
        sa.Column('created_at', sa.DateTime(), server_default=sa.text('now()'), nullable=False, comment='Record creation timestamp'),
        sa.Column('updated_at', sa.DateTime(), server_default=sa.text('now()'), nullable=False, comment='Record last update timestamp'),
        sa.Column('is_deleted', sa.Boolean(), server_default='false', nullable=False, comment='Soft delete flag'),
        sa.Column('deleted_at', sa.DateTime(), nullable=True, comment='Soft delete timestamp'),
        sa.Column('created_by', sa.Integer(), nullable=True, comment='User ID who created this record'),
        sa.Column('updated_by', sa.Integer(), nullable=True, comment='User ID who last updated this record'),
        sa.Column('customer_code', sa.String(length=20), nullable=False, comment='Unique customer code (auto-generated)'),
        sa.Column('customer_type', sa.String(length=20), nullable=False, server_default='individual', comment='Type of customer (individual, business, corporate)'),
        sa.Column('first_name', sa.String(length=100), nullable=True, comment="Customer's first name"),
        sa.Column('middle_name', sa.String(length=100), nullable=True, comment="Customer's middle name"),
        sa.Column('last_name', sa.String(length=100), nullable=True, comment="Customer's last name"),
        sa.Column('first_name_arabic', sa.String(length=100), nullable=True, comment="Customer's first name in Arabic"),
        sa.Column('last_name_arabic', sa.String(length=100), nullable=True, comment="Customer's last name in Arabic"),
        sa.Column('company_name', sa.String(length=200), nullable=True, comment='Company name for business customers'),
        sa.Column('company_name_arabic', sa.String(length=200), nullable=True, comment='Company name in Arabic'),
        sa.Column('business_type', sa.String(length=50), nullable=True, comment='Type of business'),
        sa.Column('id_type', sa.String(length=20), nullable=False, comment='Type of identification document'),
        sa.Column('id_number', sa.String(length=50), nullable=False, comment='Identification document number'),
        sa.Column('id_expiry_date', sa.Date(), nullable=True, comment='ID document expiry date'),
        sa.Column('id_issuing_country', sa.String(length=3), nullable=True, comment='Country that issued the ID'),
        sa.Column('secondary_id_type', sa.String(length=20), nullable=True, comment='Secondary ID type (passport, etc.)'),
        sa.Column('secondary_id_number', sa.String(length=50), nullable=True, comment='Secondary ID number'),
        sa.Column('passport_number', sa.String(length=50), nullable=True, comment='Passport number if applicable'),
        sa.Column('date_of_birth', sa.Date(), nullable=True, comment='Date of birth'),
        sa.Column('gender', sa.String(length=10), nullable=True, comment='Customer gender'),
        sa.Column('nationality', sa.String(length=3), nullable=True, comment='Customer nationality (country code)'),
        sa.Column('marital_status', sa.String(length=20), nullable=True, comment='Marital status'),
        sa.Column('occupation', sa.String(length=100), nullable=True, comment='Customer occupation'),
        sa.Column('phone_number', sa.String(length=20), nullable=True, comment='Primary phone number'),
        sa.Column('mobile_number', sa.String(length=20), nullable=False, comment='Mobile phone number (required)'),
        sa.Column('email', sa.String(length=255), nullable=True, comment='Email address'),
        sa.Column('address_line1', sa.String(length=200), nullable=True, comment='Primary address line'),
        sa.Column('address_line2', sa.String(length=200), nullable=True, comment='Secondary address line'),
        sa.Column('city', sa.String(length=100), nullable=True, comment='City'),
        sa.Column('state_province', sa.String(length=100), nullable=True, comment='State or province'),
        sa.Column('postal_code', sa.String(length=20), nullable=True, comment='Postal/ZIP code'),
        sa.Column('country_code', sa.String(length=3), nullable=True, comment='Country code'),
        sa.Column('status', sa.String(length=20), nullable=False, server_default='active', comment='Customer account status'),
        sa.Column('classification', sa.String(length=20), nullable=False, server_default='standard', comment='Customer classification for pricing'),
        sa.Column('risk_level', sa.String(length=20), nullable=False, server_default='low', comment='Customer risk assessment level'),
        sa.Column('kyc_status', sa.String(length=20), nullable=False, server_default='pending', comment='KYC verification status'),
        sa.Column('kyc_completed_date', sa.DateTime(), nullable=True, comment='Date when KYC was completed'),
        sa.Column('kyc_expiry_date', sa.DateTime(), nullable=True, comment='Date when KYC needs renewal'),
        sa.Column('kyc_verified_by', sa.Integer(), nullable=True, comment='User who verified the KYC'),
        sa.Column('is_pep', sa.Boolean(), server_default='false', nullable=False, comment='Politically Exposed Person flag'),
        sa.Column('aml_risk_score', sa.String(length=10), nullable=False, server_default='0', comment='AML risk score (0-100)'),
        sa.Column('sanctions_checked', sa.Boolean(), server_default='false', nullable=False, comment='Whether sanctions list was checked'),
        sa.Column('sanctions_check_date', sa.DateTime(), nullable=True, comment='Last sanctions check date'),
        sa.Column('estimated_monthly_volume', sa.Numeric(precision=15, scale=2), nullable=True, comment='Estimated monthly transaction volume'),
        sa.Column('source_of_funds', sa.String(length=100), nullable=True, comment='Source of customer funds'),
        sa.Column('daily_limit', sa.Numeric(precision=15, scale=2), nullable=True, comment='Daily transaction limit for this customer'),
        sa.Column('monthly_limit', sa.Numeric(precision=15, scale=2), nullable=True, comment='Monthly transaction limit'),
        sa.Column('single_transaction_limit', sa.Numeric(precision=15, scale=2), nullable=True, comment='Single transaction limit'),
        sa.Column('commission_rate', sa.Numeric(precision=5, scale=4), nullable=True, comment='Custom commission rate (overrides standard rates)'),
        sa.Column('minimum_commission', sa.Numeric(precision=8, scale=2), nullable=True, comment='Minimum commission amount'),
        sa.Column('preferred_language', sa.String(length=10), nullable=False, server_default='en', comment="Customer's preferred language"),
        sa.Column('preferred_currency', sa.String(length=3), nullable=True, comment="Customer's preferred currency"),
        sa.Column('notification_preferences', sa.String(length=100), nullable=False, server_default='sms,email', comment='Notification preferences (comma-separated)'),
        sa.Column('registration_date', sa.DateTime(), server_default=sa.text('now()'), nullable=False, comment='Customer registration date'),
        sa.Column('registration_branch_id', sa.Integer(), nullable=True, comment='Branch where customer was registered'),
        sa.Column('registered_by', sa.Integer(), nullable=True, comment='User who registered the customer'),
        sa.Column('referral_source', sa.String(length=100), nullable=True, comment='How customer found out about the service'),
        sa.Column('referral_code', sa.String(length=50), nullable=True, comment='Referral code used by customer'),
        sa.Column('last_transaction_date', sa.DateTime(), nullable=True, comment='Date of last transaction'),
        sa.Column('total_transactions', sa.String(length=10), nullable=False, server_default='0', comment='Total number of transactions'),
        sa.Column('total_volume', sa.Numeric(precision=20, scale=2), nullable=False, server_default='0.00', comment='Total transaction volume (base currency)'),
        sa.Column('last_login_date', sa.DateTime(), nullable=True, comment='Last login date (if customer has online access)'),
        sa.Column('profile_image_url', sa.String(length=500), nullable=True, comment='Customer profile image URL'),
        sa.Column('id_document_front_url', sa.String(length=500), nullable=True, comment='Front side of ID document'),
        sa.Column('id_document_back_url', sa.String(length=500), nullable=True, comment='Back side of ID document'),
        sa.Column('additional_documents', sa.Text(), nullable=True, comment='JSON array of additional document URLs'),
        sa.Column('is_vip', sa.Boolean(), server_default='false', nullable=False, comment='VIP customer flag'),
        sa.Column('is_blacklisted', sa.Boolean(), server_default='false', nullable=False, comment='Blacklisted customer flag'),
        sa.Column('blacklist_reason', sa.String(length=255), nullable=True, comment='Reason for blacklisting'),
        sa.Column('blacklisted_date', sa.DateTime(), nullable=True, comment='Date when customer was blacklisted'),
        sa.Column('requires_approval', sa.Boolean(), server_default='false', nullable=False, comment='Whether transactions require special approval'),
        sa.Column('notes', sa.Text(), nullable=True, comment='Additional notes about the customer'),
        sa.CheckConstraint("customer_type IN ('individual', 'business', 'corporate')", name='valid_customer_type'),
        sa.CheckConstraint("status IN ('active', 'inactive', 'suspended', 'closed')", name='valid_customer_status'),
        sa.CheckConstraint("classification IN ('standard', 'vip', 'premium', 'corporate')", name='valid_classification'),
        sa.CheckConstraint("risk_level IN ('low', 'medium', 'high')", name='valid_risk_level'),
        sa.CheckConstraint("kyc_status IN ('pending', 'in_progress', 'completed', 'rejected', 'expired')", name='valid_kyc_status'),
        sa.CheckConstraint("id_type IN ('national_id', 'passport', 'driving_license', 'residence_permit')", name='valid_id_type'),
        sa.CheckConstraint("gender IN ('male', 'female', 'other')", name='valid_gender'),
        sa.CheckConstraint('daily_limit IS NULL OR daily_limit > 0', name='positive_daily_limit'),
        sa.CheckConstraint('monthly_limit IS NULL OR monthly_limit > 0', name='positive_monthly_limit'),
        sa.CheckConstraint('commission_rate IS NULL OR (commission_rate >= 0 AND commission_rate <= 1)', name='valid_commission_rate'),
        sa.CheckConstraint('aml_risk_score::integer >= 0 AND aml_risk_score::integer <= 100', name='valid_aml_risk_score'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('customer_code'),
        sa.UniqueConstraint('id_type', 'id_number', name='unique_customer_id')
    )
    op.create_index('idx_customer_mobile', 'customers', ['mobile_number'])
    op.create_index('idx_customer_email', 'customers', ['email'])
    op.create_index('idx_customer_status_type', 'customers', ['status', 'customer_type'])
    op.create_index('idx_customer_classification', 'customers', ['classification'])
    op.create_index('idx_customer_kyc', 'customers', ['kyc_status', 'kyc_expiry_date'])
    op.create_index('idx_customer_risk', 'customers', ['risk_level', 'is_blacklisted'])
    op.create_index('idx_customer_activity', 'customers', ['last_transaction_date', 'status'])
    op.create_index(op.f('ix_customers_customer_code'), 'customers', ['customer_code'])
    op.create_index(op.f('ix_customers_id_number'), 'customers', ['id_number'])

    # Update users table to add branch_id foreign key
    op.add_column('users', sa.Column('branch_id', sa.Integer(), nullable=True, comment='ID of the branch user is assigned to'))
    op.create_index('idx_user_branch_id', 'users', ['branch_id'])

    # Continue with remaining tables in next part due to length...


def downgrade() -> None:
    """Drop all new tables created in upgrade."""
    
    # Drop in reverse order
    op.drop_index('idx_user_branch_id', table_name='users')
    op.drop_column('users', 'branch_id')
    
    op.drop_table('customers')
    op.drop_table('branch_balances')
    op.drop_table('branches')