"""Add transactions and vault tables with proper foreign keys

Revision ID: 003
Revises: 002
Create Date: 2024-01-15 14:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '003'
down_revision = '002'
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create transactions and vault tables with proper foreign key constraints."""
    
    # Create vaults table (Level 3 - References branches and users)
    op.create_table(
        'vaults',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False, comment='Primary key'),
        sa.Column('created_at', sa.DateTime(), server_default=sa.text('now()'), nullable=False, comment='Record creation timestamp'),
        sa.Column('updated_at', sa.DateTime(), server_default=sa.text('now()'), nullable=False, comment='Record last update timestamp'),
        sa.Column('is_deleted', sa.Boolean(), server_default='false', nullable=False, comment='Soft delete flag'),
        sa.Column('deleted_at', sa.DateTime(), nullable=True, comment='Soft delete timestamp'),
        sa.Column('created_by', sa.Integer(), nullable=True, comment='User ID who created this record'),
        sa.Column('updated_by', sa.Integer(), nullable=True, comment='User ID who last updated this record'),
        sa.Column('vault_code', sa.String(length=20), nullable=False, comment='Unique vault identifier'),
        sa.Column('vault_name', sa.String(length=100), nullable=False, comment='Vault display name'),
        sa.Column('vault_type', sa.String(length=20), nullable=False, server_default='main', comment='Type of vault (main, branch, mobile)'),
        sa.Column('location_description', sa.Text(), nullable=True, comment='Physical location description'),
        sa.Column('building', sa.String(length=100), nullable=True, comment='Building name or address'),
        sa.Column('floor', sa.String(length=10), nullable=True, comment='Floor number'),
        sa.Column('room', sa.String(length=20), nullable=True, comment='Room number'),
        sa.Column('capacity_rating', sa.String(length=50), nullable=True, comment='Vault capacity rating'),
        sa.Column('security_level', sa.String(length=20), nullable=False, server_default='high', comment='Security classification'),
        sa.Column('status', sa.String(length=20), nullable=False, server_default='active', comment='Vault operational status'),
        sa.Column('is_main_vault', sa.Boolean(), server_default='false', nullable=False, comment='Whether this is the main system vault'),
        sa.Column('branch_id', sa.Integer(), nullable=True, comment='Associated branch (if applicable)'),
        sa.Column('requires_dual_control', sa.Boolean(), server_default='true', nullable=False, comment='Whether vault requires dual control access'),
        sa.Column('authorized_users', sa.Text(), nullable=True, comment='JSON array of authorized user IDs'),
        sa.Column('primary_custodian_id', sa.Integer(), nullable=True, comment='Primary vault custodian'),
        sa.Column('secondary_custodian_id', sa.Integer(), nullable=True, comment='Secondary vault custodian'),
        sa.Column('operating_hours_start', sa.String(length=5), nullable=True, comment='Daily opening time (HH:MM)'),
        sa.Column('operating_hours_end', sa.String(length=5), nullable=True, comment='Daily closing time (HH:MM)'),
        sa.Column('last_audit_date', sa.DateTime(), nullable=True, comment='Last vault audit date'),
        sa.Column('last_audit_by', sa.Integer(), nullable=True, comment='User who conducted last audit'),
        sa.Column('audit_frequency_days', sa.Integer(), nullable=False, server_default='30', comment='Required audit frequency in days'),
        sa.Column('next_audit_due', sa.DateTime(), nullable=True, comment='Next scheduled audit date'),
        sa.Column('security_system_id', sa.String(length=100), nullable=True, comment='Security system identifier'),
        sa.Column('insurance_policy_number', sa.String(length=100), nullable=True, comment='Insurance policy covering this vault'),
        sa.Column('insurance_coverage_amount', sa.Numeric(precision=15, scale=2), nullable=True, comment='Insurance coverage amount'),
        sa.Column('compliance_certifications', sa.Text(), nullable=True, comment='JSON array of compliance certifications'),
        sa.Column('emergency_contact_1', sa.String(length=100), nullable=True, comment='Primary emergency contact'),
        sa.Column('emergency_contact_2', sa.String(length=100), nullable=True, comment='Secondary emergency contact'),
        sa.Column('emergency_procedures', sa.Text(), nullable=True, comment='Emergency procedures documentation'),
        sa.Column('notes', sa.Text(), nullable=True, comment='Additional vault information'),
        sa.CheckConstraint("vault_type IN ('main', 'branch', 'mobile', 'temporary')", name='valid_vault_type'),
        sa.CheckConstraint("status IN ('active', 'inactive', 'maintenance', 'emergency_locked')", name='valid_vault_status'),
        sa.CheckConstraint("security_level IN ('low', 'medium', 'high', 'maximum')", name='valid_security_level'),
        sa.CheckConstraint('audit_frequency_days > 0', name='positive_audit_frequency'),
        sa.ForeignKeyConstraint(['branch_id'], ['branches.id'], ),
        sa.ForeignKeyConstraint(['last_audit_by'], ['users.id'], ),
        sa.ForeignKeyConstraint(['primary_custodian_id'], ['users.id'], ),
        sa.ForeignKeyConstraint(['secondary_custodian_id'], ['users.id'], ),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('vault_code')
    )
    op.create_index('idx_vault_type_status', 'vaults', ['vault_type', 'status'])
    op.create_index('idx_vault_custodian', 'vaults', ['primary_custodian_id', 'secondary_custodian_id'])
    op.create_index('idx_vault_audit', 'vaults', ['last_audit_date', 'next_audit_due'])
    op.create_index('idx_vault_branch', 'vaults', ['branch_id'])
    op.create_index(op.f('ix_vaults_vault_code'), 'vaults', ['vault_code'])

    # Create transactions table (Level 4 - References customers, branches, users, exchange_rates)
    op.create_table(
        'transactions',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False, comment='Primary key'),
        sa.Column('created_at', sa.DateTime(), server_default=sa.text('now()'), nullable=False, comment='Record creation timestamp'),
        sa.Column('updated_at', sa.DateTime(), server_default=sa.text('now()'), nullable=False, comment='Record last update timestamp'),
        sa.Column('is_deleted', sa.Boolean(), server_default='false', nullable=False, comment='Soft delete flag'),
        sa.Column('deleted_at', sa.DateTime(), nullable=True, comment='Soft delete timestamp'),
        sa.Column('created_by', sa.Integer(), nullable=True, comment='User ID who created this record'),
        sa.Column('updated_by', sa.Integer(), nullable=True, comment='User ID who last updated this record'),
        sa.Column('transaction_id', sa.String(length=20), nullable=False, comment='Unique transaction identifier (auto-generated)'),
        sa.Column('transaction_type', sa.String(length=30), nullable=False, comment='Type of transaction'),
        sa.Column('reference_number', sa.String(length=50), nullable=True, comment='External reference number'),
        sa.Column('customer_id', sa.Integer(), nullable=True, comment='Customer involved in transaction'),
        sa.Column('branch_id', sa.Integer(), nullable=False, comment='Branch where transaction occurred'),
        sa.Column('user_id', sa.Integer(), nullable=False, comment='User who processed the transaction'),
        sa.Column('from_currency_code', sa.String(length=3), nullable=True, comment='Source currency code'),
        sa.Column('to_currency_code', sa.String(length=3), nullable=True, comment='Target currency code'),
        sa.Column('from_amount', sa.Numeric(precision=15, scale=4), nullable=False, comment='Amount in source currency'),
        sa.Column('to_amount', sa.Numeric(precision=15, scale=4), nullable=True, comment='Amount in target currency'),
        sa.Column('exchange_rate', sa.Numeric(precision=15, scale=8), nullable=True, comment='Exchange rate used (if applicable)'),
        sa.Column('exchange_rate_id', sa.Integer(), nullable=True, comment='Reference to exchange rate record used'),
        sa.Column('commission_rate', sa.Numeric(precision=5, scale=4), nullable=True, comment='Commission rate applied'),
        sa.Column('commission_amount', sa.Numeric(precision=10, scale=2), nullable=False, server_default='0.00', comment='Commission amount charged'),
        sa.Column('fee_amount', sa.Numeric(precision=10, scale=2), nullable=False, server_default='0.00', comment='Additional fees charged'),
        sa.Column('net_amount', sa.Numeric(precision=15, scale=4), nullable=False, comment='Net amount after all charges'),
        sa.Column('status', sa.String(length=20), nullable=False, server_default='pending', comment='Current transaction status'),
        sa.Column('transaction_date', sa.DateTime(), server_default=sa.text('now()'), nullable=False, comment='When transaction was initiated'),
        sa.Column('value_date', sa.DateTime(), nullable=True, comment='Value date for the transaction'),
        sa.Column('completed_at', sa.DateTime(), nullable=True, comment='When transaction was completed'),
        sa.Column('payment_method', sa.String(length=20), nullable=False, server_default='cash', comment='Payment method used'),
        sa.Column('payment_reference', sa.String(length=100), nullable=True, comment='Payment reference (check number, card reference, etc.)'),
        sa.Column('requires_approval', sa.Boolean(), server_default='false', nullable=False, comment='Whether transaction requires approval'),
        sa.Column('approved_by', sa.Integer(), nullable=True, comment='User who approved the transaction'),
        sa.Column('approved_at', sa.DateTime(), nullable=True, comment='When transaction was approved'),
        sa.Column('approval_notes', sa.Text(), nullable=True, comment='Notes from approver'),
        sa.Column('description', sa.Text(), nullable=True, comment='Transaction description/purpose'),
        sa.Column('notes', sa.Text(), nullable=True, comment='Internal notes about the transaction'),
        sa.Column('additional_data', postgresql.JSON(astext_type=sa.Text()), nullable=True, comment='Additional transaction-specific data (JSON)'),
        sa.Column('aml_checked', sa.Boolean(), server_default='false', nullable=False, comment='Whether AML checks were performed'),
        sa.Column('aml_risk_score', sa.String(length=10), nullable=False, server_default='0', comment='AML risk score (0-100)'),
        sa.Column('compliance_flags', sa.Text(), nullable=True, comment='Compliance flags or alerts (JSON array)'),
        sa.Column('original_transaction_id', sa.Integer(), nullable=True, comment='Original transaction if this is a reversal'),
        sa.Column('reversed_transaction_id', sa.Integer(), nullable=True, comment='Reversal transaction ID if this was reversed'),
        sa.Column('reversal_reason', sa.String(length=255), nullable=True, comment='Reason for reversal'),
        sa.Column('receipt_number', sa.String(length=50), nullable=True, comment='Receipt number issued to customer'),
        sa.Column('receipt_printed', sa.Boolean(), server_default='false', nullable=False, comment='Whether receipt was printed'),
        sa.Column('external_system_id', sa.String(length=100), nullable=True, comment='ID in external system (if integrated)'),
        sa.Column('external_status', sa.String(length=50), nullable=True, comment='Status in external system'),
        sa.CheckConstraint("transaction_type IN ('currency_exchange', 'cash_deposit', 'cash_withdrawal', 'transfer', 'commission', 'vault_deposit', 'vault_withdrawal', 'balance_adjustment', 'refund')", name='valid_transaction_type'),
        sa.CheckConstraint("status IN ('pending', 'completed', 'cancelled', 'failed', 'reversed')", name='valid_transaction_status'),
        sa.CheckConstraint("payment_method IN ('cash', 'bank_transfer', 'credit_card', 'debit_card', 'digital_wallet', 'check')", name='valid_payment_method'),
        sa.CheckConstraint('from_amount > 0', name='positive_from_amount'),
        sa.CheckConstraint('to_amount IS NULL OR to_amount > 0', name='positive_to_amount'),
        sa.CheckConstraint('commission_amount >= 0', name='non_negative_commission'),
        sa.CheckConstraint('fee_amount >= 0', name='non_negative_fee'),
        sa.CheckConstraint('exchange_rate IS NULL OR exchange_rate > 0', name='positive_exchange_rate'),
        sa.CheckConstraint('aml_risk_score::integer >= 0 AND aml_risk_score::integer <= 100', name='valid_aml_risk_score'),
        sa.ForeignKeyConstraint(['approved_by'], ['users.id'], ),
        sa.ForeignKeyConstraint(['branch_id'], ['branches.id'], ),
        sa.ForeignKeyConstraint(['customer_id'], ['customers.id'], ),
        sa.ForeignKeyConstraint(['exchange_rate_id'], ['exchange_rates.id'], ),
        sa.ForeignKeyConstraint(['original_transaction_id'], ['transactions.id'], ),
        sa.ForeignKeyConstraint(['reversed_transaction_id'], ['transactions.id'], ),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('transaction_id')
    )
    op.create_index('idx_transaction_date_status', 'transactions', ['transaction_date', 'status'])
    op.create_index('idx_transaction_customer_date', 'transactions', ['customer_id', 'transaction_date'])
    op.create_index('idx_transaction_branch_date', 'transactions', ['branch_id', 'transaction_date'])
    op.create_index('idx_transaction_currencies', 'transactions', ['from_currency_code', 'to_currency_code'])
    op.create_index('idx_transaction_amount', 'transactions', ['from_amount'])
    op.create_index('idx_transaction_reference', 'transactions', ['reference_number'])
    op.create_index('idx_transaction_receipt', 'transactions', ['receipt_number'])
    op.create_index('idx_transaction_approval', 'transactions', ['requires_approval', 'approved_at'])
    op.create_index('idx_transaction_aml', 'transactions', ['aml_checked', 'aml_risk_score'])
    op.create_index(op.f('ix_transactions_transaction_id'), 'transactions', ['transaction_id'])
    op.create_index(op.f('ix_transactions_transaction_type'), 'transactions', ['transaction_type'])
    op.create_index(op.f('ix_transactions_status'), 'transactions', ['status'])
    op.create_index(op.f('ix_transactions_transaction_date'), 'transactions', ['transaction_date'])
    op.create_index(op.f('ix_transactions_from_currency_code'), 'transactions', ['from_currency_code'])
    op.create_index(op.f('ix_transactions_to_currency_code'), 'transactions', ['to_currency_code'])

    # Now add foreign key constraint to branch_balances.last_transaction_id
    op.add_column('branch_balances', sa.Column('last_transaction_id', sa.Integer(), nullable=True, comment='ID of last transaction affecting this balance'))
    op.create_foreign_key('fk_branch_balances_last_transaction', 'branch_balances', 'transactions', ['last_transaction_id'], ['id'])

    # Create vault_balances table (Level 4 - References vaults, currencies, users, vault_transactions)
    op.create_table(
        'vault_balances',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False, comment='Primary key'),
        sa.Column('created_at', sa.DateTime(), server_default=sa.text('now()'), nullable=False, comment='Record creation timestamp'),
        sa.Column('updated_at', sa.DateTime(), server_default=sa.text('now()'), nullable=False, comment='Record last update timestamp'),
        sa.Column('is_deleted', sa.Boolean(), server_default='false', nullable=False, comment='Soft delete flag'),
        sa.Column('deleted_at', sa.DateTime(), nullable=True, comment='Soft delete timestamp'),
        sa.Column('created_by', sa.Integer(), nullable=True, comment='User ID who created this record'),
        sa.Column('updated_by', sa.Integer(), nullable=True, comment='User ID who last updated this record'),
        sa.Column('vault_id', sa.Integer(), nullable=False, comment='Reference to vault'),
        sa.Column('currency_id', sa.Integer(), nullable=False, comment='Reference to currency'),
        sa.Column('currency_code', sa.String(length=3), nullable=False, comment='Currency code for easier querying'),
        sa.Column('current_balance', sa.Numeric(precision=18, scale=4), nullable=False, server_default='0.0000', comment='Current vault balance'),
        sa.Column('reserved_balance', sa.Numeric(precision=18, scale=4), nullable=False, server_default='0.0000', comment='Reserved amount for pending operations'),
        sa.Column('denomination_breakdown', postgresql.JSON(astext_type=sa.Text()), nullable=True, comment='Physical denomination breakdown'),
        sa.Column('last_count_amount', sa.Numeric(precision=18, scale=4), nullable=True, comment='Last physically counted amount'),
        sa.Column('last_count_date', sa.DateTime(), nullable=True, comment='Last physical count date'),
        sa.Column('last_counted_by', sa.Integer(), nullable=True, comment='User who performed last count'),
        sa.Column('count_variance', sa.Numeric(precision=18, scale=4), nullable=True, comment='Variance from last count'),
        sa.Column('minimum_balance', sa.Numeric(precision=18, scale=4), nullable=False, server_default='0.0000', comment='Minimum balance to maintain'),
        sa.Column('maximum_balance', sa.Numeric(precision=18, scale=4), nullable=True, comment='Maximum balance allowed'),
        sa.Column('reorder_threshold', sa.Numeric(precision=18, scale=4), nullable=True, comment='Threshold for reorder alerts'),
        sa.Column('critical_threshold', sa.Numeric(precision=18, scale=4), nullable=True, comment='Critical low balance threshold'),
        sa.Column('is_active', sa.Boolean(), server_default='true', nullable=False, comment='Whether this balance is active'),
        sa.Column('last_transaction_id', sa.Integer(), nullable=True, comment='Last transaction affecting this balance'),
        sa.Column('last_updated_at', sa.DateTime(), server_default=sa.text('now()'), nullable=False, comment='Last balance update timestamp'),
        sa.Column('last_reconciliation_date', sa.DateTime(), nullable=True, comment='Last reconciliation date'),
        sa.Column('reconciliation_variance', sa.Numeric(precision=18, scale=4), nullable=True, comment='Variance from last reconciliation'),
        sa.Column('reconciled_by', sa.Integer(), nullable=True, comment='User who performed last reconciliation'),
        sa.Column('notes', sa.Text(), nullable=True, comment='Additional balance notes'),
        sa.CheckConstraint('current_balance >= 0', name='non_negative_current_balance_vault'),
        sa.CheckConstraint('reserved_balance >= 0', name='non_negative_reserved_balance_vault'),
        sa.CheckConstraint('minimum_balance >= 0', name='non_negative_minimum_balance_vault'),
        sa.CheckConstraint('reserved_balance <= current_balance', name='reserved_not_exceed_current_vault'),
        sa.ForeignKeyConstraint(['currency_id'], ['currencies.id'], ),
        sa.ForeignKeyConstraint(['last_counted_by'], ['users.id'], ),
        sa.ForeignKeyConstraint(['reconciled_by'], ['users.id'], ),
        sa.ForeignKeyConstraint(['vault_id'], ['vaults.id'], ),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('vault_id', 'currency_code', name='unique_vault_currency')
    )
    op.create_index('idx_vault_currency_active', 'vault_balances', ['vault_id', 'currency_code', 'is_active'])
    op.create_index('idx_vault_balance_thresholds', 'vault_balances', ['minimum_balance', 'reorder_threshold', 'critical_threshold'])
    op.create_index('idx_vault_balance_updated', 'vault_balances', ['last_updated_at'])

    # Create vault_transactions table (Level 5 - References vaults, users, transactions)
    op.create_table(
        'vault_transactions',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False, comment='Primary key'),
        sa.Column('created_at', sa.DateTime(), server_default=sa.text('now()'), nullable=False, comment='Record creation timestamp'),
        sa.Column('updated_at', sa.DateTime(), server_default=sa.text('now()'), nullable=False, comment='Record last update timestamp'),
        sa.Column('is_deleted', sa.Boolean(), server_default='false', nullable=False, comment='Soft delete flag'),
        sa.Column('deleted_at', sa.DateTime(), nullable=True, comment='Soft delete timestamp'),
        sa.Column('created_by', sa.Integer(), nullable=True, comment='User ID who created this record'),
        sa.Column('updated_by', sa.Integer(), nullable=True, comment='User ID who last updated this record'),
        sa.Column('transaction_id', sa.String(length=20), nullable=False, comment='Unique vault transaction ID'),
        sa.Column('vault_id', sa.Integer(), nullable=False, comment='Vault involved in transaction'),
        sa.Column('transaction_type', sa.String(length=30), nullable=False, comment='Type of vault transaction'),
        sa.Column('direction', sa.String(length=10), nullable=False, comment='Transaction direction (in, out)'),
        sa.Column('currency_code', sa.String(length=3), nullable=False, comment='Currency involved'),
        sa.Column('amount', sa.Numeric(precision=18, scale=4), nullable=False, comment='Transaction amount'),
        sa.Column('source_type', sa.String(length=20), nullable=True, comment='Source type (branch, bank, external)'),
        sa.Column('source_id', sa.Integer(), nullable=True, comment='Source ID (branch_id, etc.)'),
        sa.Column('source_reference', sa.String(length=100), nullable=True, comment='Source reference number'),
        sa.Column('destination_type', sa.String(length=20), nullable=True, comment='Destination type'),
        sa.Column('destination_id', sa.Integer(), nullable=True, comment='Destination ID'),
        sa.Column('destination_reference', sa.String(length=100), nullable=True, comment='Destination reference'),
        sa.Column('status', sa.String(length=20), nullable=False, server_default='pending', comment='Transaction status'),
        sa.Column('processed_by', sa.Integer(), nullable=False, comment='User who processed transaction'),
        sa.Column('approved_by', sa.Integer(), nullable=True, comment='User who approved transaction'),
        sa.Column('transaction_date', sa.DateTime(), server_default=sa.text('now()'), nullable=False, comment='Transaction date'),
        sa.Column('completed_at', sa.DateTime(), nullable=True, comment='Completion timestamp'),
        sa.Column('denomination_breakdown', postgresql.JSON(astext_type=sa.Text()), nullable=True, comment='Physical denomination breakdown'),
        sa.Column('containers_used', sa.String(length=255), nullable=True, comment='Containers or bags used for transport'),
        sa.Column('seal_numbers', sa.String(length=255), nullable=True, comment='Security seal numbers'),
        sa.Column('requires_dual_authorization', sa.Boolean(), server_default='true', nullable=False, comment='Requires dual authorization'),
        sa.Column('first_authorizer_id', sa.Integer(), nullable=True, comment='First authorizing user'),
        sa.Column('second_authorizer_id', sa.Integer(), nullable=True, comment='Second authorizing user'),
        sa.Column('verified_by', sa.Integer(), nullable=True, comment='User who verified the transaction'),
        sa.Column('verification_date', sa.DateTime(), nullable=True, comment='Verification timestamp'),
        sa.Column('related_transaction_id', sa.Integer(), nullable=True, comment='Related customer transaction'),
        sa.Column('batch_id', sa.String(length=50), nullable=True, comment='Batch ID for grouped transactions'),
        sa.Column('purpose', sa.String(length=255), nullable=True, comment='Purpose of the transaction'),
        sa.Column('notes', sa.Text(), nullable=True, comment='Transaction notes'),
        sa.CheckConstraint("transaction_type IN ('vault_deposit', 'vault_withdrawal', 'branch_transfer', 'bank_deposit', 'bank_withdrawal', 'reconciliation_adjustment')", name='valid_vault_transaction_type'),
        sa.CheckConstraint("direction IN ('in', 'out')", name='valid_direction'),
        sa.CheckConstraint("status IN ('pending', 'authorized', 'completed', 'cancelled', 'failed')", name='valid_vault_status'),
        sa.CheckConstraint('amount > 0', name='positive_amount_vault'),
        sa.ForeignKeyConstraint(['approved_by'], ['users.id'], ),
        sa.ForeignKeyConstraint(['first_authorizer_id'], ['users.id'], ),
        sa.ForeignKeyConstraint(['processed_by'], ['users.id'], ),
        sa.ForeignKeyConstraint(['related_transaction_id'], ['transactions.id'], ),
        sa.ForeignKeyConstraint(['second_authorizer_id'], ['users.id'], ),
        sa.ForeignKeyConstraint(['vault_id'], ['vaults.id'], ),
        sa.ForeignKeyConstraint(['verified_by'], ['users.id'], ),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('transaction_id', name='unique_vault_transaction_id')
    )
    op.create_index('idx_vault_transaction_date', 'vault_transactions', ['vault_id', 'transaction_date'])
    op.create_index('idx_vault_currency_amount', 'vault_transactions', ['vault_id', 'currency_code', 'amount'])
    op.create_index('idx_vault_transaction_status', 'vault_transactions', ['status', 'transaction_date'])
    op.create_index('idx_vault_transaction_batch', 'vault_transactions', ['batch_id'])
    op.create_index('idx_vault_transaction_related', 'vault_transactions', ['related_transaction_id'])
    op.create_index(op.f('ix_vault_transactions_transaction_id'), 'vault_transactions', ['transaction_id'])
    op.create_index(op.f('ix_vault_transactions_vault_id'), 'vault_transactions', ['vault_id'])
    op.create_index(op.f('ix_vault_transactions_currency_code'), 'vault_transactions', ['currency_code'])

    # Now add foreign key constraint to vault_balances.last_transaction_id
    op.create_foreign_key('fk_vault_balances_last_transaction', 'vault_balances', 'vault_transactions', ['last_transaction_id'], ['id'])

    # Create currency_exchanges table (Level 5 - Inherits from transactions)
    op.create_table(
        'currency_exchanges',
        sa.Column('id', sa.Integer(), nullable=False, comment='Reference to parent transaction'),
        sa.Column('buy_rate', sa.Numeric(precision=15, scale=8), nullable=True, comment='Buy rate offered to customer'),
        sa.Column('sell_rate', sa.Numeric(precision=15, scale=8), nullable=True, comment='Sell rate offered to customer'),
        sa.Column('spread', sa.Numeric(precision=8, scale=4), nullable=True, comment='Spread applied (difference from mid rate)'),
        sa.Column('margin_percentage', sa.Numeric(precision=5, scale=4), nullable=True, comment='Margin percentage applied'),
        sa.Column('rate_source', sa.String(length=100), nullable=True, comment='Source of the exchange rate'),
        sa.Column('rate_timestamp', sa.DateTime(), nullable=True, comment='When the rate was quoted'),
        sa.Column('rate_valid_until', sa.DateTime(), nullable=True, comment='Rate validity expiry'),
        sa.Column('delivered_amount', sa.Numeric(precision=15, scale=4), nullable=True, comment='Actual amount delivered (may differ due to denominations)'),
        sa.Column('denomination_breakdown', postgresql.JSON(astext_type=sa.Text()), nullable=True, comment='Breakdown of currency denominations'),
        sa.ForeignKeyConstraint(['id'], ['transactions.id'], ),
        sa.PrimaryKeyConstraint('id')
    )

    # Create cash_transactions table (Level 5 - Inherits from transactions)
    op.create_table(
        'cash_transactions',
        sa.Column('id', sa.Integer(), nullable=False, comment='Reference to parent transaction'),
        sa.Column('denomination_breakdown', postgresql.JSON(astext_type=sa.Text()), nullable=True, comment='Breakdown of cash denominations'),
        sa.Column('counted_by', sa.Integer(), nullable=True, comment='User who counted the cash'),
        sa.Column('verified_by', sa.Integer(), nullable=True, comment='User who verified the cash count'),
        sa.Column('vault_transaction_id', sa.Integer(), nullable=True, comment='Related vault transaction'),
        sa.ForeignKeyConstraint(['counted_by'], ['users.id'], ),
        sa.ForeignKeyConstraint(['id'], ['transactions.id'], ),
        sa.ForeignKeyConstraint(['vault_transaction_id'], ['vault_transactions.id'], ),
        sa.ForeignKeyConstraint(['verified_by'], ['users.id'], ),
        sa.PrimaryKeyConstraint('id')
    )

    # Create transfers table (Level 5 - Inherits from transactions)
    op.create_table(
        'transfers',
        sa.Column('id', sa.Integer(), nullable=False, comment='Reference to parent transaction'),
        sa.Column('sender_name', sa.String(length=200), nullable=True, comment='Name of sender'),
        sa.Column('sender_id_number', sa.String(length=50), nullable=True, comment='Sender identification number'),
        sa.Column('sender_phone', sa.String(length=20), nullable=True, comment='Sender phone number'),
        sa.Column('beneficiary_name', sa.String(length=200), nullable=True, comment='Name of beneficiary'),
        sa.Column('beneficiary_id_number', sa.String(length=50), nullable=True, comment='Beneficiary identification number'),
        sa.Column('beneficiary_phone', sa.String(length=20), nullable=True, comment='Beneficiary phone number'),
        sa.Column('transfer_purpose', sa.String(length=255), nullable=True, comment='Purpose of transfer'),
        sa.Column('destination_country', sa.String(length=3), nullable=True, comment='Destination country code'),
        sa.Column('correspondent_bank', sa.String(length=200), nullable=True, comment='Correspondent bank information'),
        sa.Column('delivery_method', sa.String(length=50), nullable=True, comment='How transfer will be delivered'),
        sa.Column('pickup_location', sa.String(length=255), nullable=True, comment='Pickup location for beneficiary'),
        sa.Column('tracking_number', sa.String(length=100), nullable=True, comment='Transfer tracking number'),
        sa.Column('expected_delivery_date', sa.DateTime(), nullable=True, comment='Expected delivery date'),
        sa.Column('delivered_at', sa.DateTime(), nullable=True, comment='When transfer was delivered'),
        sa.Column('delivered_to', sa.String(length=200), nullable=True, comment='Who received the transfer'),
        sa.ForeignKeyConstraint(['id'], ['transactions.id'], ),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('tracking_number')
    )

    # Create commissions table (Level 5 - Inherits from transactions)
    op.create_table(
        'commissions',
        sa.Column('id', sa.Integer(), nullable=False, comment='Reference to parent transaction'),
        sa.Column('source_transaction_id', sa.Integer(), nullable=False, comment='Transaction that generated this commission'),
        sa.Column('commission_type', sa.String(length=50), nullable=False, comment='Type of commission (exchange, transfer, etc.)'),
        sa.Column('rate_applied', sa.Numeric(precision=5, scale=4), nullable=False, comment='Commission rate that was applied'),
        sa.Column('base_amount', sa.Numeric(precision=15, scale=4), nullable=False, comment='Base amount commission was calculated on'),
        sa.ForeignKeyConstraint(['id'], ['transactions.id'], ),
        sa.ForeignKeyConstraint(['source_transaction_id'], ['transactions.id'], ),
        sa.PrimaryKeyConstraint('id')
    )


def downgrade() -> None:
    """Drop all tables created in upgrade."""
    
    # Drop in reverse order of creation
    op.drop_table('commissions')
    op.drop_table('transfers')
    op.drop_table('cash_transactions')
    op.drop_table('currency_exchanges')
    
    # Remove foreign key constraints before dropping tables
    op.drop_constraint('fk_vault_balances_last_transaction', 'vault_balances', type_='foreignkey')
    op.drop_constraint('fk_branch_balances_last_transaction', 'branch_balances', type_='foreignkey')
    
    op.drop_table('vault_transactions')
    op.drop_table('vault_balances')
    op.drop_table('transactions')
    op.drop_table('vaults')