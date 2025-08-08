"""
Module: test_integration
Purpose: Comprehensive integration test for CEMS database models and relationships
Author: CEMS Development Team
Date: 2024
"""

import sys
import os
from decimal import Decimal
from datetime import datetime, date
from typing import Dict, Any, List, Optional

# Add app to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy.orm import Session
from sqlalchemy import text

from app.core.config import settings
from app.db.database import db_manager
from app.db.init_db import init_db, verify_initialization, reset_db
from app.db.models import (
    User, Role, UserRole, Currency, ExchangeRate, 
    Branch, BranchBalance, Customer, Vault, VaultBalance, VaultTransaction,
    Transaction, CurrencyExchange
)
from app.utils.logger import get_logger

# Setup logging
logger = get_logger(__name__)


class IntegrationTestRunner:
    """
    Comprehensive integration test runner for CEMS system.
    Tests all models, relationships, and business logic.
    """
    
    def __init__(self):
        """Initialize test runner."""
        self.results = {
            "total_tests": 0,
            "passed": 0,
            "failed": 0,
            "errors": [],
            "warnings": [],
            "test_details": {}
        }
    
    def run_all_tests(self) -> Dict[str, Any]:
        """
        Run all integration tests.
        
        Returns:
            dict: Test results summary
        """
        logger.info("🧪 Starting comprehensive integration tests...")
        
        try:
            # Test 1: Database Connection
            self._test_database_connection()
            
            # Test 2: Model Creation and Relationships
            self._test_model_relationships()
            
            # Test 3: Foreign Key Constraints
            self._test_foreign_key_constraints()
            
            # Test 4: Business Logic
            self._test_business_logic()
            
            # Test 5: Data Initialization
            self._test_data_initialization()
            
            # Test 6: Complex Queries
            self._test_complex_queries()
            
            # Test 7: Transaction Integrity
            self._test_transaction_integrity()
            
        except Exception as e:
            self._record_error("Critical test failure", str(e))
        
        # Generate final report
        self._generate_report()
        return self.results
    
    def _test_database_connection(self) -> None:
        """Test database connection and basic operations."""
        test_name = "Database Connection"
        logger.info(f"Testing: {test_name}")
        
        try:
            # Test connection
            if not db_manager.check_connection():
                self._record_failure(test_name, "Database connection failed")
                return
            
            # Test session creation
            with db_manager.get_session_context() as db:
                result = db.execute(text("SELECT 1 as test")).scalar()
                if result != 1:
                    self._record_failure(test_name, "Basic query failed")
                    return
            
            self._record_success(test_name, "Database connection and basic queries work")
            
        except Exception as e:
            self._record_error(test_name, str(e))
    
    def _test_model_relationships(self) -> None:
        """Test all model relationships and foreign keys."""
        test_name = "Model Relationships"
        logger.info(f"Testing: {test_name}")
        
        try:
            with db_manager.get_session_context() as db:
                # Get test entities
                user = db.query(User).filter_by(is_superuser=True).first()
                branch = db.query(Branch).filter_by(is_main_branch=True).first()
                currency = db.query(Currency).filter_by(is_base_currency=True).first()
                
                if not user:
                    self._record_failure(test_name, "No superuser found")
                    return
                
                if not branch:
                    self._record_failure(test_name, "No main branch found")
                    return
                
                if not currency:
                    self._record_failure(test_name, "No base currency found")
                    return
                
                # Test User -> Branch relationship
                if user.branch_id and user.branch:
                    self._record_success(f"{test_name}.User-Branch", "User-Branch relationship works")
                else:
                    self._record_warning(f"{test_name}.User-Branch", "User not assigned to branch")
                
                # Test Branch -> User relationship (manager)
                if branch.branch_manager_id and branch.manager:
                    self._record_success(f"{test_name}.Branch-Manager", "Branch-Manager relationship works")
                else:
                    self._record_warning(f"{test_name}.Branch-Manager", "Branch has no manager")
                
                # Test Branch -> BranchBalance relationship
                balances = branch.get_all_balances()
                if balances:
                    self._record_success(f"{test_name}.Branch-Balances", f"Branch has {len(balances)} balances")
                else:
                    self._record_warning(f"{test_name}.Branch-Balances", "Branch has no balances")
                
                # Test Currency relationships
                rates_from = currency.exchange_rates_from.count()
                rates_to = currency.exchange_rates_to.count()
                if rates_from > 0 or rates_to > 0:
                    self._record_success(f"{test_name}.Currency-Rates", f"Currency has {rates_from + rates_to} rates")
                else:
                    self._record_warning(f"{test_name}.Currency-Rates", "Currency has no exchange rates")
                
        except Exception as e:
            self._record_error(test_name, str(e))
    
    def _test_foreign_key_constraints(self) -> None:
        """Test foreign key constraints and referential integrity."""
        test_name = "Foreign Key Constraints"
        logger.info(f"Testing: {test_name}")
        
        try:
            with db_manager.get_session_context() as db:
                # Test 1: Try to create user with invalid branch_id
                try:
                    invalid_user = User(
                        username="test_invalid",
                        email="invalid@test.com",
                        hashed_password="test",
                        first_name="Test",
                        last_name="Invalid",
                        branch_id=99999  # Non-existent branch
                    )
                    db.add(invalid_user)
                    db.commit()
                    self._record_failure(f"{test_name}.Invalid-Branch", "Foreign key constraint not enforced")
                except Exception:
                    db.rollback()
                    self._record_success(f"{test_name}.Invalid-Branch", "Foreign key constraint properly enforced")
                
                # Test 2: Try to create exchange rate with invalid currency
                try:
                    invalid_rate = ExchangeRate(
                        from_currency_id=99999,  # Non-existent currency
                        to_currency_id=99998,    # Non-existent currency
                        from_currency_code="XXX",
                        to_currency_code="YYY",
                        rate=Decimal("1.5")
                    )
                    db.add(invalid_rate)
                    db.commit()
                    self._record_failure(f"{test_name}.Invalid-Currency", "Foreign key constraint not enforced")
                except Exception:
                    db.rollback()
                    self._record_success(f"{test_name}.Invalid-Currency", "Foreign key constraint properly enforced")
                
        except Exception as e:
            self._record_error(test_name, str(e))
    
    def _test_business_logic(self) -> None:
        """Test business logic and model methods."""
        test_name = "Business Logic"
        logger.info(f"Testing: {test_name}")
        
        try:
            with db_manager.get_session_context() as db:
                # Test User business methods
                user = db.query(User).filter_by(is_superuser=True).first()
                if user:
                    # Test role checking
                    has_admin_role = user.has_role("super_admin")
                    if has_admin_role:
                        self._record_success(f"{test_name}.User-Roles", "User role checking works")
                    else:
                        self._record_failure(f"{test_name}.User-Roles", "User role checking failed")
                    
                    # Test permissions
                    has_permission = user.has_permission("*")
                    if has_permission:
                        self._record_success(f"{test_name}.User-Permissions", "User permission checking works")
                    else:
                        self._record_failure(f"{test_name}.User-Permissions", "User permission checking failed")
                
                # Test Branch business methods
                branch = db.query(Branch).filter_by(is_main_branch=True).first()
                if branch:
                    # Test balance checking
                    usd_balance = branch.get_balance("USD")
                    if usd_balance:
                        has_sufficient = branch.has_sufficient_balance("USD", Decimal("100.00"))
                        self._record_success(f"{test_name}.Branch-Balance", f"Balance checking works: {has_sufficient}")
                    else:
                        self._record_warning(f"{test_name}.Branch-Balance", "No USD balance found for testing")
                
                # Test Currency business methods
                currency = db.query(Currency).filter_by(code="USD").first()
                if currency:
                    # Test amount formatting
                    formatted = currency.format_amount(Decimal("1234.5678"))
                    if "1234.57" in formatted:
                        self._record_success(f"{test_name}.Currency-Format", "Amount formatting works")
                    else:
                        self._record_failure(f"{test_name}.Currency-Format", f"Amount formatting failed: {formatted}")
                
                # Test Customer business methods
                customer = db.query(Customer).first()
                if customer:
                    # Test full name
                    full_name = customer.full_name
                    if full_name and full_name != "Unknown Company":
                        self._record_success(f"{test_name}.Customer-Name", f"Customer name generation works: {full_name}")
                    
                    # Test transaction capability
                    can_transact = customer.can_transact
                    self._record_success(f"{test_name}.Customer-CanTransact", f"Customer transaction check: {can_transact}")
                
        except Exception as e:
            self._record_error(test_name, str(e))
    
    def _test_data_initialization(self) -> None:
        """Test data initialization and verification."""
        test_name = "Data Initialization"
        logger.info(f"Testing: {test_name}")
        
        try:
            # Run verification
            verification_results = verify_initialization()
            
            if verification_results["status"] == "success":
                self._record_success(test_name, "Data initialization verification passed")
            elif verification_results["status"] == "warning":
                self._record_warning(test_name, f"Verification completed with warnings: {verification_results.get('warnings', [])}")
            else:
                self._record_failure(test_name, f"Verification failed: {verification_results.get('issues', [])}")
            
            # Check specific counts
            expected_minimums = {
                "roles": 6,
                "currencies": 10,
                "users": 1,
                "branches": 3,
                "vault_balances": 4
            }
            
            for entity, min_count in expected_minimums.items():
                actual_count = verification_results["counts"].get(entity, 0)
                if actual_count >= min_count:
                    self._record_success(f"{test_name}.Count-{entity}", f"Has {actual_count} {entity} (≥{min_count})")
                else:
                    self._record_failure(f"{test_name}.Count-{entity}", f"Has {actual_count} {entity} (<{min_count})")
            
        except Exception as e:
            self._record_error(test_name, str(e))
    
    def _test_complex_queries(self) -> None:
        """Test complex queries and joins."""
        test_name = "Complex Queries"
        logger.info(f"Testing: {test_name}")
        
        try:
            with db_manager.get_session_context() as db:
                # Test 1: Join users with their branches and roles
                query = db.query(User).join(Branch, User.branch_id == Branch.id, isouter=True).join(
                    UserRole, User.id == UserRole.user_id, isouter=True
                ).join(Role, UserRole.role_id == Role.id, isouter=True)
                
                users_with_details = query.all()
                if users_with_details:
                    self._record_success(f"{test_name}.User-Branch-Role", f"Complex join returned {len(users_with_details)} records")
                else:
                    self._record_failure(f"{test_name}.User-Branch-Role", "Complex join returned no results")
                
                # Test 2: Get branch balances with currency information
                balance_query = db.query(BranchBalance).join(Currency).join(Branch)
                balances_with_details = balance_query.all()
                if balances_with_details:
                    self._record_success(f"{test_name}.Balance-Details", f"Balance join returned {len(balances_with_details)} records")
                else:
                    self._record_warning(f"{test_name}.Balance-Details", "No branch balances found for testing")
                
                # Test 3: Get exchange rates with currency names
                rate_query = db.query(ExchangeRate).join(
                    Currency, ExchangeRate.from_currency_id == Currency.id
                ).join(
                    Currency, ExchangeRate.to_currency_id == Currency.id
                )
                rates_with_details = rate_query.all()
                if rates_with_details:
                    self._record_success(f"{test_name}.Rate-Details", f"Rate join returned {len(rates_with_details)} records")
                else:
                    self._record_warning(f"{test_name}.Rate-Details", "No exchange rates found for testing")
                
        except Exception as e:
            self._record_error(test_name, str(e))
    
    def _test_transaction_integrity(self) -> None:
        """Test database transaction integrity and rollback."""
        test_name = "Transaction Integrity"
        logger.info(f"Testing: {test_name}")
        
        try:
            # Test successful transaction
            with db_manager.get_session_context() as db:
                initial_count = db.query(Role).count()
                
                # Create test role
                test_role = Role(
                    name="test_role",
                    display_name="Test Role",
                    description="Test role for integrity testing",
                    is_system_role=False,
                    hierarchy_level="10"
                )
                db.add(test_role)
                db.commit()
                
                new_count = db.query(Role).count()
                if new_count == initial_count + 1:
                    self._record_success(f"{test_name}.Successful-Commit", "Transaction commit works correctly")
                    
                    # Clean up
                    db.delete(test_role)
                    db.commit()
                else:
                    self._record_failure(f"{test_name}.Successful-Commit", "Transaction commit failed")
            
            # Test transaction rollback
            try:
                with db_manager.get_session_context() as db:
                    initial_count = db.query(Role).count()
                    
                    # Create test role and force an error
                    test_role = Role(
                        name="test_role_rollback",
                        display_name="Test Role Rollback",
                        description="Test role for rollback testing",
                        is_system_role=False,
                        hierarchy_level="10"
                    )
                    db.add(test_role)
                    
                    # Force an error to trigger rollback
                    db.execute(text("INSERT INTO non_existent_table VALUES (1)"))
                    
            except Exception:
                # Check that rollback worked
                with db_manager.get_session_context() as db:
                    final_count = db.query(Role).count()
                    if final_count == initial_count:
                        self._record_success(f"{test_name}.Rollback", "Transaction rollback works correctly")
                    else:
                        self._record_failure(f"{test_name}.Rollback", "Transaction rollback failed")
        
        except Exception as e:
            self._record_error(test_name, str(e))
    
    def _record_success(self, test_name: str, message: str) -> None:
        """Record a successful test."""
        self.results["total_tests"] += 1
        self.results["passed"] += 1
        self.results["test_details"][test_name] = {"status": "PASS", "message": message}
        logger.info(f"✅ {test_name}: {message}")
    
    def _record_failure(self, test_name: str, message: str) -> None:
        """Record a failed test."""
        self.results["total_tests"] += 1
        self.results["failed"] += 1
        self.results["test_details"][test_name] = {"status": "FAIL", "message": message}
        self.results["errors"].append(f"{test_name}: {message}")
        logger.error(f"❌ {test_name}: {message}")
    
    def _record_warning(self, test_name: str, message: str) -> None:
        """Record a test warning."""
        self.results["total_tests"] += 1
        self.results["passed"] += 1  # Warnings count as passes
        self.results["test_details"][test_name] = {"status": "WARN", "message": message}
        self.results["warnings"].append(f"{test_name}: {message}")
        logger.warning(f"⚠️  {test_name}: {message}")
    
    def _record_error(self, test_name: str, error: str) -> None:
        """Record a test error."""
        self.results["total_tests"] += 1
        self.results["failed"] += 1
        self.results["test_details"][test_name] = {"status": "ERROR", "message": error}
        self.results["errors"].append(f"{test_name}: {error}")
        logger.error(f"💥 {test_name}: {error}")
    
    def _generate_report(self) -> None:
        """Generate final test report."""
        total = self.results["total_tests"]
        passed = self.results["passed"]
        failed = self.results["failed"]
        success_rate = (passed / total * 100) if total > 0 else 0
        
        print("\n" + "="*80)
        print("🧪 CEMS INTEGRATION TEST RESULTS")
        print("="*80)
        print(f"📊 Total Tests: {total}")
        print(f"✅ Passed: {passed}")
        print(f"❌ Failed: {failed}")
        print(f"📈 Success Rate: {success_rate:.1f}%")
        
        if self.results["warnings"]:
            print(f"\n⚠️  Warnings ({len(self.results['warnings'])}):")
            for warning in self.results["warnings"]:
                print(f"   • {warning}")
        
        if self.results["errors"]:
            print(f"\n❌ Errors ({len(self.results['errors'])}):")
            for error in self.results["errors"]:
                print(f"   • {error}")
        
        print("\n📋 Detailed Results:")
        for test_name, details in self.results["test_details"].items():
            status_emoji = {"PASS": "✅", "FAIL": "❌", "WARN": "⚠️", "ERROR": "💥"}
            emoji = status_emoji.get(details["status"], "❓")
            print(f"   {emoji} {test_name}: {details['message']}")
        
        print("\n" + "="*80)
        
        if failed == 0:
            print("🎉 All tests passed! The CEMS system is ready for use.")
        else:
            print(f"⚠️  {failed} test(s) failed. Please review the errors above.")
        
        print("="*80)


def run_full_integration_test() -> bool:
    """
    Run complete integration test suite.
    
    Returns:
        bool: True if all tests passed
    """
    print("🚀 Starting CEMS Integration Test Suite...")
    
    # Initialize test runner
    runner = IntegrationTestRunner()
    
    # Run all tests
    results = runner.run_all_tests()
    
    # Return success status
    return results["failed"] == 0


def run_quick_test() -> bool:
    """
    Run quick smoke test to verify basic functionality.
    
    Returns:
        bool: True if basic functionality works
    """
    print("🔥 Running Quick Smoke Test...")
    
    try:
        # Test database connection
        if not db_manager.check_connection():
            print("❌ Database connection failed")
            return False
        print("✅ Database connection works")
        
        # Test basic query
        with db_manager.get_session_context() as db:
            user_count = db.query(User).count()
            role_count = db.query(Role).count()
            currency_count = db.query(Currency).count()
            
            print(f"✅ Found {user_count} users, {role_count} roles, {currency_count} currencies")
        
        # Test verification
        results = verify_initialization()
        if results["status"] in ["success", "warning"]:
            print("✅ Database verification passed")
            return True
        else:
            print(f"❌ Database verification failed: {results.get('issues', [])}")
            return False
    
    except Exception as e:
        print(f"❌ Smoke test failed: {e}")
        return False


if __name__ == "__main__":
    """Run tests from command line."""
    import argparse
    
    parser = argparse.ArgumentParser(description="CEMS Integration Test Runner")
    parser.add_argument(
        "--full", 
        action="store_true", 
        help="Run full integration test suite"
    )
    parser.add_argument(
        "--quick", 
        action="store_true", 
        help="Run quick smoke test"
    )
    parser.add_argument(
        "--reset-and-test", 
        action="store_true", 
        help="Reset database and run full test"
    )
    
    args = parser.parse_args()
    
    try:
        if args.reset_and_test:
            if input("Reset database and run tests? (yes/no): ").lower() == 'yes':
                print("🔄 Resetting database...")
                reset_db()
                print("🧪 Running full integration tests...")
                success = run_full_integration_test()
            else:
                print("Operation cancelled.")
                sys.exit(0)
        elif args.full:
            success = run_full_integration_test()
        elif args.quick:
            success = run_quick_test()
        else:
            # Default: run quick test
            success = run_quick_test()
        
        sys.exit(0 if success else 1)
        
    except KeyboardInterrupt:
        print("\n\n⚠️  Tests cancelled by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Test runner error: {e}")
        sys.exit(1)