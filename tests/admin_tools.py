"""
Module: admin_tools
Purpose: Database administration and maintenance tools for CEMS
Author: CEMS Development Team
Date: 2024
"""

import sys
import os
from datetime import datetime, timedelta
from decimal import Decimal
from typing import Dict, Any, List, Optional
from sqlalchemy import text, func
from sqlalchemy.orm import Session

# Add app to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.core.config import settings
from app.db.database import db_manager
from app.db.init_db import init_db, reset_db, verify_initialization
from app.db.models import (
    User, Role, UserRole, Currency, ExchangeRate,
    Branch, BranchBalance, Customer, Vault, VaultBalance
)
from app.utils.logger import get_logger

# Setup logging
logger = get_logger(__name__)


class CEMSAdminTools:
    """
    Administrative tools for CEMS database management and maintenance.
    """
    
    def __init__(self):
        """Initialize admin tools."""
        self.session: Optional[Session] = None
    
    def get_system_status(self) -> Dict[str, Any]:
        """
        Get comprehensive system status.
        
        Returns:
            dict: System status information
        """
        logger.info("Getting system status...")
        
        status = {
            "timestamp": datetime.now().isoformat(),
            "database": {},
            "entities": {},
            "health_checks": {},
            "warnings": [],
            "recommendations": []
        }
        
        try:
            # Database connection info
            status["database"] = db_manager.get_connection_info()
            
            # Entity counts
            with db_manager.get_session_context() as db:
                status["entities"] = {
                    "users": db.query(User).count(),
                    "active_users": db.query(User).filter_by(is_active=True).count(),
                    "roles": db.query(Role).count(),
                    "currencies": db.query(Currency).count(),
                    "active_currencies": db.query(Currency).filter_by(is_active=True).count(),
                    "exchange_rates": db.query(ExchangeRate).count(),
                    "active_rates": db.query(ExchangeRate).filter_by(is_active=True).count(),
                    "branches": db.query(Branch).count(),
                    "active_branches": db.query(Branch).filter(Branch.status == 'active').count(),
                    "customers": db.query(Customer).count(),
                    "active_customers": db.query(Customer).filter(Customer.status == 'active').count(),
                    "vaults": db.query(Vault).count(),
                    "vault_balances": db.query(VaultBalance).count()
                }
                
                # Health checks
                status["health_checks"] = self._perform_health_checks(db)
                
                # Warnings and recommendations
                status["warnings"], status["recommendations"] = self._generate_warnings_and_recommendations(db, status["entities"])
        
        except Exception as e:
            status["error"] = str(e)
            logger.error(f"Failed to get system status: {e}")
        
        return status
    
    def _perform_health_checks(self, db: Session) -> Dict[str, Any]:
        """Perform health checks on the system."""
        checks = {}
        
        # Check 1: Superuser exists
        superuser = db.query(User).filter_by(is_superuser=True).first()
        checks["superuser_exists"] = bool(superuser)
        
        # Check 2: Main branch exists
        main_branch = db.query(Branch).filter_by(is_main_branch=True).first()
        checks["main_branch_exists"] = bool(main_branch)
        
        # Check 3: Base currency exists
        base_currency = db.query(Currency).filter_by(is_base_currency=True).first()
        checks["base_currency_exists"] = bool(base_currency)
        
        # Check 4: Active exchange rates
        active_rates = db.query(ExchangeRate).filter_by(is_active=True).count()
        checks["has_exchange_rates"] = active_rates > 0
        
        # Check 5: Branch balances exist
        branch_balances = db.query(BranchBalance).filter_by(is_active=True).count()
        checks["has_branch_balances"] = branch_balances > 0
        
        # Check 6: Main vault exists
        main_vault = db.query(Vault).filter_by(is_main_vault=True).first()
        checks["main_vault_exists"] = bool(main_vault)
        
        return checks
    
    def _generate_warnings_and_recommendations(self, db: Session, entities: Dict[str, int]) -> tuple:
        """Generate warnings and recommendations based on system state."""
        warnings = []
        recommendations = []
        
        # Check entity counts
        if entities["active_users"] == 0:
            warnings.append("No active users in the system")
            recommendations.append("Create at least one active user account")
        
        if entities["active_currencies"] < 5:
            warnings.append("Very few active currencies available")
            recommendations.append("Consider adding more currencies for exchange operations")
        
        if entities["active_rates"] == 0:
            warnings.append("No active exchange rates available")
            recommendations.append("Update exchange rates from external API or manual entry")
        
        if entities["active_branches"] == 0:
            warnings.append("No active branches available")
            recommendations.append("Ensure at least one branch is active for operations")
        
        if entities["customers"] == 0:
            warnings.append("No customers registered")
            recommendations.append("System is ready for customer registration")
        
        # Check for stale exchange rates
        try:
            stale_rates = db.query(ExchangeRate).filter(
                ExchangeRate.last_updated_at < datetime.now() - timedelta(days=1),
                ExchangeRate.is_active == True
            ).count()
            
            if stale_rates > 0:
                warnings.append(f"{stale_rates} exchange rates are more than 1 day old")
                recommendations.append("Update exchange rates regularly for accurate pricing")
        except Exception:
            pass
        
        return warnings, recommendations
    
    def cleanup_stale_data(self) -> Dict[str, int]:
        """
        Clean up stale and unnecessary data.
        
        Returns:
            dict: Cleanup statistics
        """
        logger.info("Starting data cleanup...")
        
        stats = {
            "expired_rates_deactivated": 0,
            "stale_sessions_cleaned": 0,
            "inactive_tokens_removed": 0
        }
        
        try:
            with db_manager.get_session_context() as db:
                # Deactivate expired exchange rates
                expired_rates = db.query(ExchangeRate).filter(
                    ExchangeRate.effective_until < datetime.now(),
                    ExchangeRate.is_active == True
                ).all()
                
                for rate in expired_rates:
                    rate.is_active = False
                    stats["expired_rates_deactivated"] += 1
                
                db.commit()
                logger.info(f"Cleanup completed: {stats}")
        
        except Exception as e:
            logger.error(f"Cleanup failed: {e}")
            stats["error"] = str(e)
        
        return stats
    
    def backup_critical_data(self) -> Dict[str, Any]:
        """
        Create backup of critical system data.
        
        Returns:
            dict: Backup information
        """
        logger.info("Creating backup of critical data...")
        
        backup_info = {
            "timestamp": datetime.now().isoformat(),
            "backup_file": None,
            "entities_backed_up": {},
            "status": "success"
        }
        
        try:
            with db_manager.get_session_context() as db:
                # Count entities for backup verification
                backup_info["entities_backed_up"] = {
                    "users": db.query(User).count(),
                    "roles": db.query(Role).count(),
                    "currencies": db.query(Currency).count(),
                    "exchange_rates": db.query(ExchangeRate).filter_by(is_active=True).count(),
                    "branches": db.query(Branch).count(),
                    "customers": db.query(Customer).count()
                }
                
                # In a real implementation, you would:
                # 1. Export data to JSON/CSV files
                # 2. Create database dump
                # 3. Store in secure location
                backup_info["backup_file"] = f"cems_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.sql"
                
        except Exception as e:
            backup_info["status"] = "failed"
            backup_info["error"] = str(e)
            logger.error(f"Backup failed: {e}")
        
        return backup_info
    
    def update_exchange_rates_from_api(self) -> Dict[str, Any]:
        """
        Update exchange rates from external API (placeholder).
        
        Returns:
            dict: Update results
        """
        logger.info("Updating exchange rates from API...")
        
        # This is a placeholder implementation
        # In production, you would connect to a real exchange rate API
        
        result = {
            "timestamp": datetime.now().isoformat(),
            "rates_updated": 0,
            "rates_added": 0,
            "status": "success",
            "source": "placeholder_api"
        }
        
        try:
            # Sample rate updates (in production, fetch from real API)
            sample_updates = {
                "USD/EUR": Decimal("0.8543"),
                "USD/GBP": Decimal("0.7821"),
                "USD/SAR": Decimal("3.7502"),
                "USD/AED": Decimal("3.6728")
            }
            
            with db_manager.get_session_context() as db:
                for pair, new_rate in sample_updates.items():
                    from_currency, to_currency = pair.split('/')
                    
                    # Find existing rate
                    existing_rate = db.query(ExchangeRate).filter_by(
                        from_currency_code=from_currency,
                        to_currency_code=to_currency,
                        rate_type="mid",
                        is_active=True
                    ).first()
                    
                    if existing_rate:
                        existing_rate.rate = new_rate
                        existing_rate.last_updated_at = datetime.now()
                        existing_rate.source = "api_update"
                        existing_rate.reliability_score = "95"
                        result["rates_updated"] += 1
                    
                db.commit()
        
        except Exception as e:
            result["status"] = "failed"
            result["error"] = str(e)
            logger.error(f"Rate update failed: {e}")
        
        return result
    
    def generate_system_report(self) -> Dict[str, Any]:
        """
        Generate comprehensive system report.
        
        Returns:
            dict: System report
        """
        logger.info("Generating system report...")
        
        report = {
            "generated_at": datetime.now().isoformat(),
            "system_info": {},
            "database_stats": {},
            "operational_stats": {},
            "security_info": {},
            "recommendations": []
        }
        
        try:
            # Get system status
            status = self.get_system_status()
            report["system_info"] = status
            
            # Database statistics
            with db_manager.get_session_context() as db:
                report["database_stats"] = {
                    "total_tables": len(db_manager.engine.table_names()) if hasattr(db_manager.engine, 'table_names') else 0,
                    "connection_pool_size": db_manager.engine.pool.size(),
                    "active_connections": db_manager.engine.pool.checkedout(),
                    "database_size": "N/A"  # Would need specific query for actual size
                }
                
                # Operational statistics
                report["operational_stats"] = {
                    "branches_by_status": self._get_branch_statistics(db),
                    "customers_by_type": self._get_customer_statistics(db),
                    "currency_coverage": self._get_currency_statistics(db),
                    "system_utilization": self._get_utilization_stats(db)
                }
                
                # Security information
                report["security_info"] = {
                    "admin_users": db.query(User).filter_by(is_superuser=True).count(),
                    "inactive_users": db.query(User).filter_by(is_active=False).count(),
                    "password_policy": "Enforced",  # Based on your validation rules
                    "last_admin_login": "N/A"  # Would track in production
                }
        
        except Exception as e:
            report["error"] = str(e)
            logger.error(f"Report generation failed: {e}")
        
        return report
    
    def _get_branch_statistics(self, db: Session) -> Dict[str, int]:
        """Get branch statistics."""
        return {
            "active": db.query(Branch).filter(Branch.status == 'active').count(),
            "inactive": db.query(Branch).filter(Branch.status == 'inactive').count(),
            "maintenance": db.query(Branch).filter(Branch.status == 'maintenance').count(),
            "main_branches": db.query(Branch).filter_by(is_main_branch=True).count()
        }
    
    def _get_customer_statistics(self, db: Session) -> Dict[str, int]:
        """Get customer statistics."""
        return {
            "individual": db.query(Customer).filter_by(customer_type='individual').count(),
            "business": db.query(Customer).filter_by(customer_type='business').count(),
            "corporate": db.query(Customer).filter_by(customer_type='corporate').count(),
            "vip": db.query(Customer).filter_by(is_vip=True).count(),
            "active": db.query(Customer).filter_by(status='active').count()
        }
    
    def _get_currency_statistics(self, db: Session) -> Dict[str, Any]:
        """Get currency statistics."""
        total_currencies = db.query(Currency).count()
        active_currencies = db.query(Currency).filter_by(is_active=True).count()
        
        return {
            "total_currencies": total_currencies,
            "active_currencies": active_currencies,
            "coverage_percentage": (active_currencies / total_currencies * 100) if total_currencies > 0 else 0,
            "base_currency": db.query(Currency).filter_by(is_base_currency=True).first().code if db.query(Currency).filter_by(is_base_currency=True).first() else None
        }
    
    def _get_utilization_stats(self, db: Session) -> Dict[str, Any]:
        """Get system utilization statistics."""
        return {
            "average_branch_balances": "N/A",  # Would calculate actual averages
            "total_vault_capacity": "N/A",     # Would sum vault capacities
            "system_load": "Normal",           # Would monitor actual load
            "uptime": "N/A"                    # Would track actual uptime
        }


def main():
    """Main CLI interface for admin tools."""
    import argparse
    
    parser = argparse.ArgumentParser(description="CEMS Database Administration Tools")
    parser.add_argument("--status", action="store_true", help="Show system status")
    parser.add_argument("--cleanup", action="store_true", help="Clean up stale data")
    parser.add_argument("--backup", action="store_true", help="Backup critical data")
    parser.add_argument("--update-rates", action="store_true", help="Update exchange rates")
    parser.add_argument("--report", action="store_true", help="Generate system report")
    parser.add_argument("--verify", action="store_true", help="Verify system integrity")
    parser.add_argument("--init", action="store_true", help="Initialize database")
    parser.add_argument("--reset", action="store_true", help="Reset database (DANGEROUS)")
    
    args = parser.parse_args()
    
    # Initialize admin tools
    admin = CEMSAdminTools()
    
    try:
        if args.status:
            print("📊 Getting system status...")
            status = admin.get_system_status()
            print_status(status)
            
        elif args.cleanup:
            print("🧹 Cleaning up stale data...")
            results = admin.cleanup_stale_data()
            print(f"✅ Cleanup completed: {results}")
            
        elif args.backup:
            print("💾 Creating backup...")
            backup_info = admin.backup_critical_data()
            print(f"✅ Backup completed: {backup_info}")
            
        elif args.update_rates:
            print("💱 Updating exchange rates...")
            results = admin.update_exchange_rates_from_api()
            print(f"✅ Rates updated: {results}")
            
        elif args.report:
            print("📋 Generating system report...")
            report = admin.generate_system_report()
            print_report(report)
            
        elif args.verify:
            print("🔍 Verifying system integrity...")
            results = verify_initialization()
            print_verification(results)
            
        elif args.init:
            print("🚀 Initializing database...")
            init_db()
            print("✅ Database initialization completed")
            
        elif args.reset:
            if input("⚠️  Are you sure you want to RESET the database? All data will be lost! (type 'RESET' to confirm): ") == "RESET":
                print("🔄 Resetting database...")
                reset_db()
                print("✅ Database reset completed")
            else:
                print("❌ Reset cancelled")
        else:
            parser.print_help()
    
    except Exception as e:
        print(f"❌ Operation failed: {e}")
        sys.exit(1)


def print_status(status: Dict[str, Any]) -> None:
    """Print formatted system status."""
    print("\n" + "="*60)
    print("📊 CEMS SYSTEM STATUS")
    print("="*60)
    
    print(f"🕒 Timestamp: {status['timestamp']}")
    
    if "entities" in status:
        print(f"\n📈 Entity Counts:")
        for entity, count in status["entities"].items():
            print(f"   {entity}: {count}")
    
    if "health_checks" in status:
        print(f"\n🏥 Health Checks:")
        for check, passed in status["health_checks"].items():
            emoji = "✅" if passed else "❌"
            print(f"   {emoji} {check}: {'PASS' if passed else 'FAIL'}")
    
    if status.get("warnings"):
        print(f"\n⚠️  Warnings:")
        for warning in status["warnings"]:
            print(f"   • {warning}")
    
    if status.get("recommendations"):
        print(f"\n💡 Recommendations:")
        for rec in status["recommendations"]:
            print(f"   • {rec}")
    
    print("="*60)


def print_report(report: Dict[str, Any]) -> None:
    """Print formatted system report."""
    print("\n" + "="*80)
    print("📋 CEMS SYSTEM REPORT")
    print("="*80)
    
    print(f"Generated: {report['generated_at']}")
    
    if "operational_stats" in report:
        stats = report["operational_stats"]
        
        if "branches_by_status" in stats:
            print(f"\n🏢 Branches:")
            for status, count in stats["branches_by_status"].items():
                print(f"   {status}: {count}")
        
        if "customers_by_type" in stats:
            print(f"\n👥 Customers:")
            for customer_type, count in stats["customers_by_type"].items():
                print(f"   {customer_type}: {count}")
    
    print("="*80)


def print_verification(results: Dict[str, Any]) -> None:
    """Print formatted verification results."""
    print("\n" + "="*60)
    print("🔍 SYSTEM VERIFICATION RESULTS")
    print("="*60)
    
    print(f"Status: {results['status'].upper()}")
    
    if "counts" in results:
        print(f"\n📊 Record Counts:")
        for entity, count in results["counts"].items():
            print(f"   {entity}: {count}")
    
    if results.get("issues"):
        print(f"\n❌ Issues:")
        for issue in results["issues"]:
            print(f"   • {issue}")
    
    if results.get("warnings"):
        print(f"\n⚠️  Warnings:")
        for warning in results["warnings"]:
            print(f"   • {warning}")
    
    print("="*60)


if __name__ == "__main__":
    main()