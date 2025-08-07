"""
Module: database
Purpose: Database connection and session management for CEMS
Author: CEMS Development Team
Date: 2024
"""

import logging
from contextlib import contextmanager
from typing import Generator, Optional
from sqlalchemy import create_engine, event, pool
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.engine import Engine
from sqlalchemy.pool import QueuePool

from app.core.config import settings
from app.db.base import Base

# Configure logging
logger = logging.getLogger(__name__)


class DatabaseManager:
    """
    Database connection and session manager for CEMS.
    Handles engine creation, session management, and connection pooling.
    """
    
    def __init__(self):
        """Initialize database manager with configuration from settings."""
        self.engine: Optional[Engine] = None
        self.SessionLocal: Optional[sessionmaker] = None
        self._setup_engine()
        self._setup_session()
    
    def _setup_engine(self) -> None:
        """
        Setup SQLAlchemy engine with optimized configuration.
        """
        # Engine configuration for PostgreSQL
        engine_config = {
            "poolclass": QueuePool,
            "pool_size": 5,  # Number of connections to maintain
            "max_overflow": 10,  # Additional connections beyond pool_size
            "pool_timeout": 30,  # Seconds to wait for connection
            "pool_recycle": 3600,  # Seconds to recycle connections (1 hour)
            "pool_pre_ping": True,  # Validate connections before use
            "echo": settings.DEBUG,  # Log all SQL statements in debug mode
            "echo_pool": False,  # Log pool checkouts/checkins
            "future": True,  # Use SQLAlchemy 2.0 style
        }
        
        # Additional configuration for production
        if settings.ENVIRONMENT == "production":
            engine_config.update({
                "echo": False,  # Disable SQL logging in production
                "pool_size": 10,
                "max_overflow": 20,
            })
        
        try:
            self.engine = create_engine(
                str(settings.DATABASE_URL),
                **engine_config
            )
            
            # Setup event listeners for enhanced functionality
            self._setup_event_listeners()
            
            logger.info("Database engine configured successfully")
            
        except Exception as e:
            logger.error(f"Failed to create database engine: {e}")
            raise
    
    def _setup_session(self) -> None:
        """
        Setup SQLAlchemy session factory.
        """
        if not self.engine:
            raise RuntimeError("Database engine not initialized")
        
        self.SessionLocal = sessionmaker(
            bind=self.engine,
            autocommit=False,
            autoflush=False,
            expire_on_commit=False  # Keep objects accessible after commit
        )
        
        logger.info("Database session factory configured successfully")
    
    def _setup_event_listeners(self) -> None:
        """
        Setup SQLAlchemy event listeners for monitoring and optimization.
        """
        @event.listens_for(self.engine, "connect")
        def set_sqlite_pragma(dbapi_connection, connection_record):
            """Set SQLite specific optimizations if using SQLite."""
            if "sqlite" in str(self.engine.url):
                cursor = dbapi_connection.cursor()
                # Enable foreign key constraints
                cursor.execute("PRAGMA foreign_keys=ON")
                # Set journal mode for better concurrency
                cursor.execute("PRAGMA journal_mode=WAL")
                cursor.close()
        
        @event.listens_for(self.engine, "first_connect")
        def receive_first_connect(dbapi_connection, connection_record):
            """Log first connection to database."""
            logger.info("First database connection established")
        
        @event.listens_for(self.engine, "connect")
        def receive_connect(dbapi_connection, connection_record):
            """Log database connections in debug mode."""
            if settings.DEBUG:
                logger.debug("New database connection established")
        
        @event.listens_for(self.engine, "checkout")
        def receive_checkout(dbapi_connection, connection_record, connection_proxy):
            """Log connection checkout in debug mode."""
            if settings.DEBUG:
                logger.debug("Connection checked out from pool")
    
    def get_session(self) -> Session:
        """
        Get a new database session.
        
        Returns:
            Session: SQLAlchemy database session
            
        Raises:
            RuntimeError: If session factory is not initialized
        """
        if not self.SessionLocal:
            raise RuntimeError("Database session factory not initialized")
        
        return self.SessionLocal()
    
    @contextmanager
    def get_session_context(self) -> Generator[Session, None, None]:
        """
        Context manager for database sessions with automatic cleanup.
        
        Yields:
            Session: Database session
            
        Example:
            with db_manager.get_session_context() as session:
                user = session.query(User).first()
        """
        session = self.get_session()
        try:
            yield session
            session.commit()
        except Exception as e:
            session.rollback()
            logger.error(f"Database session error: {e}")
            raise
        finally:
            session.close()
    
    def create_tables(self) -> None:
        """
        Create all database tables.
        Should only be used in development or initial setup.
        """
        if not self.engine:
            raise RuntimeError("Database engine not initialized")
        
        try:
            Base.metadata.create_all(bind=self.engine)
            logger.info("Database tables created successfully")
        except Exception as e:
            logger.error(f"Failed to create database tables: {e}")
            raise
    
    def drop_tables(self) -> None:
        """
        Drop all database tables.
        Use with extreme caution - this will delete all data!
        """
        if not self.engine:
            raise RuntimeError("Database engine not initialized")
        
        if settings.ENVIRONMENT == "production":
            raise RuntimeError("Cannot drop tables in production environment")
        
        try:
            Base.metadata.drop_all(bind=self.engine)
            logger.warning("All database tables dropped")
        except Exception as e:
            logger.error(f"Failed to drop database tables: {e}")
            raise
    
    def check_connection(self) -> bool:
        """
        Check if database connection is working.
        
        Returns:
            bool: True if connection is working, False otherwise
        """
        try:
            with self.get_session_context() as session:
                session.execute("SELECT 1")
            return True
        except Exception as e:
            logger.error(f"Database connection check failed: {e}")
            return False
    
    def get_connection_info(self) -> dict:
        """
        Get database connection information.
        
        Returns:
            dict: Connection information
        """
        if not self.engine:
            return {"status": "not_initialized"}
        
        return {
            "status": "initialized",
            "url": str(self.engine.url).replace(str(self.engine.url.password), "***"),
            "pool_size": self.engine.pool.size(),
            "checked_in": self.engine.pool.checkedin(),
            "checked_out": self.engine.pool.checkedout(),
            "invalidated": self.engine.pool.invalidated(),
        }


# Global database manager instance
db_manager = DatabaseManager()


# Dependency function for FastAPI
def get_db() -> Generator[Session, None, None]:
    """
    FastAPI dependency to get database session.
    
    Yields:
        Session: Database session
        
    Example:
        @app.get("/users/")
        def get_users(db: Session = Depends(get_db)):
            return db.query(User).all()
    """
    session = db_manager.get_session()
    try:
        yield session
    except Exception as e:
        session.rollback()
        logger.error(f"Database session error in dependency: {e}")
        raise
    finally:
        session.close()


# Alternative dependency with automatic commit
def get_db_with_commit() -> Generator[Session, None, None]:
    """
    FastAPI dependency with automatic commit on success.
    
    Yields:
        Session: Database session that commits automatically
    """
    session = db_manager.get_session()
    try:
        yield session
        session.commit()
    except Exception as e:
        session.rollback()
        logger.error(f"Database session error with commit: {e}")
        raise
    finally:
        session.close()


# Health check function
async def check_database_health() -> dict:
    """
    Async health check for database connection.
    Used by health check endpoints.
    
    Returns:
        dict: Health status information
    """
    try:
        is_healthy = db_manager.check_connection()
        connection_info = db_manager.get_connection_info()
        
        return {
            "database": {
                "status": "healthy" if is_healthy else "unhealthy",
                "connection_info": connection_info
            }
        }
    except Exception as e:
        logger.error(f"Database health check failed: {e}")
        return {
            "database": {
                "status": "unhealthy",
                "error": str(e)
            }
        }


# Utility functions
def execute_raw_sql(sql: str, params: Optional[dict] = None) -> list:
    """
    Execute raw SQL query.
    Use with caution and prefer ORM methods when possible.
    
    Args:
        sql: Raw SQL query
        params: Query parameters
        
    Returns:
        list: Query results
    """
    with db_manager.get_session_context() as session:
        result = session.execute(sql, params or {})
        return result.fetchall()


def get_table_row_count(table_name: str) -> int:
    """
    Get row count for a specific table.
    
    Args:
        table_name: Name of the table
        
    Returns:
        int: Number of rows in the table
    """
    sql = f"SELECT COUNT(*) FROM {table_name}"
    result = execute_raw_sql(sql)
    return result[0][0] if result else 0