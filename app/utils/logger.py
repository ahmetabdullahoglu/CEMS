"""
Module: logger
Purpose: Centralized logging configuration for CEMS application
Author: CEMS Development Team
Date: 2024
"""

import logging
import logging.handlers
import sys
import os
import json
from datetime import datetime
from typing import Optional, Dict, Any
from pathlib import Path

from app.core.config import settings


class CEMSFormatter(logging.Formatter):
    """
    Custom formatter for CEMS logging with structured output.
    Provides both human-readable and JSON formats.
    """
    
    def __init__(self, json_format: bool = False):
        """
        Initialize formatter.
        
        Args:
            json_format: Whether to output JSON format
        """
        self.json_format = json_format
        
        if json_format:
            super().__init__()
        else:
            super().__init__(
                fmt=settings.LOG_FORMAT,
                datefmt="%Y-%m-%d %H:%M:%S"
            )
    
    def format(self, record: logging.LogRecord) -> str:
        """
        Format the log record.
        
        Args:
            record: Log record to format
            
        Returns:
            str: Formatted log message
        """
        if not self.json_format:
            return super().format(record)
        
        # Create structured log entry
        log_entry = {
            "timestamp": datetime.fromtimestamp(record.created).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
            "process_id": record.process,
            "thread_id": record.thread
        }
        
        # Add exception info if present
        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)
        
        # Add extra fields if present
        if hasattr(record, "extra_fields"):
            log_entry.update(record.extra_fields)
        
        return json.dumps(log_entry, ensure_ascii=False)


class CEMSLogger:
    """
    Centralized logger for CEMS application with enhanced features.
    """
    
    def __init__(self, name: str):
        """
        Initialize CEMS logger.
        
        Args:
            name: Logger name
        """
        self.logger = logging.getLogger(name)
        self._setup_logger()
    
    def _setup_logger(self):
        """Setup logger configuration."""
        if self.logger.handlers:
            return  # Already configured
        
        self.logger.setLevel(getattr(logging, settings.LOG_LEVEL.upper()))
        
        # Console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.INFO)
        console_formatter = CEMSFormatter(json_format=False)
        console_handler.setFormatter(console_formatter)
        self.logger.addHandler(console_handler)
        
        # File handler (if log file is configured)
        if settings.LOG_FILE:
            self._setup_file_handler()
        
        # JSON handler for structured logging
        if settings.ENVIRONMENT == "production":
            self._setup_json_handler()
        
        # Prevent duplicate logs
        self.logger.propagate = False
    
    def _setup_file_handler(self):
        """Setup rotating file handler."""
        try:
            # Create log directory if it doesn't exist
            log_path = Path(settings.LOG_FILE)
            log_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Rotating file handler
            file_handler = logging.handlers.RotatingFileHandler(
                filename=settings.LOG_FILE,
                maxBytes=settings.LOG_MAX_SIZE,
                backupCount=settings.LOG_BACKUP_COUNT,
                encoding="utf-8"
            )
            file_handler.setLevel(getattr(logging, settings.LOG_LEVEL.upper()))
            file_formatter = CEMSFormatter(json_format=False)
            file_handler.setFormatter(file_formatter)
            self.logger.addHandler(file_handler)
            
        except Exception as e:
            print(f"Failed to setup file handler: {e}")
    
    def _setup_json_handler(self):
        """Setup JSON structured logging handler."""
        try:
            json_log_path = settings.LOG_FILE.replace(".log", "_structured.log") if settings.LOG_FILE else "logs/cems_structured.log"
            
            # Create log directory if it doesn't exist
            log_path = Path(json_log_path)
            log_path.parent.mkdir(parents=True, exist_ok=True)
            
            json_handler = logging.handlers.RotatingFileHandler(
                filename=json_log_path,
                maxBytes=settings.LOG_MAX_SIZE,
                backupCount=settings.LOG_BACKUP_COUNT,
                encoding="utf-8"
            )
            json_handler.setLevel(logging.INFO)
            json_formatter = CEMSFormatter(json_format=True)
            json_handler.setFormatter(json_formatter)
            self.logger.addHandler(json_handler)
            
        except Exception as e:
            print(f"Failed to setup JSON handler: {e}")
    
    def _log_with_context(
        self,
        level: int,
        message: str,
        extra_fields: Optional[Dict[str, Any]] = None,
        exc_info: bool = False
    ):
        """
        Log message with additional context.
        
        Args:
            level: Log level
            message: Log message
            extra_fields: Additional fields to include
            exc_info: Include exception information
        """
        record = self.logger.makeRecord(
            name=self.logger.name,
            level=level,
            fn="",
            lno=0,
            msg=message,
            args=(),
            exc_info=exc_info
        )
        
        if extra_fields:
            record.extra_fields = extra_fields
        
        self.logger.handle(record)
    
    def debug(self, message: str, **kwargs):
        """Log debug message."""
        self._log_with_context(logging.DEBUG, message, kwargs)
    
    def info(self, message: str, **kwargs):
        """Log info message."""
        self._log_with_context(logging.INFO, message, kwargs)
    
    def warning(self, message: str, **kwargs):
        """Log warning message."""
        self._log_with_context(logging.WARNING, message, kwargs)
    
    def error(self, message: str, exc_info: bool = False, **kwargs):
        """Log error message."""
        self._log_with_context(logging.ERROR, message, kwargs, exc_info=exc_info)
    
    def critical(self, message: str, exc_info: bool = False, **kwargs):
        """Log critical message."""
        self._log_with_context(logging.CRITICAL, message, kwargs, exc_info=exc_info)
    
    # Business-specific logging methods
    def log_transaction(
        self,
        transaction_id: str,
        transaction_type: str,
        amount: float,
        currency: str,
        user_id: str,
        status: str,
        **kwargs
    ):
        """
        Log transaction activity.
        
        Args:
            transaction_id: Transaction identifier
            transaction_type: Type of transaction
            amount: Transaction amount
            currency: Currency code
            user_id: User who performed transaction
            status: Transaction status
            **kwargs: Additional transaction details
        """
        self.info(
            f"Transaction {status}: {transaction_id}",
            transaction_id=transaction_id,
            transaction_type=transaction_type,
            amount=amount,
            currency=currency,
            user_id=user_id,
            status=status,
            **kwargs
        )
    
    def log_user_activity(
        self,
        user_id: str,
        action: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        **kwargs
    ):
        """
        Log user activity.
        
        Args:
            user_id: User identifier
            action: Action performed
            ip_address: User's IP address
            user_agent: User's browser/client info
            **kwargs: Additional activity details
        """
        self.info(
            f"User activity: {user_id} - {action}",
            user_id=user_id,
            action=action,
            ip_address=ip_address,
            user_agent=user_agent,
            **kwargs
        )
    
    def log_security_event(
        self,
        event_type: str,
        severity: str,
        description: str,
        user_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        **kwargs
    ):
        """
        Log security-related events.
        
        Args:
            event_type: Type of security event
            severity: Event severity (low, medium, high, critical)
            description: Event description
            user_id: Associated user ID
            ip_address: Source IP address
            **kwargs: Additional security details
        """
        log_method = self.warning if severity in ["low", "medium"] else self.error
        
        log_method(
            f"Security Event [{severity.upper()}]: {event_type} - {description}",
            event_type=event_type,
            severity=severity,
            user_id=user_id,
            ip_address=ip_address,
            **kwargs
        )
    
    def log_system_event(
        self,
        component: str,
        event: str,
        status: str,
        **kwargs
    ):
        """
        Log system events.
        
        Args:
            component: System component
            event: Event description
            status: Event status
            **kwargs: Additional system details
        """
        self.info(
            f"System Event [{component}]: {event} - {status}",
            component=component,
            event=event,
            status=status,
            **kwargs
        )
    
    def log_api_request(
        self,
        method: str,
        endpoint: str,
        status_code: int,
        response_time: float,
        user_id: Optional[str] = None,
        **kwargs
    ):
        """
        Log API requests.
        
        Args:
            method: HTTP method
            endpoint: API endpoint
            status_code: Response status code
            response_time: Request processing time
            user_id: Requesting user ID
            **kwargs: Additional request details
        """
        self.info(
            f"API Request: {method} {endpoint} - {status_code} ({response_time:.3f}s)",
            method=method,
            endpoint=endpoint,
            status_code=status_code,
            response_time=response_time,
            user_id=user_id,
            **kwargs
        )


def setup_logging() -> CEMSLogger:
    """
    Setup and return the main application logger.
    
    Returns:
        CEMSLogger: Configured logger instance
    """
    return CEMSLogger("cems")


def get_logger(name: str) -> CEMSLogger:
    """
    Get a logger instance for a specific module.
    
    Args:
        name: Logger name (usually module name)
        
    Returns:
        CEMSLogger: Logger instance
    """
    return CEMSLogger(name)


# Module-level logger for this file
logger = get_logger(__name__)


# Utility functions for common logging patterns
def log_function_entry(func_name: str, **kwargs):
    """Log function entry with parameters."""
    logger.debug(f"Entering function: {func_name}", function=func_name, **kwargs)


def log_function_exit(func_name: str, result: Any = None, **kwargs):
    """Log function exit with result."""
    logger.debug(f"Exiting function: {func_name}", function=func_name, result=str(result)[:100], **kwargs)


def log_performance(operation: str, duration: float, **kwargs):
    """Log performance metrics."""
    logger.info(f"Performance: {operation} completed in {duration:.3f}s", operation=operation, duration=duration, **kwargs)


def log_exception(exc: Exception, context: str = "", **kwargs):
    """Log exception with context."""
    logger.error(f"Exception in {context}: {str(exc)}", exc_info=True, context=context, exception_type=type(exc).__name__, **kwargs)