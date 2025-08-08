"""
Module: main
Purpose: FastAPI application initialization and configuration for CEMS
Author: CEMS Development Team
Date: 2024
"""

from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.openapi.utils import get_openapi

import time
import logging

from app.core.config import settings
from app.core.exceptions import CEMSException
from app.utils.logger import setup_logging
from app.db import check_database_health, init_db
from app.api.v1.api import api_router

# Setup logging
logger = setup_logging()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan manager for startup and shutdown events.
    
    Args:
        app: FastAPI application instance
    """
    # Startup
    logger.info("🚀 CEMS Application Starting...")
    logger.info(f"Environment: {settings.ENVIRONMENT}")
    logger.info(f"Version: {settings.VERSION}")
    
    # Database initialization
    try:
        if settings.ENVIRONMENT == "development":
            logger.info("Initializing database for development...")
            init_db()
            logger.info("✅ Database initialization completed")
        else:
            logger.info("Checking database health...")
            health = await check_database_health()
            if health["database"]["status"] == "healthy":
                logger.info("✅ Database health check passed")
            else:
                logger.warning("⚠️ Database health check issues detected")
    except Exception as e:
        logger.error(f"❌ Database initialization failed: {e}")
    
    yield
    
    # Shutdown
    logger.info("🛑 CEMS Application Shutting Down...")


# FastAPI app initialization
app = FastAPI(
    title=settings.PROJECT_NAME,
    description="""
    # Currency Exchange Management System (CEMS)
    
    A comprehensive backend API for managing currency exchange operations, branches, and financial transactions.
    
    ## Features
    
    - **Multi-branch Operations**: Manage multiple exchange branches
    - **Real-time Exchange Rates**: Live currency conversion rates
    - **Customer Management**: Complete customer lifecycle management
    - **Transaction Processing**: All types of currency exchange transactions
    - **Vault Management**: Central and branch vault operations
    - **Comprehensive Reporting**: Financial and operational reports
    - **Role-based Access Control**: Secure user permissions
    
    ## Getting Started
    
    1. **Authentication**: Use `/api/v1/auth/login` to obtain access token
    2. **Explore**: Browse available endpoints below
    3. **Test**: Use the interactive API documentation
    
    ## Support
    
    For technical support, contact the CEMS Development Team.
    """,
    version=settings.VERSION,
    openapi_url=f"{settings.API_V1_STR}/openapi.json" if settings.ENVIRONMENT != "production" else None,
    docs_url=None,  # We'll create custom docs
    redoc_url=None,  # We'll create custom redoc
    lifespan=lifespan,
    contact={
        "name": "CEMS Development Team",
        "email": "dev@cems.com",
    },
    license_info={
        "name": "CEMS License",
        "identifier": "Proprietary",
    },
)

# CORS middleware
if settings.BACKEND_CORS_ORIGINS:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[str(origin) for origin in settings.BACKEND_CORS_ORIGINS],
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
        allow_headers=["*"],
    )

# Trusted hosts middleware for production
if settings.ENVIRONMENT == "production":
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=settings.ALLOWED_HOSTS
    )


# Request timing middleware
@app.middleware("http")
async def add_process_time_header(request: Request, call_next):
    """
    Add processing time header to all responses.
    
    Args:
        request: HTTP request object
        call_next: Next middleware in chain
        
    Returns:
        Response with X-Process-Time header
    """
    start_time = time.time()
    response = await call_next(request)
    process_time = time.time() - start_time
    response.headers["X-Process-Time"] = str(process_time)
    response.headers["X-API-Version"] = settings.VERSION
    return response


# Global exception handler
@app.exception_handler(CEMSException)
async def cems_exception_handler(request: Request, exc: CEMSException):
    """
    Global exception handler for CEMS custom exceptions.
    
    Args:
        request: HTTP request object
        exc: CEMS exception instance
        
    Returns:
        JSON response with error details
    """
    logger.error(f"CEMS Exception: {exc.message} - Details: {exc.details}")
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": True,
            "message": exc.message,
            "error_code": exc.error_code,
            "details": exc.details,
            "timestamp": time.time(),
            "path": str(request.url)
        }
    )


# Generic exception handler
@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    """
    Generic exception handler for unhandled exceptions.
    
    Args:
        request: HTTP request object
        exc: Exception instance
        
    Returns:
        JSON response with generic error message
    """
    logger.error(f"Unhandled Exception: {str(exc)}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={
            "error": True,
            "message": "Internal server error occurred",
            "error_code": "INTERNAL_ERROR",
            "details": str(exc) if settings.ENVIRONMENT != "production" else None,
            "timestamp": time.time(),
            "path": str(request.url)
        }
    )


# Custom OpenAPI schema
def custom_openapi():
    """Generate custom OpenAPI schema with enhanced information."""
    if app.openapi_schema:
        return app.openapi_schema
    
    openapi_schema = get_openapi(
        title=app.title,
        version=app.version,
        description=app.description,
        routes=app.routes,
    )
    
    # Add custom information
    openapi_schema["info"]["x-logo"] = {
        "url": "https://via.placeholder.com/120x40?text=CEMS"
    }
    
    # Add security schemes
    openapi_schema["components"]["securitySchemes"] = {
        "BearerAuth": {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "JWT",
            "description": "Enter your JWT token"
        }
    }
    
    # Add global security requirement
    openapi_schema["security"] = [{"BearerAuth": []}]
    
    app.openapi_schema = openapi_schema
    return app.openapi_schema


app.openapi = custom_openapi


# Custom documentation endpoints
@app.get("/docs", include_in_schema=False)
async def custom_swagger_ui_html():
    """Custom Swagger UI with enhanced styling."""
    if settings.ENVIRONMENT == "production":
        return JSONResponse(
            content={"message": "API documentation not available in production"},
            status_code=404
        )
    
    return get_swagger_ui_html(
        openapi_url=app.openapi_url,
        title=f"{app.title} - Interactive API Documentation",
        oauth2_redirect_url=app.swagger_ui_oauth2_redirect_url,
        swagger_js_url="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js",
        swagger_css_url="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui.css",
        swagger_ui_parameters={
            "deepLinking": True,
            "displayRequestDuration": True,
            "docExpansion": "none",
            "operationsSorter": "method",
            "filter": True,
            "showExtensions": True,
            "showCommonExtensions": True,
            "tryItOutEnabled": True,
        }
    )


# Health check endpoint
@app.get("/health", tags=["System"])
async def health_check():
    """
    Health check endpoint for monitoring and load balancers.
    
    Returns:
        dict: Health status information
    """
    # Get database health
    db_health = await check_database_health()
    
    # Overall health status
    overall_healthy = (
        db_health.get("database", {}).get("status") == "healthy"
    )
    
    return {
        "status": "healthy" if overall_healthy else "unhealthy",
        "timestamp": time.time(),
        "version": settings.VERSION,
        "environment": settings.ENVIRONMENT,
        "service": settings.PROJECT_NAME,
        "components": {
            "database": db_health.get("database", {}),
            "api": {"status": "healthy"},
        },
        "uptime": "unknown"  # Would implement actual uptime tracking
    }


# Readiness probe
@app.get("/ready", tags=["System"])
async def readiness_check():
    """
    Readiness check endpoint for Kubernetes deployments.
    
    Returns:
        dict: Readiness status
    """
    try:
        # Check critical dependencies
        db_health = await check_database_health()
        
        if db_health.get("database", {}).get("status") == "healthy":
            return {
                "status": "ready",
                "timestamp": time.time(),
                "checks": {
                    "database": "ready"
                }
            }
        else:
            return JSONResponse(
                status_code=503,
                content={
                    "status": "not_ready",
                    "timestamp": time.time(),
                    "checks": {
                        "database": "not_ready"
                    }
                }
            )
    except Exception as e:
        logger.error(f"Readiness check failed: {e}")
        return JSONResponse(
            status_code=503,
            content={
                "status": "not_ready",
                "timestamp": time.time(),
                "error": str(e)
            }
        )


# Liveness probe
@app.get("/live", tags=["System"])
async def liveness_check():
    """
    Liveness check endpoint for Kubernetes deployments.
    
    Returns:
        dict: Liveness status
    """
    return {
        "status": "alive",
        "timestamp": time.time(),
        "version": settings.VERSION
    }


# Root endpoint
@app.get("/", tags=["System"])
async def root():
    """
    Root endpoint with basic application information.
    
    Returns:
        dict: Application welcome message and information
    """
    return {
        "message": f"Welcome to {settings.PROJECT_NAME}",
        "version": settings.VERSION,
        "environment": settings.ENVIRONMENT,
        "documentation": {
            "interactive_docs": "/docs" if settings.ENVIRONMENT != "production" else None,
            "openapi_schema": f"{settings.API_V1_STR}/openapi.json" if settings.ENVIRONMENT != "production" else None
        },
        "endpoints": {
            "health": "/health",
            "ready": "/ready", 
            "live": "/live",
            "api": settings.API_V1_STR
        },
        "features": [
            "Multi-branch currency exchange management",
            "Real-time exchange rate tracking", 
            "Customer management",
            "Financial transaction processing",
            "Comprehensive reporting",
            "Role-based access control",
            "Main vault management"
        ],
        "status": "operational"
    }


# Metrics endpoint (for monitoring)
@app.get("/metrics", tags=["System"])
async def metrics():
    """
    Metrics endpoint for monitoring systems.
    
    Returns:
        dict: Basic application metrics
    """
    if settings.ENVIRONMENT == "production":
        return JSONResponse(
            content={"message": "Metrics endpoint not available in production"},
            status_code=404
        )
    
    # In production, this would return Prometheus-style metrics
    return {
        "timestamp": time.time(),
        "application": {
            "name": settings.PROJECT_NAME,
            "version": settings.VERSION,
            "environment": settings.ENVIRONMENT
        },
        "system": {
            "uptime": "unknown",
            "memory_usage": "unknown",
            "cpu_usage": "unknown"
        },
        "database": {
            "connections": "unknown",
            "queries_per_second": "unknown"
        }
    }


# API Info endpoint
@app.get(f"{settings.API_V1_STR}/info", tags=["System"])
async def api_info():
    """
    API information endpoint.
    
    Returns:
        dict: API version and capabilities
    """
    return {
        "api_version": "v1",
        "application_version": settings.VERSION,
        "environment": settings.ENVIRONMENT,
        "capabilities": {
            "authentication": True,
            "user_management": True,
            "branch_management": True,
            "currency_exchange": True,
            "customer_management": True,
            "transaction_processing": True,
            "vault_management": True,
            "reporting": True,
            "audit_trail": True
        },
        "rate_limits": {
            "requests_per_minute": settings.RATE_LIMIT_PER_MINUTE,
            "burst_requests": settings.RATE_LIMIT_BURST
        },
        "supported_currencies": [
            "USD", "EUR", "GBP", "SAR", "AED", "EGP", 
            "JOD", "KWD", "QAR", "BHD", "TRY", "JPY", "CHF", "CAD", "AUD"
        ]
    }


# Include API routers (placeholder for future implementation)
# When API endpoints are implemented, they will be included here:
# from app.api.v1.api import api_router
# app.include_router(api_router, prefix=settings.API_V1_STR)

# في أسفل الملف، تحت قسم Include API routers
app.include_router(api_router, prefix=settings.API_V1_STR)

if __name__ == "__main__":
    import uvicorn
    
    # Configuration for development server
    uvicorn_config = {
        "app": "app.main:app",
        "host": "0.0.0.0",
        "port": 8000,
        "reload": settings.ENVIRONMENT == "development",
        "log_level": "info",
        "access_log": True,
        "use_colors": True,
    }
    
    # Additional configuration for development
    if settings.ENVIRONMENT == "development":
        uvicorn_config.update({
            "reload_dirs": ["app"],
            "reload_excludes": ["*.pyc", "__pycache__"],
        })
    
    logger.info(f"Starting CEMS server on http://localhost:8000")
    logger.info(f"Environment: {settings.ENVIRONMENT}")
    logger.info(f"Documentation: http://localhost:8000/docs")
    
    uvicorn.run(**uvicorn_config)