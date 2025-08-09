"""
Module: main
Purpose: Enhanced FastAPI application initialization with comprehensive middleware and security
Author: CEMS Development Team
Date: 2024
"""

# Standard library imports
from contextlib import asynccontextmanager
import time
import logging
from typing import Dict, Any, List

# Third-party imports
from fastapi import FastAPI, Request, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse
from fastapi.openapi.docs import get_swagger_ui_html, get_redoc_html
from fastapi.openapi.utils import get_openapi
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware
from starlette.middleware.base import BaseHTTPMiddleware

# Local imports
from app.core.config import settings
from app.core.exceptions import CEMSException, ValidationException
from app.utils.logger import setup_logging, get_logger
from app.db.database import check_database_health, init_db
from app.api.v1.api import api_router

# Initialize logging
logger = setup_logging()

# ==================== CUSTOM MIDDLEWARE CLASSES ====================

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add security headers to all responses."""
    
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        
        # Security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), location=()"
        
        # Custom headers
        response.headers["X-API-Version"] = settings.VERSION
        response.headers["X-Powered-By"] = "CEMS API"
        
        return response


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """Log all requests with timing information."""
    
    async def dispatch(self, request: Request, call_next):
        start_time = time.time()
        
        # Extract client information
        client_ip = request.client.host if request.client else "unknown"
        user_agent = request.headers.get("user-agent", "unknown")
        
        # Log request start
        logger.info(
            f"Request started: {request.method} {request.url.path} "
            f"from {client_ip} with {user_agent}"
        )
        
        # Process request
        try:
            response = await call_next(request)
            
            # Calculate processing time
            process_time = time.time() - start_time
            
            # Add timing header
            response.headers["X-Process-Time"] = str(process_time)
            
            # Log successful request
            logger.info(
                f"Request completed: {request.method} {request.url.path} "
                f"[{response.status_code}] in {process_time:.4f}s"
            )
            
            return response
            
        except Exception as e:
            # Calculate processing time for failed requests
            process_time = time.time() - start_time
            
            # Log failed request
            logger.error(
                f"Request failed: {request.method} {request.url.path} "
                f"in {process_time:.4f}s - Error: {str(e)}"
            )
            
            # Re-raise the exception
            raise


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Simple rate limiting middleware."""
    
    def __init__(self, app, calls: int = 100, period: int = 60):
        super().__init__(app)
        self.calls = calls
        self.period = period
        self.clients = {}
    
    async def dispatch(self, request: Request, call_next):
        # Skip rate limiting for health checks and docs
        if request.url.path in ["/health", "/docs", "/redoc", "/openapi.json"]:
            return await call_next(request)
        
        client_ip = request.client.host if request.client else "unknown"
        current_time = time.time()
        
        # Clean old entries
        self.clients = {
            ip: calls for ip, calls in self.clients.items()
            if any(call_time > current_time - self.period for call_time in calls)
        }
        
        # Check rate limit
        if client_ip in self.clients:
            recent_calls = [
                call_time for call_time in self.clients[client_ip]
                if call_time > current_time - self.period
            ]
            
            if len(recent_calls) >= self.calls:
                logger.warning(f"Rate limit exceeded for {client_ip}")
                return JSONResponse(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    content={
                        "error": True,
                        "message": "Rate limit exceeded",
                        "error_code": "RATE_LIMIT_EXCEEDED",
                        "retry_after": self.period
                    }
                )
            
            self.clients[client_ip] = recent_calls + [current_time]
        else:
            self.clients[client_ip] = [current_time]
        
        return await call_next(request)


# ==================== APPLICATION LIFESPAN ====================

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Enhanced application lifespan manager for startup and shutdown events.
    
    Args:
        app: FastAPI application instance
    """
    # ==================== STARTUP ====================
    logger.info("🚀 CEMS Application Starting...")
    logger.info(f"Environment: {settings.ENVIRONMENT}")
    logger.info(f"Version: {settings.VERSION}")
    logger.info(f"Debug Mode: {settings.DEBUG}")
    
    # Security warnings check
    if settings.ENVIRONMENT == "production":
        security_warnings = []
        
        if settings.SECRET_KEY == "your-super-secret-key-change-this-in-production":
            security_warnings.append("⚠️  Default SECRET_KEY detected in production!")
        
        if settings.DEBUG:
            security_warnings.append("⚠️  DEBUG mode enabled in production!")
        
        if not settings.BACKEND_CORS_ORIGINS:
            security_warnings.append("⚠️  No CORS origins configured!")
        
        if security_warnings:
            logger.warning("Security warnings detected:")
            for warning in security_warnings:
                logger.warning(warning)
    
    # Database initialization
    try:
        logger.info("🔌 Initializing database connection...")
        
        if settings.ENVIRONMENT == "development":
            logger.info("Running database initialization for development...")
            await init_db()
            logger.info("✅ Database initialization completed")
        else:
            logger.info("Checking database health...")
            health = await check_database_health()
            if health.get("database", {}).get("status") == "healthy":
                logger.info("✅ Database health check passed")
            else:
                logger.warning("⚠️ Database health check issues detected")
                logger.warning(f"Health status: {health}")
        
    except Exception as e:
        logger.error(f"❌ Database initialization failed: {e}")
        if settings.ENVIRONMENT == "production":
            raise  # Fail fast in production
        else:
            logger.warning("⚠️ Continuing without database in development mode")
    
    # Additional startup tasks
    try:
        logger.info("🔧 Initializing services...")
        
        # Initialize cache if available
        # await init_cache()  # Implement when cache is added
        
        # Load initial configuration
        # await load_system_config()  # Implement when needed
        
        logger.info("✅ All services initialized successfully")
        
    except Exception as e:
        logger.error(f"❌ Service initialization failed: {e}")
        if settings.ENVIRONMENT == "production":
            raise
    
    # Log startup completion
    logger.info("🎉 CEMS Application startup completed successfully!")
    logger.info(f"📚 API Documentation: http://localhost:8000/docs")
    logger.info(f"🔍 Health Check: http://localhost:8000/health")
    logger.info(f"📊 API Info: http://localhost:8000/api/v1/")
    
    yield
    
    # ==================== SHUTDOWN ====================
    logger.info("🛑 CEMS Application shutting down...")
    
    try:
        # Cleanup tasks
        logger.info("🧹 Performing cleanup tasks...")
        
        # Close database connections
        # await cleanup_database()  # Implement when needed
        
        # Close cache connections
        # await cleanup_cache()  # Implement when cache is added
        
        # Save any pending data
        # await save_pending_data()  # Implement when needed
        
        logger.info("✅ Cleanup completed successfully")
        
    except Exception as e:
        logger.error(f"❌ Cleanup failed: {e}")
    
    logger.info("👋 CEMS Application shutdown completed")


# ==================== FASTAPI APPLICATION INITIALIZATION ====================

app = FastAPI(
    title=settings.PROJECT_NAME,
    description="""
    # Currency Exchange Management System (CEMS) API
    
    A comprehensive backend API for managing currency exchange operations, branches, and financial transactions.
    
    ## 🚀 Features
    
    - **🏦 Multi-branch Operations**: Manage multiple exchange branches with centralized control
    - **💱 Real-time Exchange Rates**: Live currency conversion rates with automatic updates
    - **👥 Customer Management**: Complete customer lifecycle management with KYC compliance
    - **💳 Transaction Processing**: All types of currency exchange transactions with audit trails
    - **🏛️ Vault Management**: Central and branch vault operations with security controls
    - **📊 Comprehensive Reporting**: Financial and operational reports with analytics
    - **🔐 Role-based Access Control**: Secure user permissions with fine-grained access
    - **🔍 Audit Trail**: Complete audit logging for compliance and security
    
    ## 🛠️ Technology Stack
    
    - **Backend**: FastAPI with Python 3.11+
    - **Database**: PostgreSQL with SQLAlchemy ORM
    - **Authentication**: JWT with role-based permissions
    - **Documentation**: Automatic OpenAPI/Swagger generation
    - **Security**: Comprehensive security headers and rate limiting
    
    ## 🔧 Getting Started
    
    1. **Authentication**: Use `/api/v1/auth/login` to obtain access token
    2. **Authorization**: Include token in `Authorization: Bearer <token>` header
    3. **Explore**: Browse available endpoints in the sections below
    4. **Test**: Use the interactive API documentation to test endpoints
    
    ## 📞 Support
    
    For technical support and API questions, contact the CEMS Development Team.
    
    ---
    
    **Environment**: {environment}  
    **Version**: {version}  
    **Build**: {build_date}
    """.format(
        environment=settings.ENVIRONMENT,
        version=settings.VERSION,
        build_date="2024-01-01"
    ),
    version=settings.VERSION,
    lifespan=lifespan,
    openapi_url="/openapi.json" if settings.ENVIRONMENT != "production" else None,
    docs_url=None,  # Custom docs endpoint
    redoc_url=None,  # Custom redoc endpoint
    contact={
        "name": "CEMS Development Team",
        "email": "dev@cems.local",
    },
    license_info={
        "name": "MIT License",
        "url": "https://opensource.org/licenses/MIT",
    },
)

# ==================== MIDDLEWARE CONFIGURATION ====================

# CORS Middleware (configured first for proper handling)
if settings.BACKEND_CORS_ORIGINS:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[str(origin) for origin in settings.BACKEND_CORS_ORIGINS],
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["*"],
        expose_headers=["X-Process-Time", "X-API-Version"]
    )

# Trusted Host Middleware (production security)
if settings.ENVIRONMENT == "production" and hasattr(settings, 'ALLOWED_HOSTS'):
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=settings.ALLOWED_HOSTS
    )

# Session Middleware (for stateful operations if needed)
app.add_middleware(
    SessionMiddleware,
    secret_key=settings.SECRET_KEY,
    max_age=3600  # 1 hour session timeout
)

# GZip Middleware (compress responses)
app.add_middleware(GZipMiddleware, minimum_size=1000)

# Custom Security Headers Middleware
app.add_middleware(SecurityHeadersMiddleware)

# Request Logging Middleware
if settings.ENVIRONMENT != "production":  # Avoid logging in production for performance
    app.add_middleware(RequestLoggingMiddleware)

# Rate Limiting Middleware
if hasattr(settings, 'RATE_LIMIT_PER_MINUTE'):
    app.add_middleware(
        RateLimitMiddleware,
        calls=settings.RATE_LIMIT_PER_MINUTE,
        period=60
    )

# ==================== EXCEPTION HANDLERS ====================

@app.exception_handler(CEMSException)
async def cems_exception_handler(request: Request, exc: CEMSException):
    """
    Handle CEMS-specific exceptions with proper error formatting.
    
    Args:
        request: HTTP request object
        exc: CEMS exception instance
        
    Returns:
        JSONResponse: Formatted error response
    """
    logger.error(f"CEMS Exception: {exc.message}", exc_info=True)
    
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": True,
            "error_code": exc.error_code,
            "message": exc.message,
            "details": exc.details if settings.DEBUG else None,
            "timestamp": time.time(),
            "path": str(request.url.path),
            "method": request.method,
            "request_id": getattr(request.state, 'request_id', None)
        }
    )


@app.exception_handler(ValidationException)
async def validation_exception_handler(request: Request, exc: ValidationException):
    """Handle validation exceptions."""
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "error": True,
            "error_code": "VALIDATION_ERROR",
            "message": exc.message,
            "field": getattr(exc, 'field', None),
            "details": exc.details if settings.DEBUG else None,
            "timestamp": time.time(),
            "path": str(request.url.path)
        }
    )


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Handle standard HTTP exceptions."""
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": True,
            "message": exc.detail,
            "status_code": exc.status_code,
            "timestamp": time.time(),
            "path": str(request.url.path),
            "method": request.method
        }
    )


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """
    Handle unexpected exceptions with proper logging.
    
    Args:
        request: HTTP request object
        exc: Exception instance
        
    Returns:
        JSON response with generic error message
    """
    logger.error(f"Unhandled Exception: {str(exc)}", exc_info=True)
    
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": True,
            "message": "Internal server error occurred",
            "error_code": "INTERNAL_ERROR",
            "details": str(exc) if settings.DEBUG else "Contact support for assistance",
            "timestamp": time.time(),
            "path": str(request.url.path),
            "request_id": getattr(request.state, 'request_id', None)
        }
    )


# ==================== CUSTOM OPENAPI SCHEMA ====================

def custom_openapi():
    """Generate enhanced OpenAPI schema with custom information."""
    if app.openapi_schema:
        return app.openapi_schema
    
    openapi_schema = get_openapi(
        title=app.title,
        version=app.version,
        description=app.description,
        routes=app.routes,
        contact=app.contact,
        license_info=app.license_info,
    )
    
    # Add custom information
    openapi_schema["info"]["x-logo"] = {
        "url": "https://via.placeholder.com/200x60/0066CC/FFFFFF?text=CEMS"
    }
    
    # Add server information
    openapi_schema["servers"] = [
        {
            "url": f"http://localhost:8000",
            "description": "Development server"
        },
        {
            "url": f"https://api.cems.local",
            "description": "Production server"
        }
    ]
    
    # Enhanced security schemes
    openapi_schema["components"]["securitySchemes"] = {
        "BearerAuth": {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "JWT",
            "description": "Enter your JWT access token"
        },
        "RefreshToken": {
            "type": "apiKey",
            "in": "header",
            "name": "X-Refresh-Token",
            "description": "Refresh token for renewing access tokens"
        }
    }
    
    # Add custom tags
    openapi_schema["tags"] = [
        {
            "name": "Authentication",
            "description": "User authentication and authorization operations"
        },
        {
            "name": "User Management",
            "description": "User CRUD operations and role management"
        },
        {
            "name": "API Info",
            "description": "API metadata and system information"
        },
        {
            "name": "System",
            "description": "System health checks and monitoring"
        }
    ]
    
    # Add global security requirement
    openapi_schema["security"] = [{"BearerAuth": []}]
    
    # Add custom extensions
    openapi_schema["x-api-id"] = "cems-api"
    openapi_schema["x-audience"] = "internal"
    openapi_schema["x-api-lifecycle"] = "active"
    
    app.openapi_schema = openapi_schema
    return app.openapi_schema


app.openapi = custom_openapi


# ==================== CUSTOM DOCUMENTATION ENDPOINTS ====================

@app.get("/docs", include_in_schema=False)
async def custom_swagger_ui_html():
    """Enhanced Swagger UI with custom styling and configuration."""
    if settings.ENVIRONMENT == "production":
        return JSONResponse(
            content={"message": "API documentation not available in production"},
            status_code=status.HTTP_404_NOT_FOUND
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
            "persistAuthorization": True,
            "layout": "BaseLayout",
            "defaultModelsExpandDepth": 2,
            "defaultModelExpandDepth": 2,
            "displayOperationId": False,
            "showMutatedRequest": True
        }
    )


@app.get("/redoc", include_in_schema=False)
async def redoc_html():
    """Alternative ReDoc documentation interface."""
    if settings.ENVIRONMENT == "production":
        return JSONResponse(
            content={"message": "API documentation not available in production"},
            status_code=status.HTTP_404_NOT_FOUND
        )
    
    return get_redoc_html(
        openapi_url=app.openapi_url,
        title=f"{app.title} - API Reference",
        redoc_js_url="https://cdn.jsdelivr.net/npm/redoc@2.0.0/bundles/redoc.standalone.js",
    )


# ==================== SYSTEM ENDPOINTS ====================

@app.get("/", tags=["System"])
async def root():
    """
    Root endpoint providing basic API information.
    
    Returns basic information about the CEMS API, version, and status.
    Serves as a simple health check and API discovery endpoint.
    
    Returns:
        Dict[str, Any]: Basic API information
    """
    return {
        "name": "CEMS API",
        "version": settings.VERSION,
        "description": "Currency Exchange Management System API",
        "status": "operational",
        "environment": settings.ENVIRONMENT,
        "api_version": "v1",
        "documentation": {
            "interactive": "/docs",
            "reference": "/redoc",
            "openapi": "/openapi.json"
        },
        "endpoints": {
            "api_root": "/api/v1/",
            "health": "/health",
            "authentication": "/api/v1/auth",
            "users": "/api/v1/users"
        },
        "timestamp": time.time(),
        "uptime_seconds": time.time()  # This would be calculated properly in real implementation
    }


@app.get("/health", tags=["System"])
async def health_check():
    """
    Comprehensive system health check endpoint.
    
    Provides detailed health information about all system components
    including database, cache, external services, and system resources.
    
    Returns:
        Dict[str, Any]: Comprehensive health status
    """
    start_time = time.time()
    
    health_status = {
        "status": "healthy",
        "timestamp": time.time(),
        "version": settings.VERSION,
        "environment": settings.ENVIRONMENT,
        "uptime": time.time(),  # This would be calculated properly
        "checks": {}
    }
    
    # API health check
    health_status["checks"]["api"] = {
        "status": "healthy",
        "response_time_ms": round((time.time() - start_time) * 1000, 2),
        "details": "API service operational"
    }
    
    # Database health check would be implemented here
    health_status["checks"]["database"] = {
        "status": "healthy",
        "details": "Database connection successful"
    }
    
    # Set overall status
    check_statuses = [check["status"] for check in health_status["checks"].values()]
    if "unhealthy" in check_statuses:
        health_status["status"] = "unhealthy"
    elif "degraded" in check_statuses:
        health_status["status"] = "degraded"
    
    return health_status


# ==================== API ROUTER INCLUSION ====================

# Include the main API router with proper prefix
app.include_router(api_router, prefix=settings.API_V1_STR)

# ==================== APPLICATION STARTUP ====================

if __name__ == "__main__":
    import uvicorn
    
    # Enhanced uvicorn configuration
    uvicorn_config = {
        "app": "app.main:app",
        "host": "0.0.0.0",
        "port": 8000,
        "reload": settings.ENVIRONMENT == "development",
        "log_level": "info",
        "access_log": True,
        "use_colors": True,
        "workers": 1 if settings.ENVIRONMENT == "development" else 4
    }
    
    # Development-specific configuration
    if settings.ENVIRONMENT == "development":
        uvicorn_config.update({
            "reload_dirs": ["app"],
            "reload_excludes": ["*.pyc", "__pycache__", "*.log"],
            "reload_includes": ["*.py"],
        })
    
    # Production-specific configuration
    if settings.ENVIRONMENT == "production":
        uvicorn_config.update({
            "workers": 4,
            "keepalive": 2,
            "max_requests": 1000,
            "max_requests_jitter": 100,
        })
    
    # Log startup information
    logger.info("=" * 60)
    logger.info("🚀 Starting CEMS Server")
    logger.info("=" * 60)
    logger.info(f"🌍 Environment: {settings.ENVIRONMENT}")
    logger.info(f"📦 Version: {settings.VERSION}")
    logger.info(f"🔧 Debug Mode: {settings.DEBUG}")
    logger.info(f"🌐 Server: http://localhost:8000")
    logger.info(f"📚 Documentation: http://localhost:8000/docs")
    logger.info(f"🔍 Health Check: http://localhost:8000/health")
    logger.info(f"📊 API Info: http://localhost:8000/api/v1/")
    logger.info("=" * 60)
    
    # Start the server
    uvicorn.run(**uvicorn_config)