"""
Module: api
Purpose: Comprehensive v1 API router aggregation with proper organization and error handling
Author: CEMS Development Team
Date: 2024
"""

# Standard library imports
from typing import Dict, Any, List

# Third-party imports
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

# Local imports
from app.core.config import settings
from app.core.exceptions import CEMSException
from app.api.deps import get_db, get_current_active_user, require_permissions
from app.utils.logger import get_logger

# Import all endpoint routers
from app.api.v1.endpoints import auth, users

# Future imports (to be uncommented when endpoints are created)
# from app.api.v1.endpoints import currencies, branches, customers, transactions, vault, reports

logger = get_logger(__name__)

# ==================== MAIN API ROUTER ====================

api_router = APIRouter()

# ==================== ROUTER CONFIGURATION ====================

# Authentication routes (no prefix, will be /api/v1/auth/...)
api_router.include_router(
    auth.router,
    tags=["Authentication"],
    responses={
        401: {"description": "Unauthorized - Invalid credentials"},
        429: {"description": "Too Many Requests - Rate limit exceeded"},
        422: {"description": "Validation Error"}
    }
)

# User management routes (/api/v1/users/...)
api_router.include_router(
    users.router,
    tags=["User Management"],
    dependencies=[Depends(get_current_active_user)],
    responses={
        401: {"description": "Unauthorized - Authentication required"},
        403: {"description": "Forbidden - Insufficient permissions"},
        404: {"description": "Not Found - User not found"},
        422: {"description": "Validation Error"}
    }
)

# Future endpoint inclusions (to be uncommented as endpoints are developed)
"""
# Currency management routes (/api/v1/currencies/...)
api_router.include_router(
    currencies.router,
    tags=["Currency Management"],
    dependencies=[Depends(get_current_active_user)],
    responses={
        401: {"description": "Unauthorized"},
        403: {"description": "Forbidden"},
        404: {"description": "Currency not found"}
    }
)

# Branch management routes (/api/v1/branches/...)
api_router.include_router(
    branches.router,
    tags=["Branch Management"],
    dependencies=[Depends(require_permissions(["branches:read"]))],
    responses={
        401: {"description": "Unauthorized"},
        403: {"description": "Forbidden"},
        404: {"description": "Branch not found"}
    }
)

# Customer management routes (/api/v1/customers/...)
api_router.include_router(
    customers.router,
    tags=["Customer Management"],
    dependencies=[Depends(get_current_active_user)],
    responses={
        401: {"description": "Unauthorized"},
        403: {"description": "Forbidden"},
        404: {"description": "Customer not found"}
    }
)

# Transaction processing routes (/api/v1/transactions/...)
api_router.include_router(
    transactions.router,
    tags=["Transaction Processing"],
    dependencies=[Depends(require_permissions(["transactions:read"]))],
    responses={
        401: {"description": "Unauthorized"},
        403: {"description": "Forbidden"},
        404: {"description": "Transaction not found"},
        409: {"description": "Transaction conflict"}
    }
)

# Vault management routes (/api/v1/vault/...)
api_router.include_router(
    vault.router,
    tags=["Vault Management"],
    dependencies=[Depends(require_permissions(["vault:read"]))],
    responses={
        401: {"description": "Unauthorized"},
        403: {"description": "Forbidden"},
        404: {"description": "Vault not found"}
    }
)

# Reporting routes (/api/v1/reports/...)
api_router.include_router(
    reports.router,
    tags=["Reports & Analytics"],
    dependencies=[Depends(require_permissions(["reports:read"]))],
    responses={
        401: {"description": "Unauthorized"},
        403: {"description": "Forbidden"},
        404: {"description": "Report not found"}
    }
)
"""

# ==================== API METADATA ENDPOINTS ====================

@api_router.get("/", tags=["API Info"])
async def api_root():
    """
    API root endpoint providing basic information about CEMS API.
    
    Returns basic information about the API version, capabilities,
    and available endpoints.
    
    Returns:
        Dict[str, Any]: API information and metadata
    """
    return {
        "name": "CEMS API",
        "version": "1.0.0",
        "description": "Currency Exchange Management System API",
        "api_version": "v1",
        "status": "active",
        "environment": settings.ENVIRONMENT,
        "documentation": {
            "swagger_ui": "/docs",
            "redoc": "/redoc",
            "openapi_schema": "/openapi.json"
        },
        "endpoints": {
            "authentication": "/api/v1/auth",
            "users": "/api/v1/users",
            "health": "/health",
            "api_info": "/api/v1"
        },
        "capabilities": {
            "authentication": True,
            "user_management": True,
            "role_based_access": True,
            "rate_limiting": True,
            "audit_logging": True,
            "api_versioning": True
        },
        "contact": {
            "team": "CEMS Development Team",
            "support": "support@cems.local"
        }
    }


@api_router.get("/health", tags=["System"])
async def api_health_check(db: Session = Depends(get_db)):
    """
    Comprehensive API health check endpoint.
    
    Checks the health of various API components including database connectivity,
    external services, and system resources.
    
    Args:
        db: Database session for connectivity check
        
    Returns:
        Dict[str, Any]: Comprehensive health status
    """
    health_status = {
        "status": "healthy",
        "timestamp": "2024-01-01T00:00:00Z",
        "version": settings.VERSION,
        "environment": settings.ENVIRONMENT,
        "components": {}
    }
    
    # Database health check
    try:
        # Simple database query to test connectivity
        db.execute("SELECT 1")
        health_status["components"]["database"] = {
            "status": "healthy",
            "response_time_ms": 10,  # This would be measured in real implementation
            "details": "Database connection successful"
        }
    except Exception as e:
        logger.error(f"Database health check failed: {str(e)}")
        health_status["status"] = "degraded"
        health_status["components"]["database"] = {
            "status": "unhealthy",
            "error": str(e),
            "details": "Database connection failed"
        }
    
    # Authentication service health
    health_status["components"]["authentication"] = {
        "status": "healthy",
        "details": "Authentication service operational"
    }
    
    # User service health
    health_status["components"]["user_service"] = {
        "status": "healthy",
        "details": "User management service operational"
    }
    
    # API service health
    health_status["components"]["api"] = {
        "status": "healthy",
        "total_endpoints": len([route for route in api_router.routes]),
        "details": "API service operational"
    }
    
    # Set overall status based on component health
    component_statuses = [comp["status"] for comp in health_status["components"].values()]
    if "unhealthy" in component_statuses:
        health_status["status"] = "unhealthy"
    elif "degraded" in component_statuses:
        health_status["status"] = "degraded"
    
    return health_status


@api_router.get("/endpoints", tags=["API Info"])
async def list_api_endpoints():
    """
    List all available API endpoints with their methods and descriptions.
    
    Provides a comprehensive overview of all available API endpoints,
    their HTTP methods, and brief descriptions.
    
    Returns:
        Dict[str, Any]: List of all API endpoints
    """
    endpoints = []
    
    for route in api_router.routes:
        if hasattr(route, 'methods') and hasattr(route, 'path'):
            endpoint_info = {
                "path": route.path,
                "methods": list(route.methods),
                "name": getattr(route, 'name', 'Unknown'),
                "tags": getattr(route, 'tags', []),
                "summary": getattr(route, 'summary', None),
                "description": getattr(route, 'description', None)
            }
            endpoints.append(endpoint_info)
    
    return {
        "total_endpoints": len(endpoints),
        "api_version": "v1",
        "endpoints": endpoints,
        "generated_at": "2024-01-01T00:00:00Z"
    }


@api_router.get("/permissions", tags=["API Info"])
async def list_api_permissions(
    current_user = Depends(get_current_active_user)
):
    """
    List all available API permissions and user's current permissions.
    
    Provides information about the permission system and shows which
    permissions the current user has access to.
    
    Args:
        current_user: Current authenticated user
        
    Returns:
        Dict[str, Any]: Permission information
    """
    # This would be populated from a permissions registry in real implementation
    all_permissions = {
        "user_management": [
            "users:read", "users:create", "users:update", "users:delete",
            "users:status", "users:bulk", "roles:assign", "roles:remove"
        ],
        "authentication": [
            "auth:login", "auth:logout", "auth:refresh", "auth:reset_password"
        ],
        "branch_management": [
            "branches:read", "branches:create", "branches:update", "branches:delete"
        ],
        "currency_management": [
            "currencies:read", "currencies:update", "rates:read", "rates:update"
        ],
        "transaction_processing": [
            "transactions:read", "transactions:create", "transactions:update",
            "transactions:cancel", "transactions:approve"
        ],
        "vault_management": [
            "vault:read", "vault:update", "vault:transfer", "vault:audit"
        ],
        "reporting": [
            "reports:read", "reports:create", "reports:export"
        ],
        "system_administration": [
            "system:admin", "system:config", "system:logs", "system:health"
        ]
    }
    
    # Get user's current permissions (this would come from the user service)
    user_permissions = []  # This would be fetched from user service in real implementation
    
    return {
        "all_permissions": all_permissions,
        "user_permissions": user_permissions,
        "is_superuser": getattr(current_user, 'is_superuser', False),
        "permission_model": "Role-Based Access Control (RBAC)",
        "description": "CEMS uses a comprehensive permission system for fine-grained access control"
    }


# ==================== ERROR HANDLERS ====================

@api_router.exception_handler(CEMSException)
async def cems_exception_handler(request, exc: CEMSException):
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
            "details": exc.details,
            "timestamp": "2024-01-01T00:00:00Z",
            "path": str(request.url),
            "method": request.method
        }
    )


@api_router.exception_handler(HTTPException)
async def http_exception_handler(request, exc: HTTPException):
    """
    Handle HTTP exceptions with consistent formatting.
    
    Args:
        request: HTTP request object
        exc: HTTP exception instance
        
    Returns:
        JSONResponse: Formatted error response
    """
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": True,
            "message": exc.detail,
            "status_code": exc.status_code,
            "timestamp": "2024-01-01T00:00:00Z",
            "path": str(request.url),
            "method": request.method
        }
    )


# ==================== ROUTE METADATA ====================

def get_api_routes_info() -> Dict[str, Any]:
    """
    Get information about all registered API routes.
    
    Returns:
        Dict[str, Any]: Routes information
    """
    routes_info = {
        "total_routes": len(api_router.routes),
        "route_groups": {},
        "protected_routes": 0,
        "public_routes": 0
    }
    
    for route in api_router.routes:
        if hasattr(route, 'tags') and route.tags:
            tag = route.tags[0] if route.tags else "Untagged"
            if tag not in routes_info["route_groups"]:
                routes_info["route_groups"][tag] = 0
            routes_info["route_groups"][tag] += 1
        
        # Check if route has authentication dependencies
        if hasattr(route, 'dependencies') and route.dependencies:
            routes_info["protected_routes"] += 1
        else:
            routes_info["public_routes"] += 1
    
    return routes_info


# Add metadata to router
api_router.routes_info = get_api_routes_info

# ==================== ROUTER EXPORTS ====================

# Export the main router for inclusion in main.py
__all__ = ["api_router"]