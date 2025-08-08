'''
Module: api
Purpose: Aggregates all v1 API routers into a single entry point
Author: CEMS Development Team
Date: 2024
'''

# Standard library imports

# Third-party imports
from fastapi import APIRouter

# Local imports
from app.api.v1.endpoints import auth, users

api_router = APIRouter(prefix="/api/v1")

api_router.include_router(auth.router)
api_router.include_router(users.router)

# To include later:
# from app.api.v1.endpoints import currencies, branches, transactions, vault, reports
# api_router.include_router(currencies.router)
# api_router.include_router(branches.router)
# api_router.include_router(transactions.router)
# api_router.include_router(vault.router)
# api_router.include_router(reports.router)
