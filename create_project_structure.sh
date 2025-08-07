#!/bin/bash

"""
Script: create_project_structure.sh
Purpose: Create complete CEMS project directory structure
Author: CEMS Development Team
Date: 2024
"""

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}Creating Currency Exchange Management System (CEMS) Project Structure...${NC}"

# Create main project directory
#PROJECT_DIR="currency-exchange-system"
PROJECT_DIR="CEMS"
#mkdir -p $PROJECT_DIR
#cd $PROJECT_DIR

# Create app directory structure
echo -e "${GREEN}Creating app directories...${NC}"
mkdir -p app/{api/v1/endpoints,core,db/models,schemas,services,repositories,utils}

# Create API files
touch app/__init__.py
touch app/main.py
touch app/api/__init__.py
touch app/api/deps.py
touch app/api/v1/__init__.py
touch app/api/v1/api.py

# Create endpoint files
touch app/api/v1/endpoints/__init__.py
touch app/api/v1/endpoints/auth.py
touch app/api/v1/endpoints/users.py
touch app/api/v1/endpoints/currencies.py
touch app/api/v1/endpoints/branches.py
touch app/api/v1/endpoints/customers.py
touch app/api/v1/endpoints/transactions.py
touch app/api/v1/endpoints/vault.py
touch app/api/v1/endpoints/reports.py

# Create core files
echo -e "${GREEN}Creating core files...${NC}"
touch app/core/__init__.py
touch app/core/config.py
touch app/core/security.py
touch app/core/constants.py
touch app/core/exceptions.py

# Create database files
echo -e "${GREEN}Creating database files...${NC}"
touch app/db/__init__.py
touch app/db/base.py
touch app/db/database.py
touch app/db/init_db.py

# Create model files
touch app/db/models/__init__.py
touch app/db/models/user.py
touch app/db/models/currency.py
touch app/db/models/branch.py
touch app/db/models/customer.py
touch app/db/models/transaction.py
touch app/db/models/vault.py

# Create schema files
echo -e "${GREEN}Creating schema files...${NC}"
touch app/schemas/__init__.py
touch app/schemas/base.py
touch app/schemas/user.py
touch app/schemas/auth.py
touch app/schemas/currency.py
touch app/schemas/branch.py
touch app/schemas/customer.py
touch app/schemas/transaction.py
touch app/schemas/vault.py
touch app/schemas/report.py

# Create service files
echo -e "${GREEN}Creating service files...${NC}"
touch app/services/__init__.py
touch app/services/auth_service.py
touch app/services/user_service.py
touch app/services/currency_service.py
touch app/services/branch_service.py
touch app/services/customer_service.py
touch app/services/transaction_service.py
touch app/services/vault_service.py
touch app/services/report_service.py

# Create repository files
echo -e "${GREEN}Creating repository files...${NC}"
touch app/repositories/__init__.py
touch app/repositories/base.py
touch app/repositories/user_repository.py
touch app/repositories/currency_repository.py
touch app/repositories/branch_repository.py
touch app/repositories/customer_repository.py
touch app/repositories/transaction_repository.py
touch app/repositories/vault_repository.py

# Create utils files
echo -e "${GREEN}Creating utils files...${NC}"
touch app/utils/__init__.py
touch app/utils/validators.py
touch app/utils/formatters.py
touch app/utils/generators.py
touch app/utils/logger.py

# Create alembic directory structure
echo -e "${GREEN}Creating alembic structure...${NC}"
mkdir -p alembic/versions
touch alembic/alembic.ini
touch alembic/env.py
touch alembic/script.py.mako

# Create tests directory structure
echo -e "${GREEN}Creating tests structure...${NC}"
mkdir -p tests/{test_endpoints,test_services,test_repositories}
touch tests/__init__.py
touch tests/conftest.py
touch tests/test_endpoints/__init__.py
touch tests/test_services/__init__.py
touch tests/test_repositories/__init__.py

# Create docker directory structure
echo -e "${GREEN}Creating docker structure...${NC}"
mkdir -p docker/postgres
touch docker/Dockerfile
touch docker/postgres/init.sql

# Create root level files
echo -e "${GREEN}Creating root level files...${NC}"
touch .env.example
touch .gitignore
touch docker-compose.yml
touch docker-compose.dev.yml
touch requirements.txt
touch requirements-dev.txt
touch README.md
touch Makefile

# Add basic content to .gitignore
cat > .gitignore << 'EOF'
# Python
__pycache__/
*.py[cod]
*$py.class
*.so
.Python
env/
venv/
ENV/
.venv
*.egg-info/
dist/
build/

# IDE
.vscode/
.idea/
*.swp
*.swo
*~

# Environment
.env
.env.local

# Database
*.db
*.sqlite3

# Logs
*.log
logs/

# Testing
.coverage
htmlcov/
.pytest_cache/
.tox/

# OS
.DS_Store
Thumbs.db
EOF

# Add basic content to .env.example
cat > .env.example << 'EOF'
# Application
APP_NAME=CEMS
APP_VERSION=1.0.0
DEBUG=False
API_V1_STR=/api/v1

# Security
SECRET_KEY=your-secret-key-here-change-in-production
ACCESS_TOKEN_EXPIRE_MINUTES=30
ALGORITHM=HS256

# Database
DATABASE_URL=postgresql://cems_user:cems_password@localhost:5432/cems_db

# PostgreSQL
POSTGRES_SERVER=localhost
POSTGRES_USER=cems_user
POSTGRES_PASSWORD=cems_password
POSTGRES_DB=cems_db
POSTGRES_PORT=5432

# First User (Admin)
FIRST_SUPERUSER=admin@cems.com
FIRST_SUPERUSER_PASSWORD=changeme

# CORS
BACKEND_CORS_ORIGINS=["http://localhost:3000","http://localhost:8000"]
EOF

# Add basic content to README.md
cat > README.md << 'EOF'
# Currency Exchange Management System (CEMS)

A comprehensive backend API for managing currency exchange operations, branches, and financial transactions.

## Features

- Multi-branch currency exchange management
- Real-time exchange rate tracking
- Customer management
- Financial transaction processing
- Comprehensive reporting
- Role-based access control (RBAC)
- Main vault management

## Tech Stack

- **Backend**: FastAPI (Python 3.11+)
- **Database**: PostgreSQL
- **ORM**: SQLAlchemy
- **Migration**: Alembic
- **Authentication**: JWT
- **Documentation**: Swagger/OpenAPI
- **Deployment**: Docker & Docker Compose

## Quick Start

1. Clone the repository
2. Copy `.env.example` to `.env` and update values
3. Run with Docker Compose:
   ```bash
   docker-compose up -d
   ```
4. Access API documentation at: http://localhost:8000/docs

## Development

```bash
# Install dependencies
pip install -r requirements.txt

# Run migrations
alembic upgrade head

# Start development server
uvicorn app.main:app --reload
```

## Project Structure

See project documentation for detailed structure.

## License

 2024 CEMS Development Team
EOF

# Add basic Makefile
cat > Makefile << 'EOF'
.PHONY: help dev test migrate seed docker-up docker-down docker-logs clean

help:
	@echo "Available commands:"
	@echo "  make dev         - Start development server"
	@echo "  make test        - Run tests"
	@echo "  make migrate     - Run database migrations"
	@echo "  make seed        - Seed initial data"
	@echo "  make docker-up   - Start Docker containers"
	@echo "  make docker-down - Stop Docker containers"
	@echo "  make docker-logs - View Docker logs"
	@echo "  make clean       - Clean cache files"

dev:
	uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

test:
	pytest tests/ -v --cov=app --cov-report=html

migrate:
	alembic upgrade head

seed:
	python -m app.db.init_db

docker-up:
	docker-compose up -d

docker-down:
	docker-compose down

docker-logs:
	docker-compose logs -f

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	rm -rf .pytest_cache
	rm -rf htmlcov
	rm -rf .coverage
EOF

echo -e "${BLUE} Project structure created successfully!${NC}"
echo -e "${GREEN}Total directories created: $(find . -type d | wc -l)${NC}"
echo -e "${GREEN}Total files created: $(find . -type f | wc -l)${NC}"
echo ""
echo -e "${BLUE}Next steps:${NC}"
echo "1. cd $PROJECT_DIR"
echo "2. Copy .env.example to .env and update values"
echo "3. Install dependencies: pip install -r requirements.txt"
echo "4. Start development: make dev"
