# ===============================================
# CEMS - Currency Exchange Management System
# Enhanced Makefile for Project Management
# ===============================================

# ==================== VARIABLES ====================
SHELL := /bin/bash
PROJECT_NAME := cems
PYTHON := python3
PIP := pip3
DOCKER_COMPOSE := docker-compose
DOCKER_COMPOSE_DEV := docker-compose -f docker-compose.dev.yml
DOCKER_COMPOSE_PROD := docker-compose -f docker-compose.yml

# Colors for pretty output
CYAN := \033[36m
GREEN := \033[32m
YELLOW := \033[33m
RED := \033[31m
NC := \033[0m
BOLD := \033[1m

# Project directories
APP_DIR := app
TESTS_DIR := tests
DOCS_DIR := docs
SCRIPTS_DIR := scripts

# ==================== HELP TARGET ====================
.PHONY: help
help: ## Show this help message
	@echo -e "$(BOLD)$(CYAN)CEMS - Currency Exchange Management System$(NC)"
	@echo -e "$(BOLD)Available commands:$(NC)\n"
	@awk 'BEGIN {FS = ":.*##"} /^[a-zA-Z_-]+:.*##/ { printf "  $(CYAN)%-20s$(NC) %s\n", $$1, $$2 }' $(MAKEFILE_LIST)
	@echo ""
	@echo -e "$(BOLD)Examples:$(NC)"
	@echo -e "  make dev                     # Start development environment"
	@echo -e "  make test                    # Run all tests"
	@echo -e "  make docker-dev-up           # Start development with Docker"
	@echo -e "  make lint-fix                # Format and fix code"
	@echo -e "  make db-reset                # Reset database completely"

# ==================== DEVELOPMENT COMMANDS ====================
.PHONY: install
install: ## Install project dependencies
	@echo -e "$(CYAN)Installing project dependencies...$(NC)"
	$(PIP) install --upgrade pip
	$(PIP) install -r requirements.txt
	@echo -e "$(GREEN)Dependencies installed successfully!$(NC)"

.PHONY: install-dev
install-dev: ## Install development dependencies
	@echo -e "$(CYAN)Installing development dependencies...$(NC)"
	$(PIP) install --upgrade pip
	$(PIP) install -r requirements.txt
	$(PIP) install pre-commit
	pre-commit install
	@echo -e "$(GREEN)Development environment ready!$(NC)"

.PHONY: dev
dev: ## Start development server with hot reload
	@echo -e "$(CYAN)Starting development server...$(NC)"
	uvicorn app.main:app --reload --host 0.0.0.0 --port 8000 --log-level debug

.PHONY: dev-https
dev-https: ## Start development server with HTTPS
	@echo -e "$(CYAN)Starting development server with HTTPS...$(NC)"
	uvicorn app.main:app --reload --host 0.0.0.0 --port 8443 --ssl-keyfile=./certs/key.pem --ssl-certfile=./certs/cert.pem

.PHONY: shell
shell: ## Start interactive Python shell with app context
	@echo -e "$(CYAN)Starting Python shell...$(NC)"
	$(PYTHON) -c "from app.main import app; from app.db.database import get_db; print('App and database ready!')"
	$(PYTHON)

# ==================== TESTING COMMANDS ====================
.PHONY: test
test: ## Run all tests
	@echo -e "$(CYAN)Running all tests...$(NC)"
	pytest $(TESTS_DIR) -v --tb=short

.PHONY: test-cov
test-cov: ## Run tests with coverage report
	@echo -e "$(CYAN)Running tests with coverage...$(NC)"
	pytest $(TESTS_DIR) -v --cov=$(APP_DIR) --cov-report=html --cov-report=term-missing

.PHONY: test-unit
test-unit: ## Run unit tests only
	@echo -e "$(CYAN)Running unit tests...$(NC)"
	pytest $(TESTS_DIR)/test_services -v

.PHONY: test-integration
test-integration: ## Run integration tests only
	@echo -e "$(CYAN)Running integration tests...$(NC)"
	pytest $(TESTS_DIR)/test_endpoints -v

.PHONY: test-watch
test-watch: ## Run tests in watch mode
	@echo -e "$(CYAN)Starting test watcher...$(NC)"
	pytest-watch --runner "pytest -v"

# ==================== CODE QUALITY COMMANDS ====================
.PHONY: lint
lint: ## Run all linting tools
	@echo -e "$(CYAN)Running code quality checks...$(NC)"
	flake8 $(APP_DIR) $(TESTS_DIR)
	mypy $(APP_DIR)
	black --check $(APP_DIR) $(TESTS_DIR)
	isort --check-only $(APP_DIR) $(TESTS_DIR)

.PHONY: lint-fix
lint-fix: ## Fix code formatting and imports
	@echo -e "$(CYAN)Fixing code formatting...$(NC)"
	black $(APP_DIR) $(TESTS_DIR)
	isort $(APP_DIR) $(TESTS_DIR)
	@echo -e "$(GREEN)Code formatting completed!$(NC)"

.PHONY: type-check
type-check: ## Run type checking with mypy
	@echo -e "$(CYAN)Running type checks...$(NC)"
	mypy $(APP_DIR) --ignore-missing-imports

.PHONY: security-check
security-check: ## Run security checks
	@echo -e "$(CYAN)Running security checks...$(NC)"
	bandit -r $(APP_DIR) -f json -o security-report.json
	safety check
	@echo -e "$(GREEN)Security checks completed!$(NC)"

# ==================== DATABASE COMMANDS ====================
.PHONY: db-upgrade
db-upgrade: ## Run database migrations
	@echo -e "$(CYAN)Running database migrations...$(NC)"
	alembic upgrade head
	@echo -e "$(GREEN)Database migrations completed!$(NC)"

.PHONY: db-downgrade
db-downgrade: ## Downgrade database by one revision
	@echo -e "$(YELLOW)Downgrading database...$(NC)"
	alembic downgrade -1

.PHONY: db-reset
db-reset: ## Reset database completely (WARNING: Deletes all data)
	@echo -e "$(RED)WARNING: This will delete all database data!$(NC)"
	@read -p "Are you sure? (y/N): " confirm && [ "$$confirm" = "y" ]
	@echo -e "$(CYAN)Resetting database...$(NC)"
	$(PYTHON) -m app.db.init_db --reset
	@echo -e "$(GREEN)Database reset completed!$(NC)"

.PHONY: db-seed
db-seed: ## Seed database with initial data
	@echo -e "$(CYAN)Seeding database with initial data...$(NC)"
	$(PYTHON) -m app.db.init_db
	@echo -e "$(GREEN)Database seeding completed!$(NC)"

.PHONY: db-migrate
db-migrate: ## Create new database migration
	@echo -e "$(CYAN)Creating new migration...$(NC)"
	@read -p "Migration message: " message && alembic revision --autogenerate -m "$$message"

.PHONY: db-shell
db-shell: ## Connect to database shell
	@echo -e "$(CYAN)Connecting to database...$(NC)"
	psql $$DATABASE_URL

.PHONY: db-backup
db-backup: ## Create database backup
	@echo -e "$(CYAN)Creating database backup...$(NC)"
	mkdir -p backups
	pg_dump $$DATABASE_URL > backups/backup_$$(date +%Y%m%d_%H%M%S).sql
	@echo -e "$(GREEN)Database backup created!$(NC)"

# ==================== DOCKER COMMANDS ====================
.PHONY: docker-build
docker-build: ## Build Docker image
	@echo -e "$(CYAN)Building Docker image...$(NC)"
	docker build -t $(PROJECT_NAME):latest -f docker/Dockerfile .

.PHONY: docker-dev-up
docker-dev-up: ## Start development environment with Docker
	@echo -e "$(CYAN)Starting development environment...$(NC)"
	$(DOCKER_COMPOSE_DEV) up -d
	@echo -e "$(GREEN)Development environment started!$(NC)"
	@echo -e "$(YELLOW)Access the application at: http://localhost:8000$(NC)"
	@echo -e "$(YELLOW)Access pgAdmin at: http://localhost:5050$(NC)"

.PHONY: docker-dev-down
docker-dev-down: ## Stop development environment
	@echo -e "$(CYAN)Stopping development environment...$(NC)"
	$(DOCKER_COMPOSE_DEV) down

.PHONY: docker-dev-logs
docker-dev-logs: ## View development logs
	$(DOCKER_COMPOSE_DEV) logs -f

.PHONY: docker-dev-shell
docker-dev-shell: ## Access development container shell
	$(DOCKER_COMPOSE_DEV) exec app-dev bash

.PHONY: docker-prod-up
docker-prod-up: ## Start production environment
	@echo -e "$(CYAN)Starting production environment...$(NC)"
	$(DOCKER_COMPOSE_PROD) up -d
	@echo -e "$(GREEN)Production environment started!$(NC)"

.PHONY: docker-prod-down
docker-prod-down: ## Stop production environment
	@echo -e "$(CYAN)Stopping production environment...$(NC)"
	$(DOCKER_COMPOSE_PROD) down

.PHONY: docker-prod-logs
docker-prod-logs: ## View production logs
	$(DOCKER_COMPOSE_PROD) logs -f

.PHONY: docker-clean
docker-clean: ## Clean Docker resources
	@echo -e "$(CYAN)Cleaning Docker resources...$(NC)"
	docker system prune -f
	docker volume prune -f
	@echo -e "$(GREEN)Docker cleanup completed!$(NC)"

# ==================== MONITORING & ANALYSIS ====================
.PHONY: jupyter
jupyter: ## Start Jupyter notebook for data analysis
	@echo -e "$(CYAN)Starting Jupyter notebook...$(NC)"
	$(DOCKER_COMPOSE_DEV) --profile analysis up jupyter -d
	@echo -e "$(GREEN)Jupyter available at: http://localhost:8888$(NC)"

.PHONY: flower
flower: ## Start Celery Flower for task monitoring
	@echo -e "$(CYAN)Starting Celery Flower...$(NC)"
	$(DOCKER_COMPOSE_DEV) --profile worker up flower -d
	@echo -e "$(GREEN)Flower available at: http://localhost:5555$(NC)"

.PHONY: worker
worker: ## Start background worker services
	@echo -e "$(CYAN)Starting worker services...$(NC)"
	$(DOCKER_COMPOSE_DEV) --profile worker up -d

# ==================== DEPLOYMENT COMMANDS ====================
.PHONY: deploy-staging
deploy-staging: ## Deploy to staging environment
	@echo -e "$(CYAN)Deploying to staging...$(NC)"
	# Add your staging deployment commands here
	@echo -e "$(GREEN)Staging deployment completed!$(NC)"

.PHONY: deploy-prod
deploy-prod: ## Deploy to production environment
	@echo -e "$(CYAN)Deploying to production...$(NC)"
	# Add your production deployment commands here
	@echo -e "$(GREEN)Production deployment completed!$(NC)"

.PHONY: health-check
health-check: ## Check application health
	@echo -e "$(CYAN)Checking application health...$(NC)"
	curl -f http://localhost:8000/health || exit 1
	@echo -e "$(GREEN)Application is healthy!$(NC)"

# ==================== DOCUMENTATION COMMANDS ====================
.PHONY: docs
docs: ## Generate documentation
	@echo -e "$(CYAN)Generating documentation...$(NC)"
	mkdocs build
	@echo -e "$(GREEN)Documentation generated!$(NC)"

.PHONY: docs-serve
docs-serve: ## Serve documentation locally
	@echo -e "$(CYAN)Serving documentation...$(NC)"
	mkdocs serve -a 0.0.0.0:8001

.PHONY: docs-deploy
docs-deploy: ## Deploy documentation
	@echo -e "$(CYAN)Deploying documentation...$(NC)"
	mkdocs gh-deploy

# ==================== MAINTENANCE COMMANDS ====================
.PHONY: clean
clean: ## Clean cache files and temporary data
	@echo -e "$(CYAN)Cleaning cache files...$(NC)"
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	find . -type f -name "*.pyo" -delete
	find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
	rm -rf .pytest_cache
	rm -rf htmlcov
	rm -rf .coverage
	rm -rf .mypy_cache
	rm -rf dist
	rm -rf build
	@echo -e "$(GREEN)Cleanup completed!$(NC)"

.PHONY: update-deps
update-deps: ## Update all dependencies
	@echo -e "$(CYAN)Updating dependencies...$(NC)"
	$(PIP) list --outdated --format=freeze | grep -v '^\-e' | cut -d = -f 1 | xargs -n1 $(PIP) install -U
	$(PIP) freeze > requirements.txt
	@echo -e "$(GREEN)Dependencies updated!$(NC)"

.PHONY: check-security
check-security: ## Check for security vulnerabilities
	@echo -e "$(CYAN)Checking for security vulnerabilities...$(NC)"
	safety check
	bandit -r $(APP_DIR)
	@echo -e "$(GREEN)Security check completed!$(NC)"

# ==================== UTILITY COMMANDS ====================
.PHONY: env-check
env-check: ## Check environment setup
	@echo -e "$(CYAN)Checking environment setup...$(NC)"
	@echo "Python version: $$($(PYTHON) --version)"
	@echo "Pip version: $$($(PIP) --version)"
	@echo "Docker version: $$(docker --version)"
	@echo "Docker Compose version: $$(docker-compose --version)"
	@$(PYTHON) -c "import sys; print(f'Python executable: {sys.executable}')"
	@echo -e "$(GREEN)Environment check completed!$(NC)"

.PHONY: create-env
create-env: ## Create .env file from template
	@echo -e "$(CYAN)Creating .env file...$(NC)"
	@if [ ! -f .env ]; then \
		cp .env.example .env; \
		echo -e "$(GREEN).env file created from template!$(NC)"; \
		echo -e "$(YELLOW)Please edit .env file with your settings$(NC)"; \
	else \
		echo -e "$(YELLOW).env file already exists$(NC)"; \
	fi

.PHONY: init-project
init-project: create-env install-dev db-upgrade db-seed ## Initialize complete project setup
	@echo -e "$(GREEN)Project initialization completed!$(NC)"
	@echo -e "$(YELLOW)Next steps:$(NC)"
	@echo -e "  1. Edit .env file with your settings"
	@echo -e "  2. Run 'make dev' to start development server"
	@echo -e "  3. Access http://localhost:8000/docs for API documentation"

# ==================== CI/CD COMMANDS ====================
.PHONY: ci-test
ci-test: ## Run CI test suite
	@echo -e "$(CYAN)Running CI test suite...$(NC)"
	pytest $(TESTS_DIR) -v --tb=short --cov=$(APP_DIR) --cov-report=xml
	flake8 $(APP_DIR) $(TESTS_DIR)
	mypy $(APP_DIR)
	black --check $(APP_DIR) $(TESTS_DIR)
	isort --check-only $(APP_DIR) $(TESTS_DIR)

.PHONY: ci-build
ci-build: ## Build for CI/CD
	@echo -e "$(CYAN)Building for CI/CD...$(NC)"
	docker build -t $(PROJECT_NAME):$${CI_COMMIT_SHA:-latest} .

# Make help the default target
.DEFAULT_GOAL := help