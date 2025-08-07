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
