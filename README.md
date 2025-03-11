# Authentication Service - B2C

A secure and scalable authentication service built with Go, providing REST API endpoints for user authentication and authorization.

## Features

- User registration and login
- JWT-based authentication
- Password hashing with bcrypt
- PostgreSQL database integration
- Environment-based configuration
- Input validation
- Secure password policies
- Rate limiting
- Clean architecture principles

## Prerequisites

- Go 1.24 or higher
- PostgreSQL 14 or higher
- Make

## Getting Started

1. Clone the repository
2. Copy `.env.example` to `.env` and configure your environment variables
3. Run database migrations: `make migrate`
4. Start the service: `make run`

## Security Features

- Password hashing using bcrypt
- JWT token-based authentication
- Rate limiting to prevent brute force attacks
- Input validation and sanitization
- Secure password policies
- CORS configuration
- Request validation

## Development

- Run tests: `make test`
- Run linter: `make lint`
- Generate mocks: `make mocks`
- Run migrations: `make migrate`
- Start postgres on your local machine, based on env.example configuration: 

docker run --name auth-service-db \
  -e POSTGRES_USER=postgres \
  -e POSTGRES_PASSWORD=postgres \
  -e POSTGRES_DB=auth_service \
  -p 5432:5432 \
  -d postgres
