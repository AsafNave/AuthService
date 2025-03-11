.PHONY: run test lint migrate mocks clean

# Go commands
GOCMD=go
GOBUILD=$(GOCMD) build
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOCLEAN=$(GOCMD) clean
GOMOD=$(GOCMD) mod
GOWORK=$(GOCMD) work

# Binary names
BINARY_NAME=auth-service

# Build the application
build:
	$(GOBUILD) -o $(BINARY_NAME) ./cmd/api

# Run the application
run:
	$(GOCMD) run ./cmd/api

# Run tests
test:
	$(GOTEST) -v ./...

# Run linter
lint:
	golangci-lint run

# Run database migrations
migrate:
	migrate -path migrations -database "postgresql://${DB_USER}:${DB_PASSWORD}@${DB_HOST}:${DB_PORT}/${DB_NAME}?sslmode=disable" up

# Generate mocks
mocks:
	mockgen -source=internal/domain/repository.go -destination=internal/mocks/repository_mock.go

# Clean build files
clean:
	$(GOCLEAN)
	rm -f $(BINARY_NAME)

# Install dependencies
deps:
	$(GOGET) -u ./...

# Initialize the project
init:
	$(GOMOD) init auth-service
	$(GOMOD) tidy

# Format code
fmt:
	$(GOCMD) fmt ./... 