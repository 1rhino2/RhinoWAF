# Makefile for RhinoWAF

.PHONY: lint test build clean install-tools

# install linting tools
install-tools:
	@echo "Installing golangci-lint..."
	@go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	@echo "Installing gosec..."
	@go install github.com/securego/gosec/v2/cmd/gosec@latest
	@echo "Done"

# run all linters
lint:
	@echo "Running golangci-lint..."
	@golangci-lint run --timeout=5m
	@echo "Running gosec..."
	@gosec -exclude=G104 ./...

# quick lint (faster checks only)
lint-fast:
	@golangci-lint run --fast

# fix auto-fixable issues
lint-fix:
	@golangci-lint run --fix

# run tests with race detection
test:
	@go test -v -race -coverprofile=coverage.out ./...
	@go tool cover -func=coverage.out

# run tests without race detection (faster)
test-fast:
	@go test -v ./...

# build the binary
build:
	@go build -o rhinowaf ./cmd/rhinowaf

# build with optimizations
build-prod:
	@go build -ldflags="-s -w" -o rhinowaf ./cmd/rhinowaf

# clean build artifacts
clean:
	@rm -f rhinowaf coverage.out gosec-report.json

# run everything (lint + test + build)
all: lint test build

# show coverage in browser
coverage:
	@go test -coverprofile=coverage.out ./...
	@go tool cover -html=coverage.out
