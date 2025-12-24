.DEFAULT_GOAL := help

.PHONY: help build test test-fast test-pretty coverage clean docker-build ci run

IMAGE ?= karloie/bastille
DOCKER_BUILD_FLAGS ?=

help: ## Show this help message
	@echo "Targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-15s %s\n", $$1, $$2}'

clean: ## Remove build artifacts
	@rm -f bastille *.test coverage.out coverage.html
	@echo "✨ Cleaned!"

build: ## Build binary
	@go build -o bastille ./app

test: build ## Run all tests (includes integration-heavy tests)
	@go test -count=1 -v ./app/...

test-pretty: ## Run all tests with pretty formatter
	@out=$$(mktemp); \
	go test -count=1 -coverprofile=coverage.out -covermode=atomic -json ./app/... 2>&1 | tee $$out | go run ./app/test_pretty.go || { echo "⚠️ pretty formatter failed; showing raw output"; cat $$out; }; \
	rm -f $$out

test-fast: ## Run fast unit tests only (skips integration-heavy tests)
	@go test -count=1 -v -short ./app/...

coverage: ## Generate coverage report
	@go test -count=1 -coverprofile=coverage.out -covermode=atomic ./...
	@go tool cover -func=coverage.out | grep -v "total:" | awk '{printf "  %-50s %8s\n", $$1":"$$2, $$3}'
	@echo ""
	@go tool cover -func=coverage.out | grep total | awk '{print "=== Total Coverage: " $$3 " ==="}'
	@echo ""
	@go tool cover -html=coverage.out -o coverage.html
	@echo "📊 HTML report generated: coverage.html"

ci: build test ## full integration run (default in CI)
	@go test -count=1 -json ./app/...

run: ## Run Docker image
	@VERSION=$${VERSION:-$$(git describe --tags --always --dirty 2>/dev/null || echo dev)}; \
	GIT_COMMIT=$$(git rev-parse --short HEAD 2>/dev/null || echo unknown); \
	BUILD_TIME=$$(date -u +%Y-%m-%dT%H:%M:%SZ); \
	: \
	echo "Building $(IMAGE):$$VERSION (commit=$$GIT_COMMIT time=$$BUILD_TIME)"; \
	docker build \
	  --build-arg VERSION=$$VERSION \
	  --build-arg GIT_COMMIT=$$GIT_COMMIT \
	  --build-arg BUILD_TIME=$$BUILD_TIME \
	  -t $(IMAGE):$$VERSION .
	@VERSION=$${VERSION:-$$(git describe --tags --always --dirty 2>/dev/null || echo dev)}; \
	docker run --rm $(IMAGE):$$VERSION
