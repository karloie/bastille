.DEFAULT_GOAL := help

.PHONY: help build test test-fast test-pretty coverage clean docker-build ci run ci-build ci-test

IMAGE ?= karloie/bastille
DOCKER_BUILD_FLAGS ?=

help: ## Show this help message
	@echo "Targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-15s %s\n", $$1, $$2}'

clean: ## Remove build artifacts
	@rm -f bastille *.test coverage.out coverage.html
	@echo "✨ Cleaned!"

build: ## Build binary
	@BUILD_VERSION=$${BUILD_VERSION:-$$(git describe --tags --always --dirty 2>/dev/null || echo dev)}; \
	BUILD_COMMIT=$$(git rev-parse --short HEAD 2>/dev/null || echo unknown); \
	BUILD_DATE=$$(date -u +%Y-%m-%dT%H:%M:%SZ); \
	go build -ldflags "-X main.Version=$$BUILD_VERSION -X main.GitCommit=$$BUILD_COMMIT -X main.BuildTime=$$BUILD_DATE" \
	  -o bastille ./cmd/bastille

test: build ## Run all tests (includes integration-heavy tests)
	go test -count=1 -v ./pkg/...

test-pretty: ## Run all tests with pretty formatter
	@out=$$(mktemp); \
	go test -count=1 -coverprofile=coverage.out -covermode=atomic -json ./pkg/... 2>&1 | tee $$out | go run ./pkg/server/test_pretty.go || { echo "⚠️ pretty formatter failed; showing raw output"; cat $$out; }; \
	rm -f $$out

test-fast: ## Run fast unit tests only (skips integration-heavy tests)
	@go test -count=1 -v -short ./pkg/...

coverage: ## Generate coverage report
	@go test -count=1 -coverprofile=coverage.out -covermode=atomic ./pkg/...
	@go tool cover -func=coverage.out | grep -v "total:" | awk '{printf "  %-50s %8s\n", $$1":"$$2, $$3}'
	@echo ""
	@go tool cover -func=coverage.out | grep total | awk '{print "=== Total Coverage: " $$3 " ==="}'
	@echo ""
	@go tool cover -html=coverage.out -o coverage.html
	@echo "📊 HTML report generated: coverage.html"

ci: build test ## full integration run (default in CI)
	@go test -count=1 -json ./pkg/...

exe: 
	@BUILD_VERSION=$${BUILD_VERSION:-$$(git describe --tags --always --dirty 2>/dev/null || echo dev)}; \
	BUILD_COMMIT=$$(git rev-parse --short HEAD 2>/dev/null || echo unknown); \
	BUILD_DATE=$$(date -u +%Y-%m-%dT%H:%M:%SZ); \
	go run -ldflags "-X main.Version=$$BUILD_VERSION -X main.GitCommit=$$BUILD_COMMIT -X main.BuildTime=$$BUILD_DATE" \
	  ./cmd/bastille/main.go --help

run: ## Run Docker image
	@BUILD_VERSION=$${BUILD_VERSION:-$$(git describe --tags --always --dirty 2>/dev/null || echo dev)}; \
	BUILD_COMMIT=$$(git rev-parse --short HEAD 2>/dev/null || echo unknown); \
	BUILD_DATE=$$(date -u +%Y-%m-%dT%H:%M:%SZ); \
	echo "Building $(IMAGE):$$BUILD_VERSION (commit=$$BUILD_COMMIT date=$$BUILD_DATE)"; \
	docker build \
	  --build-arg BUILD_VERSION=$$BUILD_VERSION \
	  --build-arg BUILD_COMMIT=$$BUILD_COMMIT \
	  --build-arg BUILD_DATE=$$BUILD_DATE \
	  -t $(IMAGE):$$BUILD_VERSION . \
	  -f Containerfile $(DOCKER_BUILD_FLAGS); \
	docker run --rm $(IMAGE):$$BUILD_VERSION

ci-build: ## Build binary (used by shipkit CI)
	@BUILD_VERSION=$${BUILD_VERSION:-$$(git describe --tags --always --dirty 2>/dev/null || echo dev)}; \
	BUILD_COMMIT=$$(git rev-parse --short HEAD 2>/dev/null || echo unknown); \
	BUILD_DATE=$$(date -u +%Y-%m-%dT%H:%M:%SZ); \
	go build -ldflags "-X main.Version=$$BUILD_VERSION -X main.GitCommit=$$BUILD_COMMIT -X main.BuildTime=$$BUILD_DATE" \
	  -o bastille ./cmd/bastille

ci-test: ## Run all tests (used by shipkit CI)
	go test -count=1 ./pkg/...