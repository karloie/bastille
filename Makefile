.DEFAULT_GOAL := help

.PHONY: help build test test-fast test-pretty test-setup coverage clean docker-build

IMAGE ?= karloie/bastille
DOCKER_BUILD_FLAGS ?=

help: ## Show this help message
	@echo "Targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-15s %s\n", $$1, $$2}'

clean: ## Remove build artifacts and test data
	@rm -f bastille *.test coverage.out coverage.html
	@rm -rf test/ca test/hostkeys test/home test/smtp_pass test/keys
	@echo "✨ Cleaned test data!"

test-setup: ## Generate test data (keys, authorized_keys, etc.)
	@go run ./app/test_setup.go

test: test-setup ## Run all tests
	@go test -v ./app/...

test-pretty: test-setup ## Run all tests with pretty formatter
	@out=$$(mktemp); \
	go test -count=1 -coverprofile=coverage.out -covermode=atomic -json ./app/... | go run ./app/test_setup.go fmt || { echo "⚠️ pretty formatter failed; showing raw output"; cat $$out; }; \
	rm -f $$out

test-fast: ## Run fast unit tests only (skip integration)
	@go test -v -run '^(TestLoadConfigDefaults|TestEnvOverrides|TestSplitList|TestEvalAlgorithms(Add|Remove)|TestConfig(Validation|String)|TestKey(Hash|sEqual)|TestStrictPathOK|TestLoadCertPermit|TestSendTunnelNotification.*)$$' ./app

build: ## Build the bastille binary
	@go build -o bastille ./app

coverage: ## Generate test coverage report with detailed breakdown
	@go test -coverprofile=coverage.out -covermode=atomic ./...
	@go tool cover -func=coverage.out | grep -v "total:" | awk '{printf "  %-50s %8s\n", $$1":"$$2, $$3}'
	@echo ""
	@go tool cover -func=coverage.out | grep total | awk '{print "=== Total Coverage: " $$3 " ==="}'
	@echo ""
	@go tool cover -html=coverage.out -o coverage.html
	@echo "📊 HTML report generated: coverage.html"

docker-run: ## Build Docker image (set IMAGE=repo/name [VERSION=...])
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
