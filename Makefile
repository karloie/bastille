.DEFAULT_GOAL := help



.PHONY: help build test test-setup coverage clean

help: ## Show this help message
	@echo "Bastille - SSH Bastion Server"
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-15s %s\n", $$1, $$2}'

clean: ## Remove build artifacts and test data
	@rm -f bastille *.test coverage.out coverage.html
	@rm -rf test/ca test/hostkeys test/home test/smtp_pass test/keys
	@echo "✨ Cleaned test data!"

test-setup: ## Generate test data (keys, authorized_keys, etc.)
	@go run ./app/test_setup.go

test: test-setup ## Run all tests
	@out=$$(mktemp); \
	go test -json ./app/... | tee $$out | go run ./app/test_setup.go fmt || { echo "⚠️ pretty formatter failed; showing raw output"; cat $$out; }; \
	rm -f $$out

build: ## Build the bastille binary
	@go build -o bastille ./app

coverage: ## Generate test coverage report with detailed breakdown
	@echo "📊 Generating coverage report..."
	@go test -coverprofile=coverage.out -covermode=atomic ./...
	@go tool cover -func=coverage.out | grep -v "total:" | awk '{printf "  %-50s %8s\n", $$1":"$$2, $$3}'
	@echo ""
	@go tool cover -func=coverage.out | grep total | awk '{print "=== Total Coverage: " $$3 " ==="}'
	@echo ""
	@go tool cover -html=coverage.out -o coverage.html
	@echo "📄 HTML report generated: coverage.html"
	@echo "💡 Run 'open coverage.html' to view in browser"
