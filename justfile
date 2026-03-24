# bastille justfile

CONTAINER_IMAGE := "karloie/bastille"
DOCKER_BUILD_FLAGS := ""

# Show available recipes
@help:
    echo "Recipes:"
    just --list

# Remove build artifacts
@clean:
    rm -f bastille *.test coverage.out coverage.html
    echo "✨ Cleaned!"

# Build binary
@build:
    #!/usr/bin/env bash
    BUILD_VERSION=${BUILD_VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}
    BUILD_COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo unknown)
    BUILD_DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    go build -ldflags "-X main.Version=$BUILD_VERSION -X main.GitCommit=$BUILD_COMMIT -X main.BuildTime=$BUILD_DATE" \
      -o bastille ./cmd/bastille

# Run all tests (includes integration-heavy tests)
test: build
    go test -count=1 -v ./pkg/...

# Run all tests with pretty formatter
@test-pretty:
    #!/usr/bin/env bash
    out=$(mktemp)
    go test -count=1 -coverprofile=coverage.out -covermode=atomic -json ./pkg/... 2>&1 | tee $out | go run ./pkg/server/test_pretty.go || { echo "⚠️ pretty formatter failed; showing raw output"; cat $out; }
    rm -f $out

# Run fast unit tests only (skips integration-heavy tests)
@test-fast:
    go test -count=1 -v -short ./pkg/...

# Generate coverage report
@coverage:
    #!/usr/bin/env bash
    go test -count=1 -coverprofile=coverage.out -covermode=atomic ./pkg/...
    go tool cover -func=coverage.out | grep -v "total:" | awk '{printf "  %-50s %8s\n", $1":"$2, $3}'
    echo ""
    go tool cover -func=coverage.out | grep total | awk '{print "=== Total Coverage: " $3 " ==="}'
    echo ""
    go tool cover -html=coverage.out -o coverage.html
    echo "📊 HTML report generated: coverage.html"

# Full integration run (default in CI)
@ci: build test
    go test -count=1 -json ./pkg/...

# Run binary directly
@exe:
    #!/usr/bin/env bash
    BUILD_VERSION=${BUILD_VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}
    BUILD_COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo unknown)
    BUILD_DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    go run -ldflags "-X main.Version=$BUILD_VERSION -X main.GitCommit=$BUILD_COMMIT -X main.BuildTime=$BUILD_DATE" \
      ./cmd/bastille/main.go --help

# Run Docker image
@run:
    #!/usr/bin/env bash
    BUILD_VERSION=${BUILD_VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}
    BUILD_COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo unknown)
    BUILD_DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    echo "Building {{CONTAINER_IMAGE}}:$BUILD_VERSION (commit=$BUILD_COMMIT date=$BUILD_DATE)"
    docker build \
      --build-arg BUILD_VERSION=$BUILD_VERSION \
      --build-arg BUILD_COMMIT=$BUILD_COMMIT \
      --build-arg BUILD_DATE=$BUILD_DATE \
      -t {{CONTAINER_IMAGE}}:$BUILD_VERSION . \
      -f Containerfile {{DOCKER_BUILD_FLAGS}}
    docker run --rm {{CONTAINER_IMAGE}}:$BUILD_VERSION

# ci-generate is called before ci-build (optional target)
# Use this for: code generation, frontend builds, npm install, etc.
@ci-generate:
    echo "📦 No code generation needed for bastille"

# Build binary (used by shipkit CI)
@ci-build:
    shipkit go-build --output=bastille --main=./cmd/bastille

# Run all tests (used by shipkit CI)
@ci-test:
    go test -count=1 ./pkg/...

# ci-integration-test is called after ci-test (optional target)
# Use this for: integration tests, e2e tests, heavier test suites
@ci-integration-test:
    echo "🧪 No separate integration tests defined for bastille"

# ci-release is called after tests pass (optional target)
# Use this for: building artifacts, pushing Docker images, creating releases
@ci-release:
    #!/usr/bin/env bash
    echo "📦 Building release artifacts..."
    
    # Ensure tools are available
    shipkit install goreleaser
    
    # Build and push Docker image with version tags (reads from plan.json)
    shipkit docker --release
    
    # Create GitHub release and update homebrew tap
    shipkit goreleaser --generate --homebrew

# ci-summary is called at the end (optional target)
# Use this for: posting summaries, sending notifications
@ci-summary:
    #!/usr/bin/env bash
    echo "📊 Generating release summary..."
    
    # Generate summary message from plan.json
    if [ -f plan.json ]; then
        VERSION=$(shipkit env | grep BUILD_VERSION | cut -d'=' -f2)
        echo ""
        echo "✅ bastille $VERSION released successfully!"
        echo ""
        echo "Artifacts:"
        echo "  - Docker: {{CONTAINER_IMAGE}}:$VERSION"
        echo "  - Docker: {{CONTAINER_IMAGE}}:latest"
        echo "  - Binary: bastille"
        echo ""
    else
        echo "✅ bastille release complete"
    fi
