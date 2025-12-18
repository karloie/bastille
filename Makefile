# Simple Makefile for building and testing the Go project

SHELL := sh

GO        ?= go
PKG       := ./...
BINARY    ?= bastille
BUILD_DIR ?= .
LDFLAGS   ?= -s -w

.DEFAULT_GOAL := build



.PHONY: all build test test-race cover fmt vet tidy clean gow down



all: build

tidy:
	$(GO) mod tidy

clean:
	docker rm --force test-bastille-1 test-target1-1 test-target2-1 || true
	docker network rm --foprbastille_testing || true
	$(GO) clean
	rm -fv $(BUILD_DIR)/$(BINARY)

dev: clean
	docker compose -f test/docker-compose.yml down --remove-orphans
	docker compose -f test/docker-compose.yml up -d --build --remove-orphans
	docker compose -f test/docker-compose.yml logs -f

fmt:
	$(GO) fmt *.go

gow:
	gow run *.go

test:
	$(GO) test *.go -v

cover:
	$(GO) test -cover *.go

build:
	$(GO) build *.go
