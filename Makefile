# Disposable Postgres for integration tests. It never touches the compose
# database, because the tests drop and recreate the reflections table.
TEST_DB_CONTAINER := sanctum-test-db
TEST_DB_PORT      := 55432
TEST_DB_URL       := postgres://postgres:test@localhost:$(TEST_DB_PORT)/postgres?sslmode=disable

.PHONY: help build run test test-integration vet fmt-check lint cover keys up down clean

help: ## List targets
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-18s %s\n", $$1, $$2}'

build: ## Build the server binary into bin/
	go build -o bin/sanctum ./cmd/server

run: build ## Run the server (needs DATABASE_URL, SANCTUM_KEK, SANCTUM_API_TOKEN)
	./bin/sanctum

test: ## Unit tests (Postgres tests are skipped)
	go test -race ./...

test-integration: ## All tests, against a throwaway Postgres container
	docker run --rm -d --name $(TEST_DB_CONTAINER) -e POSTGRES_PASSWORD=test \
		-p 127.0.0.1:$(TEST_DB_PORT):5432 postgres:16-alpine
	@until docker exec $(TEST_DB_CONTAINER) pg_isready -U postgres >/dev/null 2>&1; do sleep 1; done
	SANCTUM_TEST_DATABASE_URL="$(TEST_DB_URL)" go test -race -count=1 ./... ; \
		status=$$?; docker stop $(TEST_DB_CONTAINER) >/dev/null; exit $$status

vet: ## go vet
	go vet ./...

fmt-check: ## Fail if any file is not gofmt-formatted
	@test -z "$$(gofmt -l .)" || (gofmt -l . && exit 1)

lint: vet fmt-check ## vet + gofmt + gosec + govulncheck
	go run github.com/securego/gosec/v2/cmd/gosec@latest -quiet ./...
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...

cover: ## Coverage report
	go test -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out | tail -1

keys: ## Print a fresh KEK and API token as export lines
	@echo "export SANCTUM_KEK=$$(openssl rand -base64 32)"
	@echo "export SANCTUM_API_TOKEN=$$(openssl rand -hex 32)"

up: ## Start Postgres + Sanctum with docker compose
	docker compose up --build

down: ## Stop the compose stack (data volume is kept)
	docker compose down

clean: ## Remove build output
	rm -rf bin coverage.out
