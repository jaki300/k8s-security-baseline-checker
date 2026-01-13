.PHONY: build build-cli build-server test clean install docker-build docker-push help

# Variables
BINARY_CLI=k8s-checker
BINARY_SERVER=k8s-checker-server
VERSION?=v1.0.0
DOCKER_IMAGE?=k8s-checker
DOCKER_TAG?=latest

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod

# Build flags
LDFLAGS=-ldflags "-X main.Version=$(VERSION)"

help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Available targets:'
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-15s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

build: build-cli build-server ## Build both CLI and server

build-cli: ## Build CLI binary
	$(GOBUILD) $(LDFLAGS) -o bin/$(BINARY_CLI) ./cmd/cli

build-server: ## Build server binary
	$(GOBUILD) $(LDFLAGS) -o bin/$(BINARY_SERVER) ./cmd/server

build-all: ## Build for all platforms
	GOOS=linux GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o bin/$(BINARY_CLI)-linux-amd64 ./cmd/cli
	GOOS=linux GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o bin/$(BINARY_SERVER)-linux-amd64 ./cmd/server
	GOOS=darwin GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o bin/$(BINARY_CLI)-darwin-amd64 ./cmd/cli
	GOOS=darwin GOARCH=arm64 $(GOBUILD) $(LDFLAGS) -o bin/$(BINARY_CLI)-darwin-arm64 ./cmd/cli
	GOOS=windows GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o bin/$(BINARY_CLI)-windows-amd64.exe ./cmd/cli
	GOOS=windows GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o bin/$(BINARY_SERVER)-windows-amd64.exe ./cmd/server

test: ## Run tests
	$(GOTEST) -v ./...

test-coverage: ## Run tests with coverage
	$(GOTEST) -v -coverprofile=coverage.out ./...
	$(GOCMD) tool cover -html=coverage.out -o coverage.html

clean: ## Clean build artifacts
	rm -rf bin/
	rm -f coverage.out coverage.html

install: build-cli ## Install CLI to /usr/local/bin
	sudo cp bin/$(BINARY_CLI) /usr/local/bin/

deps: ## Download dependencies
	$(GOMOD) download
	$(GOMOD) tidy

docker-build: ## Build Docker image
	docker build -f deployments/docker/Dockerfile -t $(DOCKER_IMAGE):$(DOCKER_TAG) .

docker-push: docker-build ## Build and push Docker image
	docker push $(DOCKER_IMAGE):$(DOCKER_TAG)

docker-run: docker-build ## Run Docker container
	docker run -it --rm -v ~/.kube:/root/.kube:ro $(DOCKER_IMAGE):$(DOCKER_TAG)

k8s-deploy: ## Deploy to Kubernetes
	kubectl apply -f deployments/kubernetes/

k8s-undeploy: ## Remove from Kubernetes
	kubectl delete -f deployments/kubernetes/

lint: ## Run linter
	golangci-lint run

fmt: ## Format code
	go fmt ./...

vet: ## Run go vet
	go vet ./...

