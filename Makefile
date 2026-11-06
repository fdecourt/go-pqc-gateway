.PHONY: help build test bench run docker-build docker-up docker-down docker-test clean vulncheck

help:
	@echo "Commandes disponibles pour le micro-service de chiffrement post-quantique :"
	@echo "  make test         - Exécute les tests unitaires et d'intégration Go"
	@echo "  make bench        - Exécute les benchmarks de performances KEM / AES"
	@echo "  make vulncheck    - Analyse les vulnérabilités de dépendances via govulncheck"
	@echo "  make build        - Compile le binaire Go localement"
	@echo "  make run          - Démarre le service en local (port 8080)"
	@echo "  make docker-build - Construit l'image Docker multi-stage sécurisée"
	@echo "  make docker-up    - Démarre le conteneur via docker-compose"
	@echo "  make docker-down  - Arrête le conteneur docker-compose"
	@echo "  make docker-test  - Lance les tests automatisés au sein d'un conteneur Go éphémère"

# Effacement des temporaires cryptographiques par runtime/secret (voir Dockerfile).
SECRET_EXPERIMENT ?= runtimesecret
GOVULNCHECK_VERSION ?= v1.9.0
# Image Go des cibles docker-*, alignée sur le Dockerfile.
GO_IMAGE ?= golang:1.27.3-alpine@sha256:d200d2dd76b03a99b52651fd1325aff7dcd35422c35c01bac56571b0507f3deb

# Le moteur simulé n'est compilé qu'avec le tag "mock", et runtime/secret qu'avec
# GOEXPERIMENT=runtimesecret : les variantes livrée et de repli sont testées.
test:
	GOEXPERIMENT=$(SECRET_EXPERIMENT) go test -tags mock ./...
	GOEXPERIMENT=$(SECRET_EXPERIMENT) go test ./...
	go test ./...

test-race:
	go test -race -tags mock ./...
	GOEXPERIMENT=$(SECRET_EXPERIMENT) go test -race ./...

vulncheck:
	go run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) ./...

# Benchmarks compilés comme l'image (runtime/secret) ; bout en bout HTTP inclus.
bench:
	GOEXPERIMENT=$(SECRET_EXPERIMENT) go test -bench=. -benchmem -benchtime=3s -count=6 -run='^$$' ./tests/ | tee bench.txt
	@echo "Comparer deux séries : benchstat old.txt bench.txt"

bench-1mb:
	docker run --rm -e GOEXPERIMENT=$(SECRET_EXPERIMENT) -v "$(PWD)":/app -w /app $(GO_IMAGE) sh -c "go test -v -benchmem -bench=1MB ./tests/..."

build:
	CGO_ENABLED=0 GOEXPERIMENT=$(SECRET_EXPERIMENT) go build -trimpath -ldflags="-s -w" -o bin/pq-server ./cmd/server

run:
	go run ./cmd/server/main.go

docker-build:
	docker compose build

docker-up:
	docker compose up -d

docker-down:
	docker compose down

docker-test:
	docker run --rm -e CGO_ENABLED=0 -e GOEXPERIMENT=$(SECRET_EXPERIMENT) -v "$(PWD)":/app -w /app $(GO_IMAGE) sh -c "go test -tags mock ./... && go test ./..."

DOCKER_USER ?= fdecourt
IMAGE_TAG ?= 0.4.0

docker-push:
	docker tag pq-crypto-service:$(IMAGE_TAG) $(DOCKER_USER)/pq-crypto-service:$(IMAGE_TAG)
	docker tag pq-crypto-service:$(IMAGE_TAG) $(DOCKER_USER)/pq-crypto-service:latest
	docker push $(DOCKER_USER)/pq-crypto-service:$(IMAGE_TAG)
	docker push $(DOCKER_USER)/pq-crypto-service:latest

clean:
	rm -rf bin/
