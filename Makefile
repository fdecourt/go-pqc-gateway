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

test:
	go test -v ./...

test-race:
	go test -v -race ./...

vulncheck:
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...

bench:
	go test -bench=. -benchmem -benchtime=3s -count=6 -run='^$$' ./tests/ | tee bench.txt
	@echo "Comparer deux séries : benchstat old.txt bench.txt"

bench-1mb:
	docker run --rm -v "$(PWD)":/app -w /app golang:alpine sh -c "go test -v -benchmem -bench=1MB ./tests/..."

build:
	CGO_ENABLED=0 go build -ldflags="-s -w" -o bin/pq-server ./cmd/server

run:
	go run ./cmd/server/main.go

docker-build:
	docker compose build

docker-up:
	docker compose up -d

docker-down:
	docker compose down

docker-test:
	docker run --rm -v "$(PWD)":/app -w /app golang:alpine sh -c "CGO_ENABLED=0 go test -v ./..."

DOCKER_USER ?= fdecourt
IMAGE_TAG ?= 0.0.1

docker-push:
	docker tag pq-crypto-service:$(IMAGE_TAG) $(DOCKER_USER)/pq-crypto-service:$(IMAGE_TAG)
	docker tag pq-crypto-service:$(IMAGE_TAG) $(DOCKER_USER)/pq-crypto-service:latest
	docker push $(DOCKER_USER)/pq-crypto-service:$(IMAGE_TAG)
	docker push $(DOCKER_USER)/pq-crypto-service:latest

clean:
	rm -rf bin/
