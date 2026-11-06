# ==============================================================================
# ÉTAPE 1 : Compilation Statique & Préparation Sécurité (Build Stage)
# ==============================================================================
FROM golang:1.27.3-alpine@sha256:d200d2dd76b03a99b52651fd1325aff7dcd35422c35c01bac56571b0507f3deb AS builder

# GOEXPERIMENT=runtimesecret : les opérations cryptographiques s'exécutent sous runtime/secret,
# qui efface registres, pile et allocations temporaires (clés AES étendues, états Keccak,
# secrets intermédiaires) dès leur fin. GOTOOLCHAIN=local : la chaîne épinglée ci-dessus, et
# aucune autre, compile l'image.
ENV CGO_ENABLED=0 \
    GOEXPERIMENT=runtimesecret \
    GOTOOLCHAIN=local \
    GOFLAGS=-mod=readonly

# Certificats racine (copiés dans l'image finale). Aucun outil supplémentaire : les modules
# viennent du proxy Go et sont vérifiés par go.sum, git n'a pas sa place dans l'image de build.
RUN apk add --no-cache ca-certificates

WORKDIR /build

# Téléchargement et vérification cryptographique des dépendances Go
COPY go.mod go.sum* ./
RUN go mod download && go mod verify

# Création des entrées utilisateur/groupe non-privilégiés (UID/GID 10001) pour le conteneur scratch
RUN echo "appgroup:x:10001:" > /tmp/group && \
    echo "appuser:x:10001:10001:AppUser:/:/sbin/nologin" > /tmp/passwd

# Copie du code source complet
COPY . .

# Suite de tests complète : avec le tag "mock" (tests du moteur simulé) puis sans
# (vérifie que le binaire livré ne contient pas le mode simulé).
RUN go test -tags mock ./... && go test ./...

# Compilation statique sans dépendance dynamique (Static ELF)
ARG TARGETARCH
RUN GOOS=linux GOARCH=${TARGETARCH:-amd64} go build \
    -trimpath -buildvcs=false \
    -ldflags="-s -w -extldflags '-static'" \
    -o /bin/pq-server \
    ./cmd/server

# ==============================================================================
# ÉTAPE 2 : Image minimale "Scratch" (zéro binaire système tiers)
# ==============================================================================
FROM scratch

# Métadonnées OCI (org.opencontainers.image.*) : elles rattachent l'image publiée à son
# dépôt source, sa licence et sa version sans dépendre d'un registre particulier. Les clés
# standardisées sont préférées aux clés Docker historiques (maintainer, version) pour éviter
# de déclarer deux fois la même information.
LABEL org.opencontainers.image.title="pq-crypto-service" \
      org.opencontainers.image.description="Micro-service de chiffrement post-quantique ML-KEM + AES-256-GCM" \
      org.opencontainers.image.version="0.3.0" \
      org.opencontainers.image.licenses="BUSL-1.1" \
      org.opencontainers.image.source="https://github.com/fdecourt/go-pqc-gateway" \
      org.opencontainers.image.authors="fdecourt"

# Certificats SSL/TLS racine pour les appels HTTPS sortants sécurisés (Infisical, etc.)
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

# Configuration utilisateur non-privilégié (UID/GID 10001)
COPY --from=builder /tmp/passwd /etc/passwd
COPY --from=builder /tmp/group /etc/group

# Copie du binaire statique unique du service
COPY --from=builder /bin/pq-server /usr/local/bin/pq-server

# Textes de licence, embarqués avec le binaire qu'ils couvrent (lecture seule) : celle du
# projet, et les mentions des composants tiers (Go, circl, CA Mozilla) que leurs licences
# BSD-3-Clause et MPL-2.0 exigent de reproduire dans toute distribution binaire.
COPY --chmod=0444 LICENSE THIRD_PARTY_LICENSES /

# Basculement vers l'utilisateur non-privilégié
USER 10001:10001

# Variables d'environnement par défaut. LISTEN_ADDRESS=0.0.0.0 est indispensable pour être
# joignable via le port publié : en production, le service refuse alors de démarrer sans TLS
# (TLS_CERT_FILE/TLS_KEY_FILE), sauf opt-in explicite ALLOW_INSECURE_TCP=true sur un réseau
# privé de confiance.
ENV PORT=8080 \
    LISTEN_ADDRESS=0.0.0.0 \
    MOCK_MODE=false \
    ENVIRONMENT=production

# Exposition du port réseau interne
EXPOSE 8080

# Healthcheck natif Docker exécuté directement par le binaire Go (sans shell, curl ni wget)
HEALTHCHECK --interval=10s --timeout=3s --start-period=3s --retries=3 \
    CMD ["/usr/local/bin/pq-server", "-healthcheck"]

# Point d'entrée d'exécution
ENTRYPOINT ["/usr/local/bin/pq-server"]
