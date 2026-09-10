package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"pq-crypto-service/internal/crypto"
)

// ServiceVersion identifie la version applicative publiée du micro-service.
const ServiceVersion = "0.0.1"

// Config regroupe tous les paramètres de configuration du micro-service.
type Config struct {
	Port            int           // Port HTTP d'écoute (défaut: 8080)
	Environment     string        // Environnement d'exécution (production, staging, test, development)
	MockMode        bool          // Activer le mode simulé pour les tests / CI sans coût CPU (INTERDIT en prod)
	Algorithm       string        // Algorithme KEM utilisé (défaut: ML-KEM-1024)
	ReadTimeout     time.Duration // Délai d'expiration de lecture HTTP (défaut: 10s)
	WriteTimeout    time.Duration // Délai d'expiration d'écriture HTTP (défaut: 10s)
	IdleTimeout     time.Duration // Délai d'inactivité HTTP (défaut: 60s)
	MaxPayloadBytes int64         // Taille maximale de la charge utile en octets (défaut: 10MB)
	AccessLog       bool          // Journalisation de chaque requête HTTP (défaut: false pour max QPS)
	LogFormat       string        // Format de journalisation : "json" (défaut) ou "text"
	LogLevel        string        // Niveau de journalisation : debug, info (défaut), warn, error
	MetricsEnabled  bool          // Expose /metrics au format texte Prometheus (défaut: true)
	RateLimitRPS    float64       // Limite de débit requêtes/sec (défaut: 0 = désactivé pour haute performance)
	RateLimitBurst  int           // Capacité burst du rate limiter (défaut: 100)

	// Transport IPC Unix Domain Socket (Option haute sécurité sans réseau TCP)
	SocketPath string // Chemin du socket Unix local (ex: /tmp/pq-crypto/pq.sock). Optionnel.
	SocketMode uint32 // Permissions du socket Unix (défaut: 0660)
	SocketGID  int    // GID du groupe propriétaire du socket (défaut: -1 = inchangé)
	DisableTCP bool   // Désactiver l'écoute TCP si SocketPath est activé (défaut: false)

	// Transport Réseau TCP
	ListenAddress        string // Adresse IP d'écoute TCP (défaut: "" -> écoute sur toutes les interfaces, ou 0.0.0.0)
	TrustProxy           bool   // Fait confiance à l'en-tête X-Forwarded-For si activé (défaut: false)
	AllowLegacyEnvelopes bool   // Autorise les flux binaires historiques sans en-tête 'PQ' (défaut: false)

	// Intégration Infisical (gestionnaire de secrets sans persistance disque)
	InfisicalEnabled           bool   // Activer la synchronisation avec Infisical
	InfisicalURL               string // URL de l'instance Infisical
	InfisicalClientID          string // Client ID pour Universal Auth
	InfisicalClientSecret      string // Client Secret pour Universal Auth
	InfisicalProjectID         string // ID du projet (Workspace) dans Infisical
	InfisicalEnv               string // Environnement cible dans Infisical (ex: prod, staging, dev)
	InfisicalSecretBundleName  string // Nom du secret unique atomique contenant la paire de clés (défaut: PQ_KEM_KEYPAIR)
	InfisicalSecretPubKeyName  string // Nom de la clé secrète publique dans Infisical (mode scindé rétrocompatible)
	InfisicalSecretPrivKeyName string // Nom de la clé secrète privée dans Infisical (mode scindé rétrocompatible)
}

// envValue extrait et valide une variable d'environnement avec une valeur par défaut.
// Si la variable est définie mais invalide, une erreur explicite est renvoyée (fail-closed, pas de fallback silencieux).
func envValue[T any](name string, fallback T, parse func(string) (T, error)) (T, error) {
	valStr, ok := os.LookupEnv(name)
	if !ok || strings.TrimSpace(valStr) == "" {
		return fallback, nil
	}
	parsed, err := parse(strings.TrimSpace(valStr))
	if err != nil {
		return fallback, fmt.Errorf("variable d'environnement %s invalide (%q): %w", name, valStr, err)
	}
	return parsed, nil
}

// LoadConfig charge la configuration depuis l'environnement en validant strictement chaque variable typée.
func LoadConfig() (*Config, error) {
	var firstErr error
	record := func(err error) {
		if firstErr == nil && err != nil {
			firstErr = err
		}
	}

	cfg := &Config{}
	var err error

	cfg.Port, err = envValue("PORT", 8080, strconv.Atoi)
	record(err)
	cfg.Environment = getEnv("ENVIRONMENT", "production")
	cfg.MockMode, err = envValue("MOCK_MODE", false, strconv.ParseBool)
	record(err)
	cfg.Algorithm = getEnv("ALGORITHM", "ML-KEM-1024")

	parseSeconds := func(s string) (time.Duration, error) {
		v, e := strconv.Atoi(s)
		return time.Duration(v) * time.Second, e
	}
	cfg.ReadTimeout, err = envValue("READ_TIMEOUT_SECONDS", 10*time.Second, parseSeconds)
	record(err)
	cfg.WriteTimeout, err = envValue("WRITE_TIMEOUT_SECONDS", 10*time.Second, parseSeconds)
	record(err)
	cfg.IdleTimeout, err = envValue("IDLE_TIMEOUT_SECONDS", 60*time.Second, parseSeconds)
	record(err)

	maxPayload, err := envValue("MAX_PAYLOAD_BYTES", int64(10*1024*1024), func(s string) (int64, error) {
		return strconv.ParseInt(s, 10, 64)
	})
	record(err)
	cfg.MaxPayloadBytes = maxPayload

	cfg.AccessLog, err = envValue("ACCESS_LOG", false, strconv.ParseBool)
	record(err)
	cfg.LogFormat = strings.ToLower(getEnv("LOG_FORMAT", "json"))
	cfg.LogLevel = strings.ToLower(getEnv("LOG_LEVEL", "info"))
	cfg.MetricsEnabled, err = envValue("METRICS_ENABLED", true, strconv.ParseBool)
	record(err)
	cfg.RateLimitRPS, err = envValue("RATE_LIMIT_RPS", 0.0, func(s string) (float64, error) {
		return strconv.ParseFloat(s, 64)
	})
	record(err)
	cfg.RateLimitBurst, err = envValue("RATE_LIMIT_BURST", 100, strconv.Atoi)
	record(err)

	cfg.SocketPath = getEnv("SOCKET_PATH", "")
	cfg.SocketMode, err = envValue("SOCKET_MODE", 0660, func(s string) (uint32, error) {
		v, e := strconv.ParseUint(s, 8, 32)
		return uint32(v), e
	})
	record(err)
	cfg.SocketGID, err = envValue("SOCKET_GID", -1, strconv.Atoi)
	record(err)
	cfg.DisableTCP, err = envValue("DISABLE_TCP", false, strconv.ParseBool)
	record(err)

	cfg.ListenAddress = getEnv("LISTEN_ADDRESS", getEnv("BIND_ADDRESS", ""))
	cfg.TrustProxy, err = envValue("TRUST_PROXY", false, strconv.ParseBool)
	record(err)
	cfg.AllowLegacyEnvelopes, err = envValue("ALLOW_LEGACY_ENVELOPES", false, strconv.ParseBool)
	record(err)

	cfg.InfisicalEnabled, err = envValue("INFISICAL_ENABLED", false, strconv.ParseBool)
	record(err)
	cfg.InfisicalURL = getEnv("INFISICAL_URL", "http://infisical:8080")
	cfg.InfisicalClientID = getEnv("INFISICAL_CLIENT_ID", "")
	cfg.InfisicalClientSecret, err = getEnvSecret("INFISICAL_CLIENT_SECRET", "")
	record(err)
	cfg.InfisicalProjectID = getEnv("INFISICAL_PROJECT_ID", "")
	cfg.InfisicalEnv = getEnv("INFISICAL_ENV", "prod")
	cfg.InfisicalSecretBundleName = getEnv("INFISICAL_SECRET_BUNDLE_NAME", "PQ_KEM_KEYPAIR")
	cfg.InfisicalSecretPubKeyName = getEnv("INFISICAL_SECRET_PUBKEY_NAME", "PQ_KEM_PUBLIC_KEY")
	cfg.InfisicalSecretPrivKeyName = getEnv("INFISICAL_SECRET_PRIVKEY_NAME", "PQ_KEM_PRIVATE_KEY")

	if firstErr != nil {
		return nil, firstErr
	}
	return cfg, nil
}

// Validate contrôle rigoureusement les paramètres de configuration au démarrage.
func (c *Config) Validate() error {
	if c.DisableTCP && c.SocketPath == "" {
		return fmt.Errorf("configuration invalide: DISABLE_TCP=true requiert la définition de SOCKET_PATH")
	}
	if !c.DisableTCP {
		if c.Port <= 0 || c.Port > 65535 {
			return fmt.Errorf("PORT invalide (%d): doit être compris entre 1 et 65535", c.Port)
		}
	}
	if c.MaxPayloadBytes <= 0 {
		return fmt.Errorf("MAX_PAYLOAD_BYTES invalide (%d): doit être supérieur à 0", c.MaxPayloadBytes)
	}
	// Une valeur vide correspond à un Config construit programmatiquement :
	// on applique le défaut plutôt que d'échouer. LoadConfig, lui, valide toute valeur fournie.
	if c.LogFormat == "" {
		c.LogFormat = "json"
	}
	if c.LogLevel == "" {
		c.LogLevel = "info"
	}
	switch c.LogFormat {
	case "json", "text":
	default:
		return fmt.Errorf("LOG_FORMAT invalide (%s): valeurs acceptées json ou text", c.LogFormat)
	}
	switch c.LogLevel {
	case "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("LOG_LEVEL invalide (%s): valeurs acceptées debug, info, warn ou error", c.LogLevel)
	}
	suite, err := crypto.LookupSuite(c.Algorithm)
	if err != nil {
		return fmt.Errorf("ALGORITHM non supporté (%s)", c.Algorithm)
	}
	if strings.EqualFold(c.Environment, "production") || strings.EqualFold(c.Environment, "prod") {
		if c.MockMode || suite.ID == crypto.SuiteMock {
			return fmt.Errorf("FATAL: MOCK_MODE et suites simulées sont formellement interdits en environnement de production (ENVIRONMENT=%s, ALGORITHM=%s)", c.Environment, c.Algorithm)
		}
	}
	return nil
}

// Address retourne l'adresse réseau complète pour le serveur HTTP.
func (c *Config) Address() string {
	if c.ListenAddress != "" {
		return fmt.Sprintf("%s:%d", c.ListenAddress, c.Port)
	}
	return fmt.Sprintf(":%d", c.Port)
}

func getEnv(key, fallback string) string {
	if val, ok := os.LookupEnv(key); ok && val != "" {
		return val
	}
	return fallback
}

func getEnvSecret(key, fallback string) (string, error) {
	if filePath, ok := os.LookupEnv(key + "_FILE"); ok && filePath != "" {
		cleanPath := filepath.Clean(filePath)
		// #nosec G304
		data, err := os.ReadFile(cleanPath)
		if err != nil {
			return "", fmt.Errorf("lecture impossible du fichier secret %s (%s): %w", key+"_FILE", filePath, err)
		}
		trimmed := strings.TrimSpace(string(data))
		if trimmed == "" {
			return "", fmt.Errorf("fichier secret %s (%s) est vide", key+"_FILE", filePath)
		}
		return trimmed, nil
	}
	return getEnv(key, fallback), nil
}
