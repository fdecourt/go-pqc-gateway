package config

import (
	"bytes"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"pq-crypto-service/internal/credential"
	"pq-crypto-service/internal/secmem"
)

// ServiceVersion identifie la version applicative publiée du micro-service.
const ServiceVersion = "0.3.0"

// Config regroupe tous les paramètres de configuration du micro-service.
type Config struct {
	Port                  int           // Port HTTP d'écoute (défaut: 8080)
	Environment           string        // Environnement d'exécution (production, staging, test, development)
	MockMode              bool          // Activer le mode simulé pour les tests / CI sans coût CPU (INTERDIT en prod)
	Algorithm             string        // Algorithme KEM utilisé (défaut: ML-KEM-1024)
	ReadTimeout           time.Duration // Délai d'expiration de lecture HTTP (défaut: 10s)
	WriteTimeout          time.Duration // Délai d'expiration d'écriture HTTP (défaut: 10s)
	IdleTimeout           time.Duration // Délai d'inactivité HTTP (défaut: 60s)
	MaxPayloadBytes       int64         // Taille maximale du corps de requête en octets (défaut: 10 Mio)
	MaxConcurrentRequests int           // Requêtes cryptographiques traitées simultanément (défaut: 16 ; 0 = illimité)
	AccessLog             bool          // Journalisation de chaque requête HTTP (défaut: false pour max QPS)
	LogFormat             string        // Format de journalisation : "json" (défaut) ou "text"
	LogLevel              string        // Niveau de journalisation : debug, info (défaut), warn, error
	MetricsEnabled        bool          // Expose /metrics au format texte Prometheus (défaut: true)
	RateLimitRPS          float64       // Requêtes/s par IP (défaut: 500 ; 0 = désactivé)
	RateLimitBurst        int           // Capacité burst du rate limiter (défaut: 1000)

	// Transport IPC Unix Domain Socket (Option haute sécurité sans réseau TCP)
	SocketPath string // Chemin du socket Unix local (ex: /tmp/pq-crypto/pq.sock). Optionnel.
	SocketMode uint32 // Permissions du socket Unix (défaut: 0660)
	SocketGID  int    // GID du groupe propriétaire du socket (défaut: -1 = inchangé)
	DisableTCP bool   // Désactiver l'écoute TCP si SocketPath est activé (défaut: false)

	// Transport Réseau TCP
	ListenAddress  string         // Adresse d'écoute TCP (défaut : 127.0.0.1 ; 0.0.0.0 pour toutes les interfaces)
	TrustedProxies []netip.Prefix // Proxys dont X-Forwarded-For est cru (TRUSTED_PROXIES, CIDR) ; vide : jamais

	// TLS / mTLS de l'écouteur TCP (le socket Unix reste protégé par les permissions du système de fichiers)
	TLSCertFile           string   // Certificat serveur PEM (active TLS)
	TLSKeyFile            string   // Clé privée PEM du certificat serveur
	TLSClientCAFile       string   // Autorités des certificats clients (active mTLS : certificat client exigé)
	TLSClientAllowedNames []string // Noms (CN, SAN DNS ou URI) des certificats clients admis ; vide : tout certificat de la CA
	TLSMinVersion         uint16   // Version TLS minimale de l'écouteur (défaut : 1.3)
	AllowInsecureTCP      bool     // Accepte, en production, une écoute TCP hors loopback sans TLS (défaut: false)

	// Authentification applicative et isolation
	AuthTokens         []credential.Token // Jetons porteurs admis (AUTH_TOKENS « nom:secret,… » ou AUTH_TOKENS_FILE) ; vide : pas de jeton exigé
	BindClientIdentity bool               // Lie chaque enveloppe à l'identité du client (mTLS, jeton ou UID) : isolation cryptographique entre clients
	AuditLog           bool               // Journalise chaque opération cryptographique (opération, client, kid, issue) (défaut: true)
	MaxConnections     int                // Connexions simultanées admises par écouteur (défaut: 1024 ; 0 = illimité)
	SocketAllowedUIDs  []uint32           // UID des pairs admis sur le socket Unix (SO_PEERCRED) ; vide : permissions du fichier seules

	// Intégration Infisical (gestionnaire de secrets sans persistance disque)
	InfisicalEnabled           bool   // Activer la synchronisation avec Infisical
	InfisicalURL               string // URL de l'instance Infisical
	InfisicalClientID          string // Client ID pour Universal Auth
	InfisicalClientSecret      []byte // Client Secret pour Universal Auth ; effacé (WipeSecrets) une fois le moteur construit
	InfisicalCAFile            string // Autorité de certification de l'instance Infisical (PEM) ; vide : CA du système
	InfisicalProjectID         string // ID du projet (Workspace) dans Infisical
	InfisicalEnv               string // Environnement cible dans Infisical (ex: prod, staging, dev)
	InfisicalSecretBundleName  string // Nom du secret unique atomique contenant la paire de clés (défaut: PQ_KEM_KEYPAIR)
	InfisicalSecretPubKeyName  string // Ancien format scindé (non lu) : sa présence bloque la génération d'une paire
	InfisicalSecretPrivKeyName string // Ancien format scindé (non lu) : sa présence bloque la génération d'une paire
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
	cfg.ReadTimeout, err = envValue("READ_TIMEOUT_SECONDS", DefaultReadTimeout, parseSeconds)
	record(err)
	cfg.WriteTimeout, err = envValue("WRITE_TIMEOUT_SECONDS", DefaultWriteTimeout, parseSeconds)
	record(err)
	cfg.IdleTimeout, err = envValue("IDLE_TIMEOUT_SECONDS", DefaultIdleTimeout, parseSeconds)
	record(err)

	maxPayload, err := envValue("MAX_PAYLOAD_BYTES", int64(10<<20), func(s string) (int64, error) {
		return strconv.ParseInt(s, 10, 64)
	})
	record(err)
	cfg.MaxPayloadBytes = maxPayload
	cfg.MaxConcurrentRequests, err = envValue("MAX_CONCURRENT_REQUESTS", 16, strconv.Atoi)
	record(err)

	cfg.AccessLog, err = envValue("ACCESS_LOG", false, strconv.ParseBool)
	record(err)
	cfg.LogFormat = strings.ToLower(getEnv("LOG_FORMAT", "json"))
	cfg.LogLevel = strings.ToLower(getEnv("LOG_LEVEL", "info"))
	cfg.MetricsEnabled, err = envValue("METRICS_ENABLED", true, strconv.ParseBool)
	record(err)
	cfg.RateLimitRPS, err = envValue("RATE_LIMIT_RPS", 500.0, func(s string) (float64, error) {
		return strconv.ParseFloat(s, 64)
	})
	record(err)
	cfg.RateLimitBurst, err = envValue("RATE_LIMIT_BURST", 1000, strconv.Atoi)
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

	cfg.ListenAddress = getEnv("LISTEN_ADDRESS", getEnv("BIND_ADDRESS", "127.0.0.1"))
	cfg.TLSCertFile = getEnv("TLS_CERT_FILE", "")
	cfg.TLSKeyFile = getEnv("TLS_KEY_FILE", "")
	cfg.TLSClientCAFile = getEnv("TLS_CLIENT_CA_FILE", "")
	cfg.TLSClientAllowedNames = splitList(getEnv("TLS_CLIENT_ALLOWED_NAMES", ""))
	cfg.TLSMinVersion, err = envValue("TLS_MIN_VERSION", uint16(tlsVersion13), parseTLSVersion)
	record(err)
	cfg.AllowInsecureTCP, err = envValue("ALLOW_INSECURE_TCP", false, strconv.ParseBool)
	record(err)
	cfg.TrustedProxies, err = envValue("TRUSTED_PROXIES", nil, parsePrefixes)
	record(err)
	if _, legacy := os.LookupEnv("TRUST_PROXY"); legacy {
		record(fmt.Errorf("TRUST_PROXY est supprimée : déclarer les proxys de confiance par TRUSTED_PROXIES (CIDR), " +
			"sans quoi X-Forwarded-For permettait à tout client direct de se forger une identité"))
	}

	tokenSpec, err := takeEnvSecret("AUTH_TOKENS")
	record(err)
	cfg.AuthTokens, err = parseAuthTokens(tokenSpec)
	secmem.Wipe(tokenSpec)
	record(err)
	cfg.BindClientIdentity, err = envValue("BIND_CLIENT_IDENTITY", false, strconv.ParseBool)
	record(err)
	cfg.AuditLog, err = envValue("AUDIT_LOG", true, strconv.ParseBool)
	record(err)
	cfg.MaxConnections, err = envValue("MAX_CONNECTIONS", 1024, strconv.Atoi)
	record(err)
	cfg.SocketAllowedUIDs, err = envValue("SOCKET_ALLOWED_UIDS", nil, parseUIDs)
	record(err)

	cfg.InfisicalEnabled, err = envValue("INFISICAL_ENABLED", false, strconv.ParseBool)
	record(err)
	cfg.InfisicalURL = getEnv("INFISICAL_URL", "https://infisical:8443")
	cfg.InfisicalClientID = getEnv("INFISICAL_CLIENT_ID", "")
	cfg.InfisicalClientSecret, err = takeEnvSecret("INFISICAL_CLIENT_SECRET")
	record(err)
	cfg.InfisicalCAFile = getEnv("INFISICAL_CA_FILE", "")
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
	if err := c.validateTransportSecurity(); err != nil {
		return err
	}
	if c.SocketPath != "" && c.SocketMode&^0o770 != 0 {
		return fmt.Errorf("SOCKET_MODE invalide (%#o): seuls les droits propriétaire et groupe sont admis (0o770 au plus)", c.SocketMode)
	}
	if c.MaxConcurrentRequests < 0 {
		return fmt.Errorf("MAX_CONCURRENT_REQUESTS invalide (%d): 0 (illimité) ou plus", c.MaxConcurrentRequests)
	}
	if c.RateLimitRPS < 0 {
		return fmt.Errorf("RATE_LIMIT_RPS invalide (%g): 0 (désactivé) ou plus", c.RateLimitRPS)
	}
	if c.MaxPayloadBytes <= 0 || c.MaxPayloadBytes > MaxPayloadCeiling {
		return fmt.Errorf("MAX_PAYLOAD_BYTES invalide (%d): entre 1 et %d octets", c.MaxPayloadBytes, MaxPayloadCeiling)
	}
	// Un délai nul (Config construit programmatiquement, ou variable à 0) prend la valeur par
	// défaut : aucune configuration ne désactive les délais, sans lesquels une connexion lente
	// retient indéfiniment un créneau (Slowloris). Un délai négatif est une erreur.
	for _, t := range []struct {
		name string
		v    *time.Duration
		def  time.Duration
	}{{"READ_TIMEOUT_SECONDS", &c.ReadTimeout, DefaultReadTimeout}, {"WRITE_TIMEOUT_SECONDS", &c.WriteTimeout, DefaultWriteTimeout}, {"IDLE_TIMEOUT_SECONDS", &c.IdleTimeout, DefaultIdleTimeout}} {
		if *t.v < 0 {
			return fmt.Errorf("%s invalide (%s): doit être positif", t.name, *t.v)
		}
		if *t.v == 0 {
			*t.v = t.def
		}
	}
	if c.RateLimitRPS > 0 && c.RateLimitBurst <= 0 {
		return fmt.Errorf("RATE_LIMIT_BURST invalide (%d): au moins 1 quand RATE_LIMIT_RPS est actif", c.RateLimitBurst)
	}
	if c.SocketPath != "" && !filepath.IsAbs(c.SocketPath) {
		return fmt.Errorf("SOCKET_PATH doit être un chemin absolu (reçu %q)", c.SocketPath)
	}
	if c.MaxConnections < 0 {
		return fmt.Errorf("MAX_CONNECTIONS invalide (%d): 0 (illimité) ou plus", c.MaxConnections)
	}
	if len(c.SocketAllowedUIDs) > 0 && c.SocketPath == "" {
		return fmt.Errorf("SOCKET_ALLOWED_UIDS requiert SOCKET_PATH")
	}
	if c.BindClientIdentity && len(c.AuthTokens) == 0 && !c.MTLSEnabled() && len(c.SocketAllowedUIDs) == 0 {
		return fmt.Errorf("BIND_CLIENT_IDENTITY exige une source d'identité : AUTH_TOKENS, TLS_CLIENT_CA_FILE (mTLS) ou SOCKET_ALLOWED_UIDS")
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
	if c.InfisicalEnabled && c.IsProduction() {
		u, err := url.Parse(c.InfisicalURL)
		if err != nil || !strings.EqualFold(u.Scheme, "https") || u.Host == "" {
			return fmt.Errorf("INFISICAL_URL doit être en https:// en production (reçu %q) : la clé privée et le client_secret y transitent", c.InfisicalURL)
		}
	}
	if c.MockMode && c.IsProduction() {
		return fmt.Errorf("FATAL: MOCK_MODE n'est autorisé qu'avec ENVIRONMENT parmi %s (reçu %q)",
			strings.Join(nonProductionEnvironments, ", "), c.Environment)
	}
	return nil
}

// nonProductionEnvironments est la liste blanche des environnements où les garde-fous de
// production sont levés (mode simulé autorisé). Tout autre nom — "staging", "prd", une
// faute de frappe — est traité comme de la production : l'erreur est du côté sûr.
var nonProductionEnvironments = []string{"development", "dev", "test", "local", "ci"}

// Délais HTTP par défaut, appliqués aussi quand un délai vaut 0 (jamais « sans limite »).
const (
	DefaultReadTimeout  = 10 * time.Second
	DefaultWriteTimeout = 10 * time.Second
	DefaultIdleTimeout  = 60 * time.Second
)

// MaxPayloadCeiling borne MAX_PAYLOAD_BYTES : au-delà, le budget mémoire d'une requête
// (voir api.OpenBodyLimit) n'a plus de sens pour un service de chiffrement d'enveloppes.
const MaxPayloadCeiling = 1 << 30

// WipeSecrets efface les secrets de démarrage qui ne servent plus une fois le moteur construit.
func (c *Config) WipeSecrets() {
	secmem.Wipe(c.InfisicalClientSecret)
	c.InfisicalClientSecret = nil
}

// Versions TLS acceptées par TLS_MIN_VERSION (valeurs de crypto/tls, sans importer le paquet ici).
const (
	tlsVersion12 uint16 = 0x0303
	tlsVersion13 uint16 = 0x0304
)

func parseTLSVersion(s string) (uint16, error) {
	switch strings.TrimPrefix(strings.ToLower(s), "tls") {
	case "1.3", "13":
		return tlsVersion13, nil
	case "1.2", "12":
		return tlsVersion12, nil
	}
	return 0, fmt.Errorf("valeurs admises : 1.3 (défaut) ou 1.2")
}

// parsePrefixes lit une liste CIDR séparée par des virgules ; une adresse seule vaut /32 ou /128.
func parsePrefixes(s string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, item := range splitList(s) {
		if p, err := netip.ParsePrefix(item); err == nil {
			out = append(out, p.Masked())
			continue
		}
		a, err := netip.ParseAddr(item)
		if err != nil {
			return nil, fmt.Errorf("entrée %q : adresse IP ou CIDR attendu", item)
		}
		out = append(out, netip.PrefixFrom(a, a.BitLen()))
	}
	return out, nil
}

// minTokenSecretLen est la longueur minimale d'un secret de jeton (256 bits en Base64 ≈ 43).
const minTokenSecretLen = 32

// parseAuthTokens lit « nom:secret,nom2:secret2 ». Le nom (identité journalisée) est restreint
// à [A-Za-z0-9._-]{1,64} ; le secret fait au moins minTokenSecretLen octets et n'est conservé
// que par son empreinte SHA-256.
func parseAuthTokens(spec []byte) ([]credential.Token, error) {
	if len(spec) == 0 {
		return nil, nil
	}
	var out []credential.Token
	seen := map[string]struct{}{}
	for _, item := range bytes.Split(spec, []byte{','}) {
		item = bytes.TrimSpace(item)
		if len(item) == 0 {
			continue
		}
		name, secret, ok := bytes.Cut(item, []byte{':'})
		if !ok || !validTokenName(string(name)) {
			return nil, fmt.Errorf("AUTH_TOKENS : entrée attendue « nom:secret », nom dans [A-Za-z0-9._-]{1,64}")
		}
		if len(secret) < minTokenSecretLen {
			return nil, fmt.Errorf("AUTH_TOKENS : le secret du jeton %q fait moins de %d octets", name, minTokenSecretLen)
		}
		if _, dup := seen[string(name)]; dup {
			return nil, fmt.Errorf("AUTH_TOKENS : nom de jeton %q en double", name)
		}
		seen[string(name)] = struct{}{}
		out = append(out, credential.Token{Name: string(name), Hash: credential.HashToken(secret)})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("AUTH_TOKENS : aucune entrée valide")
	}
	return out, nil
}

func validTokenName(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

// parseUIDs lit une liste d'UID séparés par des virgules.
func parseUIDs(s string) ([]uint32, error) {
	var out []uint32
	for _, item := range splitList(s) {
		v, err := strconv.ParseUint(item, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("UID invalide %q", item)
		}
		out = append(out, uint32(v))
	}
	return out, nil
}

// splitList découpe une liste séparée par des virgules, sans entrées vides.
func splitList(s string) []string {
	var out []string
	for _, item := range strings.Split(s, ",") {
		if item = strings.TrimSpace(item); item != "" {
			out = append(out, item)
		}
	}
	return out
}

// IsProduction est l'unique règle qui décide si les garde-fous de production s'appliquent.
func (c *Config) IsProduction() bool {
	env := strings.TrimSpace(c.Environment)
	for _, e := range nonProductionEnvironments {
		if strings.EqualFold(env, e) {
			return false
		}
	}
	return true
}

// TLSEnabled indique si l'écouteur TCP est servi en TLS.
func (c *Config) TLSEnabled() bool { return c.TLSCertFile != "" }

// MTLSEnabled indique si un certificat client est exigé sur l'écouteur TCP.
func (c *Config) MTLSEnabled() bool { return c.TLSClientCAFile != "" }

// listensOnLoopbackOnly indique si l'écouteur TCP n'est joignable que depuis la machine.
func (c *Config) listensOnLoopbackOnly() bool {
	if strings.EqualFold(c.ListenAddress, "localhost") {
		return true
	}
	ip := net.ParseIP(c.ListenAddress)
	return ip != nil && ip.IsLoopback()
}

// validateTransportSecurity vérifie la cohérence TLS et refuse, en production, d'exposer
// en clair hors loopback : clés DEK et textes clairs y transiteraient lisibles sur le réseau.
func (c *Config) validateTransportSecurity() error {
	if (c.TLSCertFile == "") != (c.TLSKeyFile == "") {
		return fmt.Errorf("TLS_CERT_FILE et TLS_KEY_FILE doivent être fournis ensemble")
	}
	if c.MTLSEnabled() && !c.TLSEnabled() {
		return fmt.Errorf("TLS_CLIENT_CA_FILE (mTLS) requiert TLS_CERT_FILE et TLS_KEY_FILE")
	}
	if c.DisableTCP || c.TLSEnabled() || c.listensOnLoopbackOnly() || !c.IsProduction() {
		return nil
	}
	if !c.AllowInsecureTCP {
		return fmt.Errorf("écoute TCP en clair sur %q refusée en production : configurer TLS_CERT_FILE/TLS_KEY_FILE "+
			"(et TLS_CLIENT_CA_FILE pour mTLS), écouter sur 127.0.0.1, passer par SOCKET_PATH avec DISABLE_TCP=true, "+
			"ou assumer le risque avec ALLOW_INSECURE_TCP=true (réseau privé de confiance uniquement)", c.ListenAddress)
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

// EnvironmentSecrets énumère les variables d'environnement secrètes, retirées de
// l'environnement du processus dès leur lecture.
var EnvironmentSecrets = []string{"INFISICAL_CLIENT_SECRET", "AUTH_TOKENS"}

// takeEnvSecret lit un secret depuis KEY_FILE (fichier) ou KEY (variable), puis retire la
// variable de l'environnement du processus : elle n'a pas à rester lisible après le démarrage.
// La valeur est renvoyée en octets effaçables, jamais en chaîne Go.
func takeEnvSecret(key string) ([]byte, error) {
	defer func() { _ = os.Unsetenv(key) }()
	if filePath, ok := os.LookupEnv(key + "_FILE"); ok && filePath != "" {
		cleanPath := filepath.Clean(filePath)
		data, err := os.ReadFile(cleanPath) // #nosec G304 -- chemin fourni par l'opérateur
		if err != nil {
			return nil, fmt.Errorf("lecture impossible du fichier secret %s (%s): %w", key+"_FILE", filePath, err)
		}
		trimmed := bytes.TrimSpace(data)
		if len(trimmed) == 0 {
			secmem.Wipe(data)
			return nil, fmt.Errorf("fichier secret %s (%s) est vide", key+"_FILE", filePath)
		}
		out := append([]byte(nil), trimmed...)
		secmem.Wipe(data)
		return out, nil
	}
	val, ok := os.LookupEnv(key)
	if !ok || strings.TrimSpace(val) == "" {
		return nil, nil
	}
	return []byte(strings.TrimSpace(val)), nil
}
