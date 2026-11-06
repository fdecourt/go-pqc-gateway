package config

import (
	"os"
	"strings"
	"testing"
	"time"
)

func TestConfig_DefaultValues(t *testing.T) {
	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig par défaut a échoué: %v", err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validation par défaut a échoué: %v", err)
	}

	if cfg.Port != 8080 {
		t.Errorf("port attendu 8080, obtenu %d", cfg.Port)
	}
	if cfg.SocketPath != "" {
		t.Errorf("SocketPath par défaut devrait être vide, obtenu %q", cfg.SocketPath)
	}
	if cfg.DisableTCP != false {
		t.Errorf("DisableTCP par défaut devrait être false")
	}
	if cfg.SocketMode != 0660 {
		t.Errorf("SocketMode par défaut attendu 0660, obtenu %04o", cfg.SocketMode)
	}
	// Garde-fous anti-saturation actifs par défaut
	if cfg.MaxPayloadBytes != 10<<20 {
		t.Errorf("MaxPayloadBytes par défaut attendu 10 Mio, obtenu %d", cfg.MaxPayloadBytes)
	}
	if cfg.MaxConcurrentRequests != 16 {
		t.Errorf("MaxConcurrentRequests par défaut attendu 16, obtenu %d", cfg.MaxConcurrentRequests)
	}
	if cfg.RateLimitRPS != 500 || cfg.RateLimitBurst != 1000 {
		t.Errorf("rate-limit par défaut attendu 500/1000, obtenu %g/%d", cfg.RateLimitRPS, cfg.RateLimitBurst)
	}
}

func TestConfig_SocketAndDualListener(t *testing.T) {
	// Cas 1: Socket Unix + TCP activé (Mode Dual)
	cfg := &Config{
		Port:            8080,
		ListenAddress:   "127.0.0.1",
		MaxPayloadBytes: 10 * 1024 * 1024,
		Algorithm:       "ML-KEM-1024",
		Environment:     "production",
		SocketPath:      "/tmp/pq-crypto/pq.sock",
		DisableTCP:      false,
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validation dual mode échouée: %v", err)
	}

	// Cas 2: Socket Unix seul (TCP désactivé)
	cfgUnixOnly := &Config{
		MaxPayloadBytes: 10 * 1024 * 1024,
		Algorithm:       "ML-KEM-1024",
		Environment:     "production",
		SocketPath:      "/tmp/pq-crypto/pq.sock",
		DisableTCP:      true,
	}
	if err := cfgUnixOnly.Validate(); err != nil {
		t.Fatalf("Validation unix-only échouée: %v", err)
	}

	// Cas 3: TCP désactivé SANS SocketPath (Interdit)
	cfgInvalid := &Config{
		MaxPayloadBytes: 10 * 1024 * 1024,
		Algorithm:       "ML-KEM-1024",
		Environment:     "production",
		SocketPath:      "",
		DisableTCP:      true,
	}
	if err := cfgInvalid.Validate(); err == nil {
		t.Fatal("Validation aurait dû échouer quand DisableTCP=true sans SocketPath")
	}
}

func TestConfig_ValidationErrors(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(c *Config)
		wantErr bool
	}{
		{
			name: "Port invalide (0) quand TCP actif",
			mutate: func(c *Config) {
				c.Port = 0
				c.DisableTCP = false
			},
			wantErr: true,
		},
		{
			name: "Port invalide (>65535)",
			mutate: func(c *Config) {
				c.Port = 70000
				c.DisableTCP = false
			},
			wantErr: true,
		},
		{
			name: "MaxPayloadBytes invalide (0)",
			mutate: func(c *Config) {
				c.MaxPayloadBytes = 0
			},
			wantErr: true,
		},
		{
			name: "MockMode interdit en production",
			mutate: func(c *Config) {
				c.Environment = "production"
				c.MockMode = true
			},
			wantErr: true,
		},
		{
			name: "SOCKET_MODE ouvert à tous (0777) refusé",
			mutate: func(c *Config) {
				c.SocketPath = "/tmp/pq.sock"
				c.SocketMode = 0o777
			},
			wantErr: true,
		},
		{
			name: "SOCKET_MODE lisible par les autres (0664) refusé",
			mutate: func(c *Config) {
				c.SocketPath = "/tmp/pq.sock"
				c.SocketMode = 0o664
			},
			wantErr: true,
		},
		{
			name: "SOCKET_MODE propriétaire et groupe (0660) accepté",
			mutate: func(c *Config) {
				c.SocketPath = "/tmp/pq.sock"
				c.SocketMode = 0o660
			},
			wantErr: false,
		},
		{
			name: "MockMode interdit en staging (hors liste blanche)",
			mutate: func(c *Config) {
				c.Environment = "staging"
				c.MockMode = true
			},
			wantErr: true,
		},
		{
			name: "MockMode interdit sur faute de frappe (prd)",
			mutate: func(c *Config) {
				c.Environment = "prd"
				c.MockMode = true
			},
			wantErr: true,
		},
		{
			name: "MockMode interdit sans ENVIRONMENT",
			mutate: func(c *Config) {
				c.Environment = ""
				c.MockMode = true
			},
			wantErr: true,
		},
		{
			name: "Infisical en HTTP interdit en production",
			mutate: func(c *Config) {
				c.Environment = "production"
				c.InfisicalEnabled = true
				c.InfisicalURL = "http://infisical:8080"
			},
			wantErr: true,
		},
		{
			name: "Infisical en HTTPS accepté en production",
			mutate: func(c *Config) {
				c.Environment = "production"
				c.InfisicalEnabled = true
				c.InfisicalURL = "https://infisical.example"
			},
			wantErr: false,
		},
		{
			name: "Infisical en HTTP toléré en développement",
			mutate: func(c *Config) {
				c.Environment = "development"
				c.InfisicalEnabled = true
				c.InfisicalURL = "http://infisical:8080"
			},
			wantErr: false,
		},
		{
			name: "MockMode autorisé en test",
			mutate: func(c *Config) {
				c.Environment = "TEST"
				c.MockMode = true
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{
				Port:            8080,
				ListenAddress:   "127.0.0.1",
				MaxPayloadBytes: 10 * 1024 * 1024,
				Algorithm:       "ML-KEM-1024",
				Environment:     "test",
			}
			tt.mutate(cfg)
			err := cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() erreur = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestConfig_EnvOverrides(t *testing.T) {
	_ = os.Setenv("PORT", "9090")
	_ = os.Setenv("SOCKET_PATH", "/tmp/test.sock")
	_ = os.Setenv("DISABLE_TCP", "true")
	defer func() {
		_ = os.Unsetenv("PORT")
		_ = os.Unsetenv("SOCKET_PATH")
		_ = os.Unsetenv("DISABLE_TCP")
	}()

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig a échoué: %v", err)
	}
	if cfg.Port != 9090 {
		t.Errorf("attendu Port 9090, obtenu %d", cfg.Port)
	}
	if cfg.SocketPath != "/tmp/test.sock" {
		t.Errorf("attendu SocketPath /tmp/test.sock, obtenu %s", cfg.SocketPath)
	}
	if !cfg.DisableTCP {
		t.Errorf("attendu DisableTCP true, obtenu %t", cfg.DisableTCP)
	}
}

func TestConfig_ListenAddressAndAddress(t *testing.T) {
	cfgDefault := &Config{Port: 8080} // construit sans LoadConfig : toutes les interfaces
	if cfgDefault.Address() != ":8080" {
		t.Errorf("Address() attendu ':8080', obtenu %q", cfgDefault.Address())
	}

	cfgListen := &Config{Port: 8080, ListenAddress: "127.0.0.1"}
	if cfgListen.Address() != "127.0.0.1:8080" {
		t.Errorf("Address() attendu '127.0.0.1:8080', obtenu %q", cfgListen.Address())
	}

	_ = os.Setenv("LISTEN_ADDRESS", "0.0.0.0")
	_ = os.Setenv("TRUSTED_PROXIES", "10.0.0.0/8, 192.0.2.1, fd00::/8")
	defer func() {
		_ = os.Unsetenv("LISTEN_ADDRESS")
		_ = os.Unsetenv("TRUSTED_PROXIES")
	}()

	loaded, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig a échoué: %v", err)
	}
	if loaded.ListenAddress != "0.0.0.0" {
		t.Errorf("ListenAddress attendu '0.0.0.0', obtenu %q", loaded.ListenAddress)
	}
	if len(loaded.TrustedProxies) != 3 || loaded.TrustedProxies[1].String() != "192.0.2.1/32" {
		t.Errorf("TrustedProxies inattendus: %v", loaded.TrustedProxies)
	}
}

func TestConfig_TrustProxyRemoved(t *testing.T) {
	_ = os.Setenv("TRUST_PROXY", "true")
	defer os.Unsetenv("TRUST_PROXY")
	if _, err := LoadConfig(); err == nil {
		t.Fatal("TRUST_PROXY doit être refusée : elle laissait tout client forger X-Forwarded-For")
	}
}

func TestConfig_SecurityValidations(t *testing.T) {
	base := func() *Config {
		return &Config{Port: 8080, MaxPayloadBytes: 1 << 20, ReadTimeout: time.Second, WriteTimeout: time.Second,
			IdleTimeout: time.Second, Algorithm: "ML-KEM-768", Environment: "test", TLSMinVersion: tlsVersion13}
	}
	if err := base().Validate(); err != nil {
		t.Fatalf("configuration de base refusée: %v", err)
	}
	zero := &Config{Port: 8080, MaxPayloadBytes: 1, Environment: "test"}
	if err := zero.Validate(); err != nil || zero.ReadTimeout != DefaultReadTimeout || zero.IdleTimeout != DefaultIdleTimeout {
		t.Fatalf("un délai nul doit prendre la valeur par défaut, jamais 'illimité' : %v %v", err, zero.ReadTimeout)
	}
	cases := map[string]func(c *Config){
		"read timeout négatif":        func(c *Config) { c.ReadTimeout = -time.Second },
		"payload au-delà du plafond":  func(c *Config) { c.MaxPayloadBytes = MaxPayloadCeiling + 1 },
		"burst nul avec rate-limit":   func(c *Config) { c.RateLimitRPS = 10; c.RateLimitBurst = 0 },
		"socket relatif":              func(c *Config) { c.SocketPath = "pq.sock" },
		"mTLS sans TLS":               func(c *Config) { c.TLSClientCAFile = "ca.pem" },
		"clair hors loopback en prod": func(c *Config) { c.Environment = "production"; c.ListenAddress = "0.0.0.0" },
	}
	for name, mutate := range cases {
		c := base()
		mutate(c)
		if err := c.Validate(); err == nil {
			t.Errorf("%s : aurait dû être refusé", name)
		}
	}
}

func TestParseTLSVersionAndPrefixes(t *testing.T) {
	for in, want := range map[string]uint16{"1.3": tlsVersion13, "TLS1.2": tlsVersion12, "13": tlsVersion13} {
		if got, err := parseTLSVersion(in); err != nil || got != want {
			t.Errorf("parseTLSVersion(%q) = %#x, %v", in, got, err)
		}
	}
	if _, err := parseTLSVersion("1.1"); err == nil {
		t.Error("TLS 1.1 doit être refusé")
	}
	if _, err := parsePrefixes("10.0.0.0/8, nope"); err == nil {
		t.Error("une entrée invalide doit être refusée")
	}
}

func TestConfig_InvalidEnvStrictFailClosed(t *testing.T) {
	invalidCases := []struct {
		envKey string
		envVal string
	}{
		{"PORT", "invalid-port-string"},
		{"RATE_LIMIT_RPS", "invalid-float"},
		{"MAX_PAYLOAD_BYTES", "not_an_int"},
		{"MOCK_MODE", "not_a_bool"},
		{"SOCKET_MODE", "invalid_octal_9999"},
	}

	for _, tc := range invalidCases {
		_ = os.Setenv(tc.envKey, tc.envVal)
		_, err := LoadConfig()
		_ = os.Unsetenv(tc.envKey)
		if err == nil {
			t.Errorf("LoadConfig() aurait dû échouer (fail-closed) pour %s=%q", tc.envKey, tc.envVal)
		}
	}
}

func TestConfig_ComposeEnvConsistency(t *testing.T) {
	composeContent, err := os.ReadFile("../../docker-compose.yml")
	if err != nil {
		t.Skip("docker-compose.yml introuvable depuis le répertoire de test:", err)
	}
	composeStr := string(composeContent)

	requiredVars := []string{
		"PORT",
		"ALGORITHM",
		"MOCK_MODE",
		"ENVIRONMENT",
		"TRUSTED_PROXIES",
		"TLS_MIN_VERSION",
		"TLS_CLIENT_ALLOWED_NAMES",
		"INFISICAL_CA_FILE",
		"AUTH_TOKENS",
		"BIND_CLIENT_IDENTITY",
		"AUDIT_LOG",
		"MAX_CONNECTIONS",
		"SOCKET_ALLOWED_UIDS",
		"READ_TIMEOUT_SECONDS",
		"WRITE_TIMEOUT_SECONDS",
		"IDLE_TIMEOUT_SECONDS",
		"MAX_PAYLOAD_BYTES",
		"ACCESS_LOG",
		"RATE_LIMIT_RPS",
		"RATE_LIMIT_BURST",
		"SOCKET_PATH",
		"SOCKET_MODE",
		"SOCKET_GID",
		"DISABLE_TCP",
		"INFISICAL_ENABLED",
		"INFISICAL_URL",
		"INFISICAL_CLIENT_ID",
		"INFISICAL_CLIENT_SECRET",
		"INFISICAL_PROJECT_ID",
		"INFISICAL_ENV",
		"LISTEN_ADDRESS",
		"ALLOW_INSECURE_TCP",
		"TLS_CERT_FILE",
		"TLS_KEY_FILE",
		"TLS_CLIENT_CA_FILE",
	}

	for _, v := range requiredVars {
		if !strings.Contains(composeStr, v) {
			t.Errorf("Variable d'environnement attendue dans docker-compose.yml manquante: %s", v)
		}
	}
}

// TestConfig_ObservabilityOptions valide les nouvelles options d'observabilité :
// défauts, surcharge par l'environnement et rejet fail-closed des valeurs invalides.
func TestConfig_ObservabilityOptions(t *testing.T) {
	for _, k := range []string{"LOG_FORMAT", "LOG_LEVEL", "METRICS_ENABLED"} {
		t.Setenv(k, "")
		os.Unsetenv(k)
	}

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("chargement par défaut échoué: %v", err)
	}
	if cfg.LogFormat != "json" || cfg.LogLevel != "info" || !cfg.MetricsEnabled {
		t.Fatalf("défauts inattendus: format=%q level=%q metrics=%v", cfg.LogFormat, cfg.LogLevel, cfg.MetricsEnabled)
	}

	t.Setenv("LOG_FORMAT", "TEXT")
	t.Setenv("LOG_LEVEL", "Debug")
	t.Setenv("METRICS_ENABLED", "false")
	cfg, err = LoadConfig()
	if err != nil {
		t.Fatalf("chargement surchargé échoué: %v", err)
	}
	if cfg.LogFormat != "text" || cfg.LogLevel != "debug" || cfg.MetricsEnabled {
		t.Fatalf("surcharge non appliquée: format=%q level=%q metrics=%v", cfg.LogFormat, cfg.LogLevel, cfg.MetricsEnabled)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validation d'une configuration valide refusée: %v", err)
	}

	t.Setenv("LOG_FORMAT", "yaml")
	cfg, _ = LoadConfig()
	if err := cfg.Validate(); err == nil {
		t.Fatal("LOG_FORMAT invalide accepté (fail-closed attendu)")
	}

	t.Setenv("LOG_FORMAT", "json")
	t.Setenv("LOG_LEVEL", "verbose")
	cfg, _ = LoadConfig()
	if err := cfg.Validate(); err == nil {
		t.Fatal("LOG_LEVEL invalide accepté (fail-closed attendu)")
	}

	t.Setenv("METRICS_ENABLED", "peut-etre")
	if _, err := LoadConfig(); err == nil {
		t.Fatal("METRICS_ENABLED invalide accepté (fail-closed attendu)")
	}
}

func TestParseAuthTokens(t *testing.T) {
	ok, err := parseAuthTokens([]byte("app-a:" + strings.Repeat("a", 40) + ", app_b:" + strings.Repeat("b", 32)))
	if err != nil || len(ok) != 2 || ok[0].Name != "app-a" || ok[1].Name != "app_b" {
		t.Fatalf("liste valide refusée: %v %v", ok, err)
	}
	for name, spec := range map[string]string{
		"secret court":    "app:" + strings.Repeat("a", 31),
		"sans nom":        ":" + strings.Repeat("a", 40),
		"nom invalide":    "app a:" + strings.Repeat("a", 40),
		"nom en double":   "app:" + strings.Repeat("a", 40) + ",app:" + strings.Repeat("b", 40),
		"sans séparateur": strings.Repeat("a", 40),
	} {
		if _, err := parseAuthTokens([]byte(spec)); err == nil {
			t.Errorf("%s : aurait dû être refusé", name)
		}
	}
	if got, err := parseAuthTokens(nil); err != nil || got != nil {
		t.Fatalf("vide doit donner nil: %v %v", got, err)
	}
}

func TestConfig_IdentityValidations(t *testing.T) {
	base := &Config{Port: 8080, MaxPayloadBytes: 1, Environment: "test"}
	c := *base
	c.BindClientIdentity = true
	if err := c.Validate(); err == nil {
		t.Fatal("BIND_CLIENT_IDENTITY sans source d'identité doit être refusé")
	}
	c = *base
	c.SocketAllowedUIDs = []uint32{10001}
	if err := c.Validate(); err == nil {
		t.Fatal("SOCKET_ALLOWED_UIDS sans SOCKET_PATH doit être refusé")
	}
	c = *base
	c.MaxConnections = -1
	if err := c.Validate(); err == nil {
		t.Fatal("MAX_CONNECTIONS négatif doit être refusé")
	}
}
