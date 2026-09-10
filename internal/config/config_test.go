package config

import (
	"os"
	"strings"
	"testing"
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
	if cfg.AllowLegacyEnvelopes != false {
		t.Errorf("AllowLegacyEnvelopes par défaut devrait être false")
	}
}

func TestConfig_SocketAndDualListener(t *testing.T) {
	// Cas 1: Socket Unix + TCP activé (Mode Dual)
	cfg := &Config{
		Port:            8080,
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
			name: "Suite Mock interdite en production",
			mutate: func(c *Config) {
				c.Environment = "production"
				c.Algorithm = "MOCK"
				c.MockMode = false
			},
			wantErr: true,
		},
		{
			name: "Algorithme non supporté",
			mutate: func(c *Config) {
				c.Algorithm = "RSA-2048"
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{
				Port:            8080,
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
	cfgDefault := &Config{Port: 8080}
	if cfgDefault.Address() != ":8080" {
		t.Errorf("Address() attendu ':8080', obtenu %q", cfgDefault.Address())
	}

	cfgListen := &Config{Port: 8080, ListenAddress: "127.0.0.1"}
	if cfgListen.Address() != "127.0.0.1:8080" {
		t.Errorf("Address() attendu '127.0.0.1:8080', obtenu %q", cfgListen.Address())
	}

	_ = os.Setenv("LISTEN_ADDRESS", "0.0.0.0")
	_ = os.Setenv("TRUST_PROXY", "true")
	defer func() {
		_ = os.Unsetenv("LISTEN_ADDRESS")
		_ = os.Unsetenv("TRUST_PROXY")
	}()

	loaded, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig a échoué: %v", err)
	}
	if loaded.ListenAddress != "0.0.0.0" {
		t.Errorf("ListenAddress attendu '0.0.0.0', obtenu %q", loaded.ListenAddress)
	}
	if !loaded.TrustProxy {
		t.Errorf("TrustProxy attendu true, obtenu %t", loaded.TrustProxy)
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
		"ALLOW_LEGACY_ENVELOPES",
		"TRUST_PROXY",
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
