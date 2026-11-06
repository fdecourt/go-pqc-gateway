package config

import (
	"os"
	"strings"
	"testing"
)

// TestConfig_TransportSecurity couvre la règle « pas de TCP en clair hors loopback en production ».
func TestConfig_TransportSecurity(t *testing.T) {
	base := func() *Config {
		return &Config{Port: 8080, MaxPayloadBytes: 1 << 20, Environment: "production", ListenAddress: "0.0.0.0"}
	}
	tests := []struct {
		name    string
		mutate  func(c *Config)
		wantErr string
	}{
		{"clair hors loopback en production refusé", func(c *Config) {}, "refusée en production"},
		{"clair sur adresse vide (toutes interfaces) refusé", func(c *Config) { c.ListenAddress = "" }, "refusée en production"},
		{"clair sur IP privée refusé", func(c *Config) { c.ListenAddress = "10.0.0.5" }, "refusée en production"},
		{"loopback IPv4 accepté", func(c *Config) { c.ListenAddress = "127.0.0.1" }, ""},
		{"loopback IPv6 accepté", func(c *Config) { c.ListenAddress = "::1" }, ""},
		{"localhost accepté", func(c *Config) { c.ListenAddress = "localhost" }, ""},
		{"TLS accepté", func(c *Config) { c.TLSCertFile, c.TLSKeyFile = "c.pem", "k.pem" }, ""},
		{"opt-in explicite accepté", func(c *Config) { c.AllowInsecureTCP = true }, ""},
		{"TCP désactivé accepté", func(c *Config) { c.DisableTCP, c.SocketPath = true, "/tmp/pq.sock" }, ""},
		{"hors production accepté", func(c *Config) { c.Environment = "development" }, ""},
		{"certificat sans clé refusé", func(c *Config) { c.TLSCertFile = "c.pem" }, "ensemble"},
		{"clé sans certificat refusée", func(c *Config) { c.TLSKeyFile = "k.pem" }, "ensemble"},
		{"mTLS sans TLS refusé", func(c *Config) { c.ListenAddress = "127.0.0.1"; c.TLSClientCAFile = "ca.pem" }, "requiert"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := base()
			tt.mutate(c)
			err := c.Validate()
			switch {
			case tt.wantErr == "" && err != nil:
				t.Fatalf("erreur inattendue: %v", err)
			case tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)):
				t.Fatalf("attendu une erreur contenant %q, obtenu %v", tt.wantErr, err)
			}
		})
	}
}

// TestConfig_DefaultListenAddressIsLoopback vérifie que, sans configuration, le service
// n'écoute que sur la boucle locale.
func TestConfig_DefaultListenAddressIsLoopback(t *testing.T) {
	_ = os.Unsetenv("LISTEN_ADDRESS")
	_ = os.Unsetenv("BIND_ADDRESS")
	cfg, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ListenAddress != "127.0.0.1" {
		t.Fatalf("adresse d'écoute par défaut %q, attendu 127.0.0.1", cfg.ListenAddress)
	}
}
