package tests

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"pq-crypto-service/internal/api"
	"pq-crypto-service/internal/config"
	"pq-crypto-service/internal/crypto"
)

func TestUnixDomainSocket_Roundtrip(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "pq-sock-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	sockPath := filepath.Join(tmpDir, "test.sock")

	cfg := &config.Config{
		Port:            8080,
		SocketPath:      sockPath,
		DisableTCP:      true,
		MaxPayloadBytes: 10 * 1024 * 1024,
	}

	engine := crypto.NewMockEngine()
	router := api.NewRouter(cfg, engine)
	defer router.Close()

	server := &http.Server{
		Handler: router,
	}

	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("failed to listen on unix socket: %v", err)
	}
	defer ln.Close()

	go func() {
		_ = server.Serve(ln)
	}()
	defer func() {
		_ = server.Close()
	}()

	// Test client over Unix socket
	client := &http.Client{
		Timeout: 2 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", sockPath)
			},
		},
	}

	resp, err := client.Get("http://unix/health")
	if err != nil {
		t.Fatalf("GET /health over unix socket failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", resp.StatusCode)
	}

	var h api.HealthResponse
	if err := json.NewDecoder(resp.Body).Decode(&h); err != nil {
		t.Fatalf("failed to decode health response: %v", err)
	}
	if h.Status != "healthy" {
		t.Errorf("expected status healthy, got %s", h.Status)
	}
}
