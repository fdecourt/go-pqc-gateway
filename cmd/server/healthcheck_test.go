package main

import (
	"testing"

	"pq-crypto-service/internal/config"
)

func TestHealthcheckTarget_FollowsListenAddress(t *testing.T) {
	for _, tc := range []struct {
		listen string
		want   string
	}{
		{"", "http://127.0.0.1:8080/health"},
		{"0.0.0.0", "http://127.0.0.1:8080/health"},
		{"::", "http://127.0.0.1:8080/health"},
		{"127.0.0.1", "http://127.0.0.1:8080/health"},
		{"10.1.2.3", "http://10.1.2.3:8080/health"},
		{"fd00::5", "http://[fd00::5]:8080/health"},
		{"pq-gateway.internal", "http://pq-gateway.internal:8080/health"},
	} {
		_, got := healthcheckTarget(&config.Config{ListenAddress: tc.listen, Port: 8080})
		if got != tc.want {
			t.Errorf("LISTEN_ADDRESS=%q: sonde %q, attendu %q", tc.listen, got, tc.want)
		}
	}

	_, unix := healthcheckTarget(&config.Config{DisableTCP: true, SocketPath: "/tmp/pq.sock"})
	if unix != "http://unix/health" {
		t.Errorf("TCP désactivé: sonde %q, attendu le socket Unix", unix)
	}
}
