package main

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"strconv"
	"time"

	"pq-crypto-service/internal/config"
)

// runHealthcheck interroge /health sur l'écouteur local et renvoie le code de sortie (0 : sain).
func runHealthcheck(cfg *config.Config) int {
	client, url := healthcheckTarget(cfg)
	resp, err := client.Get(url)
	if err != nil {
		return 1
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 1
	}
	return 0
}

// healthcheckHost renvoie l'hôte joignable de l'écouteur TCP : l'adresse configurée si elle
// désigne une interface précise, le loopback si le serveur écoute sur toutes les interfaces.
func healthcheckHost(listenAddress string) string {
	ip := net.ParseIP(listenAddress)
	switch {
	case listenAddress == "", ip != nil && ip.IsUnspecified():
		return "127.0.0.1"
	default:
		return listenAddress
	}
}

// healthcheckTarget choisit le client et l'URL de la sonde : le socket Unix si TCP est
// désactivé, sinon l'écouteur TCP configuré.
func healthcheckTarget(cfg *config.Config) (*http.Client, string) {
	if cfg.DisableTCP {
		return &http.Client{
			Timeout: 2 * time.Second,
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					var d net.Dialer
					return d.DialContext(ctx, "unix", cfg.SocketPath)
				},
			},
		}, "http://unix/health"
	}
	hostPort := net.JoinHostPort(healthcheckHost(cfg.ListenAddress), strconv.Itoa(cfg.Port))
	if cfg.TLSEnabled() {
		// Sonde de liveness locale : elle vérifie que le service répond, pas son identité.
		// /health est exempté du certificat client (voir api.RequireClientCertMiddleware).
		return &http.Client{
			Timeout: 2 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: cfg.TLSMinVersion}, // #nosec G402 -- sonde locale de liveness
			},
		}, "https://" + hostPort + "/health"
	}
	return &http.Client{Timeout: 2 * time.Second}, "http://" + hostPort + "/health"
}
