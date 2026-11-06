package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"pq-crypto-service/internal/config"
)

// serverTLSConfig charge le certificat serveur et, en mTLS, les autorités des certificats clients.
//
// TLS 1.3 par défaut (TLS_MIN_VERSION=1.2 pour l'abaisser), avec l'échange de clé hybride
// X25519MLKEM768 en premier : le transport d'une passerelle post-quantique ne doit pas être
// le maillon classique. Seul HTTP/1.1 est négocié.
//
// ClientAuth vaut VerifyClientCertIfGiven : tout certificat présenté est vérifié pendant la
// poignée de main, mais son absence n'interrompt pas la connexion. L'exigence est appliquée
// par api.RequireClientCertMiddleware sur toutes les routes sauf /health, ce qui laisse la
// sonde de liveness fonctionner sans identité cliente.
func serverTLSConfig(cfg *config.Config) (*tls.Config, error) {
	warnIfKeyFileExposed(cfg.TLSKeyFile)
	cert, err := tls.LoadX509KeyPair(filepath.Clean(cfg.TLSCertFile), filepath.Clean(cfg.TLSKeyFile))
	if err != nil {
		return nil, fmt.Errorf("chargement du certificat TLS: %w", err)
	}
	tlsCfg := &tls.Config{
		MinVersion:       cfg.TLSMinVersion,
		Certificates:     []tls.Certificate{cert},
		NextProtos:       []string{"http/1.1"},
		CurvePreferences: []tls.CurveID{tls.X25519MLKEM768, tls.X25519, tls.CurveP256},
	}
	if cfg.MTLSEnabled() {
		pem, err := os.ReadFile(filepath.Clean(cfg.TLSClientCAFile))
		if err != nil {
			return nil, fmt.Errorf("lecture de TLS_CLIENT_CA_FILE: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("TLS_CLIENT_CA_FILE ne contient aucun certificat PEM valide")
		}
		tlsCfg.ClientCAs = pool
		tlsCfg.ClientAuth = tls.VerifyClientCertIfGiven
		if len(cfg.TLSClientAllowedNames) == 0 {
			slog.Warn("mtls_any_client_accepted", slog.String("detail",
				"TLS_CLIENT_ALLOWED_NAMES vide : tout certificat émis par la CA cliente peut déchiffrer"))
		}
	}
	return tlsCfg, nil
}

// warnIfKeyFileExposed signale une clé privée TLS lisible par d'autres utilisateurs. Simple
// avertissement : les secrets montés par un orchestrateur sont souvent en 0444.
func warnIfKeyFileExposed(path string) {
	fi, err := os.Stat(filepath.Clean(path))
	if err != nil {
		return
	}
	if fi.Mode().Perm()&0o077 != 0 {
		slog.Warn("tls_key_file_permissions", slog.String("path", path),
			slog.String("mode", fmt.Sprintf("%#o", fi.Mode().Perm())),
			slog.String("detail", "la clé privée TLS est lisible par le groupe ou les autres utilisateurs"))
	}
}
