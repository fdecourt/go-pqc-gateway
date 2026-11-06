package main

import (
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"

	"pq-crypto-service/internal/config"
)

// openListeners ouvre l'écouteur TCP et/ou le socket Unix demandés par la configuration.
// En cas d'échec, les écouteurs déjà ouverts sont refermés.
func openListeners(cfg *config.Config) (listeners []net.Listener, err error) {
	defer func() {
		if err != nil {
			for _, ln := range listeners {
				_ = ln.Close()
			}
		}
	}()

	if !cfg.DisableTCP {
		ln, err := listenTCP(cfg)
		if err != nil {
			return listeners, err
		}
		listeners = append(listeners, newLimitListener(ln, cfg.MaxConnections))
		slog.Info("listening", slog.String("transport", "tcp"), slog.String("address", ln.Addr().String()),
			slog.Bool("tls", cfg.TLSEnabled()), slog.Bool("mtls", cfg.MTLSEnabled()), slog.Int("max_connections", cfg.MaxConnections))
		if !cfg.TLSEnabled() && cfg.AllowInsecureTCP {
			slog.Warn("insecure_tcp_allowed", slog.String("detail",
				"ALLOW_INSECURE_TCP=true : clés et clairs circulent en HTTP non chiffré sur cet écouteur"))
		}
	}

	if cfg.SocketPath != "" {
		ln, err := listenUnix(cfg)
		if err != nil {
			return listeners, err
		}
		guarded, err := newPeerCredListener(ln, cfg.SocketAllowedUIDs)
		if err != nil {
			_ = ln.Close()
			return listeners, err
		}
		listeners = append(listeners, newLimitListener(guarded, cfg.MaxConnections))
		slog.Info("listening", slog.String("transport", "unix"), slog.String("path", cfg.SocketPath),
			slog.String("mode", fmt.Sprintf("%#o", cfg.SocketMode)), slog.Any("allowed_uids", cfg.SocketAllowedUIDs))
	}
	return listeners, nil
}

// listenTCP ouvre l'écouteur TCP, enveloppé dans TLS si un certificat est configuré.
func listenTCP(cfg *config.Config) (net.Listener, error) {
	var tlsCfg *tls.Config
	if cfg.TLSEnabled() {
		var err error
		if tlsCfg, err = serverTLSConfig(cfg); err != nil {
			return nil, err
		}
	}
	ln, err := net.Listen("tcp", cfg.Address())
	if err != nil {
		return nil, fmt.Errorf("écoute TCP sur %s: %w", cfg.Address(), err)
	}
	if tlsCfg != nil {
		ln = tls.NewListener(ln, tlsCfg)
	}
	return ln, nil
}

// listenUnix crée le socket Unix : répertoire parent, suppression d'un socket obsolète
// (jamais d'un autre type de fichier), permissions et groupe propriétaire.
func listenUnix(cfg *config.Config) (net.Listener, error) {
	path := cfg.SocketPath
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return nil, fmt.Errorf("création du répertoire du socket %s: %w", dir, err)
		}
	}
	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("%s existe et n'est pas un socket Unix : refus de suppression", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, fmt.Errorf("suppression du socket obsolète %s: %w", path, err)
		}
	}

	var ln net.Listener
	err := withSocketUmask(cfg.SocketMode, func() (err error) {
		ln, err = net.Listen("unix", path)
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("écoute sur le socket Unix %s: %w", path, err)
	}
	if err := os.Chmod(path, os.FileMode(cfg.SocketMode)); err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("permissions %#o sur le socket %s: %w", cfg.SocketMode, path, err)
	}
	if cfg.SocketGID >= 0 {
		if err := os.Chown(path, -1, cfg.SocketGID); err != nil {
			_ = ln.Close()
			return nil, fmt.Errorf("GID %d sur le socket %s: %w", cfg.SocketGID, path, err)
		}
	}
	return ln, nil
}

// removeSocket supprime le fichier du socket Unix à l'arrêt.
func removeSocket(cfg *config.Config) {
	if cfg.SocketPath == "" {
		return
	}
	// Seul un socket est supprimé : si le chemin a été remplacé entre-temps par autre chose,
	// ce n'est plus le nôtre.
	if fi, err := os.Lstat(cfg.SocketPath); err == nil && fi.Mode()&os.ModeSocket != 0 {
		_ = os.Remove(cfg.SocketPath)
	}
}
