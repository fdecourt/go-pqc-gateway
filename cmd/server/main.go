// Package main fournit le point d'entrée principal du serveur de passerelle cryptographique post-quantique.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
	_ "time/tzdata" // Embarque la base de données de fuseaux horaires directement dans le binaire statique

	"pq-crypto-service/internal/api"
	"pq-crypto-service/internal/config"
	"pq-crypto-service/internal/crypto"
	"pq-crypto-service/internal/infisical"
	"pq-crypto-service/internal/keystore"
)

func main() {
	healthcheckFlag := flag.Bool("healthcheck", false, "Exécute un healthcheck HTTP local autonome et quitte avec 0 (succès) ou 1 (échec)")
	flag.Parse()

	// 1. Chargement et validation stricte de la configuration
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("[FATAL] Échec du chargement de la configuration: %v", err)
	}
	if err := cfg.Validate(); err != nil {
		log.Fatalf("[FATAL] Configuration invalide: %v", err)
	}

	// Mode Sonde de Santé Docker autonome (permet de fonctionner en conteneur scratch sans wget ni shell)
	if *healthcheckFlag {
		var client *http.Client
		var targetURL string
		if cfg.DisableTCP {
			// Healthcheck via Unix Domain Socket IPC
			client = &http.Client{
				Timeout: 2 * time.Second,
				Transport: &http.Transport{
					DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
						var d net.Dialer
						return d.DialContext(ctx, "unix", cfg.SocketPath)
					},
				},
			}
			targetURL = "http://unix/health"
		} else {
			// Healthcheck via TCP Loopback
			client = &http.Client{Timeout: 2 * time.Second}
			targetURL = fmt.Sprintf("http://127.0.0.1:%d/health", cfg.Port)
		}

		resp, err := client.Get(targetURL)
		if resp != nil && resp.Body != nil {
			defer resp.Body.Close()
		}
		if err != nil || resp.StatusCode != http.StatusOK {
			os.Exit(1)
		}
		os.Exit(0)
	}

	// Journalisation structurée. slog.SetDefault redirige également tous les appels
	// du paquet log standard vers ce handler : la sortie du service est homogène.
	level := slog.LevelInfo
	switch cfg.LogLevel {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}
	var logHandler slog.Handler
	if cfg.LogFormat == "text" {
		logHandler = slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: level})
	} else {
		logHandler = slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level})
	}
	slog.SetDefault(slog.New(logHandler))

	slog.Info("service_starting",
		slog.String("service", "pq-crypto-service"),
		slog.String("version", config.ServiceVersion),
		slog.String("environment", cfg.Environment),
		slog.String("algorithm", cfg.Algorithm),
		slog.Bool("mock_mode", cfg.MockMode),
		slog.Bool("metrics_enabled", cfg.MetricsEnabled),
	)

	// 0. Durcissement processus système (désactivation ptrace & core dumps)
	crypto.HardenProcess()

	log.Printf("[CONFIG] Env: %s | Port: %d | Socket: %q (DisableTCP=%t) | Algo: %s | MockMode: %t | MaxPayload: %d octets",
		cfg.Environment, cfg.Port, cfg.SocketPath, cfg.DisableTCP, cfg.Algorithm, cfg.MockMode, cfg.MaxPayloadBytes)

	// 2. Initialisation du KeyStore (Infisical) si activé
	var keyStore keystore.Store
	if cfg.InfisicalEnabled {
		log.Printf("[INFISICAL] Client configuré pour %s (Workspace: %s, Env: %s)",
			cfg.InfisicalURL, cfg.InfisicalProjectID, cfg.InfisicalEnv)
		keyStore = infisical.NewClient(cfg)
	}

	// 3. Construction du moteur cryptographique via Factory (SRP & DIP)
	initCtx, cancelInit := context.WithTimeout(context.Background(), 15*time.Second)
	engineOpts := crypto.EngineOptions{
		Algorithm:            cfg.Algorithm,
		Environment:          cfg.Environment,
		MockMode:             cfg.MockMode,
		AllowLegacyEnvelopes: cfg.AllowLegacyEnvelopes,
	}
	engine, err := crypto.BuildEngine(initCtx, engineOpts, keyStore)
	cancelInit()
	if err != nil {
		log.Fatalf("[FATAL] Échec d'initialisation du moteur cryptographique: %v", err)
	}

	pk := engine.GetPublicKey()
	log.Printf("[CRYPTO] Moteur prêt: %s | Clé active: %d octets", engine.Name(), len(pk))

	// 4. Initialisation du serveur HTTP durci (Protection anti-Slowloris & exhaustion mémoire)
	router := api.NewRouter(cfg, engine)
	defer router.Close()
	srv := &http.Server{
		Handler:           router,
		ReadTimeout:       cfg.ReadTimeout,
		ReadHeaderTimeout: 3 * time.Second, // Atténuation stricte des attaques par déni de service Slowloris
		WriteTimeout:      cfg.WriteTimeout,
		IdleTimeout:       cfg.IdleTimeout,
		MaxHeaderBytes:    1 << 20, // 1 Mo max pour les en-têtes
	}

	// 5. Canal d'arrêt gracieux
	shutdownChan := make(chan os.Signal, 1)
	signal.Notify(shutdownChan, os.Interrupt, syscall.SIGTERM, syscall.SIGINT)

	// 6. Initialisation et démarrage des écouteurs (TCP et/ou Unix Domain Socket IPC)
	var listeners []net.Listener

	if !cfg.DisableTCP {
		tcpLn, err := net.Listen("tcp", cfg.Address())
		if err != nil {
			log.Fatalf("[FATAL] Échec d'écoute TCP sur %s: %v", cfg.Address(), err)
		}
		listeners = append(listeners, tcpLn)
		log.Printf("[SERVER] En écoute TCP sur http://%s", cfg.Address())
	}

	if cfg.SocketPath != "" {
		if dir := filepath.Dir(cfg.SocketPath); dir != "" && dir != "." {
			if err := os.MkdirAll(dir, 0750); err != nil {
				log.Fatalf("[FATAL] Échec création répertoire socket %s: %v", dir, err)
			}
		}
		if fi, err := os.Lstat(cfg.SocketPath); err == nil {
			if fi.Mode()&os.ModeSocket == 0 {
				log.Fatalf("[FATAL] %s existe et n'est pas un socket Unix — refus de suppression", cfg.SocketPath)
			}
			if err := os.Remove(cfg.SocketPath); err != nil {
				log.Fatalf("[FATAL] Suppression socket obsolète %s: %v", cfg.SocketPath, err)
			}
		}
		unixLn, err := net.Listen("unix", cfg.SocketPath)
		if err != nil {
			log.Fatalf("[FATAL] Échec d'écoute Unix Socket sur %s: %v", cfg.SocketPath, err)
		}
		if err := os.Chmod(cfg.SocketPath, os.FileMode(cfg.SocketMode)); err != nil {
			log.Fatalf("[FATAL] Échec d'application des permissions (%#o) sur socket %s: %v", cfg.SocketMode, cfg.SocketPath, err)
		}
		if cfg.SocketGID >= 0 {
			if err := os.Chown(cfg.SocketPath, -1, cfg.SocketGID); err != nil {
				log.Fatalf("[FATAL] Échec d'assignation du GID %d sur le socket %s: %v", cfg.SocketGID, cfg.SocketPath, err)
			}
		}
		listeners = append(listeners, unixLn)
		log.Printf("[SERVER] En écoute Unix Socket IPC sur %s (permissions: %#o)", cfg.SocketPath, cfg.SocketMode)
	}

	log.Printf("[SERVER] Endpoints actifs: /health | /public-key | /encrypt | /decrypt | /wrap-key | /unwrap-key | /generate-key | /kem/encapsulate | /kem/decapsulate | /metrics (si activé)")

	errChan := make(chan error, len(listeners))
	for _, ln := range listeners {
		go func(l net.Listener) {
			if err := srv.Serve(l); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errChan <- fmt.Errorf("écouteur %s: %w", l.Addr(), err)
			}
		}(ln)
	}

	// 7. Attente et exécution de l'arrêt gracieux
	select {
	case sig := <-shutdownChan:
		log.Printf("[SHUTDOWN] Signal reçu (%s). Arrêt gracieux en cours...", sig)
	case err := <-errChan:
		log.Printf("[FATAL] Défaillance critique d'un écouteur: %v. Arrêt gracieux en cours...", err)
	}

	shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelShutdown()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Printf("[ERROR] Erreur arrêt gracieux: %v (fermeture forcée)", err)
		_ = srv.Close()
	}

	if cfg.SocketPath != "" {
		_ = os.Remove(cfg.SocketPath)
	}

	log.Println("[SHUTDOWN] Micro-service arrêté avec succès.")
}
