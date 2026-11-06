// Package main fournit le point d'entrée du serveur de passerelle cryptographique post-quantique.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
	_ "time/tzdata" // base des fuseaux horaires embarquée dans le binaire statique

	"pq-crypto-service/internal/api"
	"pq-crypto-service/internal/config"
	"pq-crypto-service/internal/crypto"
)

const (
	engineInitTimeout = 15 * time.Second
	shutdownTimeout   = 10 * time.Second
	// maxHeaderBytes borne les en-têtes d'une requête : le plus grand en-tête utile
	// (X-Encryption-Context, 4 Kio) y tient dix fois ; le défaut de net/http (1 Mio) laisserait
	// chaque connexion lente retenir autant de mémoire.
	maxHeaderBytes = 64 << 10
)

func main() {
	healthcheck := flag.Bool("healthcheck", false, "Exécute un healthcheck HTTP local et quitte avec 0 (succès) ou 1 (échec)")
	migrateKeys := flag.Bool("migrate-keys", false, "Copie la paire de KEYSTORE_MIGRATE_FROM vers KEYSTORE, vérifie, puis quitte")
	flag.Parse()

	cfg, err := config.LoadConfig()
	if err == nil {
		err = cfg.Validate()
	}
	if err != nil {
		fatal("configuration invalide", err)
	}
	// Les secrets lus dans l'environnement sont effacés du bloc initial du processus, que
	// os.Unsetenv ne touche pas (il resterait lisible dans /proc/<pid>/environ).
	if err := scrubEnviron(config.EnvironmentSecrets()...); err != nil {
		slog.Warn("environ_scrub_failed", slog.String("error", err.Error()))
	}

	// Mode sonde Docker : fonctionne dans une image scratch, sans shell ni curl.
	if *healthcheck {
		os.Exit(runHealthcheck(cfg))
	}

	setupLogging(cfg)
	if *migrateKeys {
		err := runKeyMigration(cfg)
		cfg.WipeSecrets()
		if err != nil {
			fatal("migration des clés", err)
		}
		return
	}
	if err := run(cfg); err != nil {
		fatal("arrêt sur erreur", err)
	}
	slog.Info("service_stopped")
}

// fatal journalise une erreur fatale et termine le processus.
func fatal(msg string, err error) {
	slog.Error(msg, slog.String("error", err.Error()))
	os.Exit(1)
}

// run construit le moteur et le serveur, sert jusqu'à un signal d'arrêt, puis s'arrête proprement.
func run(cfg *config.Config) error {
	slog.Info("service_starting",
		slog.String("service", "pq-crypto-service"),
		slog.String("version", config.ServiceVersion),
		slog.String("environment", cfg.Environment),
		slog.Bool("production", cfg.IsProduction()),
		slog.String("algorithm", cfg.Algorithm),
		slog.Bool("mock_mode", cfg.MockMode),
		slog.Int("port", cfg.Port),
		slog.String("socket_path", cfg.SocketPath),
		slog.Bool("disable_tcp", cfg.DisableTCP),
		slog.Int64("max_payload_bytes", cfg.MaxPayloadBytes),
		slog.Bool("metrics_enabled", cfg.MetricsEnabled),
	)

	crypto.HardenProcess()
	warnMemoryBudget(cfg, configureMemoryLimit(cgroupMemoryFiles))
	slog.Info("secret_erasure", slog.Bool("runtime_secret", crypto.SecretErasure))
	if !crypto.SecretErasure && cfg.IsProduction() {
		slog.Warn("secret_erasure_disabled", slog.String("detail",
			"binaire compilé sans GOEXPERIMENT=runtimesecret : les temporaires cryptographiques internes ne sont pas effacés"))
	}

	if !crypto.HardwareAES() {
		slog.Warn("software_aes", slog.String("detail",
			"pas d'AES matériel (AES-NI / ARMv8 Crypto) : l'implémentation logicielle n'est pas en temps constant"))
	}

	engine, err := buildEngine(cfg)
	cfg.WipeSecrets() // les identifiants du coffre ne servent qu'au démarrage
	if err != nil {
		return fmt.Errorf("initialisation du moteur cryptographique: %w", err)
	}
	slog.Info("engine_ready", slog.String("suite", engine.Name()), slog.String("kid", engine.KeyID()))

	router := api.NewRouter(cfg, engine)
	defer router.Close()
	srv := newHTTPServer(cfg, router)

	listeners, err := openListeners(cfg)
	if err != nil {
		return err
	}
	defer removeSocket(cfg)

	return serve(srv, listeners)
}

// buildEngine instancie le moteur, adossé à Infisical si celui-ci est activé.
func buildEngine(cfg *config.Config) (crypto.Engine, error) {
	store, err := openKeystore(cfg, cfg.Keystore)
	if err != nil {
		return nil, err
	}
	if store == nil && cfg.IsProduction() && !cfg.MockMode {
		slog.Warn("keystore_disabled", slog.String("detail",
			"aucun coffre (KEYSTORE) : paire éphémère, toute donnée chiffrée deviendra illisible au redémarrage"))
	}

	ctx, cancel := context.WithTimeout(context.Background(), engineInitTimeout)
	defer cancel()
	engine, err := crypto.BuildEngine(ctx, crypto.EngineOptions{
		Algorithm: cfg.Algorithm,
		MockMode:  cfg.MockMode,
		AllowMock: !cfg.IsProduction(),
	}, store)
	closeKeystore(store) // plus aucun appel au coffre ensuite : identifiants effacés, jeton révoqué
	return engine, err
}

// newHTTPServer configure les délais (anti-Slowloris) et la taille maximale des en-têtes.
func newHTTPServer(cfg *config.Config, handler http.Handler) *http.Server {
	return &http.Server{
		Handler:           handler,
		ReadTimeout:       cfg.ReadTimeout,
		ReadHeaderTimeout: 3 * time.Second,
		WriteTimeout:      cfg.WriteTimeout,
		IdleTimeout:       cfg.IdleTimeout,
		MaxHeaderBytes:    maxHeaderBytes,
		ConnContext:       connContext,
	}
}

// serve sert sur chaque écouteur jusqu'à un signal d'arrêt ou la défaillance d'un écouteur,
// puis arrête le serveur proprement (fermeture forcée au-delà de shutdownTimeout).
func serve(srv *http.Server, listeners []net.Listener) error {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signals)

	errs := make(chan error, len(listeners))
	for _, ln := range listeners {
		go func(l net.Listener) {
			if err := srv.Serve(l); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errs <- fmt.Errorf("écouteur %s: %w", l.Addr(), err)
			}
		}(ln)
	}

	var serveErr error
	select {
	case sig := <-signals:
		slog.Info("shutdown_signal", slog.String("signal", sig.String()))
	case serveErr = <-errs:
		slog.Error("listener_failed", slog.String("error", serveErr.Error()))
	}

	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		slog.Error("graceful_shutdown_failed", slog.String("error", err.Error()))
		_ = srv.Close()
	}
	return serveErr
}
