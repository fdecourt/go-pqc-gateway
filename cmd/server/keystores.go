package main

import (
	"context"
	"fmt"
	"log/slog"
	"runtime"
	"time"

	"pq-crypto-service/internal/config"
	"pq-crypto-service/internal/keystore"
	"pq-crypto-service/internal/secmem"

	// Coffres de clés disponibles (KEYSTORE). Chaque paquet s'enregistre dans son init().
	// Ajouter un coffre (KMS de cloud, autre gestionnaire de secrets) : écrire un paquet qui
	// respecte le contrat de keystore.Backend, puis l'ajouter ici. Rien d'autre ne change.
	_ "pq-crypto-service/internal/infisical"
	_ "pq-crypto-service/internal/openbao"
)

// openKeystore ouvre le coffre nommé ; nil, nil si aucun coffre n'est configuré.
func openKeystore(cfg *config.Config, name string) (keystore.Store, error) {
	if name == "" {
		return nil, nil
	}
	backend, err := keystore.Lookup(name)
	if err != nil {
		return nil, err
	}
	var store keystore.Store
	secmem.Do(func() { store, err = backend.Open(cfg.KeystoreSettings()) })
	if err != nil {
		return nil, fmt.Errorf("coffre %s: %w", backend.Name, err)
	}
	slog.Info("keystore_enabled", slog.String("backend", backend.Name), slog.Bool("runtime_secret", secmem.Erasure))
	// Chaque échange avec le coffre s'exécute sous runtime/secret (voir keystore.WithErasure).
	return keystore.WithErasure(store), nil
}

// eraseSweepDelay laisse aux goroutines du transport HTTP le temps de se terminer avant le
// second passage du ramasse-miettes : leurs tampons ne sont libérables qu'ensuite.
const eraseSweepDelay = 2 * time.Second

// closeKeystore efface les identifiants que le coffre garde (jeton, secret), puis force des
// passages du ramasse-miettes : les allocations faites sous runtime/secret pendant les échanges
// avec le coffre (chaînes d'en-tête, tampons HTTP et TLS) ne sont effacées qu'à leur
// libération, qu'un service peu chargé pourrait retarder longtemps après le démarrage. Le
// premier passage est immédiat ; le second, différé, couvre les tampons des goroutines de
// connexion qui se terminent juste après la dernière requête.
func closeKeystore(store keystore.Store) {
	if store == nil {
		return
	}
	if closer, ok := store.(interface{ Close() }); ok {
		closer.Close()
	}
	runtime.GC()
	time.AfterFunc(eraseSweepDelay, runtime.GC)
}

// runKeyMigration copie la paire de KEYSTORE_MIGRATE_FROM vers KEYSTORE (voir keystore.Migrate).
func runKeyMigration(cfg *config.Config) error {
	if cfg.KeystoreMigrateFrom == "" || cfg.Keystore == "" {
		return fmt.Errorf("-migrate-keys exige KEYSTORE_MIGRATE_FROM (source) et KEYSTORE (cible)")
	}
	src, err := openKeystore(cfg, cfg.KeystoreMigrateFrom)
	if err != nil {
		return err
	}
	defer closeKeystore(src)
	dst, err := openKeystore(cfg, cfg.Keystore)
	if err != nil {
		return err
	}
	defer closeKeystore(dst)

	ctx, cancel := context.WithTimeout(context.Background(), engineInitTimeout)
	defer cancel()
	result, err := keystore.Migrate(ctx, src, dst)
	if err != nil {
		return err
	}
	outcome := "copiée et vérifiée"
	if result == keystore.MigrationAlreadyPresent {
		outcome = "déjà présente, identique"
	}
	slog.Info("keys_migrated",
		slog.String("from", cfg.KeystoreMigrateFrom),
		slog.String("to", cfg.Keystore),
		slog.String("outcome", outcome),
		slog.String("detail", "la source est conservée : la supprimer seulement après validation du service sur la cible"))
	return nil
}
