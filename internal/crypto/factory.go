package crypto

import (
	"bytes"
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"log/slog"

	"pq-crypto-service/internal/keystore"
)

var (
	ErrSecretNotFound     = keystore.ErrSecretNotFound
	ErrBootstrapForbidden = keystore.ErrBootstrapForbidden
	ErrBootstrapConflict  = errors.New("conflit de bootstrap concurrent détecté dans le gestionnaire de secrets")
)

// EngineOptions paramètre la construction du moteur. AllowMock est décidé par l'appelant
// (config.IsProduction) : la règle d'environnement n'existe qu'à un seul endroit.
type EngineOptions struct {
	Algorithm string
	MockMode  bool
	AllowMock bool
}

func BuildEngine(ctx context.Context, opts EngineOptions, store keystore.Store) (Engine, error) {
	if !opts.AllowMock {
		if opts.MockMode {
			return nil, errors.New("FATAL: MOCK_MODE interdit hors environnement de développement ou de test")
		}
		if suite, err := LookupSuite(opts.Algorithm); err == nil && suite.ID == SuiteMock {
			return nil, fmt.Errorf("FATAL: suite simulée %s interdite hors environnement de développement ou de test", suite.Name)
		}
	}

	if opts.MockMode {
		engine, err := NewEngineForSuite("MOCK")
		if err != nil {
			return nil, fmt.Errorf("MOCK_MODE indisponible : binaire compilé sans le build tag \"mock\" (%w)", err)
		}
		slog.Warn("mock_mode_enabled", slog.String("warning", "aucune confidentialité : clé dérivée d'une constante"))
		return engine, nil
	}

	if store != nil {
		return buildEngineWithStore(ctx, opts, store)
	}

	slog.Info("ephemeral_keys", slog.String("detail", "paire générée en RAM, aucune persistance"))
	return NewEngineForSuite(defaultAlgorithm(opts.Algorithm))
}

// defaultAlgorithm applique la suite par défaut à un algorithme non renseigné.
func defaultAlgorithm(algo string) string {
	if algo == "" {
		return "ML-KEM-1024"
	}
	return algo
}

// buildEngineWithStore charge la paire du coffre, ou l'y crée au premier démarrage.
// Au bootstrap, la paire générée est écrite, relue, comparée, puis c'est la paire RELUE qui
// alimente le moteur : le service ne sert jamais une clé que le coffre ne détient pas.
func buildEngineWithStore(ctx context.Context, opts EngineOptions, store keystore.Store) (Engine, error) {
	algo := defaultAlgorithm(opts.Algorithm)

	pk, sk, fetchErr := store.FetchKeys(ctx)
	switch {
	case fetchErr == nil:
		slog.Info("keystore_keys_loaded")
	case errors.Is(fetchErr, ErrBootstrapForbidden):
		return nil, fmt.Errorf("FATAL: %w. Régénération interdite", fetchErr)
	case !errors.Is(fetchErr, ErrSecretNotFound):
		return nil, fmt.Errorf("échec critique de récupération des clés: %w", fetchErr)
	default:
		slog.Info("keystore_bootstrap", slog.String("algorithm", algo), slog.String("reason", fetchErr.Error()))
		var err error
		if pk, sk, err = bootstrapKeys(ctx, algo, store); err != nil {
			return nil, err
		}
	}
	defer Zeroize(sk)

	engine, err := NewEngineWithKeys(algo, pk, sk)
	if err != nil {
		return nil, fmt.Errorf("initialisation du moteur avec les clés du coffre: %w", err)
	}
	if err := selfTestEngine(ctx, engine); err != nil {
		return nil, fmt.Errorf("FATAL: échec du self-test: %w", err)
	}
	slog.Info("engine_self_test_passed")
	return engine, nil
}

// bootstrapKeys génère une paire, l'écrit dans le coffre et renvoie la paire relue,
// après avoir vérifié qu'aucune instance concurrente n'a écrit entre-temps.
func bootstrapKeys(ctx context.Context, algo string, store keystore.Store) (pk, sk []byte, err error) {
	genPK, genSK, err := GenerateKeyPair(algo)
	if err != nil {
		return nil, nil, err
	}
	defer Zeroize(genSK)

	if err := store.StoreKeys(ctx, genPK, genSK); err != nil {
		return nil, nil, fmt.Errorf("FATAL: échec sauvegarde clés dans le coffre: %w", err)
	}
	slog.Info("keystore_keys_stored")

	pk, sk, err = store.FetchKeys(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("FATAL: échec relecture post-bootstrap: %w", err)
	}
	if !bytes.Equal(genPK, pk) || subtle.ConstantTimeCompare(genSK, sk) != 1 {
		Zeroize(sk)
		return nil, nil, fmt.Errorf("%w: divergence locale/coffre (course concurrente)", ErrBootstrapConflict)
	}
	return pk, sk, nil
}

// selfTestEngine vérifie qu'un aller-retour KEM complet restitue le même secret.
func selfTestEngine(ctx context.Context, engine KeyAgreement) error {
	res, err := engine.Encapsulate(ctx, nil)
	if err != nil {
		return fmt.Errorf("encapsulate: %w", err)
	}
	defer Zeroize(res.SharedSecret)

	decapSecret, err := engine.Decapsulate(ctx, res.EncapsulatedKey)
	if err != nil {
		return fmt.Errorf("decapsulate: %w", err)
	}
	defer Zeroize(decapSecret)

	if subtle.ConstantTimeCompare(res.SharedSecret, decapSecret) != 1 {
		return errors.New("incohérence du secret partagé décapsulé lors du self-test")
	}
	return nil
}
