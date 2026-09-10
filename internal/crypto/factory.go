package crypto

import (
	"bytes"
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"log"
	"strings"

	"pq-crypto-service/internal/keystore"
)

type KeyExporter interface {
	ExportKeys() (pk, sk []byte, err error)
}

var (
	ErrSecretNotFound    = keystore.ErrSecretNotFound
	ErrPartialKeypair    = keystore.ErrPartialKeypair
	ErrBootstrapConflict = errors.New("conflit de bootstrap concurrent détecté dans le gestionnaire de secrets")
)

type EngineOptions struct {
	Algorithm            string
	Environment          string
	MockMode             bool
	AllowLegacyEnvelopes bool
}

func BuildEngine(ctx context.Context, opts EngineOptions, store keystore.Store) (Engine, error) {
	isProd := strings.EqualFold(opts.Environment, "production") || strings.EqualFold(opts.Environment, "prod")
	if isProd {
		if opts.MockMode {
			return nil, fmt.Errorf("FATAL: MOCK_MODE interdit en production (ENVIRONMENT=%s)", opts.Environment)
		}
		if suite, err := LookupSuite(opts.Algorithm); err == nil && suite.ID == SuiteMock {
			return nil, fmt.Errorf("FATAL: suite simulée %s interdite en production (ENVIRONMENT=%s)", suite.Name, opts.Environment)
		}
	}

	if opts.MockMode {
		log.Printf("[CRYPTO] Démarrage en MODE SIMULATION - Environnement: %s", opts.Environment)
		return NewMockEngineWithLegacy(opts.AllowLegacyEnvelopes), nil
	}

	if store != nil {
		return buildEngineWithStore(ctx, opts, store)
	}

	log.Println("[CRYPTO] MODE ZERO-PERSISTENCE : Clés générées en RAM exclusivement (aucune écriture disque).")
	return buildEngine(opts.Algorithm, nil, nil, opts.AllowLegacyEnvelopes)
}

func buildEngine(algo string, pk, sk []byte, allowLegacy bool) (Engine, error) {
	if algo == "" {
		algo = "ML-KEM-1024"
	}
	if pk == nil || sk == nil {
		suite, err := LookupSuite(algo)
		if err != nil {
			return nil, err
		}
		log.Printf("[CRYPTO] Initialisation du KEM %s...", suite.KEMName)
	}
	return NewEngineWithKeysAndPolicy(algo, pk, sk, allowLegacy)
}

func buildEngineWithStore(ctx context.Context, opts EngineOptions, store keystore.Store) (Engine, error) {
	pkBytes, skBytes, fetchErr := store.FetchKeys(ctx)
	if fetchErr == nil {
		log.Println("[KEYSTORE] Clés existantes récupérées depuis le coffre (en RAM, zéro disque) !")
		defer Zeroize(skBytes)

		engine, err := buildEngine(opts.Algorithm, pkBytes, skBytes, opts.AllowLegacyEnvelopes)
		if err != nil {
			return nil, fmt.Errorf("initialisation du moteur avec clés persistées: %w", err)
		}
		if err := selfTestEngine(ctx, engine); err != nil {
			return nil, fmt.Errorf("FATAL: échec du self-test: %w", err)
		}
		log.Println("[KEYSTORE] Self-test cryptographique validé : moteur opérationnel.")
		return engine, nil
	}

	if errors.Is(fetchErr, ErrPartialKeypair) {
		return nil, fmt.Errorf("FATAL: état de coffre-fort partiel (%w). Régénération interdite", fetchErr)
	}
	if !errors.Is(fetchErr, ErrSecretNotFound) {
		return nil, fmt.Errorf("échec critique de récupération des clés: %w", fetchErr)
	}

	log.Printf("[KEYSTORE] Coffre vierge (%v). Génération de la paire initiale...", fetchErr)
	engine, err := buildEngine(opts.Algorithm, nil, nil, opts.AllowLegacyEnvelopes)
	if err != nil {
		return nil, err
	}

	exporter, ok := engine.(KeyExporter)
	if !ok {
		return nil, fmt.Errorf("le moteur %s ne supporte pas l'export de clés", opts.Algorithm)
	}
	pk, sk, expErr := exporter.ExportKeys()
	if expErr != nil {
		return nil, fmt.Errorf("erreur export clés: %w", expErr)
	}
	defer Zeroize(sk)

	if storeErr := store.StoreKeys(ctx, pk, sk); storeErr != nil {
		return nil, fmt.Errorf("FATAL: échec sauvegarde clés dans le coffre: %w", storeErr)
	}
	log.Println("[KEYSTORE] Paire de clés initiale transmise au coffre.")

	reReadPK, reReadSK, reErr := store.FetchKeys(ctx)
	if reErr != nil {
		return nil, fmt.Errorf("FATAL: échec relecture post-bootstrap: %w", reErr)
	}
	defer Zeroize(reReadSK)

	if !bytes.Equal(pk, reReadPK) || subtle.ConstantTimeCompare(sk, reReadSK) != 1 {
		return nil, fmt.Errorf("%w: divergence locale/coffre (course concurrente)", ErrBootstrapConflict)
	}

	if err := selfTestEngine(ctx, engine); err != nil {
		return nil, fmt.Errorf("FATAL: échec self-test post-bootstrap: %w", err)
	}
	log.Println("[KEYSTORE] Trousseau initialisé et vérifié dans le coffre : moteur opérationnel.")
	return engine, nil
}

func selfTestEngine(ctx context.Context, engine Engine) error {
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
