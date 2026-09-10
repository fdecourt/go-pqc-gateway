package crypto_test

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"

	"pq-crypto-service/internal/crypto"
)

type mockSecretManager struct {
	mu         sync.Mutex
	fetchFunc  func(ctx context.Context) ([]byte, []byte, error)
	storeFunc  func(ctx context.Context, pkBytes []byte, skBytes []byte) error
	storedPK   []byte
	storedSK   []byte
	storeCalls int
	fetchCalls int
}

func (m *mockSecretManager) FetchKeys(ctx context.Context) ([]byte, []byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.fetchCalls++
	if m.fetchFunc != nil {
		return m.fetchFunc(ctx)
	}
	if m.storedPK == nil && m.storedSK == nil {
		return nil, nil, crypto.ErrSecretNotFound
	}
	if m.storedPK == nil || m.storedSK == nil {
		return nil, nil, crypto.ErrPartialKeypair
	}
	pkCopy := make([]byte, len(m.storedPK))
	copy(pkCopy, m.storedPK)
	skCopy := make([]byte, len(m.storedSK))
	copy(skCopy, m.storedSK)
	return pkCopy, skCopy, nil
}

func (m *mockSecretManager) StoreKeys(ctx context.Context, pkBytes []byte, skBytes []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.storeCalls++
	if m.storeFunc != nil {
		return m.storeFunc(ctx, pkBytes, skBytes)
	}
	m.storedPK = make([]byte, len(pkBytes))
	copy(m.storedPK, pkBytes)
	m.storedSK = make([]byte, len(skBytes))
	copy(m.storedSK, skBytes)
	return nil
}

// TestBuildEngine_EphemeralMode vérifie que le mode éphémère (sans infisical) génère des clés en RAM
func TestBuildEngine_EphemeralMode(t *testing.T) {
	ctx := context.Background()
	opts := crypto.EngineOptions{
		Algorithm:   "ML-KEM-768",
		Environment: "test",
	}

	engine, err := crypto.BuildEngine(ctx, opts, nil)
	if err != nil {
		t.Fatalf("échec BuildEngine éphémère: %v", err)
	}
	if engine == nil {
		t.Fatal("engine nil")
	}

	res, err := engine.Encapsulate(ctx, nil)
	if err != nil {
		t.Fatalf("encapsulate: %v", err)
	}
	decap, err := engine.Decapsulate(ctx, res.EncapsulatedKey)
	if err != nil {
		t.Fatalf("decapsulate: %v", err)
	}
	if !bytes.Equal(res.SharedSecret, decap) {
		t.Fatal("secret mismatch")
	}
}

// TestBuildEngine_VaultCleanBootstrap vérifie le flux bootstrap :
// coffre vierge -> génération -> store -> re-read verify -> ready
func TestBuildEngine_VaultCleanBootstrap(t *testing.T) {
	ctx := context.Background()
	sm := &mockSecretManager{}

	opts := crypto.EngineOptions{
		Algorithm:   "ML-KEM-768",
		Environment: "test",
	}

	engine, err := crypto.BuildEngine(ctx, opts, sm)
	if err != nil {
		t.Fatalf("échec BuildEngine bootstrap: %v", err)
	}
	if engine == nil {
		t.Fatal("engine nil")
	}

	if sm.storeCalls != 1 {
		t.Errorf("attendu 1 appel StoreKeys, obtenu %d", sm.storeCalls)
	}
	// FetchKeys est appelé 2 fois : d'abord pour vérifier l'existant, puis pour re-read verification
	if sm.fetchCalls != 2 {
		t.Errorf("attendu 2 appels FetchKeys (initial + re-read), obtenu %d", sm.fetchCalls)
	}
	if sm.storedPK == nil || sm.storedSK == nil {
		t.Fatal("clés non stockées dans le secret manager")
	}
}

// TestBuildEngine_ExistingKeys vérifie le chargement de clés existantes avec self-test immédiat
func TestBuildEngine_ExistingKeys(t *testing.T) {
	ctx := context.Background()
	opts := crypto.EngineOptions{
		Algorithm:   "ML-KEM-768",
		Environment: "test",
	}

	// Préparer un vault avec une paire de clés
	firstEngine, err := crypto.NewEngineForSuite("ML-KEM-768")
	if err != nil {
		t.Fatalf("NewEngineForSuite: %v", err)
	}
	exporter := firstEngine.(crypto.KeyExporter)
	pk, sk, err := exporter.ExportKeys()
	if err != nil {
		t.Fatalf("ExportKeys: %v", err)
	}

	sm := &mockSecretManager{
		storedPK: pk,
		storedSK: sk,
	}

	secondEngine, err := crypto.BuildEngine(ctx, opts, sm)
	if err != nil {
		t.Fatalf("chargement des clés existantes échoué: %v", err)
	}

	// Aucune nouvelle écriture ne doit avoir eu lieu
	if sm.storeCalls != 0 {
		t.Errorf("attendu 0 StoreKeys sur clés existantes, obtenu %d", sm.storeCalls)
	}
	if sm.fetchCalls != 1 {
		t.Errorf("attendu 1 FetchKeys, obtenu %d", sm.fetchCalls)
	}

	// Les clés publiques doivent correspondre
	if !bytes.Equal(firstEngine.GetPublicKey(), secondEngine.GetPublicKey()) {
		t.Error("divergence des clés publiques entre instances")
	}
}

// TestBuildEngine_PartialKeypairAbort vérifie qu'une demi-clé existante provoque un rejet fatal
// et refuse catégoriquement toute régénération automatique de clé (protection anti-perte).
func TestBuildEngine_PartialKeypairAbort(t *testing.T) {
	ctx := context.Background()
	opts := crypto.EngineOptions{
		Algorithm:   "ML-KEM-768",
		Environment: "test",
	}

	sm := &mockSecretManager{
		fetchFunc: func(ctx context.Context) ([]byte, []byte, error) {
			return nil, nil, crypto.ErrPartialKeypair
		},
	}

	_, err := crypto.BuildEngine(ctx, opts, sm)
	if err == nil {
		t.Fatal("FATAL ATTENDU: BuildEngine aurait dû échouer sur ErrPartialKeypair")
	}
	if !errors.Is(err, crypto.ErrPartialKeypair) {
		t.Fatalf("erreur attendue ErrPartialKeypair, obtenu: %v", err)
	}
	if sm.storeCalls != 0 {
		t.Fatal("VIOLATION DE SÉCURITÉ: StoreKeys ne doit JAMAIS être appelé en cas d'état partiel")
	}
}

// TestBuildEngine_ConcurrentBootstrapConflict vérifie que si une autre instance a écrit
// dans le coffre pendant le bootstrap (détecté par la re-lecture), le démarrage est bloqué.
func TestBuildEngine_ConcurrentBootstrapConflict(t *testing.T) {
	ctx := context.Background()
	opts := crypto.EngineOptions{
		Algorithm:   "ML-KEM-768",
		Environment: "test",
	}

	// Simuler un conflit : le 1er fetch retourne ErrSecretNotFound,
	// mais le second fetch (re-read de vérification) retourne des clés différentes (générées par une instance rivale).
	callCount := 0
	sm := &mockSecretManager{
		fetchFunc: func(ctx context.Context) ([]byte, []byte, error) {
			callCount++
			if callCount == 1 {
				return nil, nil, crypto.ErrSecretNotFound
			}
			// Re-read : clé d'une autre instance concurrente
			rivalEngine, _ := crypto.NewEngineForSuite("ML-KEM-768")
			rivalExp := rivalEngine.(crypto.KeyExporter)
			rPK, rSK, _ := rivalExp.ExportKeys()
			return rPK, rSK, nil
		},
	}

	_, err := crypto.BuildEngine(ctx, opts, sm)
	if err == nil {
		t.Fatal("FATAL ATTENDU: conflit de bootstrap concurrent non détecté")
	}
	if !errors.Is(err, crypto.ErrBootstrapConflict) {
		t.Fatalf("attendu ErrBootstrapConflict, obtenu: %v", err)
	}
}
