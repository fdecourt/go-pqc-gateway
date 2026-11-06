//go:build !mock

package crypto_test

import (
	"context"
	"errors"
	"testing"

	"pq-crypto-service/internal/crypto"
)

// TestMock_AbsentFromReleaseBuild vérifie que, sans le build tag "mock", la suite simulée
// n'existe pas : ni MOCK_MODE ni ALGORITHM=MOCK ne peuvent l'activer, même hors production.
func TestMock_AbsentFromReleaseBuild(t *testing.T) {
	if _, err := crypto.LookupSuite("MOCK"); !errors.Is(err, crypto.ErrUnsupportedAlgorithm) {
		t.Fatalf("suite MOCK résolue dans un binaire sans tag mock: %v", err)
	}
	for _, opts := range []crypto.EngineOptions{
		{Algorithm: "ML-KEM-768", MockMode: true, AllowMock: true},
		{Algorithm: "MOCK", AllowMock: true},
	} {
		if _, err := crypto.BuildEngine(context.Background(), opts, nil); err == nil {
			t.Fatalf("moteur simulé construit sans tag mock: %+v", opts)
		}
	}
}
