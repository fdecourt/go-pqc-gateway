package crypto_test

import (
	"errors"
	"testing"

	"pq-crypto-service/internal/crypto"
)

// TestSuites_GenerateAndLoad vérifie, pour chaque suite publiée, que la paire générée est
// acceptée par FromKeys et que le moteur obtenu porte l'identité de la suite.
func TestSuites_GenerateAndLoad(t *testing.T) {
	for _, name := range []string{
		"ML-KEM-768", "ML-KEM-1024", "DUAL-X25519+ML-KEM-768", "DUAL-X25519+ML-KEM-1024",
	} {
		suite, err := crypto.LookupSuite(name)
		if err != nil {
			t.Fatalf("LookupSuite(%s): %v", name, err)
		}
		pk, sk, err := crypto.GenerateKeyPair(name)
		if err != nil {
			t.Fatalf("GenerateKeyPair(%s): %v", name, err)
		}
		engine, err := crypto.NewEngineWithKeys(name, pk, sk)
		if err != nil {
			t.Fatalf("NewEngineWithKeys(%s): %v", name, err)
		}
		if engine.SuiteID() != suite.ID || engine.Name() != suite.Name {
			t.Errorf("%s: moteur %s (0x%04X), attendu %s (0x%04X)", name, engine.Name(), uint16(engine.SuiteID()), suite.Name, uint16(suite.ID))
		}
		if engine.IsMock() != (suite.ID == crypto.SuiteMock) {
			t.Errorf("%s: IsMock incohérent", name)
		}
	}
}

func TestLookupSuite(t *testing.T) {
	// Lookup par nom complet
	s, err := crypto.LookupSuite("ML-KEM-768+AES-256-GCM")
	if err != nil || s.ID != crypto.SuiteMLKEM768_AES256GCM {
		t.Errorf("LookupSuite par nom complet a échoué: %v", err)
	}

	// Lookup par alias
	sAlias, err := crypto.LookupSuite("DUAL-HYBRID")
	if err != nil || sAlias.ID != crypto.SuiteDual768_AES256GCM {
		t.Errorf("LookupSuite par alias a échoué: %v", err)
	}

	// Lookup invalide
	_, err = crypto.LookupSuite("INVALID_ALGO")
	if !errors.Is(err, crypto.ErrUnsupportedAlgorithm) {
		t.Errorf("attendu ErrUnsupportedAlgorithm, obtenu %v", err)
	}
}
