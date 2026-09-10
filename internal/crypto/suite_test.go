package crypto_test

import (
	"errors"
	"testing"

	"pq-crypto-service/internal/crypto"
)

func TestAllSuites(t *testing.T) {
	suites := crypto.AllSuites()
	if len(suites) == 0 {
		t.Fatal("AllSuites() ne doit pas retourner une liste vide")
	}

	// Vérifier que la copie défensive protège le registre interne
	suites[0].Name = "MUTATED"
	if crypto.AllSuites()[0].Name == "MUTATED" {
		t.Error("AllSuites() doit retourner une tranche indépendante (copie défensive)")
	}
}

func TestLookupSuiteByID(t *testing.T) {
	suites := crypto.AllSuites()
	for _, s := range suites {
		found, err := crypto.LookupSuiteByID(s.ID)
		if err != nil {
			t.Fatalf("LookupSuiteByID(0x%04X) a échoué: %v", uint16(s.ID), err)
		}
		if found.ID != s.ID {
			t.Errorf("ID discordante: attendu 0x%04X, obtenu 0x%04X", uint16(s.ID), uint16(found.ID))
		}
		if found.Name != s.Name {
			t.Errorf("Nom discordant: attendu %s, obtenu %s", s.Name, found.Name)
		}
	}

	// Identifiant inconnu
	unknownID := crypto.SuiteID(0x9999)
	_, err := crypto.LookupSuiteByID(unknownID)
	if err == nil {
		t.Fatal("LookupSuiteByID(0x9999) aurait dû échouer")
	}
	if !errors.Is(err, crypto.ErrUnsupportedAlgorithm) {
		t.Errorf("attendu ErrUnsupportedAlgorithm, obtenu %v", err)
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
