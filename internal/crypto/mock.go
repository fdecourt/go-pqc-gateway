package crypto

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
)

// MockKEM implémente l'interface KEM pour les tests rapides et l'environnement CI/CD.
type MockKEM struct {
	publicKey  []byte
	privateKey []byte
}

// NewMockKEM initialise un KEM de simulation.
func NewMockKEM() *MockKEM {
	return &MockKEM{
		publicKey:  []byte("MOCK_MLKEM768_PUBLIC_KEY_SIMULATED_VECTOR_FOR_TESTING_1234567890"),
		privateKey: []byte("MOCK_MLKEM768_PRIVATE_KEY_SIMULATED_VECTOR_FOR_TESTING_1234567890"),
	}
}

// Name retourne l'identifiant du Mock KEM.
func (m *MockKEM) Name() string {
	return "MOCK-ML-KEM-768"
}

// PublicKey retourne la clé publique factice.
func (m *MockKEM) PublicKey() []byte {
	res := make([]byte, len(m.publicKey))
	copy(res, m.publicKey)
	return res
}

// IsMock confirme le mode simulé.
func (m *MockKEM) IsMock() bool {
	return true
}

// ExportKeys exporte les clés factices.
func (m *MockKEM) ExportKeys() ([]byte, []byte, error) {
	priv := make([]byte, len(m.privateKey))
	copy(priv, m.privateKey)
	return m.PublicKey(), priv, nil
}

// Encapsulate simule l'encapsulation.
func (m *MockKEM) Encapsulate(ctx context.Context, recipientPK []byte) (encapKey, sharedSecret []byte, err error) {
	targetPK := m.publicKey
	if len(recipientPK) > 0 {
		targetPK = recipientPK
	}

	h := sha256.Sum256(targetPK)
	sharedSecret = make([]byte, 32)
	copy(sharedSecret, h[:])

	encapKey = append([]byte("MOCK_ENCAP:"), h[:16]...)
	return encapKey, sharedSecret, nil
}

// Decapsulate simule la décapsulation.
func (m *MockKEM) Decapsulate(ctx context.Context, encapKey []byte) (sharedSecret []byte, err error) {
	if !bytes.HasPrefix(encapKey, []byte("MOCK_ENCAP:")) {
		return nil, fmt.Errorf("%w: échec décapsulation simulée", ErrDecapsulationFailed)
	}

	h := sha256.Sum256(m.publicKey)
	sharedSecret = make([]byte, 32)
	copy(sharedSecret, h[:])
	return sharedSecret, nil
}

// NewMockEngine initialise un moteur Engine hybride complet basé sur MockKEM (strict par défaut).
func NewMockEngine() Engine {
	return NewMockEngineWithLegacy(false)
}

// NewMockEngineWithLegacy initialise un moteur Engine hybride simulé avec politique legacy configurable.
func NewMockEngineWithLegacy(allowLegacy bool) Engine {
	s, _ := LookupSuite("MOCK")
	return newHybridEngine(NewMockKEM(), s, allowLegacy)
}
