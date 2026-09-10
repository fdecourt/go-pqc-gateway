package crypto

import (
	"context"
	"fmt"

	"github.com/cloudflare/circl/kem"
)

// MLKEM implémente l'interface KEM pour le standard NIST FIPS 203 (ML-KEM-768 et ML-KEM-1024).
type MLKEM struct {
	name       string
	scheme     kem.Scheme
	publicKey  kem.PublicKey
	privateKey kem.PrivateKey
	pkBytes    []byte
}

func NewMLKEM(scheme kem.Scheme, name string) (*MLKEM, error) {
	pk, sk, err := scheme.GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("génération de la paire %s: %w", name, err)
	}

	pkBytes, err := pk.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("sérialisation clé publique %s: %w", name, err)
	}

	return &MLKEM{
		name:       name,
		scheme:     scheme,
		publicKey:  pk,
		privateKey: sk,
		pkBytes:    pkBytes,
	}, nil
}

func NewMLKEMWithKeys(scheme kem.Scheme, name string, pkBytes, skBytes []byte) (*MLKEM, error) {
	if len(pkBytes) != scheme.PublicKeySize() {
		return nil, fmt.Errorf("%w: taille clé publique %s invalide (%d, attendu %d)", ErrInvalidKey, name, len(pkBytes), scheme.PublicKeySize())
	}
	if len(skBytes) != scheme.PrivateKeySize() {
		return nil, fmt.Errorf("%w: taille clé privée %s invalide (%d, attendu %d)", ErrInvalidKey, name, len(skBytes), scheme.PrivateKeySize())
	}

	pk, err := scheme.UnmarshalBinaryPublicKey(pkBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: clé publique %s invalide: %v", ErrInvalidKey, name, err)
	}

	sk, err := scheme.UnmarshalBinaryPrivateKey(skBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: clé privée %s invalide: %v", ErrInvalidKey, name, err)
	}

	if err := validateKEMKeyPair(scheme, pk, sk, name); err != nil {
		return nil, err
	}

	pkCopy := make([]byte, len(pkBytes))
	copy(pkCopy, pkBytes)

	return &MLKEM{
		name:       name,
		scheme:     scheme,
		publicKey:  pk,
		privateKey: sk,
		pkBytes:    pkCopy,
	}, nil
}

func (m *MLKEM) Name() string { return m.name }
func (m *MLKEM) PublicKey() []byte {
	res := make([]byte, len(m.pkBytes))
	copy(res, m.pkBytes)
	return res
}
func (m *MLKEM) IsMock() bool { return false }

func (m *MLKEM) ExportKeys() ([]byte, []byte, error) {
	skBytes, err := m.privateKey.MarshalBinary()
	if err != nil {
		return nil, nil, fmt.Errorf("sérialisation clé privée: %w", err)
	}
	pkCopy := make([]byte, len(m.pkBytes))
	copy(pkCopy, m.pkBytes)
	return pkCopy, skBytes, nil
}

func (m *MLKEM) Encapsulate(_ context.Context, recipientPK []byte) ([]byte, []byte, error) {
	targetPK := m.publicKey
	if len(recipientPK) > 0 {
		if len(recipientPK) != m.scheme.PublicKeySize() {
			return nil, nil, fmt.Errorf("%w: taille clé publique destinataire %s invalide (%d, attendu %d)",
				ErrInvalidKey, m.name, len(recipientPK), m.scheme.PublicKeySize())
		}
		var err error
		targetPK, err = m.scheme.UnmarshalBinaryPublicKey(recipientPK)
		if err != nil {
			return nil, nil, fmt.Errorf("%w: clé publique destinataire invalide: %v", ErrInvalidKey, err)
		}
	}
	return m.scheme.Encapsulate(targetPK)
}

func (m *MLKEM) Decapsulate(ctx context.Context, encapKey []byte) ([]byte, error) {
	if len(encapKey) != m.scheme.CiphertextSize() {
		return nil, fmt.Errorf("%w: taille clé encapsulée %s invalide (%d, attendu %d)",
			ErrDecapsulationFailed, m.name, len(encapKey), m.scheme.CiphertextSize())
	}
	return m.scheme.Decapsulate(m.privateKey, encapKey)
}
