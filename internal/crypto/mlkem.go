package crypto

import (
	"context"
	"crypto/rand"
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

// generateMLKEMKeyPair génère une paire ML-KEM et la renvoie sérialisée (format FIPS 203).
func generateMLKEMKeyPair(scheme kem.Scheme, name string) (pkBytes, skBytes []byte, err error) {
	pk, sk, err := scheme.GenerateKeyPair()
	clearUpperAVXState()
	if err != nil {
		return nil, nil, fmt.Errorf("génération de la paire %s: %w", name, err)
	}
	if pkBytes, err = pk.MarshalBinary(); err != nil {
		return nil, nil, fmt.Errorf("sérialisation clé publique %s: %w", name, err)
	}
	if skBytes, err = sk.MarshalBinary(); err != nil {
		return nil, nil, fmt.Errorf("sérialisation clé privée %s: %w", name, err)
	}
	return pkBytes, skBytes, nil
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
	ct, ss, err := encapsulate(m.scheme, targetPK)
	clearUpperAVXState()
	return ct, ss, err
}

// directEncapsulator est implémenté par les clés publiques ML-KEM de circl : encapsulation
// dans des tampons fournis, avec une graine fournie (pas d'allocation interne).
type directEncapsulator interface {
	EncapsulateTo(ct, ss []byte, seed []byte)
}

// encapsulate encapsule vers pk dans des tampons alloués ici, avec une graine tirée sur la
// pile ; repli sur scheme.Encapsulate pour une clé qui n'offre pas EncapsulateTo.
func encapsulate(scheme kem.Scheme, pk kem.PublicKey) (ct, ss []byte, err error) {
	direct, ok := pk.(directEncapsulator)
	if !ok {
		return scheme.Encapsulate(pk)
	}
	var seed [32]byte
	if _, err := rand.Read(seed[:]); err != nil {
		return nil, nil, fmt.Errorf("graine d'encapsulation: %w", err)
	}
	defer Zeroize(seed[:])
	ct = make([]byte, scheme.CiphertextSize())
	ss = make([]byte, scheme.SharedKeySize())
	direct.EncapsulateTo(ct, ss, seed[:])
	return ct, ss, nil
}

func (m *MLKEM) Decapsulate(ctx context.Context, encapKey []byte) ([]byte, error) {
	if len(encapKey) != m.scheme.CiphertextSize() {
		return nil, fmt.Errorf("%w: taille clé encapsulée %s invalide (%d, attendu %d)",
			ErrDecapsulationFailed, m.name, len(encapKey), m.scheme.CiphertextSize())
	}
	ss, err := m.scheme.Decapsulate(m.privateKey, encapKey)
	clearUpperAVXState()
	return ss, err
}
