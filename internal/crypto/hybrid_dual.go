package crypto

import (
	"context"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"

	"github.com/cloudflare/circl/kem"
)

const (
	X25519PubKeySize  = 32
	X25519PrivKeySize = 32
)

type DualHybridKEM struct {
	name            string
	mlkemScheme     kem.Scheme
	mlkemPK         kem.PublicKey
	mlkemSK         kem.PrivateKey
	x25519Curve     ecdh.Curve
	x25519Priv      *ecdh.PrivateKey
	x25519Pub       *ecdh.PublicKey
	combinedPKBytes []byte
}

func NewDualHybrid(scheme kem.Scheme, name string) (*DualHybridKEM, error) {
	curve := ecdh.X25519()
	xPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("génération clé X25519: %w", err)
	}
	xPub := xPriv.PublicKey()

	mlPK, mlSK, err := scheme.GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("génération clé ML-KEM: %w", err)
	}

	mlPKBytes, err := mlPK.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("sérialisation clé publique ML-KEM: %w", err)
	}

	xPubBytes := xPub.Bytes()
	combinedPK := make([]byte, len(xPubBytes)+len(mlPKBytes))
	copy(combinedPK, xPubBytes)
	copy(combinedPK[len(xPubBytes):], mlPKBytes)

	return &DualHybridKEM{
		name:            name,
		mlkemScheme:     scheme,
		mlkemPK:         mlPK,
		mlkemSK:         mlSK,
		x25519Curve:     curve,
		x25519Priv:      xPriv,
		x25519Pub:       xPub,
		combinedPKBytes: combinedPK,
	}, nil
}

func NewDualHybridWithKeys(scheme kem.Scheme, name string, combinedPK, combinedSK []byte) (*DualHybridKEM, error) {
	expectedPKSize := X25519PubKeySize + scheme.PublicKeySize()
	expectedSKSize := X25519PrivKeySize + scheme.PrivateKeySize()

	if len(combinedPK) != expectedPKSize {
		return nil, fmt.Errorf("%w: taille clé publique composite %s invalide (%d, attendu %d)", ErrInvalidKey, name, len(combinedPK), expectedPKSize)
	}
	if len(combinedSK) != expectedSKSize {
		return nil, fmt.Errorf("%w: taille clé privée composite %s invalide (%d, attendu %d)", ErrInvalidKey, name, len(combinedSK), expectedSKSize)
	}

	curve := ecdh.X25519()
	xPriv, err := curve.NewPrivateKey(combinedSK[:X25519PrivKeySize])
	if err != nil {
		return nil, fmt.Errorf("%w: clé privée X25519 invalide: %v", ErrInvalidKey, err)
	}
	xPub := xPriv.PublicKey()

	if subtle.ConstantTimeCompare(xPub.Bytes(), combinedPK[:X25519PubKeySize]) != 1 {
		return nil, fmt.Errorf("%w: clé publique X25519 incohérente", ErrInvalidKey)
	}

	mlPK, err := scheme.UnmarshalBinaryPublicKey(combinedPK[X25519PubKeySize:])
	if err != nil {
		return nil, fmt.Errorf("%w: clé publique ML-KEM invalide: %v", ErrInvalidKey, err)
	}

	mlSK, err := scheme.UnmarshalBinaryPrivateKey(combinedSK[X25519PrivKeySize:])
	if err != nil {
		return nil, fmt.Errorf("%w: clé privée ML-KEM invalide: %v", ErrInvalidKey, err)
	}

	if err := validateKEMKeyPair(scheme, mlPK, mlSK, name); err != nil {
		return nil, err
	}

	pkCopy := make([]byte, len(combinedPK))
	copy(pkCopy, combinedPK)

	return &DualHybridKEM{
		name:            name,
		mlkemScheme:     scheme,
		mlkemPK:         mlPK,
		mlkemSK:         mlSK,
		x25519Curve:     curve,
		x25519Priv:      xPriv,
		x25519Pub:       xPub,
		combinedPKBytes: pkCopy,
	}, nil
}

func (d *DualHybridKEM) Name() string { return d.name }
func (d *DualHybridKEM) PublicKey() []byte {
	res := make([]byte, len(d.combinedPKBytes))
	copy(res, d.combinedPKBytes)
	return res
}
func (d *DualHybridKEM) IsMock() bool { return false }

func (d *DualHybridKEM) ExportKeys() ([]byte, []byte, error) {
	mlSKBytes, err := d.mlkemSK.MarshalBinary()
	if err != nil {
		return nil, nil, err
	}
	defer Zeroize(mlSKBytes)

	xPrivBytes := d.x25519Priv.Bytes()
	defer Zeroize(xPrivBytes)

	combinedSK := make([]byte, len(xPrivBytes)+len(mlSKBytes))
	copy(combinedSK, xPrivBytes)
	copy(combinedSK[len(xPrivBytes):], mlSKBytes)

	combinedPK := make([]byte, len(d.combinedPKBytes))
	copy(combinedPK, d.combinedPKBytes)

	return combinedPK, combinedSK, nil
}

func (d *DualHybridKEM) CombineSecrets(xSecret, mlSecret, encapKey, recipientPK []byte) ([]byte, error) {
	if len(xSecret) != 32 || len(mlSecret) != 32 {
		return nil, fmt.Errorf("%w: secrets partagés invalides", ErrInvalidKey)
	}

	expectedEncap := X25519PubKeySize + d.mlkemScheme.CiphertextSize()
	expectedPK := X25519PubKeySize + d.mlkemScheme.PublicKeySize()

	if len(encapKey) != expectedEncap {
		return nil, fmt.Errorf("%w: taille clé encapsulée duale invalide (%d, attendu %d)", ErrInvalidKey, len(encapKey), expectedEncap)
	}
	if len(recipientPK) != expectedPK {
		return nil, fmt.Errorf("%w: taille clé publique duale invalide (%d, attendu %d)", ErrInvalidKey, len(recipientPK), expectedPK)
	}

	salt := BuildCombinerSalt(d.name, encapKey, recipientPK)
	ikm := make([]byte, 64)
	copy(ikm, xSecret)
	copy(ikm[32:], mlSecret)
	defer Zeroize(ikm)

	info := ProtocolVersion + ":HYBRID-KEM-COMBINER:" + d.name
	combinedKey, err := hkdf.Key(sha256.New, ikm, salt, info, AES256KeySize)
	if err != nil {
		return nil, fmt.Errorf("échec dérivation HKDF combinateur: %w", err)
	}
	return combinedKey, nil
}

func (d *DualHybridKEM) parseRecipientPK(recipientPK []byte) (*ecdh.PublicKey, kem.PublicKey, []byte, error) {
	if len(recipientPK) == 0 {
		return d.x25519Pub, d.mlkemPK, d.combinedPKBytes, nil
	}
	if len(recipientPK) != len(d.combinedPKBytes) {
		return nil, nil, nil, fmt.Errorf("%w: taille clé publique destinataire composite invalide (%d, attendu %d)",
			ErrInvalidKey, len(recipientPK), len(d.combinedPKBytes))
	}
	xPub, err := d.x25519Curve.NewPublicKey(recipientPK[:X25519PubKeySize])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("%w: composante X25519 destinataire invalide: %v", ErrInvalidKey, err)
	}
	mlPK, err := d.mlkemScheme.UnmarshalBinaryPublicKey(recipientPK[X25519PubKeySize:])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("%w: composante ML-KEM destinataire invalide: %v", ErrInvalidKey, err)
	}
	return xPub, mlPK, recipientPK, nil
}

func (d *DualHybridKEM) Encapsulate(_ context.Context, recipientPK []byte) ([]byte, []byte, error) {
	xPub, mlPK, effPK, err := d.parseRecipientPK(recipientPK)
	if err != nil {
		return nil, nil, err
	}

	ephXPriv, err := d.x25519Curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("clé éphémère X25519: %w", err)
	}
	xSS, err := ephXPriv.ECDH(xPub)
	if err != nil {
		return nil, nil, fmt.Errorf("ECDH X25519: %w", err)
	}
	defer Zeroize(xSS)

	mlCT, mlSS, err := d.mlkemScheme.Encapsulate(mlPK)
	if err != nil {
		return nil, nil, fmt.Errorf("encapsulation ML-KEM: %w", err)
	}
	defer Zeroize(mlSS)

	ephPub := ephXPriv.PublicKey().Bytes()
	dualEncap := make([]byte, len(ephPub)+len(mlCT))
	copy(dualEncap, ephPub)
	copy(dualEncap[len(ephPub):], mlCT)

	combinedSecret, err := d.CombineSecrets(xSS, mlSS, dualEncap, effPK)
	if err != nil {
		return nil, nil, err
	}
	return dualEncap, combinedSecret, nil
}

func (d *DualHybridKEM) Decapsulate(_ context.Context, encapKey []byte) ([]byte, error) {
	expectedEncapSize := X25519PubKeySize + d.mlkemScheme.CiphertextSize()
	if len(encapKey) != expectedEncapSize {
		return nil, fmt.Errorf("%w: taille clé encapsulée dual invalide (%d, attendu %d)",
			ErrDecapsulationFailed, len(encapKey), expectedEncapSize)
	}

	ephXPub, err := d.x25519Curve.NewPublicKey(encapKey[:X25519PubKeySize])
	if err != nil {
		return nil, fmt.Errorf("%w: composante X25519 invalide: %v", ErrDecapsulationFailed, err)
	}

	xSS, err := d.x25519Priv.ECDH(ephXPub)
	if err != nil {
		return nil, fmt.Errorf("%w: ECDH X25519: %v", ErrDecapsulationFailed, err)
	}
	defer Zeroize(xSS)

	mlSS, err := d.mlkemScheme.Decapsulate(d.mlkemSK, encapKey[X25519PubKeySize:])
	if err != nil {
		return nil, fmt.Errorf("%w: décapsulation ML-KEM: %v", ErrDecapsulationFailed, err)
	}
	defer Zeroize(mlSS)

	return d.CombineSecrets(xSS, mlSS, encapKey, d.combinedPKBytes)
}
