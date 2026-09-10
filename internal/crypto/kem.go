package crypto

import (
	"context"
	"crypto/subtle"
	"fmt"

	"github.com/cloudflare/circl/kem"
)

// KEM définit la responsabilité unique d'un mécanisme d'encapsulation de clé (SRP).
type KEM interface {
	Name() string
	PublicKey() []byte
	Encapsulate(ctx context.Context, recipientPK []byte) (encapsulatedKey, sharedSecret []byte, err error)
	Decapsulate(ctx context.Context, encapsulatedKey []byte) (sharedSecret []byte, err error)
	ExportKeys() (publicKey, privateKey []byte, err error)
	IsMock() bool
}

// validateKEMKeyPair garantit l'intégrité et la correspondance d'une paire de clés KEM par un self-test strict.
func validateKEMKeyPair(scheme kem.Scheme, pk kem.PublicKey, sk kem.PrivateKey, name string) error {
	if !sk.Public().Equal(pk) {
		return fmt.Errorf("%w: clé publique %s ne correspond pas à la clé privée", ErrInvalidKey, name)
	}
	ct, ssEncap, err := scheme.Encapsulate(pk)
	if err != nil {
		return fmt.Errorf("%w: échec test encapsulation %s: %v", ErrInvalidKey, name, err)
	}
	defer Zeroize(ssEncap)

	ssDecap, err := scheme.Decapsulate(sk, ct)
	if err != nil {
		return fmt.Errorf("%w: échec test décapsulation %s: %v", ErrInvalidKey, name, err)
	}
	defer Zeroize(ssDecap)

	if subtle.ConstantTimeCompare(ssEncap, ssDecap) != 1 {
		return fmt.Errorf("%w: incohérence self-test pour %s", ErrInvalidKey, name)
	}
	return nil
}
