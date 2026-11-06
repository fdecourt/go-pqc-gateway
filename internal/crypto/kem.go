package crypto

import (
	"context"
	"crypto/subtle"
	"fmt"

	"github.com/cloudflare/circl/kem"
)

// KEM encapsule et décapsule un secret partagé. La génération et la sérialisation des clés
// relèvent de la Suite : un KEM chargé n'expose jamais sa clé privée.
type KEM interface {
	Name() string
	// PublicKey renvoie une copie de la clé publique sérialisée.
	PublicKey() []byte
	// Encapsulate vise recipientPK, ou la clé publique locale si recipientPK est vide.
	Encapsulate(ctx context.Context, recipientPK []byte) (encapsulatedKey, sharedSecret []byte, err error)
	Decapsulate(ctx context.Context, encapsulatedKey []byte) (sharedSecret []byte, err error)
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
