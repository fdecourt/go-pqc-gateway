package crypto

import (
	"crypto/hkdf"
	"crypto/sha256"
	"fmt"
)

// DeriveSymmetricKey dérive une clé symétrique AES-256 à partir du secret partagé KEM
// en utilisant HKDF-SHA256 avec isolation de domaine cryptographique et sel de transcription canonique.
func DeriveSymmetricKey(sharedSecret, salt, domainContext []byte) ([]byte, error) {
	if len(sharedSecret) == 0 {
		return nil, fmt.Errorf("secret partagé KEM invalide ou vide")
	}

	key, err := hkdf.Key(sha256.New, sharedSecret, salt, string(domainContext), AES256KeySize)
	if err != nil {
		return nil, fmt.Errorf("erreur de dérivation de clé HKDF: %w", err)
	}
	return key, nil
}
