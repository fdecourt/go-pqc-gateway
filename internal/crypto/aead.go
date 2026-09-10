package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

// EncryptSymmetric chiffre des données en clair avec AES-256-GCM à l'aide de la clé symétrique dérivée
// et des données additionnelles authentifiées (AAD) pour prévenir toute substitution.
func EncryptSymmetric(key, plaintext, aad []byte) (nonce, ciphertext []byte, err error) {
	if len(key) != AES256KeySize {
		return nil, nil, fmt.Errorf("taille de clé symétrique invalide: %d (attendu: %d)", len(key), AES256KeySize)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, fmt.Errorf("erreur d'initialisation du bloc AES: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, fmt.Errorf("erreur d'initialisation du mode GCM: %w", err)
	}

	// Nonce cryptographique aléatoire généré via crypto/rand
	nonce = make([]byte, GCMNonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, fmt.Errorf("erreur de génération du nonce aléatoire: %w", err)
	}

	// Pré-allocation avec capacité exacte pour éviter tout réajustement dynamique de slice
	dst := make([]byte, 0, len(plaintext)+gcm.Overhead())
	// #nosec G407 -- nonce crypto/rand ligne 30, unique par appel
	ciphertext = gcm.Seal(dst, nonce, plaintext, aad)
	return nonce, ciphertext, nil
}

// DecryptSymmetric déchiffre et vérifie l'intégrité et l'authenticité des données avec AES-256-GCM et AAD.
func DecryptSymmetric(key, nonce, ciphertext, aad []byte) ([]byte, error) {
	if len(key) != AES256KeySize {
		return nil, fmt.Errorf("taille de clé symétrique invalide: %d", len(key))
	}
	if len(nonce) != GCMNonceSize {
		return nil, fmt.Errorf("taille de nonce GCM invalide: %d (attendu: %d)", len(nonce), GCMNonceSize)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("erreur d'initialisation du bloc AES: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("erreur d'initialisation du mode GCM: %w", err)
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, ErrDecryptionFailed
	}

	return plaintext, nil
}
