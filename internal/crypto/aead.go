package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

// gcmTagSize est la taille de l'étiquette d'authentification AES-GCM.
const gcmTagSize = 16

// InPlaceSlack est la capacité supplémentaire qu'un tampon de clair doit avoir, au-delà de sa
// longueur, pour que sealSymmetric y écrive le chiffré sans réallocation.
const InPlaceSlack = gcmTagSize

func newGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != AES256KeySize {
		return nil, fmt.Errorf("taille de clé symétrique invalide: %d (attendu: %d)", len(key), AES256KeySize)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("erreur d'initialisation du bloc AES: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("erreur d'initialisation du mode GCM: %w", err)
	}
	return gcm, nil
}

// sealSymmetric chiffre plaintext avec AES-256-GCM. Si inPlace et que la capacité du tampon
// de plaintext le permet, le chiffré remplace le clair dans ce même tampon (aucune copie du
// clair ne reste) ; sinon un tampon neuf est alloué. Le nonce est tiré de crypto/rand : chaque
// clé symétrique ne sert qu'à un seul message, ce qui exclut toute réutilisation de nonce.
// Le nonce est écrit dans nonce (12 octets fournis par l'appelant).
func sealSymmetric(key, nonce, plaintext, aad []byte, inPlace bool) (ciphertext []byte, err error) {
	if len(nonce) != GCMNonceSize {
		return nil, fmt.Errorf("taille de nonce GCM invalide: %d (attendu: %d)", len(nonce), GCMNonceSize)
	}
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("erreur de génération du nonce aléatoire: %w", err)
	}
	dst := plaintext[:0]
	if !inPlace || cap(plaintext)-len(plaintext) < gcm.Overhead() {
		dst = make([]byte, 0, len(plaintext)+gcm.Overhead())
	}
	// #nosec G407 -- nonce crypto/rand ci-dessus, unique par appel
	return gcm.Seal(dst, nonce, plaintext, aad), nil
}

// openSymmetric déchiffre et authentifie ciphertext. Si inPlace, le clair remplace le chiffré
// dans son tampon (il est toujours plus court) ; sinon un tampon neuf est alloué.
func openSymmetric(key, nonce, ciphertext, aad []byte, inPlace bool) ([]byte, error) {
	if len(nonce) != GCMNonceSize {
		return nil, fmt.Errorf("taille de nonce GCM invalide: %d (attendu: %d)", len(nonce), GCMNonceSize)
	}
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	var dst []byte
	if inPlace {
		dst = ciphertext[:0]
	}
	plaintext, err := gcm.Open(dst, nonce, ciphertext, aad)
	if err != nil {
		return nil, ErrDecryptionFailed
	}
	return plaintext, nil
}

// EncryptSymmetric chiffre des données en clair avec AES-256-GCM, dans un tampon neuf.
func EncryptSymmetric(key, plaintext, aad []byte) (nonce, ciphertext []byte, err error) {
	nonce = make([]byte, GCMNonceSize)
	ciphertext, err = sealSymmetric(key, nonce, plaintext, aad, false)
	return nonce, ciphertext, err
}

// DecryptSymmetric déchiffre et vérifie l'intégrité des données avec AES-256-GCM, dans un tampon neuf.
func DecryptSymmetric(key, nonce, ciphertext, aad []byte) ([]byte, error) {
	return openSymmetric(key, nonce, ciphertext, aad, false)
}
