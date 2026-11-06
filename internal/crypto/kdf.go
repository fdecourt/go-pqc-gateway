package crypto

import (
	"crypto/sha256"
	"fmt"
)

// hkdfSHA256Key dérive une clé de 32 octets par HKDF-SHA256 (RFC 5869) : Extract puis un
// seul bloc d'Expand. Tout tient sur la pile : ni objet HMAC ni état de hachage sur le tas,
// donc rien qui contienne le secret ou la clé ne survit au retour. Le résultat est identique
// à crypto/hkdf.Key (vérifié par les tests, vecteurs RFC 5869 compris).
//
// Préconditions : len(salt) <= 64 (un sel plus long serait pré-haché par HMAC ; les sels de
// ce service sont des empreintes SHA-256), len(ikm) <= 192, len(info) <= 192.
func hkdfSHA256Key(out *[AES256KeySize]byte, ikm, salt []byte, info string) error {
	if len(ikm) == 0 {
		return fmt.Errorf("secret partagé KEM invalide ou vide")
	}
	if len(salt) > sha256.BlockSize || len(ikm) > 192 || len(info) > 192 {
		return fmt.Errorf("paramètres HKDF hors bornes")
	}
	// Extract : PRK = HMAC(salt, ikm)
	var prk [sha256.Size]byte
	hmacSHA256(&prk, salt, ikm, nil)
	defer Zeroize(prk[:])
	// Expand (L = 32 = une seule itération) : OKM = HMAC(PRK, info || 0x01)
	var t [sha256.Size]byte
	hmacSHA256(&t, prk[:], []byte(info), []byte{0x01})
	*out = t
	Zeroize(t[:])
	return nil
}

// hmacSHA256 calcule HMAC-SHA256(key, m1 || m2) dans out, sur la pile. len(key) <= 64.
func hmacSHA256(out *[sha256.Size]byte, key, m1, m2 []byte) {
	var ipad, opad [sha256.BlockSize]byte
	copy(ipad[:], key)
	copy(opad[:], key)
	for i := range ipad {
		ipad[i] ^= 0x36
		opad[i] ^= 0x5c
	}
	var inner [sha256.BlockSize + 2*192 + 1]byte
	n := copy(inner[:], ipad[:])
	n += copy(inner[n:], m1)
	n += copy(inner[n:], m2)
	innerSum := sha256.Sum256(inner[:n])
	Zeroize(inner[:n])

	var outer [sha256.BlockSize + sha256.Size]byte
	copy(outer[:], opad[:])
	copy(outer[sha256.BlockSize:], innerSum[:])
	*out = sha256.Sum256(outer[:])
	Zeroize(outer[:])
	Zeroize(innerSum[:])
	Zeroize(ipad[:])
	Zeroize(opad[:])
}

// DeriveSymmetricKey dérive une clé symétrique AES-256 à partir du secret partagé KEM
// (HKDF-SHA256, sel = empreinte du transcript, info = contexte de domaine).
func DeriveSymmetricKey(sharedSecret, salt, domainContext []byte) ([]byte, error) {
	var key [AES256KeySize]byte
	if err := hkdfSHA256Key(&key, sharedSecret, salt, string(domainContext)); err != nil {
		return nil, fmt.Errorf("erreur de dérivation de clé HKDF: %w", err)
	}
	return key[:], nil
}
