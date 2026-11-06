package crypto

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

const (
	// AES256KeySize définit la taille de clé symétrique en octets (256 bits).
	AES256KeySize = 32
	// GCMNonceSize définit la taille standard du Nonce GCM en octets (12 octets / 96 bits).
	GCMNonceSize = 12

	// ProtocolVersion identifie la version de la spécification cryptographique du service.
	ProtocolVersion = "GO-PQC-GATEWAY-V2"
)

// CryptoUsage spécifie l'usage cryptographique pour garantir la séparation stricte des domaines (anti-confusion).
type CryptoUsage string

const (
	// UsageDataEncryption désigne le chiffrement direct de charge utile applicative (/encrypt).
	UsageDataEncryption CryptoUsage = "DATA_ENCRYPTION"
	// UsageKeyWrapping désigne l'enveloppement de clé symétrique cliente (/wrap-key).
	UsageKeyWrapping CryptoUsage = "KEY_WRAPPING_DEK"
	// UsageKeyAgreement désigne l'accord de clé post-quantique pur (/kem/encapsulate).
	UsageKeyAgreement CryptoUsage = "KEY_AGREEMENT"
)

// BuildDomainContext construit la chaîne de contexte HKDF garantissant la séparation de domaine.
func BuildDomainContext(algo string, usage CryptoUsage) []byte {
	return []byte(fmt.Sprintf("%s:%s:%s", ProtocolVersion, algo, usage))
}

// KeyIDSize est la taille, en octets, d'un identifiant de clé (16 caractères hexadécimaux).
const KeyIDSize = 8

// KeyID calcule l'identifiant d'une clé publique : hex(SHA-256("pqc-kid:" || pk))[:16].
// Il voyage dans l'enveloppe pour désigner la clé destinataire (rotation, trousseau).
// Il n'a pas à être authentifié : il dérive de la clé publique, déjà liée au transcript.
func KeyID(pk []byte) string {
	h := sha256.New()
	h.Write([]byte("pqc-kid:"))
	h.Write(pk)
	return hex.EncodeToString(h.Sum(nil)[:KeyIDSize])
}
